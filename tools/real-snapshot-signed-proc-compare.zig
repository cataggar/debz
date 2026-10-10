const std = @import("std");
const fs = @import("debz").root_fs;

const maximum_entries = 200_000;
const maximum_file_bytes = 512 * 1024 * 1024;
const maximum_read_bytes = 4 * 1024 * 1024;
const maximum_reported = 400;
const pinned_dpkg = "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5";
const snapshot_dpkg = "972003a11f3ae0f5b2556dce1d2c2721fb5119818b9bbef1124293024fdb6517";
const setpriv = "86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993";

pub const Record = struct {
    device: ?[]const u8 = null,
    gid: u32,
    links: ?u64 = null,
    mode: []const u8,
    sha256: ?[]const u8 = null,
    size: ?u64 = null,
    target: ?[]const u8 = null,
    type: []const u8,
    uid: u32,

    fn eql(left: Record, right: Record, ignore_digest: bool) bool {
        inline for (std.meta.fields(Record)) |member| {
            if (!ignore_digest or !std.mem.eql(u8, member.name, "sha256")) {
                const a = @field(left, member.name);
                const b = @field(right, member.name);
                const equal = if (member.type == []const u8)
                    std.mem.eql(u8, a, b)
                else if (member.type == ?[]const u8)
                    optionalTextEql(a, b)
                else
                    a == b;
                if (!equal) return false;
            }
        }
        return true;
    }

    pub fn jsonStringify(self: Record, stream: *std.json.Stringify) !void {
        try stream.beginObject();
        inline for (std.meta.fields(Record)) |member| {
            const value = @field(self, member.name);
            if (@typeInfo(member.type) == .optional) {
                if (value) |present| {
                    try stream.objectField(member.name);
                    try stream.write(present);
                }
            } else {
                try stream.objectField(member.name);
                try stream.write(value);
            }
        }
        try stream.endObject();
    }
};

pub const Entries = std.StringHashMapUnmanaged(Record);
pub const Reader = struct {
    context: *const anyopaque,
    function: *const fn (*const anyopaque, std.mem.Allocator, []const u8) anyerror![]const u8,

    fn read(self: Reader, allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
        return self.function(self.context, allocator, path);
    }
};

fn optionalTextEql(left: ?[]const u8, right: ?[]const u8) bool {
    return if (left) |a| if (right) |b| std.mem.eql(u8, a, b) else false else right == null;
}

fn optionalRecordEql(left: ?Record, right: ?Record) bool {
    return if (left) |a| if (right) |b| a.eql(b, false) else false else right == null;
}

fn hex(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const output = try allocator.alloc(u8, bytes.len * 2);
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 15];
    }
    return output;
}

fn digest(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    var value: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &value, .{});
    return hex(allocator, &value);
}

fn validHex(data: []const u8, length: usize) bool {
    if (data.len != length) return false;
    for (data) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return false;
    return true;
}

const Inventory = struct {
    root: fs.Root,
    entries: Entries = .empty,
    allocator: std.mem.Allocator,
    device: u64,
    buffer: []u8,

    fn collect(root: fs.Root, allocator: std.mem.Allocator, required_uid: u32) !Inventory {
        const before = try root.rootEntry();
        if (!before.modeled or before.kind != .directory or before.uid != required_uid)
            return error.ComparisonRootMustBeRootOwned;
        var inventory: Inventory = .{
            .root = root,
            .allocator = allocator,
            .device = before.device,
            .buffer = try allocator.alloc(u8, 1024 * 1024),
        };
        try inventory.directory(root.dir, "");
        if (!std.meta.eql(before, try root.rootEntry())) return error.PathChanged;
        return inventory;
    }

    fn directory(self: *Inventory, dir: std.Io.Dir, prefix: []const u8) anyerror!void {
        var iterator = dir.iterate();
        while (try iterator.next(self.root.io)) |member| {
            if (self.entries.count() >= maximum_entries) return error.ComparisonEntryLimit;
            const relative = if (prefix.len == 0)
                try self.allocator.dupe(u8, member.name)
            else
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ prefix, member.name });
            if (!std.unicode.utf8ValidateSlice(relative)) return error.InvalidUtf8;
            const path = try fs.Path.initPackage(relative);
            const entry = try self.root.entry(path);
            if (!entry.modeled or entry.device != self.device) return error.ComparisonCrossesMount;
            var record: Record = .{
                .uid = entry.uid,
                .gid = entry.gid,
                .mode = try std.fmt.allocPrint(self.allocator, "0o{o}", .{entry.mode}),
                .type = switch (entry.kind) {
                    .directory => "directory",
                    .sym_link => "symlink",
                    .file => "file",
                    .character_device => "character",
                    .block_device => "block",
                    .named_pipe => "fifo",
                    .unix_domain_socket => "socket",
                    else => return error.UnsupportedComparisonEntry,
                },
            };
            switch (entry.kind) {
                .file => {
                    var pin = try self.root.pinRegularFile(path);
                    defer pin.close();
                    var hash = std.crypto.hash.sha2.Sha256.init(.{});
                    const observed = try pin.observeStreamed(self.buffer, maximum_file_bytes, &hash);
                    if (!std.meta.eql(entry, observed.entry)) return error.PathChanged;
                    record.size = entry.size;
                    record.links = entry.link_count;
                    record.sha256 = try hex(self.allocator, &hash.finalResult());
                },
                .sym_link => {
                    var pin = try self.root.pinSymbolicLink(path);
                    defer pin.close();
                    var target: [fs.maximum_link_target_bytes + 1]u8 = undefined;
                    const observed = try pin.observe(&target);
                    if (!std.meta.eql(entry, observed.entry)) return error.PathChanged;
                    if (!std.unicode.utf8ValidateSlice(observed.target)) return error.InvalidUtf8;
                    record.target = try self.allocator.dupe(u8, observed.target);
                },
                .character_device, .block_device => record.device = try self.deviceNumber(path, entry),
                else => {},
            }
            try self.entries.put(self.allocator, relative, record);
            if (entry.kind == .directory) {
                var pin = try self.root.pinDirectory(path);
                defer pin.close();
                if (!std.meta.eql(entry, (try pin.metadata()).entry)) return error.PathChanged;
                if (std.mem.eql(u8, relative, "proc")) {
                    var children = pin.dir.iterate();
                    if (try children.next(self.root.io) != null) return error.ComparisonProcMustBeEmpty;
                } else {
                    try self.directory(pin.dir, relative);
                }
                _ = try pin.metadata();
            }
        }
    }

    fn deviceNumber(self: *Inventory, path: fs.Path, entry: fs.Entry) ![]const u8 {
        if (@import("builtin").os.tag != .linux) return error.OperationUnsupported;
        var parent = try self.root.openParent(path);
        defer parent.close(self.root.io);
        const leaf = try self.allocator.dupeZ(u8, parent.leaf);
        const linux = std.os.linux;
        var raw = std.mem.zeroes(linux.Statx);
        switch (linux.errno(linux.statx(parent.dir.handle, leaf, linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT, .{ .TYPE = true, .INO = true }, &raw))) {
            .SUCCESS => {},
            .NOENT => return error.FileNotFound,
            .ACCES => return error.AccessDenied,
            else => return error.DeviceObservationFailed,
        }
        if (!raw.mask.TYPE or !raw.mask.INO or raw.ino != entry.inode or
            ((@as(u64, raw.dev_major) << 32) | raw.dev_minor) != entry.device or
            !std.meta.eql(entry, try self.root.entry(path))) return error.PathChanged;
        return std.fmt.allocPrint(self.allocator, "{d}:{d}", .{ raw.rdev_major, raw.rdev_minor });
    }

    fn read(context: *const anyopaque, allocator: std.mem.Allocator, relative: []const u8) ![]const u8 {
        const self: *const Inventory = @ptrCast(@alignCast(context));
        const record = self.entries.get(relative) orelse return error.FileNotFound;
        if (!std.mem.eql(u8, record.type, "file") or record.size.? > maximum_read_bytes)
            return error.NotBoundedComparisonFile;
        var pin = try self.root.pinRegularFile(try fs.Path.initPackage(relative));
        defer pin.close();
        const bytes = (try pin.observeStableAlloc(allocator, maximum_read_bytes)).bytes;
        if (!std.mem.eql(u8, record.sha256.?, try digest(allocator, bytes))) return error.PathChanged;
        return bytes;
    }

    fn reader(self: *const Inventory) Reader {
        return .{ .context = self, .function = read };
    }
};

const Field = struct { name: []const u8, value: []const u8 };
const Status = std.StringHashMapUnmanaged([]const Field);

fn whitespace(point: u21) bool {
    return switch (point) {
        0x09...0x0d, 0x1c...0x20, 0x85, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
        else => false,
    };
}

fn words(allocator: std.mem.Allocator, text: []const u8) ![]const []const u8 {
    var tokens: std.ArrayList([]const u8) = .empty;
    var start: ?usize = null;
    var offset: usize = 0;
    while (offset < text.len) {
        const length = std.unicode.utf8ByteSequenceLength(text[offset]) catch return error.InvalidUtf8;
        if (text.len - offset < length) return error.InvalidUtf8;
        const point = std.unicode.utf8Decode(text[offset..][0..length]) catch return error.InvalidUtf8;
        if (whitespace(point)) {
            if (start) |begin| try tokens.append(allocator, text[begin..offset]);
            start = null;
        } else if (start == null) start = offset;
        offset += length;
    }
    if (start) |begin| try tokens.append(allocator, text[begin..]);
    return tokens.toOwnedSlice(allocator);
}

fn trim(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    const tokens = try words(allocator, text);
    if (tokens.len == 0) return "";
    const first = tokens[0];
    const last = tokens[tokens.len - 1];
    const offset = @intFromPtr(first.ptr) - @intFromPtr(text.ptr);
    const end = @intFromPtr(last.ptr) - @intFromPtr(text.ptr) + last.len;
    return text[offset..end];
}

fn field(fields: []const Field, name: []const u8) ?[]const u8 {
    var value: ?[]const u8 = null;
    for (fields) |item| if (std.mem.eql(u8, item.name, name)) {
        value = item.value;
    };
    return value;
}

fn stanzas(allocator: std.mem.Allocator, data: []const u8) !Status {
    if (!std.unicode.utf8ValidateSlice(data)) return error.InvalidUtf8;
    var parsed: Status = .empty;
    var blocks = std.mem.splitSequence(u8, data, "\n\n");
    while (blocks.next()) |block| {
        if ((try trim(allocator, block)).len == 0) continue;
        var fields: std.ArrayList(Field) = .empty;
        var lines = std.mem.splitScalar(u8, block, '\n');
        while (lines.next()) |line| {
            if (line.len != 0 and (line[0] == ' ' or line[0] == '\t') and fields.items.len != 0) {
                const last = &fields.items[fields.items.len - 1];
                last.value = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ last.value, line });
            } else {
                const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedStatus;
                if (colon == 0) return error.MalformedStatus;
                try fields.append(allocator, .{ .name = line[0..colon], .value = try trim(allocator, line[colon + 1 ..]) });
            }
        }
        const key = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ field(fields.items, "Package") orelse "None", field(fields.items, "Architecture") orelse "None" });
        const item = try parsed.getOrPut(allocator, key);
        if (item.found_existing) return error.DuplicateStatus;
        item.value_ptr.* = try fields.toOwnedSlice(allocator);
    }
    return parsed;
}

fn conffiles(allocator: std.mem.Allocator, value: []const u8) ![]const []const []const u8 {
    var result: std.ArrayList([]const []const u8) = .empty;
    var lines = std.mem.splitScalar(u8, value, '\n');
    while (lines.next()) |line| {
        const tokens = try words(allocator, line);
        if (tokens.len != 0) try result.append(allocator, tokens);
    }
    return result.toOwnedSlice(allocator);
}

fn stripSlash(path: []const u8) []const u8 {
    return std.mem.trimStart(u8, path, "/");
}

pub fn pendingConffiles(allocator: std.mem.Allocator, target: []const u8, status: []const u8) ![]const []const u8 {
    const parsed = try stanzas(allocator, status);
    const fields = parsed.get(try std.fmt.allocPrint(allocator, "{s}:amd64", .{target})) orelse &.{};
    var pending: std.ArrayList([]const u8) = .empty;
    for (try conffiles(allocator, field(fields, "Conffiles") orelse "")) |line| {
        if (line.len == 2 and std.mem.eql(u8, line[1], "newconffile")) try pending.append(allocator, stripSlash(line[0]));
    }
    return pending.toOwnedSlice(allocator);
}

fn fieldsEql(left: []const Field, right: []const Field, ignore_bookkeeping: bool) bool {
    var a: usize = 0;
    var b: usize = 0;
    while (true) {
        while (a < left.len and ignore_bookkeeping and bookkeeping(left[a].name)) : (a += 1) {}
        while (b < right.len and ignore_bookkeeping and bookkeeping(right[b].name)) : (b += 1) {}
        if (a == left.len or b == right.len) return a == left.len and b == right.len;
        if (!std.mem.eql(u8, left[a].name, right[b].name) or !std.mem.eql(u8, left[a].value, right[b].value)) return false;
        a += 1;
        b += 1;
    }
}

fn bookkeeping(name: []const u8) bool {
    return std.mem.eql(u8, name, "Status") or std.mem.eql(u8, name, "Config-Version") or std.mem.eql(u8, name, "Conffiles");
}

fn configurable(fields: []const Field) bool {
    const state = field(fields, "Status") orelse return false;
    return std.mem.eql(u8, state, "install ok unpacked") or std.mem.eql(u8, state, "install ok half-configured");
}

fn statusTransition(allocator: std.mem.Allocator, target: []const u8, native: []const u8, proof: []const u8, read_proof: Reader) !bool {
    const before = try stanzas(allocator, native);
    const after = try stanzas(allocator, proof);
    const key = try std.fmt.allocPrint(allocator, "{s}:amd64", .{target});
    const old = before.get(key) orelse return false;
    const new = after.get(key) orelse return false;
    if (before.count() != after.count()) return false;
    var iterator = before.iterator();
    while (iterator.next()) |item| {
        const current = after.get(item.key_ptr.*) orelse return false;
        if (!std.mem.eql(u8, item.key_ptr.*, key) and !fieldsEql(item.value_ptr.*, current, false)) return false;
    }
    if (!configurable(old) or !optionalTextEql(field(new, "Status"), "install ok installed")) return false;
    const version = field(old, "Version");
    const previous_config = field(old, "Config-Version");
    const current_config = field(new, "Config-Version");
    if (current_config != null and !optionalTextEql(current_config, version) or
        previous_config != null and !optionalTextEql(previous_config, current_config)) return false;
    const old_conffiles = try conffiles(allocator, field(old, "Conffiles") orelse "");
    const new_conffiles = try conffiles(allocator, field(new, "Conffiles") orelse "");
    if (old_conffiles.len != new_conffiles.len) return false;
    for (old_conffiles, new_conffiles) |previous, current| {
        var equal = previous.len == current.len;
        if (equal) for (previous, current) |a, b| {
            if (!std.mem.eql(u8, a, b)) equal = false;
        };
        if (equal) continue;
        if (previous.len != 2 or current.len != 2 or !std.mem.eql(u8, previous[0], current[0]) or
            !std.mem.eql(u8, previous[1], "newconffile") or !validHex(current[1], 32)) return false;
        const bytes = try read_proof.read(allocator, stripSlash(current[0]));
        var hash: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(bytes, &hash, .{});
        if (!std.mem.eql(u8, try hex(allocator, &hash), current[1])) return false;
    }
    return fieldsEql(old, new, true);
}

fn timestamp(data: []const u8) bool {
    if (data.len < 19) return false;
    for (data[0..19], 0..) |byte, index| {
        const valid = switch (index) {
            4, 7 => byte == '-',
            10 => byte == ' ',
            13, 16 => byte == ':',
            else => std.ascii.isDigit(byte),
        };
        if (!valid) return false;
    }
    return true;
}

fn dpkgLog(allocator: std.mem.Allocator, target: []const u8, data: []const u8, fields: []const Field) !bool {
    const version = field(fields, "Version") orelse return false;
    if (version.len == 0 or !configurable(fields)) return false;
    const package = try std.fmt.allocPrint(allocator, "{s}:amd64", .{target});
    var events: std.ArrayList([]const u8) = .empty;
    try events.appendSlice(allocator, &.{
        "startup packages configure",
        try std.fmt.allocPrint(allocator, "configure {s} {s} <none>", .{ package, version }),
    });
    if (optionalTextEql(field(fields, "Status"), "install ok unpacked"))
        try events.append(allocator, try std.fmt.allocPrint(allocator, "status unpacked {s} {s}", .{ package, version }));
    for ([_][]const u8{ "half-configured", "installed" }) |state|
        try events.append(allocator, try std.fmt.allocPrint(allocator, "status {s} {s} {s}", .{ state, package, version }));
    var lines = std.mem.splitScalar(u8, data, '\n');
    for (events.items) |event| {
        const line = lines.next() orelse return false;
        if (line.len != 20 + event.len or !timestamp(line) or line[19] != ' ' or !std.mem.eql(u8, line[20..], event)) return false;
    }
    const last = lines.next() orelse return false;
    return last.len == 0 and lines.next() == null;
}

fn rootFile(entry: ?Record, mode: []const u8, sha256: ?[]const u8) bool {
    const record = entry orelse return false;
    return std.mem.eql(u8, record.type, "file") and record.uid == 0 and record.gid == 0 and
        std.mem.eql(u8, record.mode, mode) and record.links == 1 and
        (sha256 == null or optionalTextEql(record.sha256, sha256));
}

fn sameExceptContent(left: ?Record, right: ?Record) bool {
    const a = left orelse return false;
    const b = right orelse return false;
    return a.eql(b, true);
}

fn installedConffile(allocator: std.mem.Allocator, path: []const u8, pending: []const []const u8, native: Entries, proof: Entries) !bool {
    for (pending) |name| {
        const staged = try std.fmt.allocPrint(allocator, "{s}.dpkg-new", .{name});
        if (!std.mem.eql(u8, path, name) and !std.mem.eql(u8, path, staged)) continue;
        const entry = native.get(staged) orelse return false;
        return !native.contains(name) and !proof.contains(staged) and std.mem.eql(u8, entry.type, "file") and
            entry.uid == 0 and entry.gid == 0 and optionalRecordEql(entry, proof.get(name));
    }
    return false;
}

fn alternativesWithoutStamps(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    var output: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, data, '\n');
    var first = true;
    while (lines.next()) |line| {
        if (!first) try output.append(allocator, '\n');
        first = false;
        const prefix = "update-alternatives ";
        const stamp_length = prefix.len + 19 + 2;
        const strip = line.len >= stamp_length and std.mem.startsWith(u8, line, prefix) and
            timestamp(line[prefix.len..]) and std.mem.eql(u8, line[prefix.len + 19 ..][0..2], ": ");
        try output.appendSlice(allocator, if (strip) line[stamp_length..] else line);
    }
    return output.toOwnedSlice(allocator);
}

pub fn classify(allocator: std.mem.Allocator, target: []const u8, path: []const u8, native: Entries, proof: Entries, read_native: Reader, read_proof: Reader, pending: []const []const u8) !?[]const u8 {
    const left = native.get(path);
    const right = proof.get(path);
    if (std.mem.eql(u8, path, "usr/bin/setpriv")) {
        if (left == null and rootFile(right, "0o755", setpriv))
            return "proof harness: closure setpriv drops CAP_SYS_ADMIN before pinned dpkg";
    } else if (std.mem.eql(u8, path, "usr/local/sbin/dpkg") and (std.mem.eql(u8, target, "udev") or std.mem.eql(u8, target, "sudo"))) {
        if (left == null and rootFile(right, "0o755", pinned_dpkg))
            return "proof harness: receipt-verified pinned dpkg";
    } else if (std.mem.eql(u8, path, "usr/bin/dpkg") and std.mem.eql(u8, target, "systemd")) {
        if (rootFile(left, "0o755", snapshot_dpkg) and rootFile(right, "0o755", pinned_dpkg))
            return "proof harness: receipt-verified pinned dpkg replaces the snapshot dpkg";
    } else if (std.mem.eql(u8, path, "var/log/dpkg.log")) {
        if (rootFile(right, "0o644", null) and (left == null or rootFile(left, "0o644", null))) {
            const before = if (left == null) "" else try read_native.read(allocator, path);
            const after = try read_proof.read(allocator, path);
            const status = try stanzas(allocator, try read_native.read(allocator, "var/lib/dpkg/status"));
            const fields = status.get(try std.fmt.allocPrint(allocator, "{s}:amd64", .{target})) orelse &.{};
            if ((before.len == 0 or before[before.len - 1] == '\n') and std.mem.startsWith(u8, after, before) and
                try dpkgLog(allocator, target, after[before.len..], fields))
                return "proof harness: unchanged raw history followed only by target configure";
        }
    } else if (std.mem.eql(u8, path, "var/lib/dpkg/status")) {
        if (rootFile(left, "0o644", null) and rootFile(right, "0o644", null) and
            try statusTransition(allocator, target, try read_native.read(allocator, path), try read_proof.read(allocator, path), read_proof))
            return "dpkg bookkeeping: only the target stanza is configured";
    } else if (std.mem.eql(u8, path, "var/lib/dpkg/status-old")) {
        if (rootFile(left, "0o644", null) and rootFile(right, "0o644", null) and
            rootFile(native.get("var/lib/dpkg/status"), "0o644", right.?.sha256))
            return "dpkg bookkeeping: the proof backs up the unconfigured status";
    } else if (std.mem.eql(u8, path, "run/mount")) {
        if (left == null and optionalRecordEql(right, .{ .type = "directory", .uid = 0, .gid = 0, .mode = "0o700" })) {
            var iterator = proof.keyIterator();
            while (iterator.next()) |name| if (std.mem.startsWith(u8, name.*, "run/mount/")) return null;
            return "proof harness: chrooted mount(8) creates libmount's empty utab directory";
        }
    } else if (std.mem.eql(u8, path, "etc/machine-id") and std.mem.eql(u8, target, "systemd")) {
        if (rootFile(left, "0o444", null) and sameExceptContent(left, right)) {
            const a = try read_native.read(allocator, path);
            const b = try read_proof.read(allocator, path);
            if (a.len == 33 and b.len == 33 and a[32] == '\n' and b[32] == '\n' and validHex(a[0..32], 32) and validHex(b[0..32], 32))
                return "systemd postinst generates a random machine ID in each copy";
        }
    } else if (std.mem.eql(u8, path, "var/log/alternatives.log")) {
        if (rootFile(left, "0o644", null) and sameExceptContent(left, right) and
            std.mem.eql(u8, try alternativesWithoutStamps(allocator, try read_native.read(allocator, path)), try alternativesWithoutStamps(allocator, try read_proof.read(allocator, path))))
            return "update-alternatives stamps the same log lines with wall-clock time";
    }
    if (try installedConffile(allocator, path, pending, native, proof))
        return "dpkg configure installs new conffiles before the replayed postinst";
    return null;
}

const Difference = struct {
    @"error": ?[]const u8 = null,
    native: ?Record,
    path: []const u8,
    proof: ?Record,
    reviewed: ?[]const u8,

    pub fn jsonStringify(self: Difference, stream: *std.json.Stringify) !void {
        try stream.beginObject();
        if (self.@"error") |diagnostic| {
            try stream.objectField("error");
            try stream.write(diagnostic);
        }
        inline for (.{ "native", "path", "proof", "reviewed" }) |name| {
            try stream.objectField(name);
            try stream.write(@field(self, name));
        }
        try stream.endObject();
    }
};

const Report = struct {
    differences: []const Difference,
    native_entries: usize,
    pending_conffiles: []const []const u8,
    proof_entries: usize,
    reviewed_differences: usize,
    target: []const u8,
    unexpected_differences: usize,
};

fn compare(allocator: std.mem.Allocator, target: []const u8, native: *const Inventory, proof: *const Inventory) !Report {
    const pending = try pendingConffiles(allocator, target, try native.reader().read(allocator, "var/lib/dpkg/status"));
    var paths: std.StringHashMapUnmanaged(void) = .empty;
    for ([_]Entries{ native.entries, proof.entries }) |entries| {
        var iterator = entries.keyIterator();
        while (iterator.next()) |path| try paths.put(allocator, path.*, {});
    }
    const sorted = try allocator.alloc([]const u8, paths.count());
    var iterator = paths.keyIterator();
    var index: usize = 0;
    while (iterator.next()) |path| : (index += 1) sorted[index] = path.*;
    std.mem.sort([]const u8, sorted, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    var differences: std.ArrayList(Difference) = .empty;
    var unexpected: usize = 0;
    for (sorted) |path| {
        const left = native.entries.get(path);
        const right = proof.entries.get(path);
        if (optionalRecordEql(left, right)) continue;
        var difference: Difference = .{ .path = path, .native = left, .proof = right, .reviewed = null };
        difference.reviewed = classify(allocator, target, path, native.entries, proof.entries, native.reader(), proof.reader(), pending) catch |err| switch (err) {
            error.MalformedStatus,
            error.DuplicateStatus,
            error.InvalidUtf8,
            error.FileNotFound,
            error.NotBoundedComparisonFile,
            error.PathChanged,
            error.FileTooLarge,
            error.NotRegularFile,
            error.SymbolicLinkComponent,
            error.EmptyPath,
            error.AbsolutePath,
            error.TraversingPath,
            error.EmptyPathComponent,
            error.InvalidPathByte,
            error.PathTooLong,
            error.PathComponentTooLong,
            error.PathTooDeep,
            => diagnostic: {
                difference.@"error" = @errorName(err);
                std.log.err("comparison content refused: {s}: {s}", .{ path, @errorName(err) });
                break :diagnostic null;
            },
            else => return err,
        };
        if (difference.reviewed == null) unexpected += 1;
        try differences.append(allocator, difference);
    }
    const reviewed = differences.items.len - unexpected;
    return .{
        .differences = try differences.toOwnedSlice(allocator),
        .native_entries = native.entries.count(),
        .pending_conffiles = pending,
        .proof_entries = proof.entries.count(),
        .reviewed_differences = reviewed,
        .target = target,
        .unexpected_differences = unexpected,
    };
}

fn execute(init: std.process.Init) !u8 {
    var args = init.minimal.args.iterate();
    _ = args.next();
    var positional: [4][]const u8 = undefined;
    var count: usize = 0;
    var report_only = false;
    while (args.next()) |argument| {
        if (std.mem.eql(u8, argument, "--report-only")) {
            if (report_only) return error.InvalidArguments;
            report_only = true;
        } else {
            if (count == positional.len or std.mem.startsWith(u8, argument, "--")) return error.InvalidArguments;
            positional[count] = argument;
            count += 1;
        }
    }
    if (count != positional.len) return error.InvalidArguments;
    const target = positional[0];
    if (!std.mem.eql(u8, target, "systemd") and !std.mem.eql(u8, target, "udev") and !std.mem.eql(u8, target, "sudo")) return error.InvalidTarget;
    const allocator = init.arena.allocator();
    const cwd = try std.Io.Dir.cwd().realPathFileAlloc(init.io, ".", allocator);
    const native_path = try std.fs.path.resolve(allocator, &.{ cwd, positional[1] });
    const proof_path = try std.fs.path.resolve(allocator, &.{ cwd, positional[2] });
    const report_path = try std.fs.path.resolve(allocator, &.{ cwd, positional[3] });
    var output_root = try fs.openAbsoluteRoot(init.io, std.fs.path.dirname(report_path) orelse return error.InvalidOutputPath);
    defer output_root.close();
    const output_path = try fs.Path.init(std.fs.path.basename(report_path));
    if (try output_root.root.entryIfExists(output_path) != null) return error.PathAlreadyExists;
    var native_root = try fs.openAbsoluteRoot(init.io, native_path);
    defer native_root.close();
    var proof_root = try fs.openAbsoluteRoot(init.io, proof_path);
    defer proof_root.close();
    const native = try Inventory.collect(native_root.root, allocator, 0);
    const proof = try Inventory.collect(proof_root.root, allocator, 0);
    const report = try compare(allocator, target, &native, &proof);
    const bytes = try std.json.Stringify.valueAlloc(allocator, report, .{ .whitespace = .indent_2, .escape_unicode = true });
    const output = try output_root.root.createRegularFile(output_path, .{ .permissions = .fromMode(0o600) });
    defer output.close(init.io);
    try output.writeStreamingAll(init.io, bytes);
    try output.writeStreamingAll(init.io, "\n");
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(init.io, &buffer);
    try stdout.interface.print("{s}: native_entries={d} proof_entries={d} reviewed_differences={d} unexpected_differences={d}\n", .{
        target, report.native_entries, report.proof_entries, report.reviewed_differences, report.unexpected_differences,
    });
    for (report.differences) |difference| if (difference.reviewed) |reason| {
        try stdout.interface.print("reviewed {s}: {s}\n", .{ difference.path, reason });
    };
    var reported: usize = 0;
    for (report.differences) |difference| {
        if (difference.reviewed != null or reported == maximum_reported) continue;
        const line = try std.json.Stringify.valueAlloc(allocator, difference, .{ .escape_unicode = true });
        try stdout.interface.print("{s}\n", .{line});
        reported += 1;
    }
    try stdout.interface.flush();
    if (report.unexpected_differences != 0 and !report_only) {
        std.log.err("{s}: native replay differs from the pinned dpkg proof", .{target});
        return 1;
    }
    return 0;
}

pub fn main(init: std.process.Init) void {
    const code = execute(init) catch |err| {
        std.log.err("signed replay comparison failed: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    std.process.exit(code);
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    entries: Entries = .empty,
    files: std.StringHashMapUnmanaged([]const u8) = .empty,

    fn file(self: *Fixture, path: []const u8, data: []const u8) !void {
        try self.entries.put(self.allocator, path, .{
            .type = "file",
            .uid = 0,
            .gid = 0,
            .mode = "0o644",
            .size = data.len,
            .links = 1,
            .sha256 = try digest(self.allocator, data),
        });
        try self.files.put(self.allocator, path, data);
    }

    fn read(context: *const anyopaque, _: std.mem.Allocator, path: []const u8) ![]const u8 {
        const self: *const Fixture = @ptrCast(@alignCast(context));
        return self.files.get(path) orelse error.FileNotFound;
    }

    fn reader(self: *const Fixture) Reader {
        return .{ .context = self, .function = read };
    }

    fn reason(self: *const Fixture, proof: *const Fixture, target: []const u8, path: []const u8) !?[]const u8 {
        const pending = try pendingConffiles(self.allocator, target, self.files.get("var/lib/dpkg/status") orelse "");
        return classify(self.allocator, target, path, self.entries, proof.entries, self.reader(), proof.reader(), pending);
    }
};

const sudo_conf = "Set disable_coredump false\n";
const before_status =
    "Package: sudo-rs\nStatus: install ok installed\nArchitecture: amd64\nVersion: 0.2.14-1ubuntu2\n\n" ++
    "Package: sudo\nStatus: install ok unpacked\nPriority: optional\nArchitecture: amd64\nVersion: 1.9.17p2-7ubuntu3\n" ++
    "Conffiles:\n /etc/pam.d/sudo 0123456789abcdef0123456789abcdef\n /etc/sudo.conf newconffile\n" ++
    "Description: classic sudo\n continued line\n\n";
const dpkg_log =
    "2026-09-30 18:09:19 startup packages configure\n" ++
    "2026-09-30 18:09:19 configure sudo:amd64 1.9.17p2-7ubuntu3 <none>\n" ++
    "2026-09-30 18:09:19 status unpacked sudo:amd64 1.9.17p2-7ubuntu3\n" ++
    "2026-09-30 18:09:19 status half-configured sudo:amd64 1.9.17p2-7ubuntu3\n" ++
    "2026-09-30 18:09:19 status installed sudo:amd64 1.9.17p2-7ubuntu3\n";

fn replace(allocator: std.mem.Allocator, data: []const u8, old: []const u8, new: []const u8) ![]const u8 {
    return std.mem.replaceOwned(u8, allocator, data, old, new);
}

fn afterStatus(allocator: std.mem.Allocator) ![]const u8 {
    var hash: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(sudo_conf, &hash, .{});
    return replace(allocator, try replace(allocator, before_status, "install ok unpacked", "install ok installed"), "newconffile", try hex(allocator, &hash));
}

test "signed comparison binds harness tools, target scope and all descriptor fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var native: Fixture = .{ .allocator = allocator };
    var proof: Fixture = .{ .allocator = allocator };
    for ([_]struct { path: []const u8, hash: []const u8, target: []const u8 }{
        .{ .path = "usr/bin/setpriv", .hash = setpriv, .target = "sudo" },
        .{ .path = "usr/local/sbin/dpkg", .hash = pinned_dpkg, .target = "udev" },
        .{ .path = "usr/bin/dpkg", .hash = pinned_dpkg, .target = "systemd" },
    }) |case| {
        try proof.file(case.path, "tool");
        proof.entries.getPtr(case.path).?.mode = "0o755";
        try std.testing.expect(try native.reason(&proof, case.target, case.path) == null);
        proof.entries.getPtr(case.path).?.sha256 = case.hash;
        if (std.mem.eql(u8, case.path, "usr/bin/dpkg")) {
            try native.file(case.path, "snapshot");
            native.entries.getPtr(case.path).?.mode = "0o755";
            native.entries.getPtr(case.path).?.sha256 = snapshot_dpkg;
        }
        try std.testing.expect(try native.reason(&proof, case.target, case.path) != null);
        const good = proof.entries.get(case.path).?;
        for (0..4) |mutation| {
            const changed = proof.entries.getPtr(case.path).?;
            changed.* = good;
            switch (mutation) {
                0 => changed.uid = 1,
                1 => changed.links = 2,
                2 => changed.mode = "0o644",
                3 => changed.sha256 = "obsolete reviewed pin",
                else => unreachable,
            }
            try std.testing.expect(try native.reason(&proof, case.target, case.path) == null);
        }
        proof.entries.getPtr(case.path).?.* = good;
        if (!std.mem.eql(u8, case.path, "usr/bin/setpriv"))
            try std.testing.expect(try native.reason(&proof, "sudo", case.path) == null or std.mem.eql(u8, case.path, "usr/local/sbin/dpkg"));
    }
}

test "signed comparison conserves every status field and authenticates only new conffile hashes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var native: Fixture = .{ .allocator = allocator };
    var proof: Fixture = .{ .allocator = allocator };
    const path = "var/lib/dpkg/status";
    const after = try afterStatus(allocator);
    try native.file(path, before_status);
    try proof.file(path, after);
    try proof.file("etc/sudo.conf", sudo_conf);
    try std.testing.expect(try native.reason(&proof, "sudo", path) != null);
    try std.testing.expect(try native.reason(&proof, "udev", path) == null);
    for ([_][]const u8{
        try replace(allocator, after, "0.2.14-1ubuntu2", "0.2.15"),
        try replace(allocator, after, "Priority: optional", "Priority: required"),
        try replace(allocator, after, "Version: 1.9.17p2-7ubuntu3\n", "Version: 1.9.17p2-7ubuntu3\nConfig-Version: 1.0\n"),
        try replace(allocator, after, "Architecture: amd64\nVersion: 0.2.14", "Architecture: arm64\nVersion: 0.2.14"),
        try replace(allocator, after, "Description: classic sudo\n continued line", "Description: changed sudo\n continued line"),
    }) |changed| {
        try proof.file(path, changed);
        try std.testing.expect(try native.reason(&proof, "sudo", path) == null);
    }
    try proof.file(path, after);
    try proof.file("etc/sudo.conf", "changed\n");
    try std.testing.expect(try native.reason(&proof, "sudo", path) == null);
    try proof.file("etc/sudo.conf", sudo_conf);
    try native.file(path, try replace(allocator, before_status, "install ok unpacked", "install ok half-configured"));
    try std.testing.expect(try native.reason(&proof, "sudo", path) != null);
    try native.file(path, before_status);
    try native.file("var/lib/dpkg/status-old", "older");
    try proof.file("var/lib/dpkg/status-old", before_status);
    try std.testing.expect(try native.reason(&proof, "sudo", "var/lib/dpkg/status-old") != null);
    try proof.file("var/lib/dpkg/status-old", after);
    try std.testing.expect(try native.reason(&proof, "sudo", "var/lib/dpkg/status-old") == null);
    try std.testing.expectError(error.DuplicateStatus, stanzas(allocator, before_status ++ before_status));
    try std.testing.expectError(error.MalformedStatus, stanzas(allocator, "not a status\n\n"));
    const unicode = try pendingConffiles(allocator, "sudo", try replace(allocator, before_status, "/etc/sudo.conf newconffile", "/etc/sudo.conf\u{a0}newconffile"));
    try std.testing.expectEqualStrings("etc/sudo.conf", unicode[0]);
}

test "signed comparison retains raw dpkg history, order, exact target version and half-configured semantics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var native: Fixture = .{ .allocator = allocator };
    var proof: Fixture = .{ .allocator = allocator };
    const path = "var/log/dpkg.log";
    const history = "2026-10-09 00:50:32 status installed sudo-rs:amd64 0.2.13-0ubuntu1.2\n";
    try native.file("var/lib/dpkg/status", before_status);
    try proof.file(path, dpkg_log);
    try std.testing.expect(try native.reason(&proof, "sudo", path) != null);
    try std.testing.expect(try native.reason(&proof, "udev", path) == null);
    try native.file(path, history);
    const after = try std.mem.concat(allocator, u8, &.{ history, dpkg_log });
    try proof.file(path, after);
    try std.testing.expect(try native.reason(&proof, "sudo", path) != null);
    for ([_][]const u8{
        dpkg_log,
        try replace(allocator, after, "sudo-rs", "other-rs"),
        try replace(allocator, after, "sudo:amd64", "udev:amd64"),
        try replace(allocator, after, "1.9.17p2-7ubuntu3", "1.0"),
        try std.mem.concat(allocator, u8, &.{ after, history }),
        try std.mem.concat(allocator, u8, &.{ after, dpkg_log }),
        after[0 .. after.len - 1],
        try replace(allocator, after, "configure sudo:", "status sudo:"),
    }) |changed| {
        try proof.file(path, changed);
        try std.testing.expect(try native.reason(&proof, "sudo", path) == null);
    }
    try native.file("var/lib/dpkg/status", try replace(allocator, before_status, "install ok unpacked", "install ok half-configured"));
    const half = try replace(allocator, dpkg_log, "2026-09-30 18:09:19 status unpacked sudo:amd64 1.9.17p2-7ubuntu3\n", "");
    try proof.file(path, try std.mem.concat(allocator, u8, &.{ history, half }));
    try std.testing.expect(try native.reason(&proof, "sudo", path) != null);
    try proof.file(path, after);
    try std.testing.expect(try native.reason(&proof, "sudo", path) == null);
    try native.file("var/lib/dpkg/status", try afterStatus(allocator));
    try std.testing.expect(try native.reason(&proof, "sudo", path) == null);
}

test "signed comparison accepts conffile publication only with identical complete descriptors and absent aliases" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var native: Fixture = .{ .allocator = allocator };
    var proof: Fixture = .{ .allocator = allocator };
    try native.file("var/lib/dpkg/status", before_status);
    try proof.file("var/lib/dpkg/status", try afterStatus(allocator));
    try native.file("etc/sudo.conf.dpkg-new", sudo_conf);
    try proof.file("etc/sudo.conf", sudo_conf);
    for ([_][]const u8{ "etc/sudo.conf", "etc/sudo.conf.dpkg-new" }) |path|
        try std.testing.expect(try native.reason(&proof, "sudo", path) != null);
    try proof.file("etc/sudo.conf", "changed\n");
    try std.testing.expect(try native.reason(&proof, "sudo", "etc/sudo.conf") == null);
    try proof.file("etc/sudo.conf", sudo_conf);
    proof.entries.getPtr("etc/sudo.conf").?.links = 2;
    try std.testing.expect(try native.reason(&proof, "sudo", "etc/sudo.conf") == null);
    try proof.file("etc/sudo.conf", sudo_conf);
    try proof.file("etc/sudo.conf.dpkg-new", sudo_conf);
    try std.testing.expect(try native.reason(&proof, "sudo", "etc/sudo.conf") == null);
    _ = proof.entries.remove("etc/sudo.conf.dpkg-new");
    try native.file("etc/sudo.conf", sudo_conf);
    try std.testing.expect(try native.reason(&proof, "sudo", "etc/sudo.conf.dpkg-new") == null);
}

test "signed comparison normalizes only random systemd machine IDs and exact alternatives timestamp prefixes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var native: Fixture = .{ .allocator = allocator };
    var proof: Fixture = .{ .allocator = allocator };
    const machine = "etc/machine-id";
    try native.file(machine, "0123456789abcdef0123456789abcdef\n");
    try proof.file(machine, "fedcba9876543210fedcba9876543210\n");
    native.entries.getPtr(machine).?.mode = "0o444";
    proof.entries.getPtr(machine).?.mode = "0o444";
    try std.testing.expect(try native.reason(&proof, "systemd", machine) != null);
    try std.testing.expect(try native.reason(&proof, "udev", machine) == null);
    try proof.file(machine, "Fedcba9876543210fedcba9876543210\n");
    proof.entries.getPtr(machine).?.mode = "0o444";
    try std.testing.expect(try native.reason(&proof, "systemd", machine) == null);
    const path = "var/log/alternatives.log";
    const original = "update-alternatives 2026-09-30 18:09:17: run with --install /usr/bin/sudo sudo /usr/bin/sudo.ws 40\n";
    try native.file(path, original);
    try proof.file(path, try replace(allocator, original, "18:09:17", "18:09:58"));
    try std.testing.expect(try native.reason(&proof, "sudo", path) != null);
    try proof.file(path, try replace(allocator, original, "sudo.ws", "sudo.xy"));
    try std.testing.expect(try native.reason(&proof, "sudo", path) == null);
    try proof.file(path, try replace(allocator, original, "2026-09-30", "2026-09-xx"));
    try std.testing.expect(try native.reason(&proof, "sudo", path) == null);
    try proof.file(path, try std.mem.concat(allocator, u8, &.{ original, original }));
    try std.testing.expect(try native.reason(&proof, "sudo", path) == null);
}

test "signed comparison rejects unknown differences and nonempty or nonprivate harness mount directories" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var native: Fixture = .{ .allocator = allocator };
    var proof: Fixture = .{ .allocator = allocator };
    try native.file("etc/shadow", "a");
    try proof.file("etc/shadow", "b");
    try std.testing.expect(try native.reason(&proof, "sudo", "etc/shadow") == null);
    try proof.entries.put(allocator, "run/mount", .{ .type = "directory", .uid = 0, .gid = 0, .mode = "0o700" });
    try std.testing.expect(try native.reason(&proof, "sudo", "run/mount") != null);
    try proof.file("run/mount/utab", "");
    try std.testing.expect(try native.reason(&proof, "sudo", "run/mount") == null);
    _ = proof.entries.remove("run/mount/utab");
    proof.entries.getPtr("run/mount").?.mode = "0o755";
    try std.testing.expect(try native.reason(&proof, "sudo", "run/mount") == null);
    try native.entries.put(allocator, "run/mount", .{ .type = "directory", .uid = 0, .gid = 0, .mode = "0o700" });
    proof.entries.getPtr("run/mount").?.mode = "0o700";
    try std.testing.expect(try native.reason(&proof, "sudo", "run/mount") == null);
}

test "signed comparison inventories actual no-follow files, aliases, hardlinks and FIFOs and refuses changed reads or nonempty proc" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    var root = try fs.openAbsoluteRoot(io, path);
    defer root.close();
    try temporary.dir.writeFile(io, .{ .sub_path = "original", .data = "original" });
    try root.root.createHardLink(try fs.Path.init("original"), try fs.Path.init("hardlink"));
    try root.root.createSymbolicLink(try fs.Path.init("alias"), "/outside-root");
    try root.root.createNamedPipe(try fs.Path.init("pipe"));
    const uid = (try root.root.rootEntry()).uid;
    const inventory = try Inventory.collect(root.root, allocator, uid);
    try std.testing.expectEqual(@as(u32, 4), inventory.entries.count());
    try std.testing.expectEqual(@as(?u64, 2), inventory.entries.get("original").?.links);
    try std.testing.expectEqualStrings("/outside-root", inventory.entries.get("alias").?.target.?);
    try std.testing.expectEqualStrings("fifo", inventory.entries.get("pipe").?.type);
    try std.testing.expectEqualStrings("original", try inventory.reader().read(allocator, "hardlink"));
    try std.testing.expectError(error.NotBoundedComparisonFile, inventory.reader().read(allocator, "alias"));
    try temporary.dir.writeFile(io, .{ .sub_path = "original", .data = "changed!" });
    try std.testing.expectError(error.PathChanged, inventory.reader().read(allocator, "original"));
    try root.root.createDirectory(try fs.Path.init("proc"), .fromMode(0o755));
    try temporary.dir.writeFile(io, .{ .sub_path = "proc/unexpected", .data = "" });
    try std.testing.expectError(error.ComparisonProcMustBeEmpty, Inventory.collect(root.root, allocator, uid));
    try std.testing.expectError(error.ComparisonRootMustBeRootOwned, Inventory.collect(root.root, allocator, uid + 1));
}

test "signed comparison report retains every unexpected entry, canonical nulls and ASCII escaping" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporary.dir.realPathFileAlloc(io, ".", allocator);
    var root = try fs.openAbsoluteRoot(io, path);
    defer root.close();
    try root.root.createDirectoryPath(try fs.Path.init("var/lib/dpkg"), .fromMode(0o755));
    try temporary.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = before_status });
    const uid = (try root.root.rootEntry()).uid;
    const native = try Inventory.collect(root.root, allocator, uid);
    try temporary.dir.writeFile(io, .{ .sub_path = "added", .data = "difference" });
    var proof = try Inventory.collect(root.root, allocator, uid);
    try proof.entries.put(allocator, "run/mount", .{ .type = "directory", .uid = 0, .gid = 0, .mode = "0o700" });
    const report = try compare(allocator, "sudo", &native, &proof);
    try std.testing.expectEqual(@as(usize, 1), report.reviewed_differences);
    try std.testing.expectEqual(@as(usize, 1), report.unexpected_differences);
    try std.testing.expectEqual(@as(usize, 2), report.differences.len);
    try std.testing.expectEqualStrings("added", report.differences[0].path);
    const encoded = try std.json.Stringify.valueAlloc(allocator, report.differences[0], .{});
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"native\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"reviewed\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"error\"") == null);
    const unicode: Difference = .{
        .path = "etc/\u{e9}",
        .native = null,
        .proof = null,
        .reviewed = null,
    };
    try std.testing.expectEqualStrings("{\"native\":null,\"path\":\"etc/\\u00e9\",\"proof\":null,\"reviewed\":null}", try std.json.Stringify.valueAlloc(allocator, unicode, .{ .escape_unicode = true }));
}
