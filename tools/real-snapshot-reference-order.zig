const std = @import("std");
const builtin = @import("builtin");
const paths = @import("real_snapshot_reference_paths.zig");
const linux = std.os.linux;
const A = std.mem.Allocator;
const eq = std.mem.eql;

pub const maximum_packages = 2000;
pub const maximum_probes = 10000;
pub const maximum_probe_output = 65536;
pub const maximum_control_bytes = 1024 * 1024;
pub const maximum_log_bytes = 16 * 1024 * 1024;
pub const maximum_archive_bytes = 512 * 1024 * 1024;
pub const libgcc_triggers = "# Triggers added by dh_makeshlibs/13.31ubuntu1\nactivate-noawait ldconfig\n";
pub const kbd_triggers = "# Triggers added by dh_installinitramfs/13.24.2ubuntu1\nactivate-noawait update-initramfs\n";
const scripts = [_][]const u8{ "preinst", "postinst", "prerm", "postrm", "config" };
const graph_fields = [_][]const u8{ "depends", "pre-depends", "provides", "conflicts", "breaks", "replaces", "multi-arch", "protected", "essential" };

pub const Package = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    digest: []const u8,
    size: usize,
    archive: []const u8,

    pub fn selector(self: Package, a: A) ![]const u8 {
        return if (eq(u8, self.architecture, "all")) self.name else std.fmt.allocPrint(a, "{s}:{s}", .{ self.name, self.architecture });
    }
    fn same(self: Package, other: Package) bool {
        return eq(u8, self.name, other.name) and eq(u8, self.version, other.version) and
            eq(u8, self.architecture, other.architecture) and eq(u8, self.digest, other.digest) and
            self.size == other.size and eq(u8, self.archive, other.archive);
    }
};
pub const Launcher = struct { path: []const u8, runtime: []const u8 };
const Pin = struct { name: []const u8, version: []const u8, architecture: []const u8 = "amd64", size: usize, digest: []const u8, depends: []const u8 = "", pre_depends: []const u8 = "" };
const libc: Pin = .{ .name = "libc6", .version = "2.43-2ubuntu2.4", .size = 2104056, .digest = "e27873bec6e0a7914834eac85748c31a360b44b0f0e971a7cd70439c2f9804e737f8f6113f15bb7f523d7a5d4a336173b43a5e22d804c440c8a11a5530bc6696", .depends = "libgcc-s1, libc-gconv-modules-extra (= 2.43-2ubuntu2.4)" };
pub const base_cycle = [_]Pin{
    libc,
    .{ .name = "libgcc-s1", .version = "16-20260322-1ubuntu1", .size = 80312, .digest = "a34e93f253ca90bd331c5eee563be6ebcc14dbf08147e82b9479f972fe566c83263b644e348757af1853f8663cb8ca2349e2c013e4a0ca0e3ea3d631297576b2", .depends = "gcc-16-base (= 16-20260322-1ubuntu1), libc6 (>= 2.35)" },
    .{ .name = "gcc-16-base", .version = "16-20260322-1ubuntu1", .size = 38296, .digest = "0767f731e71e709736596d52dbe181245a8ca181cdadbac6226aad5aa7151d8ce5149ad28625facc61d8882e76fc387af5336dc289126a0bf830b9e599b3922c" },
    .{ .name = "libc-gconv-modules-extra", .version = "2.43-2ubuntu2.4", .size = 1362202, .digest = "c385f1ca4f8054e59f977a38819e31d6f2429909ce0a88c734c874ce163851dfa7e565dded6c65c3feb3bc8cf074498b45a4c2226bb8e17a2bc8b95027a29692" },
};
pub const openssl_cycle = [_]Pin{
    .{ .name = "libssl3t64", .version = "3.5.5-1ubuntu3.6", .size = 2364586, .digest = "10df2f82619faff2ed4b890812313c35cd58abbfce858caf3403e1b654fac857bd7bc28e7a528a79a18ebfbfbdca5cffb3c2dd5b340c729fb7eb2470b76d528d", .depends = "libc6 (>= 2.38), libzstd1 (>= 1.5.5), zlib1g (>= 1:1.1.4), openssl-provider-legacy" },
    .{ .name = "openssl-provider-legacy", .version = "3.5.5-1ubuntu3.6", .size = 39690, .digest = "cbb4f55a609576d99a1b52952a674e78b2cbb7026e54c765cfd964812b65bdcdea4f5ea67961159b737fcba3093b3b15de8b7a6aff3bbf08a85805a09290c470", .depends = "libc6 (>= 2.14), libssl3t64 (>= 3.0.3)" },
    libc,
    .{ .name = "libzstd1", .version = "1.5.7+dfsg-3", .size = 308174, .digest = "284a44950a9caae10a6b7a06baead5db2d6dd2989fc01107c78c76ef5468cb489fc1a8e92d6cb84d44b5a371f8b1156bd2f5c232e79f1631dcf000a601e52183", .depends = "libc6 (>= 2.34)" },
    .{ .name = "zlib1g", .version = "1:1.3.dfsg+really1.3.1-1ubuntu3.1", .size = 61612, .digest = "a0ad94daadd3099ee40766a62a42d3fa7f431c6d805e9108d1dde07d64bfe3e7da66a41a2294598917e5ef5435df7a239d011711dd6d18037bc9b61b530ed3d4", .depends = "libc6 (>= 2.14)" },
};
pub const kbd_cycle = [_]Pin{
    .{ .name = "kbd", .version = "2.7.1-2ubuntu2", .size = 238014, .digest = "5a1fcb79b59441d380b4f6f38198ab4e7b04e50a759580302643ab1f138d88c900145612dfe0861eab37c5f9ebbb6218bc3a5585366be04d4cd00f85efa16050", .depends = "libc6 (>= 2.38), console-setup | console-setup-mini" },
    .{ .name = "console-setup-linux", .version = "1.237ubuntu3.1", .architecture = "all", .size = 6206020, .digest = "511e2f220d1f2afb6c0ae80d9488b6863b884f2db26e54d9cd343ca212c8061e6fbf637131fbd6f93673f3f9d47fe22515b22eca96a1cdf65e9e768fd2bbbb5b", .depends = "kbd (>= 0.99-12) | console-tools (>= 1:0.2.3-16), keyboard-configuration (= 1.237ubuntu3.1), init-system-helpers (>= 1.29~) | initscripts" },
    .{ .name = "console-setup", .version = "1.237ubuntu3.1", .architecture = "all", .size = 102654, .digest = "776ebf749c2a621ff9835b86b69efe1c838e948ac8265fab0f2c5eb91875ae67f1313800854b3a8a962359dfa40bee3e59cc5cf956a215ed82e15529bf622832", .depends = "console-setup-linux | hurd, xkb-data (>= 0.9), keyboard-configuration (= 1.237ubuntu3.1), debconf (>= 0.5) | debconf-2.0", .pre_depends = "debconf | debconf-2.0" },
    libc,
};

fn nameValid(value: []const u8) bool {
    if (value.len == 0 or (!std.ascii.isLower(value[0]) and !std.ascii.isDigit(value[0]))) return false;
    for (value) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '+' and byte != '.' and byte != '-') return false;
    return true;
}
fn digestValid(value: []const u8) bool {
    if (value.len != 128) return false;
    for (value) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return false;
    return true;
}
fn hash(comptime H: type, bytes: []const u8) [H.digest_length * 2]u8 {
    var result: [H.digest_length]u8 = undefined;
    H.hash(bytes, &result, .{});
    return std.fmt.bytesToHex(result, .lower);
}
fn join(a: A, root: []const u8, path: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "{s}{s}{s}", .{ root, if (eq(u8, root, "/")) "" else "/", path });
}
const Lines = struct {
    bytes: []const u8,
    index: usize = 0,
    fn next(self: *Lines) ?[]const u8 {
        if (self.index == self.bytes.len) return null;
        const start = self.index;
        while (self.index < self.bytes.len) {
            const at = self.index;
            const byte = self.bytes[at];
            const separator: usize = switch (byte) {
                '\n', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e' => 1,
                '\r' => if (at + 1 < self.bytes.len and self.bytes[at + 1] == '\n') 2 else 1,
                0xc2 => if (std.mem.startsWith(u8, self.bytes[at..], "\xc2\x85")) 2 else 0,
                0xe2 => if (std.mem.startsWith(u8, self.bytes[at..], "\xe2\x80\xa8") or std.mem.startsWith(u8, self.bytes[at..], "\xe2\x80\xa9")) 3 else 0,
                else => 0,
            };
            if (separator != 0) {
                self.index += separator;
                return self.bytes[start..at];
            }
            self.index += 1;
        }
        return self.bytes[start..];
    }
};
fn pythonSpace(codepoint: u21) bool {
    return switch (codepoint) {
        9...13, 28...32, 0x85, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
        else => false,
    };
}
fn strip(data: []const u8) []const u8 {
    var first: usize = data.len;
    var last: usize = 0;
    var index: usize = 0;
    while (index < data.len) {
        const length = std.unicode.utf8ByteSequenceLength(data[index]) catch unreachable;
        const codepoint = std.unicode.utf8Decode(data[index..][0..length]) catch unreachable;
        if (!pythonSpace(codepoint)) {
            first = @min(first, index);
            last = index + length;
        }
        index += length;
    }
    return if (last == 0) data[0..0] else data[first..last];
}

pub fn packagesFromManifest(a: A, bytes: []const u8, cache: []const u8) ![]Package {
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidReferenceArchiveManifest;
    var result: std.ArrayList(Package) = .empty;
    var lines: Lines = .{ .bytes = bytes };
    while (lines.next()) |line| {
        var columns = std.mem.splitScalar(u8, line, '\t');
        var fields: [5][]const u8 = undefined;
        for (&fields) |*column| column.* = columns.next() orelse return error.InvalidReferenceArchiveManifest;
        if (columns.next() != null) return error.InvalidReferenceArchiveManifest;
        if (!nameValid(fields[0]) or fields[1].len == 0 or !nameValid(fields[2]) or !digestValid(fields[3]) or fields[4].len == 0)
            return error.InvalidReferencePackageIdentity;
        for (fields[4]) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidReferencePackageIdentity;
        const size = std.fmt.parseInt(usize, fields[4], 10) catch return error.InvalidReferenceArchiveSize;
        if (size == 0 or size > maximum_archive_bytes) return error.InvalidReferenceArchiveSize;
        for (result.items) |package| if (eq(u8, package.name, fields[0]) and eq(u8, package.architecture, fields[2]))
            return error.DuplicateReferencePackage;
        if (result.items.len == maximum_packages) return error.ReferenceClosureExceedsPackageLimit;
        try result.append(a, .{ .name = fields[0], .version = fields[1], .architecture = fields[2], .digest = fields[3], .size = size, .archive = try std.fmt.allocPrint(a, "{s}/packages-v2/objects/sha512-{s}", .{ cache, fields[3] }) });
    }
    if (result.items.len == 0) return error.EmptyReferenceClosure;
    return result.toOwnedSlice(a);
}

pub fn verifyArchive(package: Package) !void {
    const pin = try paths.openProtected(package.archive, false);
    defer pin.close();
    return verifyPinnedArchive(package, pin);
}
pub fn verifyPinnedArchive(package: Package, pin: paths.Pinned) !void {
    if (pin.metadata.size != package.size) return error.ReferenceArchiveSizeChanged;
    const opened = try paths.openAbsolute(package.archive, false);
    defer opened.close();
    if (!paths.same(opened.metadata, pin.metadata)) return error.ReferenceArchiveIdentityChanged;
    var digest = std.crypto.hash.sha2.Sha512.init(.{});
    var buffer: [1024 * 1024]u8 = undefined;
    var offset: usize = 0;
    while (true) {
        const count = try paths.syscall(linux.pread(opened.fd, &buffer, buffer.len, @intCast(offset)));
        if (count == 0) break;
        offset += count;
        if (offset > package.size) return error.ReferenceArchiveChanged;
        digest.update(buffer[0..count]);
    }
    if (offset != package.size or !paths.same(pin.metadata, try paths.stat(opened.fd))) return error.ReferenceArchiveChanged;
    var actual: [64]u8 = undefined;
    digest.final(&actual);
    if (!eq(u8, &std.fmt.bytesToHex(actual, .lower), package.digest)) return error.ReferenceArchiveDigestChanged;
}

pub const script_profiles = [_][2][]const u8{
    .{ "systemd", "259.5-0ubuntu3.4" },
    .{ "udev", "259.5-0ubuntu3.4" },
    .{ "sudo", "1.9.17p2-1ubuntu3.1" },
};
fn profileVersion(profile: []const u8) ?[]const u8 {
    for (script_profiles) |entry| if (eq(u8, profile, entry[0])) return entry[1];
    return null;
}
pub const Cycle = enum {
    base,
    openssl,
    kbd,
    fn pins(self: Cycle) []const Pin {
        return switch (self) {
            .base => &base_cycle,
            .openssl => &openssl_cycle,
            .kbd => &kbd_cycle,
        };
    }
    fn profile(self: Cycle) []const u8 {
        return switch (self) {
            .base => "libgcc_cycle",
            .openssl => "openssl_cycle",
            .kbd => "kbd_cycle",
        };
    }
    fn verb(self: Cycle) []const u8 {
        return switch (self) {
            .base => "break_base_cycle",
            .openssl => "configure_openssl_cycle",
            .kbd => "break_kbd_cycle",
        };
    }
    fn stem(self: Cycle) []const u8 {
        return switch (self) {
            .base => "base-cycle",
            .openssl => "openssl-cycle",
            .kbd => "kbd-cycle",
        };
    }
    fn selected(self: Cycle) usize {
        return if (self == .base) 1 else 0;
    }
    fn transitions(self: Cycle) usize {
        return if (self == .openssl) 2 else 1;
    }
};
fn matchesPin(package: Package, pin: Pin) bool {
    return eq(u8, package.name, pin.name) and eq(u8, package.version, pin.version) and
        eq(u8, package.architecture, pin.architecture) and eq(u8, package.digest, pin.digest) and package.size == pin.size;
}
pub fn cyclePackages(a: A, packages: []const Package, architecture: []const u8, kind: Cycle) ![]Package {
    if (!eq(u8, architecture, "amd64")) return error.UnknownCycle;
    const cycle = try a.alloc(Package, kind.pins().len);
    for (kind.pins(), cycle) |binding, *selected| {
        var count: usize = 0;
        for (packages) |package| if (eq(u8, package.name, binding.name)) {
            count += 1;
            if (!matchesPin(package, binding)) return error.CycleIdentityChanged;
            selected.* = package;
        };
        if (count != 1) return error.CycleIdentityChanged;
    }
    return cycle;
}
pub fn dpkgCommand(a: A, launcher: Launcher, dpkg: []const u8, root: []const u8, architecture: []const u8, profile: []const u8, verb: []const u8, package: ?Package, cycle: []const Package) ![][]const u8 {
    if (eq(u8, verb, "trigger_libc_bin")) {
        if (!eq(u8, architecture, libc_bin_trigger.architecture) or !eq(u8, profile, "none") or cycle.len != 0 or
            package == null or !matchesPin(package.?, libc_bin_trigger)) return error.UnreviewedTriggerHandler;
        return a.dupe([]const u8, &.{ launcher.path, root, dpkg, architecture, profile, verb, try package.?.selector(a), launcher.runtime });
    }
    var special: ?Cycle = null;
    inline for (.{ Cycle.base, Cycle.openssl, Cycle.kbd }) |kind| {
        if (eq(u8, verb, kind.verb())) special = kind;
    }
    if (special) |kind| {
        if (!eq(u8, architecture, "amd64") or !eq(u8, profile, kind.profile()) or cycle.len != kind.pins().len or
            package == null or !package.?.same(cycle[kind.selected()])) return error.CycleIdentityChanged;
        for (cycle, kind.pins()) |p, binding| if (!matchesPin(p, binding)) return error.CycleIdentityChanged;
    } else {
        if (cycle.len != 0) return error.CycleIdentityChanged;
        if (!eq(u8, verb, "probe_unpack") and !eq(u8, verb, "unpack") and !eq(u8, verb, "probe_configure") and
            !eq(u8, verb, "configure") and !eq(u8, verb, "continue_prestate")) return error.NoSingleScriptBinding;
        if (package == null) return error.SignedPackageRequired;
        if (eq(u8, verb, "continue_prestate") and !eq(u8, profile, "systemd") and !eq(u8, profile, "udev"))
            return error.UnauthorizedHalfConfiguredContinuation;
        if (!eq(u8, profile, "none")) {
            if ((!eq(u8, verb, "configure") and !eq(u8, verb, "continue_prestate")) or !eq(u8, architecture, "amd64") or
                profileVersion(profile) == null or !eq(u8, package.?.name, profile) or !eq(u8, package.?.architecture, architecture) or
                !eq(u8, package.?.version, profileVersion(profile).?)) return error.UnauthorizedReferenceScriptProfile;
        } else if (eq(u8, verb, "configure") and profileVersion(package.?.name) != null) return error.MissingExactConfigureProfile;
    }
    var command: std.ArrayList([]const u8) = .empty;
    try command.appendSlice(a, &.{ launcher.path, root, dpkg, architecture, profile, verb, try package.?.selector(a), launcher.runtime });
    if (special != null) {
        for (cycle) |p| try command.append(a, p.archive);
    } else if (eq(u8, verb, "unpack") or eq(u8, verb, "probe_unpack")) {
        try command.appendSlice(a, &.{ package.?.archive, package.?.digest, try std.fmt.allocPrint(a, "{d}", .{package.?.size}) });
    }
    return command.toOwnedSlice(a);
}

pub const Fields = std.json.ObjectMap;
pub fn controlFields(a: A, data: []const u8) ![]Fields {
    if (!std.unicode.utf8ValidateSlice(data)) return error.InvalidReferenceControlEncoding;
    var records: std.ArrayList(Fields) = .empty;
    var stanzas = std.mem.splitSequence(u8, strip(data), "\n\n");
    while (stanzas.next()) |stanza| {
        if (stanza.len == 0) continue;
        var fields: Fields = .empty;
        var previous: ?[]const u8 = null;
        var lines: Lines = .{ .bytes = stanza };
        while (lines.next()) |line| {
            if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
                const key = previous orelse return error.InvalidReferenceIdentityContinuation;
                for ([_][]const u8{ "package", "architecture", "version", "status" }) |identity|
                    if (eq(u8, key, identity)) return error.InvalidReferenceIdentityContinuation;
                const value = try std.fmt.allocPrint(a, "{s}\n{s}", .{ fields.get(key).?.string, line });
                try fields.put(a, key, .{ .string = value });
                continue;
            }
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedReferenceDatabaseField;
            const key = line[0..colon];
            if (key.len == 0 or !std.ascii.isAlphabetic(key[0])) return error.MalformedReferenceDatabaseField;
            for (key) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-') return error.MalformedReferenceDatabaseField;
            const raw_value = line[colon + 1 ..];
            if (raw_value.len > 0 and raw_value[0] != ' ') return error.MalformedReferenceDatabaseField;
            const lower = try a.dupe(u8, key);
            for (lower) |*byte| byte.* = std.ascii.toLower(byte.*);
            if (fields.contains(lower)) return error.DuplicateReferenceDatabaseField;
            try fields.put(a, lower, .{ .string = if (raw_value.len > 0) raw_value[1..] else "" });
            previous = lower;
        }
        try records.append(a, fields);
    }
    return records.toOwnedSlice(a);
}
pub fn field(record: Fields, key: []const u8) []const u8 {
    return if (record.get(key)) |value| value.string else "";
}
pub fn parseDatabase(a: A, data: []const u8) ![]Fields {
    const records = try controlFields(a, data);
    for (records, 0..) |record, index| {
        if (!nameValid(field(record, "package")) or !nameValid(field(record, "architecture")) or
            field(record, "version").len == 0 or !record.contains("status")) return error.InvalidReferenceDatabasePackage;
        for (records[0..index]) |previous| if (eq(u8, field(previous, "package"), field(record, "package")) and
            eq(u8, field(previous, "architecture"), field(record, "architecture"))) return error.DuplicateReferenceDatabasePackage;
    }
    return records;
}
fn findRecord(records: []Fields, package: Package) ?Fields {
    for (records) |record| if (eq(u8, field(record, "package"), package.name) and eq(u8, field(record, "architecture"), package.architecture)) return record;
    return null;
}
fn statusIs(records: []Fields, package: Package, status: []const u8) bool {
    const record = findRecord(records, package) orelse return false;
    return eq(u8, field(record, "version"), package.version) and eq(u8, field(record, "status"), status);
}
fn objectsEqual(a: Fields, b: Fields) bool {
    if (a.count() != b.count()) return false;
    for (a.keys(), a.values()) |key, value| {
        const other = b.get(key) orelse return false;
        if (value == .string and other == .string) {
            if (!eq(u8, value.string, other.string)) return false;
        } else if (value == .integer and other == .integer) {
            if (value.integer != other.integer) return false;
        } else if (value == .object and other == .object) {
            if (!objectsEqual(value.object, other.object)) return false;
        } else return false;
    }
    return true;
}
pub fn conserved(before: []Fields, after: []Fields, selected: []const Package) bool {
    if (before.len != after.len) return false;
    for (before) |record| {
        const package: Package = .{ .name = field(record, "package"), .architecture = field(record, "architecture"), .version = field(record, "version"), .digest = "", .size = 0, .archive = "" };
        const actual = findRecord(after, package) orelse return false;
        var changes = false;
        for (selected) |p| if (eq(u8, p.name, package.name) and eq(u8, p.architecture, package.architecture)) {
            changes = true;
        };
        if (record.count() != actual.count()) return false;
        for (record.keys(), record.values()) |key, value| {
            const expected = if (changes and eq(u8, key, "status")) "install ok installed" else value.string;
            if (!actual.contains(key) or !eq(u8, field(actual, key), expected)) return false;
        }
    }
    return true;
}

pub const Member = struct { name: []const u8, bytes: []const u8, kind: u8 };
pub fn tarMembers(a: A, data: []const u8) ![]Member {
    if (data.len > maximum_control_bytes) return error.CycleControlChanged;
    var members: std.ArrayList(Member) = .empty;
    var reader: std.Io.Reader = .fixed(data);
    var name_buffer: [4096]u8 = undefined;
    var link_buffer: [4096]u8 = undefined;
    var iterator: std.tar.Iterator = .init(&reader, .{ .file_name_buffer = &name_buffer, .link_name_buffer = &link_buffer });
    while (iterator.next() catch return error.CycleControlChanged) |entry| {
        var name: []const u8 = try a.dupe(u8, entry.name);
        if (eq(u8, name, "./")) name = ".";
        if (members.items.len >= 128) return error.CycleControlChanged;
        if (entry.size > maximum_control_bytes) return error.CycleControlChanged;
        const bytes = try a.alloc(u8, @intCast(entry.size));
        reader.readSliceAll(bytes) catch return error.CycleControlChanged;
        iterator.unread_file_bytes = 0;
        try members.append(a, .{ .name = name, .bytes = bytes, .kind = switch (entry.kind) {
            .file => '0',
            .directory => '5',
            .sym_link => '2',
        } });
    }
    return members.toOwnedSlice(a);
}
fn member(members: []const Member, name: []const u8) ![]const u8 {
    var found: ?[]const u8 = null;
    for (members) |entry| if (eq(u8, entry.name, name)) {
        found = entry.bytes;
    };
    return found orelse error.CycleControlChanged;
}
fn memberSet(members: []const Member, expected: []const []const u8) bool {
    for (members) |entry| {
        var included = false;
        for (expected) |name| if (eq(u8, entry.name, name)) {
            included = true;
        };
        if (!included) return false;
    }
    for (expected) |name| {
        var included = false;
        for (members) |entry| if (eq(u8, entry.name, name)) {
            included = true;
        };
        if (!included) return false;
    }
    return true;
}

pub const Prestate = struct { selector: []const u8, status: []const u8, destination: []const u8 };
pub fn parsePrestate(value: []const u8) !Prestate {
    const equal = std.mem.indexOfScalar(u8, value, '=') orelse return error.InvalidPrestate;
    const selector = value[0..equal];
    const colon = std.mem.indexOfScalar(u8, selector, ':') orelse return error.InvalidPrestate;
    if (!nameValid(selector[0..colon]) or !nameValid(selector[colon + 1 ..])) return error.InvalidPrestate;
    for (selector[colon + 1 ..]) |byte| if (byte == '+' or byte == '.') return error.InvalidPrestate;
    const tail = value[equal + 1 ..];
    const delimiter = std.mem.indexOfScalar(u8, tail, ':') orelse return error.InvalidPrestate;
    const status = tail[0..delimiter];
    const destination = tail[delimiter + 1 ..];
    if ((!eq(u8, status, "unpacked") and !eq(u8, status, "half-configured")) or destination.len < 2 or destination[0] != '/')
        return error.InvalidPrestate;
    return .{ .selector = selector, .status = status, .destination = destination };
}

pub const Result = struct { code: i32, stdout: []const u8, stderr: []const u8, stdout_bytes: usize = 0, stderr_bytes: usize = 0 };
const Refusal = struct { selector: []const u8, operation: []const u8, exit_status: i32, output_bytes: usize, output_prefix_hex: []const u8, output_sha512: []const u8 };
const TestHooks = if (builtin.is_test) struct {
    state: *anyopaque,
    manifest: ?*const fn (*anyopaque) anyerror![]Package = null,
    database: ?*const fn (*anyopaque, []const u8) anyerror![]Fields = null,
    probe: ?*const fn (*anyopaque, []const []const u8) anyerror!Result = null,
    apply: ?*const fn (*anyopaque, []const []const u8) anyerror!void = null,
    archive: ?*const fn (*anyopaque, Package) anyerror!void = null,
    control: ?*const fn (*anyopaque, Package) anyerror![]Member = null,
    transition: ?*const fn (*anyopaque, Cycle) anyerror![]Package = null,
    capture: ?*const fn (*anyopaque, Package, Prestate) anyerror!void = null,
    run: ?*const fn (*anyopaque, []const []const u8) anyerror!?Result = null,
    runtime_unprotected: bool = false,
    runtime_digest: ?*const fn ([]const u8) ?[64]u8 = null,
    assume_x86_64: bool = false,
    // #265: synthetic pins and the signed-control/refusal observers of the single trigger handler.
    trigger_database: ?[]const TriggerPin = null,
    trigger_controls: ?[2]ControlPin = null,
    trigger_signed: ?*const fn (*anyopaque, Package) anyerror![2][]const u8 = null,
    trigger_refusal: ?*const fn (*anyopaque, []const u8) anyerror!void = null,
} else void;
pub const Context = struct {
    a: A,
    io: std.Io,
    environment: *const std.process.Environ.Map,
    launcher: Launcher,
    dpkg: []const u8,
    root: []const u8,
    cache: []const u8,
    evidence: []const u8,
    architecture: []const u8,
    trigger_authority: ?[]const u8 = null,
    test_hooks: if (builtin.is_test) ?TestHooks else void = if (builtin.is_test) null else {},

    pub fn read(self: Context, root: []const u8, relative: []const u8, limit: usize) ![]u8 {
        return paths.readRootFile(self.a, root, relative, limit);
    }
    pub fn database(self: Context, root: []const u8) ![]Fields {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.database) |callback| return callback(hooks.state, root);
        return parseDatabase(self.a, try self.read(root, "var/lib/dpkg/status", 4 * 1024 * 1024));
    }
    fn manifest(self: Context) ![]Package {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.manifest) |callback| return callback(hooks.state);
        return packagesFromManifest(self.a, try self.read(self.evidence, "reference-archives.tsv", std.math.maxInt(usize)), self.cache);
    }
    fn archive(self: Context, package: Package) !void {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.archive) |callback| return callback(hooks.state, package);
        return verifyArchive(package);
    }
    pub fn write(self: Context, root: []const u8, relative: []const u8, bytes: []const u8, append: bool) !void {
        _ = self;
        const fd = try paths.create(root, relative, 0o600, append);
        defer _ = linux.close(fd);
        try paths.writeAll(fd, bytes);
    }
    pub fn json(self: Context, root: []const u8, relative: []const u8, value: anytype) !void {
        var output: std.Io.Writer.Allocating = .init(self.a);
        var serializer: std.json.Stringify = .{ .writer = &output.writer, .options = .{ .whitespace = .indent_2 } };
        try jsonWrite(&serializer, value);
        try output.writer.writeByte('\n');
        try self.replace(root, relative, output.written());
    }
    pub fn replace(self: Context, root: []const u8, relative: []const u8, bytes: []const u8) !void {
        _ = self;
        const fd = try paths.create(root, relative, 0o600, true);
        defer _ = linux.close(fd);
        _ = try paths.syscall(linux.ftruncate(fd, 0));
        try paths.writeAll(fd, bytes);
    }
    pub fn argvFor(self: Context, root: []const u8, profile: []const u8, verb: []const u8, package: Package, cycle: []const Package) ![][]const u8 {
        return dpkgCommand(self.a, self.launcher, self.dpkg, root, self.architecture, profile, verb, package, cycle);
    }
    pub fn run(self: Context, argv: []const []const u8, seconds: i64, maximum: usize) !Result {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.run) |callback| if (try callback(hooks.state, argv)) |result| return result;
        const result = try std.process.run(self.a, self.io, .{ .argv = argv, .environ_map = self.environment, .stdout_limit = .limited(maximum), .stderr_limit = .limited(maximum), .timeout = .{ .duration = .{ .raw = .fromSeconds(seconds), .clock = .awake } } });
        return .{ .code = switch (result.term) {
            .exited => |code| code,
            .signal => |signal| -@as(i32, @intCast(@intFromEnum(signal))),
            else => -1,
        }, .stdout = result.stdout, .stderr = result.stderr, .stdout_bytes = result.stdout.len, .stderr_bytes = result.stderr.len };
    }
    pub fn checked(self: Context, argv: []const []const u8, seconds: i64) !void {
        const result = try self.run(argv, seconds, maximum_probe_output);
        if (result.code != 0) {
            try paths.writeAll(2, result.stderr);
            return error.ReferenceCommandFailed;
        }
    }
    pub fn runFiles(self: Context, command: []const []const u8, stdout_fd: i32, stderr_fd: i32, seconds: i64) !i32 {
        const input_null = try paths.openAbsolute("/dev/null", false);
        defer input_null.close();
        var child = try std.process.spawn(self.io, .{
            .argv = command,
            .environ_map = self.environment,
            .stdin = .{ .file = .{ .handle = input_null.fd, .flags = .{ .nonblocking = false } } },
            .stdout = .{ .file = .{ .handle = stdout_fd, .flags = .{ .nonblocking = false } } },
            .stderr = .{ .file = .{ .handle = stderr_fd, .flags = .{ .nonblocking = false } } },
        });
        defer child.kill(self.io);
        var start: linux.timespec = undefined;
        _ = try paths.syscall(linux.clock_gettime(linux.CLOCK.MONOTONIC, &start));
        while (true) {
            var status: u32 = undefined;
            const result = linux.wait4(child.id.?, &status, linux.W.NOHANG, null);
            if (linux.errno(result) == .INTR) continue;
            const pid = try paths.syscall(result);
            if (pid != 0) {
                child.id = null;
                if (linux.W.IFEXITED(status)) return linux.W.EXITSTATUS(status);
                if (linux.W.IFSIGNALED(status)) return -@as(i32, @intCast(@intFromEnum(linux.W.TERMSIG(status))));
                return -1;
            }
            var now: linux.timespec = undefined;
            _ = try paths.syscall(linux.clock_gettime(linux.CLOCK.MONOTONIC, &now));
            if (now.sec > start.sec + seconds or (now.sec == start.sec + seconds and now.nsec >= start.nsec))
                return error.ReferenceCommandTimedOut;
            try self.io.sleep(.fromMilliseconds(5), .awake);
        }
    }
    fn scratch(self: Context, evidence: []const u8, prefix: []const u8) ![]const u8 {
        var random: [16]u8 = undefined;
        self.io.random(&random);
        const name = try std.fmt.allocPrint(self.a, "{s}-{s}", .{ prefix, std.fmt.bytesToHex(random, .lower) });
        const pin = try paths.openAbsolute(evidence, true);
        defer pin.close();
        const z = try self.a.dupeZ(u8, name);
        _ = try paths.syscall(linux.mkdirat(pin.fd, z, 0o700));
        return join(self.a, evidence, name);
    }
    fn cleanupScratch(self: Context, directory: []const u8, names: []const []const u8) void {
        const pin = paths.openAbsolute(directory, true) catch return;
        defer pin.close();
        for (names) |name| {
            const z = self.a.dupeZ(u8, name) catch return;
            _ = linux.unlinkat(pin.fd, z, 0);
        }
        const z = self.a.dupeZ(u8, directory) catch return;
        _ = linux.rmdir(z);
    }
    pub fn probe(self: Context, command: []const []const u8, evidence: []const u8) !Result {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.probe) |callback| return callback(hooks.state, command);
        const scratch_dir = try self.scratch(evidence, "reference-probe");
        defer self.cleanupScratch(scratch_dir, &.{"output"});
        const output = try paths.create(scratch_dir, "output", 0o600, false);
        _ = linux.close(output);
        const reader = try paths.openAbsolute(try join(self.a, scratch_dir, "output"), false);
        defer reader.close();
        const writer = try paths.create(scratch_dir, "output", 0o600, true);
        defer _ = linux.close(writer);
        const code = try self.runFiles(command, writer, writer, 60);
        const current = try paths.stat(reader.fd);
        if (current.size > maximum_probe_output) return error.ReferenceProbeOutputExceedsLimit;
        const bytes = try paths.readPinned(self.a, .{ .fd = reader.fd, .metadata = current }, maximum_probe_output);
        return .{ .code = code, .stdout = bytes, .stderr = "", .stdout_bytes = bytes.len };
    }
    pub fn apply(self: Context, command: []const []const u8, evidence: []const u8, out: []const u8, err: []const u8) !void {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.apply) |callback| return callback(hooks.state, command);
        const output = try paths.create(evidence, out, 0o600, true);
        defer _ = linux.close(output);
        const errors = try paths.create(evidence, err, 0o600, true);
        defer _ = linux.close(errors);
        const code = try self.runFiles(command, output, errors, 120);
        if (code != 0) return error.ReferenceDpkgOperationFailed;
        if ((try paths.stat(output)).size > maximum_log_bytes or (try paths.stat(errors)).size > maximum_log_bytes)
            return error.ReferenceDpkgOutputExceedsLimit;
    }
    fn capture(self: Context, command: []const []const u8, directory: []const u8, out: []const u8, err: []const u8, seconds: i64) !Result {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.run) |callback| if (try callback(hooks.state, command)) |result|
            return .{ .code = result.code, .stdout = result.stdout[0..@min(result.stdout.len, maximum_probe_output)], .stderr = result.stderr[0..@min(result.stderr.len, maximum_probe_output)], .stdout_bytes = result.stdout.len, .stderr_bytes = result.stderr.len };
        const output = try paths.create(directory, out, 0o600, false);
        _ = linux.close(output);
        const errors = try paths.create(directory, err, 0o600, false);
        _ = linux.close(errors);
        const out_writer = try paths.create(directory, out, 0o600, true);
        defer _ = linux.close(out_writer);
        const err_writer = try paths.create(directory, err, 0o600, true);
        defer _ = linux.close(err_writer);
        const code = try self.runFiles(command, out_writer, err_writer, seconds);
        const out_pin = try paths.openAbsolute(try join(self.a, directory, out), false);
        defer out_pin.close();
        const err_pin = try paths.openAbsolute(try join(self.a, directory, err), false);
        defer err_pin.close();
        const out_size: usize = @intCast(out_pin.metadata.size);
        const err_size: usize = @intCast(err_pin.metadata.size);
        const stdout = try self.a.alloc(u8, @min(out_size, maximum_probe_output));
        const stderr = try self.a.alloc(u8, @min(err_size, maximum_probe_output));
        const out_file: std.Io.File = .{ .handle = out_pin.fd, .flags = .{ .nonblocking = false } };
        const err_file: std.Io.File = .{ .handle = err_pin.fd, .flags = .{ .nonblocking = false } };
        if (try out_file.readPositionalAll(self.io, stdout, 0) != stdout.len or
            try err_file.readPositionalAll(self.io, stderr, 0) != stderr.len) return error.ReferenceFileChanged;
        return .{ .code = code, .stdout = stdout, .stderr = stderr, .stdout_bytes = out_size, .stderr_bytes = err_size };
    }
    pub fn triggerDatabase(self: Context, root: []const u8) !Fields {
        const updates = try paths.openAbsolute(try join(self.a, root, "var/lib/dpkg/updates"), true);
        defer updates.close();
        if ((try paths.names(self.a, self.io, updates, maximum_packages)).len != 0) return error.CycleStateChanged;
        const directory = try paths.openAbsolute(try join(self.a, root, "var/lib/dpkg/triggers"), true);
        defer directory.close();
        var result: Fields = .empty;
        for (try paths.names(self.a, self.io, directory, maximum_packages)) |name| {
            const data = try self.read(root, try std.fmt.allocPrint(self.a, "var/lib/dpkg/triggers/{s}", .{name}), maximum_control_bytes);
            if (eq(u8, name, "Unincorp") and data.len != 0) return error.CycleCallbackChanged;
            var binding: Fields = .empty;
            try binding.put(self.a, "size", .{ .integer = @intCast(data.len) });
            try binding.put(self.a, "sha512", .{ .string = try self.a.dupe(u8, &hash(std.crypto.hash.sha2.Sha512, data)) });
            try result.put(self.a, name, .{ .object = binding });
        }
        return result;
    }
    fn control(self: Context, package: Package) ![]Member {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.control) |callback| return callback(hooks.state, package);
        const result = try self.run(&.{ "dpkg-deb", "--ctrl-tarfile", package.archive }, 30, maximum_control_bytes);
        if (result.code != 0 or result.stderr.len != 0) return error.CycleControlChanged;
        return tarMembers(self.a, result.stdout);
    }
    pub fn verifyCycle(self: Context, root: []const u8, cycle: []const Package, kind: Cycle) !struct { graph: Fields, records: []Fields, trigger_database: Fields } {
        const records = try self.database(root);
        const triggers_before = try self.triggerDatabase(root);
        var graph: Fields = .empty;
        for (cycle, kind.pins(), 0..) |package, binding, index| {
            self.archive(package) catch return error.CycleIdentityChanged;
            const members = try self.control(package);
            const controls = try controlFields(self.a, try member(members, "./control"));
            if (controls.len != 1 or (try member(members, "./control")).len > maximum_probe_output) return error.CycleControlChanged;
            const fields = controls[0];
            const scriptless = if (kind == .base) index == 1 else if (kind == .openssl) index < 2 else index == 0;
            if (scriptless) {
                const expected: []const []const u8 = if (kind == .kbd) &.{ ".", "./control", "./md5sums", "./triggers" } else if (kind == .openssl and index == 1)
                    &.{ ".", "./control", "./md5sums" }
                else
                    &.{ ".", "./control", "./md5sums", "./shlibs", "./symbols", "./triggers" };
                if (!memberSet(members, expected)) return error.CycleCallbackChanged;
                if (!(kind == .openssl and index == 1) and !eq(u8, try member(members, "./triggers"), if (kind == .kbd) kbd_triggers else libgcc_triggers))
                    return error.CycleCallbackChanged;
            }
            if (!eq(u8, field(fields, "package"), package.name) or !eq(u8, field(fields, "version"), package.version) or
                !eq(u8, field(fields, "architecture"), package.architecture) or !eq(u8, field(fields, "depends"), binding.depends) or
                !eq(u8, field(fields, "pre-depends"), binding.pre_depends)) return error.CycleControlChanged;
            const installed = findRecord(records, package) orelse return error.CycleStateChanged;
            if (!eq(u8, field(installed, "version"), package.version)) return error.CycleStateChanged;
            const in_cycle = index < (if (kind == .kbd) @as(usize, 3) else 2);
            const expected = if (in_cycle) "install ok unpacked" else "install ok installed";
            if (!eq(u8, field(installed, "status"), expected)) return if (!in_cycle and kind != .kbd) error.CycleOutsideDependency else error.CycleStateChanged;
            for (graph_fields) |key| if (!eq(u8, field(installed, key), field(fields, key))) return error.CycleControlChanged;
            for ([_][]const u8{ "triggers-pending", "triggers-awaited", "config-version" }) |key| if (field(installed, key).len != 0) return error.CycleCallbackChanged;
            var item: Fields = .empty;
            try item.put(self.a, "version", .{ .string = package.version });
            try item.put(self.a, "archive_sha512", .{ .string = package.digest });
            try item.put(self.a, "depends", .{ .string = binding.depends });
            try item.put(self.a, "status", .{ .string = expected });
            if (kind == .kbd) try item.put(self.a, "architecture", .{ .string = package.architecture }) else try item.put(self.a, "pre_depends", .{ .string = "" });
            if (kind == .openssl) try item.put(self.a, "multi_arch", .{ .string = field(fields, "multi-arch") });
            try graph.put(self.a, package.name, .{ .object = item });
        }
        const activation = switch (kind) {
            .base => "libgcc-s1:amd64.triggers",
            .openssl => "libssl3t64:amd64.triggers",
            .kbd => "kbd.triggers",
        };
        if (!eq(u8, try self.read(root, try std.fmt.allocPrint(self.a, "var/lib/dpkg/info/{s}", .{activation}), 1024), if (kind == .kbd) kbd_triggers else libgcc_triggers)) return error.CycleCallbackChanged;
        const no_scripts: []const []const u8 = switch (kind) {
            .base => &.{ "libgcc-s1", "libgcc-s1:amd64" },
            .openssl => &.{ "libssl3t64", "libssl3t64:amd64", "openssl-provider-legacy", "openssl-provider-legacy:amd64" },
            .kbd => &.{ "kbd", "kbd:amd64" },
        };
        for (no_scripts) |name| {
            for (scripts) |script| if (try paths.exists(root, try std.fmt.allocPrint(self.a, "var/lib/dpkg/info/{s}.{s}", .{ name, script })))
                return error.CycleCallbackChanged;
            const name_activation = try std.fmt.allocPrint(self.a, "{s}.triggers", .{name});
            if (!eq(u8, name_activation, activation) and try paths.exists(root, try std.fmt.allocPrint(self.a, "var/lib/dpkg/info/{s}", .{name_activation})))
                return error.CycleCallbackChanged;
        }
        return .{ .graph = graph, .records = records, .trigger_database = triggers_before };
    }
    pub fn transition(self: Context, root: []const u8, evidence: []const u8, packages: []const Package, kind: Cycle, stdout: []const u8, stderr: []const u8) ![]Package {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.transition) |callback| return callback(hooks.state, kind);
        const cycle = try cyclePackages(self.a, packages, self.architecture, kind);
        const before = try self.verifyCycle(root, cycle, kind);
        if (kind != .base) {
            var refusals: std.ArrayList(struct { argv: [][]const u8, exit_status: i32, output: []const u8 }) = .empty;
            for (cycle[0..kind.transitions()], 0..) |package, index| {
                const command = try self.argvFor(root, "none", "probe_configure", package, &.{});
                const result = try self.probe(command, evidence);
                try refusals.append(self.a, .{ .argv = command[3..], .exit_status = result.code, .output = try utf8Replace(self.a, result.stdout) });
                const filename = if (kind == .kbd) "kbd-cycle-refusal.json" else "openssl-cycle-refusals.json";
                if (kind == .kbd) try self.json(evidence, filename, refusals.items[0]) else try self.json(evidence, filename, refusals.items);
                const peer = if (kind == .kbd) "console-setup" else blk: {
                    const p = cycle[1 - index];
                    break :blk if (eq(u8, field(before.graph.get(p.name).?.object, "multi_arch"), "same")) try p.selector(self.a) else p.name;
                };
                const exact = try std.fmt.allocPrint(self.a, "Package {s} is not configured yet.", .{peer});
                if (result.code == 0 or std.mem.indexOf(u8, result.stdout, "dependency problems") == null or std.mem.indexOf(u8, result.stdout, exact) == null)
                    return error.CycleProbeChanged;
            }
        }
        const force: []const []const u8 = if (kind == .openssl) &.{} else &.{"--force-depends"};
        const status_sha512 = hash(std.crypto.hash.sha2.Sha512, try self.read(root, "var/lib/dpkg/status", 4 * 1024 * 1024));
        const before_name = try std.fmt.allocPrint(self.a, "{s}-before.json", .{kind.stem()});
        if (kind == .base) {
            try self.json(evidence, before_name, .{ .graph = before.graph, .records = before.records, .trigger_database = before.trigger_database, .callbacks = @as([]const []const u8, &.{}), .profile = kind.profile(), .force = force, .status_sha512 = &status_sha512 });
        } else try self.json(evidence, before_name, .{ .graph = before.graph, .records = before.records, .trigger_database = before.trigger_database, .callbacks = @as([]const []const u8, &.{}), .profile = kind.profile(), .force = force });
        const command = try self.argvFor(root, kind.profile(), kind.verb(), cycle[kind.selected()], cycle);
        try self.apply(command, evidence, stdout, stderr);
        const after = try self.database(root);
        const triggers_after = try self.triggerDatabase(root);
        const selected = if (kind == .openssl) cycle[0..2] else cycle[kind.selected()..][0..1];
        if (!conserved(before.records, after, selected) or !objectsEqual(before.trigger_database, triggers_after)) return error.CycleNoProgress;
        const after_name = try std.fmt.allocPrint(self.a, "{s}-after.json", .{kind.stem()});
        if (kind == .base) {
            try self.json(evidence, after_name, .{ .operation = command[3..], .callbacks = @as([]const []const u8, &.{}), .status = "install ok installed", .trigger_database = triggers_after, .status_sha512 = &hash(std.crypto.hash.sha2.Sha512, try self.read(root, "var/lib/dpkg/status", 4 * 1024 * 1024)), .records = after });
        } else try self.json(evidence, after_name, .{ .operation = command[3..], .callbacks = @as([]const []const u8, &.{}), .force = force, .trigger_database = triggers_after, .records = after });
        return selected;
    }
    fn packageStatus(self: Context, root: []const u8, package: Package) ![]const u8 {
        const result = try self.run(&.{ "dpkg-query", try std.fmt.allocPrint(self.a, "--admindir={s}/var/lib/dpkg", .{root}), "-W", "-f=${Version} ${Status}", try package.selector(self.a) }, 60, 4096);
        if (result.code != 0 or result.stderr.len != 0 or !std.unicode.utf8ValidateSlice(result.stdout)) return error.InvalidReferenceStatusQuery;
        return result.stdout;
    }
    fn mounted(self: Context, path: []const u8) !bool {
        const result = try self.run(&.{ "mountpoint", "-q", "--", path }, 30, maximum_probe_output);
        if (result.code != 0 and result.code != 32) return error.ReferenceMountpointQueryFailed;
        return result.code == 0;
    }
    fn emptyDirectory(self: Context, path: []const u8) !bool {
        const pin = try paths.openAbsolute(path, true);
        defer pin.close();
        return (try paths.names(self.a, self.io, pin, maximum_packages)).len == 0;
    }
    pub fn interruptPostinst(self: Context, root: []const u8, package: Package, evidence: []const u8, out: []const u8, err: []const u8) !void {
        const relative = try std.fmt.allocPrint(self.a, "var/lib/dpkg/info/{s}.postinst", .{package.name});
        const script = try join(self.a, root, relative);
        const original = try self.read(root, relative, maximum_probe_output);
        const version = profileVersion(package.name) orelse return error.UnauthorizedInterruptedPrestatePackage;
        if (!eq(u8, package.version, version)) return error.UnauthorizedInterruptedPrestatePackage;
        try self.checked(&.{ "mount", "--bind", "--", script, script }, 30);
        const result = blk: {
            errdefer self.checked(&.{ "umount", "--", script }, 30) catch {};
            try self.checked(&.{ "mount", "-o", "remount,bind,ro,noexec,nosuid,nodev", "--", script }, 30);
            const scratch_dir = try self.scratch(evidence, "reference-configure");
            defer self.cleanupScratch(scratch_dir, &.{ "stdout", "stderr" });
            break :blk try self.capture(try self.argvFor(root, package.name, "configure", package, &.{}), scratch_dir, "stdout", "stderr", 120);
        };
        try self.checked(&.{ "umount", "--", script }, 30);
        if (result.stdout_bytes > maximum_probe_output or result.stderr_bytes > maximum_probe_output) return error.InterruptedConfigureOutputExceedsLimit;
        try self.write(evidence, out, result.stdout, true);
        try self.write(evidence, err, result.stderr, true);
        if (result.code == 0 or std.mem.indexOf(u8, result.stderr, "post-installation script") == null or
            std.mem.indexOf(u8, result.stderr, "Permission denied") == null) return error.PrestatePostinstNotDeniedBeforeExecution;
        if (!eq(u8, original, try self.read(root, relative, maximum_probe_output))) return error.PrestatePostinstChanged;
    }
    pub fn capturePrestate(self: Context, root: []const u8, package: Package, prestate: Prestate, evidence: []const u8, out: []const u8, err: []const u8) !void {
        if (builtin.is_test) if (self.test_hooks) |hooks| if (hooks.capture) |callback| return callback(hooks.state, package, prestate);
        try paths.absolute(prestate.destination);
        const parent = std.fs.path.dirname(prestate.destination).?;
        if (try paths.exists(parent, std.fs.path.basename(prestate.destination))) return error.PrestateDestinationMustBeNew;
        if (eq(u8, prestate.status, "half-configured")) try self.interruptPostinst(root, package, evidence, out, err);
        const expected = try std.fmt.allocPrint(self.a, "{s} install ok {s}", .{ package.version, prestate.status });
        if (!eq(u8, try self.packageStatus(root, package), expected)) return error.UnexpectedPrestateStatus;
        const proc = try join(self.a, root, "proc");
        const was_mounted = try self.mounted(proc);
        if (was_mounted) try self.checked(&.{ "umount", "--", proc }, 30);
        {
            errdefer if (was_mounted) self.checked(&.{ "mount", "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", proc }, 30) catch {};
            if (try self.mounted(proc) or !try self.emptyDirectory(proc)) return error.PrestateProcMountpointNotEmpty;
            try self.checked(&.{ "cp", "-a", "--one-file-system", "--", root, prestate.destination }, 600);
            const destination = try paths.openAbsolute(prestate.destination, true);
            defer destination.close();
            _ = try paths.syscall(linux.fchmod(destination.fd, 0o700));
        }
        if (was_mounted) try self.checked(&.{ "mount", "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", proc }, 30);
        try self.write(parent, "prestates.tsv", try std.fmt.allocPrint(self.a, "{s}\t{s}\t{s}\n", .{ try package.selector(self.a), expected, prestate.destination }), true);
    }
    pub fn install(self: Context, prestates: []const Prestate) !void {
        const packages = try self.manifest();
        try validateTargets(self.a, packages, prestates);
        const states = try self.a.alloc(enum { pending, unpacked, configured }, packages.len);
        @memset(states, .pending);
        const captured = try self.a.alloc(bool, prestates.len);
        @memset(captured, false);
        var targets = prestates.len;
        var probes: usize = 0;
        var applied: [3]bool = @splat(false);
        var configured: usize = 0;
        var unpacked: std.ArrayList(usize) = .empty;
        while (configured != packages.len) {
            var progressed = false;
            var deferred: std.ArrayList([]const u8) = .empty;
            var refusals: std.ArrayList(Refusal) = .empty;
            for (packages, states, 0..) |package, *state, package_index| {
                if (state.* != .pending) continue;
                const command = try self.argvFor(self.root, "none", "probe_unpack", package, &.{});
                probes += 1;
                if (probes > maximum_probes) return error.ReferenceDependencyProbeLimitExceeded;
                const result = try self.probe(command, self.evidence);
                if (result.code != 0) {
                    if (std.mem.indexOf(u8, result.stdout, "pre-dependency problem") == null) return error.ReferenceDpkgUnpackRefused;
                    try deferred.append(self.a, try package.selector(self.a));
                    try refusals.append(self.a, try refusal(self.a, package, "probe_unpack", result));
                    continue;
                }
                try self.archive(package);
                try self.apply(try self.argvFor(self.root, "none", "unpack", package, &.{}), self.evidence, "reference-install.stdout", "reference-install.stderr");
                state.* = .unpacked;
                try unpacked.append(self.a, package_index);
                progressed = true;
            }
            var unpacked_index: usize = 0;
            while (unpacked_index < unpacked.items.len) {
                const package_index = unpacked.items[unpacked_index];
                const package = packages[package_index];
                probes += 1;
                if (probes > maximum_probes) return error.ReferenceDependencyProbeLimitExceeded;
                const result = try self.probe(try self.argvFor(self.root, "none", "probe_configure", package, &.{}), self.evidence);
                if (result.code != 0) {
                    if (std.mem.indexOf(u8, result.stdout, "dependency problems") == null) return error.ReferenceDpkgConfigureRefused;
                    try deferred.append(self.a, try package.selector(self.a));
                    try refusals.append(self.a, try refusal(self.a, package, "probe_configure", result));
                    unpacked_index += 1;
                    continue;
                }
                if (!statusIs(try self.database(self.root), package, "install ok unpacked")) return error.ReferencePackageStateVersionChanged;
                const profile = if (profileVersion(package.name) != null) package.name else "none";
                if (profileVersion(profile)) |version| if (!eq(u8, package.version, version)) return error.UnauthorizedReferenceScriptVersion;
                var selected: ?usize = null;
                const selector = try package.selector(self.a);
                for (prestates, captured, 0..) |prestate, done, index| if (!done and eq(u8, selector, prestate.selector)) {
                    selected = index;
                };
                if (selected != null and eq(u8, selector, "sudo:amd64")) {
                    const companion_index = findPackage(packages, "sudo-rs").?;
                    const companion = packages[companion_index];
                    const db = try self.database(self.root);
                    if (!statusIs(db, companion, "install ok installed")) {
                        const record = findRecord(db, companion);
                        if (states[companion_index] == .configured or (record != null and !eq(u8, field(record.?, "version"), companion.version)))
                            return error.SignedSudoPrestateCompanionStateVersionChanged;
                        try deferred.append(self.a, selector);
                        unpacked_index += 1;
                        continue;
                    }
                }
                var operation: []const u8 = "configure";
                if (selected) |index| {
                    captured[index] = true;
                    targets -= 1;
                    try self.capturePrestate(self.root, package, prestates[index], self.evidence, "reference-install.stdout", "reference-install.stderr");
                    if (targets == 0) return;
                    if (eq(u8, prestates[index].status, "half-configured")) {
                        if (!statusIs(try self.database(self.root), package, "install ok half-configured")) return error.CapturedPrestateStateVersionChanged;
                        operation = "continue_prestate";
                    }
                }
                try self.apply(try self.argvFor(self.root, profile, operation, package, &.{}), self.evidence, "reference-install.stdout", "reference-install.stderr");
                states[package_index] = .configured;
                _ = unpacked.orderedRemove(unpacked_index);
                configured += 1;
                progressed = true;
            }
            if (!progressed) {
                try self.json(self.evidence, "reference-no-progress.json", .{
                    .base_cycle_applied = applied[0],
                    .openssl_cycle_applied = applied[1],
                    .kbd_cycle_applied = applied[2],
                    .deferred = deferred.items,
                    .refusals = refusals.items[0..@min(refusals.items.len, 128)],
                    .refusals_truncated = refusals.items.len > 128,
                });
                var chosen: ?Cycle = null;
                if (!applied[0]) {
                    const cycle = try cyclePackages(self.a, packages, self.architecture, .base);
                    if (states[findPackage(packages, cycle[1].name).?] != .unpacked) return error.CycleStateChanged;
                    chosen = .base;
                } else if (!applied[1] and unpackedSet(packages, states, &.{ "libssl3t64", "openssl-provider-legacy" })) {
                    probes += 2;
                    chosen = .openssl;
                } else if (!applied[2] and unpackedSet(packages, states, &.{ "kbd", "console-setup-linux", "console-setup" })) {
                    probes += 1;
                    chosen = .kbd;
                }
                if (probes > maximum_probes) return error.ReferenceDependencyProbeLimitExceeded;
                const kind = chosen orelse return error.CycleNoProgress;
                for (try self.transition(self.root, self.evidence, packages, kind, "reference-install.stdout", "reference-install.stderr")) |p| {
                    const selected_index = findPackage(packages, p.name).?;
                    states[selected_index] = .configured;
                    for (unpacked.items, 0..) |unpacked_package, i| if (unpacked_package == selected_index) {
                        _ = unpacked.orderedRemove(i);
                        break;
                    };
                    configured += 1;
                }
                applied[@intFromEnum(kind)] = true;
            }
        }
        if (targets != 0) return error.PrestatePackageNeverConfigured;
        return processTriggers(self, packages);
    }
    pub fn report(self: Context) !void {
        const packages = try self.manifest();
        const records = try self.database(self.root);
        if (records.len != packages.len) return error.ReferenceDatabaseDiffersFromSignedClosure;
        var output: std.Io.Writer.Allocating = .init(self.a);
        for (packages) |package| {
            if (!statusIs(records, package, "install ok installed")) return error.ReferencePackageNotInstalledAtSignedVersion;
            try output.writer.print("ii  {s} {s}\n", .{ try package.selector(self.a), package.version });
        }
        try self.replace(self.evidence, "reference-installed.txt", output.written());
        const directory = try paths.openAbsolute(try join(self.a, self.root, "var/lib/dpkg/info"), true);
        defer directory.close();
        for (try paths.names(self.a, self.io, directory, maximum_packages * 12)) |entry| {
            if (!std.mem.endsWith(u8, entry, ".list")) continue;
            const data = try self.read(self.root, try std.fmt.allocPrint(self.a, "var/lib/dpkg/info/{s}", .{entry}), 8 * 1024 * 1024);
            var lines = std.mem.splitScalar(u8, data, '\n');
            while (lines.next()) |line| if (eq(u8, std.mem.trimEnd(u8, line, "\r"), "/dev/null")) return error.ReferencePackageClaimsExcludedDevice;
        }
    }
};

// --- #265 single signed trigger handler (begin) ---------------------------------
// After the closure is configured with --no-triggers, pinned dpkg settles one
// individually reviewed signed handler at a time, never through --pending. Every
// pin below is the genuine amd64 pre-handler state that hosted run 38348813924
// observed (reference-trigger-authority.json); the launcher compiles the same pins
// and re-verifies them inside the chroot immediately before exec. No expectation
// is ever derived from the native root.
pub const TriggerPin = struct { name: []const u8, size: usize, mode: u32, sha512: []const u8 };
pub const ControlPin = struct { name: []const u8, size: usize, mode: u32, sha256: []const u8 };
pub const IndependentPending = struct { name: []const u8, architecture: []const u8, version: []const u8, pending: []const u8 };
pub const libc_bin_trigger: Pin = .{ .name = "libc-bin", .version = "2.43-2ubuntu2.4", .size = 700954, .digest = "350969573c25805e77d2ab180ebb445da1be72266f9aa5a162c2c38ec52f6935a58d7810d5795ba5fad415f5fa12fefe9194ff7e0534e292d1f63a56811e420f", .depends = "libc6 (>> 2.43), libc6 (<< 2.44)" };
const libc_bin_members = [_][]const u8{ ".", "./conffiles", "./control", "./md5sums", "./postinst", "./triggers" };
pub const libc_bin_controls = [2]ControlPin{
    .{ .name = "postinst", .size = 847, .mode = 0o755, .sha256 = "3daa7e3ffd429c1d77287f0fc840a490a607697906d2303452f70578647ce0d4" },
    .{ .name = "triggers", .size = 440, .mode = 0o644, .sha256 = "c3d6b5df131336e54c31dc5687929467de7abea5c5798e3d6a6b2a64ef971fd4" },
};
pub const independent_pending = [_]IndependentPending{.{ .name = "procps", .architecture = "amd64", .version = "2:4.0.4-9ubuntu1", .pending = "/usr/lib/sysctl.d" }};
pub const reviewed_trigger_database = [_]TriggerPin{
    .{ .name = "File", .size = 506, .mode = 0o644, .sha512 = "2e29346ce69bddb1a10d4ebb1e13a09f6fd083264b7af7d68abf2343968834cd48b1572ae0b7b2b6d3ef267b094394683dd3052547a7ed6b177e4774d83067f9" },
    .{ .name = "Lock", .size = 0, .mode = 0o600, .sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
    .{ .name = "Unincorp", .size = 0, .mode = 0o644, .sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
    .{ .name = "ldconfig", .size = 9, .mode = 0o644, .sha512 = "bcfb72bee1c74357157290fdbce71b775e7d3a99ba26578b61183e0131eefaf1bf5677e4ba11064d4e5179f1a8d7957501ca70587bfc8cbff7021c8f31b52dea" },
    .{ .name = "libc-upgrade", .size = 16, .mode = 0o644, .sha512 = "0ceb3fa2819b9a2d4d8bafb2c19869a52b47f026bc3d1917b4c9eb5d2f3d3428a2579567d3e4379f513b481efcb44f3675023171061550778e19697c12c96b67" },
};
const trigger_control_suffixes = scripts ++ [_][]const u8{"triggers"};
const maximum_trigger_files = 64;
const maximum_trigger_controls = 16;
const maximum_status_bytes = 4 * 1024 * 1024;

pub const TriggerSelector = struct { name: []const u8, architecture: []const u8 };
const libc_bin_selector = [_]TriggerSelector{.{ .name = "libc-bin", .architecture = "amd64" }};
pub const TriggerFile = struct {
    bytes: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    pub fn same(self: TriggerFile, other: TriggerFile) bool {
        return eq(u8, self.bytes, other.bytes) and self.mode == other.mode and self.uid == other.uid and
            self.gid == other.gid and self.nlink == other.nlink;
    }
    fn protectedBy(self: TriggerFile, owner: [2]u32) bool {
        return self.uid == owner[0] and self.gid == owner[1] and self.nlink == 1 and self.mode & 0o022 == 0;
    }
};
pub const TriggerEntry = struct { name: []const u8, file: TriggerFile };
pub const TriggerState = struct {
    owner: [2]u32,
    status: TriggerFile,
    updates: []const TriggerEntry,
    trigger_database: []const TriggerEntry,
    controls: []const TriggerEntry,
    controls_truncated: bool,
};
pub const TriggerRecord = struct { name: []const u8, architecture: []const u8, fields: Fields };
pub const TriggerAttempt = struct { selector: []const u8, argv: []const []const u8, outcome: []const u8 };
pub const AdmittedTrigger = struct { package: Package, state: TriggerState };
/// One refusal reason per run, carried beside error.TriggerRefusal like the Python exception text.
pub const TriggerRun = struct {
    ctx: Context,
    reason: []const u8 = "",
    attempts: std.ArrayList(TriggerAttempt) = .empty,
    fn refuse(self: *TriggerRun, comptime format: []const u8, args: anytype) error{ TriggerRefusal, OutOfMemory } {
        self.reason = std.fmt.allocPrint(self.ctx.a, format, args) catch return error.OutOfMemory;
        return error.TriggerRefusal;
    }
};

fn triggerDatabasePins(ctx: Context) []const TriggerPin {
    if (builtin.is_test) if (ctx.test_hooks) |hooks| if (hooks.trigger_database) |pins| return pins;
    return &reviewed_trigger_database;
}
fn libcBinControlPins(ctx: Context) [2]ControlPin {
    if (builtin.is_test) if (ctx.test_hooks) |hooks| if (hooks.trigger_controls) |pins| return pins;
    return libc_bin_controls;
}
fn triggerEntry(entries: []const TriggerEntry, name: []const u8) ?TriggerFile {
    for (entries) |entry| if (eq(u8, entry.name, name)) return entry.file;
    return null;
}
fn entriesEqual(left: []const TriggerEntry, right: []const TriggerEntry) bool {
    if (left.len != right.len) return false;
    for (left) |entry| {
        const other = triggerEntry(right, entry.name) orelse return false;
        if (!entry.file.same(other)) return false;
    }
    return true;
}
fn findTriggerRecord(records: []const TriggerRecord, name: []const u8, architecture: []const u8) ?Fields {
    for (records) |record| if (eq(u8, record.name, name) and eq(u8, record.architecture, architecture)) return record.fields;
    return null;
}
fn sameOptional(left: Fields, right: Fields, key: []const u8) bool {
    const actual = left.get(key) orelse return !right.contains(key);
    const expected = right.get(key) orelse return false;
    return eq(u8, actual.string, expected.string);
}
fn bytesLess(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn triggerFile(a: A, directory: i32, name: []const u8, limit: usize) !TriggerFile {
    const pin = try paths.openBeneath(directory, name, false);
    defer pin.close();
    if (pin.metadata.mode & 0o170000 != 0o100000 or pin.metadata.size > limit) return error.TriggerStateNotBoundedRegularFile;
    const bytes = try paths.readPinned(a, pin, limit);
    return .{ .bytes = bytes, .mode = pin.metadata.mode & 0o7777, .uid = pin.metadata.uid, .gid = pin.metadata.gid, .nlink = pin.metadata.nlink };
}
fn triggerDirectory(parent: i32, name: []const u8, owner: [2]u32) !paths.Pinned {
    const pin = try paths.openBeneath(parent, name, true);
    if (pin.metadata.uid != owner[0] or pin.metadata.gid != owner[1] or pin.metadata.mode & 0o022 != 0) {
        pin.close();
        return error.UnprotectedTriggerStateDirectory;
    }
    return pin;
}
fn triggerEntries(ctx: Context, directory: paths.Pinned) ![]TriggerEntry {
    const names = try paths.names(ctx.a, ctx.io, directory, maximum_trigger_files);
    const entries = try ctx.a.alloc(TriggerEntry, names.len);
    for (names, entries) |name, *entry| entry.* = .{ .name = name, .file = try triggerFile(ctx.a, directory.fd, name, maximum_control_bytes) };
    return entries;
}
fn triggerPresent(directory: i32, name: []const u8) !bool {
    var buffer: [256]u8 = undefined;
    if (name.len >= buffer.len) return error.NoncanonicalReferencePath;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = 0;
    var info: linux.Statx = undefined;
    const result = linux.statx(directory, @ptrCast(&buffer), linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &info);
    if (linux.errno(result) == .NOENT) return false;
    _ = try paths.syscall(result);
    return true;
}
/// Bounded, descriptor-rooted bytes of every database input a handler can change.
fn readTriggerState(ctx: Context, controls: []const TriggerSelector) !TriggerState {
    const a = ctx.a;
    const root = try paths.openAbsolute(ctx.root, true);
    defer root.close();
    const owner = [2]u32{ root.metadata.uid, root.metadata.gid };
    const lib = try paths.openBeneath(root.fd, "var/lib", true);
    defer lib.close();
    const database = try triggerDirectory(lib.fd, "dpkg", owner);
    defer database.close();
    const status = try triggerFile(a, database.fd, "status", maximum_status_bytes);
    const updates_directory = try triggerDirectory(database.fd, "updates", owner);
    defer updates_directory.close();
    const updates = try triggerEntries(ctx, updates_directory);
    const triggers_directory = try triggerDirectory(database.fd, "triggers", owner);
    defer triggers_directory.close();
    const trigger_database = try triggerEntries(ctx, triggers_directory);
    const info = try triggerDirectory(database.fd, "info", owner);
    defer info.close();
    var selected: std.ArrayList(TriggerEntry) = .empty;
    for (controls[0..@min(controls.len, maximum_trigger_controls)]) |control| {
        for ([_][]const u8{ control.name, try std.fmt.allocPrint(a, "{s}:{s}", .{ control.name, control.architecture }) }) |prefix| {
            for (trigger_control_suffixes) |suffix| {
                const name = try std.fmt.allocPrint(a, "{s}.{s}", .{ prefix, suffix });
                if (!try triggerPresent(info.fd, name)) continue;
                const file = try triggerFile(a, info.fd, name, maximum_control_bytes);
                for (selected.items) |*entry| {
                    if (eq(u8, entry.name, name)) {
                        entry.file = file;
                        break;
                    }
                } else try selected.append(a, .{ .name = name, .file = file });
            }
        }
    }
    return .{ .owner = owner, .status = status, .updates = updates, .trigger_database = trigger_database, .controls = try selected.toOwnedSlice(a), .controls_truncated = controls.len > maximum_trigger_controls };
}
fn triggerState(run: *TriggerRun, controls: []const TriggerSelector) !TriggerState {
    return readTriggerState(run.ctx, controls) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return run.refuse("TriggerStateChanged: {s}", .{@errorName(err)}),
    };
}
fn triggerRecords(run: *TriggerRun, status: []const u8) ![]TriggerRecord {
    const a = run.ctx.a;
    const stanzas = controlFields(a, status) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return run.refuse("TriggerStatusMalformed: {s}", .{@errorName(err)}),
    };
    const records = try a.alloc(TriggerRecord, stanzas.len);
    for (stanzas, records, 0..) |fields, *record, index| {
        const name = field(fields, "package");
        const architecture = field(fields, "architecture");
        if (!nameValid(name) or !nameValid(architecture) or field(fields, "version").len == 0 or field(fields, "status").len == 0)
            return run.refuse("TriggerStatusMalformed: incomplete package identity", .{});
        for (records[0..index]) |previous| if (eq(u8, previous.name, name) and eq(u8, previous.architecture, architecture))
            return run.refuse("DuplicateTriggerIdentity: {s}:{s}", .{ name, architecture });
        record.* = .{ .name = name, .architecture = architecture, .fields = fields };
    }
    return records;
}

const SignedMember = struct { name: []const u8, regular: bool, mode: u64, uid: u64, gid: u64, bytes: []const u8 };
fn tarNumber(bytes: []const u8) !u64 {
    if (bytes[0] & 0x80 != 0) return error.UnsupportedSignedControlNumber;
    const text = std.mem.trim(u8, bytes[0 .. std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len], " \t\n\r\x0b\x0c\x1c\x1d\x1e\x1f");
    var value: u64 = 0;
    for (text) |digit| {
        if (digit < '0' or digit > '7') return error.InvalidSignedControlNumber;
        value = value * 8 + (digit - '0');
    }
    return value;
}
/// Plain ustar/v7 members exactly as dpkg-deb --ctrl-tarfile emits them; every other form refuses.
fn signedTarMembers(a: A, data: []const u8) ![]SignedMember {
    if (data.len == 0 or data.len > maximum_control_bytes) return error.InvalidSignedControlArchive;
    var members: std.ArrayList(SignedMember) = .empty;
    var offset: usize = 0;
    while (offset < data.len) {
        if (data.len - offset < 512) return error.TruncatedSignedControlArchive;
        const header = data[offset..][0..512];
        if (std.mem.allEqual(u8, header, 0)) break;
        var unsigned_sum: i64 = 256;
        var signed_sum: i64 = 256;
        for (header, 0..) |byte, index| {
            if (index >= 148 and index < 156) continue;
            unsigned_sum += byte;
            signed_sum += @as(i8, @bitCast(byte));
        }
        const checksum: i64 = @intCast(try tarNumber(header[148..156]));
        if (checksum != unsigned_sum and checksum != signed_sum) return error.InvalidSignedControlChecksum;
        const kind = header[156];
        var name: []const u8 = header[0 .. std.mem.indexOfScalar(u8, header[0..100], 0) orelse 100];
        const directory = kind == '5' or (kind == 0 and std.mem.endsWith(u8, name, "/"));
        if (!directory and kind != '0' and kind != 0) return error.UnsupportedSignedControlMember;
        if (directory) name = std.mem.trimEnd(u8, name, "/");
        const prefix: []const u8 = header[345 .. 345 + (std.mem.indexOfScalar(u8, header[345..500], 0) orelse 155)];
        const size = try tarNumber(header[124..136]);
        // tarfile.TarInfo.frombuf also parses mtime, devmajor and devminor.
        for ([_][2]usize{ .{ 136, 148 }, .{ 329, 337 }, .{ 337, 345 } }) |range| _ = try tarNumber(header[range[0]..range[1]]);
        if ((directory and size != 0) or size > data.len) return error.InvalidSignedControlMember;
        offset += 512;
        const length: usize = @intCast(size);
        const padded = std.mem.alignForward(usize, length, 512);
        if (padded > data.len - offset) return error.TruncatedSignedControlArchive;
        if (members.items.len == 128) return error.InvalidSignedControlArchive;
        try members.append(a, .{
            .name = if (prefix.len != 0) try std.fmt.allocPrint(a, "{s}/{s}", .{ prefix, name }) else name,
            .regular = !directory,
            .mode = try tarNumber(header[100..108]),
            .uid = try tarNumber(header[108..116]),
            .gid = try tarNumber(header[116..124]),
            .bytes = data[offset..][0..length],
        });
        offset += padded;
    }
    return members.toOwnedSlice(a);
}
fn signedMember(members: []const SignedMember, name: []const u8) ?SignedMember {
    for (members) |entry| if (eq(u8, entry.name, name)) return entry;
    return null;
}
const SignedControls = struct { controls: [2][]const u8, fields: Fields };
fn readSignedLibcBin(ctx: Context, package: Package, pins: [2]ControlPin) !SignedControls {
    try ctx.archive(package);
    const result = try ctx.run(&.{ "dpkg-deb", "--ctrl-tarfile", package.archive }, 30, maximum_control_bytes);
    if (result.code != 0) return error.SignedControlExtractionFailed;
    if (result.stdout.len > maximum_control_bytes or result.stderr.len != 0) return error.OversizedOrNoisyControlArchive;
    const members = try signedTarMembers(ctx.a, result.stdout);
    const names = try ctx.a.alloc([]const u8, members.len);
    for (members, names) |entry, *name| name.* = entry.name;
    std.mem.sort([]const u8, names, {}, bytesLess);
    if (names.len != libc_bin_members.len) return error.SignedControlMembersDiffer;
    for (names, libc_bin_members) |actual, expected| if (!eq(u8, actual, expected)) return error.SignedControlMembersDiffer;
    var controls: [2][]const u8 = undefined;
    for (pins, &controls) |pin, *bytes| {
        const entry = signedMember(members, try std.fmt.allocPrint(ctx.a, "./{s}", .{pin.name})) orelse return error.SignedControlMembersDiffer;
        if (!entry.regular or entry.uid != 0 or entry.gid != 0 or entry.bytes.len != pin.size or entry.mode & 0o7777 != pin.mode or
            !eq(u8, &hash(std.crypto.hash.sha2.Sha256, entry.bytes), pin.sha256)) return error.SignedControlScriptDiffers;
        bytes.* = entry.bytes;
    }
    const control_member = signedMember(members, "./control") orelse return error.MissingSignedControl;
    if (!control_member.regular or control_member.bytes.len > maximum_probe_output) return error.MissingSignedControl;
    const stanzas = try controlFields(ctx.a, control_member.bytes);
    if (stanzas.len != 1) return error.SignedControlStanzaCount;
    return .{ .controls = controls, .fields = stanzas[0] };
}
fn signedLibcBinControls(run: *TriggerRun, package: Package) ![2][]const u8 {
    const ctx = run.ctx;
    if (builtin.is_test) if (ctx.test_hooks) |hooks| if (hooks.trigger_signed) |callback| return callback(hooks.state, package);
    const signed = readSignedLibcBin(ctx, package, libcBinControlPins(ctx)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return run.refuse("TriggerHandlerChanged: signed libc-bin controls: {s}", .{@errorName(err)}),
    };
    const fields = signed.fields;
    if (!eq(u8, field(fields, "package"), package.name) or !eq(u8, field(fields, "version"), package.version) or
        !eq(u8, field(fields, "architecture"), package.architecture) or !eq(u8, field(fields, "depends"), libc_bin_trigger.depends) or
        field(fields, "pre-depends").len != 0) return run.refuse("TriggerDependencyChanged: signed libc-bin control fields differ", .{});
    return signed.controls;
}
fn independentPending(record: TriggerRecord) ?IndependentPending {
    for (independent_pending) |entry| if (eq(u8, entry.name, record.name) and eq(u8, entry.architecture, record.architecture)) return entry;
    return null;
}

pub fn admitLibcBinTrigger(run: *TriggerRun, packages: []const Package) !AdmittedTrigger {
    const ctx = run.ctx;
    const pin = libc_bin_trigger;
    var matches: usize = 0;
    var package: Package = undefined;
    for (packages) |candidate| if (eq(u8, candidate.name, pin.name)) {
        matches += 1;
        package = candidate;
    };
    if (matches != 1 or !matchesPin(package, pin))
        return run.refuse("UnreviewedTriggerHandler: libc-bin archive differs from the reviewed handler", .{});
    const signed = try signedLibcBinControls(run, package);
    const state = try triggerState(run, &libc_bin_selector);
    const owner = state.owner;
    if (state.updates.len != 0) return run.refuse("TriggerStateChanged: unsettled database journal before the handler", .{});
    if (!state.status.protectedBy(owner)) return run.refuse("TriggerStateChanged: unprotected status database", .{});
    const database_pins = triggerDatabasePins(ctx);
    var database_reviewed = state.trigger_database.len == database_pins.len;
    for (database_pins) |entry| {
        const file = triggerEntry(state.trigger_database, entry.name) orelse {
            database_reviewed = false;
            break;
        };
        if (file.bytes.len != entry.size or file.mode != entry.mode or
            !eq(u8, &hash(std.crypto.hash.sha2.Sha512, file.bytes), entry.sha512) or !file.protectedBy(owner)) database_reviewed = false;
    }
    if (!database_reviewed) return run.refuse("TriggerDatabaseChanged: trigger database differs from the reviewed pre-handler state", .{});
    const control_pins = libcBinControlPins(ctx);
    var controls_signed = state.controls.len == control_pins.len;
    for (control_pins, signed) |control, bytes| {
        const file = triggerEntry(state.controls, try std.fmt.allocPrint(ctx.a, "{s}.{s}", .{ pin.name, control.name })) orelse {
            controls_signed = false;
            break;
        };
        if (!eq(u8, file.bytes, bytes) or file.mode != control.mode or !file.protectedBy(owner)) controls_signed = false;
    }
    if (!controls_signed) return run.refuse("TriggerHandlerChanged: installed libc-bin controls differ from the signed archive", .{});
    const records = try triggerRecords(run, state.status.bytes);
    var named: usize = 0;
    for (records) |record| if (eq(u8, record.name, pin.name)) {
        named += 1;
    };
    if (named != 1 or findTriggerRecord(records, pin.name, pin.architecture) == null)
        return run.refuse("MixedSelectedTriggerState: libc-bin:amd64 is not the one selected record", .{});
    var independent: usize = 0;
    for (records) |record| {
        const fields = record.fields;
        if (fields.contains("triggers-awaited")) return run.refuse("UnreviewedAwaitedTrigger: {s}:{s}", .{ record.name, record.architecture });
        if (fields.contains("config-version"))
            return run.refuse("TriggerStateChanged: {s}:{s} records a configuration version", .{ record.name, record.architecture });
        const pending: ?[]const u8 = if (fields.get("triggers-pending")) |value| value.string else null;
        if (eq(u8, record.name, pin.name) and eq(u8, record.architecture, pin.architecture)) {
            if (!eq(u8, field(fields, "version"), pin.version) or !eq(u8, field(fields, "status"), "install ok triggers-pending") or
                !eq(u8, field(fields, "depends"), pin.depends) or fields.contains("pre-depends") or pending == null or !eq(u8, pending.?, "ldconfig"))
                return run.refuse("MixedSelectedTriggerState: libc-bin:amd64 is not pending exactly ldconfig", .{});
        } else if (independentPending(record)) |reviewed| {
            if (!eq(u8, field(fields, "version"), reviewed.version) or pending == null or !eq(u8, pending.?, reviewed.pending) or
                !eq(u8, field(fields, "status"), "install ok triggers-pending"))
                return run.refuse("IndependentTriggerChanged: {s}:{s}", .{ record.name, record.architecture });
            independent += 1;
        } else if (pending) |value| {
            return run.refuse("UnreviewedTriggerHandler: {s}:{s} ({s})", .{ record.name, record.architecture, value });
        } else if (!eq(u8, field(fields, "status"), "install ok installed")) {
            return run.refuse("TriggerStateChanged: {s}:{s} is {s}", .{ record.name, record.architecture, field(fields, "status") });
        }
    }
    const libc6 = findTriggerRecord(records, "libc6", pin.architecture);
    if (libc6 == null or !eq(u8, field(libc6.?, "version"), libc.version))
        return run.refuse("TriggerDependencyChanged: libc6:amd64 is not configured at the signed version", .{});
    if (independent != independent_pending.len)
        return run.refuse("IndependentTriggerChanged: reviewed independent pending handler missing", .{});
    return .{ .package = package, .state = state };
}

pub fn expectedLibcBinStatus(run: *TriggerRun, before: []const u8) ![]const u8 {
    const a = run.ctx.a;
    if (!std.unicode.utf8ValidateSlice(before)) return error.InvalidReferenceControlEncoding;
    var lines: std.ArrayList([]const u8) = .empty;
    var split = std.mem.splitScalar(u8, before, '\n');
    while (split.next()) |line| try lines.append(a, line);
    var starts: usize = 0;
    var start: usize = 0;
    for (lines.items, 0..) |line, index| if (eq(u8, line, "Package: libc-bin") and (index == 0 or lines.items[index - 1].len == 0)) {
        starts += 1;
        start = index;
    };
    if (starts != 1) return run.refuse("MixedSelectedTriggerState: no unique libc-bin stanza", .{});
    var end = start;
    while (end < lines.items.len and lines.items[end].len != 0) end += 1;
    const stanza = lines.items[start..end];
    var statuses: usize = 0;
    var pending: usize = 0;
    var amd64 = false;
    for (stanza) |line| {
        if (eq(u8, line, "Status: install ok triggers-pending")) statuses += 1;
        if (eq(u8, line, "Triggers-Pending: ldconfig")) pending += 1;
        if (eq(u8, line, "Architecture: amd64")) amd64 = true;
    }
    if (statuses != 1 or pending != 1 or !amd64)
        return run.refuse("MixedSelectedTriggerState: libc-bin stanza is not the reviewed pending record", .{});
    var settled: std.ArrayList([]const u8) = .empty;
    try settled.appendSlice(a, lines.items[0..start]);
    for (stanza) |line| {
        if (eq(u8, line, "Triggers-Pending: ldconfig")) continue;
        try settled.append(a, if (eq(u8, line, "Status: install ok triggers-pending")) "Status: install ok installed" else line);
    }
    try settled.appendSlice(a, lines.items[end..]);
    return std.mem.join(a, "\n", settled.items);
}

fn pythonSplit(a: A, text: []const u8) ![]const []const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    var start: ?usize = null;
    var index: usize = 0;
    while (index < text.len) {
        const point = pythonCodepoint(text, index);
        if (pythonSpace(point.value)) {
            if (start) |first| try words.append(a, text[first..index]);
            start = null;
        } else if (start == null) start = index;
        index += point.size;
    }
    if (start) |first| try words.append(a, text[first..]);
    return words.toOwnedSlice(a);
}
/// Python repr() of a str; unassigned code points outside the escaped ranges pass through unchanged.
fn pythonRepr(a: A, text: []const u8) ![]const u8 {
    const quote: u8 = if (std.mem.indexOfScalar(u8, text, '\'') != null and std.mem.indexOfScalar(u8, text, '"') == null) '"' else '\'';
    var output: std.ArrayList(u8) = .empty;
    try output.append(a, quote);
    var index: usize = 0;
    while (index < text.len) {
        const point = pythonCodepoint(text, index);
        const bytes = text[index..][0..point.size];
        index += point.size;
        switch (point.value) {
            '\\' => try output.appendSlice(a, "\\\\"),
            '\t' => try output.appendSlice(a, "\\t"),
            '\n' => try output.appendSlice(a, "\\n"),
            '\r' => try output.appendSlice(a, "\\r"),
            0...8, 0x0b...0x0c, 0x0e...0x1f, 0x7f...0xa0, 0xad => try output.print(a, "\\x{x:0>2}", .{point.value}),
            0x600...0x605, 0x61c, 0x6dd, 0x70f, 0x8e2, 0x1680, 0x180e, 0x2000...0x200f, 0x2028...0x202f, 0x205f...0x206f, 0x3000, 0xd800...0xdfff, 0xe000...0xf8ff, 0xfeff, 0xfff9...0xfffb, 0xfffe...0xffff => try output.print(a, "\\u{x:0>4}", .{point.value}),
            0xe0001, 0xe0020...0xe007f, 0xf0000...0x10ffff => try output.print(a, "\\U{x:0>8}", .{point.value}),
            else => if (point.value == quote) {
                try output.append(a, '\\');
                try output.append(a, quote);
            } else try output.appendSlice(a, bytes),
        }
    }
    try output.append(a, quote);
    return output.toOwnedSlice(a);
}

/// Classifies everything but the one reviewed libc-bin transition.
fn transitionRefusal(run: *TriggerRun, before: TriggerState, after: TriggerState) !?[]const u8 {
    const a = run.ctx.a;
    const old = try triggerRecords(run, before.status.bytes);
    const new = triggerRecords(run, after.status.bytes) catch |err| switch (err) {
        error.TriggerRefusal => return try std.fmt.allocPrint(a, "TriggerDatabaseChanged: status after the handler: {s}", .{run.reason}),
        else => return err,
    };
    const selected = findTriggerRecord(new, "libc-bin", "amd64") orelse return "TriggerDatabaseChanged: libc-bin:amd64 record vanished";
    const pending = try pythonSplit(a, field(selected, "triggers-pending"));
    if (!eq(u8, field(selected, "status"), "install ok installed") or pending.len != 0 or selected.contains("triggers-awaited")) {
        if (eq(u8, after.status.bytes, before.status.bytes) and after.updates.len == 0 and entriesEqual(after.trigger_database, before.trigger_database))
            return "CycleNoProgress: libc-bin:amd64 handler left the database unchanged";
        for (pending) |item| if (eq(u8, item, "ldconfig")) return "CyclicTriggerActivation: libc-bin:amd64 handler re-activated its own ldconfig interest";
        if (pending.len != 0)
            return try std.fmt.allocPrint(a, "RecursiveTriggerActivation: libc-bin:amd64 left pending {s}", .{try std.mem.join(a, " ", pending[0..@min(pending.len, 8)])});
        return try std.fmt.allocPrint(a, "TriggerDatabaseChanged: libc-bin:amd64 ended {s}", .{try pythonRepr(a, field(selected, "status"))});
    }
    if (after.updates.len != 0) return "TriggerStateChanged: unsettled database journal after the handler";
    if (triggerEntry(after.trigger_database, "Unincorp")) |unincorporated| if (unincorporated.bytes.len != 0)
        return "RecursiveTriggerActivation: the handler left unincorporated trigger activations";
    if (!entriesEqual(after.trigger_database, before.trigger_database)) return "TriggerDatabaseChanged: trigger interest database changed during the handler";
    if (!entriesEqual(after.controls, before.controls)) return "TriggerHandlerChanged: libc-bin controls changed during the handler";
    var same_records = old.len == new.len;
    for (old) |record| if (findTriggerRecord(new, record.name, record.architecture) == null) {
        same_records = false;
    };
    if (!same_records) return "ExternalTriggerCallback: the handler added or removed package records";
    for (old) |record| {
        if (eq(u8, record.name, "libc-bin") and eq(u8, record.architecture, "amd64")) continue;
        const current = findTriggerRecord(new, record.name, record.architecture).?;
        if (!sameOptional(current, record.fields, "triggers-pending") or !sameOptional(current, record.fields, "triggers-awaited"))
            return try std.fmt.allocPrint(a, "RecursiveTriggerActivation: {s}:{s} trigger state changed", .{ record.name, record.architecture });
        if (!objectsEqual(current, record.fields)) return try std.fmt.allocPrint(a, "ExternalTriggerCallback: {s}:{s} changed", .{ record.name, record.architecture });
    }
    if (!eq(u8, after.status.bytes, try expectedLibcBinStatus(run, before.status.bytes)))
        return "TriggerDatabaseChanged: status bytes differ from the one reviewed libc-bin transition";
    return null;
}

const HandlerFailure = struct { err: []const u8, state_error: ?[]const u8 };
fn writeHandlerRecord(ctx: Context, phase: []const u8, package: Package, command: []const []const u8, state: ?TriggerState, failure: ?HandlerFailure) !void {
    const a = ctx.a;
    var object: std.json.ObjectMap = .empty;
    try object.put(a, "schema", .{ .string = "io.github.cataggar.debz.reference-trigger-handler.v1" });
    try object.put(a, "selector", .{ .string = try package.selector(a) });
    try object.put(a, "archive_sha512", .{ .string = package.digest });
    try object.put(a, "argv", try stringsValue(a, command[3..]));
    try object.put(a, "postinst_argv", try stringsValue(a, &.{ "triggered", "ldconfig" }));
    try object.put(a, "phase", .{ .string = phase });
    const state_value: std.json.Value = if (state) |value| try triggerStateValue(a, value) else .null;
    try object.put(a, "state", state_value);
    if (failure) |value| {
        try object.put(a, "error", .{ .string = value.err });
        const state_error: std.json.Value = if (value.state_error) |text| .{ .string = text } else .null;
        try object.put(a, "state_error", state_error);
    }
    try writeTriggerJson(ctx, try std.fmt.allocPrint(a, "reference-trigger-libc-bin-{s}.json", .{phase}), .{ .object = object });
}
fn writeTransitionRecord(ctx: Context, verified: Result) !void {
    const a = ctx.a;
    var object: std.json.ObjectMap = .empty;
    try object.put(a, "schema", .{ .string = "io.github.cataggar.debz.reference-trigger-transition.v1" });
    try object.put(a, "argv", try stringsValue(a, &.{ "verify-transition", "amd64", "reference-trigger-libc-bin-before.status", "reference-trigger-libc-bin-after.status" }));
    try object.put(a, "returncode", .{ .integer = verified.code });
    try object.put(a, "stdout", .{ .string = try utf8Replace(a, verified.stdout[0..@min(verified.stdout.len, maximum_probe_output)]) });
    try object.put(a, "stderr", .{ .string = try utf8Replace(a, verified.stderr[0..@min(verified.stderr.len, maximum_probe_output)]) });
    try writeTriggerJson(ctx, "reference-trigger-libc-bin-transition.json", .{ .object = object });
}

fn runLibcBinTrigger(run: *TriggerRun, packages: []const Package) !void {
    const ctx = run.ctx;
    const a = ctx.a;
    const authority = ctx.trigger_authority orelse
        return run.refuse("IndependentTransitionUnavailable: no independent trigger authority; libc-bin:amd64 not executed", .{});
    const admitted = try admitLibcBinTrigger(run, packages);
    const package = admitted.package;
    const before = admitted.state;
    const command = ctx.argvFor(ctx.root, "none", "trigger_libc_bin", package, &.{}) catch |err| switch (err) {
        error.UnreviewedTriggerHandler => return run.refuse("UnreviewedTriggerHandler: unauthorized trigger operation", .{}),
        else => return err,
    };
    try ctx.write(ctx.evidence, "reference-trigger-libc-bin-before.status", before.status.bytes, false);
    try writeHandlerRecord(ctx, "before", package, command, before, null);
    try run.attempts.append(a, .{ .selector = try package.selector(a), .argv = command[3..], .outcome = "started" });
    const attempt = &run.attempts.items[run.attempts.items.len - 1];
    ctx.apply(command, ctx.evidence, "reference-install.stdout", "reference-install.stderr") catch |err| {
        const failure: anyerror = err;
        if (failure == error.OutOfMemory) return error.OutOfMemory;
        attempt.outcome = "failed";
        var state_error: ?[]const u8 = null;
        const failed: ?TriggerState = triggerState(run, &libc_bin_selector) catch |unreadable| switch (unreadable) {
            error.TriggerRefusal => blk: {
                state_error = run.reason;
                break :blk null;
            },
            else => return unreadable,
        };
        try writeHandlerRecord(ctx, "failed", package, command, failed, .{ .err = @errorName(failure), .state_error = state_error });
        return run.refuse("FailedTriggerHandler: libc-bin:amd64: {s}", .{@errorName(failure)});
    };
    attempt.outcome = "refused";
    const after = try triggerState(run, &libc_bin_selector);
    try ctx.write(ctx.evidence, "reference-trigger-libc-bin-after.status", after.status.bytes, false);
    try writeHandlerRecord(ctx, "after", package, command, after, null);
    if (try transitionRefusal(run, before, after)) |reason| return run.refuse("{s}", .{reason});
    const before_path = try join(a, ctx.evidence, "reference-trigger-libc-bin-before.status");
    const after_path = try join(a, ctx.evidence, "reference-trigger-libc-bin-after.status");
    const verified = ctx.run(&.{ authority, "verify-transition", "amd64", before_path, after_path }, 60, maximum_control_bytes) catch |err| {
        const failure: anyerror = err;
        if (failure == error.OutOfMemory) return error.OutOfMemory;
        return run.refuse("IndependentTransitionRefused: {s}", .{@errorName(failure)});
    };
    try writeTransitionRecord(ctx, verified);
    if (verified.code != 0)
        return run.refuse("IndependentTransitionRefused: {s}", .{strip(try utf8Replace(a, verified.stderr[0..@min(verified.stderr.len, 512)]))});
    attempt.outcome = "settled";
}

fn recordLess(_: void, left: TriggerRecord, right: TriggerRecord) bool {
    return switch (std.mem.order(u8, left.name, right.name)) {
        .lt => true,
        .gt => false,
        .eq => std.mem.lessThan(u8, left.architecture, right.architecture),
    };
}
fn retainTriggerTerminal(run: *TriggerRun, attempts: []const TriggerAttempt, reason: []const u8) !void {
    const ctx = run.ctx;
    const a = ctx.a;
    var state = try triggerState(run, &.{});
    var parse_error: ?[]const u8 = null;
    const records: []const TriggerRecord = triggerRecords(run, state.status.bytes) catch |err| switch (err) {
        error.TriggerRefusal => blk: {
            parse_error = run.reason;
            break :blk &.{};
        },
        else => return err,
    };
    var selected: std.ArrayList(TriggerRecord) = .empty;
    for (records) |record| if (record.fields.contains("triggers-pending") or record.fields.contains("triggers-awaited")) {
        try selected.append(a, record);
    };
    std.mem.sort(TriggerRecord, selected.items, {}, recordLess);
    if (selected.items.len != 0) {
        const selectors = try a.alloc(TriggerSelector, selected.items.len);
        for (selected.items, selectors) |record, *selector| selector.* = .{ .name = record.name, .architecture = record.architecture };
        const with_controls = try triggerState(run, selectors);
        if (!with_controls.status.same(state.status)) return error.TriggerStateChangedWhileRetainingTerminalEvidence;
        state = with_controls;
    }
    var accepted = std.json.Array.init(a);
    var attempt_values = std.json.Array.init(a);
    for (attempts) |attempt| {
        if (eq(u8, attempt.outcome, "settled")) try accepted.append(.{ .string = attempt.selector });
        var item: std.json.ObjectMap = .empty;
        try item.put(a, "selector", .{ .string = attempt.selector });
        try item.put(a, "argv", try stringsValue(a, attempt.argv));
        try item.put(a, "outcome", .{ .string = attempt.outcome });
        try attempt_values.append(.{ .object = item });
    }
    var pending = std.json.Array.init(a);
    for (selected.items) |record| {
        var item: std.json.ObjectMap = .empty;
        try item.put(a, "selector", .{ .string = try std.fmt.allocPrint(a, "{s}:{s}", .{ record.name, record.architecture }) });
        try item.put(a, "status", .{ .string = field(record.fields, "status") });
        try item.put(a, "triggers_pending", .{ .string = field(record.fields, "triggers-pending") });
        try item.put(a, "triggers_awaited", .{ .string = field(record.fields, "triggers-awaited") });
        try pending.append(.{ .object = item });
    }
    var object: std.json.ObjectMap = .empty;
    try object.put(a, "schema", .{ .string = "io.github.cataggar.debz.reference-trigger-terminal.v1" });
    try object.put(a, "architecture", .{ .string = ctx.architecture });
    try object.put(a, "reason", .{ .string = reason });
    try object.put(a, "attempts", .{ .array = attempt_values });
    try object.put(a, "accepted", .{ .array = accepted });
    try object.put(a, "pending", .{ .array = pending });
    const parse_value: std.json.Value = if (parse_error) |text| .{ .string = text } else .null;
    try object.put(a, "status_parse_error", parse_value);
    try object.put(a, "state", try triggerStateValue(a, state));
    try object.put(a, "pending_operation_authorized", .{ .bool = false });
    try writeTriggerJson(ctx, "reference-trigger-terminal.json", .{ .object = object });
}

fn settleTriggers(run: *TriggerRun, packages: []const Package) !void {
    const ctx = run.ctx;
    const a = ctx.a;
    if (!eq(u8, ctx.architecture, "amd64"))
        return run.refuse("UnreviewedTriggerHandler: no reviewed handler or observed pre-handler state for {s}", .{ctx.architecture});
    try runLibcBinTrigger(run, packages);
    const records = try triggerRecords(run, (try triggerState(run, &.{})).status.bytes);
    var unsettled: std.ArrayList([]const u8) = .empty;
    for (records) |record| {
        const fields = record.fields;
        if (eq(u8, field(fields, "status"), "install ok installed") and !fields.contains("triggers-pending") and !fields.contains("triggers-awaited")) continue;
        const detail = if (fields.get("triggers-pending")) |value| value.string else field(fields, "status");
        try unsettled.append(a, try std.fmt.allocPrint(a, "{s}:{s} ({s})", .{ record.name, record.architecture, detail }));
    }
    if (unsettled.items.len == 0) return;
    std.mem.sort([]const u8, unsettled.items, {}, bytesLess);
    return run.refuse("UnreviewedTriggerHandler: {s}: no reviewed signed handler; --pending and multi-package trigger processing are not authorized", .{try std.mem.join(a, ", ", unsettled.items[0..@min(unsettled.items.len, 20)])});
}
/// Settles the one reviewed handler, or refuses after retaining the exact terminal trigger bytes.
pub fn processTriggers(ctx: Context, packages: []const Package) !void {
    var run: TriggerRun = .{ .ctx = ctx };
    settleTriggers(&run, packages) catch |err| switch (err) {
        error.TriggerRefusal => {
            var retention: TriggerRun = .{ .ctx = ctx };
            var note: ?[]const u8 = null;
            retainTriggerTerminal(&retention, run.attempts.items, run.reason) catch |retained| {
                const failure: anyerror = retained;
                if (failure == error.OutOfMemory) return error.OutOfMemory;
                note = if (failure == error.TriggerRefusal) retention.reason else @errorName(failure);
            };
            if (builtin.is_test) if (ctx.test_hooks) |hooks| if (hooks.trigger_refusal) |callback| {
                try callback(hooks.state, run.reason);
                return error.TriggerRefusal;
            };
            paths.writeAll(2, try std.fmt.allocPrint(ctx.a, "{s}\n", .{run.reason})) catch {};
            if (note) |text| paths.writeAll(2, try std.fmt.allocPrint(ctx.a, "terminal trigger evidence was not retained: {s}\n", .{text})) catch {};
            return error.TriggerRefusal;
        },
        else => return err,
    };
}

// Python json.dumps(value, sort_keys=True) + "\n": ", "/": " separators, ASCII-only
// escapes, and file names ordered by their surrogateescape code points.
const PythonCodepoint = struct { value: u21, size: usize };
fn pythonCodepoint(text: []const u8, index: usize) PythonCodepoint {
    const escaped: PythonCodepoint = .{ .value = 0xdc00 + @as(u21, text[index]), .size = 1 };
    const length = std.unicode.utf8ByteSequenceLength(text[index]) catch return escaped;
    if (length > text.len - index) return escaped;
    const value = std.unicode.utf8Decode(text[index..][0..length]) catch return escaped;
    return .{ .value = value, .size = length };
}
fn pythonKeyLess(_: void, left: []const u8, right: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (i < left.len and j < right.len) {
        const l = pythonCodepoint(left, i);
        const r = pythonCodepoint(right, j);
        if (l.value != r.value) return l.value < r.value;
        i += l.size;
        j += r.size;
    }
    return i == left.len and j < right.len;
}
fn pythonJsonString(a: A, output: *std.ArrayList(u8), text: []const u8) error{OutOfMemory}!void {
    try output.append(a, '"');
    var index: usize = 0;
    while (index < text.len) {
        const point = pythonCodepoint(text, index);
        index += point.size;
        switch (point.value) {
            '"' => try output.appendSlice(a, "\\\""),
            '\\' => try output.appendSlice(a, "\\\\"),
            '\n' => try output.appendSlice(a, "\\n"),
            '\r' => try output.appendSlice(a, "\\r"),
            '\t' => try output.appendSlice(a, "\\t"),
            0x08 => try output.appendSlice(a, "\\b"),
            0x0c => try output.appendSlice(a, "\\f"),
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try output.append(a, @intCast(point.value)),
            0x10000...0x10ffff => {
                const value = point.value - 0x10000;
                try output.print(a, "\\u{x:0>4}\\u{x:0>4}", .{ 0xd800 + (value >> 10), 0xdc00 + (value & 0x3ff) });
            },
            else => try output.print(a, "\\u{x:0>4}", .{point.value}),
        }
    }
    try output.append(a, '"');
}
fn pythonJsonValue(a: A, output: *std.ArrayList(u8), value: std.json.Value) error{ OutOfMemory, UnsupportedTriggerEvidenceValue }!void {
    switch (value) {
        .null => try output.appendSlice(a, "null"),
        .bool => |flag| try output.appendSlice(a, if (flag) "true" else "false"),
        .integer => |number| try output.print(a, "{d}", .{number}),
        .string => |text| try pythonJsonString(a, output, text),
        .array => |items| {
            try output.append(a, '[');
            for (items.items, 0..) |item, index| {
                if (index != 0) try output.appendSlice(a, ", ");
                try pythonJsonValue(a, output, item);
            }
            try output.append(a, ']');
        },
        .object => |object| {
            const keys = try a.dupe([]const u8, object.keys());
            std.mem.sort([]const u8, keys, {}, pythonKeyLess);
            try output.append(a, '{');
            for (keys, 0..) |key, index| {
                if (index != 0) try output.appendSlice(a, ", ");
                try pythonJsonString(a, output, key);
                try output.appendSlice(a, ": ");
                try pythonJsonValue(a, output, object.get(key).?);
            }
            try output.append(a, '}');
        },
        else => return error.UnsupportedTriggerEvidenceValue,
    }
}
pub fn pythonJson(a: A, value: std.json.Value) ![]const u8 {
    var output: std.ArrayList(u8) = .empty;
    try pythonJsonValue(a, &output, value);
    try output.append(a, '\n');
    return output.toOwnedSlice(a);
}
fn writeTriggerJson(ctx: Context, name: []const u8, value: std.json.Value) !void {
    try ctx.write(ctx.evidence, name, try pythonJson(ctx.a, value), false);
}
fn stringsValue(a: A, items: []const []const u8) !std.json.Value {
    var array = std.json.Array.init(a);
    for (items) |item| try array.append(.{ .string = item });
    return .{ .array = array };
}
fn triggerFileValue(a: A, file: TriggerFile) !std.json.Value {
    const encoded = try a.alloc(u8, std.base64.standard.Encoder.calcSize(file.bytes.len));
    var object: std.json.ObjectMap = .empty;
    try object.put(a, "size", .{ .integer = @intCast(file.bytes.len) });
    try object.put(a, "mode", .{ .integer = file.mode });
    try object.put(a, "uid", .{ .integer = file.uid });
    try object.put(a, "gid", .{ .integer = file.gid });
    try object.put(a, "nlink", .{ .integer = file.nlink });
    try object.put(a, "sha256", .{ .string = try a.dupe(u8, &hash(std.crypto.hash.sha2.Sha256, file.bytes)) });
    try object.put(a, "sha512", .{ .string = try a.dupe(u8, &hash(std.crypto.hash.sha2.Sha512, file.bytes)) });
    try object.put(a, "content_base64", .{ .string = std.base64.standard.Encoder.encode(encoded, file.bytes) });
    return .{ .object = object };
}
fn triggerEntriesValue(a: A, entries: []const TriggerEntry) !std.json.Value {
    var object: std.json.ObjectMap = .empty;
    for (entries) |entry| try object.put(a, entry.name, try triggerFileValue(a, entry.file));
    return .{ .object = object };
}
fn triggerStateValue(a: A, state: TriggerState) !std.json.Value {
    var owner = std.json.Array.init(a);
    try owner.append(.{ .integer = state.owner[0] });
    try owner.append(.{ .integer = state.owner[1] });
    var object: std.json.ObjectMap = .empty;
    try object.put(a, "owner", .{ .array = owner });
    try object.put(a, "status", try triggerFileValue(a, state.status));
    try object.put(a, "updates", try triggerEntriesValue(a, state.updates));
    try object.put(a, "trigger_database", try triggerEntriesValue(a, state.trigger_database));
    try object.put(a, "controls", try triggerEntriesValue(a, state.controls));
    try object.put(a, "controls_truncated", .{ .bool = state.controls_truncated });
    return .{ .object = object };
}
// --- #265 single signed trigger handler (end) -----------------------------------

fn jsonWrite(serializer: *std.json.Stringify, value: anytype) !void {
    const T = @TypeOf(value);
    if (T == Fields) return serializer.write(std.json.Value{ .object = value });
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            try serializer.beginObject();
            inline for (info.fields) |item| {
                try serializer.objectField(item.name);
                try jsonWrite(serializer, @field(value, item.name));
            }
            try serializer.endObject();
        },
        .pointer => |info| switch (info.size) {
            .one => try jsonWrite(serializer, value.*),
            .slice => {
                if (info.child == u8) return serializer.write(value);
                try serializer.beginArray();
                for (value) |item| try jsonWrite(serializer, item);
                try serializer.endArray();
            },
            else => @compileError("unsupported reference evidence pointer"),
        },
        .array => |info| {
            if (info.child == u8) return serializer.write(&value);
            try serializer.beginArray();
            for (value) |item| try jsonWrite(serializer, item);
            try serializer.endArray();
        },
        else => try serializer.write(value),
    }
}

fn findPackage(packages: []const Package, name: []const u8) ?usize {
    for (packages, 0..) |package, index| if (eq(u8, package.name, name)) return index;
    return null;
}
fn unpackedSet(packages: []const Package, states: anytype, names: []const []const u8) bool {
    for (names) |name| {
        const index = findPackage(packages, name) orelse return false;
        if (states[index] != .unpacked) return false;
    }
    return true;
}
pub fn validateTargets(a: A, packages: []const Package, prestates: []const Prestate) !void {
    for (prestates, 0..) |target, index| {
        for (prestates[0..index]) |previous| {
            if (eq(u8, previous.selector, target.selector)) return error.DuplicatePrestateSelector;
            if (eq(u8, previous.destination, target.destination)) return error.DuplicatePrestateDestination;
        }
        var included = false;
        for (packages) |package| if (eq(u8, try package.selector(a), target.selector)) {
            included = true;
        };
        if (!included) return error.PrestatePackageNotInVerifiedClosure;
        if (eq(u8, target.selector, "sudo:amd64")) {
            var companions: usize = 0;
            for (packages) |package| if (eq(u8, package.name, "sudo-rs")) {
                companions += 1;
                if (!eq(u8, package.version, "0.2.13-0ubuntu1.2") or !eq(u8, package.architecture, "amd64")) return error.SignedSudoPrestateExactCompanionRequired;
            };
            if (companions != 1) return error.SignedSudoPrestateExactCompanionRequired;
        }
    }
}
fn utf8Replace(a: A, bytes: []const u8) ![]const u8 {
    var result: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < bytes.len) {
        const first = bytes[index];
        const size: usize = if (first < 0x80) 1 else if (first >= 0xc2 and first <= 0xdf) 2 else if (first >= 0xe0 and first <= 0xef) 3 else if (first >= 0xf0 and first <= 0xf4) 4 else 0;
        var prefix: usize = 1;
        while (prefix < size and prefix < bytes.len - index) : (prefix += 1) {
            const next = bytes[index + prefix];
            if (next < 0x80 or next > 0xbf) break;
            if (prefix == 1 and ((first == 0xe0 and next < 0xa0) or (first == 0xed and next > 0x9f) or
                (first == 0xf0 and next < 0x90) or (first == 0xf4 and next > 0x8f))) break;
        }
        if (size == 0 or prefix != size) {
            try result.appendSlice(a, "\xef\xbf\xbd");
        } else try result.appendSlice(a, bytes[index..][0..size]);
        index += prefix;
    }
    return result.toOwnedSlice(a);
}
fn refusal(a: A, package: Package, operation: []const u8, result: Result) !Refusal {
    const prefix = result.stdout[0..@min(result.stdout.len, 4096)];
    const hex = try a.alloc(u8, prefix.len * 2);
    const digits = "0123456789abcdef";
    for (prefix, 0..) |byte, index| {
        hex[2 * index] = digits[byte >> 4];
        hex[2 * index + 1] = digits[byte & 15];
    }
    return .{ .selector = try package.selector(a), .operation = operation, .exit_status = result.code, .output_bytes = result.stdout.len, .output_prefix_hex = hex, .output_sha512 = try a.dupe(u8, &hash(std.crypto.hash.sha2.Sha512, result.stdout)) };
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    var values: std.StringHashMap([]const u8) = .init(a);
    var prestates: std.ArrayList(Prestate) = .empty;
    var report_only = false;
    var index: usize = 1;
    while (index < args.len) {
        const key = args[index];
        index += 1;
        if (eq(u8, key, "--report-only")) {
            report_only = true;
            continue;
        }
        if (index == args.len) return error.InvalidReferenceOrderArguments;
        const value = args[index];
        index += 1;
        if (eq(u8, key, "--prestate")) {
            try prestates.append(a, try parsePrestate(value));
            continue;
        }
        var accepted = false;
        for ([_][]const u8{ "--dpkg", "--root", "--cache", "--evidence", "--prove-base-cycle", "--launcher", "--runtime", "--architecture", "--trigger-authority" }) |allowed|
            if (eq(u8, key, allowed)) {
                accepted = true;
            };
        if (!accepted) return error.InvalidReferenceOrderArguments;
        try values.put(key, value);
    }
    var environment: std.process.Environ.Map = .init(a);
    for ([_][2][]const u8{
        .{ "PATH", "/usr/sbin:/usr/bin:/sbin:/bin" }, .{ "HOME", "/" },                           .{ "LC_ALL", "C" },
        .{ "DEBIAN_FRONTEND", "noninteractive" },     .{ "DEBCONF_NONINTERACTIVE_SEEN", "true" }, .{ "DPKG_COLORS", "never" },
    }) |entry| try environment.put(entry[0], entry[1]);
    const root = values.get("--root") orelse return error.InvalidReferenceOrderArguments;
    const cache = values.get("--cache") orelse return error.InvalidReferenceOrderArguments;
    const evidence = values.get("--evidence") orelse return error.InvalidReferenceOrderArguments;
    const architecture = values.get("--architecture") orelse return error.InvalidReferenceOrderArguments;
    if (!eq(u8, architecture, "amd64") and !eq(u8, architecture, "arm64")) return error.InvalidReferenceOrderArguments;
    for ([_][]const u8{ root, cache, evidence }) |path| try paths.absolute(path);
    var context: Context = .{ .a = a, .io = init.io, .environment = &environment, .root = root, .cache = cache, .evidence = evidence, .architecture = architecture, .dpkg = values.get("--dpkg") orelse "", .launcher = .{ .path = values.get("--launcher") orelse "", .runtime = values.get("--runtime") orelse "" } };
    if (report_only) return context.report();
    _ = try paths.protected(context.launcher.path, false);
    _ = try paths.protected(context.dpkg, false);
    _ = try paths.protected(context.launcher.runtime, true);
    _ = try paths.protected(cache, true);
    _ = try paths.protected(evidence, true);
    if (values.get("--trigger-authority")) |authority| {
        if (authority.len == 0 or authority[0] != '/' or prestates.items.len != 0 or values.get("--prove-base-cycle") != null) {
            paths.writeAll(2, "IndependentTransitionUnavailable: invalid trigger authority request\n") catch {};
            return error.TriggerRefusal;
        }
        _ = try paths.protected(authority, false);
        context.trigger_authority = authority;
    }
    if (values.get("--prove-base-cycle")) |setpriv| {
        if (!eq(u8, architecture, "amd64") or prestates.items.len != 0) return error.CycleProofPrestate;
        return proveBaseCycle(context, setpriv);
    }
    return context.install(prestates.items);
}

pub fn proveBaseCycle(ctx: Context, setpriv: []const u8) !void {
    const unit_proof = if (builtin.is_test) if (ctx.test_hooks) |hooks| hooks.assume_x86_64 else false else false;
    if ((builtin.cpu.arch != .x86_64 and !unit_proof) or (try ctx.database(ctx.root)).len != 0) return error.CycleProofPrestate;
    const unit_source = if (builtin.is_test) if (ctx.test_hooks) |hooks| hooks.runtime_unprotected else false else false;
    if (!unit_source) _ = try paths.protected(ctx.root, true);
    const setpriv_pin = try (if (unit_source) paths.openAbsolute(setpriv, false) else paths.openProtected(setpriv, false));
    defer setpriv_pin.close();
    const setpriv_bytes = try paths.readPinned(ctx.a, setpriv_pin, maximum_control_bytes);
    var setpriv_digest = hash(std.crypto.hash.sha2.Sha256, setpriv_bytes);
    if (builtin.is_test) if (ctx.test_hooks) |hooks| if (hooks.runtime_digest) |callback| if (callback(setpriv_bytes)) |provided| {
        setpriv_digest = provided;
    };
    if (!eq(u8, &setpriv_digest, "86965a019d37dc11d176ce8cbe9f5f5f8f37027c95e03cb4a8cad4c73d940993"))
        return error.CycleProofRuntimeChanged;
    const cycle = try cyclePackages(ctx.a, try ctx.manifest(), "amd64", .base);
    const proof = try join(ctx.a, ctx.evidence, "base-cycle-proof");
    const evidence_pin = try paths.openAbsolute(ctx.evidence, true);
    defer evidence_pin.close();
    _ = try paths.syscall(linux.mkdirat(evidence_pin.fd, "base-cycle-proof", 0o700));
    const seed = try join(ctx.a, proof, "seed");
    try ctx.checked(&.{ "cp", "-a", "--one-file-system", "--", ctx.root, seed }, 60);
    for ([_]usize{ 2, 3, 0, 1 }) |index| {
        try ctx.archive(cycle[index]);
        try ctx.apply(try ctx.argvFor(seed, "none", "unpack", cycle[index], &.{}), proof, "unpack.stdout", "unpack.stderr");
    }
    for (cycle[2..]) |package| try ctx.apply(try ctx.argvFor(seed, "none", "configure", package, &.{}), proof, "unpack.stdout", "unpack.stderr");
    _ = try ctx.verifyCycle(seed, cycle, .base);
    for (cycle[0..2]) |package| {
        const result = try ctx.probe(try ctx.argvFor(seed, "none", "probe_configure", package, &.{}), proof);
        if (result.code == 0 or std.mem.indexOf(u8, result.stdout, "dependency problems") == null) return error.CycleProofMissingStall;
    }
    const candidate = try join(ctx.a, proof, "candidate");
    const baseline = try join(ctx.a, proof, "pending");
    for ([_][]const u8{ candidate, baseline }) |destination| try ctx.checked(&.{ "cp", "-a", "--one-file-system", "--", seed, destination }, 60);
    const refused_command = try ctx.argvFor(candidate, Cycle.base.profile(), Cycle.base.verb(), cycle[1], cycle);
    const before_refusal = try ctx.database(candidate);
    const before_triggers = try ctx.triggerDatabase(candidate);
    const injected = "var/lib/dpkg/info/libgcc-s1:amd64.postinst";
    const injected_path = try join(ctx.a, candidate, injected);
    try ctx.write(candidate, injected, "#!/bin/sh\necho unbound-cycle-callback-executed\nexit 0\n", false);
    try ctx.checked(&.{ "chmod", "0755", "--", try join(ctx.a, candidate, injected) }, 30);
    const refusal_result = blk: {
        defer ctx.checked(&.{ "rm", "--", injected_path }, 30) catch {};
        const observed = try ctx.probe(refused_command, proof);
        if (observed.code == 0 or std.mem.indexOf(u8, observed.stdout, "unbound-cycle-callback-executed") != null or
            std.mem.indexOf(u8, observed.stdout, "stage 11") == null or !conserved(before_refusal, try ctx.database(candidate), &.{}) or
            !objectsEqual(before_triggers, try ctx.triggerDatabase(candidate))) return error.CycleProofCallbackChanged;
        break :blk observed;
    };
    try ctx.write(proof, "callback-refusal.log", refusal_result.stdout, false);
    _ = try ctx.transition(candidate, proof, cycle, .base, "candidate.stdout", "candidate.stderr");
    if ((try ctx.database(baseline)).len != 4) return error.CycleProofCallbackChanged;
    _ = try ctx.verifyCycle(baseline, cycle, .base);
    var script_relative: ?[]const u8 = null;
    for ([_][]const u8{ "var/lib/dpkg/info/libc6.postinst", "var/lib/dpkg/info/libc6:amd64.postinst" }) |relative| {
        if (try paths.exists(baseline, relative)) {
            if (script_relative != null) return error.CycleProofCallbackChanged;
            script_relative = relative;
        }
    }
    const relative = script_relative orelse return error.CycleProofCallbackChanged;
    const script = try join(ctx.a, baseline, relative);
    const signed_script = try member(try ctx.control(cycle[0]), "./postinst");
    if (signed_script.len == 0 or !eq(u8, signed_script, try ctx.read(baseline, relative, maximum_probe_output))) return error.CycleProofCallbackChanged;
    try ctx.checked(&.{ "cp", "--", ctx.dpkg, try join(ctx.a, baseline, "usr/bin/dpkg") }, 30);
    try ctx.checked(&.{ "cp", "--", setpriv, try join(ctx.a, baseline, "usr/bin/setpriv") }, 30);
    try ctx.checked(&.{ "chmod", "0755", "--", try join(ctx.a, baseline, "usr/bin/setpriv") }, 30);
    const runtime = try stagePendingRuntime(ctx, baseline, setpriv);
    const before_pending = try ctx.database(baseline);
    try ctx.checked(&.{ "mount", "--bind", "--", script, script }, 30);
    const command: []const []const u8 = &.{
        "unshare",          "--mount",                                                                           "--pid",           "--fork",              "--kill-child=SIGKILL", "--propagation", "private",  "--",               "chroot",           baseline,
        "/usr/bin/setpriv", "--bounding-set=-all,+chown,+dac_override,+fowner,+fsetid,+setgid,+setuid,+setfcap", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",       "/usr/bin/dpkg", "--root=/", "--force-not-root", "--force-bad-path", "--force-confold",
        "--no-triggers",    "--configure",                                                                       "--pending",
    };
    const observed = blk: {
        errdefer ctx.checked(&.{ "umount", "--", script }, 30) catch {};
        try ctx.checked(&.{ "mount", "-o", "remount,bind,ro,noexec,nosuid,nodev", "--", script }, 30);
        const scratch_dir = try ctx.scratch(proof, "reference-pending");
        defer ctx.cleanupScratch(scratch_dir, &.{ "stdout", "stderr" });
        const result = try ctx.capture(command, scratch_dir, "stdout", "stderr", 120);
        try recordPendingResult(ctx, proof, command, result, runtime);
        break :blk result;
    };
    try ctx.checked(&.{ "umount", "--", script }, 30);
    const after_pending = try ctx.database(baseline);
    try ctx.json(proof, "pending-status.json", .{ .before = before_pending, .after = after_pending, .trigger_database = try ctx.triggerDatabase(baseline) });
    try validatePendingResult(observed);
    if (!eq(u8, signed_script, try ctx.read(baseline, relative, maximum_probe_output))) return error.CycleProofCallbackChanged;
    const wanted = try ctx.database(candidate);
    const expected = try ctx.a.alloc(Fields, wanted.len);
    for (wanted, expected) |record, *copy| {
        copy.* = try record.clone(ctx.a);
        if (eq(u8, field(record, "package"), "libc6") and eq(u8, field(record, "architecture"), "amd64"))
            try copy.put(ctx.a, "status", .{ .string = "install ok half-configured" });
    }
    if (!conserved(expected, after_pending, &.{})) return error.CycleProofScheduleChanged;
    try ctx.json(proof, "comparison.json", .{
        .schema = "io.github.cataggar.debz.base-cycle-proof.v1",
        .callbacks_executed = @as([]const []const u8, &.{}),
        .callback_denied = "libc6 postinst configure",
        .candidate = wanted,
        .pending = after_pending,
        .candidate_trigger_database = try ctx.triggerDatabase(candidate),
        .pending_trigger_database = try ctx.triggerDatabase(baseline),
        .pending_argv = command,
        .pending_setpriv_runtime = runtime,
        .difference = "pending attempts libc6 configure; single breaker leaves libc6 unpacked",
        .parity_claim = false,
    });
    for ([_][]const u8{ seed, candidate, baseline }) |destination| try ctx.checked(&.{ "rm", "-rf", "--one-file-system", "--", destination }, 60);
}
pub const PendingRuntime = struct { source: []const u8, target: []const u8, sha256: []const u8, size: usize, mode: []const u8 };
pub fn recordPendingResult(ctx: Context, proof: []const u8, command: []const []const u8, result: Result, runtime: PendingRuntime) !void {
    try ctx.write(proof, "pending.stdout", result.stdout[0..@min(result.stdout.len, maximum_probe_output)], false);
    try ctx.write(proof, "pending.stderr", result.stderr[0..@min(result.stderr.len, maximum_probe_output)], false);
    try ctx.json(proof, "pending-result.json", .{
        .schema = "io.github.cataggar.debz.base-cycle-pending-result.v1",
        .argv = command,
        .returncode = result.code,
        .setpriv_runtime = runtime,
        .stdout_bytes = result.stdout_bytes,
        .stderr_bytes = result.stderr_bytes,
        .output_truncated = result.stdout_bytes > maximum_probe_output or result.stderr_bytes > maximum_probe_output,
    });
}
pub fn validatePendingResult(result: Result) !void {
    if (result.stdout_bytes > maximum_probe_output or result.stderr_bytes > maximum_probe_output or result.code == 0 or
        std.mem.indexOf(u8, result.stderr, "Permission denied") == null or std.mem.indexOf(u8, result.stderr, "post-installation script") == null)
        return error.CycleProofCallbackChanged;
}
pub fn stagePendingRuntime(ctx: Context, baseline: []const u8, setpriv: []const u8) !PendingRuntime {
    const parent = std.fs.path.dirname(setpriv).?;
    const source = try join(ctx.a, parent, "libcap-ng.so.0.0.0");
    const unit_source = if (builtin.is_test) if (ctx.test_hooks) |hooks| hooks.runtime_unprotected else false else false;
    const pin = (if (unit_source) paths.openAbsolute(source, false) else paths.openProtected(source, false)) catch return error.CycleProofRuntimeChanged;
    defer pin.close();
    if (pin.metadata.size != 26928 or pin.metadata.mode & 0o7777 != 0o644) return error.CycleProofRuntimeChanged;
    const data = try paths.readPinned(ctx.a, pin, 26928);
    var digest_bytes = hash(std.crypto.hash.sha2.Sha256, data);
    if (builtin.is_test) if (ctx.test_hooks) |hooks| if (hooks.runtime_digest) |callback| if (callback(data)) |provided| {
        digest_bytes = provided;
    };
    const digest = try ctx.a.dupe(u8, &digest_bytes);
    if (!eq(u8, digest, "60c767df6642a42ee28bf9a5b8975fe7ed59d4d87372b2737ccdf1a0ef1b268f")) return error.CycleProofRuntimeChanged;
    const target = "usr/lib/x86_64-linux-gnu/libcap-ng.so.0";
    if (!unit_source) _ = paths.protected(try join(ctx.a, baseline, "usr/lib/x86_64-linux-gnu"), true) catch return error.CycleProofRuntimeChanged;
    const fd = paths.create(baseline, target, 0o644, false) catch return error.CycleProofRuntimeChanged;
    defer _ = linux.close(fd);
    try paths.writeAll(fd, data);
    _ = try paths.syscall(linux.fchmod(fd, 0o644));
    return .{ .source = source, .target = target, .sha256 = digest, .size = data.len, .mode = "0644" };
}

test "original status records retain valueless continuations and reject ambiguous identities" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const valid = "Package: demo\nArchitecture: amd64\nVersion: 1\nStatus: install ok unpacked\nConffiles:\n /etc/demo.conf 0123456789abcdef\n\n";
    const records = try parseDatabase(a, valid);
    try std.testing.expectEqualStrings("\n /etc/demo.conf 0123456789abcdef", field(records[0], "conffiles"));
    for ([_][]const u8{ "Priority:optional", "Bad Key: x", "Conffiles" }) |malformed| {
        const data = try std.fmt.allocPrint(a, "{s}{s}\n", .{ valid[0 .. valid.len - 1], malformed });
        try std.testing.expectError(error.MalformedReferenceDatabaseField, controlFields(a, data));
    }
    try std.testing.expectError(error.DuplicateReferenceDatabaseField, controlFields(a, "Package: demo\npackage: other\n"));
    try std.testing.expectError(error.InvalidReferenceIdentityContinuation, controlFields(a, "Package: demo\n changed\n"));
}

test "normal command binding refuses triggers pending mixed selectors and wrong signed profiles" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const launcher: Launcher = .{ .path = "/launcher", .runtime = "/runtime" };
    const package: Package = .{ .name = "sudo", .version = "1.9.17p2-1ubuntu3.1", .architecture = "amd64", .digest = "a" ** 128, .size = 42, .archive = "/sudo.deb" };
    const command = try dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "sudo", "configure", package, &.{});
    try std.testing.expectEqualStrings("sudo:amd64", command[6]);
    for ([_][]const u8{ "triggers_only", "triggers_pending", "configure_pending" }) |verb|
        try std.testing.expectError(error.NoSingleScriptBinding, dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "sudo", verb, package, &.{}));
    try std.testing.expectError(error.MissingExactConfigureProfile, dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "none", "configure", package, &.{}));
    try std.testing.expectError(error.UnauthorizedReferenceScriptProfile, dpkgCommand(a, launcher, "/dpkg", "/root", "arm64", "sudo", "configure", package, &.{}));
    try std.testing.expectError(error.UnauthorizedHalfConfiguredContinuation, dpkgCommand(a, launcher, "/dpkg", "/root", "amd64", "sudo", "continue_prestate", package, &.{}));
}

test "five-field original TSV enforces duplicates decimal bounds and empty closures" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const line = "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t42\n";
    const package = (try packagesFromManifest(a, line, "/cache"))[0];
    try std.testing.expectEqualStrings("/cache/packages-v2/objects/sha512-" ++ "a" ** 128, package.archive);
    try std.testing.expectError(error.DuplicateReferencePackage, packagesFromManifest(a, line ++ line, "/cache"));
    try std.testing.expectError(error.InvalidReferenceArchiveManifest, packagesFromManifest(a, "demo\t1\tamd64\ta\t42\textra\n", "/cache"));
    try std.testing.expectError(error.InvalidReferenceArchiveSize, packagesFromManifest(a, "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t0\n", "/cache"));
    try std.testing.expectError(error.InvalidReferenceArchiveSize, packagesFromManifest(a, "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t536870913\n", "/cache"));
    try std.testing.expectError(error.InvalidReferencePackageIdentity, packagesFromManifest(a, "demo\t1\tamd64\t" ++ "a" ** 128 ++ "\t+42\n", "/cache"));
    try std.testing.expectError(error.EmptyReferenceClosure, packagesFromManifest(a, "", "/cache"));
}

test "original refusal diagnostics use Python replacement boundaries without altering raw observations" {
    const replacement = "\xef\xbf\xbd";
    for ([_][2][]const u8{
        .{ "ok\xc2\xa0\xe2\x82\xac\xf0\x90\x80\x80", "ok\xc2\xa0\xe2\x82\xac\xf0\x90\x80\x80" },
        .{ "\xe2\x82", replacement },
        .{ "\xf0\x90\x80", replacement },
        .{ "\xe2\x82!", replacement ++ "!" },
        .{ "\xe2!", replacement ++ "!" },
        .{ "\xe0\x9f\x80", replacement ** 3 },
        .{ "\xed\xa0\x80", replacement ** 3 },
        .{ "\xf4\x90\x80\x80", replacement ** 4 },
        .{ "\xf5\x80\x80\x80", replacement ** 4 },
        .{ "\xc0\x80\xff", replacement ** 3 },
    }) |example| {
        const observed = try utf8Replace(std.testing.allocator, example[0]);
        defer std.testing.allocator.free(observed);
        try std.testing.expectEqualStrings(example[1], observed);
    }
}
