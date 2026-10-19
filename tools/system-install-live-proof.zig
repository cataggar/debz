const std = @import("std");
const builtin = @import("builtin");

const ROOT = "/";
const DPKG = "var/lib/dpkg";
const STATUS = DPKG ++ "/status";
const STATE = "var/lib/debz";
const EVIDENCE = STATE ++ "/system-install";
const OPERATIONS = EVIDENCE ++ "/operations";
const LOCKS = STATE ++ "/locks";
const CACHE = "var/cache/debz";
const LOGICAL_ROOT = "/run/debz/system-root";
const SCHEMA = "https://debz.dev/schema/";
const GENERATION = "system-install-execution-v1";
const BOUND = 1209600;
const SIGNER = "BC528686B50D79E339D3721CEB3E94ADBE1229CF";
const SOURCE = "/etc/apt/sources.list.d/microsoft-prod.list";
const KEYRING = "/usr/share/keyrings/microsoft-prod.gpg";
const DERIVED = "signed_sha256_derived_sha512";
const PRIVILEGE = "system install requires root privilege (run with sudo); nothing was changed";
const ABSENT_PACKAGE = "debz-live-proof-absent";
const ABSENT = "package has no available candidate; nothing was changed";
const PENDING = GENERATION ++ " is not available in this build; nothing was changed; the exact lock is retained";
const MIB = 1024 * 1024;
const FILE_LIMIT = 64 * MIB;
const TREE_LIMIT = 256 * MIB;

const ProofError = error{ProofFailure};

var last_failure_message: ?[]const u8 = null;

fn fail(comptime fmt: []const u8, args: anytype) ProofError {
    if (std.fmt.allocPrint(std.heap.page_allocator, fmt, args)) |msg| {
        last_failure_message = msg;
    } else |_| {
        last_failure_message = "proof check failed";
    }
    return error.ProofFailure;
}

fn require(condition: bool, message: []const u8) ProofError!void {
    if (!condition) {
        last_failure_message = message;
        return error.ProofFailure;
    }
}

fn isLowerHex(text: []const u8, expected_len: usize) bool {
    if (text.len != expected_len) return false;
    for (text) |c| {
        if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return false;
    }
    return true;
}

fn isNonEmptyLowerHex(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |c| {
        if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return false;
    }
    return true;
}

fn containsAsciiCaseInsensitive(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn sha512Hex(data: []const u8) [128]u8 {
    var digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn requestSha512(allocator: std.mem.Allocator, package: []const u8, backend: []const u8) ![]const u8 {
    const raw = try std.fmt.allocPrint(allocator, "debz system install request v1\x00{s}\x00{s}\x00/", .{ package, backend });
    const hex = sha512Hex(raw);
    return allocator.dupe(u8, &hex);
}

fn profileObject(allocator: std.mem.Allocator, arch: []const u8) !std.json.ObjectMap {
    var profile: std.json.ObjectMap = .empty;
    try profile.put(allocator, "name", .{ .string = "system_default" });
    try profile.put(allocator, "root", .{ .string = "/" });
    try profile.put(allocator, "cache_path", .{ .string = "/var/cache/debz" });
    try profile.put(allocator, "state_path", .{ .string = "/var/lib/debz" });
    try profile.put(allocator, "locks_path", .{ .string = "/var/lib/debz/locks" });
    try profile.put(allocator, "evidence_path", .{ .string = "/var/lib/debz/system-install" });
    try profile.put(allocator, "architecture", .{ .string = arch });
    try profile.put(allocator, "conffile", .{ .string = "keep_existing" });
    try profile.put(allocator, "noninteractive", .{ .bool = true });
    return profile;
}

fn parseJson(allocator: std.mem.Allocator, raw: []const u8, label: []const u8) !std.json.Value {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
        .max_value_len = FILE_LIMIT,
        .parse_numbers = false,
    }) catch |err| return fail("{s}: invalid JSON ({s})", .{ label, @errorName(err) });
    return parsed.value;
}

fn jsonEqual(a: std.json.Value, b: std.json.Value) bool {
    switch (a) {
        .null => return b == .null,
        .bool => |av| return b == .bool and av == b.bool,
        .integer => |av| return switch (b) {
            .integer => |bv| av == bv,
            .number_string => |bv| (std.fmt.parseInt(i64, bv, 10) catch return false) == av,
            else => false,
        },
        .float => |av| return b == .float and av == b.float,
        .number_string => |av| return switch (b) {
            .number_string => |bv| std.mem.eql(u8, av, bv),
            .integer => |bv| (std.fmt.parseInt(i64, av, 10) catch return false) == bv,
            else => false,
        },
        .string => |av| return b == .string and std.mem.eql(u8, av, b.string),
        .array => |av| {
            if (b != .array or av.items.len != b.array.items.len) return false;
            for (av.items, b.array.items) |ai, bi| {
                if (!jsonEqual(ai, bi)) return false;
            }
            return true;
        },
        .object => |av| {
            if (b != .object or av.count() != b.object.count()) return false;
            var it = av.iterator();
            while (it.next()) |entry| {
                const bv = b.object.get(entry.key_ptr.*) orelse return false;
                if (!jsonEqual(entry.value_ptr.*, bv)) return false;
            }
            return true;
        },
    }
}

fn getObj(value: std.json.Value) !std.json.ObjectMap {
    if (value != .object) return fail("expected JSON object", .{});
    return value.object;
}

fn getField(obj: std.json.ObjectMap, key: []const u8) !std.json.Value {
    return obj.get(key) orelse fail("missing JSON field {s}", .{key});
}

fn getStringField(obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const val = try getField(obj, key);
    if (val != .string) return fail("expected string field {s}", .{key});
    return val.string;
}

fn getBoolField(obj: std.json.ObjectMap, key: []const u8) !bool {
    const val = try getField(obj, key);
    if (val != .bool) return fail("expected bool field {s}", .{key});
    return val.bool;
}

fn getU64Value(val: std.json.Value) !u64 {
    return switch (val) {
        .integer => |v| if (v >= 0) @intCast(v) else fail("negative integer", .{}),
        .number_string => |s| std.fmt.parseInt(u64, s, 10) catch fail("invalid u64 {s}", .{s}),
        else => fail("expected integer JSON value", .{}),
    };
}

fn getU64Field(obj: std.json.ObjectMap, key: []const u8) !u64 {
    return getU64Value(try getField(obj, key));
}

fn getArrayField(obj: std.json.ObjectMap, key: []const u8) ![]const std.json.Value {
    const val = try getField(obj, key);
    if (val != .array) return fail("expected array field {s}", .{key});
    return val.array.items;
}

const EntryKind = enum {
    directory,
    file,
    symlink,
    other,
};

const LstatInfo = struct {
    kind: EntryKind,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: u64,
    mtime_ns: i128,
};

fn lstatAt(dir: std.Io.Dir, rel: []const u8) !LstatInfo {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const linux = std.os.linux;
    if (rel.len > 4096) return fail("path too long: {s}", .{rel});
    var path_buf: [4097]u8 = undefined;
    @memcpy(path_buf[0..rel.len], rel);
    path_buf[rel.len] = 0;
    const request: linux.STATX = .{
        .TYPE = true,
        .MODE = true,
        .NLINK = true,
        .UID = true,
        .GID = true,
        .SIZE = true,
        .MTIME = true,
    };
    const flags: u32 = linux.AT.NO_AUTOMOUNT | linux.AT.SYMLINK_NOFOLLOW |
        @as(u32, if (rel.len == 0) linux.AT.EMPTY_PATH else 0);
    var raw = std.mem.zeroes(linux.Statx);
    const path_ptr: [*:0]const u8 = @ptrCast(&path_buf);
    switch (linux.errno(linux.statx(dir.handle, path_ptr, flags, request, &raw))) {
        .SUCCESS => {},
        .NOENT => return error.FileNotFound,
        else => return fail("statx failed for {s}", .{rel}),
    }
    const mode: u32 = raw.mode;
    const kind: EntryKind = switch (mode & linux.S.IFMT) {
        linux.S.IFDIR => .directory,
        linux.S.IFREG => .file,
        linux.S.IFLNK => .symlink,
        else => .other,
    };
    return .{
        .kind = kind,
        .mode = mode,
        .uid = raw.uid,
        .gid = raw.gid,
        .nlink = raw.nlink,
        .size = raw.size,
        .mtime_ns = @as(i128, raw.mtime.sec) * std.time.ns_per_s + raw.mtime.nsec,
    };
}

fn pathExistsAt(dir: std.Io.Dir, rel: []const u8) !bool {
    _ = lstatAt(dir, rel) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn readlinkAt(allocator: std.mem.Allocator, dir: std.Io.Dir, rel: []const u8) ![]u8 {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const linux = std.os.linux;
    if (rel.len > 4096) return fail("path too long: {s}", .{rel});
    var path_buf: [4097]u8 = undefined;
    @memcpy(path_buf[0..rel.len], rel);
    path_buf[rel.len] = 0;
    var link_buf: [4096]u8 = undefined;
    const path_ptr: [*:0]const u8 = @ptrCast(&path_buf);
    const res = linux.readlinkat(dir.handle, path_ptr, &link_buf, link_buf.len);
    if (linux.errno(res) != .SUCCESS) return fail("readlinkat failed for {s}", .{rel});
    return allocator.dupe(u8, link_buf[0..res]);
}

fn readRegularBytes(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    rel: []const u8,
) ![]u8 {
    const clean_rel = if (rel.len > 0 and rel[0] == '/') rel[1..] else rel;
    const st = lstatAt(dir, clean_rel) catch |err| switch (err) {
        error.FileNotFound => return fail("missing regular file: {s}", .{clean_rel}),
        else => return err,
    };
    try require(st.kind == .file, "expected regular file");
    try require(st.size <= FILE_LIMIT, "file exceeds size limit");
    var file = dir.openFile(io, clean_rel, .{ .mode = .read_only, .follow_symlinks = false }) catch |err|
        return fail("openFile failed for {s}: {s}", .{ clean_rel, @errorName(err) });
    defer file.close(io);
    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    return reader.interface.allocRemaining(allocator, .limited(FILE_LIMIT)) catch |err|
        return fail("read failed for {s}: {s}", .{ clean_rel, @errorName(err) });
}

fn listSortedNames(
    allocator: std.mem.Allocator,
    io: std.Io,
    base: std.Io.Dir,
    rel: []const u8,
) ![][]u8 {
    var sub = if (rel.len == 0)
        base
    else
        base.openDir(io, rel, .{ .follow_symlinks = false, .iterate = true }) catch |err|
            return fail("openDir failed for {s}: {s}", .{ rel, @errorName(err) });
    defer if (rel.len != 0) sub.close(io);

    var names: std.ArrayList([]u8) = .empty;
    errdefer {
        for (names.items) |n| allocator.free(n);
        names.deinit(allocator);
    }
    var it = sub.iterate();
    while (try it.next(io)) |entry| {
        try names.append(allocator, try allocator.dupe(u8, entry.name));
    }
    std.mem.sort([]u8, names.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);
    return names.toOwnedSlice(allocator);
}

const InstalledFact = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    selection: []const u8,

    fn lessThan(_: void, a: InstalledFact, b: InstalledFact) bool {
        const pkg = std.mem.order(u8, a.name, b.name);
        if (pkg != .eq) return pkg == .lt;
        return std.mem.order(u8, a.architecture, b.architecture) == .lt;
    }

    fn toJsonValue(self: InstalledFact, allocator: std.mem.Allocator) !std.json.Value {
        var obj: std.json.ObjectMap = .empty;
        try obj.put(allocator, "name", .{ .string = self.name });
        try obj.put(allocator, "version", .{ .string = self.version });
        try obj.put(allocator, "architecture", .{ .string = self.architecture });
        try obj.put(allocator, "selection", .{ .string = self.selection });
        return .{ .object = obj };
    }
};

const StatusParseResult = struct {
    stanza_count: usize,
    facts: []InstalledFact,
    problems: [][]const u8,
};

fn parseStatus(allocator: std.mem.Allocator, raw: []const u8) !StatusParseResult {
    var facts: std.ArrayList(InstalledFact) = .empty;
    var problems: std.ArrayList([]const u8) = .empty;
    var stanza_count: usize = 0;

    var blocks = std.mem.splitSequence(u8, raw, "\n\n");
    while (blocks.next()) |block| {
        const trimmed_block = std.mem.trim(u8, block, " \t\r\n");
        if (trimmed_block.len == 0) continue;
        stanza_count += 1;

        var pkg_val: []const u8 = "";
        var status_val: []const u8 = "";
        var version_val: []const u8 = "";
        var arch_val: []const u8 = "";
        var triggers_pending: []const u8 = "";
        var triggers_awaited: []const u8 = "";
        var has_continuation = false;

        var lines = std.mem.splitScalar(u8, block, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trimEnd(u8, raw_line, "\r");
            if (line.len == 0) continue;
            if (line[0] == ' ' or line[0] == '\t') {
                try require(has_continuation, "status continuation line without a field");
                continue;
            }
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse
                return fail("malformed status line {s}", .{line});
            has_continuation = true;
            const key = std.mem.trim(u8, line[0..colon], " \t");
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(key, "package")) {
                pkg_val = value;
            } else if (std.ascii.eqlIgnoreCase(key, "status")) {
                status_val = value;
            } else if (std.ascii.eqlIgnoreCase(key, "version")) {
                version_val = value;
            } else if (std.ascii.eqlIgnoreCase(key, "architecture")) {
                arch_val = value;
            } else if (std.ascii.eqlIgnoreCase(key, "triggers-pending")) {
                triggers_pending = value;
            } else if (std.ascii.eqlIgnoreCase(key, "triggers-awaited")) {
                triggers_awaited = value;
            }
        }

        var words_it = std.mem.tokenizeAny(u8, status_val, " \t\r");
        const want = words_it.next() orelse return fail("status stanza without want/flag/current: {s}", .{pkg_val});
        const flag = words_it.next() orelse return fail("status stanza without want/flag/current: {s}", .{pkg_val});
        const current = words_it.next() orelse return fail("status stanza without want/flag/current: {s}", .{pkg_val});
        try require(words_it.next() == null, "status stanza without want/flag/current");

        const label = try std.fmt.allocPrint(allocator, "{s}:{s} {s} {s} {s}", .{ pkg_val, arch_val, want, flag, current });
        if (!std.mem.eql(u8, flag, "ok")) {
            try problems.append(allocator, try std.fmt.allocPrint(allocator, "{s}: error flag", .{label}));
        } else if (std.mem.eql(u8, current, "installed")) {
            if (!std.mem.eql(u8, want, "install") and !std.mem.eql(u8, want, "hold")) {
                try problems.append(allocator, try std.fmt.allocPrint(allocator, "{s}: installed without install or hold selection", .{label}));
            }
        } else if (!std.mem.eql(u8, current, "config-files") or
            (!std.mem.eql(u8, want, "deinstall") and !std.mem.eql(u8, want, "purge")))
        {
            try problems.append(allocator, try std.fmt.allocPrint(allocator, "{s}: unfinished state", .{label}));
        }
        if (std.mem.trim(u8, triggers_pending, " \t").len != 0 or std.mem.trim(u8, triggers_awaited, " \t").len != 0) {
            try problems.append(allocator, try std.fmt.allocPrint(allocator, "{s}: pending or awaited triggers", .{label}));
        }

        if (std.mem.eql(u8, flag, "ok") and std.mem.eql(u8, current, "installed")) {
            try facts.append(allocator, .{
                .name = pkg_val,
                .version = version_val,
                .architecture = arch_val,
                .selection = want,
            });
        }
    }

    std.mem.sort(InstalledFact, facts.items, {}, InstalledFact.lessThan);
    return .{
        .stanza_count = stanza_count,
        .facts = try facts.toOwnedSlice(allocator),
        .problems = try problems.toOwnedSlice(allocator),
    };
}

fn checkPrestate(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    arch: []const u8,
    stdout: *std.Io.Writer,
) !u8 {
    const status_bytes = try readRegularBytes(allocator, io, root_dir, STATUS);
    const parsed_status = try parseStatus(allocator, status_bytes);

    var problems: std.ArrayList([]const u8) = .empty;
    try problems.appendSlice(allocator, parsed_status.problems);

    const root_st = try lstatAt(root_dir, "");
    const owner = root_st.uid;
    var entries: u64 = 0;
    var files: u64 = 0;
    var bytes: u64 = 0;
    var max_depth: u64 = 0;

    const StackItem = struct { rel: []const u8, depth: u64 };
    var stack: std.ArrayList(StackItem) = .empty;
    try stack.append(allocator, .{ .rel = DPKG, .depth = 0 });

    while (stack.items.len > 0) {
        const item = stack.pop().?;
        const rel = item.rel;
        const depth = item.depth;
        entries += 1;
        if (depth > max_depth) max_depth = depth;
        if (depth > 32 or rel.len > 4096) {
            try problems.append(allocator, try std.fmt.allocPrint(allocator, "{s}: deeper or longer than the baseline limits", .{rel}));
        }
        const info = try lstatAt(root_dir, rel);
        if (info.uid != owner or (info.mode & 0o022) != 0) {
            try problems.append(allocator, try std.fmt.allocPrint(allocator, "{s}: not root owned or group/other writable", .{rel}));
        }
        if (info.kind == .directory) {
            const names = try listSortedNames(allocator, io, root_dir, rel);
            if (std.mem.eql(u8, rel, DPKG ++ "/updates") and names.len != 0) {
                try problems.append(allocator, try std.fmt.allocPrint(allocator, "{s}: pending dpkg updates", .{rel}));
            }
            var idx = names.len;
            while (idx > 0) {
                idx -= 1;
                const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ rel, names[idx] });
                try stack.append(allocator, .{ .rel = child, .depth = depth + 1 });
            }
            continue;
        }
        if (info.kind != .file or info.nlink != 1) {
            try problems.append(allocator, try std.fmt.allocPrint(allocator, "{s}: not a singly linked regular file", .{rel}));
            continue;
        }
        files += 1;
        bytes += info.size;
        if (info.size > FILE_LIMIT) {
            try problems.append(allocator, try std.fmt.allocPrint(allocator, "{s}: larger than the per-file baseline limit", .{rel}));
        }
        if (std.mem.eql(u8, rel, DPKG ++ "/triggers/Unincorp")) {
            const unincorp_bytes = try readRegularBytes(allocator, io, root_dir, rel);
            if (std.mem.trim(u8, unincorp_bytes, " \t\r\n").len != 0) {
                try problems.append(allocator, try std.fmt.allocPrint(allocator, "{s}: unincorporated triggers", .{rel}));
            }
        }
    }
    if (entries > 200_000 or files > 100_000 or bytes > TREE_LIMIT) {
        try problems.append(allocator, "the dpkg database exceeds the baseline entry, file or byte limits");
    }

    var held_vals: std.ArrayList(std.json.Value) = .empty;
    for (parsed_status.facts) |fact| {
        if (std.mem.eql(u8, fact.selection, "hold")) {
            try held_vals.append(allocator, try fact.toJsonValue(allocator));
        }
    }

    var arch_map: std.json.ObjectMap = .empty;
    for ([_][]const u8{ "arch", "arch-native" }) |name| {
        const rel = try std.fmt.allocPrint(allocator, DPKG ++ "/{s}", .{name});
        if (try pathExistsAt(root_dir, rel)) {
            const st = try lstatAt(root_dir, rel);
            if (st.kind == .file) {
                const raw = try readRegularBytes(allocator, io, root_dir, rel);
                var words: std.ArrayList(std.json.Value) = .empty;
                var w_it = std.mem.tokenizeAny(u8, raw, " \t\r\n");
                while (w_it.next()) |w| try words.append(allocator, .{ .string = w });
                try arch_map.put(allocator, name, .{ .array = std.json.Array.fromOwnedSlice(allocator, words.items) });
            }
        }
    }

    var probs_json: std.ArrayList(std.json.Value) = .empty;
    for (problems.items) |p| try probs_json.append(allocator, .{ .string = p });

    var tree_obj: std.json.ObjectMap = .empty;
    try tree_obj.put(allocator, "bytes", .{ .integer = @intCast(bytes) });
    try tree_obj.put(allocator, "depth", .{ .integer = @intCast(max_depth) });
    try tree_obj.put(allocator, "entries", .{ .integer = @intCast(entries) });
    try tree_obj.put(allocator, "files", .{ .integer = @intCast(files) });

    var report_obj: std.json.ObjectMap = .empty;
    try report_obj.put(allocator, "architecture", .{ .string = arch });
    try report_obj.put(allocator, "dpkg_architectures", .{ .object = arch_map });
    try report_obj.put(allocator, "healthy", .{ .bool = problems.items.len == 0 });
    try report_obj.put(allocator, "held", .{ .array = std.json.Array.fromOwnedSlice(allocator, held_vals.items) });
    try report_obj.put(allocator, "installed_facts", .{ .integer = @intCast(parsed_status.facts.len) });
    try report_obj.put(allocator, "problems", .{ .array = std.json.Array.fromOwnedSlice(allocator, probs_json.items) });
    try report_obj.put(allocator, "status_stanzas", .{ .integer = @intCast(parsed_status.stanza_count) });
    try report_obj.put(allocator, "tree", .{ .object = tree_obj });

    const report_json = try std.json.Stringify.valueAlloc(allocator, std.json.Value{ .object = report_obj }, .{ .whitespace = .indent_1 });
    try stdout.writeAll(report_json);
    try stdout.writeByte('\n');
    try stdout.flush();
    return if (problems.items.len == 0) 0 else 1;
}

fn isExcludedSnapshotPath(rel: []const u8) bool {
    return std.mem.eql(u8, rel, DPKG ++ "/lock") or
        std.mem.eql(u8, rel, DPKG ++ "/lock-frontend") or
        std.mem.eql(u8, rel, DPKG ++ "/triggers/Lock");
}

fn snapshot(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    stdout: *std.Io.Writer,
) !u8 {
    var lines: std.ArrayList([]u8) = .empty;
    var stack: std.ArrayList([]const u8) = .empty;
    try stack.append(allocator, DPKG);

    while (stack.items.len > 0) {
        const rel = stack.pop().?;
        const info = try lstatAt(root_dir, rel);
        if (info.kind == .directory) {
            const names = try listSortedNames(allocator, io, root_dir, rel);
            var idx = names.len;
            while (idx > 0) {
                idx -= 1;
                const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ rel, names[idx] });
                try stack.append(allocator, child);
            }
        }
        if (isExcludedSnapshotPath(rel)) continue;
        const mode = info.mode & 0o7777;
        const line = switch (info.kind) {
            .directory => try std.json.Stringify.valueAlloc(allocator, .{
                "directory",
                mode,
                info.uid,
                info.gid,
                @as(u64, 0),
                info.mtime_ns,
                "",
                rel,
            }, .{}),
            .file => blk: {
                const file_bytes = try readRegularBytes(allocator, io, root_dir, rel);
                const hex = sha512Hex(file_bytes);
                break :blk try std.json.Stringify.valueAlloc(allocator, .{
                    "file",
                    mode,
                    info.uid,
                    info.gid,
                    info.size,
                    info.mtime_ns,
                    &hex,
                    rel,
                }, .{});
            },
            .symlink => blk: {
                const target = try readlinkAt(allocator, root_dir, rel);
                break :blk try std.json.Stringify.valueAlloc(allocator, .{
                    "symlink",
                    mode,
                    info.uid,
                    info.gid,
                    @as(u64, 0),
                    info.mtime_ns,
                    target,
                    rel,
                }, .{});
            },
            .other => try std.json.Stringify.valueAlloc(allocator, .{
                "other",
                mode,
                info.uid,
                info.gid,
                @as(u64, 0),
                info.mtime_ns,
                "",
                rel,
            }, .{}),
        };
        try lines.append(allocator, line);
    }

    std.mem.sort([]u8, lines.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);
    for (lines.items) |line| {
        try stdout.writeAll(line);
        try stdout.writeByte('\n');
    }
    try stdout.flush();
    return 0;
}

fn verifyRepoAdd(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    out_dir: std.Io.Dir,
    descriptor: []const u8,
    arch: []const u8,
    stdout: *std.Io.Writer,
) !u8 {
    const repo_stdout = try readRegularBytes(allocator, io, out_dir, "repo-add.stdout");
    _ = try readRegularBytes(allocator, io, out_dir, "repo-add.stderr");
    const repo_exit_raw = try readRegularBytes(allocator, io, out_dir, "repo-add.exit");
    const status = std.fmt.parseInt(i64, std.mem.trim(u8, repo_exit_raw, " \t\r\n"), 10) catch
        return fail("invalid repo-add.exit", .{});
    try require(status == 0, "repo add exited non-zero");

    const result_val = try parseJson(allocator, repo_stdout, "repo-add.stdout");
    const result = try getObj(result_val);
    try require((try getU64Field(result, "exit_status")) == 0, "repo add exit_status != 0");
    try require((try getBoolField(result, "installed")) == true, "repo add installed != true");
    try require((try getBoolField(result, "refreshed")) == true, "repo add refreshed != true");
    try require(std.mem.eql(u8, try getStringField(result, "refreshed_phase"), "complete"), "repo add refreshed_phase != complete");
    const desc_obj = try getObj(try getField(result, "descriptor"));
    try require(std.mem.eql(u8, try getStringField(desc_obj, "sha256"), descriptor), "repo add installed an unreviewed descriptor");

    const paths_obj = try getObj(try getField(result, "paths"));
    const target_manifest_logical = try getStringField(paths_obj, "target_manifest");
    const raw = try readRegularBytes(allocator, io, root_dir, target_manifest_logical);
    const snap_val = try parseJson(allocator, raw, target_manifest_logical);
    const snap = try getObj(snap_val);
    try require(std.mem.eql(u8, try getStringField(snap, "schema"), SCHEMA ++ "apt-config-snapshot-v3"), "the APT configuration snapshot is not version 3");
    try require((try getU64Field(snap, "version")) == 3, "the APT configuration snapshot is not version 3");
    try require(std.mem.eql(u8, try getStringField(snap, "native_architecture"), arch), "the snapshot names another native architecture");

    var bounded_obj: std.json.ObjectMap = .empty;
    try bounded_obj.put(allocator, "mode", .{ .string = "allow_missing_valid_until_with_max_age_seconds" });
    try bounded_obj.put(allocator, "maximum_release_age_seconds", .{ .integer = BOUND });
    const bounded_val = std.json.Value{ .object = bounded_obj };

    const sources = try getArrayField(snap, "sources");
    try require(sources.len == 1, "expected only the reviewed Microsoft source");
    const source = try getObj(sources[0]);
    try require(std.mem.eql(u8, try getStringField(source, "logical_path"), SOURCE) and std.mem.eql(u8, try getStringField(source, "format"), "legacy"), "unexpected source");
    try require(jsonEqual(try getField(source, "freshness"), bounded_val), "the Microsoft source lost its explicit bound");
    try require(std.mem.eql(u8, try getStringField(source, "archive_binding"), DERIVED), "the Microsoft source is not the reviewed derived SHA-512 opt-in");

    const policies = try getArrayField(snap, "repository_policies");
    try require(policies.len > 0, "no repository policy was recorded");
    var pol_ids: std.ArrayList([]const u8) = .empty;
    for (policies) |pol_val| {
        const pol = try getObj(pol_val);
        try require(jsonEqual(try getField(pol, "freshness"), bounded_val) and std.mem.eql(u8, try getStringField(pol, "archive_binding"), DERIVED), "unexpected repository policy");
        try pol_ids.append(allocator, try getStringField(pol, "repository_id"));
    }
    var snap_repo_ids: std.ArrayList([]const u8) = .empty;
    for (try getArrayField(snap, "repository_ids")) |rid_val| {
        if (rid_val != .string) return fail("repository_id is not string", .{});
        try snap_repo_ids.append(allocator, rid_val.string);
    }
    std.mem.sort([]const u8, pol_ids.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);
    std.mem.sort([]const u8, snap_repo_ids.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);
    try require(stringSlicesEqual(pol_ids.items, snap_repo_ids.items), "repository policies do not cover exactly the configured repositories");

    const keyrings = try getArrayField(snap, "keyrings");
    var matched_keyrings: usize = 0;
    var expected_signer_lower: [SIGNER.len]u8 = undefined;
    _ = std.ascii.lowerString(&expected_signer_lower, SIGNER);
    for (keyrings) |kr_val| {
        const kr = try getObj(kr_val);
        if (std.mem.eql(u8, try getStringField(kr, "logical_path"), KEYRING)) {
            matched_keyrings += 1;
            const fps = try getArrayField(kr, "primary_fingerprints");
            try require(fps.len == 1 and fps[0] == .string and std.mem.eql(u8, fps[0].string, &expected_signer_lower), "the Microsoft keyring names another signer");
            const use_str = try getStringField(kr, "use");
            try require(std.mem.eql(u8, use_str, "declared") or std.mem.eql(u8, use_str, "declared_and_global"), "the Microsoft keyring is not declared");
        }
    }
    try require(matched_keyrings == 1, "the Microsoft keyring is not recorded");

    try stdout.writeAll(raw);
    try stdout.flush();
    return 0;
}

const CacheEntry = struct {
    size: u64,
    sha256: [64]u8,
    sha512: [128]u8,
};

const CacheIndex = struct {
    entries: []CacheEntry,

    fn init(allocator: std.mem.Allocator, io: std.Io, root_dir: std.Io.Dir) !CacheIndex {
        var list: std.ArrayList(CacheEntry) = .empty;
        if (try pathExistsAt(root_dir, CACHE)) {
            var stack: std.ArrayList([]const u8) = .empty;
            try stack.append(allocator, CACHE);
            while (stack.items.len > 0) {
                const rel = stack.pop().?;
                const st = try lstatAt(root_dir, rel);
                switch (st.kind) {
                    .directory => {
                        const names = try listSortedNames(allocator, io, root_dir, rel);
                        var idx = names.len;
                        while (idx > 0) {
                            idx -= 1;
                            const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ rel, names[idx] });
                            try stack.append(allocator, child);
                        }
                    },
                    .file => {
                        const data = try readRegularBytes(allocator, io, root_dir, rel);
                        try list.append(allocator, .{
                            .size = st.size,
                            .sha256 = sha256Hex(data),
                            .sha512 = sha512Hex(data),
                        });
                    },
                    else => {},
                }
            }
        }
        return .{ .entries = try list.toOwnedSlice(allocator) };
    }

    fn matches(
        self: CacheIndex,
        allocator: std.mem.Allocator,
        io: std.Io,
        size: u64,
        sha256: []const u8,
    ) ![][]const u8 {
        _ = io;
        var out: std.ArrayList([]const u8) = .empty;
        for (self.entries) |*entry| {
            if (entry.size == size and std.mem.eql(u8, &entry.sha256, sha256)) {
                try out.append(allocator, &entry.sha512);
            }
        }
        return out.toOwnedSlice(allocator);
    }
};

fn allEqualSlice(items: []const []const u8, expected: []const u8) bool {
    for (items) |item| {
        if (!std.mem.eql(u8, item, expected)) return false;
    }
    return true;
}

fn stringSlicesEqual(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ai, bi| {
        if (!std.mem.eql(u8, ai, bi)) return false;
    }
    return true;
}

const EnvelopeDoc = struct {
    payload: std.json.ObjectMap,
    digest: []const u8,
};

fn parseEnvelopeBytes(allocator: std.mem.Allocator, raw: []const u8, label: []const u8) !EnvelopeDoc {
    const trimmed = std.mem.trimEnd(u8, raw, "\r\n");
    const prefix = "{\"payload\":";
    const mid = ",\"digest_sha512\":\"";
    const suffix = "\"}";
    try require(
        trimmed.len > prefix.len + mid.len + 128 + suffix.len and
            std.mem.startsWith(u8, trimmed, prefix) and
            std.mem.endsWith(u8, trimmed, suffix),
        "not a digest envelope",
    );
    const digest_start = trimmed.len - suffix.len - 128;
    const mid_start = digest_start - mid.len;
    try require(std.mem.eql(u8, trimmed[mid_start..digest_start], mid), "not a digest envelope");
    const payload_bytes = trimmed[prefix.len..mid_start];
    const recorded = trimmed[digest_start .. digest_start + 128];
    const computed = sha512Hex(payload_bytes);
    try require(isLowerHex(recorded, 128) and std.mem.eql(u8, recorded, &computed), "the envelope digest does not cover its payload");
    const payload_val = try parseJson(allocator, payload_bytes, label);
    const full_val = try parseJson(allocator, trimmed, label);
    var expected_env: std.json.ObjectMap = .empty;
    try expected_env.put(allocator, "payload", payload_val);
    try expected_env.put(allocator, "digest_sha512", .{ .string = recorded });
    try require(jsonEqual(full_val, .{ .object = expected_env }), "unexpected envelope");
    return .{
        .payload = try getObj(payload_val),
        .digest = try allocator.dupe(u8, recorded),
    };
}

fn classText(auth: []const u8) ![]const u8 {
    if (std.mem.eql(u8, auth, DERIVED)) {
        return "signed SHA-256; SHA-512 derived locally from the signed SHA-256 match (derived_from_signed_sha256; not independently signed)";
    }
    if (std.mem.eql(u8, auth, "signed_sha256_only")) {
        return "signed SHA-256 only; no SHA-512 published by the signed index";
    }
    return fail("unexpected archive_authentication {s}", .{auth});
}

fn freshnessText(freshness_val: std.json.Value) ![]const u8 {
    const f = try getObj(freshness_val);
    try require(
        f.count() == 2 and
            std.mem.eql(u8, try getStringField(f, "policy"), "bounded_missing_valid_until") and
            (try getU64Field(f, "maximum_release_age_seconds")) == BOUND,
        "unexpected repository freshness",
    );
    return "missing Valid-Until accepted for at most 1209600 s (explicit repository bound)";
}

fn renderHuman(allocator: std.mem.Allocator, result: std.json.ObjectMap) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.print(allocator, "install: {s}\n", .{try getStringField(result, "summary")});
    if (result.get("attempt_id")) |att| {
        if (att == .string) {
            const resumed = try getBoolField(result, "resumed");
            try out.print(allocator, "attempt: {s}{s}\n", .{ att.string, if (resumed) " (resumed)" else "" });
        }
    }
    if (result.get("backend")) |b| {
        if (b == .string) try out.print(allocator, "backend: {s}\n", .{b.string});
    }
    if (result.get("lock")) |l| {
        if (l == .string) try out.print(allocator, "exact lock: {s}\n", .{l.string});
    }
    if (result.get("evidence_path")) |ev| {
        if (ev == .string) try out.print(allocator, "evidence: {s}\n", .{ev.string});
    }
    if (result.get("plan")) |plan_val| {
        if (plan_val == .object) {
            const plan = plan_val.object;
            const archives = try getArrayField(plan, "archives");
            try out.print(allocator, "actions ({d}):\n", .{archives.len});
            for (archives) |av| {
                const a = try getObj(av);
                try out.print(
                    allocator,
                    "  install {s} {s} [{s}] {s}: {s}\n",
                    .{
                        try getStringField(a, "package"),
                        try getStringField(a, "version"),
                        try getStringField(a, "architecture"),
                        try getStringField(a, "retention"),
                        try classText(try getStringField(a, "archive_authentication")),
                    },
                );
            }
            const repos = try getArrayField(plan, "repositories");
            for (repos) |rv| {
                const r = try getObj(rv);
                try out.print(
                    allocator,
                    "repository {s} {s} {s}: {s}\n",
                    .{
                        try getStringField(r, "uri"),
                        try getStringField(r, "suite"),
                        try getStringField(r, "component"),
                        try freshnessText(try getField(r, "freshness")),
                    },
                );
            }
            const installed = try getObj(try getField(plan, "installed"));
            try out.print(
                allocator,
                "installed facts: {d} from the healthy installed package database (no archive origin)\n",
                .{try getU64Field(installed, "fact_count")},
            );
            for (try getArrayField(installed, "held")) |hv| {
                const h = try getObj(hv);
                try out.print(
                    allocator,
                    "  held {s} {s} [{s}] (no archive origin)\n",
                    .{
                        try getStringField(h, "name"),
                        try getStringField(h, "version"),
                        try getStringField(h, "architecture"),
                    },
                );
            }
        }
    }
    for (try getArrayField(result, "diagnostics")) |dv| {
        const d = try getObj(dv);
        try out.print(
            allocator,
            "debz[{s}]: {s}\n",
            .{ try getStringField(d, "id"), try getStringField(d, "message") },
        );
    }
    return out.toOwnedSlice(allocator);
}

const ArchiveIdentityRecord = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    signed_sha256: []const u8,
    derived_sha512: ?[]const u8 = null,

    fn lessThan(_: void, a: ArchiveIdentityRecord, b: ArchiveIdentityRecord) bool {
        const p = std.mem.order(u8, a.package, b.package);
        if (p != .eq) return p == .lt;
        const v = std.mem.order(u8, a.version, b.version);
        if (v != .eq) return v == .lt;
        return std.mem.order(u8, a.architecture, b.architecture) == .lt;
    }
};

const Verifier = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    root_dir: std.Io.Dir,
    out_dir: std.Io.Dir,
    arch: []const u8,
    facts: []InstalledFact,
    cache: CacheIndex,
    attempts: std.ArrayList([]const u8) = .empty,
    locks: std.ArrayList([]const u8) = .empty,
    databases: std.ArrayList([]const u8) = .empty,
    archive_identities: std.ArrayList(ArchiveIdentityRecord) = .empty,
    reports: std.ArrayList(std.json.Value) = .empty,

    fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        root_dir: std.Io.Dir,
        out_dir: std.Io.Dir,
        arch: []const u8,
    ) !Verifier {
        const status_bytes = try readRegularBytes(allocator, io, root_dir, STATUS);
        const status_parsed = try parseStatus(allocator, status_bytes);
        try require(status_parsed.problems.len == 0, "the installed package database is not healthy");

        return .{
            .allocator = allocator,
            .io = io,
            .root_dir = root_dir,
            .out_dir = out_dir,
            .arch = arch,
            .facts = status_parsed.facts,
            .cache = try CacheIndex.init(allocator, io, root_dir),
        };
    }

    fn pathExists(self: *Verifier, rel: []const u8) !bool {
        return pathExistsAt(self.root_dir, rel);
    }

    fn readEnvelope(self: *Verifier, relative: []const u8) !EnvelopeDoc {
        const raw = try readRegularBytes(self.allocator, self.io, self.root_dir, relative);
        return parseEnvelopeBytes(self.allocator, raw, relative);
    }

    fn recordDatabase(self: *Verifier, db_sha512: []const u8) !void {
        for (self.databases.items) |existing| {
            if (std.mem.eql(u8, existing, db_sha512)) return;
        }
        try self.databases.append(self.allocator, db_sha512);
    }

    fn recordSigned(self: *Verifier, pkg: []const u8, ver: []const u8, arch: []const u8, signed: []const u8) !void {
        for (self.archive_identities.items) |*item| {
            if (std.mem.eql(u8, item.package, pkg) and std.mem.eql(u8, item.version, ver) and std.mem.eql(u8, item.architecture, arch)) {
                try require(std.mem.eql(u8, item.signed_sha256, signed), "archive changed its signed SHA-256");
                return;
            }
        }
        try self.archive_identities.append(self.allocator, .{
            .package = pkg,
            .version = ver,
            .architecture = arch,
            .signed_sha256 = signed,
        });
    }

    fn recordDerived(self: *Verifier, pkg: []const u8, ver: []const u8, arch: []const u8, derived: []const u8) !void {
        for (self.archive_identities.items) |*item| {
            if (std.mem.eql(u8, item.package, pkg) and std.mem.eql(u8, item.version, ver) and std.mem.eql(u8, item.architecture, arch)) {
                if (item.derived_sha512) |existing| {
                    try require(std.mem.eql(u8, existing, derived), "archive changed its derived SHA-512");
                } else {
                    item.derived_sha512 = derived;
                }
                return;
            }
        }
        return fail("derived SHA-512 recorded before signed SHA-256", .{});
    }

    fn extractHumanAttempt(stderr: []const u8) ![]const u8 {
        var lines = std.mem.splitScalar(u8, stderr, '\n');
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "attempt: ")) {
                const candidate = line["attempt: ".len..];
                if (isNonEmptyLowerHex(candidate)) return candidate;
            }
        }
        return fail("the human report names no attempt", .{});
    }

    fn describeArchive(self: *Verifier, archive: std.json.ObjectMap) !std.json.Value {
        const pub_digests = try getArrayField(archive, "published_digests");
        const first_pub = try getObj(pub_digests[0]);
        var obj: std.json.ObjectMap = .empty;
        try obj.put(self.allocator, "package", try getField(archive, "package"));
        try obj.put(self.allocator, "version", try getField(archive, "version"));
        try obj.put(self.allocator, "architecture", try getField(archive, "architecture"));
        try obj.put(self.allocator, "retention", try getField(archive, "retention"));
        try obj.put(self.allocator, "archive_authentication", try getField(archive, "archive_authentication"));
        try obj.put(self.allocator, "signed_sha256", try getField(first_pub, "value"));
        if (archive.get("derived_sha512")) |d| {
            try obj.put(self.allocator, "derived_sha512", d);
        } else {
            try obj.put(self.allocator, "derived_sha512", .null);
        }
        return .{ .object = obj };
    }

    fn runOne(self: *Verifier, name: []const u8, user: []const u8, output: []const u8, raw_backend: []const u8, package: []const u8) !void {
        const stdout_rel = try std.fmt.allocPrint(self.allocator, "runs/{s}.stdout", .{name});
        const stderr_rel = try std.fmt.allocPrint(self.allocator, "runs/{s}.stderr", .{name});
        const exit_rel = try std.fmt.allocPrint(self.allocator, "runs/{s}.exit", .{name});
        const stdout = try readRegularBytes(self.allocator, self.io, self.out_dir, stdout_rel);
        const stderr = try readRegularBytes(self.allocator, self.io, self.out_dir, stderr_rel);
        const exit_raw = try readRegularBytes(self.allocator, self.io, self.out_dir, exit_rel);
        const status = std.fmt.parseInt(i64, std.mem.trim(u8, exit_raw, " \t\r\n"), 10) catch
            return fail("{s}: invalid exit status", .{name});
        try require(!containsAsciiCaseInsensitive(stdout, "upstream") and !containsAsciiCaseInsensitive(stderr, "upstream"), "output mentions an upstream digest");

        var result_opt: ?std.json.Value = null;
        if (std.mem.eql(u8, output, "json")) {
            try require(stderr.len == 0, "unexpected stderr on json run");
            try require(stdout.len > 0 and stdout[stdout.len - 1] == '\n' and std.mem.count(u8, stdout, "\n") == 1, "not one JSON line");
            result_opt = try parseJson(self.allocator, stdout, name);
        } else {
            try require(stdout.len == 0, "a refused human run wrote stdout");
        }
        const backend = if (std.mem.eql(u8, raw_backend, "default")) "legacy_dpkg" else raw_backend;
        if (!std.mem.eql(u8, user, "root")) {
            return self.unprivileged(name, result_opt, status, package);
        }
        const attempt = if (result_opt) |rv|
            try getStringField(try getObj(rv), "attempt_id")
        else
            try extractHumanAttempt(stderr);

        try require(isLowerHex(attempt, 32), "invalid attempt id");
        for (self.attempts.items) |seen| {
            try require(!std.mem.eql(u8, seen, attempt), "attempt was reused");
        }
        try self.attempts.append(self.allocator, attempt);

        const expected = if (std.mem.eql(u8, package, ABSENT_PACKAGE))
            try self.absent(name, attempt, backend, package, status)
        else
            try self.planned(name, attempt, backend, package, status);

        if (result_opt) |rv| {
            try require(jsonEqual(rv, .{ .object = expected }), "the JSON result differs from its evidence");
        } else {
            const rendered = try renderHuman(self.allocator, expected);
            try require(std.mem.eql(u8, stderr, rendered), "the human report differs from its evidence");
        }

        var described_archives: std.ArrayList(std.json.Value) = .empty;
        if (expected.get("plan")) |plan_val| {
            if (plan_val == .object) {
                for (try getArrayField(plan_val.object, "archives")) |av| {
                    try described_archives.append(self.allocator, try self.describeArchive(try getObj(av)));
                }
            }
        }
        var rep: std.json.ObjectMap = .empty;
        try rep.put(self.allocator, "name", .{ .string = name });
        try rep.put(self.allocator, "exit_status", .{ .integer = status });
        try rep.put(self.allocator, "outcome", try getField(expected, "outcome"));
        try rep.put(self.allocator, "attempt_id", .{ .string = attempt });
        try rep.put(self.allocator, "backend", .{ .string = backend });
        try rep.put(self.allocator, "package", .{ .string = package });
        try rep.put(self.allocator, "archives", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, described_archives.items) });
        try self.reports.append(self.allocator, .{ .object = rep });
    }

    fn unprivileged(self: *Verifier, name: []const u8, result_opt: ?std.json.Value, status: i64, package: []const u8) !void {
        _ = name;
        try require(status == 3, "unprivileged exited with unexpected status");
        var diag: std.json.ObjectMap = .empty;
        try diag.put(self.allocator, "id", .{ .string = "transaction_backend_unavailable" });
        try diag.put(self.allocator, "message", .{ .string = PRIVILEGE });
        const diags = try self.allocator.alloc(std.json.Value, 1);
        diags[0] = .{ .object = diag };
        const docs = try self.allocator.alloc(std.json.Value, 0);

        var expected: std.json.ObjectMap = .empty;
        try expected.put(self.allocator, "schema", .{ .string = SCHEMA ++ "system-install-result-v1" });
        try expected.put(self.allocator, "version", .{ .integer = 1 });
        try expected.put(self.allocator, "operation", .{ .string = "install" });
        try expected.put(self.allocator, "exit_status", .{ .integer = 3 });
        try expected.put(self.allocator, "outcome", .{ .string = "rejected" });
        try expected.put(self.allocator, "changed", .{ .bool = false });
        try expected.put(self.allocator, "package", .{ .string = package });
        try expected.put(self.allocator, "summary", .{ .string = PRIVILEGE });
        try expected.put(self.allocator, "resumed", .{ .bool = false });
        try expected.put(self.allocator, "documents", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, docs) });
        try expected.put(self.allocator, "diagnostics", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, diags) });

        try require(result_opt != null and jsonEqual(result_opt.?, .{ .object = expected }), "unexpected unprivileged result");

        var rep: std.json.ObjectMap = .empty;
        try rep.put(self.allocator, "name", .{ .string = "unprivileged-native-symcrypt" });
        try rep.put(self.allocator, "exit_status", .{ .integer = status });
        try rep.put(self.allocator, "outcome", .{ .string = "rejected" });
        try rep.put(self.allocator, "package", .{ .string = package });
        try self.reports.append(self.allocator, .{ .object = rep });
    }

    const ChainResult = struct {
        progress: std.json.ObjectMap,
        progress_digest: []const u8,
        command: []const u8,
        operation: []const u8,
        request_digest: []const u8,
    };

    fn chain(self: *Verifier, attempt: []const u8, backend: []const u8, package: []const u8, expected_files: []const []const u8) !ChainResult {
        const operation = try std.fmt.allocPrint(self.allocator, OPERATIONS ++ "/{s}", .{attempt});
        const actual_files = try listSortedNames(self.allocator, self.io, self.root_dir, operation);
        try require(stringSlicesEqual(actual_files, expected_files), "unexpected operation documents");

        const command = try std.fmt.allocPrint(self.allocator, "debz install --transaction-backend {s} {s}", .{ backend, package });
        const req_doc = try self.readEnvelope(try std.fmt.allocPrint(self.allocator, "{s}/request-v1.json", .{operation}));
        var expected_req: std.json.ObjectMap = .empty;
        try expected_req.put(self.allocator, "schema", .{ .string = SCHEMA ++ "system-install-request-v1" });
        try expected_req.put(self.allocator, "version", .{ .integer = 1 });
        try expected_req.put(self.allocator, "attempt_id", .{ .string = attempt });
        try expected_req.put(self.allocator, "operation", .{ .string = "install" });
        try expected_req.put(self.allocator, "package", .{ .string = package });
        try expected_req.put(self.allocator, "backend", .{ .string = backend });
        try expected_req.put(self.allocator, "profile", .{ .object = try profileObject(self.allocator, self.arch) });
        try expected_req.put(self.allocator, "command", .{ .string = command });
        try expected_req.put(self.allocator, "request_sha512", .{ .string = try requestSha512(self.allocator, package, backend) });
        try require(jsonEqual(.{ .object = req_doc.payload }, .{ .object = expected_req }), "unexpected request document");

        var prog_doc = try self.readEnvelope(try std.fmt.allocPrint(self.allocator, "{s}/progress-v1.json", .{operation}));
        const prev_prog = try getStringField(prog_doc.payload, "previous_progress_sha512");
        try require(isLowerHex(prev_prog, 128), "progress is not chained");
        _ = prog_doc.payload.swapRemove("previous_progress_sha512");

        return .{
            .progress = prog_doc.payload,
            .progress_digest = prog_doc.digest,
            .command = command,
            .operation = operation,
            .request_digest = req_doc.digest,
        };
    }

    const DocPair = struct { kind: []const u8, digest: []const u8 };

    fn buildDocuments(self: *Verifier, attempt: []const u8, pairs: []const DocPair) !std.json.Value {
        const items = try self.allocator.alloc(std.json.Value, pairs.len);
        for (pairs, 0..) |pair, i| {
            const path = if (std.mem.eql(u8, pair.kind, "lock"))
                try std.fmt.allocPrint(self.allocator, "/" ++ LOCKS ++ "/install-{s}.json", .{attempt})
            else
                try std.fmt.allocPrint(self.allocator, "/" ++ OPERATIONS ++ "/{s}/{s}-v1.json", .{ attempt, pair.kind });
            var obj: std.json.ObjectMap = .empty;
            try obj.put(self.allocator, "kind", .{ .string = pair.kind });
            try obj.put(self.allocator, "path", .{ .string = path });
            try obj.put(self.allocator, "document_sha512", .{ .string = pair.digest });
            items[i] = .{ .object = obj };
        }
        return .{ .array = std.json.Array.fromOwnedSlice(self.allocator, items) };
    }

    fn absent(self: *Verifier, name: []const u8, attempt: []const u8, backend: []const u8, package: []const u8, status: i64) !std.json.ObjectMap {
        _ = name;
        try require(status == 5, "absent run exited with unexpected status");
        const rejected_files = [_][]const u8{ "progress-v1.json", "receipt-v1.json", "request-v1.json" };
        const ch = try self.chain(attempt, backend, package, &rejected_files);
        try require(!try self.pathExists(try std.fmt.allocPrint(self.allocator, LOCKS ++ "/install-{s}.json", .{attempt})), "a refused plan published a lock");

        var terminal: std.json.ObjectMap = .empty;
        try terminal.put(self.allocator, "outcome", .{ .string = "rejected" });
        try terminal.put(self.allocator, "changed", .{ .bool = false });
        try terminal.put(self.allocator, "exit_status", .{ .integer = 5 });
        try terminal.put(self.allocator, "id", .{ .string = "planning_failed" });
        try terminal.put(self.allocator, "message", .{ .string = ABSENT });

        var expected_prog: std.json.ObjectMap = .empty;
        try expected_prog.put(self.allocator, "schema", .{ .string = SCHEMA ++ "system-install-progress-v1" });
        try expected_prog.put(self.allocator, "version", .{ .integer = 1 });
        try expected_prog.put(self.allocator, "attempt_id", .{ .string = attempt });
        try expected_prog.put(self.allocator, "generation", .{ .integer = 2 });
        try expected_prog.put(self.allocator, "request_document_sha512", .{ .string = ch.request_digest });
        try expected_prog.put(self.allocator, "phase", .{ .string = "terminal" });
        try expected_prog.put(self.allocator, "terminal", .{ .object = terminal });
        try require(jsonEqual(.{ .object = ch.progress }, .{ .object = expected_prog }), "unexpected absent progress");

        const receipt_doc = try self.readEnvelope(try std.fmt.allocPrint(self.allocator, "{s}/receipt-v1.json", .{ch.operation}));
        var expected_rec: std.json.ObjectMap = .empty;
        try expected_rec.put(self.allocator, "schema", .{ .string = SCHEMA ++ "system-install-receipt-v1" });
        try expected_rec.put(self.allocator, "version", .{ .integer = 1 });
        try expected_rec.put(self.allocator, "attempt_id", .{ .string = attempt });
        try expected_rec.put(self.allocator, "request_document_sha512", .{ .string = ch.request_digest });
        try expected_rec.put(self.allocator, "progress_document_sha512", .{ .string = ch.progress_digest });
        try expected_rec.put(self.allocator, "terminal", .{ .object = terminal });
        try require(jsonEqual(.{ .object = receipt_doc.payload }, .{ .object = expected_rec }), "unexpected absent receipt");

        var diag: std.json.ObjectMap = .empty;
        try diag.put(self.allocator, "id", .{ .string = "planning_failed" });
        try diag.put(self.allocator, "message", .{ .string = ABSENT });
        const diags = try self.allocator.alloc(std.json.Value, 1);
        diags[0] = .{ .object = diag };

        var res: std.json.ObjectMap = .empty;
        try res.put(self.allocator, "schema", .{ .string = SCHEMA ++ "system-install-result-v1" });
        try res.put(self.allocator, "version", .{ .integer = 1 });
        try res.put(self.allocator, "operation", .{ .string = "install" });
        try res.put(self.allocator, "exit_status", .{ .integer = 5 });
        try res.put(self.allocator, "outcome", .{ .string = "rejected" });
        try res.put(self.allocator, "changed", .{ .bool = false });
        try res.put(self.allocator, "package", .{ .string = package });
        try res.put(self.allocator, "summary", .{ .string = ABSENT });
        try res.put(self.allocator, "backend", .{ .string = backend });
        try res.put(self.allocator, "command", .{ .string = ch.command });
        try res.put(self.allocator, "attempt_id", .{ .string = attempt });
        try res.put(self.allocator, "resumed", .{ .bool = false });
        try res.put(self.allocator, "profile", .{ .object = try profileObject(self.allocator, self.arch) });
        try res.put(self.allocator, "evidence_path", .{ .string = try std.fmt.allocPrint(self.allocator, "/{s}", .{ch.operation}) });
        try res.put(self.allocator, "documents", try self.buildDocuments(attempt, &.{
            .{ .kind = "request", .digest = ch.request_digest },
            .{ .kind = "progress", .digest = ch.progress_digest },
            .{ .kind = "receipt", .digest = receipt_doc.digest },
        }));
        try res.put(self.allocator, "diagnostics", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, diags) });
        return res;
    }

    fn planned(self: *Verifier, name: []const u8, attempt: []const u8, backend: []const u8, package: []const u8, status: i64) !std.json.ObjectMap {
        try require(status == 3, "planned run exited with unexpected status");
        const planned_files = [_][]const u8{
            "authorization-v1.json",
            "program-v1.json",
            "progress-v1.json",
            "receipt-v1.json",
            "request-v1.json",
        };
        const ch = try self.chain(attempt, backend, package, &planned_files);
        const lock_name = try std.fmt.allocPrint(self.allocator, "install-{s}.json", .{attempt});
        const lock_relative = try std.fmt.allocPrint(self.allocator, LOCKS ++ "/{s}", .{lock_name});
        const lock_bytes = try readRegularBytes(self.allocator, self.io, self.root_dir, lock_relative);
        const lock_file_sha512_arr = sha512Hex(lock_bytes);
        const lock_file_sha512 = try self.allocator.dupe(u8, &lock_file_sha512_arr);

        var lock_reference: std.json.ObjectMap = .empty;
        try lock_reference.put(self.allocator, "path", .{ .string = lock_relative });
        try lock_reference.put(self.allocator, "document_sha512", .{ .string = lock_file_sha512 });

        const lock_doc = try self.readEnvelope(lock_relative);
        try self.locks.append(self.allocator, lock_name);

        const program_doc = try self.readEnvelope(try std.fmt.allocPrint(self.allocator, "{s}/program-v1.json", .{ch.operation}));
        const auth_doc = try self.readEnvelope(try std.fmt.allocPrint(self.allocator, "{s}/authorization-v1.json", .{ch.operation}));
        const receipt_doc = try self.readEnvelope(try std.fmt.allocPrint(self.allocator, "{s}/receipt-v1.json", .{ch.operation}));

        const summary = try std.fmt.allocPrint(self.allocator, "{s} is planned and authorized by exact lock /{s}; {s}", .{
            package,
            lock_relative,
            PENDING,
        });
        var terminal: std.json.ObjectMap = .empty;
        try terminal.put(self.allocator, "outcome", .{ .string = "refused_before_mutation" });
        try terminal.put(self.allocator, "changed", .{ .bool = false });
        try terminal.put(self.allocator, "exit_status", .{ .integer = 3 });
        try terminal.put(self.allocator, "id", .{ .string = "transaction_backend_unavailable" });
        try terminal.put(self.allocator, "message", .{ .string = summary });

        var expected_prog: std.json.ObjectMap = .empty;
        try expected_prog.put(self.allocator, "schema", .{ .string = SCHEMA ++ "system-install-progress-v1" });
        try expected_prog.put(self.allocator, "version", .{ .integer = 1 });
        try expected_prog.put(self.allocator, "attempt_id", .{ .string = attempt });
        try expected_prog.put(self.allocator, "generation", .{ .integer = 4 });
        try expected_prog.put(self.allocator, "request_document_sha512", .{ .string = ch.request_digest });
        try expected_prog.put(self.allocator, "phase", .{ .string = "terminal" });
        try expected_prog.put(self.allocator, "lock", .{ .object = lock_reference });
        try expected_prog.put(self.allocator, "program_document_sha512", .{ .string = program_doc.digest });
        try expected_prog.put(self.allocator, "authorization_document_sha512", .{ .string = auth_doc.digest });
        try expected_prog.put(self.allocator, "terminal", .{ .object = terminal });
        try require(jsonEqual(.{ .object = ch.progress }, .{ .object = expected_prog }), "unexpected planned progress");

        var expected_rec: std.json.ObjectMap = .empty;
        try expected_rec.put(self.allocator, "schema", .{ .string = SCHEMA ++ "system-install-receipt-v1" });
        try expected_rec.put(self.allocator, "version", .{ .integer = 1 });
        try expected_rec.put(self.allocator, "attempt_id", .{ .string = attempt });
        try expected_rec.put(self.allocator, "request_document_sha512", .{ .string = ch.request_digest });
        try expected_rec.put(self.allocator, "progress_document_sha512", .{ .string = ch.progress_digest });
        try expected_rec.put(self.allocator, "terminal", .{ .object = terminal });
        try expected_rec.put(self.allocator, "lock", .{ .object = lock_reference });
        try expected_rec.put(self.allocator, "program_document_sha512", .{ .string = program_doc.digest });
        try expected_rec.put(self.allocator, "authorization_document_sha512", .{ .string = auth_doc.digest });
        try require(jsonEqual(.{ .object = receipt_doc.payload }, .{ .object = expected_rec }), "unexpected planned receipt");

        var expected_auth: std.json.ObjectMap = .empty;
        try expected_auth.put(self.allocator, "schema", .{ .string = SCHEMA ++ "system-install-authorization-v1" });
        try expected_auth.put(self.allocator, "version", .{ .integer = 1 });
        try expected_auth.put(self.allocator, "authority", .{ .string = "system_install_invocation" });
        try expected_auth.put(self.allocator, "attempt_id", .{ .string = attempt });
        try expected_auth.put(self.allocator, "command", .{ .string = ch.command });
        try expected_auth.put(self.allocator, "request_document_sha512", .{ .string = ch.request_digest });
        try expected_auth.put(self.allocator, "program_document_sha512", .{ .string = program_doc.digest });
        try expected_auth.put(self.allocator, "lock", .{ .object = lock_reference });
        try expected_auth.put(self.allocator, "backend", .{ .string = backend });
        try expected_auth.put(self.allocator, "conffile", .{ .string = "keep_existing" });
        try expected_auth.put(self.allocator, "noninteractive", .{ .bool = true });
        try expected_auth.put(self.allocator, "execution_generation", .{ .string = GENERATION });
        try require(jsonEqual(.{ .object = auth_doc.payload }, .{ .object = expected_auth }), "unexpected authorization");

        const prg = try self.verifyProgram(name, program_doc.payload, attempt, backend, package, ch.request_digest, lock_reference);
        const installed_obj = try getObj(try getField(program_doc.payload, "installed"));
        const prog_facts = try getArrayField(installed_obj, "facts");
        try self.verifyLock(name, lock_doc.payload, backend, program_doc.payload, prog_facts);

        var held_list: std.ArrayList(std.json.Value) = .empty;
        for (prog_facts) |fv| {
            const fo = try getObj(fv);
            if (std.mem.eql(u8, try getStringField(fo, "selection"), "hold")) {
                try held_list.append(self.allocator, fv);
            }
        }

        var plan_installed: std.json.ObjectMap = .empty;
        try plan_installed.put(self.allocator, "authority", .{ .string = "healthy_installed_prestate" });
        try plan_installed.put(self.allocator, "origin", .{ .string = "installed_package_database" });
        try plan_installed.put(self.allocator, "database_sha512", try getField(installed_obj, "database_sha512"));
        try plan_installed.put(self.allocator, "fact_count", .{ .integer = @intCast(prog_facts.len) });
        try plan_installed.put(self.allocator, "held", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, held_list.items) });

        var plan_obj: std.json.ObjectMap = .empty;
        try plan_obj.put(self.allocator, "target_architecture", .{ .string = self.arch });
        try plan_obj.put(self.allocator, "archives", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, @constCast(prg.archives)) });
        try plan_obj.put(self.allocator, "installed", .{ .object = plan_installed });
        try plan_obj.put(self.allocator, "repositories", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, @constCast(prg.repositories)) });

        var diag: std.json.ObjectMap = .empty;
        try diag.put(self.allocator, "id", .{ .string = "transaction_backend_unavailable" });
        try diag.put(self.allocator, "message", .{ .string = summary });
        const diags = try self.allocator.alloc(std.json.Value, 1);
        diags[0] = .{ .object = diag };

        var res: std.json.ObjectMap = .empty;
        try res.put(self.allocator, "schema", .{ .string = SCHEMA ++ "system-install-result-v1" });
        try res.put(self.allocator, "version", .{ .integer = 1 });
        try res.put(self.allocator, "operation", .{ .string = "install" });
        try res.put(self.allocator, "exit_status", .{ .integer = 3 });
        try res.put(self.allocator, "outcome", .{ .string = "refused_before_mutation" });
        try res.put(self.allocator, "changed", .{ .bool = false });
        try res.put(self.allocator, "package", .{ .string = package });
        try res.put(self.allocator, "summary", .{ .string = summary });
        try res.put(self.allocator, "backend", .{ .string = backend });
        try res.put(self.allocator, "command", .{ .string = ch.command });
        try res.put(self.allocator, "attempt_id", .{ .string = attempt });
        try res.put(self.allocator, "resumed", .{ .bool = false });
        try res.put(self.allocator, "profile", .{ .object = try profileObject(self.allocator, self.arch) });
        try res.put(self.allocator, "lock", .{ .string = try std.fmt.allocPrint(self.allocator, "/{s}", .{lock_relative}) });
        try res.put(self.allocator, "evidence_path", .{ .string = try std.fmt.allocPrint(self.allocator, "/{s}", .{ch.operation}) });
        try res.put(self.allocator, "documents", try self.buildDocuments(attempt, &.{
            .{ .kind = "request", .digest = ch.request_digest },
            .{ .kind = "progress", .digest = ch.progress_digest },
            .{ .kind = "lock", .digest = lock_file_sha512 },
            .{ .kind = "program", .digest = program_doc.digest },
            .{ .kind = "authorization", .digest = auth_doc.digest },
            .{ .kind = "receipt", .digest = receipt_doc.digest },
        }));
        try res.put(self.allocator, "plan", .{ .object = plan_obj });
        try res.put(self.allocator, "diagnostics", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, diags) });
        return res;
    }

    fn verifyProgram(
        self: *Verifier,
        name: []const u8,
        program: std.json.ObjectMap,
        attempt: []const u8,
        backend: []const u8,
        package: []const u8,
        request_digest: []const u8,
        lock_reference: std.json.ObjectMap,
    ) !struct { archives: []const std.json.Value, repositories: []const std.json.Value } {
        _ = name;
        const native = std.mem.eql(u8, backend, "native");
        const binding = if (native) DERIVED else "published_digests";
        const repositories = try getArrayField(program, "repositories");
        try require(repositories.len > 0, "the program names no repository");

        var repo_ids: std.ArrayList([]const u8) = .empty;
        for (repositories) |rv| {
            const repo = try getObj(rv);
            const rid = try getStringField(repo, "id");
            try require(isNonEmptyLowerHex(rid), "invalid repository id");
            try repo_ids.append(self.allocator, rid);

            var fresh_obj: std.json.ObjectMap = .empty;
            try fresh_obj.put(self.allocator, "policy", .{ .string = "bounded_missing_valid_until" });
            try fresh_obj.put(self.allocator, "maximum_release_age_seconds", .{ .integer = BOUND });
            const signers = try self.allocator.alloc(std.json.Value, 1);
            signers[0] = .{ .string = SIGNER };

            var expected_repo: std.json.ObjectMap = .empty;
            try expected_repo.put(self.allocator, "id", .{ .string = rid });
            try expected_repo.put(self.allocator, "uri", .{ .string = "https://packages.microsoft.com/ubuntu/24.04/prod" });
            try expected_repo.put(self.allocator, "suite", .{ .string = "noble" });
            try expected_repo.put(self.allocator, "component", .{ .string = "main" });
            try expected_repo.put(self.allocator, "archive_binding", .{ .string = binding });
            try expected_repo.put(self.allocator, "signers", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, signers) });
            try expected_repo.put(self.allocator, "freshness", .{ .object = fresh_obj });
            try require(jsonEqual(rv, .{ .object = expected_repo }), "unexpected repository authority");
        }

        const archives = try getArrayField(program, "archives");
        if (std.mem.eql(u8, package, "symcrypt")) {
            try require(archives.len == 1, "unexpected archive closure for symcrypt");
            const a0 = try getObj(archives[0]);
            try require(std.mem.eql(u8, try getStringField(a0, "package"), "symcrypt") and std.mem.eql(u8, try getStringField(a0, "retention"), "requested"), "unexpected archive closure for symcrypt");
        } else if (std.mem.eql(u8, package, "symcrypt-openssl")) {
            try require(archives.len == 2, "unexpected archive closure for symcrypt-openssl");
            const a0 = try getObj(archives[0]);
            const a1 = try getObj(archives[1]);
            try require(
                std.mem.eql(u8, try getStringField(a0, "package"), "symcrypt") and
                    std.mem.eql(u8, try getStringField(a0, "retention"), "dependency") and
                    std.mem.eql(u8, try getStringField(a1, "package"), "symcrypt-openssl") and
                    std.mem.eql(u8, try getStringField(a1, "retention"), "requested"),
                "unexpected archive closure for symcrypt-openssl",
            );
        } else {
            return fail("unexpected package {s}", .{package});
        }

        for (archives) |av| {
            const archive_obj = try getObj(av);
            const arch_str = try getStringField(archive_obj, "architecture");
            const ver_str = try getStringField(archive_obj, "version");
            const pkg_str = try getStringField(archive_obj, "package");
            try require((std.mem.eql(u8, arch_str, self.arch) or std.mem.eql(u8, arch_str, "all")) and ver_str.len > 0, "unexpected archive");

            const repo_id = try getStringField(archive_obj, "repository_id");
            var repo_listed = false;
            for (repo_ids.items) |rid| {
                if (std.mem.eql(u8, rid, repo_id)) {
                    repo_listed = true;
                    break;
                }
            }
            try require(repo_listed, "an archive names an unlisted repository");
            const declared_size = try getU64Field(archive_obj, "declared_size");
            try require((try getBoolField(archive_obj, "dpkg_selection_hold")) == false and declared_size > 0, "unexpected archive");

            const published = try getArrayField(archive_obj, "published_digests");
            try require(published.len == 1, "the signed index should publish only SHA-256");
            const pub0 = try getObj(published[0]);
            try require(
                std.mem.eql(u8, try getStringField(pub0, "algorithm"), "sha256") and
                    std.mem.eql(u8, try getStringField(archive_obj, "primary"), "sha256"),
                "the signed index should publish only SHA-256",
            );
            const signed = try getStringField(pub0, "value");
            try self.recordSigned(pkg_str, ver_str, arch_str, signed);

            const auth_str = try getStringField(archive_obj, "archive_authentication");
            if (native) {
                const derived_obj = try getObj(try getField(archive_obj, "derived_sha512"));
                const derived_val = try getStringField(derived_obj, "value");
                const provenance_str = try getStringField(derived_obj, "provenance");
                try require(
                    std.mem.eql(u8, auth_str, DERIVED) and
                        derived_obj.count() == 2 and
                        std.mem.eql(u8, provenance_str, "derived_from_signed_sha256") and
                        isLowerHex(derived_val, 128),
                    "archive is not derived_from_signed_sha256",
                );
                try self.recordDerived(pkg_str, ver_str, arch_str, derived_val);
                const found = try self.cache.matches(self.allocator, self.io, declared_size, signed);
                try require(found.len > 0, "no cached archive matches the signed SHA-256");
                try require(allEqualSlice(found, derived_val), "the derived SHA-512 is not over the signed SHA-256 bytes");
            } else {
                try require(std.mem.eql(u8, auth_str, "signed_sha256_only") and !archive_obj.contains("derived_sha512"), "the legacy plan claims a SHA-512");
            }
        }

        var expected_facts: std.ArrayList(std.json.Value) = .empty;
        for (self.facts) |fact| {
            var in_planned = false;
            for (archives) |av| {
                const ao = try getObj(av);
                if (std.mem.eql(u8, try getStringField(ao, "package"), fact.name) and
                    std.mem.eql(u8, try getStringField(ao, "architecture"), fact.architecture))
                {
                    in_planned = true;
                    break;
                }
            }
            if (!in_planned) {
                try expected_facts.append(self.allocator, try fact.toJsonValue(self.allocator));
            }
        }

        const installed = try getObj(try getField(program, "installed"));
        const db_sha512 = try getStringField(installed, "database_sha512");
        try require(isLowerHex(db_sha512, 128), "no installed database identity");
        try self.recordDatabase(db_sha512);

        var expected_installed: std.json.ObjectMap = .empty;
        try expected_installed.put(self.allocator, "authority", .{ .string = "healthy_installed_prestate" });
        try expected_installed.put(self.allocator, "origin", .{ .string = "installed_package_database" });
        try expected_installed.put(self.allocator, "database_sha512", .{ .string = db_sha512 });
        try expected_installed.put(self.allocator, "facts", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, expected_facts.items) });
        try require(jsonEqual(.{ .object = installed }, .{ .object = expected_installed }), "the program's installed facts differ from /var/lib/dpkg/status");

        var expected_program: std.json.ObjectMap = .empty;
        try expected_program.put(self.allocator, "schema", .{ .string = SCHEMA ++ "system-install-program-v1" });
        try expected_program.put(self.allocator, "version", .{ .integer = 1 });
        try expected_program.put(self.allocator, "attempt_id", .{ .string = attempt });
        try expected_program.put(self.allocator, "request_document_sha512", .{ .string = request_digest });
        try expected_program.put(self.allocator, "lock", .{ .object = lock_reference });
        try expected_program.put(self.allocator, "backend", .{ .string = backend });
        try expected_program.put(self.allocator, "target_architecture", .{ .string = self.arch });
        try expected_program.put(self.allocator, "execution_generation", .{ .string = GENERATION });
        try expected_program.put(self.allocator, "archives", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, @constCast(archives)) });
        try expected_program.put(self.allocator, "installed", .{ .object = installed });
        try expected_program.put(self.allocator, "repositories", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, @constCast(repositories)) });
        try require(jsonEqual(.{ .object = program }, .{ .object = expected_program }), "unexpected program fields");

        return .{ .archives = archives, .repositories = repositories };
    }

    fn verifyLock(
        self: *Verifier,
        name: []const u8,
        lock: std.json.ObjectMap,
        backend: []const u8,
        program: std.json.ObjectMap,
        facts: []const std.json.Value,
    ) !void {
        _ = name;
        try require(
            std.mem.eql(u8, try getStringField(lock, "schema"), SCHEMA ++ "exact-closure-lock-v5") and
                (try getU64Field(lock, "version")) == 5,
            "the exact lock is not version 5",
        );
        try require(
            std.mem.eql(u8, try getStringField(lock, "backend"), backend) and
                std.mem.eql(u8, try getStringField(lock, "usage"), "healthy_prestate_planning_only"),
            "the exact lock names another backend or usage",
        );
        const prestate = try getObj(try getField(lock, "installed_prestate"));
        try require(
            std.mem.eql(u8, try getStringField(prestate, "schema"), SCHEMA ++ "healthy-installed-prestate-v1") and
                std.mem.eql(u8, try getStringField(prestate, "authority"), "healthy_installed_prestate"),
            "no healthy prestate",
        );
        const observed = try getObj(try getField(prestate, "observed"));
        try require(
            std.mem.eql(u8, try getStringField(observed, "root_path"), LOGICAL_ROOT) and
                std.mem.eql(u8, try getStringField(observed, "native_architecture"), self.arch),
            "the prestate names another root or architecture",
        );
        const prog_installed = try getObj(try getField(program, "installed"));
        var expected_db_id: std.json.ObjectMap = .empty;
        try expected_db_id.put(self.allocator, "algorithm", .{ .string = "sha512" });
        try expected_db_id.put(self.allocator, "value", try getField(prog_installed, "database_sha512"));
        try require(jsonEqual(try getField(observed, "database_identity"), .{ .object = expected_db_id }), "the lock and program bind different installed databases");
        try require(
            jsonEqual(try getField(observed, "packages"), .{ .array = std.json.Array.fromOwnedSlice(self.allocator, @constCast(facts)) }),
            "the lock and program bind different installed facts",
        );

        const archive_lock_val = try parseJson(self.allocator, try getStringField(lock, "archive_lock_json"), "archive_lock_json");
        const archive_lock = try getObj(archive_lock_val);
        try require(
            std.mem.eql(u8, try getStringField(archive_lock, "schema"), SCHEMA ++ "exact-closure-lock-v3") and
                (try getU64Field(archive_lock, "version")) == 3,
            "the archive closure is not an exact v3 lock",
        );
        try require(
            std.mem.eql(u8, try getStringField(archive_lock, "target_architecture"), self.arch) and
                (try getArrayField(archive_lock, "local_artifacts")).len == 0,
            "unexpected archive closure scope",
        );

        const lock_repos = try getArrayField(archive_lock, "repositories");
        const prog_repos = try getArrayField(program, "repositories");
        try require(lock_repos.len == prog_repos.len, "the lock and program name different repositories");
        for (prog_repos) |prv| {
            const pr = try getObj(prv);
            const pr_id = try getStringField(pr, "id");
            var matched_lr: ?std.json.ObjectMap = null;
            for (lock_repos) |lrv| {
                const lr = try getObj(lrv);
                if (std.mem.eql(u8, try getStringField(lr, "id"), pr_id)) {
                    matched_lr = lr;
                    break;
                }
            }
            const entry = matched_lr orelse return fail("the lock and program name different repositories", .{});
            const entry_binding = if (entry.get("archive_binding")) |ab|
                (if (ab == .string) ab.string else return fail("invalid archive_binding", .{}))
            else
                "published_digests";
            try require(std.mem.eql(u8, entry_binding, try getStringField(pr, "archive_binding")), "the lock and program bind repository differently");

            const lock_fps = try getArrayField(entry, "signer_fingerprints");
            const prog_fps = try getArrayField(pr, "signers");
            try require(lock_fps.len == prog_fps.len, "the lock and program name different signers");
            for (lock_fps, prog_fps) |lfp, pfp| {
                if (lfp != .string or pfp != .string) return fail("signer is not string", .{});
                try require(std.ascii.eqlIgnoreCase(lfp.string, pfp.string), "the lock and program name different signers");
            }
        }

        const packages = try getArrayField(archive_lock, "packages");
        const prog_archives = try getArrayField(program, "archives");
        try require(packages.len == prog_archives.len, "the lock and program differ in size");
        for (packages, prog_archives) |pv, av| {
            const entry = try getObj(pv);
            const archive = try getObj(av);
            const pub0 = try getObj((try getArrayField(archive, "published_digests"))[0]);
            const signed = try getStringField(pub0, "value");
            const origin = try getObj(try getField(entry, "origin"));

            var dig_entry: std.json.ObjectMap = .empty;
            try dig_entry.put(self.allocator, "algorithm", .{ .string = "sha256" });
            try dig_entry.put(self.allocator, "digest", .{ .string = signed });
            const digs = try self.allocator.alloc(std.json.Value, 1);
            digs[0] = .{ .object = dig_entry };
            var expected_arch_id: std.json.ObjectMap = .empty;
            try expected_arch_id.put(self.allocator, "primary", .{ .string = "sha256" });
            try expected_arch_id.put(self.allocator, "digests", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, digs) });

            try require(
                std.mem.eql(u8, try getStringField(entry, "name"), try getStringField(archive, "package")) and
                    std.mem.eql(u8, try getStringField(entry, "version"), try getStringField(archive, "version")) and
                    std.mem.eql(u8, try getStringField(entry, "architecture"), try getStringField(archive, "architecture")) and
                    std.mem.eql(u8, try getStringField(entry, "retention"), try getStringField(archive, "retention")) and
                    (try getU64Field(entry, "declared_size")) == (try getU64Field(archive, "declared_size")) and
                    (try getBoolField(entry, "dpkg_selection_hold")) == (try getBoolField(archive, "dpkg_selection_hold")) and
                    std.mem.eql(u8, try getStringField(origin, "type"), "authenticated_repository") and
                    std.mem.eql(u8, try getStringField(origin, "repository_id"), try getStringField(archive, "repository_id")) and
                    jsonEqual(try getField(entry, "archive_identity"), .{ .object = expected_arch_id }),
                "the lock and program differ for archive",
            );

            if (archive.get("derived_sha512")) |derived_val| {
                const derived = try getObj(derived_val);
                var expected_derived_id: std.json.ObjectMap = .empty;
                try expected_derived_id.put(self.allocator, "provenance", .{ .string = "derived_from_signed_sha256" });
                try expected_derived_id.put(self.allocator, "algorithm", .{ .string = "sha512" });
                try expected_derived_id.put(self.allocator, "digest", try getField(derived, "value"));
                try require(
                    entry.contains("derived_archive_identity") and
                        jsonEqual(try getField(entry, "derived_archive_identity"), .{ .object = expected_derived_id }),
                    "the lock and program differ in the derived SHA-512",
                );
            } else {
                try require(!entry.contains("derived_archive_identity"), "the legacy lock records a SHA-512");
            }
        }
    }

    fn verifyAll(self: *Verifier) !std.json.Value {
        const index_raw = try readRegularBytes(self.allocator, self.io, self.out_dir, "runs/index");
        var root_runs: usize = 0;
        var lines = std.mem.splitScalar(u8, index_raw, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0) continue;
            var it = std.mem.tokenizeAny(u8, line, " \t");
            const name = it.next() orelse return fail("malformed runs/index line", .{});
            const user = it.next() orelse return fail("malformed runs/index line", .{});
            const output = it.next() orelse return fail("malformed runs/index line", .{});
            const backend = it.next() orelse return fail("malformed runs/index line", .{});
            const package = it.next() orelse return fail("malformed runs/index line", .{});
            try require(it.next() == null, "malformed runs/index line");
            try self.runOne(name, user, output, backend, package);
            if (std.mem.eql(u8, user, "root")) root_runs += 1;
        }

        try require(!try self.pathExists(EVIDENCE ++ "/active-v1.json"), "an owned attempt was left unsettled");
        try require(self.attempts.items.len == root_runs, "a root run left no attempt");

        const op_dirs = if (try self.pathExists(OPERATIONS))
            try listSortedNames(self.allocator, self.io, self.root_dir, OPERATIONS)
        else
            try self.allocator.alloc([]u8, 0);
        const sorted_attempts = try self.allocator.dupe([]const u8, self.attempts.items);
        std.mem.sort([]const u8, sorted_attempts, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.lessThan);
        try require(stringSlicesEqual(op_dirs, sorted_attempts), "the evidence directory holds attempts no run reported");

        var published_list: std.ArrayList([]const u8) = .empty;
        if (try self.pathExists(LOCKS)) {
            const lock_names = try listSortedNames(self.allocator, self.io, self.root_dir, LOCKS);
            for (lock_names) |ln| {
                if (std.mem.startsWith(u8, ln, "install-") and std.mem.endsWith(u8, ln, ".json")) {
                    try published_list.append(self.allocator, ln);
                }
            }
        }
        const published = try published_list.toOwnedSlice(self.allocator);
        std.mem.sort([]const u8, self.locks.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.lessThan);
        try require(stringSlicesEqual(published, self.locks.items), "the locks directory holds install locks no planned run reported");

        var held_vals: std.ArrayList(std.json.Value) = .empty;
        for (self.facts) |fact| {
            if (std.mem.eql(u8, fact.selection, "hold")) {
                try held_vals.append(self.allocator, try fact.toJsonValue(self.allocator));
            }
        }
        std.mem.sort([]const u8, self.databases.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.lessThan);
        var db_vals: std.ArrayList(std.json.Value) = .empty;
        for (self.databases.items) |db| try db_vals.append(self.allocator, .{ .string = db });

        std.mem.sort(ArchiveIdentityRecord, self.archive_identities.items, {}, ArchiveIdentityRecord.lessThan);
        var arch_id_vals: std.ArrayList(std.json.Value) = .empty;
        for (self.archive_identities.items) |aid| {
            var obj: std.json.ObjectMap = .empty;
            try obj.put(self.allocator, "package", .{ .string = aid.package });
            try obj.put(self.allocator, "version", .{ .string = aid.version });
            try obj.put(self.allocator, "architecture", .{ .string = aid.architecture });
            try obj.put(self.allocator, "signed_sha256", .{ .string = aid.signed_sha256 });
            if (aid.derived_sha512) |d| {
                try obj.put(self.allocator, "derived_sha512", .{ .string = d });
            } else {
                try obj.put(self.allocator, "derived_sha512", .null);
            }
            try arch_id_vals.append(self.allocator, .{ .object = obj });
        }

        var root_obj: std.json.ObjectMap = .empty;
        try root_obj.put(self.allocator, "architecture", .{ .string = self.arch });
        try root_obj.put(self.allocator, "runs", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, self.reports.items) });
        try root_obj.put(self.allocator, "installed_facts", .{ .integer = @intCast(self.facts.len) });
        try root_obj.put(self.allocator, "held", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, held_vals.items) });
        try root_obj.put(self.allocator, "database_identities", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, db_vals.items) });
        try root_obj.put(self.allocator, "archive_identities", .{ .array = std.json.Array.fromOwnedSlice(self.allocator, arch_id_vals.items) });
        return .{ .object = root_obj };
    }
};

fn runCli(allocator: std.mem.Allocator, io: std.Io, args: []const []const u8) !u8 {
    if (args.len < 2) return fail("usage: debz-system-install-live-proof <prestate|snapshot|repo-add|verify> ...", .{});
    var root_dir = std.Io.Dir.openDirAbsolute(io, ROOT, .{ .follow_symlinks = false, .iterate = true }) catch |err|
        return fail("openDirAbsolute(/) failed: {s}", .{@errorName(err)});
    defer root_dir.close(io);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "prestate")) {
        if (args.len != 3) return fail("usage: prestate ARCH", .{});
        return checkPrestate(allocator, io, root_dir, args[2], stdout);
    } else if (std.mem.eql(u8, cmd, "snapshot")) {
        if (args.len != 2) return fail("usage: snapshot", .{});
        return snapshot(allocator, io, root_dir, stdout);
    } else if (std.mem.eql(u8, cmd, "repo-add")) {
        if (args.len != 5) return fail("usage: repo-add OUT DESCRIPTOR ARCH", .{});
        var out_dir = std.Io.Dir.openDirAbsolute(io, args[2], .{ .follow_symlinks = false, .iterate = true }) catch |err|
            return fail("openDirAbsolute({s}) failed: {s}", .{ args[2], @errorName(err) });
        defer out_dir.close(io);
        return verifyRepoAdd(allocator, io, root_dir, out_dir, args[3], args[4], stdout);
    } else if (std.mem.eql(u8, cmd, "verify")) {
        if (args.len != 4) return fail("usage: verify OUT ARCH", .{});
        var out_dir = std.Io.Dir.openDirAbsolute(io, args[2], .{ .follow_symlinks = false, .iterate = true }) catch |err|
            return fail("openDirAbsolute({s}) failed: {s}", .{ args[2], @errorName(err) });
        defer out_dir.close(io);
        var verifier = try Verifier.init(allocator, io, root_dir, out_dir, args[3]);
        const summary_val = try verifier.verifyAll();
        const summary_json = try std.json.Stringify.valueAlloc(allocator, summary_val, .{ .whitespace = .indent_1 });
        try stdout.writeAll(summary_json);
        try stdout.writeByte('\n');
        try stdout.flush();
        return 0;
    } else {
        return fail("unknown subcommand: {s}", .{cmd});
    }
}

pub fn main(init: std.process.Init) !u8 {
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    return runCli(allocator, init.io, args) catch |err| {
        var stderr_buf: [1024]u8 = undefined;
        var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buf);
        const msg = last_failure_message orelse @errorName(err);
        stderr_writer.interface.print("system-install-live-proof: {s}\n", .{msg}) catch {};
        stderr_writer.interface.flush() catch {};
        return 1;
    };
}

test "parseStatus classifies healthy installed and config-files stanzas" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const sample =
        \\Package: bash
        \\Status: install ok installed
        \\Version: 5.2.21-2ubuntu4
        \\Architecture: amd64
        \\
        \\Package: old-pkg
        \\Status: deinstall ok config-files
        \\Version: 1.0-1
        \\Architecture: all
        \\
    ;
    const parsed = try parseStatus(allocator, sample);
    try std.testing.expectEqual(@as(usize, 0), parsed.problems.len);
    try std.testing.expectEqual(@as(usize, 2), parsed.stanza_count);
    try std.testing.expectEqual(@as(usize, 1), parsed.facts.len);
    try std.testing.expectEqualStrings("bash", parsed.facts[0].name);
    try std.testing.expectEqualStrings("install", parsed.facts[0].selection);
}

test "parseEnvelopeBytes and upstream check behave deterministically" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const payload = "{\"a\":1,\"b\":\"two\"}";
    const digest = sha512Hex(payload);
    const raw = try std.fmt.allocPrint(allocator, "{{\"payload\":{s},\"digest_sha512\":\"{s}\"}}\n", .{ payload, &digest });
    const env = try parseEnvelopeBytes(allocator, raw, "test");
    try std.testing.expectEqualStrings(&digest, env.digest);
    try std.testing.expect(containsAsciiCaseInsensitive("Found UPSTREAM digest", "upstream"));
    try std.testing.expect(!containsAsciiCaseInsensitive("signed_sha256_derived_sha512", "upstream"));
}

test "parseStatus classifies Ubuntu Noble OpenSSL baseline and held facts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const noble_sample =
        \\Package: libc6
        \\Status: install ok installed
        \\Version: 2.39-0ubuntu8.4
        \\Architecture: amd64
        \\
        \\Package: libssl3t64
        \\Status: install ok installed
        \\Version: 3.0.13-0ubuntu3.5
        \\Architecture: amd64
        \\Provides: libssl3 (= 3.0.13-0ubuntu3.5)
        \\
        \\Package: openssl
        \\Status: install ok installed
        \\Version: 3.0.13-0ubuntu3.5
        \\Architecture: amd64
        \\
        \\Package: local-fips-policy
        \\Status: hold ok installed
        \\Version: 24.04.1-local
        \\Architecture: amd64
        \\
    ;
    const parsed = try parseStatus(allocator, noble_sample);
    try std.testing.expectEqual(@as(usize, 0), parsed.problems.len);
    try std.testing.expectEqual(@as(usize, 4), parsed.stanza_count);
    try std.testing.expectEqual(@as(usize, 4), parsed.facts.len);
    try std.testing.expectEqualStrings("libc6", parsed.facts[0].name);
    try std.testing.expectEqualStrings("libssl3t64", parsed.facts[1].name);
    try std.testing.expectEqualStrings("local-fips-policy", parsed.facts[2].name);
    try std.testing.expectEqualStrings("hold", parsed.facts[2].selection);
    try std.testing.expectEqualStrings("openssl", parsed.facts[3].name);
    try std.testing.expectEqualStrings("install", parsed.facts[3].selection);
}

