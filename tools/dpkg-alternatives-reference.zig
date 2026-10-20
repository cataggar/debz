const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

fn dupeZ(allocator: std.mem.Allocator, text: []const u8) ![:0]u8 {
    return allocator.dupeSentinel(u8, text, 0);
}

pub const reference_relative = "tools/fixtures/vendor-state/dpkg-alternatives-reference-v1.json";
pub const schema_relative = "schema/dpkg-alternatives-reference-v1.json";
pub const schema_id = "https://debz.dev/schema/dpkg-alternatives-reference-v1";
pub const trace_relative = "var/log/debz-alternatives-oracle.trace";
pub const fd_errors_relative = "var/log/debz-alternatives-oracle.fd-errors";
pub const failures_relative = "debz-alternatives-oracle.failures";
pub const pause_relative = "debz-alternatives-oracle.pause";
pub const paused_relative = "debz-alternatives-oracle.paused";
pub const dpkg_log_relative = "var/log/dpkg.log";
pub const alt_log_relative = "var/log/alternatives.log";
pub const group_name = "debz-alternatives";
pub const canonical_task_invocation = "2026-09-20T12:22:59.658+00:00";
pub const guard_relative = ".debz-native-disposable";
pub const guard_content = "debz native materialization fixture v1\n";
pub const default_package_name = "debz-native-demo";
pub const epoch: i64 = 1_700_000_000;

pub const script_kinds = [_][]const u8{ "preinst", "postinst", "prerm", "postrm" };
pub const forbidden_frontend_env = [_][]const u8{
    "DEBCONF_DB_FALLBACK",
    "DEBCONF_DB_OVERRIDE",
    "DEBCONF_DEBUG",
    "DEBIAN_FRONTEND",
};
pub const forbidden_frontend_paths = [_][]const u8{
    "usr/bin/apt",
    "usr/bin/apt-get",
    "usr/sbin/dpkg-preconfigure",
    "usr/bin/debconf",
};

pub const pinned_dpkg_config =
    \\# dpkg configuration file
    \\#
    \\# This file can contain default options for dpkg.  All command-line
    \\# options are allowed.  Values can be specified by putting them after
    \\# the option, separated by whitespace and/or an `=' sign.
    \\#
    \\
    \\# Do not enable debsig-verify by default; since the distribution is not using
    \\# embedded signatures, debsig-verify would reject all packages.
    \\no-debsig
    \\
    \\# Log status changes and actions to a file.
    \\log /var/log/dpkg.log
    \\
;

pub const Limits = struct {
    pub const maximum_groups: usize = 32;
    pub const maximum_relationships: usize = 128;
    pub const maximum_requested_paths: usize = 256;
    pub const maximum_linked_entries: usize = 256;
    pub const maximum_record_bytes: usize = 256 * 1024;
    pub const maximum_total_record_bytes: usize = 2 * 1024 * 1024;
    pub const maximum_output_bytes: usize = 128 * 1024;
    pub const maximum_log_bytes: usize = 256 * 1024;
    pub const maximum_path_bytes: usize = 4096;
    pub const maximum_arguments: usize = 512;
    pub const maximum_argument_bytes: usize = 4096;
    pub const maximum_cases: usize = 64;
    pub const maximum_info_files: usize = 32;
    pub const maximum_info_bytes: usize = 1024 * 1024;
    pub const maximum_database_files: usize = 64;
    pub const maximum_database_bytes: usize = 1024 * 1024;
    pub const maximum_payload_files: usize = 64;
    pub const maximum_payload_bytes: usize = 1024 * 1024;
    pub const maximum_host_entries: usize = 100_000;
    pub const maximum_archive_bytes: usize = 8 * 1024 * 1024;
    pub const dependency_timeout_seconds: i64 = 10;
    pub const subprocess_timeout_seconds: i64 = 30;
    pub const subprocess_cleanup_seconds: i64 = 2;
    pub const pause_timeout_seconds: i64 = 10;
    pub const maximum_status_bytes: usize = 256 * 1024;
    pub const maximum_updates: usize = 32;
};

const LimitEntry = struct { name: []const u8, value: i64 };
const limit_contract_entries = [_]LimitEntry{
    .{ .name = "dependency_timeout_seconds", .value = Limits.dependency_timeout_seconds },
    .{ .name = "maximum_archive_bytes", .value = Limits.maximum_archive_bytes },
    .{ .name = "maximum_argument_bytes", .value = Limits.maximum_argument_bytes },
    .{ .name = "maximum_arguments", .value = Limits.maximum_arguments },
    .{ .name = "maximum_cases", .value = Limits.maximum_cases },
    .{ .name = "maximum_database_bytes", .value = Limits.maximum_database_bytes },
    .{ .name = "maximum_database_files", .value = Limits.maximum_database_files },
    .{ .name = "maximum_groups", .value = Limits.maximum_groups },
    .{ .name = "maximum_host_entries", .value = Limits.maximum_host_entries },
    .{ .name = "maximum_info_bytes", .value = Limits.maximum_info_bytes },
    .{ .name = "maximum_info_files", .value = Limits.maximum_info_files },
    .{ .name = "maximum_linked_entries", .value = Limits.maximum_linked_entries },
    .{ .name = "maximum_log_bytes", .value = Limits.maximum_log_bytes },
    .{ .name = "maximum_output_bytes", .value = Limits.maximum_output_bytes },
    .{ .name = "maximum_path_bytes", .value = Limits.maximum_path_bytes },
    .{ .name = "maximum_payload_bytes", .value = Limits.maximum_payload_bytes },
    .{ .name = "maximum_payload_files", .value = Limits.maximum_payload_files },
    .{ .name = "maximum_record_bytes", .value = Limits.maximum_record_bytes },
    .{ .name = "maximum_relationships", .value = Limits.maximum_relationships },
    .{ .name = "maximum_requested_paths", .value = Limits.maximum_requested_paths },
    .{ .name = "maximum_total_record_bytes", .value = Limits.maximum_total_record_bytes },
    .{ .name = "pause_timeout_seconds", .value = Limits.pause_timeout_seconds },
    .{ .name = "subprocess_cleanup_seconds", .value = Limits.subprocess_cleanup_seconds },
    .{ .name = "subprocess_timeout_seconds", .value = Limits.subprocess_timeout_seconds },
};

const Sha256 = std.crypto.hash.sha2.Sha256;
const Md5 = std.crypto.hash.Md5;

fn fail(comptime fmt: []const u8, args: anytype) error{OracleError} {
    if (!@inComptime() and !builtin.is_test) {
        std.debug.print("dpkg-alternatives-reference: " ++ fmt ++ "\n", args);
    }
    return error.OracleError;
}

pub fn sha256HexAlloc(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    return allocator.dupe(u8, &hex);
}

pub fn base64EncodeAlloc(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const out = try allocator.alloc(u8, encoder.calcSize(data.len));
    _ = encoder.encode(out, data);
    return out;
}

pub fn base64DecodeAlloc(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const size = try decoder.calcSizeForSlice(encoded);
    const out = try allocator.alloc(u8, size);
    try decoder.decode(out, encoded);
    return out;
}

pub fn isIdentityName(text: []const u8) bool {
    if (text.len == 0) return false;
    if (!std.ascii.isLower(text[0]) and !std.ascii.isDigit(text[0])) return false;
    for (text[1..]) |byte| {
        if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '+' and byte != '.' and byte != '-')
            return false;
    }
    return true;
}

fn isUpdateName(text: []const u8) bool {
    if (text.len != 4) return false;
    for (text) |byte| if (!std.ascii.isDigit(byte)) return false;
    return true;
}

fn inList(comptime list: []const []const u8, candidate: []const u8) bool {
    for (list) |item| {
        if (std.mem.eql(u8, item, candidate)) return true;
    }
    return false;
}

fn canonicalValue(
    value: std.json.Value,
    stream: *std.json.Stringify,
    allocator: std.mem.Allocator,
    depth: usize,
) anyerror!void {
    if (depth > 64) return error.OracleError;
    switch (value) {
        .object => |object| {
            const keys = try allocator.dupe([]const u8, object.keys());
            defer allocator.free(keys);
            std.sort.heap([]const u8, keys, {}, struct {
                fn less(_: void, left: []const u8, right: []const u8) bool {
                    return std.mem.order(u8, left, right) == .lt;
                }
            }.less);
            try stream.beginObject();
            for (keys) |key| {
                try stream.objectField(key);
                try canonicalValue(object.get(key).?, stream, allocator, depth + 1);
            }
            try stream.endObject();
        },
        .array => |array| {
            try stream.beginArray();
            for (array.items) |item| try canonicalValue(item, stream, allocator, depth + 1);
            try stream.endArray();
        },
        else => try stream.write(value),
    }
}

pub fn canonicalJson(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var stream: std.json.Stringify = .{
        .writer = &output.writer,
        .options = .{ .whitespace = .indent_2, .escape_unicode = true },
    };
    try canonicalValue(value, &stream, allocator, 0);
    try output.writer.writeByte('\n');
    return output.toOwnedSlice();
}

pub fn jsonEqual(left: std.json.Value, right: std.json.Value) bool {
    switch (left) {
        .null => return right == .null,
        .bool => |b| return right == .bool and b == right.bool,
        .integer => |i| return right == .integer and i == right.integer,
        .float => |f| return right == .float and f == right.float,
        .number_string => |s| return right == .number_string and std.mem.eql(u8, s, right.number_string),
        .string => |s| return right == .string and std.mem.eql(u8, s, right.string),
        .array => |arr| {
            if (right != .array or arr.items.len != right.array.items.len) return false;
            for (arr.items, right.array.items) |a, b| {
                if (!jsonEqual(a, b)) return false;
            }
            return true;
        },
        .object => |obj| {
            if (right != .object or obj.count() != right.object.count()) return false;
            var it = obj.iterator();
            while (it.next()) |entry| {
                const other = right.object.get(entry.key_ptr.*) orelse return false;
                if (!jsonEqual(entry.value_ptr.*, other)) return false;
            }
            return true;
        },
    }
}

pub fn cloneJsonValue(allocator: std.mem.Allocator, value: std.json.Value) !std.json.Value {
    switch (value) {
        .null, .bool, .integer, .float => return value,
        .number_string => |s| return .{ .number_string = try allocator.dupe(u8, s) },
        .string => |s| return .{ .string = try allocator.dupe(u8, s) },
        .array => |arr| {
            var copy: std.json.Array = .init(allocator);
            try copy.ensureTotalCapacity(arr.items.len);
            for (arr.items) |item| {
                copy.appendAssumeCapacity(try cloneJsonValue(allocator, item));
            }
            return .{ .array = copy };
        },
        .object => |obj| {
            var copy: std.json.ObjectMap = .empty;
            var it = obj.iterator();
            while (it.next()) |entry| {
                try copy.put(
                    allocator,
                    try allocator.dupe(u8, entry.key_ptr.*),
                    try cloneJsonValue(allocator, entry.value_ptr.*),
                );
            }
            return .{ .object = copy };
        },
    }
}

pub const FileMetadata = struct {
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u64,
    uid: u32,
    gid: u32,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
};

fn errnoFailed(rc: usize) bool {
    return linux.errno(rc) != .SUCCESS;
}

pub fn lstatPath(allocator: std.mem.Allocator, path: []const u8) !FileMetadata {
    const path_z = try dupeZ(allocator, path);
    defer allocator.free(path_z);
    var stx: linux.Statx = std.mem.zeroes(linux.Statx);
    const rc = linux.statx(
        linux.AT.FDCWD,
        path_z.ptr,
        linux.AT.SYMLINK_NOFOLLOW | linux.AT.STATX_SYNC_AS_STAT,
        linux.STATX.BASIC_STATS,
        &stx,
    );
    return switch (linux.errno(rc)) {
        .SUCCESS => .{
            .dev = (@as(u64, stx.dev_major) << 32) | @as(u64, stx.dev_minor),
            .ino = stx.ino,
            .mode = stx.mode,
            .nlink = stx.nlink,
            .uid = stx.uid,
            .gid = stx.gid,
            .size = stx.size,
            .mtime_sec = stx.mtime.sec,
            .mtime_nsec = stx.mtime.nsec,
            .ctime_sec = stx.ctime.sec,
            .ctime_nsec = stx.ctime.nsec,
        },
        .NOENT => error.FileNotFound,
        else => error.OracleError,
    };
}

pub fn lexistsPath(allocator: std.mem.Allocator, path: []const u8) !bool {
    _ = lstatPath(allocator, path) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

pub fn readSymlinkAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const path_z = try dupeZ(allocator, path);
    defer allocator.free(path_z);
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const rc = linux.readlinkat(linux.AT.FDCWD, path_z.ptr, &buf, buf.len);
    if (errnoFailed(rc)) return fail("readlink failed on {s}", .{path});
    if (rc > Limits.maximum_path_bytes) return fail("alternatives symlink target exceeds its limit: {s}", .{path});
    return allocator.dupe(u8, buf[0..rc]);
}

pub fn readRegular(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    maximum: usize,
) ![]u8 {
    const metadata = lstatPath(allocator, path) catch |err| switch (err) {
        error.FileNotFound => return fail("required regular file is missing: {s}", .{path}),
        else => return err,
    };
    if ((metadata.mode & linux.S.IFMT) != linux.S.IFREG) {
        return fail("path must be a regular non-symlink file: {s}", .{path});
    }
    if (metadata.size > maximum) {
        return fail("file exceeds its byte limit: {s}", .{path});
    }
    var file = std.Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false }) catch {
        return fail("path must be a regular non-symlink file: {s}", .{path});
    };
    defer file.close(io);
    var reader = file.reader(io, &.{});
    const data = reader.interface.allocRemaining(allocator, .limited(maximum + 1)) catch {
        return fail("file exceeds its byte limit: {s}", .{path});
    };
    errdefer allocator.free(data);
    if (data.len > maximum) {
        return fail("file exceeds its byte limit: {s}", .{path});
    }
    if (data.len != metadata.size) {
        return fail("file changed while reading: {s}", .{path});
    }
    return data;
}

pub fn optionalRegular(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    maximum: usize,
) !?[]u8 {
    if (!try lexistsPath(allocator, path)) return null;
    return try readRegular(allocator, io, path, maximum);
}

pub fn writeRegular(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    data: []const u8,
    mode: u32,
) !void {
    const parent = std.fs.path.dirname(path) orelse return fail("invalid path: {s}", .{path});
    if (std.Io.Dir.openDirAbsolute(io, parent, .{})) |existing| {
        existing.close(io);
    } else |_| {
        try std.Io.Dir.cwd().createDirPath(io, parent);
    }
    const path_z = try dupeZ(allocator, path);
    defer allocator.free(path_z);
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{
        .truncate = true,
        .permissions = .fromMode(mode),
    });
    defer file.close(io);
    try file.writeStreamingAll(io, data);
    try file.setPermissions(io, .fromMode(mode));
    _ = linux.chmod(path_z.ptr, mode);
}

pub fn setEpochTimes(allocator: std.mem.Allocator, path: []const u8, seconds: i64) !void {
    const path_z = try dupeZ(allocator, path);
    defer allocator.free(path_z);
    const times = [2]linux.timespec{
        .{ .sec = seconds, .nsec = 0 },
        .{ .sec = seconds, .nsec = 0 },
    };
    const rc = linux.utimensat(linux.AT.FDCWD, path_z.ptr, &times, linux.AT.SYMLINK_NOFOLLOW);
    if (errnoFailed(rc)) return fail("utimensat failed on {s}", .{path});
}

pub fn boundedScandir(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    maximum: usize,
) ![][]u8 {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true, .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return fail("cannot open directory: {s}", .{path}),
    };
    defer dir.close(io);
    var names: std.ArrayList([]u8) = .empty;
    errdefer {
        for (names.items) |item| allocator.free(item);
        names.deinit(allocator);
    }
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (names.items.len + 1 > maximum) {
            return fail("directory entry count exceeds its limit: {s}", .{path});
        }
        try names.append(allocator, try allocator.dupe(u8, entry.name));
    }
    std.sort.heap([]u8, names.items, {}, struct {
        fn less(_: void, left: []u8, right: []u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.less);
    return names.toOwnedSlice(allocator);
}

pub fn validateAbsolutePath(value: []const u8) ![]const u8 {
    if (value.len == 0 or
        value[0] != '/' or
        std.mem.eql(u8, value, "/") or
        std.mem.indexOf(u8, value, "//") != null or
        value.len > Limits.maximum_path_bytes or
        std.mem.indexOfScalar(u8, value, 0) != null)
    {
        return fail("unsafe absolute alternatives path: '{s}'", .{value});
    }
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7F) {
            return fail("unsafe absolute alternatives path: '{s}'", .{value});
        }
    }
    const trimmed = if (value.len > 1 and value[value.len - 1] == '/') value[1 .. value.len - 1] else value[1..];
    var it = std.mem.splitScalar(u8, trimmed, '/');
    while (it.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) {
            return fail("unsafe absolute alternatives path: '{s}'", .{value});
        }
    }
    return value;
}

pub fn validateName(value: []const u8) ![]const u8 {
    if (!isIdentityName(value) or value.len > 128 or std.mem.indexOfScalar(u8, value, '/') != null) {
        return fail("unsafe alternatives name: '{s}'", .{value});
    }
    return value;
}

pub fn validateRoot(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !void {
    if (!std.fs.path.isAbsolute(root) or std.mem.eql(u8, root, "/")) {
        return fail("alternatives execution requires an absolute disposable root", .{});
    }
    var current: std.ArrayList(u8) = .empty;
    defer current.deinit(allocator);
    var it = std.mem.splitScalar(u8, root[1..], '/');
    while (it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) {
            return fail("alternatives root contains an ambiguous component", .{});
        }
        try current.append(allocator, '/');
        try current.appendSlice(allocator, component);
        const meta = try lstatPath(allocator, current.items);
        if ((meta.mode & linux.S.IFMT) != linux.S.IFDIR) {
            return fail("alternatives root component is not a real directory: {s}", .{current.items});
        }
    }
    const guard_path = try std.fs.path.join(allocator, &.{ root, guard_relative });
    defer allocator.free(guard_path);
    const guard_bytes = readRegular(allocator, io, guard_path, 128) catch {
        return fail("alternatives execution requires the disposable-root guard", .{});
    };
    defer allocator.free(guard_bytes);
    if (!std.mem.eql(u8, guard_bytes, guard_content)) {
        return fail("alternatives execution requires the disposable-root guard", .{});
    }
    for ([_][]const u8{ "etc/alternatives", "var/lib/dpkg/alternatives" }) |relative| {
        const state_dir = try std.fs.path.join(allocator, &.{ root, relative });
        defer allocator.free(state_dir);
        const meta = lstatPath(allocator, state_dir) catch {
            return fail("alternatives state directory is unsafe: {s}", .{state_dir});
        };
        if ((meta.mode & linux.S.IFMT) != linux.S.IFDIR) {
            return fail("alternatives state directory is unsafe: {s}", .{state_dir});
        }
    }
}

pub fn validateAdminRecords(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
) !void {
    try validateRoot(allocator, io, root);
    const admin = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg/alternatives" });
    defer allocator.free(admin);
    const entries = try boundedScandir(allocator, io, admin, Limits.maximum_groups);
    defer {
        for (entries) |e| allocator.free(e);
        allocator.free(entries);
    }
    var total: u64 = 0;
    for (entries) |entry_name| {
        const base = if (std.mem.endsWith(u8, entry_name, ".dpkg-tmp"))
            entry_name[0 .. entry_name.len - ".dpkg-tmp".len]
        else
            entry_name;
        _ = try validateName(base);
        const entry_path = try std.fs.path.join(allocator, &.{ admin, entry_name });
        defer allocator.free(entry_path);
        const meta = try lstatPath(allocator, entry_path);
        if ((meta.mode & linux.S.IFMT) != linux.S.IFREG) {
            return fail("alternatives record must be regular: {s}", .{entry_name});
        }
        total += meta.size;
        if (meta.size > Limits.maximum_record_bytes or total > Limits.maximum_total_record_bytes) {
            return fail("alternatives record bytes exceed their limit", .{});
        }
    }
}

pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    repository: []const u8,
    disposable_runtime: []const u8,
    native_reference: []const u8,
    reference_dpkg: []const u8 = "dpkg",

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        environ: std.process.Environ,
        repository: []const u8,
    ) !Context {
        const default_runtime = try std.fs.path.join(allocator, &.{ repository, "zig-out/bin/debz-disposable-runtime" });
        const default_reference = try std.fs.path.join(allocator, &.{ repository, "zig-out/bin/debz-native-dpkg-reference" });
        return .{
            .allocator = allocator,
            .io = io,
            .environ = environ,
            .repository = repository,
            .disposable_runtime = environ.getPosix("DEBZ_DISPOSABLE_RUNTIME") orelse default_runtime,
            .native_reference = environ.getPosix("DEBZ_NATIVE_DPKG_REFERENCE") orelse default_reference,
        };
    }

    pub fn repoPath(self: Context, relative: []const u8) ![]u8 {
        return std.fs.path.resolve(self.allocator, &.{ self.repository, relative });
    }

    pub fn nativeReference(self: Context, arguments: []const []const u8) ![]u8 {
        if (!std.fs.path.isAbsolute(self.native_reference)) {
            return fail("native reference helper requires an absolute path: {s}", .{self.native_reference});
        }
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);
        try argv.append(self.allocator, self.native_reference);
        try argv.appendSlice(self.allocator, arguments);

        var env_map = try self.environ.createMap(self.allocator);
        defer env_map.deinit();
        try env_map.put("LC_ALL", "C");

        const result = std.process.run(self.allocator, self.io, .{
            .argv = argv.items,
            .cwd = .{ .path = self.repository },
            .environ_map = &env_map,
            .stdout_limit = .limited(256 * 1024),
            .stderr_limit = .limited(256 * 1024),
        }) catch return fail("native reference helper failed", .{});
        defer self.allocator.free(result.stderr);
        switch (result.term) {
            .exited => |code| if (code != 0) {
                self.allocator.free(result.stdout);
                return fail("native reference helper exited {d}: {s}", .{ code, result.stderr });
            },
            else => {
                self.allocator.free(result.stdout);
                return fail("native reference helper terminated abnormally", .{});
            },
        }
        return result.stdout;
    }

    pub fn referenceDescription(self: Context) !std.json.Value {
        const raw = try self.nativeReference(&.{"--describe"});
        return std.json.parseFromSliceLeaky(std.json.Value, self.allocator, raw, .{});
    }

    pub fn verifyReference(self: Context, path: []const u8, architecture: []const u8, tool: []const u8) !void {
        const out = try self.nativeReference(&.{
            "--architecture",
            architecture,
            "--verify-binding",
            path,
            "--tool",
            tool,
        });
        self.allocator.free(out);
    }

    pub fn selectReferences(
        self: Context,
        dpkg_path: ?[]const u8,
        update_path: ?[]const u8,
        architecture: []const u8,
    ) !struct { dpkg: []const u8, update_alternatives: []const u8 } {
        const desc = try self.referenceDescription();
        const version = desc.object.get("version").?.string;
        const prefix = try std.fs.path.join(self.allocator, &.{
            self.repository,
            ".cache/native-dpkg-reference",
            version,
            architecture,
            "usr/bin",
        });
        const selected_dpkg = dpkg_path orelse try std.fs.path.join(self.allocator, &.{ prefix, "dpkg" });
        const selected_update = update_path orelse try std.fs.path.join(self.allocator, &.{ prefix, "update-alternatives" });

        for ([_]struct { path: []const u8, tool: []const u8 }{
            .{ .path = selected_dpkg, .tool = "dpkg" },
            .{ .path = selected_update, .tool = "update-alternatives" },
        }) |item| {
            const meta = lstatPath(self.allocator, item.path) catch {
                return fail(
                    "missing pinned references; run zig-out/bin/debz-native-dpkg-reference as the build user",
                    .{},
                );
            };
            if ((meta.mode & linux.S.IFMT) != linux.S.IFREG) {
                return fail(
                    "missing pinned references; run zig-out/bin/debz-native-dpkg-reference as the build user",
                    .{},
                );
            }
            if (!std.fs.path.isAbsolute(item.path)) {
                return fail("pinned reference must be an absolute, non-symlink path", .{});
            }
            const real = std.Io.Dir.cwd().realPathFileAlloc(self.io, item.path, self.allocator) catch {
                return fail("pinned reference must be an absolute, non-symlink path", .{});
            };
            defer self.allocator.free(real);
            if (!std.mem.eql(u8, real, item.path)) {
                return fail("pinned reference must be an absolute, non-symlink path", .{});
            }
            try self.verifyReference(item.path, architecture, item.tool);
        }
        return .{ .dpkg = selected_dpkg, .update_alternatives = selected_update };
    }

    pub fn copyProgram(
        self: Context,
        root: []const u8,
        source: []const u8,
        destination: []const u8,
    ) !void {
        _ = try validateAbsolutePath(destination);
        const limit_str = try std.fmt.allocPrint(self.allocator, "{d}", .{Limits.maximum_archive_bytes});
        const argv = [_][]const u8{
            self.disposable_runtime,
            root,
            source,
            destination,
            "--max-file-bytes",
            limit_str,
        };
        const result = std.process.run(self.allocator, self.io, .{
            .argv = &argv,
            .stdout_limit = .limited(64 * 1024),
            .stderr_limit = .limited(64 * 1024),
        }) catch return error.FileNotFound;
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        switch (result.term) {
            .exited => |code| if (code != 0) {
                return fail("debz-disposable-runtime exited {d}: {s}", .{ code, result.stderr });
            },
            else => return fail("debz-disposable-runtime terminated abnormally", .{}),
        }
    }

    pub fn makeBasicRoot(self: Context, root: []const u8, architecture: []const u8) !void {
        for ([_][]const u8{ "info", "updates", "triggers" }) |subdir| {
            const full = try std.fs.path.join(self.allocator, &.{ root, "var/lib/dpkg", subdir });
            defer self.allocator.free(full);
            try std.Io.Dir.cwd().createDirPath(self.io, full);
        }
        const guard_path = try std.fs.path.join(self.allocator, &.{ root, guard_relative });
        defer self.allocator.free(guard_path);
        try writeRegular(self.allocator, self.io, guard_path, guard_content, 0o600);

        const status_path = try std.fs.path.join(self.allocator, &.{ root, "var/lib/dpkg/status" });
        defer self.allocator.free(status_path);
        try writeRegular(self.allocator, self.io, status_path, "", 0o644);

        const format_path = try std.fs.path.join(self.allocator, &.{ root, "var/lib/dpkg/info/format" });
        defer self.allocator.free(format_path);
        try writeRegular(self.allocator, self.io, format_path, "1\n", 0o644);

        const arch_path = try std.fs.path.join(self.allocator, &.{ root, "var/lib/dpkg/arch" });
        defer self.allocator.free(arch_path);
        const arch_content = try std.fmt.allocPrint(self.allocator, "{s}\n", .{architecture});
        defer self.allocator.free(arch_content);
        try writeRegular(self.allocator, self.io, arch_path, arch_content, 0o644);
    }

    pub fn sleepSourcePath(self: Context) ![]const u8 {
        const real_sleep = try std.Io.Dir.cwd().realPathFileAlloc(self.io, "/bin/sleep", self.allocator);
        defer self.allocator.free(real_sleep);
        const meta = try lstatPath(self.allocator, real_sleep);
        if (meta.size <= Limits.maximum_archive_bytes) return "/bin/sleep";
        if (try lexistsPath(self.allocator, "/bin/gnusleep")) return "/bin/gnusleep";
        return "/bin/sleep";
    }

    pub fn makeRoot(self: Context, root: []const u8, architecture: []const u8, dpkg_runtime: bool) !void {
        try self.makeBasicRoot(root, architecture);
        for ([_][]const u8{
            "etc/alternatives",
            "usr/bin",
            "usr/lib",
            "usr/share/man/man1",
            "var/lib/dpkg/alternatives",
            "var/log",
        }) |relative| {
            const full = try std.fs.path.join(self.allocator, &.{ root, relative });
            defer self.allocator.free(full);
            try std.Io.Dir.cwd().createDirPath(self.io, full);
            const full_z = try dupeZ(self.allocator, full);
            defer self.allocator.free(full_z);
            _ = linux.chmod(full_z.ptr, 0o755);
        }
        if (dpkg_runtime) {
            try self.copyProgram(root, "/bin/sh", "/bin/sh");
            try self.copyProgram(root, try self.sleepSourcePath(), "/bin/sleep");
            for (forbidden_frontend_paths) |relative| {
                const candidate = try std.fs.path.join(self.allocator, &.{ root, relative });
                defer self.allocator.free(candidate);
                if (try lexistsPath(self.allocator, candidate)) {
                    return fail("ambient frontend contaminated fixture root: {s}", .{relative});
                }
            }
            const info_dir = try std.fs.path.join(self.allocator, &.{ root, "var/lib/dpkg/info" });
            defer self.allocator.free(info_dir);
            const entries = try boundedScandir(self.allocator, self.io, info_dir, 2);
            if (entries.len != 1 or !std.mem.eql(u8, entries[0], "format")) {
                return fail("ambient package metadata contaminated fixture root", .{});
            }
            const format_path = try std.fs.path.join(self.allocator, &.{ info_dir, "format" });
            const format_bytes = try readRegular(self.allocator, self.io, format_path, 16);
            if (!std.mem.eql(u8, format_bytes, "1\n")) {
                return fail("ambient package metadata contaminated fixture root", .{});
            }
            const tmp_ci = try std.fs.path.join(self.allocator, &.{ root, "var/lib/dpkg/tmp.ci" });
            if (try lexistsPath(self.allocator, tmp_ci)) {
                return fail("ambient control staging contaminated fixture root", .{});
            }
        }
    }

    pub fn referenceCommand(self: Context, root: []const u8) ![]const []const u8 {
        if (!std.fs.path.isAbsolute(root) or std.mem.eql(u8, root, "/")) {
            return fail("reference execution requires a disposable fixture root", .{});
        }
        const real = std.Io.Dir.cwd().realPathFileAlloc(self.io, root, self.allocator) catch {
            return fail("reference execution requires a disposable fixture root", .{});
        };
        defer self.allocator.free(real);
        if (!std.mem.eql(u8, real, root)) {
            return fail("reference execution requires a disposable fixture root", .{});
        }
        const guard_path = try std.fs.path.join(self.allocator, &.{ root, guard_relative });
        defer self.allocator.free(guard_path);
        const guard_bytes = readRegular(self.allocator, self.io, guard_path, 128) catch {
            return fail("reference execution requires a disposable fixture root", .{});
        };
        defer self.allocator.free(guard_bytes);
        if (!std.mem.eql(u8, guard_bytes, guard_content)) {
            return fail("reference execution requires a disposable fixture root", .{});
        }
        const root_arg = try std.fmt.allocPrint(self.allocator, "--root={s}", .{root});
        var cmd = try self.allocator.alloc([]const u8, 5);
        cmd[0] = self.reference_dpkg;
        cmd[1] = "--force-not-root";
        cmd[2] = "--force-bad-path";
        cmd[3] = "--no-triggers";
        cmd[4] = root_arg;
        return cmd;
    }

    pub fn directDpkgCommand(
        self: Context,
        executable: []const u8,
        root: []const u8,
        arguments: []const []const u8,
    ) ![]const []const u8 {
        var copy_ctx = self;
        copy_ctx.reference_dpkg = executable;
        const base = try copy_ctx.referenceCommand(root);
        if (!std.mem.eql(u8, base[0], executable)) {
            return fail("reference command did not select the pinned dpkg executable", .{});
        }
        var cmd: std.ArrayList([]const u8) = .empty;
        try cmd.appendSlice(self.allocator, base);
        try cmd.append(
            self.allocator,
            try std.fmt.allocPrint(self.allocator, "--log={s}/{s}", .{ root, dpkg_log_relative }),
        );
        try cmd.appendSlice(self.allocator, arguments);
        for (cmd.items) |argument| {
            const name = std.fs.path.basename(argument);
            if (std.mem.eql(u8, name, "apt") or
                std.mem.eql(u8, name, "apt-get") or
                std.mem.eql(u8, name, "debconf") or
                std.mem.eql(u8, name, "dpkg-preconfigure"))
            {
                return fail("frontend executable entered the direct-dpkg command", .{});
            }
        }
        return cmd.toOwnedSlice(self.allocator);
    }

    pub fn loadReference(self: Context) !std.json.Value {
        const ref_path = try self.repoPath(reference_relative);
        const raw = try readRegular(self.allocator, self.io, ref_path, Limits.maximum_total_record_bytes);
        const reference = std.json.parseFromSliceLeaky(std.json.Value, self.allocator, raw, .{
            .duplicate_field_behavior = .@"error",
        }) catch return fail("unsupported dpkg alternatives reference", .{});
        if (reference != .object) return fail("unsupported dpkg alternatives reference", .{});
        const schema = reference.object.get("schema") orelse return fail("unsupported dpkg alternatives reference", .{});
        const version = reference.object.get("version") orelse return fail("unsupported dpkg alternatives reference", .{});
        if (schema != .string or !std.mem.eql(u8, schema.string, schema_id) or
            version != .integer or version.integer != 1)
        {
            return fail("unsupported dpkg alternatives reference", .{});
        }
        const canonical = try canonicalJson(self.allocator, reference);
        if (!std.mem.eql(u8, raw, canonical)) {
            return fail("dpkg alternatives reference is not canonical JSON", .{});
        }
        return reference;
    }

    pub fn verifyFileBinding(self: Context, path: []const u8, binding: std.json.Value) !void {
        const data = try readRegular(self.allocator, self.io, path, Limits.maximum_archive_bytes);
        const expected_size: usize = @intCast(binding.object.get("size").?.integer);
        const expected_sha256 = binding.object.get("sha256").?.string;
        const actual_sha256 = try sha256HexAlloc(self.allocator, data);
        if (data.len != expected_size or !std.mem.eql(u8, actual_sha256, expected_sha256)) {
            return fail("pinned source binding changed: {s}", .{path});
        }
    }

    pub fn verifySourceBindings(self: Context, reference: std.json.Value) !std.json.Value {
        const boundary = reference.object.get("boundary").?.object;
        const limits_obj = boundary.get("limits").?.object;
        if (limits_obj.count() != limit_contract_entries.len) {
            return fail("published oracle limits changed", .{});
        }
        for (limit_contract_entries) |entry| {
            const actual = limits_obj.get(entry.name) orelse return fail("published oracle limits changed", .{});
            if (actual != .integer or actual.integer != entry.value) {
                return fail("published oracle limits changed", .{});
            }
        }
        const task_inv = boundary.get("invocation_clock").?.object.get("task_invocation").?.string;
        if (!std.mem.eql(u8, task_inv, canonical_task_invocation)) {
            return fail("canonical task invocation binding changed", .{});
        }

        const source = reference.object.get("source").?.object;
        const fixtures_dir = try self.repoPath("tools/fixtures/vendor-state");
        const vendor = source.get("vendor_reference").?.object;

        const index_binding = vendor.get("index").?;
        const index_path = try std.fs.path.join(self.allocator, &.{ fixtures_dir, index_binding.object.get("path").?.string });
        try self.verifyFileBinding(index_path, index_binding);

        const ref_binding = vendor.get("reference").?;
        const vendor_ref_path = try std.fs.path.join(self.allocator, &.{ fixtures_dir, ref_binding.object.get("path").?.string });
        try self.verifyFileBinding(vendor_ref_path, ref_binding);

        const manifests = vendor.get("manifests").?.array.items;
        const expected_arches = boundary.get("architectures").?.array.items;
        if (manifests.len != expected_arches.len) {
            return fail("vendor manifest architecture coverage changed", .{});
        }
        for (manifests, expected_arches) |manifest, expected_arch| {
            const m_path = try std.fs.path.join(self.allocator, &.{ fixtures_dir, manifest.object.get("path").?.string });
            try self.verifyFileBinding(m_path, manifest);
            if (!std.mem.eql(u8, manifest.object.get("architecture").?.string, expected_arch.string)) {
                return fail("vendor manifest architecture coverage changed", .{});
            }
        }

        const derived_raw = try readRegular(self.allocator, self.io, vendor_ref_path, Limits.maximum_archive_bytes);
        const derived = try std.json.parseFromSliceLeaky(std.json.Value, self.allocator, derived_raw, .{});
        const alternatives = derived.object.get("alternatives").?;
        const groups = alternatives.object.get("groups").?.array.items;
        const requested_paths = alternatives.object.get("requested_paths").?.array.items;
        const linked_entries = alternatives.object.get("linked_entries").?.array.items;
        var total_links: usize = 0;
        for (groups) |g| {
            total_links += g.object.get("links").?.array.items.len;
        }
        if (groups.len != 14 or requested_paths.len != 189 or linked_entries.len != 190 or total_links != 72) {
            return fail("pinned vendor alternatives inventory changed", .{});
        }

        const projection = reference.object.get("vendor_projection").?.object;
        const alt_canonical = try canonicalJson(self.allocator, alternatives);
        const alt_sha = try sha256HexAlloc(self.allocator, alt_canonical);
        if (!std.mem.eql(u8, projection.get("alternatives_sha256").?.string, alt_sha)) {
            return fail("vendor alternatives projection digest changed", .{});
        }
        const group_names = projection.get("group_names").?.array.items;
        if (group_names.len != groups.len) {
            return fail("vendor alternatives group ordering changed", .{});
        }
        for (group_names, groups) |gn, g| {
            if (!std.mem.eql(u8, gn.string, g.object.get("name").?.string)) {
                return fail("vendor alternatives group ordering changed", .{});
            }
        }

        const derived_source = derived.object.get("source").?.object;
        const derived_manifests = derived_source.get("manifests").?.array.items;
        if (manifests.len != derived_manifests.len) {
            return fail("vendor manifest bindings changed", .{});
        }
        for (manifests, derived_manifests) |m_item, dm_item| {
            if (!std.mem.eql(u8, m_item.object.get("architecture").?.string, dm_item.object.get("architecture").?.string) or
                !std.mem.eql(u8, m_item.object.get("path").?.string, dm_item.object.get("path").?.string) or
                !std.mem.eql(u8, m_item.object.get("sha256").?.string, dm_item.object.get("sha256").?.string) or
                m_item.object.get("size").?.integer != dm_item.object.get("size").?.integer)
            {
                return fail("vendor manifest bindings changed", .{});
            }
        }
        if (!jsonEqual(index_binding, derived_source.get("index").?)) {
            return fail("vendor index binding changed", .{});
        }
        const index_source = derived_source.get("index_source").?.object;
        if (!std.mem.eql(u8, vendor.get("snapshot").?.string, index_source.get("snapshot_uri").?.string) or
            !std.mem.eql(u8, vendor.get("workflow_run").?.string, index_source.get("workflow_run_url").?.string))
        {
            return fail("vendor invocation provenance changed", .{});
        }

        const description = try self.referenceDescription();
        const dpkg = source.get("dpkg").?.object;
        if (!std.mem.eql(u8, dpkg.get("version").?.string, description.object.get("version").?.string)) {
            return fail("dpkg reference version binding changed", .{});
        }
        const config_sha = try sha256HexAlloc(self.allocator, pinned_dpkg_config);
        if (!std.mem.eql(u8, dpkg.get("configuration_sha256").?.string, config_sha)) {
            return fail("dpkg configuration binding changed", .{});
        }
        const desc_arches = description.object.get("architectures").?.object;
        const dpkg_arches = dpkg.get("architectures").?.object;
        var arch_it = desc_arches.iterator();
        while (arch_it.next()) |entry| {
            const arch = entry.key_ptr.*;
            const pins = entry.value_ptr.*.object;
            const expected_pin = (dpkg_arches.get(arch) orelse return fail("dpkg tool pins changed for {s}", .{arch})).object;
            if (!std.mem.eql(u8, pins.get("archive").?.string, expected_pin.get("archive_sha256").?.string) or
                !std.mem.eql(u8, pins.get("executable").?.string, expected_pin.get("dpkg_sha256").?.string) or
                !std.mem.eql(u8, pins.get("update_alternatives").?.string, expected_pin.get("update_alternatives_sha256").?.string))
            {
                return fail("dpkg tool pins changed for {s}", .{arch});
            }
        }

        const fix_pkg = source.get("fixture_packages").?.object;
        if (!std.mem.eql(u8, fix_pkg.get("baseline_architecture").?.string, "amd64") or
            fix_pkg.get("clock_epoch").?.integer != epoch or
            !std.mem.eql(u8, fix_pkg.get("maintainer").?.string, "debz fixture <fixture@example.invalid>") or
            !std.mem.eql(u8, fix_pkg.get("namespace").?.string, "debz-alt-*") or
            !std.mem.eql(u8, fix_pkg.get("package_builder").?.string, "repository deterministic Python ar/tar builder"))
        {
            return fail("fixture package provenance changed", .{});
        }

        _ = try verifyArchitectureEvidence(self.allocator, reference);
        return derived;
    }
};

pub const EnvPair = struct { name: []const u8, value: []const u8 };

pub fn baseEnvironment(allocator: std.mem.Allocator) ![]EnvPair {
    var pairs = try allocator.alloc(EnvPair, 3);
    pairs[0] = .{ .name = "PATH", .value = "/usr/sbin:/usr/bin:/sbin:/bin" };
    pairs[1] = .{ .name = "LANG", .value = "C" };
    pairs[2] = .{ .name = "LC_ALL", .value = "C" };
    return pairs;
}

pub fn fixtureEnvironment(allocator: std.mem.Allocator, io: std.Io, workspace: []const u8) ![]EnvPair {
    const home = try std.fs.path.join(allocator, &.{ workspace, "home" });
    const tmp = try std.fs.path.join(allocator, &.{ workspace, "tmp" });
    try std.Io.Dir.cwd().createDirPath(io, home);
    try std.Io.Dir.cwd().createDirPath(io, tmp);
    var pairs = try allocator.alloc(EnvPair, 6);
    pairs[0] = .{ .name = "PATH", .value = "/usr/sbin:/usr/bin:/sbin:/bin" };
    pairs[1] = .{ .name = "LANG", .value = "C" };
    pairs[2] = .{ .name = "LC_ALL", .value = "C" };
    pairs[3] = .{ .name = "HOME", .value = home };
    pairs[4] = .{ .name = "TMPDIR", .value = tmp };
    pairs[5] = .{ .name = "SOURCE_DATE_EPOCH", .value = "1700000000" };
    return pairs;
}

pub fn validateEnvironment(environment: []const EnvPair) !void {
    if (environment.len > 16) {
        return fail("fixture environment exceeds its variable limit", .{});
    }
    for (environment) |pair| {
        if (pair.name.len == 0 or
            std.mem.indexOfScalar(u8, pair.name, '=') != null or
            std.mem.indexOfScalar(u8, pair.name, 0) != null or
            std.mem.indexOfScalar(u8, pair.value, 0) != null or
            pair.name.len + 1 + pair.value.len > 4096)
        {
            return fail("unsafe fixture environment entry: {s}", .{pair.name});
        }
    }
    for (forbidden_frontend_env) |forbidden| {
        for (environment) |pair| {
            if (std.mem.eql(u8, pair.name, forbidden)) {
                return fail("frontend environment entered alternatives fixture: {s}", .{forbidden});
            }
        }
    }
}

pub fn validateConfigDirectory(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    const meta = lstatPath(allocator, path) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if ((meta.mode & linux.S.IFMT) != linux.S.IFDIR) {
        return fail("ambient dpkg config directory is not a real directory: {s}", .{path});
    }
    const entries = try boundedScandir(allocator, io, path, 64);
    defer {
        for (entries) |e| allocator.free(e);
        allocator.free(entries);
    }
    if (entries.len != 0) {
        return fail("ambient dpkg config fragments are forbidden: {s}", .{path});
    }
}

pub fn validateHostConfiguration(
    allocator: std.mem.Allocator,
    io: std.Io,
    home: []const u8,
    config_root: []const u8,
) !void {
    const config_path = try std.fs.path.join(allocator, &.{ config_root, "dpkg.cfg" });
    defer allocator.free(config_path);
    const raw = try readRegular(allocator, io, config_path, 4096);
    defer allocator.free(raw);
    if (!std.mem.eql(u8, raw, pinned_dpkg_config)) {
        return fail("ambient dpkg.cfg differs from the pinned benign config", .{});
    }
    const fragments_dir = try std.fs.path.join(allocator, &.{ config_root, "dpkg.cfg.d" });
    defer allocator.free(fragments_dir);
    try validateConfigDirectory(allocator, io, fragments_dir);

    const user_cfg = try std.fs.path.join(allocator, &.{ home, ".dpkg.cfg" });
    defer allocator.free(user_cfg);
    if (try lexistsPath(allocator, user_cfg)) {
        return fail("ambient dpkg config file is forbidden: {s}", .{user_cfg});
    }
}

pub fn validateObservationArchitecture(reference: std.json.Value, architecture: []const u8) !void {
    const boundary = reference.object.get("boundary").?.object;
    if (boundary.get("observed_architectures")) |obs_arches| {
        for (obs_arches.array.items) |item| {
            if (std.mem.eql(u8, item.string, architecture)) return;
        }
    } else if (boundary.get("observed_architecture")) |obs_arch| {
        if (std.mem.eql(u8, obs_arch.string, architecture)) return;
    }
    return fail("published alternatives observation is architecture-specific: requested={s}", .{architecture});
}

fn decodeJsonPointer(allocator: std.mem.Allocator, pointer: []const u8) ![][]u8 {
    if (pointer.len <= 1 or pointer[0] != '/') {
        return fail("architecture difference path is not a JSON pointer", .{});
    }
    var parts: std.ArrayList([]u8) = .empty;
    errdefer {
        for (parts.items) |p| allocator.free(p);
        parts.deinit(allocator);
    }
    var it = std.mem.splitScalar(u8, pointer[1..], '/');
    while (it.next()) |raw_part| {
        const s1 = try std.mem.replaceOwned(u8, allocator, raw_part, "~1", "/");
        defer allocator.free(s1);
        const s2 = try std.mem.replaceOwned(u8, allocator, s1, "~0", "~");
        try parts.append(allocator, s2);
    }
    return parts.toOwnedSlice(allocator);
}

fn replaceJsonPointer(
    allocator: std.mem.Allocator,
    document: *std.json.Value,
    pointer: []const u8,
    value: std.json.Value,
) !void {
    const parts = try decodeJsonPointer(allocator, pointer);
    defer {
        for (parts) |p| allocator.free(p);
        allocator.free(parts);
    }
    var selected: *std.json.Value = document;
    for (parts[0 .. parts.len - 1]) |part| {
        switch (selected.*) {
            .array => |*arr| {
                const idx = std.fmt.parseInt(usize, part, 10) catch {
                    return fail("architecture difference list path is out of range", .{});
                };
                if (idx >= arr.items.len) return fail("architecture difference list path is out of range", .{});
                selected = &arr.items[idx];
            },
            .object => |*obj| {
                selected = obj.getPtr(part) orelse return fail("architecture difference path is missing", .{});
            },
            else => return fail("architecture difference path is missing", .{}),
        }
    }
    const final = parts[parts.len - 1];
    switch (selected.*) {
        .array => |*arr| {
            const idx = std.fmt.parseInt(usize, final, 10) catch {
                return fail("architecture difference list path is out of range", .{});
            };
            if (idx >= arr.items.len) return fail("architecture difference list path is out of range", .{});
            arr.items[idx] = try cloneJsonValue(allocator, value);
        },
        .object => |*obj| {
            const ptr = obj.getPtr(final) orelse return fail("architecture difference path is missing", .{});
            ptr.* = try cloneJsonValue(allocator, value);
        },
        else => return fail("architecture difference path is missing", .{}),
    }
}

pub fn verifyArchitectureEvidence(allocator: std.mem.Allocator, reference: std.json.Value) !std.json.Value {
    const evidence = reference.object.get("architecture_evidence").?.object;
    const baseline = evidence.get("baseline").?.object;
    const observed = reference.object.get("observed_behavior").?;
    const observed_raw = try canonicalJson(allocator, observed);
    defer allocator.free(observed_raw);
    const observed_sha = try sha256HexAlloc(allocator, observed_raw);
    defer allocator.free(observed_sha);
    const baseline_size: usize = @intCast(baseline.get("observation_size").?.integer);
    if (!std.mem.eql(u8, baseline.get("architecture").?.string, "amd64") or
        !std.mem.eql(u8, baseline.get("observation_sha256").?.string, observed_sha) or
        baseline_size != observed_raw.len)
    {
        return fail("amd64 architecture evidence baseline changed", .{});
    }
    const arm64 = evidence.get("arm64").?.object;
    const differences = arm64.get("differences_from_baseline").?.array.items;
    const diff_count: usize = @intCast(arm64.get("difference_count").?.integer);
    if (diff_count != differences.len) {
        return fail("arm64 architecture difference count changed", .{});
    }
    for (differences, 0..) |diff, i| {
        const path = diff.object.get("path").?.string;
        if (i > 0) {
            const prev = differences[i - 1].object.get("path").?.string;
            if (!std.mem.lessThan(u8, prev, path)) {
                return fail("arm64 architecture differences are not canonical", .{});
            }
        }
    }
    var reconstructed = try cloneJsonValue(allocator, observed);
    for (differences) |difference| {
        try replaceJsonPointer(
            allocator,
            &reconstructed,
            difference.object.get("path").?.string,
            difference.object.get("value").?,
        );
    }
    const reconstructed_raw = try canonicalJson(allocator, reconstructed);
    defer allocator.free(reconstructed_raw);
    const reconstructed_sha = try sha256HexAlloc(allocator, reconstructed_raw);
    defer allocator.free(reconstructed_sha);
    const artifact = arm64.get("observation").?.object;
    const artifact_size: usize = @intCast(artifact.get("size").?.integer);
    if (!std.mem.eql(u8, artifact.get("sha256").?.string, reconstructed_sha) or
        artifact_size != reconstructed_raw.len)
    {
        return fail("arm64 architecture observation binding changed", .{});
    }
    const obs_arches = reference.object.get("boundary").?.object.get("observed_architectures").?.array.items;
    if (obs_arches.len != 2 or
        !std.mem.eql(u8, obs_arches[0].string, "amd64") or
        !std.mem.eql(u8, obs_arches[1].string, "arm64"))
    {
        return fail("published architecture evidence coverage changed", .{});
    }
    return reconstructed;
}

pub fn publishedObservation(
    allocator: std.mem.Allocator,
    reference: std.json.Value,
    architecture: []const u8,
) !std.json.Value {
    try validateObservationArchitecture(reference, architecture);
    const baseline_arch = reference.object.get("architecture_evidence").?.object.get("baseline").?.object.get("architecture").?.string;
    if (std.mem.eql(u8, architecture, baseline_arch)) {
        return reference.object.get("observed_behavior").?;
    }
    if (std.mem.eql(u8, architecture, "arm64")) {
        return verifyArchitectureEvidence(allocator, reference);
    }
    return fail("missing published observation for architecture: {s}", .{architecture});
}

fn tarOctal(field: []u8, value: u64) void {
    @memset(field, '0');
    field[field.len - 1] = 0;
    var remaining = value;
    var offset = field.len - 1;
    while (remaining != 0 and offset > 0) {
        offset -= 1;
        field[offset] = '0' + @as(u8, @intCast(remaining & 7));
        remaining >>= 3;
    }
}

fn gnuTarHeader(
    name: []const u8,
    mode: u32,
    mtime: u64,
    size: u64,
    typeflag: u8,
    linkname: []const u8,
) [512]u8 {
    var header: [512]u8 = @splat(0);
    const name_len: usize = @min(name.len, 100);
    @memcpy(header[0..name_len], name[0..name_len]);
    tarOctal(header[100..108], mode & 0o7777);
    tarOctal(header[108..116], 0);
    tarOctal(header[116..124], 0);
    tarOctal(header[124..136], size);
    tarOctal(header[136..148], mtime);
    @memset(header[148..156], ' ');
    header[156] = typeflag;
    const link_len: usize = @min(linkname.len, 100);
    @memcpy(header[157 .. 157 + link_len], linkname[0..link_len]);
    @memcpy(header[257..265], "ustar  \x00");
    @memcpy(header[265..269], "root");
    @memcpy(header[297..301], "root");
    var sum: u64 = 0;
    for (header) |byte| sum += byte;
    tarOctal(header[148..155], sum);
    header[155] = ' ';
    return header;
}

fn collectRelativePaths(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    control: bool,
) ![][]u8 {
    var dir = try std.Io.Dir.openDirAbsolute(io, root, .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(io);
    var rels: std.ArrayList([]u8) = .empty;
    errdefer {
        for (rels.items) |r| allocator.free(r);
        rels.deinit(allocator);
    }
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (!control) {
            if (std.mem.eql(u8, entry.path, "DEBIAN") or std.mem.startsWith(u8, entry.path, "DEBIAN/")) {
                continue;
            }
        }
        try rels.append(allocator, try allocator.dupe(u8, entry.path));
    }
    std.sort.heap([]u8, rels.items, {}, struct {
        fn less(_: void, left: []u8, right: []u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.less);
    return rels.toOwnedSlice(allocator);
}

pub fn buildTar(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: []const u8,
    control: bool,
) ![]u8 {
    const root = if (control)
        try std.fs.path.join(allocator, &.{ source, "DEBIAN" })
    else
        try allocator.dupe(u8, source);
    defer allocator.free(root);

    const relatives = try collectRelativePaths(allocator, io, root, control);
    defer {
        for (relatives) |r| allocator.free(r);
        allocator.free(relatives);
    }

    const InodeKey = struct { dev: u64, ino: u64 };
    var hardlinks: std.AutoHashMap(InodeKey, []const u8) = .init(allocator);
    defer hardlinks.deinit();

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    for (relatives) |relative| {
        const full_path = try std.fs.path.join(allocator, &.{ root, relative });
        defer allocator.free(full_path);
        const metadata = try lstatPath(allocator, full_path);
        const ftype = metadata.mode & linux.S.IFMT;
        const base_name = try std.fmt.allocPrint(allocator, "./{s}", .{relative});

        if (ftype == linux.S.IFDIR) {
            const dir_name = try std.fmt.allocPrint(allocator, "{s}/", .{base_name});
            defer allocator.free(dir_name);
            const hdr = gnuTarHeader(dir_name, metadata.mode, @intCast(metadata.mtime_sec), 0, '5', "");
            try output.appendSlice(allocator, &hdr);
        } else if (ftype == linux.S.IFLNK) {
            const target = try readSymlinkAlloc(allocator, full_path);
            defer allocator.free(target);
            const hdr = gnuTarHeader(base_name, metadata.mode, @intCast(metadata.mtime_sec), 0, '2', target);
            try output.appendSlice(allocator, &hdr);
        } else if (ftype == linux.S.IFREG) {
            const key: InodeKey = .{ .dev = metadata.dev, .ino = metadata.ino };
            if (metadata.nlink > 1 and hardlinks.contains(key)) {
                const target = hardlinks.get(key).?;
                const hdr = gnuTarHeader(base_name, metadata.mode, @intCast(metadata.mtime_sec), 0, '1', target);
                try output.appendSlice(allocator, &hdr);
            } else {
                if (metadata.nlink > 1) {
                    try hardlinks.put(key, base_name);
                }
                const data = try readRegular(allocator, io, full_path, Limits.maximum_archive_bytes);
                defer allocator.free(data);
                const hdr = gnuTarHeader(base_name, metadata.mode, @intCast(metadata.mtime_sec), data.len, '0', "");
                try output.appendSlice(allocator, &hdr);
                try output.appendSlice(allocator, data);
                const pad = (512 - (data.len % 512)) % 512;
                try output.appendNTimes(allocator, 0, pad);
            }
        } else {
            return fail("unsupported package input type: {s}", .{full_path});
        }
    }

    try output.appendNTimes(allocator, 0, 1024);
    const record_pad = (10240 - (output.items.len % 10240)) % 10240;
    try output.appendNTimes(allocator, 0, record_pad);

    if (output.items.len > Limits.maximum_archive_bytes) {
        return fail("uncompressed package tar exceeds its byte limit", .{});
    }
    return output.toOwnedSlice(allocator);
}

fn writeArMember(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    name: []const u8,
    data: []const u8,
) !void {
    if (name.len > 15 or std.mem.indexOfScalar(u8, name, '/') != null) {
        return fail("invalid package archive member name: {s}", .{name});
    }
    var name_col: [16]u8 = @splat(' ');
    @memcpy(name_col[0..name.len], name);
    name_col[name.len] = '/';
    const header = try std.fmt.allocPrint(
        allocator,
        "{s}{d:<12}{d:<6}{d:<6}{o:<8}{d:<10}`\n",
        .{ name_col, @as(u64, @intCast(epoch)), @as(u32, 0), @as(u32, 0), @as(u32, 0o100644), data.len },
    );
    defer allocator.free(header);
    if (header.len != 60) return fail("invalid package archive header", .{});
    try output.appendSlice(allocator, header);
    try output.appendSlice(allocator, data);
    if (data.len % 2 == 1) {
        try output.append(allocator, '\n');
    }
}

pub fn buildPackageArchive(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: []const u8,
    destination: []const u8,
) !void {
    const control_tar = try buildTar(allocator, io, source, true);
    defer allocator.free(control_tar);
    const data_tar = try buildTar(allocator, io, source, false);
    defer allocator.free(data_tar);

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try output.appendSlice(allocator, "!<arch>\n");
    try writeArMember(allocator, &output, "debian-binary", "2.0\n");
    try writeArMember(allocator, &output, "control.tar", control_tar);
    try writeArMember(allocator, &output, "data.tar", data_tar);

    if (output.items.len > Limits.maximum_archive_bytes) {
        return fail("package archive exceeds its byte limit", .{});
    }
    try writeRegular(allocator, io, destination, output.items, 0o644);
    try setEpochTimes(allocator, destination, epoch);
}

pub const ScriptEntry = struct {
    kind: []const u8,
    body: []const u8,
};

pub const ExtraFile = struct {
    relative: []const u8,
    content: []const u8,
};

pub const MakePackageOptions = struct {
    package: []const u8 = default_package_name,
    feature: []const u8 = "data",
    extra_files: []const ExtraFile = &.{},
    scripts: []const ScriptEntry = &.{},
    alternatives_body: ?[]const u8 = null,
    alternatives_mode: u32 = 0o640,
};

pub fn makeMaterializationPackage(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace: []const u8,
    architecture: []const u8,
    version: []const u8,
    options: MakePackageOptions,
) ![]u8 {
    const stem = try std.fmt.allocPrint(allocator, "{s}_{s}_{s}", .{ options.package, version, options.feature });
    const source = try std.fs.path.join(allocator, &.{ workspace, try std.fmt.allocPrint(allocator, "{s}.source", .{stem}) });
    const payload = try std.fmt.allocPrint(allocator, "usr/share/{s}", .{options.package});

    const control = try std.fmt.allocPrint(
        allocator,
        "Package: {s}\nVersion: {s}\nArchitecture: {s}\nMaintainer: debz fixture <fixture@example.invalid>\nDescription: native data-only materialization fixture\n",
        .{ options.package, version, architecture },
    );
    try writeRegular(
        allocator,
        io,
        try std.fs.path.join(allocator, &.{ source, "DEBIAN/control" }),
        control,
        0o644,
    );

    const data_path = try std.fs.path.join(allocator, &.{ source, payload, "data" });
    try writeRegular(
        allocator,
        io,
        data_path,
        try std.fmt.allocPrint(allocator, "data version {s}\n", .{version}),
        0o644,
    );

    const data_link_path = try std.fs.path.join(allocator, &.{ source, payload, "data.link" });
    const data_z = try dupeZ(allocator, data_path);
    const link_z = try dupeZ(allocator, data_link_path);
    if (errnoFailed(linux.linkat(linux.AT.FDCWD, data_z.ptr, linux.AT.FDCWD, link_z.ptr, 0))) {
        return fail("linkat failed", .{});
    }

    const current_path = try std.fs.path.join(allocator, &.{ source, payload, "current" });
    const current_z = try dupeZ(allocator, current_path);
    if (errnoFailed(linux.symlinkat("data", linux.AT.FDCWD, current_z.ptr))) {
        return fail("symlinkat failed", .{});
    }

    try writeRegular(
        allocator,
        io,
        try std.fs.path.join(allocator, &.{ source, payload, "mode" }),
        "permission-sensitive payload\n",
        if (std.mem.eql(u8, version, "1")) 0o600 else 0o640,
    );

    const version_file = if (std.mem.eql(u8, version, "1")) "obsolete" else "introduced";
    try writeRegular(
        allocator,
        io,
        try std.fs.path.join(allocator, &.{ source, payload, version_file }),
        try std.fmt.allocPrint(allocator, "only in {s}\n", .{version}),
        0o644,
    );

    const empty_dir = try std.fs.path.join(allocator, &.{ source, payload, "empty" });
    try std.Io.Dir.cwd().createDirPath(io, empty_dir);

    for (options.extra_files) |extra| {
        try writeRegular(
            allocator,
            io,
            try std.fs.path.join(allocator, &.{ source, extra.relative }),
            extra.content,
            0o644,
        );
    }

    for (options.scripts) |script| {
        if (!inList(&script_kinds, script.kind)) {
            return fail("unsupported maintainer-script fixture: {s}", .{script.kind});
        }
        try writeRegular(
            allocator,
            io,
            try std.fs.path.join(allocator, &.{ source, "DEBIAN", script.kind }),
            script.body,
            0o755,
        );
    }

    if (options.alternatives_body) |alt_body| {
        try writeRegular(
            allocator,
            io,
            try std.fs.path.join(allocator, &.{ source, "DEBIAN/alternatives" }),
            alt_body,
            options.alternatives_mode,
        );
    }

    const data_relatives = try collectRelativePaths(allocator, io, source, false);
    var checksums: std.ArrayList(u8) = .empty;
    for (data_relatives) |rel| {
        const full = try std.fs.path.join(allocator, &.{ source, rel });
        const meta = try lstatPath(allocator, full);
        if ((meta.mode & linux.S.IFMT) != linux.S.IFREG) continue;
        const content = try readRegular(allocator, io, full, Limits.maximum_archive_bytes);
        var digest: [Md5.digest_length]u8 = undefined;
        Md5.hash(content, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        try checksums.appendSlice(allocator, &hex);
        try checksums.appendSlice(allocator, "  ");
        try checksums.appendSlice(allocator, rel);
        try checksums.append(allocator, '\n');
    }
    try writeRegular(
        allocator,
        io,
        try std.fs.path.join(allocator, &.{ source, "DEBIAN/md5sums" }),
        checksums.items,
        0o644,
    );

    var src_dir = try std.Io.Dir.openDirAbsolute(io, source, .{ .iterate = true, .follow_symlinks = false });
    defer src_dir.close(io);
    var all_paths: std.ArrayList([]u8) = .empty;
    {
        var walker = try src_dir.walk(allocator);
        defer walker.deinit();
        while (try walker.next(io)) |entry| {
            try all_paths.append(allocator, try std.fs.path.join(allocator, &.{ source, entry.path }));
        }
    }
    try all_paths.append(allocator, try allocator.dupe(u8, source));
    for (all_paths.items) |p| {
        const meta = try lstatPath(allocator, p);
        if ((meta.mode & linux.S.IFMT) == linux.S.IFDIR) {
            const p_z = try dupeZ(allocator, p);
            const dir_mode: u32 = if (std.mem.eql(u8, p, empty_dir)) 0o750 else 0o755;
            _ = linux.chmod(p_z.ptr, dir_mode);
        }
    }
    var i: usize = all_paths.items.len;
    while (i > 0) {
        i -= 1;
        try setEpochTimes(allocator, all_paths.items[i], epoch);
    }

    const destination = try std.fs.path.join(allocator, &.{ workspace, try std.fmt.allocPrint(allocator, "{s}.deb", .{stem}) });
    try buildPackageArchive(allocator, io, source, destination);
    return destination;
}

pub fn alternativesMember(allocator: std.mem.Allocator, version: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "opaque alternatives metadata {s}\n\x00\xff", .{version});
}

pub fn packageScripts(
    allocator: std.mem.Allocator,
    package: []const u8,
    version: []const u8,
    group: []const u8,
    priority: i64,
) ![]ScriptEntry {
    const candidate = try std.fmt.allocPrint(allocator, "/usr/lib/debz-alternatives/{s}-{s}", .{ package, version });
    const manual = try std.fmt.allocPrint(allocator, "/usr/share/man/man1/{s}-{s}.1", .{ package, version });
    var result = try allocator.alloc(ScriptEntry, script_kinds.len);
    for (script_kinds, 0..) |kind, idx| {
        const action = if (std.mem.eql(u8, kind, "postinst"))
            try std.fmt.allocPrint(
                allocator,
                "\ncase \"$1\" in\n    configure|abort-upgrade|abort-remove|abort-deconfigure)\n        /usr/bin/update-alternatives --install /usr/bin/{s} {s} {s} {d}             --slave /usr/share/man/man1/{s}.1 {s}.1 {s}\n        ;;\nesac\n",
                .{ group, group, candidate, priority, group, group, manual },
            )
        else if (std.mem.eql(u8, kind, "prerm"))
            try std.fmt.allocPrint(
                allocator,
                "\ncase \"$1\" in\n    remove|upgrade|deconfigure)\n        /usr/bin/update-alternatives --remove {s} {s}\n        ;;\nesac\n",
                .{ group, candidate },
            )
        else
            "";
        const identity = try std.fmt.allocPrint(allocator, "{s}@{s}:{s}", .{ package, version, kind });
        const body = try std.fmt.allocPrint(
            allocator,
            \\#!/bin/sh
            \\if [ "${{DEBCONF_DB_FALLBACK+x}}" = x ] ||
            \\   [ "${{DEBCONF_DB_OVERRIDE+x}}" = x ] ||
            \\   [ "${{DEBCONF_DEBUG+x}}" = x ] ||
            \\   [ "${{DEBIAN_FRONTEND+x}}" = x ]; then
            \\    exit 24
            \\fi
            \\fds=''
            \\for fd in 0 1 2 3 4 5 6 7 8 9; do
            \\    if ( eval ": <&$fd" ) 2>> /{s}; then
            \\        if [ -n "$fds" ]; then fds="$fds,"; fi
            \\        fds="$fds$fd"
            \\    fi
            \\done
            \\printf '%s\t%d' '{s}' "$#" >> /{s}
            \\for argument do
            \\    printf '\t%d:%s' "${{#argument}}" "$argument" >> /{s}
            \\done
            \\printf '\tcwd=%s\tfds=%s\n' "$PWD" "$fds" >> /{s}
            \\{s}
            \\marker='{s}:'"$1"
            \\if [ -f /{s} ]; then
            \\    IFS= read -r selected < /{s}
            \\    if [ "$selected" = "$marker" ]; then
            \\        printf '%s\n' "$marker" > /{s}
            \\        /bin/sleep 30
            \\    fi
            \\fi
            \\if [ -f /{s} ]; then
            \\    IFS= read -r selected < /{s}
            \\    if [ "$selected" = "$marker" ]; then
            \\        exit 23
            \\    fi
            \\fi
            \\exit 0
            \\
        ,
            .{
                fd_errors_relative,
                identity,
                trace_relative,
                trace_relative,
                trace_relative,
                action,
                identity,
                pause_relative,
                pause_relative,
                paused_relative,
                failures_relative,
                failures_relative,
            },
        );
        result[idx] = .{ .kind = kind, .body = body };
    }
    return result;
}

pub fn makePackage(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace: []const u8,
    architecture: []const u8,
    package: []const u8,
    version: []const u8,
    group: []const u8,
    priority: i64,
    scripted: bool,
) ![]u8 {
    const candidate = try std.fmt.allocPrint(allocator, "usr/lib/debz-alternatives/{s}-{s}", .{ package, version });
    const manual = try std.fmt.allocPrint(allocator, "usr/share/man/man1/{s}-{s}.1", .{ package, version });
    const extras = try allocator.alloc(ExtraFile, 2);
    extras[0] = .{
        .relative = candidate,
        .content = try std.fmt.allocPrint(allocator, "provider {s} {s}\n", .{ package, version }),
    };
    extras[1] = .{
        .relative = manual,
        .content = try std.fmt.allocPrint(allocator, "manual {s} {s}\n", .{ package, version }),
    };
    const scripts = if (scripted)
        try packageScripts(allocator, package, version, group, priority)
    else
        &[_]ScriptEntry{};
    return makeMaterializationPackage(allocator, io, workspace, architecture, version, .{
        .package = package,
        .extra_files = extras,
        .scripts = scripts,
        .alternatives_body = try alternativesMember(allocator, version),
        .alternatives_mode = 0o640,
    });
}

fn prepareExecArrays(
    allocator: std.mem.Allocator,
    command: []const []const u8,
    environment: []const EnvPair,
) !struct {
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
} {
    var argv_buf = try allocator.allocSentinel(?[*:0]const u8, command.len, null);
    for (command, 0..) |arg, i| {
        argv_buf[i] = (try dupeZ(allocator, arg)).ptr;
    }
    var envp_buf = try allocator.allocSentinel(?[*:0]const u8, environment.len, null);
    for (environment, 0..) |pair, i| {
        const line = try std.fmt.allocPrintSentinel(allocator, "{s}={s}", .{ pair.name, pair.value }, 0);
        envp_buf[i] = line.ptr;
    }
    return .{ .argv = argv_buf.ptr, .envp = envp_buf.ptr };
}

fn spawnChildProcess(
    allocator: std.mem.Allocator,
    io: std.Io,
    command: []const []const u8,
    environment: []const EnvPair,
    log_path: []const u8,
) !i32 {
    const parent = std.fs.path.dirname(log_path) orelse return fail("invalid log path", .{});
    try std.Io.Dir.cwd().createDirPath(io, parent);
    const log_z = try dupeZ(allocator, log_path);
    const open_flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
        .CLOEXEC = true,
    };
    const log_fd_rc = linux.openat(linux.AT.FDCWD, log_z.ptr, open_flags, 0o644);
    if (errnoFailed(log_fd_rc)) return fail("cannot open log file: {s}", .{log_path});
    const log_fd: i32 = @intCast(log_fd_rc);
    defer _ = linux.close(log_fd);

    const null_flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true };
    const null_fd_rc = linux.openat(linux.AT.FDCWD, "/dev/null", null_flags, 0);
    if (errnoFailed(null_fd_rc)) return fail("cannot open /dev/null", .{});
    const null_fd: i32 = @intCast(null_fd_rc);
    defer _ = linux.close(null_fd);

    const exec_arrays = try prepareExecArrays(allocator, command, environment);
    const pid_rc = linux.fork();
    if (errnoFailed(pid_rc)) return fail("fork failed", .{});
    if (pid_rc == 0) {
        _ = linux.setsid();
        _ = linux.chdir("/");
        const fsize_limit = linux.rlimit{
            .cur = Limits.maximum_log_bytes,
            .max = Limits.maximum_log_bytes,
        };
        _ = linux.setrlimit(.FSIZE, &fsize_limit);
        const core_limit = linux.rlimit{ .cur = 0, .max = 0 };
        _ = linux.setrlimit(.CORE, &core_limit);
        _ = linux.dup2(null_fd, linux.STDIN_FILENO);
        _ = linux.dup2(log_fd, linux.STDOUT_FILENO);
        _ = linux.dup2(log_fd, linux.STDERR_FILENO);
        for (3..128) |fd| {
            _ = linux.close(@intCast(fd));
        }
        const nofile_limit = linux.rlimit{ .cur = 64, .max = 64 };
        _ = linux.setrlimit(.NOFILE, &nofile_limit);
        _ = linux.execve(exec_arrays.argv[0].?, exec_arrays.argv, exec_arrays.envp);
        linux.exit_group(127);
    }
    return @intCast(pid_rc);
}

fn sleepMillis(ms: i64) void {
    const req = linux.timespec{
        .sec = @divTrunc(ms, 1000),
        .nsec = @rem(ms, 1000) * 1_000_000,
    };
    _ = linux.nanosleep(&req, null);
}

fn currentRealtimeNanoseconds() i128 {
    var ts: linux.timespec = .{ .sec = 0, .nsec = 0 };
    _ = linux.clock_gettime(.REALTIME, &ts);
    return @as(i128, ts.sec) * 1_000_000_000 + @as(i128, ts.nsec);
}

pub fn runBoundedProcess(
    allocator: std.mem.Allocator,
    io: std.Io,
    command: []const []const u8,
    environment: []const EnvPair,
    output_path: []const u8,
    timeout_seconds: i64,
) !i64 {
    const pid = try spawnChildProcess(allocator, io, command, environment, output_path);
    var status: i32 = 0;
    const deadline_ms = timeout_seconds * 1000;
    var elapsed_ms: i64 = 0;
    while (true) {
        const wrc = linux.wait4(pid, &status, linux.W.NOHANG, null);
        if (linux.errno(wrc) == .INTR) continue;
        if (errnoFailed(wrc)) return fail("wait4 failed", .{});
        if (wrc != 0) break;
        if (elapsed_ms >= deadline_ms) {
            _ = linux.kill(-pid, .KILL);
            _ = linux.wait4(pid, &status, 0, null);
            return fail("subprocess exceeded its {d}-second timeout: {s}", .{ timeout_seconds, command[0] });
        }
        sleepMillis(10);
        elapsed_ms += 10;
    }

    const cleanup_deadline_ms = Limits.subprocess_cleanup_seconds * 1000;
    var cleanup_elapsed_ms: i64 = 0;
    while (true) {
        const krc = linux.kill(-pid, @enumFromInt(0));
        if (linux.errno(krc) == .SRCH) break;
        if (cleanup_elapsed_ms >= cleanup_deadline_ms) {
            _ = linux.kill(-pid, .KILL);
            return fail("subprocess left a live process group: {s}", .{command[0]});
        }
        sleepMillis(10);
        cleanup_elapsed_ms += 10;
    }

    const status_word: u32 = @bitCast(status);
    if (linux.W.IFEXITED(status_word)) {
        return @intCast(linux.W.EXITSTATUS(status_word));
    }
    if (linux.W.IFSIGNALED(status_word)) {
        return -@as(i64, @intCast(@intFromEnum(linux.W.TERMSIG(status_word))));
    }
    return fail("subprocess terminated abnormally: {s}", .{command[0]});
}

fn decodeBackslashReplace(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    if (std.unicode.utf8ValidateSlice(data)) {
        return allocator.dupe(u8, data);
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < data.len) {
        const seq_len = std.unicode.utf8ByteSequenceLength(data[i]) catch 0;
        if (seq_len > 0 and i + seq_len <= data.len and std.unicode.utf8ValidateSlice(data[i .. i + seq_len])) {
            try out.appendSlice(allocator, data[i .. i + seq_len]);
            i += seq_len;
        } else {
            const escaped = try std.fmt.allocPrint(allocator, "\\x{x:0>2}", .{data[i]});
            defer allocator.free(escaped);
            try out.appendSlice(allocator, escaped);
            i += 1;
        }
    }
    return out.toOwnedSlice(allocator);
}

fn parseTimestamp19(text: []const u8) ?i64 {
    if (text.len != 19) return null;
    if (text[4] != '-' or text[7] != '-' or text[10] != ' ' or text[13] != ':' or text[16] != ':') return null;
    for ([_]usize{ 0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18 }) |idx| {
        if (!std.ascii.isDigit(text[idx])) return null;
    }
    const year = std.fmt.parseInt(i64, text[0..4], 10) catch return null;
    const month = std.fmt.parseInt(i64, text[5..7], 10) catch return null;
    const day = std.fmt.parseInt(i64, text[8..10], 10) catch return null;
    const hour = std.fmt.parseInt(i64, text[11..13], 10) catch return null;
    const minute = std.fmt.parseInt(i64, text[14..16], 10) catch return null;
    const second = std.fmt.parseInt(i64, text[17..19], 10) catch return null;

    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400;
    const m_adj = if (month > 2) month - 3 else month + 9;
    const doy = @divFloor(153 * m_adj + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return days * 86400 + hour * 3600 + minute * 60 + second;
}

pub fn normalizeOutput(allocator: std.mem.Allocator, data: []const u8, workspace: []const u8) ![]u8 {
    if (data.len > Limits.maximum_output_bytes) {
        return fail("subprocess output exceeds its byte limit", .{});
    }
    const replaced = try std.mem.replaceOwned(u8, allocator, data, workspace, "<workspace>");
    defer allocator.free(replaced);
    return decodeBackslashReplace(allocator, replaced);
}

pub fn normalizeAlternativesLog(allocator: std.mem.Allocator, data: []const u8, workspace: []const u8) ![]u8 {
    if (data.len > Limits.maximum_log_bytes) {
        return fail("alternatives log exceeds its byte limit", .{});
    }
    const ws_replaced = try std.mem.replaceOwned(u8, allocator, data, workspace, "<workspace>");
    defer allocator.free(ws_replaced);

    const prefix = "update-alternatives ";
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < ws_replaced.len) {
        const at_line_start = (i == 0 or ws_replaced[i - 1] == '\n');
        if (at_line_start and
            i + prefix.len + 20 <= ws_replaced.len and
            std.mem.eql(u8, ws_replaced[i .. i + prefix.len], prefix) and
            parseTimestamp19(ws_replaced[i + prefix.len .. i + prefix.len + 19]) != null and
            ws_replaced[i + prefix.len + 19] == ':')
        {
            try out.appendSlice(allocator, "update-alternatives <clock>:");
            i += prefix.len + 20;
        } else {
            try out.append(allocator, ws_replaced[i]);
            i += 1;
        }
    }
    return decodeBackslashReplace(allocator, out.items);
}

pub fn normalizeDpkgLog(allocator: std.mem.Allocator, data: []const u8, workspace: []const u8) ![]u8 {
    if (data.len > Limits.maximum_log_bytes) {
        return fail("dpkg log exceeds its byte limit", .{});
    }
    const ws_replaced = try std.mem.replaceOwned(u8, allocator, data, workspace, "<workspace>");
    defer allocator.free(ws_replaced);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < ws_replaced.len) {
        const at_line_start = (i == 0 or ws_replaced[i - 1] == '\n');
        if (at_line_start and
            i + 20 <= ws_replaced.len and
            parseTimestamp19(ws_replaced[i .. i + 19]) != null and
            ws_replaced[i + 19] == ' ')
        {
            try out.appendSlice(allocator, "<clock> ");
            i += 20;
        } else {
            try out.append(allocator, ws_replaced[i]);
            i += 1;
        }
    }
    return decodeBackslashReplace(allocator, out.items);
}

pub fn normalizeCommand(
    allocator: std.mem.Allocator,
    command: []const []const u8,
    workspace: []const u8,
    executable: []const u8,
    label: []const u8,
) !std.json.Value {
    var selected: std.json.Array = .init(allocator);
    for (command, 0..) |argument, index| {
        if (index == 0) {
            if (!std.mem.eql(u8, argument, executable)) {
                return fail("{s} command did not select its pinned executable", .{label});
            }
            try selected.append(.{
                .string = try std.fmt.allocPrint(allocator, "<pinned-{s}>", .{label}),
            });
        } else {
            try selected.append(.{
                .string = try std.mem.replaceOwned(u8, allocator, argument, workspace, "<workspace>"),
            });
        }
    }
    return .{ .array = selected };
}

pub fn logDelta(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    before: []const u8,
    maximum: usize,
) ![]u8 {
    const after = (try optionalRegular(allocator, io, path, maximum)) orelse try allocator.dupe(u8, "");
    defer allocator.free(after);
    if (!std.mem.startsWith(u8, after, before)) {
        return fail("subprocess log was replaced instead of appended: {s}", .{path});
    }
    return allocator.dupe(u8, after[before.len..]);
}

pub fn validateLogClocks(
    data: []const u8,
    alternatives_format: bool,
    started_ns: i128,
    ended_ns: i128,
    label: []const u8,
) !void {
    const min_sec: i64 = @intCast(@divFloor(started_ns, 1_000_000_000) - 2);
    const max_sec: i64 = @intCast(@divFloor(ended_ns, 1_000_000_000) + 3);
    const prefix = "update-alternatives ";
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        const maybe_clock: ?i64 = if (alternatives_format) blk: {
            if (line.len >= prefix.len + 20 and
                std.mem.eql(u8, line[0..prefix.len], prefix) and
                line[prefix.len + 19] == ':')
            {
                break :blk parseTimestamp19(line[prefix.len .. prefix.len + 19]);
            }
            break :blk null;
        } else blk: {
            if (line.len >= 20 and line[19] == ' ') {
                break :blk parseTimestamp19(line[0..19]);
            }
            break :blk null;
        };
        if (maybe_clock) |clock_sec| {
            if (clock_sec < min_sec or clock_sec > max_sec) {
                return fail("{s} log timestamp is outside the invocation window", .{label});
            }
        }
    }
}

pub fn updateCommand(
    allocator: std.mem.Allocator,
    io: std.Io,
    executable: []const u8,
    root: []const u8,
    arguments: []const []const u8,
) ![]const []const u8 {
    try validateRoot(allocator, io, root);
    if (arguments.len > Limits.maximum_arguments) {
        return fail("alternatives argument count exceeds its limit", .{});
    }
    for (arguments) |argument| {
        if (argument.len > Limits.maximum_argument_bytes or std.mem.indexOfScalar(u8, argument, 0) != null) {
            return fail("alternatives argument exceeds its byte limit", .{});
        }
    }
    var cmd: std.ArrayList([]const u8) = .empty;
    try cmd.appendSlice(allocator, &.{
        executable,
        "--root",
        root,
        "--log",
        try std.fmt.allocPrint(allocator, "/{s}", .{alt_log_relative}),
    });
    try cmd.appendSlice(allocator, arguments);
    return cmd.toOwnedSlice(allocator);
}

pub const RunUpdateOptions = struct {
    workspace: []const u8,
    raw: bool = false,
    preflight: bool = true,
};

pub fn runUpdate(
    allocator: std.mem.Allocator,
    io: std.Io,
    executable: []const u8,
    root: []const u8,
    arguments: []const []const u8,
    environment: []const EnvPair,
    output_path: []const u8,
    options: RunUpdateOptions,
) !std.json.Value {
    if (!options.raw and options.preflight) {
        try validateAdminRecords(allocator, io, root);
    }
    const command = if (options.raw) blk: {
        var cmd: std.ArrayList([]const u8) = .empty;
        try cmd.appendSlice(allocator, &.{
            executable,
            "--root",
            root,
            "--log",
            try std.fmt.allocPrint(allocator, "/{s}", .{alt_log_relative}),
        });
        try cmd.appendSlice(allocator, arguments);
        break :blk try cmd.toOwnedSlice(allocator);
    } else try updateCommand(allocator, io, executable, root, arguments);

    const alt_log_path = try std.fs.path.join(allocator, &.{ root, alt_log_relative });
    const log_before = (try optionalRegular(allocator, io, alt_log_path, Limits.maximum_log_bytes)) orelse "";
    const started = currentRealtimeNanoseconds();
    const returncode = try runBoundedProcess(
        allocator,
        io,
        command,
        environment,
        output_path,
        Limits.subprocess_timeout_seconds,
    );
    const ended = currentRealtimeNanoseconds();
    const data = try readRegular(allocator, io, output_path, Limits.maximum_output_bytes);
    if (returncode != 0 and returncode != 2) {
        return fail("update-alternatives exited unexpectedly: {d}; {s}", .{ returncode, output_path });
    }
    const log_bytes = try logDelta(allocator, io, alt_log_path, log_before, Limits.maximum_log_bytes);
    try validateLogClocks(log_bytes, true, started, ended, "alternatives");

    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "command", try normalizeCommand(allocator, command, options.workspace, executable, "update-alternatives"));
    try obj.put(allocator, "exit", .{ .integer = returncode });
    try obj.put(allocator, "log", .{ .string = try normalizeAlternativesLog(allocator, log_bytes, options.workspace) });
    try obj.put(allocator, "output", .{ .string = try normalizeOutput(allocator, data, options.workspace) });
    return .{ .object = obj };
}

pub fn mapAbsolute(allocator: std.mem.Allocator, root: []const u8, value: []const u8) ![]u8 {
    const validated = try validateAbsolutePath(value);
    const trimmed = std.mem.trimStart(u8, validated, "/");
    return std.fs.path.join(allocator, &.{ root, trimmed });
}

pub fn writeTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    value: []const u8,
    content: []const u8,
) !void {
    const path = try mapAbsolute(allocator, root, value);
    try writeRegular(allocator, io, path, content, 0o755);
}

pub fn regularFact(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    maximum: usize,
) !std.json.Value {
    const data = try readRegular(allocator, io, path, maximum);
    const metadata = try lstatPath(allocator, path);
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "bytes_base64", .{ .string = try base64EncodeAlloc(allocator, data) });
    try obj.put(allocator, "gid", .{ .integer = @intCast(metadata.gid) });
    try obj.put(allocator, "mode", .{ .string = try std.fmt.allocPrint(allocator, "{o:0>4}", .{metadata.mode & 0o7777}) });
    try obj.put(allocator, "sha256", .{ .string = try sha256HexAlloc(allocator, data) });
    try obj.put(allocator, "size", .{ .integer = @intCast(data.len) });
    try obj.put(allocator, "uid", .{ .integer = @intCast(metadata.uid) });
    return .{ .object = obj };
}

pub fn symlinkFact(allocator: std.mem.Allocator, path: []const u8) !std.json.Value {
    const metadata = try lstatPath(allocator, path);
    if ((metadata.mode & linux.S.IFMT) != linux.S.IFLNK) {
        return fail("expected alternatives symlink: {s}", .{path});
    }
    const target = try readSymlinkAlloc(allocator, path);
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "gid", .{ .integer = @intCast(metadata.gid) });
    try obj.put(allocator, "mode", .{ .string = try std.fmt.allocPrint(allocator, "{o:0>4}", .{metadata.mode & 0o7777}) });
    try obj.put(allocator, "target", .{ .string = target });
    try obj.put(allocator, "uid", .{ .integer = @intCast(metadata.uid) });
    return .{ .object = obj };
}

pub fn optionalPathFact(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !std.json.Value {
    const metadata = lstatPath(allocator, path) catch |err| switch (err) {
        error.FileNotFound => return .null,
        else => return err,
    };
    const ftype = metadata.mode & linux.S.IFMT;
    if (ftype == linux.S.IFREG) {
        var fact = try regularFact(allocator, io, path, Limits.maximum_record_bytes);
        try fact.object.put(allocator, "kind", .{ .string = "regular" });
        return fact;
    }
    if (ftype == linux.S.IFLNK) {
        var fact = try symlinkFact(allocator, path);
        try fact.object.put(allocator, "kind", .{ .string = "symlink" });
        return fact;
    }
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "gid", .{ .integer = @intCast(metadata.gid) });
    const kind = if (ftype == linux.S.IFDIR)
        "directory"
    else if (ftype == linux.S.IFIFO)
        "fifo"
    else
        "special";
    try obj.put(allocator, "kind", .{ .string = kind });
    try obj.put(allocator, "mode", .{ .string = try std.fmt.allocPrint(allocator, "{o:0>4}", .{metadata.mode & 0o7777}) });
    try obj.put(allocator, "uid", .{ .integer = @intCast(metadata.uid) });
    return .{ .object = obj };
}

pub fn groupState(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    name: []const u8,
    generic_paths: []const []const u8,
) !std.json.Value {
    _ = try validateName(name);
    const record_path = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg/alternatives", name });
    const alt_dir = try std.fs.path.join(allocator, &.{ root, "etc/alternatives" });
    const entries = try boundedScandir(allocator, io, alt_dir, Limits.maximum_linked_entries);
    var selectors: std.json.Array = .init(allocator);
    for (entries) |entry_name| {
        if (std.mem.eql(u8, entry_name, "README")) continue;
        const entry_path = try std.fs.path.join(allocator, &.{ alt_dir, entry_name });
        var sel_obj: std.json.ObjectMap = .empty;
        try sel_obj.put(allocator, "fact", try optionalPathFact(allocator, io, entry_path));
        try sel_obj.put(allocator, "name", .{ .string = entry_name });
        try selectors.append(.{ .object = sel_obj });
    }
    var generic_links: std.json.Array = .init(allocator);
    for (generic_paths) |gpath| {
        const mapped = try mapAbsolute(allocator, root, gpath);
        var gl_obj: std.json.ObjectMap = .empty;
        try gl_obj.put(allocator, "fact", try optionalPathFact(allocator, io, mapped));
        try gl_obj.put(allocator, "path", .{ .string = try allocator.dupe(u8, gpath) });
        try generic_links.append(.{ .object = gl_obj });
    }
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "generic_links", .{ .array = generic_links });
    try obj.put(allocator, "record", try optionalPathFact(allocator, io, record_path));
    try obj.put(allocator, "selectors", .{ .array = selectors });
    return .{ .object = obj };
}

pub fn installArguments(
    allocator: std.mem.Allocator,
    group: std.json.Value,
    priority: i64,
) ![]const []const u8 {
    const links = group.object.get("links").?.array.items;
    var master_opt: ?std.json.Value = null;
    for (links) |link| {
        if (std.mem.eql(u8, link.object.get("relationship").?.string, "master")) {
            master_opt = link;
            break;
        }
    }
    const master = master_opt orelse return fail("missing master link", .{});
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(allocator, &.{
        "--install",
        try std.fmt.allocPrint(allocator, "/{s}", .{master.object.get("link_path").?.string}),
        group.object.get("name").?.string,
        master.object.get("selector_target").?.string,
        try std.fmt.allocPrint(allocator, "{d}", .{priority}),
    });
    for (links) |link| {
        if (std.mem.eql(u8, link.object.get("relationship").?.string, "slave")) {
            try args.appendSlice(allocator, &.{
                "--slave",
                try std.fmt.allocPrint(allocator, "/{s}", .{link.object.get("link_path").?.string}),
                std.fs.path.basename(link.object.get("selector_path").?.string),
                link.object.get("selector_target").?.string,
            });
        }
    }
    return args.toOwnedSlice(allocator);
}

pub fn observeVendorProjection(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    executable: []const u8,
    derived: std.json.Value,
) !std.json.Value {
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "vendor-projection" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
    const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
    try ctx.makeRoot(root, architecture, false);
    const bin_link = try std.fs.path.join(ctx.allocator, &.{ root, "bin" });
    const bin_z = try dupeZ(ctx.allocator, bin_link);
    if (errnoFailed(linux.symlinkat("usr/bin", linux.AT.FDCWD, bin_z.ptr))) {
        return fail("symlinkat bin failed", .{});
    }

    const alternatives = derived.object.get("alternatives").?.object;
    const groups = alternatives.get("groups").?.array.items;
    const req_items = alternatives.get("requested_paths").?.array.items;

    var requested_list: std.ArrayList([]const u8) = .empty;
    for (req_items) |item| {
        const p = item.object.get("path").?.string;
        var exists = false;
        for (requested_list.items) |existing| {
            if (std.mem.eql(u8, existing, p)) {
                exists = true;
                break;
            }
        }
        if (!exists) try requested_list.append(ctx.allocator, p);
    }
    std.sort.heap([]const u8, requested_list.items, {}, struct {
        fn less(_: void, left: []const u8, right: []const u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.less);

    for (requested_list.items) |relative| {
        if (std.mem.startsWith(u8, relative, "etc/alternatives/")) continue;
        var is_link_path = false;
        outer: for (groups) |group| {
            for (group.object.get("links").?.array.items) |link| {
                if (std.mem.eql(u8, relative, link.object.get("link_path").?.string)) {
                    is_link_path = true;
                    break :outer;
                }
            }
        }
        if (is_link_path) continue;
        const full = try std.fs.path.join(ctx.allocator, &.{ root, relative });
        if (!try lexistsPath(ctx.allocator, full)) {
            const content = try std.fmt.allocPrint(ctx.allocator, "synthetic target:{s}\n", .{relative});
            try writeRegular(ctx.allocator, ctx.io, full, content, 0o755);
        }
    }
    try writeRegular(
        ctx.allocator,
        ctx.io,
        try std.fs.path.join(ctx.allocator, &.{ root, "etc/alternatives/README" }),
        "synthetic inert alternatives readme\n",
        0o644,
    );

    var observations: std.json.Array = .init(ctx.allocator);
    for (groups, 0..) |group, index| {
        const gname = group.object.get("name").?.string;
        const log_path = try std.fs.path.join(
            ctx.allocator,
            &.{ directory, try std.fmt.allocPrint(ctx.allocator, "{d:0>2}-{s}.log", .{ index, gname }) },
        );
        const args = try installArguments(ctx.allocator, group, 50);
        const result = try runUpdate(ctx.allocator, ctx.io, executable, root, args, environment, log_path, .{
            .workspace = workspace,
        });
        const links = group.object.get("links").?.array.items;
        var generic_paths = try ctx.allocator.alloc([]const u8, links.len);
        for (links, 0..) |link, l_idx| {
            generic_paths[l_idx] = try std.fmt.allocPrint(ctx.allocator, "/{s}", .{link.object.get("link_path").?.string});
        }
        const state = try groupState(ctx.allocator, ctx.io, root, gname, generic_paths);
        if (result.object.get("exit").?.integer != 0 or state.object.get("record").? == .null) {
            return fail("vendor group projection failed: {s}", .{gname});
        }
        var filtered_selectors: std.json.Array = .init(ctx.allocator);
        for (state.object.get("selectors").?.array.items) |sel_item| {
            const sel_name = sel_item.object.get("name").?.string;
            var keep = false;
            for (links) |link| {
                if (std.mem.eql(u8, sel_name, std.fs.path.basename(link.object.get("selector_path").?.string))) {
                    keep = true;
                    break;
                }
            }
            if (keep) try filtered_selectors.append(sel_item);
        }
        var obs_obj: std.json.ObjectMap = .empty;
        try obs_obj.put(ctx.allocator, "generic_links", state.object.get("generic_links").?);
        try obs_obj.put(ctx.allocator, "name", .{ .string = gname });
        try obs_obj.put(ctx.allocator, "record", state.object.get("record").?);
        try obs_obj.put(ctx.allocator, "result", result);
        try obs_obj.put(ctx.allocator, "selectors", .{ .array = filtered_selectors });
        try observations.append(.{ .object = obs_obj });
    }

    for (requested_list.items) |relative| {
        const full = try std.fs.path.join(ctx.allocator, &.{ root, relative });
        if (!try lexistsPath(ctx.allocator, full)) {
            return fail("vendor requested paths were not materialized: {s}", .{relative});
        }
    }

    var req_json_arr: std.json.Array = .init(ctx.allocator);
    for (requested_list.items) |rel| {
        try req_json_arr.append(.{ .string = rel });
    }
    const req_canonical = try canonicalJson(ctx.allocator, .{ .array = req_json_arr });
    const req_sha = try sha256HexAlloc(ctx.allocator, req_canonical);

    var relationship_count: i64 = 0;
    for (groups) |g| {
        relationship_count += @intCast(g.object.get("links").?.array.items.len);
    }

    var ts_contract: std.json.ObjectMap = .empty;
    try ts_contract.put(ctx.allocator, "log", .{ .string = "local CLOCK_REALTIME seconds within invocation" });
    try ts_contract.put(ctx.allocator, "records", .{ .string = "filesystem clock at atomic rename" });
    try ts_contract.put(ctx.allocator, "symlinks", .{ .string = "whole-second invocation time set by update-alternatives" });

    var out_obj: std.json.ObjectMap = .empty;
    try out_obj.put(ctx.allocator, "group_count", .{ .integer = @intCast(observations.items.len) });
    try out_obj.put(ctx.allocator, "groups", .{ .array = observations });
    try out_obj.put(ctx.allocator, "relationship_count", .{ .integer = relationship_count });
    try out_obj.put(ctx.allocator, "requested_path_count", .{ .integer = @intCast(requested_list.items.len) });
    try out_obj.put(ctx.allocator, "requested_paths_sha256", .{ .string = req_sha });
    try out_obj.put(ctx.allocator, "timestamp_contract", .{ .object = ts_contract });
    return .{ .object = out_obj };
}

pub fn observeSelection(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    executable: []const u8,
) !std.json.Value {
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "selection" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
    const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
    try ctx.makeRoot(root, architecture, false);
    for ([_][]const u8{ "a", "b", "c" }) |name| {
        try writeTarget(
            ctx.allocator,
            ctx.io,
            root,
            try std.fmt.allocPrint(ctx.allocator, "/usr/lib/debz-choice/{s}", .{name}),
            try std.fmt.allocPrint(ctx.allocator, "{s}\n", .{name}),
        );
        try writeTarget(
            ctx.allocator,
            ctx.io,
            root,
            try std.fmt.allocPrint(ctx.allocator, "/usr/share/man/man1/debz-choice-{s}.1", .{name}),
            try std.fmt.allocPrint(ctx.allocator, "{s} manual\n", .{name}),
        );
    }

    const StepSpec = struct { label: []const u8, args: []const []const u8 };
    const installArgs = struct {
        fn build(alloc: std.mem.Allocator, name: []const u8, prio: []const u8) ![]const []const u8 {
            const arr = try alloc.alloc([]const u8, 9);
            arr[0] = "--install";
            arr[1] = "/usr/bin/debz-choice";
            arr[2] = "debz-choice";
            arr[3] = try std.fmt.allocPrint(alloc, "/usr/lib/debz-choice/{s}", .{name});
            arr[4] = prio;
            arr[5] = "--slave";
            arr[6] = "/usr/share/man/man1/debz-choice.1";
            arr[7] = "debz-choice.1";
            arr[8] = try std.fmt.allocPrint(alloc, "/usr/share/man/man1/debz-choice-{s}.1", .{name});
            return arr;
        }
    }.build;

    const specs = [_]StepSpec{
        .{ .label = "install-b-10", .args = try installArgs(ctx.allocator, "b", "10") },
        .{ .label = "install-a-10-tie", .args = try installArgs(ctx.allocator, "a", "10") },
        .{ .label = "install-c-20", .args = try installArgs(ctx.allocator, "c", "20") },
        .{ .label = "set-a-manual", .args = &.{ "--set", "debz-choice", "/usr/lib/debz-choice/a" } },
        .{ .label = "raise-c-30-manual-sticks", .args = try installArgs(ctx.allocator, "c", "30") },
        .{ .label = "auto-selects-c", .args = &.{ "--auto", "debz-choice" } },
        .{ .label = "remove-c-tie-selects-a", .args = &.{ "--remove", "debz-choice", "/usr/lib/debz-choice/c" } },
        .{ .label = "remove-a-selects-b", .args = &.{ "--remove", "debz-choice", "/usr/lib/debz-choice/a" } },
        .{ .label = "remove-all", .args = &.{ "--remove-all", "debz-choice" } },
    };

    var steps: std.json.Array = .init(ctx.allocator);
    const generic_paths = [_][]const u8{ "/usr/bin/debz-choice", "/usr/share/man/man1/debz-choice.1" };
    for (specs, 0..) |spec, idx| {
        const log_path = try std.fs.path.join(
            ctx.allocator,
            &.{ directory, try std.fmt.allocPrint(ctx.allocator, "{d:0>2}-{s}.log", .{ idx, spec.label }) },
        );
        const result = try runUpdate(ctx.allocator, ctx.io, executable, root, spec.args, environment, log_path, .{
            .workspace = workspace,
        });
        var step_obj: std.json.ObjectMap = .empty;
        try step_obj.put(ctx.allocator, "operation", .{ .string = spec.label });
        try step_obj.put(ctx.allocator, "result", result);
        try step_obj.put(ctx.allocator, "state", try groupState(ctx.allocator, ctx.io, root, "debz-choice", &generic_paths));
        try steps.append(.{ .object = step_obj });
    }
    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "steps", .{ .array = steps });
    return .{ .object = out };
}

pub fn observeMissingAndGroupShape(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    executable: []const u8,
) !std.json.Value {
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "missing-shape" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
    const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
    try ctx.makeRoot(root, architecture, false);
    try writeTarget(ctx.allocator, ctx.io, root, "/usr/lib/debz-missing/present", "present\n");
    try writeTarget(ctx.allocator, ctx.io, root, "/usr/lib/debz-missing/second", "second\n");
    try writeTarget(ctx.allocator, ctx.io, root, "/usr/share/man/man1/debz-missing-second.1", "second manual\n");

    const paths = [_][]const u8{ "/usr/bin/debz-missing", "/usr/share/man/man1/debz-missing.1" };
    var steps: std.json.Array = .init(ctx.allocator);

    const runStep = struct {
        fn call(
            c: Context,
            ws: []const u8,
            dir: []const u8,
            rt: []const u8,
            exec_path: []const u8,
            env: []const EnvPair,
            st: *std.json.Array,
            label: []const u8,
            args: []const []const u8,
            gp: []const []const u8,
        ) !void {
            const log_path = try std.fs.path.join(
                c.allocator,
                &.{ dir, try std.fmt.allocPrint(c.allocator, "{d:0>2}-{s}.log", .{ st.items.len, label }) },
            );
            const result = try runUpdate(c.allocator, c.io, exec_path, rt, args, env, log_path, .{
                .workspace = ws,
            });
            var step_obj: std.json.ObjectMap = .empty;
            try step_obj.put(c.allocator, "operation", .{ .string = label });
            try step_obj.put(c.allocator, "result", result);
            try step_obj.put(c.allocator, "state", try groupState(c.allocator, c.io, rt, "debz-missing", gp));
            try st.append(.{ .object = step_obj });
        }
    }.call;

    try runStep(ctx, workspace, directory, root, executable, environment, &steps, "install-missing-high", &.{
        "--install",
        paths[0],
        "debz-missing",
        "/usr/lib/debz-missing/absent",
        "50",
        "--slave",
        paths[1],
        "debz-missing.1",
        "/usr/share/man/man1/debz-missing-absent.1",
    }, &paths);

    try runStep(ctx, workspace, directory, root, executable, environment, &steps, "install-present-low", &.{
        "--install",
        paths[0],
        "debz-missing",
        "/usr/lib/debz-missing/present",
        "10",
    }, &paths);

    try runStep(ctx, workspace, directory, root, executable, environment, &steps, "reregister-present-with-missing-slave", &.{
        "--install",
        paths[0],
        "debz-missing",
        "/usr/lib/debz-missing/present",
        "10",
        "--slave",
        paths[1],
        "debz-missing.1",
        "/usr/share/man/man1/debz-missing-absent.1",
    }, &paths);

    try runStep(ctx, workspace, directory, root, executable, environment, &steps, "install-second-with-slave", &.{
        "--install",
        paths[0],
        "debz-missing",
        "/usr/lib/debz-missing/second",
        "20",
        "--slave",
        paths[1],
        "debz-missing.1",
        "/usr/share/man/man1/debz-missing-second.1",
    }, &paths);

    try runStep(ctx, workspace, directory, root, executable, environment, &steps, "reregister-selected-without-slave", &.{
        "--install",
        paths[0],
        "debz-missing",
        "/usr/lib/debz-missing/second",
        "20",
    }, &paths);

    const second_z = try dupeZ(ctx.allocator, try std.fs.path.join(ctx.allocator, &.{ root, "usr/lib/debz-missing/second" }));
    _ = linux.unlinkat(linux.AT.FDCWD, second_z.ptr, 0);
    try runStep(ctx, workspace, directory, root, executable, environment, &steps, "query-prunes-missing-selected", &.{
        "--query",
        "debz-missing",
    }, &paths);

    const present_z = try dupeZ(ctx.allocator, try std.fs.path.join(ctx.allocator, &.{ root, "usr/lib/debz-missing/present" }));
    _ = linux.unlinkat(linux.AT.FDCWD, present_z.ptr, 0);
    try runStep(ctx, workspace, directory, root, executable, environment, &steps, "auto-with-all-targets-missing", &.{
        "--auto",
        "debz-missing",
    }, &paths);

    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "steps", .{ .array = steps });
    return .{ .object = out };
}

pub fn observeMalformed(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    executable: []const u8,
) !std.json.Value {
    const CaseSpec = struct { label: []const u8, content: []const u8 };
    const specs = [_]CaseSpec{
        .{ .label = "empty", .content = "" },
        .{ .label = "truncated", .content = "auto\n/usr/bin/bad\n" },
        .{ .label = "invalid-mode", .content = "invalid\n/usr/bin/bad\n\n" },
        .{ .label = "invalid-priority", .content = "auto\n/usr/bin/bad\n\n/usr/lib/bad\nnot-a-number\n\n" },
        .{ .label = "embedded-nul", .content = "auto\n/usr/bin/bad\x00suffix\n\n" },
    };
    var cases: std.json.Array = .init(ctx.allocator);
    for (specs) |spec| {
        const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "malformed", spec.label });
        try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
        const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
        try ctx.makeRoot(root, architecture, false);
        try writeTarget(ctx.allocator, ctx.io, root, "/usr/lib/bad", "bad\n");
        try writeRegular(
            ctx.allocator,
            ctx.io,
            try std.fs.path.join(ctx.allocator, &.{ root, "var/lib/dpkg/alternatives/bad" }),
            spec.content,
            0o644,
        );
        const result = try runUpdate(
            ctx.allocator,
            ctx.io,
            executable,
            root,
            &.{ "--query", "bad" },
            environment,
            try std.fs.path.join(ctx.allocator, &.{ directory, "query.log" }),
            .{ .workspace = workspace },
        );
        var input_obj: std.json.ObjectMap = .empty;
        try input_obj.put(ctx.allocator, "sha256", .{ .string = try sha256HexAlloc(ctx.allocator, spec.content) });
        try input_obj.put(ctx.allocator, "size", .{ .integer = @intCast(spec.content.len) });

        var case_obj: std.json.ObjectMap = .empty;
        try case_obj.put(ctx.allocator, "case", .{ .string = spec.label });
        try case_obj.put(ctx.allocator, "input", .{ .object = input_obj });
        try case_obj.put(ctx.allocator, "result", result);
        try case_obj.put(ctx.allocator, "state", try groupState(ctx.allocator, ctx.io, root, "bad", &.{"/usr/bin/bad"}));
        try cases.append(.{ .object = case_obj });
    }

    const preflight = try std.fs.path.join(ctx.allocator, &.{ workspace, "malformed/preflight" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, preflight);
    var rejections: std.json.Array = .init(ctx.allocator);

    for ([_][]const u8{ "directory", "symlink", "fifo" }) |label| {
        const root = try std.fs.path.join(ctx.allocator, &.{ preflight, label });
        try ctx.makeRoot(root, architecture, false);
        const record = try std.fs.path.join(ctx.allocator, &.{ root, "var/lib/dpkg/alternatives/bad" });
        const rec_z = try dupeZ(ctx.allocator, record);
        if (std.mem.eql(u8, label, "directory")) {
            try std.Io.Dir.cwd().createDirPath(ctx.io, record);
        } else if (std.mem.eql(u8, label, "symlink")) {
            _ = linux.symlinkat("target", linux.AT.FDCWD, rec_z.ptr);
        } else {
            _ = linux.mknodat(linux.AT.FDCWD, rec_z.ptr, linux.S.IFIFO | 0o600, 0);
        }
        if (validateAdminRecords(ctx.allocator, ctx.io, root)) |_| {
            return fail("non-regular alternatives record was accepted: {s}", .{label});
        } else |_| {
            var rej_obj: std.json.ObjectMap = .empty;
            try rej_obj.put(ctx.allocator, "case", .{ .string = label });
            try rej_obj.put(ctx.allocator, "error", .{ .string = "alternatives record must be regular: bad" });
            try rejections.append(.{ .object = rej_obj });
        }
    }

    {
        const root = try std.fs.path.join(ctx.allocator, &.{ preflight, "oversized" });
        try ctx.makeRoot(root, architecture, false);
        const record = try std.fs.path.join(ctx.allocator, &.{ root, "var/lib/dpkg/alternatives/bad" });
        const oversized_bytes = try ctx.allocator.alloc(u8, Limits.maximum_record_bytes + 1);
        @memset(oversized_bytes, 'x');
        try writeRegular(ctx.allocator, ctx.io, record, oversized_bytes, 0o644);
        if (validateAdminRecords(ctx.allocator, ctx.io, root)) |_| {
            return fail("oversized alternatives record was accepted", .{});
        } else |_| {
            var rej_obj: std.json.ObjectMap = .empty;
            try rej_obj.put(ctx.allocator, "case", .{ .string = "oversized" });
            try rej_obj.put(ctx.allocator, "error", .{ .string = "alternatives record bytes exceed their limit" });
            try rejections.append(.{ .object = rej_obj });
        }
    }

    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "oracle_preflight_rejections", .{ .array = rejections });
    try out.put(ctx.allocator, "regular_record_cases", .{ .array = cases });
    return .{ .object = out };
}

pub fn observeAttacks(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    executable: []const u8,
) !std.json.Value {
    var results: std.json.Array = .init(ctx.allocator);
    for ([_][]const u8{ "/../escape", "/usr/bin/../escape", "relative", "/", "/a//b" }) |value| {
        if (validateAbsolutePath(value)) |_| {
            return fail("unsafe attack path was accepted: {s}", .{value});
        } else |_| {
            var obj: std.json.ObjectMap = .empty;
            try obj.put(ctx.allocator, "case", .{ .string = try std.fmt.allocPrint(ctx.allocator, "path:{s}", .{value}) });
            try obj.put(ctx.allocator, "error", .{ .string = try std.fmt.allocPrint(ctx.allocator, "unsafe absolute alternatives path: '{s}'", .{value}) });
            try results.append(.{ .object = obj });
        }
    }
    for ([_][]const u8{ "../escape", "a/b", ".hidden", "A", "" }) |value| {
        if (validateName(value)) |_| {
            return fail("unsafe attack name was accepted: {s}", .{value});
        } else |_| {
            var obj: std.json.ObjectMap = .empty;
            try obj.put(ctx.allocator, "case", .{ .string = try std.fmt.allocPrint(ctx.allocator, "name:{s}", .{value}) });
            try obj.put(ctx.allocator, "error", .{ .string = try std.fmt.allocPrint(ctx.allocator, "unsafe alternatives name: '{s}'", .{value}) });
            try results.append(.{ .object = obj });
        }
    }

    var raw_cases: std.json.Array = .init(ctx.allocator);
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "attacks" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);

    {
        const root = try std.fs.path.join(ctx.allocator, &.{ directory, "traversal-root" });
        try ctx.makeRoot(root, architecture, false);
        try writeTarget(ctx.allocator, ctx.io, root, "/usr/lib/provider", "provider\n");
        const result = try runUpdate(
            ctx.allocator,
            ctx.io,
            executable,
            root,
            &.{ "--install", "/../escaped-link", "escape", "/usr/lib/provider", "10" },
            environment,
            try std.fs.path.join(ctx.allocator, &.{ directory, "traversal.log" }),
            .{ .workspace = workspace, .raw = true },
        );
        var obj: std.json.ObjectMap = .empty;
        try obj.put(ctx.allocator, "case", .{ .string = "generic-link-traversal" });
        try obj.put(ctx.allocator, "outside_root", try optionalPathFact(ctx.allocator, ctx.io, try std.fs.path.join(ctx.allocator, &.{ directory, "escaped-link" })));
        try obj.put(ctx.allocator, "record", try optionalPathFact(ctx.allocator, ctx.io, try std.fs.path.join(ctx.allocator, &.{ root, "var/lib/dpkg/alternatives/escape" })));
        try obj.put(ctx.allocator, "result", result);
        try raw_cases.append(.{ .object = obj });
    }

    {
        const root = try std.fs.path.join(ctx.allocator, &.{ directory, "symlink-root" });
        try ctx.makeRoot(root, architecture, false);
        const escaped = try std.fs.path.join(ctx.allocator, &.{ directory, "escaped-alt" });
        try std.Io.Dir.cwd().createDirPath(ctx.io, escaped);
        const alt_dir = try std.fs.path.join(ctx.allocator, &.{ root, "etc/alternatives" });
        const alt_z = try dupeZ(ctx.allocator, alt_dir);
        const esc_z = try dupeZ(ctx.allocator, escaped);
        _ = linux.unlinkat(linux.AT.FDCWD, alt_z.ptr, linux.AT.REMOVEDIR);
        _ = linux.symlinkat(esc_z.ptr, linux.AT.FDCWD, alt_z.ptr);
        try writeTarget(ctx.allocator, ctx.io, root, "/usr/lib/provider", "provider\n");
        const result = try runUpdate(
            ctx.allocator,
            ctx.io,
            executable,
            root,
            &.{ "--install", "/usr/bin/escape", "escape", "/usr/lib/provider", "10" },
            environment,
            try std.fs.path.join(ctx.allocator, &.{ directory, "symlink.log" }),
            .{ .workspace = workspace, .raw = true },
        );
        var obj: std.json.ObjectMap = .empty;
        try obj.put(ctx.allocator, "case", .{ .string = "alternatives-directory-symlink" });
        try obj.put(ctx.allocator, "generic", try optionalPathFact(ctx.allocator, ctx.io, try std.fs.path.join(ctx.allocator, &.{ root, "usr/bin/escape" })));
        try obj.put(ctx.allocator, "outside_root", try optionalPathFact(ctx.allocator, ctx.io, try std.fs.path.join(ctx.allocator, &.{ escaped, "escape" })));
        try obj.put(ctx.allocator, "result", result);
        try raw_cases.append(.{ .object = obj });
    }

    {
        const root = try std.fs.path.join(ctx.allocator, &.{ directory, "cycle-root" });
        try ctx.makeRoot(root, architecture, false);
        const result = try runUpdate(
            ctx.allocator,
            ctx.io,
            executable,
            root,
            &.{ "--install", "/usr/bin/cycle", "cycle", "/usr/bin/cycle", "10" },
            environment,
            try std.fs.path.join(ctx.allocator, &.{ directory, "cycle.log" }),
            .{ .workspace = workspace, .raw = true },
        );
        var obj: std.json.ObjectMap = .empty;
        try obj.put(ctx.allocator, "case", .{ .string = "self-referential-provider" });
        try obj.put(ctx.allocator, "result", result);
        try obj.put(ctx.allocator, "state", try groupState(ctx.allocator, ctx.io, root, "cycle", &.{"/usr/bin/cycle"}));
        try raw_cases.append(.{ .object = obj });
    }

    {
        const root = try std.fs.path.join(ctx.allocator, &.{ directory, "indirect-cycle-root" });
        try ctx.makeRoot(root, architecture, false);
        try writeTarget(ctx.allocator, ctx.io, root, "/usr/lib/cycle-provider", "provider\n");
        const setup_result = try runUpdate(
            ctx.allocator,
            ctx.io,
            executable,
            root,
            &.{ "--install", "/usr/bin/cycle-link", "cycle-link", "/usr/lib/cycle-provider", "10" },
            environment,
            try std.fs.path.join(ctx.allocator, &.{ directory, "indirect-cycle-install.log" }),
            .{ .workspace = workspace },
        );
        const provider = try std.fs.path.join(ctx.allocator, &.{ root, "usr/lib/cycle-provider" });
        const prov_z = try dupeZ(ctx.allocator, provider);
        _ = linux.unlinkat(linux.AT.FDCWD, prov_z.ptr, 0);
        _ = linux.symlinkat("/usr/bin/cycle-link", linux.AT.FDCWD, prov_z.ptr);
        const result = try runUpdate(
            ctx.allocator,
            ctx.io,
            executable,
            root,
            &.{ "--query", "cycle-link" },
            environment,
            try std.fs.path.join(ctx.allocator, &.{ directory, "indirect-cycle-query.log" }),
            .{ .workspace = workspace },
        );
        var obj: std.json.ObjectMap = .empty;
        try obj.put(ctx.allocator, "case", .{ .string = "indirect-symlink-cycle" });
        try obj.put(ctx.allocator, "provider", try optionalPathFact(ctx.allocator, ctx.io, provider));
        try obj.put(ctx.allocator, "result", result);
        try obj.put(ctx.allocator, "setup_result", setup_result);
        try obj.put(ctx.allocator, "state", try groupState(ctx.allocator, ctx.io, root, "cycle-link", &.{"/usr/bin/cycle-link"}));
        try raw_cases.append(.{ .object = obj });
    }

    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "oracle_rejections", .{ .array = results });
    try out.put(ctx.allocator, "raw_tool_cases", .{ .array = raw_cases });
    return .{ .object = out };
}

pub fn observeAtomicity(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    executable: []const u8,
) !std.json.Value {
    var results: std.json.Array = .init(ctx.allocator);
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "atomicity" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
    for ([_]struct { label: []const u8, blocker: []const u8 }{
        .{ .label = "database-temporary-blocked", .blocker = "var/lib/dpkg/alternatives/atomic.dpkg-tmp" },
        .{ .label = "selector-temporary-blocked", .blocker = "etc/alternatives/atomic.dpkg-tmp" },
        .{ .label = "generic-temporary-blocked", .blocker = "usr/bin/atomic.dpkg-tmp" },
    }) |item| {
        const root = try std.fs.path.join(ctx.allocator, &.{ directory, item.label });
        try ctx.makeRoot(root, architecture, false);
        try writeTarget(ctx.allocator, ctx.io, root, "/usr/lib/atomic-provider", "provider\n");
        const blocker_path = try std.fs.path.join(ctx.allocator, &.{ root, item.blocker });
        try std.Io.Dir.cwd().createDirPath(ctx.io, blocker_path);
        const result = try runUpdate(
            ctx.allocator,
            ctx.io,
            executable,
            root,
            &.{ "--install", "/usr/bin/atomic", "atomic", "/usr/lib/atomic-provider", "10" },
            environment,
            try std.fs.path.join(ctx.allocator, &.{ directory, try std.fmt.allocPrint(ctx.allocator, "{s}.log", .{item.label}) }),
            .{ .workspace = workspace, .preflight = false },
        );
        var obj: std.json.ObjectMap = .empty;
        try obj.put(ctx.allocator, "blocker", try optionalPathFact(ctx.allocator, ctx.io, blocker_path));
        try obj.put(ctx.allocator, "case", .{ .string = item.label });
        try obj.put(ctx.allocator, "result", result);
        try obj.put(ctx.allocator, "state", try groupState(ctx.allocator, ctx.io, root, "atomic", &.{"/usr/bin/atomic"}));
        try results.append(.{ .object = obj });
    }
    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "failure_injection", .{ .array = results });
    return .{ .object = out };
}

pub const Deb822Record = std.StringArrayHashMapUnmanaged([]const u8);

pub fn parseDeb822(
    allocator: std.mem.Allocator,
    data: []const u8,
    label: []const u8,
) ![]Deb822Record {
    if (data.len > Limits.maximum_status_bytes) {
        return fail("database text exceeds limit: {s}", .{label});
    }
    if (!std.unicode.utf8ValidateSlice(data)) {
        return fail("database text is not UTF-8: {s}", .{label});
    }
    var records: std.ArrayList(Deb822Record) = .empty;
    var paragraphs = std.mem.splitSequence(u8, data, "\n\n");
    while (paragraphs.next()) |paragraph| {
        if (paragraph.len == 0) continue;
        var record: Deb822Record = .empty;
        var current_key: ?[]const u8 = null;
        var lines = std.mem.splitScalar(u8, paragraph, '\n');
        while (lines.next()) |raw_line| {
            const line = if (std.mem.endsWith(u8, raw_line, "\r")) raw_line[0 .. raw_line.len - 1] else raw_line;
            if (line.len == 0) continue;
            if (line[0] == ' ' or line[0] == '\t') {
                const key = current_key orelse return fail("orphan continuation in {s}", .{label});
                const prev = record.get(key).?;
                try record.put(allocator, key, try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ prev, line }));
                continue;
            }
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse {
                return fail("malformed database field in {s}", .{label});
            };
            const name = line[0..colon];
            if (name.len == 0 or record.contains(name)) {
                return fail("malformed database field in {s}", .{label});
            }
            const value = std.mem.trimStart(u8, line[colon + 1 ..], " ");
            current_key = name;
            try record.put(allocator, name, try allocator.dupe(u8, value));
        }
        if (record.count() != 0) {
            try records.append(allocator, record);
        }
    }
    return records.toOwnedSlice(allocator);
}

pub fn packageRecord(
    allocator: std.mem.Allocator,
    data: []const u8,
    package: []const u8,
    label: []const u8,
) !?Deb822Record {
    const records = try parseDeb822(allocator, data, label);
    var selected: ?Deb822Record = null;
    for (records) |rec| {
        if (rec.get("Package")) |pkg| {
            if (std.mem.eql(u8, pkg, package)) {
                if (selected != null) return fail("duplicate package record in {s}", .{label});
                selected = rec;
            }
        }
    }
    return selected;
}

pub fn summarizeRecord(allocator: std.mem.Allocator, record: ?Deb822Record) !std.json.Value {
    const rec = record orelse return .null;
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "architecture", .{ .string = rec.get("Architecture") orelse return fail("missing Architecture", .{}) });
    try obj.put(allocator, "description", .{ .string = rec.get("Description") orelse return fail("missing Description", .{}) });
    try obj.put(allocator, "maintainer", .{ .string = rec.get("Maintainer") orelse return fail("missing Maintainer", .{}) });
    try obj.put(allocator, "status", .{ .string = rec.get("Status") orelse return fail("missing Status", .{}) });
    try obj.put(allocator, "version", .{ .string = rec.get("Version") orelse return fail("missing Version", .{}) });
    if (rec.get("Config-Version")) |cv| {
        try obj.put(allocator, "config_version", .{ .string = cv });
    }
    return .{ .object = obj };
}

pub fn databaseState(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    package: []const u8,
) !std.json.Value {
    const status_path = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg/status" });
    const status_bytes = try readRegular(allocator, io, status_path, Limits.maximum_status_bytes);
    const committed = try packageRecord(allocator, status_bytes, package, "status");

    const updates_dir = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg/updates" });
    const entries = try boundedScandir(allocator, io, updates_dir, Limits.maximum_updates);
    var numeric: std.ArrayList(Deb822Record) = .empty;
    var temporary = false;
    for (entries) |entry_name| {
        const entry_path = try std.fs.path.join(allocator, &.{ updates_dir, entry_name });
        const meta = try lstatPath(allocator, entry_path);
        if ((meta.mode & linux.S.IFMT) != linux.S.IFREG) {
            return fail("dpkg update entry is not regular: {s}", .{entry_name});
        }
        if (std.mem.eql(u8, entry_name, "tmp.i")) {
            _ = try readRegular(allocator, io, entry_path, Limits.maximum_status_bytes);
            temporary = true;
        } else if (isUpdateName(entry_name)) {
            const bytes = try readRegular(allocator, io, entry_path, Limits.maximum_status_bytes);
            const rec = try packageRecord(
                allocator,
                bytes,
                package,
                try std.fmt.allocPrint(allocator, "updates/{s}", .{entry_name}),
            );
            if (rec) |r| try numeric.append(allocator, r);
        } else {
            return fail("unexpected dpkg update entry: {s}", .{entry_name});
        }
    }
    const latest = if (numeric.items.len != 0) numeric.items[numeric.items.len - 1] else null;
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "committed", try summarizeRecord(allocator, committed));
    try obj.put(allocator, "journal_latest", try summarizeRecord(allocator, latest));
    try obj.put(allocator, "journal_nonempty", .{ .bool = numeric.items.len != 0 });
    try obj.put(allocator, "temporary_update", .{ .bool = temporary });
    return .{ .object = obj };
}

pub fn prepareDpkgRoot(
    ctx: Context,
    root: []const u8,
    architecture: []const u8,
    update_alternatives: []const u8,
) !void {
    try ctx.makeRoot(root, architecture, true);
    try ctx.copyProgram(root, update_alternatives, "/usr/bin/update-alternatives");
    const copied = try std.fs.path.join(ctx.allocator, &.{ root, "usr/bin/update-alternatives" });
    try ctx.verifyReference(copied, architecture, "update-alternatives");
    try writeRegular(
        ctx.allocator,
        ctx.io,
        try std.fs.path.join(ctx.allocator, &.{ root, trace_relative }),
        "",
        0o644,
    );
}

pub fn packageInfo(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    package: []const u8,
) !std.json.Value {
    const info_dir = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg/info" });
    const entries = try boundedScandir(allocator, io, info_dir, Limits.maximum_info_files + 1);
    const prefix = try std.fmt.allocPrint(allocator, "{s}.", .{package});
    var selected: std.json.Array = .init(allocator);
    var total: usize = 0;
    for (entries) |entry_name| {
        if (!std.mem.startsWith(u8, entry_name, prefix)) continue;
        const entry_path = try std.fs.path.join(allocator, &.{ info_dir, entry_name });
        var fact = try regularFact(allocator, io, entry_path, Limits.maximum_record_bytes);
        const sz: usize = @intCast(fact.object.get("size").?.integer);
        total += sz;
        if (total > Limits.maximum_info_bytes) {
            return fail("package info bytes exceed their aggregate limit", .{});
        }
        try fact.object.put(allocator, "name", .{ .string = try allocator.dupe(u8, entry_name[prefix.len..]) });
        try selected.append(fact);
    }
    if (selected.items.len > Limits.maximum_info_files) {
        return fail("package info count exceeds its limit", .{});
    }
    return .{ .array = selected };
}

pub fn traceLines(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
) !std.json.Value {
    const trace_path = try std.fs.path.join(allocator, &.{ root, trace_relative });
    const data = try readRegular(allocator, io, trace_path, Limits.maximum_output_bytes);
    if (!std.unicode.utf8ValidateSlice(data)) {
        return fail("maintainer-script trace is not UTF-8", .{});
    }
    const trimmed = if (std.mem.endsWith(u8, data, "\n")) data[0 .. data.len - 1] else data;
    var records: std.json.Array = .init(allocator);
    if (trimmed.len != 0) {
        var lines = std.mem.splitScalar(u8, trimmed, '\n');
        var line_count: usize = 0;
        while (lines.next()) |line| {
            line_count += 1;
            if (line_count > 128) {
                return fail("maintainer-script trace exceeds its record limit", .{});
            }
            var fields_list: std.ArrayList([]const u8) = .empty;
            var f_it = std.mem.splitScalar(u8, line, '\t');
            while (f_it.next()) |f| try fields_list.append(allocator, f);
            const fields = fields_list.items;
            if (fields.len < 4) return fail("malformed alternatives script trace", .{});
            const count = std.fmt.parseInt(usize, fields[1], 10) catch {
                return fail("invalid alternatives script argument count", .{});
            };
            if (count > Limits.maximum_arguments or fields.len != count + 4) {
                return fail("alternatives script argument bounds changed", .{});
            }
            var arguments: std.json.Array = .init(allocator);
            for (fields[2 .. 2 + count]) |field| {
                const colon = std.mem.indexOfScalar(u8, field, ':') orelse {
                    return fail("malformed alternatives script argument", .{});
                };
                const len_str = field[0..colon];
                const val_str = field[colon + 1 ..];
                if (len_str.len == 0) return fail("malformed alternatives script argument", .{});
                for (len_str) |ch| if (!std.ascii.isDigit(ch)) return fail("malformed alternatives script argument", .{});
                const expected_len = std.fmt.parseInt(usize, len_str, 10) catch return fail("malformed alternatives script argument", .{});
                if (expected_len != val_str.len or val_str.len > Limits.maximum_argument_bytes) {
                    return fail("malformed alternatives script argument", .{});
                }
                try arguments.append(.{ .string = try allocator.dupe(u8, val_str) });
            }
            if (!std.mem.eql(u8, fields[2 + count], "cwd=/") or
                !std.mem.eql(u8, fields[3 + count], "fds=0,1,2"))
            {
                return fail("alternatives script cwd/fd contract changed", .{});
            }
            var rec_obj: std.json.ObjectMap = .empty;
            try rec_obj.put(allocator, "arguments", .{ .array = arguments });
            try rec_obj.put(allocator, "script", .{ .string = try allocator.dupe(u8, fields[0]) });
            try records.append(.{ .object = rec_obj });
        }
    }
    const fd_err_path = try std.fs.path.join(allocator, &.{ root, fd_errors_relative });
    if (try optionalRegular(allocator, io, fd_err_path, Limits.maximum_output_bytes)) |errs| {
        allocator.free(errs);
    }
    return .{ .array = records };
}

pub fn boundedTreeFacts(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    bases: []const []const u8,
    maximum_files: usize,
    maximum_bytes: usize,
    excluded: []const []const u8,
) !std.json.Value {
    var selected: std.json.Array = .init(allocator);
    var total_bytes: usize = 0;
    var visited: usize = 0;

    const Visitor = struct {
        alloc: std.mem.Allocator,
        io_ctx: std.Io,
        root_dir: []const u8,
        max_files: usize,
        max_bytes: usize,
        excl: []const []const u8,
        sel: *std.json.Array,
        tot: *usize,
        vis: *usize,

        fn visit(self: *@This(), directory: []const u8, rel_prefix: []const u8) anyerror!void {
            if (self.vis.* > self.max_files) {
                return fail("directory entry count exceeds its limit: {s}", .{directory});
            }
            const entries = try boundedScandir(self.alloc, self.io_ctx, directory, self.max_files - self.vis.*);
            for (entries) |entry_name| {
                self.vis.* += 1;
                const item_path = try std.fs.path.join(self.alloc, &.{ directory, entry_name });
                const relative = try std.fmt.allocPrint(self.alloc, "{s}/{s}", .{ rel_prefix, entry_name });
                var skip = false;
                for (self.excl) |prefix| {
                    if (std.mem.eql(u8, relative, prefix) or
                        (std.mem.startsWith(u8, relative, prefix) and relative.len > prefix.len and relative[prefix.len] == '/'))
                    {
                        skip = true;
                        break;
                    }
                }
                if (skip) continue;
                const meta = try lstatPath(self.alloc, item_path);
                if ((meta.mode & linux.S.IFMT) == linux.S.IFDIR) {
                    try self.visit(item_path, relative);
                    continue;
                }
                const fact = try optionalPathFact(self.alloc, self.io_ctx, item_path);
                if (fact == .null) {
                    return fail("observed fixture file disappeared: {s}", .{item_path});
                }
                if (std.mem.eql(u8, fact.object.get("kind").?.string, "regular")) {
                    self.tot.* += @intCast(fact.object.get("size").?.integer);
                }
                if (self.tot.* > self.max_bytes) {
                    return fail("observed fixture tree exceeds its byte limit", .{});
                }
                var obs_obj: std.json.ObjectMap = .empty;
                try obs_obj.put(self.alloc, "fact", fact);
                try obs_obj.put(self.alloc, "path", .{ .string = relative });
                try self.sel.append(.{ .object = obs_obj });
                if (self.sel.items.len > self.max_files) {
                    return fail("observed fixture tree exceeds its file limit", .{});
                }
            }
        }
    };

    var visitor: Visitor = .{
        .alloc = allocator,
        .io_ctx = io,
        .root_dir = root,
        .max_files = maximum_files,
        .max_bytes = maximum_bytes,
        .excl = excluded,
        .sel = &selected,
        .tot = &total_bytes,
        .vis = &visited,
    };

    for (bases) |base| {
        const path = try std.fs.path.join(allocator, &.{ root, base });
        const meta = lstatPath(allocator, path) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        if ((meta.mode & linux.S.IFMT) != linux.S.IFDIR) {
            return fail("observed fixture tree is not a real directory: {s}", .{path});
        }
        try visitor.visit(path, base);
    }
    return .{ .array = selected };
}

pub fn databaseFiles(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !std.json.Value {
    return boundedTreeFacts(
        allocator,
        io,
        root,
        &.{"var/lib/dpkg"},
        Limits.maximum_database_files,
        Limits.maximum_database_bytes,
        &.{ "var/lib/dpkg/alternatives", "var/lib/dpkg/info" },
    );
}

pub fn allInfoFiles(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !std.json.Value {
    return boundedTreeFacts(
        allocator,
        io,
        root,
        &.{"var/lib/dpkg/info"},
        Limits.maximum_database_files,
        Limits.maximum_info_bytes,
        &.{},
    );
}

pub fn payloadFiles(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !std.json.Value {
    return boundedTreeFacts(
        allocator,
        io,
        root,
        &.{ "usr/lib/debz-alternatives", "usr/share/man/man1" },
        Limits.maximum_payload_files,
        Limits.maximum_payload_bytes,
        &.{},
    );
}

pub fn dpkgState(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    package: []const u8,
    group: []const u8,
) !std.json.Value {
    const generic_paths = [_][]const u8{
        try std.fmt.allocPrint(allocator, "/usr/bin/{s}", .{group}),
        try std.fmt.allocPrint(allocator, "/usr/share/man/man1/{s}.1", .{group}),
    };
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "all_info", try allInfoFiles(allocator, io, root));
    try obj.put(allocator, "alternatives", try groupState(allocator, io, root, group, &generic_paths));
    try obj.put(allocator, "database", try databaseState(allocator, io, root, package));
    try obj.put(allocator, "database_files", try databaseFiles(allocator, io, root));
    try obj.put(allocator, "info", try packageInfo(allocator, io, root, package));
    try obj.put(allocator, "payload", try payloadFiles(allocator, io, root));
    try obj.put(allocator, "trace", try traceLines(allocator, io, root));
    return .{ .object = obj };
}

pub fn runDpkg(
    ctx: Context,
    executable: []const u8,
    root: []const u8,
    arguments: []const []const u8,
    environment: []const EnvPair,
    output_path: []const u8,
    workspace: []const u8,
) !std.json.Value {
    try validateRoot(ctx.allocator, ctx.io, root);
    if (arguments.len > Limits.maximum_arguments) {
        return fail("dpkg argument count exceeds its limit", .{});
    }
    for (arguments) |argument| {
        if (std.mem.indexOfScalar(u8, argument, 0) != null or argument.len > Limits.maximum_argument_bytes) {
            return fail("dpkg argument exceeds its byte limit", .{});
        }
    }
    const command = try ctx.directDpkgCommand(executable, root, arguments);
    const dpkg_log_path = try std.fs.path.join(ctx.allocator, &.{ root, dpkg_log_relative });
    const log_before = (try optionalRegular(ctx.allocator, ctx.io, dpkg_log_path, Limits.maximum_log_bytes)) orelse "";
    const started = currentRealtimeNanoseconds();
    const returncode = try runBoundedProcess(
        ctx.allocator,
        ctx.io,
        command,
        environment,
        output_path,
        Limits.subprocess_timeout_seconds,
    );
    const ended = currentRealtimeNanoseconds();
    const data = try readRegular(ctx.allocator, ctx.io, output_path, Limits.maximum_output_bytes);
    if (returncode != 0 and returncode != 1) {
        return fail("direct dpkg exited unexpectedly: {d}; {s}", .{ returncode, output_path });
    }
    const log_bytes = try logDelta(ctx.allocator, ctx.io, dpkg_log_path, log_before, Limits.maximum_log_bytes);
    try validateLogClocks(log_bytes, false, started, ended, "dpkg");

    var obj: std.json.ObjectMap = .empty;
    try obj.put(ctx.allocator, "command", try normalizeCommand(ctx.allocator, command, workspace, executable, "dpkg"));
    try obj.put(ctx.allocator, "exit", .{ .integer = returncode });
    try obj.put(ctx.allocator, "log", .{ .string = try normalizeDpkgLog(ctx.allocator, log_bytes, workspace) });
    try obj.put(ctx.allocator, "output", .{ .string = try normalizeOutput(ctx.allocator, data, workspace) });
    return .{ .object = obj };
}

pub fn setMarker(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    relative: []const u8,
    value: ?[]const u8,
) !void {
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    if (value) |val| {
        try writeRegular(
            allocator,
            io,
            path,
            try std.fmt.allocPrint(allocator, "{s}\n", .{val}),
            0o600,
        );
    } else if (try lexistsPath(allocator, path)) {
        const path_z = try dupeZ(allocator, path);
        _ = linux.unlinkat(linux.AT.FDCWD, path_z.ptr, 0);
    }
}

pub fn archiveFact(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Value {
    const data = try readRegular(allocator, io, path, Limits.maximum_archive_bytes);
    defer allocator.free(data);
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "sha256", .{ .string = try sha256HexAlloc(allocator, data) });
    try obj.put(allocator, "size", .{ .integer = @intCast(data.len) });
    return .{ .object = obj };
}

pub fn observeSuccessfulDpkg(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    dpkg: []const u8,
    update_alternatives: []const u8,
) !std.json.Value {
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "dpkg-success" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
    const pkg_dir = try std.fs.path.join(ctx.allocator, &.{ directory, "packages" });
    const package = "debz-alt-lifecycle";
    const group = "debz-alt-lifecycle";
    const arch_1 = try makePackage(ctx.allocator, ctx.io, pkg_dir, architecture, package, "1", group, 10, true);
    const arch_2 = try makePackage(ctx.allocator, ctx.io, pkg_dir, architecture, package, "2", group, 20, true);

    const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
    try prepareDpkgRoot(ctx, root, architecture, update_alternatives);

    const PhaseSpec = struct { label: []const u8, args: []const []const u8 };
    const specs = [_]PhaseSpec{
        .{ .label = "install", .args = &.{ "--install", arch_1 } },
        .{ .label = "reinstall", .args = &.{ "--install", arch_1 } },
        .{ .label = "upgrade", .args = &.{ "--install", arch_2 } },
        .{ .label = "remove", .args = &.{ "--remove", package } },
        .{ .label = "purge", .args = &.{ "--purge", package } },
    };

    var phases: std.json.Array = .init(ctx.allocator);
    for (specs) |spec| {
        const result = try runDpkg(
            ctx,
            dpkg,
            root,
            spec.args,
            environment,
            try std.fs.path.join(ctx.allocator, &.{ directory, try std.fmt.allocPrint(ctx.allocator, "{s}.log", .{spec.label}) }),
            workspace,
        );
        if (result.object.get("exit").?.integer != 0) {
            return fail("successful alternatives lifecycle failed: {s}", .{spec.label});
        }
        var phase_obj: std.json.ObjectMap = .empty;
        try phase_obj.put(ctx.allocator, "operation", .{ .string = spec.label });
        try phase_obj.put(ctx.allocator, "result", result);
        try phase_obj.put(ctx.allocator, "state", try dpkgState(ctx.allocator, ctx.io, root, package, group));
        try phases.append(.{ .object = phase_obj });
    }

    var archives_obj: std.json.ObjectMap = .empty;
    try archives_obj.put(ctx.allocator, "1", try archiveFact(ctx.allocator, ctx.io, arch_1));
    try archives_obj.put(ctx.allocator, "2", try archiveFact(ctx.allocator, ctx.io, arch_2));

    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "archives", .{ .object = archives_obj });
    try out.put(ctx.allocator, "phases", .{ .array = phases });
    return .{ .object = out };
}

pub fn observeScriptlessMember(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    dpkg: []const u8,
    update_alternatives: []const u8,
) !std.json.Value {
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "dpkg-scriptless" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
    const package = "debz-alt-metadata";
    const group = "debz-alt-metadata";
    const archive = try makePackage(
        ctx.allocator,
        ctx.io,
        try std.fs.path.join(ctx.allocator, &.{ directory, "packages" }),
        architecture,
        package,
        "1",
        group,
        10,
        false,
    );
    const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
    try prepareDpkgRoot(ctx, root, architecture, update_alternatives);

    const install_result = try runDpkg(
        ctx,
        dpkg,
        root,
        &.{ "--install", archive },
        environment,
        try std.fs.path.join(ctx.allocator, &.{ directory, "install.log" }),
        workspace,
    );
    if (install_result.object.get("exit").?.integer != 0) {
        return fail("scriptless alternatives-member install failed", .{});
    }
    const installed = try dpkgState(ctx.allocator, ctx.io, root, package, group);
    if (installed.object.get("alternatives").?.object.get("record").? != .null) {
        return fail("direct dpkg interpreted a scriptless alternatives member", .{});
    }

    const remove_result = try runDpkg(
        ctx,
        dpkg,
        root,
        &.{ "--remove", package },
        environment,
        try std.fs.path.join(ctx.allocator, &.{ directory, "remove.log" }),
        workspace,
    );
    if (remove_result.object.get("exit").?.integer != 0) {
        return fail("scriptless alternatives-member removal failed", .{});
    }
    const removed = try dpkgState(ctx.allocator, ctx.io, root, package, group);

    const purge_result = try runDpkg(
        ctx,
        dpkg,
        root,
        &.{ "--purge", package },
        environment,
        try std.fs.path.join(ctx.allocator, &.{ directory, "purge.log" }),
        workspace,
    );
    if (purge_result.object.get("exit").?.integer != 0) {
        return fail("scriptless alternatives-member purge failed", .{});
    }
    const purged = try dpkgState(ctx.allocator, ctx.io, root, package, group);

    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "archive", try archiveFact(ctx.allocator, ctx.io, archive));
    try out.put(ctx.allocator, "install_result", install_result);
    try out.put(ctx.allocator, "installed", installed);
    try out.put(ctx.allocator, "purge_result", purge_result);
    try out.put(ctx.allocator, "purged", purged);
    try out.put(ctx.allocator, "remove_result", remove_result);
    try out.put(ctx.allocator, "removed", removed);
    return .{ .object = out };
}

pub fn observeConflictingProviders(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    dpkg: []const u8,
    update_alternatives: []const u8,
) !std.json.Value {
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "dpkg-providers" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
    const group = "debz-alt-provider";
    const pkg_a = "debz-alt-provider-a";
    const pkg_b = "debz-alt-provider-b";
    const pkg_dir = try std.fs.path.join(ctx.allocator, &.{ directory, "packages" });
    const arch_a = try makePackage(ctx.allocator, ctx.io, pkg_dir, architecture, pkg_a, "1", group, 10, true);
    const arch_b = try makePackage(ctx.allocator, ctx.io, pkg_dir, architecture, pkg_b, "1", group, 20, true);

    const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
    try prepareDpkgRoot(ctx, root, architecture, update_alternatives);

    const PhaseSpec = struct { label: []const u8, args: []const []const u8, pkg: []const u8 };
    const specs = [_]PhaseSpec{
        .{ .label = "install-a", .args = &.{ "--install", arch_a }, .pkg = pkg_a },
        .{ .label = "install-b", .args = &.{ "--install", arch_b }, .pkg = pkg_b },
        .{ .label = "remove-b", .args = &.{ "--remove", pkg_b }, .pkg = pkg_b },
        .{ .label = "purge-a", .args = &.{ "--purge", pkg_a }, .pkg = pkg_a },
    };

    var phases: std.json.Array = .init(ctx.allocator);
    const generic_paths = [_][]const u8{
        "/usr/bin/debz-alt-provider",
        "/usr/share/man/man1/debz-alt-provider.1",
    };
    for (specs) |spec| {
        const result = try runDpkg(
            ctx,
            dpkg,
            root,
            spec.args,
            environment,
            try std.fs.path.join(ctx.allocator, &.{ directory, try std.fmt.allocPrint(ctx.allocator, "{s}.log", .{spec.label}) }),
            workspace,
        );
        if (result.object.get("exit").?.integer != 0) {
            return fail("conflicting-provider lifecycle failed: {s}", .{spec.label});
        }
        var phase_obj: std.json.ObjectMap = .empty;
        try phase_obj.put(ctx.allocator, "all_info", try allInfoFiles(ctx.allocator, ctx.io, root));
        try phase_obj.put(ctx.allocator, "alternatives", try groupState(ctx.allocator, ctx.io, root, group, &generic_paths));
        try phase_obj.put(ctx.allocator, "database_files", try databaseFiles(ctx.allocator, ctx.io, root));
        try phase_obj.put(ctx.allocator, "info", try packageInfo(ctx.allocator, ctx.io, root, spec.pkg));
        try phase_obj.put(ctx.allocator, "operation", .{ .string = spec.label });
        try phase_obj.put(ctx.allocator, "package", try databaseState(ctx.allocator, ctx.io, root, spec.pkg));
        try phase_obj.put(ctx.allocator, "payload", try payloadFiles(ctx.allocator, ctx.io, root));
        try phase_obj.put(ctx.allocator, "result", result);
        try phase_obj.put(ctx.allocator, "trace", try traceLines(ctx.allocator, ctx.io, root));
        try phases.append(.{ .object = phase_obj });
    }

    var archives_obj: std.json.ObjectMap = .empty;
    try archives_obj.put(ctx.allocator, pkg_a, try archiveFact(ctx.allocator, ctx.io, arch_a));
    try archives_obj.put(ctx.allocator, pkg_b, try archiveFact(ctx.allocator, ctx.io, arch_b));

    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "archives", .{ .object = archives_obj });
    try out.put(ctx.allocator, "phases", .{ .array = phases });
    return .{ .object = out };
}

pub fn observeConflictingPackages(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    dpkg: []const u8,
    update_alternatives: []const u8,
) !std.json.Value {
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "dpkg-package-conflict" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
    const shared = "usr/lib/debz-alternatives/package-conflict";
    const pkg_dir = try std.fs.path.join(ctx.allocator, &.{ directory, "packages" });

    const first_name = "debz-alt-conflict-a";
    const second_name = "debz-alt-conflict-b";
    const first = try makeMaterializationPackage(ctx.allocator, ctx.io, pkg_dir, architecture, "1", .{
        .package = first_name,
        .extra_files = &.{.{ .relative = shared, .content = "first owner\n" }},
        .alternatives_body = "opaque conflict metadata\n",
        .alternatives_mode = 0o644,
    });
    const second = try makeMaterializationPackage(ctx.allocator, ctx.io, pkg_dir, architecture, "1", .{
        .package = second_name,
        .extra_files = &.{.{ .relative = shared, .content = "second owner\n" }},
        .alternatives_body = "opaque conflict metadata\n",
        .alternatives_mode = 0o644,
    });

    const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
    try prepareDpkgRoot(ctx, root, architecture, update_alternatives);

    const first_result = try runDpkg(
        ctx,
        dpkg,
        root,
        &.{ "--install", first },
        environment,
        try std.fs.path.join(ctx.allocator, &.{ directory, "first.log" }),
        workspace,
    );
    if (first_result.object.get("exit").?.integer != 0) {
        return fail("failed to seed package file-conflict case", .{});
    }
    const second_result = try runDpkg(
        ctx,
        dpkg,
        root,
        &.{ "--install", second },
        environment,
        try std.fs.path.join(ctx.allocator, &.{ directory, "second.log" }),
        workspace,
    );
    if (second_result.object.get("exit").?.integer != 1) {
        return fail("conflicting package payload did not fail", .{});
    }

    const shared_path = try std.fs.path.join(ctx.allocator, &.{ root, shared });
    var shared_fact = try regularFact(ctx.allocator, ctx.io, shared_path, Limits.maximum_record_bytes);
    const decoded = try base64DecodeAlloc(ctx.allocator, shared_fact.object.get("bytes_base64").?.string);
    if (!std.mem.eql(u8, decoded, "first owner\n")) {
        return fail("package conflict replaced the first owner's bytes", .{});
    }
    try shared_fact.object.put(ctx.allocator, "kind", .{ .string = "regular" });

    const status_bytes = try readRegular(
        ctx.allocator,
        ctx.io,
        try std.fs.path.join(ctx.allocator, &.{ root, "var/lib/dpkg/status" }),
        Limits.maximum_status_bytes,
    );
    const second_rec_opt = try packageRecord(ctx.allocator, status_bytes, second_name, "status");
    var second_status: std.json.Value = .null;
    if (second_rec_opt) |rec| {
        var rec_obj: std.json.ObjectMap = .empty;
        var it = rec.iterator();
        while (it.next()) |entry| {
            try rec_obj.put(ctx.allocator, entry.key_ptr.*, .{ .string = entry.value_ptr.* });
        }
        second_status = .{ .object = rec_obj };
    }

    var shared_file_obj: std.json.ObjectMap = .empty;
    try shared_file_obj.put(ctx.allocator, "fact", shared_fact);
    try shared_file_obj.put(ctx.allocator, "path", .{ .string = shared });

    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "all_info", try allInfoFiles(ctx.allocator, ctx.io, root));
    try out.put(ctx.allocator, "database_files", try databaseFiles(ctx.allocator, ctx.io, root));
    try out.put(ctx.allocator, "first_archive", try archiveFact(ctx.allocator, ctx.io, first));
    try out.put(ctx.allocator, "first_result", first_result);
    try out.put(ctx.allocator, "first_state", try databaseState(ctx.allocator, ctx.io, root, first_name));
    try out.put(ctx.allocator, "payload", try payloadFiles(ctx.allocator, ctx.io, root));
    try out.put(ctx.allocator, "second_archive", try archiveFact(ctx.allocator, ctx.io, second));
    try out.put(ctx.allocator, "second_result", second_result);
    try out.put(ctx.allocator, "second_status", second_status);
    try out.put(ctx.allocator, "shared_file", .{ .object = shared_file_obj });
    return .{ .object = out };
}

pub fn failureCase(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    dpkg: []const u8,
    update_alternatives: []const u8,
    case: []const u8,
) !std.json.Value {
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "dpkg-failures", case });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
    const package = try std.fmt.allocPrint(ctx.allocator, "debz-alt-{s}", .{case});
    const group = package;
    const pkg_dir = try std.fs.path.join(ctx.allocator, &.{ directory, "packages" });
    const arch_1 = try makePackage(ctx.allocator, ctx.io, pkg_dir, architecture, package, "1", group, 10, true);
    const arch_2 = try makePackage(ctx.allocator, ctx.io, pkg_dir, architecture, package, "2", group, 20, true);

    const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
    try prepareDpkgRoot(ctx, root, architecture, update_alternatives);

    var seed_result: std.json.Value = .null;
    if (!std.mem.eql(u8, case, "fresh-postinst")) {
        seed_result = try runDpkg(
            ctx,
            dpkg,
            root,
            &.{ "--install", arch_1 },
            environment,
            try std.fs.path.join(ctx.allocator, &.{ directory, "seed.log" }),
            workspace,
        );
        if (seed_result.object.get("exit").?.integer != 0) {
            return fail("failed to seed alternatives failure case: {s}", .{case});
        }
        try writeRegular(
            ctx.allocator,
            ctx.io,
            try std.fs.path.join(ctx.allocator, &.{ root, trace_relative }),
            "",
            0o644,
        );
    }

    var marker: []const u8 = undefined;
    var operation: []const []const u8 = undefined;
    var recovery: []const []const u8 = undefined;
    if (std.mem.eql(u8, case, "fresh-postinst")) {
        marker = try std.fmt.allocPrint(ctx.allocator, "{s}@1:postinst:configure", .{package});
        operation = &.{ "--install", arch_1 };
        recovery = &.{ "--configure", package };
    } else if (std.mem.eql(u8, case, "upgrade-prerm")) {
        marker = try std.fmt.allocPrint(ctx.allocator, "{s}@1:prerm:upgrade", .{package});
        operation = &.{ "--install", arch_2 };
        recovery = &.{ "--install", arch_2 };
    } else if (std.mem.eql(u8, case, "upgrade-postinst")) {
        marker = try std.fmt.allocPrint(ctx.allocator, "{s}@2:postinst:configure", .{package});
        operation = &.{ "--install", arch_2 };
        recovery = &.{ "--configure", package };
    } else if (std.mem.eql(u8, case, "remove-postrm")) {
        marker = try std.fmt.allocPrint(ctx.allocator, "{s}@1:postrm:remove", .{package});
        operation = &.{ "--remove", package };
        recovery = &.{ "--remove", package };
    } else {
        return fail("unknown dpkg alternatives failure case: {s}", .{case});
    }

    try setMarker(ctx.allocator, ctx.io, root, failures_relative, marker);
    const operation_result = try runDpkg(
        ctx,
        dpkg,
        root,
        operation,
        environment,
        try std.fs.path.join(ctx.allocator, &.{ directory, "failed.log" }),
        workspace,
    );
    const expected_failed_exit: i64 = if (std.mem.eql(u8, case, "upgrade-prerm")) 0 else 1;
    if (operation_result.object.get("exit").?.integer != expected_failed_exit) {
        return fail("dpkg failure case exit changed: {s}", .{case});
    }
    const failed = try dpkgState(ctx.allocator, ctx.io, root, package, group);
    try setMarker(ctx.allocator, ctx.io, root, failures_relative, null);
    const recovery_result = try runDpkg(
        ctx,
        dpkg,
        root,
        recovery,
        environment,
        try std.fs.path.join(ctx.allocator, &.{ directory, "recovery.log" }),
        workspace,
    );
    if (recovery_result.object.get("exit").?.integer != 0) {
        return fail("dpkg failure recovery did not settle: {s}", .{case});
    }
    const recovered = try dpkgState(ctx.allocator, ctx.io, root, package, group);

    var archives_obj: std.json.ObjectMap = .empty;
    try archives_obj.put(ctx.allocator, "1", try archiveFact(ctx.allocator, ctx.io, arch_1));
    try archives_obj.put(ctx.allocator, "2", try archiveFact(ctx.allocator, ctx.io, arch_2));

    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "archives", .{ .object = archives_obj });
    try out.put(ctx.allocator, "case", .{ .string = case });
    try out.put(ctx.allocator, "failed", failed);
    try out.put(ctx.allocator, "operation_result", operation_result);
    try out.put(ctx.allocator, "recovered", recovered);
    try out.put(ctx.allocator, "recovery_result", recovery_result);
    try out.put(ctx.allocator, "seed_result", seed_result);
    return .{ .object = out };
}

pub fn interruptDpkg(
    ctx: Context,
    executable: []const u8,
    root: []const u8,
    arguments: []const []const u8,
    environment: []const EnvPair,
    output_path: []const u8,
    marker: []const u8,
    workspace: []const u8,
) !std.json.Value {
    try setMarker(ctx.allocator, ctx.io, root, pause_relative, marker);
    const command = try ctx.directDpkgCommand(executable, root, arguments);
    const dpkg_log_path = try std.fs.path.join(ctx.allocator, &.{ root, dpkg_log_relative });
    const log_before = (try optionalRegular(ctx.allocator, ctx.io, dpkg_log_path, Limits.maximum_log_bytes)) orelse "";
    const started = currentRealtimeNanoseconds();
    const pid = try spawnChildProcess(ctx.allocator, ctx.io, command, environment, output_path);
    const paused_path = try std.fs.path.join(ctx.allocator, &.{ root, paused_relative });

    var status: i32 = 0;
    const deadline_ms = Limits.pause_timeout_seconds * 1000;
    var elapsed_ms: i64 = 0;
    var reached = false;
    while (elapsed_ms < deadline_ms) {
        if (try optionalRegular(ctx.allocator, ctx.io, paused_path, 256)) |bytes| {
            ctx.allocator.free(bytes);
            reached = true;
            break;
        }
        const wrc = linux.wait4(pid, &status, linux.W.NOHANG, null);
        if (linux.errno(wrc) != .INTR and !errnoFailed(wrc) and wrc != 0) {
            return fail("dpkg exited before alternatives interruption", .{});
        }
        sleepMillis(50);
        elapsed_ms += 50;
    }
    if (!reached) {
        _ = linux.kill(-pid, .KILL);
        _ = linux.wait4(pid, &status, 0, null);
        return fail("dpkg did not reach alternatives interruption", .{});
    }
    _ = linux.kill(-pid, .KILL);
    while (true) {
        const wrc = linux.wait4(pid, &status, 0, null);
        if (linux.errno(wrc) == .INTR) continue;
        if (errnoFailed(wrc)) return fail("wait4 failed after SIGKILL", .{});
        break;
    }
    const ended = currentRealtimeNanoseconds();
    const status_word: u32 = @bitCast(status);
    if (!linux.W.IFSIGNALED(status_word) or linux.W.TERMSIG(status_word) != .KILL) {
        return fail("interrupted dpkg returned unexpectedly", .{});
    }
    const data = try readRegular(ctx.allocator, ctx.io, output_path, Limits.maximum_output_bytes);
    const log_bytes = try logDelta(ctx.allocator, ctx.io, dpkg_log_path, log_before, Limits.maximum_log_bytes);
    try validateLogClocks(log_bytes, false, started, ended, "dpkg");
    try setMarker(ctx.allocator, ctx.io, root, pause_relative, null);
    const paused_z = try dupeZ(ctx.allocator, paused_path);
    _ = linux.unlinkat(linux.AT.FDCWD, paused_z.ptr, 0);

    var obj: std.json.ObjectMap = .empty;
    try obj.put(ctx.allocator, "command", try normalizeCommand(ctx.allocator, command, workspace, executable, "dpkg"));
    try obj.put(ctx.allocator, "exit", .{ .integer = -9 });
    try obj.put(ctx.allocator, "log", .{ .string = try normalizeDpkgLog(ctx.allocator, log_bytes, workspace) });
    try obj.put(ctx.allocator, "output", .{ .string = try normalizeOutput(ctx.allocator, data, workspace) });
    return .{ .object = obj };
}

pub fn observeInterruption(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    dpkg: []const u8,
    update_alternatives: []const u8,
) !std.json.Value {
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "dpkg-interruption" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
    const package = "debz-alt-interrupted";
    const group = package;
    const archive = try makePackage(
        ctx.allocator,
        ctx.io,
        try std.fs.path.join(ctx.allocator, &.{ directory, "packages" }),
        architecture,
        package,
        "1",
        group,
        10,
        true,
    );
    const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
    try prepareDpkgRoot(ctx, root, architecture, update_alternatives);

    const interruption_result = try interruptDpkg(
        ctx,
        dpkg,
        root,
        &.{ "--install", archive },
        environment,
        try std.fs.path.join(ctx.allocator, &.{ directory, "interrupted.log" }),
        try std.fmt.allocPrint(ctx.allocator, "{s}@1:postinst:configure", .{package}),
        workspace,
    );
    const interrupted = try dpkgState(ctx.allocator, ctx.io, root, package, group);
    const recovery_result = try runDpkg(
        ctx,
        dpkg,
        root,
        &.{ "--configure", package },
        environment,
        try std.fs.path.join(ctx.allocator, &.{ directory, "recovery.log" }),
        workspace,
    );
    if (recovery_result.object.get("exit").?.integer != 0) {
        return fail("interrupted alternatives package did not recover", .{});
    }

    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "archive", try archiveFact(ctx.allocator, ctx.io, archive));
    try out.put(ctx.allocator, "interrupted", interrupted);
    try out.put(ctx.allocator, "interruption_result", interruption_result);
    try out.put(ctx.allocator, "recovered", try dpkgState(ctx.allocator, ctx.io, root, package, group));
    try out.put(ctx.allocator, "recovery_result", recovery_result);
    return .{ .object = out };
}

pub fn observeDpkg(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    dpkg: []const u8,
    update_alternatives: []const u8,
) !std.json.Value {
    var failures: std.json.Array = .init(ctx.allocator);
    for ([_][]const u8{
        "fresh-postinst",
        "upgrade-prerm",
        "upgrade-postinst",
        "remove-postrm",
    }) |case| {
        try failures.append(try failureCase(ctx, workspace, environment, architecture, dpkg, update_alternatives, case));
    }

    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "conflicting_packages", try observeConflictingPackages(ctx, workspace, environment, architecture, dpkg, update_alternatives));
    try out.put(ctx.allocator, "conflicting_providers", try observeConflictingProviders(ctx, workspace, environment, architecture, dpkg, update_alternatives));
    try out.put(ctx.allocator, "failure_recovery", .{ .array = failures });
    try out.put(ctx.allocator, "interruption_recovery", try observeInterruption(ctx, workspace, environment, architecture, dpkg, update_alternatives));
    try out.put(ctx.allocator, "scriptless_alternatives_member", try observeScriptlessMember(ctx, workspace, environment, architecture, dpkg, update_alternatives));
    try out.put(ctx.allocator, "successful_lifecycle", try observeSuccessfulDpkg(ctx, workspace, environment, architecture, dpkg, update_alternatives));
    return .{ .object = out };
}

pub fn observe(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    dpkg: []const u8,
    update_alternatives: []const u8,
    derived: std.json.Value,
) !std.json.Value {
    var external: std.json.ObjectMap = .empty;
    try external.put(ctx.allocator, "atomicity", try observeAtomicity(ctx, workspace, environment, architecture, update_alternatives));
    try external.put(ctx.allocator, "malformed_records", try observeMalformed(ctx, workspace, environment, architecture, update_alternatives));
    try external.put(ctx.allocator, "missing_targets_and_group_shape", try observeMissingAndGroupShape(ctx, workspace, environment, architecture, update_alternatives));
    try external.put(ctx.allocator, "path_and_symlink_attacks", try observeAttacks(ctx, workspace, environment, architecture, update_alternatives));
    try external.put(ctx.allocator, "selection", try observeSelection(ctx, workspace, environment, architecture, update_alternatives));
    try external.put(ctx.allocator, "vendor_projection", try observeVendorProjection(ctx, workspace, environment, architecture, update_alternatives, derived));

    var separation: std.json.ObjectMap = .empty;
    try separation.put(ctx.allocator, "ambient_host_alternatives_used", .{ .bool = false });
    try separation.put(ctx.allocator, "dpkg_invokes_update_alternatives_implicitly", .{ .bool = false });
    try separation.put(ctx.allocator, "maintainer_script_updates_are_external_tool_side_effects", .{ .bool = true });
    try separation.put(ctx.allocator, "package_alternatives_member_is_copied_but_not_interpreted", .{ .bool = true });

    var out: std.json.ObjectMap = .empty;
    try out.put(ctx.allocator, "direct_dpkg", try observeDpkg(ctx, workspace, environment, architecture, dpkg, update_alternatives));
    try out.put(ctx.allocator, "external_update_alternatives", .{ .object = external });
    try out.put(ctx.allocator, "separation", .{ .object = separation });
    return .{ .object = out };
}

pub const HostPathSig = struct {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
};

pub fn hostPathSignature(allocator: std.mem.Allocator, path: []const u8) !?HostPathSig {
    const meta = lstatPath(allocator, path) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if ((meta.mode & linux.S.IFMT) != linux.S.IFREG) {
        return fail("host alternatives path is not a regular file: {s}", .{path});
    }
    return .{
        .dev = meta.dev,
        .ino = meta.ino,
        .size = meta.size,
        .mtime_sec = meta.mtime_sec,
        .mtime_nsec = meta.mtime_nsec,
        .ctime_sec = meta.ctime_sec,
        .ctime_nsec = meta.ctime_nsec,
    };
}

pub const HostTreeSig = struct {
    count: usize,
    digest: [Sha256.digest_length]u8,
};

pub fn hostTreeSignature(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !?HostTreeSig {
    const meta = lstatPath(allocator, root) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if ((meta.mode & linux.S.IFMT) != linux.S.IFDIR) {
        return fail("host isolation path is not a real directory: {s}", .{root});
    }
    var hasher = Sha256.init(.{});
    var count: usize = 0;

    const Walker = struct {
        alloc: std.mem.Allocator,
        io_ctx: std.Io,
        root_path: []const u8,
        h: *Sha256,
        cnt: *usize,

        fn visit(self: *@This(), path: []const u8, relative: []const u8) anyerror!void {
            const item = try lstatPath(self.alloc, path);
            self.cnt.* += 1;
            if (self.cnt.* > Limits.maximum_host_entries) {
                return fail("host isolation inventory exceeds its limit: {s}", .{self.root_path});
            }
            self.h.update(relative);
            self.h.update("\x00");
            const line = try std.fmt.allocPrint(
                self.alloc,
                "{d}:{d}:{d}:{d}:{d}:{d}:{d}:{d}",
                .{ item.dev, item.ino, item.mode, item.size, item.mtime_sec, item.mtime_nsec, item.ctime_sec, item.ctime_nsec },
            );
            defer self.alloc.free(line);
            self.h.update(line);
            self.h.update("\x00");
            const ftype = item.mode & linux.S.IFMT;
            if (ftype == linux.S.IFLNK) {
                const target = try readSymlinkAlloc(self.alloc, path);
                defer self.alloc.free(target);
                self.h.update(target);
            } else if (ftype == linux.S.IFDIR) {
                const entries = try boundedScandir(
                    self.alloc,
                    self.io_ctx,
                    path,
                    Limits.maximum_host_entries - self.cnt.*,
                );
                defer {
                    for (entries) |e| self.alloc.free(e);
                    self.alloc.free(entries);
                }
                for (entries) |entry_name| {
                    const child_rel = if (relative.len != 0)
                        try std.fmt.allocPrint(self.alloc, "{s}/{s}", .{ relative, entry_name })
                    else
                        try self.alloc.dupe(u8, entry_name);
                    defer self.alloc.free(child_rel);
                    const child_path = try std.fs.path.join(self.alloc, &.{ path, entry_name });
                    defer self.alloc.free(child_path);
                    try self.visit(child_path, child_rel);
                }
            }
        }
    };

    var walker: Walker = .{
        .alloc = allocator,
        .io_ctx = io,
        .root_path = root,
        .h = &hasher,
        .cnt = &count,
    };
    try walker.visit(root, "");
    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return .{ .count = count, .digest = digest };
}

pub fn hostAlternativesGenericSignature(
    allocator: std.mem.Allocator,
    io: std.Io,
) ![Sha256.digest_length]u8 {
    var hasher = Sha256.init(.{});
    const admin = "/var/lib/dpkg/alternatives";
    const entries = boundedScandir(allocator, io, admin, Limits.maximum_host_entries) catch |err| switch (err) {
        error.FileNotFound => {
            var digest: [Sha256.digest_length]u8 = undefined;
            hasher.final(&digest);
            return digest;
        },
        else => return err,
    };
    var paths: std.ArrayList([]const u8) = .empty;
    var total: usize = 0;
    for (entries) |entry_name| {
        const path = try std.fs.path.join(allocator, &.{ admin, entry_name });
        const data = try readRegular(allocator, io, path, Limits.maximum_record_bytes);
        total += data.len;
        if (total > Limits.maximum_total_record_bytes) {
            return fail("host alternatives records exceed their aggregate limit", .{});
        }
        const trimmed = if (std.mem.endsWith(u8, data, "\n")) data[0 .. data.len - 1] else data;
        var lines_list: std.ArrayList([]const u8) = .empty;
        var l_it = std.mem.splitScalar(u8, trimmed, '\n');
        while (l_it.next()) |raw_l| {
            const l = if (std.mem.endsWith(u8, raw_l, "\r")) raw_l[0 .. raw_l.len - 1] else raw_l;
            try lines_list.append(allocator, l);
        }
        const lines = lines_list.items;
        if (lines.len < 3 or (!std.mem.eql(u8, lines[0], "auto") and !std.mem.eql(u8, lines[0], "manual"))) {
            return fail("host alternatives record is malformed: {s}", .{path});
        }
        var index: usize = 1;
        try paths.append(allocator, lines[index]);
        index += 1;
        while (index < lines.len and lines[index].len != 0) {
            if (index + 1 >= lines.len) {
                return fail("host alternatives record is truncated: {s}", .{path});
            }
            index += 1;
            try paths.append(allocator, lines[index]);
            index += 1;
        }
    }
    std.sort.heap([]const u8, paths.items, {}, struct {
        fn less(_: void, left: []const u8, right: []const u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.less);
    var prev: ?[]const u8 = null;
    for (paths.items) |value| {
        if (prev != null and std.mem.eql(u8, prev.?, value)) continue;
        prev = value;
        _ = try validateAbsolutePath(value);
        hasher.update(value);
        hasher.update("\x00");
        if (lstatPath(allocator, value)) |meta| {
            const line = try std.fmt.allocPrint(
                allocator,
                "{d}:{d}:{d}:{d}:{d}:{d}:{d}:{d}",
                .{ meta.dev, meta.ino, meta.mode, meta.size, meta.mtime_sec, meta.mtime_nsec, meta.ctime_sec, meta.ctime_nsec },
            );
            defer allocator.free(line);
            hasher.update(line);
            if ((meta.mode & linux.S.IFMT) == linux.S.IFLNK) {
                const target = try readSymlinkAlloc(allocator, value);
                defer allocator.free(target);
                hasher.update(":");
                hasher.update(target);
            }
        } else |err| switch (err) {
            error.FileNotFound => hasher.update("none"),
            else => return err,
        }
        hasher.update("\x00");
    }
    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

pub const HostState = struct {
    alternatives_database: ?HostTreeSig,
    alternatives_generic_links: [Sha256.digest_length]u8,
    alternatives_links: ?HostTreeSig,
    dpkg_config: ?HostTreeSig,
    dpkg_database: ?HostTreeSig,
    alternatives_log: ?HostPathSig,
    dpkg_log: ?HostPathSig,
};

pub fn captureHostState(allocator: std.mem.Allocator, io: std.Io) !HostState {
    return .{
        .alternatives_database = try hostTreeSignature(allocator, io, "/var/lib/dpkg/alternatives"),
        .alternatives_generic_links = try hostAlternativesGenericSignature(allocator, io),
        .alternatives_links = try hostTreeSignature(allocator, io, "/etc/alternatives"),
        .dpkg_config = try hostTreeSignature(allocator, io, "/etc/dpkg"),
        .dpkg_database = try hostTreeSignature(allocator, io, "/var/lib/dpkg"),
        .alternatives_log = try hostPathSignature(allocator, "/var/log/alternatives.log"),
        .dpkg_log = try hostPathSignature(allocator, "/var/log/dpkg.log"),
    };
}

pub fn assertHostUnchanged(allocator: std.mem.Allocator, io: std.Io, expected: HostState) !void {
    const observed = try captureHostState(allocator, io);
    if (!std.meta.eql(observed.alternatives_database, expected.alternatives_database)) {
        return fail("host alternatives database changed during observation", .{});
    }
    if (!std.mem.eql(u8, &observed.alternatives_generic_links, &expected.alternatives_generic_links)) {
        return fail("host alternatives generic links changed during observation", .{});
    }
    if (!std.meta.eql(observed.alternatives_links, expected.alternatives_links)) {
        return fail("host alternatives links changed during observation", .{});
    }
    if (!std.meta.eql(observed.dpkg_config, expected.dpkg_config)) {
        return fail("host dpkg config changed during observation", .{});
    }
    if (!std.meta.eql(observed.dpkg_database, expected.dpkg_database)) {
        return fail("host dpkg database changed during observation", .{});
    }
    if (!std.meta.eql(observed.alternatives_log, expected.alternatives_log)) {
        return fail("host alternatives log changed during observation", .{});
    }
    if (!std.meta.eql(observed.dpkg_log, expected.dpkg_log)) {
        return fail("host dpkg log changed during observation", .{});
    }
}

fn writeCapture(
    ctx: Context,
    capture_path: []const u8,
    observed: std.json.Value,
) !void {
    const tmp_root = try ctx.repoPath(".tmp");
    const destination = try std.fs.path.resolve(ctx.allocator, &.{ ctx.repository, capture_path });
    const parent = std.fs.path.dirname(destination) orelse return fail("invalid capture path", .{});
    const grandparent = std.fs.path.dirname(parent) orelse return fail("invalid capture path", .{});
    if (!std.mem.eql(u8, grandparent, tmp_root)) {
        return fail("captured observation must be a file in a directory directly under .tmp", .{});
    }
    if (try lexistsPath(ctx.allocator, destination)) {
        return fail("captured observation path already exists", .{});
    }
    try std.Io.Dir.cwd().createDirPath(ctx.io, parent);
    const encoded = try canonicalJson(ctx.allocator, observed);
    try writeRegular(ctx.allocator, ctx.io, destination, encoded, 0o644);
}

fn hasLdd(allocator: std.mem.Allocator, io: std.Io, environ: std.process.Environ) bool {
    if (environ.getPosix("PATH")) |path_env| {
        var it = std.mem.splitScalar(u8, path_env, ':');
        while (it.next()) |dir| {
            if (dir.len == 0) continue;
            const candidate = std.fs.path.join(allocator, &.{ dir, "ldd" }) catch continue;
            defer allocator.free(candidate);
            std.Io.Dir.accessAbsolute(io, candidate, .{ .execute = true }) catch continue;
            return true;
        }
    }
    return false;
}

pub fn validateAgainstSchema(
    root_schema: std.json.Value,
    schema_node: std.json.Value,
    instance: std.json.Value,
) anyerror!void {
    if (schema_node == .bool) {
        if (!schema_node.bool) return error.SchemaValidationFailed;
        return;
    }
    if (schema_node != .object) return error.InvalidSchema;
    const obj = schema_node.object;

    if (obj.get("$ref")) |ref_val| {
        const ref_str = ref_val.string;
        const prefix = "#/$defs/";
        if (!std.mem.startsWith(u8, ref_str, prefix)) return error.UnsupportedSchemaRef;
        const defs = root_schema.object.get("$defs") orelse return error.MissingSchemaDefs;
        const target = defs.object.get(ref_str[prefix.len..]) orelse return error.UnknownSchemaRef;
        try validateAgainstSchema(root_schema, target, instance);
    }

    if (obj.get("oneOf")) |one_of| {
        var matches: usize = 0;
        for (one_of.array.items) |sub| {
            if (validateAgainstSchema(root_schema, sub, instance)) |_| {
                matches += 1;
            } else |_| {}
        }
        if (matches != 1) return error.SchemaOneOfFailed;
    }

    if (obj.get("const")) |const_val| {
        if (!jsonEqual(instance, const_val)) return error.SchemaConstFailed;
    }

    if (obj.get("enum")) |enum_val| {
        var matched = false;
        for (enum_val.array.items) |item| {
            if (jsonEqual(instance, item)) {
                matched = true;
                break;
            }
        }
        if (!matched) return error.SchemaEnumFailed;
    }

    if (obj.get("type")) |type_val| {
        var type_ok = false;
        if (type_val == .string) {
            type_ok = matchesJsonType(type_val.string, instance);
        } else if (type_val == .array) {
            for (type_val.array.items) |t| {
                if (matchesJsonType(t.string, instance)) {
                    type_ok = true;
                    break;
                }
            }
        }
        if (!type_ok) return error.SchemaTypeMismatch;
    }

    switch (instance) {
        .integer => |val| {
            if (obj.get("minimum")) |min_v| {
                if (val < min_v.integer) return error.SchemaMinimumFailed;
            }
            if (obj.get("maximum")) |max_v| {
                if (val > max_v.integer) return error.SchemaMaximumFailed;
            }
        },
        .string => |str| {
            if (obj.get("minLength")) |min_l| {
                if (str.len < @as(usize, @intCast(min_l.integer))) return error.SchemaMinLengthFailed;
            }
            if (obj.get("maxLength")) |max_l| {
                if (str.len > @as(usize, @intCast(max_l.integer))) return error.SchemaMaxLengthFailed;
            }
            if (obj.get("pattern")) |pat_v| {
                if (!matchesSchemaPattern(pat_v.string, str)) return error.SchemaPatternFailed;
            }
        },
        .array => |arr| {
            if (obj.get("minItems")) |min_i| {
                if (arr.items.len < @as(usize, @intCast(min_i.integer))) return error.SchemaMinItemsFailed;
            }
            if (obj.get("maxItems")) |max_i| {
                if (arr.items.len > @as(usize, @intCast(max_i.integer))) return error.SchemaMaxItemsFailed;
            }
            if (obj.get("uniqueItems")) |uniq_v| {
                if (uniq_v == .bool and uniq_v.bool) {
                    for (arr.items, 0..) |left, i| {
                        for (arr.items[i + 1 ..]) |right| {
                            if (jsonEqual(left, right)) return error.SchemaUniqueItemsFailed;
                        }
                    }
                }
            }
            var prefix_len: usize = 0;
            if (obj.get("prefixItems")) |pfx_items| {
                prefix_len = pfx_items.array.items.len;
                for (pfx_items.array.items, 0..) |sub_schema, idx| {
                    if (idx < arr.items.len) {
                        try validateAgainstSchema(root_schema, sub_schema, arr.items[idx]);
                    }
                }
            }
            if (obj.get("items")) |items_schema| {
                if (items_schema == .bool) {
                    if (!items_schema.bool and arr.items.len > prefix_len) {
                        return error.SchemaAdditionalItemsFailed;
                    }
                } else {
                    for (arr.items) |item| {
                        try validateAgainstSchema(root_schema, items_schema, item);
                    }
                }
            }
        },
        .object => |inst_obj| {
            if (obj.get("minProperties")) |min_p| {
                if (inst_obj.count() < @as(usize, @intCast(min_p.integer))) return error.SchemaMinPropertiesFailed;
            }
            if (obj.get("maxProperties")) |max_p| {
                if (inst_obj.count() > @as(usize, @intCast(max_p.integer))) return error.SchemaMaxPropertiesFailed;
            }
            if (obj.get("required")) |req_v| {
                for (req_v.array.items) |req_key| {
                    if (!inst_obj.contains(req_key.string)) return error.SchemaRequiredPropertyMissing;
                }
            }
            const prop_names = obj.get("propertyNames");
            const props = obj.get("properties");
            const addl = obj.get("additionalProperties");
            var it = inst_obj.iterator();
            while (it.next()) |entry| {
                const key = entry.key_ptr.*;
                const val = entry.value_ptr.*;
                if (prop_names) |pn_schema| {
                    try validateAgainstSchema(root_schema, pn_schema, .{ .string = key });
                }
                if (props != null and props.?.object.get(key) != null) {
                    try validateAgainstSchema(root_schema, props.?.object.get(key).?, val);
                } else if (addl) |addl_schema| {
                    if (addl_schema == .bool) {
                        if (!addl_schema.bool) return error.SchemaAdditionalPropertyForbidden;
                    } else {
                        try validateAgainstSchema(root_schema, addl_schema, val);
                    }
                }
            }
        },
        else => {},
    }
}

fn matchesJsonType(expected: []const u8, instance: std.json.Value) bool {
    if (std.mem.eql(u8, expected, "object")) return instance == .object;
    if (std.mem.eql(u8, expected, "array")) return instance == .array;
    if (std.mem.eql(u8, expected, "string")) return instance == .string;
    if (std.mem.eql(u8, expected, "integer")) return instance == .integer;
    if (std.mem.eql(u8, expected, "boolean")) return instance == .bool;
    if (std.mem.eql(u8, expected, "null")) return instance == .null;
    return false;
}

fn matchesSchemaPattern(pattern: []const u8, text: []const u8) bool {
    const hex_pattern = "^[0-9a-f]{" ++ "64}$";
    if (std.mem.eql(u8, pattern, hex_pattern)) {
        if (text.len != Sha256.digest_length * 2) return false;
        for (text) |ch| if (!std.ascii.isDigit(ch) and (ch < 'a' or ch > 'f')) return false;
        return true;
    }
    if (std.mem.eql(u8, pattern, "^[a-z0-9][a-z0-9+.-]*$")) {
        return isIdentityName(text);
    }
    if (std.mem.eql(u8, pattern, "^[0-7]{4}$")) {
        if (text.len != 4) return false;
        for (text) |ch| if (ch < '0' or ch > '7') return false;
        return true;
    }
    if (std.mem.eql(u8, pattern, "^[A-Za-z0-9+/]*={0,2}$")) {
        var eq_count: usize = 0;
        for (text) |ch| {
            if (ch == '=') {
                eq_count += 1;
                if (eq_count > 2) return false;
            } else {
                if (eq_count != 0) return false;
                if (!std.ascii.isAlphanumeric(ch) and ch != '+' and ch != '/') return false;
            }
        }
        return true;
    }
    if (std.mem.eql(u8, pattern, "^[^/\\u0000-\\u001f\\u007f]+$")) {
        if (text.len == 0) return false;
        for (text) |ch| {
            if (ch == '/' or ch <= 0x1f or ch == 0x7f) return false;
        }
        return true;
    }
    if (std.mem.eql(u8, pattern, "^/[^\\u0000-\\u001f\\u007f]+$")) {
        if (text.len < 2 or text[0] != '/') return false;
        for (text[1..]) |ch| {
            if (ch <= 0x1f or ch == 0x7f) return false;
        }
        return true;
    }
    if (std.mem.eql(u8, pattern, "^/(?:[^/\\u0000-\\u001f\\u007f]+/)*[^/\\u0000-\\u001f\\u007f]+$")) {
        if (text.len < 2 or text[0] != '/' or text[text.len - 1] == '/' or std.mem.indexOf(u8, text, "//") != null) return false;
        for (text) |ch| {
            if (ch <= 0x1f or ch == 0x7f) return false;
        }
        return true;
    }
    if (std.mem.eql(u8, pattern, "^(?!/)(?!.*(?:^|/)\\.\\.?/)(?!.*//)[^\\u0000-\\u001f\\u007f]+$")) {
        if (text.len == 0 or text[0] == '/' or std.mem.indexOf(u8, text, "//") != null) return false;
        for (text) |ch| {
            if (ch <= 0x1f or ch == 0x7f) return false;
        }
        var it = std.mem.splitScalar(u8, text, '/');
        while (it.next()) |part| {
            if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
        }
        return true;
    }
    return false;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const io = init.io;
    const repository = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    var ctx = try Context.init(allocator, io, init.minimal.environ, repository);

    var architecture: ?[]const u8 = null;
    var reference_dpkg: ?[]const u8 = null;
    var reference_update_alternatives: ?[]const u8 = null;
    var workspace_arg: ?[]const u8 = null;
    var capture_observed: ?[]const u8 = null;
    var print_observed = false;
    var update_reference = false;

    var args_it = try init.minimal.args.iterateAllocator(allocator);
    _ = args_it.next();
    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--architecture")) {
            architecture = args_it.next() orelse {
                std.debug.print("missing --architecture value\n", .{});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, arg, "--reference-dpkg")) {
            reference_dpkg = args_it.next() orelse {
                std.debug.print("missing --reference-dpkg value\n", .{});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, arg, "--reference-update-alternatives")) {
            reference_update_alternatives = args_it.next() orelse {
                std.debug.print("missing --reference-update-alternatives value\n", .{});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, arg, "--workspace")) {
            workspace_arg = args_it.next() orelse {
                std.debug.print("missing --workspace value\n", .{});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, arg, "--capture-observed")) {
            capture_observed = args_it.next() orelse {
                std.debug.print("missing --capture-observed value\n", .{});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, arg, "--print-observed")) {
            print_observed = true;
        } else if (std.mem.eql(u8, arg, "--update-reference")) {
            update_reference = true;
        } else {
            std.debug.print("unknown argument: {s}\n", .{arg});
            std.process.exit(2);
        }
    }

    const arch = architecture orelse {
        std.debug.print("--architecture is required\n", .{});
        std.process.exit(2);
    };
    if (!std.mem.eql(u8, arch, "amd64") and !std.mem.eql(u8, arch, "arm64")) {
        std.debug.print("unsupported architecture: {s}\n", .{arch});
        std.process.exit(2);
    }

    var selected_outputs: usize = 0;
    if (capture_observed != null) selected_outputs += 1;
    if (print_observed) selected_outputs += 1;
    if (update_reference) selected_outputs += 1;
    if (selected_outputs > 1) {
        std.debug.print("--capture-observed, --print-observed and --update-reference are mutually exclusive\n", .{});
        std.process.exit(2);
    }

    if (linux.geteuid() != 0) {
        return fail("dpkg alternatives reference execution requires root", .{});
    }
    if (!hasLdd(allocator, io, init.minimal.environ)) {
        return fail("required reference tool is missing: ldd", .{});
    }

    var reference = try ctx.loadReference();
    const derived = try ctx.verifySourceBindings(reference);
    var expected_observation: ?std.json.Value = null;
    if (capture_observed == null) {
        expected_observation = try publishedObservation(allocator, reference, arch);
    }
    if (update_reference and !std.mem.eql(u8, arch, "amd64")) {
        return fail("only the amd64 baseline observation can be regenerated", .{});
    }
    const refs = try ctx.selectReferences(reference_dpkg, reference_update_alternatives, arch);
    ctx.reference_dpkg = refs.dpkg;

    const base_env = try baseEnvironment(allocator);
    try validateEnvironment(base_env);

    const temporary_root = try ctx.repoPath(".tmp");
    try std.Io.Dir.cwd().createDirPath(io, temporary_root);
    var cleanup_workspace = false;
    const workspace = if (workspace_arg) |ws_arg| blk: {
        const resolved = try std.fs.path.resolve(allocator, &.{ repository, ws_arg });
        const parent = std.fs.path.dirname(resolved) orelse "";
        if (!std.mem.eql(u8, parent, temporary_root)) {
            std.debug.print("--workspace must name a new directory directly under .tmp\n", .{});
            std.process.exit(2);
        }
        const ws_z = try dupeZ(allocator, resolved);
        if (errnoFailed(linux.mkdirat(linux.AT.FDCWD, ws_z.ptr, 0o700))) {
            return fail("cannot create workspace directory: {s}", .{resolved});
        }
        break :blk resolved;
    } else blk: {
        var rand_bytes: [8]u8 = undefined;
        try io.randomSecure(&rand_bytes);
        const hex = std.fmt.bytesToHex(rand_bytes, .lower);
        const ws = try std.fs.path.join(
            allocator,
            &.{ temporary_root, try std.fmt.allocPrint(allocator, "dpkg-alternatives-reference-{s}", .{hex}) },
        );
        const ws_z = try dupeZ(allocator, ws);
        if (errnoFailed(linux.mkdirat(linux.AT.FDCWD, ws_z.ptr, 0o700))) {
            return fail("cannot create temporary workspace: {s}", .{ws});
        }
        cleanup_workspace = true;
        break :blk ws;
    };
    defer if (cleanup_workspace) {
        var tmp_dir = std.Io.Dir.openDirAbsolute(io, temporary_root, .{ .iterate = true, .follow_symlinks = false }) catch unreachable;
        defer tmp_dir.close(io);
        tmp_dir.deleteTree(io, std.fs.path.basename(workspace)) catch {};
    };

    const host_state = try captureHostState(allocator, io);
    defer {
        assertHostUnchanged(allocator, io, host_state) catch {
            std.debug.print("host state changed during alternatives reference execution\n", .{});
            std.process.exit(1);
        };
        ctx.verifyReference(refs.dpkg, arch, "dpkg") catch {
            std.debug.print("dpkg reference verification failed\n", .{});
            std.process.exit(1);
        };
        ctx.verifyReference(refs.update_alternatives, arch, "update-alternatives") catch {
            std.debug.print("update-alternatives reference verification failed\n", .{});
            std.process.exit(1);
        };
    }

    const environment = try fixtureEnvironment(allocator, io, workspace);
    try validateEnvironment(environment);
    try validateHostConfiguration(allocator, io, environment[3].value, "/etc/dpkg");
    const observed = try observe(ctx, workspace, environment, arch, refs.dpkg, refs.update_alternatives, derived);

    try assertHostUnchanged(allocator, io, host_state);
    try ctx.verifyReference(refs.dpkg, arch, "dpkg");
    try ctx.verifyReference(refs.update_alternatives, arch, "update-alternatives");

    if (update_reference) {
        try reference.object.put(allocator, "observed_behavior", observed);
        const ref_path = try ctx.repoPath(reference_relative);
        const encoded = try canonicalJson(allocator, reference);
        try writeRegular(allocator, io, ref_path, encoded, 0o644);
    } else if (capture_observed) |cap_path| {
        try writeCapture(ctx, cap_path, observed);
    } else if (!jsonEqual(observed, expected_observation.?)) {
        return fail("observed alternatives behavior differs from the canonical reference", .{});
    }

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    if (print_observed) {
        const encoded = try canonicalJson(allocator, observed);
        try stdout_writer.interface.writeAll(encoded);
    }
    const groups_len = derived.object.get("alternatives").?.object.get("groups").?.array.items.len;
    const req_len = derived.object.get("alternatives").?.object.get("requested_paths").?.array.items.len;
    try stdout_writer.interface.print(
        "dpkg/update-alternatives reference passed ({s}, {d} groups, {d} requested paths)\n",
        .{ arch, groups_len, req_len },
    );
    try stdout_writer.interface.flush();
}

const TestWorkspace = struct {
    arena: *std.heap.ArenaAllocator,
    ctx: Context,
    tmp_root: []const u8,
    workspace: []const u8,

    fn init() !TestWorkspace {
        const arena = try std.testing.allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer {
            arena.deinit();
            std.testing.allocator.destroy(arena);
        }
        const alloc = arena.allocator();
        const io = std.testing.io;
        const repo = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", alloc);
        const ctx = try Context.init(alloc, io, std.testing.environ, repo);
        const tmp_root = try ctx.repoPath(".tmp");
        try std.Io.Dir.cwd().createDirPath(io, tmp_root);
        var rand_bytes: [8]u8 = undefined;
        try io.randomSecure(&rand_bytes);
        const hex = std.fmt.bytesToHex(rand_bytes, .lower);
        const ws = try std.fs.path.join(
            alloc,
            &.{ tmp_root, try std.fmt.allocPrint(alloc, "dpkg-alternatives-reference-unit-{s}", .{hex}) },
        );
        try std.Io.Dir.cwd().createDirPath(io, ws);
        return .{
            .arena = arena,
            .ctx = ctx,
            .tmp_root = tmp_root,
            .workspace = ws,
        };
    }

    fn deinit(self: *TestWorkspace) void {
        if (std.Io.Dir.openDirAbsolute(std.testing.io, self.tmp_root, .{ .iterate = true, .follow_symlinks = false })) |dir_val| {
            var dir = dir_val;
            defer dir.close(std.testing.io);
            dir.deleteTree(std.testing.io, std.fs.path.basename(self.workspace)) catch {};
        } else |_| {}
        self.arena.deinit();
        std.testing.allocator.destroy(self.arena);
    }
};

fn testRecordText(allocator: std.mem.Allocator, state: std.json.Value) !?[]u8 {
    const rec = state.object.get("record").?;
    if (rec == .null) return null;
    return try base64DecodeAlloc(allocator, rec.object.get("bytes_base64").?.string);
}

fn testSelectorTarget(state: std.json.Value, name: []const u8) !?[]const u8 {
    var selected: ?[]const u8 = null;
    for (state.object.get("selectors").?.array.items) |item| {
        if (std.mem.eql(u8, item.object.get("name").?.string, name)) {
            const fact = item.object.get("fact").?;
            if (fact != .null) {
                if (selected != null) return error.DuplicateSelector;
                selected = fact.object.get("target").?.string;
            }
        }
    }
    return selected;
}

test "reference is canonical schema valid and source bound" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const reference = try tw.ctx.loadReference();
    const schema_path = try tw.ctx.repoPath(schema_relative);
    const schema_raw = try readRegular(alloc, tw.ctx.io, schema_path, Limits.maximum_total_record_bytes);
    const schema = try std.json.parseFromSliceLeaky(std.json.Value, alloc, schema_raw, .{});
    try validateAgainstSchema(schema, schema, reference);

    const ref_path = try tw.ctx.repoPath(reference_relative);
    const ref_bytes = try readRegular(alloc, tw.ctx.io, ref_path, Limits.maximum_total_record_bytes);
    const canonical = try canonicalJson(alloc, reference);
    try std.testing.expectEqualStrings(ref_bytes, canonical);

    const derived = try tw.ctx.verifySourceBindings(reference);
    const alternatives = derived.object.get("alternatives").?.object;
    const groups = alternatives.get("groups").?.array.items;
    try std.testing.expectEqual(@as(usize, 14), groups.len);
    try std.testing.expectEqual(@as(usize, 189), alternatives.get("requested_paths").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 190), alternatives.get("linked_entries").?.array.items.len);
    var link_sum: usize = 0;
    for (groups) |g| link_sum += g.object.get("links").?.array.items.len;
    try std.testing.expectEqual(@as(usize, 72), link_sum);

    const cfg_sha = try sha256HexAlloc(alloc, pinned_dpkg_config);
    try std.testing.expectEqualStrings(
        cfg_sha,
        reference.object.get("source").?.object.get("dpkg").?.object.get("configuration_sha256").?.string,
    );
    try std.testing.expectEqualStrings(
        canonical_task_invocation,
        reference.object.get("boundary").?.object.get("invocation_clock").?.object.get("task_invocation").?.string,
    );

    var invalid = try cloneJsonValue(alloc, reference);
    var step0_res = invalid.object.getPtr("observed_behavior").?.object
        .getPtr("external_update_alternatives").?.object
        .getPtr("selection").?.object
        .getPtr("steps").?.array.items[0].object
        .getPtr("result").?;
    _ = step0_res.object.orderedRemove("command");
    try std.testing.expectError(
        error.SchemaRequiredPropertyMissing,
        validateAgainstSchema(schema, schema, invalid),
    );
}

test "publication has exact dual architecture evidence" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const reference = try tw.ctx.loadReference();
    try validateObservationArchitecture(reference, "amd64");
    try validateObservationArchitecture(reference, "arm64");
    try std.testing.expectError(error.OracleError, validateObservationArchitecture(reference, "riscv64"));

    const obs_arches = reference.object.get("boundary").?.object.get("observed_architectures").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), obs_arches.len);
    try std.testing.expectEqualStrings("amd64", obs_arches[0].string);
    try std.testing.expectEqualStrings("arm64", obs_arches[1].string);

    const evidence = reference.object.get("architecture_evidence").?.object.get("arm64").?.object;
    try std.testing.expectEqual(@as(i64, 190), evidence.get("difference_count").?.integer);
    const summary = evidence.get("difference_summary").?.object;
    try std.testing.expectEqual(@as(i64, 64), summary.get("architecture_derived_bytes_base64").?.integer);
    try std.testing.expectEqual(@as(i64, 26), summary.get("architecture_derived_logs").?.integer);
    try std.testing.expectEqual(@as(i64, 80), summary.get("architecture_derived_sha256").?.integer);
    try std.testing.expectEqual(@as(i64, 20), summary.get("architecture_fields").?.integer);

    var cap_arch_count: usize = 0;
    var arch_count: usize = 0;
    var b64_count: usize = 0;
    var log_count: usize = 0;
    var sha_count: usize = 0;
    for (evidence.get("differences_from_baseline").?.array.items) |diff| {
        const path = diff.object.get("path").?.string;
        const last = std.fs.path.basename(path);
        if (std.mem.eql(u8, last, "Architecture")) cap_arch_count += 1;
        if (std.mem.eql(u8, last, "architecture")) arch_count += 1;
        if (std.mem.eql(u8, last, "bytes_base64")) b64_count += 1;
        if (std.mem.eql(u8, last, "log")) log_count += 1;
        if (std.mem.eql(u8, last, "sha256")) sha_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), cap_arch_count);
    try std.testing.expectEqual(@as(usize, 19), arch_count);
    try std.testing.expectEqual(@as(usize, 64), b64_count);
    try std.testing.expectEqual(@as(usize, 26), log_count);
    try std.testing.expectEqual(@as(usize, 80), sha_count);

    const arm64 = try verifyArchitectureEvidence(alloc, reference);
    const observed = reference.object.get("observed_behavior").?.object;
    try std.testing.expect(jsonEqual(
        arm64.object.get("external_update_alternatives").?,
        observed.get("external_update_alternatives").?,
    ));
    try std.testing.expect(jsonEqual(
        arm64.object.get("separation").?,
        observed.get("separation").?,
    ));
}

test "vendor projection covers every pinned group and requested path" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const reference = try tw.ctx.loadReference();
    const projection = reference.object.get("observed_behavior").?.object
        .get("external_update_alternatives").?.object
        .get("vendor_projection").?.object;
    try std.testing.expectEqual(@as(i64, 14), projection.get("group_count").?.integer);
    try std.testing.expectEqual(@as(i64, 72), projection.get("relationship_count").?.integer);
    try std.testing.expectEqual(@as(i64, 189), projection.get("requested_path_count").?.integer);

    const groups = projection.get("groups").?.array.items;
    const expected_names = reference.object.get("vendor_projection").?.object.get("group_names").?.array.items;
    try std.testing.expectEqual(expected_names.len, groups.len);
    for (groups, expected_names) |group, exp_name| {
        const gobj = group.object;
        try std.testing.expectEqualStrings(exp_name.string, gobj.get("name").?.string);
        const rec = gobj.get("record").?.object;
        try std.testing.expectEqualStrings("regular", rec.get("kind").?.string);
        try std.testing.expectEqualStrings("0644", rec.get("mode").?.string);
        try std.testing.expectEqual(@as(i64, 0), rec.get("uid").?.integer);
        try std.testing.expectEqual(@as(i64, 0), rec.get("gid").?.integer);
        const text = (try testRecordText(alloc, group)).?;
        try std.testing.expect(std.mem.startsWith(u8, text, "auto\n"));

        for (gobj.get("generic_links").?.array.items) |item| {
            const fact = item.object.get("fact").?.object;
            try std.testing.expectEqualStrings("symlink", fact.get("kind").?.string);
            try std.testing.expectEqualStrings("0777", fact.get("mode").?.string);
            try std.testing.expectEqual(@as(i64, 0), fact.get("uid").?.integer);
            try std.testing.expectEqual(@as(i64, 0), fact.get("gid").?.integer);
        }
        for (gobj.get("selectors").?.array.items) |item| {
            const fact = item.object.get("fact").?.object;
            try std.testing.expectEqualStrings("symlink", fact.get("kind").?.string);
            try std.testing.expectEqualStrings("0777", fact.get("mode").?.string);
            try std.testing.expectEqual(@as(i64, 0), fact.get("uid").?.integer);
            try std.testing.expectEqual(@as(i64, 0), fact.get("gid").?.integer);
        }
    }
}

test "auto manual priority ties and removal are exact" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const reference = try tw.ctx.loadReference();
    const steps = reference.object.get("observed_behavior").?.object
        .get("external_update_alternatives").?.object
        .get("selection").?.object
        .get("steps").?.array.items;

    var by_name: std.StringHashMapUnmanaged(std.json.Value) = .empty;
    for (steps) |step| {
        try std.testing.expectEqual(@as(i64, 0), step.object.get("result").?.object.get("exit").?.integer);
        try by_name.put(alloc, step.object.get("operation").?.string, step);
    }

    try std.testing.expectEqualStrings(
        "/usr/lib/debz-choice/b",
        (try testSelectorTarget(by_name.get("install-a-10-tie").?.object.get("state").?, "debz-choice")).?,
    );
    try std.testing.expectEqualStrings(
        "/usr/lib/debz-choice/a",
        (try testSelectorTarget(by_name.get("remove-c-tie-selects-a").?.object.get("state").?, "debz-choice")).?,
    );
    try std.testing.expectEqualStrings(
        "/usr/lib/debz-choice/a",
        (try testSelectorTarget(by_name.get("raise-c-30-manual-sticks").?.object.get("state").?, "debz-choice")).?,
    );
    try std.testing.expect(std.mem.startsWith(
        u8,
        (try testRecordText(alloc, by_name.get("set-a-manual").?.object.get("state").?)).?,
        "manual\n",
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        (try testRecordText(alloc, by_name.get("auto-selects-c").?.object.get("state").?)).?,
        "auto\n",
    ));
    const remove_all_state = by_name.get("remove-all").?.object.get("state").?.object;
    try std.testing.expect(remove_all_state.get("record").? == .null);
    try std.testing.expectEqual(@as(usize, 0), remove_all_state.get("selectors").?.array.items.len);
}

test "missing targets shape changes and corrupt records are observed" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const reference = try tw.ctx.loadReference();
    const external = reference.object.get("observed_behavior").?.object
        .get("external_update_alternatives").?.object;
    var steps: std.StringHashMapUnmanaged(std.json.Value) = .empty;
    for (external.get("missing_targets_and_group_shape").?.object.get("steps").?.array.items) |step| {
        try steps.put(alloc, step.object.get("operation").?.string, step);
    }

    const missing_high = steps.get("install-missing-high").?.object;
    try std.testing.expectEqual(@as(i64, 2), missing_high.get("result").?.object.get("exit").?.integer);
    try std.testing.expect(missing_high.get("state").?.object.get("record").? == .null);
    try std.testing.expect(std.mem.indexOf(u8, missing_high.get("result").?.object.get("output").?.string, "doesn't exist") != null);

    try std.testing.expectEqualStrings(
        "/usr/lib/debz-missing/second",
        (try testSelectorTarget(steps.get("install-second-with-slave").?.object.get("state").?, "debz-missing")).?,
    );
    try std.testing.expect((try testSelectorTarget(steps.get("reregister-selected-without-slave").?.object.get("state").?, "debz-missing.1")) == null);
    try std.testing.expect(steps.get("auto-with-all-targets-missing").?.object.get("state").?.object.get("record").? == .null);

    const malformed = external.get("malformed_records").?.object;
    const reg_cases = malformed.get("regular_record_cases").?.array.items;
    try std.testing.expectEqual(@as(usize, 5), reg_cases.len);
    for (reg_cases) |item| {
        try std.testing.expectEqual(@as(i64, 2), item.object.get("result").?.object.get("exit").?.integer);
    }
    const rejections = malformed.get("oracle_preflight_rejections").?.array.items;
    try std.testing.expectEqual(@as(usize, 4), rejections.len);
}

test "attack and atomicity partial states are canonical" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const reference = try tw.ctx.loadReference();
    const external = reference.object.get("observed_behavior").?.object
        .get("external_update_alternatives").?.object;
    var attacks: std.StringHashMapUnmanaged(std.json.Value) = .empty;
    for (external.get("path_and_symlink_attacks").?.object.get("raw_tool_cases").?.array.items) |item| {
        try attacks.put(alloc, item.object.get("case").?.string, item);
    }

    const trav = attacks.get("generic-link-traversal").?.object;
    try std.testing.expectEqual(@as(i64, 0), trav.get("result").?.object.get("exit").?.integer);
    try std.testing.expectEqualStrings("/etc/alternatives/escape", trav.get("outside_root").?.object.get("target").?.string);

    const sym = attacks.get("alternatives-directory-symlink").?.object;
    try std.testing.expectEqualStrings("/usr/lib/provider", sym.get("outside_root").?.object.get("target").?.string);

    const self_ref = attacks.get("self-referential-provider").?.object;
    try std.testing.expectEqual(@as(i64, 2), self_ref.get("result").?.object.get("exit").?.integer);

    const ind_cycle = attacks.get("indirect-symlink-cycle").?.object;
    try std.testing.expectEqual(@as(i64, 0), ind_cycle.get("result").?.object.get("exit").?.integer);
    try std.testing.expect(std.mem.indexOf(u8, ind_cycle.get("result").?.object.get("output").?.string, "doesn't exist") != null);
    try std.testing.expectEqualStrings("/usr/bin/cycle-link", ind_cycle.get("provider").?.object.get("target").?.string);
    try std.testing.expect(ind_cycle.get("state").?.object.get("record").? != .null);

    const failures = external.get("atomicity").?.object.get("failure_injection").?.array.items;
    for (failures) |item| {
        try std.testing.expectEqual(@as(i64, 2), item.object.get("result").?.object.get("exit").?.integer);
        try std.testing.expect(item.object.get("state").?.object.get("record").? == .null);
        var has_tmp = false;
        for (item.object.get("state").?.object.get("selectors").?.array.items) |sel| {
            if (std.mem.eql(u8, sel.object.get("name").?.string, "atomic.dpkg-tmp")) has_tmp = true;
        }
        try std.testing.expect(has_tmp);
        try std.testing.expect(std.mem.indexOf(u8, item.object.get("result").?.object.get("log").?.string, "link group atomic updated") != null);
    }
}

test "direct dpkg member lifecycle scripts failures and recovery" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const reference = try tw.ctx.loadReference();
    const direct = reference.object.get("observed_behavior").?.object.get("direct_dpkg").?.object;
    const scriptless = direct.get("scriptless_alternatives_member").?.object;
    try std.testing.expect(scriptless.get("installed").?.object.get("alternatives").?.object.get("record").? == .null);

    var found_alt_info: ?std.json.Value = null;
    for (scriptless.get("installed").?.object.get("info").?.array.items) |item| {
        if (std.mem.eql(u8, item.object.get("name").?.string, "alternatives")) found_alt_info = item;
    }
    try std.testing.expectEqualStrings("0640", found_alt_info.?.object.get("mode").?.string);
    try std.testing.expectEqual(@as(usize, 0), scriptless.get("removed").?.object.get("info").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 0), scriptless.get("purged").?.object.get("info").?.array.items.len);

    var phases: std.StringHashMapUnmanaged(std.json.Value) = .empty;
    for (direct.get("successful_lifecycle").?.object.get("phases").?.array.items) |phase| {
        try std.testing.expectEqual(@as(i64, 0), phase.object.get("result").?.object.get("exit").?.integer);
        try phases.put(alloc, phase.object.get("operation").?.string, phase);
    }
    try std.testing.expectEqualStrings(
        "install ok installed",
        phases.get("install").?.object.get("state").?.object.get("database").?.object.get("committed").?.object.get("status").?.string,
    );
    try std.testing.expectEqualStrings(
        "2",
        phases.get("upgrade").?.object.get("state").?.object.get("database").?.object.get("committed").?.object.get("version").?.string,
    );
    try std.testing.expect(phases.get("upgrade").?.object.get("state").?.object.get("alternatives").?.object.get("record").? != .null);
    try std.testing.expect(phases.get("remove").?.object.get("state").?.object.get("alternatives").?.object.get("record").? == .null);
    try std.testing.expectEqual(@as(usize, 0), phases.get("purge").?.object.get("state").?.object.get("info").?.array.items.len);

    const conflict = direct.get("conflicting_packages").?.object;
    try std.testing.expectEqual(@as(i64, 0), conflict.get("first_result").?.object.get("exit").?.integer);
    try std.testing.expectEqual(@as(i64, 1), conflict.get("second_result").?.object.get("exit").?.integer);
    try std.testing.expect(std.mem.indexOf(u8, conflict.get("second_result").?.object.get("output").?.string, "trying to overwrite") != null);
    const shared_bytes = try base64DecodeAlloc(alloc, conflict.get("shared_file").?.object.get("fact").?.object.get("bytes_base64").?.string);
    try std.testing.expectEqualStrings("first owner\n", shared_bytes);
    try std.testing.expectEqualStrings("usr/lib/debz-alternatives/package-conflict", conflict.get("shared_file").?.object.get("path").?.string);

    var failures: std.StringHashMapUnmanaged(std.json.Value) = .empty;
    for (direct.get("failure_recovery").?.array.items) |item| {
        try std.testing.expectEqual(@as(i64, 0), item.object.get("recovery_result").?.object.get("exit").?.integer);
        try std.testing.expectEqual(@as(usize, 2), item.object.get("archives").?.object.count());
        try failures.put(alloc, item.object.get("case").?.string, item);
    }
    try std.testing.expectEqual(@as(i64, 1), failures.get("fresh-postinst").?.object.get("operation_result").?.object.get("exit").?.integer);
    try std.testing.expectEqual(@as(i64, 0), failures.get("upgrade-prerm").?.object.get("operation_result").?.object.get("exit").?.integer);
    try std.testing.expectEqual(@as(i64, 1), failures.get("upgrade-postinst").?.object.get("operation_result").?.object.get("exit").?.integer);
    try std.testing.expectEqual(@as(i64, 1), failures.get("remove-postrm").?.object.get("operation_result").?.object.get("exit").?.integer);

    const interruption = direct.get("interruption_recovery").?.object;
    try std.testing.expectEqual(@as(i64, -9), interruption.get("interruption_result").?.object.get("exit").?.integer);
    try std.testing.expect(interruption.get("interrupted").?.object.get("database").?.object.get("journal_nonempty").?.bool);
    try std.testing.expect(interruption.get("interrupted").?.object.get("database").?.object.get("temporary_update").?.bool);
    try std.testing.expectEqual(@as(i64, 0), interruption.get("recovery_result").?.object.get("exit").?.integer);
    try std.testing.expect(!interruption.get("recovered").?.object.get("database").?.object.get("journal_nonempty").?.bool);
}

test "every execution binds command outcome and relevant filesystem" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const reference = try tw.ctx.loadReference();
    var results: std.ArrayList(std.json.Value) = .empty;

    const Collector = struct {
        list: *std.ArrayList(std.json.Value),
        alloc: std.mem.Allocator,

        fn collect(self: *@This(), val: std.json.Value) !void {
            switch (val) {
                .object => |obj| {
                    if (obj.count() == 4 and
                        obj.contains("command") and
                        obj.contains("exit") and
                        obj.contains("log") and
                        obj.contains("output"))
                    {
                        try self.list.append(self.alloc, val);
                    }
                    var it = obj.iterator();
                    while (it.next()) |entry| try self.collect(entry.value_ptr.*);
                },
                .array => |arr| {
                    for (arr.items) |item| try self.collect(item);
                },
                else => {},
            }
        }
    };

    var collector: Collector = .{ .list = &results, .alloc = alloc };
    try collector.collect(reference.object.get("observed_behavior").?);
    try std.testing.expectEqual(@as(usize, 70), results.items.len);

    for (results.items) |res| {
        const cmd = res.object.get("command").?.array.items;
        const first = cmd[0].string;
        try std.testing.expect(
            std.mem.eql(u8, first, "<pinned-dpkg>") or
                std.mem.eql(u8, first, "<pinned-update-alternatives>"),
        );
        for (cmd) |arg| {
            try std.testing.expect(std.mem.indexOf(u8, arg.string, tw.ctx.repository) == null);
        }
    }
    const canonical = try canonicalJson(alloc, reference);
    try std.testing.expect(std.mem.indexOf(u8, canonical, tw.ctx.repository) == null);
}

test "paths records scripts and root guards fail closed" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    for ([_][]const u8{ "/../escape", "/usr/bin/../escape", "relative", "/", "/a//b" }) |p| {
        try std.testing.expectError(error.OracleError, validateAbsolutePath(p));
    }
    for ([_][]const u8{ "../escape", "a/b", ".hidden", "A", "" }) |n| {
        try std.testing.expectError(error.OracleError, validateName(n));
    }

    const scripts = try packageScripts(alloc, "debz-alt-test", "1", "debz-alt-test", 10);
    for (scripts) |script| {
        const script_file = try std.fs.path.join(alloc, &.{ tw.workspace, try std.fmt.allocPrint(alloc, "check-{s}.sh", .{script.kind}) });
        try writeRegular(alloc, tw.ctx.io, script_file, script.body, 0o755);
        const res = try std.process.run(alloc, tw.ctx.io, .{
            .argv = &.{ "/bin/sh", "-n", script_file },
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, res.term);
    }

    const root = try std.fs.path.join(alloc, &.{ tw.workspace, "root" });
    try tw.ctx.makeRoot(root, "amd64", false);
    try validateRoot(alloc, tw.ctx.io, root);

    const escaped = try std.fs.path.join(alloc, &.{ tw.workspace, "escaped" });
    try std.Io.Dir.cwd().createDirPath(tw.ctx.io, escaped);
    const alt_dir = try std.fs.path.join(alloc, &.{ root, "etc/alternatives" });
    const alt_z = try dupeZ(alloc, alt_dir);
    const esc_z = try dupeZ(alloc, escaped);
    _ = linux.unlinkat(linux.AT.FDCWD, alt_z.ptr, linux.AT.REMOVEDIR);
    _ = linux.symlinkat(esc_z.ptr, linux.AT.FDCWD, alt_z.ptr);
    try std.testing.expectError(error.OracleError, validateRoot(alloc, tw.ctx.io, root));
}

test "native runtime copies the real alternatives consumer closure" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const root = try std.fs.path.join(alloc, &.{ tw.workspace, "root" });
    try tw.ctx.makeRoot(root, "amd64", true);
    const source = try std.fs.path.join(alloc, &.{ tw.workspace, "choice" });
    const source_bytes = "#! '/bin/sh' -e\nexit 0\n";
    try writeRegular(alloc, tw.ctx.io, source, source_bytes, 0o751);

    const source_z = try dupeZ(alloc, source);
    const ts = [2]linux.timespec{
        .{ .sec = 1_700_000_000, .nsec = 123_456_789 },
        .{ .sec = 1_700_000_000, .nsec = 123_456_789 },
    };
    _ = linux.utimensat(linux.AT.FDCWD, source_z.ptr, &ts, 0);
    const xattr_val = "alternatives original attribute";
    _ = linux.setxattr(source_z.ptr, "user.debz-fixture", xattr_val.ptr, xattr_val.len, 0);

    try tw.ctx.copyProgram(root, source, "/usr/bin/choice");
    const copied = try std.fs.path.join(alloc, &.{ root, "usr/bin/choice" });
    const copied_bytes = try readRegular(alloc, tw.ctx.io, copied, 4096);
    try std.testing.expectEqualStrings(source_bytes, copied_bytes);

    const src_meta = try lstatPath(alloc, source);
    const dst_meta = try lstatPath(alloc, copied);
    try std.testing.expectEqual(src_meta.mode, dst_meta.mode);
    try std.testing.expectEqual(src_meta.mtime_sec, dst_meta.mtime_sec);
    try std.testing.expectEqual(src_meta.mtime_nsec, dst_meta.mtime_nsec);

    const copied_z = try dupeZ(alloc, copied);
    var xbuf: [128]u8 = undefined;
    const xlen = linux.getxattr(copied_z.ptr, "user.debz-fixture", &xbuf, xbuf.len);
    try std.testing.expect(!errnoFailed(xlen));
    try std.testing.expectEqualStrings(xattr_val, xbuf[0..xlen]);

    const sh_copied = try std.Io.Dir.cwd().readFileAlloc(tw.ctx.io, try std.fs.path.join(alloc, &.{ root, "bin/sh" }), alloc, .limited(4 * 1024 * 1024));
    const sh_host = try std.Io.Dir.cwd().readFileAlloc(tw.ctx.io, "/bin/sh", alloc, .limited(4 * 1024 * 1024));
    try std.testing.expectEqualSlices(u8, sh_host, sh_copied);

    const sleep_copied = try std.Io.Dir.cwd().readFileAlloc(tw.ctx.io, try std.fs.path.join(alloc, &.{ root, "bin/sleep" }), alloc, .limited(Limits.maximum_archive_bytes));
    const sleep_host = try std.Io.Dir.cwd().readFileAlloc(tw.ctx.io, try tw.ctx.sleepSourcePath(), alloc, .limited(Limits.maximum_archive_bytes));
    try std.testing.expectEqualSlices(u8, sleep_host, sleep_copied);

    try tw.ctx.copyProgram(root, try std.fs.path.join(alloc, &.{ tw.workspace, "absent" }), "/usr/bin/choice");
    const copied_after = try readRegular(alloc, tw.ctx.io, copied, 4096);
    try std.testing.expectEqualStrings(source_bytes, copied_after);
}

test "native runtime is required and preserves the alternatives file bound" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const root = try std.fs.path.join(alloc, &.{ tw.workspace, "root" });
    try tw.ctx.makeRoot(root, "amd64", false);
    const source = try std.fs.path.join(alloc, &.{ tw.workspace, "choice" });
    try writeRegular(alloc, tw.ctx.io, source, "plain static fixture\n", 0o644);

    var missing_ctx = tw.ctx;
    missing_ctx.disposable_runtime = try std.fs.path.join(alloc, &.{ tw.workspace, "missing-native-runtime" });
    try std.testing.expectError(error.FileNotFound, missing_ctx.copyProgram(root, source, "/usr/bin/choice"));
    try std.testing.expect(!try lexistsPath(alloc, try std.fs.path.join(alloc, &.{ root, "usr/bin/choice" })));

    var file = try std.Io.Dir.openFileAbsolute(tw.ctx.io, source, .{ .mode = .read_write });
    defer file.close(tw.ctx.io);
    try file.setLength(tw.ctx.io, Limits.maximum_archive_bytes + 1);
    try std.testing.expectError(error.OracleError, tw.ctx.copyProgram(root, source, "/usr/bin/choice"));
    try std.testing.expect(!try lexistsPath(alloc, try std.fs.path.join(alloc, &.{ root, "usr/bin/choice" })));
}

test "subprocess timeout kills the complete process group" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const output = try std.fs.path.join(alloc, &.{ tw.workspace, "timeout.log" });
    const env = try baseEnvironment(alloc);
    try std.testing.expectError(
        error.OracleError,
        runBoundedProcess(alloc, tw.ctx.io, &.{ "/bin/sh", "-c", "sleep 30" }, env, output, 1),
    );
}

test "generated fixture packages match published digests across architectures" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.ctx.allocator;

    const reference = try tw.ctx.loadReference();
    for ([_][]const u8{ "amd64", "arm64" }) |arch| {
        const obs = try publishedObservation(alloc, reference, arch);
        const direct = obs.object.get("direct_dpkg").?.object;
        const arch_ws = try std.fs.path.join(alloc, &.{ tw.workspace, arch });

        const scriptless = try makePackage(alloc, tw.ctx.io, try std.fs.path.join(alloc, &.{ arch_ws, "scriptless" }), arch, "debz-alt-metadata", "1", "debz-alt-metadata", 10, false);
        try std.testing.expect(jsonEqual(
            direct.get("scriptless_alternatives_member").?.object.get("archive").?,
            try archiveFact(alloc, tw.ctx.io, scriptless),
        ));

        const succ_1 = try makePackage(alloc, tw.ctx.io, try std.fs.path.join(alloc, &.{ arch_ws, "succ" }), arch, "debz-alt-lifecycle", "1", "debz-alt-lifecycle", 10, true);
        const succ_2 = try makePackage(alloc, tw.ctx.io, try std.fs.path.join(alloc, &.{ arch_ws, "succ" }), arch, "debz-alt-lifecycle", "2", "debz-alt-lifecycle", 20, true);
        const exp_succ = direct.get("successful_lifecycle").?.object.get("archives").?.object;
        try std.testing.expect(jsonEqual(exp_succ.get("1").?, try archiveFact(alloc, tw.ctx.io, succ_1)));
        try std.testing.expect(jsonEqual(exp_succ.get("2").?, try archiveFact(alloc, tw.ctx.io, succ_2)));

        const shared = "usr/lib/debz-alternatives/package-conflict";
        const conf_a = try makeMaterializationPackage(alloc, tw.ctx.io, try std.fs.path.join(alloc, &.{ arch_ws, "conflict" }), arch, "1", .{
            .package = "debz-alt-conflict-a",
            .extra_files = &.{.{ .relative = shared, .content = "first owner\n" }},
            .alternatives_body = "opaque conflict metadata\n",
            .alternatives_mode = 0o644,
        });
        const conf_b = try makeMaterializationPackage(alloc, tw.ctx.io, try std.fs.path.join(alloc, &.{ arch_ws, "conflict" }), arch, "1", .{
            .package = "debz-alt-conflict-b",
            .extra_files = &.{.{ .relative = shared, .content = "second owner\n" }},
            .alternatives_body = "opaque conflict metadata\n",
            .alternatives_mode = 0o644,
        });
        const exp_conf = direct.get("conflicting_packages").?.object;
        try std.testing.expect(jsonEqual(exp_conf.get("first_archive").?, try archiveFact(alloc, tw.ctx.io, conf_a)));
        try std.testing.expect(jsonEqual(exp_conf.get("second_archive").?, try archiveFact(alloc, tw.ctx.io, conf_b)));
    }
}


