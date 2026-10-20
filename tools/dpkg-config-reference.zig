const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

fn dupeZ(allocator: std.mem.Allocator, text: []const u8) ![:0]u8 {
    return allocator.dupeSentinel(u8, text, 0);
}

pub const reference_relative = "tools/fixtures/vendor-state/dpkg-config-reference-v1.json";
pub const schema_relative = "schema/dpkg-config-reference-v1.json";
pub const schema_id = "https://debz.dev/schema/dpkg-config-reference-v1";
pub const package_name = "debz-config-oracle";
pub const trace_relative = "var/log/debz-config-oracle.trace";
pub const env_trace_relative = "var/log/debz-config-oracle.environment";
pub const fd_errors_relative = "var/log/debz-config-oracle.fd-errors";
pub const config_invocations_relative = "var/log/debz-config-oracle.config-invocations";
pub const vendor_config_invocations_relative = "config-called";
pub const dpkg_log_relative = "var/log/dpkg.log";
pub const failures_relative = "debz-config-oracle.failures";
pub const pause_relative = "debz-config-oracle.pause";
pub const paused_relative = "debz-config-oracle.paused";
pub const guard_relative = ".debz-native-disposable";
pub const guard_content = "debz native materialization fixture v1\n";
pub const epoch: i64 = 1_700_000_000;

pub const tokens = [_][]const u8{ "v1", "v1r", "v2" };
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
pub const control_names = [_][]const u8{
    "control",
    "conffiles",
    "md5sums",
    "config",
    "preinst",
    "postinst",
    "prerm",
    "postrm",
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
    pub const maximum_packages: usize = 16;
    pub const maximum_control_members: usize = 16;
    pub const maximum_control_bytes: usize = 256 * 1024;
    pub const maximum_file_bytes: usize = 256 * 1024;
    pub const maximum_log_bytes: usize = 128 * 1024;
    pub const maximum_trace_bytes: usize = 128 * 1024;
    pub const maximum_trace_records: usize = 128;
    pub const maximum_environment_records: usize = 128;
    pub const maximum_environment_variables: usize = 32;
    pub const maximum_environment_line_bytes: usize = 4096;
    pub const maximum_arguments: usize = 16;
    pub const maximum_argument_bytes: usize = 256;
    pub const maximum_updates: usize = 32;
    pub const maximum_info_files: usize = 32;
    pub const maximum_info_bytes: usize = 1024 * 1024;
    pub const maximum_archive_bytes: usize = 8 * 1024 * 1024;
    pub const maximum_status_bytes: usize = 256 * 1024;
    pub const subprocess_timeout_seconds: i64 = 60;
    pub const pause_timeout_seconds: i64 = 10;
    pub const pause_script_timeout_seconds: usize = 30;
};

const LimitEntry = struct { name: []const u8, value: i64 };
const limit_contract_entries = [_]LimitEntry{
    .{ .name = "maximum_archive_bytes", .value = Limits.maximum_archive_bytes },
    .{ .name = "maximum_argument_bytes", .value = Limits.maximum_argument_bytes },
    .{ .name = "maximum_arguments", .value = Limits.maximum_arguments },
    .{ .name = "maximum_control_bytes", .value = Limits.maximum_control_bytes },
    .{ .name = "maximum_control_members", .value = Limits.maximum_control_members },
    .{ .name = "maximum_environment_line_bytes", .value = Limits.maximum_environment_line_bytes },
    .{ .name = "maximum_environment_records", .value = Limits.maximum_environment_records },
    .{ .name = "maximum_environment_variables", .value = Limits.maximum_environment_variables },
    .{ .name = "maximum_file_bytes", .value = Limits.maximum_file_bytes },
    .{ .name = "maximum_info_bytes", .value = Limits.maximum_info_bytes },
    .{ .name = "maximum_info_files", .value = Limits.maximum_info_files },
    .{ .name = "maximum_log_bytes", .value = Limits.maximum_log_bytes },
    .{ .name = "maximum_packages", .value = Limits.maximum_packages },
    .{ .name = "maximum_status_bytes", .value = Limits.maximum_status_bytes },
    .{ .name = "maximum_trace_bytes", .value = Limits.maximum_trace_bytes },
    .{ .name = "maximum_trace_records", .value = Limits.maximum_trace_records },
    .{ .name = "maximum_updates", .value = Limits.maximum_updates },
    .{ .name = "pause_script_timeout_seconds", .value = Limits.pause_script_timeout_seconds },
    .{ .name = "pause_timeout_seconds", .value = Limits.pause_timeout_seconds },
    .{ .name = "subprocess_timeout_seconds", .value = Limits.subprocess_timeout_seconds },
};

const Sha256 = std.crypto.hash.sha2.Sha256;
const Md5 = std.crypto.hash.Md5;

fn fail(comptime fmt: []const u8, args: anytype) error{OracleError} {
    if (!@inComptime() and !builtin.is_test) {
        std.debug.print("dpkg-config-reference: " ++ fmt ++ "\n", args);
    }
    return error.OracleError;
}

pub fn sha256HexAlloc(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    return allocator.dupe(u8, &hex);
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
        return fail("fixture path must be a regular non-symlink file: {s}", .{path});
    }
    if (metadata.size > maximum) {
        return fail("fixture file exceeds its byte limit: {s}", .{path});
    }
    var file = std.Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false }) catch {
        return fail("fixture path must be a regular non-symlink file: {s}", .{path});
    };
    defer file.close(io);
    var reader = file.reader(io, &.{});
    const data = reader.interface.allocRemaining(allocator, .limited(maximum + 1)) catch {
        return fail("fixture file exceeds its byte limit: {s}", .{path});
    };
    errdefer allocator.free(data);
    if (data.len > maximum) {
        return fail("fixture file exceeds its byte limit: {s}", .{path});
    }
    if (data.len != metadata.size) {
        return fail("fixture file changed while reading: {s}", .{path});
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
        var dir = existing;
        dir.close(io);
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

pub fn listDirectorySorted(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) ![][]u8 {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true, .follow_symlinks = false }) catch {
        return fail("cannot open directory: {s}", .{path});
    };
    defer dir.close(io);
    var names: std.ArrayList([]u8) = .empty;
    errdefer {
        for (names.items) |item| allocator.free(item);
        names.deinit(allocator);
    }
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        try names.append(allocator, try allocator.dupe(u8, entry.name));
    }
    std.sort.heap([]u8, names.items, {}, struct {
        fn less(_: void, left: []u8, right: []u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.less);
    return names.toOwnedSlice(allocator);
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
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, self.allocator, raw, .{});
        return parsed;
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

    pub fn selectReferenceHelper(
        self: Context,
        executable: ?[]const u8,
        architecture: []const u8,
        root_accounts: bool,
    ) ![]u8 {
        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(self.allocator);
        try args.appendSlice(self.allocator, &.{ "--architecture", architecture });
        if (executable) |exec_path| {
            try args.appendSlice(self.allocator, &.{ "--select", exec_path });
        } else {
            try args.append(self.allocator, "--check-host");
        }
        if (root_accounts) {
            try args.append(self.allocator, "--root-accounts");
        }
        const out = try self.nativeReference(args.items);
        defer self.allocator.free(out);
        const trimmed = std.mem.trim(u8, out, " \t\r\n");
        var lines = std.mem.splitScalar(u8, trimmed, '\n');
        var last: []const u8 = trimmed;
        while (lines.next()) |line| {
            if (line.len != 0) last = line;
        }
        return self.allocator.dupe(u8, std.mem.trim(u8, last, " \t\r"));
    }

    pub fn selectReference(self: Context, path: ?[]const u8, architecture: []const u8) ![]u8 {
        var selected: []const u8 = undefined;
        if (path) |given| {
            selected = given;
        } else {
            const desc = try self.referenceDescription();
            const version = desc.object.get("version").?.string;
            selected = try std.fs.path.join(self.allocator, &.{
                self.repository,
                ".cache/native-dpkg-reference",
                version,
                architecture,
                "usr/bin/dpkg",
            });
            const meta = lstatPath(self.allocator, selected) catch {
                return fail(
                    "missing pinned dpkg reference; run zig-out/bin/debz-native-dpkg-reference as the build user",
                    .{},
                );
            };
            if ((meta.mode & linux.S.IFMT) != linux.S.IFREG) {
                return fail(
                    "missing pinned dpkg reference; run zig-out/bin/debz-native-dpkg-reference as the build user",
                    .{},
                );
            }
        }
        return self.selectReferenceHelper(selected, architecture, false);
    }

    pub fn copyProgram(
        self: Context,
        root: []const u8,
        source: []const u8,
        destination: []const u8,
        max_file_bytes: ?usize,
    ) !void {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{ self.disposable_runtime, root, source, destination });
        if (max_file_bytes) |limit| {
            try argv.appendSlice(self.allocator, &.{
                "--max-file-bytes",
                try std.fmt.allocPrint(self.allocator, "{d}", .{limit}),
            });
        }
        const result = std.process.run(self.allocator, self.io, .{
            .argv = argv.items,
            .stdout_limit = .limited(64 * 1024),
            .stderr_limit = .limited(64 * 1024),
        }) catch return fail("debz-disposable-runtime failed", .{});
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

    pub fn makeRoot(self: Context, root: []const u8, architecture: []const u8, instrumented: bool) !void {
        try self.makeBasicRoot(root, architecture);
        const log_dir = try std.fs.path.join(self.allocator, &.{ root, "var/log" });
        defer self.allocator.free(log_dir);
        try std.Io.Dir.cwd().createDirPath(self.io, log_dir);
        try self.copyProgram(root, "/bin/sh", "/bin/sh", null);
        if (instrumented) {
            try self.copyProgram(root, "/usr/bin/env", "/oracle-env", null);
            try self.copyProgram(root, "/bin/sleep", "/oracle-sleep", null);
        }
        for (forbidden_frontend_paths) |relative| {
            const candidate = try std.fs.path.join(self.allocator, &.{ root, relative });
            defer self.allocator.free(candidate);
            if (try lexistsPath(self.allocator, candidate)) {
                return fail("ambient frontend contaminated fixture root: {s}", .{relative});
            }
        }
        const info_dir = try std.fs.path.join(self.allocator, &.{ root, "var/lib/dpkg/info" });
        defer self.allocator.free(info_dir);
        const entries = try listDirectorySorted(self.allocator, self.io, info_dir);
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
        const base = try self.referenceCommand(root);
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
        const raw = try readRegular(self.allocator, self.io, ref_path, Limits.maximum_file_bytes);
        const reference = std.json.parseFromSliceLeaky(std.json.Value, self.allocator, raw, .{
            .duplicate_field_behavior = .@"error",
        }) catch return fail("unsupported dpkg config reference", .{});
        if (reference != .object) return fail("unsupported dpkg config reference", .{});
        const schema = reference.object.get("schema") orelse return fail("unsupported dpkg config reference", .{});
        const version = reference.object.get("version") orelse return fail("unsupported dpkg config reference", .{});
        if (schema != .string or !std.mem.eql(u8, schema.string, schema_id) or
            version != .integer or version.integer != 1)
        {
            return fail("unsupported dpkg config reference", .{});
        }
        const canonical = try canonicalJson(self.allocator, reference);
        if (!std.mem.eql(u8, raw, canonical)) {
            return fail("dpkg config reference is not canonical JSON", .{});
        }
        return reference;
    }

    pub fn verifyFileBinding(self: Context, path: []const u8, binding: std.json.Value) !void {
        const data = try readRegular(self.allocator, self.io, path, Limits.maximum_file_bytes * 8);
        const expected_size: usize = @intCast(binding.object.get("size").?.integer);
        const expected_sha256 = binding.object.get("sha256").?.string;
        const actual_sha256 = try sha256HexAlloc(self.allocator, data);
        if (data.len != expected_size or !std.mem.eql(u8, actual_sha256, expected_sha256)) {
            return fail("pinned source binding changed: {s}", .{path});
        }
    }

    pub fn verifySourceBindings(self: Context, reference: std.json.Value) !void {
        const source = reference.object.get("source").?.object;
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
        const vendor = source.get("vendor_reference").?.object;
        const fixtures_dir = try self.repoPath("tools/fixtures/vendor-state");

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

        const derived_raw = try readRegular(self.allocator, self.io, vendor_ref_path, Limits.maximum_file_bytes * 8);
        const derived = try std.json.parseFromSliceLeaky(std.json.Value, self.allocator, derived_raw, .{});
        const expected_members = reference.object.get("members").?.array.items;
        var observed_members: std.ArrayList(std.json.Value) = .empty;
        for (derived.object.get("control_members").?.array.items) |member| {
            if (std.mem.eql(u8, member.object.get("classification").?.string, "debconf-config")) {
                try observed_members.append(self.allocator, member);
            }
        }
        if (observed_members.items.len != expected_members.len) {
            return fail("pinned config-member identities no longer match the vendor reference", .{});
        }
        for (observed_members.items, expected_members) |obs_m, exp_m| {
            if (!jsonEqual(obs_m, exp_m)) {
                return fail("pinned config-member identities no longer match the vendor reference", .{});
            }
        }

        const req_id = vendor.get("requirement_id").?.string;
        var found_req: ?std.json.Value = null;
        for (derived.object.get("reference_execution_requirements").?.array.items) |item| {
            if (std.mem.eql(u8, item.object.get("id").?.string, req_id)) {
                found_req = item;
                break;
            }
        }
        const requirement = found_req orelse return fail("vendor reference no longer carries the config execution requirement", .{});
        const req_identities = requirement.object.get("applies_to").?.object.get("identities").?.array.items;
        if (req_identities.len != expected_members.len) {
            return fail("vendor config execution requirement identities changed", .{});
        }
        for (req_identities, expected_members) |req_ident, exp_m| {
            if (!std.mem.eql(u8, req_ident.string, exp_m.object.get("identity").?.string)) {
                return fail("vendor config execution requirement identities changed", .{});
            }
        }

        const dpkg = source.get("dpkg").?.object;
        const description = try self.referenceDescription();
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
            const expected_pin = (dpkg_arches.get(arch) orelse return fail("dpkg pin changed for {s}", .{arch})).object;
            if (!std.mem.eql(u8, pins.get("archive").?.string, expected_pin.get("archive_sha256").?.string) or
                !std.mem.eql(u8, pins.get("executable").?.string, expected_pin.get("executable_sha256").?.string))
            {
                return fail("dpkg pin changed for {s}", .{arch});
            }
        }
        _ = try verifyArchitectureEvidence(self.allocator, reference);
    }
};

pub fn validateControlName(name: []const u8) !void {
    if (!inList(&control_names, name) or
        std.mem.indexOfScalar(u8, name, '/') != null or
        std.mem.eql(u8, name, ".") or
        std.mem.eql(u8, name, ".."))
    {
        return fail("unsafe fixture control member: {s}", .{name});
    }
    for (name) |byte| {
        if (byte < 0x20 or byte == 0x7F) {
            return fail("unsafe fixture control member: {s}", .{name});
        }
    }
}

pub fn validateControlTree(allocator: std.mem.Allocator, io: std.Io, source: []const u8) !void {
    const control = try std.fs.path.join(allocator, &.{ source, "DEBIAN" });
    defer allocator.free(control);
    const meta = lstatPath(allocator, control) catch {
        return fail("fixture DEBIAN path must be a real directory", .{});
    };
    if ((meta.mode & linux.S.IFMT) != linux.S.IFDIR) {
        return fail("fixture DEBIAN path must be a real directory", .{});
    }
    const members = try listDirectorySorted(allocator, io, control);
    defer {
        for (members) |m| allocator.free(m);
        allocator.free(members);
    }
    if (members.len > Limits.maximum_control_members) {
        return fail("fixture control-member count exceeds its limit", .{});
    }
    var total: u64 = 0;
    for (members) |member_name| {
        try validateControlName(member_name);
        const member_path = try std.fs.path.join(allocator, &.{ control, member_name });
        defer allocator.free(member_path);
        const member_meta = try lstatPath(allocator, member_path);
        if ((member_meta.mode & linux.S.IFMT) != linux.S.IFREG) {
            return fail("fixture control member must be regular: {s}", .{member_name});
        }
        if (member_meta.size > Limits.maximum_file_bytes) {
            return fail("fixture control member exceeds its byte limit: {s}", .{member_name});
        }
        total += member_meta.size;
        if (total > Limits.maximum_control_bytes) {
            return fail("fixture control bytes exceed their aggregate limit", .{});
        }
    }
}

pub const EnvPair = struct { name: []const u8, value: []const u8 };

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
    for (forbidden_frontend_env) |forbidden| {
        for (environment) |pair| {
            if (std.mem.eql(u8, pair.name, forbidden)) {
                return fail("direct-dpkg fixture contains frontend environment: {s}", .{forbidden});
            }
        }
    }
    if (environment.len > Limits.maximum_environment_variables) {
        return fail("fixture environment exceeds its variable limit", .{});
    }
    for (environment) |pair| {
        if (pair.name.len == 0 or
            std.mem.indexOfScalar(u8, pair.name, '=') != null or
            std.mem.indexOfScalar(u8, pair.name, 0) != null or
            std.mem.indexOfScalar(u8, pair.value, 0) != null or
            pair.name.len + 1 + pair.value.len > Limits.maximum_environment_line_bytes)
        {
            return fail("unsafe fixture environment entry: {s}", .{pair.name});
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
    const entries = try listDirectorySorted(allocator, io, path);
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
    return fail("published direct-dpkg observation is architecture-specific: requested={s}", .{architecture});
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
        return fail("arm64 architecture differences are not canonical", .{});
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

pub fn fileFact(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    name: []const u8,
    maximum: usize,
) !std.json.Value {
    const data = try readRegular(allocator, io, path, maximum);
    defer allocator.free(data);
    const metadata = try lstatPath(allocator, path);
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "gid", .{ .integer = @intCast(metadata.gid) });
    try obj.put(allocator, "mode", .{ .string = try std.fmt.allocPrint(allocator, "{o:0>4}", .{metadata.mode & 0o7777}) });
    try obj.put(allocator, "name", .{ .string = try allocator.dupe(u8, name) });
    try obj.put(allocator, "sha256", .{ .string = try sha256HexAlloc(allocator, data) });
    try obj.put(allocator, "size", .{ .integer = @intCast(data.len) });
    try obj.put(allocator, "uid", .{ .integer = @intCast(metadata.uid) });
    return .{ .object = obj };
}

pub fn directoryFacts(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    allowed_names: ?[]const []const u8,
    prefix: ?[]const u8,
) !std.json.Value {
    const metadata = lstatPath(allocator, path) catch |err| switch (err) {
        error.FileNotFound => return .{ .array = .init(allocator) },
        else => return err,
    };
    if ((metadata.mode & linux.S.IFMT) != linux.S.IFDIR) {
        return fail("observed fixture path is not a real directory: {s}", .{path});
    }
    const entries = try listDirectorySorted(allocator, io, path);
    var selected: std.json.Array = .init(allocator);
    var total: usize = 0;
    for (entries) |entry_name| {
        const entry_path = try std.fs.path.join(allocator, &.{ path, entry_name });
        var name: []const u8 = entry_name;
        if (prefix) |pfx| {
            if (std.mem.eql(u8, entry_name, "format")) {
                const fmt_bytes = try readRegular(allocator, io, entry_path, 16);
                if (!std.mem.eql(u8, fmt_bytes, "1\n")) {
                    return fail("dpkg info format marker changed", .{});
                }
                continue;
            }
            if (!std.mem.startsWith(u8, entry_name, pfx)) {
                return fail("ambient package info entry entered fixture: {s}", .{entry_name});
            }
            name = entry_name[pfx.len..];
        }
        if (name.len == 0 or std.mem.indexOfScalar(u8, name, '/') != null) {
            return fail("unexpected observed fixture member: {s}", .{entry_name});
        }
        for (name) |byte| {
            if (byte < 0x20 or byte == 0x7F) {
                return fail("unexpected observed fixture member: {s}", .{entry_name});
            }
        }
        if (allowed_names) |allowed| {
            var found = false;
            for (allowed) |candidate| {
                if (std.mem.eql(u8, candidate, name)) {
                    found = true;
                    break;
                }
            }
            if (!found) return fail("unexpected observed fixture member: {s}", .{entry_name});
        }
        const fact = try fileFact(allocator, io, entry_path, name, Limits.maximum_file_bytes);
        total += @intCast(fact.object.get("size").?.integer);
        if (total > Limits.maximum_info_bytes) {
            return fail("observed package info bytes exceed their aggregate limit", .{});
        }
        try selected.append(fact);
    }
    if (selected.items.len > Limits.maximum_info_files) {
        return fail("observed package info count exceeds its limit", .{});
    }
    return .{ .array = selected };
}

pub fn archiveFact(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Value {
    const data = try readRegular(allocator, io, path, Limits.maximum_archive_bytes);
    defer allocator.free(data);
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "sha256", .{ .string = try sha256HexAlloc(allocator, data) });
    try obj.put(allocator, "size", .{ .integer = @intCast(data.len) });
    return .{ .object = obj };
}

pub fn packageInput(
    allocator: std.mem.Allocator,
    io: std.Io,
    archive: []const u8,
    source_dir: []const u8,
    identity: []const u8,
    version: []const u8,
) !std.json.Value {
    const debian_dir = try std.fs.path.join(allocator, &.{ source_dir, "DEBIAN" });
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "archive", try archiveFact(allocator, io, archive));
    try obj.put(allocator, "control", try directoryFacts(allocator, io, debian_dir, &control_names, null));
    try obj.put(allocator, "identity", .{ .string = try allocator.dupe(u8, identity) });
    try obj.put(allocator, "version", .{ .string = try allocator.dupe(u8, version) });
    return .{ .object = obj };
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
            const full_z = try dupeZ(allocator, full_path);
            defer allocator.free(full_z);
            var link_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const rc = linux.readlinkat(linux.AT.FDCWD, full_z.ptr, &link_buf, link_buf.len);
            if (errnoFailed(rc)) return fail("readlink failed on {s}", .{full_path});
            const target = link_buf[0..rc];
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

pub const MakePackageOptions = struct {
    package: []const u8 = package_name,
    feature: []const u8 = "data",
    conffile_content: []const u8 = "package configuration\n",
    scripts: []const ScriptEntry = &.{},
    config_body: ?[]const u8 = null,
};

pub fn makePackage(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace: []const u8,
    architecture: []const u8,
    version: []const u8,
    options: MakePackageOptions,
) !struct { archive: []u8, source: []u8 } {
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

    if (std.mem.eql(u8, options.feature, "conffile")) {
        try writeRegular(
            allocator,
            io,
            try std.fs.path.join(allocator, &.{ source, "etc/debz-native.conf" }),
            options.conffile_content,
            0o644,
        );
        try writeRegular(
            allocator,
            io,
            try std.fs.path.join(allocator, &.{ source, "DEBIAN/conffiles" }),
            "/etc/debz-native.conf\n",
            0o644,
        );
    } else if (!std.mem.eql(u8, options.feature, "data")) {
        return fail("unknown fixture feature: {s}", .{options.feature});
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

    if (options.config_body) |body| {
        try prepareControl(allocator, io, source, body);
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
    return .{ .archive = destination, .source = source };
}

pub fn configBody(
    allocator: std.mem.Allocator,
    token: []const u8,
    exit_code: u8,
    invalid_interpreter: bool,
) ![]u8 {
    if (!inList(&tokens, token) or exit_code < 1 or exit_code > 125) {
        return fail("invalid synthetic config identity", .{});
    }
    const interpreter = if (invalid_interpreter)
        try std.fmt.allocPrint(allocator, "#!/nonexistent-debz-config-{s}", .{token})
    else
        try allocator.dupe(u8, "#!/bin/sh");
    defer allocator.free(interpreter);
    return std.fmt.allocPrint(
        allocator,
        \\{s}
        \\# identity:{s}
        \\printf '%s\t%s\t%d' 'config@{s}' "$0" "$#" >> /{s}
        \\for argument do
        \\    printf '\t%d:%s' "${{#argument}}" "$argument" >> /{s}
        \\done
        \\printf '\tcwd=%s\n' "$PWD" >> /{s}
        \\/oracle-env >> /{s}
        \\exit {d}
        \\
    ,
        .{
            interpreter,
            token,
            token,
            config_invocations_relative,
            config_invocations_relative,
            config_invocations_relative,
            config_invocations_relative,
            exit_code,
        },
    );
}

pub fn vendorConfigBody(
    allocator: std.mem.Allocator,
    package: []const u8,
    size: usize,
    exit_code: u8,
) ![]u8 {
    if (!isIdentityName(package) or size > Limits.maximum_file_bytes) {
        return fail("invalid pinned vendor config fixture", .{});
    }
    const prefix = try std.fmt.allocPrint(
        allocator,
        \\#!/bin/sh
        \\# identity:{s}
        \\echo {s}:"$*" >> /{s}
        \\exit {d}
        \\
    ,
        .{ package, package, vendor_config_invocations_relative, exit_code },
    );
    defer allocator.free(prefix);
    if (prefix.len > size) {
        return fail("vendor config fixture does not fit pinned size: {s}", .{package});
    }
    const body = try allocator.alloc(u8, size);
    @memcpy(body[0..prefix.len], prefix);
    @memset(body[prefix.len..], '#');
    return body;
}

pub fn maintainerScripts(allocator: std.mem.Allocator, token: []const u8) ![]ScriptEntry {
    if (!inList(&tokens, token)) {
        return fail("invalid maintainer-script identity", .{});
    }
    var result = try allocator.alloc(ScriptEntry, script_kinds.len);
    for (script_kinds, 0..) |kind, idx| {
        const body = try std.fmt.allocPrint(
            allocator,
            \\#!/bin/sh
            \\read_config_identity() {{
            \\    path="$1"
            \\    value='<absent>'
            \\    if [ -f "$path" ]; then
            \\        marker=''
            \\        {{ IFS= read -r ignored; IFS= read -r marker; }} < "$path"
            \\        case "$marker" in
            \\            '# identity:'*) value="${{marker#*:}}" ;;
            \\            *) value='<invalid>' ;;
            \\        esac
            \\    fi
            \\    printf '%s' "$value"
            \\}}
            \\
            \\fds=''
            \\for fd in 0 1 2 3 4 5 6 7 8 9; do
            \\    if ( eval ": <&$fd" ) 2>> /{s}; then
            \\        if [ -n "$fds" ]; then fds="$fds,"; fi
            \\        fds="$fds$fd"
            \\    fi
            \\done
            \\
            \\printf '%s\t%d' '{s}@{s}' "$#" >> /{s}
            \\for argument do
            \\    printf '\t%d:%s' "${{#argument}}" "$argument" >> /{s}
            \\done
            \\printf '\tinfo=%s\tstaging=%s\tcwd=%s\tfds=%s\n'     "$(read_config_identity /var/lib/dpkg/info/{s}.config)"     "$(read_config_identity /var/lib/dpkg/tmp.ci/config)" "$PWD" "$fds" >> /{s}
            \\
            \\printf 'BEGIN\t%s\n' '{s}@{s}' >> /{s}
            \\SHLVL=1 _=/oracle-env /oracle-env >> /{s}
            \\printf 'END\n' >> /{s}
            \\
            \\if [ -f /{s} ]; then
            \\    while IFS= read -r failure; do
            \\        if [ "$failure" = "{s}:{s}:$1" ]; then
            \\            exit 23
            \\        fi
            \\    done < /{s}
            \\fi
            \\
            \\if [ -f /{s} ]; then
            \\    IFS= read -r selected < /{s}
            \\    if [ "$selected" = "{s}:{s}:$1" ]; then
            \\        printf '%s\n' "$selected" > /{s}
            \\        index=0
            \\        while [ "$index" -lt {d} ]; do
            \\            /oracle-sleep 1
            \\            index=$((index + 1))
            \\        done
            \\        exit 24
            \\    fi
            \\fi
            \\exit 0
            \\
        ,
            .{
                fd_errors_relative,
                kind,
                token,
                trace_relative,
                trace_relative,
                package_name,
                trace_relative,
                kind,
                token,
                env_trace_relative,
                env_trace_relative,
                env_trace_relative,
                failures_relative,
                token,
                kind,
                failures_relative,
                pause_relative,
                pause_relative,
                token,
                kind,
                paused_relative,
                Limits.pause_script_timeout_seconds,
            },
        );
        result[idx] = .{ .kind = kind, .body = body };
    }
    return result;
}

pub fn prepareControl(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: []const u8,
    body: []const u8,
) !void {
    const config_path = try std.fs.path.join(allocator, &.{ source, "DEBIAN/config" });
    defer allocator.free(config_path);
    try writeRegular(allocator, io, config_path, body, 0o755);
}

pub const LifecyclePackages = struct {
    v1_archive: []const u8,
    v1r_archive: []const u8,
    v2_archive: []const u8,
    v1_body: []const u8,
    v1r_body: []const u8,
    v2_body: []const u8,
    inputs: std.json.Value,

    pub fn bodyFor(self: LifecyclePackages, token: []const u8) ![]const u8 {
        if (std.mem.eql(u8, token, "v1")) return self.v1_body;
        if (std.mem.eql(u8, token, "v1r")) return self.v1r_body;
        if (std.mem.eql(u8, token, "v2")) return self.v2_body;
        return fail("unknown config token: {s}", .{token});
    }
};

pub fn makeLifecyclePackages(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace: []const u8,
    architecture: []const u8,
) !LifecyclePackages {
    const v1_body = try configBody(allocator, "v1", 91, false);
    const v1r_body = try configBody(allocator, "v1r", 92, false);
    const v2_body = try configBody(allocator, "v2", 93, true);

    const specs = [_]struct {
        token: []const u8,
        version: []const u8,
        body: []const u8,
    }{
        .{ .token = "v1", .version = "1", .body = v1_body },
        .{ .token = "v1r", .version = "1", .body = v1r_body },
        .{ .token = "v2", .version = "2", .body = v2_body },
    };

    var archives: [3][]const u8 = undefined;
    var inputs: std.json.Array = .init(allocator);
    for (specs, 0..) |spec, idx| {
        const pkg_ws = try std.fs.path.join(allocator, &.{ workspace, try std.fmt.allocPrint(allocator, "package-{s}", .{spec.token}) });
        const scripts = try maintainerScripts(allocator, spec.token);
        const built = try makePackage(allocator, io, pkg_ws, architecture, spec.version, .{
            .package = package_name,
            .feature = "conffile",
            .scripts = scripts,
            .config_body = spec.body,
        });
        try validateControlTree(allocator, io, built.source);
        archives[idx] = built.archive;
        try inputs.append(try packageInput(allocator, io, built.archive, built.source, spec.token, spec.version));
    }

    return .{
        .v1_archive = archives[0],
        .v1r_archive = archives[1],
        .v2_archive = archives[2],
        .v1_body = v1_body,
        .v1r_body = v1r_body,
        .v2_body = v2_body,
        .inputs = .{ .array = inputs },
    };
}

pub const VendorPackages = struct {
    archives: [][]const u8,
    packages: [][]const u8,
    bodies: [][]const u8,
    inputs: std.json.Value,
};

pub fn makeVendorPackages(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace: []const u8,
    architecture: []const u8,
    members: []const std.json.Value,
) !VendorPackages {
    if (members.len > Limits.maximum_packages) {
        return fail("vendor config package count exceeds its limit", .{});
    }
    var archives = try allocator.alloc([]const u8, members.len);
    var packages = try allocator.alloc([]const u8, members.len);
    var bodies = try allocator.alloc([]const u8, members.len);
    var inputs: std.json.Array = .init(allocator);

    for (members, 0..) |member, index| {
        const pkg = member.object.get("owner").?.object.get("package").?.string;
        const fact = member.object.get("architectures").?.object.get(architecture).?.object;
        const size: usize = @intCast(fact.get("size").?.integer);
        const body = try vendorConfigBody(allocator, pkg, size, @intCast(70 + index));
        const pkg_ws = try std.fs.path.join(allocator, &.{ workspace, try std.fmt.allocPrint(allocator, "vendor-{s}", .{pkg}) });
        const built = try makePackage(allocator, io, pkg_ws, architecture, "1", .{
            .package = pkg,
            .feature = "data",
            .config_body = body,
        });
        try validateControlTree(allocator, io, built.source);
        archives[index] = built.archive;
        packages[index] = pkg;
        bodies[index] = body;
        try inputs.append(try packageInput(allocator, io, built.archive, built.source, pkg, "1"));
    }

    return .{
        .archives = archives,
        .packages = packages,
        .bodies = bodies,
        .inputs = .{ .array = inputs },
    };
}

fn boundedLog(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    const data = try readRegular(allocator, io, path, Limits.maximum_log_bytes);
    allocator.free(data);
}

pub const HostFileSignature = struct {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
};

pub fn hostFileSignature(allocator: std.mem.Allocator, path: []const u8) !?HostFileSignature {
    const meta = lstatPath(allocator, path) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if ((meta.mode & linux.S.IFMT) != linux.S.IFREG) {
        return fail("host observation path is not a regular file: {s}", .{path});
    }
    return .{
        .dev = meta.dev,
        .ino = meta.ino,
        .size = meta.size,
        .mtime_sec = meta.mtime_sec,
        .mtime_nsec = meta.mtime_nsec,
    };
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
    new_session: bool,
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
        if (new_session) {
            _ = linux.setsid();
        }
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

pub fn runDpkg(
    ctx: Context,
    executable: []const u8,
    root: []const u8,
    arguments: []const []const u8,
    environment: []const EnvPair,
    log_path: []const u8,
) !u8 {
    const command = try ctx.directDpkgCommand(executable, root, arguments);
    const pid = try spawnChildProcess(ctx.allocator, ctx.io, command, environment, log_path, true);
    var status: i32 = 0;
    const deadline_ms = Limits.subprocess_timeout_seconds * 1000;
    var elapsed_ms: i64 = 0;
    while (true) {
        const wrc = linux.wait4(pid, &status, linux.W.NOHANG, null);
        if (linux.errno(wrc) == .INTR) continue;
        if (errnoFailed(wrc)) return fail("wait4 failed", .{});
        if (wrc != 0) break;
        if (elapsed_ms >= deadline_ms) {
            _ = linux.kill(-pid, .KILL);
            _ = linux.wait4(pid, &status, 0, null);
            return fail("direct dpkg timed out: {s}", .{log_path});
        }
        sleepMillis(10);
        elapsed_ms += 10;
    }
    try boundedLog(ctx.allocator, ctx.io, log_path);
    const dpkg_log_path = try std.fs.path.join(ctx.allocator, &.{ root, dpkg_log_relative });
    try boundedLog(ctx.allocator, ctx.io, dpkg_log_path);
    const status_word: u32 = @bitCast(status);
    if (!linux.W.IFEXITED(status_word)) {
        return fail("direct dpkg exited unexpectedly; {s}", .{log_path});
    }
    const code = linux.W.EXITSTATUS(status_word);
    if (code != 0 and code != 1) {
        return fail("direct dpkg exited unexpectedly: {d}; {s}", .{ code, log_path });
    }
    return code;
}

pub fn interruptDpkg(
    ctx: Context,
    executable: []const u8,
    root: []const u8,
    arguments: []const []const u8,
    selected: []const u8,
    environment: []const EnvPair,
    log_path: []const u8,
) !void {
    const pause_path = try std.fs.path.join(ctx.allocator, &.{ root, pause_relative });
    const paused_path = try std.fs.path.join(ctx.allocator, &.{ root, paused_relative });
    try writeRegular(
        ctx.allocator,
        ctx.io,
        pause_path,
        try std.fmt.allocPrint(ctx.allocator, "{s}\n", .{selected}),
        0o600,
    );
    const command = try ctx.directDpkgCommand(executable, root, arguments);
    const pid = try spawnChildProcess(ctx.allocator, ctx.io, command, environment, log_path, true);
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
            return fail("dpkg exited before the selected interruption: {s}", .{selected});
        }
        sleepMillis(50);
        elapsed_ms += 50;
    }
    if (!reached) {
        _ = linux.kill(-pid, .KILL);
        _ = linux.wait4(pid, &status, 0, null);
        return fail("dpkg did not reach the selected interruption: {s}", .{selected});
    }
    _ = linux.kill(-pid, .KILL);
    while (true) {
        const wrc = linux.wait4(pid, &status, 0, null);
        if (linux.errno(wrc) == .INTR) continue;
        if (errnoFailed(wrc)) return fail("wait4 failed after SIGKILL", .{});
        break;
    }
    try boundedLog(ctx.allocator, ctx.io, log_path);
    const dpkg_log_path = try std.fs.path.join(ctx.allocator, &.{ root, dpkg_log_relative });
    try boundedLog(ctx.allocator, ctx.io, dpkg_log_path);

    const pause_z = try dupeZ(ctx.allocator, pause_path);
    const paused_z = try dupeZ(ctx.allocator, paused_path);
    _ = linux.unlinkat(linux.AT.FDCWD, pause_z.ptr, 0);
    _ = linux.unlinkat(linux.AT.FDCWD, paused_z.ptr, 0);

    const status_word: u32 = @bitCast(status);
    if (!linux.W.IFSIGNALED(status_word) or linux.W.TERMSIG(status_word) != .KILL) {
        return fail("interrupted dpkg returned unexpectedly", .{});
    }
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
    const entries = try listDirectorySorted(allocator, io, updates_dir);
    if (entries.len > Limits.maximum_updates) {
        return fail("dpkg update journal exceeds its entry limit", .{});
    }
    var numeric: std.ArrayList(Deb822Record) = .empty;
    var temporary = false;
    for (entries) |entry_name| {
        const entry_path = try std.fs.path.join(allocator, &.{ updates_dir, entry_name });
        const meta = try lstatPath(allocator, entry_path);
        if ((meta.mode & linux.S.IFMT) != linux.S.IFREG) {
            return fail("dpkg update entry is not regular: {s}", .{entry_name});
        }
        if (std.mem.eql(u8, entry_name, "tmp.i")) {
            const tmp_bytes = try readRegular(allocator, io, entry_path, Limits.maximum_status_bytes);
            allocator.free(tmp_bytes);
            temporary = true;
        } else if (isUpdateName(entry_name)) {
            const upd_bytes = try readRegular(allocator, io, entry_path, Limits.maximum_status_bytes);
            const label = try std.fmt.allocPrint(allocator, "updates/{s}", .{entry_name});
            if (try packageRecord(allocator, upd_bytes, package, label)) |rec| {
                try numeric.append(allocator, rec);
            }
        } else {
            return fail("unexpected dpkg update entry: {s}", .{entry_name});
        }
    }

    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "committed", try summarizeRecord(allocator, committed));
    try obj.put(
        allocator,
        "journal_latest",
        if (numeric.items.len != 0)
            try summarizeRecord(allocator, numeric.items[numeric.items.len - 1])
        else
            .null,
    );
    try obj.put(allocator, "journal_nonempty", .{ .bool = numeric.items.len != 0 });
    try obj.put(allocator, "temporary_update", .{ .bool = temporary });
    return .{ .object = obj };
}

pub fn configIdentity(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !?[]const u8 {
    const data = (try optionalRegular(allocator, io, path, Limits.maximum_file_bytes)) orelse return null;
    var lines = std.mem.splitScalar(u8, data, '\n');
    _ = lines.next();
    const second_raw = lines.next() orelse return fail("config member lacks a fixture identity: {s}", .{path});
    const second = if (std.mem.endsWith(u8, second_raw, "\r")) second_raw[0 .. second_raw.len - 1] else second_raw;
    const prefix = "# identity:";
    if (!std.mem.startsWith(u8, second, prefix)) {
        return fail("config member lacks a fixture identity: {s}", .{path});
    }
    return try allocator.dupe(u8, second[prefix.len..]);
}

pub fn assertConfig(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    expected: ?[]const u8,
    staging: ?[]const u8,
    packages: LifecyclePackages,
) !void {
    const info_path = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg/info/" ++ package_name ++ ".config" });
    const temp_path = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg/tmp.ci/config" });
    const actual_info = try configIdentity(allocator, io, info_path);
    const actual_staging = try configIdentity(allocator, io, temp_path);
    const info_matches = if (expected) |exp| (actual_info != null and std.mem.eql(u8, actual_info.?, exp)) else actual_info == null;
    const staging_matches = if (staging) |stg| (actual_staging != null and std.mem.eql(u8, actual_staging.?, stg)) else actual_staging == null;
    if (!info_matches or !staging_matches) {
        return fail("wrong config publication", .{});
    }
    const checks = [_]struct { path: []const u8, identity: ?[]const u8 }{
        .{ .path = info_path, .identity = expected },
        .{ .path = temp_path, .identity = staging },
    };
    for (checks) |check| {
        if (check.identity) |ident| {
            const data = try readRegular(allocator, io, check.path, Limits.maximum_file_bytes);
            const meta = try lstatPath(allocator, check.path);
            const expected_body = try packages.bodyFor(ident);
            if (!std.mem.eql(u8, data, expected_body) or
                (meta.mode & 0o7777) != 0o755 or
                meta.uid != 0 or
                meta.gid != 0)
            {
                return fail("config bytes, mode, or ownership changed: {s}", .{check.path});
            }
        } else {
            if (try lexistsPath(allocator, check.path)) {
                return fail("unexpected config path remains: {s}", .{check.path});
            }
        }
    }
}

pub fn packageInfoFacts(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    package: []const u8,
) !std.json.Value {
    if (!isIdentityName(package)) {
        return fail("invalid package identity for info capture: {s}", .{package});
    }
    const info_dir = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg/info" });
    const pfx = try std.fmt.allocPrint(allocator, "{s}.", .{package});
    return directoryFacts(allocator, io, info_dir, null, pfx);
}

pub fn cohortInfoFacts(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    packages: []const []const u8,
) !std.StringArrayHashMapUnmanaged(std.json.Value) {
    var result: std.StringArrayHashMapUnmanaged(std.json.Value) = .empty;
    for (packages) |pkg| {
        try result.put(allocator, pkg, .{ .array = .init(allocator) });
    }
    const info_dir = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg/info" });
    const meta = lstatPath(allocator, info_dir) catch {
        return fail("dpkg info path is not a real directory", .{});
    };
    if ((meta.mode & linux.S.IFMT) != linux.S.IFDIR) {
        return fail("dpkg info path is not a real directory", .{});
    }
    const entries = try listDirectorySorted(allocator, io, info_dir);
    var total_bytes: usize = 0;
    var total_files: usize = 0;
    for (entries) |entry_name| {
        const entry_path = try std.fs.path.join(allocator, &.{ info_dir, entry_name });
        if (std.mem.eql(u8, entry_name, "format")) {
            const fmt = try readRegular(allocator, io, entry_path, 16);
            if (!std.mem.eql(u8, fmt, "1\n")) {
                return fail("dpkg info format marker changed", .{});
            }
            continue;
        }
        var matched_pkg: ?[]const u8 = null;
        var matched_pfx_len: usize = 0;
        for (packages) |pkg| {
            const pfx = try std.fmt.allocPrint(allocator, "{s}.", .{pkg});
            if (std.mem.startsWith(u8, entry_name, pfx)) {
                if (matched_pkg != null) {
                    return fail("ambient package info entry entered fixture: {s}", .{entry_name});
                }
                matched_pkg = pkg;
                matched_pfx_len = pfx.len;
            }
        }
        const pkg = matched_pkg orelse return fail("ambient package info entry entered fixture: {s}", .{entry_name});
        const fact = try fileFact(allocator, io, entry_path, entry_name[matched_pfx_len..], Limits.maximum_file_bytes);
        total_bytes += @intCast(fact.object.get("size").?.integer);
        if (total_bytes > Limits.maximum_info_bytes) {
            return fail("vendor cohort info bytes exceed their aggregate limit", .{});
        }
        total_files += 1;
        try result.getPtr(pkg).?.array.append(fact);
    }
    if (total_files > Limits.maximum_info_files) {
        return fail("vendor cohort info count exceeds its limit", .{});
    }
    return result;
}

pub fn filesystemState(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "info", try packageInfoFacts(allocator, io, root, package_name));
    const staging_dir = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg/tmp.ci" });
    try obj.put(allocator, "staging", try directoryFacts(allocator, io, staging_dir, &control_names, null));
    return .{ .object = obj };
}

pub fn assertNoConfigInvocation(allocator: std.mem.Allocator, io: std.Io, root: []const u8) !void {
    for ([_][]const u8{ config_invocations_relative, vendor_config_invocations_relative }) |relative| {
        const path = try std.fs.path.join(allocator, &.{ root, relative });
        if (try optionalRegular(allocator, io, path, Limits.maximum_trace_bytes)) |bytes| {
            defer allocator.free(bytes);
            if (bytes.len != 0) {
                return fail("direct dpkg invoked a config script: {s}", .{relative});
            }
        }
    }
}

pub const TraceRecord = struct {
    script: []const u8,
    arguments: []const []const u8,
    info_config: ?[]const u8,
    staging_config: ?[]const u8,
};

pub fn parseTrace(allocator: std.mem.Allocator, io: std.Io, root: []const u8) ![]TraceRecord {
    const trace_path = try std.fs.path.join(allocator, &.{ root, trace_relative });
    const raw = (try optionalRegular(allocator, io, trace_path, Limits.maximum_trace_bytes)) orelse return &.{};
    if (!std.unicode.utf8ValidateSlice(raw)) {
        return fail("maintainer-script trace is not UTF-8", .{});
    }
    const trimmed = if (std.mem.endsWith(u8, raw, "\n")) raw[0 .. raw.len - 1] else raw;
    if (trimmed.len == 0) return &.{};

    var records: std.ArrayList(TraceRecord) = .empty;
    var lines = std.mem.splitScalar(u8, trimmed, '\n');
    while (lines.next()) |raw_line| {
        const line = if (std.mem.endsWith(u8, raw_line, "\r")) raw_line[0 .. raw_line.len - 1] else raw_line;
        if (records.items.len >= Limits.maximum_trace_records) {
            return fail("maintainer-script trace exceeds its record limit", .{});
        }
        var fields: std.ArrayList([]const u8) = .empty;
        var field_it = std.mem.splitScalar(u8, line, '\t');
        while (field_it.next()) |f| try fields.append(allocator, f);
        if (fields.items.len < 6) {
            return fail("malformed maintainer-script trace: {s}", .{line});
        }
        const script = fields.items[0];
        const count = std.fmt.parseInt(usize, fields.items[1], 10) catch {
            return fail("invalid maintainer-script argument count", .{});
        };
        if (count > Limits.maximum_arguments or fields.items.len != count + 6) {
            return fail("maintainer-script argument bounds changed", .{});
        }
        var arguments = try allocator.alloc([]const u8, count);
        for (fields.items[2 .. 2 + count], 0..) |field, idx| {
            const colon = std.mem.indexOfScalar(u8, field, ':') orelse {
                return fail("malformed length-prefixed maintainer-script argument", .{});
            };
            const len_str = field[0..colon];
            if (len_str.len == 0) return fail("malformed length-prefixed maintainer-script argument", .{});
            for (len_str) |ch| if (!std.ascii.isDigit(ch)) {
                return fail("malformed length-prefixed maintainer-script argument", .{});
            };
            const expected_len = std.fmt.parseInt(usize, len_str, 10) catch {
                return fail("malformed length-prefixed maintainer-script argument", .{});
            };
            const value = field[colon + 1 ..];
            if (value.len != expected_len or value.len > Limits.maximum_argument_bytes) {
                return fail("maintainer-script argument length changed", .{});
            }
            arguments[idx] = try allocator.dupe(u8, value);
        }
        var info_val: ?[]const u8 = null;
        var staging_val: ?[]const u8 = null;
        var cwd_val: ?[]const u8 = null;
        var fds_val: ?[]const u8 = null;
        for (fields.items[2 + count ..]) |attr_field| {
            const eq = std.mem.indexOfScalar(u8, attr_field, '=') orelse {
                return fail("malformed maintainer-script trace attributes", .{});
            };
            const key = attr_field[0..eq];
            const val = attr_field[eq + 1 ..];
            if (std.mem.eql(u8, key, "info")) {
                if (info_val != null) return fail("malformed maintainer-script trace attributes", .{});
                info_val = val;
            } else if (std.mem.eql(u8, key, "staging")) {
                if (staging_val != null) return fail("malformed maintainer-script trace attributes", .{});
                staging_val = val;
            } else if (std.mem.eql(u8, key, "cwd")) {
                if (cwd_val != null) return fail("malformed maintainer-script trace attributes", .{});
                cwd_val = val;
            } else if (std.mem.eql(u8, key, "fds")) {
                if (fds_val != null) return fail("malformed maintainer-script trace attributes", .{});
                fds_val = val;
            } else {
                return fail("maintainer-script trace attribute set changed", .{});
            }
        }
        if (info_val == null or staging_val == null or cwd_val == null or fds_val == null) {
            return fail("maintainer-script trace attribute set changed", .{});
        }
        if (!std.mem.eql(u8, cwd_val.?, "/") or !std.mem.eql(u8, fds_val.?, "0,1,2")) {
            return fail("maintainer-script cwd/fd contract changed", .{});
        }
        try records.append(allocator, .{
            .script = try allocator.dupe(u8, script),
            .arguments = arguments,
            .info_config = if (std.mem.eql(u8, info_val.?, "<absent>")) null else try allocator.dupe(u8, info_val.?),
            .staging_config = if (std.mem.eql(u8, staging_val.?, "<absent>")) null else try allocator.dupe(u8, staging_val.?),
        });
    }

    const fd_errors_path = try std.fs.path.join(allocator, &.{ root, fd_errors_relative });
    if (try optionalRegular(allocator, io, fd_errors_path, Limits.maximum_trace_bytes)) |err_bytes| {
        allocator.free(err_bytes);
    }
    return records.toOwnedSlice(allocator);
}

fn validateEnvironmentTrace(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    trace: []const TraceRecord,
    workspace: []const u8,
    architecture: []const u8,
) !void {
    const env_path = try std.fs.path.join(allocator, &.{ root, env_trace_relative });
    const raw = (try optionalRegular(allocator, io, env_path, Limits.maximum_trace_bytes)) orelse {
        if (trace.len != 0) {
            return fail("maintainer scripts ran without environment evidence", .{});
        }
        return;
    };
    if (!std.unicode.utf8ValidateSlice(raw)) {
        return fail("environment trace is not UTF-8", .{});
    }
    const trimmed = if (std.mem.endsWith(u8, raw, "\n")) raw[0 .. raw.len - 1] else raw;
    var lines: std.ArrayList([]const u8) = .empty;
    if (trimmed.len != 0) {
        var line_it = std.mem.splitScalar(u8, trimmed, '\n');
        while (line_it.next()) |raw_line| {
            const l = if (std.mem.endsWith(u8, raw_line, "\r")) raw_line[0 .. raw_line.len - 1] else raw_line;
            try lines.append(allocator, l);
        }
    }

    const home = try std.fs.path.join(allocator, &.{ workspace, "home" });
    const tmp = try std.fs.path.join(allocator, &.{ workspace, "tmp" });

    var index: usize = 0;
    var record_count: usize = 0;
    while (index < lines.items.len) {
        const header = lines.items[index];
        if (!std.mem.startsWith(u8, header, "BEGIN\t")) {
            return fail("malformed environment trace header", .{});
        }
        const identity = header["BEGIN\t".len..];
        if (std.mem.indexOfScalar(u8, identity, '\t') != null) {
            return fail("malformed environment trace header", .{});
        }
        const at = std.mem.indexOfScalar(u8, identity, '@') orelse {
            return fail("invalid script environment identity: {s}", .{identity});
        };
        const kind = identity[0..at];
        if (!inList(&script_kinds, kind)) {
            return fail("invalid script environment identity: {s}", .{identity});
        }
        if (record_count >= trace.len or !std.mem.eql(u8, identity, trace[record_count].script)) {
            return fail("environment evidence is not ordered with script evidence", .{});
        }
        index += 1;
        var values: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
        while (index < lines.items.len and !std.mem.eql(u8, lines.items[index], "END")) {
            const line = lines.items[index];
            if (line.len > Limits.maximum_environment_line_bytes) {
                return fail("environment trace line exceeds its byte limit", .{});
            }
            const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
                return fail("malformed environment trace entry", .{});
            };
            const name = line[0..eq];
            const val = line[eq + 1 ..];
            if (name.len == 0 or values.contains(name)) {
                return fail("malformed environment trace entry", .{});
            }
            try values.put(allocator, name, val);
            if (values.count() > Limits.maximum_environment_variables) {
                return fail("environment trace variable count exceeds its limit", .{});
            }
            index += 1;
        }
        if (index >= lines.items.len) {
            return fail("unterminated environment trace", .{});
        }
        index += 1;
        record_count += 1;
        if (record_count > Limits.maximum_environment_records) {
            return fail("environment trace record count exceeds its limit", .{});
        }

        const expected = [_]EnvPair{
            .{ .name = "DPKG_ADMINDIR", .value = "/var/lib/dpkg" },
            .{ .name = "DPKG_FORCE", .value = "security-mac,downgrade,not-root,bad-path" },
            .{ .name = "DPKG_MAINTSCRIPT_ARCH", .value = architecture },
            .{ .name = "DPKG_MAINTSCRIPT_DEBUG", .value = "0" },
            .{ .name = "DPKG_MAINTSCRIPT_NAME", .value = kind },
            .{ .name = "DPKG_MAINTSCRIPT_PACKAGE", .value = package_name },
            .{ .name = "DPKG_MAINTSCRIPT_PACKAGE_REFCOUNT", .value = "1" },
            .{ .name = "DPKG_ROOT", .value = "" },
            .{ .name = "DPKG_RUNNING_VERSION", .value = "1.22.22" },
            .{ .name = "HOME", .value = home },
            .{ .name = "LANG", .value = "C" },
            .{ .name = "LC_ALL", .value = "C" },
            .{ .name = "PATH", .value = "/usr/sbin:/usr/bin:/sbin:/bin" },
            .{ .name = "PWD", .value = "/" },
            .{ .name = "SHLVL", .value = "1" },
            .{ .name = "SOURCE_DATE_EPOCH", .value = "1700000000" },
            .{ .name = "TMPDIR", .value = tmp },
            .{ .name = "_", .value = "/oracle-env" },
        };
        if (values.count() != expected.len) {
            return fail("maintainer-script environment changed for {s}", .{identity});
        }
        for (expected) |exp| {
            const actual = values.get(exp.name) orelse {
                return fail("maintainer-script environment changed for {s}", .{identity});
            };
            if (!std.mem.eql(u8, actual, exp.value)) {
                return fail("maintainer-script environment changed for {s}", .{identity});
            }
        }
    }
    if (record_count != trace.len) {
        return fail("environment evidence is not ordered with script evidence", .{});
    }
}

fn validateInstrumentation(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    workspace: []const u8,
    architecture: []const u8,
) ![]TraceRecord {
    const trace = try parseTrace(allocator, io, root);
    try validateEnvironmentTrace(allocator, io, root, trace, workspace, architecture);
    try assertNoConfigInvocation(allocator, io, root);
    return trace;
}

pub fn compactTrace(allocator: std.mem.Allocator, trace: []const TraceRecord) !std.json.Value {
    var arr: std.json.Array = .init(allocator);
    for (trace) |item| {
        var args_out: std.Io.Writer.Allocating = .init(allocator);
        var stream: std.json.Stringify = .{
            .writer = &args_out.writer,
            .options = .{ .whitespace = .minified, .escape_unicode = true },
        };
        try stream.beginArray();
        for (item.arguments) |arg| try stream.write(arg);
        try stream.endArray();
        const args_json = try args_out.toOwnedSlice();

        const line = try std.fmt.allocPrint(
            allocator,
            "{s}\t{s}\t{s}\t{s}",
            .{
                item.script,
                args_json,
                item.info_config orelse "-",
                item.staging_config orelse "-",
            },
        );
        try arr.append(.{ .string = line });
    }
    return .{ .array = arr };
}

fn setLines(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    relative: []const u8,
    lines: []const []const u8,
) !void {
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    if (lines.len != 0) {
        const joined = try std.mem.join(allocator, "\n", lines);
        const content = try std.fmt.allocPrint(allocator, "{s}\n", .{joined});
        try writeRegular(allocator, io, path, content, 0o600);
    } else if (try lexistsPath(allocator, path)) {
        const path_z = try dupeZ(allocator, path);
        _ = linux.unlinkat(linux.AT.FDCWD, path_z.ptr, 0);
    }
}

fn effectiveRecord(state: std.json.Value) std.json.Value {
    const jl = state.object.get("journal_latest").?;
    if (jl != .null) return jl;
    return state.object.get("committed").?;
}

const Scenario = struct {
    ctx: Context,
    directory: []const u8,
    root: []const u8,
    workspace: []const u8,
    architecture: []const u8,
    environment: []const EnvPair,
    executable: []const u8,
    index: usize = 0,

    fn init(
        ctx: Context,
        workspace: []const u8,
        name: []const u8,
        architecture: []const u8,
        environment: []const EnvPair,
        executable: []const u8,
    ) !Scenario {
        const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, name });
        try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
        const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
        try ctx.makeRoot(root, architecture, true);
        return .{
            .ctx = ctx,
            .directory = directory,
            .root = root,
            .workspace = workspace,
            .architecture = architecture,
            .environment = environment,
            .executable = executable,
        };
    }

    fn run(
        self: *Scenario,
        operation: []const u8,
        arguments: []const []const u8,
        failures: []const []const u8,
        expected_exit: u8,
    ) !struct { state: std.json.Value, trace: []TraceRecord } {
        const before = (try parseTrace(self.ctx.allocator, self.ctx.io, self.root)).len;
        try setLines(self.ctx.allocator, self.ctx.io, self.root, failures_relative, failures);
        const destination = try std.fs.path.join(
            self.ctx.allocator,
            &.{ self.directory, try std.fmt.allocPrint(self.ctx.allocator, "{d}-{s}.log", .{ self.index, operation }) },
        );
        self.index += 1;
        const observed = try runDpkg(self.ctx, self.executable, self.root, arguments, self.environment, destination);
        if (observed != expected_exit) {
            return fail("{s}/{s}: exit {d}, expected {d}", .{ std.fs.path.basename(self.directory), operation, observed, expected_exit });
        }
        const trace = try validateInstrumentation(
            self.ctx.allocator,
            self.ctx.io,
            self.root,
            self.workspace,
            self.architecture,
        );
        return .{
            .state = try databaseState(self.ctx.allocator, self.ctx.io, self.root, package_name),
            .trace = trace[before..],
        };
    }

    fn interrupt(
        self: *Scenario,
        operation: []const u8,
        arguments: []const []const u8,
        selected: []const u8,
    ) !struct { state: std.json.Value, trace: []TraceRecord } {
        const before = (try parseTrace(self.ctx.allocator, self.ctx.io, self.root)).len;
        try setLines(self.ctx.allocator, self.ctx.io, self.root, failures_relative, &.{});
        const destination = try std.fs.path.join(
            self.ctx.allocator,
            &.{ self.directory, try std.fmt.allocPrint(self.ctx.allocator, "{d}-{s}-interrupted.log", .{ self.index, operation }) },
        );
        self.index += 1;
        try interruptDpkg(self.ctx, self.executable, self.root, arguments, selected, self.environment, destination);
        const trace = try validateInstrumentation(
            self.ctx.allocator,
            self.ctx.io,
            self.root,
            self.workspace,
            self.architecture,
        );
        return .{
            .state = try databaseState(self.ctx.allocator, self.ctx.io, self.root, package_name),
            .trace = trace[before..],
        };
    }
};

fn phaseObservation(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    operation: []const u8,
    state: std.json.Value,
    trace: []const TraceRecord,
    config: ?[]const u8,
) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "database", state);
    try obj.put(allocator, "filesystem", try filesystemState(allocator, io, root));
    try obj.put(allocator, "operation", .{ .string = try allocator.dupe(u8, operation) });
    try obj.put(allocator, "state", effectiveRecord(state));
    try obj.put(allocator, "config", if (config) |c| .{ .string = try allocator.dupe(u8, c) } else .null);
    try obj.put(allocator, "trace", try compactTrace(allocator, trace));
    return .{ .object = obj };
}

fn observeVendorCohort(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    executable: []const u8,
    members: []const std.json.Value,
) !struct { observation: std.json.Value, inputs: std.json.Value } {
    const directory = try std.fs.path.join(ctx.allocator, &.{ workspace, "vendor-cohort" });
    try std.Io.Dir.cwd().createDirPath(ctx.io, directory);
    const pkgs_dir = try std.fs.path.join(ctx.allocator, &.{ directory, "packages" });
    const vendor = try makeVendorPackages(ctx.allocator, ctx.io, pkgs_dir, architecture, members);

    const root = try std.fs.path.join(ctx.allocator, &.{ directory, "root" });
    try ctx.makeRoot(root, architecture, false);

    var install_args: std.ArrayList([]const u8) = .empty;
    try install_args.append(ctx.allocator, "--install");
    try install_args.appendSlice(ctx.allocator, vendor.archives);
    const install_log = try std.fs.path.join(ctx.allocator, &.{ directory, "install.log" });
    const install_exit = try runDpkg(ctx, executable, root, install_args.items, environment, install_log);

    for (vendor.packages, vendor.bodies) |pkg, expected_body| {
        const cfg_path = try std.fs.path.join(
            ctx.allocator,
            &.{ root, try std.fmt.allocPrint(ctx.allocator, "var/lib/dpkg/info/{s}.config", .{pkg}) },
        );
        const data = try readRegular(ctx.allocator, ctx.io, cfg_path, Limits.maximum_file_bytes);
        const meta = try lstatPath(ctx.allocator, cfg_path);
        if (!std.mem.eql(u8, data, expected_body) or
            (meta.mode & 0o7777) != 0o755 or
            meta.uid != 0 or
            meta.gid != 0)
        {
            return fail("vendor identity config was not retained exactly: {s}", .{pkg});
        }
    }

    var installed_info = try cohortInfoFacts(ctx.allocator, ctx.io, root, vendor.packages);
    const status_path = try std.fs.path.join(ctx.allocator, &.{ root, "var/lib/dpkg/status" });
    const installed_status = try readRegular(ctx.allocator, ctx.io, status_path, Limits.maximum_status_bytes);

    var installed_state: std.json.Array = .init(ctx.allocator);
    var installed_identities: std.json.Array = .init(ctx.allocator);
    var remove_args: std.ArrayList([]const u8) = .empty;
    try remove_args.append(ctx.allocator, "--remove");

    for (vendor.packages) |pkg| {
        var entry: std.json.ObjectMap = .empty;
        try entry.put(ctx.allocator, "info", installed_info.get(pkg).?);
        try entry.put(ctx.allocator, "package", .{ .string = pkg });
        try entry.put(
            ctx.allocator,
            "state",
            try summarizeRecord(ctx.allocator, try packageRecord(ctx.allocator, installed_status, pkg, "status")),
        );
        try installed_state.append(.{ .object = entry });
        try installed_identities.append(.{
            .string = try std.fmt.allocPrint(ctx.allocator, "{s}.config", .{pkg}),
        });
        try remove_args.append(
            ctx.allocator,
            try std.fmt.allocPrint(ctx.allocator, "{s}:{s}", .{ pkg, architecture }),
        );
    }

    try assertNoConfigInvocation(ctx.allocator, ctx.io, root);
    const remove_log = try std.fs.path.join(ctx.allocator, &.{ directory, "remove.log" });
    const remove_exit = try runDpkg(ctx, executable, root, remove_args.items, environment, remove_log);

    for (vendor.packages) |pkg| {
        const cfg_path = try std.fs.path.join(
            ctx.allocator,
            &.{ root, try std.fmt.allocPrint(ctx.allocator, "var/lib/dpkg/info/{s}.config", .{pkg}) },
        );
        if (try lexistsPath(ctx.allocator, cfg_path)) {
            return fail("vendor identity config survived successful removal: {s}", .{pkg});
        }
    }

    var removed_info = try cohortInfoFacts(ctx.allocator, ctx.io, root, vendor.packages);
    const removed_status = try readRegular(ctx.allocator, ctx.io, status_path, Limits.maximum_status_bytes);
    try assertNoConfigInvocation(ctx.allocator, ctx.io, root);

    var removed_state: std.json.Array = .init(ctx.allocator);
    for (vendor.packages) |pkg| {
        var entry: std.json.ObjectMap = .empty;
        try entry.put(ctx.allocator, "info", removed_info.get(pkg).?);
        try entry.put(ctx.allocator, "package", .{ .string = pkg });
        try entry.put(
            ctx.allocator,
            "state",
            try summarizeRecord(ctx.allocator, try packageRecord(ctx.allocator, removed_status, pkg, "status")),
        );
        try removed_state.append(.{ .object = entry });
    }

    var obs: std.json.ObjectMap = .empty;
    try obs.put(ctx.allocator, "config_invocation_count", .{ .integer = 0 });
    try obs.put(ctx.allocator, "install_exit", .{ .integer = install_exit });
    try obs.put(ctx.allocator, "installed_identities", .{ .array = installed_identities });
    try obs.put(ctx.allocator, "installed_state", .{ .array = installed_state });
    try obs.put(ctx.allocator, "remove_exit", .{ .integer = remove_exit });
    try obs.put(ctx.allocator, "removed_state", .{ .array = removed_state });
    try obs.put(ctx.allocator, "retained_after_remove", .{ .array = .init(ctx.allocator) });
    return .{ .observation = .{ .object = obs }, .inputs = vendor.inputs };
}

fn observeSuccess(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    executable: []const u8,
    packages: LifecyclePackages,
) !std.json.Value {
    var scenario = try Scenario.init(ctx, workspace, "successful-lifecycle", architecture, environment, executable);
    const pkg_arch = try std.fmt.allocPrint(ctx.allocator, "{s}:{s}", .{ package_name, architecture });
    const steps = [_]struct {
        operation: []const u8,
        args: [2][]const u8,
        expected_config: ?[]const u8,
    }{
        .{ .operation = "install", .args = .{ "--install", packages.v1_archive }, .expected_config = "v1" },
        .{ .operation = "reinstall", .args = .{ "--install", packages.v1r_archive }, .expected_config = "v1r" },
        .{ .operation = "upgrade", .args = .{ "--install", packages.v2_archive }, .expected_config = "v2" },
        .{ .operation = "remove", .args = .{ "--remove", pkg_arch }, .expected_config = null },
        .{ .operation = "purge", .args = .{ "--purge", pkg_arch }, .expected_config = null },
    };
    var observations: std.json.Array = .init(ctx.allocator);
    for (steps) |step| {
        const res = try scenario.run(step.operation, &step.args, &.{}, 0);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, step.expected_config, null, packages);
        try observations.append(
            try phaseObservation(
                ctx.allocator,
                ctx.io,
                scenario.root,
                step.operation,
                res.state,
                res.trace,
                step.expected_config,
            ),
        );
    }
    return .{ .array = observations };
}

fn observeFailures(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    executable: []const u8,
    packages: LifecyclePackages,
) !std.json.Value {
    var results: std.json.Array = .init(ctx.allocator);
    const pkg_arch = try std.fmt.allocPrint(ctx.allocator, "{s}:{s}", .{ package_name, architecture });

    {
        var scenario = try Scenario.init(ctx, workspace, "failure-postinst-fresh", architecture, environment, executable);
        const failed = try scenario.run("install", &.{ "--install", packages.v1_archive }, &.{"v1:postinst:configure"}, 1);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v1", null, packages);
        const failed_fs = try filesystemState(ctx.allocator, ctx.io, scenario.root);
        const retry = try scenario.run("configure", &.{ "--configure", pkg_arch }, &.{}, 0);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v1", null, packages);

        var obj: std.json.ObjectMap = .empty;
        try obj.put(ctx.allocator, "case", .{ .string = "fresh-postinst-failure" });
        try obj.put(ctx.allocator, "failed_database", failed.state);
        try obj.put(ctx.allocator, "failed_state", effectiveRecord(failed.state));
        try obj.put(ctx.allocator, "failed_config", .{ .string = "v1" });
        try obj.put(ctx.allocator, "failed_filesystem", failed_fs);
        try obj.put(ctx.allocator, "failed_trace", try compactTrace(ctx.allocator, failed.trace));
        try obj.put(ctx.allocator, "recovery_database", retry.state);
        try obj.put(ctx.allocator, "recovery_state", effectiveRecord(retry.state));
        try obj.put(ctx.allocator, "recovery_config", .{ .string = "v1" });
        try obj.put(ctx.allocator, "recovery_filesystem", try filesystemState(ctx.allocator, ctx.io, scenario.root));
        try obj.put(ctx.allocator, "recovery_trace", try compactTrace(ctx.allocator, retry.trace));
        try results.append(.{ .object = obj });
    }

    {
        var scenario = try Scenario.init(ctx, workspace, "failure-postinst-upgrade", architecture, environment, executable);
        _ = try scenario.run("seed", &.{ "--install", packages.v1_archive }, &.{}, 0);
        const failed = try scenario.run("upgrade", &.{ "--install", packages.v2_archive }, &.{"v2:postinst:configure"}, 1);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v2", null, packages);
        const failed_fs = try filesystemState(ctx.allocator, ctx.io, scenario.root);
        const retry = try scenario.run("configure", &.{ "--configure", pkg_arch }, &.{}, 0);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v2", null, packages);

        var obj: std.json.ObjectMap = .empty;
        try obj.put(ctx.allocator, "case", .{ .string = "upgrade-postinst-failure" });
        try obj.put(ctx.allocator, "failed_database", failed.state);
        try obj.put(ctx.allocator, "failed_state", effectiveRecord(failed.state));
        try obj.put(ctx.allocator, "failed_config", .{ .string = "v2" });
        try obj.put(ctx.allocator, "failed_filesystem", failed_fs);
        try obj.put(ctx.allocator, "failed_trace", try compactTrace(ctx.allocator, failed.trace));
        try obj.put(ctx.allocator, "recovery_database", retry.state);
        try obj.put(ctx.allocator, "recovery_state", effectiveRecord(retry.state));
        try obj.put(ctx.allocator, "recovery_config", .{ .string = "v2" });
        try obj.put(ctx.allocator, "recovery_filesystem", try filesystemState(ctx.allocator, ctx.io, scenario.root));
        try obj.put(ctx.allocator, "recovery_trace", try compactTrace(ctx.allocator, retry.trace));
        try results.append(.{ .object = obj });
    }

    {
        var scenario = try Scenario.init(ctx, workspace, "failure-preinst-upgrade", architecture, environment, executable);
        _ = try scenario.run("seed", &.{ "--install", packages.v1_archive }, &.{}, 0);
        const failed = try scenario.run("upgrade", &.{ "--install", packages.v2_archive }, &.{"v2:preinst:upgrade"}, 1);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v1", null, packages);

        var obj: std.json.ObjectMap = .empty;
        try obj.put(ctx.allocator, "case", .{ .string = "incoming-preinst-failure" });
        try obj.put(ctx.allocator, "failed_database", failed.state);
        try obj.put(ctx.allocator, "failed_state", effectiveRecord(failed.state));
        try obj.put(ctx.allocator, "failed_config", .{ .string = "v1" });
        try obj.put(ctx.allocator, "failed_filesystem", try filesystemState(ctx.allocator, ctx.io, scenario.root));
        try obj.put(ctx.allocator, "failed_trace", try compactTrace(ctx.allocator, failed.trace));
        try results.append(.{ .object = obj });
    }

    {
        var scenario = try Scenario.init(ctx, workspace, "failure-postrm-upgrade", architecture, environment, executable);
        _ = try scenario.run("seed", &.{ "--install", packages.v1_archive }, &.{}, 0);
        const failed = try scenario.run(
            "upgrade",
            &.{ "--install", packages.v2_archive },
            &.{ "v1:postrm:upgrade", "v2:postrm:failed-upgrade" },
            1,
        );
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v1", null, packages);

        var obj: std.json.ObjectMap = .empty;
        try obj.put(ctx.allocator, "case", .{ .string = "double-postrm-upgrade-failure" });
        try obj.put(ctx.allocator, "failed_database", failed.state);
        try obj.put(ctx.allocator, "failed_state", effectiveRecord(failed.state));
        try obj.put(ctx.allocator, "failed_config", .{ .string = "v1" });
        try obj.put(ctx.allocator, "failed_filesystem", try filesystemState(ctx.allocator, ctx.io, scenario.root));
        try obj.put(ctx.allocator, "failed_trace", try compactTrace(ctx.allocator, failed.trace));
        try results.append(.{ .object = obj });
    }

    {
        var scenario = try Scenario.init(ctx, workspace, "failure-postrm-remove", architecture, environment, executable);
        _ = try scenario.run("seed", &.{ "--install", packages.v1_archive }, &.{}, 0);
        const failed = try scenario.run("remove", &.{ "--remove", pkg_arch }, &.{"v1:postrm:remove"}, 1);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v1", null, packages);
        const failed_fs = try filesystemState(ctx.allocator, ctx.io, scenario.root);
        const retry = try scenario.run("remove-retry", &.{ "--remove", pkg_arch }, &.{}, 0);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, null, null, packages);

        var obj: std.json.ObjectMap = .empty;
        try obj.put(ctx.allocator, "case", .{ .string = "remove-postrm-failure" });
        try obj.put(ctx.allocator, "failed_database", failed.state);
        try obj.put(ctx.allocator, "failed_state", effectiveRecord(failed.state));
        try obj.put(ctx.allocator, "failed_config", .{ .string = "v1" });
        try obj.put(ctx.allocator, "failed_filesystem", failed_fs);
        try obj.put(ctx.allocator, "failed_trace", try compactTrace(ctx.allocator, failed.trace));
        try obj.put(ctx.allocator, "recovery_database", retry.state);
        try obj.put(ctx.allocator, "recovery_state", effectiveRecord(retry.state));
        try obj.put(ctx.allocator, "recovery_config", .null);
        try obj.put(ctx.allocator, "recovery_filesystem", try filesystemState(ctx.allocator, ctx.io, scenario.root));
        try obj.put(ctx.allocator, "recovery_trace", try compactTrace(ctx.allocator, retry.trace));
        try results.append(.{ .object = obj });
    }

    {
        var scenario = try Scenario.init(ctx, workspace, "failure-postrm-purge", architecture, environment, executable);
        _ = try scenario.run("seed", &.{ "--install", packages.v1_archive }, &.{}, 0);
        const failed = try scenario.run("purge", &.{ "--purge", pkg_arch }, &.{"v1:postrm:purge"}, 1);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, null, null, packages);
        const failed_fs = try filesystemState(ctx.allocator, ctx.io, scenario.root);
        const retry = try scenario.run("purge-retry", &.{ "--purge", pkg_arch }, &.{}, 0);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, null, null, packages);

        var obj: std.json.ObjectMap = .empty;
        try obj.put(ctx.allocator, "case", .{ .string = "purge-postrm-failure" });
        try obj.put(ctx.allocator, "failed_database", failed.state);
        try obj.put(ctx.allocator, "failed_state", effectiveRecord(failed.state));
        try obj.put(ctx.allocator, "failed_config", .null);
        try obj.put(ctx.allocator, "failed_filesystem", failed_fs);
        try obj.put(ctx.allocator, "failed_trace", try compactTrace(ctx.allocator, failed.trace));
        try obj.put(ctx.allocator, "recovery_database", retry.state);
        try obj.put(ctx.allocator, "recovery_state", effectiveRecord(retry.state));
        try obj.put(ctx.allocator, "recovery_config", .null);
        try obj.put(ctx.allocator, "recovery_filesystem", try filesystemState(ctx.allocator, ctx.io, scenario.root));
        try obj.put(ctx.allocator, "recovery_trace", try compactTrace(ctx.allocator, retry.trace));
        try results.append(.{ .object = obj });
    }

    return .{ .array = results };
}

fn interruptionObservation(
    allocator: std.mem.Allocator,
    case_name: []const u8,
    state: std.json.Value,
    trace: []const TraceRecord,
    config: ?[]const u8,
    staging: ?[]const u8,
    interrupted_filesystem: std.json.Value,
    recovery_state: std.json.Value,
    recovery_trace: []const TraceRecord,
    recovery_config: ?[]const u8,
    recovery_filesystem: std.json.Value,
) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "case", .{ .string = case_name });
    try obj.put(allocator, "interrupted_database", state);
    try obj.put(allocator, "interrupted_config", if (config) |c| .{ .string = c } else .null);
    try obj.put(allocator, "interrupted_filesystem", interrupted_filesystem);
    try obj.put(allocator, "interrupted_staging_config", if (staging) |s| .{ .string = s } else .null);
    try obj.put(allocator, "interrupted_trace", try compactTrace(allocator, trace));
    try obj.put(allocator, "recovery_database", recovery_state);
    try obj.put(allocator, "recovery_state", effectiveRecord(recovery_state));
    try obj.put(allocator, "recovery_config", if (recovery_config) |rc| .{ .string = rc } else .null);
    try obj.put(allocator, "recovery_filesystem", recovery_filesystem);
    try obj.put(allocator, "recovery_trace", try compactTrace(allocator, recovery_trace));
    return .{ .object = obj };
}

fn observeInterruptions(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    executable: []const u8,
    packages: LifecyclePackages,
) !std.json.Value {
    var results: std.json.Array = .init(ctx.allocator);
    const pkg_arch = try std.fmt.allocPrint(ctx.allocator, "{s}:{s}", .{ package_name, architecture });

    {
        var scenario = try Scenario.init(ctx, workspace, "interruption-postinst", architecture, environment, executable);
        const intr = try scenario.interrupt("install", &.{ "--install", packages.v1_archive }, "v1:postinst:configure");
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v1", null, packages);
        const intr_fs = try filesystemState(ctx.allocator, ctx.io, scenario.root);
        const rec = try scenario.run("configure", &.{ "--configure", pkg_arch }, &.{}, 0);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v1", null, packages);
        try results.append(
            try interruptionObservation(
                ctx.allocator,
                "postinst-interruption",
                intr.state,
                intr.trace,
                "v1",
                null,
                intr_fs,
                rec.state,
                rec.trace,
                "v1",
                try filesystemState(ctx.allocator, ctx.io, scenario.root),
            ),
        );
    }

    {
        var scenario = try Scenario.init(ctx, workspace, "interruption-preinst-upgrade", architecture, environment, executable);
        _ = try scenario.run("seed", &.{ "--install", packages.v1_archive }, &.{}, 0);
        const intr = try scenario.interrupt("upgrade", &.{ "--install", packages.v2_archive }, "v2:preinst:upgrade");
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v1", "v2", packages);
        const intr_fs = try filesystemState(ctx.allocator, ctx.io, scenario.root);
        const rec = try scenario.run("upgrade-retry", &.{ "--install", packages.v2_archive }, &.{}, 0);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v2", null, packages);
        try results.append(
            try interruptionObservation(
                ctx.allocator,
                "upgrade-preinst-interruption",
                intr.state,
                intr.trace,
                "v1",
                "v2",
                intr_fs,
                rec.state,
                rec.trace,
                "v2",
                try filesystemState(ctx.allocator, ctx.io, scenario.root),
            ),
        );
    }

    {
        var scenario = try Scenario.init(ctx, workspace, "interruption-postrm-remove", architecture, environment, executable);
        _ = try scenario.run("seed", &.{ "--install", packages.v1_archive }, &.{}, 0);
        const intr = try scenario.interrupt("remove", &.{ "--remove", pkg_arch }, "v1:postrm:remove");
        try assertConfig(ctx.allocator, ctx.io, scenario.root, "v1", null, packages);
        const intr_fs = try filesystemState(ctx.allocator, ctx.io, scenario.root);
        const rec = try scenario.run("remove-retry", &.{ "--remove", pkg_arch }, &.{}, 0);
        try assertConfig(ctx.allocator, ctx.io, scenario.root, null, null, packages);
        try results.append(
            try interruptionObservation(
                ctx.allocator,
                "remove-postrm-interruption",
                intr.state,
                intr.trace,
                "v1",
                null,
                intr_fs,
                rec.state,
                rec.trace,
                null,
                try filesystemState(ctx.allocator, ctx.io, scenario.root),
            ),
        );
    }

    return .{ .array = results };
}

pub fn observe(
    ctx: Context,
    workspace: []const u8,
    environment: []const EnvPair,
    architecture: []const u8,
    executable: []const u8,
    reference: std.json.Value,
) !std.json.Value {
    const lifecycle_ws = try std.fs.path.join(ctx.allocator, &.{ workspace, "lifecycle-packages" });
    const lifecycle = try makeLifecyclePackages(ctx.allocator, ctx.io, lifecycle_ws, architecture);
    const vendor = try observeVendorCohort(
        ctx,
        workspace,
        environment,
        architecture,
        executable,
        reference.object.get("members").?.array.items,
    );

    var pkg_inputs: std.json.ObjectMap = .empty;
    try pkg_inputs.put(ctx.allocator, "architecture", .{ .string = architecture });
    try pkg_inputs.put(ctx.allocator, "lifecycle", lifecycle.inputs);
    try pkg_inputs.put(ctx.allocator, "vendor", vendor.inputs);

    var open_fds: std.json.Array = .init(ctx.allocator);
    for ([_]i64{ 0, 1, 2 }) |fd| try open_fds.append(.{ .integer = fd });
    var closed_fds: std.json.Array = .init(ctx.allocator);
    for ([_]i64{ 3, 4, 5, 6, 7, 8, 9 }) |fd| try closed_fds.append(.{ .integer = fd });
    var script_ctx: std.json.ObjectMap = .empty;
    try script_ctx.put(ctx.allocator, "cwd", .{ .string = "/" });
    try script_ctx.put(ctx.allocator, "open_fds", .{ .array = open_fds });
    try script_ctx.put(ctx.allocator, "closed_probe_fds", .{ .array = closed_fds });
    try script_ctx.put(ctx.allocator, "environment", .{ .string = "exact-bounded-direct-dpkg-maintscript-environment" });

    var result: std.json.ObjectMap = .empty;
    try result.put(ctx.allocator, "package_inputs", .{ .object = pkg_inputs });
    try result.put(ctx.allocator, "vendor_identity_cohort", vendor.observation);
    try result.put(ctx.allocator, "successful_lifecycle", try observeSuccess(ctx, workspace, environment, architecture, executable, lifecycle));
    try result.put(ctx.allocator, "failure_recovery", try observeFailures(ctx, workspace, environment, architecture, executable, lifecycle));
    try result.put(ctx.allocator, "interruption_recovery", try observeInterruptions(ctx, workspace, environment, architecture, executable, lifecycle));
    try result.put(ctx.allocator, "script_context", .{ .object = script_ctx });
    try result.put(ctx.allocator, "config_invocation_count", .{ .integer = 0 });
    try result.put(ctx.allocator, "frontend_invocation_count", .{ .integer = 0 });
    return .{ .object = result };
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

fn writeHostConfig(ctx: Context, destination_arg: []const u8) !void {
    const tmp_root = try ctx.repoPath(".tmp");
    const destination = try std.fs.path.resolve(ctx.allocator, &.{ ctx.repository, destination_arg });
    if (!std.mem.startsWith(u8, destination, tmp_root) or destination.len <= tmp_root.len or destination[tmp_root.len] != '/') {
        return fail("host config destination must be inside .tmp", .{});
    }
    try writeRegular(ctx.allocator, ctx.io, destination, pinned_dpkg_config, 0o644);
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
            if (obj.get("required")) |req_v| {
                for (req_v.array.items) |req_key| {
                    if (!inst_obj.contains(req_key.string)) return error.SchemaRequiredPropertyMissing;
                }
            }
            const props = obj.get("properties");
            const addl = obj.get("additionalProperties");
            var it = inst_obj.iterator();
            while (it.next()) |entry| {
                const key = entry.key_ptr.*;
                const val = entry.value_ptr.*;
                if (props != null and props.?.object.get(key) != null) {
                    try validateAgainstSchema(root_schema, props.?.object.get(key).?, val);
                } else if (addl != null and addl.? == .bool and !addl.?.bool) {
                    return error.SchemaAdditionalPropertyForbidden;
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
    if (std.mem.eql(u8, pattern, "^[a-z0-9][a-z0-9+.-]*\\.config$")) {
        if (!std.mem.endsWith(u8, text, ".config")) return false;
        return isIdentityName(text[0 .. text.len - ".config".len]);
    }
    if (std.mem.eql(u8, pattern, "^(v1|v1r|v2|[a-z0-9][a-z0-9+.-]*)$")) {
        return inList(&tokens, text) or isIdentityName(text);
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
    if (std.mem.eql(u8, pattern, "^(?!/)(?!.*//)(?!.*(?:^|/)\\.\\.?(?:/|$))[^\\u0000-\\u001f\\u007f]+$")) {
        if (text.len == 0 or text[0] == '/' or std.mem.indexOf(u8, text, "//") != null) return false;
        for (text) |ch| {
            if (ch <= 0x1f or ch == 0x7f) return false;
        }
        var it = std.mem.splitScalar(u8, text, '/');
        while (it.next()) |part| {
            if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
        }
        return true;
    }
    if (std.mem.eql(u8, pattern, "^(preinst|postinst|prerm|postrm)@(v1|v1r|v2)\\t\\[[^\\r\\n]*\\]\\t(-|v1|v1r|v2)\\t(-|v1|v1r|v2)$")) {
        var it = std.mem.splitScalar(u8, text, '\t');
        const script = it.next() orelse return false;
        const args = it.next() orelse return false;
        const info = it.next() orelse return false;
        const staging = it.next() orelse return false;
        if (it.next() != null) return false;
        const at = std.mem.indexOfScalar(u8, script, '@') orelse return false;
        if (!inList(&script_kinds, script[0..at]) or !inList(&tokens, script[at + 1 ..])) return false;
        if (args.len < 2 or args[0] != '[' or args[args.len - 1] != ']') return false;
        if (std.mem.indexOfAny(u8, args, "\r\n") != null) return false;
        const validCfg = struct {
            fn ok(s: []const u8) bool {
                return std.mem.eql(u8, s, "-") or inList(&tokens, s);
            }
        }.ok;
        return validCfg(info) and validCfg(staging);
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
    var workspace_arg: ?[]const u8 = null;
    var capture_observed: ?[]const u8 = null;
    var print_observed = false;
    var update_reference = false;
    var write_host_config_arg: ?[]const u8 = null;

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
        } else if (std.mem.eql(u8, arg, "--write-host-config")) {
            write_host_config_arg = args_it.next() orelse {
                std.debug.print("missing --write-host-config value\n", .{});
                std.process.exit(2);
            };
        } else {
            std.debug.print("unknown argument: {s}\n", .{arg});
            std.process.exit(2);
        }
    }

    if (write_host_config_arg) |dest| {
        if (architecture != null or reference_dpkg != null or workspace_arg != null or
            capture_observed != null or print_observed or update_reference)
        {
            std.debug.print("--write-host-config cannot be combined with other flags\n", .{});
            std.process.exit(2);
        }
        try writeHostConfig(ctx, dest);
        return;
    }

    const arch = architecture orelse "amd64";
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
        return fail("dpkg config reference execution requires root", .{});
    }
    if (!hasLdd(allocator, io, init.minimal.environ)) {
        return fail("required reference tool is missing: ldd", .{});
    }

    var reference = try ctx.loadReference();
    try ctx.verifySourceBindings(reference);
    var expected_observation: ?std.json.Value = null;
    if (capture_observed == null) {
        expected_observation = try publishedObservation(allocator, reference, arch);
    }
    if (update_reference and !std.mem.eql(u8, arch, "amd64")) {
        return fail("only the amd64 baseline observation can be regenerated", .{});
    }
    const executable = try ctx.selectReference(reference_dpkg, arch);
    ctx.reference_dpkg = executable;

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
            &.{ temporary_root, try std.fmt.allocPrint(allocator, "dpkg-config-reference-{s}", .{hex}) },
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

    const host_status_path = "/var/lib/dpkg/status";
    const host_log_path = "/var/log/dpkg.log";
    const host_status = try readRegular(allocator, io, host_status_path, 64 * 1024 * 1024);
    const host_log = try hostFileSignature(allocator, host_log_path);
    defer {
        const after_status = readRegular(allocator, io, host_status_path, 64 * 1024 * 1024) catch &.{};
        if (!std.mem.eql(u8, after_status, host_status)) {
            std.debug.print("host dpkg status changed during config reference execution\n", .{});
            std.process.exit(1);
        }
        const after_log = hostFileSignature(allocator, host_log_path) catch null;
        if (!std.meta.eql(after_log, host_log)) {
            std.debug.print("host dpkg log changed during config reference execution\n", .{});
            std.process.exit(1);
        }
    }

    const environment = try fixtureEnvironment(allocator, io, workspace);
    try validateEnvironment(environment);
    try validateHostConfiguration(allocator, io, environment[3].value, "/etc/dpkg");
    const observed = try observe(ctx, workspace, environment, arch, executable, reference);

    if (!update_reference and capture_observed == null and !jsonEqual(observed, expected_observation.?)) {
        const diagnostic = try std.fs.path.join(allocator, &.{ workspace, "observed.json" });
        const encoded = try canonicalJson(allocator, observed);
        try writeRegular(allocator, io, diagnostic, encoded, 0o644);
        return fail("direct dpkg config behavior changed; bounded observation: {s}", .{diagnostic});
    }

    const after_status = try readRegular(allocator, io, host_status_path, 64 * 1024 * 1024);
    if (!std.mem.eql(u8, after_status, host_status)) {
        return fail("host dpkg status changed during config reference execution", .{});
    }
    const after_log = try hostFileSignature(allocator, host_log_path);
    if (!std.meta.eql(after_log, host_log)) {
        return fail("host dpkg log changed during config reference execution", .{});
    }

    if (update_reference) {
        try reference.object.put(allocator, "observed_behavior", observed);
        const ref_path = try ctx.repoPath(reference_relative);
        const encoded = try canonicalJson(allocator, reference);
        try writeRegular(allocator, io, ref_path, encoded, 0o644);
    }
    if (capture_observed) |cap_path| {
        try writeCapture(ctx, cap_path, observed);
    }
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    if (print_observed) {
        const encoded = try canonicalJson(allocator, observed);
        try stdout_writer.interface.writeAll(encoded);
    }
    const dpkg_version = reference.object.get("source").?.object.get("dpkg").?.object.get("version").?.string;
    try stdout_writer.interface.print(
        "dpkg config reference: direct dpkg {s} {s} passed\n",
        .{ dpkg_version, arch },
    );
    try stdout_writer.interface.flush();
}

const TestWorkspace = struct {
    arena: *std.heap.ArenaAllocator,
    ctx: Context,
    path: []const u8,
    parent_path: []const u8,
    leaf: []const u8,

    fn init() !TestWorkspace {
        const arena = try std.testing.allocator.create(std.heap.ArenaAllocator);
        errdefer std.testing.allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer arena.deinit();
        const alloc = arena.allocator();
        const io = std.testing.io;
        const repo = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", alloc);
        const ctx = try Context.init(alloc, io, std.testing.environ, repo);
        const parent_path = try ctx.repoPath(".tmp");
        try std.Io.Dir.cwd().createDirPath(io, parent_path);
        var random_bytes: [8]u8 = undefined;
        try io.randomSecure(&random_bytes);
        const hex = std.fmt.bytesToHex(random_bytes, .lower);
        const leaf = try std.fmt.allocPrint(alloc, "dpkg-config-reference-unit-{s}", .{hex});
        const path = try std.fs.path.join(alloc, &.{ parent_path, leaf });
        try std.Io.Dir.cwd().createDirPath(io, path);
        return .{
            .arena = arena,
            .ctx = ctx,
            .path = path,
            .parent_path = parent_path,
            .leaf = leaf,
        };
    }

    fn deinit(self: *TestWorkspace) void {
        const io = std.testing.io;
        if (std.Io.Dir.openDirAbsolute(io, self.parent_path, .{ .iterate = true, .follow_symlinks = false })) |dir_val| {
            var dir = dir_val;
            dir.deleteTree(io, self.leaf) catch {};
            dir.close(io);
        } else |_| {}
        self.arena.deinit();
        std.testing.allocator.destroy(self.arena);
    }
};

test "published reference is canonical and schema valid" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.arena.allocator();

    const reference = try tw.ctx.loadReference();
    const schema_path = try tw.ctx.repoPath(schema_relative);
    const schema_raw = try readRegular(alloc, std.testing.io, schema_path, Limits.maximum_file_bytes);
    const schema = try std.json.parseFromSliceLeaky(std.json.Value, alloc, schema_raw, .{});
    try validateAgainstSchema(schema, schema, reference);

    const ref_path = try tw.ctx.repoPath(reference_relative);
    const ref_raw = try readRegular(alloc, std.testing.io, ref_path, Limits.maximum_file_bytes);
    const canonical = try canonicalJson(alloc, reference);
    try std.testing.expectEqualSlices(u8, ref_raw, canonical);

    const expected_identities = [_][]const u8{
        "chrony.config",
        "console-setup.config",
        "debconf.config",
        "iproute2.config",
        "keyboard-configuration.config",
        "locales.config",
        "tzdata.config",
    };
    const members = reference.object.get("members").?.array.items;
    try std.testing.expectEqual(expected_identities.len, members.len);
    for (expected_identities, members) |exp, member| {
        try std.testing.expectEqualStrings(exp, member.object.get("identity").?.string);
    }
}

test "source digests and dpkg pins are revalidated" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const reference = try tw.ctx.loadReference();
    try tw.ctx.verifySourceBindings(reference);

    const desc = try tw.ctx.referenceDescription();
    const desc_arches = desc.object.get("architectures").?.object;
    const ref_arches = reference.object.get("source").?.object.get("dpkg").?.object.get("architectures").?.object;
    try std.testing.expectEqual(desc_arches.count(), ref_arches.count());
    var it = desc_arches.iterator();
    while (it.next()) |entry| {
        const pins = entry.value_ptr.*.object;
        const ref_pin = ref_arches.get(entry.key_ptr.*).?.object;
        try std.testing.expectEqualStrings(pins.get("archive").?.string, ref_pin.get("archive_sha256").?.string);
        try std.testing.expectEqualStrings(pins.get("executable").?.string, ref_pin.get("executable_sha256").?.string);
    }
}

test "adversarial config scripts are bounded and observable" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.arena.allocator();

    const cases = [_]struct { token: []const u8, code: u8, invalid: bool }{
        .{ .token = "v1", .code = 91, .invalid = false },
        .{ .token = "v1r", .code = 92, .invalid = false },
        .{ .token = "v2", .code = 93, .invalid = true },
    };
    for (cases) |c| {
        const body = try configBody(alloc, c.token, c.code, c.invalid);
        try std.testing.expect(body.len <= Limits.maximum_file_bytes);
        const ident_marker = try std.fmt.allocPrint(alloc, "# identity:{s}\n", .{c.token});
        const exit_marker = try std.fmt.allocPrint(alloc, "exit {d}\n", .{c.code});
        try std.testing.expect(std.mem.indexOf(u8, body, ident_marker) != null);
        try std.testing.expect(std.mem.indexOf(u8, body, exit_marker) != null);
        try std.testing.expect(std.mem.indexOf(u8, body, config_invocations_relative) != null);

        const script_path = try std.fs.path.join(alloc, &.{ tw.path, try std.fmt.allocPrint(alloc, "check-{s}.sh", .{c.token}) });
        try writeRegular(alloc, std.testing.io, script_path, body, 0o755);
        const res = try std.process.run(alloc, std.testing.io, .{
            .argv = &.{ "/bin/sh", "-n", script_path },
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, res.term);
    }
}

test "script environment shell variables are explicit" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const scripts = try maintainerScripts(tw.arena.allocator(), "v1");
    for (scripts) |entry| {
        try std.testing.expect(std.mem.indexOf(u8, entry.body, "SHLVL=1 _=/oracle-env /oracle-env") != null);
    }
}

test "vendor config fixtures match all pinned sizes" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.arena.allocator();
    const reference = try tw.ctx.loadReference();
    const members = reference.object.get("members").?.array.items;
    for ([_][]const u8{ "amd64", "arm64" }) |arch| {
        for (members, 0..) |member, index| {
            const pkg = member.object.get("owner").?.object.get("package").?.string;
            const fact = member.object.get("architectures").?.object.get(arch).?.object;
            const size: usize = @intCast(fact.get("size").?.integer);
            const body = try vendorConfigBody(alloc, pkg, size, @intCast(70 + index));
            try std.testing.expectEqual(size, body.len);
            const ident_marker = try std.fmt.allocPrint(alloc, "# identity:{s}\n", .{pkg});
            try std.testing.expect(std.mem.indexOf(u8, body, ident_marker) != null);
            try std.testing.expect(std.mem.indexOf(u8, body, vendor_config_invocations_relative) != null);
        }
    }
    for (members) |member| {
        const arches = member.object.get("architectures").?.object;
        try std.testing.expect(jsonEqual(arches.get("amd64").?, arches.get("arm64").?));
    }
}

test "fixture control tree rejects traversal symlinks and special files" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.arena.allocator();
    const source = try std.fs.path.join(alloc, &.{ tw.path, "source" });
    const body = try configBody(alloc, "v1", 91, false);
    try prepareControl(alloc, std.testing.io, source, body);
    try validateControlTree(alloc, std.testing.io, source);

    for ([_][]const u8{ "../config", "/config", "nested/config", ".", "" }) |bad_name| {
        try std.testing.expectError(error.OracleError, validateControlName(bad_name));
    }

    const cfg_path = try std.fs.path.join(alloc, &.{ source, "DEBIAN/config" });
    const cfg_z = try allocatorDupeZ(alloc, cfg_path);
    _ = linux.unlinkat(linux.AT.FDCWD, cfg_z.ptr, 0);

    const target_path = try std.fs.path.join(alloc, &.{ source, "target" });
    try writeRegular(alloc, std.testing.io, target_path, "target", 0o644);
    _ = linux.symlinkat("../target", linux.AT.FDCWD, cfg_z.ptr);
    try std.testing.expectError(error.OracleError, validateControlTree(alloc, std.testing.io, source));

    _ = linux.unlinkat(linux.AT.FDCWD, cfg_z.ptr, 0);
    _ = linux.mknodat(linux.AT.FDCWD, cfg_z.ptr, linux.S.IFIFO | 0o600, 0);
    try std.testing.expectError(error.OracleError, validateControlTree(alloc, std.testing.io, source));
}

fn allocatorDupeZ(allocator: std.mem.Allocator, text: []const u8) ![:0]u8 {
    return dupeZ(allocator, text);
}

test "frontend environment is refused" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.arena.allocator();
    const clean = [_]EnvPair{
        .{ .name = "PATH", .value = "/usr/sbin:/usr/bin:/sbin:/bin" },
        .{ .name = "LANG", .value = "C" },
        .{ .name = "LC_ALL", .value = "C" },
    };
    try validateEnvironment(&clean);
    for (forbidden_frontend_env) |name| {
        var contaminated = try alloc.alloc(EnvPair, clean.len + 1);
        @memcpy(contaminated[0..clean.len], &clean);
        contaminated[clean.len] = .{ .name = name, .value = "contaminated" };
        try std.testing.expectError(error.OracleError, validateEnvironment(contaminated));
    }
}

test "ambient dpkg configuration is pinned and hook free" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.arena.allocator();
    const config_root = try std.fs.path.join(alloc, &.{ tw.path, "etc/dpkg" });
    const home = try std.fs.path.join(alloc, &.{ tw.path, "home" });
    try std.Io.Dir.cwd().createDirPath(std.testing.io, config_root);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, home);
    const cfg_file = try std.fs.path.join(alloc, &.{ config_root, "dpkg.cfg" });
    try writeRegular(alloc, std.testing.io, cfg_file, pinned_dpkg_config, 0o644);
    try validateHostConfiguration(alloc, std.testing.io, home, config_root);

    const hook_path = try std.fs.path.join(alloc, &.{ config_root, "dpkg.cfg.d/hook" });
    try writeRegular(alloc, std.testing.io, hook_path, "pre-invoke touch /ambient-hook\n", 0o644);
    try std.testing.expectError(
        error.OracleError,
        validateHostConfiguration(alloc, std.testing.io, home, config_root),
    );
    const hook_z = try dupeZ(alloc, hook_path);
    _ = linux.unlinkat(linux.AT.FDCWD, hook_z.ptr, 0);

    const user_cfg = try std.fs.path.join(alloc, &.{ home, ".dpkg.cfg" });
    try writeRegular(alloc, std.testing.io, user_cfg, "path-exclude=*\n", 0o644);
    try std.testing.expectError(
        error.OracleError,
        validateHostConfiguration(alloc, std.testing.io, home, config_root),
    );
}

test "package builder is deterministic and dpkg readable" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.arena.allocator();
    const scripts = try maintainerScripts(alloc, "v1");
    const cfg = try configBody(alloc, "v1", 91, false);

    const ws1 = try std.fs.path.join(alloc, &.{ tw.path, "first" });
    const ws2 = try std.fs.path.join(alloc, &.{ tw.path, "second" });
    const first = try makePackage(alloc, std.testing.io, ws1, "amd64", "1", .{
        .package = package_name,
        .feature = "conffile",
        .scripts = scripts,
        .config_body = cfg,
    });
    const second = try makePackage(alloc, std.testing.io, ws2, "amd64", "1", .{
        .package = package_name,
        .feature = "conffile",
        .scripts = scripts,
        .config_body = cfg,
    });
    const bytes1 = try readRegular(alloc, std.testing.io, first.archive, Limits.maximum_archive_bytes);
    const bytes2 = try readRegular(alloc, std.testing.io, second.archive, Limits.maximum_archive_bytes);
    try std.testing.expectEqualSlices(u8, bytes1, bytes2);

    const res = try std.process.run(alloc, std.testing.io, .{
        .argv = &.{ "dpkg-deb", "--info", first.archive },
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, res.term);

    const reference = try tw.ctx.loadReference();
    for ([_][]const u8{ "amd64", "arm64" }) |arch| {
        const obs = try publishedObservation(alloc, reference, arch);
        const arch_ws = try std.fs.path.join(alloc, &.{ tw.path, arch });
        const lc = try makeLifecyclePackages(
            alloc,
            std.testing.io,
            try std.fs.path.join(alloc, &.{ arch_ws, "lc" }),
            arch,
        );
        const vd = try makeVendorPackages(
            alloc,
            std.testing.io,
            try std.fs.path.join(alloc, &.{ arch_ws, "vd" }),
            arch,
            reference.object.get("members").?.array.items,
        );
        const exp_lc = obs.object.get("package_inputs").?.object.get("lifecycle").?.array.items;
        const exp_vd = obs.object.get("package_inputs").?.object.get("vendor").?.array.items;
        for (lc.inputs.array.items, exp_lc) |act, exp| {
            try std.testing.expect(jsonEqual(act.object.get("archive").?, exp.object.get("archive").?));
        }
        for (vd.inputs.array.items, exp_vd) |act, exp| {
            try std.testing.expect(jsonEqual(act.object.get("archive").?, exp.object.get("archive").?));
        }
    }
}

test "published observation is dual architecture and state complete" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.arena.allocator();
    const reference = try tw.ctx.loadReference();
    const boundary = reference.object.get("boundary").?.object;
    const obs_arches = boundary.get("observed_architectures").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), obs_arches.len);
    try std.testing.expectEqualStrings("amd64", obs_arches[0].string);
    try std.testing.expectEqualStrings("arm64", obs_arches[1].string);
    try std.testing.expect(std.mem.indexOf(u8, boundary.get("architecture_scope").?.string, "amd64 and arm64") != null);

    try validateObservationArchitecture(reference, "amd64");
    try validateObservationArchitecture(reference, "arm64");
    try std.testing.expectError(error.OracleError, validateObservationArchitecture(reference, "riscv64"));

    const observed = reference.object.get("observed_behavior").?.object;
    const arm64 = try verifyArchitectureEvidence(alloc, reference);
    const evidence = reference.object.get("architecture_evidence").?.object.get("arm64").?.object;
    try std.testing.expectEqual(@as(i64, 78), evidence.get("difference_count").?.integer);

    const summary = evidence.get("difference_summary").?.object;
    try std.testing.expectEqual(@as(i64, 27), summary.get("architecture_derived_sha256").?.integer);
    try std.testing.expectEqual(@as(i64, 6), summary.get("architecture_derived_sizes").?.integer);
    try std.testing.expectEqual(@as(i64, 45), summary.get("architecture_fields").?.integer);

    var arch_cnt: usize = 0;
    var sha_cnt: usize = 0;
    var size_cnt: usize = 0;
    for (evidence.get("differences_from_baseline").?.array.items) |diff| {
        const path = diff.object.get("path").?.string;
        const leaf = std.fs.path.basename(path);
        if (std.mem.eql(u8, leaf, "architecture")) arch_cnt += 1 else if (std.mem.eql(u8, leaf, "sha256")) sha_cnt += 1 else if (std.mem.eql(u8, leaf, "size")) size_cnt += 1 else return error.UnexpectedDifferenceField;
    }
    try std.testing.expectEqual(@as(usize, 45), arch_cnt);
    try std.testing.expectEqual(@as(usize, 27), sha_cnt);
    try std.testing.expectEqual(@as(usize, 6), size_cnt);

    try std.testing.expectEqualStrings(
        "arm64",
        arm64.object.get("package_inputs").?.object.get("architecture").?.string,
    );
    const inputs = observed.get("package_inputs").?.object;
    try std.testing.expectEqualStrings("amd64", inputs.get("architecture").?.string);
    const lc_inputs = inputs.get("lifecycle").?.array.items;
    const vd_inputs = inputs.get("vendor").?.array.items;
    try std.testing.expectEqual(@as(usize, 3), lc_inputs.len);
    try std.testing.expectEqual(@as(usize, 7), vd_inputs.len);

    var unique_archives: std.StringHashMapUnmanaged(void) = .empty;
    for (lc_inputs) |item| {
        try unique_archives.put(alloc, item.object.get("archive").?.object.get("sha256").?.string, {});
    }
    for (vd_inputs) |item| {
        try unique_archives.put(alloc, item.object.get("archive").?.object.get("sha256").?.string, {});
    }
    try std.testing.expectEqual(@as(usize, 10), unique_archives.count());

    const members = reference.object.get("members").?.array.items;
    for (vd_inputs, members) |pkg_input, member| {
        try std.testing.expectEqualStrings(
            member.object.get("owner").?.object.get("package").?.string,
            pkg_input.object.get("identity").?.string,
        );
        var found_cfg_size: ?i64 = null;
        for (pkg_input.object.get("control").?.array.items) |ctrl| {
            if (std.mem.eql(u8, ctrl.object.get("name").?.string, "config")) {
                found_cfg_size = ctrl.object.get("size").?.integer;
            }
        }
        try std.testing.expectEqual(
            member.object.get("architectures").?.object.get("amd64").?.object.get("size").?.integer,
            found_cfg_size.?,
        );
    }

    const succ = observed.get("successful_lifecycle").?.array.items;
    for (succ) |phase| {
        const db = phase.object.get("database").?.object;
        try std.testing.expect(!db.get("journal_nonempty").?.bool);
        try std.testing.expect(!db.get("temporary_update").?.bool);
        try std.testing.expect(jsonEqual(db.get("committed").?, phase.object.get("state").?));
        try std.testing.expectEqual(
            @as(usize, 0),
            phase.object.get("filesystem").?.object.get("staging").?.array.items.len,
        );
    }
    const remove_info = succ[succ.len - 2].object.get("filesystem").?.object.get("info").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), remove_info.len);
    try std.testing.expectEqualStrings("list", remove_info[0].object.get("name").?.string);
    try std.testing.expectEqualStrings("postrm", remove_info[1].object.get("name").?.string);
    const purge_info = succ[succ.len - 1].object.get("filesystem").?.object.get("info").?.array.items;
    try std.testing.expectEqual(@as(usize, 0), purge_info.len);

    for (observed.get("failure_recovery").?.array.items) |case_item| {
        const fdb = case_item.object.get("failed_database").?.object;
        try std.testing.expect(!fdb.get("journal_nonempty").?.bool);
        try std.testing.expect(!fdb.get("temporary_update").?.bool);
        if (case_item.object.get("recovery_database")) |rdb| {
            try std.testing.expect(!rdb.object.get("journal_nonempty").?.bool);
            try std.testing.expect(!rdb.object.get("temporary_update").?.bool);
        }
    }
    for (observed.get("interruption_recovery").?.array.items) |case_item| {
        const idb = case_item.object.get("interrupted_database").?.object;
        try std.testing.expect(idb.get("journal_nonempty").?.bool);
        try std.testing.expect(idb.get("temporary_update").?.bool);
        const rdb = case_item.object.get("recovery_database").?.object;
        try std.testing.expect(!rdb.get("journal_nonempty").?.bool);
        try std.testing.expect(!rdb.get("temporary_update").?.bool);
    }

    const vc = observed.get("vendor_identity_cohort").?.object;
    for (vc.get("installed_state").?.array.items) |pkg| {
        var found = false;
        for (pkg.object.get("info").?.array.items) |item| {
            if (std.mem.eql(u8, item.object.get("name").?.string, "config")) {
                try std.testing.expectEqualStrings("0755", item.object.get("mode").?.string);
                try std.testing.expectEqual(@as(i64, 0), item.object.get("uid").?.integer);
                try std.testing.expectEqual(@as(i64, 0), item.object.get("gid").?.integer);
                found = true;
            }
        }
        try std.testing.expect(found);
    }
    for (vc.get("removed_state").?.array.items) |pkg| {
        try std.testing.expectEqual(@as(usize, 0), pkg.object.get("info").?.array.items.len);
        try std.testing.expect(pkg.object.get("state").? == .null);
    }
}

test "trace parser preserves empty arguments and bounds output" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.arena.allocator();
    const root = try std.fs.path.join(alloc, &.{ tw.path, "root" });
    const trace_file = try std.fs.path.join(alloc, &.{ root, trace_relative });
    const line = "postinst@v1\t2\t9:configure\t0:\tinfo=v1\tstaging=<absent>\tcwd=/\tfds=0,1,2\n";
    try writeRegular(alloc, std.testing.io, trace_file, line, 0o644);

    const parsed = try parseTrace(alloc, std.testing.io, root);
    try std.testing.expectEqual(@as(usize, 1), parsed.len);
    try std.testing.expectEqualStrings("postinst@v1", parsed[0].script);
    try std.testing.expectEqual(@as(usize, 2), parsed[0].arguments.len);
    try std.testing.expectEqualStrings("configure", parsed[0].arguments[0]);
    try std.testing.expectEqualStrings("", parsed[0].arguments[1]);
    try std.testing.expectEqualStrings("v1", parsed[0].info_config.?);
    try std.testing.expect(parsed[0].staging_config == null);

    const oversized = try alloc.alloc(u8, Limits.maximum_trace_bytes + 1);
    @memset(oversized, 'x');
    try writeRegular(alloc, std.testing.io, trace_file, oversized, 0o644);
    try std.testing.expectError(error.OracleError, parseTrace(alloc, std.testing.io, root));
}

test "reference roots and native guards remain fail closed" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const alloc = tw.arena.allocator();

    const unguarded = try std.fs.path.join(alloc, &.{ tw.path, "unguarded" });
    try std.Io.Dir.cwd().createDirPath(std.testing.io, unguarded);
    try std.testing.expectError(error.OracleError, tw.ctx.referenceCommand("/"));
    try std.testing.expectError(error.OracleError, tw.ctx.referenceCommand(unguarded));

    const guarded = try std.fs.path.join(alloc, &.{ tw.path, "guarded" });
    try tw.ctx.makeBasicRoot(guarded, "amd64");
    const cmd = try tw.ctx.directDpkgCommand(tw.ctx.reference_dpkg, guarded, &.{"--audit"});
    const expected_log_arg = try std.fmt.allocPrint(alloc, "--log={s}/{s}", .{ guarded, dpkg_log_relative });
    var found_log = false;
    for (cmd) |arg| {
        if (std.mem.eql(u8, arg, expected_log_arg)) found_log = true;
    }
    try std.testing.expect(found_log);

    try std.testing.expectError(
        error.OracleError,
        tw.ctx.directDpkgCommand(tw.ctx.reference_dpkg, guarded, &.{"/usr/bin/apt"}),
    );

    const native_unpack = try readRegular(
        alloc,
        std.testing.io,
        try tw.ctx.repoPath("src/native_unpack.zig"),
        2 * 1024 * 1024,
    );
    try std.testing.expect(std.mem.indexOf(u8, native_unpack, "if (database.model.opaque_info.len != 0)") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, native_unpack, ".{ .outcome = .handoff, .detail = \"unsupported_archive_metadata\" }") != null,
    );

    const archive_application = try readRegular(
        alloc,
        std.testing.io,
        try tw.ctx.repoPath("src/archive_application.zig"),
        2 * 1024 * 1024,
    );
    try std.testing.expect(std.mem.indexOf(u8, archive_application, "V1 models and preserves it but never") != null);
    try std.testing.expect(std.mem.indexOf(u8, archive_application, "return self != .config;") != null);
}

test "reference records exact direct dpkg outcome" {
    var tw = try TestWorkspace.init();
    defer tw.deinit();
    const reference = try tw.ctx.loadReference();
    const observed = reference.object.get("observed_behavior").?.object;
    try std.testing.expectEqual(@as(i64, 0), observed.get("config_invocation_count").?.integer);
    try std.testing.expectEqual(@as(i64, 0), observed.get("frontend_invocation_count").?.integer);

    const expected_ops = [_][]const u8{ "install", "reinstall", "upgrade", "remove", "purge" };
    const succ = observed.get("successful_lifecycle").?.array.items;
    try std.testing.expectEqual(expected_ops.len, succ.len);
    for (expected_ops, succ) |exp, item| {
        try std.testing.expectEqualStrings(exp, item.object.get("operation").?.string);
    }

    const expected_failures = [_][]const u8{
        "fresh-postinst-failure",
        "upgrade-postinst-failure",
        "incoming-preinst-failure",
        "double-postrm-upgrade-failure",
        "remove-postrm-failure",
        "purge-postrm-failure",
    };
    const fails = observed.get("failure_recovery").?.array.items;
    try std.testing.expectEqual(expected_failures.len, fails.len);
    for (expected_failures, fails) |exp, item| {
        try std.testing.expectEqualStrings(exp, item.object.get("case").?.string);
    }

    const expected_interruptions = [_][]const u8{
        "postinst-interruption",
        "upgrade-preinst-interruption",
        "remove-postrm-interruption",
    };
    const intrs = observed.get("interruption_recovery").?.array.items;
    try std.testing.expectEqual(expected_interruptions.len, intrs.len);
    for (expected_interruptions, intrs) |exp, item| {
        try std.testing.expectEqualStrings(exp, item.object.get("case").?.string);
    }
}
