const std = @import("std");
const order = @import("real-snapshot-reference-order.zig");
const paths = @import("real_snapshot_reference_paths.zig");
const linux = std.os.linux;
const builtin = @import("builtin");
const c = @cImport({
    @cUndef("_FORTIFY_SOURCE");
    @cInclude("sys/socket.h");
    @cInclude("sys/stat.h");
    @cInclude("netinet/in.h");
    @cInclude("sys/un.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
});
const eq = std.mem.eql;
const A = std.mem.Allocator;

pub const escape_checks = [_][]const u8{
    "pid-namespace",      "no-proc-view",       "inherited-descriptors", "no-new-privileges",    "seccomp-filter",       "capabilities",
    "path-escape",        "re-chroot-denied",   "pivot-root-denied",     "handle-escape-denied", "mount-denied",         "umount-denied",
    "move-mount-denied",  "device-node-denied", "module-load-denied",    "module-file-denied",   "module-remove-denied", "host-admin-denied",
    "host-time-denied",   "raw-network-denied", "unshare-denied",        "setns-denied",         "clone-user-denied",    "clone-network-denied",
    "clone-mount-denied", "clone3-denied",
};
const control_exempt = [_][]const u8{ "inherited-descriptors", "path-escape" };
const profile_exempt = "no-proc-view";
const confined_checks = [_][]const u8{ "archive-mount", "descendant-started" };
const profile_common = [_][]const u8{ "proc-mount", "proc-root", "proc-hidepid", "archive-unbound", "descendant-started" };
const marker = ".debz-escape-probe-descendant";
const profiles = [_][]const u8{ "systemd", "udev", "sudo" };

fn profileVersion(profile: []const u8) []const u8 {
    return if (eq(u8, profile, "sudo")) "1.9.17p2-1ubuntu3.1" else "259.5-0ubuntu3.4";
}
fn hex(comptime H: type, bytes: []const u8) [H.digest_length * 2]u8 {
    var digest: [H.digest_length]u8 = undefined;
    H.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}
fn join(a: A, root: []const u8, path: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "{s}/{s}", .{ root, path });
}
fn ensure(condition: bool, message: []const u8) !void {
    if (!condition) {
        try paths.writeAll(2, message);
        try paths.writeAll(2, "\n");
        return error.ProtectedReferenceProofFailed;
    }
}

pub fn probeResults(a: A, output: []const u8) !std.StringHashMap([]const u8) {
    var result: std.StringHashMap([]const u8) = .init(a);
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        var columns = std.mem.splitScalar(u8, line, ' ');
        if (!eq(u8, columns.next() orelse "", "debz-escape-probe:")) continue;
        const name = columns.next() orelse continue;
        const status = columns.next() orelse continue;
        if (eq(u8, status, "info")) continue;
        if (result.contains(name) or (!eq(u8, status, "ok") and !eq(u8, status, "FAIL"))) return error.AmbiguousEscapeProbeReport;
        try result.put(name, status);
    }
    return result;
}
pub fn probeDetail(a: A, output: []const u8, check: []const u8) !std.StringHashMap([]const u8) {
    const prefix = try std.fmt.allocPrint(a, "debz-escape-probe: {s} ok ", .{check});
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| if (std.mem.startsWith(u8, line, prefix)) {
        if (found != null) return error.AmbiguousEscapeProbeDetail;
        found = line[prefix.len..];
    };
    var result: std.StringHashMap([]const u8) = .init(a);
    var fields = std.mem.tokenizeAny(u8, found orelse return error.MissingEscapeProbeDetail, " \t\r");
    while (fields.next()) |field| if (std.mem.indexOfScalar(u8, field, '=')) |delimiter|
        try result.put(field[0..delimiter], field[delimiter + 1 ..]);
    return result;
}
fn require(result: order.Result, expected: []const u8) !void {
    try ensure(result.code != 0 and std.mem.indexOf(u8, result.stderr, expected) != null, expected);
}

const Options = struct {
    launcher: []const u8,
    runtime: []const u8,
    runtime_tool: []const u8,
    dpkg: []const u8,
    root_template: []const u8,
    workspace: []const u8,
    archive: []const u8,
    archive_sha512: []const u8,
    archive_size: usize,
    escape_probe: []const u8,
    escape_archive: []const u8,
    escape_archive_sha512: []const u8,
    escape_archive_size: usize,
    profile_scripts: []const u8,
    architecture: []const u8,
};
const Teardown = struct {
    polls: usize,
    processes_scanned: usize,
    surviving_processes: []const u32,
    mountinfo_entries: usize,
    mounts_under_root: []const []const u8,
    archive_mountpoint: struct { size: u64, nlink: u32, mode: []const u8 },
    proc_entries: [][]const u8,
};
const Harness = struct {
    ctx: order.Context,
    options: Options,
    test_unprotected: if (builtin.is_test) bool else void = if (builtin.is_test) false else {},
    test_operation: if (builtin.is_test) ?*const fn ([]const u8) order.Result else void = if (builtin.is_test) null else {},
    test_teardown: if (builtin.is_test) bool else void = if (builtin.is_test) false else {},

    fn absoluteRead(self: Harness, path: []const u8, limit: usize) ![]u8 {
        const pin = try paths.openAbsolute(path, false);
        defer pin.close();
        return paths.readPinned(self.ctx.a, pin, limit);
    }
    fn hostProc(self: Harness, name: []const u8, limit: usize) ![]u8 {
        return std.Io.Dir.cwd().readFileAlloc(self.ctx.io, name, self.ctx.a, .limited(limit));
    }
    fn protectedDirectory(self: Harness, path: []const u8, empty: bool) !void {
        const pin = (if (builtin.is_test and self.test_unprotected) paths.openAbsolute(path, true) else paths.openProtected(path, true)) catch {
            try paths.writeAll(2, "reference path has writable or non-root ancestor\n");
            return error.UnprotectedReferencePath;
        };
        defer pin.close();
        const info = pin.metadata;
        try ensure(info.mode & 0o7777 == 0o700, "protected proof directory must be root-only 0700");
        if (empty) {
            try ensure((try paths.names(self.ctx.a, self.ctx.io, pin, 24000)).len == 0, "protected proof workspace must be new and empty");
        }
    }
    fn freshRoot(self: Harness, workspace: []const u8, name: []const u8) ![]const u8 {
        const root = try std.fmt.allocPrint(self.ctx.a, "{s}/{s}-root", .{ workspace, name });
        try self.checkTemplate(self.options.root_template, "");
        try self.ctx.checked(&.{ "cp", "-a", "--one-file-system", "--", self.options.root_template, root }, 60);
        const pin = try paths.openAbsolute(root, true);
        defer pin.close();
        _ = try paths.syscall(linux.fchmod(pin.fd, 0o700));
        try self.protectedDirectory(root, false);
        try ensure((try self.ctx.read(root, "var/lib/dpkg/status", 4 * 1024 * 1024)).len == 0, "proof template is not an empty dpkg root");
        const proc = try paths.openAbsolute(try join(self.ctx.a, root, "proc"), true);
        defer proc.close();
        try ensure((try paths.names(self.ctx.a, self.ctx.io, proc, 24000)).len == 0, "proof template proc mountpoint is not empty");
        return root;
    }
    fn checkTemplate(self: Harness, directory: []const u8, relative: []const u8) !void {
        const pin = try paths.openAbsolute(directory, true);
        defer pin.close();
        for (try paths.names(self.ctx.a, self.ctx.io, pin, 1000000)) |name| {
            const name_z = try self.ctx.a.dupeZ(u8, name);
            var info: linux.Statx = undefined;
            _ = try paths.syscall(linux.statx(pin.fd, name_z, linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &info));
            const path = if (relative.len == 0) name else try join(self.ctx.a, relative, name);
            switch (info.mode & 0o170000) {
                0o040000 => try self.checkTemplate(try join(self.ctx.a, directory, name), path),
                0o100000, 0o120000 => {},
                0o020000 => try ensure(eq(u8, path, "dev/null") and info.rdev_major == 1 and info.rdev_minor == 3, "unsupported protected template member"),
                else => return error.UnsupportedProtectedTemplateMember,
            }
        }
    }
    fn teardown(self: Harness, root: []const u8) !Teardown {
        if (builtin.is_test and self.test_teardown) return .{ .polls = 0, .processes_scanned = 0, .surviving_processes = &.{}, .mountinfo_entries = 0, .mounts_under_root = &.{}, .archive_mountpoint = .{ .size = 0, .nlink = 1, .mode = "0o600" }, .proc_entries = &.{} };
        const root_pin = try paths.openAbsolute(root, true);
        defer root_pin.close();
        var polls: usize = 0;
        var scanned: usize = 0;
        while (polls < 20) : (polls += 1) {
            scanned = 0;
            var survivors: usize = 0;
            const proc = try paths.openAbsolute("/proc", true);
            defer proc.close();
            for (try paths.names(self.ctx.a, self.ctx.io, proc, 1000000)) |name| {
                _ = std.fmt.parseInt(u32, name, 10) catch continue;
                scanned += 1;
                const path = try self.ctx.a.dupeZ(u8, try std.fmt.allocPrint(self.ctx.a, "/proc/{s}/root", .{name}));
                var info: linux.Statx = undefined;
                const status = linux.statx(linux.AT.FDCWD, path, 0, .BASIC_STATS, &info);
                if (linux.errno(status) == .NOENT or linux.errno(status) == .SRCH) continue;
                _ = try paths.syscall(status);
                if (info.ino == root_pin.metadata.ino and info.dev_major == root_pin.metadata.dev_major and info.dev_minor == root_pin.metadata.dev_minor)
                    survivors += 1;
            }
            if (survivors == 0) break;
            try ensure(polls != 19, "processes retain reference root after namespace teardown");
            try self.ctx.io.sleep(.fromMilliseconds(100), .awake);
        }
        var mounts: usize = 0;
        var lines = std.mem.tokenizeScalar(u8, try self.hostProc("/proc/self/mountinfo", 16 * 1024 * 1024), '\n');
        while (lines.next()) |line| {
            mounts += 1;
            var columns = std.mem.tokenizeScalar(u8, line, ' ');
            for (0..4) |_| _ = columns.next() orelse return error.MalformedHostMountInfo;
            const escaped = columns.next() orelse return error.MalformedHostMountInfo;
            var text: std.Io.Writer.Allocating = .init(self.ctx.a);
            var index: usize = 0;
            while (index < escaped.len) : (index += 1) {
                if (escaped[index] == '\\' and index + 3 < escaped.len) {
                    const code = escaped[index + 1 ..][0..3];
                    if (eq(u8, code, "040") or eq(u8, code, "011")) {
                        try text.writer.writeByte(if (eq(u8, code, "040")) ' ' else '\t');
                        index += 3;
                        continue;
                    }
                }
                try text.writer.writeByte(escaped[index]);
            }
            const mount = text.written();
            try ensure(!eq(u8, mount, root) and !(std.mem.startsWith(u8, mount, root) and mount.len > root.len and mount[root.len] == '/'), "reference mount survived under root");
        }
        const archive = try paths.openBeneath(root_pin.fd, ".debz-reference-archive", false);
        defer archive.close();
        const proc = try paths.openBeneath(root_pin.fd, "proc", true);
        defer proc.close();
        const entries = try paths.names(self.ctx.a, self.ctx.io, proc, 24000);
        try ensure(archive.metadata.mode & 0o170000 == 0o100000 and archive.metadata.size == 0 and archive.metadata.nlink == 1 and entries.len == 0, "reference archive or proc mountpoint changed under root");
        try ensure(!try paths.exists(root, ".debz-reference-runtime"), "temporary reference runtime survived under root");
        return .{ .polls = polls + 1, .processes_scanned = scanned, .surviving_processes = &.{}, .mountinfo_entries = mounts, .mounts_under_root = &.{}, .archive_mountpoint = .{ .size = 0, .nlink = 1, .mode = try std.fmt.allocPrint(self.ctx.a, "0o{o}", .{archive.metadata.mode & 0o7777}) }, .proc_entries = entries };
    }
    fn operation(self: Harness, name: []const u8, root: []const u8, runtime: []const u8, archive: ?[]const u8, digest: ?[]const u8, size: usize, verb: []const u8, profile: []const u8, selector: []const u8, readable: bool, inherited: ?i32) !order.Result {
        if (builtin.is_test) if (self.test_operation) |callback| return callback(name);
        var command: std.ArrayList([]const u8) = .empty;
        try command.appendSlice(self.ctx.a, &.{ self.options.launcher, root, self.options.dpkg, self.options.architecture, profile, verb, selector, runtime });
        if (archive) |path| try command.appendSlice(self.ctx.a, &.{ path, digest.?, try std.fmt.allocPrint(self.ctx.a, "{d}", .{size}) });
        const out_name = try std.fmt.allocPrint(self.ctx.a, "{s}.stdout", .{name});
        const err_name = try std.fmt.allocPrint(self.ctx.a, "{s}.stderr", .{name});
        const out_fd = try paths.create(self.options.workspace, out_name, 0o600, true);
        defer _ = linux.close(out_fd);
        const err_fd = try paths.create(self.options.workspace, err_name, 0o600, true);
        defer _ = linux.close(err_fd);
        const readable_fd = if (readable) blk: {
            const path = try self.ctx.a.dupeZ(u8, try join(self.ctx.a, self.options.workspace, out_name));
            break :blk @as(i32, @intCast(try paths.syscall(linux.open(path, .{ .ACCMODE = .RDWR, .APPEND = true, .CLOEXEC = true, .NOFOLLOW = true }, 0))));
        } else out_fd;
        defer if (readable) {
            _ = linux.close(readable_fd);
        };
        if (inherited) |fd| {
            _ = try paths.syscall(linux.fcntl(fd, linux.F.SETFD, 0));
        }
        defer if (inherited) |fd| {
            _ = linux.fcntl(fd, linux.F.SETFD, linux.FD_CLOEXEC);
        };
        const code = self.ctx.runFiles(command.items, readable_fd, err_fd, 45) catch |err| switch (err) {
            error.ReferenceCommandTimedOut => @as(i32, -1),
            else => return err,
        };
        // For the alias refusal, inspect the real clone, not the refused alias.
        const real_root = if (eq(u8, name, "symlink")) try join(self.ctx.a, self.options.workspace, "symlink-root") else root;
        const teardown_result = try self.teardown(real_root);
        const error_output = try self.ctx.read(self.options.workspace, err_name, order.maximum_log_bytes);
        try self.ctx.json(self.options.workspace, try std.fmt.allocPrint(self.ctx.a, "{s}.json", .{name}), .{
            .argv = command.items,
            .exit_status = code,
            .stderr = error_output,
            .teardown = teardown_result,
            .database = if (code == 0) try databaseRows(self.ctx.a, try self.ctx.database(real_root)) else null,
        });
        return .{ .code = code, .stdout = try self.ctx.read(self.options.workspace, out_name, order.maximum_log_bytes), .stderr = error_output };
    }
    fn standard(self: Harness, name: []const u8, root: []const u8, verb: []const u8, inherited: ?i32) !order.Result {
        return self.operation(name, root, self.options.runtime, self.options.archive, self.options.archive_sha512, self.options.archive_size, verb, "none", try std.fmt.allocPrint(self.ctx.a, "debz-reference-proof:{s}", .{self.options.architecture}), false, inherited);
    }
    fn writeBeneath(self: Harness, root: []const u8, relative: []const u8, bytes: []const u8, mode: u32, replace: bool) !void {
        const directory = try paths.openAbsolute(root, true);
        defer directory.close();
        try paths.relative(relative);
        const parent = if (std.fs.path.dirname(relative)) |part| try paths.openBeneath(directory.fd, part, true) else directory;
        defer if (std.fs.path.dirname(relative) != null) parent.close();
        const name = try self.ctx.a.dupeZ(u8, std.fs.path.basename(relative));
        const fd: i32 = @intCast(try paths.syscall(linux.openat(parent.fd, name, .{
            .ACCMODE = .WRONLY,
            .NOFOLLOW = true,
            .CLOEXEC = true,
            .NONBLOCK = true,
            .CREAT = !replace,
            .EXCL = !replace,
        }, mode)));
        defer _ = linux.close(fd);
        const info = try paths.stat(fd);
        if (info.mode & 0o170000 != 0o100000) return error.InvalidProfileRootMember;
        _ = try paths.syscall(linux.ftruncate(fd, 0));
        _ = try paths.syscall(linux.fchmod(fd, mode));
        try paths.writeAll(fd, bytes);
    }
    fn profileScripts(self: Harness) !std.StringHashMap([]const u8) {
        const directory = if (builtin.is_test and self.test_unprotected) try paths.openAbsolute(self.options.profile_scripts, true) else try paths.openProtected(self.options.profile_scripts, true);
        defer directory.close();
        const names = try paths.names(self.ctx.a, self.ctx.io, directory, 24000);
        var result: std.StringHashMap([]const u8) = .init(self.ctx.a);
        if (!eq(u8, self.options.architecture, "amd64")) {
            try ensure(names.len == 0, "arm64 must not stage amd64 profile scripts");
            return result;
        }
        try ensure(names.len == 3, "amd64 profile scripts must be exactly the bound postinsts");
        for (profiles) |profile| {
            const name = try std.fmt.allocPrint(self.ctx.a, "{s}.postinst", .{profile});
            var included = false;
            for (names) |entry| if (eq(u8, entry, name)) {
                included = true;
            };
            try ensure(included, "amd64 profile scripts must be exactly the bound postinsts");
            const path = try join(self.ctx.a, self.options.profile_scripts, name);
            const pin = if (builtin.is_test and self.test_unprotected) try paths.openAbsolute(path, false) else try paths.openProtected(path, false);
            defer pin.close();
            try result.put(profile, try paths.readPinned(self.ctx.a, pin, 64 * 1024));
        }
        return result;
    }
    fn profileRoot(self: Harness, name: []const u8, profile: []const u8, script: []const u8, probe: []const u8, version: []const u8) ![]const u8 {
        const root = try self.freshRoot(self.options.workspace, name);
        const status = try std.fmt.allocPrint(self.ctx.a, "Package: {s}\nStatus: install ok unpacked\nPriority: optional\nSection: admin\nMaintainer: debz reference proof <reference-proof@debz.invalid>\nArchitecture: amd64\nVersion: {s}\nDescription: debz protected proc-view proof\n", .{ profile, version });
        try self.writeBeneath(root, "var/lib/dpkg/status", status, 0o644, true);
        try self.writeBeneath(root, try std.fmt.allocPrint(self.ctx.a, "var/lib/dpkg/info/{s}.list", .{profile}), "", 0o644, false);
        try self.writeBeneath(root, try std.fmt.allocPrint(self.ctx.a, "var/lib/dpkg/info/{s}.postinst", .{profile}), script, 0o755, false);
        try self.writeBeneath(root, "usr/bin/sh", probe, 0o755, false);
        return root;
    }
    fn proveRuntime(self: Harness, identity: []const u8) !void {
        const manifest = try std.json.parseFromSlice(std.json.Value, self.ctx.a, try self.ctx.read(self.options.runtime, "binding.json", 128 * 1024), .{ .allocate = .alloc_always });
        const record = manifest.value.object;
        const objects = record.get("objects").?.array.items;
        var results: order.Fields = .empty;
        for ([_][]const u8{ record.get("loader").?.string, "libpcre2-8.so.0" }) |object_name| {
            var selected: ?std.json.Value = null;
            for (objects) |object| if (eq(u8, object.object.get("name").?.string, object_name)) {
                selected = object;
            };
            const binding = selected orelse return error.InvalidOriginalRuntimeBinding;
            const root_path = binding.object.get("root_path").?.string;
            for ([_][]const u8{ "missing", "altered", "symlink", "private-altered" }) |mutation| {
                const name = try std.fmt.allocPrint(self.ctx.a, "runtime-{s}-{s}", .{ object_name, mutation });
                const root = try self.freshRoot(self.options.workspace, name);
                var prefix = self.options.runtime;
                var target = try join(self.ctx.a, root, root_path[1..]);
                if (eq(u8, mutation, "missing") or eq(u8, mutation, "symlink")) try self.ctx.checked(&.{ "rm", "--", target }, 30);
                if (eq(u8, mutation, "symlink")) try self.ctx.checked(&.{ "ln", "-s", "--", try join(self.ctx.a, prefix, object_name), target }, 30);
                if (eq(u8, mutation, "private-altered")) {
                    prefix = try std.fmt.allocPrint(self.ctx.a, "{s}/{s}-prefix", .{ self.options.workspace, name });
                    try self.ctx.checked(&.{ "cp", "-a", "--one-file-system", "--", self.options.runtime, prefix }, 60);
                    try self.protectedDirectory(prefix, false);
                    target = try join(self.ctx.a, prefix, object_name);
                }
                if (eq(u8, mutation, "altered") or eq(u8, mutation, "private-altered")) {
                    const bytes = try self.absoluteRead(target, 16 * 1024 * 1024);
                    if (bytes.len == 0) return error.InvalidOriginalRuntimeBinding;
                    bytes[0] ^= 1;
                    const pin = try paths.openAbsolute(target, false);
                    defer pin.close();
                    try self.writeBeneath(self.options.workspace, target[self.options.workspace.len + 1 ..], bytes, pin.metadata.mode & 0o7777, true);
                }
                const result = try self.operation(name, root, prefix, self.options.archive, self.options.archive_sha512, self.options.archive_size, "unpack", "none", try std.fmt.allocPrint(self.ctx.a, "debz-reference-proof:{s}", .{self.options.architecture}), false, null);
                const expected = if (eq(u8, mutation, "missing") or eq(u8, mutation, "symlink")) "RuntimeInputRefused" else "RuntimeDigestChanged";
                try require(result, expected);
                try ensure((try self.ctx.read(root, "var/lib/dpkg/status", 4 * 1024 * 1024)).len == 0 and
                    !try paths.exists(root, "usr/share/debz-reference-proof/marker"), "dpkg started despite runtime refusal");
                var row: order.Fields = .empty;
                try row.put(self.ctx.a, "refusal", .{ .string = expected });
                try row.put(self.ctx.a, "dpkg_started", .{ .bool = false });
                try results.put(self.ctx.a, name, .{ .object = row });
            }
            const name = try std.fmt.allocPrint(self.ctx.a, "runtime-{s}-postbinding", .{object_name});
            const root = try self.freshRoot(self.options.workspace, name);
            const observed = try self.ctx.run(&.{ self.options.runtime_tool, "prove-postbinding", self.options.architecture, self.options.runtime, root, identity, object_name }, 45, order.maximum_probe_output);
            try ensure(observed.code == 0 and std.mem.indexOf(u8, observed.stderr, "RuntimeSourceChanged; no dpkg or script executed") != null, "post-binding drift proof failed");
            try ensure((try self.ctx.read(root, "var/lib/dpkg/status", 4 * 1024 * 1024)).len == 0, "post-binding proof mutated package database");
            const teardown_result = try self.teardown(root);
            var output: std.Io.Writer.Allocating = .init(self.ctx.a);
            try std.json.Stringify.value(teardown_result, .{}, &output.writer);
            const value = try std.json.parseFromSlice(std.json.Value, self.ctx.a, output.written(), .{});
            var row: order.Fields = .empty;
            try row.put(self.ctx.a, "refusal", .{ .string = "RuntimeSourceChanged" });
            try row.put(self.ctx.a, "dpkg_started", .{ .bool = false });
            try row.put(self.ctx.a, "teardown", value.value);
            try results.put(self.ctx.a, name, .{ .object = row });
        }
        const root = try self.freshRoot(self.options.workspace, "runtime-unbound-preload");
        try self.writeBeneath(root, "etc/ld.so.preload", "/unbound-library.so\n", 0o644, false);
        try require(try self.standard("runtime-unbound-preload", root, "unpack", null), "UnboundRuntimePreload");
        try ensure((try self.ctx.read(root, "var/lib/dpkg/status", 4 * 1024 * 1024)).len == 0, "dpkg started with unbound preload");
        var row: order.Fields = .empty;
        try row.put(self.ctx.a, "refusal", .{ .string = "UnboundRuntimePreload" });
        try row.put(self.ctx.a, "dpkg_started", .{ .bool = false });
        try results.put(self.ctx.a, "runtime-unbound-preload", .{ .object = row });
        try self.ctx.json(self.options.workspace, "runtime-preflight-proof.json", .{
            .architecture = self.options.architecture,
            .original_archive_bindings = manifest.value,
            .cases = results,
        });
    }
    fn networkControl(self: Harness, name: []const u8, root: []const u8) !Network {
        const tcp = c.socket(c.AF_INET, c.SOCK_STREAM | c.SOCK_CLOEXEC, 0);
        if (tcp < 0) return error.HostNetworkControlFailed;
        errdefer _ = c.close(tcp);
        var address: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
        address.sin_family = c.AF_INET;
        address.sin_addr.s_addr = std.mem.nativeToBig(u32, 0x7f000001);
        if (c.bind(tcp, @ptrCast(&address), @sizeOf(c.struct_sockaddr_in)) != 0 or c.listen(tcp, 2) != 0) return error.HostNetworkControlFailed;
        var length: c.socklen_t = @sizeOf(c.struct_sockaddr_in);
        if (c.getsockname(tcp, @ptrCast(&address), &length) != 0) return error.HostNetworkControlFailed;
        const port = std.mem.bigToNative(u16, address.sin_port);
        const unix = c.socket(c.AF_UNIX, c.SOCK_STREAM | c.SOCK_CLOEXEC, 0);
        if (unix < 0) return error.HostNetworkControlFailed;
        errdefer _ = c.close(unix);
        const name_input = try std.fmt.allocPrint(self.ctx.a, "{s}/{s}", .{ self.options.workspace, name });
        const unix_name = try std.fmt.allocPrint(self.ctx.a, "debz-reference-{s}", .{hex(std.crypto.hash.sha2.Sha256, name_input)});
        var unix_address: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
        unix_address.sun_family = c.AF_UNIX;
        @memcpy(@as([*]u8, @ptrCast(&unix_address.sun_path))[1..][0..unix_name.len], unix_name);
        if (c.bind(unix, @ptrCast(&unix_address), @intCast(@offsetOf(c.struct_sockaddr_un, "sun_path") + 1 + unix_name.len)) != 0 or c.listen(unix, 2) != 0)
            return error.HostNetworkControlFailed;
        const inherited = c.fcntl(tcp, c.F_DUPFD, @as(c_int, 200));
        if (inherited < 0) return error.HostNetworkControlFailed;
        errdefer _ = c.close(inherited);
        const command: []const []const u8 = &.{ self.options.escape_probe, "network-host", try std.fmt.allocPrint(self.ctx.a, "{d}", .{port}), unix_name, try std.fmt.allocPrint(self.ctx.a, "{d}", .{inherited}) };
        const observed = try self.ctx.run(command, 10, order.maximum_probe_output);
        const prefix = try std.fmt.allocPrint(self.ctx.a, "{s}.network-host", .{name});
        try self.ctx.write(self.options.workspace, try std.fmt.allocPrint(self.ctx.a, "{s}.stdout", .{prefix}), observed.stdout, false);
        try self.ctx.write(self.options.workspace, try std.fmt.allocPrint(self.ctx.a, "{s}.stderr", .{prefix}), observed.stderr, false);
        try self.ctx.json(self.options.workspace, try std.fmt.allocPrint(self.ctx.a, "{s}.json", .{prefix}), .{ .argv = command, .exit_status = observed.code, .port = port, .abstract_unix = unix_name, .inherited_fd = inherited });
        try ensure(observed.code == 0 and eq(u8, observed.stdout, "DEBZ_HOST_NETWORK_PROOF tcp=reachable abstract_unix=reachable inherited_fd=open\n"), "host network controls were not genuinely reachable");
        try self.writeBeneath(root, ".debz-network-control", try std.fmt.allocPrint(self.ctx.a, "{d}\n{s}\n{d}", .{ port, unix_name, inherited }), 0o600, false);
        return .{ .tcp = tcp, .unix = unix, .inherited = inherited };
    }
    fn proveProfiles(self: Harness, signed_scripts: std.StringHashMap([]const u8)) ![]const u8 {
        const probe = try self.absoluteRead(self.options.escape_probe, 16 * 1024 * 1024);
        if (!eq(u8, self.options.architecture, "amd64")) {
            for (profiles) |profile| {
                const name = try std.fmt.allocPrint(self.ctx.a, "profile-{s}-{s}", .{ profile, self.options.architecture });
                const root = try self.freshRoot(self.options.workspace, name);
                try require(try self.operation(name, root, self.options.runtime, null, null, 0, "configure", profile, try std.fmt.allocPrint(self.ctx.a, "{s}:{s}", .{ profile, self.options.architecture }), false, null), "InvalidProfile");
            }
            return "arm64 refusal of the amd64-only signed proc profiles";
        }
        const boot_id = std.mem.trim(u8, try self.hostProc("/proc/sys/kernel/random/boot_id", 4096), " \r\n");
        for (profiles) |profile| {
            const name = try std.fmt.allocPrint(self.ctx.a, "profile-{s}", .{profile});
            const root = try self.profileRoot(name, profile, signed_scripts.get(profile).?, probe, profileVersion(profile));
            const network = try self.networkControl(name, root);
            const result = blk: {
                defer network.close();
                break :blk try self.operation(name, root, self.options.runtime, null, null, 0, "configure", profile, try std.fmt.allocPrint(self.ctx.a, "{s}:amd64", .{profile}), false, network.inherited);
            };
            const observed = try probeResults(self.ctx.a, result.stdout);
            try ensure(result.code == 0 and !observed.contains(profile_exempt), "signed proc profile refused or used wrong view");
            for (escape_checks) |check| {
                if (eq(u8, check, profile_exempt)) continue;
                try ensure(eq(u8, observed.get(check) orelse "", "ok"), check);
            }
            for (profile_common ++ .{ "private-network", "result" }) |check| try ensure(eq(u8, observed.get(check) orelse "", "ok"), check);
            const views: []const []const u8 = if (eq(u8, profile, "systemd")) &.{ "proc-read-only", "proc-sys-masked", "proc-boot-id" } else &.{"proc-pid-only"};
            for (views) |check| try ensure(eq(u8, observed.get(check) orelse "", "ok"), check);
            try ensure(eq(u8, (try probeDetail(self.ctx.a, result.stdout, "result")).get("mode") orelse "", profile), "probe ran with wrong signed profile");
            if (eq(u8, profile, "systemd")) try ensure(eq(u8, (try probeDetail(self.ctx.a, result.stdout, "proc-boot-id")).get("boot_id") orelse "", boot_id), "masked boot ID is not the host boot ID");
            try self.descendant(root);
            const records = try self.ctx.database(root);
            try ensure(records.len == 1 and eq(u8, order.field(records[0], "package"), profile) and
                eq(u8, order.field(records[0], "status"), "install ok installed") and eq(u8, order.field(records[0], "version"), profileVersion(profile)), "pinned dpkg did not configure bound package");
        }
        const changed = try self.ctx.a.dupe(u8, signed_scripts.get("systemd").?);
        changed[changed.len - 2] ^= 1;
        const Negative = struct { name: []const u8, profile: []const u8, selector: []const u8, script: []const u8, version: []const u8, expected: []const u8 };
        for ([_]Negative{
            .{ .name = "profile-tampered-script", .profile = "systemd", .selector = "systemd:amd64", .script = changed, .version = profileVersion("systemd"), .expected = "SourceChanged" },
            .{ .name = "profile-wrong-version", .profile = "systemd", .selector = "systemd:amd64", .script = signed_scripts.get("systemd").?, .version = "259.5-0ubuntu3.3", .expected = "ReferenceSetupFailed" },
            .{ .name = "profile-wrong-selector", .profile = "systemd", .selector = "udev:amd64", .script = signed_scripts.get("systemd").?, .version = profileVersion("systemd"), .expected = "InvalidProfile" },
            .{ .name = "profile-unbound-configure", .profile = "none", .selector = "systemd:amd64", .script = signed_scripts.get("systemd").?, .version = profileVersion("systemd"), .expected = "InvalidProfile" },
        }) |negative| {
            const root = try self.profileRoot(negative.name, "systemd", negative.script, probe, negative.version);
            const result = try self.operation(negative.name, root, self.options.runtime, null, null, 0, "configure", negative.profile, negative.selector, false, null);
            try require(result, negative.expected);
            if (eq(u8, negative.name, "profile-wrong-version")) try ensure(std.mem.indexOf(u8, result.stderr, "failed at stage 10") != null, "in-root profile binding did not refuse");
            const records = try self.ctx.database(root);
            try ensure(records.len == 1 and eq(u8, order.field(records[0], "status"), "install ok unpacked"), "refused profile changed package state");
            try ensure(!try paths.exists(root, marker), "probe ran despite binding refusal");
        }
        return "amd64 systemd boot-ID and udev/sudo PID-only proc views with four binding refusals";
    }
    fn descendant(self: Harness, root: []const u8) !void {
        const value = std.mem.trim(u8, try self.ctx.read(root, marker, 64), " \r\n");
        _ = std.fmt.parseInt(u32, value, 10) catch return error.DetachedDescendantNeverStarted;
    }
    fn execute(self: Harness) !void {
        if (linux.geteuid() != 0 or linux.getegid() != 0) {
            try paths.writeAll(2, "protected reference proof requires UID/GID 0 (PermissionError)\n");
            return error.ProtectedReferenceProofRequiresRoot;
        }
        _ = c.umask(0o077);
        const args = self.options;
        for ([_][]const u8{ args.launcher, args.dpkg, args.runtime_tool, args.archive, args.escape_probe, args.escape_archive }) |path|
            _ = try paths.protected(path, false);
        try self.protectedDirectory(args.runtime, false);
        try self.protectedDirectory(args.root_template, false);
        try self.protectedDirectory(args.workspace, true);
        const identity = hex(std.crypto.hash.sha2.Sha256, try self.absoluteRead(args.dpkg, 8 * 1024 * 1024));
        const wanted = if (eq(u8, args.architecture, "amd64")) "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5" else "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79";
        try ensure(eq(u8, &identity, wanted), "reference dpkg executable is not the pinned architecture artifact");
        const signed_scripts = try self.profileScripts();
        const proc = try paths.protected(try join(self.ctx.a, args.root_template, "proc"), true);
        const mountpoint = try paths.protected(try join(self.ctx.a, args.root_template, ".debz-reference-archive"), false);
        const template = try paths.protected(args.root_template, true);
        try ensure(proc.mode & 0o7777 == 0o755 and mountpoint.mode & 0o7777 == 0o600 and mountpoint.nlink == 1 and mountpoint.size == 0 and
            mountpoint.dev_major == template.dev_major and mountpoint.dev_minor == template.dev_minor, "protected proof template has invalid proc/archive mountpoints");
        for ([_]order.Package{
            .{ .name = "proof", .version = "1", .architecture = args.architecture, .digest = args.archive_sha512, .size = args.archive_size, .archive = args.archive },
            .{ .name = "escape", .version = "1", .architecture = args.architecture, .digest = args.escape_archive_sha512, .size = args.escape_archive_size, .archive = args.escape_archive },
        }) |package| {
            if (package.digest.len != 128 or package.size == 0 or package.size > order.maximum_archive_bytes) return error.InvalidAuthenticatedArchiveIdentity;
            for (package.digest) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidAuthenticatedArchiveIdentity;
            order.verifyArchive(package) catch |err| {
                try paths.writeAll(2, if (err == error.ReferenceArchiveSizeChanged) "authenticated archive size differs\n" else "authenticated archive SHA512 differs\n");
                return err;
            };
        }
        try self.proveRuntime(&identity);
        for ([_][]const u8{ "probe", "unpack" }) |name| {
            const root = try self.freshRoot(args.workspace, name);
            const root_before = try paths.protected(root, true);
            const etc_before = try paths.protected(try join(self.ctx.a, root, "etc"), true);
            const parent = try paths.openAbsolute(args.workspace, true);
            defer parent.close();
            const inherited: i32 = @intCast(try paths.syscall(linux.fcntl(parent.fd, linux.F.DUPFD, 200)));
            defer _ = linux.close(inherited);
            const result = try self.standard(name, root, if (eq(u8, name, "probe")) "probe_unpack" else "unpack", inherited);
            try ensure(result.code == 0, "pinned dpkg refused protected probe/unpack");
            if (eq(u8, name, "probe")) {
                const root_after = try paths.protected(root, true);
                const etc_after = try paths.protected(try join(self.ctx.a, root, "etc"), true);
                try ensure(root_before.mtime.sec == root_after.mtime.sec and root_before.mtime.nsec == root_after.mtime.nsec and
                    etc_before.mtime.sec == etc_after.mtime.sec and etc_before.mtime.nsec == etc_after.mtime.nsec, "read-only probe changed directory timestamps through temporary runtime mounts");
            } else try ensure((try self.ctx.database(root)).len != 0, "pinned dpkg reported success without database entry");
        }
        for ([_][]const u8{ "wrong-digest", "wrong-size" }) |name| {
            const root = try self.freshRoot(args.workspace, name);
            const digest = if (eq(u8, name, "wrong-digest")) (if (eq(u8, args.archive_sha512, "0" ** 128)) "1" ** 128 else "0" ** 128) else args.archive_sha512;
            const size = if (eq(u8, name, "wrong-size")) (if (args.archive_size < order.maximum_archive_bytes) args.archive_size + 1 else args.archive_size - 1) else args.archive_size;
            try require(try self.operation(name, root, args.runtime, args.archive, digest, size, "unpack", "none", try std.fmt.allocPrint(self.ctx.a, "debz-reference-proof:{s}", .{args.architecture}), false, null), if (eq(u8, name, "wrong-digest")) "SourceChanged" else "InvalidSourceFile");
            try ensure((try self.ctx.read(root, "var/lib/dpkg/status", 4 * 1024 * 1024)).len == 0, "root database changed after refusal");
        }
        const bad_output = try self.freshRoot(args.workspace, "bad-output");
        try require(try self.operation("bad-output", bad_output, args.runtime, args.archive, args.archive_sha512, args.archive_size, "unpack", "none", try std.fmt.allocPrint(self.ctx.a, "debz-reference-proof:{s}", .{args.architecture}), true, null), "InvalidStandardStream");
        const symlink_root = try self.freshRoot(args.workspace, "symlink");
        const root_alias = try join(self.ctx.a, args.workspace, "symlink-to-root");
        try self.ctx.checked(&.{ "ln", "-s", "--", symlink_root, root_alias }, 30);
        try require(try self.standard("symlink", root_alias, "unpack", null), "ReferenceSetupFailed");
        const archive_root = try self.freshRoot(args.workspace, "symlink-archive");
        const archive_alias = try join(self.ctx.a, args.workspace, "symlink-to-archive");
        try self.ctx.checked(&.{ "ln", "-s", "--", args.archive, archive_alias }, 30);
        try require(try self.operation("symlink-archive", archive_root, args.runtime, archive_alias, args.archive_sha512, args.archive_size, "unpack", "none", try std.fmt.allocPrint(self.ctx.a, "debz-reference-proof:{s}", .{args.architecture}), false, null), "ReferenceSetupFailed");
        const writable_parent = try join(self.ctx.a, args.workspace, "writable-parent");
        try self.ctx.checked(&.{ "mkdir", "-m", "0700", "--", writable_parent }, 30);
        const writable_root = try self.freshRoot(writable_parent, "writable");
        try self.ctx.checked(&.{ "chmod", "0777", "--", writable_parent }, 30);
        {
            defer self.ctx.checked(&.{ "chmod", "0700", "--", writable_parent }, 30) catch {};
            try require(try self.standard("writable", writable_root, "unpack", null), "UnprotectedPath");
        }
        const control_fd = try paths.create(args.workspace, "escape-control.stdout", 0o600, false);
        defer _ = linux.close(control_fd);
        const control_code = try self.ctx.runFiles(&.{ args.escape_probe, "control" }, control_fd, control_fd, 45);
        const control_results = try probeResults(self.ctx.a, try self.ctx.read(args.workspace, "escape-control.stdout", order.maximum_probe_output));
        try ensure(control_code == 1 and eq(u8, control_results.get("result") orelse "", "FAIL"), "unconfined probe did not observe root authority");
        for (escape_checks) |check| {
            if (eq(u8, check, control_exempt[0]) or eq(u8, check, control_exempt[1])) continue;
            try ensure(eq(u8, control_results.get(check) orelse "", "FAIL"), check);
        }
        const escape_root = try self.freshRoot(args.workspace, "escape");
        const network = try self.networkControl("escape", escape_root);
        const observed = blk: {
            defer network.close();
            break :blk try self.operation("escape", escape_root, args.runtime, args.escape_archive, args.escape_archive_sha512, args.escape_archive_size, "unpack", "none", try std.fmt.allocPrint(self.ctx.a, "debz-reference-escape-probe:{s}", .{args.architecture}), false, network.inherited);
        };
        try ensure(observed.code == 0, "confined pinned-dpkg escape probe refused");
        const results = try probeResults(self.ctx.a, observed.stdout);
        for (escape_checks ++ confined_checks ++ .{ "private-network", "result" }) |check| try ensure(eq(u8, results.get(check) orelse "", "ok"), check);
        try ensure(eq(u8, (try probeDetail(self.ctx.a, observed.stdout, "archive-mount")).get("size") orelse "", try std.fmt.allocPrint(self.ctx.a, "{d}", .{args.escape_archive_size})), "bound archive is not authenticated escape archive");
        try self.descendant(escape_root);
        const records = try self.ctx.database(escape_root);
        try ensure(records.len == 1 and eq(u8, order.field(records[0], "package"), "debz-reference-escape-probe") and
            eq(u8, order.field(records[0], "architecture"), args.architecture), "pinned dpkg did not record probe package");
        const profile_result = try self.proveProfiles(signed_scripts);
        try paths.writeAll(1, try std.fmt.allocPrint(self.ctx.a, "protected pinned-dpkg runtime: ten loader/recursive-library and one preload preflight refusals; probe/unpack, six refusals, unconfined escape control and {d} confined escape checks, read-only archive mount and descendant teardown, denied reachable-host TCP/abstract-UNIX and inherited sockets, private interface/IPv4/IPv6 route observation and usable loopback, {s}: executed without skips\n", .{ escape_checks.len, profile_result }));
    }
};
const Network = struct {
    tcp: i32,
    unix: i32,
    inherited: i32,
    fn close(self: Network) void {
        _ = c.close(self.inherited);
        _ = c.close(self.tcp);
        _ = c.close(self.unix);
    }
};
fn databaseRows(a: A, records: []order.Fields) ![][]const []const u8 {
    const result = try a.alloc([]const []const u8, records.len);
    for (records, result) |record, *row| {
        const values = try a.alloc([]const u8, 3);
        values[0] = try std.fmt.allocPrint(a, "{s}:{s}", .{ order.field(record, "package"), order.field(record, "architecture") });
        values[1] = order.field(record, "status");
        values[2] = order.field(record, "version");
        row.* = values;
    }
    std.mem.sort([]const []const u8, result, {}, struct {
        fn less(_: void, left: []const []const u8, right: []const []const u8) bool {
            return std.mem.lessThan(u8, left[0], right[0]);
        }
    }.less);
    return result;
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(a);
    var values: std.StringHashMap([]const u8) = .init(a);
    var index: usize = 1;
    while (index < argv.len) : (index += 2) {
        if (index + 1 == argv.len or values.contains(argv[index])) return error.InvalidProtectedProofArguments;
        try values.put(argv[index], argv[index + 1]);
    }
    var options: Options = undefined;
    inline for (@typeInfo(Options).@"struct".fields) |field| {
        const key = comptime blk: {
            var text = ("--" ++ field.name).*;
            for (&text) |*byte| if (byte.* == '_') {
                byte.* = '-';
            };
            break :blk text;
        };
        const value = values.get(&key) orelse return error.InvalidProtectedProofArguments;
        if (field.type == usize) @field(options, field.name) = try std.fmt.parseInt(usize, value, 10) else @field(options, field.name) = value;
    }
    if (values.count() != @typeInfo(Options).@"struct".fields.len or
        (!eq(u8, options.architecture, "amd64") and !eq(u8, options.architecture, "arm64"))) return error.InvalidProtectedProofArguments;
    var environment: std.process.Environ.Map = .init(a);
    for ([_][2][]const u8{
        .{ "PATH", "/usr/sbin:/usr/bin:/sbin:/bin" }, .{ "HOME", "/" },                           .{ "LC_ALL", "C" },
        .{ "DEBIAN_FRONTEND", "noninteractive" },     .{ "DEBCONF_NONINTERACTIVE_SEEN", "true" }, .{ "DPKG_COLORS", "never" },
    }) |entry| try environment.put(entry[0], entry[1]);
    const harness: Harness = .{ .ctx = .{ .a = a, .io = init.io, .environment = &environment, .launcher = .{ .path = options.launcher, .runtime = options.runtime }, .dpkg = options.dpkg, .root = options.root_template, .cache = "/", .evidence = options.workspace, .architecture = options.architecture }, .options = options };
    return harness.execute();
}

test "original escape report requires exactly one check and one bound detail" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const original = "Preparing to unpack /.debz-reference-archive ...\ndebz-escape-probe: mount-denied ok errno=PERM\ndebz-escape-probe: shared-network-namespace info inet_socket=SUCCESS\ndebz-escape-probe: result ok failures=0 mode=install\n";
    const result = try probeResults(a, original);
    try std.testing.expectEqual(@as(usize, 2), result.count());
    try std.testing.expectEqualStrings("ok", result.get("mount-denied").?);
    try std.testing.expectEqualStrings("ok", result.get("result").?);
    try std.testing.expectError(error.AmbiguousEscapeProbeReport, probeResults(a, "debz-escape-probe: mount-denied ok\ndebz-escape-probe: mount-denied FAIL"));
    try std.testing.expectError(error.AmbiguousEscapeProbeReport, probeResults(a, "debz-escape-probe: mount-denied skipped"));
    const mounted = "debz-escape-probe: archive-mount ok size=4096 mount_root=true write=ROFS";
    try std.testing.expectEqualStrings("4096", (try probeDetail(a, mounted, "archive-mount")).get("size").?);
    try std.testing.expectError(error.MissingEscapeProbeDetail, probeDetail(a, "", "archive-mount"));
    try std.testing.expectError(error.MissingEscapeProbeDetail, probeDetail(a, try std.mem.replaceOwned(u8, a, mounted, " ok ", " FAIL "), "archive-mount"));
    try std.testing.expectError(error.AmbiguousEscapeProbeDetail, probeDetail(a, mounted ++ "\n" ++ mounted, "archive-mount"));
}

test "original escape control confined and signed profile vocabularies match the probe and ordering profiles" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const original_escape = [_][]const u8{
        "pid-namespace",        "no-proc-view",         "inherited-descriptors", "no-new-privileges",
        "seccomp-filter",       "capabilities",         "path-escape",           "re-chroot-denied",
        "pivot-root-denied",    "handle-escape-denied", "mount-denied",          "umount-denied",
        "move-mount-denied",    "device-node-denied",   "module-load-denied",    "module-file-denied",
        "module-remove-denied", "host-admin-denied",    "host-time-denied",      "raw-network-denied",
        "unshare-denied",       "setns-denied",         "clone-user-denied",     "clone-network-denied",
        "clone-mount-denied",   "clone3-denied",
    };
    try std.testing.expectEqual(original_escape.len, escape_checks.len);
    for (original_escape, escape_checks) |expected, actual| try std.testing.expectEqualStrings(expected, actual);
    const original_exempt = [_][]const u8{ "inherited-descriptors", "path-escape" };
    try std.testing.expectEqual(original_exempt.len, control_exempt.len);
    for (original_exempt, control_exempt) |expected, actual| try std.testing.expectEqualStrings(expected, actual);
    var detected: usize = 0;
    for (escape_checks) |check| {
        var exempt = false;
        for (control_exempt) |name| exempt = exempt or eq(u8, check, name);
        if (!exempt) detected += 1;
    }
    for (control_exempt) |exempt| {
        var found: usize = 0;
        for (escape_checks) |check| if (eq(u8, check, exempt)) {
            found += 1;
        };
        try std.testing.expectEqual(@as(usize, 1), found);
    }
    try std.testing.expectEqual(escape_checks.len, detected + control_exempt.len);
    for (confined_checks) |confined| for (escape_checks) |check| try std.testing.expect(!eq(u8, confined, check));
    try std.testing.expectEqualStrings("no-proc-view", profile_exempt);
    const probe = @embedFile("real-snapshot-reference-escape-probe.zig");
    const views = [_][]const u8{ "proc-read-only", "proc-sys-masked", "proc-boot-id", "proc-pid-only" };
    for (escape_checks ++ confined_checks ++ profile_common ++ views ++ [_][]const u8{"result"}) |check|
        try std.testing.expect(std.mem.indexOf(u8, probe, try std.fmt.allocPrint(a, "\"{s}\"", .{check})) != null);
    try std.testing.expectEqual(order.script_profiles.len, profiles.len);
    for (profiles) |profile| {
        var matches: usize = 0;
        for (order.script_profiles) |entry| if (eq(u8, entry[0], profile)) {
            matches += 1;
            try std.testing.expectEqualStrings(entry[1], profileVersion(profile));
        };
        try std.testing.expectEqual(@as(usize, 1), matches);
    }
}

fn testHarness(a: A, env: *const std.process.Environ.Map, root: []const u8) !Harness {
    const options: Options = .{
        .launcher = "/unit/launcher",
        .runtime_tool = "/unit/runtime-tool",
        .dpkg = "/unit/dpkg",
        .runtime = try join(a, root, "runtime"),
        .root_template = try join(a, root, "template"),
        .workspace = root,
        .archive = "/unit/package.deb",
        .archive_sha512 = "a" ** 128,
        .archive_size = 42,
        .escape_probe = "/unit/escape-probe",
        .escape_archive = "/unit/escape.deb",
        .escape_archive_sha512 = "b" ** 128,
        .escape_archive_size = 42,
        .profile_scripts = root,
        .architecture = "amd64",
    };
    return .{ .options = options, .test_unprotected = true, .test_teardown = true, .ctx = .{ .a = a, .io = std.testing.io, .environment = env, .launcher = .{ .path = options.launcher, .runtime = options.runtime }, .dpkg = options.dpkg, .root = options.root_template, .evidence = root, .cache = root, .architecture = "amd64" } };
}
fn testRoot(a: A, work: std.testing.TmpDir) ![]const u8 {
    var buffer: [4096]u8 = undefined;
    const length = try work.dir.realPath(std.testing.io, &buffer);
    return a.dupe(u8, buffer[0..length]);
}

test "original amd64 profile staging is an exact bounded set and arm64 never borrows it" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var harness = try testHarness(a, &env, try testRoot(a, work));
    try std.testing.expectError(error.ProtectedReferenceProofFailed, harness.profileScripts());
    harness.options.architecture = "arm64";
    try std.testing.expect((try harness.profileScripts()).count() == 0);
    try work.dir.writeFile(std.testing.io, .{ .sub_path = "systemd.postinst", .data = "#!/bin/sh\n" });
    try std.testing.expectError(error.ProtectedReferenceProofFailed, harness.profileScripts());
    harness.options.architecture = "amd64";
    try std.testing.expectError(error.ProtectedReferenceProofFailed, harness.profileScripts());
    for (profiles) |profile| try work.dir.writeFile(std.testing.io, .{
        .sub_path = try std.fmt.allocPrint(a, "{s}.postinst", .{profile}),
        .data = try std.fmt.allocPrint(a, "#!/bin/sh\n# {s}\n", .{profile}),
    });
    const scripts = try harness.profileScripts();
    try std.testing.expectEqual(@as(usize, 3), scripts.count());
    for (profiles) |profile| try std.testing.expectEqualStrings(try std.fmt.allocPrint(a, "#!/bin/sh\n# {s}\n", .{profile}), scripts.get(profile).?);
    try work.dir.writeFile(std.testing.io, .{ .sub_path = "extra.postinst", .data = "#!/bin/sh\n" });
    try std.testing.expectError(error.ProtectedReferenceProofFailed, harness.profileScripts());
    try work.dir.deleteFile(std.testing.io, "extra.postinst");
    const oversized = try a.alloc(u8, 64 * 1024 + 1);
    @memset(oversized, '#');
    try work.dir.writeFile(std.testing.io, .{ .sub_path = "udev.postinst", .data = oversized });
    try std.testing.expectError(error.InvalidReferenceDatabaseFile, harness.profileScripts());
}

test "runtime mutation negatives retain eleven original cases without modifying private authority source" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    try env.put("PATH", "/usr/bin:/bin");
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const root = try testRoot(a, work);
    var harness = try testHarness(a, &env, root);
    for ([_][]const u8{ "runtime", "template/usr/lib", "template/var/lib/dpkg", "template/etc", "template/proc" }) |directory|
        try work.dir.createDirPath(std.testing.io, directory);
    const runtime_pin = try paths.openAbsolute(harness.options.runtime, true);
    defer runtime_pin.close();
    _ = try paths.syscall(linux.fchmod(runtime_pin.fd, 0o700));
    const original = "original library bytes";
    for ([_][]const u8{ "loader.so", "libpcre2-8.so.0" }) |name| {
        try work.dir.writeFile(std.testing.io, .{ .sub_path = try std.fmt.allocPrint(a, "runtime/{s}", .{name}), .data = original });
        try work.dir.writeFile(std.testing.io, .{ .sub_path = try std.fmt.allocPrint(a, "template/usr/lib/{s}", .{name}), .data = original });
    }
    const record = "{\"loader\":\"loader.so\",\"objects\":[{\"name\":\"loader.so\",\"root_path\":\"/usr/lib/loader.so\"},{\"name\":\"libpcre2-8.so.0\",\"root_path\":\"/usr/lib/libpcre2-8.so.0\"}]}";
    try work.dir.writeFile(std.testing.io, .{ .sub_path = "runtime/binding.json", .data = record });
    try work.dir.writeFile(std.testing.io, .{ .sub_path = "template/var/lib/dpkg/status", .data = "" });
    try work.dir.writeFile(std.testing.io, .{ .sub_path = "template/.debz-reference-archive", .data = "" });
    const Hooks = struct {
        fn operation(name: []const u8) order.Result {
            return .{ .code = 1, .stdout = "", .stderr = if (std.mem.endsWith(u8, name, "unbound-preload")) "UnboundRuntimePreload" else if (std.mem.endsWith(u8, name, "missing") or std.mem.endsWith(u8, name, "symlink")) "RuntimeInputRefused" else "RuntimeDigestChanged" };
        }
        fn run(_: *anyopaque, argv: []const []const u8) !?order.Result {
            if (eq(u8, argv[0], "/unit/runtime-tool")) return .{ .code = 0, .stdout = "", .stderr = "RuntimeSourceChanged; no dpkg or script executed" };
            return null;
        }
    };
    harness.test_operation = Hooks.operation;
    harness.ctx.test_hooks = .{ .state = &harness, .run = Hooks.run };
    try harness.proveRuntime("a" ** 64);
    const report = try std.json.parseFromSlice(std.json.Value, a, try harness.ctx.read(root, "runtime-preflight-proof.json", 128 * 1024), .{});
    try std.testing.expectEqual(@as(usize, 11), report.value.object.get("cases").?.object.count());
    for ([_][]const u8{ "loader.so", "libpcre2-8.so.0" }) |name| {
        try std.testing.expectEqualStrings(original, try harness.ctx.read(root, try std.fmt.allocPrint(a, "runtime/{s}", .{name}), 1024));
        var changed = original.*;
        changed[0] ^= 1;
        try std.testing.expectEqualStrings(&changed, try harness.ctx.read(root, try std.fmt.allocPrint(a, "runtime-{s}-altered-root/usr/lib/{s}", .{ name, name }), 1024));
        try std.testing.expectEqualStrings(&changed, try harness.ctx.read(root, try std.fmt.allocPrint(a, "runtime-{s}-private-altered-prefix/{s}", .{ name, name }), 1024));
        const alias = try std.fmt.allocPrint(a, "runtime-{s}-symlink-root/usr/lib/{s}", .{ name, name });
        try std.testing.expectError(error.ReferencePathRefused, harness.ctx.read(root, alias, 1024));
    }
}

test "original host network authority requires exact genuine receipt and retains all failed diagnostics" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    const receipt = "DEBZ_HOST_NETWORK_PROOF tcp=reachable abstract_unix=reachable inherited_fd=open\n";
    const Mock = struct {
        result: order.Result,
        calls: usize = 0,
        fn run(pointer: *anyopaque, argv: []const []const u8) !?order.Result {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            self.calls += 1;
            try std.testing.expectEqualStrings("network-host", argv[1]);
            const fd = try std.fmt.parseInt(i32, argv[4], 10);
            try std.testing.expect(fd >= 200);
            try std.testing.expectEqual(@as(usize, 0), try paths.syscall(linux.fcntl(fd, linux.F.GETFD, 0)));
            return self.result;
        }
    };
    for ([_]order.Result{
        .{ .code = 0, .stdout = receipt, .stderr = "original diagnostic\n" },
        .{ .code = 1, .stdout = receipt, .stderr = "original diagnostic\n" },
        .{ .code = 0, .stdout = "", .stderr = "original diagnostic\n" },
        .{ .code = 0, .stdout = receipt ++ "extra\n", .stderr = "original diagnostic\n" },
    }, 0..) |result, index| {
        var work = std.testing.tmpDir(.{ .iterate = true });
        defer work.cleanup();
        try work.dir.createDir(std.testing.io, "root", .default_dir);
        const root = try testRoot(a, work);
        var harness = try testHarness(a, &env, root);
        var mock: Mock = .{ .result = result };
        harness.ctx.test_hooks = .{ .state = &mock, .run = Mock.run };
        const test_root = try join(a, root, "root");
        if (index == 0) {
            const network = try harness.networkControl("fixture", test_root);
            defer network.close();
            try std.testing.expect(network.inherited >= 200);
            var fields = std.mem.splitScalar(u8, try harness.ctx.read(test_root, ".debz-network-control", 1024), '\n');
            try std.testing.expect(try std.fmt.parseInt(u16, fields.next().?, 10) > 0);
            try std.testing.expect(std.mem.startsWith(u8, fields.next().?, "debz-reference-"));
            try std.testing.expectEqual(network.inherited, try std.fmt.parseInt(i32, fields.next().?, 10));
        } else {
            try std.testing.expectError(error.ProtectedReferenceProofFailed, harness.networkControl("fixture", test_root));
            try std.testing.expect(!try paths.exists(test_root, ".debz-network-control"));
        }
        try std.testing.expectEqual(@as(usize, 1), mock.calls);
        try std.testing.expectEqualStrings(result.stdout, try harness.ctx.read(root, "fixture.network-host.stdout", 1024));
        try std.testing.expectEqualStrings(result.stderr, try harness.ctx.read(root, "fixture.network-host.stderr", 1024));
        const record = try std.json.parseFromSlice(std.json.Value, a, try harness.ctx.read(root, "fixture.network-host.json", 4096), .{});
        try std.testing.expectEqual(@as(i64, result.code), record.value.object.get("exit_status").?.integer);
    }
}
