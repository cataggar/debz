//! Require real root-owned pinned-dpkg namespace operations, never fixture skips.

const std = @import("std");
const linux = std.os.linux;
const reference_paths = @import("reference_paths");
const reference_order = @import("reference_order");
const escape_probe_source = @embedFile("real-snapshot-reference-escape-probe.zig");

pub const ESCAPE_CHECKS = [_][]const u8{
    "pid-namespace",
    "no-proc-view",
    "inherited-descriptors",
    "no-new-privileges",
    "seccomp-filter",
    "capabilities",
    "path-escape",
    "re-chroot-denied",
    "pivot-root-denied",
    "handle-escape-denied",
    "mount-denied",
    "umount-denied",
    "move-mount-denied",
    "device-node-denied",
    "module-load-denied",
    "module-file-denied",
    "module-remove-denied",
    "host-admin-denied",
    "host-time-denied",
    "raw-network-denied",
    "unshare-denied",
    "setns-denied",
    "clone-user-denied",
    "clone-network-denied",
    "clone-mount-denied",
    "clone3-denied",
};

pub const CONTROL_DETECTS = [_][]const u8{
    "pid-namespace",
    "no-proc-view",
    "no-new-privileges",
    "seccomp-filter",
    "capabilities",
    "re-chroot-denied",
    "pivot-root-denied",
    "handle-escape-denied",
    "mount-denied",
    "umount-denied",
    "move-mount-denied",
    "device-node-denied",
    "module-load-denied",
    "module-file-denied",
    "module-remove-denied",
    "host-admin-denied",
    "host-time-denied",
    "raw-network-denied",
    "unshare-denied",
    "setns-denied",
    "clone-user-denied",
    "clone-network-denied",
    "clone-mount-denied",
    "clone3-denied",
};

pub const DESCENDANT_MARKER = ".debz-escape-probe-descendant";
pub const CONFINED_CHECKS = [_][]const u8{ "archive-mount", "descendant-started" };

pub const PROFILE_ESCAPE_CHECKS = [_][]const u8{
    "pid-namespace",
    "inherited-descriptors",
    "no-new-privileges",
    "seccomp-filter",
    "capabilities",
    "path-escape",
    "re-chroot-denied",
    "pivot-root-denied",
    "handle-escape-denied",
    "mount-denied",
    "umount-denied",
    "move-mount-denied",
    "device-node-denied",
    "module-load-denied",
    "module-file-denied",
    "module-remove-denied",
    "host-admin-denied",
    "host-time-denied",
    "raw-network-denied",
    "unshare-denied",
    "setns-denied",
    "clone-user-denied",
    "clone-network-denied",
    "clone-mount-denied",
    "clone3-denied",
};

pub const PROFILE_COMMON_CHECKS = [_][]const u8{
    "proc-mount",
    "proc-root",
    "proc-hidepid",
    "archive-unbound",
    "descendant-started",
};

pub const ProfileViewEntry = struct {
    profile: []const u8,
    checks: []const []const u8,
};

pub const PROFILE_VIEW_CHECKS = [_]ProfileViewEntry{
    .{ .profile = "systemd", .checks = &.{ "proc-read-only", "proc-sys-masked", "proc-boot-id" } },
    .{ .profile = "udev", .checks = &.{"proc-pid-only"} },
    .{ .profile = "sudo", .checks = &.{"proc-pid-only"} },
};

pub const PROFILE_SCRIPT_LIMIT: usize = 64 * 1024;

pub const PINNED_DPKG_DIGESTS = [_]struct { architecture: []const u8, sha256: []const u8 }{
    .{ .architecture = "amd64", .sha256 = "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5" },
    .{ .architecture = "arm64", .sha256 = "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79" },
};

pub fn profileViewChecks(profile: []const u8) ?[]const []const u8 {
    for (PROFILE_VIEW_CHECKS) |entry| {
        if (std.mem.eql(u8, entry.profile, profile)) return entry.checks;
    }
    return null;
}

pub fn pinnedDpkgDigest(architecture: []const u8) ?[]const u8 {
    for (PINNED_DPKG_DIGESTS) |entry| {
        if (std.mem.eql(u8, entry.architecture, architecture)) return entry.sha256;
    }
    return null;
}

pub fn profileVersion(profile: []const u8) ?[]const u8 {
    for (reference_order.profile_versions) |entry| {
        if (std.mem.eql(u8, entry.name, profile)) return entry.version;
    }
    return null;
}

const Meta = struct {
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    dev: u64,
    ino: u64,
    nlink: u64,
    rdev_major: u32,
    rdev_minor: u32,
};

fn syscall(rc: usize) !usize {
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .NOENT => error.FileNotFound,
        .EXIST => error.PathAlreadyExists,
        .ACCES, .PERM => error.AccessDenied,
        .NOTDIR => error.NotDir,
        .ISDIR => error.IsDir,
        .LOOP => error.SymLinkLoop,
        else => error.SystemResources,
    };
}

fn cPath(path: []const u8, buf: *[std.fs.max_path_bytes]u8) ![*:0]const u8 {
    if (path.len == 0 or path.len >= buf.len or std.mem.indexOfScalar(u8, path, 0) != null) {
        return error.InvalidPath;
    }
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0].ptr;
}

fn lstatPath(path: []const u8) !Meta {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(path, &buf);
    var stx: linux.Statx = undefined;
    _ = try syscall(linux.statx(
        linux.AT.FDCWD,
        ptr,
        linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT,
        .BASIC_STATS,
        &stx,
    ));
    return .{
        .mode = stx.mode,
        .uid = stx.uid,
        .gid = stx.gid,
        .size = stx.size,
        .dev = (@as(u64, stx.dev_major) << 32) | stx.dev_minor,
        .ino = stx.ino,
        .nlink = stx.nlink,
        .rdev_major = stx.rdev_major,
        .rdev_minor = stx.rdev_minor,
    };
}

fn statFollowPath(path: []const u8) !Meta {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(path, &buf);
    var stx: linux.Statx = undefined;
    _ = try syscall(linux.statx(
        linux.AT.FDCWD,
        ptr,
        linux.AT.NO_AUTOMOUNT,
        .BASIC_STATS,
        &stx,
    ));
    return .{
        .mode = stx.mode,
        .uid = stx.uid,
        .gid = stx.gid,
        .size = stx.size,
        .dev = (@as(u64, stx.dev_major) << 32) | stx.dev_minor,
        .ino = stx.ino,
        .nlink = stx.nlink,
        .rdev_major = stx.rdev_major,
        .rdev_minor = stx.rdev_minor,
    };
}

fn statMtimeNs(path: []const u8) !i128 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(path, &buf);
    var stx: linux.Statx = undefined;
    _ = try syscall(linux.statx(
        linux.AT.FDCWD,
        ptr,
        linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT,
        .BASIC_STATS,
        &stx,
    ));
    return @as(i128, stx.mtime.sec) * 1_000_000_000 + stx.mtime.nsec;
}

fn listDirNames(allocator: std.mem.Allocator, dir_path: []const u8) !std.ArrayList([]const u8) {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(dir_path, &buf);
    const fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        ptr,
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    )));
    defer _ = linux.close(fd);
    var names: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (names.items) |item| allocator.free(item);
        names.deinit(allocator);
    }
    var dent_buf: [8192]u8 align(@alignOf(linux.dirent64)) = undefined;
    while (true) {
        const nread = try syscall(linux.getdents64(fd, &dent_buf, dent_buf.len));
        if (nread == 0) break;
        var offset: usize = 0;
        while (offset < nread) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&dent_buf[offset]);
            const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
            const name = std.mem.span(name_ptr);
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                try names.append(allocator, try allocator.dupe(u8, name));
            }
            offset += entry.reclen;
        }
    }
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    return names;
}

fn freeStringList(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8)) void {
    for (list.items) |item| allocator.free(item);
    list.deinit(allocator);
}

pub fn protectedDirectory(path: []const u8, empty: bool) !void {
    const metadata = try reference_paths.protected(path, true);
    if ((metadata.mode & 0o7777) != 0o700) return error.UnprotectedProofDirectory;
    if (empty) {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const ptr = try cPath(path, &buf);
        const fd: i32 = @intCast(try syscall(linux.openat(
            linux.AT.FDCWD,
            ptr,
            .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
            0,
        )));
        defer _ = linux.close(fd);
        var dent_buf: [4096]u8 align(@alignOf(linux.dirent64)) = undefined;
        while (true) {
            const nread = try syscall(linux.getdents64(fd, &dent_buf, dent_buf.len));
            if (nread == 0) break;
            var offset: usize = 0;
            while (offset < nread) {
                const entry: *align(1) const linux.dirent64 = @ptrCast(&dent_buf[offset]);
                const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
                const name = std.mem.span(name_ptr);
                if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                    return error.NonEmptyProofWorkspace;
                }
                offset += entry.reclen;
            }
        }
    }
}

fn readHostFile(allocator: std.mem.Allocator, path: []const u8, limit: usize) ![]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(path, &buf);
    const fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        ptr,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    )));
    defer _ = linux.close(fd);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const got = try syscall(linux.read(fd, &chunk, chunk.len));
        if (got == 0) break;
        if (out.items.len + got > limit) return error.FileTooLarge;
        try out.appendSlice(allocator, chunk[0..got]);
    }
    return try out.toOwnedSlice(allocator);
}

fn unescapeMountField(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var idx: usize = 0;
    while (idx < raw.len) {
        if (idx + 4 <= raw.len and std.mem.eql(u8, raw[idx .. idx + 4], "\\040")) {
            try out.append(allocator, ' ');
            idx += 4;
        } else if (idx + 4 <= raw.len and std.mem.eql(u8, raw[idx .. idx + 4], "\\011")) {
            try out.append(allocator, '\t');
            idx += 4;
        } else {
            try out.append(allocator, raw[idx]);
            idx += 1;
        }
    }
    return try out.toOwnedSlice(allocator);
}

pub const TeardownReport = struct {
    polls: usize,
    processes_scanned: usize,
    mountinfo_entries: usize,
    archive_size: u64,
    archive_nlink: u64,
    archive_mode: u16,
};

pub fn assertTeardown(allocator: std.mem.Allocator, root: []const u8) !TeardownReport {
    const root_meta = try lstatPath(root);
    var polls: usize = 0;
    var scanned: usize = 0;
    for (0..20) |attempt| {
        polls = attempt + 1;
        scanned = 0;
        var surviving: usize = 0;
        var proc_entries = try listDirNames(allocator, "/proc");
        defer freeStringList(allocator, &proc_entries);
        for (proc_entries.items) |entry_name| {
            var all_digits = entry_name.len > 0;
            for (entry_name) |ch| {
                if (!std.ascii.isDigit(ch)) {
                    all_digits = false;
                    break;
                }
            }
            if (!all_digits) continue;
            scanned += 1;
            const proc_root_path = try std.fmt.allocPrint(allocator, "/proc/{s}/root", .{entry_name});
            defer allocator.free(proc_root_path);
            const current = statFollowPath(proc_root_path) catch continue;
            if (current.dev == root_meta.dev and current.ino == root_meta.ino) {
                surviving += 1;
            }
        }
        if (surviving == 0) break;
        if (attempt == 19) return error.ProcessesRetainReferenceRoot;
        var delay: linux.timespec = .{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
        _ = linux.nanosleep(&delay, null);
    }

    const mountinfo = try readHostFile(allocator, "/proc/self/mountinfo", 4 * 1024 * 1024);
    defer allocator.free(mountinfo);
    var mounts: usize = 0;
    var lines = std.mem.splitScalar(u8, mountinfo, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        mounts += 1;
        var fields = std.mem.splitScalar(u8, line, ' ');
        _ = fields.next();
        _ = fields.next();
        _ = fields.next();
        _ = fields.next();
        const raw_mp = fields.next() orelse continue;
        const mountpoint = try unescapeMountField(allocator, raw_mp);
        defer allocator.free(mountpoint);
        if (std.mem.eql(u8, mountpoint, root) or
            (mountpoint.len > root.len and std.mem.startsWith(u8, mountpoint, root) and mountpoint[root.len] == '/'))
        {
            return error.ReferenceMountSurvived;
        }
    }

    const archive_path = try std.fmt.allocPrint(allocator, "{s}/.debz-reference-archive", .{root});
    defer allocator.free(archive_path);
    const archive = try lstatPath(archive_path);
    const proc_path = try std.fmt.allocPrint(allocator, "{s}/proc", .{root});
    defer allocator.free(proc_path);
    var proc_names = try listDirNames(allocator, proc_path);
    defer freeStringList(allocator, &proc_names);
    if ((archive.mode & linux.S.IFMT) != linux.S.IFREG or
        archive.size != 0 or
        archive.nlink != 1 or
        proc_names.items.len != 0)
    {
        return error.ReferenceMountpointChanged;
    }

    const runtime_path = try std.fmt.allocPrint(allocator, "{s}/.debz-reference-runtime", .{root});
    defer allocator.free(runtime_path);
    if (lstatPath(runtime_path)) |_| {
        return error.TemporaryReferenceRuntimeSurvived;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    return .{
        .polls = polls,
        .processes_scanned = scanned,
        .mountinfo_entries = mounts,
        .archive_size = archive.size,
        .archive_nlink = archive.nlink,
        .archive_mode = archive.mode & 0o7777,
    };
}

fn chmodPath(path: []const u8, mode: usize) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(path, &buf);
    _ = try syscall(linux.fchmodat(linux.AT.FDCWD, ptr, @intCast(mode)));
}

fn mkdirPath(path: []const u8, mode: usize) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(path, &buf);
    _ = try syscall(linux.mkdirat(linux.AT.FDCWD, ptr, @intCast(mode)));
}

fn symlinkPath(target: []const u8, link_path: []const u8) !void {
    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    const target_ptr = try cPath(target, &target_buf);
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_ptr = try cPath(link_path, &link_buf);
    _ = try syscall(linux.symlinkat(target_ptr, linux.AT.FDCWD, link_ptr));
}

fn readlinkPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_ptr = try cPath(path, &path_buf);
    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try syscall(linux.readlinkat(linux.AT.FDCWD, path_ptr, &target_buf, target_buf.len));
    return try allocator.dupe(u8, target_buf[0..len]);
}

fn unlinkPath(path: []const u8) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(path, &buf);
    _ = try syscall(linux.unlinkat(linux.AT.FDCWD, ptr, 0));
}

fn copyRegularFile(src: []const u8, dst: []const u8, mode: usize) !void {
    var src_buf: [std.fs.max_path_bytes]u8 = undefined;
    const src_ptr = try cPath(src, &src_buf);
    const src_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        src_ptr,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    )));
    defer _ = linux.close(src_fd);

    var dst_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dst_ptr = try cPath(dst, &dst_buf);
    const dst_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        dst_ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true },
        @intCast(mode),
    )));
    defer _ = linux.close(dst_fd);

    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const got = try syscall(linux.read(src_fd, &chunk, chunk.len));
        if (got == 0) break;
        var written: usize = 0;
        while (written < got) {
            written += try syscall(linux.write(dst_fd, chunk[written..got].ptr, got - written));
        }
    }
    _ = try syscall(linux.fchmod(dst_fd, @intCast(mode)));
}

fn copyTemplateTreeRecursive(
    allocator: std.mem.Allocator,
    template_root: []const u8,
    src_dir: []const u8,
    dst_dir: []const u8,
    is_root: bool,
) !void {
    const dir_meta = try lstatPath(src_dir);
    try mkdirPath(dst_dir, if (is_root) 0o700 else (dir_meta.mode & 0o7777));
    var names = try listDirNames(allocator, src_dir);
    defer freeStringList(allocator, &names);
    for (names.items) |name| {
        const src_child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ src_dir, name });
        defer allocator.free(src_child);
        const dst_child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dst_dir, name });
        defer allocator.free(dst_child);
        const meta = try lstatPath(src_child);
        const kind = meta.mode & linux.S.IFMT;
        if (kind == linux.S.IFDIR) {
            try copyTemplateTreeRecursive(allocator, template_root, src_child, dst_child, false);
        } else if (kind == linux.S.IFLNK) {
            const target = try readlinkPath(allocator, src_child);
            defer allocator.free(target);
            try symlinkPath(target, dst_child);
        } else if (kind == linux.S.IFCHR) {
            const rel = src_child[template_root.len + 1 ..];
            if (!std.mem.eql(u8, rel, "dev/null") or meta.rdev_major != 1 or meta.rdev_minor != 3) {
                return error.UnsupportedProtectedTemplateMember;
            }
            var dst_buf: [std.fs.max_path_bytes]u8 = undefined;
            const dst_ptr = try cPath(dst_child, &dst_buf);
            const rdev: u32 = (1 << 8) | 3;
            _ = try syscall(linux.mknodat(
                linux.AT.FDCWD,
                dst_ptr,
                linux.S.IFCHR | @as(u32, meta.mode & 0o7777),
                rdev,
            ));
        } else if (kind == linux.S.IFREG) {
            try copyRegularFile(src_child, dst_child, meta.mode & 0o7777);
        } else {
            return error.UnsupportedProtectedTemplateMember;
        }
    }
    try chmodPath(dst_dir, if (is_root) 0o700 else (dir_meta.mode & 0o7777));
}

pub fn freshRoot(
    allocator: std.mem.Allocator,
    template: []const u8,
    workspace: []const u8,
    name: []const u8,
) ![]u8 {
    const destination = try std.fmt.allocPrint(allocator, "{s}/{s}-root", .{ workspace, name });
    errdefer allocator.free(destination);
    try copyTemplateTreeRecursive(allocator, template, template, destination, true);
    try protectedDirectory(destination, false);
    const status = try reference_paths.readRootFile(allocator, destination, "var/lib/dpkg/status", 4 * 1024 * 1024);
    defer allocator.free(status);
    if (status.len != 0) return error.NonEmptyProofTemplateDatabase;
    const proc_dir = try std.fmt.allocPrint(allocator, "{s}/proc", .{destination});
    defer allocator.free(proc_dir);
    var proc_names = try listDirNames(allocator, proc_dir);
    defer freeStringList(allocator, &proc_names);
    if (proc_names.items.len != 0) return error.NonEmptyProofTemplateProc;
    return destination;
}

pub fn probeDetail(
    allocator: std.mem.Allocator,
    output: []const u8,
    check: []const u8,
) !std.StringHashMap([]const u8) {
    const prefix = try std.fmt.allocPrint(allocator, "debz-escape-probe: {s} ok ", .{check});
    defer allocator.free(prefix);
    var matched_line: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (std.mem.startsWith(u8, line, prefix)) {
            if (matched_line != null) return error.AmbiguousEscapeProbeDetail;
            matched_line = line[prefix.len..];
        }
    }
    const detail_line = matched_line orelse return error.MissingEscapeProbeDetail;
    var details = std.StringHashMap([]const u8).init(allocator);
    errdefer {
        var it = details.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        details.deinit();
    }
    var fields = std.mem.tokenizeAny(u8, detail_line, " \t");
    while (fields.next()) |field| {
        const eq = std.mem.indexOfScalar(u8, field, '=') orelse continue;
        const k = try allocator.dupe(u8, field[0..eq]);
        errdefer allocator.free(k);
        const v = try allocator.dupe(u8, field[eq + 1 ..]);
        errdefer allocator.free(v);
        if (details.fetchRemove(k)) |old| {
            allocator.free(old.key);
            allocator.free(old.value);
        }
        try details.put(k, v);
    }
    return details;
}

pub fn freeStringMap(allocator: std.mem.Allocator, map: *std.StringHashMap([]const u8)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        allocator.free(entry.value_ptr.*);
    }
    map.deinit();
}

pub fn probeResults(
    allocator: std.mem.Allocator,
    output: []const u8,
) !std.StringHashMap([]const u8) {
    var results = std.StringHashMap([]const u8).init(allocator);
    errdefer freeStringMap(allocator, &results);
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        var fields = std.mem.splitScalar(u8, line, ' ');
        const first = fields.next() orelse continue;
        const check = fields.next() orelse continue;
        const status = fields.next() orelse continue;
        if (!std.mem.eql(u8, first, "debz-escape-probe:") or std.mem.eql(u8, status, "info")) continue;
        if (results.contains(check) or (!std.mem.eql(u8, status, "ok") and !std.mem.eql(u8, status, "FAIL"))) {
            return error.AmbiguousEscapeProbeReport;
        }
        const key_copy = try allocator.dupe(u8, check);
        errdefer allocator.free(key_copy);
        const val_copy = try allocator.dupe(u8, status);
        errdefer allocator.free(val_copy);
        try results.put(key_copy, val_copy);
    }
    return results;
}

pub fn writeBeneath(
    root: []const u8,
    relative: []const u8,
    data: []const u8,
    mode: usize,
    replace: bool,
) !void {
    const slash = std.mem.lastIndexOfScalar(u8, relative, '/');
    const parent = if (slash) |idx| relative[0..idx] else "";
    const name = if (slash) |idx| relative[idx + 1 ..] else relative;
    if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) {
        return error.InvalidRelativePath;
    }
    var root_fd = try reference_paths.openAbsolute(root, true);
    const directory = blk: {
        errdefer if (root_fd >= 0) {
            _ = linux.close(root_fd);
        };
        if (parent.len == 0) {
            const d = root_fd;
            root_fd = -1;
            break :blk d;
        }
        const d = try reference_paths.openBeneath(root_fd, parent, true);
        _ = linux.close(root_fd);
        root_fd = -1;
        break :blk d;
    };
    defer _ = linux.close(directory);

    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    const name_ptr = try cPath(name, &name_buf);
    const flags: linux.O = if (replace)
        .{ .ACCMODE = .WRONLY, .TRUNC = true, .NOFOLLOW = true, .CLOEXEC = true }
    else
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true };
    const fd: i32 = @intCast(try syscall(linux.openat(directory, name_ptr, flags, @intCast(mode))));
    defer _ = linux.close(fd);
    const meta = try reference_paths.fstat(fd);
    if ((meta.mode & linux.S.IFMT) != linux.S.IFREG) return error.NotRegularFile;
    _ = try syscall(linux.fchmod(fd, @intCast(mode)));
    var written: usize = 0;
    while (written < data.len) {
        written += try syscall(linux.write(fd, data[written..].ptr, data.len - written));
    }
}

pub fn profileScripts(
    allocator: std.mem.Allocator,
    directory: []const u8,
    architecture: []const u8,
) !std.StringHashMap([]const u8) {
    _ = try reference_paths.protected(directory, true);
    var names = try listDirNames(allocator, directory);
    defer freeStringList(allocator, &names);

    var scripts = std.StringHashMap([]const u8).init(allocator);
    errdefer freeStringMap(allocator, &scripts);

    if (!std.mem.eql(u8, architecture, "amd64")) {
        if (names.items.len != 0) return error.UnexpectedArchitectureProfileScripts;
        return scripts;
    }
    const expected = [_][]const u8{ "sudo.postinst", "systemd.postinst", "udev.postinst" };
    if (names.items.len != expected.len) return error.InvalidProfileScripts;
    for (expected, 0..) |exp, idx| {
        if (!std.mem.eql(u8, names.items[idx], exp)) return error.InvalidProfileScripts;
    }
    for (PROFILE_VIEW_CHECKS) |entry| {
        const script_path = try std.fmt.allocPrint(allocator, "{s}/{s}.postinst", .{ directory, entry.profile });
        defer allocator.free(script_path);
        const meta = try reference_paths.protected(script_path, false);
        if (meta.size > PROFILE_SCRIPT_LIMIT) return error.ProfileScriptExceedsLimit;
        const bytes = try readHostFile(allocator, script_path, PROFILE_SCRIPT_LIMIT);
        errdefer allocator.free(bytes);
        const key = try allocator.dupe(u8, entry.profile);
        errdefer allocator.free(key);
        try scripts.put(key, bytes);
    }
    return scripts;
}

pub fn profileRoot(
    allocator: std.mem.Allocator,
    template: []const u8,
    workspace: []const u8,
    name: []const u8,
    profile: []const u8,
    script: []const u8,
    probe: []const u8,
    version: ?[]const u8,
) ![]u8 {
    const root = try freshRoot(allocator, template, workspace, name);
    errdefer allocator.free(root);
    const resolved_version = version orelse (profileVersion(profile) orelse return error.UnknownProfile);
    const status_bytes = try std.fmt.allocPrint(
        allocator,
        "Package: {s}\nStatus: install ok unpacked\nPriority: optional\n" ++
            "Section: admin\nMaintainer: debz reference proof <reference-proof@debz.invalid>\n" ++
            "Architecture: amd64\nVersion: {s}\n" ++
            "Description: debz protected proc-view proof\n",
        .{ profile, resolved_version },
    );
    defer allocator.free(status_bytes);
    try writeBeneath(root, "var/lib/dpkg/status", status_bytes, 0o644, true);

    const list_rel = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}.list", .{profile});
    defer allocator.free(list_rel);
    try writeBeneath(root, list_rel, "", 0o644, false);

    const postinst_rel = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}.postinst", .{profile});
    defer allocator.free(postinst_rel);
    try writeBeneath(root, postinst_rel, script, 0o755, false);

    try writeBeneath(root, "usr/bin/sh", probe, 0o755, false);
    return root;
}

pub fn requireUnchangedProfile(
    allocator: std.mem.Allocator,
    root: []const u8,
    profile: []const u8,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var packages = try reference_order.currentStatuses(arena.allocator(), root);
    const entry = packages.get(.{ .name = profile, .architecture = "amd64" }) orelse
        return error.RefusedProfileChangedPackageState;
    if (!std.mem.eql(u8, entry.status, "install ok unpacked")) {
        return error.RefusedProfileChangedPackageState;
    }
    const marker_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, DESCENDANT_MARKER });
    defer allocator.free(marker_path);
    if (lstatPath(marker_path)) |_| {
        return error.ProbeRanDespiteRefusal;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
}

pub const OperationOptions = struct {
    readable_output: bool = false,
    inherited_fd: ?i32 = null,
    package_name: []const u8 = "debz-reference-proof",
    profile: []const u8 = "none",
    selector: ?[]const u8 = null,
};

pub const OperationResult = struct {
    status: i32,
    stderr: []u8,
};

pub const OperationFn = *const fn (
    allocator: std.mem.Allocator,
    workspace: []const u8,
    name: []const u8,
    launcher: []const u8,
    dpkg: []const u8,
    runtime: []const u8,
    root: []const u8,
    architecture: []const u8,
    archive: ?[]const u8,
    digest: ?[]const u8,
    size: ?u64,
    verb: []const u8,
    options: OperationOptions,
) anyerror!OperationResult;

fn execForkedCommand(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    stdin_fd: i32,
    stdout_fd: i32,
    stderr_fd: i32,
    inherited_fd: ?i32,
) !i32 {
    var c_args = try allocator.alloc(?[*:0]const u8, argv.len + 1);
    var arg_slices = try allocator.alloc([:0]u8, argv.len);
    var allocated_count: usize = 0;
    defer {
        for (arg_slices[0..allocated_count]) |s| allocator.free(s);
        allocator.free(arg_slices);
        allocator.free(c_args);
    }
    @memset(c_args, null);
    for (argv, 0..) |arg, idx| {
        const dup = try allocator.allocSentinel(u8, arg.len, 0);
        @memcpy(dup[0..arg.len], arg);
        arg_slices[idx] = dup;
        allocated_count += 1;
        c_args[idx] = dup.ptr;
    }
    const envp: [*:null]const ?[*:0]const u8 = &.{
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/",
        "LC_ALL=C",
        "DEBIAN_FRONTEND=noninteractive",
        "DEBCONF_NONINTERACTIVE_SEEN=true",
        "DPKG_COLORS=never",
        null,
    };
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.ForkFailed;
    if (forked == 0) {
        if (inherited_fd) |pass_fd| {
            _ = linux.fcntl(pass_fd, linux.F.SETFD, @as(usize, 0));
        }
        if (linux.errno(linux.dup2(stdin_fd, 0)) != .SUCCESS) linux.exit(127);
        if (linux.errno(linux.dup2(stdout_fd, 1)) != .SUCCESS) linux.exit(127);
        if (linux.errno(linux.dup2(stderr_fd, 2)) != .SUCCESS) linux.exit(127);
        _ = linux.execve(c_args[0].?, @ptrCast(c_args.ptr), envp);
        linux.exit(127);
    }
    const pid: i32 = @intCast(forked);
    var status: i32 = 0;
    while (linux.errno(linux.waitpid(pid, &status, 0)) == .INTR) {}
    const ustatus: u32 = @bitCast(status);
    if (linux.W.IFEXITED(ustatus)) return @intCast(linux.W.EXITSTATUS(ustatus));
    if (linux.W.IFSIGNALED(ustatus)) return -@as(i32, @intCast(@intFromEnum(linux.W.TERMSIG(ustatus))));
    return -1;
}

pub fn operation(
    allocator: std.mem.Allocator,
    workspace: []const u8,
    name: []const u8,
    launcher: []const u8,
    dpkg: []const u8,
    runtime: []const u8,
    root: []const u8,
    architecture: []const u8,
    archive: ?[]const u8,
    digest: ?[]const u8,
    size: ?u64,
    verb: []const u8,
    options: OperationOptions,
) !OperationResult {
    const stdout_path = try std.fmt.allocPrint(allocator, "{s}/{s}.stdout", .{ workspace, name });
    defer allocator.free(stdout_path);
    const stderr_path = try std.fmt.allocPrint(allocator, "{s}/{s}.stderr", .{ workspace, name });
    defer allocator.free(stderr_path);

    const selector = if (options.selector) |sel|
        try allocator.dupe(u8, sel)
    else
        try std.fmt.allocPrint(allocator, "{s}:{s}", .{ options.package_name, architecture });
    defer allocator.free(selector);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{ launcher, root, dpkg, architecture, options.profile, verb, selector, runtime });
    var size_str: ?[]u8 = null;
    defer if (size_str) |s| allocator.free(s);
    if (archive != null) {
        size_str = try std.fmt.allocPrint(allocator, "{d}", .{size.?});
        try argv.appendSlice(allocator, &.{ archive.?, digest.?, size_str.? });
    }

    const stdin_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        "/dev/null",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        0,
    )));
    defer _ = linux.close(stdin_fd);

    var stdout_buf: [std.fs.max_path_bytes]u8 = undefined;
    const stdout_ptr = try cPath(stdout_path, &stdout_buf);
    const stdout_flags: linux.O = if (options.readable_output)
        .{ .ACCMODE = .RDWR, .CREAT = true, .APPEND = true, .CLOEXEC = true }
    else
        .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true };
    const stdout_fd: i32 = @intCast(try syscall(linux.openat(linux.AT.FDCWD, stdout_ptr, stdout_flags, 0o600)));
    defer _ = linux.close(stdout_fd);

    var stderr_buf: [std.fs.max_path_bytes]u8 = undefined;
    const stderr_ptr = try cPath(stderr_path, &stderr_buf);
    const stderr_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        stderr_ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true },
        0o600,
    )));
    defer _ = linux.close(stderr_fd);

    const status = try execForkedCommand(allocator, argv.items, stdin_fd, stdout_fd, stderr_fd, null);
    const teardown = try assertTeardown(allocator, root);
    const err_bytes = try readHostFile(allocator, stderr_path, 4 * 1024 * 1024);
    errdefer allocator.free(err_bytes);

    var json_out: std.ArrayList(u8) = .empty;
    defer json_out.deinit(allocator);
    try json_out.appendSlice(allocator, "{\n  \"argv\": [");
    for (argv.items, 0..) |arg, idx| {
        if (idx > 0) try json_out.appendSlice(allocator, ", ");
        const escaped = try std.json.Stringify.valueAlloc(allocator, arg, .{});
        defer allocator.free(escaped);
        try json_out.appendSlice(allocator, escaped);
    }
    const err_escaped = try std.json.Stringify.valueAlloc(allocator, err_bytes, .{});
    defer allocator.free(err_escaped);
    const record_tail = try std.fmt.allocPrint(
        allocator,
        "],\n  \"exit_status\": {d},\n  \"stderr\": {s},\n  \"teardown\": {{\"polls\": {d}, \"processes_scanned\": {d}, \"mountinfo_entries\": {d}}}\n}}\n",
        .{ status, err_escaped, teardown.polls, teardown.processes_scanned, teardown.mountinfo_entries },
    );
    defer allocator.free(record_tail);
    try json_out.appendSlice(allocator, record_tail);

    const json_rel = try std.fmt.allocPrint(allocator, "{s}.json", .{name});
    defer allocator.free(json_rel);
    try writeBeneath(workspace, json_rel, json_out.items, 0o600, false);

    return .{ .status = status, .stderr = err_bytes };
}

pub fn requireRefusal(status: i32, err_text: []const u8, expected: []const u8) !void {
    if (status == 0 or std.mem.indexOf(u8, err_text, expected) == null) {
        return error.ExpectedRefusalNotObserved;
    }
}

pub const ProcessResult = struct {
    exit_code: u8,
    stdout: []u8,
    stderr: []u8,
};

pub const RunnerFn = *const fn (
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    inherited_fd: ?i32,
) anyerror!ProcessResult;

pub fn defaultRunner(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    inherited_fd: ?i32,
) !ProcessResult {
    var stdout_pipe: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&stdout_pipe, .{ .CLOEXEC = true })) != .SUCCESS) return error.PipeFailed;
    defer {
        if (stdout_pipe[0] >= 0) _ = linux.close(stdout_pipe[0]);
        if (stdout_pipe[1] >= 0) _ = linux.close(stdout_pipe[1]);
    }
    var stderr_pipe: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&stderr_pipe, .{ .CLOEXEC = true })) != .SUCCESS) return error.PipeFailed;
    defer {
        if (stderr_pipe[0] >= 0) _ = linux.close(stderr_pipe[0]);
        if (stderr_pipe[1] >= 0) _ = linux.close(stderr_pipe[1]);
    }
    const stdin_fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        "/dev/null",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        0,
    )));
    defer _ = linux.close(stdin_fd);

    const exit_status = try execForkedCommand(allocator, argv, stdin_fd, stdout_pipe[1], stderr_pipe[1], inherited_fd);
    _ = linux.close(stdout_pipe[1]);
    stdout_pipe[1] = -1;
    _ = linux.close(stderr_pipe[1]);
    stderr_pipe[1] = -1;

    var stdout_list: std.ArrayList(u8) = .empty;
    errdefer stdout_list.deinit(allocator);
    var chunk: [16 * 1024]u8 = undefined;
    while (true) {
        const got = try syscall(linux.read(stdout_pipe[0], &chunk, chunk.len));
        if (got == 0) break;
        try stdout_list.appendSlice(allocator, chunk[0..got]);
    }
    var stderr_list: std.ArrayList(u8) = .empty;
    errdefer stderr_list.deinit(allocator);
    while (true) {
        const got = try syscall(linux.read(stderr_pipe[0], &chunk, chunk.len));
        if (got == 0) break;
        try stderr_list.appendSlice(allocator, chunk[0..got]);
    }
    return .{
        .exit_code = if (exit_status >= 0 and exit_status <= 255) @intCast(exit_status) else 255,
        .stdout = try stdout_list.toOwnedSlice(allocator),
        .stderr = try stderr_list.toOwnedSlice(allocator),
    };
}

pub const NetworkControl = struct {
    tcp_fd: i32,
    unix_fd: i32,
    inherited_fd: i32,

    pub fn deinit(self: *NetworkControl) void {
        if (self.inherited_fd >= 0) _ = linux.close(self.inherited_fd);
        if (self.tcp_fd >= 0) _ = linux.close(self.tcp_fd);
        if (self.unix_fd >= 0) _ = linux.close(self.unix_fd);
    }
};

pub fn openNetworkControl(
    allocator: std.mem.Allocator,
    workspace: []const u8,
    name: []const u8,
    root: []const u8,
    probe: []const u8,
    runner: RunnerFn,
) !NetworkControl {
    const tcp_fd: i32 = @intCast(try syscall(linux.socket(
        linux.AF.INET,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
        0,
    )));
    errdefer _ = linux.close(tcp_fd);
    var in_addr: linux.sockaddr.in = .{
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    _ = try syscall(linux.bind(tcp_fd, @ptrCast(&in_addr), @sizeOf(linux.sockaddr.in)));
    _ = try syscall(linux.listen(tcp_fd, 2));
    var in_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    _ = try syscall(linux.getsockname(tcp_fd, @ptrCast(&in_addr), &in_len));
    const port = std.mem.bigToNative(u16, in_addr.port);

    const unix_fd: i32 = @intCast(try syscall(linux.socket(
        linux.AF.UNIX,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
        0,
    )));
    errdefer _ = linux.close(unix_fd);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(workspace);
    hasher.update("/");
    hasher.update(name);
    var digest_raw: [32]u8 = undefined;
    hasher.final(&digest_raw);
    const digest_hex = std.fmt.bytesToHex(digest_raw, .lower);
    const unix_name = try std.fmt.allocPrint(allocator, "debz-reference-{s}", .{digest_hex});
    defer allocator.free(unix_name);

    var un_addr: linux.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(un_addr.path[1..][0..unix_name.len], unix_name);
    _ = try syscall(linux.bind(unix_fd, @ptrCast(&un_addr), @intCast(2 + 1 + unix_name.len)));
    _ = try syscall(linux.listen(unix_fd, 2));

    // Duplicate without FD_CLOEXEC so the child inherits `inherited_fd`.
    const inherited_fd: i32 = @intCast(try syscall(linux.fcntl(tcp_fd, linux.F.DUPFD, @as(usize, 200))));
    errdefer _ = linux.close(inherited_fd);

    const port_str = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(port_str);
    const inherited_str = try std.fmt.allocPrint(allocator, "{d}", .{inherited_fd});
    defer allocator.free(inherited_str);
    const command = [_][]const u8{ probe, "network-host", port_str, unix_name, inherited_str };

    const control = try runner(allocator, &command, inherited_fd);
    defer {
        allocator.free(control.stdout);
        allocator.free(control.stderr);
    }

    const slash = std.mem.lastIndexOfScalar(u8, workspace, '/') orelse return error.InvalidPath;
    const anchor = if (slash == 0) "/" else workspace[0..slash];
    const ws_name = workspace[slash + 1 ..];
    const prefix = try std.fmt.allocPrint(allocator, "{s}/{s}.network-host", .{ ws_name, name });
    defer allocator.free(prefix);

    const stdout_rel = try std.fmt.allocPrint(allocator, "{s}.stdout", .{prefix});
    defer allocator.free(stdout_rel);
    const stderr_rel = try std.fmt.allocPrint(allocator, "{s}.stderr", .{prefix});
    defer allocator.free(stderr_rel);
    const json_rel = try std.fmt.allocPrint(allocator, "{s}.json", .{prefix});
    defer allocator.free(json_rel);

    try writeBeneath(anchor, stdout_rel, control.stdout, 0o600, false);
    try writeBeneath(anchor, stderr_rel, control.stderr, 0o600, false);

    const probe_escaped = try std.json.Stringify.valueAlloc(allocator, probe, .{});
    defer allocator.free(probe_escaped);
    const json_bytes = try std.fmt.allocPrint(
        allocator,
        "{{\n  \"argv\": [{s}, \"network-host\", \"{s}\", \"{s}\", \"{s}\"],\n  \"exit_status\": {d},\n  \"port\": {d},\n  \"abstract_unix\": \"{s}\",\n  \"inherited_fd\": {d}\n}}\n",
        .{ probe_escaped, port_str, unix_name, inherited_str, control.exit_code, port, unix_name, inherited_fd },
    );
    defer allocator.free(json_bytes);
    try writeBeneath(anchor, json_rel, json_bytes, 0o600, false);

    const expected = "DEBZ_HOST_NETWORK_PROOF tcp=reachable abstract_unix=reachable inherited_fd=open\n";
    if (control.exit_code != 0 or !std.mem.eql(u8, control.stdout, expected)) {
        return error.UnreachableHostNetworkControl;
    }

    if (!std.mem.startsWith(u8, root, workspace) or root.len <= workspace.len or root[workspace.len] != '/') {
        return error.RootNotBeneathWorkspace;
    }
    const root_rel = root[workspace.len + 1 ..];
    const control_rel = try std.fmt.allocPrint(allocator, "{s}/.debz-network-control", .{root_rel});
    defer allocator.free(control_rel);
    const control_payload = try std.fmt.allocPrint(allocator, "{d}\n{s}\n{d}", .{ port, unix_name, inherited_fd });
    defer allocator.free(control_payload);
    try writeBeneath(workspace, control_rel, control_payload, 0o600, false);

    return .{
        .tcp_fd = tcp_fd,
        .unix_fd = unix_fd,
        .inherited_fd = inherited_fd,
    };
}

pub const ProofArgs = struct {
    launcher: []const u8,
    runtime: []const u8,
    runtime_tool: []const u8,
    dpkg: []const u8,
    root_template: []const u8,
    workspace: []const u8,
    archive: []const u8,
    archive_sha512: []const u8,
    archive_size: u64,
    escape_probe: []const u8 = "",
    escape_archive: []const u8 = "",
    escape_archive_sha512: []const u8 = "",
    escape_archive_size: u64 = 0,
    profile_scripts: []const u8 = "",
    architecture: []const u8,
};

pub const FreshRootFn = *const fn (
    allocator: std.mem.Allocator,
    template: []const u8,
    workspace: []const u8,
    name: []const u8,
) anyerror![]u8;

pub const ProtectedDirFn = *const fn (path: []const u8, empty: bool) anyerror!void;
pub const TeardownFn = *const fn (allocator: std.mem.Allocator, root: []const u8) anyerror!TeardownReport;

pub const RuntimeProofHooks = struct {
    fresh_root: FreshRootFn = freshRoot,
    protected_directory: ProtectedDirFn = protectedDirectory,
    operation: OperationFn = operation,
    assert_teardown: TeardownFn = assertTeardown,
    runner: RunnerFn = defaultRunner,
};

const BindingObject = struct {
    name: []const u8,
    root_path: []const u8,
};

const BindingRecord = struct {
    loader: []const u8,
    objects: []const BindingObject,
};

pub fn proveRuntimeWithHooks(
    allocator: std.mem.Allocator,
    args: ProofArgs,
    identity: []const u8,
    hooks: RuntimeProofHooks,
) !void {
    const binding_bytes = try reference_paths.readRootFile(allocator, args.runtime, "binding.json", 128 * 1024);
    defer allocator.free(binding_bytes);
    var parsed = try std.json.parseFromSlice(BindingRecord, allocator, binding_bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    var selected: [2]BindingObject = undefined;
    for ([_][]const u8{ parsed.value.loader, "libpcre2-8.so.0" }, 0..) |wanted, idx| {
        var found: ?BindingObject = null;
        for (parsed.value.objects) |obj| {
            if (std.mem.eql(u8, obj.name, wanted)) {
                found = obj;
                break;
            }
        }
        selected[idx] = found orelse return error.MissingRuntimeBindingObject;
    }

    var cases_json: std.ArrayList(u8) = .empty;
    defer cases_json.deinit(allocator);
    var case_count: usize = 0;

    for (selected) |binding| {
        for ([_][]const u8{ "missing", "altered", "symlink", "private-altered" }) |mutation| {
            const name = try std.fmt.allocPrint(allocator, "runtime-{s}-{s}", .{ binding.name, mutation });
            defer allocator.free(name);
            const root = try hooks.fresh_root(allocator, args.root_template, args.workspace, name);
            defer allocator.free(root);

            var prefix = try allocator.dupe(u8, args.runtime);
            defer allocator.free(prefix);

            const trimmed_root_path = std.mem.trimStart(u8, binding.root_path, "/");
            var target = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, trimmed_root_path });
            defer allocator.free(target);

            if (std.mem.eql(u8, mutation, "missing")) {
                try unlinkPath(target);
            } else if (std.mem.eql(u8, mutation, "symlink")) {
                try unlinkPath(target);
                const link_dest = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ args.runtime, binding.name });
                defer allocator.free(link_dest);
                try symlinkPath(link_dest, target);
            } else if (std.mem.eql(u8, mutation, "private-altered")) {
                allocator.free(prefix);
                prefix = try std.fmt.allocPrint(allocator, "{s}/{s}-prefix", .{ args.workspace, name });
                try copyTemplateTreeRecursive(allocator, args.runtime, args.runtime, prefix, true);
                try hooks.protected_directory(prefix, false);
                allocator.free(target);
                target = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, binding.name });
            }

            if (std.mem.eql(u8, mutation, "altered") or std.mem.eql(u8, mutation, "private-altered")) {
                const meta = try lstatPath(target);
                const data = try readHostFile(allocator, target, 64 * 1024 * 1024);
                defer allocator.free(data);
                if (data.len == 0) return error.EmptyRuntimeLibrary;
                data[0] ^= 1;
                if (!std.mem.startsWith(u8, target, args.workspace) or
                    target.len <= args.workspace.len or
                    target[args.workspace.len] != '/')
                {
                    return error.TargetNotBeneathWorkspace;
                }
                const rel = target[args.workspace.len + 1 ..];
                try writeBeneath(args.workspace, rel, data, meta.mode & 0o7777, true);
            }

            const op_res = try hooks.operation(
                allocator,
                args.workspace,
                name,
                args.launcher,
                args.dpkg,
                prefix,
                root,
                args.architecture,
                args.archive,
                args.archive_sha512,
                args.archive_size,
                "unpack",
                .{},
            );
            defer allocator.free(op_res.stderr);

            const expected = if (std.mem.eql(u8, mutation, "missing") or std.mem.eql(u8, mutation, "symlink"))
                "RuntimeInputRefused"
            else
                "RuntimeDigestChanged";
            try requireRefusal(op_res.status, op_res.stderr, expected);

            const status_bytes = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/status", 4 * 1024 * 1024);
            defer allocator.free(status_bytes);
            if (status_bytes.len != 0) return error.DpkgStartedDespiteRuntimeRefusal;
            const marker = try std.fmt.allocPrint(allocator, "{s}/usr/share/debz-reference-proof/marker", .{root});
            defer allocator.free(marker);
            if (lstatPath(marker)) |_| {
                return error.DpkgStartedDespiteRuntimeRefusal;
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            }

            if (case_count > 0) try cases_json.appendSlice(allocator, ",\n");
            const entry_json = try std.fmt.allocPrint(
                allocator,
                "    \"{s}\": {{\"refusal\": \"{s}\", \"dpkg_started\": false}}",
                .{ name, expected },
            );
            defer allocator.free(entry_json);
            try cases_json.appendSlice(allocator, entry_json);
            case_count += 1;
        }

        const pb_name = try std.fmt.allocPrint(allocator, "runtime-{s}-postbinding", .{binding.name});
        defer allocator.free(pb_name);
        const pb_root = try hooks.fresh_root(allocator, args.root_template, args.workspace, pb_name);
        defer allocator.free(pb_root);
        const pb_cmd = [_][]const u8{
            args.runtime_tool,
            "prove-postbinding",
            args.architecture,
            args.runtime,
            pb_root,
            identity,
            binding.name,
        };
        const pb_res = try hooks.runner(allocator, &pb_cmd, null);
        defer {
            allocator.free(pb_res.stdout);
            allocator.free(pb_res.stderr);
        }
        if (pb_res.exit_code != 0 or
            std.mem.indexOf(u8, pb_res.stderr, "RuntimeSourceChanged; no dpkg or script executed") == null)
        {
            return error.PostBindingDriftProofFailed;
        }
        const pb_status = try reference_paths.readRootFile(allocator, pb_root, "var/lib/dpkg/status", 4 * 1024 * 1024);
        defer allocator.free(pb_status);
        if (pb_status.len != 0) return error.PostBindingMutatedDatabase;
        _ = try hooks.assert_teardown(allocator, pb_root);

        if (case_count > 0) try cases_json.appendSlice(allocator, ",\n");
        const pb_json = try std.fmt.allocPrint(
            allocator,
            "    \"{s}\": {{\"refusal\": \"RuntimeSourceChanged\", \"dpkg_started\": false}}",
            .{pb_name},
        );
        defer allocator.free(pb_json);
        try cases_json.appendSlice(allocator, pb_json);
        case_count += 1;
    }

    const preload_name = "runtime-unbound-preload";
    const preload_root = try hooks.fresh_root(allocator, args.root_template, args.workspace, preload_name);
    defer allocator.free(preload_root);
    try writeBeneath(preload_root, "etc/ld.so.preload", "/unbound-library.so\n", 0o644, false);
    const preload_res = try hooks.operation(
        allocator,
        args.workspace,
        preload_name,
        args.launcher,
        args.dpkg,
        args.runtime,
        preload_root,
        args.architecture,
        args.archive,
        args.archive_sha512,
        args.archive_size,
        "unpack",
        .{},
    );
    defer allocator.free(preload_res.stderr);
    try requireRefusal(preload_res.status, preload_res.stderr, "UnboundRuntimePreload");
    const preload_status = try reference_paths.readRootFile(allocator, preload_root, "var/lib/dpkg/status", 4 * 1024 * 1024);
    defer allocator.free(preload_status);
    if (preload_status.len != 0) return error.DpkgStartedWithUnboundPreload;

    if (case_count > 0) try cases_json.appendSlice(allocator, ",\n");
    try cases_json.appendSlice(
        allocator,
        "    \"runtime-unbound-preload\": {\"refusal\": \"UnboundRuntimePreload\", \"dpkg_started\": false}",
    );

    const proof_json = try std.fmt.allocPrint(
        allocator,
        "{{\n  \"architecture\": \"{s}\",\n  \"original_archive_bindings\": {s},\n  \"cases\": {{\n{s}\n  }}\n}}\n",
        .{ args.architecture, std.mem.trim(u8, binding_bytes, " \t\r\n"), cases_json.items },
    );
    defer allocator.free(proof_json);
    try writeBeneath(args.workspace, "runtime-preflight-proof.json", proof_json, 0o600, false);
}

pub fn proveProfiles(
    allocator: std.mem.Allocator,
    args: ProofArgs,
    scripts: *const std.StringHashMap([]const u8),
) ![]u8 {
    const probe = try readHostFile(allocator, args.escape_probe, 16 * 1024 * 1024);
    defer allocator.free(probe);

    if (!std.mem.eql(u8, args.architecture, "amd64")) {
        for (PROFILE_VIEW_CHECKS) |entry| {
            const name = try std.fmt.allocPrint(allocator, "profile-{s}-{s}", .{ entry.profile, args.architecture });
            defer allocator.free(name);
            const root = try freshRoot(allocator, args.root_template, args.workspace, name);
            defer allocator.free(root);
            const selector = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ entry.profile, args.architecture });
            defer allocator.free(selector);
            const res = try operation(
                allocator,
                args.workspace,
                name,
                args.launcher,
                args.dpkg,
                args.runtime,
                root,
                args.architecture,
                null,
                null,
                null,
                "configure",
                .{ .profile = entry.profile, .selector = selector },
            );
            defer allocator.free(res.stderr);
            try requireRefusal(res.status, res.stderr, "InvalidProfile");
        }
        return try std.fmt.allocPrint(allocator, "{s} refusal of the amd64-only signed proc profiles", .{args.architecture});
    }

    const host_boot_id_raw = try readHostFile(allocator, "/proc/sys/kernel/random/boot_id", 128);
    defer allocator.free(host_boot_id_raw);
    const host_boot_id = std.mem.trim(u8, host_boot_id_raw, " \t\r\n");

    for (PROFILE_VIEW_CHECKS) |entry| {
        const name = try std.fmt.allocPrint(allocator, "profile-{s}", .{entry.profile});
        defer allocator.free(name);
        const script = scripts.get(entry.profile) orelse return error.MissingProfileScript;
        const root = try profileRoot(allocator, args.root_template, args.workspace, name, entry.profile, script, probe, null);
        defer allocator.free(root);
        const selector = try std.fmt.allocPrint(allocator, "{s}:amd64", .{entry.profile});
        defer allocator.free(selector);
        const res = blk: {
            var net = try openNetworkControl(allocator, args.workspace, name, root, args.escape_probe, defaultRunner);
            defer net.deinit();
            break :blk try operation(
                allocator,
                args.workspace,
                name,
                args.launcher,
                args.dpkg,
                args.runtime,
                root,
                args.architecture,
                null,
                null,
                null,
                "configure",
                .{ .inherited_fd = net.inherited_fd, .profile = entry.profile, .selector = selector },
            );
        };
        defer allocator.free(res.stderr);

        const stdout_path = try std.fmt.allocPrint(allocator, "{s}/{s}.stdout", .{ args.workspace, name });
        defer allocator.free(stdout_path);
        const output = try readHostFile(allocator, stdout_path, 4 * 1024 * 1024);
        defer allocator.free(output);
        var results = try probeResults(allocator, output);
        defer freeStringMap(allocator, &results);

        if (res.status != 0 or results.contains("no-proc-view")) return error.ProfileProcViewCheckFailed;
        for (PROFILE_ESCAPE_CHECKS) |check| {
            if (!std.mem.eql(u8, results.get(check) orelse "", "ok")) return error.ProfileProcViewCheckFailed;
        }
        for (PROFILE_COMMON_CHECKS) |check| {
            if (!std.mem.eql(u8, results.get(check) orelse "", "ok")) return error.ProfileProcViewCheckFailed;
        }
        for (entry.checks) |check| {
            if (!std.mem.eql(u8, results.get(check) orelse "", "ok")) return error.ProfileProcViewCheckFailed;
        }
        for ([_][]const u8{ "private-network", "result" }) |check| {
            if (!std.mem.eql(u8, results.get(check) orelse "", "ok")) return error.ProfileProcViewCheckFailed;
        }

        var result_detail = try probeDetail(allocator, output, "result");
        defer freeStringMap(allocator, &result_detail);
        if (!std.mem.eql(u8, result_detail.get("mode") orelse "", entry.profile)) {
            return error.ProfileProbeWrongMode;
        }
        if (std.mem.eql(u8, entry.profile, "systemd")) {
            var boot_detail = try probeDetail(allocator, output, "proc-boot-id");
            defer freeStringMap(allocator, &boot_detail);
            if (!std.mem.eql(u8, boot_detail.get("boot_id") orelse "", host_boot_id)) {
                return error.ProfileBootIdMismatch;
            }
        }
        const marker_bytes = try reference_paths.readRootFile(allocator, root, DESCENDANT_MARKER, 64);
        defer allocator.free(marker_bytes);
        const trimmed_marker = std.mem.trim(u8, marker_bytes, " \t\r\n");
        if (trimmed_marker.len == 0) return error.DetachedDescendantNeverStarted;
        for (trimmed_marker) |ch| {
            if (!std.ascii.isDigit(ch)) return error.DetachedDescendantNeverStarted;
        }
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        var pkgs = try reference_order.currentStatuses(arena.allocator(), root);
        const expected_ver = profileVersion(entry.profile) orelse return error.UnknownProfile;
        const pkg = pkgs.get(.{ .name = entry.profile, .architecture = "amd64" }) orelse
            return error.PinnedDpkgDidNotConfigureBoundPackage;
        if (!std.mem.eql(u8, pkg.status, "install ok installed") or
            !std.mem.eql(u8, pkg.version, expected_ver))
        {
            return error.PinnedDpkgDidNotConfigureBoundPackage;
        }
    }

    const systemd_script = scripts.get("systemd") orelse return error.MissingProfileScript;
    const tampered = try allocator.dupe(u8, systemd_script);
    defer allocator.free(tampered);
    tampered[tampered.len - 2] ^= 0x01;

    const NegativeCase = struct {
        name: []const u8,
        profile: []const u8,
        selector: []const u8,
        script: []const u8,
        version: ?[]const u8,
        expected: []const u8,
    };
    const negatives = [_]NegativeCase{
        .{ .name = "profile-tampered-script", .profile = "systemd", .selector = "systemd:amd64", .script = tampered, .version = null, .expected = "SourceChanged" },
        .{ .name = "profile-wrong-version", .profile = "systemd", .selector = "systemd:amd64", .script = systemd_script, .version = "259.5-0ubuntu3.3", .expected = "ReferenceSetupFailed" },
        .{ .name = "profile-wrong-selector", .profile = "systemd", .selector = "udev:amd64", .script = systemd_script, .version = null, .expected = "InvalidProfile" },
        .{ .name = "profile-unbound-configure", .profile = "none", .selector = "systemd:amd64", .script = systemd_script, .version = null, .expected = "InvalidProfile" },
    };
    for (negatives) |neg| {
        const root = try profileRoot(allocator, args.root_template, args.workspace, neg.name, "systemd", neg.script, probe, neg.version);
        defer allocator.free(root);
        const res = try operation(
            allocator,
            args.workspace,
            neg.name,
            args.launcher,
            args.dpkg,
            args.runtime,
            root,
            args.architecture,
            null,
            null,
            null,
            "configure",
            .{ .profile = neg.profile, .selector = neg.selector },
        );
        defer allocator.free(res.stderr);
        try requireRefusal(res.status, res.stderr, neg.expected);
        if (std.mem.eql(u8, neg.name, "profile-wrong-version") and
            std.mem.indexOf(u8, res.stderr, "failed at stage 10") == null)
        {
            return error.InRootBindingDidNotRefuseAtStage10;
        }
        try requireUnchangedProfile(allocator, root, "systemd");
    }
    return try allocator.dupe(
        u8,
        "amd64 systemd boot-ID and udev/sudo PID-only proc views with four binding refusals",
    );
}

fn verifySha512File(path: []const u8, digest_hex: []const u8, declared_size: u64) !void {
    if (digest_hex.len != 128) return error.InvalidArchiveSha512;
    for (digest_hex) |ch| {
        if (!std.ascii.isHex(ch) or std.ascii.isUpper(ch)) return error.InvalidArchiveSha512;
    }
    if (declared_size == 0 or declared_size > 512 * 1024 * 1024) return error.InvalidArchiveSize;
    const meta = try lstatPath(path);
    if (meta.size != declared_size) return error.ArchiveSizeMismatch;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(path, &buf);
    const fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        ptr,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    )));
    defer _ = linux.close(fd);
    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const got = try syscall(linux.read(fd, &chunk, chunk.len));
        if (got == 0) break;
        hasher.update(chunk[0..got]);
    }
    var raw: [64]u8 = undefined;
    hasher.final(&raw);
    const hex = std.fmt.bytesToHex(raw, .lower);
    if (!std.mem.eql(u8, &hex, digest_hex)) return error.ArchiveSha512Mismatch;
}

fn sha256FileHex(path: []const u8) ![64]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(path, &buf);
    const fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        ptr,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    )));
    defer _ = linux.close(fd);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const got = try syscall(linux.read(fd, &chunk, chunk.len));
        if (got == 0) break;
        hasher.update(chunk[0..got]);
    }
    var raw: [32]u8 = undefined;
    hasher.final(&raw);
    return std.fmt.bytesToHex(raw, .lower);
}

fn writeAllFd(fd: i32, bytes: []const u8) void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (linux.errno(rc) != .SUCCESS or rc == 0) return;
        offset += rc;
    }
}

pub fn runMain(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    var launcher: ?[]const u8 = null;
    var runtime: ?[]const u8 = null;
    var runtime_tool: ?[]const u8 = null;
    var dpkg: ?[]const u8 = null;
    var root_template: ?[]const u8 = null;
    var workspace: ?[]const u8 = null;
    var archive: ?[]const u8 = null;
    var archive_sha512: ?[]const u8 = null;
    var archive_size: ?u64 = null;
    var escape_probe: ?[]const u8 = null;
    var escape_archive: ?[]const u8 = null;
    var escape_archive_sha512: ?[]const u8 = null;
    var escape_archive_size: ?u64 = null;
    var profile_scripts_dir: ?[]const u8 = null;
    var architecture: ?[]const u8 = null;

    var idx: usize = 0;
    while (idx < argv.len) : (idx += 2) {
        if (idx + 1 >= argv.len) return error.InvalidArguments;
        const flag = argv[idx];
        const val = argv[idx + 1];
        if (std.mem.eql(u8, flag, "--launcher")) {
            launcher = val;
        } else if (std.mem.eql(u8, flag, "--runtime")) {
            runtime = val;
        } else if (std.mem.eql(u8, flag, "--runtime-tool")) {
            runtime_tool = val;
        } else if (std.mem.eql(u8, flag, "--dpkg")) {
            dpkg = val;
        } else if (std.mem.eql(u8, flag, "--root-template")) {
            root_template = val;
        } else if (std.mem.eql(u8, flag, "--workspace")) {
            workspace = val;
        } else if (std.mem.eql(u8, flag, "--archive")) {
            archive = val;
        } else if (std.mem.eql(u8, flag, "--archive-sha512")) {
            archive_sha512 = val;
        } else if (std.mem.eql(u8, flag, "--archive-size")) {
            archive_size = try std.fmt.parseInt(u64, val, 10);
        } else if (std.mem.eql(u8, flag, "--escape-probe")) {
            escape_probe = val;
        } else if (std.mem.eql(u8, flag, "--escape-archive")) {
            escape_archive = val;
        } else if (std.mem.eql(u8, flag, "--escape-archive-sha512")) {
            escape_archive_sha512 = val;
        } else if (std.mem.eql(u8, flag, "--escape-archive-size")) {
            escape_archive_size = try std.fmt.parseInt(u64, val, 10);
        } else if (std.mem.eql(u8, flag, "--profile-scripts")) {
            profile_scripts_dir = val;
        } else if (std.mem.eql(u8, flag, "--architecture")) {
            architecture = val;
        } else {
            return error.InvalidArguments;
        }
    }

    const args = ProofArgs{
        .launcher = launcher orelse return error.InvalidArguments,
        .runtime = runtime orelse return error.InvalidArguments,
        .runtime_tool = runtime_tool orelse return error.InvalidArguments,
        .dpkg = dpkg orelse return error.InvalidArguments,
        .root_template = root_template orelse return error.InvalidArguments,
        .workspace = workspace orelse return error.InvalidArguments,
        .archive = archive orelse return error.InvalidArguments,
        .archive_sha512 = archive_sha512 orelse return error.InvalidArguments,
        .archive_size = archive_size orelse return error.InvalidArguments,
        .escape_probe = escape_probe orelse return error.InvalidArguments,
        .escape_archive = escape_archive orelse return error.InvalidArguments,
        .escape_archive_sha512 = escape_archive_sha512 orelse return error.InvalidArguments,
        .escape_archive_size = escape_archive_size orelse return error.InvalidArguments,
        .profile_scripts = profile_scripts_dir orelse return error.InvalidArguments,
        .architecture = architecture orelse return error.InvalidArguments,
    };

    if (linux.geteuid() != 0 or linux.getegid() != 0) {
        return error.PermissionError;
    }
    _ = linux.syscall1(.umask, 0o077);

    for ([_][]const u8{
        args.launcher,
        args.dpkg,
        args.runtime,
        args.runtime_tool,
        args.root_template,
        args.workspace,
        args.archive,
        args.escape_probe,
        args.escape_archive,
        args.profile_scripts,
    }) |p| {
        if (!std.mem.startsWith(u8, p, "/")) return error.NonAbsoluteProofInput;
    }

    for ([_][]const u8{
        args.launcher,
        args.dpkg,
        args.runtime_tool,
        args.archive,
        args.escape_probe,
        args.escape_archive,
    }) |p| {
        _ = try reference_paths.protected(p, false);
    }
    try protectedDirectory(args.runtime, false);
    try protectedDirectory(args.root_template, false);
    try protectedDirectory(args.workspace, true);

    const pinned_sha256 = pinnedDpkgDigest(args.architecture) orelse return error.UnsupportedArchitecture;
    const identity = try sha256FileHex(args.dpkg);
    if (!std.mem.eql(u8, &identity, pinned_sha256)) return error.UnpinnedReferenceDpkg;

    var scripts = try profileScripts(allocator, args.profile_scripts, args.architecture);
    defer freeStringMap(allocator, &scripts);

    const template_proc = try std.fmt.allocPrint(allocator, "{s}/proc", .{args.root_template});
    defer allocator.free(template_proc);
    const template_archive = try std.fmt.allocPrint(allocator, "{s}/.debz-reference-archive", .{args.root_template});
    defer allocator.free(template_archive);
    const proc_meta = try reference_paths.protected(template_proc, true);
    const mount_meta = try reference_paths.protected(template_archive, false);
    const template_meta = try lstatPath(args.root_template);
    const mount_dev = (@as(u64, mount_meta.dev_major) << 32) | mount_meta.dev_minor;
    if ((proc_meta.mode & 0o7777) != 0o755 or
        (mount_meta.mode & 0o7777) != 0o600 or
        mount_meta.nlink != 1 or
        mount_meta.size != 0 or
        mount_dev != template_meta.dev)
    {
        return error.InvalidProofTemplateMountpoints;
    }

    try verifySha512File(args.archive, args.archive_sha512, args.archive_size);
    try verifySha512File(args.escape_archive, args.escape_archive_sha512, args.escape_archive_size);

    try proveRuntimeWithHooks(allocator, args, &identity, .{});

    for ([_][2][]const u8{
        .{ "probe", "probe_unpack" },
        .{ "unpack", "unpack" },
    }) |pair| {
        const name = pair[0];
        const verb = pair[1];
        const root = try freshRoot(allocator, args.root_template, args.workspace, name);
        defer allocator.free(root);
        const etc_path = try std.fmt.allocPrint(allocator, "{s}/etc", .{root});
        defer allocator.free(etc_path);
        const root_before = try statMtimeNs(root);
        const etc_before = try statMtimeNs(etc_path);

        var ws_buf: [std.fs.max_path_bytes]u8 = undefined;
        const ws_ptr = try cPath(args.workspace, &ws_buf);
        const parent_fd: i32 = @intCast(try syscall(linux.openat(
            linux.AT.FDCWD,
            ws_ptr,
            .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
            0,
        )));
        defer _ = linux.close(parent_fd);

        const res = try operation(
            allocator,
            args.workspace,
            name,
            args.launcher,
            args.dpkg,
            args.runtime,
            root,
            args.architecture,
            args.archive,
            args.archive_sha512,
            args.archive_size,
            verb,
            .{ .inherited_fd = parent_fd },
        );
        defer allocator.free(res.stderr);
        if (res.status != 0) return error.PinnedDpkgRefusedValidOperation;
        if (std.mem.eql(u8, name, "probe")) {
            if (try statMtimeNs(root) != root_before or try statMtimeNs(etc_path) != etc_before) {
                return error.ProbeChangedDirectoryTimestamps;
            }
        }
        if (std.mem.eql(u8, name, "unpack")) {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const pkgs = try reference_order.currentStatuses(arena.allocator(), root);
            if (pkgs.count() == 0) return error.UnpackProducedEmptyDatabase;
        }
    }

    const changed_size = if (args.archive_size < 512 * 1024 * 1024) args.archive_size + 1 else args.archive_size - 1;
    const zero_128: [128]u8 = @splat('0');
    const one_128: [128]u8 = @splat('1');
    const wrong_digest: []const u8 = if (!std.mem.eql(u8, args.archive_sha512, &zero_128)) &zero_128 else &one_128;

    const ArchiveRefusal = struct {
        name: []const u8,
        digest: []const u8,
        size: u64,
        expected: []const u8,
    };
    for ([_]ArchiveRefusal{
        .{ .name = "wrong-digest", .digest = wrong_digest, .size = args.archive_size, .expected = "SourceChanged" },
        .{ .name = "wrong-size", .digest = args.archive_sha512, .size = changed_size, .expected = "InvalidSourceFile" },
    }) |case| {
        const root = try freshRoot(allocator, args.root_template, args.workspace, case.name);
        defer allocator.free(root);
        const res = try operation(
            allocator,
            args.workspace,
            case.name,
            args.launcher,
            args.dpkg,
            args.runtime,
            root,
            args.architecture,
            args.archive,
            case.digest,
            case.size,
            "unpack",
            .{},
        );
        defer allocator.free(res.stderr);
        try requireRefusal(res.status, res.stderr, case.expected);
        const status_bytes = try reference_paths.readRootFile(allocator, root, "var/lib/dpkg/status", 4 * 1024 * 1024);
        defer allocator.free(status_bytes);
        if (status_bytes.len != 0) return error.RootDatabaseChangedAfterRefusal;
    }

    {
        const root = try freshRoot(allocator, args.root_template, args.workspace, "bad-output");
        defer allocator.free(root);
        const res = try operation(
            allocator,
            args.workspace,
            "bad-output",
            args.launcher,
            args.dpkg,
            args.runtime,
            root,
            args.architecture,
            args.archive,
            args.archive_sha512,
            args.archive_size,
            "unpack",
            .{ .readable_output = true },
        );
        defer allocator.free(res.stderr);
        try requireRefusal(res.status, res.stderr, "InvalidStandardStream");
    }

    {
        const root = try freshRoot(allocator, args.root_template, args.workspace, "symlink");
        defer allocator.free(root);
        const link = try std.fmt.allocPrint(allocator, "{s}/symlink-to-root", .{args.workspace});
        defer allocator.free(link);
        try symlinkPath(root, link);
        const res = try operation(
            allocator,
            args.workspace,
            "symlink",
            args.launcher,
            args.dpkg,
            args.runtime,
            link,
            args.architecture,
            args.archive,
            args.archive_sha512,
            args.archive_size,
            "unpack",
            .{},
        );
        defer allocator.free(res.stderr);
        try requireRefusal(res.status, res.stderr, "ReferenceSetupFailed");
    }

    {
        const root = try freshRoot(allocator, args.root_template, args.workspace, "symlink-archive");
        defer allocator.free(root);
        const archive_link = try std.fmt.allocPrint(allocator, "{s}/symlink-to-archive", .{args.workspace});
        defer allocator.free(archive_link);
        try symlinkPath(args.archive, archive_link);
        const res = try operation(
            allocator,
            args.workspace,
            "symlink-archive",
            args.launcher,
            args.dpkg,
            args.runtime,
            root,
            args.architecture,
            archive_link,
            args.archive_sha512,
            args.archive_size,
            "unpack",
            .{},
        );
        defer allocator.free(res.stderr);
        try requireRefusal(res.status, res.stderr, "ReferenceSetupFailed");
    }

    {
        const parent = try std.fmt.allocPrint(allocator, "{s}/writable-parent", .{args.workspace});
        defer allocator.free(parent);
        try mkdirPath(parent, 0o700);
        const root = try freshRoot(allocator, args.root_template, parent, "writable");
        defer allocator.free(root);
        try chmodPath(parent, 0o777);
        defer chmodPath(parent, 0o700) catch {};
        const res = try operation(
            allocator,
            args.workspace,
            "writable",
            args.launcher,
            args.dpkg,
            args.runtime,
            root,
            args.architecture,
            args.archive,
            args.archive_sha512,
            args.archive_size,
            "unpack",
            .{},
        );
        defer allocator.free(res.stderr);
        try requireRefusal(res.status, res.stderr, "UnprotectedPath");
    }

    {
        const control_cmd = [_][]const u8{ args.escape_probe, "control" };
        const control = try defaultRunner(allocator, &control_cmd, null);
        defer {
            allocator.free(control.stdout);
            allocator.free(control.stderr);
        }
        try writeBeneath(args.workspace, "escape-control.stdout", control.stdout, 0o600, false);
        var control_results = try probeResults(allocator, control.stdout);
        defer freeStringMap(allocator, &control_results);
        if (control.exit_code != 1 or !std.mem.eql(u8, control_results.get("result") orelse "", "FAIL")) {
            return error.UnconfinedControlMissedAuthority;
        }
        for (CONTROL_DETECTS) |check| {
            if (!std.mem.eql(u8, control_results.get(check) orelse "", "FAIL")) {
                return error.UnconfinedControlMissedAuthority;
            }
        }
    }

    {
        const root = try freshRoot(allocator, args.root_template, args.workspace, "escape");
        defer allocator.free(root);
        const res = blk: {
            var net = try openNetworkControl(allocator, args.workspace, "escape", root, args.escape_probe, defaultRunner);
            defer net.deinit();
            break :blk try operation(
                allocator,
                args.workspace,
                "escape",
                args.launcher,
                args.dpkg,
                args.runtime,
                root,
                args.architecture,
                args.escape_archive,
                args.escape_archive_sha512,
                args.escape_archive_size,
                "unpack",
                .{ .inherited_fd = net.inherited_fd, .package_name = "debz-reference-escape-probe" },
            );
        };
        defer allocator.free(res.stderr);

        const escape_stdout_path = try std.fmt.allocPrint(allocator, "{s}/escape.stdout", .{args.workspace});
        defer allocator.free(escape_stdout_path);
        const escape_output = try readHostFile(allocator, escape_stdout_path, 4 * 1024 * 1024);
        defer allocator.free(escape_output);
        var results = try probeResults(allocator, escape_output);
        defer freeStringMap(allocator, &results);
        if (res.status != 0) return error.EscapeConfinementCheckFailed;
        for (ESCAPE_CHECKS) |check| {
            if (!std.mem.eql(u8, results.get(check) orelse "", "ok")) return error.EscapeConfinementCheckFailed;
        }
        for (CONFINED_CHECKS) |check| {
            if (!std.mem.eql(u8, results.get(check) orelse "", "ok")) return error.EscapeConfinementCheckFailed;
        }
        for ([_][]const u8{ "private-network", "result" }) |check| {
            if (!std.mem.eql(u8, results.get(check) orelse "", "ok")) return error.EscapeConfinementCheckFailed;
        }

        var archive_detail = try probeDetail(allocator, escape_output, "archive-mount");
        defer freeStringMap(allocator, &archive_detail);
        const expected_size_str = try std.fmt.allocPrint(allocator, "{d}", .{args.escape_archive_size});
        defer allocator.free(expected_size_str);
        if (!std.mem.eql(u8, archive_detail.get("size") orelse "", expected_size_str)) {
            return error.BoundArchiveSizeMismatch;
        }

        const marker_bytes = try reference_paths.readRootFile(allocator, root, DESCENDANT_MARKER, 64);
        defer allocator.free(marker_bytes);
        const trimmed_marker = std.mem.trim(u8, marker_bytes, " \t\r\n");
        if (trimmed_marker.len == 0) return error.DetachedDescendantNeverStarted;
        for (trimmed_marker) |ch| {
            if (!std.ascii.isDigit(ch)) return error.DetachedDescendantNeverStarted;
        }

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const pkgs = try reference_order.currentStatuses(arena.allocator(), root);
        if (!pkgs.contains(.{ .name = "debz-reference-escape-probe", .architecture = args.architecture })) {
            return error.PinnedDpkgDidNotRecordProbePackage;
        }
    }

    const profiles = try proveProfiles(allocator, args, &scripts);
    defer allocator.free(profiles);
    const summary = try std.fmt.allocPrint(
        allocator,
        "protected pinned-dpkg runtime: ten loader/recursive-library and one preload preflight refusals; " ++
            "probe/unpack, six refusals, unconfined escape control and " ++
            "{d} confined escape checks, read-only archive mount and " ++
            "descendant teardown, denied reachable-host TCP/abstract-UNIX and inherited sockets, " ++
            "private interface/IPv4/IPv6 route observation and usable loopback, {s}: executed without skips\n",
        .{ ESCAPE_CHECKS.len, profiles },
    );
    defer allocator.free(summary);
    writeAllFd(1, summary);
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args_iter = std.process.Args.Iterator.init(init.args);
    _ = args_iter.next();
    var args_list: std.ArrayList([]const u8) = .empty;
    defer args_list.deinit(allocator);
    while (args_iter.next()) |arg| {
        try args_list.append(allocator, arg);
    }

    runMain(allocator, args_list.items) catch |err| {
        var msg_buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "{s}: protected reference proof failed\n", .{@errorName(err)}) catch "protected reference proof failed\n";
        writeAllFd(2, msg);
        return 1;
    };
    return 0;
}

const TestTempDir = struct {
    allocator: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    abs_path: []u8,

    fn init(allocator: std.mem.Allocator) !TestTempDir {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var fd_path_buf: [64]u8 = undefined;
        const fd_slice = try std.fmt.bufPrint(&fd_path_buf, "/proc/self/fd/{d}\x00", .{tmp.dir.handle});
        const fd_path: [*:0]const u8 = @ptrCast(fd_slice.ptr);
        var real_buf: [std.fs.max_path_bytes]u8 = undefined;
        const len = try syscall(linux.readlinkat(linux.AT.FDCWD, fd_path, &real_buf, real_buf.len));
        const abs_path = try allocator.dupe(u8, real_buf[0..len]);
        return .{ .allocator = allocator, .tmp = tmp, .abs_path = abs_path };
    }

    fn deinit(self: *TestTempDir) void {
        self.allocator.free(self.abs_path);
        self.tmp.cleanup();
    }
};

fn writeTestFile(root_abs: []const u8, rel: []const u8, content: []const u8, mode: usize) !void {
    if (std.mem.lastIndexOfScalar(u8, rel, '/')) |slash| {
        var idx: usize = 0;
        while (idx <= slash) : (idx += 1) {
            if (idx == slash or rel[idx] == '/') {
                const sub = rel[0..idx];
                if (sub.len > 0) {
                    var sub_buf: [std.fs.max_path_bytes]u8 = undefined;
                    const full_sub = try std.fmt.bufPrint(&sub_buf, "{s}/{s}", .{ root_abs, sub });
                    mkdirPath(full_sub, 0o755) catch |err| switch (err) {
                        error.PathAlreadyExists => {},
                        else => return err,
                    };
                }
            }
        }
    }
    var full_buf: [std.fs.max_path_bytes]u8 = undefined;
    const full = try std.fmt.bufPrint(&full_buf, "{s}/{s}", .{ root_abs, rel });
    var c_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ptr = try cPath(full, &c_buf);
    const fd: i32 = @intCast(try syscall(linux.openat(
        linux.AT.FDCWD,
        ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true, .CLOEXEC = true },
        @intCast(mode),
    )));
    defer _ = linux.close(fd);
    _ = try syscall(linux.fchmod(fd, @intCast(mode)));
    var written: usize = 0;
    while (written < content.len) {
        written += try syscall(linux.write(fd, content[written..].ptr, content.len - written));
    }
}

test "arm64 stages no amd64 profile scripts and amd64 requires exact bound postinsts" {
    const allocator = std.testing.allocator;
    var tdir = try TestTempDir.init(allocator);
    defer tdir.deinit();
    reference_paths.setTestRootOverride(tdir.abs_path);
    defer reference_paths.setTestRootOverride(null);

    var arm_empty = try profileScripts(allocator, tdir.abs_path, "arm64");
    defer freeStringMap(allocator, &arm_empty);
    try std.testing.expectEqual(@as(usize, 0), arm_empty.count());

    try std.testing.expectError(error.InvalidProfileScripts, profileScripts(allocator, tdir.abs_path, "amd64"));

    try writeTestFile(tdir.abs_path, "systemd.postinst", "#!/bin/sh\n# systemd\n", 0o644);
    try std.testing.expectError(error.UnexpectedArchitectureProfileScripts, profileScripts(allocator, tdir.abs_path, "arm64"));

    try writeTestFile(tdir.abs_path, "udev.postinst", "#!/bin/sh\n# udev\n", 0o644);
    try writeTestFile(tdir.abs_path, "sudo.postinst", "#!/bin/sh\n# sudo\n", 0o644);
    var amd_scripts = try profileScripts(allocator, tdir.abs_path, "amd64");
    defer freeStringMap(allocator, &amd_scripts);
    try std.testing.expectEqual(@as(usize, 3), amd_scripts.count());
    try std.testing.expect(amd_scripts.contains("systemd"));
    try std.testing.expect(amd_scripts.contains("udev"));
    try std.testing.expect(amd_scripts.contains("sudo"));

    try writeTestFile(tdir.abs_path, "extra.postinst", "#!/bin/sh\n", 0o644);
    try std.testing.expectError(error.InvalidProfileScripts, profileScripts(allocator, tdir.abs_path, "amd64"));
    const extra_path = try std.fmt.allocPrint(allocator, "{s}/extra.postinst", .{tdir.abs_path});
    defer allocator.free(extra_path);
    try unlinkPath(extra_path);

    const oversized = try allocator.alloc(u8, PROFILE_SCRIPT_LIMIT + 1);
    defer allocator.free(oversized);
    @memset(oversized, '#');
    try writeTestFile(tdir.abs_path, "udev.postinst", oversized, 0o644);
    try std.testing.expectError(error.ProfileScriptExceedsLimit, profileScripts(allocator, tdir.abs_path, "amd64"));
}

test "profile checks and escape probe reports match real-snapshot-reference-escape-probe.zig" {
    const allocator = std.testing.allocator;
    const report =
        "Preparing to unpack /.debz-reference-archive ...\n" ++
        "debz-escape-probe: mount-denied ok errno=PERM\n" ++
        "debz-escape-probe: shared-network-namespace info inet_socket=SUCCESS\n" ++
        "debz-escape-probe: result ok failures=0 mode=install\n";
    var results = try probeResults(allocator, report);
    defer freeStringMap(allocator, &results);
    try std.testing.expectEqual(@as(usize, 2), results.count());
    try std.testing.expectEqualStrings("ok", results.get("mount-denied").?);
    try std.testing.expectEqualStrings("ok", results.get("result").?);

    try std.testing.expectError(
        error.AmbiguousEscapeProbeReport,
        probeResults(allocator, "debz-escape-probe: mount-denied ok\ndebz-escape-probe: mount-denied FAIL"),
    );
    try std.testing.expectError(
        error.AmbiguousEscapeProbeReport,
        probeResults(allocator, "debz-escape-probe: mount-denied skipped"),
    );

    try std.testing.expectEqual(ESCAPE_CHECKS.len - 2, CONTROL_DETECTS.len);
    for (PROFILE_ESCAPE_CHECKS) |check| {
        try std.testing.expect(!std.mem.eql(u8, check, "no-proc-view"));
        const needle = try std.fmt.allocPrint(allocator, "\"{s}\"", .{check});
        defer allocator.free(needle);
        try std.testing.expect(std.mem.indexOf(u8, escape_probe_source, needle) != null);
    }
    for (ESCAPE_CHECKS) |check| {
        const needle = try std.fmt.allocPrint(allocator, "\"{s}\"", .{check});
        defer allocator.free(needle);
        try std.testing.expect(std.mem.indexOf(u8, escape_probe_source, needle) != null);
    }
    for (CONFINED_CHECKS) |check| {
        const needle = try std.fmt.allocPrint(allocator, "\"{s}\"", .{check});
        defer allocator.free(needle);
        try std.testing.expect(std.mem.indexOf(u8, escape_probe_source, needle) != null);
    }
    for (PROFILE_COMMON_CHECKS) |check| {
        const needle = try std.fmt.allocPrint(allocator, "\"{s}\"", .{check});
        defer allocator.free(needle);
        try std.testing.expect(std.mem.indexOf(u8, escape_probe_source, needle) != null);
    }
    try std.testing.expectEqual(reference_order.profile_versions.len, PROFILE_VIEW_CHECKS.len);
    for (PROFILE_VIEW_CHECKS) |entry| {
        try std.testing.expect(profileVersion(entry.profile) != null);
        for (entry.checks) |check| {
            const needle = try std.fmt.allocPrint(allocator, "\"{s}\"", .{check});
            defer allocator.free(needle);
            try std.testing.expect(std.mem.indexOf(u8, escape_probe_source, needle) != null);
        }
    }

    const mounted = "debz-escape-probe: archive-mount ok size=4096 mount_root=true write=ROFS";
    var detail = try probeDetail(allocator, mounted, "archive-mount");
    defer freeStringMap(allocator, &detail);
    try std.testing.expectEqualStrings("4096", detail.get("size").?);

    try std.testing.expectError(error.MissingEscapeProbeDetail, probeDetail(allocator, "", "archive-mount"));
    try std.testing.expectError(
        error.MissingEscapeProbeDetail,
        probeDetail(allocator, "debz-escape-probe: archive-mount FAIL size=4096", "archive-mount"),
    );
    try std.testing.expectError(
        error.AmbiguousEscapeProbeDetail,
        probeDetail(allocator, mounted ++ "\n" ++ mounted, "archive-mount"),
    );
}

test "reference network controls require reachable host and retain refusals" {
    const allocator = std.testing.allocator;

    const receipt = "DEBZ_HOST_NETWORK_PROOF tcp=reachable abstract_unix=reachable inherited_fd=open\n";
    const Case = struct {
        status: u8,
        stdout: []const u8,
    };
    const Mock = struct {
        var current_status: u8 = 0;
        var current_stdout: []const u8 = "";
        var observed_inherited: ?i32 = null;

        fn run(alloc: std.mem.Allocator, _: []const []const u8, inherited_fd: ?i32) !ProcessResult {
            observed_inherited = inherited_fd;
            return .{
                .exit_code = current_status,
                .stdout = try alloc.dupe(u8, current_stdout),
                .stderr = try alloc.dupe(u8, "original diagnostic\n"),
            };
        }
    };

    for ([_]Case{
        .{ .status = 0, .stdout = receipt },
        .{ .status = 1, .stdout = receipt },
        .{ .status = 0, .stdout = "" },
        .{ .status = 0, .stdout = receipt ++ "extra\n" },
    }) |case| {
        var tdir = try TestTempDir.init(allocator);
        defer tdir.deinit();
        reference_paths.setTestRootOverride(tdir.abs_path);
        defer reference_paths.setTestRootOverride(null);
        const workspace = try std.fmt.allocPrint(allocator, "{s}/workspace", .{tdir.abs_path});
        defer allocator.free(workspace);
        try mkdirPath(workspace, 0o700);
        const root = try std.fmt.allocPrint(allocator, "{s}/root", .{workspace});
        defer allocator.free(root);
        try mkdirPath(root, 0o700);
        const probe = try std.fmt.allocPrint(allocator, "{s}/probe", .{workspace});
        defer allocator.free(probe);

        Mock.current_status = case.status;
        Mock.current_stdout = case.stdout;
        Mock.observed_inherited = null;

        const control_file = try std.fmt.allocPrint(allocator, "{s}/.debz-network-control", .{root});
        defer allocator.free(control_file);

        if (case.status == 0 and std.mem.eql(u8, case.stdout, receipt)) {
            var net = try openNetworkControl(allocator, workspace, "fixture", root, probe, Mock.run);
            defer net.deinit();
            try std.testing.expect(net.inherited_fd >= 200);
            try std.testing.expectEqual(@as(?i32, net.inherited_fd), Mock.observed_inherited);
            const payload = try readHostFile(allocator, control_file, 1024);
            defer allocator.free(payload);
            var lines = std.mem.splitScalar(u8, payload, '\n');
            const port = try std.fmt.parseInt(u16, lines.next().?, 10);
            try std.testing.expect(port > 0);
            const unix_name = lines.next().?;
            try std.testing.expect(std.mem.startsWith(u8, unix_name, "debz-reference-"));
            const inherited_str = lines.next().?;
            try std.testing.expectEqual(net.inherited_fd, try std.fmt.parseInt(i32, inherited_str, 10));
        } else {
            try std.testing.expectError(
                error.UnreachableHostNetworkControl,
                openNetworkControl(allocator, workspace, "fixture", root, probe, Mock.run),
            );
            try std.testing.expectError(error.FileNotFound, lstatPath(control_file));
        }

        const saved_out_path = try std.fmt.allocPrint(allocator, "{s}/fixture.network-host.stdout", .{workspace});
        defer allocator.free(saved_out_path);
        const saved_err_path = try std.fmt.allocPrint(allocator, "{s}/fixture.network-host.stderr", .{workspace});
        defer allocator.free(saved_err_path);
        const saved_json_path = try std.fmt.allocPrint(allocator, "{s}/fixture.network-host.json", .{workspace});
        defer allocator.free(saved_json_path);

        const saved_out = try readHostFile(allocator, saved_out_path, 4096);
        defer allocator.free(saved_out);
        try std.testing.expectEqualStrings(case.stdout, saved_out);
        const saved_err = try readHostFile(allocator, saved_err_path, 4096);
        defer allocator.free(saved_err);
        try std.testing.expectEqualStrings("original diagnostic\n", saved_err);
        const saved_json = try readHostFile(allocator, saved_json_path, 4096);
        defer allocator.free(saved_json);
        const expected_exit = try std.fmt.allocPrint(allocator, "\"exit_status\": {d}", .{case.status});
        defer allocator.free(expected_exit);
        try std.testing.expect(std.mem.indexOf(u8, saved_json, expected_exit) != null);
    }
}

test "runtime mutation negatives reach checks using workspace-rooted writes" {
    const allocator = std.testing.allocator;

    var tdir = try TestTempDir.init(allocator);
    defer tdir.deinit();
    reference_paths.setTestRootOverride(tdir.abs_path);
    defer reference_paths.setTestRootOverride(null);

    const runtime = try std.fmt.allocPrint(allocator, "{s}/runtime", .{tdir.abs_path});
    defer allocator.free(runtime);
    try mkdirPath(runtime, 0o700);
    const original = "original library bytes";
    try writeTestFile(runtime, "loader.so", original, 0o755);
    try writeTestFile(runtime, "libpcre2-8.so.0", original, 0o644);
    try writeTestFile(
        runtime,
        "binding.json",
        "{\"loader\": \"loader.so\", \"objects\": [{\"name\": \"loader.so\", \"root_path\": \"/usr/lib/loader.so\"}, {\"name\": \"libpcre2-8.so.0\", \"root_path\": \"/usr/lib/libpcre2-8.so.0\"}]}",
        0o644,
    );

    const workspace = try std.fmt.allocPrint(allocator, "{s}/proof", .{tdir.abs_path});
    defer allocator.free(workspace);
    try mkdirPath(workspace, 0o700);

    const Hooks = struct {
        fn fresh(alloc: std.mem.Allocator, _: []const u8, dest: []const u8, name: []const u8) ![]u8 {
            const root = try std.fmt.allocPrint(alloc, "{s}/{s}-root", .{ dest, name });
            errdefer alloc.free(root);
            try mkdirPath(root, 0o700);
            try writeTestFile(root, "var/lib/dpkg/status", "", 0o644);
            const etc = try std.fmt.allocPrint(alloc, "{s}/etc", .{root});
            defer alloc.free(etc);
            try mkdirPath(etc, 0o755);
            try writeTestFile(root, "usr/lib/loader.so", original, 0o755);
            try writeTestFile(root, "usr/lib/libpcre2-8.so.0", original, 0o644);
            return root;
        }

        fn noopProtected(_: []const u8, _: bool) !void {}

        fn fakeOp(
            alloc: std.mem.Allocator,
            _: []const u8,
            name: []const u8,
            _: []const u8,
            _: []const u8,
            _: []const u8,
            _: []const u8,
            _: []const u8,
            _: ?[]const u8,
            _: ?[]const u8,
            _: ?u64,
            _: []const u8,
            _: OperationOptions,
        ) !OperationResult {
            const msg = if (std.mem.endsWith(u8, name, "unbound-preload"))
                "UnboundRuntimePreload"
            else if (std.mem.endsWith(u8, name, "missing") or std.mem.endsWith(u8, name, "symlink"))
                "RuntimeInputRefused"
            else
                "RuntimeDigestChanged";
            return .{ .status = 1, .stderr = try alloc.dupe(u8, msg) };
        }

        fn fakeTeardown(_: std.mem.Allocator, _: []const u8) !TeardownReport {
            return .{
                .polls = 1,
                .processes_scanned = 1,
                .mountinfo_entries = 1,
                .archive_size = 0,
                .archive_nlink = 1,
                .archive_mode = 0o600,
            };
        }

        fn fakeRunner(alloc: std.mem.Allocator, _: []const []const u8, _: ?i32) !ProcessResult {
            return .{
                .exit_code = 0,
                .stdout = try alloc.dupe(u8, ""),
                .stderr = try alloc.dupe(u8, "RuntimeSourceChanged; no dpkg or script executed"),
            };
        }
    };

    const args = ProofArgs{
        .launcher = "/launcher",
        .runtime = runtime,
        .runtime_tool = "/runtime-tool",
        .dpkg = "/dpkg",
        .root_template = tdir.abs_path,
        .workspace = workspace,
        .archive = "/package.deb",
        .archive_sha512 = &@as([128]u8, @splat('a')),
        .archive_size = 42,
        .architecture = "amd64",
    };

    try proveRuntimeWithHooks(allocator, args, &@as([64]u8, @splat('a')), .{
        .fresh_root = Hooks.fresh,
        .protected_directory = Hooks.noopProtected,
        .operation = Hooks.fakeOp,
        .assert_teardown = Hooks.fakeTeardown,
        .runner = Hooks.fakeRunner,
    });

    for ([_][]const u8{ "loader.so", "libpcre2-8.so.0" }) |name| {
        const orig_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ runtime, name });
        defer allocator.free(orig_path);
        const orig_bytes = try readHostFile(allocator, orig_path, 1024);
        defer allocator.free(orig_bytes);
        try std.testing.expectEqualStrings(original, orig_bytes);

        const altered_path = try std.fmt.allocPrint(allocator, "{s}/runtime-{s}-altered-root/usr/lib/{s}", .{ workspace, name, name });
        defer allocator.free(altered_path);
        const altered_bytes = try readHostFile(allocator, altered_path, 1024);
        defer allocator.free(altered_bytes);
        try std.testing.expectEqual(original[0] ^ 1, altered_bytes[0]);
        try std.testing.expectEqualStrings(original[1..], altered_bytes[1..]);

        const priv_path = try std.fmt.allocPrint(allocator, "{s}/runtime-{s}-private-altered-prefix/{s}", .{ workspace, name, name });
        defer allocator.free(priv_path);
        const priv_bytes = try readHostFile(allocator, priv_path, 1024);
        defer allocator.free(priv_bytes);
        try std.testing.expectEqual(original[0] ^ 1, priv_bytes[0]);
        try std.testing.expectEqualStrings(original[1..], priv_bytes[1..]);
    }

    const report_path = try std.fmt.allocPrint(allocator, "{s}/runtime-preflight-proof.json", .{workspace});
    defer allocator.free(report_path);
    const report_bytes = try readHostFile(allocator, report_path, 16384);
    defer allocator.free(report_bytes);
    for ([_][]const u8{
        "\"runtime-loader.so-missing\"",
        "\"runtime-loader.so-altered\"",
        "\"runtime-loader.so-symlink\"",
        "\"runtime-loader.so-private-altered\"",
        "\"runtime-loader.so-postbinding\"",
        "\"runtime-libpcre2-8.so.0-missing\"",
        "\"runtime-libpcre2-8.so.0-altered\"",
        "\"runtime-libpcre2-8.so.0-symlink\"",
        "\"runtime-libpcre2-8.so.0-private-altered\"",
        "\"runtime-libpcre2-8.so.0-postbinding\"",
        "\"runtime-unbound-preload\"",
    }) |key| {
        try std.testing.expect(std.mem.indexOf(u8, report_bytes, key) != null);
    }
}
