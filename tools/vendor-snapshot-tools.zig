const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const CAPTURE_SCHEMA = "https://debz.dev/schema/vendor-state-inventory-v1";
pub const REFERENCE_SCHEMA = "https://debz.dev/schema/vendor-state-reference-v1";

pub const ARCHITECTURES = [_][]const u8{ "amd64", "arm64" };

pub const CLASSIFICATIONS = [_][]const u8{
    "format",
    "control",
    "ownership-list",
    "checksums",
    "conffiles",
    "triggers",
    "maintainer-script",
    "debconf-config",
    "package-alternatives",
    "retained-metadata",
    "unclassified",
};

pub const MAINTAINER_SCRIPTS = [_][]const u8{ "preinst", "postinst", "prerm", "postrm" };
pub const RETAINED_METADATA = [_][]const u8{ "templates", "shlibs", "symbols" };

pub const SENSITIVE_PATHS = [_][]const u8{
    "dev",
    "proc",
    "sys",
    "run",
    "root",
    "home",
    "tmp",
    "var/tmp",
    "var/log",
    "var/lib/cloud",
    "var/lib/private",
    "etc/shadow",
    "etc/gshadow",
    "etc/sudoers",
    "etc/sudoers.d",
    "etc/ssh",
    "etc/ssl/private",
    "etc/apt/auth.conf",
    "etc/apt/auth.conf.d",
};

pub const PUBLIC_REFERENCE_ROOTS = [_][]const u8{
    "bin",
    "lib",
    "lib32",
    "lib64",
    "libx32",
    "sbin",
    "usr",
};

pub const WRITE_WITNESS_PATHS = [_][]const u8{"dev/null"};
pub const MAX_JSON_INTEGER: i64 = (@as(i64, 1) << 53) - 1;
pub const MAX_DOCUMENT_PATH_BYTES: usize = 4096;
pub const MAX_TEXT_BYTES: usize = 4096;
pub const MAX_INDEX_BYTES: usize = 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
const HEX_DIGEST_BYTES: usize = 2 * 32;

pub const Limits = struct {
    max_control_members: i64 = 100_000,
    max_alternatives_records: i64 = 20_000,
    max_metadata_file_bytes: i64 = 8 * 1024 * 1024,
    max_total_metadata_bytes: i64 = 256 * 1024 * 1024,
    max_referenced_paths: i64 = 50_000,
    max_linked_entries: i64 = 100_000,
    max_link_hops: i64 = 64,
    max_link_target_bytes: i64 = 4096,
    max_linked_file_bytes: i64 = 256 * 1024 * 1024,
    max_total_linked_bytes: i64 = 1024 * 1024 * 1024,
};

pub const Diagnostic = struct {
    message: []const u8 = "",

    pub fn set(self: *Diagnostic, allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) void {
        self.message = std.fmt.allocPrint(allocator, fmt, args) catch "allocation failure";
    }
};

const StatIdentity = struct {
    dev_major: u32,
    dev_minor: u32,
    ino: u64,
    mode: u16,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: u32,
    ctime_sec: i64,
    ctime_nsec: u32,

    fn fromStatx(stx: linux.Statx) StatIdentity {
        return .{
            .dev_major = stx.dev_major,
            .dev_minor = stx.dev_minor,
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
        };
    }

    fn eql(a: StatIdentity, b: StatIdentity) bool {
        return a.dev_major == b.dev_major and
            a.dev_minor == b.dev_minor and
            a.ino == b.ino and
            a.mode == b.mode and
            a.nlink == b.nlink and
            a.uid == b.uid and
            a.gid == b.gid and
            a.size == b.size and
            a.mtime_sec == b.mtime_sec and
            a.mtime_nsec == b.mtime_nsec and
            a.ctime_sec == b.ctime_sec and
            a.ctime_nsec == b.ctime_nsec;
    }
};

fn statxAt(dir_fd: linux.fd_t, name: []const u8, nofollow: bool) !StatIdentity {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (name.len >= path_buf.len) return error.NameTooLong;
    @memcpy(path_buf[0..name.len], name);
    path_buf[name.len] = 0;
    const name_z: [*:0]const u8 = path_buf[0..name.len :0];
    var stx: linux.Statx = std.mem.zeroes(linux.Statx);
    const flags: u32 = if (name.len == 0)
        linux.AT.EMPTY_PATH
    else if (nofollow)
        linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT
    else
        0;
    const rc = linux.statx(dir_fd, name_z, flags, linux.STATX.BASIC_STATS, &stx);
    switch (linux.errno(rc)) {
        .SUCCESS => return StatIdentity.fromStatx(stx),
        .NOENT => return error.FileNotFound,
        .ACCES, .PERM => return error.AccessDenied,
        .NOTDIR => return error.NotDir,
        else => return error.StatFailed,
    }
}

fn fstatx(fd: linux.fd_t) !StatIdentity {
    return statxAt(fd, "", false);
}

fn openatFd(dir_fd: linux.fd_t, name: []const u8, flags: linux.O, mode: linux.mode_t) !linux.fd_t {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (name.len >= path_buf.len) return error.NameTooLong;
    @memcpy(path_buf[0..name.len], name);
    path_buf[name.len] = 0;
    const name_z: [*:0]const u8 = path_buf[0..name.len :0];
    const rc = linux.openat(dir_fd, name_z, flags, mode);
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .NOENT => return error.FileNotFound,
        .EXIST => return error.PathAlreadyExists,
        .ACCES, .PERM => return error.AccessDenied,
        .NOTDIR => return error.NotDir,
        .LOOP => return error.SymLinkLoop,
        else => return error.OpenFailed,
    }
}

fn dupFd(fd: linux.fd_t) !linux.fd_t {
    const rc = linux.dup(fd);
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => return error.DupFailed,
    }
}

fn closeFd(fd: linux.fd_t) void {
    _ = linux.close(fd);
}

fn directoryFlags() linux.O {
    return .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
}

fn regularFlags() linux.O {
    return .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
}

fn sliceContains(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

fn validateComponent(allocator: std.mem.Allocator, value: []const u8, diag: *Diagnostic) ![]const u8 {
    if (value.len == 0 or
        std.mem.eql(u8, value, ".") or
        std.mem.eql(u8, value, "..") or
        std.mem.indexOfScalar(u8, value, '/') != null or
        std.mem.indexOfScalar(u8, value, 0) != null)
    {
        diag.set(allocator, "unsafe path component: {s}", .{value});
        return error.CaptureFailed;
    }
    for (value) |ch| {
        if (ch < 32 or ch == 127) {
            diag.set(allocator, "unsafe path component: {s}", .{value});
            return error.CaptureFailed;
        }
    }
    if (!std.unicode.utf8ValidateSlice(value)) {
        diag.set(allocator, "path is not valid UTF-8: {s}", .{value});
        return error.CaptureFailed;
    }
    return value;
}

fn normalizeRelative(allocator: std.mem.Allocator, value: []const u8, diag: *Diagnostic) ![]const u8 {
    if (value.len == 0 or
        std.mem.startsWith(u8, value, "/") or
        std.mem.endsWith(u8, value, "/") or
        std.mem.indexOf(u8, value, "//") != null or
        std.mem.indexOfScalar(u8, value, 0) != null)
    {
        diag.set(allocator, "invalid relative path: {s}", .{value});
        return error.CaptureFailed;
    }
    if (!std.unicode.utf8ValidateSlice(value)) {
        diag.set(allocator, "path is not valid UTF-8: {s}", .{value});
        return error.CaptureFailed;
    }
    if (value.len > MAX_DOCUMENT_PATH_BYTES) {
        diag.set(allocator, "relative path exceeds limit: {s}", .{value});
        return error.CaptureFailed;
    }
    var it = std.mem.splitScalar(u8, value, '/');
    while (it.next()) |part| {
        _ = try validateComponent(allocator, part, diag);
    }
    return value;
}

fn validateAbsolutePath(
    allocator: std.mem.Allocator,
    value: []const u8,
    label: []const u8,
    allow_root: bool,
    diag: *Diagnostic,
) ![]const u8 {
    if (value.len == 0 or
        !std.mem.startsWith(u8, value, "/") or
        std.mem.indexOfScalar(u8, value, 0) != null or
        std.mem.indexOf(u8, value, "//") != null or
        (!std.mem.eql(u8, value, "/") and std.mem.endsWith(u8, value, "/")))
    {
        diag.set(allocator, "{s} must be a canonical absolute path", .{label});
        return error.CaptureFailed;
    }
    if (std.mem.eql(u8, value, "/")) {
        if (!allow_root) {
            diag.set(allocator, "{s} must not be the host root", .{label});
            return error.CaptureFailed;
        }
        return value;
    }
    var it = std.mem.splitScalar(u8, value[1..], '/');
    while (it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) {
            diag.set(allocator, "{s} contains an ambiguous component", .{label});
            return error.CaptureFailed;
        }
        _ = try validateComponent(allocator, component, diag);
    }
    return value;
}

fn isDirMode(mode: u16) bool {
    return (mode & linux.S.IFMT) == linux.S.IFDIR;
}

fn isRegMode(mode: u16) bool {
    return (mode & linux.S.IFMT) == linux.S.IFREG;
}

fn isLnkMode(mode: u16) bool {
    return (mode & linux.S.IFMT) == linux.S.IFLNK;
}

fn fileKind(mode: u16) []const u8 {
    return switch (mode & linux.S.IFMT) {
        linux.S.IFREG => "regular",
        linux.S.IFDIR => "directory",
        linux.S.IFLNK => "symlink",
        linux.S.IFIFO => "fifo",
        linux.S.IFSOCK => "socket",
        linux.S.IFCHR => "character-device",
        linux.S.IFBLK => "block-device",
        else => "unknown",
    };
}

fn formatMode(allocator: std.mem.Allocator, mode: u16) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{o:0>4}", .{mode & 0o7777});
}

fn openAbsoluteDirectory(
    allocator: std.mem.Allocator,
    value: []const u8,
    label: []const u8,
    allow_root: bool,
    diag: *Diagnostic,
) !linux.fd_t {
    const path = try validateAbsolutePath(allocator, value, label, allow_root, diag);
    var current = openatFd(linux.AT.FDCWD, "/", directoryFlags(), 0) catch |err| {
        diag.set(allocator, "cannot open host root while resolving {s}: {s}", .{ label, @errorName(err) });
        return error.CaptureFailed;
    };
    errdefer closeFd(current);
    if (std.mem.eql(u8, path, "/")) return current;

    var prefix: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, path[1..], '/');
    while (it.next()) |component| {
        try prefix.append(allocator, '/');
        try prefix.appendSlice(allocator, component);
        const expected = statxAt(current, component, true) catch |err| {
            diag.set(allocator, "cannot stat {s} component {s}: {s}", .{ label, prefix.items, @errorName(err) });
            return error.CaptureFailed;
        };
        if (!isDirMode(expected.mode) or isLnkMode(expected.mode)) {
            diag.set(allocator, "{s} component must be a real directory: {s}", .{ label, prefix.items });
            return error.CaptureFailed;
        }
        const following = openatFd(current, component, directoryFlags(), 0) catch |err| {
            diag.set(allocator, "cannot open {s} component {s}: {s}", .{ label, prefix.items, @errorName(err) });
            return error.CaptureFailed;
        };
        const opened = fstatx(following) catch |err| {
            closeFd(following);
            diag.set(allocator, "cannot stat opened {s} component {s}: {s}", .{ label, prefix.items, @errorName(err) });
            return error.CaptureFailed;
        };
        if (!isDirMode(opened.mode) or !StatIdentity.eql(expected, opened)) {
            closeFd(following);
            diag.set(allocator, "{s} component changed while opening: {s}", .{ label, prefix.items });
            return error.CaptureFailed;
        }
        closeFd(current);
        current = following;
    }
    return current;
}

fn openDirectoryAt(
    allocator: std.mem.Allocator,
    root_fd: linux.fd_t,
    relative: []const u8,
    required: bool,
    diag: *Diagnostic,
) !?linux.fd_t {
    const normalized = try normalizeRelative(allocator, relative, diag);
    var current = dupFd(root_fd) catch {
        diag.set(allocator, "cannot dup root directory for {s}", .{normalized});
        return error.CaptureFailed;
    };
    var it = std.mem.splitScalar(u8, normalized, '/');
    while (it.next()) |component| {
        const expected = statxAt(current, component, true) catch |err| {
            closeFd(current);
            if (err == error.FileNotFound) {
                if (required) {
                    diag.set(allocator, "required directory is missing: {s}", .{normalized});
                    return error.CaptureFailed;
                }
                return null;
            }
            diag.set(allocator, "cannot stat directory {s}: {s}", .{ normalized, @errorName(err) });
            return error.CaptureFailed;
        };
        if (!isDirMode(expected.mode) or isLnkMode(expected.mode)) {
            closeFd(current);
            diag.set(allocator, "directory is unsafe: {s}", .{normalized});
            return error.CaptureFailed;
        }
        const following = openatFd(current, component, directoryFlags(), 0) catch |err| {
            closeFd(current);
            diag.set(allocator, "cannot open directory {s}: {s}", .{ normalized, @errorName(err) });
            return error.CaptureFailed;
        };
        const opened = fstatx(following) catch |err| {
            closeFd(following);
            closeFd(current);
            diag.set(allocator, "cannot stat opened directory {s}: {s}", .{ normalized, @errorName(err) });
            return error.CaptureFailed;
        };
        if (!isDirMode(opened.mode) or !StatIdentity.eql(expected, opened)) {
            closeFd(following);
            closeFd(current);
            diag.set(allocator, "directory changed while opening: {s}", .{normalized});
            return error.CaptureFailed;
        }
        closeFd(current);
        current = following;
    }
    return current;
}

fn stringLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn boundedChildren(
    allocator: std.mem.Allocator,
    dir_fd: linux.fd_t,
    maximum: i64,
    label: []const u8,
    diag: *Diagnostic,
) !struct { children: [][]const u8, stat: StatIdentity } {
    const before = fstatx(dir_fd) catch |err| {
        diag.set(allocator, "cannot stat {s}: {s}", .{ label, @errorName(err) });
        return error.CaptureFailed;
    };
    const scan_fd = openatFd(dir_fd, ".", directoryFlags(), 0) catch |err| {
        diag.set(allocator, "cannot scan {s}: {s}", .{ label, @errorName(err) });
        return error.CaptureFailed;
    };
    defer closeFd(scan_fd);
    const scan_stat = fstatx(scan_fd) catch |err| {
        diag.set(allocator, "cannot stat {s}: {s}", .{ label, @errorName(err) });
        return error.CaptureFailed;
    };
    if (!StatIdentity.eql(before, scan_stat)) {
        diag.set(allocator, "{s} directory changed while scanning", .{label});
        return error.CaptureFailed;
    }

    var children: std.ArrayList([]const u8) = .empty;
    var buf: [8192]u8 align(@alignOf(linux.dirent64)) = undefined;
    while (true) {
        const rc = linux.getdents64(scan_fd, &buf, buf.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |err| {
                diag.set(allocator, "cannot scan {s}: {s}", .{ label, @tagName(err) });
                return error.CaptureFailed;
            },
        }
        if (rc == 0) break;
        var offset: usize = 0;
        while (offset < rc) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buf[offset]);
            const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
            const name = std.mem.sliceTo(name_ptr, 0);
            offset += entry.reclen;
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            try children.append(allocator, try allocator.dupe(u8, name));
            if (@as(i64, @intCast(children.items.len)) > maximum) {
                diag.set(allocator, "{s} count limit exceeded", .{label});
                return error.CaptureFailed;
            }
        }
    }
    const after = fstatx(dir_fd) catch |err| {
        diag.set(allocator, "cannot scan {s}: {s}", .{ label, @errorName(err) });
        return error.CaptureFailed;
    };
    if (!StatIdentity.eql(before, after)) {
        diag.set(allocator, "{s} directory changed while scanning", .{label});
        return error.CaptureFailed;
    }
    std.mem.sort([]const u8, children.items, {}, stringLessThan);
    return .{ .children = children.items, .stat = before };
}

fn requireUnchangedDirectory(
    allocator: std.mem.Allocator,
    dir_fd: linux.fd_t,
    expected: StatIdentity,
    label: []const u8,
    diag: *Diagnostic,
) !void {
    const observed = fstatx(dir_fd) catch |err| {
        diag.set(allocator, "cannot restat {s} directory: {s}", .{ label, @errorName(err) });
        return error.CaptureFailed;
    };
    if (!StatIdentity.eql(expected, observed)) {
        diag.set(allocator, "{s} directory changed during capture", .{label});
        return error.CaptureFailed;
    }
}

fn readRegularAt(
    allocator: std.mem.Allocator,
    dir_fd: linux.fd_t,
    name: []const u8,
    display_path: []const u8,
    expected: StatIdentity,
    maximum: i64,
    budget: *i64,
    budget_key: []const u8,
    total_maximum: i64,
    retain: bool,
    diag: *Diagnostic,
) !struct { hex_str: []const u8, data: ?[]const u8 } {
    if (!isRegMode(expected.mode)) {
        diag.set(allocator, "not a regular file: {s}", .{display_path});
        return error.CaptureFailed;
    }
    if (expected.nlink != 1) {
        diag.set(allocator, "hard-linked regular file is unsupported: {s}", .{display_path});
        return error.CaptureFailed;
    }
    if (expected.size > @as(u64, @intCast(MAX_JSON_INTEGER))) {
        diag.set(allocator, "regular-file size is outside the inventory schema: {s}", .{display_path});
        return error.CaptureFailed;
    }
    const size_i64: i64 = @intCast(expected.size);
    if (size_i64 > maximum) {
        diag.set(allocator, "regular file exceeds limit: {s}", .{display_path});
        return error.CaptureFailed;
    }
    const total = budget.* + size_i64;
    if (total > total_maximum or total > MAX_JSON_INTEGER) {
        diag.set(allocator, "aggregate regular-file limit exceeded: {s}", .{budget_key});
        return error.CaptureFailed;
    }
    const fd = openatFd(dir_fd, name, regularFlags(), 0) catch |err| {
        diag.set(allocator, "cannot open regular file {s}: {s}", .{ display_path, @errorName(err) });
        return error.CaptureFailed;
    };
    defer closeFd(fd);

    const opened = fstatx(fd) catch |err| {
        diag.set(allocator, "cannot read regular file {s}: {s}", .{ display_path, @errorName(err) });
        return error.CaptureFailed;
    };
    if (!isRegMode(opened.mode) or opened.nlink != 1 or !StatIdentity.eql(expected, opened)) {
        diag.set(allocator, "regular file changed before hashing: {s}", .{display_path});
        return error.CaptureFailed;
    }

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const contents: ?[]u8 = if (retain) try allocator.alloc(u8, @intCast(expected.size)) else null;
    var observed: usize = 0;
    var chunk_buf: [64 * 1024]u8 = undefined;
    var remaining: usize = @intCast(expected.size);
    while (remaining > 0) {
        const to_read = @min(chunk_buf.len, remaining);
        const rc = linux.read(fd, &chunk_buf, to_read);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |err| {
                diag.set(allocator, "cannot read regular file {s}: {s}", .{ display_path, @tagName(err) });
                return error.CaptureFailed;
            },
        }
        if (rc == 0) {
            diag.set(allocator, "regular file changed while hashing: {s}", .{display_path});
            return error.CaptureFailed;
        }
        const chunk = chunk_buf[0..rc];
        hasher.update(chunk);
        if (contents) |buf| {
            @memcpy(buf[observed .. observed + rc], chunk);
        }
        remaining -= rc;
        observed += rc;
    }
    var extra_byte: [1]u8 = undefined;
    const extra_rc = linux.read(fd, &extra_byte, 1);
    if (linux.errno(extra_rc) == .SUCCESS and extra_rc > 0) {
        diag.set(allocator, "regular file grew while hashing: {s}", .{display_path});
        return error.CaptureFailed;
    }
    const finished = fstatx(fd) catch |err| {
        diag.set(allocator, "cannot read regular file {s}: {s}", .{ display_path, @errorName(err) });
        return error.CaptureFailed;
    };
    if (!StatIdentity.eql(opened, finished) or observed != @as(usize, @intCast(expected.size))) {
        diag.set(allocator, "regular file changed while hashing: {s}", .{display_path});
        return error.CaptureFailed;
    }
    budget.* = total;
    const raw_out = hasher.finalResult();
    const hex_chars = std.fmt.bytesToHex(raw_out, .lower);
    return .{
        .hex_str = try allocator.dupe(u8, &hex_chars),
        .data = contents,
    };
}

pub fn classifyControlMember(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "format")) return "format";
    const dot_idx = std.mem.lastIndexOfScalar(u8, name, '.') orelse return "unclassified";
    const suffix = name[dot_idx + 1 ..];
    if (std.mem.eql(u8, suffix, "control")) return "control";
    if (std.mem.eql(u8, suffix, "list")) return "ownership-list";
    if (std.mem.eql(u8, suffix, "md5sums")) return "checksums";
    if (std.mem.eql(u8, suffix, "conffiles")) return "conffiles";
    if (std.mem.eql(u8, suffix, "triggers")) return "triggers";
    if (sliceContains(&MAINTAINER_SCRIPTS, suffix)) return "maintainer-script";
    if (std.mem.eql(u8, suffix, "config")) return "debconf-config";
    if (std.mem.eql(u8, suffix, "alternatives")) return "package-alternatives";
    if (sliceContains(&RETAINED_METADATA, suffix)) return "retained-metadata";
    return "unclassified";
}

fn rejectSensitiveReference(allocator: std.mem.Allocator, relative: []const u8, diag: *Diagnostic) !void {
    for (SENSITIVE_PATHS) |denied| {
        if (std.mem.eql(u8, relative, denied) or
            (relative.len > denied.len and std.mem.startsWith(u8, relative, denied) and relative[denied.len] == '/'))
        {
            diag.set(allocator, "alternative reference enters excluded state: {s}", .{relative});
            return error.CaptureFailed;
        }
    }
}

fn isEtcAlternatives(relative: []const u8) bool {
    return std.mem.eql(u8, relative, "etc/alternatives") or
        std.mem.startsWith(u8, relative, "etc/alternatives/");
}

fn pathIsOrHasDescendant(paths: []const []const u8, relative: []const u8) bool {
    for (paths) |candidate| {
        if (std.mem.eql(u8, candidate, relative) or
            (candidate.len > relative.len and std.mem.startsWith(u8, candidate, relative) and candidate[relative.len] == '/'))
        {
            return true;
        }
    }
    return false;
}

const ReferencePolicy = struct {
    etc_references: []const []const u8,
    owned_etc_references: std.StringHashMapUnmanaged(void),
    ordered_owned_etc_references: []const []const u8,
};

fn allowedDeclaredReference(allocator: std.mem.Allocator, relative: []const u8, diag: *Diagnostic) !void {
    try rejectSensitiveReference(allocator, relative, diag);
    const slash = std.mem.indexOfScalar(u8, relative, '/') orelse relative.len;
    const top_level = relative[0..slash];
    if (!sliceContains(&PUBLIC_REFERENCE_ROOTS, top_level) and !std.mem.eql(u8, top_level, "etc")) {
        diag.set(allocator, "alternative reference enters excluded state: {s}", .{relative});
        return error.CaptureFailed;
    }
}

fn allowedReference(
    allocator: std.mem.Allocator,
    relative: []const u8,
    policy: ReferencePolicy,
    diag: *Diagnostic,
) !void {
    try rejectSensitiveReference(allocator, relative, diag);
    const slash = std.mem.indexOfScalar(u8, relative, '/') orelse relative.len;
    const top_level = relative[0..slash];
    if (sliceContains(&PUBLIC_REFERENCE_ROOTS, top_level)) return;
    if (std.mem.eql(u8, relative, "etc") or
        isEtcAlternatives(relative) or
        pathIsOrHasDescendant(policy.etc_references, relative))
    {
        return;
    }
    diag.set(allocator, "alternative reference enters excluded state: {s}", .{relative});
    return error.CaptureFailed;
}

fn absoluteReference(
    allocator: std.mem.Allocator,
    value: []const u8,
    maximum_bytes: i64,
    diag: *Diagnostic,
) ![]const u8 {
    if (!std.unicode.utf8ValidateSlice(value)) {
        diag.set(allocator, "path is not valid UTF-8: {s}", .{value});
        return error.CaptureFailed;
    }
    if (!std.mem.startsWith(u8, value, "/") or
        std.mem.eql(u8, value, "/") or
        std.mem.endsWith(u8, value, "/") or
        std.mem.indexOf(u8, value, "//") != null or
        std.mem.indexOfScalar(u8, value, 0) != null or
        @as(i64, @intCast(value.len)) > maximum_bytes or
        value.len > MAX_DOCUMENT_PATH_BYTES)
    {
        diag.set(allocator, "malformed absolute alternative path: {s}", .{value});
        return error.CaptureFailed;
    }
    const relative = try normalizeRelative(allocator, value[1..], diag);
    try allowedDeclaredReference(allocator, relative, diag);
    return try allocator.dupe(u8, relative);
}

fn isRefBoundaryPredecessor(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r' or ch == 0x0b or ch == 0x0c or ch == ':' or ch == '=';
}

fn isAsciiWhitespace(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r' or ch == 0x0b or ch == 0x0c;
}

fn extractReferences(
    allocator: std.mem.Allocator,
    data: []const u8,
    source: []const u8,
    maximum: i64,
    maximum_path_bytes: i64,
    diag: *Diagnostic,
) ![][]const u8 {
    if (!std.unicode.utf8ValidateSlice(data)) {
        diag.set(allocator, "{s} is not UTF-8", .{source});
        return error.CaptureFailed;
    }
    for (data) |ch| {
        if (ch == 0 or (ch < 32 and ch != '\n' and ch != '\r' and ch != '\t')) {
            diag.set(allocator, "{s} contains control bytes", .{source});
            return error.CaptureFailed;
        }
    }
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var list: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < data.len) {
        if (data[i] == '/' and (i == 0 or isRefBoundaryPredecessor(data[i - 1]))) {
            const start = i;
            i += 1;
            while (i < data.len and !isAsciiWhitespace(data[i])) : (i += 1) {}
            if (i > start + 1) {
                const ref = try absoluteReference(allocator, data[start..i], maximum_path_bytes, diag);
                if (!seen.contains(ref)) {
                    try seen.put(allocator, ref, {});
                    try list.append(allocator, ref);
                    if (@as(i64, @intCast(list.items.len)) > maximum) {
                        diag.set(allocator, "alternative reference count limit exceeded", .{});
                        return error.CaptureFailed;
                    }
                }
            }
        } else {
            i += 1;
        }
    }
    std.mem.sort([]const u8, list.items, {}, stringLessThan);
    return list.items;
}

fn mergeReferences(
    allocator: std.mem.Allocator,
    destination: *std.StringHashMapUnmanaged(void),
    additions: []const []const u8,
    maximum: i64,
    diag: *Diagnostic,
) !void {
    for (additions) |item| {
        if (!destination.contains(item)) {
            try destination.put(allocator, item, {});
        }
    }
    if (@as(i64, @intCast(destination.count())) > maximum) {
        diag.set(allocator, "alternative reference count limit exceeded", .{});
        return error.CaptureFailed;
    }
}

fn makeMetadataJson(
    allocator: std.mem.Allocator,
    obj: *std.json.ObjectMap,
    st: StatIdentity,
) !void {
    try obj.put(allocator, "mode", .{ .string = try formatMode(allocator, st.mode) });
    try obj.put(allocator, "uid", .{ .integer = @intCast(st.uid) });
    try obj.put(allocator, "gid", .{ .integer = @intCast(st.gid) });
}

fn makeStringArrayJson(allocator: std.mem.Allocator, items: []const []const u8) !std.json.Value {
    var arr = std.json.Array.init(allocator);
    for (items) |item| {
        try arr.append(.{ .string = item });
    }
    return .{ .array = arr };
}

fn scanMetadata(
    allocator: std.mem.Allocator,
    root_fd: linux.fd_t,
    limits: Limits,
    diag: *Diagnostic,
) !struct {
    control_members: []std.json.Value,
    alternatives_records: []std.json.Value,
    references: std.StringHashMapUnmanaged(void),
    policy: ReferencePolicy,
} {
    var metadata_budget: i64 = 0;
    var references: std.StringHashMapUnmanaged(void) = .empty;
    var ownership_lists: std.ArrayList([]const u8) = .empty;
    var control_members: std.ArrayList(std.json.Value) = .empty;

    const info_fd = (try openDirectoryAt(allocator, root_fd, "var/lib/dpkg/info", true, diag)).?;
    defer closeFd(info_fd);
    {
        const scanned = try boundedChildren(allocator, info_fd, limits.max_control_members, "control-member", diag);
        for (scanned.children) |child_name| {
            const name = try validateComponent(allocator, child_name, diag);
            const relative = try normalizeRelative(
                allocator,
                try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}", .{name}),
                diag,
            );
            const metadata = statxAt(info_fd, name, true) catch |err| {
                diag.set(allocator, "cannot stat {s}: {s}", .{ relative, @errorName(err) });
                return error.CaptureFailed;
            };
            if (!isRegMode(metadata.mode)) {
                diag.set(allocator, "control member is not a regular file: {s}", .{relative});
                return error.CaptureFailed;
            }
            const classification = classifyControlMember(name);
            const retain = std.mem.eql(u8, classification, "ownership-list") or
                std.mem.eql(u8, classification, "package-alternatives");
            const read_res = try readRegularAt(
                allocator,
                info_fd,
                name,
                relative,
                metadata,
                limits.max_metadata_file_bytes,
                &metadata_budget,
                "metadata_bytes",
                limits.max_total_metadata_bytes,
                retain,
                diag,
            );
            if (std.mem.eql(u8, classification, "ownership-list")) {
                try ownership_lists.append(allocator, read_res.data.?);
            }
            const referenced = if (std.mem.eql(u8, classification, "package-alternatives"))
                try extractReferences(
                    allocator,
                    read_res.data orelse "",
                    relative,
                    limits.max_referenced_paths,
                    limits.max_link_target_bytes,
                    diag,
                )
            else
                &[_][]const u8{};
            try mergeReferences(allocator, &references, referenced, limits.max_referenced_paths, diag);

            var obj: std.json.ObjectMap = .empty;
            try obj.put(allocator, "path", .{ .string = relative });
            try obj.put(allocator, "classification", .{ .string = classification });
            try makeMetadataJson(allocator, &obj, metadata);
            try obj.put(allocator, "size", .{ .integer = @intCast(metadata.size) });
            try obj.put(allocator, "sha256", .{ .string = read_res.hex_str });
            try obj.put(allocator, "referenced_paths", try makeStringArrayJson(allocator, referenced));
            try control_members.append(allocator, .{ .object = obj });
        }
        try requireUnchangedDirectory(allocator, info_fd, scanned.stat, "control-member", diag);
    }

    var alternatives_records: std.ArrayList(std.json.Value) = .empty;
    if (try openDirectoryAt(allocator, root_fd, "var/lib/dpkg/alternatives", false, diag)) |alt_fd| {
        defer closeFd(alt_fd);
        const scanned = try boundedChildren(allocator, alt_fd, limits.max_alternatives_records, "alternatives-record", diag);
        for (scanned.children) |child_name| {
            const name = try validateComponent(allocator, child_name, diag);
            const relative = try normalizeRelative(
                allocator,
                try std.fmt.allocPrint(allocator, "var/lib/dpkg/alternatives/{s}", .{name}),
                diag,
            );
            const metadata = statxAt(alt_fd, name, true) catch |err| {
                diag.set(allocator, "cannot stat {s}: {s}", .{ relative, @errorName(err) });
                return error.CaptureFailed;
            };
            if (!isRegMode(metadata.mode)) {
                diag.set(allocator, "alternatives record is not a regular file: {s}", .{relative});
                return error.CaptureFailed;
            }
            const read_res = try readRegularAt(
                allocator,
                alt_fd,
                name,
                relative,
                metadata,
                limits.max_metadata_file_bytes,
                &metadata_budget,
                "metadata_bytes",
                limits.max_total_metadata_bytes,
                true,
                diag,
            );
            const referenced = try extractReferences(
                allocator,
                read_res.data orelse "",
                relative,
                limits.max_referenced_paths,
                limits.max_link_target_bytes,
                diag,
            );
            try mergeReferences(allocator, &references, referenced, limits.max_referenced_paths, diag);

            var obj: std.json.ObjectMap = .empty;
            try obj.put(allocator, "path", .{ .string = relative });
            try makeMetadataJson(allocator, &obj, metadata);
            try obj.put(allocator, "size", .{ .integer = @intCast(metadata.size) });
            try obj.put(allocator, "sha256", .{ .string = read_res.hex_str });
            try obj.put(allocator, "referenced_paths", try makeStringArrayJson(allocator, referenced));
            try alternatives_records.append(allocator, .{ .object = obj });
        }
        try requireUnchangedDirectory(allocator, alt_fd, scanned.stat, "alternatives-record", diag);
    }

    var etc_refs: std.ArrayList([]const u8) = .empty;
    var encoded_etc_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    var ref_it = references.keyIterator();
    while (ref_it.next()) |key_ptr| {
        const reference = key_ptr.*;
        if (std.mem.eql(u8, reference, "etc") or
            (std.mem.startsWith(u8, reference, "etc/") and !isEtcAlternatives(reference)))
        {
            try etc_refs.append(allocator, reference);
            const with_slash = try std.fmt.allocPrint(allocator, "/{s}", .{reference});
            try encoded_etc_map.put(allocator, with_slash, reference);
        }
    }
    std.mem.sort([]const u8, etc_refs.items, {}, stringLessThan);

    var owned_etc_set: std.StringHashMapUnmanaged(void) = .empty;
    var owned_etc_list: std.ArrayList([]const u8) = .empty;
    for (ownership_lists.items) |data| {
        var line_it = std.mem.splitScalar(u8, data, '\n');
        while (line_it.next()) |raw_line| {
            const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
                raw_line[0 .. raw_line.len - 1]
            else
                raw_line;
            if (encoded_etc_map.get(line)) |ref| {
                if (!owned_etc_set.contains(ref)) {
                    try owned_etc_set.put(allocator, ref, {});
                    try owned_etc_list.append(allocator, ref);
                }
            }
        }
    }
    std.mem.sort([]const u8, owned_etc_list.items, {}, stringLessThan);

    return .{
        .control_members = control_members.items,
        .alternatives_records = alternatives_records.items,
        .references = references,
        .policy = .{
            .etc_references = etc_refs.items,
            .owned_etc_references = owned_etc_set,
            .ordered_owned_etc_references = owned_etc_list.items,
        },
    };
}

fn joinSlash(allocator: std.mem.Allocator, parts: []const []const u8) ![]const u8 {
    if (parts.len == 0) return "";
    var out: std.ArrayList(u8) = .empty;
    for (parts, 0..) |part, i| {
        if (i > 0) try out.append(allocator, '/');
        try out.appendSlice(allocator, part);
    }
    return out.items;
}

fn resolveLinkTarget(
    allocator: std.mem.Allocator,
    parent: []const []const u8,
    target: []const u8,
    limits: Limits,
    policy: ReferencePolicy,
    diag: *Diagnostic,
) ![][]const u8 {
    if (!std.unicode.utf8ValidateSlice(target)) {
        diag.set(allocator, "path is not valid UTF-8: {s}", .{target});
        return error.CaptureFailed;
    }
    if (target.len == 0 or
        std.mem.indexOfScalar(u8, target, 0) != null or
        @as(i64, @intCast(target.len)) > limits.max_link_target_bytes or
        target.len > MAX_DOCUMENT_PATH_BYTES or
        std.mem.indexOf(u8, target, "//") != null)
    {
        diag.set(allocator, "unsafe symlink target: {s}", .{target});
        return error.CaptureFailed;
    }
    for (target) |ch| {
        if (ch < 32 or ch == 127) {
            diag.set(allocator, "unsafe symlink target: {s}", .{target});
            return error.CaptureFailed;
        }
    }
    var result: std.ArrayList([]const u8) = .empty;
    if (!std.mem.startsWith(u8, target, "/")) {
        try result.appendSlice(allocator, parent);
    }
    var it = std.mem.splitScalar(u8, target, '/');
    while (it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            if (result.items.len == 0) {
                diag.set(allocator, "symlink target escapes reference root: {s}", .{target});
                return error.CaptureFailed;
            }
            _ = result.pop();
            continue;
        }
        try result.append(allocator, try validateComponent(allocator, component, diag));
    }
    if (result.items.len == 0) {
        diag.set(allocator, "symlink target resolves to reference root: {s}", .{target});
        return error.CaptureFailed;
    }
    const relative = try normalizeRelative(allocator, try joinSlash(allocator, result.items), diag);
    try allowedReference(allocator, relative, policy, diag);
    return result.items;
}

fn readlinkStable(
    allocator: std.mem.Allocator,
    parent_fd: linux.fd_t,
    name: []const u8,
    relative: []const u8,
    expected: StatIdentity,
    diag: *Diagnostic,
) ![]const u8 {
    if (expected.nlink != 1) {
        diag.set(allocator, "hard-linked symlink is unsupported: {s}", .{relative});
        return error.CaptureFailed;
    }
    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (name.len >= name_buf.len) {
        diag.set(allocator, "cannot read symlink {s}: NameTooLong", .{relative});
        return error.CaptureFailed;
    }
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;
    const name_z: [*:0]const u8 = name_buf[0..name.len :0];
    var target_buf: [MAX_DOCUMENT_PATH_BYTES + 2]u8 = undefined;
    const rc = linux.readlinkat(parent_fd, name_z, &target_buf, target_buf.len);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |err| {
            diag.set(allocator, "cannot read symlink {s}: {s}", .{ relative, @tagName(err) });
            return error.CaptureFailed;
        },
    }
    const target = try allocator.dupe(u8, target_buf[0..rc]);
    const observed = statxAt(parent_fd, name, true) catch |err| {
        diag.set(allocator, "cannot read symlink {s}: {s}", .{ relative, @errorName(err) });
        return error.CaptureFailed;
    };
    if (!isLnkMode(observed.mode) or !StatIdentity.eql(expected, observed)) {
        diag.set(allocator, "symlink changed while reading: {s}", .{relative});
        return error.CaptureFailed;
    }
    if (!std.unicode.utf8ValidateSlice(target)) {
        diag.set(allocator, "path is not valid UTF-8: {s}", .{target});
        return error.CaptureFailed;
    }
    if (target.len != @as(usize, @intCast(expected.size))) {
        diag.set(allocator, "symlink size changed while reading: {s}", .{relative});
        return error.CaptureFailed;
    }
    return target;
}

fn openKnownDirectoryAt(
    allocator: std.mem.Allocator,
    parent_fd: linux.fd_t,
    name: []const u8,
    relative: []const u8,
    expected: StatIdentity,
    diag: *Diagnostic,
) !struct { fd: linux.fd_t, stat: StatIdentity } {
    const fd = openatFd(parent_fd, name, directoryFlags(), 0) catch |err| {
        diag.set(allocator, "cannot open linked directory {s}: {s}", .{ relative, @errorName(err) });
        return error.CaptureFailed;
    };
    const opened = fstatx(fd) catch |err| {
        closeFd(fd);
        diag.set(allocator, "cannot open linked directory {s}: {s}", .{ relative, @errorName(err) });
        return error.CaptureFailed;
    };
    if (!isDirMode(opened.mode) or !StatIdentity.eql(expected, opened)) {
        closeFd(fd);
        diag.set(allocator, "linked directory changed while opening: {s}", .{relative});
        return error.CaptureFailed;
    }
    return .{ .fd = fd, .stat = opened };
}

fn jsonValueEql(a: std.json.Value, b: std.json.Value) bool {
    switch (a) {
        .null => return b == .null,
        .bool => |av| return b == .bool and av == b.bool,
        .integer => |av| return b == .integer and av == b.integer,
        .float => |av| return b == .float and av == b.float,
        .number_string => |av| return b == .number_string and std.mem.eql(u8, av, b.number_string),
        .string => |av| return b == .string and std.mem.eql(u8, av, b.string),
        .array => |aa| {
            if (b != .array or aa.items.len != b.array.items.len) return false;
            for (aa.items, b.array.items) |ai, bi| {
                if (!jsonValueEql(ai, bi)) return false;
            }
            return true;
        },
        .object => |ao| {
            if (b != .object or ao.count() != b.object.count()) return false;
            var it = ao.iterator();
            while (it.next()) |entry| {
                const bv = b.object.get(entry.key_ptr.*) orelse return false;
                if (!jsonValueEql(entry.value_ptr.*, bv)) return false;
            }
            return true;
        },
    }
}

fn addLinkedEntry(
    allocator: std.mem.Allocator,
    entries: *std.StringHashMapUnmanaged(std.json.Value),
    identities: *std.StringHashMapUnmanaged(?StatIdentity),
    path: []const u8,
    entry: std.json.Value,
    limits: Limits,
    metadata: ?StatIdentity,
    diag: *Diagnostic,
) !void {
    if (entries.get(path)) |previous| {
        const prev_id = identities.get(path).?;
        const same_id = if (prev_id) |pi|
            (if (metadata) |mi| StatIdentity.eql(pi, mi) else false)
        else
            metadata == null;
        if (!jsonValueEql(previous, entry) or !same_id) {
            diag.set(allocator, "linked state changed during capture: {s}", .{path});
            return error.CaptureFailed;
        }
        return;
    }
    if (@as(i64, @intCast(entries.count())) >= limits.max_linked_entries) {
        diag.set(allocator, "linked-filesystem entry count limit exceeded", .{});
        return error.CaptureFailed;
    }
    try entries.put(allocator, path, entry);
    try identities.put(allocator, path, metadata);
}

fn splitSlashAlloc(allocator: std.mem.Allocator, path: []const u8) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |part| {
        try list.append(allocator, part);
    }
    return list.items;
}

fn captureReference(
    allocator: std.mem.Allocator,
    root_fd: linux.fd_t,
    requested: []const u8,
    limits: Limits,
    policy: ReferencePolicy,
    entries: *std.StringHashMapUnmanaged(std.json.Value),
    identities: *std.StringHashMapUnmanaged(?StatIdentity),
    linked_budget: *i64,
    diag: *Diagnostic,
) !void {
    const normalized_req = try normalizeRelative(allocator, requested, diag);
    var unresolved = try splitSlashAlloc(allocator, normalized_req);
    var resolved: std.ArrayList([]const u8) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    try seen.put(allocator, normalized_req, {});
    var hops: i64 = 0;
    var current_fd = try dupFd(root_fd);
    defer closeFd(current_fd);

    while (unresolved.len > 0) {
        const component = unresolved[0];
        unresolved = unresolved[1..];

        var current_parts: std.ArrayList([]const u8) = .empty;
        try current_parts.appendSlice(allocator, resolved.items);
        try current_parts.append(allocator, component);
        const relative = try normalizeRelative(allocator, try joinSlash(allocator, current_parts.items), diag);
        try allowedReference(allocator, relative, policy, diag);
        const parent_metadata = fstatx(current_fd) catch |err| {
            diag.set(allocator, "cannot stat linked parent for {s}: {s}", .{ relative, @errorName(err) });
            return error.CaptureFailed;
        };

        const metadata = statxAt(current_fd, component, true) catch |err| {
            if (err == error.FileNotFound) {
                var pending_parts: std.ArrayList([]const u8) = .empty;
                try pending_parts.appendSlice(allocator, current_parts.items);
                try pending_parts.appendSlice(allocator, unresolved);
                const pending = try normalizeRelative(allocator, try joinSlash(allocator, pending_parts.items), diag);
                if ((std.mem.eql(u8, relative, "etc") or
                    (std.mem.startsWith(u8, relative, "etc/") and !isEtcAlternatives(relative))) and
                    !isEtcAlternatives(pending) and
                    !pathIsOrHasDescendant(policy.ordered_owned_etc_references, relative))
                {
                    diag.set(allocator, "alternative reference enters unowned etc state: {s}", .{relative});
                    return error.CaptureFailed;
                }
                var obj: std.json.ObjectMap = .empty;
                try obj.put(allocator, "path", .{ .string = relative });
                try obj.put(allocator, "kind", .{ .string = "absent" });
                try addLinkedEntry(allocator, entries, identities, relative, .{ .object = obj }, limits, null, diag);
                try requireUnchangedDirectory(allocator, current_fd, parent_metadata, relative, diag);
                return;
            }
            diag.set(allocator, "cannot stat linked path {s}: {s}", .{ relative, @errorName(err) });
            return error.CaptureFailed;
        };

        const kind = fileKind(metadata.mode);
        if (std.mem.eql(u8, kind, "symlink")) {
            const target = try readlinkStable(allocator, current_fd, component, relative, metadata, diag);
            try requireUnchangedDirectory(allocator, current_fd, parent_metadata, relative, diag);
            const resolved_target = try resolveLinkTarget(allocator, resolved.items, target, limits, policy, diag);
            const resolved_target_str = try joinSlash(allocator, resolved_target);
            if (std.mem.startsWith(u8, relative, "etc/") and
                !isEtcAlternatives(relative) and
                !policy.owned_etc_references.contains(relative) and
                !isEtcAlternatives(resolved_target_str))
            {
                diag.set(allocator, "unowned etc alternative link does not target etc/alternatives: {s}", .{relative});
                return error.CaptureFailed;
            }
            var obj: std.json.ObjectMap = .empty;
            try obj.put(allocator, "path", .{ .string = relative });
            try obj.put(allocator, "kind", .{ .string = "symlink" });
            try makeMetadataJson(allocator, &obj, metadata);
            try obj.put(allocator, "target", .{ .string = target });
            try addLinkedEntry(allocator, entries, identities, relative, .{ .object = obj }, limits, metadata, diag);

            hops += 1;
            if (hops > limits.max_link_hops) {
                diag.set(allocator, "symlink hop limit exceeded: {s}", .{requested});
                return error.CaptureFailed;
            }
            var combined_parts: std.ArrayList([]const u8) = .empty;
            try combined_parts.appendSlice(allocator, resolved_target);
            try combined_parts.appendSlice(allocator, unresolved);
            const combined = try normalizeRelative(allocator, try joinSlash(allocator, combined_parts.items), diag);
            if (seen.contains(combined)) {
                diag.set(allocator, "symlink cycle while resolving {s}", .{requested});
                return error.CaptureFailed;
            }
            try seen.put(allocator, combined, {});
            unresolved = try splitSlashAlloc(allocator, combined);
            resolved.clearRetainingCapacity();
            closeFd(current_fd);
            current_fd = try dupFd(root_fd);
            continue;
        }
        if (std.mem.eql(u8, kind, "directory")) {
            const opened_dir = try openKnownDirectoryAt(allocator, current_fd, component, relative, metadata, diag);
            try requireUnchangedDirectory(allocator, current_fd, parent_metadata, relative, diag);
            if (unresolved.len > 0) {
                closeFd(current_fd);
                current_fd = opened_dir.fd;
                try resolved.append(allocator, component);
                continue;
            }
            closeFd(opened_dir.fd);
            if ((std.mem.eql(u8, relative, "etc") or
                (std.mem.startsWith(u8, relative, "etc/") and !isEtcAlternatives(relative))) and
                !policy.owned_etc_references.contains(relative))
            {
                diag.set(allocator, "alternative reference enters unowned etc state: {s}", .{relative});
                return error.CaptureFailed;
            }
            var obj: std.json.ObjectMap = .empty;
            try obj.put(allocator, "path", .{ .string = relative });
            try obj.put(allocator, "kind", .{ .string = "directory" });
            try makeMetadataJson(allocator, &obj, opened_dir.stat);
            try addLinkedEntry(allocator, entries, identities, relative, .{ .object = obj }, limits, opened_dir.stat, diag);
            return;
        }
        if (std.mem.eql(u8, kind, "regular")) {
            if (unresolved.len > 0) {
                diag.set(allocator, "non-directory component in linked path {s}: {s}", .{ requested, relative });
                return error.CaptureFailed;
            }
            if (std.mem.startsWith(u8, relative, "etc/") and
                !isEtcAlternatives(relative) and
                !policy.owned_etc_references.contains(relative))
            {
                diag.set(allocator, "alternative reference enters unowned etc state: {s}", .{relative});
                return error.CaptureFailed;
            }
            const hex_str = if (entries.get(relative)) |previous|
                previous.object.get("sha256").?.string
            else blk: {
                const read_res = try readRegularAt(
                    allocator,
                    current_fd,
                    component,
                    relative,
                    metadata,
                    limits.max_linked_file_bytes,
                    linked_budget,
                    "linked_bytes",
                    limits.max_total_linked_bytes,
                    false,
                    diag,
                );
                break :blk read_res.hex_str;
            };
            var obj: std.json.ObjectMap = .empty;
            try obj.put(allocator, "path", .{ .string = relative });
            try obj.put(allocator, "kind", .{ .string = "regular" });
            try makeMetadataJson(allocator, &obj, metadata);
            try obj.put(allocator, "size", .{ .integer = @intCast(metadata.size) });
            try obj.put(allocator, "sha256", .{ .string = hex_str });
            try addLinkedEntry(allocator, entries, identities, relative, .{ .object = obj }, limits, metadata, diag);
            try requireUnchangedDirectory(allocator, current_fd, parent_metadata, relative, diag);
            return;
        }
        diag.set(allocator, "linked path is a special file: {s} ({s})", .{ relative, kind });
        return error.CaptureFailed;
    }
}

fn captureLinkedFilesystem(
    allocator: std.mem.Allocator,
    root_fd: linux.fd_t,
    references: *std.StringHashMapUnmanaged(void),
    limits: Limits,
    policy: ReferencePolicy,
    diag: *Diagnostic,
) !struct { requested: [][]const u8, entries: []std.json.Value } {
    const alt_fd_opt = try openDirectoryAt(allocator, root_fd, "etc/alternatives", false, diag);
    defer if (alt_fd_opt) |fd| closeFd(fd);
    var alt_stat_opt: ?StatIdentity = null;

    if (alt_fd_opt) |alt_fd| {
        const scanned = try boundedChildren(allocator, alt_fd, limits.max_referenced_paths, "etc/alternatives entry", diag);
        alt_stat_opt = scanned.stat;
        for (scanned.children) |child_name| {
            const name = try validateComponent(allocator, child_name, diag);
            const rel = try normalizeRelative(
                allocator,
                try std.fmt.allocPrint(allocator, "etc/alternatives/{s}", .{name}),
                diag,
            );
            if (!references.contains(rel)) {
                try references.put(allocator, rel, {});
            }
            if (@as(i64, @intCast(references.count())) > limits.max_referenced_paths) {
                diag.set(allocator, "alternative reference count limit exceeded", .{});
                return error.CaptureFailed;
            }
        }
    }
    if (@as(i64, @intCast(references.count())) > limits.max_referenced_paths) {
        diag.set(allocator, "alternative reference count limit exceeded", .{});
        return error.CaptureFailed;
    }

    var requested: std.ArrayList([]const u8) = .empty;
    var ref_it = references.keyIterator();
    while (ref_it.next()) |key_ptr| {
        try requested.append(allocator, key_ptr.*);
    }
    std.mem.sort([]const u8, requested.items, {}, stringLessThan);

    var entries: std.StringHashMapUnmanaged(std.json.Value) = .empty;
    var identities: std.StringHashMapUnmanaged(?StatIdentity) = .empty;
    var linked_budget: i64 = 0;

    for (requested.items) |rel| {
        try captureReference(allocator, root_fd, rel, limits, policy, &entries, &identities, &linked_budget, diag);
    }
    if (alt_fd_opt != null and alt_stat_opt != null) {
        try requireUnchangedDirectory(allocator, alt_fd_opt.?, alt_stat_opt.?, "etc/alternatives entry", diag);
    }

    var entry_keys: std.ArrayList([]const u8) = .empty;
    var entry_it = entries.keyIterator();
    while (entry_it.next()) |k| {
        try entry_keys.append(allocator, k.*);
    }
    std.mem.sort([]const u8, entry_keys.items, {}, stringLessThan);

    var sorted_entries: std.ArrayList(std.json.Value) = .empty;
    for (entry_keys.items) |k| {
        try sorted_entries.append(allocator, entries.get(k).?);
    }
    return .{ .requested = requested.items, .entries = sorted_entries.items };
}

fn captureWriteWitness(
    allocator: std.mem.Allocator,
    root_fd: linux.fd_t,
    relative: []const u8,
    limits: Limits,
    diag: *Diagnostic,
) !std.json.Value {
    const slash = std.mem.lastIndexOfScalar(u8, relative, '/').?;
    const parent = relative[0..slash];
    const name = relative[slash + 1 ..];
    const dir_fd_opt = try openDirectoryAt(allocator, root_fd, parent, false, diag);
    if (dir_fd_opt == null) {
        var obj: std.json.ObjectMap = .empty;
        try obj.put(allocator, "path", .{ .string = relative });
        try obj.put(allocator, "kind", .{ .string = "absent" });
        return .{ .object = obj };
    }
    const dir_fd = dir_fd_opt.?;
    defer closeFd(dir_fd);

    const metadata = statxAt(dir_fd, name, true) catch |err| {
        if (err == error.FileNotFound) {
            var obj: std.json.ObjectMap = .empty;
            try obj.put(allocator, "path", .{ .string = relative });
            try obj.put(allocator, "kind", .{ .string = "absent" });
            return .{ .object = obj };
        }
        diag.set(allocator, "cannot stat write witness {s}: {s}", .{ relative, @errorName(err) });
        return error.CaptureFailed;
    };
    const kind = fileKind(metadata.mode);
    if (std.mem.eql(u8, kind, "regular")) {
        var witness_budget: i64 = 0;
        const read_res = try readRegularAt(
            allocator,
            dir_fd,
            name,
            relative,
            metadata,
            limits.max_linked_file_bytes,
            &witness_budget,
            "witness_bytes",
            limits.max_linked_file_bytes,
            false,
            diag,
        );
        var obj: std.json.ObjectMap = .empty;
        try obj.put(allocator, "path", .{ .string = relative });
        try obj.put(allocator, "kind", .{ .string = "regular" });
        try makeMetadataJson(allocator, &obj, metadata);
        try obj.put(allocator, "size", .{ .integer = @intCast(metadata.size) });
        try obj.put(allocator, "sha256", .{ .string = read_res.hex_str });
        return .{ .object = obj };
    }
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "path", .{ .string = relative });
    try obj.put(allocator, "kind", .{ .string = kind });
    try makeMetadataJson(allocator, &obj, metadata);
    if (std.mem.eql(u8, kind, "symlink")) {
        const target = try readlinkStable(allocator, dir_fd, name, relative, metadata, diag);
        try obj.put(allocator, "target", .{ .string = target });
    }
    return .{ .object = obj };
}

fn validateLimits(allocator: std.mem.Allocator, limits: Limits, diag: *Diagnostic) !void {
    inline for (LIMIT_KEYS) |field_name| {
        const val = @field(limits, field_name);
        if (val < 1 or val > MAX_JSON_INTEGER) {
            diag.set(allocator, "{s} must be a positive schema-safe integer", .{field_name});
            return error.CaptureFailed;
        }
    }
}

pub fn capture(
    allocator: std.mem.Allocator,
    reference_root: []const u8,
    architecture: []const u8,
    limits: Limits,
    diag: *Diagnostic,
) !std.json.Value {
    if (!sliceContains(&ARCHITECTURES, architecture)) {
        diag.set(allocator, "unsupported architecture: {s}", .{architecture});
        return error.CaptureFailed;
    }
    try validateLimits(allocator, limits, diag);
    const root_fd = try openAbsoluteDirectory(allocator, reference_root, "reference root", false, diag);
    defer closeFd(root_fd);
    const root_metadata = fstatx(root_fd) catch |err| {
        diag.set(allocator, "cannot stat reference root: {s}", .{@errorName(err)});
        return error.CaptureFailed;
    };

    var meta = try scanMetadata(allocator, root_fd, limits, diag);
    const linked = try captureLinkedFilesystem(allocator, root_fd, &meta.references, limits, meta.policy, diag);
    var write_witnesses = std.json.Array.init(allocator);
    for (WRITE_WITNESS_PATHS) |wpath| {
        try write_witnesses.append(try captureWriteWitness(allocator, root_fd, wpath, limits, diag));
    }
    try requireUnchangedDirectory(allocator, root_fd, root_metadata, "reference root", diag);

    var counts_obj: std.json.ObjectMap = .empty;
    for (CLASSIFICATIONS) |cls| {
        try counts_obj.put(allocator, cls, .{ .integer = 0 });
    }
    for (meta.control_members) |entry| {
        const cls = entry.object.get("classification").?.string;
        const cur = counts_obj.get(cls).?.integer;
        try counts_obj.put(allocator, cls, .{ .integer = cur + 1 });
    }

    var limits_obj: std.json.ObjectMap = .empty;
    inline for (LIMIT_KEYS) |field_name| {
        try limits_obj.put(allocator, field_name, .{ .integer = @field(limits, field_name) });
    }

    var controls_arr = std.json.Array.init(allocator);
    try controls_arr.appendSlice(meta.control_members);
    var controls_obj: std.json.ObjectMap = .empty;
    try controls_obj.put(allocator, "classification_counts", .{ .object = counts_obj });
    try controls_obj.put(allocator, "entries", .{ .array = controls_arr });

    var alt_arr = std.json.Array.init(allocator);
    try alt_arr.appendSlice(meta.alternatives_records);

    var linked_entries_arr = std.json.Array.init(allocator);
    try linked_entries_arr.appendSlice(linked.entries);
    var linked_obj: std.json.ObjectMap = .empty;
    try linked_obj.put(allocator, "requested_paths", try makeStringArrayJson(allocator, linked.requested));
    try linked_obj.put(allocator, "entries", .{ .array = linked_entries_arr });

    var doc: std.json.ObjectMap = .empty;
    try doc.put(allocator, "schema", .{ .string = CAPTURE_SCHEMA });
    try doc.put(allocator, "version", .{ .integer = 1 });
    try doc.put(allocator, "architecture", .{ .string = architecture });
    try doc.put(allocator, "limits", .{ .object = limits_obj });
    try doc.put(allocator, "control_members", .{ .object = controls_obj });
    try doc.put(allocator, "alternatives_database", .{ .array = alt_arr });
    try doc.put(allocator, "linked_filesystem", .{ .object = linked_obj });
    try doc.put(allocator, "write_witnesses", .{ .array = write_witnesses });
    return .{ .object = doc };
}

fn writeIndent(out: *std.ArrayList(u8), allocator: std.mem.Allocator, depth: usize) !void {
    try out.appendNTimes(allocator, ' ', depth * 2);
}

fn writeJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try out.append(allocator, '"');
    for (s) |ch| {
        switch (ch) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            0x08 => try out.appendSlice(allocator, "\\b"),
            0x0c => try out.appendSlice(allocator, "\\f"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (ch < 0x20) {
                    var esc: [6]u8 = undefined;
                    _ = std.fmt.bufPrint(&esc, "\\u{x:0>4}", .{ch}) catch unreachable;
                    try out.appendSlice(allocator, &esc);
                } else {
                    try out.append(allocator, ch);
                }
            },
        }
    }
    try out.append(allocator, '"');
}

fn writeCanonicalValue(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: std.json.Value,
    depth: usize,
) !void {
    switch (value) {
        .null => try out.appendSlice(allocator, "null"),
        .bool => |b| try out.appendSlice(allocator, if (b) "true" else "false"),
        .integer => |n| {
            var buf: [32]u8 = undefined;
            const s = std.fmt.bufPrint(&buf, "{d}", .{n}) catch unreachable;
            try out.appendSlice(allocator, s);
        },
        .float, .number_string => return error.InvalidNumericConstant,
        .string => |s| try writeJsonString(out, allocator, s),
        .array => |arr| {
            if (arr.items.len == 0) {
                try out.appendSlice(allocator, "[]");
                return;
            }
            try out.appendSlice(allocator, "[\n");
            for (arr.items, 0..) |item, i| {
                try writeIndent(out, allocator, depth + 1);
                try writeCanonicalValue(out, allocator, item, depth + 1);
                if (i + 1 < arr.items.len) try out.append(allocator, ',');
                try out.append(allocator, '\n');
            }
            try writeIndent(out, allocator, depth);
            try out.append(allocator, ']');
        },
        .object => |obj| {
            if (obj.count() == 0) {
                try out.appendSlice(allocator, "{}");
                return;
            }
            var keys = try allocator.alloc([]const u8, obj.count());
            defer allocator.free(keys);
            for (obj.keys(), 0..) |k, idx| {
                keys[idx] = k;
            }
            std.mem.sort([]const u8, keys, {}, stringLessThan);
            try out.appendSlice(allocator, "{\n");
            for (keys, 0..) |k, i| {
                try writeIndent(out, allocator, depth + 1);
                try writeJsonString(out, allocator, k);
                try out.appendSlice(allocator, ": ");
                try writeCanonicalValue(out, allocator, obj.get(k).?, depth + 1);
                if (i + 1 < keys.len) try out.append(allocator, ',');
                try out.append(allocator, '\n');
            }
            try writeIndent(out, allocator, depth);
            try out.append(allocator, '}');
        },
    }
}

pub fn canonicalJson(allocator: std.mem.Allocator, document: std.json.Value) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try writeCanonicalValue(&out, allocator, document, 0);
    try out.append(allocator, '\n');
    return out.items;
}

pub fn writeCaptureOutput(
    allocator: std.mem.Allocator,
    output: []const u8,
    reference_root: []const u8,
    contents: []const u8,
    diag: *Diagnostic,
) !void {
    const output_path = try validateAbsolutePath(allocator, output, "output", false, diag);
    const reference_path = try validateAbsolutePath(allocator, reference_root, "reference root", false, diag);
    const parent_path = std.fs.path.dirname(output_path) orelse "/";
    const name = try validateComponent(allocator, std.fs.path.basename(output_path), diag);
    const parent_fd = try openAbsoluteDirectory(allocator, parent_path, "output parent", true, diag);
    defer closeFd(parent_fd);

    if (std.mem.eql(u8, output_path, reference_path) or
        (output_path.len > reference_path.len and
            std.mem.startsWith(u8, output_path, reference_path) and
            output_path[reference_path.len] == '/'))
    {
        diag.set(allocator, "output must be outside the reference root", .{});
        return error.CaptureFailed;
    }

    const flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    };
    const fd = openatFd(parent_fd, name, flags, 0o600) catch |err| {
        diag.set(allocator, "cannot create output {s}: {s}", .{ output_path, @errorName(err) });
        return error.CaptureFailed;
    };
    defer closeFd(fd);

    errdefer {
        var name_buf: [std.fs.max_path_bytes]u8 = undefined;
        @memcpy(name_buf[0..name.len], name);
        name_buf[name.len] = 0;
        const name_z: [*:0]const u8 = name_buf[0..name.len :0];
        _ = linux.unlinkat(parent_fd, name_z, 0);
    }

    var written: usize = 0;
    while (written < contents.len) {
        const rc = linux.write(fd, contents[written..].ptr, contents.len - written);
        if (linux.errno(rc) != .SUCCESS or rc == 0) {
            diag.set(allocator, "short write creating output {s}", .{output_path});
            return error.CaptureFailed;
        }
        written += rc;
    }
    _ = linux.fsync(fd);
    const st = fstatx(fd) catch |err| {
        diag.set(allocator, "output changed while writing: {s}: {s}", .{ output_path, @errorName(err) });
        return error.CaptureFailed;
    };
    if (!isRegMode(st.mode) or st.nlink != 1 or st.size != contents.len) {
        diag.set(allocator, "output changed while writing: {s}", .{output_path});
        return error.CaptureFailed;
    }
}

// ============================================================================
// Vendor-state reference derivation
// ============================================================================

const EXPECTED_CONTROL_MEMBERS: usize = 829;
const EXPECTED_ALTERNATIVES_RECORDS: usize = 14;
const EXPECTED_REQUESTED_PATHS: usize = 189;
const EXPECTED_LINKED_ENTRIES: usize = 190;
const EXPECTED_CONFIG_MEMBERS: usize = 7;
const EXPECTED_PATH_QUALIFICATIONS: usize = 422;
const EXPECTED_CONTROL_CONTENT_DIFFERENCES: usize = 275;

const EXPECTED_CONFIG_IDENTITIES = [_][]const u8{
    "chrony.config",
    "console-setup.config",
    "debconf.config",
    "iproute2.config",
    "keyboard-configuration.config",
    "locales.config",
    "tzdata.config",
};

const EXPECTED_ALTERNATIVES_GROUPS = [_][]const u8{
    "awk",
    "builtins.7.gz",
    "editor",
    "ex",
    "nc",
    "newt-palette",
    "pager",
    "rmt",
    "rview",
    "sudo",
    "vi",
    "view",
    "vtrgb",
    "which",
};

const EXPECTED_LINKED_DIFFERENCES = [_][]const u8{
    "usr/bin/less",
    "usr/bin/mawk",
    "usr/bin/more",
    "usr/bin/nc.openbsd",
    "usr/bin/sudo.ws",
    "usr/bin/vim.tiny",
    "usr/lib/cargo/bin/sudo",
    "usr/lib/cargo/bin/visudo",
    "usr/sbin/rmt-tar",
    "usr/sbin/visudo.ws",
};

const INDEX_KEYS = [_][]const u8{ "capture_schema", "index_version", "manifests", "source" };
const INDEX_MANIFEST_KEYS = [_][]const u8{
    "architecture",
    "artifact_id",
    "artifact_member",
    "artifact_name",
    "artifact_sha256",
    "artifact_size_bytes",
    "inventory",
    "job_id",
    "manifest_path",
    "manifest_sha256",
    "manifest_size_bytes",
};
const SOURCE_KEYS = [_][]const u8{
    "commit",
    "repository",
    "snapshot_suite",
    "snapshot_uri",
    "workflow",
    "workflow_path",
    "workflow_run_attempt",
    "workflow_run_id",
    "workflow_run_url",
};
const LIMIT_KEYS = [_][]const u8{
    "max_control_members",
    "max_alternatives_records",
    "max_metadata_file_bytes",
    "max_total_metadata_bytes",
    "max_referenced_paths",
    "max_linked_entries",
    "max_link_hops",
    "max_link_target_bytes",
    "max_linked_file_bytes",
    "max_total_linked_bytes",
};
const CONTROL_FACT_FIELDS = [_][]const u8{
    "mode",
    "uid",
    "gid",
    "size",
    "sha256",
    "referenced_paths",
};
const LINKED_FACT_FIELDS = [_][]const u8{ "mode", "uid", "gid", "size", "sha256", "target" };

const HandlingTriple = struct {
    handling: []const u8,
    rationale: []const u8,
    requirement: []const u8,
};

fn classificationHandling(classification: []const u8) HandlingTriple {
    if (std.mem.eql(u8, classification, "format")) return .{
        .handling = "supported-typed-state",
        .rationale = "The package database validates info/format as the typed format-1 marker.",
        .requirement = "none",
    };
    if (std.mem.eql(u8, classification, "control")) return .{
        .handling = "bounded-inert-retained-metadata",
        .rationale = "Installed *.control bytes are bounded opaque package metadata and are not interpreted.",
        .requirement = "none",
    };
    if (std.mem.eql(u8, classification, "ownership-list")) return .{
        .handling = "supported-typed-state",
        .rationale = "The package database parses bounded canonical ownership paths and builds the ownership index.",
        .requirement = "none",
    };
    if (std.mem.eql(u8, classification, "checksums")) return .{
        .handling = "supported-typed-state",
        .rationale = "The package database parses bounded lowercase MD5 records for logical payload paths.",
        .requirement = "none",
    };
    if (std.mem.eql(u8, classification, "conffiles")) return .{
        .handling = "supported-typed-state",
        .rationale = "The package database and native lifecycle model typed conffile declarations and digests.",
        .requirement = "none",
    };
    if (std.mem.eql(u8, classification, "triggers")) return .{
        .handling = "supported-typed-state",
        .rationale = "The package database and native lifecycle model the supported trigger declaration grammar.",
        .requirement = "none",
    };
    if (std.mem.eql(u8, classification, "maintainer-script")) return .{
        .handling = "supported-typed-state",
        .rationale = "Lifecycle scripts are typed by owner, kind, mode, size, and digest before bounded execution.",
        .requirement = "none",
    };
    if (std.mem.eql(u8, classification, "debconf-config")) return .{
        .handling = "reference-execution-required",
        .rationale = "The config script is bounded and preserved, but this manifest does not prove invocation or effects.",
        .requirement = "Observe reference frontend invocation, ordering, arguments, environment, outcome, and resulting state.",
    };
    if (std.mem.eql(u8, classification, "package-alternatives")) return .{
        .handling = "reference-execution-required",
        .rationale = "A package alternatives member has active dpkg semantics and may not be treated as inert metadata.",
        .requirement = "Capture exact package-member bytes and compare reference registration and mutation behavior.",
    };
    return .{
        .handling = "bounded-inert-retained-metadata",
        .rationale = "templates, shlibs, and symbols are typed by owner and kind and retained byte-for-byte without interpretation.",
        .requirement = "none",
    };
}

fn roleOrder(role: []const u8) u8 {
    if (std.mem.eql(u8, role, "path-alias")) return 0;
    if (std.mem.eql(u8, role, "front-link")) return 1;
    if (std.mem.eql(u8, role, "selector-link")) return 2;
    if (std.mem.eql(u8, role, "candidate-target")) return 3;
    return 4;
}

fn roleLessThan(_: void, a: []const u8, b: []const u8) bool {
    return roleOrder(a) < roleOrder(b);
}

fn readRegularBytes(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum: usize,
    label: []const u8,
    diag: *Diagnostic,
) ![]const u8 {
    const expected = statxAt(linux.AT.FDCWD, path, true) catch |err| {
        diag.set(allocator, "cannot stat {s}: {s}: {s}", .{ label, path, @errorName(err) });
        return error.DerivationFailed;
    };
    if (!isRegMode(expected.mode)) {
        diag.set(allocator, "{s} is not a regular file: {s}", .{ label, path });
        return error.DerivationFailed;
    }
    if (expected.size > maximum) {
        diag.set(allocator, "{s} exceeds byte limit: {s}", .{ label, path });
        return error.DerivationFailed;
    }
    const flags: linux.O = .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
    };
    const fd = openatFd(linux.AT.FDCWD, path, flags, 0) catch |err| {
        diag.set(allocator, "cannot open {s}: {s}: {s}", .{ label, path, @errorName(err) });
        return error.DerivationFailed;
    };
    defer closeFd(fd);

    const opened = fstatx(fd) catch |err| {
        diag.set(allocator, "cannot stat {s}: {s}: {s}", .{ label, path, @errorName(err) });
        return error.DerivationFailed;
    };
    if (!isRegMode(opened.mode) or !StatIdentity.eql(expected, opened)) {
        diag.set(allocator, "{s} changed before reading: {s}", .{ label, path });
        return error.DerivationFailed;
    }

    var out: std.ArrayList(u8) = .empty;
    var chunk_buf: [64 * 1024]u8 = undefined;
    while (out.items.len <= maximum) {
        const max_read = @min(chunk_buf.len, maximum + 1 - out.items.len);
        const rc = linux.read(fd, &chunk_buf, max_read);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |err| {
                diag.set(allocator, "cannot read {s}: {s}: {s}", .{ label, path, @tagName(err) });
                return error.DerivationFailed;
            },
        }
        if (rc == 0) break;
        try out.appendSlice(allocator, chunk_buf[0..rc]);
    }
    if (out.items.len > maximum) {
        diag.set(allocator, "{s} exceeds byte limit: {s}", .{ label, path });
        return error.DerivationFailed;
    }
    const finished = fstatx(fd) catch |err| {
        diag.set(allocator, "cannot stat {s}: {s}: {s}", .{ label, path, @errorName(err) });
        return error.DerivationFailed;
    };
    if (out.items.len != @as(usize, @intCast(opened.size)) or !StatIdentity.eql(opened, finished)) {
        diag.set(allocator, "{s} changed while reading: {s}", .{ label, path });
        return error.DerivationFailed;
    }
    return out.items;
}

fn containsNonstandardNumericConstant(raw: []const u8) bool {
    var in_string = false;
    var escaped = false;
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        const ch = raw[i];
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }
        if (ch == '"') {
            in_string = true;
            continue;
        }
        if (std.mem.startsWith(u8, raw[i..], "NaN") or
            std.mem.startsWith(u8, raw[i..], "Infinity") or
            std.mem.startsWith(u8, raw[i..], "-Infinity"))
        {
            return true;
        }
    }
    return false;
}

fn readDocument(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum: usize,
    label: []const u8,
    diag: *Diagnostic,
) !struct { raw: []const u8, doc: std.json.ObjectMap } {
    const raw = try readRegularBytes(allocator, path, maximum, label, diag);
    if (!std.unicode.utf8ValidateSlice(raw)) {
        diag.set(allocator, "{s} is not canonical UTF-8 JSON: {s}", .{ label, path });
        return error.DerivationFailed;
    }
    if (containsNonstandardNumericConstant(raw)) {
        diag.set(allocator, "non-standard JSON numeric constant", .{});
        return error.DerivationFailed;
    }
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, allocator, raw, .{
        .duplicate_field_behavior = .@"error",
    }) catch |err| {
        if (err == error.DuplicateField) {
            diag.set(allocator, "duplicate JSON object field", .{});
        } else {
            diag.set(allocator, "{s} is not canonical UTF-8 JSON: {s}", .{ label, path });
        }
        return error.DerivationFailed;
    };
    if (parsed != .object) {
        diag.set(allocator, "{s} must be a JSON object: {s}", .{ label, path });
        return error.DerivationFailed;
    }
    const encoded = canonicalJson(allocator, parsed) catch {
        diag.set(allocator, "{s} is not canonical UTF-8 JSON: {s}", .{ label, path });
        return error.DerivationFailed;
    };
    if (!std.mem.eql(u8, encoded, raw)) {
        diag.set(allocator, "{s} is not canonical JSON: {s}", .{ label, path });
        return error.DerivationFailed;
    }
    return .{ .raw = raw, .doc = parsed.object };
}

fn requireKeys(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    expected: []const []const u8,
    label: []const u8,
    diag: *Diagnostic,
) !void {
    if (obj.count() != expected.len) {
        diag.set(allocator, "{s} fields differ", .{label});
        return error.DerivationFailed;
    }
    for (expected) |k| {
        if (!obj.contains(k)) {
            diag.set(allocator, "{s} fields differ: missing {s}", .{ label, k });
            return error.DerivationFailed;
        }
    }
}

fn derivePositiveInteger(
    allocator: std.mem.Allocator,
    val: ?std.json.Value,
    label: []const u8,
    diag: *Diagnostic,
) !i64 {
    const v = val orelse {
        diag.set(allocator, "{s} must be a positive schema-safe integer", .{label});
        return error.DerivationFailed;
    };
    if (v != .integer or v.integer < 1 or v.integer > MAX_JSON_INTEGER) {
        diag.set(allocator, "{s} must be a positive schema-safe integer", .{label});
        return error.DerivationFailed;
    }
    return v.integer;
}

fn deriveCount(
    allocator: std.mem.Allocator,
    val: ?std.json.Value,
    label: []const u8,
    diag: *Diagnostic,
) !i64 {
    const v = val orelse {
        diag.set(allocator, "{s} must be a schema-safe count", .{label});
        return error.DerivationFailed;
    };
    if (v != .integer or v.integer < 0 or v.integer > MAX_JSON_INTEGER) {
        diag.set(allocator, "{s} must be a schema-safe count", .{label});
        return error.DerivationFailed;
    }
    return v.integer;
}

fn deriveText(
    allocator: std.mem.Allocator,
    val: ?std.json.Value,
    label: []const u8,
    diag: *Diagnostic,
) ![]const u8 {
    const v = val orelse {
        diag.set(allocator, "{s} must be nonempty text", .{label});
        return error.DerivationFailed;
    };
    if (v != .string or v.string.len == 0) {
        diag.set(allocator, "{s} must be nonempty text", .{label});
        return error.DerivationFailed;
    }
    if (!std.unicode.utf8ValidateSlice(v.string)) {
        diag.set(allocator, "{s} must be UTF-8", .{label});
        return error.DerivationFailed;
    }
    return v.string;
}

fn deriveBoundedText(
    allocator: std.mem.Allocator,
    val: ?std.json.Value,
    label: []const u8,
    diag: *Diagnostic,
) ![]const u8 {
    const text = try deriveText(allocator, val, label, diag);
    if (text.len > MAX_TEXT_BYTES) {
        diag.set(allocator, "{s} exceeds text byte limit", .{label});
        return error.DerivationFailed;
    }
    for (text) |ch| {
        if (ch < 32 or ch == 127) {
            diag.set(allocator, "{s} contains control characters", .{label});
            return error.DerivationFailed;
        }
    }
    return text;
}

fn isLowerHexLen(text: []const u8, expected_len: usize) bool {
    if (text.len != expected_len) return false;
    for (text) |ch| {
        if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'))) return false;
    }
    return true;
}

fn deriveHexToken(
    allocator: std.mem.Allocator,
    val: ?std.json.Value,
    label: []const u8,
    diag: *Diagnostic,
) ![]const u8 {
    const text = try deriveText(allocator, val, label, diag);
    if (!isLowerHexLen(text, HEX_DIGEST_BYTES)) {
        diag.set(allocator, "{s} must be a lowercase SHA-256 digest", .{label});
        return error.DerivationFailed;
    }
    return text;
}

fn deriveMode(
    allocator: std.mem.Allocator,
    val: ?std.json.Value,
    label: []const u8,
    diag: *Diagnostic,
) ![]const u8 {
    const text = try deriveText(allocator, val, label, diag);
    if (text.len != 4) {
        diag.set(allocator, "{s} is a malformed mode", .{label});
        return error.DerivationFailed;
    }
    for (text) |ch| {
        if (ch < '0' or ch > '7') {
            diag.set(allocator, "{s} is a malformed mode", .{label});
            return error.DerivationFailed;
        }
    }
    return text;
}

fn deriveComponent(
    allocator: std.mem.Allocator,
    value: []const u8,
    label: []const u8,
    diag: *Diagnostic,
) ![]const u8 {
    if (value.len == 0 or
        std.mem.eql(u8, value, ".") or
        std.mem.eql(u8, value, "..") or
        std.mem.indexOfScalar(u8, value, '/') != null or
        std.mem.indexOfScalar(u8, value, 0) != null)
    {
        diag.set(allocator, "{s} contains an unsafe path component", .{label});
        return error.DerivationFailed;
    }
    for (value) |ch| {
        if (ch < 32 or ch == 127) {
            diag.set(allocator, "{s} contains an unsafe path component", .{label});
            return error.DerivationFailed;
        }
    }
    return value;
}

fn deriveRelativePath(
    allocator: std.mem.Allocator,
    val: ?std.json.Value,
    label: []const u8,
    diag: *Diagnostic,
) ![]const u8 {
    const text = try deriveText(allocator, val, label, diag);
    if (text.len > MAX_DOCUMENT_PATH_BYTES) {
        diag.set(allocator, "{s} exceeds path byte limit", .{label});
        return error.DerivationFailed;
    }
    if (std.mem.startsWith(u8, text, "/") or
        std.mem.endsWith(u8, text, "/") or
        std.mem.indexOf(u8, text, "//") != null)
    {
        diag.set(allocator, "{s} is not a bounded relative path", .{label});
        return error.DerivationFailed;
    }
    var it = std.mem.splitScalar(u8, text, '/');
    while (it.next()) |comp| {
        _ = try deriveComponent(allocator, comp, label, diag);
    }
    return text;
}

fn derivePublicReferencePath(
    allocator: std.mem.Allocator,
    val: ?std.json.Value,
    label: []const u8,
    diag: *Diagnostic,
) ![]const u8 {
    const path = try deriveRelativePath(allocator, val, label, diag);
    for (SENSITIVE_PATHS) |denied| {
        if (std.mem.eql(u8, path, denied) or
            (path.len > denied.len and std.mem.startsWith(u8, path, denied) and path[denied.len] == '/'))
        {
            diag.set(allocator, "{s} enters excluded sensitive state", .{label});
            return error.DerivationFailed;
        }
    }
    const slash = std.mem.indexOfScalar(u8, path, '/') orelse path.len;
    const top_level = path[0..slash];
    if (!sliceContains(&PUBLIC_REFERENCE_ROOTS, top_level) and !std.mem.eql(u8, top_level, "etc")) {
        diag.set(allocator, "{s} leaves the public reference roots", .{label});
        return error.DerivationFailed;
    }
    return path;
}

fn deriveTargetPath(
    allocator: std.mem.Allocator,
    link_path: []const u8,
    target_val: ?std.json.Value,
    label: []const u8,
    diag: *Diagnostic,
) ![]const u8 {
    const text = try deriveText(allocator, target_val, label, diag);
    if (std.mem.indexOfScalar(u8, text, 0) != null or
        std.mem.indexOf(u8, text, "//") != null or
        text.len > MAX_DOCUMENT_PATH_BYTES)
    {
        diag.set(allocator, "{s} is an unsafe symlink target", .{label});
        return error.DerivationFailed;
    }
    for (text) |ch| {
        if (ch < 32 or ch == 127) {
            diag.set(allocator, "{s} is an unsafe symlink target", .{label});
            return error.DerivationFailed;
        }
    }
    var result: std.ArrayList([]const u8) = .empty;
    if (!std.mem.startsWith(u8, text, "/")) {
        var link_it = std.mem.splitScalar(u8, link_path, '/');
        while (link_it.next()) |part| {
            if (link_it.peek() != null) {
                try result.append(allocator, part);
            }
        }
    }
    var it = std.mem.splitScalar(u8, text, '/');
    while (it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            if (result.items.len == 0) {
                diag.set(allocator, "{s} escapes the reference root", .{label});
                return error.DerivationFailed;
            }
            _ = result.pop();
            continue;
        }
        try result.append(allocator, try deriveComponent(allocator, component, label, diag));
    }
    if (result.items.len == 0) {
        diag.set(allocator, "{s} resolves to the reference root", .{label});
        return error.DerivationFailed;
    }
    const joined = try joinSlash(allocator, result.items);
    return deriveRelativePath(allocator, .{ .string = joined }, label, diag);
}

fn derivePublicHttpsUri(
    allocator: std.mem.Allocator,
    val: ?std.json.Value,
    label: []const u8,
    diag: *Diagnostic,
) ![]const u8 {
    const text = try deriveBoundedText(allocator, val, label, diag);
    if (!std.mem.startsWith(u8, text, "https://")) {
        diag.set(allocator, "{s} must be a public HTTPS URI", .{label});
        return error.DerivationFailed;
    }
    for (text) |ch| {
        if (isAsciiWhitespace(ch) or ch == '?' or ch == '#') {
            diag.set(allocator, "{s} must be a public HTTPS URI", .{label});
            return error.DerivationFailed;
        }
    }
    const after_scheme = text["https://".len..];
    const slash = std.mem.indexOfScalar(u8, after_scheme, '/') orelse after_scheme.len;
    const netloc = after_scheme[0..slash];
    if (netloc.len == 0 or std.mem.indexOfScalar(u8, netloc, '@') != null) {
        diag.set(allocator, "{s} must be a public HTTPS URI", .{label});
        return error.DerivationFailed;
    }
    return text;
}

fn deriveSortedUniquePublicPaths(
    allocator: std.mem.Allocator,
    val: ?std.json.Value,
    label: []const u8,
    diag: *Diagnostic,
) ![][]const u8 {
    const v = val orelse {
        diag.set(allocator, "{s} must be an array", .{label});
        return error.DerivationFailed;
    };
    if (v != .array) {
        diag.set(allocator, "{s} must be an array", .{label});
        return error.DerivationFailed;
    }
    var checked: std.ArrayList([]const u8) = .empty;
    for (v.array.items, 0..) |item, index| {
        const item_label = try std.fmt.allocPrint(allocator, "{s}[{d}]", .{ label, index });
        const path = try derivePublicReferencePath(allocator, item, item_label, diag);
        if (checked.items.len > 0) {
            const prev = checked.items[checked.items.len - 1];
            if (std.mem.eql(u8, prev, path)) {
                diag.set(allocator, "{s} contains duplicates", .{label});
                return error.DerivationFailed;
            }
            if (!std.mem.lessThan(u8, prev, path)) {
                diag.set(allocator, "{s} must be bytewise sorted", .{label});
                return error.DerivationFailed;
            }
        }
        try checked.append(allocator, path);
    }
    return checked.items;
}

fn validateFileMetadata(
    allocator: std.mem.Allocator,
    item: std.json.ObjectMap,
    label: []const u8,
    diag: *Diagnostic,
) !void {
    _ = try deriveRelativePath(allocator, item.get("path"), try std.fmt.allocPrint(allocator, "{s}.path", .{label}), diag);
    _ = try deriveMode(allocator, item.get("mode"), try std.fmt.allocPrint(allocator, "{s}.mode", .{label}), diag);
    for ([_][]const u8{ "uid", "gid" }) |field| {
        const fv = item.get(field) orelse {
            diag.set(allocator, "{s}.{s} is outside the schema", .{ label, field });
            return error.DerivationFailed;
        };
        if (fv != .integer or fv.integer < 0 or fv.integer > 4_294_967_295) {
            diag.set(allocator, "{s}.{s} is outside the schema", .{ label, field });
            return error.DerivationFailed;
        }
    }
}

fn validateMetadataFile(
    allocator: std.mem.Allocator,
    item_val: std.json.Value,
    label: []const u8,
    limits: Limits,
    control: bool,
    diag: *Diagnostic,
) !void {
    if (item_val != .object) {
        diag.set(allocator, "{s} must be an object", .{label});
        return error.DerivationFailed;
    }
    const item = item_val.object;
    const control_keys = [_][]const u8{ "path", "mode", "uid", "gid", "size", "sha256", "referenced_paths", "classification" };
    const alt_keys = [_][]const u8{ "path", "mode", "uid", "gid", "size", "sha256", "referenced_paths" };
    try requireKeys(allocator, item, if (control) &control_keys else &alt_keys, label, diag);
    try validateFileMetadata(allocator, item, label, diag);
    const size = try deriveCount(allocator, item.get("size"), try std.fmt.allocPrint(allocator, "{s}.size", .{label}), diag);
    if (size > limits.max_metadata_file_bytes) {
        diag.set(allocator, "{s} exceeds metadata file byte limit", .{label});
        return error.DerivationFailed;
    }
    _ = try deriveHexToken(allocator, item.get("sha256"), try std.fmt.allocPrint(allocator, "{s}.sha256", .{label}), diag);
    _ = try deriveSortedUniquePublicPaths(allocator, item.get("referenced_paths"), try std.fmt.allocPrint(allocator, "{s}.referenced_paths", .{label}), diag);
    if (control) {
        const classification = try deriveText(allocator, item.get("classification"), label, diag);
        if (!sliceContains(&CLASSIFICATIONS, classification)) {
            diag.set(allocator, "{s} has an unknown classification", .{label});
            return error.DerivationFailed;
        }
        const path = item.get("path").?.string;
        const base = std.fs.path.basename(path);
        const observed = classifyControlMember(base);
        if (!std.mem.eql(u8, classification, observed)) {
            diag.set(allocator, "{s} classification mismatch: {s} != {s}", .{ label, classification, observed });
            return error.DerivationFailed;
        }
    }
}

fn validateLinkedEntry(
    allocator: std.mem.Allocator,
    item_val: std.json.Value,
    label: []const u8,
    limits: Limits,
    diag: *Diagnostic,
) !void {
    if (item_val != .object) {
        diag.set(allocator, "{s} must be an object", .{label});
        return error.DerivationFailed;
    }
    const item = item_val.object;
    const path = try derivePublicReferencePath(allocator, item.get("path"), try std.fmt.allocPrint(allocator, "{s}.path", .{label}), diag);
    const kind_val = item.get("kind") orelse {
        diag.set(allocator, "{s} has unsupported linked entry kind", .{label});
        return error.DerivationFailed;
    };
    if (kind_val != .string) {
        diag.set(allocator, "{s} has unsupported linked entry kind", .{label});
        return error.DerivationFailed;
    }
    const kind = kind_val.string;
    if (std.mem.eql(u8, kind, "regular")) {
        const reg_keys = [_][]const u8{ "path", "kind", "mode", "uid", "gid", "size", "sha256" };
        try requireKeys(allocator, item, &reg_keys, label, diag);
        try validateFileMetadata(allocator, item, label, diag);
        const size = try deriveCount(allocator, item.get("size"), try std.fmt.allocPrint(allocator, "{s}.size", .{label}), diag);
        if (size > limits.max_linked_file_bytes) {
            diag.set(allocator, "{s} exceeds linked file byte limit", .{label});
            return error.DerivationFailed;
        }
        _ = try deriveHexToken(allocator, item.get("sha256"), try std.fmt.allocPrint(allocator, "{s}.sha256", .{label}), diag);
        return;
    }
    if (std.mem.eql(u8, kind, "symlink")) {
        const sym_keys = [_][]const u8{ "path", "kind", "mode", "uid", "gid", "target" };
        try requireKeys(allocator, item, &sym_keys, label, diag);
        try validateFileMetadata(allocator, item, label, diag);
        const target = try deriveText(allocator, item.get("target"), try std.fmt.allocPrint(allocator, "{s}.target", .{label}), diag);
        if (@as(i64, @intCast(target.len)) > limits.max_link_target_bytes) {
            diag.set(allocator, "{s} symlink target exceeds byte limit", .{label});
            return error.DerivationFailed;
        }
        const resolved = try deriveTargetPath(allocator, path, item.get("target"), try std.fmt.allocPrint(allocator, "{s}.target", .{label}), diag);
        _ = try derivePublicReferencePath(allocator, .{ .string = resolved }, try std.fmt.allocPrint(allocator, "{s}.resolved_target", .{label}), diag);
        return;
    }
    diag.set(allocator, "{s} has unsupported linked entry kind: {s}", .{ label, kind });
    return error.DerivationFailed;
}

fn validateWriteWitness(
    allocator: std.mem.Allocator,
    item_val: std.json.Value,
    label: []const u8,
    limits: Limits,
    diag: *Diagnostic,
) !void {
    if (item_val != .object) {
        diag.set(allocator, "{s} must be an object", .{label});
        return error.DerivationFailed;
    }
    const item = item_val.object;
    const path = try deriveText(allocator, item.get("path"), label, diag);
    if (!sliceContains(&WRITE_WITNESS_PATHS, path)) {
        diag.set(allocator, "{s}.path is not an admitted write witness", .{label});
        return error.DerivationFailed;
    }
    const kind = try deriveText(allocator, item.get("kind"), label, diag);
    if (std.mem.eql(u8, kind, "absent")) {
        const keys = [_][]const u8{ "path", "kind" };
        try requireKeys(allocator, item, &keys, label, diag);
        return;
    }
    if (std.mem.eql(u8, kind, "regular")) {
        const keys = [_][]const u8{ "path", "kind", "mode", "uid", "gid", "size", "sha256" };
        try requireKeys(allocator, item, &keys, label, diag);
        try validateFileMetadata(allocator, item, label, diag);
        const size = try deriveCount(allocator, item.get("size"), label, diag);
        if (size > limits.max_linked_file_bytes) {
            diag.set(allocator, "{s} exceeds write-witness file byte limit", .{label});
            return error.DerivationFailed;
        }
        _ = try deriveHexToken(allocator, item.get("sha256"), label, diag);
        return;
    }
    const other_kinds = [_][]const u8{ "directory", "symlink", "character-device", "block-device", "fifo", "socket", "unknown" };
    if (sliceContains(&other_kinds, kind)) {
        const keys_with_target = [_][]const u8{ "path", "kind", "mode", "uid", "gid", "target" };
        const keys_no_target = [_][]const u8{ "path", "kind", "mode", "uid", "gid" };
        try requireKeys(allocator, item, if (item.contains("target")) &keys_with_target else &keys_no_target, label, diag);
        try validateFileMetadata(allocator, item, label, diag);
        if (item.get("target")) |tval| {
            const target = try deriveText(allocator, tval, label, diag);
            if (@as(i64, @intCast(target.len)) > limits.max_link_target_bytes) {
                diag.set(allocator, "{s} symlink target exceeds byte limit", .{label});
                return error.DerivationFailed;
            }
        }
        return;
    }
    diag.set(allocator, "{s} has unsupported write-witness kind: {s}", .{ label, kind });
    return error.DerivationFailed;
}

fn expectedClassificationCount(cls: []const u8) i64 {
    if (std.mem.eql(u8, cls, "checksums")) return 177;
    if (std.mem.eql(u8, cls, "conffiles")) return 39;
    if (std.mem.eql(u8, cls, "control")) return 0;
    if (std.mem.eql(u8, cls, "debconf-config")) return 7;
    if (std.mem.eql(u8, cls, "format")) return 1;
    if (std.mem.eql(u8, cls, "maintainer-script")) return 186;
    if (std.mem.eql(u8, cls, "ownership-list")) return 177;
    if (std.mem.eql(u8, cls, "package-alternatives")) return 0;
    if (std.mem.eql(u8, cls, "retained-metadata")) return 158;
    if (std.mem.eql(u8, cls, "triggers")) return 84;
    return 0;
}

fn expectedControlDiffCount(cls: []const u8) i64 {
    if (std.mem.eql(u8, cls, "checksums")) return 140;
    if (std.mem.eql(u8, cls, "conffiles")) return 1;
    if (std.mem.eql(u8, cls, "maintainer-script")) return 28;
    if (std.mem.eql(u8, cls, "ownership-list")) return 94;
    if (std.mem.eql(u8, cls, "retained-metadata")) return 9;
    if (std.mem.eql(u8, cls, "triggers")) return 3;
    return 0;
}

fn computeInventory(allocator: std.mem.Allocator, document: std.json.ObjectMap) !std.json.Value {
    const controls = document.get("control_members").?.object.get("entries").?.array.items;
    const alternatives = document.get("alternatives_database").?.array.items;
    const linked = document.get("linked_filesystem").?.object.get("entries").?.array.items;
    const requested = document.get("linked_filesystem").?.object.get("requested_paths").?.array.items;

    var alt_bytes: i64 = 0;
    for (alternatives) |item| alt_bytes += item.object.get("size").?.integer;
    var ctrl_bytes: i64 = 0;
    for (controls) |item| ctrl_bytes += item.object.get("size").?.integer;

    var regular_count: i64 = 0;
    var symlink_count: i64 = 0;
    var linked_reg_bytes: i64 = 0;
    for (linked) |item| {
        const k = item.object.get("kind").?.string;
        if (std.mem.eql(u8, k, "regular")) {
            regular_count += 1;
            linked_reg_bytes += item.object.get("size").?.integer;
        } else if (std.mem.eql(u8, k, "symlink")) {
            symlink_count += 1;
        }
    }
    var kind_counts: std.json.ObjectMap = .empty;
    if (regular_count > 0) try kind_counts.put(allocator, "regular", .{ .integer = regular_count });
    if (symlink_count > 0) try kind_counts.put(allocator, "symlink", .{ .integer = symlink_count });

    var inv: std.json.ObjectMap = .empty;
    try inv.put(allocator, "alternatives_record_bytes", .{ .integer = alt_bytes });
    try inv.put(allocator, "alternatives_record_count", .{ .integer = @intCast(alternatives.len) });
    try inv.put(allocator, "classification_counts", document.get("control_members").?.object.get("classification_counts").?);
    try inv.put(allocator, "control_member_bytes", .{ .integer = ctrl_bytes });
    try inv.put(allocator, "control_member_count", .{ .integer = @intCast(controls.len) });
    try inv.put(allocator, "linked_entry_count", .{ .integer = @intCast(linked.len) });
    try inv.put(allocator, "linked_entry_kind_counts", .{ .object = kind_counts });
    try inv.put(allocator, "linked_regular_bytes", .{ .integer = linked_reg_bytes });
    try inv.put(allocator, "requested_path_count", .{ .integer = @intCast(requested.len) });
    return .{ .object = inv };
}

fn validateManifest(
    allocator: std.mem.Allocator,
    document: std.json.ObjectMap,
    architecture: []const u8,
    diag: *Diagnostic,
) !void {
    const keys_with_ww = [_][]const u8{
        "schema",
        "version",
        "architecture",
        "limits",
        "control_members",
        "alternatives_database",
        "linked_filesystem",
        "write_witnesses",
    };
    const keys_no_ww = [_][]const u8{
        "schema",
        "version",
        "architecture",
        "limits",
        "control_members",
        "alternatives_database",
        "linked_filesystem",
    };
    try requireKeys(
        allocator,
        document,
        if (document.contains("write_witnesses")) &keys_with_ww else &keys_no_ww,
        try std.fmt.allocPrint(allocator, "{s} manifest", .{architecture}),
        diag,
    );
    const schema = try deriveText(allocator, document.get("schema"), architecture, diag);
    const version = try derivePositiveInteger(allocator, document.get("version"), architecture, diag);
    if (!std.mem.eql(u8, schema, CAPTURE_SCHEMA) or version != 1) {
        diag.set(allocator, "{s} manifest capture schema mismatch", .{architecture});
        return error.DerivationFailed;
    }
    const arch_str = try deriveText(allocator, document.get("architecture"), architecture, diag);
    if (!std.mem.eql(u8, arch_str, architecture)) {
        diag.set(allocator, "{s} manifest architecture mismatch", .{architecture});
        return error.DerivationFailed;
    }
    const limits_val = document.get("limits").?;
    if (limits_val != .object) {
        diag.set(allocator, "{s} limits must be an object", .{architecture});
        return error.DerivationFailed;
    }
    try requireKeys(allocator, limits_val.object, &LIMIT_KEYS, try std.fmt.allocPrint(allocator, "{s} limits", .{architecture}), diag);
    const expected_limits = Limits{};
    inline for (LIMIT_KEYS) |field_name| {
        const got = try derivePositiveInteger(
            allocator,
            limits_val.object.get(field_name),
            try std.fmt.allocPrint(allocator, "{s}.limits.{s}", .{ architecture, field_name }),
            diag,
        );
        if (got != @field(expected_limits, field_name)) {
            diag.set(allocator, "{s} capture limits changed", .{architecture});
            return error.DerivationFailed;
        }
    }

    const controls_wrapper = document.get("control_members").?;
    if (controls_wrapper != .object) {
        diag.set(allocator, "{s} control_members must be an object", .{architecture});
        return error.DerivationFailed;
    }
    const cw_keys = [_][]const u8{ "classification_counts", "entries" };
    try requireKeys(allocator, controls_wrapper.object, &cw_keys, try std.fmt.allocPrint(allocator, "{s} control_members", .{architecture}), diag);
    const declared_counts = controls_wrapper.object.get("classification_counts").?;
    if (declared_counts != .object) {
        diag.set(allocator, "{s} classification_counts must be an object", .{architecture});
        return error.DerivationFailed;
    }
    try requireKeys(allocator, declared_counts.object, &CLASSIFICATIONS, try std.fmt.allocPrint(allocator, "{s} classification_counts", .{architecture}), diag);
    for (CLASSIFICATIONS) |cls| {
        _ = try deriveCount(allocator, declared_counts.object.get(cls), cls, diag);
    }

    const controls_val = controls_wrapper.object.get("entries").?;
    const alternatives_val = document.get("alternatives_database").?;
    const linked_wrapper = document.get("linked_filesystem").?;
    if (controls_val != .array or alternatives_val != .array) {
        diag.set(allocator, "{s} metadata entries must be arrays", .{architecture});
        return error.DerivationFailed;
    }
    if (linked_wrapper != .object) {
        diag.set(allocator, "{s} linked_filesystem must be an object", .{architecture});
        return error.DerivationFailed;
    }
    const lw_keys = [_][]const u8{ "requested_paths", "entries" };
    try requireKeys(allocator, linked_wrapper.object, &lw_keys, try std.fmt.allocPrint(allocator, "{s} linked_filesystem", .{architecture}), diag);
    const linked_val = linked_wrapper.object.get("entries").?;
    if (linked_val != .array) {
        diag.set(allocator, "{s} linked entries must be an array", .{architecture});
        return error.DerivationFailed;
    }

    const controls = controls_val.array.items;
    const alternatives = alternatives_val.array.items;
    const linked = linked_val.array.items;

    for (controls, 0..) |item, index| {
        const lbl = try std.fmt.allocPrint(allocator, "{s}.control[{d}]", .{ architecture, index });
        try validateMetadataFile(allocator, item, lbl, expected_limits, true, diag);
        if (!std.mem.startsWith(u8, item.object.get("path").?.string, "var/lib/dpkg/info/")) {
            diag.set(allocator, "{s} control path leaves dpkg info", .{architecture});
            return error.DerivationFailed;
        }
    }
    for (alternatives, 0..) |item, index| {
        const lbl = try std.fmt.allocPrint(allocator, "{s}.alternatives[{d}]", .{ architecture, index });
        try validateMetadataFile(allocator, item, lbl, expected_limits, false, diag);
        if (!std.mem.startsWith(u8, item.object.get("path").?.string, "var/lib/dpkg/alternatives/")) {
            diag.set(allocator, "{s} alternatives path leaves alternatives database", .{architecture});
            return error.DerivationFailed;
        }
    }
    const requested = try deriveSortedUniquePublicPaths(
        allocator,
        linked_wrapper.object.get("requested_paths"),
        try std.fmt.allocPrint(allocator, "{s}.requested_paths", .{architecture}),
        diag,
    );
    for (linked, 0..) |item, index| {
        const lbl = try std.fmt.allocPrint(allocator, "{s}.linked[{d}]", .{ architecture, index });
        try validateLinkedEntry(allocator, item, lbl, expected_limits, diag);
    }
    if (document.get("write_witnesses")) |ww_val| {
        if (ww_val != .array) {
            diag.set(allocator, "{s} write_witnesses must be an array", .{architecture});
            return error.DerivationFailed;
        }
        for (ww_val.array.items, 0..) |item, index| {
            const lbl = try std.fmt.allocPrint(allocator, "{s}.write_witnesses[{d}]", .{ architecture, index });
            try validateWriteWitness(allocator, item, lbl, expected_limits, diag);
        }
    }

    const arrays_to_check = [_]struct { label: []const u8, items: []const std.json.Value }{
        .{ .label = "control", .items = controls },
        .{ .label = "alternatives", .items = alternatives },
        .{ .label = "linked", .items = linked },
    };
    for (arrays_to_check) |entry| {
        for (entry.items, 0..) |item, idx| {
            if (idx > 0) {
                const prev = entry.items[idx - 1].object.get("path").?.string;
                const cur = item.object.get("path").?.string;
                if (std.mem.eql(u8, prev, cur)) {
                    diag.set(allocator, "{s} {s} paths contain duplicates", .{ architecture, entry.label });
                    return error.DerivationFailed;
                }
                if (!std.mem.lessThan(u8, prev, cur)) {
                    diag.set(allocator, "{s} {s} paths are not sorted", .{ architecture, entry.label });
                    return error.DerivationFailed;
                }
            }
        }
    }

    var observed_counts: std.StringHashMapUnmanaged(i64) = .empty;
    for (CLASSIFICATIONS) |cls| try observed_counts.put(allocator, cls, 0);
    for (controls) |item| {
        const cls = item.object.get("classification").?.string;
        try observed_counts.put(allocator, cls, observed_counts.get(cls).? + 1);
    }
    for (CLASSIFICATIONS) |cls| {
        const obs = observed_counts.get(cls).?;
        const decl = declared_counts.object.get(cls).?.integer;
        if (obs != decl) {
            diag.set(allocator, "{s} classification counts do not match entries", .{architecture});
            return error.DerivationFailed;
        }
    }
    if (observed_counts.get("unclassified").? != 0) {
        diag.set(allocator, "{s} has an unclassified control member", .{architecture});
        return error.DerivationFailed;
    }
    if (observed_counts.get("package-alternatives").? != 0) {
        diag.set(allocator, "{s} package alternatives members require a new reference boundary", .{architecture});
        return error.DerivationFailed;
    }
    for (CLASSIFICATIONS) |cls| {
        if (observed_counts.get(cls).? != expectedClassificationCount(cls)) {
            diag.set(allocator, "{s} classification boundary changed", .{architecture});
            return error.DerivationFailed;
        }
    }
    if (controls.len != EXPECTED_CONTROL_MEMBERS) {
        diag.set(allocator, "{s} control-member boundary changed", .{architecture});
        return error.DerivationFailed;
    }
    if (alternatives.len != EXPECTED_ALTERNATIVES_RECORDS) {
        diag.set(allocator, "{s} alternatives-record boundary changed", .{architecture});
        return error.DerivationFailed;
    }
    if (requested.len != EXPECTED_REQUESTED_PATHS) {
        diag.set(allocator, "{s} requested-path boundary changed", .{architecture});
        return error.DerivationFailed;
    }
    if (linked.len != EXPECTED_LINKED_ENTRIES) {
        diag.set(allocator, "{s} linked-entry boundary changed", .{architecture});
        return error.DerivationFailed;
    }
    if (observed_counts.get("debconf-config").? != EXPECTED_CONFIG_MEMBERS) {
        diag.set(allocator, "{s} config-member boundary changed", .{architecture});
        return error.DerivationFailed;
    }
}

fn isValidPackageName(name: []const u8) bool {
    if (name.len == 0) return false;
    const first = name[0];
    if (!((first >= 'a' and first <= 'z') or (first >= '0' and first <= '9'))) return false;
    for (name[1..]) |ch| {
        if (!((ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '+' or ch == '.' or ch == '-')) return false;
    }
    return true;
}

fn isValidArchName(name: []const u8) bool {
    if (name.len == 0) return false;
    const first = name[0];
    if (!((first >= 'a' and first <= 'z') or (first >= '0' and first <= '9'))) return false;
    for (name[1..]) |ch| {
        if (!((ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '-')) return false;
    }
    return true;
}

fn isValidRepoSlug(repo: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, repo, '/') orelse return false;
    if (slash == 0 or slash + 1 >= repo.len) return false;
    if (std.mem.indexOfScalar(u8, repo[slash + 1 ..], '/') != null) return false;
    for ([_][]const u8{ repo[0..slash], repo[slash + 1 ..] }) |part| {
        for (part) |ch| {
            if (!((ch >= 'A' and ch <= 'Z') or (ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '_' or ch == '.' or ch == '-')) return false;
        }
    }
    return true;
}

fn controlIdentity(
    allocator: std.mem.Allocator,
    item: std.json.ObjectMap,
    architecture: []const u8,
    diag: *Diagnostic,
) !struct { id_str: []const u8, owner: std.json.Value } {
    const path = item.get("path").?.string;
    const name = std.fs.path.basename(path);
    if (std.mem.eql(u8, name, "format")) {
        var owner: std.json.ObjectMap = .empty;
        try owner.put(allocator, "kind", .{ .string = "database-global" });
        return .{ .id_str = "format", .owner = .{ .object = owner } };
    }
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse {
        diag.set(allocator, "{s} control member has invalid package: {s}", .{ architecture, name });
        return error.DerivationFailed;
    };
    const stem = name[0..dot];
    const suffix = name[dot + 1 ..];
    var package = stem;
    var qualified = false;
    if (std.mem.lastIndexOfScalar(u8, stem, ':')) |colon| {
        package = stem[0..colon];
        const qualifier = stem[colon + 1 ..];
        if (!std.mem.eql(u8, qualifier, architecture) or !isValidArchName(qualifier)) {
            diag.set(allocator, "{s} control member has invalid architecture qualifier: {s}", .{ architecture, name });
            return error.DerivationFailed;
        }
        qualified = true;
    }
    if (!isValidPackageName(package)) {
        diag.set(allocator, "{s} control member has invalid package: {s}", .{ architecture, name });
        return error.DerivationFailed;
    }
    const id_str = if (qualified)
        try std.fmt.allocPrint(allocator, "{s}:ARCH.{s}", .{ package, suffix })
    else
        try std.fmt.allocPrint(allocator, "{s}.{s}", .{ package, suffix });
    var owner: std.json.ObjectMap = .empty;
    try owner.put(allocator, "kind", .{ .string = "package" });
    try owner.put(allocator, "package", .{ .string = package });
    try owner.put(allocator, "architecture_qualified", .{ .bool = qualified });
    return .{ .id_str = id_str, .owner = .{ .object = owner } };
}

fn controlFact(allocator: std.mem.Allocator, item: std.json.ObjectMap) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "path", item.get("path").?);
    try obj.put(allocator, "mode", item.get("mode").?);
    try obj.put(allocator, "uid", item.get("uid").?);
    try obj.put(allocator, "gid", item.get("gid").?);
    try obj.put(allocator, "size", item.get("size").?);
    try obj.put(allocator, "sha256", item.get("sha256").?);
    try obj.put(allocator, "referenced_paths", item.get("referenced_paths").?);
    return .{ .object = obj };
}

fn linkedFact(allocator: std.mem.Allocator, item: std.json.ObjectMap) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    var it = item.iterator();
    while (it.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, "path") or std.mem.eql(u8, entry.key_ptr.*, "kind")) continue;
        try obj.put(allocator, entry.key_ptr.*, entry.value_ptr.*);
    }
    return .{ .object = obj };
}

const Resolution = struct {
    path: []const u8,
    chain: [][]const u8,
    terminal_path: []const u8,

    fn toJson(self: Resolution, allocator: std.mem.Allocator) !std.json.Value {
        var obj: std.json.ObjectMap = .empty;
        try obj.put(allocator, "path", .{ .string = self.path });
        try obj.put(allocator, "chain", try makeStringArrayJson(allocator, self.chain));
        try obj.put(allocator, "terminal_path", .{ .string = self.terminal_path });
        return .{ .object = obj };
    }
};

fn resolveRequested(
    allocator: std.mem.Allocator,
    start: []const u8,
    linked: std.StringHashMapUnmanaged(std.json.ObjectMap),
    maximum_hops: i64,
    diag: *Diagnostic,
) !Resolution {
    var current = try deriveRelativePath(allocator, .{ .string = start }, "requested path", diag);
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    try seen.put(allocator, current, {});
    var chain: std.ArrayList([]const u8) = .empty;
    var hops: i64 = 0;

    while (true) {
        const parts = try splitSlashAlloc(allocator, current);
        var followed = false;
        var length: usize = 1;
        while (length <= parts.len) : (length += 1) {
            const prefix = try joinSlash(allocator, parts[0..length]);
            const entry = linked.get(prefix) orelse continue;
            try chain.append(allocator, prefix);
            const kind = entry.get("kind").?.string;
            if (std.mem.eql(u8, kind, "regular")) {
                if (length != parts.len) {
                    diag.set(allocator, "non-directory linked component while resolving {s}: {s}", .{ start, prefix });
                    return error.DerivationFailed;
                }
                return .{
                    .path = start,
                    .chain = chain.items,
                    .terminal_path = prefix,
                };
            }
            if (!std.mem.eql(u8, kind, "symlink")) {
                diag.set(allocator, "unsupported linked terminal while resolving {s}: {s}", .{ start, kind });
                return error.DerivationFailed;
            }
            const target = try deriveTargetPath(
                allocator,
                prefix,
                entry.get("target"),
                try std.fmt.allocPrint(allocator, "symlink {s}", .{prefix}),
                diag,
            );
            const remaining = parts[length..];
            if (remaining.len > 0) {
                var next_parts: std.ArrayList([]const u8) = .empty;
                try next_parts.append(allocator, target);
                try next_parts.appendSlice(allocator, remaining);
                current = try deriveRelativePath(allocator, .{ .string = try joinSlash(allocator, next_parts.items) }, "resolved path", diag);
            } else {
                current = target;
            }
            hops += 1;
            if (hops > maximum_hops) {
                diag.set(allocator, "symlink hop limit exceeded while resolving {s}", .{start});
                return error.DerivationFailed;
            }
            if (seen.contains(current)) {
                diag.set(allocator, "symlink cycle while resolving {s}", .{start});
                return error.DerivationFailed;
            }
            try seen.put(allocator, current, {});
            followed = true;
            break;
        }
        if (!followed) {
            diag.set(allocator, "linked path has no recorded terminal: {s}", .{start});
            return error.DerivationFailed;
        }
    }
}

fn validateIndex(
    allocator: std.mem.Allocator,
    index: std.json.ObjectMap,
    diag: *Diagnostic,
) ![]std.json.ObjectMap {
    try requireKeys(allocator, index, &INDEX_KEYS, "vendor-state index", diag);
    const index_ver = try derivePositiveInteger(allocator, index.get("index_version"), "vendor-state index", diag);
    if (index_ver != 1) {
        diag.set(allocator, "vendor-state index version mismatch", .{});
        return error.DerivationFailed;
    }
    const cs = index.get("capture_schema").?;
    if (cs != .object or cs.object.count() != 2) {
        diag.set(allocator, "vendor-state capture schema mismatch", .{});
        return error.DerivationFailed;
    }
    const cs_id = try deriveText(allocator, cs.object.get("id"), "capture_schema.id", diag);
    const cs_ver = try derivePositiveInteger(allocator, cs.object.get("version"), "capture_schema.version", diag);
    if (!std.mem.eql(u8, cs_id, CAPTURE_SCHEMA) or cs_ver != 1) {
        diag.set(allocator, "vendor-state capture schema mismatch", .{});
        return error.DerivationFailed;
    }

    const src_val = index.get("source").?;
    if (src_val != .object) {
        diag.set(allocator, "vendor-state source must be an object", .{});
        return error.DerivationFailed;
    }
    const source = src_val.object;
    try requireKeys(allocator, source, &SOURCE_KEYS, "vendor-state source", diag);
    const commit = try deriveBoundedText(allocator, source.get("commit"), "vendor-state source commit", diag);
    if (!isLowerHexLen(commit, 40)) {
        diag.set(allocator, "vendor-state source commit is malformed", .{});
        return error.DerivationFailed;
    }
    const repository = try deriveBoundedText(allocator, source.get("repository"), "vendor-state source repository", diag);
    if (!isValidRepoSlug(repository)) {
        diag.set(allocator, "vendor-state source repository is malformed", .{});
        return error.DerivationFailed;
    }
    var repo_it = std.mem.splitScalar(u8, repository, '/');
    while (repo_it.next()) |comp| {
        _ = try deriveComponent(allocator, comp, "vendor-state source repository", diag);
    }
    const suite = try deriveBoundedText(allocator, source.get("snapshot_suite"), "vendor-state source snapshot suite", diag);
    _ = try deriveComponent(allocator, suite, "vendor-state source snapshot suite", diag);
    _ = try derivePublicHttpsUri(allocator, source.get("snapshot_uri"), "vendor-state source snapshot URI", diag);
    _ = try deriveBoundedText(allocator, source.get("workflow"), "vendor-state source workflow", diag);
    _ = try deriveRelativePath(allocator, source.get("workflow_path"), "vendor-state source workflow path", diag);
    _ = try derivePositiveInteger(allocator, source.get("workflow_run_attempt"), "vendor-state source workflow run attempt", diag);
    const run_id = try derivePositiveInteger(allocator, source.get("workflow_run_id"), "vendor-state source workflow run ID", diag);
    const run_url = try derivePublicHttpsUri(allocator, source.get("workflow_run_url"), "vendor-state source workflow run URL", diag);
    const expected_run_url = try std.fmt.allocPrint(allocator, "https://github.com/{s}/actions/runs/{d}", .{ repository, run_id });
    if (!std.mem.eql(u8, run_url, expected_run_url)) {
        diag.set(allocator, "vendor-state source workflow run URL is inconsistent", .{});
        return error.DerivationFailed;
    }

    const manifests_val = index.get("manifests").?;
    if (manifests_val != .array or manifests_val.array.items.len != ARCHITECTURES.len) {
        diag.set(allocator, "vendor-state index must contain two manifests", .{});
        return error.DerivationFailed;
    }
    var result: std.ArrayList(std.json.ObjectMap) = .empty;
    for (ARCHITECTURES, manifests_val.array.items) |arch, item_val| {
        if (item_val != .object) {
            diag.set(allocator, "{s} index manifest must be an object", .{arch});
            return error.DerivationFailed;
        }
        const item = item_val.object;
        try requireKeys(allocator, item, &INDEX_MANIFEST_KEYS, try std.fmt.allocPrint(allocator, "{s} index manifest", .{arch}), diag);
        const item_arch = try deriveText(allocator, item.get("architecture"), arch, diag);
        if (!std.mem.eql(u8, item_arch, arch)) {
            diag.set(allocator, "vendor-state manifests must be ordered amd64 then arm64", .{});
            return error.DerivationFailed;
        }
        for ([_][]const u8{ "artifact_id", "artifact_size_bytes", "job_id", "manifest_size_bytes" }) |field| {
            _ = try derivePositiveInteger(allocator, item.get(field), field, diag);
        }
        _ = try deriveHexToken(allocator, item.get("artifact_sha256"), "artifact_sha256", diag);
        _ = try deriveHexToken(allocator, item.get("manifest_sha256"), "manifest_sha256", diag);
        const manifest_name = try deriveBoundedText(allocator, item.get("manifest_path"), "manifest_path", diag);
        if (!std.mem.eql(u8, std.fs.path.basename(manifest_name), manifest_name) or
            std.mem.eql(u8, manifest_name, ".") or
            std.mem.eql(u8, manifest_name, ".."))
        {
            diag.set(allocator, "{s} manifest path is not a filename", .{arch});
            return error.DerivationFailed;
        }
        const artifact_name = try deriveBoundedText(allocator, item.get("artifact_name"), "artifact_name", diag);
        _ = try deriveComponent(allocator, artifact_name, "artifact_name", diag);
        const artifact_member = try deriveBoundedText(allocator, item.get("artifact_member"), "artifact_member", diag);
        if (!std.mem.eql(u8, std.fs.path.basename(artifact_member), artifact_member) or
            std.mem.eql(u8, artifact_member, ".") or
            std.mem.eql(u8, artifact_member, ".."))
        {
            diag.set(allocator, "{s} artifact member is not a filename", .{arch});
            return error.DerivationFailed;
        }
        if (item.get("inventory").? != .object) {
            diag.set(allocator, "{s} inventory must be an object", .{arch});
            return error.DerivationFailed;
        }
        try result.append(allocator, item);
    }
    return result.items;
}

fn unknownOwnershipJson(allocator: std.mem.Allocator) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "status", .{ .string = "not-captured" });
    try obj.put(allocator, "rationale", .{ .string = "The manifests do not retain package ownership lists or provider registration records for alternatives paths." });
    return .{ .object = obj };
}

fn unknownSelectionModeJson(allocator: std.mem.Allocator) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "status", .{ .string = "reference-execution-required" });
    try obj.put(allocator, "rationale", .{ .string = "The manifest hashes the alternatives record but does not retain the record bytes needed to distinguish auto from manual mode." });
    return .{ .object = obj };
}

fn unknownPrioritiesJson(allocator: std.mem.Allocator) !std.json.Value {
    var obj: std.json.ObjectMap = .empty;
    try obj.put(allocator, "status", .{ .string = "reference-execution-required" });
    try obj.put(allocator, "rationale", .{ .string = "The manifest does not retain candidate priorities or registration rows." });
    return .{ .object = obj };
}

const ControlEntryPair = struct {
    item: std.json.ObjectMap,
    owner: std.json.Value,
};

fn deriveControlMembers(
    allocator: std.mem.Allocator,
    amd64_doc: std.json.ObjectMap,
    arm64_doc: std.json.ObjectMap,
    diag: *Diagnostic,
) !struct {
    members: std.json.Value,
    path_qualifications: std.json.Value,
    control_content: std.json.Value,
    control_content_counts: std.json.Value,
    handling_counts: std.json.Value,
    config_identities: [][]const u8,
} {
    var amd64_map: std.StringHashMapUnmanaged(ControlEntryPair) = .empty;
    var arm64_map: std.StringHashMapUnmanaged(ControlEntryPair) = .empty;
    var identities: std.ArrayList([]const u8) = .empty;

    for (amd64_doc.get("control_members").?.object.get("entries").?.array.items) |item_val| {
        const res = try controlIdentity(allocator, item_val.object, "amd64", diag);
        if (amd64_map.contains(res.id_str)) {
            diag.set(allocator, "amd64 duplicate logical control identity: {s}", .{res.id_str});
            return error.DerivationFailed;
        }
        try amd64_map.put(allocator, res.id_str, .{ .item = item_val.object, .owner = res.owner });
        try identities.append(allocator, res.id_str);
    }
    for (arm64_doc.get("control_members").?.object.get("entries").?.array.items) |item_val| {
        const res = try controlIdentity(allocator, item_val.object, "arm64", diag);
        if (arm64_map.contains(res.id_str)) {
            diag.set(allocator, "arm64 duplicate logical control identity: {s}", .{res.id_str});
            return error.DerivationFailed;
        }
        try arm64_map.put(allocator, res.id_str, .{ .item = item_val.object, .owner = res.owner });
    }
    if (amd64_map.count() != arm64_map.count()) {
        diag.set(allocator, "control-member logical identities differ by architecture", .{});
        return error.DerivationFailed;
    }
    for (identities.items) |id_str| {
        if (!arm64_map.contains(id_str)) {
            diag.set(allocator, "control-member logical identities differ by architecture", .{});
            return error.DerivationFailed;
        }
    }
    std.mem.sort([]const u8, identities.items, {}, stringLessThan);

    var members = std.json.Array.init(allocator);
    var path_qualifications = std.json.Array.init(allocator);
    var content_differences = std.json.Array.init(allocator);
    var handling_counts_map: std.StringHashMapUnmanaged(i64) = .empty;
    var diff_counts_obj: std.json.ObjectMap = .empty;
    for (CLASSIFICATIONS) |cls| try diff_counts_obj.put(allocator, cls, .{ .integer = 0 });
    var config_ids: std.ArrayList([]const u8) = .empty;

    for (identities.items) |id_str| {
        const amd64_pair = amd64_map.get(id_str).?;
        const arm64_pair = arm64_map.get(id_str).?;
        const cls = amd64_pair.item.get("classification").?.string;
        const arm_cls = arm64_pair.item.get("classification").?.string;
        if (!std.mem.eql(u8, cls, arm_cls)) {
            diag.set(allocator, "control classification differs: {s}", .{id_str});
            return error.DerivationFailed;
        }
        if (!jsonValueEql(amd64_pair.owner, arm64_pair.owner)) {
            diag.set(allocator, "control ownership differs: {s}", .{id_str});
            return error.DerivationFailed;
        }
        if (std.mem.eql(u8, cls, "unclassified")) {
            diag.set(allocator, "unclassified control member: {s}", .{id_str});
            return error.DerivationFailed;
        }
        if (std.mem.eql(u8, cls, "debconf-config")) {
            try config_ids.append(allocator, id_str);
        }
        const h = classificationHandling(cls);
        try handling_counts_map.put(allocator, h.handling, (handling_counts_map.get(h.handling) orelse 0) + 1);

        const amd64_fact = try controlFact(allocator, amd64_pair.item);
        const arm64_fact = try controlFact(allocator, arm64_pair.item);
        var archs_obj: std.json.ObjectMap = .empty;
        try archs_obj.put(allocator, "amd64", amd64_fact);
        try archs_obj.put(allocator, "arm64", arm64_fact);

        var member_obj: std.json.ObjectMap = .empty;
        try member_obj.put(allocator, "identity", .{ .string = id_str });
        try member_obj.put(allocator, "classification", .{ .string = cls });
        try member_obj.put(allocator, "owner", amd64_pair.owner);
        try member_obj.put(allocator, "handling", .{ .string = h.handling });
        try member_obj.put(allocator, "rationale", .{ .string = h.rationale });
        try member_obj.put(allocator, "reference_execution_requirement", .{ .string = h.requirement });
        try member_obj.put(allocator, "architectures", .{ .object = archs_obj });
        try members.append(.{ .object = member_obj });

        const amd_path = amd64_fact.object.get("path").?.string;
        const arm_path = arm64_fact.object.get("path").?.string;
        if (!std.mem.eql(u8, amd_path, arm_path)) {
            const owner_kind = amd64_pair.owner.object.get("kind").?.string;
            const arch_qual = amd64_pair.owner.object.get("architecture_qualified") orelse std.json.Value{ .bool = false };
            if (!std.mem.eql(u8, owner_kind, "package") or !arch_qual.bool) {
                diag.set(allocator, "unexpected control path difference: {s}", .{id_str});
                return error.DerivationFailed;
            }
            var pq_obj: std.json.ObjectMap = .empty;
            try pq_obj.put(allocator, "identity", .{ .string = id_str });
            try pq_obj.put(allocator, "amd64_path", .{ .string = amd_path });
            try pq_obj.put(allocator, "arm64_path", .{ .string = arm_path });
            try path_qualifications.append(.{ .object = pq_obj });
        }

        var changed_fields: std.ArrayList([]const u8) = .empty;
        for (CONTROL_FACT_FIELDS) |field| {
            if (!jsonValueEql(amd64_fact.object.get(field).?, arm64_fact.object.get(field).?)) {
                try changed_fields.append(allocator, field);
            }
        }
        if (changed_fields.items.len > 0) {
            const valid_diff = (changed_fields.items.len == 1 and std.mem.eql(u8, changed_fields.items[0], "sha256")) or
                (changed_fields.items.len == 2 and std.mem.eql(u8, changed_fields.items[0], "size") and std.mem.eql(u8, changed_fields.items[1], "sha256"));
            if (!valid_diff) {
                diag.set(allocator, "unsupported control difference {s}", .{id_str});
                return error.DerivationFailed;
            }
            const cur_cnt = diff_counts_obj.get(cls).?.integer;
            try diff_counts_obj.put(allocator, cls, .{ .integer = cur_cnt + 1 });
            var cd_obj: std.json.ObjectMap = .empty;
            try cd_obj.put(allocator, "identity", .{ .string = id_str });
            try cd_obj.put(allocator, "classification", .{ .string = cls });
            try cd_obj.put(allocator, "changed_fields", try makeStringArrayJson(allocator, changed_fields.items));
            try content_differences.append(.{ .object = cd_obj });
        }
    }

    var handling_counts_obj: std.json.ObjectMap = .empty;
    var h_it = handling_counts_map.iterator();
    while (h_it.next()) |entry| {
        try handling_counts_obj.put(allocator, entry.key_ptr.*, .{ .integer = entry.value_ptr.* });
    }

    return .{
        .members = .{ .array = members },
        .path_qualifications = .{ .array = path_qualifications },
        .control_content = .{ .array = content_differences },
        .control_content_counts = .{ .object = diff_counts_obj },
        .handling_counts = .{ .object = handling_counts_obj },
        .config_identities = config_ids.items,
    };
}

fn linkObjLessThan(_: void, a: std.json.Value, b: std.json.Value) bool {
    return std.mem.lessThan(u8, a.object.get("link_path").?.string, b.object.get("link_path").?.string);
}

fn candidateObjLessThan(_: void, a: std.json.Value, b: std.json.Value) bool {
    return std.mem.lessThan(u8, a.object.get("path").?.string, b.object.get("path").?.string);
}

fn deriveAlternatives(
    allocator: std.mem.Allocator,
    amd64_doc: std.json.ObjectMap,
    arm64_doc: std.json.ObjectMap,
    diag: *Diagnostic,
) !struct {
    alternatives: std.json.Value,
    linked_differences: std.json.Value,
    group_names: [][]const u8,
    master_count: usize,
    slave_count: usize,
    regular_count: usize,
    symlink_count: usize,
    retained_paths: [][]const u8,
} {
    if (!jsonValueEql(amd64_doc.get("alternatives_database").?, arm64_doc.get("alternatives_database").?)) {
        diag.set(allocator, "alternatives records differ by architecture", .{});
        return error.DerivationFailed;
    }
    const amd_req_val = amd64_doc.get("linked_filesystem").?.object.get("requested_paths").?;
    const arm_req_val = arm64_doc.get("linked_filesystem").?.object.get("requested_paths").?;
    if (!jsonValueEql(amd_req_val, arm_req_val)) {
        diag.set(allocator, "alternatives requested paths differ by architecture", .{});
        return error.DerivationFailed;
    }

    var amd64_linked: std.StringHashMapUnmanaged(std.json.ObjectMap) = .empty;
    var arm64_linked: std.StringHashMapUnmanaged(std.json.ObjectMap) = .empty;
    var linked_paths: std.ArrayList([]const u8) = .empty;

    for (amd64_doc.get("linked_filesystem").?.object.get("entries").?.array.items) |item| {
        const p = item.object.get("path").?.string;
        try amd64_linked.put(allocator, p, item.object);
        try linked_paths.append(allocator, p);
    }
    for (arm64_doc.get("linked_filesystem").?.object.get("entries").?.array.items) |item| {
        const p = item.object.get("path").?.string;
        try arm64_linked.put(allocator, p, item.object);
    }
    if (amd64_linked.count() != arm64_linked.count()) {
        diag.set(allocator, "linked filesystem paths differ by architecture", .{});
        return error.DerivationFailed;
    }
    std.mem.sort([]const u8, linked_paths.items, {}, stringLessThan);
    for (linked_paths.items) |path| {
        const amd_item = amd64_linked.get(path).?;
        const arm_item = arm64_linked.get(path) orelse {
            diag.set(allocator, "linked filesystem paths differ by architecture", .{});
            return error.DerivationFailed;
        };
        if (!std.mem.eql(u8, amd_item.get("kind").?.string, arm_item.get("kind").?.string)) {
            diag.set(allocator, "linked entry kind differs: {s}", .{path});
            return error.DerivationFailed;
        }
        for ([_][]const u8{ "mode", "uid", "gid", "target" }) |field| {
            const av = amd_item.get(field);
            const bv = arm_item.get(field);
            const same = if (av) |a| (if (bv) |b| jsonValueEql(a, b) else false) else bv == null;
            if (!same) {
                diag.set(allocator, "linked topology differs at {s}: {s}", .{ path, field });
                return error.DerivationFailed;
            }
        }
    }

    const max_hops = amd64_doc.get("limits").?.object.get("max_link_hops").?.integer;
    var resolutions: std.StringHashMapUnmanaged(Resolution) = .empty;
    var reached_amd: std.StringHashMapUnmanaged(void) = .empty;
    var reached_arm: std.StringHashMapUnmanaged(void) = .empty;

    for (amd_req_val.array.items) |req_item| {
        const req_path = req_item.string;
        const res_amd = try resolveRequested(allocator, req_path, amd64_linked, max_hops, diag);
        const res_arm = try resolveRequested(allocator, req_path, arm64_linked, max_hops, diag);
        for (res_amd.chain) |cp| try reached_amd.put(allocator, cp, {});
        for (res_arm.chain) |cp| try reached_arm.put(allocator, cp, {});
        if (!jsonValueEql(try res_amd.toJson(allocator), try res_arm.toJson(allocator))) {
            diag.set(allocator, "linked path resolutions differ by architecture", .{});
            return error.DerivationFailed;
        }
        try resolutions.put(allocator, req_path, res_amd);
    }
    if (reached_amd.count() != amd64_linked.count() or reached_arm.count() != arm64_linked.count()) {
        diag.set(allocator, "linked entries are not fully reached", .{});
        return error.DerivationFailed;
    }

    var roles: std.StringHashMapUnmanaged(std.ArrayList([]const u8)) = .empty;
    for (linked_paths.items) |p| {
        try roles.put(allocator, p, .empty);
    }
    const addRole = struct {
        fn call(
            alloc: std.mem.Allocator,
            map: *std.StringHashMapUnmanaged(std.ArrayList([]const u8)),
            p: []const u8,
            role: []const u8,
        ) !void {
            const list_ptr = map.getPtr(p).?;
            if (!sliceContains(list_ptr.items, role)) {
                try list_ptr.append(alloc, role);
            }
        }
    }.call;

    var associated_requested: std.StringHashMapUnmanaged(void) = .empty;
    var groups = std.json.Array.init(allocator);
    var group_names: std.ArrayList([]const u8) = .empty;
    var master_count: usize = 0;
    var slave_count: usize = 0;

    for (amd64_doc.get("alternatives_database").?.array.items) |record_val| {
        const record = record_val.object;
        const name = std.fs.path.basename(record.get("path").?.string);
        try group_names.append(allocator, name);
        var links: std.ArrayList(std.json.Value) = .empty;
        var candidates: std.ArrayList(std.json.Value) = .empty;

        for (record.get("referenced_paths").?.array.items) |ref_val| {
            const path = ref_val.string;
            try associated_requested.put(allocator, path, {});
            const resolution = resolutions.get(path) orelse {
                diag.set(allocator, "alternatives record references an uncaptured path: {s}", .{path});
                return error.DerivationFailed;
            };
            var selectors: std.ArrayList([]const u8) = .empty;
            var selector_indices: std.ArrayList(usize) = .empty;
            for (resolution.chain, 0..) |entry_path, idx| {
                if (std.mem.startsWith(u8, entry_path, "etc/alternatives/") and
                    std.mem.eql(u8, amd64_linked.get(entry_path).?.get("kind").?.string, "symlink"))
                {
                    try selectors.append(allocator, entry_path);
                    try selector_indices.append(allocator, idx);
                }
            }
            if (selectors.items.len > 1) {
                diag.set(allocator, "alternatives path crosses multiple selectors: {s}", .{path});
                return error.DerivationFailed;
            }
            if (selectors.items.len == 0) {
                if (resolution.chain.len > 1) {
                    for (resolution.chain[0 .. resolution.chain.len - 1]) |ep| {
                        try addRole(allocator, &roles, ep, "path-alias");
                    }
                }
                try addRole(allocator, &roles, resolution.terminal_path, "candidate-target");
                var cand_obj: std.json.ObjectMap = .empty;
                try cand_obj.put(allocator, "path", .{ .string = path });
                try cand_obj.put(allocator, "terminal_path", .{ .string = resolution.terminal_path });
                try cand_obj.put(allocator, "selected_by", try makeStringArrayJson(allocator, &.{}) );
                try candidates.append(allocator, .{ .object = cand_obj });
                continue;
            }
            const selector = selectors.items[0];
            const selector_index = selector_indices.items[0];
            try associated_requested.put(allocator, selector, {});
            if (selector_index == 0) {
                diag.set(allocator, "alternatives record directly names selector instead of link: {s}", .{path});
                return error.DerivationFailed;
            }
            const front = resolution.chain[selector_index - 1];
            for (resolution.chain[0 .. selector_index - 1]) |ep| {
                try addRole(allocator, &roles, ep, "path-alias");
            }
            try addRole(allocator, &roles, front, "front-link");
            try addRole(allocator, &roles, selector, "selector-link");
            if (selector_index + 1 < resolution.chain.len) {
                for (resolution.chain[selector_index + 1 .. resolution.chain.len - 1]) |ep| {
                    try addRole(allocator, &roles, ep, "path-alias");
                }
            }
            try addRole(allocator, &roles, resolution.terminal_path, "candidate-target");
            const master_selector = try std.fmt.allocPrint(allocator, "etc/alternatives/{s}", .{name});
            const relationship = if (std.mem.eql(u8, selector, master_selector)) "master" else "slave";
            if (std.mem.eql(u8, relationship, "master")) master_count += 1 else slave_count += 1;

            var link_obj: std.json.ObjectMap = .empty;
            try link_obj.put(allocator, "relationship", .{ .string = relationship });
            try link_obj.put(allocator, "link_path", .{ .string = path });
            try link_obj.put(allocator, "selector_path", .{ .string = selector });
            try link_obj.put(allocator, "selector_target", amd64_linked.get(selector).?.get("target").?);
            try link_obj.put(allocator, "terminal_path", .{ .string = resolution.terminal_path });
            try link_obj.put(allocator, "ownership", try unknownOwnershipJson(allocator));
            try links.append(allocator, .{ .object = link_obj });
        }

        std.mem.sort(std.json.Value, links.items, {}, linkObjLessThan);
        std.mem.sort(std.json.Value, candidates.items, {}, candidateObjLessThan);

        var seen_selectors: std.StringHashMapUnmanaged(void) = .empty;
        var group_masters: usize = 0;
        var selected_terminals: std.StringHashMapUnmanaged(std.ArrayList([]const u8)) = .empty;
        for (links.items) |lval| {
            const lobj = lval.object;
            const sp = lobj.get("selector_path").?.string;
            if (seen_selectors.contains(sp)) {
                diag.set(allocator, "alternatives group {s} has duplicate selector relationships", .{name});
                return error.DerivationFailed;
            }
            try seen_selectors.put(allocator, sp, {});
            if (std.mem.eql(u8, lobj.get("relationship").?.string, "master")) group_masters += 1;
            const tp = lobj.get("terminal_path").?.string;
            if (!selected_terminals.contains(tp)) {
                try selected_terminals.put(allocator, tp, .empty);
            }
            try selected_terminals.getPtr(tp).?.append(allocator, lobj.get("link_path").?.string);
        }
        if (group_masters != 1) {
            diag.set(allocator, "alternatives group {s} does not have exactly one master link", .{name});
            return error.DerivationFailed;
        }

        var cand_terminals: std.StringHashMapUnmanaged(void) = .empty;
        for (candidates.items) |*cval| {
            const tp = cval.object.get("terminal_path").?.string;
            if (cand_terminals.contains(tp)) {
                diag.set(allocator, "alternatives group {s} has duplicate candidate terminals", .{name});
                return error.DerivationFailed;
            }
            try cand_terminals.put(allocator, tp, {});
            if (selected_terminals.get(tp)) |sel_list| {
                std.mem.sort([]const u8, sel_list.items, {}, stringLessThan);
                try cval.object.put(allocator, "selected_by", try makeStringArrayJson(allocator, sel_list.items));
            }
        }
        var st_it = selected_terminals.keyIterator();
        while (st_it.next()) |tp_ptr| {
            if (!cand_terminals.contains(tp_ptr.*)) {
                diag.set(allocator, "alternatives group {s} selects an undeclared candidate", .{name});
                return error.DerivationFailed;
            }
        }

        var links_arr = std.json.Array.init(allocator);
        try links_arr.appendSlice(links.items);
        var cands_arr = std.json.Array.init(allocator);
        try cands_arr.appendSlice(candidates.items);

        var grp_obj: std.json.ObjectMap = .empty;
        try grp_obj.put(allocator, "name", .{ .string = name });
        try grp_obj.put(allocator, "present_in_architectures", try makeStringArrayJson(allocator, &ARCHITECTURES));
        try grp_obj.put(allocator, "record", record_val);
        try grp_obj.put(allocator, "ownership", try unknownOwnershipJson(allocator));
        try grp_obj.put(allocator, "selection_mode", try unknownSelectionModeJson(allocator));
        try grp_obj.put(allocator, "priorities", try unknownPrioritiesJson(allocator));
        try grp_obj.put(allocator, "links", .{ .array = links_arr });
        try grp_obj.put(allocator, "candidate_paths", .{ .array = cands_arr });
        try grp_obj.put(allocator, "reference_execution_requirement", .{ .string = "Decode exact record bytes and observe reference registration, selection, and mutation behavior." });
        try groups.append(.{ .object = grp_obj });
    }

    var retained_requested = std.json.Array.init(allocator);
    var retained_paths: std.ArrayList([]const u8) = .empty;
    for (amd_req_val.array.items) |req_item| {
        const path = req_item.string;
        if (associated_requested.contains(path)) continue;
        const resolution = resolutions.get(path).?;
        const terminal = amd64_linked.get(resolution.terminal_path).?;
        if (!std.mem.startsWith(u8, path, "etc/alternatives/") or
            !std.mem.eql(u8, terminal.get("kind").?.string, "regular"))
        {
            diag.set(allocator, "unclassified alternatives requested path: {s}", .{path});
            return error.DerivationFailed;
        }
        if (resolution.chain.len > 1) {
            for (resolution.chain[0 .. resolution.chain.len - 1]) |ep| {
                try addRole(allocator, &roles, ep, "path-alias");
            }
        }
        try addRole(allocator, &roles, resolution.terminal_path, "retained-selector-metadata");
        try retained_paths.append(allocator, path);
        var ret_obj: std.json.ObjectMap = .empty;
        try ret_obj.put(allocator, "path", .{ .string = path });
        try ret_obj.put(allocator, "terminal_path", .{ .string = resolution.terminal_path });
        try ret_obj.put(allocator, "handling", .{ .string = "bounded-inert-retained-metadata" });
        try ret_obj.put(allocator, "rationale", .{ .string = "This regular etc/alternatives entry is not a selector or alternatives database record and is retained by identity." });
        try retained_requested.append(.{ .object = ret_obj });
    }

    var linked_entries = std.json.Array.init(allocator);
    var linked_differences = std.json.Array.init(allocator);
    var regular_count: usize = 0;
    var symlink_count: usize = 0;

    for (linked_paths.items) |path| {
        const amd_item = amd64_linked.get(path).?;
        const arm_item = arm64_linked.get(path).?;
        const role_list = roles.get(path).?;
        if (role_list.items.len == 0) {
            diag.set(allocator, "linked entry has no derived role: {s}", .{path});
            return error.DerivationFailed;
        }
        std.mem.sort([]const u8, role_list.items, {}, roleLessThan);
        const kind = amd_item.get("kind").?.string;
        if (std.mem.eql(u8, kind, "regular")) regular_count += 1 else if (std.mem.eql(u8, kind, "symlink")) symlink_count += 1;

        const amd_fact = try linkedFact(allocator, amd_item);
        const arm_fact = try linkedFact(allocator, arm_item);
        var archs_obj: std.json.ObjectMap = .empty;
        try archs_obj.put(allocator, "amd64", amd_fact);
        try archs_obj.put(allocator, "arm64", arm_fact);

        var le_obj: std.json.ObjectMap = .empty;
        try le_obj.put(allocator, "identity", .{ .string = path });
        try le_obj.put(allocator, "kind", .{ .string = kind });
        try le_obj.put(allocator, "roles", try makeStringArrayJson(allocator, role_list.items));
        try le_obj.put(allocator, "ownership", try unknownOwnershipJson(allocator));
        try le_obj.put(allocator, "architectures", .{ .object = archs_obj });
        try linked_entries.append(.{ .object = le_obj });

        var changed_fields: std.ArrayList([]const u8) = .empty;
        for (LINKED_FACT_FIELDS) |field| {
            const av = amd_fact.object.get(field);
            const bv = arm_fact.object.get(field);
            const same = if (av) |a| (if (bv) |b| jsonValueEql(a, b) else false) else bv == null;
            if (!same) try changed_fields.append(allocator, field);
        }
        if (changed_fields.items.len > 0) {
            if (!std.mem.eql(u8, kind, "regular") or
                changed_fields.items.len != 2 or
                !std.mem.eql(u8, changed_fields.items[0], "size") or
                !std.mem.eql(u8, changed_fields.items[1], "sha256"))
            {
                diag.set(allocator, "unsupported linked entry difference {s}", .{path});
                return error.DerivationFailed;
            }
            var ld_obj: std.json.ObjectMap = .empty;
            try ld_obj.put(allocator, "identity", .{ .string = path });
            try ld_obj.put(allocator, "kind", .{ .string = "regular" });
            try ld_obj.put(allocator, "changed_fields", try makeStringArrayJson(allocator, changed_fields.items));
            try linked_differences.append(.{ .object = ld_obj });
        }
    }

    var requested_output = std.json.Array.init(allocator);
    for (amd_req_val.array.items) |req_item| {
        try requested_output.append(try resolutions.get(req_item.string).?.toJson(allocator));
    }

    var alt_obj: std.json.ObjectMap = .empty;
    try alt_obj.put(allocator, "groups", .{ .array = groups });
    try alt_obj.put(allocator, "requested_paths", .{ .array = requested_output });
    try alt_obj.put(allocator, "linked_entries", .{ .array = linked_entries });
    try alt_obj.put(allocator, "retained_selector_metadata", .{ .array = retained_requested });

    return .{
        .alternatives = .{ .object = alt_obj },
        .linked_differences = .{ .array = linked_differences },
        .group_names = group_names.items,
        .master_count = master_count,
        .slave_count = slave_count,
        .regular_count = regular_count,
        .symlink_count = symlink_count,
        .retained_paths = retained_paths.items,
    };
}

fn sliceEqlStrings(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, x, y)) return false;
    }
    return true;
}

pub fn derive(
    allocator: std.mem.Allocator,
    index_path: []const u8,
    diag: *Diagnostic,
) !std.json.Value {
    const base_name = std.fs.path.basename(index_path);
    if (!std.mem.eql(u8, base_name, "index-v1.json")) {
        diag.set(allocator, "vendor-state index filename must be index-v1.json", .{});
        return error.DerivationFailed;
    }
    const index_dir = std.fs.path.dirname(index_path) orelse ".";
    const index_doc = try readDocument(allocator, index_path, MAX_INDEX_BYTES, "vendor-state index", diag);
    const manifest_refs = try validateIndex(allocator, index_doc.doc, diag);

    var docs: std.StringHashMapUnmanaged(std.json.ObjectMap) = .empty;
    var source_manifests = std.json.Array.init(allocator);

    for (manifest_refs) |ref| {
        const arch = ref.get("architecture").?.string;
        const rel_manifest = ref.get("manifest_path").?.string;
        const manifest_path = try std.fs.path.join(allocator, &.{ index_dir, rel_manifest });
        const m_doc = try readDocument(
            allocator,
            manifest_path,
            MAX_MANIFEST_BYTES,
            try std.fmt.allocPrint(allocator, "{s} manifest", .{arch}),
            diag,
        );
        if (@as(i64, @intCast(m_doc.raw.len)) != ref.get("manifest_size_bytes").?.integer) {
            diag.set(allocator, "{s} manifest size binding mismatch", .{arch});
            return error.DerivationFailed;
        }
        var raw_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(m_doc.raw, &raw_hash, .{});
        const hex_chars = std.fmt.bytesToHex(raw_hash, .lower);
        if (!std.mem.eql(u8, &hex_chars, ref.get("manifest_sha256").?.string)) {
            diag.set(allocator, "{s} manifest digest binding mismatch", .{arch});
            return error.DerivationFailed;
        }
        try validateManifest(allocator, m_doc.doc, arch, diag);
        const inv = try computeInventory(allocator, m_doc.doc);
        if (!jsonValueEql(inv, ref.get("inventory").?)) {
            diag.set(allocator, "{s} index inventory binding mismatch", .{arch});
            return error.DerivationFailed;
        }
        try docs.put(allocator, arch, m_doc.doc);

        var art_obj: std.json.ObjectMap = .empty;
        try art_obj.put(allocator, "id", ref.get("artifact_id").?);
        try art_obj.put(allocator, "name", ref.get("artifact_name").?);
        try art_obj.put(allocator, "member", ref.get("artifact_member").?);
        try art_obj.put(allocator, "size", ref.get("artifact_size_bytes").?);
        try art_obj.put(allocator, "sha256", ref.get("artifact_sha256").?);
        try art_obj.put(allocator, "job_id", ref.get("job_id").?);

        var sm_obj: std.json.ObjectMap = .empty;
        try sm_obj.put(allocator, "architecture", .{ .string = arch });
        try sm_obj.put(allocator, "path", .{ .string = rel_manifest });
        try sm_obj.put(allocator, "size", ref.get("manifest_size_bytes").?);
        try sm_obj.put(allocator, "sha256", ref.get("manifest_sha256").?);
        try sm_obj.put(allocator, "artifact", .{ .object = art_obj });
        try source_manifests.append(.{ .object = sm_obj });
    }

    const ctrl = try deriveControlMembers(allocator, docs.get("amd64").?, docs.get("arm64").?, diag);
    const alt = try deriveAlternatives(allocator, docs.get("amd64").?, docs.get("arm64").?, diag);

    if (!sliceEqlStrings(ctrl.config_identities, &EXPECTED_CONFIG_IDENTITIES)) {
        diag.set(allocator, "config-script identity boundary changed", .{});
        return error.DerivationFailed;
    }
    if (!sliceEqlStrings(alt.group_names, &EXPECTED_ALTERNATIVES_GROUPS)) {
        diag.set(allocator, "alternatives-group identity boundary changed", .{});
        return error.DerivationFailed;
    }
    if (ctrl.path_qualifications.array.items.len != EXPECTED_PATH_QUALIFICATIONS) {
        diag.set(allocator, "architecture-qualified control boundary changed", .{});
        return error.DerivationFailed;
    }
    if (ctrl.control_content.array.items.len != EXPECTED_CONTROL_CONTENT_DIFFERENCES) {
        diag.set(allocator, "control-content difference boundary changed", .{});
        return error.DerivationFailed;
    }
    for (CLASSIFICATIONS) |cls| {
        if (ctrl.control_content_counts.object.get(cls).?.integer != expectedControlDiffCount(cls)) {
            diag.set(allocator, "control-content difference boundary changed", .{});
            return error.DerivationFailed;
        }
    }
    if (alt.linked_differences.array.items.len != EXPECTED_LINKED_DIFFERENCES.len) {
        diag.set(allocator, "linked-content difference boundary changed", .{});
        return error.DerivationFailed;
    }
    for (alt.linked_differences.array.items, EXPECTED_LINKED_DIFFERENCES) |item, exp_id| {
        if (!std.mem.eql(u8, item.object.get("identity").?.string, exp_id)) {
            diag.set(allocator, "linked-content difference boundary changed", .{});
            return error.DerivationFailed;
        }
    }
    if (alt.master_count != 14 or alt.slave_count != 58) {
        diag.set(allocator, "alternatives relationship boundary changed", .{});
        return error.DerivationFailed;
    }
    if (alt.regular_count != 45 or alt.symlink_count != 145) {
        diag.set(allocator, "linked-entry kind boundary changed", .{});
        return error.DerivationFailed;
    }
    if (!sliceEqlStrings(alt.retained_paths, &[_][]const u8{"etc/alternatives/README"})) {
        diag.set(allocator, "retained alternatives metadata boundary changed", .{});
        return error.DerivationFailed;
    }

    var per_arch: std.json.ObjectMap = .empty;
    for (manifest_refs) |ref| {
        const arch = ref.get("architecture").?.string;
        var arch_inv: std.json.ObjectMap = .empty;
        var inv_it = ref.get("inventory").?.object.iterator();
        while (inv_it.next()) |entry| {
            try arch_inv.put(allocator, entry.key_ptr.*, entry.value_ptr.*);
        }
        try arch_inv.put(allocator, "config_member_count", .{ .integer = EXPECTED_CONFIG_MEMBERS });
        try arch_inv.put(allocator, "package_alternatives_member_count", .{ .integer = 0 });
        try arch_inv.put(allocator, "unclassified_control_member_count", .{ .integer = 0 });
        try arch_inv.put(allocator, "control_handling_counts", ctrl.handling_counts);
        try per_arch.put(allocator, arch, .{ .object = arch_inv });
    }

    var limits_obj: std.json.ObjectMap = .empty;
    const exp_limits = Limits{};
    inline for (LIMIT_KEYS) |field_name| {
        try limits_obj.put(allocator, field_name, .{ .integer = @field(exp_limits, field_name) });
    }

    var idx_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(index_doc.raw, &idx_hash, .{});
    const idx_hex = std.fmt.bytesToHex(idx_hash, .lower);
    var idx_info: std.json.ObjectMap = .empty;
    try idx_info.put(allocator, "path", .{ .string = base_name });
    try idx_info.put(allocator, "size", .{ .integer = @intCast(index_doc.raw.len) });
    try idx_info.put(allocator, "sha256", .{ .string = try allocator.dupe(u8, &idx_hex) });

    var source_obj: std.json.ObjectMap = .empty;
    try source_obj.put(allocator, "capture_schema", index_doc.doc.get("capture_schema").?);
    try source_obj.put(allocator, "capture_limits", .{ .object = limits_obj });
    try source_obj.put(allocator, "index", .{ .object = idx_info });
    try source_obj.put(allocator, "index_source", index_doc.doc.get("source").?);
    try source_obj.put(allocator, "manifests", .{ .array = source_manifests });

    var boundary_obj: std.json.ObjectMap = .empty;
    try boundary_obj.put(allocator, "architectures", try makeStringArrayJson(allocator, &ARCHITECTURES));
    try boundary_obj.put(allocator, "per_architecture", .{ .object = per_arch });
    try boundary_obj.put(allocator, "paired_control_member_count", .{ .integer = @intCast(ctrl.members.array.items.len) });
    try boundary_obj.put(allocator, "alternatives_group_count", .{ .integer = @intCast(alt.group_names.len) });
    try boundary_obj.put(allocator, "requested_path_count", .{ .integer = EXPECTED_REQUESTED_PATHS });
    try boundary_obj.put(allocator, "linked_entry_count", .{ .integer = EXPECTED_LINKED_ENTRIES });

    const invariants = [_][]const u8{
        "classification-counts",
        "control-logical-identities",
        "alternatives-records",
        "requested-paths",
        "linked-path-kinds-modes-owners-targets",
    };
    var cross_diff: std.json.ObjectMap = .empty;
    try cross_diff.put(allocator, "path_qualifications", ctrl.path_qualifications);
    try cross_diff.put(allocator, "control_content", ctrl.control_content);
    try cross_diff.put(allocator, "control_content_counts", ctrl.control_content_counts);
    try cross_diff.put(allocator, "linked_content", alt.linked_differences);
    try cross_diff.put(allocator, "invariants", try makeStringArrayJson(allocator, &invariants));

    var reqs_arr = std.json.Array.init(allocator);
    {
        var applies: std.json.ObjectMap = .empty;
        try applies.put(allocator, "kind", .{ .string = "control-members" });
        try applies.put(allocator, "identities", try makeStringArrayJson(allocator, ctrl.config_identities));
        var r1: std.json.ObjectMap = .empty;
        try r1.put(allocator, "id", .{ .string = "debconf-config-execution" });
        try r1.put(allocator, "applies_to", .{ .object = applies });
        try r1.put(allocator, "manifest_proves", .{ .string = "Installed path, owning package name, mode, uid, gid, size, and SHA-256 for each config script." });
        try r1.put(allocator, "required_reference_execution", .{ .string = "Observe whether and how the reference frontend invokes each config script, including ordering, argv, environment, outcome, and resulting state." });
        try reqs_arr.append(.{ .object = r1 });
    }
    {
        var applies: std.json.ObjectMap = .empty;
        try applies.put(allocator, "kind", .{ .string = "alternatives-groups" });
        try applies.put(allocator, "identities", try makeStringArrayJson(allocator, alt.group_names));
        var r2: std.json.ObjectMap = .empty;
        try r2.put(allocator, "id", .{ .string = "alternatives-record-semantics" });
        try r2.put(allocator, "applies_to", .{ .object = applies });
        try r2.put(allocator, "manifest_proves", .{ .string = "Record identity and digest, declared paths, current master/slave selector topology, selected targets, and linked filesystem identities." });
        try r2.put(allocator, "required_reference_execution", .{ .string = "Capture exact record bytes to type auto/manual mode, candidate rows, priorities, and provider registration." });
        try reqs_arr.append(.{ .object = r2 });
    }
    {
        var applies: std.json.ObjectMap = .empty;
        try applies.put(allocator, "kind", .{ .string = "alternatives-groups" });
        try applies.put(allocator, "identities", try makeStringArrayJson(allocator, alt.group_names));
        var r3: std.json.ObjectMap = .empty;
        try r3.put(allocator, "id", .{ .string = "alternatives-mutation-behavior" });
        try r3.put(allocator, "applies_to", .{ .object = applies });
        try r3.put(allocator, "manifest_proves", .{ .string = "One post-installation state only; no causality or mutation sequence is present." });
        try r3.put(allocator, "required_reference_execution", .{ .string = "Run bounded reference install, upgrade, remove, purge, failure, and recovery cases and compare exact record and link mutations before production support changes." });
        try reqs_arr.append(.{ .object = r3 });
    }

    var doc: std.json.ObjectMap = .empty;
    try doc.put(allocator, "schema", .{ .string = REFERENCE_SCHEMA });
    try doc.put(allocator, "version", .{ .integer = 1 });
    try doc.put(allocator, "source", .{ .object = source_obj });
    try doc.put(allocator, "boundary", .{ .object = boundary_obj });
    try doc.put(allocator, "control_members", ctrl.members);
    try doc.put(allocator, "alternatives", alt.alternatives);
    try doc.put(allocator, "cross_architecture_differences", .{ .object = cross_diff });
    try doc.put(allocator, "reference_execution_requirements", .{ .array = reqs_arr });
    return .{ .object = doc };
}

fn writeNewFile(
    allocator: std.mem.Allocator,
    path: []const u8,
    data: []const u8,
    diag: *Diagnostic,
) !void {
    const flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .CLOEXEC = true,
    };
    const fd = openatFd(linux.AT.FDCWD, path, flags, 0o666) catch |err| {
        diag.set(allocator, "cannot create output {s}: {s}", .{ path, @errorName(err) });
        return error.DerivationFailed;
    };
    defer closeFd(fd);

    var written: usize = 0;
    while (written < data.len) {
        const rc = linux.write(fd, data[written..].ptr, data.len - written);
        if (linux.errno(rc) != .SUCCESS or rc == 0) {
            diag.set(allocator, "cannot create output {s}: short write", .{path});
            return error.DerivationFailed;
        }
        written += rc;
    }
    _ = linux.fsync(fd);
}

fn printStderr(comptime fmt: []const u8, args: anytype) void {
    if (builtin.is_test) return;
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = linux.write(2, msg.ptr, msg.len);
}

pub fn captureMain(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    var reference_root: ?[]const u8 = null;
    var architecture: ?[]const u8 = null;
    var output: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--reference-root")) {
            if (i + 1 >= args.len) {
                printStderr("vendor-state-capture: missing --reference-root value\n", .{});
                return 2;
            }
            i += 1;
            reference_root = args[i];
        } else if (std.mem.eql(u8, arg, "--architecture")) {
            if (i + 1 >= args.len) {
                printStderr("vendor-state-capture: missing --architecture value\n", .{});
                return 2;
            }
            i += 1;
            architecture = args[i];
        } else if (std.mem.eql(u8, arg, "--output")) {
            if (i + 1 >= args.len) {
                printStderr("vendor-state-capture: missing --output value\n", .{});
                return 2;
            }
            i += 1;
            output = args[i];
        } else {
            printStderr("vendor-state-capture: unknown argument: {s}\n", .{arg});
            return 2;
        }
    }
    if (reference_root == null or architecture == null or output == null) {
        printStderr("vendor-state-capture: --reference-root, --architecture, and --output are required\n", .{});
        return 2;
    }

    var diag: Diagnostic = .{};
    const root_path = validateAbsolutePath(allocator, reference_root.?, "reference root", false, &diag) catch {
        printStderr("vendor-state-capture: {s}\n", .{diag.message});
        return 2;
    };
    const doc = capture(allocator, root_path, architecture.?, Limits{}, &diag) catch {
        printStderr("vendor-state-capture: {s}\n", .{diag.message});
        return 2;
    };
    const encoded = canonicalJson(allocator, doc) catch {
        printStderr("vendor-state-capture: failed to encode canonical JSON\n", .{});
        return 2;
    };
    writeCaptureOutput(allocator, output.?, root_path, encoded, &diag) catch {
        printStderr("vendor-state-capture: {s}\n", .{diag.message});
        return 2;
    };
    return 0;
}

pub fn deriveMain(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    var index_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var check_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--index")) {
            if (i + 1 >= args.len) {
                printStderr("derive-vendor-state-reference: missing --index value\n", .{});
                return 1;
            }
            i += 1;
            index_path = args[i];
        } else if (std.mem.eql(u8, arg, "--output")) {
            if (i + 1 >= args.len) {
                printStderr("derive-vendor-state-reference: missing --output value\n", .{});
                return 1;
            }
            i += 1;
            output_path = args[i];
        } else if (std.mem.eql(u8, arg, "--check")) {
            if (i + 1 >= args.len) {
                printStderr("derive-vendor-state-reference: missing --check value\n", .{});
                return 1;
            }
            i += 1;
            check_path = args[i];
        } else {
            printStderr("derive-vendor-state-reference: unknown argument: {s}\n", .{arg});
            return 1;
        }
    }
    if (index_path == null or (output_path == null and check_path == null) or (output_path != null and check_path != null)) {
        printStderr("derive-vendor-state-reference: --index and exactly one of --output or --check are required\n", .{});
        return 1;
    }

    var diag: Diagnostic = .{};
    const doc = derive(allocator, index_path.?, &diag) catch {
        printStderr("derive-vendor-state-reference: {s}\n", .{diag.message});
        return 1;
    };
    const encoded = canonicalJson(allocator, doc) catch {
        printStderr("derive-vendor-state-reference: document cannot be encoded as canonical JSON\n", .{});
        return 1;
    };
    if (check_path) |chk| {
        const expected = readRegularBytes(allocator, chk, encoded.len, "reference check file", &diag) catch {
            printStderr("derive-vendor-state-reference: {s}\n", .{diag.message});
            return 1;
        };
        if (!std.mem.eql(u8, expected, encoded)) {
            printStderr("derive-vendor-state-reference: derived reference differs from {s}\n", .{chk});
            return 1;
        }
    } else {
        writeNewFile(allocator, output_path.?, encoded, &diag) catch {
            printStderr("derive-vendor-state-reference: {s}\n", .{diag.message});
            return 1;
        };
    }
    return 0;
}

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .linux) return error.LinuxRequired;
    const arena = init.arena.allocator();
    var args_list: std.ArrayList([]const u8) = .empty;
    var args_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    defer args_it.deinit();
    _ = args_it.next();
    while (args_it.next()) |arg| {
        try args_list.append(arena, arg);
    }
    const args = args_list.items;
    if (args.len == 0) {
        printStderr("vendor-state-capture: subcommand or arguments required\n", .{});
        std.process.exit(2);
    }
    if (std.mem.eql(u8, args[0], "capture")) {
        std.process.exit(captureMain(arena, args[1..]));
    }
    if (std.mem.eql(u8, args[0], "derive")) {
        std.process.exit(deriveMain(arena, args[1..]));
    }
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--index") or std.mem.eql(u8, arg, "--check")) {
            std.process.exit(deriveMain(arena, args));
        }
    }
    std.process.exit(captureMain(arena, args));
}

// ============================================================================
// Unit tests
// ============================================================================

fn mkdirAllAt(dir_fd: linux.fd_t, rel_path: []const u8) !void {
    var cur = try dupFd(dir_fd);
    defer closeFd(cur);
    var it = std.mem.splitScalar(u8, rel_path, '/');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        @memcpy(buf[0..part.len], part);
        buf[part.len] = 0;
        const part_z: [*:0]const u8 = buf[0..part.len :0];
        const rc = linux.mkdirat(cur, part_z, 0o755);
        switch (linux.errno(rc)) {
            .SUCCESS, .EXIST => {},
            else => return error.MkdirFailed,
        }
        const next = try openatFd(cur, part, directoryFlags(), 0);
        closeFd(cur);
        cur = next;
    }
}

fn writeFileAt(dir_fd: linux.fd_t, rel_path: []const u8, data: []const u8, mode: linux.mode_t) !void {
    if (std.fs.path.dirname(rel_path)) |parent| {
        try mkdirAllAt(dir_fd, parent);
    }
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(buf[0..rel_path.len], rel_path);
    buf[rel_path.len] = 0;
    const rel_z: [*:0]const u8 = buf[0..rel_path.len :0];
    const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true };
    const fd_rc = linux.openat(dir_fd, rel_z, flags, mode);
    if (linux.errno(fd_rc) != .SUCCESS) return error.WriteFailed;
    const fd: linux.fd_t = @intCast(fd_rc);
    defer closeFd(fd);
    var written: usize = 0;
    while (written < data.len) {
        const wrc = linux.write(fd, data[written..].ptr, data.len - written);
        if (linux.errno(wrc) != .SUCCESS or wrc == 0) return error.WriteFailed;
        written += wrc;
    }
    _ = linux.fchmod(fd, mode);
}

fn symlinkAt(dir_fd: linux.fd_t, target: []const u8, link_path: []const u8) !void {
    if (std.fs.path.dirname(link_path)) |parent| {
        try mkdirAllAt(dir_fd, parent);
    }
    var tbuf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(tbuf[0..target.len], target);
    tbuf[target.len] = 0;
    const target_z: [*:0]const u8 = tbuf[0..target.len :0];

    var lbuf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(lbuf[0..link_path.len], link_path);
    lbuf[link_path.len] = 0;
    const link_z: [*:0]const u8 = lbuf[0..link_path.len :0];

    if (linux.errno(linux.symlinkat(target_z, dir_fd, link_z)) != .SUCCESS) return error.SymlinkFailed;
}

fn hardlinkAt(old_dir_fd: linux.fd_t, old_path: []const u8, new_dir_fd: linux.fd_t, new_path: []const u8) !void {
    if (std.fs.path.dirname(new_path)) |parent| {
        try mkdirAllAt(new_dir_fd, parent);
    }
    var obuf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(obuf[0..old_path.len], old_path);
    obuf[old_path.len] = 0;
    const old_z: [*:0]const u8 = obuf[0..old_path.len :0];

    var nbuf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(nbuf[0..new_path.len], new_path);
    nbuf[new_path.len] = 0;
    const new_z: [*:0]const u8 = nbuf[0..new_path.len :0];

    if (linux.errno(linux.linkat(old_dir_fd, old_z, new_dir_fd, new_z, 0)) != .SUCCESS) return error.LinkFailed;
}

fn mkfifoAt(dir_fd: linux.fd_t, rel_path: []const u8) !void {
    if (std.fs.path.dirname(rel_path)) |parent| {
        try mkdirAllAt(dir_fd, parent);
    }
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(buf[0..rel_path.len], rel_path);
    buf[rel_path.len] = 0;
    const rel_z: [*:0]const u8 = buf[0..rel_path.len :0];
    if (linux.errno(linux.mknodat(dir_fd, rel_z, linux.S.IFIFO | 0o600, 0)) != .SUCCESS) return error.FifoFailed;
}

const FixtureRoot = struct { fd: linux.fd_t, abs: []const u8 };

fn createMinimalRoot(allocator: std.mem.Allocator, base_fd: linux.fd_t, base_abs: []const u8, name: []const u8) !FixtureRoot {
    const rel_info = try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/info", .{name});
    try mkdirAllAt(base_fd, rel_info);
    const fd = try openatFd(base_fd, name, directoryFlags(), 0);
    const abs = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ base_abs, name });
    return .{ .fd = fd, .abs = abs };
}

fn createFixtureRoot(allocator: std.mem.Allocator, base_fd: linux.fd_t, base_abs: []const u8, name: []const u8, reverse: bool) !FixtureRoot {
    const root = try createMinimalRoot(allocator, base_fd, base_abs, name);
    errdefer closeFd(root.fd);

    const Member = struct { filename: []const u8, contents: []const u8, mode: linux.mode_t };
    const members = [_]Member{
        .{ .filename = "format", .contents = "1\n", .mode = 0o644 },
        .{ .filename = "demo.control", .contents = "Package: demo\n", .mode = 0o644 },
        .{ .filename = "demo.list", .contents = "/usr/bin/editor\n", .mode = 0o644 },
        .{ .filename = "demo.md5sums", .contents = "00000000000000000000000000000000  usr/bin/editor\n", .mode = 0o644 },
        .{ .filename = "demo.conffiles", .contents = "/etc/demo.conf\n", .mode = 0o644 },
        .{ .filename = "demo.triggers", .contents = "interest /usr/share/demo\n", .mode = 0o644 },
        .{ .filename = "demo.preinst", .contents = "#!/bin/sh\nexit 0\n", .mode = 0o755 },
        .{ .filename = "demo.config", .contents = "#!/bin/sh\nexit 0\n", .mode = 0o755 },
        .{ .filename = "demo.alternatives", .contents = "Name: editor\nLink: /usr/bin/editor\nAlternative: /usr/bin/editor.real\n", .mode = 0o644 },
        .{ .filename = "demo.templates", .contents = "Template: demo/question\n", .mode = 0o644 },
        .{ .filename = "demo.vendor-state", .contents = "\x00opaque vendor metadata\n", .mode = 0o640 },
    };
    for (0..members.len) |idx| {
        const m = if (reverse) members[members.len - 1 - idx] else members[idx];
        const rel = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}", .{m.filename});
        try writeFileAt(root.fd, rel, m.contents, m.mode);
    }
    try writeFileAt(
        root.fd,
        "var/lib/dpkg/alternatives/editor",
        "auto\n/usr/bin/editor\neditor.1.gz\n/usr/share/man/man1/editor.1.gz\n\n/usr/bin/editor.real\n50\n/usr/share/man/man1/editor.real.1.gz\n",
        0o644,
    );
    try writeFileAt(root.fd, "usr/bin/editor.real", "fixture editor\n", 0o755);
    try writeFileAt(root.fd, "usr/share/man/man1/editor.real.1.gz", "fixture manual\n", 0o644);
    try symlinkAt(root.fd, "/etc/alternatives/editor", "usr/bin/editor");
    try symlinkAt(root.fd, "/etc/alternatives/editor.1.gz", "usr/share/man/man1/editor.1.gz");
    try symlinkAt(root.fd, "/usr/bin/editor.real", "etc/alternatives/editor");
    try symlinkAt(root.fd, "/usr/share/man/man1/editor.real.1.gz", "etc/alternatives/editor.1.gz");
    return root;
}

fn cwdAbsolutePath(allocator: std.mem.Allocator) ![]const u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const rc = linux.getcwd(&buf, buf.len);
    if (linux.errno(rc) != .SUCCESS) return error.GetCwdFailed;
    const slice = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&buf)), 0);
    return allocator.dupe(u8, slice);
}

test "vendor-state capture is deterministic, architecture-tagged, and records write witnesses" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cwd_abs = try cwdAbsolutePath(allocator);
    const base_abs = try std.fmt.allocPrint(allocator, "{s}/.zig-cache/tmp/{s}", .{ cwd_abs, tmp.sub_path });

    const first_root = try createFixtureRoot(allocator, tmp.dir.handle, base_abs, "first", false);
    defer closeFd(first_root.fd);
    const second_root = try createFixtureRoot(allocator, tmp.dir.handle, base_abs, "second", true);
    defer closeFd(second_root.fd);

    var diag: Diagnostic = .{};
    const first = try capture(allocator, first_root.abs, "amd64", Limits{}, &diag);
    const second = try capture(allocator, second_root.abs, "amd64", Limits{}, &diag);

    const first_json = try canonicalJson(allocator, first);
    const second_json = try canonicalJson(allocator, second);
    try std.testing.expectEqualSlices(u8, first_json, second_json);
    try std.testing.expectEqualStrings(CAPTURE_SCHEMA, first.object.get("schema").?.string);
    try std.testing.expectEqualStrings("amd64", first.object.get("architecture").?.string);
    try std.testing.expectEqual(@as(i64, 1), first.object.get("version").?.integer);

    const ww = first.object.get("write_witnesses").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), ww.len);
    try std.testing.expectEqualStrings("dev/null", ww[0].object.get("path").?.string);
    try std.testing.expectEqualStrings("absent", ww[0].object.get("kind").?.string);

    // Record regular dev/null write witness
    const witness_root = try createFixtureRoot(allocator, tmp.dir.handle, base_abs, "witness", false);
    defer closeFd(witness_root.fd);
    try writeFileAt(witness_root.fd, "dev/null", "", 0o600);
    const witness_doc = try capture(allocator, witness_root.abs, "amd64", Limits{}, &diag);
    const ww_reg = witness_doc.object.get("write_witnesses").?.array.items[0].object;
    try std.testing.expectEqualStrings("regular", ww_reg.get("kind").?.string);
    try std.testing.expectEqualStrings("0600", ww_reg.get("mode").?.string);
    try std.testing.expectEqual(@as(i64, 0), ww_reg.get("size").?.integer);

    // CLI output and refusals
    const out_path = try std.fmt.allocPrint(allocator, "{s}/vendor-state.json", .{base_abs});
    try std.testing.expectEqual(@as(u8, 0), captureMain(allocator, &.{
        "--reference-root",
        first_root.abs,
        "--architecture",
        "amd64",
        "--output",
        out_path,
    }));
    // Repeated output must fail closed
    try std.testing.expectEqual(@as(u8, 2), captureMain(allocator, &.{
        "--reference-root",
        first_root.abs,
        "--architecture",
        "amd64",
        "--output",
        out_path,
    }));
    // Output inside reference root must fail closed
    const inside_out = try std.fmt.allocPrint(allocator, "{s}/capture.json", .{first_root.abs});
    try std.testing.expectEqual(@as(u8, 2), captureMain(allocator, &.{
        "--reference-root",
        first_root.abs,
        "--architecture",
        "amd64",
        "--output",
        inside_out,
    }));
}

test "vendor-state capture enforces bounds, traversal, etc ownership, hardlink, and special-file refusals" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cwd_abs = try cwdAbsolutePath(allocator);
    const base_abs = try std.fmt.allocPrint(allocator, "{s}/.zig-cache/tmp/{s}", .{ cwd_abs, tmp.sub_path });

    const bounds_root = try createFixtureRoot(allocator, tmp.dir.handle, base_abs, "bounds", false);
    defer closeFd(bounds_root.fd);
    try writeFileAt(bounds_root.fd, "var/lib/dpkg/alternatives/second", "/usr/bin/editor.real\n", 0o644);

    const Case = struct { limits: Limits, expected: []const u8 };
    const bound_cases = [_]Case{
        .{ .limits = .{ .max_control_members = 1 }, .expected = "control-member count limit exceeded" },
        .{ .limits = .{ .max_metadata_file_bytes = 1 }, .expected = "regular file exceeds limit" },
        .{ .limits = .{ .max_alternatives_records = 1 }, .expected = "alternatives-record count limit exceeded" },
        .{ .limits = .{ .max_total_metadata_bytes = 1 }, .expected = "aggregate regular-file limit exceeded" },
        .{ .limits = .{ .max_referenced_paths = 1 }, .expected = "alternative reference count limit exceeded" },
        .{ .limits = .{ .max_link_target_bytes = 5 }, .expected = "malformed absolute alternative path" },
        .{ .limits = .{ .max_linked_entries = 1 }, .expected = "linked-filesystem entry count limit exceeded" },
        .{ .limits = .{ .max_linked_file_bytes = 1 }, .expected = "regular file exceeds limit" },
        .{ .limits = .{ .max_total_linked_bytes = 1 }, .expected = "aggregate regular-file limit exceeded" },
        .{ .limits = .{ .max_link_hops = 1 }, .expected = "symlink hop limit exceeded" },
    };
    for (bound_cases) |c| {
        var diag: Diagnostic = .{};
        try std.testing.expectError(error.CaptureFailed, capture(allocator, bounds_root.abs, "amd64", c.limits, &diag));
        try std.testing.expect(std.mem.indexOf(u8, diag.message, c.expected) != null);
    }

    // Non-sensitive owned etc alternative succeeds
    const etc_root = try createMinimalRoot(allocator, tmp.dir.handle, base_abs, "etc-alt");
    defer closeFd(etc_root.fd);
    try writeFileAt(etc_root.fd, "var/lib/dpkg/info/libnewt0.52.list", "/etc/newt/palette.original\n/etc/newt/palette.ubuntu\n", 0o644);
    try writeFileAt(etc_root.fd, "var/lib/dpkg/alternatives/newt-palette", "auto\n/etc/newt/palette\n\n/etc/newt/palette.ubuntu\n50\n/etc/newt/palette.original\n20\n", 0o644);
    try symlinkAt(etc_root.fd, "/etc/alternatives/newt-palette", "etc/newt/palette");
    try symlinkAt(etc_root.fd, "/etc/newt/palette.ubuntu", "etc/alternatives/newt-palette");
    try writeFileAt(etc_root.fd, "etc/newt/palette.ubuntu", "root=white,black\n", 0o644);
    try writeFileAt(etc_root.fd, "etc/newt/palette.original", "root=white,blue\n", 0o644);
    {
        var diag: Diagnostic = .{};
        const doc = try capture(allocator, etc_root.abs, "amd64", Limits{}, &diag);
        const req = doc.object.get("linked_filesystem").?.object.get("requested_paths").?.array.items;
        try std.testing.expectEqual(@as(usize, 4), req.len);
    }

    // Unowned etc state rejected
    const unowned_root = try createMinimalRoot(allocator, tmp.dir.handle, base_abs, "etc-unowned");
    defer closeFd(unowned_root.fd);
    try writeFileAt(unowned_root.fd, "var/lib/dpkg/alternatives/ambient", "/etc/hostname\n", 0o644);
    try writeFileAt(unowned_root.fd, "etc/hostname", "runner-host\n", 0o644);
    {
        var diag: Diagnostic = .{};
        try std.testing.expectError(error.CaptureFailed, capture(allocator, unowned_root.abs, "amd64", Limits{}, &diag));
        try std.testing.expect(std.mem.indexOf(u8, diag.message, "unowned etc state") != null);
    }

    // Hardlink and FIFO rejected
    const hl_root = try createMinimalRoot(allocator, tmp.dir.handle, base_abs, "hardlink");
    defer closeFd(hl_root.fd);
    try writeFileAt(hl_root.fd, "var/lib/dpkg/info/demo.config", "metadata\n", 0o644);
    try hardlinkAt(hl_root.fd, "var/lib/dpkg/info/demo.config", hl_root.fd, "var/lib/dpkg/info/demo.config2");
    {
        var diag: Diagnostic = .{};
        try std.testing.expectError(error.CaptureFailed, capture(allocator, hl_root.abs, "amd64", Limits{}, &diag));
        try std.testing.expect(std.mem.indexOf(u8, diag.message, "hard-linked regular file") != null);
    }

    const fifo_root = try createMinimalRoot(allocator, tmp.dir.handle, base_abs, "fifo");
    defer closeFd(fifo_root.fd);
    try writeFileAt(fifo_root.fd, "var/lib/dpkg/alternatives/editor", "/usr/bin/editor\n", 0o644);
    try mkfifoAt(fifo_root.fd, "usr/bin/editor");
    {
        var diag: Diagnostic = .{};
        try std.testing.expectError(error.CaptureFailed, capture(allocator, fifo_root.abs, "amd64", Limits{}, &diag));
        try std.testing.expect(std.mem.indexOf(u8, diag.message, "linked path is a special file") != null);
    }
}

test "pinned vendor-state reference derivation reproduces reference-v1.json byte-for-byte" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var diag: Diagnostic = .{};
    const index_path = "tools/fixtures/vendor-state/index-v1.json";
    const ref_path = "tools/fixtures/vendor-state/reference-v1.json";

    const derived = try derive(allocator, index_path, &diag);
    const encoded = try canonicalJson(allocator, derived);
    const expected_raw = try readRegularBytes(allocator, ref_path, encoded.len + 1024, "reference-v1.json", &diag);
    try std.testing.expectEqualSlices(u8, expected_raw, encoded);

    try std.testing.expectEqual(@as(u8, 0), deriveMain(allocator, &.{
        "--index",
        index_path,
        "--check",
        ref_path,
    }));
}

test "vendor-state reference derivation rejects malformed, unsafe, and mutated inputs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cwd_abs = try cwdAbsolutePath(allocator);
    const base_abs = try std.fmt.allocPrint(allocator, "{s}/.zig-cache/tmp/{s}", .{ cwd_abs, tmp.sub_path });

    // Non-standard JSON numeric constant (NaN)
    try writeFileAt(tmp.dir.handle, "nan/index-v1.json", "{\"source\": NaN}\n", 0o644);
    {
        var diag: Diagnostic = .{};
        const nan_idx = try std.fmt.allocPrint(allocator, "{s}/nan/index-v1.json", .{base_abs});
        try std.testing.expectError(error.DerivationFailed, derive(allocator, nan_idx, &diag));
        try std.testing.expect(std.mem.indexOf(u8, diag.message, "non-standard JSON numeric constant") != null);
    }

    // Symlink index rejected
    const real_idx_abs = try std.fmt.allocPrint(allocator, "{s}/tools/fixtures/vendor-state/index-v1.json", .{cwd_abs});
    try symlinkAt(tmp.dir.handle, real_idx_abs, "sym/index-v1.json");
    {
        var diag: Diagnostic = .{};
        const sym_idx = try std.fmt.allocPrint(allocator, "{s}/sym/index-v1.json", .{base_abs});
        try std.testing.expectError(error.DerivationFailed, derive(allocator, sym_idx, &diag));
        try std.testing.expect(std.mem.indexOf(u8, diag.message, "not a regular file") != null);
    }

    // FIFO index rejected
    try mkfifoAt(tmp.dir.handle, "fifo/index-v1.json");
    {
        var diag: Diagnostic = .{};
        const fifo_idx = try std.fmt.allocPrint(allocator, "{s}/fifo/index-v1.json", .{base_abs});
        try std.testing.expectError(error.DerivationFailed, derive(allocator, fifo_idx, &diag));
        try std.testing.expect(std.mem.indexOf(u8, diag.message, "not a regular file") != null);
    }

    // Private URI with query parameter rejected
    {
        var diag: Diagnostic = .{};
        const orig = try readDocument(allocator, "tools/fixtures/vendor-state/index-v1.json", MAX_INDEX_BYTES, "index", &diag);
        var mutated_doc = orig.doc;
        var src = mutated_doc.get("source").?.object;
        try src.put(allocator, "snapshot_uri", .{ .string = "https://snapshot.ubuntu.com/ubuntu/20260816T000000Z?token=secret" });
        try mutated_doc.put(allocator, "source", .{ .object = src });
        const raw = try canonicalJson(allocator, .{ .object = mutated_doc });
        try writeFileAt(tmp.dir.handle, "priv/index-v1.json", raw, 0o644);
        const priv_idx = try std.fmt.allocPrint(allocator, "{s}/priv/index-v1.json", .{base_abs});
        try std.testing.expectError(error.DerivationFailed, derive(allocator, priv_idx, &diag));
        try std.testing.expect(std.mem.indexOf(u8, diag.message, "public HTTPS URI") != null);
    }
}
