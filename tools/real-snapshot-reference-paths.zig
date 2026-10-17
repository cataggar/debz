//! Descriptor-rooted, no-follow path validation, protected reference tree checks,
//! and prehashed minisign signature verification for privileged snapshot staging.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const maximum_artifact_bytes: u64 = 512 * 1024 * 1024;
pub const maximum_path_bytes: usize = 4096;
pub const writable_mask: u16 = 0o022;
pub const special_mask: u16 = 0o7000;

pub const Error = error{
    NoncanonicalReferencePath,
    UnprotectedReferenceRoot,
    UnprotectedReferencePath,
    WrongReferenceFileType,
    KeyringPinMismatch,
    CompilerNotExecutable,
    ToolchainSymlinkEscapes,
    InvalidBoundedReferenceRead,
    InvalidReferenceDatabaseFile,
    ReferenceFileChanged,
    ReferenceSyscallRefused,
    MalformedMinisignPublicKey,
    UnsupportedMinisignPublicKeyAlgorithm,
    MalformedMinisignSignatureFile,
    MalformedMinisignSignature,
    LegacyMinisignSignatureRefused,
    SignatureKeyIdMismatch,
    TrustedCommentMismatch,
    MalformedMinisignGlobalSignature,
    ArtifactNameMismatch,
    InvalidArtifactSizePin,
    ArtifactSizeOrDigestMismatch,
    Ed25519VerificationFailed,
    PackageManifestExists,
};

var test_root_override: ?[]const u8 = null;
var test_force_root_owned_lstat: bool = false;

pub fn setTestRootOverride(prefix: ?[]const u8) void {
    if (builtin.is_test) test_root_override = prefix;
}

fn syscall(result: usize) !usize {
    return switch (linux.errno(result)) {
        .SUCCESS => result,
        .EXIST => error.PackageManifestExists,
        else => error.ReferenceSyscallRefused,
    };
}

fn rawStatx(dir_fd: i32, path: [*:0]const u8, flags: u32) !linux.Statx {
    var value = std.mem.zeroes(linux.Statx);
    _ = try syscall(linux.statx(dir_fd, path, flags, .BASIC_STATS, &value));
    return value;
}

fn isWithinPath(candidate: []const u8, base: []const u8) bool {
    if (std.mem.eql(u8, base, "/")) return candidate.len > 0 and candidate[0] == '/';
    if (!std.mem.startsWith(u8, candidate, base)) return false;
    return candidate.len == base.len or candidate[base.len] == '/';
}

pub fn fstat(fd: i32) !linux.Statx {
    var value = try rawStatx(fd, "", linux.AT.EMPTY_PATH | linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT);
    if (builtin.is_test) {
        if (test_root_override) |root_prefix| {
            value.uid = 0;
            value.gid = 0;
            var proc_buf: [64]u8 = undefined;
            const proc_slice = std.fmt.bufPrint(&proc_buf, "/proc/self/fd/{d}\x00", .{fd}) catch return value;
            const proc_path: [*:0]const u8 = @ptrCast(proc_slice.ptr);
            var link_buf: [maximum_path_bytes]u8 = undefined;
            const link_rc = linux.readlink(proc_path, &link_buf, link_buf.len);
            if (linux.errno(link_rc) == .SUCCESS) {
                const resolved = link_buf[0..link_rc];
                if (!isWithinPath(resolved, root_prefix)) {
                    value.mode &= ~writable_mask;
                }
            }
        }
    }
    return value;
}

pub fn lstatPath(path: []const u8) !linux.Statx {
    if (path.len == 0 or path.len >= maximum_path_bytes) return error.NoncanonicalReferencePath;
    var buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&buf);
    var value = try rawStatx(linux.AT.FDCWD, path_z, linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT);
    if (builtin.is_test) {
        if (test_force_root_owned_lstat) {
            value.uid = 0;
            value.gid = 0;
        } else if (test_root_override) |root_prefix| {
            value.uid = 0;
            value.gid = 0;
            if (!isWithinPath(path, root_prefix)) {
                value.mode &= ~writable_mask;
            }
        }
    }
    return value;
}

fn validateRelativeCanonical(relative: []const u8) !void {
    if (relative.len == 0 or relative.len >= maximum_path_bytes) return error.NoncanonicalReferencePath;
    if (relative[0] == '/' or relative[relative.len - 1] == '/') return error.NoncanonicalReferencePath;
    var it = std.mem.splitScalar(u8, relative, '/');
    while (it.next()) |part| {
        if (part.len == 0 or part.len > 255 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, ".."))
            return error.NoncanonicalReferencePath;
        if (std.mem.indexOfScalar(u8, part, 0) != null)
            return error.NoncanonicalReferencePath;
    }
}

pub fn isCanonicalAbsolute(path: []const u8) bool {
    if (path.len == 0 or path.len >= maximum_path_bytes or path[0] != '/') return false;
    if (std.mem.eql(u8, path, "/")) return true;
    validateRelativeCanonical(path[1..]) catch return false;
    return true;
}

fn openComponentAt(dir_fd: i32, part: []const u8, directory: bool) !i32 {
    if (part.len == 0 or part.len > 255) return error.NoncanonicalReferencePath;
    var buf: [256]u8 = undefined;
    @memcpy(buf[0..part.len], part);
    buf[part.len] = 0;
    const part_z: [*:0]const u8 = @ptrCast(&buf);
    const flags: linux.O = .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .CLOEXEC = true,
        .DIRECTORY = directory,
    };
    return @intCast(try syscall(linux.openat(dir_fd, part_z, flags, 0)));
}

pub fn openBeneath(root_fd: i32, relative: []const u8, directory: bool) !i32 {
    try validateRelativeCanonical(relative);
    var current: i32 = @intCast(try syscall(linux.fcntl(root_fd, linux.F.DUPFD_CLOEXEC, @as(usize, 0))));
    errdefer if (current != -1) {
        _ = linux.close(current);
    };
    var it = std.mem.splitScalar(u8, relative, '/');
    while (it.next()) |part| {
        const is_last = it.rest().len == 0;
        const next_fd = try openComponentAt(current, part, !is_last or directory);
        _ = linux.close(current);
        current = next_fd;
    }
    const result = current;
    current = -1;
    return result;
}

pub fn openAbsolute(path: []const u8, directory: bool) !i32 {
    if (!isCanonicalAbsolute(path)) return error.NoncanonicalReferencePath;
    const root_flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const root_fd: i32 = @intCast(try syscall(linux.openat(linux.AT.FDCWD, "/", root_flags, 0)));
    defer _ = linux.close(root_fd);
    if (std.mem.eql(u8, path, "/")) {
        if (!directory) return error.NoncanonicalReferencePath;
        return @intCast(try syscall(linux.fcntl(root_fd, linux.F.DUPFD_CLOEXEC, @as(usize, 0))));
    }
    return openBeneath(root_fd, path[1..], directory);
}

pub fn openProtected(path: []const u8, directory: bool) !i32 {
    if (path.len == 0 or path[0] != '/') return error.NoncanonicalReferencePath;
    if (!isCanonicalAbsolute(path)) return error.NoncanonicalReferencePath;
    const root_flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    var current: i32 = @intCast(try syscall(linux.openat(linux.AT.FDCWD, "/", root_flags, 0)));
    errdefer if (current != -1) {
        _ = linux.close(current);
    };
    const root_meta = try fstat(current);
    if (root_meta.uid != 0 or root_meta.gid != 0 or (root_meta.mode & writable_mask) != 0)
        return error.UnprotectedReferenceRoot;
    if (!std.mem.eql(u8, path, "/")) {
        var it = std.mem.splitScalar(u8, path[1..], '/');
        while (it.next()) |part| {
            const is_last = it.rest().len == 0;
            const next_fd = try openComponentAt(current, part, !is_last or directory);
            _ = linux.close(current);
            current = next_fd;
            const meta = try fstat(current);
            if (meta.uid != 0 or meta.gid != 0 or (meta.mode & writable_mask) != 0 or
                (!is_last and (meta.mode & linux.S.IFMT) != linux.S.IFDIR))
            {
                return error.UnprotectedReferencePath;
            }
        }
    }
    const result_meta = try fstat(current);
    if ((directory and (result_meta.mode & linux.S.IFMT) != linux.S.IFDIR) or
        (!directory and (result_meta.mode & linux.S.IFMT) != linux.S.IFREG))
    {
        return error.WrongReferenceFileType;
    }
    const result_fd = current;
    current = -1;
    return result_fd;
}

pub fn protected(path: []const u8, directory: bool) !linux.Statx {
    const fd = try openProtected(path, directory);
    defer _ = linux.close(fd);
    return fstat(fd);
}

pub fn verifyKeyring(path: []const u8, size: usize, expected_digest: []const u8) ![64]u8 {
    const fd = try openProtected(path, false);
    defer _ = linux.close(fd);
    const meta = try fstat(fd);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var observed: usize = 0;
    var buf: [64 * 1024]u8 = undefined;
    while (observed <= size) {
        const remaining = (size + 1) - observed;
        const chunk_len = @min(buf.len, remaining);
        const got = try syscall(linux.read(fd, &buf, chunk_len));
        if (got == 0) break;
        hasher.update(buf[0..got]);
        observed += got;
    }
    var digest_bytes: [32]u8 = undefined;
    hasher.final(&digest_bytes);
    const actual_hex = std.fmt.bytesToHex(digest_bytes, .lower);
    if (meta.size != size or observed != size or !std.mem.eql(u8, &actual_hex, expected_digest))
        return error.KeyringPinMismatch;
    return actual_hex;
}

fn readlinkAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (path.len == 0 or path.len >= maximum_path_bytes) return error.NoncanonicalReferencePath;
    var path_buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_buf);
    var link_buf: [maximum_path_bytes]u8 = undefined;
    const len = try syscall(linux.readlink(path_z, &link_buf, link_buf.len));
    return allocator.dupe(u8, link_buf[0..len]);
}

fn resolveStrictPathAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var current = try allocator.dupe(u8, path);
    errdefer allocator.free(current);
    var hops: usize = 0;
    while (hops < 40) : (hops += 1) {
        const meta = try lstatPath(current);
        if ((meta.mode & linux.S.IFMT) != linux.S.IFLNK) {
            return current;
        }
        const target = try readlinkAlloc(allocator, current);
        defer allocator.free(target);
        const next = if (target.len > 0 and target[0] == '/')
            try std.fs.path.resolve(allocator, &.{target})
        else blk: {
            const parent = std.fs.path.dirname(current) orelse "/";
            break :blk try std.fs.path.resolve(allocator, &.{ parent, target });
        };
        allocator.free(current);
        current = next;
    }
    return error.ReferenceSyscallRefused;
}

const WalkEntry = struct {
    path: []u8,
    meta: linux.Statx,

    fn deinit(self: WalkEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
    }
};

fn collectWalkEntries(allocator: std.mem.Allocator, root_path: []const u8) ![]WalkEntry {
    var list: std.ArrayList(WalkEntry) = .empty;
    errdefer {
        for (list.items) |item| item.deinit(allocator);
        list.deinit(allocator);
    }
    var queue: std.ArrayList([]u8) = .empty;
    defer {
        for (queue.items) |dir_path| allocator.free(dir_path);
        queue.deinit(allocator);
    }
    try queue.append(allocator, try allocator.dupe(u8, root_path));
    var q_index: usize = 0;
    while (q_index < queue.items.len) : (q_index += 1) {
        const current_dir = queue.items[q_index];
        const fd = try openAbsolute(current_dir, true);
        defer _ = linux.close(fd);
        var dents_buf: [8192]u8 = undefined;
        while (true) {
            const nread = try syscall(linux.getdents64(fd, &dents_buf, dents_buf.len));
            if (nread == 0) break;
            var bpos: usize = 0;
            while (bpos < nread) {
                const dent: *align(1) const linux.dirent64 = @ptrCast(&dents_buf[bpos]);
                const name_ptr: [*:0]const u8 = @ptrCast(&dent.name);
                const name = std.mem.span(name_ptr);
                bpos += dent.reclen;
                if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
                const child_path = if (std.mem.eql(u8, current_dir, "/"))
                    try std.fmt.allocPrint(allocator, "/{s}", .{name})
                else
                    try std.fmt.allocPrint(allocator, "{s}/{s}", .{ current_dir, name });
                errdefer allocator.free(child_path);
                const meta = try lstatPath(child_path);
                if ((meta.mode & linux.S.IFMT) == linux.S.IFDIR) {
                    try queue.append(allocator, try allocator.dupe(u8, child_path));
                }
                try list.append(allocator, .{ .path = child_path, .meta = meta });
            }
        }
    }
    return list.toOwnedSlice(allocator);
}

pub fn toolchain(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const meta = try protected(path, false);
    if ((meta.mode & 0o111) == 0) return error.CompilerNotExecutable;
    const parent = std.fs.path.dirname(path) orelse return error.NoncanonicalReferencePath;
    const library = try std.fs.path.join(allocator, &.{ parent, "lib" });
    errdefer allocator.free(library);
    _ = try protected(library, true);
    const entries = try collectWalkEntries(allocator, library);
    defer {
        for (entries) |entry| entry.deinit(allocator);
        allocator.free(entries);
    }
    for (entries) |entry| {
        if ((entry.meta.mode & linux.S.IFMT) == linux.S.IFLNK) {
            const target = try resolveStrictPathAlloc(allocator, entry.path);
            defer allocator.free(target);
            if (!isWithinPath(target, library)) return error.ToolchainSymlinkEscapes;
            const target_meta = try lstatPath(target);
            _ = try protected(target, (target_meta.mode & linux.S.IFMT) == linux.S.IFDIR);
        } else {
            _ = try protected(entry.path, (entry.meta.mode & linux.S.IFMT) == linux.S.IFDIR);
        }
    }
    return library;
}

pub fn readRootFile(allocator: std.mem.Allocator, root: []const u8, relative: []const u8, limit: usize) ![]u8 {
    const root_fd = try openAbsolute(root, true);
    defer _ = linux.close(root_fd);
    const fd = try openBeneath(root_fd, relative, false);
    defer _ = linux.close(fd);
    const meta = try fstat(fd);
    if ((meta.mode & linux.S.IFMT) != linux.S.IFREG or meta.size > limit)
        return error.InvalidReferenceDatabaseFile;
    var data: std.ArrayList(u8) = .empty;
    errdefer data.deinit(allocator);
    var buf: [64 * 1024]u8 = undefined;
    while (data.items.len <= limit) {
        const remaining = (limit + 1) - data.items.len;
        const chunk_len = @min(buf.len, remaining);
        const got = try syscall(linux.read(fd, &buf, chunk_len));
        if (got == 0) break;
        try data.appendSlice(allocator, buf[0..got]);
    }
    if (data.items.len != meta.size) return error.ReferenceFileChanged;
    return data.toOwnedSlice(allocator);
}

pub fn formatFileMode(mode: u16) [10]u8 {
    var out: [10]u8 = .{ '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' };
    out[0] = switch (mode & linux.S.IFMT) {
        linux.S.IFDIR => 'd',
        linux.S.IFCHR => 'c',
        linux.S.IFBLK => 'b',
        linux.S.IFREG => '-',
        linux.S.IFIFO => 'p',
        linux.S.IFLNK => 'l',
        linux.S.IFSOCK => 's',
        else => '?',
    };
    if ((mode & 0o0400) != 0) out[1] = 'r';
    if ((mode & 0o0200) != 0) out[2] = 'w';
    if ((mode & 0o4000) != 0) {
        out[3] = if ((mode & 0o0100) != 0) 's' else 'S';
    } else if ((mode & 0o0100) != 0) {
        out[3] = 'x';
    }
    if ((mode & 0o0040) != 0) out[4] = 'r';
    if ((mode & 0o0020) != 0) out[5] = 'w';
    if ((mode & 0o2000) != 0) {
        out[6] = if ((mode & 0o0010) != 0) 's' else 'S';
    } else if ((mode & 0o0010) != 0) {
        out[6] = 'x';
    }
    if ((mode & 0o0004) != 0) out[7] = 'r';
    if ((mode & 0o0002) != 0) out[8] = 'w';
    if ((mode & 0o1000) != 0) {
        out[9] = if ((mode & 0o0001) != 0) 't' else 'T';
    } else if ((mode & 0o0001) != 0) {
        out[9] = 'x';
    }
    return out;
}

pub fn describeAlloc(allocator: std.mem.Allocator, path: []const u8, meta: linux.Statx) ![]u8 {
    const mode_chars = formatFileMode(meta.mode);
    return std.fmt.allocPrint(allocator, "{s} {d}:{d} {s}", .{ mode_chars, meta.uid, meta.gid, path });
}

pub fn freeStrings(allocator: std.mem.Allocator, items: [][]u8) void {
    for (items) |item| allocator.free(item);
    allocator.free(items);
}

pub fn ancestry(allocator: std.mem.Allocator, output: *std.ArrayList(u8), tree: []const u8) ![][]u8 {
    var failures: std.ArrayList([]u8) = .empty;
    errdefer {
        for (failures.items) |item| allocator.free(item);
        failures.deinit(allocator);
    }
    if (!isCanonicalAbsolute(tree) or std.mem.eql(u8, tree, "/")) {
        try failures.append(allocator, try std.fmt.allocPrint(
            allocator,
            "tree path is not canonical and absolute: {s}",
            .{tree},
        ));
        return failures.toOwnedSlice(allocator);
    }
    var current: []const u8 = tree;
    while (true) {
        const meta = try lstatPath(current);
        const desc = try describeAlloc(allocator, current, meta);
        defer allocator.free(desc);
        try output.appendSlice(allocator, desc);
        try output.append(allocator, '\n');
        if (meta.uid != 0 or meta.gid != 0 or (meta.mode & linux.S.IFMT) != linux.S.IFDIR or (meta.mode & writable_mask) != 0) {
            try failures.append(allocator, try std.fmt.allocPrint(
                allocator,
                "unprotected ancestor: {s}",
                .{desc},
            ));
        }
        if (std.mem.eql(u8, current, tree) and (meta.mode & 0o7777) != 0o700) {
            try failures.append(allocator, try std.fmt.allocPrint(
                allocator,
                "protected tree must be mode 0700: {s}",
                .{desc},
            ));
        }
        if (std.mem.eql(u8, current, "/")) break;
        current = std.fs.path.dirname(current) orelse "/";
    }
    return failures.toOwnedSlice(allocator);
}

pub fn treeFailures(allocator: std.mem.Allocator, output: *std.ArrayList(u8), tree: []const u8) ![][]u8 {
    var failures: std.ArrayList([]u8) = .empty;
    errdefer {
        for (failures.items) |item| allocator.free(item);
        failures.deinit(allocator);
    }
    const root_meta = try lstatPath(tree);
    const entries = try collectWalkEntries(allocator, tree);
    defer {
        for (entries) |entry| entry.deinit(allocator);
        allocator.free(entries);
    }
    var exceptions: usize = 0;
    for (entries) |entry| {
        const desc = try describeAlloc(allocator, entry.path, entry.meta);
        defer allocator.free(desc);
        if (entry.meta.dev_major != root_meta.dev_major or entry.meta.dev_minor != root_meta.dev_minor) {
            try failures.append(allocator, try std.fmt.allocPrint(
                allocator,
                "mount beneath protected tree: {s}",
                .{entry.path},
            ));
        }
        if (entry.meta.uid != 0 or entry.meta.gid != 0) {
            try failures.append(allocator, try std.fmt.allocPrint(
                allocator,
                "non-root entry: {s}",
                .{desc},
            ));
        } else if ((entry.meta.mode & linux.S.IFMT) == linux.S.IFLNK or (entry.meta.mode & writable_mask) == 0) {
            continue;
        } else if ((entry.meta.mode & linux.S.IFMT) == linux.S.IFDIR and (entry.meta.mode & 0o1000) != 0) {
            exceptions += 1;
            const line = try std.fmt.allocPrint(allocator, "sticky-directory {s}\n", .{desc});
            defer allocator.free(line);
            try output.appendSlice(allocator, line);
        } else if ((entry.meta.mode & linux.S.IFMT) == linux.S.IFCHR and entry.meta.rdev_major == 1 and entry.meta.rdev_minor == 3) {
            exceptions += 1;
            const line = try std.fmt.allocPrint(allocator, "null-device {s}\n", .{desc});
            defer allocator.free(line);
            try output.appendSlice(allocator, line);
        } else {
            try failures.append(allocator, try std.fmt.allocPrint(
                allocator,
                "group/other-writable entry: {s}",
                .{desc},
            ));
        }
    }
    const summary = try std.fmt.allocPrint(
        allocator,
        "tree={s} entries={d} audited_exceptions={d} failures={d}\n",
        .{ tree, entries.len, exceptions, failures.items.len },
    );
    defer allocator.free(summary);
    try output.appendSlice(allocator, summary);
    return failures.toOwnedSlice(allocator);
}

fn lessThanWalkEntry(_: void, left: WalkEntry, right: WalkEntry) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

fn sha256RegularNoFollow(path: []const u8) ![64]u8 {
    const fd = try openAbsolute(path, false);
    defer _ = linux.close(fd);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const got = try syscall(linux.read(fd, &buf, buf.len));
        if (got == 0) break;
        hasher.update(buf[0..got]);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

fn writeExclusiveNoFollow(path: []const u8, payload: []const u8) !void {
    if (path.len == 0 or path.len >= maximum_path_bytes) return error.NoncanonicalReferencePath;
    var buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&buf);
    const flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const fd: i32 = @intCast(try syscall(linux.openat(linux.AT.FDCWD, path_z, flags, 0o644)));
    defer _ = linux.close(fd);
    var written: usize = 0;
    while (written < payload.len) {
        const count = try syscall(linux.write(fd, payload[written..].ptr, payload.len - written));
        if (count == 0) return error.ReferenceSyscallRefused;
        written += count;
    }
}

pub fn packageFailures(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    directory: []const u8,
    manifest_output: []const u8,
) ![][]u8 {
    var failures: std.ArrayList([]u8) = .empty;
    errdefer {
        for (failures.items) |item| allocator.free(item);
        failures.deinit(allocator);
    }
    const base = resolveStrictPathAlloc(allocator, directory) catch {
        try failures.append(allocator, try std.fmt.allocPrint(
            allocator,
            "package directory is not canonical: {s}",
            .{directory},
        ));
        return failures.toOwnedSlice(allocator);
    };
    defer allocator.free(base);
    if (!isCanonicalAbsolute(directory) or !std.mem.eql(u8, base, directory)) {
        try failures.append(allocator, try std.fmt.allocPrint(
            allocator,
            "package directory is not canonical: {s}",
            .{directory},
        ));
        return failures.toOwnedSlice(allocator);
    }
    const entries = try collectWalkEntries(allocator, directory);
    defer {
        for (entries) |entry| entry.deinit(allocator);
        allocator.free(entries);
    }
    std.mem.sort(WalkEntry, entries, {}, lessThanWalkEntry);
    var manifest_bytes: std.ArrayList(u8) = .empty;
    defer manifest_bytes.deinit(allocator);
    var lines_count: usize = 0;
    var executables: usize = 0;
    for (entries) |entry| {
        const relative = entry.path[directory.len + 1 ..];
        const mode: u16 = entry.meta.mode & 0o7777;
        const desc = try describeAlloc(allocator, entry.path, entry.meta);
        defer allocator.free(desc);
        if (entry.meta.uid != 0 or entry.meta.gid != 0 or
            ((entry.meta.mode & linux.S.IFMT) != linux.S.IFLNK and (entry.meta.mode & (writable_mask | special_mask)) != 0))
        {
            try failures.append(allocator, try std.fmt.allocPrint(
                allocator,
                "untightened package entry: {s}",
                .{desc},
            ));
        }
        switch (entry.meta.mode & linux.S.IFMT) {
            linux.S.IFLNK => {
                const target = try readlinkAlloc(allocator, entry.path);
                defer allocator.free(target);
                const parent = std.fs.path.dirname(entry.path) orelse directory;
                const resolved = try std.fs.path.resolve(allocator, &.{ parent, target });
                defer allocator.free(resolved);
                if ((target.len > 0 and target[0] == '/') or !isWithinPath(resolved, base)) {
                    try failures.append(allocator, try std.fmt.allocPrint(
                        allocator,
                        "package symlink escapes its tree: {s} -> {s}",
                        .{ entry.path, target },
                    ));
                }
                const line = try std.fmt.allocPrint(allocator, "link {s} {s}\n", .{ target, relative });
                defer allocator.free(line);
                try manifest_bytes.appendSlice(allocator, line);
                lines_count += 1;
            },
            linux.S.IFREG => {
                const digest = try sha256RegularNoFollow(entry.path);
                if ((mode & 0o111) != 0) executables += 1;
                const line = try std.fmt.allocPrint(allocator, "{o:0>4} {s} {s}\n", .{ mode, digest, relative });
                defer allocator.free(line);
                try manifest_bytes.appendSlice(allocator, line);
                lines_count += 1;
            },
            linux.S.IFDIR => {
                const line = try std.fmt.allocPrint(allocator, "{o:0>4} directory {s}\n", .{ mode, relative });
                defer allocator.free(line);
                try manifest_bytes.appendSlice(allocator, line);
                lines_count += 1;
            },
            else => {
                try failures.append(allocator, try std.fmt.allocPrint(
                    allocator,
                    "unexpected package file type: {s}",
                    .{desc},
                ));
            },
        }
    }
    if (lines_count == 0) {
        try failures.append(allocator, try std.fmt.allocPrint(
            allocator,
            "no fetched packages beneath {s}",
            .{directory},
        ));
    }
    try writeExclusiveNoFollow(manifest_output, manifest_bytes.items);
    const summary = try std.fmt.allocPrint(
        allocator,
        "packages={s} entries={d} executable_sources={d} failures={d}\n",
        .{ directory, lines_count, executables, failures.items.len },
    );
    defer allocator.free(summary);
    try output.appendSlice(allocator, summary);
    return failures.toOwnedSlice(allocator);
}

fn decodeBase64Exact(comptime size: usize, encoded: []const u8, err_tag: Error) Error![size]u8 {
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch return err_tag;
    if (decoded_len != size) return err_tag;
    var out: [size]u8 = undefined;
    std.base64.standard.Decoder.decode(&out, encoded) catch return err_tag;
    return out;
}

pub fn ed25519Verify(public_key: [32]u8, message: []const u8, signature: [64]u8) Error!void {
    const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return error.Ed25519VerificationFailed;
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
    sig.verify(message, pk) catch return error.Ed25519VerificationFailed;
}

fn validTimestampField(field: []const u8) bool {
    const prefix = "timestamp:";
    if (!std.mem.startsWith(u8, field, prefix)) return false;
    const digits = field[prefix.len..];
    if (digits.len == 0 or digits.len > 20) return false;
    for (digits) |ch| {
        if (!std.ascii.isDigit(ch)) return false;
    }
    return true;
}

fn readRegularNoFollowAlloc(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    if (path.len == 0 or path.len >= maximum_path_bytes) return error.NoncanonicalReferencePath;
    var buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&buf);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true };
    const fd: i32 = @intCast(try syscall(linux.openat(linux.AT.FDCWD, path_z, flags, 0)));
    defer _ = linux.close(fd);
    const meta = try fstat(fd);
    if ((meta.mode & linux.S.IFMT) != linux.S.IFREG or meta.size > max_bytes)
        return error.ReferenceSyscallRefused;
    const out = try allocator.alloc(u8, @intCast(meta.size));
    errdefer allocator.free(out);
    var offset: usize = 0;
    while (offset < out.len) {
        const got = try syscall(linux.read(fd, out[offset..].ptr, out.len - offset));
        if (got == 0) break;
        offset += got;
    }
    if (offset != out.len) return error.ReferenceFileChanged;
    return out;
}

pub fn verifyMinisign(
    allocator: std.mem.Allocator,
    public_key: []const u8,
    artifact: []const u8,
    signature_path: []const u8,
    name: []const u8,
    sha256: []const u8,
    size: u64,
) ![]u8 {
    const raw_key = try decodeBase64Exact(42, public_key, error.MalformedMinisignPublicKey);
    if (!std.mem.eql(u8, raw_key[0..2], "Ed")) return error.UnsupportedMinisignPublicKeyAlgorithm;
    const key_id = raw_key[2..10].*;
    const key = raw_key[10..42].*;

    const sig_bytes = try readRegularNoFollowAlloc(allocator, signature_path, 64 * 1024);
    defer allocator.free(sig_bytes);

    var lines: [6][]const u8 = undefined;
    var line_count: usize = 0;
    var line_it = std.mem.splitScalar(u8, sig_bytes, '\n');
    while (line_it.next()) |line| {
        if (line_count >= lines.len) return error.MalformedMinisignSignatureFile;
        lines[line_count] = line;
        line_count += 1;
    }
    if ((line_count != 4 and line_count != 5) or
        (line_count == 5 and lines[4].len != 0) or
        !std.mem.startsWith(u8, lines[0], "untrusted comment: ") or
        !std.mem.startsWith(u8, lines[2], "trusted comment: "))
    {
        return error.MalformedMinisignSignatureFile;
    }
    const blob = try decodeBase64Exact(74, lines[1], error.MalformedMinisignSignature);
    if (!std.mem.eql(u8, blob[0..2], "ED")) return error.LegacyMinisignSignatureRefused;
    if (!std.mem.eql(u8, blob[2..10], &key_id)) return error.SignatureKeyIdMismatch;

    const trusted = lines[2]["trusted comment: ".len..];
    var fields: [4][]const u8 = undefined;
    var field_count: usize = 0;
    var field_it = std.mem.splitScalar(u8, trusted, '\t');
    while (field_it.next()) |field| {
        if (field_count >= fields.len) return error.TrustedCommentMismatch;
        fields[field_count] = field;
        field_count += 1;
    }
    if (field_count != 3 or
        !validTimestampField(fields[0]) or
        !std.mem.startsWith(u8, fields[1], "file:") or
        !std.mem.eql(u8, fields[1]["file:".len..], name) or
        !std.mem.eql(u8, fields[2], "hashed"))
    {
        return error.TrustedCommentMismatch;
    }
    const global_signature = try decodeBase64Exact(64, lines[3], error.MalformedMinisignGlobalSignature);
    if (!std.mem.eql(u8, std.fs.path.basename(artifact), name)) return error.ArtifactNameMismatch;
    if (size == 0 or size > maximum_artifact_bytes) return error.InvalidArtifactSizePin;

    if (artifact.len == 0 or artifact.len >= maximum_path_bytes) return error.NoncanonicalReferencePath;
    var artifact_buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(artifact_buf[0..artifact.len], artifact);
    artifact_buf[artifact.len] = 0;
    const artifact_z: [*:0]const u8 = @ptrCast(&artifact_buf);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true };
    const fd: i32 = @intCast(try syscall(linux.openat(linux.AT.FDCWD, artifact_z, flags, 0)));
    defer _ = linux.close(fd);
    const meta = try fstat(fd);
    if ((meta.mode & linux.S.IFMT) != linux.S.IFREG) return error.ReferenceSyscallRefused;

    var prehash = std.crypto.hash.blake2.Blake2b512.init(.{});
    var sha256_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var observed: u64 = 0;
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const got = try syscall(linux.read(fd, &chunk, chunk.len));
        if (got == 0) break;
        observed += got;
        if (observed > size) break;
        prehash.update(chunk[0..got]);
        sha256_hasher.update(chunk[0..got]);
    }
    var sha256_bytes: [32]u8 = undefined;
    sha256_hasher.final(&sha256_bytes);
    const actual_sha256 = std.fmt.bytesToHex(sha256_bytes, .lower);
    if (observed != size or !std.mem.eql(u8, &actual_sha256, sha256))
        return error.ArtifactSizeOrDigestMismatch;

    var prehash_digest: [64]u8 = undefined;
    prehash.final(&prehash_digest);
    const file_sig = blob[10..74].*;
    try ed25519Verify(key, &prehash_digest, file_sig);

    const global_message = try std.mem.concat(allocator, u8, &.{ &file_sig, trusted });
    defer allocator.free(global_message);
    try ed25519Verify(key, global_message, global_signature);

    var reversed_key_id: [8]u8 = undefined;
    for (0..8) |index| {
        reversed_key_id[index] = key_id[7 - index];
    }
    const key_id_hex = std.fmt.bytesToHex(reversed_key_id, .upper);
    return std.fmt.allocPrint(
        allocator,
        "verified {s} sha256={s} size={d} key_id={s} trusted_comment='{s}'",
        .{ name, sha256, size, key_id_hex, trusted },
    );
}

fn writeAllFd(fd: i32, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = try syscall(linux.write(fd, bytes[offset..].ptr, bytes.len - offset));
        if (count == 0) return error.ReferenceSyscallRefused;
        offset += count;
    }
}

fn reportFailures(failures: []const []const u8) u8 {
    const limit = @min(failures.len, 50);
    for (failures[0..limit]) |failure| {
        writeAllFd(2, failure) catch {};
        writeAllFd(2, "\n") catch {};
    }
    return if (failures.len != 0) 1 else 0;
}

pub fn runCli(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 2 and std.mem.eql(u8, args[0], "ancestry")) {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(allocator);
        const failures = try ancestry(allocator, &out, args[1]);
        defer freeStrings(allocator, failures);
        try writeAllFd(1, out.items);
        return reportFailures(failures);
    }
    if (args.len == 2 and std.mem.eql(u8, args[0], "tree")) {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(allocator);
        const anc_failures = try ancestry(allocator, &out, args[1]);
        defer freeStrings(allocator, anc_failures);
        const tr_failures = try treeFailures(allocator, &out, args[1]);
        defer freeStrings(allocator, tr_failures);
        try writeAllFd(1, out.items);
        var combined: std.ArrayList([]const u8) = .empty;
        defer combined.deinit(allocator);
        for (anc_failures) |item| try combined.append(allocator, item);
        for (tr_failures) |item| try combined.append(allocator, item);
        return reportFailures(combined.items);
    }
    if (args.len == 3 and std.mem.eql(u8, args[0], "packages")) {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(allocator);
        const failures = try packageFailures(allocator, &out, args[1], args[2]);
        defer freeStrings(allocator, failures);
        try writeAllFd(1, out.items);
        return reportFailures(failures);
    }
    if (args.len == 4 and std.mem.eql(u8, args[0], "verify-keyring")) {
        const size = std.fmt.parseInt(usize, args[2], 10) catch return 2;
        const digest = verifyKeyring(args[1], size, args[3]) catch |err| {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "keyring verification failed: {s}\n", .{@errorName(err)}) catch "keyring verification failed\n";
            try writeAllFd(2, msg);
            return 1;
        };
        try writeAllFd(1, &digest);
        try writeAllFd(1, "\n");
        return 0;
    }
    if (args.len == 2 and std.mem.eql(u8, args[0], "toolchain")) {
        const lib = toolchain(allocator, args[1]) catch |err| {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "toolchain verification failed: {s}\n", .{@errorName(err)}) catch "toolchain verification failed\n";
            try writeAllFd(2, msg);
            return 1;
        };
        defer allocator.free(lib);
        try writeAllFd(1, lib);
        try writeAllFd(1, "\n");
        return 0;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[0], "protected")) {
        var directory = false;
        var index: usize = 1;
        if (std.mem.eql(u8, args[index], "--directory")) {
            directory = true;
            index += 1;
        }
        if (index >= args.len) return 2;
        while (index < args.len) : (index += 1) {
            _ = protected(args[index], directory) catch |err| {
                var buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "protected path check failed: {s}\n", .{@errorName(err)}) catch "protected path check failed\n";
                try writeAllFd(2, msg);
                return 1;
            };
        }
        return 0;
    }
    if (args.len == 13 and std.mem.eql(u8, args[0], "verify-minisign")) {
        var public_key: ?[]const u8 = null;
        var artifact: ?[]const u8 = null;
        var signature_path: ?[]const u8 = null;
        var name: ?[]const u8 = null;
        var sha256: ?[]const u8 = null;
        var size: ?u64 = null;
        var index: usize = 1;
        while (index + 1 < args.len) : (index += 2) {
            const flag = args[index];
            const val = args[index + 1];
            if (std.mem.eql(u8, flag, "--public-key")) {
                public_key = val;
            } else if (std.mem.eql(u8, flag, "--artifact")) {
                artifact = val;
            } else if (std.mem.eql(u8, flag, "--signature")) {
                signature_path = val;
            } else if (std.mem.eql(u8, flag, "--name")) {
                name = val;
            } else if (std.mem.eql(u8, flag, "--sha256")) {
                sha256 = val;
            } else if (std.mem.eql(u8, flag, "--size")) {
                size = std.fmt.parseInt(u64, val, 10) catch return 2;
            } else return 2;
        }
        const summary = verifyMinisign(
            allocator,
            public_key orelse return 2,
            artifact orelse return 2,
            signature_path orelse return 2,
            name orelse return 2,
            sha256 orelse return 2,
            size orelse return 2,
        ) catch |err| {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "minisign verification failed: {s}\n", .{@errorName(err)}) catch "minisign verification failed\n";
            try writeAllFd(2, msg);
            return 1;
        };
        defer allocator.free(summary);
        try writeAllFd(1, summary);
        try writeAllFd(1, "\n");
        return 0;
    }
    try writeAllFd(
        2,
        "usage: debz-reference-paths ancestry|tree TREE | packages DIR OUTPUT | verify-keyring PATH SIZE SHA256 | toolchain PATH | protected [--directory] PATH... | verify-minisign --public-key KEY --artifact PATH --signature PATH --name NAME --sha256 SHA256 --size SIZE\n",
    );
    return 2;
}

pub fn main(init: std.process.Init) !u8 {
    var args_list: std.ArrayList([]const u8) = .empty;
    defer args_list.deinit(init.gpa);
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |arg| {
        try args_list.append(init.gpa, arg);
    }
    return runCli(init.gpa, args_list.items);
}

const TestSigner = struct {
    pair: std.crypto.sign.Ed25519.KeyPair,
    key_id: [8]u8,
    public_b64: [56]u8,

    fn init(seed_byte: u8) !TestSigner {
        const seed: [32]u8 = @splat(seed_byte);
        const pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        const key_id: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
        var raw_pub: [42]u8 = undefined;
        @memcpy(raw_pub[0..2], "Ed");
        @memcpy(raw_pub[2..10], &key_id);
        @memcpy(raw_pub[10..42], &pair.public_key.toBytes());
        var public_b64: [56]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&public_b64, &raw_pub);
        return .{ .pair = pair, .key_id = key_id, .public_b64 = public_b64 };
    }

    fn minisig(
        self: TestSigner,
        allocator: std.mem.Allocator,
        payload: []const u8,
        name: []const u8,
        algorithm: *const [2]u8,
        override_key_id: ?[8]u8,
        override_comment: ?[]const u8,
    ) ![]u8 {
        var prehashed: [64]u8 = undefined;
        std.crypto.hash.blake2.Blake2b512.hash(payload, &prehashed, .{});
        const signed_payload: []const u8 = if (std.mem.eql(u8, algorithm, "ED")) &prehashed else payload;
        const file_sig = (try self.pair.sign(signed_payload, null)).toBytes();
        var blob: [74]u8 = undefined;
        @memcpy(blob[0..2], algorithm);
        @memcpy(blob[2..10], &(override_key_id orelse self.key_id));
        @memcpy(blob[10..74], &file_sig);
        var blob_b64: [100]u8 = undefined;
        const blob_encoded = std.base64.standard.Encoder.encode(&blob_b64, &blob);

        const default_comment = try std.fmt.allocPrint(allocator, "timestamp:1\tfile:{s}\thashed", .{name});
        defer allocator.free(default_comment);
        const trusted = override_comment orelse default_comment;

        const global_input = try std.mem.concat(allocator, u8, &.{ &file_sig, trusted });
        defer allocator.free(global_input);
        const global_sig = (try self.pair.sign(global_input, null)).toBytes();
        var global_b64: [88]u8 = undefined;
        const global_encoded = std.base64.standard.Encoder.encode(&global_b64, &global_sig);

        return std.fmt.allocPrint(
            allocator,
            "untrusted comment: test\n{s}\ntrusted comment: {s}\n{s}\n",
            .{ blob_encoded, trusted, global_encoded },
        );
    }
};

fn makeTempRoot(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir) ![:0]u8 {
    return tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
}

fn chmodPath(path: []const u8, mode: u16) !void {
    var buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&buf);
    _ = try syscall(linux.fchmodat(linux.AT.FDCWD, path_z, mode));
}

fn symlinkAtPath(target: []const u8, link_path: []const u8) !void {
    var target_buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(target_buf[0..target.len], target);
    target_buf[target.len] = 0;
    var link_buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(link_buf[0..link_path.len], link_path);
    link_buf[link_path.len] = 0;
    _ = try syscall(linux.symlinkat(@ptrCast(&target_buf), linux.AT.FDCWD, @ptrCast(&link_buf)));
}

test "published zig trusted comment signature verifies with the pinned key" {
    const zig_key = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U";
    const zig_x86_64_minisig =
        "untrusted comment: signature from minisign secret key\n" ++
        "RUSGOq2NVecA2VBoEOeGzBPCLUN923PdJ8Siq4/5/Yft5EkLCQS/d3Z26i8qvr3E/yADtLLDGeS1g1yq6GHQXNI2oLMXynajRgo=\n" ++
        "trusted comment: timestamp:1790965431\tfile:zig-x86_64-linux-0.17.0.tar.xz\thashed\n" ++
        "sRbmsqhOqH2oWybcev78e/pu1CRtIZ2Ga/YW2G/WGv79JHI2Sat9FpkGSo2Sik31aJbuPjxGV8tAdBgci59rDQ==\n";
    var line_it = std.mem.splitScalar(u8, zig_x86_64_minisig, '\n');
    _ = line_it.next().?;
    const line1 = line_it.next().?;
    const line2 = line_it.next().?;
    const line3 = line_it.next().?;

    const raw_key = try decodeBase64Exact(42, zig_key, error.MalformedMinisignPublicKey);
    const blob = try decodeBase64Exact(74, line1, error.MalformedMinisignSignature);
    try std.testing.expectEqualSlices(u8, "ED", blob[0..2]);
    try std.testing.expectEqualSlices(u8, raw_key[2..10], blob[2..10]);
    const trusted = line2["trusted comment: ".len..];
    const global_sig = try decodeBase64Exact(64, line3, error.MalformedMinisignGlobalSignature);

    const message = try std.mem.concat(std.testing.allocator, u8, &.{ blob[10..74], trusted });
    defer std.testing.allocator.free(message);
    try ed25519Verify(raw_key[10..42].*, message, global_sig);

    const tampered = try std.mem.concat(std.testing.allocator, u8, &.{ message, "x" });
    defer std.testing.allocator.free(tampered);
    try std.testing.expectError(error.Ed25519VerificationFailed, ed25519Verify(raw_key[10..42].*, tampered, global_sig));
}

test "prehashed minisign signature binds bytes name size digest and refuses tampering" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try makeTempRoot(allocator, &tmp);
    defer allocator.free(root);

    const signer = try TestSigner.init(7);
    const other_signer = try TestSigner.init(9);
    const zero_sha256: [64]u8 = @splat('0');
    const name = "zig-test-linux-0.17.0.tar.xz";
    const payload = "pinned toolchain bytes\npinned toolchain bytes\npinned toolchain bytes\npinned toolchain bytes\n";
    const artifact = try std.fs.path.join(allocator, &.{ root, name });
    defer allocator.free(artifact);
    const sig_path = try std.fs.path.join(allocator, &.{ root, "zig-test-linux-0.17.0.tar.xz.minisig" });
    defer allocator.free(sig_path);

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = name, .data = payload });
    var sha256_bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &sha256_bytes, .{});
    const sha256_hex = std.fmt.bytesToHex(sha256_bytes, .lower);
    const sha256_upper = std.fmt.bytesToHex(sha256_bytes, .upper);

    const good = try signer.minisig(allocator, payload, name, "ED", null, null);
    defer allocator.free(good);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "zig-test-linux-0.17.0.tar.xz.minisig", .data = good });

    const verified = try verifyMinisign(allocator, &signer.public_b64, artifact, sig_path, name, &sha256_hex, payload.len);
    defer allocator.free(verified);
    try std.testing.expect(std.mem.indexOf(u8, verified, "verified zig-test-linux-0.17.0.tar.xz") != null);

    try std.testing.expectError(
        error.ArtifactSizeOrDigestMismatch,
        verifyMinisign(allocator, &signer.public_b64, artifact, sig_path, name, &zero_sha256, payload.len),
    );
    try std.testing.expectError(
        error.ArtifactSizeOrDigestMismatch,
        verifyMinisign(allocator, &signer.public_b64, artifact, sig_path, name, &sha256_upper, payload.len),
    );
    try std.testing.expectError(
        error.ArtifactSizeOrDigestMismatch,
        verifyMinisign(allocator, &signer.public_b64, artifact, sig_path, name, "", payload.len),
    );
    try std.testing.expectError(
        error.ArtifactSizeOrDigestMismatch,
        verifyMinisign(allocator, &signer.public_b64, artifact, sig_path, name, &sha256_hex, payload.len - 1),
    );
    try std.testing.expectError(
        error.TrustedCommentMismatch,
        verifyMinisign(allocator, &signer.public_b64, artifact, sig_path, "zig-other-linux-0.17.0.tar.xz", &sha256_hex, payload.len),
    );
    try std.testing.expectError(
        error.Ed25519VerificationFailed,
        verifyMinisign(allocator, &other_signer.public_b64, artifact, sig_path, name, &sha256_hex, payload.len),
    );

    const legacy = try signer.minisig(allocator, payload, name, "Ed", null, null);
    defer allocator.free(legacy);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "zig-test-linux-0.17.0.tar.xz.minisig", .data = legacy });
    try std.testing.expectError(
        error.LegacyMinisignSignatureRefused,
        verifyMinisign(allocator, &signer.public_b64, artifact, sig_path, name, &sha256_hex, payload.len),
    );

    const bad_key_id = try signer.minisig(allocator, payload, name, "ED", @splat(0), null);
    defer allocator.free(bad_key_id);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "zig-test-linux-0.17.0.tar.xz.minisig", .data = bad_key_id });
    try std.testing.expectError(
        error.SignatureKeyIdMismatch,
        verifyMinisign(allocator, &signer.public_b64, artifact, sig_path, name, &sha256_hex, payload.len),
    );

    const bad_comment = try signer.minisig(allocator, payload, name, "ED", null, "file:zig-test-linux-0.17.0.tar.xz");
    defer allocator.free(bad_comment);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "zig-test-linux-0.17.0.tar.xz.minisig", .data = bad_comment });
    try std.testing.expectError(
        error.TrustedCommentMismatch,
        verifyMinisign(allocator, &signer.public_b64, artifact, sig_path, name, &sha256_hex, payload.len),
    );

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "zig-test-linux-0.17.0.tar.xz.minisig", .data = good });
    try tmp.dir.deleteFile(std.testing.io, name);
    try symlinkAtPath(sig_path, artifact);
    try std.testing.expectError(
        error.ReferenceSyscallRefused,
        verifyMinisign(allocator, &signer.public_b64, artifact, sig_path, name, &sha256_hex, payload.len),
    );
}

test "unprotected ancestry tree and package sources fail closed" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try makeTempRoot(allocator, &tmp);
    defer allocator.free(root);

    try chmodPath(root, 0o755);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const anc_failures = try ancestry(allocator, &out, root);
    defer freeStrings(allocator, anc_failures);
    var saw_mode_0700 = false;
    for (anc_failures) |failure| {
        if (std.mem.startsWith(u8, failure, "protected tree must be mode 0700: drwxr-xr-x"))
            saw_mode_0700 = true;
    }
    try std.testing.expect(saw_mode_0700);

    out.clearRetainingCapacity();
    const rel_failures = try ancestry(allocator, &out, "relative");
    defer freeStrings(allocator, rel_failures);
    try std.testing.expectEqual(@as(usize, 1), rel_failures.len);
    try std.testing.expectEqualStrings("tree path is not canonical and absolute: relative", rel_failures[0]);

    const writable_path = try std.fs.path.join(allocator, &.{ root, "writable" });
    defer allocator.free(writable_path);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "writable", .data = "x" });
    try chmodPath(writable_path, 0o666);

    test_force_root_owned_lstat = true;
    defer test_force_root_owned_lstat = false;

    out.clearRetainingCapacity();
    const tr_failures = try treeFailures(allocator, &out, root);
    defer freeStrings(allocator, tr_failures);
    try std.testing.expectEqual(@as(usize, 1), tr_failures.len);
    try std.testing.expect(std.mem.indexOf(u8, tr_failures[0], "group/other-writable entry") != null);
    try tmp.dir.deleteFile(std.testing.io, "writable");

    try tmp.dir.createDirPath(std.testing.io, "zig-pkg/pkg");
    const packages_dir = try std.fs.path.join(allocator, &.{ root, "zig-pkg" });
    defer allocator.free(packages_dir);
    const script_path = try std.fs.path.join(allocator, &.{ root, "zig-pkg/pkg/autogen.sh" });
    defer allocator.free(script_path);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "zig-pkg/pkg/autogen.sh", .data = "#!/bin/sh\nexit 1\n" });
    try chmodPath(script_path, 0o777);
    const inside_link = try std.fs.path.join(allocator, &.{ root, "zig-pkg/pkg/inside" });
    defer allocator.free(inside_link);
    try symlinkAtPath("autogen.sh", inside_link);

    const loose_manifest = try std.fs.path.join(allocator, &.{ root, "loose.txt" });
    defer allocator.free(loose_manifest);
    out.clearRetainingCapacity();
    const pkg_loose = try packageFailures(allocator, &out, packages_dir, loose_manifest);
    defer freeStrings(allocator, pkg_loose);
    try std.testing.expectEqual(@as(usize, 1), pkg_loose.len);
    try std.testing.expect(std.mem.startsWith(u8, pkg_loose[0], "untightened package entry:"));

    try chmodPath(script_path, 0o755);
    const tight_manifest = try std.fs.path.join(allocator, &.{ root, "tight.txt" });
    defer allocator.free(tight_manifest);
    out.clearRetainingCapacity();
    const pkg_tight = try packageFailures(allocator, &out, packages_dir, tight_manifest);
    defer freeStrings(allocator, pkg_tight);
    try std.testing.expectEqual(@as(usize, 0), pkg_tight.len);

    const manifest_content = try readRegularNoFollowAlloc(allocator, tight_manifest, 64 * 1024);
    defer allocator.free(manifest_content);
    try std.testing.expect(std.mem.indexOf(u8, manifest_content, "link autogen.sh pkg/inside\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, manifest_content, "pkg/autogen.sh\n") != null);

    try std.testing.expectError(
        error.PackageManifestExists,
        packageFailures(allocator, &out, packages_dir, tight_manifest),
    );

    const escape_link = try std.fs.path.join(allocator, &.{ root, "zig-pkg/pkg/escape" });
    defer allocator.free(escape_link);
    try symlinkAtPath("../../outside", escape_link);
    const escape_manifest = try std.fs.path.join(allocator, &.{ root, "escape.txt" });
    defer allocator.free(escape_manifest);
    out.clearRetainingCapacity();
    const pkg_escape = try packageFailures(allocator, &out, packages_dir, escape_manifest);
    defer freeStrings(allocator, pkg_escape);
    try std.testing.expectEqual(@as(usize, 1), pkg_escape.len);
    try std.testing.expect(std.mem.indexOf(u8, pkg_escape[0], "escapes its tree") != null);
}

test "keyring toolchain and readRootFile enforce descriptor-rooted no-follow pins" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try makeTempRoot(allocator, &tmp);
    defer allocator.free(root);
    try chmodPath(root, 0o755);

    const keyring = try std.fs.path.join(allocator, &.{ root, "keyring" });
    defer allocator.free(keyring);
    const payload = "reviewed fixture bytes";
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "keyring", .data = payload });
    try chmodPath(keyring, 0o644);
    var digest_bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest_bytes, .{});
    const digest = std.fmt.bytesToHex(digest_bytes, .lower);

    try std.testing.expectError(error.UnprotectedReferencePath, verifyKeyring(keyring, payload.len, &digest));

    test_root_override = root;
    defer test_root_override = null;

    const zero_digest: [64]u8 = @splat('0');
    const actual = try verifyKeyring(keyring, payload.len, &digest);
    try std.testing.expectEqualSlices(u8, &digest, &actual);
    try std.testing.expectError(error.KeyringPinMismatch, verifyKeyring(keyring, payload.len + 1, &digest));
    try std.testing.expectError(error.KeyringPinMismatch, verifyKeyring(keyring, payload.len, &zero_digest));

    try chmodPath(keyring, 0o666);
    try std.testing.expectError(error.UnprotectedReferencePath, verifyKeyring(keyring, payload.len, &digest));
    try chmodPath(keyring, 0o644);

    const linked_keyring = try std.fs.path.join(allocator, &.{ root, "linked-keyring" });
    defer allocator.free(linked_keyring);
    try symlinkAtPath(keyring, linked_keyring);
    try std.testing.expectError(error.ReferenceSyscallRefused, verifyKeyring(linked_keyring, payload.len, &digest));

    const compiler = try std.fs.path.join(allocator, &.{ root, "zig" });
    defer allocator.free(compiler);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "zig", .data = "#!/bin/sh\nexit 0\n" });
    try chmodPath(compiler, 0o755);
    try tmp.dir.createDirPath(std.testing.io, "lib");
    const lib_dir = try std.fs.path.join(allocator, &.{ root, "lib" });
    defer allocator.free(lib_dir);
    try chmodPath(lib_dir, 0o755);
    const std_zig = try std.fs.path.join(allocator, &.{ root, "lib/std.zig" });
    defer allocator.free(std_zig);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "lib/std.zig", .data = "fixture" });
    try chmodPath(std_zig, 0o644);

    const verified_lib = try toolchain(allocator, compiler);
    defer allocator.free(verified_lib);
    try std.testing.expectEqualStrings(lib_dir, verified_lib);

    try chmodPath(std_zig, 0o666);
    try std.testing.expectError(error.UnprotectedReferencePath, toolchain(allocator, compiler));
    try chmodPath(std_zig, 0o644);

    const escape = try std.fs.path.join(allocator, &.{ root, "lib/escape" });
    defer allocator.free(escape);
    try symlinkAtPath(compiler, escape);
    try std.testing.expectError(error.ToolchainSymlinkEscapes, toolchain(allocator, compiler));
    try tmp.dir.deleteFile(std.testing.io, "lib/escape");

    const db_bytes = try readRootFile(allocator, root, "lib/std.zig", 64);
    defer allocator.free(db_bytes);
    try std.testing.expectEqualStrings("fixture", db_bytes);
    try std.testing.expectError(error.InvalidReferenceDatabaseFile, readRootFile(allocator, root, "lib/std.zig", 3));
}
