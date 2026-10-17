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
    UnsafeOrOversizedCoordinationMember,
    CoordinationMemberChanged,
    CoordinationEvidenceExceedsLimit,
    UnsafeOrOversizedEvidenceMember,
    EvidenceExceedsLimit,
    KeyringPackagePinMismatch,
    InvalidKeyringArArchive,
    UnsupportedKeyringArMemberName,
    DuplicateKeyringArMember,
    MissingKeyringArMember,
    InvalidKeyringDebianBinary,
    InvalidKeyringZstdArchive,
    KeyringDataArchiveExceedsLimit,
    UnsafeKeyringTarMemberName,
    InvalidKeyringTarArchive,
    DuplicateKeyringTarMember,
    KeyringTarMemberNotRegular,
    KeyringTarMemberSizeMismatch,
    MissingKeyringTarMember,
    KeyringMemberPinMismatch,
    KeyringStagedCopyPinMismatch,
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

fn openComponentAtOptional(dir_fd: i32, part: []const u8, directory: bool) !?i32 {
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
    const rc = linux.openat(dir_fd, part_z, flags, 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .NOENT => null,
        else => error.ReferenceSyscallRefused,
    };
}

pub fn openBeneathOptional(root_fd: i32, relative: []const u8, directory: bool) !?i32 {
    try validateRelativeCanonical(relative);
    var current: i32 = @intCast(try syscall(linux.fcntl(root_fd, linux.F.DUPFD_CLOEXEC, @as(usize, 0))));
    errdefer if (current != -1) {
        _ = linux.close(current);
    };
    var it = std.mem.splitScalar(u8, relative, '/');
    while (it.next()) |part| {
        const is_last = it.rest().len == 0;
        const next_fd = (try openComponentAtOptional(current, part, !is_last or directory)) orelse return null;
        _ = linux.close(current);
        current = next_fd;
    }
    const result = current;
    current = -1;
    return result;
}

pub fn openAbsoluteOptional(path: []const u8, directory: bool) !?i32 {
    if (!isCanonicalAbsolute(path)) return error.NoncanonicalReferencePath;
    const root_flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const root_fd: i32 = @intCast(try syscall(linux.openat(linux.AT.FDCWD, "/", root_flags, 0)));
    defer _ = linux.close(root_fd);
    if (std.mem.eql(u8, path, "/")) {
        if (!directory) return error.NoncanonicalReferencePath;
        return @intCast(try syscall(linux.fcntl(root_fd, linux.F.DUPFD_CLOEXEC, @as(usize, 0))));
    }
    return openBeneathOptional(root_fd, path[1..], directory);
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

pub const keyring_decompressed_limit: usize = 1024 * 1024;

fn unlinkIgnoreMissing(path: []const u8) void {
    if (path.len == 0 or path.len >= maximum_path_bytes) return;
    var buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&buf);
    _ = linux.unlinkat(linux.AT.FDCWD, path_z, 0);
}

fn appendKeyringEvidence(
    allocator: std.mem.Allocator,
    evidence_path: []const u8,
    role: []const u8,
    path: []const u8,
    entry: linux.Statx,
    algorithm: []const u8,
    digest: []const u8,
) !void {
    if (evidence_path.len == 0 or evidence_path.len >= maximum_path_bytes) return error.NoncanonicalReferencePath;
    var buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(buf[0..evidence_path.len], evidence_path);
    buf[evidence_path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&buf);
    const flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .APPEND = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const fd: i32 = @intCast(try syscall(linux.openat(linux.AT.FDCWD, path_z, flags, 0)));
    defer _ = linux.close(fd);
    const row = try std.fmt.allocPrint(
        allocator,
        "{s}\t{s}\t{d}:{d}:{o:0>3}:{d}\t{s}\t{s}\n",
        .{ path, role, entry.uid, entry.gid, entry.mode & 0o7777, entry.size, algorithm, digest },
    );
    defer allocator.free(row);
    try writeAllFd(fd, row);
}

fn requireRootOwnedKeyringFile(
    allocator: std.mem.Allocator,
    evidence_path: []const u8,
    role: []const u8,
    path: []const u8,
    entry: linux.Statx,
    mode: u16,
) !void {
    if (entry.uid != 0 or
        entry.gid != 0 or
        (entry.mode & linux.S.IFMT) != linux.S.IFREG or
        (entry.mode & 0o7777) != mode)
    {
        try appendKeyringEvidence(allocator, evidence_path, role, path, entry, "-", "-");
        return error.UnprotectedReferencePath;
    }
}

pub fn parseArMember(archive: []const u8, expected_name: []const u8) Error![]const u8 {
    if (!std.mem.startsWith(u8, archive, "!<arch>\n")) return error.InvalidKeyringArArchive;
    var offset: usize = 8;
    var found: ?[]const u8 = null;
    while (offset < archive.len) {
        if (offset + 60 > archive.len) return error.InvalidKeyringArArchive;
        const header = archive[offset .. offset + 60];
        offset += 60;
        if (!std.mem.eql(u8, header[58..60], "`\n")) return error.InvalidKeyringArArchive;
        for (header[0..16]) |ch| {
            if (ch < 0x20 or ch > 0x7e) return error.InvalidKeyringArArchive;
        }
        const raw_name = std.mem.trim(u8, header[0..16], " ");
        if (std.mem.startsWith(u8, raw_name, "//") or std.mem.startsWith(u8, raw_name, "/"))
            return error.UnsupportedKeyringArMemberName;
        const name = std.mem.trimEnd(u8, raw_name, "/");
        const size_text = std.mem.trim(u8, header[48..58], " ");
        const size = std.fmt.parseInt(usize, size_text, 10) catch return error.InvalidKeyringArArchive;
        if (offset + size > archive.len) return error.InvalidKeyringArArchive;
        const payload = archive[offset .. offset + size];
        offset += size + (size % 2);
        if (std.mem.eql(u8, name, expected_name)) {
            if (found != null) return error.DuplicateKeyringArMember;
            found = payload;
        }
    }
    return found orelse error.MissingKeyringArMember;
}

pub fn zstdDecompressBounded(allocator: std.mem.Allocator, payload: []const u8, limit: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var in: std.Io.Reader = .fixed(payload);
    const window_buf = try allocator.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer allocator.free(window_buf);
    var zstd_stream: std.compress.zstd.Decompress = .init(&in, window_buf, .{});
    var chunk: [16 * 1024]u8 = undefined;
    while (true) {
        const got = zstd_stream.reader.readSliceShort(&chunk) catch return error.InvalidKeyringZstdArchive;
        if (got == 0) break;
        if (out.items.len + got > limit) return error.KeyringDataArchiveExceedsLimit;
        try out.appendSlice(allocator, chunk[0..got]);
    }
    if (zstd_stream.err != null or in.seek != payload.len or out.items.len == 0)
        return error.InvalidKeyringZstdArchive;
    return out.toOwnedSlice(allocator);
}

fn tarCString(field: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, field, 0)) |nul| return field[0..nul];
    return field;
}

fn parseTarOctal(field: []const u8) Error!u64 {
    const ltrimmed = std.mem.trimStart(u8, field, "0 ");
    const rtrimmed = std.mem.trimEnd(u8, ltrimmed, " \x00");
    if (rtrimmed.len == 0) return 0;
    return std.fmt.parseInt(u64, rtrimmed, 8) catch return error.InvalidKeyringTarArchive;
}

pub fn extractTarMember(archive: []const u8, expected_name: []const u8, expected_size: u64) Error![]const u8 {
    if (expected_name.len == 0 or
        expected_name[0] == '/' or
        std.mem.eql(u8, expected_name, "..") or
        std.mem.startsWith(u8, expected_name, "../") or
        std.mem.endsWith(u8, expected_name, "/..") or
        std.mem.indexOf(u8, expected_name, "/../") != null)
    {
        return error.UnsafeKeyringTarMemberName;
    }
    if (archive.len == 0 or archive.len % 512 != 0) return error.InvalidKeyringTarArchive;
    var offset: usize = 0;
    var found: ?[]const u8 = null;
    while (offset < archive.len) {
        const block = archive[offset .. offset + 512];
        offset += 512;
        if (std.mem.allEqual(u8, block, 0)) continue;
        const expected_sum = try parseTarOctal(block[148..156]);
        var actual_sum: u64 = 0;
        for (block, 0..) |byte, idx| {
            actual_sum += if (idx >= 148 and idx < 156) ' ' else byte;
        }
        if (actual_sum != expected_sum) return error.InvalidKeyringTarArchive;
        const member_size = try parseTarOctal(block[124..136]);
        if (member_size > archive.len) return error.InvalidKeyringTarArchive;
        const size_usize: usize = @intCast(member_size);
        const padded = std.mem.alignForward(usize, size_usize, 512);
        if (offset + padded > archive.len) return error.InvalidKeyringTarArchive;
        const payload = archive[offset .. offset + size_usize];
        offset += padded;

        const name_part = tarCString(block[0..100]);
        const is_ustar = std.mem.eql(u8, block[257..262], "ustar") and (block[262] == 0 or block[262] == ' ');
        const prefix_part = if (is_ustar) tarCString(block[345..500]) else "";
        var name_buf: [256]u8 = undefined;
        const full_name: []const u8 = if (prefix_part.len > 0) blk: {
            if (prefix_part.len + 1 + name_part.len > name_buf.len) return error.InvalidKeyringTarArchive;
            @memcpy(name_buf[0..prefix_part.len], prefix_part);
            name_buf[prefix_part.len] = '/';
            @memcpy(name_buf[prefix_part.len + 1 ..][0..name_part.len], name_part);
            break :blk name_buf[0 .. prefix_part.len + 1 + name_part.len];
        } else name_part;

        const typeflag = block[156];
        if (std.mem.eql(u8, full_name, expected_name)) {
            if (found != null) return error.DuplicateKeyringTarMember;
            if (typeflag != '0' and typeflag != 0) return error.KeyringTarMemberNotRegular;
            if (member_size != expected_size) return error.KeyringTarMemberSizeMismatch;
            found = payload;
        }
    }
    return found orelse error.MissingKeyringTarMember;
}

pub fn stageArchiveKeyring(
    allocator: std.mem.Allocator,
    deb_path: []const u8,
    expected_deb_sha512: []const u8,
    expected_deb_size: u64,
    member: []const u8,
    target: []const u8,
    expected_keyring_sha256: []const u8,
    expected_keyring_size: u64,
    evidence_path: []const u8,
) ![]u8 {
    if (expected_deb_size == 0 or expected_deb_size > keyring_decompressed_limit)
        return error.KeyringPackagePinMismatch;
    if (expected_keyring_size == 0 or expected_keyring_size > keyring_decompressed_limit)
        return error.KeyringMemberPinMismatch;

    const package_stat = lstatPath(deb_path) catch |err| {
        unlinkIgnoreMissing(deb_path);
        return err;
    };
    const deb_bytes = readRegularNoFollowAlloc(allocator, deb_path, keyring_decompressed_limit) catch |err| {
        unlinkIgnoreMissing(deb_path);
        return err;
    };
    defer allocator.free(deb_bytes);

    var deb_sha512_bytes: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(deb_bytes, &deb_sha512_bytes, .{});
    const actual_deb_sha512 = std.fmt.bytesToHex(deb_sha512_bytes, .lower);
    try appendKeyringEvidence(allocator, evidence_path, "downloaded-package", deb_path, package_stat, "sha512", &actual_deb_sha512);
    if (deb_bytes.len != expected_deb_size or
        package_stat.size != expected_deb_size or
        !std.mem.eql(u8, &actual_deb_sha512, expected_deb_sha512))
    {
        unlinkIgnoreMissing(deb_path);
        return error.KeyringPackagePinMismatch;
    }
    requireRootOwnedKeyringFile(allocator, evidence_path, "downloaded-package", deb_path, package_stat, 0o600) catch |err| {
        unlinkIgnoreMissing(deb_path);
        return err;
    };

    const debian_binary = parseArMember(deb_bytes, "debian-binary") catch |err| {
        unlinkIgnoreMissing(deb_path);
        return err;
    };
    if (!std.mem.eql(u8, debian_binary, "2.0\n")) {
        unlinkIgnoreMissing(deb_path);
        return error.InvalidKeyringDebianBinary;
    }
    const data_archive = parseArMember(deb_bytes, "data.tar.zst") catch |err| {
        unlinkIgnoreMissing(deb_path);
        return err;
    };
    const data_tar = zstdDecompressBounded(allocator, data_archive, keyring_decompressed_limit) catch |err| {
        unlinkIgnoreMissing(deb_path);
        return err;
    };
    defer allocator.free(data_tar);
    const keyring = extractTarMember(data_tar, member, expected_keyring_size) catch |err| {
        unlinkIgnoreMissing(deb_path);
        return err;
    };
    var keyring_sha256_bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(keyring, &keyring_sha256_bytes, .{});
    const actual_keyring_sha256 = std.fmt.bytesToHex(keyring_sha256_bytes, .lower);
    if (keyring.len != expected_keyring_size or !std.mem.eql(u8, &actual_keyring_sha256, expected_keyring_sha256)) {
        unlinkIgnoreMissing(deb_path);
        return error.KeyringMemberPinMismatch;
    }

    if (target.len == 0 or target.len >= maximum_path_bytes) return error.NoncanonicalReferencePath;
    var target_buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(target_buf[0..target.len], target);
    target_buf[target.len] = 0;
    const target_z: [*:0]const u8 = @ptrCast(&target_buf);
    const create_flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const target_fd: i32 = @intCast(try syscall(linux.openat(linux.AT.FDCWD, target_z, create_flags, 0o644)));
    errdefer unlinkIgnoreMissing(target);
    {
        defer _ = linux.close(target_fd);
        if (!builtin.is_test or linux.geteuid() == 0) {
            _ = try syscall(linux.fchown(target_fd, 0, 0));
        }
        try writeAllFd(target_fd, keyring);
        _ = try syscall(linux.fchmod(target_fd, 0o644));
    }

    const target_stat = try lstatPath(target);
    try appendKeyringEvidence(allocator, evidence_path, "staged-keyring", target, target_stat, "sha256", &actual_keyring_sha256);
    try requireRootOwnedKeyringFile(allocator, evidence_path, "staged-keyring", target, target_stat, 0o644);

    const target_bytes = try readRegularNoFollowAlloc(allocator, target, keyring_decompressed_limit);
    defer allocator.free(target_bytes);
    var target_sha256_bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(target_bytes, &target_sha256_bytes, .{});
    const target_sha256 = std.fmt.bytesToHex(target_sha256_bytes, .lower);
    if (target_bytes.len != expected_keyring_size or
        target_stat.size != expected_keyring_size or
        !std.mem.eql(u8, &target_sha256, expected_keyring_sha256))
    {
        return error.KeyringStagedCopyPinMismatch;
    }

    return std.fmt.allocPrint(
        allocator,
        "verified Ubuntu archive keyring from pinned package: {s} package_size={d} package_sha512={s} keyring_size={d} keyring_sha256={s}",
        .{ target, deb_bytes.len, actual_deb_sha512, keyring.len, actual_keyring_sha256 },
    );
}

pub const coordination_names = [_][]const u8{
    "root-operation-v1.json",
    "native-execution-intent-v1.json",
    "native-execution-progress-v1.log",
    "native-managed-state-v1.json",
    "native-lifecycle-script-v1.json",
    "native-trigger-events-v1.json",
    "native-transaction-authorization-v1.json",
    "native-transaction-authorization-v2.json",
    "native-transaction-authorization-v3.json",
    "native-transaction-program-v1.json",
    "native-transaction-program-v2.json",
    "native-transaction-program-v3.json",
    "root-mutation-v1.json",
    "root-mutation-v2.log",
};

const CoordinationRow = struct {
    name: []const u8,
    status: enum { unread, absent, present },
    size: usize = 0,
    sha256: [64]u8 = undefined,
};

fn writeExclusiveAtFd(dir_fd: i32, name: []const u8, mode: u16, bytes: []const u8) !void {
    if (name.len == 0 or name.len > 255) return error.NoncanonicalReferencePath;
    var buf: [256]u8 = undefined;
    @memcpy(buf[0..name.len], name);
    buf[name.len] = 0;
    const name_z: [*:0]const u8 = @ptrCast(&buf);
    const flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const fd: i32 = @intCast(try syscall(linux.openat(dir_fd, name_z, flags, mode)));
    defer _ = linux.close(fd);
    try writeAllFd(fd, bytes);
}

fn writeCoordinationInventory(
    allocator: std.mem.Allocator,
    evidence_fd: i32,
    capture_complete: bool,
    rows: []const CoordinationRow,
) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.appendSlice(allocator, "{\n  \"version\": 1,\n  \"capture_complete\": ");
    try out.appendSlice(allocator, if (capture_complete) "true" else "false");
    if (rows.len == 0) {
        try out.appendSlice(allocator, ",\n  \"files\": []\n}\n");
    } else {
        try out.appendSlice(allocator, ",\n  \"files\": [\n");
        for (rows, 0..) |row, idx| {
            const comma: []const u8 = if (idx + 1 < rows.len) "," else "";
            switch (row.status) {
                .unread => {
                    const text = try std.fmt.allocPrint(
                        allocator,
                        "    {{\n      \"source\": \"var/lib/debz/{s}\",\n      \"status\": \"unread\"\n    }}{s}\n",
                        .{ row.name, comma },
                    );
                    defer allocator.free(text);
                    try out.appendSlice(allocator, text);
                },
                .absent => {
                    const text = try std.fmt.allocPrint(
                        allocator,
                        "    {{\n      \"source\": \"var/lib/debz/{s}\",\n      \"status\": \"absent\"\n    }}{s}\n",
                        .{ row.name, comma },
                    );
                    defer allocator.free(text);
                    try out.appendSlice(allocator, text);
                },
                .present => {
                    const text = try std.fmt.allocPrint(
                        allocator,
                        "    {{\n      \"source\": \"var/lib/debz/{s}\",\n      \"status\": \"present\",\n      \"file\": \"native-coordination/{s}\",\n      \"size\": {d},\n      \"sha256\": \"{s}\"\n    }}{s}\n",
                        .{ row.name, row.name, row.size, row.sha256, comma },
                    );
                    defer allocator.free(text);
                    try out.appendSlice(allocator, text);
                },
            }
        }
        try out.appendSlice(allocator, "  ]\n}\n");
    }
    try writeExclusiveAtFd(evidence_fd, "native-coordination-inventory-v1.json", 0o600, out.items);
}

pub fn captureCoordination(allocator: std.mem.Allocator, root: []const u8, evidence: []const u8) !void {
    const evidence_fd = try openAbsolute(evidence, true);
    defer _ = linux.close(evidence_fd);

    var rows: std.ArrayList(CoordinationRow) = .empty;
    defer rows.deinit(allocator);
    var capture_complete = false;
    errdefer if (!capture_complete) {
        writeCoordinationInventory(allocator, evidence_fd, false, rows.items) catch {};
    };

    const root_fd_opt = try openAbsoluteOptional(root, true);
    defer if (root_fd_opt) |rfd| {
        _ = linux.close(rfd);
    };
    const source_fd_opt: ?i32 = if (root_fd_opt) |rfd|
        try openBeneathOptional(rfd, "var/lib/debz", true)
    else
        null;
    defer if (source_fd_opt) |sfd| {
        _ = linux.close(sfd);
    };

    _ = try syscall(linux.mkdirat(evidence_fd, "native-coordination", 0o700));
    const output_fd = try openBeneath(evidence_fd, "native-coordination", true);
    defer _ = linux.close(output_fd);

    var coordination_bytes: usize = 0;
    for (coordination_names) |name| {
        try rows.append(allocator, .{ .name = name, .status = .unread });
        const row = &rows.items[rows.items.len - 1];
        const source_fd = source_fd_opt orelse {
            row.status = .absent;
            continue;
        };
        var name_buf: [256]u8 = undefined;
        @memcpy(name_buf[0..name.len], name);
        name_buf[name.len] = 0;
        const name_z: [*:0]const u8 = @ptrCast(&name_buf);
        const open_flags: linux.O = .{
            .ACCMODE = .RDONLY,
            .NOFOLLOW = true,
            .CLOEXEC = true,
            .NONBLOCK = true,
        };
        const rc = linux.openat(source_fd, name_z, open_flags, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .NOENT => {
                row.status = .absent;
                continue;
            },
            else => return error.ReferenceSyscallRefused,
        }
        const fd: i32 = @intCast(rc);
        defer _ = linux.close(fd);

        const before = try fstat(fd);
        if ((before.mode & linux.S.IFMT) != linux.S.IFREG or before.nlink != 1 or before.size > 128 * 1024 * 1024)
            return error.UnsafeOrOversizedCoordinationMember;

        const max_member_bytes: usize = 128 * 1024 * 1024;
        var data: std.ArrayList(u8) = .empty;
        defer data.deinit(allocator);
        var chunk: [64 * 1024]u8 = undefined;
        while (data.items.len <= max_member_bytes) {
            const remaining = (max_member_bytes + 1) - data.items.len;
            const ask = @min(chunk.len, remaining);
            const got = try syscall(linux.read(fd, &chunk, ask));
            if (got == 0) break;
            try data.appendSlice(allocator, chunk[0..got]);
        }
        const after = try fstat(fd);
        if (data.items.len != before.size or
            before.mode != after.mode or
            before.nlink != after.nlink or
            before.size != after.size or
            before.mtime.sec != after.mtime.sec or
            before.mtime.nsec != after.mtime.nsec or
            before.ctime.sec != after.ctime.sec or
            before.ctime.nsec != after.ctime.nsec)
        {
            return error.CoordinationMemberChanged;
        }
        coordination_bytes += data.items.len;
        if (coordination_bytes > 512 * 1024 * 1024) return error.CoordinationEvidenceExceedsLimit;

        try writeExclusiveAtFd(output_fd, name, 0o600, data.items);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data.items, &digest, .{});
        row.status = .present;
        row.size = data.items.len;
        row.sha256 = std.fmt.bytesToHex(digest, .lower);
    }
    capture_complete = true;
    try writeCoordinationInventory(allocator, evidence_fd, true, rows.items);
}

fn writeTruncateNoFollow(path: []const u8, payload: []const u8) !void {
    if (path.len == 0 or path.len >= maximum_path_bytes) return error.NoncanonicalReferencePath;
    var buf: [maximum_path_bytes]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&buf);
    const flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const fd: i32 = @intCast(try syscall(linux.openat(linux.AT.FDCWD, path_z, flags, 0o644)));
    defer _ = linux.close(fd);
    try writeAllFd(fd, payload);
}

fn ensureParentDirsUnderTarget(target: []const u8, relative: []const u8) !void {
    const dir_rel = std.fs.path.dirname(relative) orelse return;
    const target_fd = try openAbsolute(target, true);
    defer _ = linux.close(target_fd);
    var current: i32 = @intCast(try syscall(linux.fcntl(target_fd, linux.F.DUPFD_CLOEXEC, @as(usize, 0))));
    defer _ = linux.close(current);
    var it = std.mem.splitScalar(u8, dir_rel, '/');
    while (it.next()) |part| {
        if (part.len == 0 or part.len > 255) return error.NoncanonicalReferencePath;
        var buf: [256]u8 = undefined;
        @memcpy(buf[0..part.len], part);
        buf[part.len] = 0;
        const part_z: [*:0]const u8 = @ptrCast(&buf);
        const rc = linux.mkdirat(current, part_z, 0o755);
        switch (linux.errno(rc)) {
            .SUCCESS, .EXIST => {},
            else => return error.ReferenceSyscallRefused,
        }
        const next_fd = try openComponentAt(current, part, true);
        _ = linux.close(current);
        current = next_fd;
    }
}

fn writeTargetSha256Sums(allocator: std.mem.Allocator, target: []const u8) !void {
    const entries = try collectWalkEntries(allocator, target);
    defer {
        for (entries) |entry| entry.deinit(allocator);
        allocator.free(entries);
    }
    std.mem.sort(WalkEntry, entries, {}, lessThanWalkEntry);
    var sums: std.ArrayList(u8) = .empty;
    defer sums.deinit(allocator);
    for (entries) |entry| {
        if ((entry.meta.mode & linux.S.IFMT) != linux.S.IFREG) continue;
        if (std.mem.eql(u8, std.fs.path.basename(entry.path), "SHA256SUMS")) continue;
        const relative = entry.path[target.len + 1 ..];
        const digest = try sha256RegularNoFollow(entry.path);
        const line = try std.fmt.allocPrint(allocator, "{s}  {s}\n", .{ digest, relative });
        defer allocator.free(line);
        try sums.appendSlice(allocator, line);
    }
    if (sums.items.len == 0) try sums.append(allocator, '\n');
    const sums_path = try std.fs.path.join(allocator, &.{ target, "SHA256SUMS" });
    defer allocator.free(sums_path);
    try writeTruncateNoFollow(sums_path, sums.items);
}

fn exportEvidenceInner(
    allocator: std.mem.Allocator,
    source: []const u8,
    target: []const u8,
    failure_detail: *?[]u8,
) !void {
    const entries = try collectWalkEntries(allocator, source);
    defer {
        for (entries) |entry| entry.deinit(allocator);
        allocator.free(entries);
    }
    var total: u64 = 0;
    for (entries) |entry| {
        if ((entry.meta.mode & linux.S.IFMT) == linux.S.IFDIR) continue;
        if ((entry.meta.mode & linux.S.IFMT) != linux.S.IFREG or entry.meta.size > 128 * 1024 * 1024) {
            failure_detail.* = try std.fmt.allocPrint(allocator, "unsafe or oversized evidence member: {s}", .{entry.path});
            return error.UnsafeOrOversizedEvidenceMember;
        }
        total += entry.meta.size;
        if (total > 512 * 1024 * 1024) {
            failure_detail.* = try allocator.dupe(u8, "evidence exceeds 512 MiB");
            return error.EvidenceExceedsLimit;
        }
    }
    for (entries) |entry| {
        if ((entry.meta.mode & linux.S.IFMT) == linux.S.IFDIR) continue;
        const relative = entry.path[source.len + 1 ..];
        try ensureParentDirsUnderTarget(target, relative);
        const destination = try std.fs.path.join(allocator, &.{ target, relative });
        defer allocator.free(destination);

        const src_fd = try openAbsolute(entry.path, false);
        defer _ = linux.close(src_fd);

        var dst_buf: [maximum_path_bytes]u8 = undefined;
        @memcpy(dst_buf[0..destination.len], destination);
        dst_buf[destination.len] = 0;
        const dst_z: [*:0]const u8 = @ptrCast(&dst_buf);
        const dst_flags: linux.O = .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        };
        const dst_fd: i32 = @intCast(try syscall(linux.openat(linux.AT.FDCWD, dst_z, dst_flags, 0o644)));
        defer _ = linux.close(dst_fd);

        var chunk: [64 * 1024]u8 = undefined;
        while (true) {
            const got = try syscall(linux.read(src_fd, &chunk, chunk.len));
            if (got == 0) break;
            try writeAllFd(dst_fd, chunk[0..got]);
        }
    }
    const summary_path = try std.fs.path.join(allocator, &.{ target, "artifact-summary.txt" });
    defer allocator.free(summary_path);
    const summary_text = try std.fmt.allocPrint(allocator, "bytes_before_index={d}\n", .{total});
    defer allocator.free(summary_text);
    try writeTruncateNoFollow(summary_path, summary_text);
}

pub fn exportEvidence(allocator: std.mem.Allocator, source: []const u8, target: []const u8) !void {
    defer writeTargetSha256Sums(allocator, target) catch {};
    var failure_detail: ?[]u8 = null;
    defer if (failure_detail) |msg| allocator.free(msg);
    exportEvidenceInner(allocator, source, target, &failure_detail) catch |err| {
        const msg = failure_detail orelse @errorName(err);
        if (std.fs.path.join(allocator, &.{ target, "export-failure.txt" })) |failure_path| {
            defer allocator.free(failure_path);
            if (std.fmt.allocPrint(allocator, "{s}\n", .{msg})) |failure_line| {
                defer allocator.free(failure_line);
                writeTruncateNoFollow(failure_path, failure_line) catch {};
            } else |_| {}
        } else |_| {}
        if (!builtin.is_test) {
            writeAllFd(2, msg) catch {};
            writeAllFd(2, "\n") catch {};
        }
        return err;
    };
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
    if (args.len == 9 and std.mem.eql(u8, args[0], "stage-keyring")) {
        const expected_deb_size = std.fmt.parseInt(u64, args[3], 10) catch return 2;
        const expected_keyring_size = std.fmt.parseInt(u64, args[7], 10) catch return 2;
        const summary = stageArchiveKeyring(
            allocator,
            args[1],
            args[2],
            expected_deb_size,
            args[4],
            args[5],
            args[6],
            expected_keyring_size,
            args[8],
        ) catch |err| {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "keyring staging failed: {s}\n", .{@errorName(err)}) catch "keyring staging failed\n";
            try writeAllFd(2, msg);
            return 1;
        };
        defer allocator.free(summary);
        try writeAllFd(1, summary);
        try writeAllFd(1, "\n");
        return 0;
    }
    if (args.len == 3 and std.mem.eql(u8, args[0], "capture-coordination")) {
        captureCoordination(allocator, args[1], args[2]) catch |err| {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "coordination capture failed: {s}\n", .{@errorName(err)}) catch "coordination capture failed\n";
            try writeAllFd(2, msg);
            return 1;
        };
        return 0;
    }
    if (args.len == 3 and std.mem.eql(u8, args[0], "export-evidence")) {
        exportEvidence(allocator, args[1], args[2]) catch return 1;
        return 0;
    }
    try writeAllFd(
        2,
        "usage: debz-reference-paths ancestry|tree TREE | packages DIR OUTPUT | verify-keyring PATH SIZE SHA256 | stage-keyring PACKAGE PACKAGE_SHA512 PACKAGE_SIZE MEMBER TARGET KEYRING_SHA256 KEYRING_SIZE EVIDENCE | toolchain PATH | protected [--directory] PATH... | verify-minisign --public-key KEY --artifact PATH --signature PATH --name NAME --sha256 SHA256 --size SIZE | capture-coordination ROOT EVIDENCE | export-evidence EVIDENCE UPLOAD\n",
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

test "captureCoordination and exportEvidence enforce bounds and refuse symlinks" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try makeTempRoot(allocator, &tmp);
    defer allocator.free(root);

    try tmp.dir.createDirPath(std.testing.io, "candidate/var/lib/debz");
    try tmp.dir.createDirPath(std.testing.io, "evidence/staging");
    try tmp.dir.createDirPath(std.testing.io, "upload");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "candidate/var/lib/debz/root-operation-v1.json", .data = "{\"phase\":\"script\"}\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "evidence/create.json", .data = "{\"exit_status\":8}\n" });

    const candidate_dir = try std.fs.path.join(allocator, &.{ root, "candidate" });
    defer allocator.free(candidate_dir);
    const evidence_dir = try std.fs.path.join(allocator, &.{ root, "evidence" });
    defer allocator.free(evidence_dir);
    const upload_dir = try std.fs.path.join(allocator, &.{ root, "upload" });
    defer allocator.free(upload_dir);

    try captureCoordination(allocator, candidate_dir, evidence_dir);
    const inv_path = try std.fs.path.join(allocator, &.{ evidence_dir, "native-coordination-inventory-v1.json" });
    defer allocator.free(inv_path);
    const inv = try readRegularNoFollowAlloc(allocator, inv_path, 64 * 1024);
    defer allocator.free(inv);
    try std.testing.expect(std.mem.indexOf(u8, inv, "\"capture_complete\": true") != null);

    try exportEvidence(allocator, evidence_dir, upload_dir);
    const sums_path = try std.fs.path.join(allocator, &.{ upload_dir, "SHA256SUMS" });
    defer allocator.free(sums_path);
    const sums = try readRegularNoFollowAlloc(allocator, sums_path, 64 * 1024);
    defer allocator.free(sums);
    try std.testing.expect(std.mem.indexOf(u8, sums, "  native-coordination/root-operation-v1.json\n") != null);

    const untrusted_link = try std.fs.path.join(allocator, &.{ evidence_dir, "untrusted" });
    defer allocator.free(untrusted_link);
    try symlinkAtPath(inv_path, untrusted_link);
    try std.testing.expectError(error.UnsafeOrOversizedEvidenceMember, exportEvidence(allocator, evidence_dir, upload_dir));
    const failure_path = try std.fs.path.join(allocator, &.{ upload_dir, "export-failure.txt" });
    defer allocator.free(failure_path);
    const failure_txt = try readRegularNoFollowAlloc(allocator, failure_path, 64 * 1024);
    defer allocator.free(failure_txt);
    try std.testing.expect(std.mem.indexOf(u8, failure_txt, "unsafe or oversized evidence member") != null);
}

fn buildTestTarMember(allocator: std.mem.Allocator, name: []const u8, typeflag: u8, payload: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var header: [512]u8 = @splat(0);
    @memcpy(header[0..name.len], name);
    _ = try std.fmt.bufPrint(header[100..108], "{o:0>7}\x00", .{@as(u32, 0o644)});
    _ = try std.fmt.bufPrint(header[108..116], "{o:0>7}\x00", .{@as(u32, 0)});
    _ = try std.fmt.bufPrint(header[116..124], "{o:0>7}\x00", .{@as(u32, 0)});
    _ = try std.fmt.bufPrint(header[124..136], "{o:0>11}\x00", .{payload.len});
    _ = try std.fmt.bufPrint(header[136..148], "{o:0>11}\x00", .{@as(u32, 0)});
    @memset(header[148..156], ' ');
    header[156] = typeflag;
    @memcpy(header[257..263], "ustar\x00");
    @memcpy(header[263..265], "00");
    var sum: u32 = 0;
    for (header) |byte| sum += byte;
    _ = try std.fmt.bufPrint(header[148..156], "{o:0>6}\x00 ", .{sum});
    try out.appendSlice(allocator, &header);
    try out.appendSlice(allocator, payload);
    const pad = (512 - (payload.len % 512)) % 512;
    try out.appendNTimes(allocator, 0, pad);
    try out.appendNTimes(allocator, 0, 1024);
    return out.toOwnedSlice(allocator);
}

fn buildTestZstdRawFrame(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "\x28\xb5\x2f\xfd");
    try out.append(allocator, 0x60);
    var content_size_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &content_size_bytes, @intCast(payload.len - 256), .little);
    try out.appendSlice(allocator, &content_size_bytes);
    const block_header: u24 = (@as(u24, @intCast(payload.len)) << 3) | 1;
    var bh_bytes: [3]u8 = undefined;
    std.mem.writeInt(u24, &bh_bytes, block_header, .little);
    try out.appendSlice(allocator, &bh_bytes);
    try out.appendSlice(allocator, payload);
    return out.toOwnedSlice(allocator);
}

fn appendTestArMember(allocator: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, payload: []const u8) !void {
    var header: [60]u8 = @splat(' ');
    @memcpy(header[0..name.len], name);
    @memcpy(header[16..18], "0 ");
    @memcpy(header[28..30], "0 ");
    @memcpy(header[34..36], "0 ");
    @memcpy(header[40..46], "100644");
    const size_slice = try std.fmt.bufPrint(header[48..58], "{d}", .{payload.len});
    header[48 + size_slice.len] = ' ';
    header[58] = '`';
    header[59] = '\n';
    try out.appendSlice(allocator, &header);
    try out.appendSlice(allocator, payload);
    if (payload.len % 2 == 1) try out.append(allocator, '\n');
}

test "stageArchiveKeyring verifies package and tar member pins and unlinks on refusal" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try makeTempRoot(allocator, &tmp);
    defer allocator.free(root);
    test_root_override = root;
    defer test_root_override = null;

    const member_name = "./usr/share/keyrings/ubuntu-archive-keyring.gpg";
    const keyring_payload = "reviewed-ubuntu-archive-keyring-bytes";
    var keyring_sha256_bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(keyring_payload, &keyring_sha256_bytes, .{});
    const keyring_sha256 = std.fmt.bytesToHex(keyring_sha256_bytes, .lower);

    const tar_bytes = try buildTestTarMember(allocator, member_name, '0', keyring_payload);
    defer allocator.free(tar_bytes);
    const zstd_bytes = try buildTestZstdRawFrame(allocator, tar_bytes);
    defer allocator.free(zstd_bytes);

    var deb_buf: std.ArrayList(u8) = .empty;
    defer deb_buf.deinit(allocator);
    try deb_buf.appendSlice(allocator, "!<arch>\n");
    try appendTestArMember(allocator, &deb_buf, "debian-binary", "2.0\n");
    try appendTestArMember(allocator, &deb_buf, "data.tar.zst", zstd_bytes);
    const deb_bytes = deb_buf.items;

    var deb_sha512_bytes: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(deb_bytes, &deb_sha512_bytes, .{});
    const deb_sha512 = std.fmt.bytesToHex(deb_sha512_bytes, .lower);

    const deb_path = try std.fs.path.join(allocator, &.{ root, "ubuntu-keyring.deb" });
    defer allocator.free(deb_path);
    const target_path = try std.fs.path.join(allocator, &.{ root, "ubuntu-archive-keyring.gpg" });
    defer allocator.free(target_path);
    const evidence_path = try std.fs.path.join(allocator, &.{ root, "archive-keyring-path.tsv" });
    defer allocator.free(evidence_path);

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "archive-keyring-path.tsv", .data = "path\trole\tuid:gid:mode:size\talgorithm\tdigest\n" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "ubuntu-keyring.deb", .data = deb_bytes });
    try chmodPath(deb_path, 0o600);

    const summary = try stageArchiveKeyring(
        allocator,
        deb_path,
        &deb_sha512,
        deb_bytes.len,
        member_name,
        target_path,
        &keyring_sha256,
        keyring_payload.len,
        evidence_path,
    );
    defer allocator.free(summary);
    try std.testing.expect(std.mem.indexOf(u8, summary, "verified Ubuntu archive keyring from pinned package:") != null);

    const staged = try readRegularNoFollowAlloc(allocator, target_path, 4096);
    defer allocator.free(staged);
    try std.testing.expectEqualStrings(keyring_payload, staged);
    const evidence = try readRegularNoFollowAlloc(allocator, evidence_path, 4096);
    defer allocator.free(evidence);
    try std.testing.expect(std.mem.indexOf(u8, evidence, "\tdownloaded-package\t") != null);
    try std.testing.expect(std.mem.indexOf(u8, evidence, "\tstaged-keyring\t") != null);

    // Pre-existing target is refused without overwriting it.
    try std.testing.expectError(
        error.PackageManifestExists,
        stageArchiveKeyring(
            allocator,
            deb_path,
            &deb_sha512,
            deb_bytes.len,
            member_name,
            target_path,
            &keyring_sha256,
            keyring_payload.len,
            evidence_path,
        ),
    );
    try tmp.dir.deleteFile(std.testing.io, "ubuntu-archive-keyring.gpg");

    // Wrong keyring SHA-256 unlinks the downloaded package.
    const zero_sha256: [64]u8 = @splat('0');
    try std.testing.expectError(
        error.KeyringMemberPinMismatch,
        stageArchiveKeyring(
            allocator,
            deb_path,
            &deb_sha512,
            deb_bytes.len,
            member_name,
            target_path,
            &zero_sha256,
            keyring_payload.len,
            evidence_path,
        ),
    );
    try std.testing.expectError(error.ReferenceSyscallRefused, lstatPath(deb_path));

    // Wrong package SHA-512 unlinks the downloaded package.
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "ubuntu-keyring.deb", .data = deb_bytes });
    try chmodPath(deb_path, 0o600);
    const zero_sha512: [128]u8 = @splat('0');
    try std.testing.expectError(
        error.KeyringPackagePinMismatch,
        stageArchiveKeyring(
            allocator,
            deb_path,
            &zero_sha512,
            deb_bytes.len,
            member_name,
            target_path,
            &keyring_sha256,
            keyring_payload.len,
            evidence_path,
        ),
    );
    try std.testing.expectError(error.ReferenceSyscallRefused, lstatPath(deb_path));

    try std.testing.expectError(error.UnsafeKeyringTarMemberName, extractTarMember(tar_bytes, "/etc/passwd", 1));
    try std.testing.expectError(error.UnsafeKeyringTarMemberName, extractTarMember(tar_bytes, "a/../b", 1));
}


