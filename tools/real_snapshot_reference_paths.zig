const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const Pinned = struct {
    fd: i32,
    metadata: linux.Statx,

    pub fn close(self: Pinned) void {
        _ = linux.close(self.fd);
    }
};

pub fn syscall(result: usize) !usize {
    return switch (linux.errno(result)) {
        .SUCCESS => result,
        .NOENT => error.FileNotFound,
        .EXIST => error.PathAlreadyExists,
        else => error.ReferencePathRefused,
    };
}

pub fn stat(fd: i32) !linux.Statx {
    var result: linux.Statx = undefined;
    _ = try syscall(linux.statx(fd, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &result));
    return result;
}

pub fn same(a: linux.Statx, b: linux.Statx) bool {
    return a.dev_major == b.dev_major and a.dev_minor == b.dev_minor and
        a.ino == b.ino and a.mode == b.mode and a.uid == b.uid and a.gid == b.gid and
        a.nlink == b.nlink and a.size == b.size and
        a.mtime.sec == b.mtime.sec and a.mtime.nsec == b.mtime.nsec and
        a.ctime.sec == b.ctime.sec and a.ctime.nsec == b.ctime.nsec;
}

pub fn relative(path: []const u8) !void {
    if (path.len == 0 or path.len > 4096 or path[0] == '/' or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.NoncanonicalReferencePath;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or part.len > 255 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, ".."))
            return error.NoncanonicalReferencePath;
    }
}

pub fn absolute(path: []const u8) !void {
    if (path.len == 0 or path[0] != '/') return error.NoncanonicalReferencePath;
    if (path.len == 1) return;
    try relative(path[1..]);
}

fn component(fd: i32, name: []const u8, directory: bool, flags: linux.O, mode: u32) !i32 {
    var buffer: [256]u8 = undefined;
    if (name.len > 255) return error.NoncanonicalReferencePath;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = 0;
    var actual = flags;
    actual.NOFOLLOW = true;
    actual.CLOEXEC = true;
    actual.DIRECTORY = directory;
    actual.NONBLOCK = !directory;
    return @intCast(try syscall(linux.openat(fd, @ptrCast(&buffer), actual, mode)));
}

pub fn openBeneath(root_fd: i32, path: []const u8, directory: bool) !Pinned {
    try relative(path);
    var current: i32 = @intCast(try syscall(linux.fcntl(root_fd, linux.F.DUPFD_CLOEXEC, 0)));
    defer _ = linux.close(current);
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        const last = parts.index == null;
        const next = try component(current, part, !last or directory, .{ .ACCMODE = .RDONLY }, 0);
        _ = linux.close(current);
        current = next;
        if (last) {
            const result = Pinned{ .fd = current, .metadata = try stat(current) };
            current = -1;
            return result;
        }
    }
    unreachable;
}

pub fn openAbsolute(path: []const u8, directory: bool) !Pinned {
    try absolute(path);
    const root: i32 = @intCast(try syscall(linux.open("/", .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0)));
    defer _ = linux.close(root);
    if (path.len == 1 and directory) {
        const fd: i32 = @intCast(try syscall(linux.fcntl(root, linux.F.DUPFD_CLOEXEC, 0)));
        return .{ .fd = fd, .metadata = try stat(fd) };
    }
    return openBeneath(root, path[1..], directory);
}

fn protectedMetadata(info: linux.Statx, directory: bool) !void {
    if (info.uid != 0 or info.gid != 0 or info.mode & 0o022 != 0)
        return error.UnprotectedReferencePath;
    if (info.mode & 0o170000 != (if (directory) @as(u16, 0o040000) else @as(u16, 0o100000)))
        return error.WrongReferenceFileType;
}

var test_owner_root: if (builtin.is_test) ?[]const u8 else void = if (builtin.is_test) null else {};
fn protectedStat(fd: i32) !linux.Statx {
    var info = try stat(fd);
    if (builtin.is_test) if (test_owner_root) |root| {
        // Unit fixtures cannot be root-owned: ownership is assumed, while modes beneath the fixture root stay authoritative.
        var link: [32]u8 = undefined;
        var target: [std.fs.max_path_bytes]u8 = undefined;
        const length = try syscall(linux.readlink(try std.fmt.bufPrintZ(&link, "/proc/self/fd/{d}", .{fd}), &target, target.len));
        const path = target[0..length];
        info.uid = 0;
        info.gid = 0;
        if (!std.mem.eql(u8, path, root) and !(std.mem.startsWith(u8, path, root) and path.len > root.len and path[root.len] == '/'))
            info.mode &= ~@as(u16, 0o022);
    };
    return info;
}

pub fn openProtected(path: []const u8, directory: bool) !Pinned {
    try absolute(path);
    var current: i32 = @intCast(try syscall(linux.open("/", .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0)));
    errdefer _ = linux.close(current);
    try protectedMetadata(try protectedStat(current), true);
    if (path.len > 1) {
        var parts = std.mem.splitScalar(u8, path[1..], '/');
        while (parts.next()) |part| {
            const last = parts.index == null;
            const next = try component(current, part, !last or directory, .{ .ACCMODE = .RDONLY }, 0);
            _ = linux.close(current);
            current = next;
            try protectedMetadata(try protectedStat(current), !last or directory);
        }
    } else if (!directory) return error.WrongReferenceFileType;
    return .{ .fd = current, .metadata = try stat(current) };
}

pub fn protected(path: []const u8, directory: bool) !linux.Statx {
    const pin = try openProtected(path, directory);
    defer pin.close();
    return pin.metadata;
}

pub fn readPinned(allocator: std.mem.Allocator, pin: Pinned, limit: usize) ![]u8 {
    if (pin.metadata.mode & 0o170000 != 0o100000 or pin.metadata.size > limit)
        return error.InvalidReferenceDatabaseFile;
    const bytes = try allocator.alloc(u8, @intCast(pin.metadata.size));
    errdefer allocator.free(bytes);
    var count: usize = 0;
    while (count < bytes.len) {
        const got = try syscall(linux.pread(pin.fd, bytes[count..].ptr, bytes.len - count, @intCast(count)));
        if (got == 0) return error.ReferenceFileChanged;
        count += got;
    }
    var excess: [1]u8 = undefined;
    if (try syscall(linux.pread(pin.fd, &excess, 1, @intCast(bytes.len))) != 0 or
        !same(pin.metadata, try stat(pin.fd))) return error.ReferenceFileChanged;
    return bytes;
}

pub fn readRootFile(allocator: std.mem.Allocator, root: []const u8, path: []const u8, limit: usize) ![]u8 {
    const directory = try openAbsolute(root, true);
    defer directory.close();
    const pin = try openBeneath(directory.fd, path, false);
    defer pin.close();
    return readPinned(allocator, pin, limit);
}

pub fn names(allocator: std.mem.Allocator, io: std.Io, pin: Pinned, limit: usize) ![][]const u8 {
    var result: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (result.items) |name| allocator.free(name);
        result.deinit(allocator);
    }
    const dir: std.Io.Dir = .{ .handle = pin.fd };
    var iterator = dir.iterate();
    while (try iterator.next(io)) |item| {
        if (result.items.len >= limit) return error.ReferenceDirectoryExceedsBound;
        try result.append(allocator, try allocator.dupe(u8, item.name));
    }
    std.mem.sort([]const u8, result.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    return result.toOwnedSlice(allocator);
}

pub fn exists(root: []const u8, path: []const u8) !bool {
    try relative(path);
    const directory = try openAbsolute(root, true);
    defer directory.close();
    const parent = std.fs.path.dirname(path);
    const pin = if (parent) |p| openBeneath(directory.fd, p, true) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    } else directory;
    defer if (parent != null) pin.close();
    var buffer: [256]u8 = undefined;
    const leaf = std.fs.path.basename(path);
    @memcpy(buffer[0..leaf.len], leaf);
    buffer[leaf.len] = 0;
    var info: linux.Statx = undefined;
    const result = linux.statx(pin.fd, @ptrCast(&buffer), linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &info);
    if (linux.errno(result) == .NOENT) return false;
    _ = try syscall(result);
    return true;
}

pub fn create(root: []const u8, path: []const u8, mode: u32, append: bool) !i32 {
    try relative(path);
    const directory = try openAbsolute(root, true);
    defer directory.close();
    const parent = std.fs.path.dirname(path);
    const pin = if (parent) |p| try openBeneath(directory.fd, p, true) else directory;
    defer if (parent != null) pin.close();
    const fd = try component(pin.fd, std.fs.path.basename(path), false, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = !append,
        .APPEND = append,
    }, mode);
    errdefer _ = linux.close(fd);
    const info = try stat(fd);
    if (info.mode & 0o170000 != 0o100000 or info.nlink != 1) return error.WrongReferenceFileType;
    return fd;
}

pub fn writeAll(fd: i32, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const got = try syscall(linux.write(fd, bytes[offset..].ptr, bytes.len - offset));
        if (got == 0) return error.ReferenceWriteFailed;
        offset += got;
    }
}

pub fn verifyKeyring(allocator: std.mem.Allocator, path: []const u8, size: usize, digest: []const u8) ![64]u8 {
    const pin = try openProtected(path, false);
    defer pin.close();
    const payload = try readPinned(allocator, pin, size);
    defer allocator.free(payload);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &hash, .{});
    const actual = std.fmt.bytesToHex(hash, .lower);
    if (payload.len != size or !std.mem.eql(u8, &actual, digest)) return error.UbuntuArchiveKeyringMemberPinMismatch;
    return actual;
}

fn libraryTree(allocator: std.mem.Allocator, io: std.Io, library: []const u8, path: []const u8, depth: usize, count: *usize) !void {
    if (depth > 128 or count.* > 200000) return error.ReferenceToolchainExceedsBound;
    const pin = try openProtected(path, true);
    defer pin.close();
    const entries = try names(allocator, io, pin, 200000);
    defer {
        for (entries) |entry| allocator.free(entry);
        allocator.free(entries);
    }
    for (entries) |name| {
        count.* += 1;
        const entry = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ path, name });
        defer allocator.free(entry);
        const name_z = try allocator.dupeZ(u8, name);
        defer allocator.free(name_z);
        var info: linux.Statx = undefined;
        _ = try syscall(linux.statx(pin.fd, name_z, linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &info));
        if (info.mode & 0o170000 == 0o120000) {
            var resolved: [std.fs.max_path_bytes]u8 = undefined;
            const length = try std.Io.Dir.cwd().realPathFile(io, entry, &resolved);
            const target = resolved[0..length];
            if (!std.mem.startsWith(u8, target, library) or
                (target.len != library.len and target[library.len] != '/'))
                return error.ToolchainLibrarySymlinkEscapes;
            const target_pin = try openAbsolute(target, false);
            defer target_pin.close();
            _ = try protected(target, target_pin.metadata.mode & 0o170000 == 0o040000);
        } else if (info.mode & 0o170000 == 0o040000) {
            try libraryTree(allocator, io, library, entry, depth + 1, count);
        } else {
            _ = try protected(entry, false);
        }
    }
}

pub fn toolchain(allocator: std.mem.Allocator, io: std.Io, compiler: []const u8) ![]u8 {
    const info = try protected(compiler, false);
    if (info.mode & 0o111 == 0) return error.ReferenceCompilerNotExecutable;
    const library = try std.fmt.allocPrint(allocator, "{s}/lib", .{std.fs.path.dirname(compiler).?});
    errdefer allocator.free(library);
    var count: usize = 0;
    try libraryTree(allocator, io, library, library, 0, &count);
    return library;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const a = init.arena.allocator();
    if (args.len == 4 and std.mem.eql(u8, args[1], "protected")) {
        const directory = std.mem.eql(u8, args[2], "directory");
        if (!directory and !std.mem.eql(u8, args[2], "file")) return error.InvalidReferencePathsArguments;
        _ = try protected(args[3], directory);
    } else if (args.len == 3 and std.mem.eql(u8, args[1], "toolchain")) {
        const library = try toolchain(a, init.io, args[2]);
        try writeAll(1, library);
        try writeAll(1, "\n");
    } else if (args.len == 5 and std.mem.eql(u8, args[1], "keyring")) {
        const actual = try verifyKeyring(a, args[2], try std.fmt.parseInt(usize, args[3], 10), args[4]);
        try writeAll(1, &actual);
        try writeAll(1, "\n");
    } else return error.InvalidReferencePathsArguments;
}

test "descriptor-rooted paths reject traversals and aliases before reading" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const size = try work.dir.realPath(io, &buffer);
    const root = buffer[0..size];
    try work.dir.createDirPath(io, "var/lib/dpkg");
    try work.dir.writeFile(io, .{ .sub_path = "var/lib/dpkg/status", .data = "original\n" });
    const bytes = try readRootFile(a, root, "var/lib/dpkg/status", 64);
    defer a.free(bytes);
    try std.testing.expectEqualStrings("original\n", bytes);
    try std.testing.expectError(error.NoncanonicalReferencePath, readRootFile(a, root, "../status", 64));
    try work.dir.symLink(io, "/etc", "alias", .{ .is_directory = true });
    try std.testing.expectError(error.ReferencePathRefused, readRootFile(a, root, "alias/passwd", 65536));
    try work.dir.symLink(io, "/etc/passwd", "leaf", .{});
    try std.testing.expectError(error.ReferencePathRefused, readRootFile(a, root, "leaf", 65536));
    try std.testing.expectError(error.InvalidReferenceDatabaseFile, readRootFile(a, root, "var/lib/dpkg/status", 1));
}

test "protected component metadata rejects either nonroot owner mutable ancestry or wrong type" {
    var original = std.mem.zeroes(linux.Statx);
    original.mode = 0o100644;
    try protectedMetadata(original, false);
    for (0..5) |mutation| {
        var changed = original;
        switch (mutation) {
            0 => changed.uid = 1,
            1 => changed.gid = 1,
            2 => changed.mode |= 0o020,
            3 => changed.mode |= 0o002,
            4 => changed.mode = 0o040755,
            else => unreachable,
        }
        try std.testing.expectError(if (mutation == 4) error.WrongReferenceFileType else error.UnprotectedReferencePath, protectedMetadata(changed, false));
    }
    original.mode = 0o040755;
    try protectedMetadata(original, true);
    try std.testing.expectError(error.WrongReferenceFileType, protectedMetadata(original, false));
}

test "pinned reads detect metadata drift and all rooted descriptor duplicates remain close on exec" {
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    const io = std.testing.io;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const size = try work.dir.realPath(io, &buffer);
    const root = buffer[0..size];
    try work.dir.writeFile(io, .{ .sub_path = "status", .data = "unchanged\n" });
    const directory = try openAbsolute(root, true);
    defer directory.close();
    const file = try openBeneath(directory.fd, "status", false);
    defer file.close();
    for ([_]i32{ directory.fd, file.fd }) |fd|
        try std.testing.expect(try syscall(linux.fcntl(fd, linux.F.GETFD, 0)) & linux.FD_CLOEXEC != 0);
    const changed_mode: u32 = if (file.metadata.mode & 0o777 == 0o600) 0o644 else 0o600;
    _ = try syscall(linux.fchmod(file.fd, changed_mode));
    try std.testing.expectError(error.ReferenceFileChanged, readPinned(std.testing.allocator, file, 64));
    try std.testing.expect(!try exists(root, "missing-parent/status"));
}

// Original protected-input observations, with fixture ownership assumed through test_owner_root.
fn expectOsRefusal(result: anytype) !void {
    if (result) |_| return error.AcceptedOriginalOsRefusal else |err| switch (err) {
        error.ReferencePathRefused, error.FileNotFound, error.PathAlreadyExists => {},
        else => return err,
    }
}

test "original keyring refuses unprotected writable symlinked and wrong bytes" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try work.dir.realPath(io, &buffer)];
    const root_pin = try openAbsolute(root, true);
    defer root_pin.close();
    _ = try syscall(linux.fchmod(root_pin.fd, 0o700));
    const payload = "reviewed fixture bytes";
    try work.dir.writeFile(io, .{ .sub_path = "keyring", .data = payload });
    const keyring = try std.fmt.allocPrint(a, "{s}/keyring", .{root});
    const keyring_pin = try openAbsolute(keyring, false);
    defer keyring_pin.close();
    _ = try syscall(linux.fchmod(keyring_pin.fd, 0o644));
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &hash, .{});
    const digest = std.fmt.bytesToHex(hash, .lower);
    try std.testing.expectError(error.UnprotectedReferencePath, verifyKeyring(a, keyring, payload.len, &digest));
    test_owner_root = root;
    defer test_owner_root = null;
    try std.testing.expectEqualStrings(&digest, &(try verifyKeyring(a, keyring, payload.len, &digest)));
    try std.testing.expectError(error.UbuntuArchiveKeyringMemberPinMismatch, verifyKeyring(a, keyring, payload.len + 1, &digest));
    try std.testing.expectError(error.UbuntuArchiveKeyringMemberPinMismatch, verifyKeyring(a, keyring, payload.len, "0" ** 64));
    try work.dir.writeFile(io, .{ .sub_path = "keyring", .data = payload[0 .. payload.len - 1] ++ "?" });
    try std.testing.expectError(error.UbuntuArchiveKeyringMemberPinMismatch, verifyKeyring(a, keyring, payload.len, &digest));
    try work.dir.writeFile(io, .{ .sub_path = "keyring", .data = payload });
    _ = try syscall(linux.fchmod(keyring_pin.fd, 0o666));
    try std.testing.expectError(error.UnprotectedReferencePath, verifyKeyring(a, keyring, payload.len, &digest));
    _ = try syscall(linux.fchmod(keyring_pin.fd, 0o644));
    try work.dir.symLink(io, keyring, "linked", .{});
    try expectOsRefusal(verifyKeyring(a, try std.fmt.allocPrint(a, "{s}/linked", .{root}), payload.len, &digest));
    try work.dir.symLink(io, root, "linked-dir", .{ .is_directory = true });
    try expectOsRefusal(verifyKeyring(a, try std.fmt.allocPrint(a, "{s}/linked-dir/keyring", .{root}), payload.len, &digest));
    _ = try syscall(linux.fchmod(root_pin.fd, 0o777));
    try std.testing.expectError(error.UnprotectedReferencePath, verifyKeyring(a, keyring, payload.len, &digest));
}

test "original compiler binds protected library ancestry without resolving input links" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    var work = std.testing.tmpDir(.{ .iterate = true });
    defer work.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try work.dir.realPath(io, &buffer)];
    const root_pin = try openAbsolute(root, true);
    defer root_pin.close();
    _ = try syscall(linux.fchmod(root_pin.fd, 0o700));
    try work.dir.writeFile(io, .{ .sub_path = "zig", .data = "#!/bin/sh\nexit 0\n" });
    const compiler = try std.fmt.allocPrint(a, "{s}/zig", .{root});
    const compiler_pin = try openAbsolute(compiler, false);
    defer compiler_pin.close();
    _ = try syscall(linux.fchmod(compiler_pin.fd, 0o755));
    try work.dir.createDir(io, "lib", .default_dir);
    const library = try std.fmt.allocPrint(a, "{s}/lib", .{root});
    const library_pin = try openAbsolute(library, true);
    defer library_pin.close();
    _ = try syscall(linux.fchmod(library_pin.fd, 0o755));
    try work.dir.writeFile(io, .{ .sub_path = "lib/std.zig", .data = "fixture" });
    const source_pin = try openAbsolute(try std.fmt.allocPrint(a, "{s}/lib/std.zig", .{root}), false);
    defer source_pin.close();
    _ = try syscall(linux.fchmod(source_pin.fd, 0o644));
    try std.testing.expectError(error.UnprotectedReferencePath, toolchain(a, io, compiler));
    test_owner_root = root;
    defer test_owner_root = null;
    try std.testing.expectEqualStrings(library, try toolchain(a, io, compiler));
    _ = try syscall(linux.fchmod(compiler_pin.fd, 0o777));
    try std.testing.expectError(error.UnprotectedReferencePath, toolchain(a, io, compiler));
    _ = try syscall(linux.fchmod(compiler_pin.fd, 0o755));
    _ = try syscall(linux.fchmod(source_pin.fd, 0o666));
    try std.testing.expectError(error.UnprotectedReferencePath, toolchain(a, io, compiler));
    _ = try syscall(linux.fchmod(source_pin.fd, 0o644));
    try work.dir.symLink(io, compiler, "lib/escape", .{});
    try std.testing.expectError(error.ToolchainLibrarySymlinkEscapes, toolchain(a, io, compiler));
    try work.dir.deleteFile(io, "lib/escape");
    try work.dir.symLink(io, compiler, "linked-zig", .{});
    try expectOsRefusal(toolchain(a, io, try std.fmt.allocPrint(a, "{s}/linked-zig", .{root})));
    try std.Io.Dir.rename(work.dir, "lib", work.dir, "real-lib", io);
    try work.dir.symLink(io, try std.fmt.allocPrint(a, "{s}/real-lib", .{root}), "lib", .{ .is_directory = true });
    try expectOsRefusal(toolchain(a, io, compiler));
}
