//! Descriptor-rooted setup, fixture mutations, and callback sealing for
//! disposable signed arm64 less/bash/util-linux and amd64/arm64 Python reference roots.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const reference_paths = @import("reference_paths");

pub const maximum_regular_bytes: usize = 8 * 1024 * 1024;
pub const maximum_capture_bytes: usize = 16 * 1024 * 1024;
pub const maximum_tar_capture_bytes: u64 = 64 * 1024 * 1024;
pub const maximum_member_bytes: usize = 2 * 1024 * 1024;

pub const Error = error{
    InvalidFixtureMutationPath,
    UnsafeFixtureRegularFile,
    FixtureSourceExceedsByteLimit,
    FixtureSourceBytesChanged,
    UnsafeFixtureDirectoryOwner,
    UnsafeExistingFixtureDirectoryMode,
    UnexpectedFixtureAlias,
    ProtectedFixtureSourceChanged,
    FiveNegativeRootsRequired,
    UnsupportedSignedLessScriptMutation,
    FixtureRootMustBeMode0700,
    UnexpectedSignedLessScriptFixture,
    UnexpectedSignedLessPreinstFixture,
    UnexpectedSignedLessShellAlias,
    CapturedSourceProcMustBeEmpty,
    SignedPythonListPathSetChanged,
    UnexpectedReferenceNullDevice,
    EightPythonNegativeRootsRequired,
    UnexpectedPythonNegativeRootMetadata,
    FourStrictPythonNegativeRootsRequired,
    UnexpectedSignedMinimalProducer,
    PythonReferenceCaptureExceedsByteLimit,
    UnknownPythonFixtureStage,
    UnexpectedFreshTemplateLib64Alias,
    AmbiguousSignedSourceArchive,
    UnauthenticatedSourceArchive,
    SourceArchiveDiffersFromProductionAuthority,
    SourceArchiveMetadataChanged,
    SourceArchiveBytesChanged,
    SignedSourceDataArchiveExceedsBound,
    UnexpectedSignedRuntimeMember,
    SignedLdconfigCacheProducerChanged,
    UnsupportedSignedAlternativesSource,
    InvalidGoalLockSet,
    SourceTargetMustBeArm64,
    SignedRuntimeMemberChanged,
    SignedLessOwnershipPathSetChanged,
    SignedLessPreinstChanged,
    SignedLessPostinstChanged,
    SignedBashOwnershipPathSetChanged,
    SignedBashPostinstChanged,
    SignedPerlBaseInterpreterMetadataChanged,
    SignedPerlBaseInterpreterChanged,
    SignedLibc6LibmRuntimeChanged,
    SignedLessPrestateOwnershipPathSetChanged,
    SignedUtilLinuxOwnershipPathSetChanged,
    SignedUtilLinuxPostinstChanged,
    ProtectedSourceSetupRequiresRoot,
    UnknownSourceSetupStage,
    FixtureFileAlreadyExists,
    FixtureFileNotFound,
} || reference_paths.Error || std.mem.Allocator.Error;

pub const ArtifactPin = struct {
    name: []const u8,
    version: []const u8,
    declared_size: u64,
    sha512: []const u8,
};

pub const source_artifacts = [_]ArtifactPin{
    .{
        .name = "less",
        .version = "668-1build1",
        .declared_size = 171138,
        .sha512 = "f3d538070be0217eec1c5e747f0b6ed05b08b22a006001dafac6c87747ab46e9055fb8bf1985aed2d4010f57d597108dbff22ed73f92959703fffa57ec84e0e8",
    },
    .{
        .name = "dash",
        .version = "0.5.12-12ubuntu3",
        .declared_size = 95716,
        .sha512 = "c4a44690b1541936c4c85956f8e5bef0c915ce05afe6618230b70f4906803f8710b314b9093b451787b995bcd7b25a3947f51c8efa03dbda16c7eac720f93c6e",
    },
    .{
        .name = "dpkg",
        .version = "1.23.7ubuntu1",
        .declared_size = 1260980,
        .sha512 = "824a6a3f33837c16dedb4faff92bd15b0dbe82d27dd9b25403f87ec4572acc6332159a6374558185ca503e18de6f637d2a79e7db9fafaab3ccae4ac77427eee5",
    },
    .{
        .name = "libc6",
        .version = "2.43-2ubuntu2.4",
        .declared_size = 1642036,
        .sha512 = "865127bc2d7d9218e2a3482b7e0b5ae3649c31bcac82d0437a7231c798f56a1939f0f18fc664111a7c446eef6f9864176c040ad78b7aac1a6a3afe4d4b9cbeb7",
    },
};

pub const bash_artifacts = [_]ArtifactPin{
    .{
        .name = "bash",
        .version = "5.3-2ubuntu1",
        .declared_size = 829052,
        .sha512 = "7cdebc65396efe02fa527b6314b733266cec1026313b57e5a14d29225679bf6c402763fc4ea8b50387f4135623fd3372bfc033c6e7f7cb23573d83308bc20701",
    },
    .{
        .name = "libtinfo6",
        .version = "6.6+20251231-1",
        .declared_size = 107766,
        .sha512 = "301fe9df359848c63f76e5c626aaf40beb954ce95ffa96526532d7e6b86e4539099df41348aecdc9af45fd96a247d5c3f84d0393dc1408202027b545556193af",
    },
    .{
        .name = "libc-bin",
        .version = "2.43-2ubuntu2.4",
        .declared_size = 597592,
        .sha512 = "e964f5753787fa44c95c7144507b178b970359b1ea90a732b2f2b6a1831d67ef3bf5b900d57ae682d3481676f8080b6382a130c6e13112a40fb698435ee124cc",
    },
};

pub const util_linux_artifacts = [_]ArtifactPin{
    .{
        .name = "util-linux",
        .version = "2.41.3-3ubuntu2.2",
        .declared_size = 1055344,
        .sha512 = "adfe77778337bbf3d72b60d2c1f0089821b561876c792104bbe62a8429120d7cdbc665d537993954e2a0312a996a06d3259f7ebcb080b7ad18c64805fdbbdfad",
    },
    .{
        .name = "init-system-helpers",
        .version = "1.69",
        .declared_size = 39536,
        .sha512 = "8db5ef8d468542689fb47d78a28d4936762339e9b001d6655074a3357e39ff9933b1be7feebda417f42d1a7bd5b447e3476b0dc3964a245a60212a37728cebb5",
    },
    .{
        .name = "perl-base",
        .version = "5.40.1-7ubuntu0.3",
        .declared_size = 1787114,
        .sha512 = "41d0be5882f2c4d996a9e5c75e42d9a852158285da60526a03ff4b073666e039353e9b8c72e25156f38bdc359ff2dfe016a1e105bd8d16b0560aaa13319539a4",
    },
    .{
        .name = "libcrypt1",
        .version = "1:4.5.1-1",
        .declared_size = 88276,
        .sha512 = "d088db1e2abe0d16d3dd0308417db9163eaa1311ab752ec1b2d05df9ba25ca2e20b2dec38ec0daa841f51885bddd59bcc0b48c353ca7ecba23dc5d2df11c0ac3",
    },
};

var test_allow_regular_null_device: bool = false;

pub fn findArtifactPin(package: []const u8) ?ArtifactPin {
    inline for (.{ source_artifacts, bash_artifacts, util_linux_artifacts }) |table| {
        for (table) |pin| {
            if (std.mem.eql(u8, pin.name, package)) return pin;
        }
    }
    return null;
}

pub fn expectedArchiveArchitecture(package: []const u8) []const u8 {
    if (std.mem.eql(u8, package, "init-system-helpers")) return "all";
    return "arm64";
}

fn syscall(result: usize) !usize {
    return switch (linux.errno(result)) {
        .SUCCESS => result,
        .EXIST => error.FixtureFileAlreadyExists,
        .NOENT => error.FixtureFileNotFound,
        else => error.ReferenceSyscallRefused,
    };
}

fn rawStatxAt(dir_fd: i32, path: [*:0]const u8, flags: u32) !linux.Statx {
    var value = std.mem.zeroes(linux.Statx);
    _ = try syscall(linux.statx(dir_fd, path, flags, .BASIC_STATS, &value));
    return value;
}

fn rawFstat(fd: i32) !linux.Statx {
    return rawStatxAt(fd, "", linux.AT.EMPTY_PATH | linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT);
}

fn writeAllFd(fd: i32, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try syscall(linux.write(fd, bytes[written..].ptr, bytes.len - written));
        if (n == 0) return error.ReferenceSyscallRefused;
        written += n;
    }
}

fn readBoundedFd(allocator: std.mem.Allocator, fd: i32, limit: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var buf: [64 * 1024]u8 = undefined;
    while (out.items.len <= limit) {
        const remaining = (limit + 1) - out.items.len;
        const chunk = @min(buf.len, remaining);
        const got = try syscall(linux.read(fd, &buf, chunk));
        if (got == 0) break;
        try out.appendSlice(allocator, buf[0..got]);
    }
    return out.toOwnedSlice(allocator);
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

pub const ParentDescriptor = struct {
    fd: i32,
    name: []const u8,
};

pub fn openParentDescriptor(root: []const u8, relative: []const u8) !ParentDescriptor {
    if (relative.len == 0 or relative[0] == '/') return error.InvalidFixtureMutationPath;
    const slash = std.mem.lastIndexOfScalar(u8, relative, '/');
    const parent = if (slash) |idx| relative[0..idx] else "";
    const name = if (slash) |idx| relative[idx + 1 ..] else relative;
    if (name.len == 0 or name.len > 255 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, ".."))
        return error.InvalidFixtureMutationPath;
    if (std.mem.indexOfScalar(u8, name, 0) != null)
        return error.InvalidFixtureMutationPath;

    const root_fd = try reference_paths.openAbsolute(root, true);
    if (slash != null) {
        defer _ = linux.close(root_fd);
        const parent_fd = try reference_paths.openBeneath(root_fd, parent, true);
        return .{ .fd = parent_fd, .name = name };
    }
    return .{ .fd = root_fd, .name = name };
}

pub fn regularMetadata(descriptor: i32) !linux.Statx {
    const metadata = try rawFstat(descriptor);
    if ((metadata.mode & linux.S.IFMT) != linux.S.IFREG or
        metadata.nlink != 1 or
        metadata.uid != linux.geteuid() or
        metadata.gid != linux.getegid())
    {
        return error.UnsafeFixtureRegularFile;
    }
    return metadata;
}

fn toNameZ(name: []const u8, buf: *[256]u8) ![*:0]const u8 {
    if (name.len == 0 or name.len > 255 or std.mem.indexOfScalar(u8, name, 0) != null)
        return error.InvalidFixtureMutationPath;
    @memcpy(buf[0..name.len], name);
    buf[name.len] = 0;
    return @ptrCast(buf);
}

fn dupeZSlice(allocator: std.mem.Allocator, text: []const u8) ![:0]u8 {
    if (std.mem.indexOfScalar(u8, text, 0) != null) return error.InvalidFixtureMutationPath;
    const out = try allocator.allocSentinel(u8, text.len, 0);
    @memcpy(out, text);
    return out;
}

pub fn openRegularDescriptor(root: []const u8, relative: []const u8) !i32 {
    const parent = try openParentDescriptor(root, relative);
    defer _ = linux.close(parent.fd);
    var name_buf: [256]u8 = undefined;
    const name_z = try toNameZ(parent.name, &name_buf);
    const flags: linux.O = .{
        .ACCMODE = .RDWR,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    };
    const descriptor: i32 = @intCast(try syscall(linux.openat(parent.fd, name_z, flags, 0)));
    errdefer _ = linux.close(descriptor);
    _ = try regularMetadata(descriptor);
    return descriptor;
}

pub fn replaceContents(descriptor: i32, contents: []const u8) !void {
    _ = try regularMetadata(descriptor);
    _ = try syscall(linux.ftruncate(descriptor, 0));
    _ = try syscall(linux.lseek(descriptor, 0, linux.SEEK.SET));
    try writeAllFd(descriptor, contents);
}

pub fn overwriteRegular(root: []const u8, relative: []const u8, contents: []const u8) !void {
    const descriptor = try openRegularDescriptor(root, relative);
    defer _ = linux.close(descriptor);
    try replaceContents(descriptor, contents);
}

pub fn createExclusive(root: []const u8, relative: []const u8, contents: []const u8, mode: u16) !void {
    const parent = try openParentDescriptor(root, relative);
    defer _ = linux.close(parent.fd);
    var name_buf: [256]u8 = undefined;
    const name_z = try toNameZ(parent.name, &name_buf);
    const flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const descriptor: i32 = @intCast(try syscall(linux.openat(parent.fd, name_z, flags, mode)));
    defer _ = linux.close(descriptor);
    _ = try regularMetadata(descriptor);
    try writeAllFd(descriptor, contents);
    _ = try syscall(linux.fchmod(descriptor, mode));
}

pub fn readRegular(allocator: std.mem.Allocator, root: []const u8, relative: []const u8, maximum: usize) ![]u8 {
    const parent = try openParentDescriptor(root, relative);
    defer _ = linux.close(parent.fd);
    var name_buf: [256]u8 = undefined;
    const name_z = try toNameZ(parent.name, &name_buf);
    const flags: linux.O = .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    };
    const descriptor: i32 = @intCast(try syscall(linux.openat(parent.fd, name_z, flags, 0)));
    defer _ = linux.close(descriptor);
    const metadata = try regularMetadata(descriptor);
    if (metadata.size > maximum) return error.FixtureSourceExceedsByteLimit;
    const content = try readBoundedFd(allocator, descriptor, maximum);
    errdefer allocator.free(content);
    if (content.len != metadata.size) return error.FixtureSourceBytesChanged;
    return content;
}

pub fn chmodRegular(root: []const u8, relative: []const u8, mode: u16) !void {
    const descriptor = try openRegularDescriptor(root, relative);
    defer _ = linux.close(descriptor);
    _ = try syscall(linux.fchmod(descriptor, mode));
}

pub fn ensureDirectory(root: []const u8, relative: []const u8, mode: u16, exclusive: bool) !void {
    const parent = try openParentDescriptor(root, relative);
    defer _ = linux.close(parent.fd);
    var name_buf: [256]u8 = undefined;
    const name_z = try toNameZ(parent.name, &name_buf);
    var created = false;
    const mkdir_rc = linux.mkdirat(parent.fd, name_z, mode);
    switch (linux.errno(mkdir_rc)) {
        .SUCCESS => created = true,
        .EXIST => if (exclusive) return error.FixtureFileAlreadyExists,
        else => return error.ReferenceSyscallRefused,
    }
    const flags: linux.O = .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const descriptor: i32 = @intCast(try syscall(linux.openat(parent.fd, name_z, flags, 0)));
    defer _ = linux.close(descriptor);
    const metadata = try rawFstat(descriptor);
    if (metadata.uid != linux.geteuid() or metadata.gid != linux.getegid())
        return error.UnsafeFixtureDirectoryOwner;
    if (created) {
        _ = try syscall(linux.fchmod(descriptor, mode));
    } else if ((metadata.mode & 0o7777) != mode) {
        return error.UnsafeExistingFixtureDirectoryMode;
    }
}

pub fn replaceSymlink(root: []const u8, relative: []const u8, expected: []const u8, target: []const u8) !void {
    const parent = try openParentDescriptor(root, relative);
    defer _ = linux.close(parent.fd);
    var name_buf: [256]u8 = undefined;
    const name_z = try toNameZ(parent.name, &name_buf);
    const metadata = try rawStatxAt(parent.fd, name_z, linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT);
    var link_buf: [reference_paths.maximum_path_bytes]u8 = undefined;
    const link_len = try syscall(linux.readlinkat(parent.fd, name_z, &link_buf, link_buf.len));
    if ((metadata.mode & linux.S.IFMT) != linux.S.IFLNK or
        metadata.nlink != 1 or
        metadata.uid != linux.geteuid() or
        metadata.gid != linux.getegid() or
        !std.mem.eql(u8, link_buf[0..link_len], expected))
    {
        return error.UnexpectedFixtureAlias;
    }
    if (target.len == 0 or target.len >= reference_paths.maximum_path_bytes or std.mem.indexOfScalar(u8, target, 0) != null)
        return error.InvalidFixtureMutationPath;
    var target_buf: [reference_paths.maximum_path_bytes]u8 = undefined;
    @memcpy(target_buf[0..target.len], target);
    target_buf[target.len] = 0;
    const target_z: [*:0]const u8 = @ptrCast(&target_buf);
    _ = try syscall(linux.unlinkat(parent.fd, name_z, 0));
    _ = try syscall(linux.symlinkat(target_z, parent.fd, name_z));
}

pub fn copyExclusive(allocator: std.mem.Allocator, root: []const u8, relative: []const u8, source: []const u8, mode: u16) !void {
    _ = try reference_paths.protected(source, false);
    const descriptor = try reference_paths.openAbsolute(source, false);
    defer _ = linux.close(descriptor);
    const metadata = try regularMetadata(descriptor);
    if (metadata.size > maximum_regular_bytes) return error.FixtureSourceExceedsByteLimit;
    const contents = try readBoundedFd(allocator, descriptor, @intCast(metadata.size));
    defer allocator.free(contents);
    if (contents.len != metadata.size) return error.ProtectedFixtureSourceChanged;
    try createExclusive(root, relative, contents, mode);
}

pub fn mutateNegativeRoots(allocator: std.mem.Allocator, roots: []const []const u8, kind: []const u8) !void {
    if (roots.len != 5) return error.FiveNegativeRootsRequired;
    const is_preinst = std.mem.eql(u8, kind, "preinst");
    const is_postinst = std.mem.eql(u8, kind, "postinst");
    if (!is_preinst and !is_postinst) return error.UnsupportedSignedLessScriptMutation;
    for (roots) |root| {
        const metadata = try reference_paths.protected(root, true);
        if ((metadata.mode & 0o7777) != 0o700) return error.FixtureRootMustBeMode0700;
    }
    const bad_script = roots[0];
    const bad_mode = roots[1];
    const bad_tool = roots[2];
    const bad_alias = roots[3];
    const bad_prestate = roots[4];
    const relative = if (is_preinst) "var/lib/dpkg/info/less.preinst" else "var/lib/dpkg/info/less.postinst";
    {
        const descriptor = try openRegularDescriptor(bad_script, relative);
        defer _ = linux.close(descriptor);
        const contents = try readBoundedFd(allocator, descriptor, 1024);
        defer allocator.free(contents);
        const expected_len: usize = if (is_preinst) 292 else 374;
        if (contents.len != expected_len) return error.UnexpectedSignedLessScriptFixture;
        if (is_preinst) {
            if (std.mem.indexOf(u8, contents, "exit 0") == null)
                return error.UnexpectedSignedLessPreinstFixture;
            const mutated = try std.mem.replaceOwned(u8, allocator, contents, "exit 0", "exit 1");
            defer allocator.free(mutated);
            try replaceContents(descriptor, mutated);
        } else {
            const mutated = try std.fmt.allocPrint(allocator, "{s}\nunreviewed callback\n", .{contents});
            defer allocator.free(mutated);
            try replaceContents(descriptor, mutated);
        }
    }
    try chmodRegular(bad_mode, relative, 0o644);
    try overwriteRegular(bad_tool, "usr/bin/update-alternatives", "foreign alternatives tool\n");
    {
        const parent = try openParentDescriptor(bad_alias, "usr/bin/sh");
        defer _ = linux.close(parent.fd);
        var name_buf: [256]u8 = undefined;
        const name_z = try toNameZ(parent.name, &name_buf);
        const alias_path = try std.fs.path.join(allocator, &.{ bad_alias, "usr/bin/sh" });
        defer allocator.free(alias_path);
        const metadata = try reference_paths.lstatPath(alias_path);
        var link_buf: [reference_paths.maximum_path_bytes]u8 = undefined;
        const link_len = try syscall(linux.readlinkat(parent.fd, name_z, &link_buf, link_buf.len));
        if ((metadata.mode & linux.S.IFMT) != linux.S.IFLNK or
            metadata.nlink != 1 or
            metadata.uid != 0 or
            metadata.gid != 0 or
            !std.mem.eql(u8, link_buf[0..link_len], "dash"))
        {
            return error.UnexpectedSignedLessShellAlias;
        }
        _ = try syscall(linux.unlinkat(parent.fd, name_z, 0));
        _ = try syscall(linux.symlinkat("foreign-sh", parent.fd, name_z));
    }
    try createExclusive(bad_prestate, "etc/ld.so.cache", "unbound loader cache\n", 0o644);
}

pub fn mutateBashNegativeRoots(allocator: std.mem.Allocator, workspace: []const u8) !void {
    const relative = "var/lib/dpkg/info/bash.postinst";
    const bad_script = try std.fs.path.join(allocator, &.{ workspace, "bad-script" });
    defer allocator.free(bad_script);
    const bad_mode = try std.fs.path.join(allocator, &.{ workspace, "bad-mode" });
    defer allocator.free(bad_mode);
    const bad_tool = try std.fs.path.join(allocator, &.{ workspace, "bad-tool" });
    defer allocator.free(bad_tool);
    const bad_alias = try std.fs.path.join(allocator, &.{ workspace, "bad-alias" });
    defer allocator.free(bad_alias);
    const bad_prestate = try std.fs.path.join(allocator, &.{ workspace, "bad-prestate" });
    defer allocator.free(bad_prestate);
    const bad_cache = try std.fs.path.join(allocator, &.{ workspace, "bad-cache" });
    defer allocator.free(bad_cache);

    const script = try readRegular(allocator, bad_script, relative, 1024);
    defer allocator.free(script);
    const mutated_script = try std.fmt.allocPrint(allocator, "{s}\nunreviewed callback\n", .{script});
    defer allocator.free(mutated_script);
    try overwriteRegular(bad_script, relative, mutated_script);
    try chmodRegular(bad_mode, relative, 0o644);
    try overwriteRegular(bad_tool, "usr/bin/update-alternatives", "foreign alternatives tool\n");
    try replaceSymlink(bad_alias, "usr/lib/aarch64-linux-gnu/libtinfo.so.6", "libtinfo.so.6.6", "foreign-tinfo");
    try createExclusive(bad_prestate, "usr/bin/update-menus", "#!/bin/sh\nexit 0\n", 0o755);
    const cache = try readRegular(allocator, bad_cache, "etc/ld.so.cache", 1024 * 1024);
    defer allocator.free(cache);
    if (std.mem.indexOf(u8, cache, "/lib/aarch64-linux-gnu/libc.so.6") == null)
        return error.MissingBashLibcCacheProvider;
    const mutated_cache = try std.mem.replaceOwned(
        u8,
        allocator,
        cache,
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/bad/aarch64-linux-gnu/libc.so.6",
    );
    defer allocator.free(mutated_cache);
    try overwriteRegular(bad_cache, "etc/ld.so.cache", mutated_cache);
}

pub fn mutateUtilLinuxNegativeRoots(allocator: std.mem.Allocator, workspace: []const u8) !void {
    const relative = "var/lib/dpkg/info/util-linux.postinst";
    const bad_script = try std.fs.path.join(allocator, &.{ workspace, "bad-script" });
    defer allocator.free(bad_script);
    const bad_mode = try std.fs.path.join(allocator, &.{ workspace, "bad-mode" });
    defer allocator.free(bad_mode);
    const bad_tool = try std.fs.path.join(allocator, &.{ workspace, "bad-tool" });
    defer allocator.free(bad_tool);
    const bad_alias = try std.fs.path.join(allocator, &.{ workspace, "bad-alias" });
    defer allocator.free(bad_alias);
    const bad_prestate = try std.fs.path.join(allocator, &.{ workspace, "bad-prestate" });
    defer allocator.free(bad_prestate);
    const bad_cache = try std.fs.path.join(allocator, &.{ workspace, "bad-cache" });
    defer allocator.free(bad_cache);

    const script = try readRegular(allocator, bad_script, relative, 4096);
    defer allocator.free(script);
    const mutated_script = try std.fmt.allocPrint(allocator, "{s}\nunreviewed callback\n", .{script});
    defer allocator.free(mutated_script);
    try overwriteRegular(bad_script, relative, mutated_script);
    try chmodRegular(bad_mode, relative, 0o644);
    try overwriteRegular(bad_tool, "usr/bin/deb-systemd-helper", "foreign systemd helper\n");
    try replaceSymlink(bad_alias, "usr/lib/aarch64-linux-gnu/libcrypt.so.1", "libcrypt.so.1.1.0", "foreign-crypt");
    try createExclusive(bad_prestate, "usr/sbin/deb-systemd-helper", "#!/bin/sh\nexit 0\n", 0o755);
    const cache = try readRegular(allocator, bad_cache, "etc/ld.so.cache", 1024 * 1024);
    defer allocator.free(cache);
    if (std.mem.indexOf(u8, cache, "/lib/aarch64-linux-gnu/libm.so.6") == null)
        return error.MissingUtilLinuxLibmCacheProvider;
    const mutated_cache = try std.mem.replaceOwned(
        u8,
        allocator,
        cache,
        "/lib/aarch64-linux-gnu/libm.so.6",
        "/bad/aarch64-linux-gnu/libm.so.6",
    );
    defer allocator.free(mutated_cache);
    try overwriteRegular(bad_cache, "etc/ld.so.cache", mutated_cache);
}

pub fn writeExclusiveStdin(
    allocator: std.mem.Allocator,
    root: []const u8,
    relative: []const u8,
    mode: u16,
    maximum_bytes: usize,
) !void {
    _ = try reference_paths.protected(root, true);
    const content = try readBoundedFd(allocator, linux.STDIN_FILENO, maximum_bytes);
    defer allocator.free(content);
    try createExclusive(root, relative, content, mode);
}

pub fn stageDpkgReference(
    allocator: std.mem.Allocator,
    root: []const u8,
    pinned: []const u8,
    archive_path: []const u8,
    archive_relative: []const u8,
) !void {
    _ = try reference_paths.protected(root, true);
    try ensureDirectory(root, "usr/local", 0o755, false);
    try ensureDirectory(root, "usr/local/sbin", 0o755, false);
    try copyExclusive(allocator, root, "usr/local/sbin/dpkg", pinned, 0o755);
    try copyExclusive(allocator, root, archive_relative, archive_path, 0o644);
}

fn directoryIsEmpty(fd: i32) !bool {
    var dents_buf: [4096]u8 = undefined;
    while (true) {
        const nread = try syscall(linux.getdents64(fd, &dents_buf, dents_buf.len));
        if (nread == 0) return true;
        var bpos: usize = 0;
        while (bpos < nread) {
            const dent: *align(1) const linux.dirent64 = @ptrCast(&dents_buf[bpos]);
            const name_ptr: [*:0]const u8 = @ptrCast(&dent.name);
            const name = std.mem.span(name_ptr);
            bpos += dent.reclen;
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) return false;
        }
    }
}

pub fn preparePythonEmpty(allocator: std.mem.Allocator, root: []const u8) !void {
    const dev_path = try std.fs.path.join(allocator, &.{ root, "dev" });
    defer allocator.free(dev_path);
    const proc_path = try std.fs.path.join(allocator, &.{ root, "proc" });
    defer allocator.free(proc_path);
    _ = try reference_paths.protected(root, true);
    _ = try reference_paths.protected(dev_path, true);
    _ = try reference_paths.protected(proc_path, true);
    {
        const proc_fd = try reference_paths.openAbsolute(proc_path, true);
        defer _ = linux.close(proc_fd);
        if (!try directoryIsEmpty(proc_fd)) return error.CapturedSourceProcMustBeEmpty;
    }
    const list_pins = [_]struct {
        name: []const u8,
        relative: []const u8,
        size: usize,
        sha256: []const u8,
    }{
        .{
            .name = "python3",
            .relative = "var/lib/dpkg/info/python3.list",
            .size = 918,
            .sha256 = "383196acd094063e8e49dc4511deb7094e264a41d872bb889d21b197a550f628",
        },
        .{
            .name = "python3-minimal",
            .relative = "var/lib/dpkg/info/python3-minimal.list",
            .size = 781,
            .sha256 = "82003099685ad735bdf486d434276cdb0b82b88f269330f87504a5739008f519",
        },
    };
    for (list_pins) |pin| {
        const content = try readRegular(allocator, root, pin.relative, 2048);
        defer allocator.free(content);
        const actual = sha256Hex(content);
        if (content.len != pin.size or !std.mem.eql(u8, &actual, pin.sha256))
            return error.SignedPythonListPathSetChanged;
    }
    {
        const parent = try openParentDescriptor(root, "dev/null");
        defer _ = linux.close(parent.fd);
        var name_buf: [256]u8 = undefined;
        const name_z = try toNameZ(parent.name, &name_buf);
        const metadata = try rawStatxAt(parent.fd, name_z, linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT);
        const is_valid_null = if (builtin.is_test and test_allow_regular_null_device)
            (metadata.mode & linux.S.IFMT) == linux.S.IFREG or
                ((metadata.mode & linux.S.IFMT) == linux.S.IFCHR and metadata.rdev_major == 1 and metadata.rdev_minor == 3)
        else
            (metadata.mode & linux.S.IFMT) == linux.S.IFCHR and metadata.rdev_major == 1 and metadata.rdev_minor == 3;
        if (!is_valid_null or
            metadata.uid != linux.geteuid() or
            metadata.gid != linux.getegid() or
            metadata.nlink != 1)
        {
            return error.UnexpectedReferenceNullDevice;
        }
        _ = try syscall(linux.unlinkat(parent.fd, name_z, 0));
    }
    try createExclusive(root, "dev/null", "", 0o600);
}

pub fn preflightPython(allocator: std.mem.Allocator, root: []const u8) !void {
    const root_fd = try reference_paths.openAbsolute(root, true);
    defer _ = linux.close(root_fd);
    for ([_][]const u8{
        "dev",
        "proc",
        "usr/bin",
        "usr/sbin",
        "var/lib/dpkg/info",
        "usr/share/doc/python3",
        "tmp",
    }) |relative| {
        const opened = try reference_paths.openBeneath(root_fd, relative, true);
        _ = linux.close(opened);
    }
    for ([_][]const u8{ "usr/local", "usr/local/sbin" }) |relative| {
        var current: i32 = @intCast(try syscall(linux.fcntl(root_fd, linux.F.DUPFD_CLOEXEC, @as(usize, 0))));
        defer if (current != -1) {
            _ = linux.close(current);
        };
        var it = std.mem.splitScalar(u8, relative, '/');
        while (it.next()) |part| {
            var part_buf: [256]u8 = undefined;
            const part_z = try toNameZ(part, &part_buf);
            const flags: linux.O = .{
                .ACCMODE = .RDONLY,
                .NOFOLLOW = true,
                .CLOEXEC = true,
                .DIRECTORY = true,
            };
            const rc = linux.openat(current, part_z, flags, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    _ = linux.close(current);
                    current = @intCast(rc);
                },
                .NOENT => break,
                else => return error.ReferenceSyscallRefused,
            }
        }
    }
    for ([_][]const u8{
        "dev/null",
        "var/lib/dpkg/info/python3.preinst",
        "var/lib/dpkg/info/python3-minimal.postinst",
        "usr/bin/py3compile",
    }) |relative| {
        const bytes = try readRegular(allocator, root, relative, maximum_regular_bytes);
        allocator.free(bytes);
    }
}

pub fn basicPythonNegatives(roots: []const []const u8) !void {
    if (roots.len != 8) return error.EightPythonNegativeRootsRequired;
    const html = roots[0];
    const link = roots[1];
    const shadow = roots[2];
    const null_root = roots[3];
    const null_0640 = roots[4];
    const bad_root = roots[5];
    const script = roots[6];
    const proc = roots[7];
    try ensureDirectory(html, "usr/share/doc/python3/html", 0o755, true);
    try replaceSymlink(link, "usr/bin/python3", "python3.14", "python3.invalid");
    try createExclusive(shadow, "usr/sbin/update-alternatives", "shadow\n", 0o644);
    try chmodRegular(null_root, "dev/null", 0o666);
    try chmodRegular(null_0640, "dev/null", 0o640);
    {
        const descriptor = try reference_paths.openAbsolute(bad_root, true);
        defer _ = linux.close(descriptor);
        const metadata = try rawFstat(descriptor);
        if (metadata.uid != linux.geteuid() or
            metadata.gid != linux.getegid() or
            (metadata.mode & 0o7777) != 0o700)
        {
            return error.UnexpectedPythonNegativeRootMetadata;
        }
        _ = try syscall(linux.fchmod(descriptor, 0o755));
    }
    try overwriteRegular(script, "var/lib/dpkg/info/python3.preinst", "stale script\n");
    try createExclusive(proc, "proc/unexpected", "unexpected\n", 0o644);
}

pub fn strictPythonNegatives(allocator: std.mem.Allocator, roots: []const []const u8) !void {
    if (roots.len != 4) return error.FourStrictPythonNegativeRootsRequired;
    const bad_hash = roots[0];
    const bad_mode = roots[1];
    const postinst = roots[2];
    const compiler = roots[3];
    try overwriteRegular(bad_hash, "dev/null", "/usr/bin/py3compile ");
    try chmodRegular(bad_mode, "dev/null", 0o600);
    {
        const descriptor = try openRegularDescriptor(postinst, "var/lib/dpkg/info/python3-minimal.postinst");
        defer _ = linux.close(descriptor);
        const content = try readBoundedFd(allocator, descriptor, 1024);
        defer allocator.free(content);
        const actual = sha256Hex(content);
        if (content.len != 117 or !std.mem.eql(u8, &actual, "be10656c9edf975f5dfe48fe5819172e905e14dcd4ff372af5d8b45b26168edd"))
            return error.UnexpectedSignedMinimalProducer;
        const mutated = try std.mem.replaceOwned(u8, allocator, content, "which", "false");
        defer allocator.free(mutated);
        try replaceContents(descriptor, mutated);
    }
    try overwriteRegular(compiler, "usr/bin/py3compile", "stale compiler\n");
}

fn closePipePair(fds: [2]i32) void {
    if (fds[0] != -1) _ = linux.close(fds[0]);
    if (fds[1] != -1) _ = linux.close(fds[1]);
}

pub fn capturePythonProcess(
    allocator: std.mem.Allocator,
    root: []const u8,
    stdout_rel: []const u8,
    stderr_rel: []const u8,
    argv: []const []const u8,
) !u8 {
    if (argv.len == 0) return error.UnknownPythonFixtureStage;
    var outputs: [2]i32 = .{ -1, -1 };
    defer {
        for (outputs) |fd| {
            if (fd != -1) _ = linux.close(fd);
        }
    }
    for ([_][]const u8{ stdout_rel, stderr_rel }, 0..) |relative, index| {
        const parent = try openParentDescriptor(root, relative);
        defer _ = linux.close(parent.fd);
        var name_buf: [256]u8 = undefined;
        const name_z = try toNameZ(parent.name, &name_buf);
        const flags: linux.O = .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        };
        const fd: i32 = @intCast(try syscall(linux.openat(parent.fd, name_z, flags, 0o600)));
        outputs[index] = fd;
        _ = try regularMetadata(fd);
    }

    var stdout_pipe: [2]i32 = .{ -1, -1 };
    var stderr_pipe: [2]i32 = .{ -1, -1 };
    _ = try syscall(linux.pipe2(&stdout_pipe, .{ .CLOEXEC = true }));
    errdefer closePipePair(stdout_pipe);
    _ = try syscall(linux.pipe2(&stderr_pipe, .{ .CLOEXEC = true }));
    errdefer closePipePair(stderr_pipe);

    var argv_owned = try allocator.alloc(?[:0]u8, argv.len);
    defer {
        for (argv_owned) |entry| {
            if (entry) |slice| allocator.free(slice);
        }
        allocator.free(argv_owned);
    }
    @memset(argv_owned, null);
    var argv_z = try allocator.alloc(?[*:0]const u8, argv.len + 1);
    defer allocator.free(argv_z);
    @memset(argv_z, null);
    for (argv, 0..) |arg, idx| {
        const duped = try dupeZSlice(allocator, arg);
        argv_owned[idx] = duped;
        argv_z[idx] = duped.ptr;
    }

    var resolved_exec_buf: [reference_paths.maximum_path_bytes]u8 = undefined;
    var exec_path_z: [*:0]const u8 = argv_z[0].?;
    if (std.mem.indexOfScalar(u8, argv[0], '/') == null) {
        for ([_][]const u8{ "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/" }) |prefix| {
            if (prefix.len + argv[0].len + 1 > resolved_exec_buf.len) continue;
            @memcpy(resolved_exec_buf[0..prefix.len], prefix);
            @memcpy(resolved_exec_buf[prefix.len .. prefix.len + argv[0].len], argv[0]);
            resolved_exec_buf[prefix.len + argv[0].len] = 0;
            const candidate: [*:0]const u8 = @ptrCast(&resolved_exec_buf);
            if (linux.errno(linux.faccessat(linux.AT.FDCWD, candidate, linux.X_OK, 0)) == .SUCCESS) {
                exec_path_z = candidate;
                break;
            }
        }
    }

    const pid_rc = try syscall(linux.fork());
    if (pid_rc == 0) {
        _ = linux.close(stdout_pipe[0]);
        _ = linux.close(stderr_pipe[0]);
        _ = linux.dup2(stdout_pipe[1], linux.STDOUT_FILENO);
        _ = linux.dup2(stderr_pipe[1], linux.STDERR_FILENO);
        _ = linux.close(stdout_pipe[1]);
        _ = linux.close(stderr_pipe[1]);
        const default_envp: [*:null]const ?[*:0]const u8 = &.{
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/",
            "LC_ALL=C",
            "DEBIAN_FRONTEND=noninteractive",
            "DEBCONF_NONINTERACTIVE_SEEN=true",
            "DPKG_COLORS=never",
            null,
        };
        const envp: [*:null]const ?[*:0]const u8 = if (process_environ.block.isEmpty())
            default_envp
        else
            process_environ.block.slice.ptr;
        _ = linux.execve(exec_path_z, @ptrCast(argv_z.ptr), envp);
        linux.exit_group(127);
    }
    const child_pid: i32 = @intCast(pid_rc);
    _ = linux.close(stdout_pipe[1]);
    stdout_pipe[1] = -1;
    _ = linux.close(stderr_pipe[1]);
    stderr_pipe[1] = -1;
    defer {
        closePipePair(stdout_pipe);
        closePipePair(stderr_pipe);
    }

    var poll_fds: [2]linux.pollfd = .{
        .{ .fd = stdout_pipe[0], .events = linux.POLL.IN, .revents = 0 },
        .{ .fd = stderr_pipe[0], .events = linux.POLL.IN, .revents = 0 },
    };
    var counts: [2]usize = .{ 0, 0 };
    var oversized = false;
    var active: usize = 2;
    var buf: [65536]u8 = undefined;
    while (active > 0) {
        const poll_rc = linux.poll(&poll_fds, poll_fds.len, -1);
        if (linux.errno(poll_rc) == .INTR) continue;
        _ = try syscall(poll_rc);
        for (&poll_fds, 0..) |*pfd, index| {
            if (pfd.fd == -1) continue;
            if ((pfd.revents & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR)) != 0) {
                const got = try syscall(linux.read(pfd.fd, &buf, buf.len));
                if (got == 0) {
                    _ = linux.close(pfd.fd);
                    pfd.fd = -1;
                    if (index == 0) stdout_pipe[0] = -1 else stderr_pipe[0] = -1;
                    active -= 1;
                    continue;
                }
                const remaining = maximum_capture_bytes -| counts[index];
                const bounded_len = @min(got, remaining);
                if (bounded_len != got) oversized = true;
                if (bounded_len > 0) {
                    try writeAllFd(outputs[index], buf[0..bounded_len]);
                    counts[index] += bounded_len;
                }
            }
        }
    }

    var status: i32 = 0;
    while (true) {
        const wait_rc = linux.wait4(child_pid, &status, 0, null);
        if (linux.errno(wait_rc) == .INTR) continue;
        _ = try syscall(wait_rc);
        break;
    }
    if (oversized) return error.PythonReferenceCaptureExceedsByteLimit;
    const status_word: u32 = @bitCast(status);
    if (linux.W.IFEXITED(status_word)) return linux.W.EXITSTATUS(status_word);
    if (linux.W.IFSIGNALED(status_word)) return @intCast(128 + @backingInt(linux.W.TERMSIG(status_word)));
    return 1;
}

pub fn dispatchPython(allocator: std.mem.Allocator, arguments: []const []const u8) !u8 {
    if (arguments.len < 2) return error.UnknownPythonFixtureStage;
    const command = arguments[0];
    const paths = arguments[1..];
    if (std.mem.eql(u8, command, "capture")) {
        if (paths.len < 4) return error.UnknownPythonFixtureStage;
        return capturePythonProcess(allocator, paths[0], paths[1], paths[2], paths[3..]);
    }
    if (std.mem.eql(u8, command, "empty")) {
        try preparePythonEmpty(allocator, paths[0]);
    } else if (std.mem.eql(u8, command, "preflight")) {
        try preflightPython(allocator, paths[0]);
    } else if (std.mem.eql(u8, command, "mode")) {
        if (paths.len < 2) return error.UnknownPythonFixtureStage;
        const mode = std.fmt.parseInt(u16, paths[1], 8) catch return error.UnknownPythonFixtureStage;
        try chmodRegular(paths[0], "dev/null", mode);
    } else if (std.mem.eql(u8, command, "basic")) {
        try basicPythonNegatives(paths);
    } else if (std.mem.eql(u8, command, "strict")) {
        try strictPythonNegatives(allocator, paths);
    } else if (std.mem.eql(u8, command, "dpkg")) {
        if (paths.len != 3) return error.UnknownPythonFixtureStage;
        try stageDpkgReference(allocator, paths[0], paths[1], paths[2], "var/lib/dpkg/python3-probe.deb");
    } else if (std.mem.eql(u8, command, "directory")) {
        if (paths.len < 2) return error.UnknownPythonFixtureStage;
        try ensureDirectory(paths[0], paths[1], 0o700, false);
    } else {
        return error.UnknownPythonFixtureStage;
    }
    return 0;
}

pub fn createAlias(root: []const u8, relative: []const u8, target: []const u8) !void {
    const parent = try openParentDescriptor(root, relative);
    defer _ = linux.close(parent.fd);
    var name_buf: [256]u8 = undefined;
    const name_z = try toNameZ(parent.name, &name_buf);
    if (target.len == 0 or target.len >= reference_paths.maximum_path_bytes or std.mem.indexOfScalar(u8, target, 0) != null)
        return error.InvalidFixtureMutationPath;
    var target_buf: [reference_paths.maximum_path_bytes]u8 = undefined;
    @memcpy(target_buf[0..target.len], target);
    target_buf[target.len] = 0;
    const target_z: [*:0]const u8 = @ptrCast(&target_buf);
    _ = try syscall(linux.symlinkat(target_z, parent.fd, name_z));
}

pub fn removeLib64(root: []const u8) !void {
    const descriptor = try reference_paths.openAbsolute(root, true);
    defer _ = linux.close(descriptor);
    const metadata = try rawStatxAt(descriptor, "lib64", linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT);
    var link_buf: [reference_paths.maximum_path_bytes]u8 = undefined;
    const link_len = try syscall(linux.readlinkat(descriptor, "lib64", &link_buf, link_buf.len));
    if ((metadata.mode & linux.S.IFMT) != linux.S.IFLNK or
        metadata.nlink != 1 or
        metadata.uid != linux.geteuid() or
        metadata.gid != linux.getegid() or
        !std.mem.eql(u8, link_buf[0..link_len], "usr/lib64"))
    {
        return error.UnexpectedFreshTemplateLib64Alias;
    }
    _ = try syscall(linux.unlinkat(descriptor, "lib64", 0));
}

pub fn verifyLockArchive(
    allocator: std.mem.Allocator,
    lock: std.json.Value,
    cache: []const u8,
    package: []const u8,
) ![]u8 {
    const expected_arch = expectedArchiveArchitecture(package);
    if (lock != .object) return error.AmbiguousSignedSourceArchive;
    const packages_val = lock.object.get("packages") orelse return error.AmbiguousSignedSourceArchive;
    if (packages_val != .array) return error.AmbiguousSignedSourceArchive;

    var matched: ?std.json.ObjectMap = null;
    var match_count: usize = 0;
    for (packages_val.array.items) |item| {
        if (item != .object) continue;
        const name_val = item.object.get("name") orelse continue;
        const arch_val = item.object.get("architecture") orelse continue;
        if (name_val == .string and arch_val == .string and
            std.mem.eql(u8, name_val.string, package) and
            std.mem.eql(u8, arch_val.string, expected_arch))
        {
            matched = item.object;
            match_count += 1;
        }
    }
    if (match_count != 1) return error.AmbiguousSignedSourceArchive;
    const entry = matched.?;

    const origin_val = entry.get("origin") orelse return error.UnauthenticatedSourceArchive;
    if (origin_val != .object) return error.UnauthenticatedSourceArchive;
    const origin_type = origin_val.object.get("type") orelse return error.UnauthenticatedSourceArchive;
    if (origin_type != .string or !std.mem.eql(u8, origin_type.string, "authenticated_repository"))
        return error.UnauthenticatedSourceArchive;

    const identity_val = entry.get("archive_identity") orelse return error.UnauthenticatedSourceArchive;
    if (identity_val != .object) return error.UnauthenticatedSourceArchive;
    const primary_val = identity_val.object.get("primary") orelse return error.UnauthenticatedSourceArchive;
    if (primary_val != .string or !std.mem.eql(u8, primary_val.string, "sha512"))
        return error.UnauthenticatedSourceArchive;
    const digests_val = identity_val.object.get("digests") orelse return error.UnauthenticatedSourceArchive;
    if (digests_val != .array) return error.UnauthenticatedSourceArchive;

    var sha512_digest: ?[]const u8 = null;
    var sha512_count: usize = 0;
    for (digests_val.array.items) |digest_item| {
        if (digest_item != .object) continue;
        const alg = digest_item.object.get("algorithm") orelse continue;
        const dig = digest_item.object.get("digest") orelse continue;
        if (alg == .string and dig == .string and std.mem.eql(u8, alg.string, "sha512")) {
            sha512_digest = dig.string;
            sha512_count += 1;
        }
    }
    if (sha512_count != 1) return error.UnauthenticatedSourceArchive;
    const digest_str = sha512_digest.?;

    const version_val = entry.get("version") orelse return error.UnauthenticatedSourceArchive;
    const size_val = entry.get("declared_size") orelse return error.UnauthenticatedSourceArchive;
    if (version_val != .string or size_val != .integer or size_val.integer < 0)
        return error.UnauthenticatedSourceArchive;
    const declared_size: u64 = @intCast(size_val.integer);

    if (findArtifactPin(package)) |pin| {
        if (!std.mem.eql(u8, version_val.string, pin.version) or
            declared_size != pin.declared_size or
            !std.mem.eql(u8, digest_str, pin.sha512))
        {
            return error.SourceArchiveDiffersFromProductionAuthority;
        }
    }

    const leaf_name = try std.fmt.allocPrint(allocator, "sha512-{s}", .{digest_str});
    defer allocator.free(leaf_name);
    const path = try std.fs.path.join(allocator, &.{ cache, leaf_name });
    errdefer allocator.free(path);

    _ = try reference_paths.protected(path, false);
    const descriptor = try reference_paths.openAbsolute(path, false);
    defer _ = linux.close(descriptor);
    const metadata = try rawFstat(descriptor);
    if (metadata.nlink != 1 or metadata.size != declared_size)
        return error.SourceArchiveMetadataChanged;

    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    var buf: [65536]u8 = undefined;
    var total_read: u64 = 0;
    while (true) {
        const got = try syscall(linux.read(descriptor, &buf, buf.len));
        if (got == 0) break;
        hasher.update(buf[0..got]);
        total_read += got;
    }
    var actual_bytes: [64]u8 = undefined;
    hasher.final(&actual_bytes);
    const actual_hex = std.fmt.bytesToHex(actual_bytes, .lower);
    if (total_read != declared_size or !std.mem.eql(u8, &actual_hex, digest_str))
        return error.SourceArchiveBytesChanged;

    return path;
}

fn parseTarOctal(field: []const u8) !u64 {
    const trimmed = std.mem.trim(u8, field, " \x00");
    if (trimmed.len == 0) return 0;
    return std.fmt.parseInt(u64, trimmed, 8) catch error.UnexpectedSignedRuntimeMember;
}

pub fn extractTarPayloadMember(allocator: std.mem.Allocator, payload: []const u8, name: []const u8) ![]u8 {
    var offset: usize = 0;
    var found: ?[]const u8 = null;
    var match_count: usize = 0;
    var pax_path: ?[]const u8 = null;

    while (offset + 512 <= payload.len) {
        const header = payload[offset .. offset + 512];
        offset += 512;
        var all_zero = true;
        for (header) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) break;

        const size_u64 = try parseTarOctal(header[124..136]);
        if (size_u64 > payload.len - offset) return error.UnexpectedSignedRuntimeMember;
        const size: usize = @intCast(size_u64);
        const content = payload[offset .. offset + size];
        const padded = std.mem.alignForward(usize, size, 512);
        if (padded > payload.len - offset) return error.UnexpectedSignedRuntimeMember;
        offset += padded;

        const typeflag = header[156];
        if (typeflag == 'x') {
            var pos: usize = 0;
            while (pos < content.len) {
                const nl = std.mem.indexOfScalarPos(u8, content, pos, '\n') orelse break;
                const record = content[pos..nl];
                pos = nl + 1;
                const sp = std.mem.indexOfScalar(u8, record, ' ') orelse continue;
                const kv = record[sp + 1 ..];
                if (std.mem.startsWith(u8, kv, "path=")) {
                    pax_path = kv["path=".len..];
                }
            }
            continue;
        }
        defer pax_path = null;
        if (typeflag == 'g' or typeflag == 'L' or typeflag == 'K') continue;

        const raw_name = std.mem.sliceTo(header[0..100], 0);
        const prefix = std.mem.sliceTo(header[345..500], 0);
        var combined_buf: [512]u8 = undefined;
        const full_name = if (pax_path) |p|
            p
        else if (prefix.len > 0)
            std.fmt.bufPrint(&combined_buf, "{s}/{s}", .{ prefix, raw_name }) catch return error.UnexpectedSignedRuntimeMember
        else
            raw_name;
        const normalized = if (std.mem.startsWith(u8, full_name, "./")) full_name[2..] else full_name;
        if (!std.mem.eql(u8, normalized, name)) continue;

        const uid = try parseTarOctal(header[108..116]);
        const gid = try parseTarOctal(header[116..124]);
        const is_regular = (typeflag == '0' or typeflag == 0);
        if (!is_regular or uid != 0 or gid != 0 or size > maximum_member_bytes)
            return error.UnexpectedSignedRuntimeMember;
        found = content;
        match_count += 1;
    }
    if (match_count != 1 or found == null) return error.UnexpectedSignedRuntimeMember;
    return allocator.dupe(u8, found.?);
}

pub fn extractArchiveMember(allocator: std.mem.Allocator, archive_path: []const u8, name: []const u8) ![]u8 {
    const parent_path = std.fs.path.dirname(archive_path) orelse return error.NoncanonicalReferencePath;
    const base_name = std.fs.path.basename(archive_path);
    const parent_fd = try reference_paths.openAbsolute(parent_path, true);
    defer _ = linux.close(parent_fd);

    const temp_name = try std.fmt.allocPrint(allocator, "{s}.less-source.tar", .{base_name});
    defer allocator.free(temp_name);
    var temp_name_buf: [256]u8 = undefined;
    const temp_name_z = try toNameZ(temp_name, &temp_name_buf);

    const flags: linux.O = .{
        .ACCMODE = .RDWR,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const capture_fd: i32 = @intCast(try syscall(linux.openat(parent_fd, temp_name_z, flags, 0o600)));
    defer {
        _ = linux.close(capture_fd);
        _ = linux.unlinkat(parent_fd, temp_name_z, 0);
    }

    const archive_z = try dupeZSlice(allocator, archive_path);
    defer allocator.free(archive_z);
    const pid_rc = try syscall(linux.fork());
    if (pid_rc == 0) {
        const limit = linux.rlimit{
            .cur = maximum_tar_capture_bytes,
            .max = maximum_tar_capture_bytes,
        };
        _ = linux.setrlimit(.FSIZE, &limit);
        _ = linux.dup2(capture_fd, linux.STDOUT_FILENO);
        const child_argv = [_:null]?[*:0]const u8{
            "/usr/bin/dpkg-deb",
            "--fsys-tarfile",
            archive_z.ptr,
        };
        const envp: [*:null]const ?[*:0]const u8 = &.{
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/",
            "LC_ALL=C",
            "DEBIAN_FRONTEND=noninteractive",
            "DEBCONF_NONINTERACTIVE_SEEN=true",
            "DPKG_COLORS=never",
            null,
        };
        _ = linux.execve("/usr/bin/dpkg-deb", &child_argv, envp);
        linux.exit_group(127);
    }
    const child_pid: i32 = @intCast(pid_rc);
    var status: i32 = 0;
    while (true) {
        const wait_rc = linux.wait4(child_pid, &status, 0, null);
        if (linux.errno(wait_rc) == .INTR) continue;
        _ = try syscall(wait_rc);
        break;
    }
    const status_word: u32 = @bitCast(status);
    if (!linux.W.IFEXITED(status_word) or linux.W.EXITSTATUS(status_word) != 0)
        return error.ReferenceSyscallRefused;

    const meta = try rawFstat(capture_fd);
    if (meta.size > maximum_tar_capture_bytes) return error.SignedSourceDataArchiveExceedsBound;
    _ = try syscall(linux.lseek(capture_fd, 0, linux.SEEK.SET));
    const payload = try readBoundedFd(allocator, capture_fd, @intCast(maximum_tar_capture_bytes));
    defer allocator.free(payload);

    return extractTarPayloadMember(allocator, payload, name);
}

pub fn stageLdconfigProducer(
    allocator: std.mem.Allocator,
    root: []const u8,
    libc_bin_lock: std.json.Value,
    cache: []const u8,
) !void {
    const archive_path = try verifyLockArchive(allocator, libc_bin_lock, cache, "libc-bin");
    defer allocator.free(archive_path);
    const producer = try extractArchiveMember(allocator, archive_path, "usr/sbin/ldconfig");
    defer allocator.free(producer);
    const actual = sha256Hex(producer);
    if (producer.len != 865848 or
        !std.mem.eql(u8, &actual, "b78066d6243748c6565675a63eec5f0d41b6adb3b4635adea6906326db41f9fa"))
    {
        return error.SignedLdconfigCacheProducerChanged;
    }
    try createExclusive(root, "var/lib/dpkg/producer-ldconfig", producer, 0o755);
}

fn readProtectedBytes(allocator: std.mem.Allocator, path: []const u8, limit: usize) ![]u8 {
    const fd = try reference_paths.openAbsolute(path, false);
    defer _ = linux.close(fd);
    const meta = try rawFstat(fd);
    if ((meta.mode & linux.S.IFMT) != linux.S.IFREG or meta.size > limit)
        return error.FixtureSourceExceedsByteLimit;
    const bytes = try readBoundedFd(allocator, fd, limit);
    errdefer allocator.free(bytes);
    if (bytes.len != meta.size) return error.FixtureSourceBytesChanged;
    return bytes;
}

fn parseArm64LockFile(allocator: std.mem.Allocator, path: []const u8) !std.json.Parsed(std.json.Value) {
    const raw = try readProtectedBytes(allocator, path, maximum_regular_bytes);
    defer allocator.free(raw);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return error.SourceTargetMustBeArm64;
    errdefer parsed.deinit();
    if (parsed.value != .object) return error.SourceTargetMustBeArm64;
    const arch_val = parsed.value.object.get("target_architecture") orelse return error.SourceTargetMustBeArm64;
    if (arch_val != .string or !std.mem.eql(u8, arch_val.string, "arm64"))
        return error.SourceTargetMustBeArm64;
    return parsed;
}

pub fn prepareSource(
    allocator: std.mem.Allocator,
    root: []const u8,
    lock_path: []const u8,
    cache: []const u8,
    pinned: []const u8,
    additional_locks: []const []const u8,
    selected_package: []const u8,
) !void {
    const is_less = std.mem.eql(u8, selected_package, "less");
    const is_bash = std.mem.eql(u8, selected_package, "bash");
    if (!is_less and !is_bash) return error.UnsupportedSignedAlternativesSource;
    const valid_locks = if (is_bash)
        (additional_locks.len == 0 or additional_locks.len == 3 or additional_locks.len == 4)
    else
        (additional_locks.len == 0 or additional_locks.len == 3);
    if (!valid_locks) return error.InvalidGoalLockSet;

    _ = try reference_paths.protected(lock_path, false);
    for (additional_locks) |extra| {
        _ = try reference_paths.protected(extra, false);
    }
    _ = try reference_paths.protected(pinned, false);
    _ = try reference_paths.protected("/usr/bin/dpkg-deb", false);
    _ = try reference_paths.protected(root, true);

    const has_separate = additional_locks.len > 0;
    const dpkg_lock_path = lock_path;
    const pkg_lock_path = if (has_separate) additional_locks[0] else lock_path;
    const dash_lock_path = if (has_separate) additional_locks[1] else lock_path;
    const util_linux_lock_path = if (has_separate) additional_locks[2] else lock_path;
    const libc_bin_lock_path: ?[]const u8 = if (additional_locks.len == 4) additional_locks[3] else null;

    var dpkg_lock = try parseArm64LockFile(allocator, dpkg_lock_path);
    defer dpkg_lock.deinit();
    var pkg_lock = try parseArm64LockFile(allocator, pkg_lock_path);
    defer pkg_lock.deinit();
    var dash_lock = try parseArm64LockFile(allocator, dash_lock_path);
    defer dash_lock.deinit();
    var util_linux_lock = try parseArm64LockFile(allocator, util_linux_lock_path);
    defer util_linux_lock.deinit();
    var libc_bin_lock = if (libc_bin_lock_path) |p| try parseArm64LockFile(allocator, p) else null;
    defer if (libc_bin_lock) |*l| l.deinit();

    if (is_less) {
        for (source_artifacts) |pin| {
            const source_lock = if (std.mem.eql(u8, pin.name, "libc6") or std.mem.eql(u8, pin.name, "dpkg"))
                dpkg_lock.value
            else if (std.mem.eql(u8, pin.name, "dash"))
                dash_lock.value
            else
                pkg_lock.value;
            const verified = try verifyLockArchive(allocator, source_lock, cache, pin.name);
            allocator.free(verified);
        }
    } else {
        for ([_][]const u8{ "bash", "libtinfo6", "dash", "dpkg", "libc6" }) |name| {
            const source_lock = if (std.mem.eql(u8, name, "bash") or std.mem.eql(u8, name, "libtinfo6"))
                pkg_lock.value
            else if (std.mem.eql(u8, name, "dash"))
                dash_lock.value
            else
                dpkg_lock.value;
            const verified = try verifyLockArchive(allocator, source_lock, cache, name);
            allocator.free(verified);
        }
    }

    try removeLib64(root);
    for ([_][]const u8{
        "etc",
        "etc/alternatives",
        "var/lib/dpkg/alternatives",
        "var/lib/debz-lifecycle-scripts",
    }) |rel| {
        try ensureDirectory(root, rel, 0o755, false);
    }

    const runtime_members = [_]struct {
        package: []const u8,
        path: []const u8,
        mode: u16,
    }{
        .{ .package = "dash", .path = "usr/bin/dash", .mode = 0o755 },
        .{ .package = "dpkg", .path = "usr/bin/update-alternatives", .mode = 0o755 },
        .{ .package = "util-linux", .path = "usr/bin/setpriv", .mode = 0o755 },
        .{ .package = "libcap-ng0", .path = "usr/lib/aarch64-linux-gnu/libcap-ng.so.0.0.0", .mode = 0o644 },
    };
    for (runtime_members) |item| {
        const lock_val = if (std.mem.eql(u8, item.package, "dash"))
            dash_lock.value
        else if (std.mem.eql(u8, item.package, "dpkg"))
            dpkg_lock.value
        else
            util_linux_lock.value;
        const deb_path = try verifyLockArchive(allocator, lock_val, cache, item.package);
        defer allocator.free(deb_path);
        const bytes = try extractArchiveMember(allocator, deb_path, item.path);
        defer allocator.free(bytes);
        try createExclusive(root, item.path, bytes, item.mode);
    }

    try createAlias(root, "usr/bin/sh", "dash");
    try createAlias(root, "usr/lib/aarch64-linux-gnu/libcap-ng.so.0", "libcap-ng.so.0.0.0");

    if (is_bash) {
        const util_linux_deb = try verifyLockArchive(allocator, util_linux_lock.value, cache, "util-linux");
        defer allocator.free(util_linux_deb);
        try copyExclusive(allocator, root, "var/lib/dpkg/producer-util-linux.deb", util_linux_deb, 0o644);
        try copyExclusive(allocator, root, "var/lib/dpkg/producer-util-linux.lock.json", util_linux_lock_path, 0o644);
        const tinfo_deb = try verifyLockArchive(allocator, pkg_lock.value, cache, "libtinfo6");
        defer allocator.free(tinfo_deb);
        const tinfo_bytes = try readProtectedBytes(allocator, tinfo_deb, maximum_regular_bytes);
        defer allocator.free(tinfo_bytes);
        try createExclusive(root, "var/lib/dpkg/producer-libtinfo6.deb", tinfo_bytes, 0o644);
        if (libc_bin_lock) |l| {
            try stageLdconfigProducer(allocator, root, l.value, cache);
        }
    }

    const pinned_bytes = try readProtectedBytes(allocator, pinned, maximum_regular_bytes);
    defer allocator.free(pinned_bytes);
    try createExclusive(root, "var/lib/dpkg/producer-dpkg", pinned_bytes, 0o755);

    const original_deb = try verifyLockArchive(allocator, pkg_lock.value, cache, selected_package);
    defer allocator.free(original_deb);
    const original_bytes = try readProtectedBytes(allocator, original_deb, maximum_regular_bytes);
    defer allocator.free(original_bytes);
    const producer_rel = try std.fmt.allocPrint(allocator, "var/lib/dpkg/producer-{s}.deb", .{selected_package});
    defer allocator.free(producer_rel);
    try createExclusive(root, producer_rel, original_bytes, 0o644);
}

pub fn prepareUtilLinux(
    allocator: std.mem.Allocator,
    root: []const u8,
    lock_paths: *const [7][]const u8,
    cache: []const u8,
    pinned: []const u8,
) !void {
    for (lock_paths) |p| {
        _ = try reference_paths.protected(p, false);
    }
    _ = try reference_paths.protected(pinned, false);
    _ = try reference_paths.protected("/usr/bin/dpkg-deb", false);
    _ = try reference_paths.protected(root, true);

    var parsed_locks: [7]std.json.Parsed(std.json.Value) = undefined;
    var parsed_count: usize = 0;
    defer {
        for (parsed_locks[0..parsed_count]) |*l| l.deinit();
    }
    for (lock_paths, 0..) |p, idx| {
        parsed_locks[idx] = try parseArm64LockFile(allocator, p);
        parsed_count += 1;
    }
    // Indices: 0=dpkg, 1=less, 2=dash, 3=util-linux, 4=libc-bin, 5=init-system-helpers, 6=perl-base
    const archive_checks = [_]struct { name: []const u8, goal_index: usize }{
        .{ .name = "util-linux", .goal_index = 3 },
        .{ .name = "init-system-helpers", .goal_index = 5 },
        .{ .name = "perl-base", .goal_index = 6 },
        .{ .name = "libcrypt1", .goal_index = 6 },
        .{ .name = "less", .goal_index = 1 },
        .{ .name = "libtinfo6", .goal_index = 1 },
        .{ .name = "dash", .goal_index = 2 },
        .{ .name = "dpkg", .goal_index = 0 },
        .{ .name = "libc6", .goal_index = 0 },
        .{ .name = "libc-bin", .goal_index = 4 },
    };
    for (archive_checks) |check| {
        const verified = try verifyLockArchive(allocator, parsed_locks[check.goal_index].value, cache, check.name);
        allocator.free(verified);
    }

    try removeLib64(root);
    for ([_][]const u8{
        "etc",
        "etc/alternatives",
        "var/lib/dpkg/alternatives",
        "var/lib/debz-lifecycle-scripts",
    }) |rel| {
        try ensureDirectory(root, rel, 0o755, false);
    }

    const runtime_pins = [_]struct {
        package: []const u8,
        goal_index: usize,
        path: []const u8,
        mode: u16,
        expected_size: usize,
        expected_sha256: []const u8,
    }{
        .{
            .package = "dash",
            .goal_index = 2,
            .path = "usr/bin/dash",
            .mode = 0o755,
            .expected_size = 133864,
            .expected_sha256 = "87630eb41654f7888e28fa5ef3ed0a351682e939d382b9239a24a8aefe84aeb9",
        },
        .{
            .package = "dpkg",
            .goal_index = 0,
            .path = "usr/bin/update-alternatives",
            .mode = 0o755,
            .expected_size = 68032,
            .expected_sha256 = "dae71fcd81f5373b8f1c19b300d10317dd3d323f577b7e5a45a50301fa217807",
        },
        .{
            .package = "util-linux",
            .goal_index = 3,
            .path = "usr/bin/setpriv",
            .mode = 0o755,
            .expected_size = 68024,
            .expected_sha256 = "44faaf7cfa4f49215642e592a9f2da9b99ef86ed7bf453d8abc78d8fce5f43c4",
        },
        .{
            .package = "libcap-ng0",
            .goal_index = 3,
            .path = "usr/lib/aarch64-linux-gnu/libcap-ng.so.0.0.0",
            .mode = 0o644,
            .expected_size = 67856,
            .expected_sha256 = "c64f9619d98c36eda6fdd02130438620796e30ca388e7c746e1ed43ec3e83956",
        },
        .{
            .package = "init-system-helpers",
            .goal_index = 5,
            .path = "usr/bin/deb-systemd-helper",
            .mode = 0o755,
            .expected_size = 24358,
            .expected_sha256 = "a895d5f077651960b6ca4ed9c53f8b36eae422ae170f61c972d0c6579e9f8732",
        },
        .{
            .package = "libcrypt1",
            .goal_index = 6,
            .path = "usr/lib/aarch64-linux-gnu/libcrypt.so.1.1.0",
            .mode = 0o644,
            .expected_size = 264200,
            .expected_sha256 = "5c5436f75b65261219cbcffe59ed99aed2047d98525526ed62b623884c1135f9",
        },
    };
    for (runtime_pins) |pin| {
        const deb_path = try verifyLockArchive(allocator, parsed_locks[pin.goal_index].value, cache, pin.package);
        defer allocator.free(deb_path);
        const extracted = try extractArchiveMember(allocator, deb_path, pin.path);
        defer allocator.free(extracted);
        const actual = sha256Hex(extracted);
        if (extracted.len != pin.expected_size or !std.mem.eql(u8, &actual, pin.expected_sha256))
            return error.SignedRuntimeMemberChanged;
        try createExclusive(root, pin.path, extracted, pin.mode);
    }

    try createAlias(root, "usr/bin/sh", "dash");
    try createAlias(root, "usr/lib/aarch64-linux-gnu/libcap-ng.so.0", "libcap-ng.so.0.0.0");
    try createAlias(root, "usr/lib/aarch64-linux-gnu/libcrypt.so.1", "libcrypt.so.1.1.0");
    try stageLdconfigProducer(allocator, root, parsed_locks[4].value, cache);

    const pinned_bytes = try readProtectedBytes(allocator, pinned, maximum_regular_bytes);
    defer allocator.free(pinned_bytes);
    try createExclusive(root, "var/lib/dpkg/producer-dpkg", pinned_bytes, 0o755);

    const producer_debs = [_]struct { name: []const u8, goal_index: usize }{
        .{ .name = "perl-base", .goal_index = 6 },
        .{ .name = "libtinfo6", .goal_index = 1 },
        .{ .name = "less", .goal_index = 1 },
        .{ .name = "util-linux", .goal_index = 3 },
    };
    for (producer_debs) |item| {
        const deb = try verifyLockArchive(allocator, parsed_locks[item.goal_index].value, cache, item.name);
        defer allocator.free(deb);
        const rel = try std.fmt.allocPrint(allocator, "var/lib/dpkg/producer-{s}.deb", .{item.name});
        defer allocator.free(rel);
        try copyExclusive(allocator, root, rel, deb, 0o644);
    }
}

pub fn sealLess(allocator: std.mem.Allocator, root: []const u8) !void {
    const content = try readRegular(allocator, root, "var/lib/dpkg/info/less.list", 2048);
    defer allocator.free(content);
    const list_hash = sha256Hex(content);
    if (content.len != 583 or !std.mem.eql(u8, &list_hash, "0206e202ee08fa90d694df6ee0a0f438258ce7f442ff3bc8db4ead65514c62ae"))
        return error.SignedLessOwnershipPathSetChanged;

    const preinst = try readRegular(allocator, root, "var/lib/dpkg/info/less.preinst", 1024);
    defer allocator.free(preinst);
    const preinst_hash = sha256Hex(preinst);
    if (preinst.len != 292 or !std.mem.eql(u8, &preinst_hash, "c72b2f152d56cae58b8f39efe22e6f0d85d676c4ac3060f40cfe0c463f1f8d94"))
        return error.SignedLessPreinstChanged;

    const script = try readRegular(allocator, root, "var/lib/dpkg/info/less.postinst", 1024);
    defer allocator.free(script);
    const script_hash = sha256Hex(script);
    if (script.len != 374 or !std.mem.eql(u8, &script_hash, "a33a1e6ef5a22e63a66e42853fc0bcff3107b4653d7b5cea891354a5f28db6c4"))
        return error.SignedLessPostinstChanged;

    try createExclusive(root, "var/lib/debz-lifecycle-scripts/less.preinst", preinst, 0o755);
    try createExclusive(root, "var/lib/debz-lifecycle-scripts/less.postinst", script, 0o755);
}

pub fn sealBash(allocator: std.mem.Allocator, root: []const u8) !void {
    const listing = try readRegular(allocator, root, "var/lib/dpkg/info/bash.list", 2048);
    defer allocator.free(listing);
    const list_hash = sha256Hex(listing);
    if (listing.len != 1068 or !std.mem.eql(u8, &list_hash, "f258025bf7b7200aaef0a62c5793535fab6500c7de9d7fbffc069eb78444505c"))
        return error.SignedBashOwnershipPathSetChanged;

    const script = try readRegular(allocator, root, "var/lib/dpkg/info/bash.postinst", 1024);
    defer allocator.free(script);
    const script_hash = sha256Hex(script);
    if (script.len != 491 or !std.mem.eql(u8, &script_hash, "72dfde3dbe58a2eb3766ac52a485626b27213cd9b6fa7b14705cde793620343d"))
        return error.SignedBashPostinstChanged;

    try createExclusive(root, "var/lib/debz-lifecycle-scripts/bash.postinst", script, 0o755);
}

pub fn sealUtilLinux(allocator: std.mem.Allocator, root: []const u8) !void {
    {
        const parent = try openParentDescriptor(root, "usr/bin/perl");
        defer _ = linux.close(parent.fd);
        var name_buf: [256]u8 = undefined;
        const name_z = try toNameZ(parent.name, &name_buf);
        const flags: linux.O = .{
            .ACCMODE = .RDONLY,
            .NOFOLLOW = true,
            .NONBLOCK = true,
            .CLOEXEC = true,
        };
        const descriptor: i32 = @intCast(try syscall(linux.openat(parent.fd, name_z, flags, 0)));
        defer _ = linux.close(descriptor);
        const metadata = try rawFstat(descriptor);
        if ((metadata.mode & linux.S.IFMT) != linux.S.IFREG or
            (metadata.nlink != 1 and metadata.nlink != 2) or
            metadata.uid != linux.geteuid() or
            metadata.gid != linux.getegid() or
            (metadata.mode & 0o7777) != 0o755)
        {
            return error.SignedPerlBaseInterpreterMetadataChanged;
        }
        const perl = try readBoundedFd(allocator, descriptor, 4 * 1024 * 1024);
        defer allocator.free(perl);
        const perl_hash = sha256Hex(perl);
        if (perl.len != 3942544 or !std.mem.eql(u8, &perl_hash, "51d562fb5f145f8c12610790b6f67b2868d1aa7c977906b533250f00903681cd"))
            return error.SignedPerlBaseInterpreterChanged;
    }

    const libm = try readRegular(allocator, root, "usr/lib/aarch64-linux-gnu/libm.so.6", 1024 * 1024);
    defer allocator.free(libm);
    const libm_hash = sha256Hex(libm);
    if (libm.len != 723144 or !std.mem.eql(u8, &libm_hash, "ffeae799646fae7a8af80402a88f4bc84bfc110af834f5e756aae2fa0a1a9602"))
        return error.SignedLibc6LibmRuntimeChanged;

    const less_list = try readRegular(allocator, root, "var/lib/dpkg/info/less.list", 2048);
    defer allocator.free(less_list);
    const less_hash = sha256Hex(less_list);
    if (less_list.len != 583 or !std.mem.eql(u8, &less_hash, "0206e202ee08fa90d694df6ee0a0f438258ce7f442ff3bc8db4ead65514c62ae"))
        return error.SignedLessPrestateOwnershipPathSetChanged;

    const listing = try readRegular(allocator, root, "var/lib/dpkg/info/util-linux.list", 16384);
    defer allocator.free(listing);
    const list_hash = sha256Hex(listing);
    if (listing.len != 8922 or !std.mem.eql(u8, &list_hash, "45503af3321a520be18c144f94e3c8a10eae22e8c5f5eb41532af3777db6a0bf"))
        return error.SignedUtilLinuxOwnershipPathSetChanged;

    const script = try readRegular(allocator, root, "var/lib/dpkg/info/util-linux.postinst", 4096);
    defer allocator.free(script);
    const script_hash = sha256Hex(script);
    if (script.len != 2112 or !std.mem.eql(u8, &script_hash, "31f01940fe6aa22a9b35b54029eb5e4dd4ea5146dd2bacdb495d0d37eb210fc9"))
        return error.SignedUtilLinuxPostinstChanged;

    try createExclusive(root, "var/lib/debz-lifecycle-scripts/util-linux.postinst", script, 0o755);
}

fn requireRootProcess() !void {
    if (linux.geteuid() != 0 or linux.getegid() != 0)
        return error.ProtectedSourceSetupRequiresRoot;
}

pub fn runCli(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len < 2) return error.UnknownSourceSetupStage;
    const cmd = args[1];
    const rest = args[2..];

    if (std.mem.eql(u8, cmd, "python")) {
        return dispatchPython(allocator, rest);
    }
    if (std.mem.eql(u8, cmd, "less-mutate-negatives")) {
        var kind: []const u8 = "preinst";
        var roots = rest;
        if (rest.len >= 2 and std.mem.eql(u8, rest[0], "--kind")) {
            kind = rest[1];
            roots = rest[2..];
        }
        try mutateNegativeRoots(allocator, roots, kind);
        return 0;
    }
    if (std.mem.eql(u8, cmd, "less-stage-dpkg")) {
        if (rest.len < 3 or rest.len > 4) return error.UnknownSourceSetupStage;
        const archive_rel = if (rest.len == 4) rest[3] else "var/lib/dpkg/less-probe.deb";
        try stageDpkgReference(allocator, rest[0], rest[1], rest[2], archive_rel);
        return 0;
    }
    if (std.mem.eql(u8, cmd, "bash-mutate-negatives")) {
        if (rest.len != 1) return error.UnknownSourceSetupStage;
        try mutateBashNegativeRoots(allocator, rest[0]);
        return 0;
    }
    if (std.mem.eql(u8, cmd, "util-linux-mutate-negatives")) {
        if (rest.len != 1) return error.UnknownSourceSetupStage;
        try mutateUtilLinuxNegativeRoots(allocator, rest[0]);
        return 0;
    }
    if (std.mem.eql(u8, cmd, "create-exclusive-stdin")) {
        if (rest.len != 4) return error.UnknownSourceSetupStage;
        const mode = std.fmt.parseInt(u16, rest[2], 8) catch return error.UnknownSourceSetupStage;
        const max_bytes = std.fmt.parseInt(usize, rest[3], 10) catch return error.UnknownSourceSetupStage;
        try writeExclusiveStdin(allocator, rest[0], rest[1], mode, max_bytes);
        return 0;
    }

    try requireRootProcess();
    if (std.mem.eql(u8, cmd, "prepare")) {
        if (rest.len < 4) return error.UnknownSourceSetupStage;
        try prepareSource(allocator, rest[0], rest[1], rest[2], rest[3], rest[4..], "less");
    } else if (std.mem.eql(u8, cmd, "prepare-bash")) {
        if (rest.len < 4) return error.UnknownSourceSetupStage;
        try prepareSource(allocator, rest[0], rest[1], rest[2], rest[3], rest[4..], "bash");
    } else if (std.mem.eql(u8, cmd, "prepare-util-linux")) {
        if (rest.len != 10) return error.UnknownSourceSetupStage;
        const lock_paths: [7][]const u8 = .{
            rest[1],
            rest[4],
            rest[5],
            rest[6],
            rest[7],
            rest[8],
            rest[9],
        };
        try prepareUtilLinux(allocator, rest[0], &lock_paths, rest[2], rest[3]);
    } else if (std.mem.eql(u8, cmd, "seal")) {
        if (rest.len != 1) return error.UnknownSourceSetupStage;
        try sealLess(allocator, rest[0]);
    } else if (std.mem.eql(u8, cmd, "seal-bash")) {
        if (rest.len != 1) return error.UnknownSourceSetupStage;
        try sealBash(allocator, rest[0]);
    } else if (std.mem.eql(u8, cmd, "seal-util-linux")) {
        if (rest.len != 1) return error.UnknownSourceSetupStage;
        try sealUtilLinux(allocator, rest[0]);
    } else {
        return error.UnknownSourceSetupStage;
    }
    return 0;
}

var process_environ: std.process.Environ = .empty;

pub fn main(init: std.process.Init) !void {
    process_environ = init.minimal.environ;
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);
    const status = runCli(allocator, args) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "debz-reference-stage: {s}\n", .{@errorName(err)}) catch "debz-reference-stage: error\n";
        _ = linux.write(linux.STDERR_FILENO, msg.ptr, msg.len);
        std.process.exit(1);
    };
    if (status != 0) std.process.exit(status);
}

const TestRoot = struct {
    tmp: std.testing.TmpDir,
    path: []u8,

    fn init(allocator: std.mem.Allocator) !TestRoot {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var proc_buf: [64]u8 = undefined;
        const proc_slice = try std.fmt.bufPrint(&proc_buf, "/proc/self/fd/{d}\x00", .{tmp.dir.handle});
        const proc_path: [*:0]const u8 = @ptrCast(proc_slice.ptr);
        var link_buf: [reference_paths.maximum_path_bytes]u8 = undefined;
        const link_len = try syscall(linux.readlink(proc_path, &link_buf, link_buf.len));
        const path = try allocator.dupe(u8, link_buf[0..link_len]);
        return .{ .tmp = tmp, .path = path };
    }

    fn deinit(self: *TestRoot, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.tmp.cleanup();
    }
};

fn writeTarEntry(
    allocator: std.mem.Allocator,
    tar: *std.ArrayList(u8),
    name: []const u8,
    typeflag: u8,
    uid: u32,
    gid: u32,
    body: []const u8,
) !void {
    var header = std.mem.zeroes([512]u8);
    @memcpy(header[0..name.len], name);
    _ = try std.fmt.bufPrint(header[100..108], "{o:0>7}\x00", .{@as(u32, 0o755)});
    _ = try std.fmt.bufPrint(header[108..116], "{o:0>7}\x00", .{uid});
    _ = try std.fmt.bufPrint(header[116..124], "{o:0>7}\x00", .{gid});
    _ = try std.fmt.bufPrint(header[124..136], "{o:0>11}\x00", .{body.len});
    _ = try std.fmt.bufPrint(header[136..148], "{o:0>11}\x00", .{@as(u32, 0)});
    @memset(header[148..156], ' ');
    header[156] = typeflag;
    @memcpy(header[257..263], "ustar\x00");
    @memcpy(header[263..265], "00");
    var chksum: u32 = 0;
    for (header) |b| chksum += b;
    _ = try std.fmt.bufPrint(header[148..156], "{o:0>6}\x00 ", .{chksum});
    try tar.appendSlice(allocator, &header);
    try tar.appendSlice(allocator, body);
    const pad = (512 - (body.len % 512)) % 512;
    if (pad > 0) try tar.appendNTimes(allocator, 0, pad);
}

test "less fixture writes preserve regular and exclusive contract and refuse aliases/hardlinks/fifos" {
    const allocator = std.testing.allocator;
    var tr = try TestRoot.init(allocator);
    defer tr.deinit(allocator);

    try ensureDirectory(tr.path, "usr", 0o755, false);
    try ensureDirectory(tr.path, "usr/bin", 0o755, false);
    try ensureDirectory(tr.path, "etc", 0o755, false);
    try ensureDirectory(tr.path, "outside", 0o755, false);

    try createExclusive(tr.path, "usr/bin/update-alternatives", "original tool with longer contents\n", 0o755);
    try overwriteRegular(tr.path, "usr/bin/update-alternatives", "bad tool\n");
    const tool_bytes = try readRegular(allocator, tr.path, "usr/bin/update-alternatives", 1024);
    defer allocator.free(tool_bytes);
    try std.testing.expectEqualStrings("bad tool\n", tool_bytes);

    try createExclusive(tr.path, "etc/ld.so.cache", "bad cache\n", 0o644);
    try std.testing.expectError(
        error.FixtureFileAlreadyExists,
        createExclusive(tr.path, "etc/ld.so.cache", "replacement\n", 0o644),
    );

    // Leaf symlink refusal for overwriteRegular and createExclusive
    try createExclusive(tr.path, "outside/witness", "must remain intact\n", 0o644);
    const witness_abs = try std.fs.path.join(allocator, &.{ tr.path, "outside/witness" });
    defer allocator.free(witness_abs);
    try createAlias(tr.path, "etc/alias-cache", witness_abs);
    try std.testing.expectError(
        error.FixtureFileAlreadyExists,
        createExclusive(tr.path, "etc/alias-cache", "bad\n", 0o644),
    );
    try std.testing.expectError(
        error.ReferenceSyscallRefused,
        overwriteRegular(tr.path, "etc/alias-cache", "bad\n"),
    );

    // Hardlink and FIFO refusal before truncation
    {
        const parent = try openParentDescriptor(tr.path, "usr/bin/hardlinked");
        defer _ = linux.close(parent.fd);
        const witness_parent = try openParentDescriptor(tr.path, "outside/witness");
        defer _ = linux.close(witness_parent.fd);
        _ = try syscall(linux.linkat(witness_parent.fd, "witness", parent.fd, "hardlinked", 0));
        try std.testing.expectError(
            error.UnsafeFixtureRegularFile,
            overwriteRegular(tr.path, "usr/bin/hardlinked", "bad tool\n"),
        );
        try std.testing.expectError(
            error.UnsafeFixtureRegularFile,
            readRegular(allocator, tr.path, "outside/witness", 1024),
        );
        _ = try syscall(linux.unlinkat(parent.fd, "hardlinked", 0));
    }
    {
        const parent = try openParentDescriptor(tr.path, "usr/bin/fifo");
        defer _ = linux.close(parent.fd);
        _ = try syscall(linux.mknodat(parent.fd, "fifo", linux.S.IFIFO | 0o600, 0));
    }
    try std.testing.expectError(
        error.UnsafeFixtureRegularFile,
        overwriteRegular(tr.path, "usr/bin/fifo", "bad tool\n"),
    );

    const witness_after = try readRegular(allocator, tr.path, "outside/witness", 1024);
    defer allocator.free(witness_after);
    try std.testing.expectEqualStrings("must remain intact\n", witness_after);
}

test "directory creation refuses aliases and enforces mode under restrictive umask" {
    const allocator = std.testing.allocator;
    var tr = try TestRoot.init(allocator);
    defer tr.deinit(allocator);

    try ensureDirectory(tr.path, "outside", 0o755, true);
    try ensureDirectory(tr.path, "usr", 0o755, true);
    const outside_abs = try std.fs.path.join(allocator, &.{ tr.path, "outside" });
    defer allocator.free(outside_abs);
    try createAlias(tr.path, "usr/local", outside_abs);

    try std.testing.expectError(
        error.ReferenceSyscallRefused,
        ensureDirectory(tr.path, "usr/local", 0o755, false),
    );
    {
        const parent = try openParentDescriptor(tr.path, "usr/local");
        defer _ = linux.close(parent.fd);
        _ = try syscall(linux.unlinkat(parent.fd, "local", 0));
    }

    const prev_umask = linux.syscall1(.umask, 0o077);
    defer _ = linux.syscall1(.umask, prev_umask);
    try ensureDirectory(tr.path, "usr/local", 0o755, false);

    const local_abs = try std.fs.path.join(allocator, &.{ tr.path, "usr/local" });
    defer allocator.free(local_abs);
    const fd = try reference_paths.openAbsolute(local_abs, true);
    defer _ = linux.close(fd);
    const meta = try rawFstat(fd);
    try std.testing.expectEqual(@as(u16, 0o755), meta.mode & 0o777);
}

test "python staging, basic negatives, and capture enforce exclusive and bounded invariants" {
    const allocator = std.testing.allocator;
    var tr = try TestRoot.init(allocator);
    defer tr.deinit(allocator);
    reference_paths.setTestRootOverride(tr.path);
    defer reference_paths.setTestRootOverride(null);

    try ensureDirectory(tr.path, "safe", 0o700, true);
    try ensureDirectory(tr.path, "safe/usr", 0o755, true);
    try ensureDirectory(tr.path, "safe/var", 0o755, true);
    try ensureDirectory(tr.path, "safe/var/lib", 0o755, true);
    try ensureDirectory(tr.path, "safe/var/lib/dpkg", 0o755, true);
    try createExclusive(tr.path, "pinned", "pinned bytes", 0o755);
    try createExclusive(tr.path, "archive", "archive bytes", 0o644);

    const safe_root = try std.fs.path.join(allocator, &.{ tr.path, "safe" });
    defer allocator.free(safe_root);
    const pinned_path = try std.fs.path.join(allocator, &.{ tr.path, "pinned" });
    defer allocator.free(pinned_path);
    const archive_path = try std.fs.path.join(allocator, &.{ tr.path, "archive" });
    defer allocator.free(archive_path);

    _ = try dispatchPython(allocator, &.{ "dpkg", safe_root, pinned_path, archive_path });
    try std.testing.expectError(
        error.FixtureFileAlreadyExists,
        dispatchPython(allocator, &.{ "dpkg", safe_root, pinned_path, archive_path }),
    );
    const staged_dpkg = try readRegular(allocator, safe_root, "usr/local/sbin/dpkg", 1024);
    defer allocator.free(staged_dpkg);
    try std.testing.expectEqualStrings("pinned bytes", staged_dpkg);
    const staged_deb = try readRegular(allocator, safe_root, "var/lib/dpkg/python3-probe.deb", 1024);
    defer allocator.free(staged_deb);
    try std.testing.expectEqualStrings("archive bytes", staged_deb);

    const status = try dispatchPython(allocator, &.{
        "capture",
        safe_root,
        "stdout",
        "stderr",
        "timeout",
        "--signal=TERM",
        "10s",
        "/bin/sh",
        "-c",
        "printf 'captured\\n'",
    });
    try std.testing.expectEqual(@as(u8, 0), status);
    const captured = try readRegular(allocator, safe_root, "stdout", 1024);
    defer allocator.free(captured);
    try std.testing.expectEqualStrings("captured\n", captured);
    try std.testing.expectError(
        error.FixtureFileAlreadyExists,
        dispatchPython(allocator, &.{
            "capture",
            safe_root,
            "stdout",
            "stderr",
            "/bin/sh",
            "-c",
            "printf 'captured\\n'",
        }),
    );
    try std.testing.expectError(
        error.PythonReferenceCaptureExceedsByteLimit,
        dispatchPython(allocator, &.{
            "capture",
            safe_root,
            "oversized",
            "oversized-stderr",
            "/usr/bin/head",
            "-c",
            "17825792",
            "/dev/zero",
        }),
    );
    const oversized_fd = try openRegularDescriptor(safe_root, "oversized");
    defer _ = linux.close(oversized_fd);
    const oversized_meta = try regularMetadata(oversized_fd);
    try std.testing.expectEqual(@as(u64, maximum_capture_bytes), oversized_meta.size);
}

test "verifyLockArchive refuses unreviewed coordinates before opening cache" {
    const allocator = std.testing.allocator;
    const pin = source_artifacts[0]; // less
    const valid_json = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "target_architecture": "arm64",
        \\  "packages": [{{
        \\    "name": "{s}",
        \\    "architecture": "arm64",
        \\    "version": "{s}",
        \\    "declared_size": {d},
        \\    "origin": {{"type": "authenticated_repository"}},
        \\    "archive_identity": {{
        \\      "primary": "sha512",
        \\      "digests": [{{"algorithm": "sha512", "digest": "{s}"}}]
        \\    }}
        \\  }}]
        \\}}
    , .{ pin.name, pin.version, pin.declared_size, pin.sha512 });
    defer allocator.free(valid_json);

    const wrong_version = try std.mem.replaceOwned(u8, allocator, valid_json, pin.version, "other");
    defer allocator.free(wrong_version);
    var parsed_ver = try std.json.parseFromSlice(std.json.Value, allocator, wrong_version, .{});
    defer parsed_ver.deinit();
    try std.testing.expectError(
        error.SourceArchiveDiffersFromProductionAuthority,
        verifyLockArchive(allocator, parsed_ver.value, "/nonexistent-cache", "less"),
    );

    const wrong_origin = try std.mem.replaceOwned(u8, allocator, valid_json, "authenticated_repository", "local_artifact");
    defer allocator.free(wrong_origin);
    var parsed_origin = try std.json.parseFromSlice(std.json.Value, allocator, wrong_origin, .{});
    defer parsed_origin.deinit();
    try std.testing.expectError(
        error.UnauthenticatedSourceArchive,
        verifyLockArchive(allocator, parsed_origin.value, "/nonexistent-cache", "less"),
    );

    const wrong_arch = try std.mem.replaceOwned(u8, allocator, valid_json, "\"architecture\": \"arm64\"", "\"architecture\": \"all\"");
    defer allocator.free(wrong_arch);
    var parsed_arch = try std.json.parseFromSlice(std.json.Value, allocator, wrong_arch, .{});
    defer parsed_arch.deinit();
    try std.testing.expectError(
        error.AmbiguousSignedSourceArchive,
        verifyLockArchive(allocator, parsed_arch.value, "/nonexistent-cache", "less"),
    );
}

test "extractArchiveMember refuses pre-existing .less-source.tar alias and extractTarPayloadMember validates entries" {
    const allocator = std.testing.allocator;
    var tr = try TestRoot.init(allocator);
    defer tr.deinit(allocator);

    try createExclusive(tr.path, "outside", "must stay intact", 0o644);
    const outside_abs = try std.fs.path.join(allocator, &.{ tr.path, "outside" });
    defer allocator.free(outside_abs);
    try createAlias(tr.path, "archive.less-source.tar", outside_abs);

    const archive_abs = try std.fs.path.join(allocator, &.{ tr.path, "archive" });
    defer allocator.free(archive_abs);
    try std.testing.expectError(
        error.FixtureFileAlreadyExists,
        extractArchiveMember(allocator, archive_abs, "usr/bin/dash"),
    );
    const intact = try readRegular(allocator, tr.path, "outside", 1024);
    defer allocator.free(intact);
    try std.testing.expectEqualStrings("must stay intact", intact);

    var tar_bytes: std.ArrayList(u8) = .empty;
    defer tar_bytes.deinit(allocator);
    try writeTarEntry(allocator, &tar_bytes, "./usr/bin/dash", '0', 0, 0, "dash binary bytes");
    try tar_bytes.appendNTimes(allocator, 0, 1024);
    const extracted = try extractTarPayloadMember(allocator, tar_bytes.items, "usr/bin/dash");
    defer allocator.free(extracted);
    try std.testing.expectEqualStrings("dash binary bytes", extracted);

    var bad_uid_tar: std.ArrayList(u8) = .empty;
    defer bad_uid_tar.deinit(allocator);
    try writeTarEntry(allocator, &bad_uid_tar, "./usr/bin/dash", '0', 1000, 0, "dash binary bytes");
    try bad_uid_tar.appendNTimes(allocator, 0, 1024);
    try std.testing.expectError(
        error.UnexpectedSignedRuntimeMember,
        extractTarPayloadMember(allocator, bad_uid_tar.items, "usr/bin/dash"),
    );
}

test "sealLess and sealBash refuse altered lists or symlinked scripts before publishing callbacks" {
    const allocator = std.testing.allocator;
    var tr = try TestRoot.init(allocator);
    defer tr.deinit(allocator);

    for ([_][]const u8{
        "var",
        "var/lib",
        "var/lib/dpkg",
        "var/lib/dpkg/info",
        "var/lib/debz-lifecycle-scripts",
    }) |rel| {
        try ensureDirectory(tr.path, rel, 0o755, false);
    }
    try createExclusive(tr.path, "var/lib/dpkg/info/bash.list", "wrong list\n", 0o644);
    try createExclusive(tr.path, "var/lib/dpkg/info/bash.postinst", "wrong postinst\n", 0o755);
    try std.testing.expectError(error.SignedBashOwnershipPathSetChanged, sealBash(allocator, tr.path));

    const lifecycle_abs = try std.fs.path.join(allocator, &.{ tr.path, "var/lib/debz-lifecycle-scripts" });
    defer allocator.free(lifecycle_abs);
    const lc_fd = try reference_paths.openAbsolute(lifecycle_abs, true);
    defer _ = linux.close(lc_fd);
    try std.testing.expect(try directoryIsEmpty(lc_fd));
}
