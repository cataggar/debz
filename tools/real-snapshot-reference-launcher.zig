const std = @import("std");
const linux = std.os.linux;

const OpenHow = extern struct { flags: u64, mode: u64 = 0, resolve: u64 };
const resolve_no_symlinks: u64 = 0x02 | 0x04;
const proc_flags = linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC;
const mask_flags = linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC;
const close_range_cloexec: usize = 4;
const Bpf = extern struct { code: u16, jt: u8 = 0, jf: u8 = 0, k: u32 };
const BpfProgram = extern struct { len: u16, filter: [*]const Bpf };
const deny_syscalls = [_]linux.SYS{
    .mount,         .umount2,       .pivot_root,        .unshare,   .setns,
    .fsopen,        .fsconfig,      .fsmount,           .open_tree, .move_mount,
    .mount_setattr, .mknodat,       .open_by_handle_at, .chroot,    .init_module,
    .finit_module,  .delete_module, .kexec_load,        .reboot,    .swapon,
    .swapoff,
} ++ (if (@import("builtin").cpu.arch == .x86_64)
    [_]linux.SYS{ .mknod, .kexec_file_load }
else
    [_]linux.SYS{});
const filesystem_account_caps = .{
    linux.CAP.CHOWN,   linux.CAP.DAC_OVERRIDE, linux.CAP.FOWNER,
    linux.CAP.FSETID,  linux.CAP.SETGID,       linux.CAP.SETUID,
    linux.CAP.SETFCAP,
};
// The kernel reads pid at byte 4; linux.cap_user_header_t uses usize and pads it to byte 8.
const CapHeader = extern struct { version: u32 = 0x20080522, pid: i32 = 0 };
comptime {
    std.debug.assert(@sizeOf(CapHeader) == 8 and @offsetOf(CapHeader, "pid") == 4);
}
const filter = generateFilter();
const archive_target: [*:0]const u8 = "/.debz-reference-archive";
const MountAttribute = extern struct {
    attr_set: u64 = 0,
    attr_clear: u64 = 0,
    propagation: u64 = 0,
    user_namespace_fd: u64 = 0,
};

fn cloneMountDescriptor(fd: i32) usize {
    return linux.syscall3(
        .open_tree,
        @bitCast(@as(isize, fd)),
        @intFromPtr(@as([*:0]const u8, "")),
        1 | (1 << @bitOffsetOf(linux.O, "CLOEXEC")) | linux.AT.EMPTY_PATH,
    );
}

fn setMountAttributes(fd: i32, attributes: *const MountAttribute) usize {
    return linux.syscall5(
        .mount_setattr,
        @bitCast(@as(isize, fd)),
        @intFromPtr(@as([*:0]const u8, "")),
        linux.AT.EMPTY_PATH,
        @intFromPtr(attributes),
        @sizeOf(MountAttribute),
    );
}
const environment: [*:null]const ?[*:0]const u8 = &.{
    "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/",
    "LC_ALL=C",
    "DEBIAN_FRONTEND=noninteractive",
    "DEBCONF_NONINTERACTIVE_SEEN=true",
    "DPKG_COLORS=never",
    null,
};

const Profile = enum { none, systemd, udev, sudo };
const Verb = enum { probe_unpack, unpack, probe_configure, configure };
const ScriptBinding = struct {
    name: []const u8,
    version: []const u8,
    size: usize,
    digest: []const u8,
};
const script_bindings = [_]ScriptBinding{
    .{ .name = "systemd", .version = "261.2-1ubuntu2", .size = 4942, .digest = "39df51226d6dd8456a388d3315e7d02b446dcec9944515a109933c65c8c1b412" },
    .{ .name = "udev", .version = "261.2-1ubuntu2", .size = 2533, .digest = "861ba57cdb3f94bae94af237b9284b01bceb956ee69bb09d3b54e381567336ee" },
    .{ .name = "sudo", .version = "1.9.17p2-7ubuntu3", .size = 1927, .digest = "e766407bf70ad03d8006de9f3f8700f7ed22b532d8e299ac88e522e2c80a2cb8" },
};
const dpkg_digests = [_][]const u8{
    "0a20f6015fbb7c011571f3ed227a138b12ce282e46b7fdfc239558bc5a7bc9e5",
    "d8878dcd8949b2d18359b98082e18b2c3bb77f4cbe14e7a90f58b3fad2670e79",
};

const Pinned = struct { fd: i32, metadata: linux.Statx };
const Options = struct {
    root: [:0]const u8,
    dpkg: [:0]const u8,
    architecture: []const u8,
    profile: Profile,
    verb: Verb,
    selector: ?[:0]const u8 = null,
    archive: ?[:0]const u8 = null,
    archive_sha512: ?[]const u8 = null,
    archive_size: ?usize = null,
};

pub fn main(init: std.process.Init) !void {
    const supervisor = linux.getppid();
    if (supervisor <= 1) return error.MissingSupervisor;
    _ = try checked(linux.prctl(
        @intFromEnum(linux.PR.SET_PDEATHSIG),
        @intFromEnum(linux.SIG.KILL),
        0,
        0,
        0,
    ));
    if (linux.getppid() != supervisor) return error.SupervisorExited;
    try verifyStandardStreams();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const root = args.next() orelse return error.InvalidArguments;
    const dpkg = args.next() orelse return error.InvalidArguments;
    const architecture = args.next() orelse return error.InvalidArguments;
    const profile_name = args.next() orelse return error.InvalidArguments;
    const verb_name = args.next() orelse return error.InvalidArguments;
    const profile = std.meta.stringToEnum(Profile, profile_name) orelse return error.InvalidArguments;
    const verb = std.meta.stringToEnum(Verb, verb_name) orelse return error.InvalidArguments;
    const selector = args.next();
    const archive = args.next();
    const digest = args.next();
    const size_text = args.next();
    if (args.next() != null) return error.InvalidArguments;
    const options: Options = .{
        .root = try init.arena.allocator().dupeZ(u8, root),
        .dpkg = try init.arena.allocator().dupeZ(u8, dpkg),
        .architecture = architecture,
        .profile = profile,
        .verb = verb,
        .selector = if (selector) |value| try init.arena.allocator().dupeZ(u8, value) else null,
        .archive = if (archive) |value| try init.arena.allocator().dupeZ(u8, value) else null,
        .archive_sha512 = digest,
        .archive_size = if (size_text) |value| try std.fmt.parseInt(usize, value, 10) else null,
    };
    try validateOptions(options);
    const status = try run(init.arena.allocator(), options);
    std.process.exit(status);
}

fn validAbsolute(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or
            std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

fn validateOptions(options: Options) !void {
    if (!validAbsolute(options.root) or !validAbsolute(options.dpkg) or
        (options.archive != null and !validAbsolute(options.archive.?)))
        return error.InvalidArguments;
    const architecture_index: usize = if (std.mem.eql(u8, options.architecture, "amd64"))
        0
    else if (std.mem.eql(u8, options.architecture, "arm64"))
        1
    else
        return error.UnsupportedArchitecture;
    const unpacking = options.verb == .unpack or options.verb == .probe_unpack;
    const configuring = options.verb == .configure or options.verb == .probe_configure;
    if (unpacking != (options.archive != null) or
        unpacking != (options.archive_sha512 != null) or
        unpacking != (options.archive_size != null) or
        (unpacking or configuring) != (options.selector != null))
        return error.InvalidArguments;
    if (options.selector) |selector| {
        if (selector.len == 0 or selector.len > 120 or
            std.mem.indexOfAny(u8, selector, "/ \t\n\x00") != null or selector[0] == '-')
            return error.InvalidArguments;
    }
    if (options.profile != .none) {
        if (options.verb != .configure or architecture_index != 0)
            return error.InvalidProfile;
        const binding = script_bindings[@intFromEnum(options.profile) - 1];
        const selector_name = options.selector.?;
        if (selector_name.len != binding.name.len + ":amd64".len or
            !std.mem.startsWith(u8, selector_name, binding.name) or
            !std.mem.eql(u8, selector_name[binding.name.len..], ":amd64"))
            return error.InvalidProfile;
    } else if (options.verb == .configure) {
        for (script_bindings) |binding| {
            if (std.mem.eql(u8, options.selector.?, binding.name) or
                (options.selector.?.len > binding.name.len and
                    std.mem.startsWith(u8, options.selector.?, binding.name) and
                    options.selector.?[binding.name.len] == ':'))
                return error.InvalidProfile;
        }
    }
    if (unpacking) {
        if (options.archive_size.? == 0 or options.archive_size.? > 512 * 1024 * 1024 or
            options.archive_sha512.?.len != 128) return error.InvalidArguments;
        for (options.archive_sha512.?) |digit| {
            if (!std.ascii.isHex(digit) or std.ascii.isUpper(digit))
                return error.InvalidArguments;
        }
    }
}

fn checked(result: usize) !usize {
    return switch (linux.errno(result)) {
        .SUCCESS => result,
        else => |err| {
            std.log.err("reference launcher syscall refused: {s}", .{@tagName(err)});
            return error.ReferenceSetupFailed;
        },
    };
}

fn metadata(fd: i32) !linux.Statx {
    var value: linux.Statx = undefined;
    _ = try checked(linux.statx(fd, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &value));
    return value;
}

fn allowedStandardStream(slot: i32, info: linux.Statx, flags: usize) bool {
    const access = flags & 3;
    const path_flag: usize = 1 << @bitOffsetOf(linux.O, "PATH");
    if (flags & path_flag != 0 or info.uid != 0 or info.gid != 0) return false;
    if (slot == 0) {
        return (info.mode & 0o170000) == 0o020000 and
            info.rdev_major == 1 and info.rdev_minor == 3 and access == 0;
    }
    const append_flag: usize = 1 << @bitOffsetOf(linux.O, "APPEND");
    return (slot == 1 or slot == 2) and
        (info.mode & 0o170000) == 0o100000 and
        (info.mode & 0o022) == 0 and info.nlink <= 1 and
        access == 1 and flags & append_flag != 0;
}

fn verifyStandardStream(slot: i32, fd: i32) !void {
    const info = metadata(fd) catch return error.InvalidStandardStream;
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS or !allowedStandardStream(slot, info, flags))
        return error.InvalidStandardStream;
}

fn verifyStandardStreams() !void {
    inline for (0..3) |slot| try verifyStandardStream(@intCast(slot), @intCast(slot));
}

fn openPinned(path: [:0]const u8, directory: bool) !Pinned {
    const flags: linux.O = .{ .PATH = true, .CLOEXEC = true, .DIRECTORY = directory };
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve_no_symlinks };
    const fd: i32 = @intCast(try checked(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(path.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    )));
    errdefer _ = linux.close(fd);
    return .{ .fd = fd, .metadata = try metadata(fd) };
}

fn same(left: linux.Statx, right: linux.Statx) bool {
    return left.dev_major == right.dev_major and left.dev_minor == right.dev_minor and
        left.ino == right.ino and left.mode == right.mode and left.uid == right.uid and
        left.gid == right.gid and left.size == right.size and left.nlink == right.nlink and
        left.mtime.sec == right.mtime.sec and left.mtime.nsec == right.mtime.nsec and
        left.ctime.sec == right.ctime.sec and left.ctime.nsec == right.ctime.nsec;
}

fn protectedAncestors(path: [:0]const u8) !void {
    if (!validAbsolute(path)) return error.UnprotectedPath;
    var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (path.len >= buffer.len) return error.UnprotectedPath;
    @memcpy(buffer[0..path.len], path);
    for (buffer[0..path.len], 0..) |byte, index| {
        if (byte != '/' or index == 0) continue;
        buffer[index] = 0;
        const pinned = try openPinned(buffer[0..index :0], true);
        _ = linux.close(pinned.fd);
        if (pinned.metadata.uid != 0 or pinned.metadata.gid != 0 or
            (pinned.metadata.mode & 0o022) != 0) return error.UnprotectedPath;
        buffer[index] = '/';
    }
}

fn hashFile(fd: i32, comptime Hash: type, maximum: usize) ![Hash.digest_length]u8 {
    var hash = Hash.init(.{});
    var count: usize = 0;
    var bytes: [8192]u8 = undefined;
    while (true) {
        const got = try checked(linux.read(fd, &bytes, bytes.len));
        if (got == 0) break;
        count = std.math.add(usize, count, got) catch return error.FileTooLarge;
        if (count > maximum) return error.FileTooLarge;
        hash.update(bytes[0..got]);
    }
    var digest: [Hash.digest_length]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn openVerified(
    path: [:0]const u8,
    comptime Hash: type,
    expected: []const u8,
    size: ?usize,
    maximum: usize,
) !Pinned {
    try protectedAncestors(path);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true };
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve_no_symlinks };
    const fd: i32 = @intCast(try checked(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(path.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    )));
    errdefer _ = linux.close(fd);
    const before = try metadata(fd);
    if (before.uid != 0 or before.gid != 0 or (before.mode & 0o170000) != 0o100000 or
        (before.mode & 0o022) != 0 or before.nlink != 1 or
        before.size > maximum or (size != null and before.size != size.?))
        return error.InvalidSourceFile;
    const digest = try hashFile(fd, Hash, maximum);
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), expected) or
        !same(before, try metadata(fd))) return error.SourceChanged;
    return .{ .fd = fd, .metadata = before };
}

fn bindingStatusMatches(status: []const u8, binding: ScriptBinding) bool {
    var matched = false;
    var paragraphs = std.mem.splitSequence(u8, status, "\n\n");
    while (paragraphs.next()) |paragraph| {
        if (paragraph.len == 0) continue;
        var name: ?[]const u8 = null;
        var architecture: ?[]const u8 = null;
        var version: ?[]const u8 = null;
        var state: ?[]const u8 = null;
        var identity_field = false;
        var lines = std.mem.splitScalar(u8, paragraph, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (line[0] == ' ' or line[0] == '\t') {
                if (identity_field) return false;
                continue;
            }
            identity_field = false;
            const separator = std.mem.indexOf(u8, line, ": ") orelse return false;
            const key = line[0..separator];
            const value = line[separator + 2 ..];
            if (std.ascii.eqlIgnoreCase(key, "Package")) {
                if (name != null) return false;
                name = value;
                identity_field = true;
            } else if (std.ascii.eqlIgnoreCase(key, "Architecture")) {
                if (architecture != null) return false;
                architecture = value;
                identity_field = true;
            } else if (std.ascii.eqlIgnoreCase(key, "Version")) {
                if (version != null) return false;
                version = value;
                identity_field = true;
            } else if (std.ascii.eqlIgnoreCase(key, "Status")) {
                if (state != null) return false;
                state = value;
                identity_field = true;
            }
        }
        if (name != null and std.mem.eql(u8, name.?, binding.name)) {
            if (matched or architecture == null or version == null or state == null or
                !std.mem.eql(u8, architecture.?, "amd64") or
                !std.mem.eql(u8, version.?, binding.version) or
                !std.mem.eql(u8, state.?, "install ok unpacked")) return false;
            matched = true;
        }
    }
    return matched;
}

fn verifyInstalledBinding(binding: ScriptBinding) !void {
    const path: [:0]const u8 = "/var/lib/dpkg/status";
    try protectedAncestors(path);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true };
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve_no_symlinks };
    const fd: i32 = @intCast(try checked(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(path.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    )));
    defer _ = linux.close(fd);
    const before = try metadata(fd);
    if (before.uid != 0 or before.gid != 0 or
        (before.mode & 0o170000) != 0o100000 or (before.mode & 0o022) != 0 or
        before.nlink != 1 or before.size > 4 * 1024 * 1024)
        return error.InvalidInstalledBinding;
    const size: usize = @intCast(before.size);
    const bytes = try std.heap.page_allocator.alloc(u8, size + 1);
    defer std.heap.page_allocator.free(bytes);
    var count: usize = 0;
    while (count < bytes.len) {
        const got = try checked(linux.read(fd, bytes[count..].ptr, bytes.len - count));
        if (got == 0) break;
        count += got;
    }
    if (count != size or !same(before, try metadata(fd)) or
        !bindingStatusMatches(bytes[0..count], binding))
        return error.InvalidInstalledBinding;
    const script_path = try std.fmt.allocPrintSentinel(
        std.heap.page_allocator,
        "/var/lib/dpkg/info/{s}.postinst",
        .{binding.name},
        0,
    );
    defer std.heap.page_allocator.free(script_path);
    const script = try openVerified(
        script_path,
        std.crypto.hash.sha2.Sha256,
        binding.digest,
        binding.size,
        binding.size,
    );
    _ = linux.close(script.fd);
}

fn protectedRoot(root: [:0]const u8) !Pinned {
    try protectedAncestors(root);
    const pinned = try openPinned(root, true);
    errdefer _ = linux.close(pinned.fd);
    if (pinned.metadata.mode != 0o40700 or pinned.metadata.uid != 0 or
        pinned.metadata.gid != 0) return error.UnprotectedRoot;
    return pinned;
}

fn emptyDirectory(path: [:0]const u8) !void {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .DIRECTORY = true };
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve_no_symlinks };
    const fd: i32 = @intCast(try checked(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(path.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    )));
    defer _ = linux.close(fd);
    var bytes: [2048]u8 = undefined;
    while (true) {
        const count = try checked(linux.syscall3(.getdents64, @bitCast(@as(isize, fd)), @intFromPtr(&bytes), bytes.len));
        if (count == 0) return;
        var offset: usize = 0;
        while (offset < count) {
            if (count - offset < 20) return error.InvalidMountpoint;
            const entry_size = std.mem.readInt(u16, bytes[offset + 16 ..][0..2], .little);
            if (entry_size < 20 or entry_size > count - offset)
                return error.InvalidMountpoint;
            const name = std.mem.sliceTo(bytes[offset + 19 .. offset + entry_size], 0);
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, ".."))
                return error.MountpointNotEmpty;
            offset += entry_size;
        }
    }
}

fn readBootId() ![37]u8 {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true };
    const how: OpenHow = .{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve_no_symlinks };
    const fd: i32 = @intCast(try checked(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr("/proc/sys/kernel/random/boot_id"),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    )));
    defer _ = linux.close(fd);
    const entry = try metadata(fd);
    if (entry.mode != 0o100444 or entry.uid != 0 or entry.gid != 0 or entry.nlink != 1)
        return error.InvalidBootId;
    var bytes: [38]u8 = undefined;
    const count = try checked(linux.read(fd, &bytes, bytes.len));
    if (count != 37 or bytes[36] != '\n') return error.InvalidBootId;
    for (bytes[0..36], 0..) |digit, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (digit != '-') return error.InvalidBootId;
        } else if (!std.ascii.isHex(digit) or std.ascii.isUpper(digit)) {
            return error.InvalidBootId;
        }
    }
    return bytes[0..37].*;
}

const Child = struct {
    options: Options,
    root: Pinned,
    proc_mountpoint: Pinned,
    archive_mountpoint: Pinned,
    dpkg: Pinned,
    archive: ?Pinned,
    boot_id: ?[37]u8,
    status_pipe: [2]i32,
    control_pipe: [2]i32,
};

fn fail(status: i32, stage: u8, err: linux.E) noreturn {
    var bytes: [5]u8 = .{ stage, 0, 0, 0, 0 };
    std.mem.writeInt(u32, bytes[1..5], @intFromEnum(err), .little);
    _ = linux.write(status, &bytes, bytes.len);
    linux.exit(125);
}

fn must(result: usize, fd: i32, stage: u8) void {
    if (linux.errno(result) != .SUCCESS) fail(fd, stage, linux.errno(result));
}

fn mountArchive(child: Child) linux.E {
    const archive = child.archive orelse return .SUCCESS;
    const tree_result = cloneMountDescriptor(archive.fd);
    if (linux.errno(tree_result) != .SUCCESS) return linux.errno(tree_result);
    const tree: i32 = @intCast(tree_result);
    defer _ = linux.close(tree);
    const attributes: MountAttribute = .{
        .attr_set = 1 | 2 | 4 | 8,
        .attr_clear = 0,
        .propagation = 0,
    };
    const attributes_result = setMountAttributes(tree, &attributes);
    if (linux.errno(attributes_result) != .SUCCESS)
        return linux.errno(attributes_result);
    const target = openPinned(archive_target[0..std.mem.len(archive_target) :0], false) catch return .STALE;
    defer _ = linux.close(target.fd);
    if (!same(target.metadata, child.archive_mountpoint.metadata)) return .STALE;
    return linux.errno(linux.move_mount(tree, "", target.fd, "", .{
        .F_SYMLINKS = false,
        .F_AUTOMOUNTS = false,
        .F_EMPTY_PATH = true,
        .T_SYMLINKS = false,
        .T_AUTOMOUNTS = false,
        .T_EMPTY_PATH = true,
        .SET_GROUP = false,
    }));
}

fn mountProc(child: Child) linux.E {
    if (child.options.profile == .none) return .SUCCESS;
    const proc = openPinned("/proc", true) catch return .STALE;
    defer _ = linux.close(proc.fd);
    if (!same(proc.metadata, child.proc_mountpoint.metadata)) return .STALE;
    emptyDirectory("/proc") catch return .EXIST;
    const mounted = linux.errno(linux.mount(
        "proc",
        "/proc",
        "proc",
        proc_flags,
        @intFromPtr(if (child.options.profile == .systemd)
            @as([*:0]const u8, "hidepid=2")
        else
            @as([*:0]const u8, "hidepid=2,subset=pid")),
    ));
    if (mounted != .SUCCESS) return mounted;
    const visible = linux.open("/proc/1/root", .{ .PATH = true, .CLOEXEC = true }, 0);
    if (linux.errno(visible) != .SUCCESS) return linux.errno(visible);
    const observed = metadata(@intCast(visible)) catch {
        _ = linux.close(@intCast(visible));
        return .STALE;
    };
    _ = linux.close(@intCast(visible));
    if (observed.dev_major != child.root.metadata.dev_major or
        observed.dev_minor != child.root.metadata.dev_minor or
        observed.ino != child.root.metadata.ino)
        return .STALE;
    if (child.options.profile == .systemd) return maskBootId(child.boot_id.?);
    for ([_][*:0]const u8{ "/proc/sys", "/proc/sys/kernel/random/boot_id" }) |path| {
        const present = linux.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
        if (linux.errno(present) == .SUCCESS) {
            _ = linux.close(@intCast(present));
            return .EXIST;
        }
        if (linux.errno(present) != .NOENT) return linux.errno(present);
    }
    return .SUCCESS;
}

fn maskBootId(boot_id: [37]u8) linux.E {
    const masked = linux.errno(linux.mount(
        "tmpfs",
        "/proc/sys",
        "tmpfs",
        mask_flags,
        @intFromPtr("mode=0700,size=65536"),
    ));
    if (masked != .SUCCESS) return masked;
    for ([_][*:0]const u8{ "/proc/sys/kernel", "/proc/sys/kernel/random" }) |path| {
        const created = linux.errno(linux.mkdir(path, 0o555));
        if (created != .SUCCESS) return created;
        const mode = linux.errno(linux.chmod(path, 0o555));
        if (mode != .SUCCESS) return mode;
    }
    const file_result = linux.open(
        "/proc/sys/kernel/random/boot_id",
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true, .NOFOLLOW = true },
        0o444,
    );
    if (linux.errno(file_result) != .SUCCESS) return linux.errno(file_result);
    const file: i32 = @intCast(file_result);
    const wrote = linux.write(file, &boot_id, boot_id.len);
    if (linux.errno(wrote) != .SUCCESS or wrote != boot_id.len) {
        _ = linux.close(file);
        return .IO;
    }
    const mode = linux.errno(linux.fchmod(file, 0o444));
    _ = linux.close(file);
    if (mode != .SUCCESS) return mode;
    const protected = linux.errno(linux.mount(
        null,
        "/proc/sys",
        null,
        linux.MS.REMOUNT | proc_flags,
        0,
    ));
    if (protected != .SUCCESS) return protected;
    for ([_][*:0]const u8{
        "/proc/sys/kernel/random/uuid", "/proc/sys/kernel/pid_max",
        "/proc/sys/vm",                 "/proc/sys/net",
    }) |path| {
        const present = linux.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
        if (linux.errno(present) == .SUCCESS) {
            _ = linux.close(@intCast(present));
            return .EXIST;
        }
        if (linux.errno(present) != .NOENT) return linux.errno(present);
    }
    const present = linux.open(
        "/proc/sys/kernel/random/boot_id",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true },
        0,
    );
    if (linux.errno(present) != .SUCCESS) return linux.errno(present);
    var observed: [38]u8 = undefined;
    const got = linux.read(@intCast(present), &observed, observed.len);
    _ = linux.close(@intCast(present));
    if (linux.errno(got) != .SUCCESS or got != boot_id.len or
        !std.mem.eql(u8, observed[0..got], &boot_id)) return .STALE;
    const writable = linux.open(
        "/proc/sys/extra",
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
        0o600,
    );
    if (linux.errno(writable) == .SUCCESS) {
        _ = linux.close(@intCast(writable));
        return .EXIST;
    }
    if (linux.errno(writable) != .ROFS) return linux.errno(writable);
    return .SUCCESS;
}

fn allowedCapability(capability: u32) bool {
    inline for (filesystem_account_caps) |allowed| {
        if (capability == allowed) return true;
    }
    return false;
}

fn allowedCapabilityMask(word: usize) u32 {
    var mask: u32 = 0;
    inline for (filesystem_account_caps) |capability| {
        if (capability / 32 == word)
            mask |= @as(u32, 1) << @intCast(capability % 32);
    }
    return mask;
}

fn restrictCapabilityData(data: *[2]linux.cap_user_data_t) void {
    for (data, 0..) |*entry, word| {
        const mask = allowedCapabilityMask(word);
        entry.effective &= mask;
        entry.permitted &= mask;
        entry.inheritable &= mask;
    }
}

fn readCapabilities(data: *[2]linux.cap_user_data_t) linux.E {
    var header: CapHeader = .{};
    return linux.errno(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(data)));
}

fn writeCapabilities(data: *const [2]linux.cap_user_data_t) linux.E {
    var header: CapHeader = .{};
    return linux.errno(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(data)));
}

fn capabilityCount(out: *u32) linux.E {
    var capability: u32 = 0;
    while (capability <= 64) : (capability += 1) {
        const present = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), capability, 0, 0, 0);
        const result = linux.errno(present);
        if (result == .INVAL and capability != 0) {
            out.* = capability;
            return .SUCCESS;
        }
        if (result != .SUCCESS) return result;
        if (capability == 64) return .RANGE;
        if (present > 1) return .INVAL;
    }
    return .RANGE;
}

fn restrictReferencePrivileges() linux.E {
    var count: u32 = 0;
    const counted = capabilityCount(&count);
    if (counted != .SUCCESS) return counted;
    const ambient = linux.errno(linux.prctl(
        @intFromEnum(linux.PR.CAP_AMBIENT),
        4,
        0,
        0,
        0,
    ));
    if (ambient != .SUCCESS) return ambient;
    for (0..count) |index| {
        const capability: u32 = @intCast(index);
        if (allowedCapability(capability)) continue;
        const bounded = linux.errno(linux.prctl(
            @intFromEnum(linux.PR.CAPBSET_DROP),
            capability,
            0,
            0,
            0,
        ));
        if (bounded != .SUCCESS) return bounded;
    }
    const restricted = linux.errno(linux.prctl(
        @intFromEnum(linux.PR.SET_NO_NEW_PRIVS),
        1,
        0,
        0,
        0,
    ));
    if (restricted != .SUCCESS) return restricted;
    var data: [2]linux.cap_user_data_t = undefined;
    const captured = readCapabilities(&data);
    if (captured != .SUCCESS) return captured;
    restrictCapabilityData(&data);
    const removed = writeCapabilities(&data);
    if (removed != .SUCCESS) return removed;
    const checked_caps = readCapabilities(&data);
    if (checked_caps != .SUCCESS) return checked_caps;
    for (data, 0..) |entry, word| {
        if (((entry.effective | entry.permitted | entry.inheritable) &
            ~allowedCapabilityMask(word)) != 0) return .PERM;
    }
    if (linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0) != 1)
        return .PERM;
    for (0..count) |index| {
        const capability: u32 = @intCast(index);
        const bounded = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), capability, 0, 0, 0);
        if (linux.errno(bounded) != .SUCCESS or bounded > 1 or
            (!allowedCapability(capability) and bounded != 0)) return .PERM;
        if (linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), 1, capability, 0, 0) != 0)
            return .PERM;
    }
    var policy: BpfProgram = .{ .len = filter.len, .filter = &filter };
    const installed = linux.errno(linux.syscall3(
        .seccomp,
        1,
        0,
        @intFromPtr(&policy),
    ));
    if (installed != .SUCCESS) return installed;
    return .SUCCESS;
}

fn generateFilter() [6 + deny_syscalls.len * 3 + 3 + 5 + 1]Bpf {
    const arch: u32 = switch (@import("builtin").cpu.arch) {
        .x86_64 => 0xc000003e,
        .aarch64 => 0xc00000b7,
        else => @compileError("reference launcher supports only native amd64 and arm64"),
    };
    var result: [6 + deny_syscalls.len * 3 + 3 + 5 + 1]Bpf = undefined;
    var index: usize = 0;
    result[index] = .{ .code = 0x20, .k = 4 }; // seccomp_data.arch
    index += 1;
    result[index] = .{ .code = 0x15, .jt = 1, .k = arch };
    index += 1;
    result[index] = .{ .code = 0x06, .k = 0x80000000 };
    index += 1;
    result[index] = .{ .code = 0x20, .k = 0 };
    index += 1;
    result[index] = .{ .code = 0x35, .jf = 1, .k = 0x40000000 };
    index += 1;
    result[index] = .{ .code = 0x06, .k = 0x80000000 }; // refuse x32 syscall aliases
    index += 1;
    inline for (deny_syscalls) |sys| {
        result[index] = .{ .code = 0x20, .k = 0 }; // syscall number
        index += 1;
        result[index] = .{ .code = 0x15, .jt = 0, .jf = 1, .k = @intFromEnum(sys) };
        index += 1;
        result[index] = .{ .code = 0x06, .k = 0x00050001 }; // EPERM
        index += 1;
    }
    result[index] = .{ .code = 0x20, .k = 0 };
    index += 1;
    result[index] = .{ .code = 0x15, .jf = 1, .k = @intFromEnum(linux.SYS.clone3) };
    index += 1;
    result[index] = .{ .code = 0x06, .k = 0x00050026 }; // ENOSYS, libc may retry clone
    index += 1;
    result[index] = .{ .code = 0x20, .k = 0 };
    index += 1;
    result[index] = .{ .code = 0x15, .jf = 3, .k = @intFromEnum(linux.SYS.clone) };
    index += 1;
    result[index] = .{ .code = 0x20, .k = 16 }; // clone flags, first syscall argument
    index += 1;
    result[index] = .{ .code = 0x45, .jf = 1, .k = linux.CLONE.NEWUSER | linux.CLONE.NEWNS | linux.CLONE.NEWPID };
    index += 1;
    result[index] = .{ .code = 0x06, .k = 0x00050001 };
    index += 1;
    result[index] = .{ .code = 0x06, .k = 0x7fff0000 }; // allow ordinary syscalls
    return result;
}

fn evaluateFilter(architecture: u32, number: u32, flags: u32) !u32 {
    var pc: usize = 0;
    var value: u32 = 0;
    while (pc < filter.len) {
        const instruction = filter[pc];
        switch (instruction.code) {
            0x20 => value = switch (instruction.k) {
                0 => number,
                4 => architecture,
                16 => flags,
                else => return error.UnexpectedFilterInstruction,
            },
            0x15 => pc += if (value == instruction.k) instruction.jt else instruction.jf,
            0x35 => pc += if (value >= instruction.k) instruction.jt else instruction.jf,
            0x45 => pc += if (value & instruction.k != 0) instruction.jt else instruction.jf,
            0x06 => return instruction.k,
            else => return error.UnexpectedFilterInstruction,
        }
        pc += 1;
    }
    return error.UnterminatedFilter;
}

fn childMain(input: Child) noreturn {
    var child = input;
    _ = linux.close(child.status_pipe[0]);
    _ = linux.close(child.control_pipe[1]);
    const status = child.status_pipe[1];
    if (linux.getpid() != 1) fail(status, 1, .INVAL);
    verifyStandardStreams() catch fail(status, 1, .BADF);
    must(linux.prctl(
        @intFromEnum(linux.PR.SET_PDEATHSIG),
        @intFromEnum(linux.SIG.KILL),
        0,
        0,
        0,
    ), status, 2);
    var probe: [1]u8 = undefined;
    const alive = linux.read(child.control_pipe[0], &probe, probe.len);
    if (alive != 0 and linux.errno(alive) != .AGAIN)
        fail(status, 2, .CHILD);
    _ = linux.close(child.control_pipe[0]);
    must(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0), status, 3);
    if (child.options.archive) |path| {
        const reopened = openPinned(path, false) catch fail(status, 3, .STALE);
        if (!same(reopened.metadata, child.archive.?.metadata))
            fail(status, 3, .STALE);
        child.archive = reopened;
    }
    // Reopen the pinned root in the new mount namespace, then leave no outside cwd.
    const root = openPinned(child.options.root, true) catch fail(status, 4, .STALE);
    if (!same(root.metadata, child.root.metadata)) fail(status, 4, .STALE);
    must(linux.fchdir(root.fd), status, 4);
    must(linux.chroot("."), status, 4);
    must(linux.chdir("/"), status, 4);
    _ = linux.close(root.fd);
    if (child.options.profile != .none) {
        verifyInstalledBinding(script_bindings[@intFromEnum(child.options.profile) - 1]) catch
            fail(status, 10, .STALE);
    }
    const archive_setup = mountArchive(child);
    if (archive_setup != .SUCCESS) fail(status, 5, archive_setup);
    const proc_setup = mountProc(child);
    if (proc_setup != .SUCCESS) fail(status, 6, proc_setup);
    const dropped = restrictReferencePrivileges();
    if (dropped != .SUCCESS) fail(status, 7, dropped);
    verifyStandardStreams() catch fail(status, 8, .BADF);
    must(linux.syscall3(.close_range, 3, std.math.maxInt(u32), close_range_cloexec), status, 8);

    const common = [_]?[*:0]const u8{
        "dpkg", "--root=/", "--force-not-root", "--force-bad-path", "--force-confold",
    };
    const selector: ?[*:0]const u8 = if (child.options.selector) |value| value.ptr else null;
    const extra: [*:null]const ?[*:0]const u8 = switch (child.options.verb) {
        .probe_unpack => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--no-act", "--unpack", archive_target, null },
        .unpack => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--unpack", archive_target, null },
        .probe_configure => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--no-act", "--configure", selector, null },
        .configure => &.{ common[0], common[1], common[2], common[3], common[4], "--no-triggers", "--configure", selector, null },
    };
    must(linux.syscall5(
        .execveat,
        @bitCast(@as(isize, child.dpkg.fd)),
        @intFromPtr(@as([*:0]const u8, "")),
        @intFromPtr(extra),
        @intFromPtr(environment),
        linux.AT.EMPTY_PATH,
    ), status, 9);
    fail(status, 9, .IO);
}

fn run(allocator: std.mem.Allocator, options: Options) !u8 {
    const root = try protectedRoot(options.root);
    defer _ = linux.close(root.fd);
    const expected_dpkg = dpkg_digests[
        if (std.mem.eql(u8, options.architecture, "amd64"))
            @as(usize, 0)
        else
            @as(usize, 1)
    ];
    const dpkg = try openVerified(
        options.dpkg,
        std.crypto.hash.sha2.Sha256,
        expected_dpkg,
        null,
        8 * 1024 * 1024,
    );
    defer _ = linux.close(dpkg.fd);
    const archive: ?Pinned = if (options.archive) |path|
        try openVerified(
            path,
            std.crypto.hash.sha2.Sha512,
            options.archive_sha512.?,
            options.archive_size.?,
            options.archive_size.?,
        )
    else
        null;
    defer {
        if (archive) |value| _ = linux.close(value.fd);
    }
    const root_proc = try std.fmt.allocPrintSentinel(allocator, "{s}/proc", .{options.root}, 0);
    const proc = try openPinned(root_proc, true);
    defer _ = linux.close(proc.fd);
    if (proc.metadata.uid != 0 or proc.metadata.gid != 0 or proc.metadata.mode != 0o40755)
        return error.InvalidProcMountpoint;
    if (proc.metadata.dev_major != root.metadata.dev_major or
        proc.metadata.dev_minor != root.metadata.dev_minor) return error.InvalidProcMountpoint;
    try emptyDirectory(root_proc);
    const root_target = try std.fmt.allocPrintSentinel(allocator, "{s}{s}", .{ options.root, archive_target }, 0);
    const target = try openPinned(root_target, false);
    defer _ = linux.close(target.fd);
    if (target.metadata.uid != 0 or target.metadata.gid != 0 or
        target.metadata.mode != 0o100600 or target.metadata.size != 0 or
        target.metadata.nlink != 1 or target.metadata.dev_major != root.metadata.dev_major or
        target.metadata.dev_minor != root.metadata.dev_minor) return error.InvalidArchiveMountpoint;
    if (options.profile != .none) {
        const binding = script_bindings[@intFromEnum(options.profile) - 1];
        const script_path = try std.fmt.allocPrintSentinel(
            allocator,
            "{s}/var/lib/dpkg/info/{s}.postinst",
            .{ options.root, binding.name },
            0,
        );
        const script = try openVerified(
            script_path,
            std.crypto.hash.sha2.Sha256,
            binding.digest,
            binding.size,
            binding.size,
        );
        _ = linux.close(script.fd);
    }
    const boot_id = if (options.profile == .systemd) try readBootId() else null;

    var fds: [2]i32 = undefined;
    _ = try checked(linux.pipe2(&fds, .{ .CLOEXEC = true }));
    defer {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
    }
    var control: [2]i32 = undefined;
    _ = try checked(linux.pipe2(&control, .{ .CLOEXEC = true, .NONBLOCK = true }));
    defer {
        _ = linux.close(control[0]);
        _ = linux.close(control[1]);
    }
    const child: Child = .{
        .options = options,
        .root = root,
        .proc_mountpoint = proc,
        .archive_mountpoint = target,
        .dpkg = dpkg,
        .archive = archive,
        .boot_id = boot_id,
        .status_pipe = fds,
        .control_pipe = control,
    };
    const cloned = linux.clone2(
        linux.CLONE.NEWNS | linux.CLONE.NEWPID | @intFromEnum(linux.SIG.CHLD),
        0,
    );
    _ = try checked(cloned);
    if (cloned == 0) childMain(child);
    const pid: i32 = @intCast(cloned);
    _ = linux.close(fds[1]);
    fds[1] = -1;
    _ = linux.close(control[0]);
    control[0] = -1;
    var status: u32 = 0;
    while (true) {
        const waited = linux.syscall4(
            .wait4,
            @bitCast(@as(isize, pid)),
            @intFromPtr(&status),
            0,
            0,
        );
        if (linux.errno(waited) == .INTR) continue;
        _ = try checked(waited);
        break;
    }
    var failure: [5]u8 = undefined;
    const size = try checked(linux.read(fds[0], &failure, failure.len));
    if (size != 0) {
        if (size != failure.len) return error.InvalidSetupEvidence;
        std.log.err("reference namespace setup failed at stage {d}, errno {d}", .{
            failure[0], std.mem.readInt(u32, failure[1..5], .little),
        });
        return error.ReferenceSetupFailed;
    }
    if (!linux.W.IFEXITED(status)) return error.ReferenceProcessSignaled;
    return linux.W.EXITSTATUS(status);
}

test "reference capability transition clears ambient and high bounding privileges" {
    try capabilityTransitionProbe();
}

test "reference launcher rejects wider profiles and unsafe operation shapes" {
    const base: Options = .{
        .root = "/root/proof/root",
        .dpkg = "/root/proof/dpkg",
        .architecture = "amd64",
        .profile = .none,
        .verb = .configure,
        .selector = "demo:amd64",
    };
    try validateOptions(base);
    var changed = base;
    changed.profile = .systemd;
    try std.testing.expectError(error.InvalidProfile, validateOptions(changed));
    changed.selector = "systemd:amd64";
    try validateOptions(changed);
    changed.selector = "udev:amd64";
    try std.testing.expectError(error.InvalidProfile, validateOptions(changed));
    changed.profile = .udev;
    try validateOptions(changed);
    changed.profile = .sudo;
    changed.selector = "sudo:amd64";
    try validateOptions(changed);
    changed.profile = .none;
    try std.testing.expectError(error.InvalidProfile, validateOptions(changed));
    changed.verb = .probe_configure;
    try validateOptions(changed);
    changed.verb = .configure;
    changed.profile = .sudo;
    changed.architecture = "arm64";
    try std.testing.expectError(error.InvalidProfile, validateOptions(changed));
    changed = base;
    changed.selector = "--pending";
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
    changed = base;
    changed.verb = .unpack;
    changed.archive = "/root/proof/archive";
    changed.archive_sha512 = "0" ** 128;
    changed.archive_size = 1;
    try validateOptions(changed);
    changed.archive_sha512 = "G" ** 128;
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
    changed = base;
    try std.testing.expect(std.meta.stringToEnum(Verb, "configure_batch") == null);
    try std.testing.expect(std.meta.stringToEnum(Verb, "triggers") == null);
    changed = base;
    changed.root = "/root/../host";
    try std.testing.expectError(error.InvalidArguments, validateOptions(changed));
}

test "reference syscall filter denies namespace changes and permits ordinary forks" {
    const arch: u32 = switch (@import("builtin").cpu.arch) {
        .x86_64 => 0xc000003e,
        .aarch64 => 0xc00000b7,
        else => unreachable,
    };
    try std.testing.expectEqual(@as(u32, 0x80000000), try evaluateFilter(0, @intFromEnum(linux.SYS.getpid), 0));
    try std.testing.expectEqual(@as(u32, 0x80000000), try evaluateFilter(arch, 0x40000000, 0));
    try std.testing.expectEqual(@as(u32, 0x7fff0000), try evaluateFilter(arch, @intFromEnum(linux.SYS.getpid), 0));
    inline for (deny_syscalls) |number| {
        try std.testing.expectEqual(@as(u32, 0x00050001), try evaluateFilter(arch, @intFromEnum(number), 0));
    }
    try std.testing.expectEqual(@as(u32, 0x00050001), try evaluateFilter(arch, @intFromEnum(linux.SYS.chroot), 0));
    try std.testing.expectEqual(@as(u32, 0x00050026), try evaluateFilter(arch, @intFromEnum(linux.SYS.clone3), 0));
    inline for (.{ linux.CLONE.NEWUSER, linux.CLONE.NEWNS, linux.CLONE.NEWPID }) |flag| {
        try std.testing.expectEqual(@as(u32, 0x00050001), try evaluateFilter(arch, @intFromEnum(linux.SYS.clone), flag));
    }
    try std.testing.expectEqual(@as(u32, 0x7fff0000), try evaluateFilter(arch, @intFromEnum(linux.SYS.clone), 0));
}

test "reference capability transition retains only filesystem and account authority" {
    const expected = linux.CAP.TO_MASK(linux.CAP.CHOWN) |
        linux.CAP.TO_MASK(linux.CAP.DAC_OVERRIDE) |
        linux.CAP.TO_MASK(linux.CAP.FOWNER) |
        linux.CAP.TO_MASK(linux.CAP.FSETID) |
        linux.CAP.TO_MASK(linux.CAP.SETGID) |
        linux.CAP.TO_MASK(linux.CAP.SETUID) |
        linux.CAP.TO_MASK(linux.CAP.SETFCAP);
    try std.testing.expectEqual(expected, allowedCapabilityMask(0));
    try std.testing.expectEqual(@as(u32, 0), allowedCapabilityMask(1));
    inline for (.{ linux.CAP.SYS_CHROOT, linux.CAP.SYS_ADMIN, linux.CAP.SYS_MODULE, linux.CAP.MKNOD }) |capability|
        try std.testing.expect(!allowedCapability(capability));
    try std.testing.expect(!allowedCapability(39)); // CAP_BPF, in the second capset word
    try std.testing.expect(!allowedCapability(40)); // CAP_CHECKPOINT_RESTORE

    var data: [2]linux.cap_user_data_t = .{
        .{ .effective = 0xffffffff, .permitted = 0xffffffff, .inheritable = 0xffffffff },
        .{ .effective = 0xffffffff, .permitted = 0xffffffff, .inheritable = 0xffffffff },
    };
    restrictCapabilityData(&data);
    try std.testing.expectEqual(expected, data[0].effective);
    try std.testing.expectEqual(expected, data[0].permitted);
    try std.testing.expectEqual(expected, data[0].inheritable);
    try std.testing.expectEqual(@as(u32, 0), data[1].effective);
    try std.testing.expectEqual(@as(u32, 0), data[1].permitted);
    try std.testing.expectEqual(@as(u32, 0), data[1].inheritable);
}

fn capabilityTransitionProbe() !void {
    const child = linux.fork();
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(child));
    if (child == 0) {
        const isolated = linux.errno(linux.syscall1(.unshare, linux.CLONE.NEWUSER));
        if (isolated == .PERM or isolated == .NOSYS) linux.exit(77);
        if (isolated != .SUCCESS) linux.exit(1);
        var data: [2]linux.cap_user_data_t = undefined;
        if (readCapabilities(&data) != .SUCCESS) linux.exit(2);
        if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), linux.CAP.SYS_MODULE, 0, 0, 0) == 1 and
            data[0].effective & linux.CAP.TO_MASK(linux.CAP.SYS_MODULE) == 0) linux.exit(12);
        if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), 39, 0, 0, 0) == 1 and
            data[1].effective & (@as(u32, 1) << 7) == 0) linux.exit(13);
        data[0].inheritable |= linux.CAP.TO_MASK(linux.CAP.CHOWN);
        if (writeCapabilities(&data) != .SUCCESS) linux.exit(3);
        if (linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), 2, linux.CAP.CHOWN, 0, 0) != 0)
            linux.exit(4);
        if (restrictReferencePrivileges() != .SUCCESS) linux.exit(5);
        if (readCapabilities(&data) != .SUCCESS) linux.exit(6);
        if (data[1].effective != 0 or data[1].permitted != 0 or data[1].inheritable != 0)
            linux.exit(7);
        inline for (.{
            linux.CAP.SYS_MODULE, linux.CAP.SYS_CHROOT, linux.CAP.SYS_ADMIN,
            linux.CAP.MKNOD,      linux.CAP.SETPCAP,
        }) |capability| {
            if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), capability, 0, 0, 0) != 0)
                linux.exit(8);
        }
        inline for (.{ @as(u32, 39), @as(u32, 40) }) |capability| {
            if (linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), capability, 0, 0, 0) != 0)
                linux.exit(9);
        }
        if (linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), 1, linux.CAP.CHOWN, 0, 0) != 0)
            linux.exit(10);
        if (linux.errno(linux.syscall0(.init_module)) != .PERM) linux.exit(11);
        linux.exit(0);
    }
    var status: u32 = 0;
    const waited = linux.syscall4(
        .wait4,
        @bitCast(@as(isize, @intCast(child))),
        @intFromPtr(&status),
        0,
        0,
    );
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(waited));
    try std.testing.expect(linux.W.IFEXITED(status));
    if (linux.W.EXITSTATUS(status) == 77) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

test "reference module syscalls are denied by the installed filter" {
    const child = linux.fork();
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(child));
    if (child == 0) {
        const no_new_privileges = linux.errno(linux.prctl(
            @intFromEnum(linux.PR.SET_NO_NEW_PRIVS),
            1,
            0,
            0,
            0,
        ));
        if (no_new_privileges != .SUCCESS) linux.exit(1);
        var policy: BpfProgram = .{ .len = filter.len, .filter = &filter };
        const installed = linux.errno(linux.syscall3(.seccomp, 1, 0, @intFromPtr(&policy)));
        if (installed != .SUCCESS) linux.exit(2);
        inline for (.{ linux.SYS.init_module, linux.SYS.finit_module, linux.SYS.delete_module }) |call| {
            if (linux.errno(linux.syscall0(call)) != .PERM) linux.exit(3);
        }
        linux.exit(0);
    }
    var status: u32 = 0;
    const waited = linux.syscall4(
        .wait4,
        @bitCast(@as(isize, @intCast(child))),
        @intFromPtr(&status),
        0,
        0,
    );
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(waited));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
}

test "reference standard streams refuse directory-backed stdin and readable host output" {
    const directory = linux.open("/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(directory));
    defer _ = linux.close(@intCast(directory));
    const info = try metadata(@intCast(directory));
    const directory_flags = try checked(linux.fcntl(@intCast(directory), linux.F.GETFL, 0));
    try std.testing.expectEqual(@as(u32, 0o040000), info.mode & 0o170000);
    try std.testing.expectError(error.InvalidStandardStream, verifyStandardStream(0, @intCast(directory)));
    try std.testing.expect(same(info, try metadata(@intCast(directory))));
    try std.testing.expect(!allowedStandardStream(0, info, directory_flags));
    try std.testing.expect(!allowedStandardStream(1, info, directory_flags));

    var input = std.mem.zeroes(linux.Statx);
    input.mode = 0o020666;
    input.rdev_major = 1;
    input.rdev_minor = 3;
    try std.testing.expect(allowedStandardStream(0, input, 0));
    try std.testing.expect(!allowedStandardStream(0, input, 1));
    var output = std.mem.zeroes(linux.Statx);
    output.mode = 0o100600;
    output.nlink = 1;
    const append: usize = 1 << @bitOffsetOf(linux.O, "APPEND");
    try std.testing.expect(allowedStandardStream(1, output, 1 | append));
    try std.testing.expect(allowedStandardStream(2, output, 1 | append));
    try std.testing.expect(!allowedStandardStream(1, output, 2 | append));
    try std.testing.expect(!allowedStandardStream(2, output, 1));
    output.mode = 0o100622;
    try std.testing.expect(!allowedStandardStream(1, output, 1 | append));
}

test "reference proc profile is bound to the installed dpkg status version" {
    const binding = script_bindings[0];
    const valid =
        "Package: other\nVersion: 1\nArchitecture: amd64\n" ++
        "Status: install ok installed\n\n" ++
        "Package: systemd\nVersion: 261.2-1ubuntu2\nArchitecture: amd64\n" ++
        "Status: install ok unpacked\n\n";
    try std.testing.expect(bindingStatusMatches(valid, binding));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nVersion: 261.2-1ubuntu3\nArchitecture: amd64\n" ++
            "Status: install ok unpacked\n\n",
        binding,
    ));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nVersion: 261.2-1ubuntu2\nArchitecture: arm64\n" ++
            "Status: install ok unpacked\n\n",
        binding,
    ));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nVersion: 261.2-1ubuntu2\nArchitecture: amd64\n" ++
            "Status: install ok triggers-pending\n\n",
        binding,
    ));
    try std.testing.expect(!bindingStatusMatches(valid ++
        "Package: systemd\nVersion: 261.2-1ubuntu2\nArchitecture: amd64\n" ++
        "Status: install ok unpacked\n\n", binding));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nVersion: 261.2-1ubuntu2\nVersion: 261.2-1ubuntu2\n" ++
            "Architecture: amd64\nStatus: install ok unpacked\n\n",
        binding,
    ));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nversion: 261.2-1ubuntu3\nVersion: 261.2-1ubuntu2\n" ++
            "Architecture: amd64\nStatus: install ok unpacked\n\n",
        binding,
    ));
    try std.testing.expect(!bindingStatusMatches(
        "Package: systemd\nVersion: 261.2-1ubuntu2\nArchitecture: amd64\n" ++
            "Status: install ok unpacked\n continued\n\n",
        binding,
    ));
}
