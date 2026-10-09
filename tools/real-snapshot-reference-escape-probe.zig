//! Static confinement probe packaged as a reference proof `preinst`.
//!
//! `install` (dpkg's preinst argument) runs inside the protected launcher as a
//! child of pinned dpkg, which is PID 1 of the reference namespaces. It reports
//! every escape attempt and starts a detached descendant that must be killed by
//! namespace teardown. `control` runs the same checks unconfined, without the
//! descendant, to show that each check detects authority when it is present.
//! Every attempted operation targets a missing path, an invalid argument or the
//! probe's own process, so an unconfined control run changes no host state.
//!
//! Installed as a profile root's `/bin/sh`, the probe is also the interpreter
//! the kernel starts for a digest-bound signed `systemd`, `udev` or `sudo`
//! postinst (`/bin/sh SCRIPT configure [VERSION]`). It never interprets the
//! script; it reports the exact proc view the launcher gave that profile
//! instead of `no-proc-view`, then runs the same escape checks.
const std = @import("std");
const linux = std.os.linux;
const network_probe = @import("network_probe");

const CapHeader = extern struct { version: u32 = 0x20080522, pid: i32 = 0 };
const allowed_caps = [_]u32{
    linux.CAP.CHOWN,  linux.CAP.DAC_OVERRIDE, linux.CAP.FOWNER,  linux.CAP.FSETID,
    linux.CAP.SETGID, linux.CAP.SETUID,       linux.CAP.SETFCAP,
};
const missing: [*:0]const u8 = "/.debz-escape-probe-missing";
const missing_child: [*:0]const u8 = "/.debz-escape-probe-missing/node";
const descendant_marker: [*:0]const u8 = "/.debz-escape-probe-descendant";
const archive_mountpoint: [*:0]const u8 = "/.debz-reference-archive";
// The 64-bit `struct statfs` shared by x86_64 and the asm-generic aarch64 ABI.
const Statfs = extern struct {
    type: i64,
    bsize: i64,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    fsid: [2]i32,
    namelen: i64,
    frsize: i64,
    flags: i64,
    spare: [4]i64,
};
const st_rdonly_nosuid_nodev_noexec: i64 = 1 | 2 | 4 | 8;
const statx_attr_mount_root: u64 = 0x2000;
const proc_super_magic: i64 = 0x9fa0;
const tmpfs_magic: i64 = 0x01021994;
const Profile = enum { systemd, udev, sudo };

var failures: u32 = 0;
var mountinfo_buffer: [1 << 18]u8 = undefined;

fn report(name: []const u8, ok: bool, comptime detail: []const u8, args: anytype) void {
    var bytes: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&bytes, "debz-escape-probe: {s} {s} " ++ detail ++ "\n", .{
        name, if (ok) "ok" else "FAIL",
    } ++ args) catch "debz-escape-probe: report overflow FAIL\n";
    if (!ok) failures += 1;
    _ = linux.write(1, line.ptr, line.len);
}

fn info(name: []const u8, comptime detail: []const u8, args: anytype) void {
    var bytes: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&bytes, "debz-escape-probe: {s} info " ++ detail ++ "\n", .{name} ++ args) catch return;
    _ = linux.write(1, line.ptr, line.len);
}

fn errno(result: usize) linux.E {
    return linux.errno(result);
}

fn allowed(capability: u32) bool {
    for (allowed_caps) |value| if (value == capability) return true;
    return false;
}

fn allowedMask(word: usize) u32 {
    var mask: u32 = 0;
    for (allowed_caps) |capability| {
        if (capability / 32 == word) mask |= @as(u32, 1) << @intCast(capability % 32);
    }
    return mask;
}

fn denied(name: []const u8, result: usize, expected: linux.E) void {
    const observed = errno(result);
    report(name, observed == expected, "errno={s}", .{@tagName(observed)});
}

fn deniedDescriptor(name: []const u8, result: usize, expected: linux.E) void {
    // A descriptor obtained by an unconfined control run must not stay open.
    if (errno(result) == .SUCCESS) _ = linux.close(@intCast(result));
    denied(name, result, expected);
}

fn namespaceClone(name: []const u8, flag: u32) void {
    const result = linux.clone2(flag | @intFromEnum(linux.SIG.CHLD), 0);
    if (errno(result) == .SUCCESS and result == 0) linux.exit(0);
    if (errno(result) == .SUCCESS) {
        var status: u32 = 0;
        _ = linux.waitpid(@intCast(result), &status, 0);
    }
    report(name, errno(result) == .PERM, "errno={s}", .{@tagName(errno(result))});
}

fn checkNamespaces() void {
    const parent = linux.getppid();
    report("pid-namespace", linux.getpid() != 1 and parent == 1, "pid={d} ppid={d}", .{ linux.getpid(), parent });
}

fn checkProc() void {
    const status = linux.open("/proc/self/status", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (errno(status) == .SUCCESS) _ = linux.close(@intCast(status));
    var entries: usize = 0;
    const directory = linux.open("/proc", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (errno(directory) == .SUCCESS) {
        defer _ = linux.close(@intCast(directory));
        var bytes: [4096]u8 = undefined;
        while (true) {
            const count = linux.getdents64(@intCast(directory), &bytes, bytes.len);
            if (errno(count) != .SUCCESS or count == 0) break;
            var offset: usize = 0;
            while (offset + 19 < count) {
                const size = std.mem.readInt(u16, bytes[offset + 16 ..][0..2], .little);
                if (size < 20 or size > count - offset) break;
                const name = std.mem.sliceTo(bytes[offset + 19 .. offset + size], 0);
                if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) entries += 1;
                offset += size;
            }
        }
    }
    report("no-proc-view", errno(status) == .NOENT and entries == 0, "self_status={s} proc_entries={d}", .{
        @tagName(errno(status)), entries,
    });
}

const Identity = struct { status: linux.E, value: [2]u64 = .{ 0, 0 } };

fn statIdentity(path: [*:0]const u8, flags: u32) Identity {
    var value: linux.Statx = undefined;
    const status = errno(linux.statx(linux.AT.FDCWD, path, flags, .BASIC_STATS, &value));
    if (status != .SUCCESS) return .{ .status = status };
    return .{ .status = status, .value = .{ (@as(u64, value.dev_major) << 32) | value.dev_minor, value.ino } };
}

fn identity(path: [*:0]const u8) ?[2]u64 {
    const result = statIdentity(path, linux.AT.SYMLINK_NOFOLLOW);
    return if (result.status == .SUCCESS) result.value else null;
}

fn checkRootPath() void {
    const root = identity("/");
    const parent = identity("/..");
    const deep = identity("/../../../..");
    report("path-escape", root != null and parent != null and deep != null and
        std.mem.eql(u64, &root.?, &parent.?) and std.mem.eql(u64, &root.?, &deep.?), "root_is_parent={}", .{
        root != null and parent != null and std.mem.eql(u64, &root.?, &parent.?),
    });
    denied("re-chroot-denied", linux.chroot(missing), .PERM);
    denied("pivot-root-denied", linux.pivot_root(missing, missing), .PERM);
    deniedDescriptor("handle-escape-denied", linux.syscall3(
        .open_by_handle_at,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        0,
        0,
    ), .PERM);
}

fn checkDescriptors() void {
    var open: usize = 0;
    var directories: usize = 0;
    var first: i32 = -1;
    var fd: i32 = 3;
    while (fd < 4096) : (fd += 1) {
        if (errno(linux.fcntl(fd, linux.F.GETFD, 0)) != .SUCCESS) continue;
        open += 1;
        if (first < 0) first = fd;
        var value: linux.Statx = undefined;
        if (errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &value)) == .SUCCESS and
            value.mode & 0o170000 == 0o040000) directories += 1;
    }
    report("inherited-descriptors", open == 0, "open={d} directories={d} first={d}", .{ open, directories, first });
}

fn checkPrivileges() void {
    const no_new_privileges = linux.prctl(@intFromEnum(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0);
    report("no-new-privileges", no_new_privileges == 1, "value={d}", .{no_new_privileges});
    const seccomp = linux.prctl(@intFromEnum(linux.PR.GET_SECCOMP), 0, 0, 0, 0);
    report("seccomp-filter", seccomp == 2, "mode={d}", .{seccomp});

    var header: CapHeader = .{};
    var data: [2]linux.cap_user_data_t = undefined;
    const captured = errno(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&data)));
    var extra_sets = captured != .SUCCESS;
    if (!extra_sets) {
        for (data, 0..) |entry, word| {
            if (((entry.effective | entry.permitted | entry.inheritable) & ~allowedMask(word)) != 0)
                extra_sets = true;
        }
    }
    var extra_bounding: u32 = 0;
    var ambient: u32 = 0;
    var count: u32 = 0;
    while (count < 64) : (count += 1) {
        const bounded = linux.prctl(@intFromEnum(linux.PR.CAPBSET_READ), count, 0, 0, 0);
        if (errno(bounded) == .INVAL) break;
        if (bounded == 1 and !allowed(count)) extra_bounding += 1;
        if (linux.prctl(@intFromEnum(linux.PR.CAP_AMBIENT), 1, count, 0, 0) == 1) ambient += 1;
    }
    report("capabilities", !extra_sets and extra_bounding == 0 and ambient == 0 and count > 0, "effective0=0x{x} permitted0=0x{x} word1=0x{x} extra_bounding={d} ambient={d} known={d}", .{
        data[0].effective, data[0].permitted, data[1].effective | data[1].permitted,
        extra_bounding,    ambient,           count,
    });
}

fn checkKernelAuthority() void {
    denied("mount-denied", linux.mount("none", missing, "tmpfs", 0, 0), .PERM);
    denied("umount-denied", linux.umount2(missing, 0), .PERM);
    deniedDescriptor("move-mount-denied", linux.syscall3(
        .open_tree,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(missing),
        0,
    ), .PERM);
    denied("device-node-denied", linux.mknodat(linux.AT.FDCWD, missing_child, 0o060600, 0x0800), .PERM);
    denied("module-load-denied", linux.syscall3(.init_module, 0, 0, 0), .PERM);
    denied("module-file-denied", linux.syscall3(.finit_module, @bitCast(@as(isize, -1)), 0, 0), .PERM);
    denied("module-remove-denied", linux.syscall2(.delete_module, 0, 0), .PERM);
    var name: [65]u8 = @splat('x');
    denied("host-admin-denied", linux.syscall2(.sethostname, @intFromPtr(&name), name.len), .PERM);
    denied("host-time-denied", linux.syscall2(.settimeofday, 0, 0), .PERM);
    deniedDescriptor("raw-network-denied", linux.socket(linux.AF.PACKET, linux.SOCK.RAW | linux.SOCK.CLOEXEC, 0), .PERM);
}

fn checkNamespaceChanges() void {
    denied("unshare-denied", linux.unshare(linux.CLONE.NEWNS), .PERM);
    denied("setns-denied", linux.setns(-1, 0), .PERM);
    namespaceClone("clone-user-denied", linux.CLONE.NEWUSER);
    namespaceClone("clone-network-denied", linux.CLONE.NEWNET);
    namespaceClone("clone-mount-denied", linux.CLONE.NEWNS);
    const clone3 = errno(linux.syscall2(.clone3, 0, 0));
    report("clone3-denied", clone3 == .NOSYS, "errno={s}", .{@tagName(clone3)});
}

fn networkInformation() void {
    const socket = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    info("network-socket", "inet_socket={s}", .{@tagName(errno(socket))});
    if (errno(socket) == .SUCCESS) _ = linux.close(@intCast(socket));
    inline for (.{
        "/proc/1/net/dev",
        "/proc/self/net/route",
        "/sys/class/net",
    }) |path| {
        const opened = linux.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
        info("network-view", "path={s} open={s}", .{ path, @tagName(errno(opened)) });
        if (errno(opened) == .SUCCESS) _ = linux.close(@intCast(opened));
    }
}

fn checkArchiveMount() void {
    // The launcher replaces the root's empty mountpoint with a read-only,
    // nosuid, nodev, noexec bind of the pinned archive for this operation.
    var value: linux.Statx = undefined;
    const stat_status = errno(linux.statx(linux.AT.FDCWD, archive_mountpoint, linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &value));
    const size: u64 = if (stat_status == .SUCCESS) value.size else 0;
    const regular = stat_status == .SUCCESS and value.mode & 0o170000 == 0o100000;
    // Zig 0.16's packed STATX_ATTR puts MOUNT_ROOT at bit 10, not the kernel's 0x2000.
    const mount_root = stat_status == .SUCCESS and
        @as(u64, @bitCast(value.attributes_mask)) & statx_attr_mount_root != 0 and
        @as(u64, @bitCast(value.attributes)) & statx_attr_mount_root != 0;
    const writer = linux.open(archive_mountpoint, .{ .ACCMODE = .WRONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (errno(writer) == .SUCCESS) _ = linux.close(@intCast(writer));
    var flags: i64 = 0;
    const reader = linux.open(archive_mountpoint, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (errno(reader) == .SUCCESS) {
        var filesystem: Statfs = undefined;
        if (errno(linux.syscall2(.fstatfs, reader, @intFromPtr(&filesystem))) == .SUCCESS) flags = filesystem.flags;
        _ = linux.close(@intCast(reader));
    }
    report("archive-mount", regular and size > 0 and mount_root and errno(writer) == .ROFS and
        flags & st_rdonly_nosuid_nodev_noexec == st_rdonly_nosuid_nodev_noexec, "size={d} mount_root={} write={s} flags=0x{x}", .{
        size, mount_root, @tagName(errno(writer)), flags,
    });
}

fn statfsFlags(path: [*:0]const u8, magic: i64) ?i64 {
    var filesystem: Statfs = undefined;
    if (errno(linux.syscall2(.statfs, @intFromPtr(path), @intFromPtr(&filesystem))) != .SUCCESS) return null;
    if (filesystem.type != magic) return null;
    return filesystem.flags;
}

fn absent(path: [*:0]const u8) linux.E {
    const result = linux.open(path, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (errno(result) == .SUCCESS) {
        _ = linux.close(@intCast(result));
        return .SUCCESS;
    }
    return errno(result);
}

const Listing = struct { count: usize = 0, numeric: usize = 0, other: usize = 0, has_one: bool = false, matched: usize = 0 };

/// Counts the entries of a directory; `matched` counts the names in `expected`.
fn list(path: [*:0]const u8, expected: []const []const u8) ?Listing {
    const directory = linux.open(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (errno(directory) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(directory));
    var listing: Listing = .{};
    var bytes: [4096]u8 = undefined;
    while (true) {
        const count = linux.getdents64(@intCast(directory), &bytes, bytes.len);
        if (errno(count) != .SUCCESS) return null;
        if (count == 0) break;
        var offset: usize = 0;
        while (offset + 19 < count) {
            const size = std.mem.readInt(u16, bytes[offset + 16 ..][0..2], .little);
            if (size < 20 or size > count - offset) return null;
            const name = std.mem.sliceTo(bytes[offset + 19 .. offset + size], 0);
            offset += size;
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            listing.count += 1;
            var numeric = name.len > 0;
            for (name) |byte| numeric = numeric and std.ascii.isDigit(byte);
            if (numeric) listing.numeric += 1 else listing.other += 1;
            if (std.mem.eql(u8, name, "1")) listing.has_one = true;
            for (expected) |item| {
                if (std.mem.eql(u8, name, item)) listing.matched += 1;
            }
        }
    }
    return listing;
}

/// The super options of the only mount at `/proc` in this process's mountinfo.
fn procSuperOptions(buffer: []u8) ?[]const u8 {
    const file = linux.open("/proc/self/mountinfo", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (errno(file) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(file));
    var length: usize = 0;
    while (length < buffer.len) {
        const got = linux.read(@intCast(file), buffer[length..].ptr, buffer.len - length);
        if (errno(got) != .SUCCESS) return null;
        if (got == 0) break;
        length += got;
    }
    if (length == buffer.len) return null;
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, buffer[0..length], '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ' ');
        var index: usize = 0;
        var mountpoint: []const u8 = "";
        while (fields.next()) |field| : (index += 1) {
            if (index == 4) mountpoint = field;
            if (std.mem.eql(u8, field, "-")) break;
        }
        if (!std.mem.eql(u8, mountpoint, "/proc")) continue;
        const kind = fields.next() orelse return null;
        _ = fields.next() orelse return null;
        const options = fields.next() orelse return null;
        if (found != null or !std.mem.eql(u8, kind, "proc")) return null;
        found = options;
    }
    return found;
}

fn hasOption(options: []const u8, option: []const u8) bool {
    var items = std.mem.splitScalar(u8, options, ',');
    while (items.next()) |item| {
        if (std.mem.eql(u8, item, option)) return true;
    }
    return false;
}

fn checkProcView(profile: Profile) void {
    // Every profile mounts a fresh read-only, nosuid, nodev, noexec procfs of
    // the private PID namespace whose PID 1 (dpkg) shares the chroot.
    const flags = statfsFlags("/proc", proc_super_magic);
    const status = linux.open("/proc/self/status", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (errno(status) == .SUCCESS) _ = linux.close(@intCast(status));
    report("proc-mount", flags != null and flags.? & st_rdonly_nosuid_nodev_noexec == st_rdonly_nosuid_nodev_noexec and
        errno(status) == .SUCCESS, "flags=0x{x} self_status={s}", .{ flags orelse -1, @tagName(errno(status)) });
    // Follow PID 1's root magic link: its target, not the link inode, must be this root.
    const root = identity("/");
    const pid_one_root = statIdentity("/proc/1/root", 0);
    const same_root = root != null and pid_one_root.status == .SUCCESS and std.mem.eql(u64, &root.?, &pid_one_root.value);
    report("proc-root", same_root, "pid1_root_is_root={} pid1_root_stat={s}", .{ same_root, @tagName(pid_one_root.status) });
    const options = procSuperOptions(&mountinfo_buffer);
    const pid_only = profile != .systemd;
    report("proc-hidepid", options != null and hasOption(options.?, "hidepid=invisible") and
        hasOption(options.?, "subset=pid") == pid_only, "options={s}", .{options orelse "missing"});
    const entries = list("/proc", &.{ "self", "thread-self" });
    if (entries) |value| info("proc-entries", "total={d} numeric={d} other={d}", .{ value.count, value.numeric, value.other });
    const read_only = linux.open("/proc/sysrq-trigger", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (errno(read_only) == .SUCCESS) _ = linux.close(@intCast(read_only));
    if (pid_only) {
        // subset=pid: only PID directories and the self links remain.
        const sys = absent("/proc/sys");
        const meminfo = absent("/proc/meminfo");
        report("proc-pid-only", entries != null and entries.?.has_one and entries.?.other == entries.?.matched and
            entries.?.matched == 2 and sys == .NOENT and meminfo == .NOENT and errno(read_only) == .NOENT, "other={d} sys={s} meminfo={s} sysrq={s}", .{
            if (entries) |value| value.other else 0, @tagName(sys), @tagName(meminfo), @tagName(errno(read_only)),
        });
        return;
    }
    // systemd: the full PID view, with /proc/sys replaced by a read-only tmpfs
    // that holds only the host boot ID.
    report("proc-read-only", errno(read_only) == .ROFS and entries != null and entries.?.has_one, "sysrq_write={s}", .{@tagName(errno(read_only))});
    const sys_flags = statfsFlags("/proc/sys", tmpfs_magic);
    const sys_entries = list("/proc/sys", &.{"kernel"});
    const kernel_entries = list("/proc/sys/kernel", &.{"random"});
    const random_entries = list("/proc/sys/kernel/random", &.{"boot_id"});
    const uuid = absent("/proc/sys/kernel/random/uuid");
    const extra = linux.open("/proc/sys/extra", .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true }, 0o600);
    if (errno(extra) == .SUCCESS) _ = linux.close(@intCast(extra));
    const writer = linux.open("/proc/sys/kernel/random/boot_id", .{ .ACCMODE = .WRONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (errno(writer) == .SUCCESS) _ = linux.close(@intCast(writer));
    const only = struct {
        fn one(listing: ?Listing) bool {
            return listing != null and listing.?.count == 1 and listing.?.matched == 1;
        }
    }.one;
    report("proc-sys-masked", sys_flags != null and sys_flags.? & st_rdonly_nosuid_nodev_noexec == st_rdonly_nosuid_nodev_noexec and
        only(sys_entries) and only(kernel_entries) and only(random_entries) and uuid == .NOENT and
        errno(extra) == .ROFS and errno(writer) == .ROFS, "flags=0x{x} uuid={s} create={s} write={s}", .{
        sys_flags orelse -1, @tagName(uuid), @tagName(errno(extra)), @tagName(errno(writer)),
    });
    var boot_id: [38]u8 = undefined;
    var boot_id_length: usize = 0;
    const reader = linux.open("/proc/sys/kernel/random/boot_id", .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (errno(reader) == .SUCCESS) {
        const got = linux.read(@intCast(reader), &boot_id, boot_id.len);
        if (errno(got) == .SUCCESS) boot_id_length = got;
        _ = linux.close(@intCast(reader));
    }
    var valid = boot_id_length == 37 and boot_id[36] == '\n';
    if (valid) {
        for (boot_id[0..36], 0..) |digit, index| {
            valid = valid and if (index == 8 or index == 13 or index == 18 or index == 23)
                digit == '-'
            else
                std.ascii.isHex(digit) and !std.ascii.isUpper(digit);
        }
    }
    report("proc-boot-id", valid, "boot_id={s}", .{if (valid) boot_id[0..36] else "invalid"});
}

fn checkArchiveUnbound() void {
    // Configure operations bind no archive; the mountpoint stays the empty file.
    var value: linux.Statx = undefined;
    const stat_status = errno(linux.statx(linux.AT.FDCWD, archive_mountpoint, linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &value));
    const mount_root = stat_status == .SUCCESS and
        @as(u64, @bitCast(value.attributes_mask)) & statx_attr_mount_root != 0 and
        @as(u64, @bitCast(value.attributes)) & statx_attr_mount_root != 0;
    report("archive-unbound", stat_status == .SUCCESS and value.mode & 0o170000 == 0o100000 and value.size == 0 and !mount_root, "size={d} mount_root={}", .{
        if (stat_status == .SUCCESS) value.size else 0, mount_root,
    });
}

/// The kernel starts `/bin/sh SCRIPT configure [VERSION]` for a signed postinst.
fn scriptProfile(args: []const [*:0]const u8) ?Profile {
    if (args.len < 3 or args.len > 4 or !std.mem.eql(u8, std.mem.span(args[2]), "configure")) return null;
    inline for (@typeInfo(Profile).@"enum".fields) |field| {
        if (std.mem.eql(u8, std.mem.span(args[1]), "/var/lib/dpkg/info/" ++ field.name ++ ".postinst"))
            return @enumFromInt(field.value);
    }
    return null;
}

fn startDescendant() void {
    var ready: [2]i32 = undefined;
    if (errno(linux.pipe2(&ready, .{ .CLOEXEC = true })) != .SUCCESS) {
        report("descendant-started", false, "pipe", .{});
        return;
    }
    const child = linux.fork();
    if (errno(child) != .SUCCESS) {
        report("descendant-started", false, "fork={s}", .{@tagName(errno(child))});
        return;
    }
    if (child == 0) {
        _ = linux.close(ready[0]);
        _ = linux.setsid();
        const grandchild = linux.fork();
        if (errno(grandchild) != .SUCCESS) linux.exit(1);
        if (grandchild != 0) linux.exit(0);
        const marker = linux.open(
            descendant_marker,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true },
            0o600,
        );
        if (errno(marker) != .SUCCESS) linux.exit(1);
        var bytes: [24]u8 = undefined;
        const text = std.fmt.bufPrint(&bytes, "{d}\n", .{linux.getpid()}) catch linux.exit(1);
        _ = linux.write(@intCast(marker), text.ptr, text.len);
        _ = linux.close(@intCast(marker));
        _ = linux.write(ready[1], "r", 1);
        _ = linux.close(ready[1]);
        const delay: linux.timespec = .{ .sec = 600, .nsec = 0 };
        while (true) _ = linux.nanosleep(&delay, null);
    }
    _ = linux.close(ready[1]);
    var status: u32 = 0;
    _ = linux.waitpid(@intCast(child), &status, 0);
    var byte: [1]u8 = undefined;
    const got = linux.read(ready[0], &byte, 1);
    _ = linux.close(ready[0]);
    report("descendant-started", errno(got) == .SUCCESS and got == 1, "detached_sleeper={}", .{got == 1});
}

fn networkControl(profile: ?Profile) !void {
    const opened = linux.open("/.debz-network-control", .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, 0);
    if (linux.errno(opened) != .SUCCESS) return error.MissingReferenceNetworkControl;
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);
    var bytes: [256]u8 = undefined;
    const count = linux.read(fd, &bytes, bytes.len);
    if (linux.errno(count) != .SUCCESS or count == 0 or count == bytes.len)
        return error.InvalidReferenceNetworkControl;
    var fields = std.mem.splitScalar(u8, bytes[0..count], '\n');
    const port = try std.fmt.parseInt(u16, fields.next() orelse
        return error.InvalidReferenceNetworkControl, 10);
    const name = fields.next() orelse return error.InvalidReferenceNetworkControl;
    const inherited = try std.fmt.parseInt(i32, fields.next() orelse
        return error.InvalidReferenceNetworkControl, 10);
    if (fields.next() != null) return error.InvalidReferenceNetworkControl;
    try network_probe.observe(
        if (profile) |value| switch (value) {
            .systemd => .systemd,
            .udev => .udev,
            .sudo => .sudo,
        } else .reference,
        port,
        name,
        inherited,
    );
}

pub fn main(init: std.process.Init.Minimal) u8 {
    const args = init.args.vector;
    if (args.len < 2) return 2;
    if (std.mem.eql(u8, std.mem.span(args[1]), "network-host")) {
        if (args.len != 5) return 2;
        const port = std.fmt.parseInt(u16, std.mem.span(args[2]), 10) catch return 2;
        const inherited = std.fmt.parseInt(i32, std.mem.span(args[4]), 10) catch return 2;
        network_probe.observe(.host, port, std.mem.span(args[3]), inherited) catch |err| {
            std.log.err("reference host network control failed: {s}", .{@errorName(err)});
            return 1;
        };
        return 0;
    }
    const profile = scriptProfile(args);
    const mode = if (profile) |value| @tagName(value) else std.mem.span(args[1]);
    const confined = profile != null or std.mem.eql(u8, mode, "install");
    if (!confined and !std.mem.eql(u8, mode, "control")) return 2;
    checkNamespaces();
    if (profile) |value| checkProcView(value) else checkProc();
    checkDescriptors();
    checkPrivileges();
    checkRootPath();
    checkKernelAuthority();
    checkNamespaceChanges();
    networkInformation();
    if (confined) {
        networkControl(profile) catch |err| {
            report("private-network", false, "error={s}", .{@errorName(err)});
        };
        if (failures == 0) report("private-network", true, "host-network=denied loopback=usable", .{});
    }
    if (profile != null) {
        checkArchiveUnbound();
        startDescendant();
    } else if (confined) {
        checkArchiveMount();
        startDescendant();
    }
    report("result", failures == 0, "failures={d} mode={s}", .{ failures, mode });
    return if (failures == 0) 0 else 1;
}
