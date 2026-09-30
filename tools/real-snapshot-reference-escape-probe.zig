//! Static confinement probe packaged as a reference proof `preinst`.
//!
//! `install` (dpkg's preinst argument) runs inside the protected launcher as a
//! child of pinned dpkg, which is PID 1 of the reference namespaces. It reports
//! every escape attempt and starts a detached descendant that must be killed by
//! namespace teardown. `control` runs the same checks unconfined, without the
//! descendant, to show that each check detects authority when it is present.
//! Every attempted operation targets a missing path, an invalid argument or the
//! probe's own process, so an unconfined control run changes no host state.
const std = @import("std");
const linux = std.os.linux;

const CapHeader = extern struct { version: u32 = 0x20080522, pid: i32 = 0 };
const allowed_caps = [_]u32{
    linux.CAP.CHOWN,  linux.CAP.DAC_OVERRIDE, linux.CAP.FOWNER, linux.CAP.FSETID,
    linux.CAP.SETGID, linux.CAP.SETUID,       linux.CAP.SETFCAP,
};
const missing: [*:0]const u8 = "/.debz-escape-probe-missing";
const missing_child: [*:0]const u8 = "/.debz-escape-probe-missing/node";
const descendant_marker: [*:0]const u8 = "/.debz-escape-probe-descendant";

var failures: u32 = 0;

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

fn identity(path: [*:0]const u8) ?[2]u64 {
    var value: linux.Statx = undefined;
    if (errno(linux.statx(linux.AT.FDCWD, path, linux.AT.SYMLINK_NOFOLLOW, .BASIC_STATS, &value)) != .SUCCESS)
        return null;
    return .{ (@as(u64, value.dev_major) << 32) | value.dev_minor, value.ino };
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
    report("capabilities", !extra_sets and extra_bounding == 0 and ambient == 0 and count > 0,
        "effective0=0x{x} permitted0=0x{x} word1=0x{x} extra_bounding={d} ambient={d} known={d}", .{
        data[0].effective, data[0].permitted, data[1].effective | data[1].permitted,
        extra_bounding, ambient, count,
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
    // #278 owns the shared host network decision; record it without judging.
    const socket = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    info("shared-network-namespace", "inet_socket={s}", .{@tagName(errno(socket))});
    if (errno(socket) == .SUCCESS) _ = linux.close(@intCast(socket));
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

pub fn main(init: std.process.Init.Minimal) u8 {
    const args = init.args.vector;
    if (args.len < 2) return 2;
    const mode = std.mem.span(args[1]);
    const confined = std.mem.eql(u8, mode, "install");
    if (!confined and !std.mem.eql(u8, mode, "control")) return 2;
    checkNamespaces();
    checkProc();
    checkDescriptors();
    checkPrivileges();
    checkRootPath();
    checkKernelAuthority();
    checkNamespaceChanges();
    networkInformation();
    if (confined) startDescendant();
    report("result", failures == 0, "failures={d} mode={s}", .{ failures, mode });
    return if (failures == 0) 0 else 1;
}
