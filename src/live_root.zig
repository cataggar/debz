//! Private live-host-root projection for the future `debz apt` facade.
//!
//! The production backend must never be handed `/`.  This module creates a
//! private mount namespace, changes `/` propagation to private, and recursively
//! bind-mounts the namespace's source root at `logical_root_path`.  Existing
//! product and backend code sees only that stable alternate spelling.
//!
//! A small supervisor remains outside a nested PID namespace while the trusted
//! callback runs as that namespace's init process.  When init exits Linux
//! destroys every remaining process in that PID namespace; the supervisor then
//! unmounts the bind and exits, destroying the mount namespace.  Catchable
//! interrupt signals are relayed parent -> supervisor -> namespace init.
//!
//! The `/run/debz` directory, lock, and empty mountpoint are root-owned,
//! no-follow opened, mode checked, and protected by an open-file-description
//! lock.  Source, mountpoint, and mounted-root identities are re-read around
//! every namespace transition.  Replacement or an unexpected host-visible
//! mount fails closed.

const std = @import("std");
const builtin = @import("builtin");
const transaction_recovery = @import("transaction_recovery.zig");

const linux = std.os.linux;

pub const logical_root_path = "/run/debz/system-root";
pub const runtime_directory_path = "/run/debz";
pub const lock_path = "/run/debz/live-root.lock";

pub const host_root_allowed = false;

pub const ChildFn = *const fn (context: ?*anyopaque, install_root: []const u8) anyerror!u8;

pub const Request = struct {
    context: ?*anyopaque = null,
    child: ChildFn,
    termination_grace_ms: u64 = 1_000,
};

pub const SetupStage = enum(u8) {
    source_validation,
    mountpoint_validation,
    mount_namespace,
    private_propagation,
    recursive_bind,
    bind_validation,
    pid_namespace,
    workload_fork,
    callback,
    cleanup,
};

pub const SetupFailure = struct {
    stage: SetupStage,
    errno: u32 = 0,
};

pub const Result = union(enum) {
    exited: u8,
    signaled: u32,
    interrupted: u32,
    setup_failed: SetupFailure,
};

pub const Error = error{
    UnsupportedPlatform,
    NotPrivileged,
    UnsafeRuntimeDirectory,
    UnsafeLockFile,
    UnsafeMountpoint,
    ActiveHostMount,
    RootReplaced,
    MountpointReplaced,
    NamespaceUnavailable,
    PipeFailed,
    ForkFailed,
    SignalSetupFailed,
    WaitFailed,
    SystemCallFailed,
};

pub fn platformSupported(os: std.Target.Os.Tag) bool {
    return os == .linux;
}

/// Runs `request.child` with the host root available only at
/// `logical_root_path`.  The callback is trusted product code: it must not
/// change signal masks or attempt to join another PID or mount namespace.
pub fn run(request: Request) Error!Result {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    if (linux.geteuid() != 0) return error.NotPrivileged;

    var pinned = try PinnedPaths.open();
    defer pinned.close();

    var watched = interruptSet();
    var old_mask: linux.sigset_t = undefined;
    if (linux.errno(linux.sigprocmask(linux.SIG.BLOCK, &watched, &old_mask)) != .SUCCESS)
        return error.SignalSetupFailed;
    defer _ = linux.sigprocmask(linux.SIG.SETMASK, &old_mask, null);

    const signal_fd_raw = linux.signalfd(
        -1,
        &watched,
        linux.SFD.CLOEXEC | linux.SFD.NONBLOCK,
    );
    if (linux.errno(signal_fd_raw) != .SUCCESS) return error.SignalSetupFailed;
    const signal_fd: i32 = @intCast(signal_fd_raw);
    defer _ = linux.close(signal_fd);

    var report_pipe: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&report_pipe, .{ .CLOEXEC = true })) != .SUCCESS)
        return error.PipeFailed;
    defer {
        closeFd(&report_pipe[0]);
        closeFd(&report_pipe[1]);
    }

    const forked = linux.fork();
    switch (linux.errno(forked)) {
        .SUCCESS => {},
        else => return error.ForkFailed,
    }
    const pid: i32 = @intCast(forked);
    if (pid == 0) supervisorMain(request, pinned, old_mask, report_pipe);

    closeFd(&report_pipe[1]);
    _ = linux.setpgid(pid, pid);
    const waited = try superviseProcess(pid, signal_fd, request.termination_grace_ms);
    const failure = readFailure(report_pipe[0]);
    if (failure) |value| return .{ .setup_failed = value };
    if (waited.interrupt) |signal| return .{ .interrupted = signal };
    return termination(waited.status);
}

const Identity = struct {
    device: u64,
    inode: u64,
    mount_id: u64,
    uid: u32,
    gid: u32,
    mode: u16,
    kind: u16,
    link_count: u32,

    fn sameEntry(self: Identity, other: Identity) bool {
        return self.device == other.device and self.inode == other.inode;
    }

    fn eql(self: Identity, other: Identity) bool {
        return self.sameEntry(other) and
            self.mount_id == other.mount_id and
            self.uid == other.uid and self.gid == other.gid and
            self.mode == other.mode and self.kind == other.kind;
    }
};

const PinnedPaths = struct {
    source_fd: i32,
    runtime_fd: i32,
    mountpoint_fd: i32,
    lock_fd: i32,
    source: Identity,
    runtime: Identity,
    mountpoint: Identity,

    fn open() Error!PinnedPaths {
        const source_fd = try openDirectoryAbsolute("/");
        errdefer _ = linux.close(source_fd);
        const source = try identityOf(source_fd);

        const run_fd = try openDirectoryAbsolute("/run");
        defer _ = linux.close(run_fd);
        try ensureDirectory(run_fd, "debz", 0o700);
        const runtime_fd = try openDirectoryAt(run_fd, "debz");
        errdefer _ = linux.close(runtime_fd);
        const runtime = try identityOf(runtime_fd);
        if (!privateRootDirectory(runtime)) return error.UnsafeRuntimeDirectory;

        const lock_fd = try openLock(runtime_fd);
        errdefer _ = linux.close(lock_fd);
        const lock_identity = try identityOf(lock_fd);
        if (!privateRootFile(lock_identity)) return error.UnsafeLockFile;
        switch (linux.errno(linux.flock(lock_fd, 2))) {
            .SUCCESS => {},
            else => return error.SystemCallFailed,
        }
        const named_lock = try identityAt(runtime_fd, "live-root.lock");
        if (!named_lock.eql(lock_identity)) return error.UnsafeLockFile;

        try ensureDirectory(runtime_fd, "system-root", 0o700);
        const mountpoint_fd = try openDirectoryAt(runtime_fd, "system-root");
        errdefer _ = linux.close(mountpoint_fd);
        const mountpoint = try identityOf(mountpoint_fd);
        const named = try identityAt(runtime_fd, "system-root");
        try validateHostMountpoint(runtime, mountpoint, named);

        return .{
            .source_fd = source_fd,
            .runtime_fd = runtime_fd,
            .mountpoint_fd = mountpoint_fd,
            .lock_fd = lock_fd,
            .source = source,
            .runtime = runtime,
            .mountpoint = mountpoint,
        };
    }

    fn close(self: *PinnedPaths) void {
        closeFd(&self.mountpoint_fd);
        closeFd(&self.lock_fd);
        closeFd(&self.runtime_fd);
        closeFd(&self.source_fd);
    }
};

fn privateRootDirectory(identity: Identity) bool {
    return identity.kind == linux.S.IFDIR and
        identity.uid == 0 and identity.gid == 0 and
        identity.mode & 0o7777 == 0o700;
}

fn privateRootFile(identity: Identity) bool {
    return identity.kind == linux.S.IFREG and
        identity.uid == 0 and identity.gid == 0 and
        identity.mode & 0o7777 == 0o600 and identity.link_count == 1;
}

fn validateHostMountpoint(runtime: Identity, opened: Identity, named: Identity) Error!void {
    if (!privateRootDirectory(opened)) return error.UnsafeMountpoint;
    if (opened.mount_id != runtime.mount_id) return error.ActiveHostMount;
    if (!named.eql(opened)) return error.MountpointReplaced;
}

fn openDirectoryAbsolute(path: [*:0]const u8) Error!i32 {
    const raw = linux.open(path, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    return fdResult(raw);
}

fn openDirectoryAt(parent: i32, path: [*:0]const u8) Error!i32 {
    const raw = linux.openat(parent, path, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    return fdResult(raw);
}

fn openLock(parent: i32) Error!i32 {
    const raw = linux.openat(parent, "live-root.lock", .{
        .ACCMODE = .RDWR,
        .CREAT = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0o600);
    return fdResult(raw);
}

fn fdResult(raw: usize) Error!i32 {
    return switch (linux.errno(raw)) {
        .SUCCESS => @intCast(raw),
        .ACCES, .PERM => error.NotPrivileged,
        else => error.SystemCallFailed,
    };
}

fn ensureDirectory(parent: i32, path: [*:0]const u8, mode: linux.mode_t) Error!void {
    switch (linux.errno(linux.mkdirat(parent, path, mode))) {
        .SUCCESS, .EXIST => {},
        .ACCES, .PERM => return error.NotPrivileged,
        else => return error.SystemCallFailed,
    }
}

fn identityOf(fd: i32) Error!Identity {
    return identityAt(fd, "");
}

fn identityAt(parent: i32, path: [*:0]const u8) Error!Identity {
    const request: linux.STATX = .{
        .TYPE = true,
        .MODE = true,
        .UID = true,
        .GID = true,
        .INO = true,
        .NLINK = true,
        .MNT_ID = true,
    };
    var raw = std.mem.zeroes(linux.Statx);
    const flags: u32 = linux.AT.NO_AUTOMOUNT | linux.AT.SYMLINK_NOFOLLOW |
        @as(u32, if (path[0] == 0) linux.AT.EMPTY_PATH else 0);
    switch (linux.errno(linux.statx(parent, path, flags, request, &raw))) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.NotPrivileged,
        else => return error.SystemCallFailed,
    }
    const filled: u32 = @bitCast(raw.mask);
    const wanted: u32 = @bitCast(request);
    if (filled & wanted != wanted) return error.SystemCallFailed;
    return .{
        .device = (@as(u64, raw.dev_major) << 32) | raw.dev_minor,
        .inode = raw.ino,
        .mount_id = raw.mnt_id,
        .uid = raw.uid,
        .gid = raw.gid,
        .mode = raw.mode,
        .kind = raw.mode & linux.S.IFMT,
        .link_count = raw.nlink,
    };
}

const FailureWire = extern struct {
    magic: u32 = failure_magic,
    stage: u8,
    padding: [3]u8 = .{ 0, 0, 0 },
    errno: u32,
};

const failure_magic: u32 = 0x445a4c52;

fn supervisorMain(
    request: Request,
    pinned: PinnedPaths,
    old_mask: linux.sigset_t,
    pipes: [2]i32,
) noreturn {
    closeRaw(pipes[0]);
    _ = linux.setpgid(0, 0);

    var mounted = false;
    validateSource(pinned) catch |err| childFail(pipes[1], .source_validation, errorNumber(err));
    validateMountpoint(pinned) catch |err|
        childFail(pipes[1], .mountpoint_validation, errorNumber(err));

    switch (linux.errno(linux.unshare(linux.CLONE.NEWNS))) {
        .SUCCESS => {},
        else => |err| childFail(pipes[1], .mount_namespace, @intFromEnum(err)),
    }
    switch (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0))) {
        .SUCCESS => {},
        else => |err| childFail(pipes[1], .private_propagation, @intFromEnum(err)),
    }
    validateSource(pinned) catch |err| childFail(pipes[1], .source_validation, errorNumber(err));
    validateMountpoint(pinned) catch |err|
        childFail(pipes[1], .mountpoint_validation, errorNumber(err));

    switch (linux.errno(linux.mount("/", logical_root_path, null, linux.MS.BIND | linux.MS.REC, 0))) {
        .SUCCESS => mounted = true,
        else => |err| childFail(pipes[1], .recursive_bind, @intFromEnum(err)),
    }
    validateBind(pinned) catch |err| {
        if (mounted) unmountBestEffort();
        childFail(pipes[1], .bind_validation, errorNumber(err));
    };

    switch (linux.errno(linux.unshare(linux.CLONE.NEWPID))) {
        .SUCCESS => {},
        else => |err| {
            unmountBestEffort();
            childFail(pipes[1], .pid_namespace, @intFromEnum(err));
        },
    }

    const worker_raw = linux.fork();
    switch (linux.errno(worker_raw)) {
        .SUCCESS => {},
        else => |err| {
            unmountBestEffort();
            childFail(pipes[1], .workload_fork, @intFromEnum(err));
        },
    }
    const worker: i32 = @intCast(worker_raw);
    if (worker == 0) workloadMain(request, old_mask, pipes[1]);

    const status = superviseWorkload(worker, request.termination_grace_ms) catch {
        _ = linux.kill(worker, .KILL);
        _ = reapBlocking(worker);
        unmountBestEffort();
        childFail(pipes[1], .cleanup, 0);
    };
    // Once namespace PID 1 has exited, Linux has killed every other process in
    // that PID namespace.  No descendant can retain this mount namespace.
    switch (linux.errno(linux.umount2(logical_root_path, linux.UMOUNT_NOFOLLOW))) {
        .SUCCESS => mounted = false,
        else => |err| childFail(pipes[1], .cleanup, @intFromEnum(err)),
    }
    if (mounted) unmountBestEffort();
    validateMountpoint(pinned) catch |err|
        childFail(pipes[1], .mountpoint_validation, errorNumber(err));
    closeRaw(pipes[1]);
    exitStatus(status);
}

fn workloadMain(request: Request, old_mask: linux.sigset_t, report_fd: i32) noreturn {
    _ = linux.sigprocmask(linux.SIG.SETMASK, &old_mask, null);
    resetInterruptActions();
    const code = request.child(request.context, logical_root_path) catch
        childFail(report_fd, .callback, 0);
    closeRaw(report_fd);
    linux.exit_group(code);
}

fn validateSource(pinned: PinnedPaths) Error!void {
    const descriptor = try identityOf(pinned.source_fd);
    const named_fd = try openDirectoryAbsolute("/");
    defer _ = linux.close(named_fd);
    const named = try identityOf(named_fd);
    if (!descriptor.eql(pinned.source) or !named.eql(pinned.source))
        return error.RootReplaced;
}

fn validateMountpoint(pinned: PinnedPaths) Error!void {
    const descriptor = try identityOf(pinned.mountpoint_fd);
    const named = try identityAt(pinned.runtime_fd, "system-root");
    if (!descriptor.eql(pinned.mountpoint) or !named.eql(pinned.mountpoint))
        return error.MountpointReplaced;
}

fn validateBind(pinned: PinnedPaths) Error!void {
    try validateSource(pinned);
    const mounted_fd = try openDirectoryAbsolute(logical_root_path);
    defer _ = linux.close(mounted_fd);
    const mounted = try identityOf(mounted_fd);
    if (!mounted.sameEntry(pinned.source) or mounted.mount_id == pinned.source.mount_id)
        return error.RootReplaced;
}

fn unmountBestEffort() void {
    _ = linux.umount2(logical_root_path, linux.MNT.DETACH | linux.UMOUNT_NOFOLLOW);
}

fn interruptSet() linux.sigset_t {
    var set = linux.sigemptyset();
    inline for ([_]linux.SIG{ .INT, .QUIT, .HUP, .TERM }) |signal|
        linux.sigaddset(&set, signal);
    return set;
}

fn resetInterruptActions() void {
    const empty = linux.sigemptyset();
    inline for ([_]linux.SIG{ .INT, .QUIT, .HUP, .TERM }) |signal| {
        const action: linux.Sigaction = .{
            .handler = .{ .handler = linux.SIG.DFL },
            .mask = empty,
            .flags = 0,
        };
        _ = linux.sigaction(signal, &action, null);
    }
}

const WaitResult = struct {
    status: u32,
    interrupt: ?u32 = null,
};

fn superviseProcess(pid: i32, signal_fd: i32, grace_ms: u64) Error!WaitResult {
    var interrupt: ?u32 = null;
    while (!probeExited(pid)) {
        if (readSignal(signal_fd)) |signal| {
            if (interrupt == null) interrupt = @intFromEnum(signal);
            _ = linux.kill(-pid, signal);
            if (!awaitExit(pid, grace_ms)) _ = linux.kill(-pid, .KILL);
        }
        sleepMilliseconds(5);
    }
    // The supervisor normally proves its nested PID namespace empty.  This
    // final sweep is issued before reap while the process-group id is pinned.
    _ = linux.kill(-pid, .KILL);
    return .{ .status = try reapBlocking(pid), .interrupt = interrupt };
}

fn superviseWorkload(pid: i32, grace_ms: u64) Error!u32 {
    var watched = interruptSet();
    const signal_fd_raw = linux.signalfd(
        -1,
        &watched,
        linux.SFD.CLOEXEC | linux.SFD.NONBLOCK,
    );
    if (linux.errno(signal_fd_raw) != .SUCCESS) return error.SignalSetupFailed;
    const signal_fd: i32 = @intCast(signal_fd_raw);
    defer _ = linux.close(signal_fd);

    while (!probeExited(pid)) {
        if (readSignal(signal_fd)) |signal| {
            _ = linux.kill(pid, signal);
            if (!awaitExit(pid, grace_ms)) _ = linux.kill(pid, .KILL);
        }
        sleepMilliseconds(5);
    }
    return reapBlocking(pid);
}

fn readSignal(fd: i32) ?linux.SIG {
    var info: linux.signalfd_siginfo = undefined;
    const raw = linux.read(fd, @ptrCast(&info), @sizeOf(linux.signalfd_siginfo));
    if (linux.errno(raw) != .SUCCESS or raw != @sizeOf(linux.signalfd_siginfo)) return null;
    return switch (info.signo) {
        @intFromEnum(linux.SIG.INT) => .INT,
        @intFromEnum(linux.SIG.QUIT) => .QUIT,
        @intFromEnum(linux.SIG.HUP) => .HUP,
        @intFromEnum(linux.SIG.TERM) => .TERM,
        else => null,
    };
}

fn awaitExit(pid: i32, grace_ms: u64) bool {
    const deadline = monotonicMilliseconds() + grace_ms;
    while (monotonicMilliseconds() < deadline) {
        if (probeExited(pid)) return true;
        sleepMilliseconds(5);
    }
    return probeExited(pid);
}

fn probeExited(pid: i32) bool {
    while (true) {
        var info: linux.siginfo_t = std.mem.zeroes(linux.siginfo_t);
        const raw = linux.waitid(.PID, pid, &info, linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT, null);
        switch (linux.errno(raw)) {
            .SUCCESS => return info.fields.common.first.piduid.pid == pid,
            .INTR => continue,
            else => return true,
        }
    }
}

fn reapBlocking(pid: i32) Error!u32 {
    var status: u32 = 0;
    while (true) {
        const raw = linux.waitpid(pid, &status, 0);
        switch (linux.errno(raw)) {
            .SUCCESS => return status,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
}

fn termination(status: u32) Result {
    if (linux.W.IFEXITED(status)) return .{ .exited = linux.W.EXITSTATUS(status) };
    if (linux.W.IFSIGNALED(status))
        return .{ .signaled = @intFromEnum(linux.W.TERMSIG(status)) };
    return .{ .signaled = status };
}

fn exitStatus(status: u32) noreturn {
    if (linux.W.IFEXITED(status)) linux.exit_group(linux.W.EXITSTATUS(status));
    if (linux.W.IFSIGNALED(status)) {
        const signal = linux.W.TERMSIG(status);
        _ = linux.kill(linux.getpid(), signal);
        linux.exit_group(128 + @intFromEnum(signal));
    }
    linux.exit_group(125);
}

fn childFail(fd: i32, stage: SetupStage, errno: u32) noreturn {
    var wire: FailureWire = .{ .stage = @intFromEnum(stage), .errno = errno };
    _ = linux.write(fd, @ptrCast(&wire), @sizeOf(FailureWire));
    closeRaw(fd);
    linux.exit_group(125);
}

fn readFailure(fd: i32) ?SetupFailure {
    var wire: FailureWire = undefined;
    var filled: usize = 0;
    while (filled < @sizeOf(FailureWire)) {
        const raw = linux.read(
            fd,
            @as([*]u8, @ptrCast(&wire)) + filled,
            @sizeOf(FailureWire) - filled,
        );
        switch (linux.errno(raw)) {
            .SUCCESS => {
                if (raw == 0) break;
                filled += raw;
            },
            .INTR => continue,
            else => break,
        }
    }
    if (filled != @sizeOf(FailureWire) or wire.magic != failure_magic) return null;
    if (wire.stage > @intFromEnum(SetupStage.cleanup)) return null;
    return .{ .stage = @enumFromInt(wire.stage), .errno = wire.errno };
}

fn errorNumber(err: anyerror) u32 {
    return switch (err) {
        error.NotPrivileged, error.NamespaceUnavailable => @intFromEnum(linux.E.PERM),
        else => 0,
    };
}

fn monotonicMilliseconds() u64 {
    var value: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &value)) != .SUCCESS) return 0;
    return @as(u64, @intCast(value.sec)) * std.time.ms_per_s +
        @as(u64, @intCast(value.nsec)) / std.time.ns_per_ms;
}

fn sleepMilliseconds(milliseconds: u64) void {
    var request: linux.timespec = .{
        .sec = @intCast(milliseconds / std.time.ms_per_s),
        .nsec = @intCast((milliseconds % std.time.ms_per_s) * std.time.ns_per_ms),
    };
    while (linux.errno(linux.nanosleep(&request, &request)) == .INTR) {}
}

fn closeFd(fd: *i32) void {
    if (fd.* >= 0) {
        _ = linux.close(fd.*);
        fd.* = -1;
    }
}

fn closeRaw(fd: i32) void {
    if (fd >= 0) _ = linux.close(fd);
}

// The setup state machine is independent of Linux syscalls so ordering and
// every cleanup edge can be tested without privilege.
fn enter(operations: anytype) !void {
    try operations.validateSource();
    try operations.validateMountpoint();
    try operations.unshareMount();
    try operations.makePrivate();
    try operations.validateSource();
    try operations.validateMountpoint();
    try operations.recursiveBind();
    errdefer operations.unmount();
    try operations.validateBind();
}

const Event = enum {
    source,
    mountpoint,
    unshare,
    private,
    bind,
    bind_validation,
    child,
    unmount,
    signal,
    kill,
    reap,
};

const RecordingOperations = struct {
    events: [32]Event = undefined,
    event_count: usize = 0,
    calls: usize = 0,
    fail_call: ?usize = null,
    replace_root_on_source_call: ?usize = null,
    replace_mountpoint_on_call: ?usize = null,
    source_calls: usize = 0,
    mountpoint_calls: usize = 0,
    fail_child: bool = false,

    fn record(self: *RecordingOperations, event: Event) !void {
        self.events[self.event_count] = event;
        self.event_count += 1;
        self.calls += 1;
        if (self.fail_call == self.calls) return error.Injected;
    }

    fn validateSource(self: *RecordingOperations) !void {
        try self.record(.source);
        self.source_calls += 1;
        if (self.replace_root_on_source_call == self.source_calls)
            return error.RootReplaced;
    }

    fn validateMountpoint(self: *RecordingOperations) !void {
        try self.record(.mountpoint);
        self.mountpoint_calls += 1;
        if (self.replace_mountpoint_on_call == self.mountpoint_calls)
            return error.MountpointReplaced;
    }

    fn unshareMount(self: *RecordingOperations) !void {
        try self.record(.unshare);
    }

    fn makePrivate(self: *RecordingOperations) !void {
        try self.record(.private);
    }

    fn recursiveBind(self: *RecordingOperations) !void {
        try self.record(.bind);
    }

    fn validateBind(self: *RecordingOperations) !void {
        try self.record(.bind_validation);
    }

    fn runChild(self: *RecordingOperations) !u8 {
        try self.record(.child);
        if (self.fail_child) return error.ChildFailed;
        return 0;
    }

    fn unmount(self: *RecordingOperations) void {
        self.events[self.event_count] = .unmount;
        self.event_count += 1;
    }
};

fn expectEvents(expected: []const Event, operations: *const RecordingOperations) !void {
    try std.testing.expectEqualSlices(Event, expected, operations.events[0..operations.event_count]);
}

fn exerciseLifecycle(operations: anytype) !u8 {
    try enter(operations);
    defer operations.unmount();
    return operations.runChild();
}

const RecordingSupervisor = struct {
    events: [4]Event = undefined,
    count: usize = 0,
    exits_during_grace: bool = false,

    fn append(self: *RecordingSupervisor, event: Event) void {
        self.events[self.count] = event;
        self.count += 1;
    }

    fn signal(self: *RecordingSupervisor) void {
        self.append(.signal);
    }

    fn awaitExit(self: *RecordingSupervisor) bool {
        return self.exits_during_grace;
    }

    fn kill(self: *RecordingSupervisor) void {
        self.append(.kill);
    }

    fn reap(self: *RecordingSupervisor) void {
        self.append(.reap);
    }
};

fn finishInterrupted(operations: anytype) void {
    operations.signal();
    if (!operations.awaitExit()) operations.kill();
    operations.reap();
}

test "live_root.test.stable alternate root never aliases host root" {
    try std.testing.expectEqualStrings("/run/debz/system-root", logical_root_path);
    try std.testing.expect(!std.mem.eql(u8, logical_root_path, "/"));
    try std.testing.expect(!host_root_allowed);
    try std.testing.expectEqual(
        transaction_recovery.rootIdentity(logical_root_path),
        transaction_recovery.rootIdentity(logical_root_path),
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &transaction_recovery.rootIdentity(logical_root_path),
        &transaction_recovery.rootIdentity("/"),
    ));
}

test "live_root.test.unsupported platforms fail closed" {
    try std.testing.expect(platformSupported(.linux));
    try std.testing.expect(!platformSupported(.windows));
    try std.testing.expect(!platformSupported(.macos));
}

test "live_root.test.stale empty mountpoint is reusable but mounts and replacements fail" {
    const runtime: Identity = .{
        .device = 1,
        .inode = 10,
        .mount_id = 7,
        .uid = 0,
        .gid = 0,
        .mode = linux.S.IFDIR | 0o700,
        .kind = linux.S.IFDIR,
        .link_count = 3,
    };
    const empty: Identity = .{
        .device = 1,
        .inode = 11,
        .mount_id = 7,
        .uid = 0,
        .gid = 0,
        .mode = linux.S.IFDIR | 0o700,
        .kind = linux.S.IFDIR,
        .link_count = 2,
    };
    try validateHostMountpoint(runtime, empty, empty);

    var mounted = empty;
    mounted.mount_id = 8;
    try std.testing.expectError(
        error.ActiveHostMount,
        validateHostMountpoint(runtime, mounted, mounted),
    );

    var replacement = empty;
    replacement.inode = 12;
    try std.testing.expectError(
        error.MountpointReplaced,
        validateHostMountpoint(runtime, empty, replacement),
    );
}

test "live_root.test.namespace setup ordering is fixed" {
    var operations: RecordingOperations = .{};
    try enter(&operations);
    try expectEvents(
        &.{
            .source,
            .mountpoint,
            .unshare,
            .private,
            .source,
            .mountpoint,
            .bind,
            .bind_validation,
        },
        &operations,
    );
}

test "live_root.test.cleanup covers every setup failure boundary" {
    // Failures through bind itself have no successful mount to remove.
    for (1..9) |failure| {
        var operations: RecordingOperations = .{ .fail_call = failure };
        try std.testing.expectError(error.Injected, enter(&operations));
        const should_unmount = failure == 8;
        try std.testing.expectEqual(
            should_unmount,
            operations.event_count != 0 and
                operations.events[operations.event_count - 1] == .unmount,
        );
    }
}

test "live_root.test.normal and callback exits both unmount" {
    var success: RecordingOperations = .{};
    try std.testing.expectEqual(@as(u8, 0), try exerciseLifecycle(&success));
    try std.testing.expectEqual(Event.unmount, success.events[success.event_count - 1]);

    var failure: RecordingOperations = .{ .fail_child = true };
    try std.testing.expectError(error.ChildFailed, exerciseLifecycle(&failure));
    try std.testing.expectEqual(Event.unmount, failure.events[failure.event_count - 1]);
}

test "live_root.test.root replacement fails before mounting" {
    var operations: RecordingOperations = .{ .replace_root_on_source_call = 1 };
    try std.testing.expectError(error.RootReplaced, enter(&operations));
    try expectEvents(&.{.source}, &operations);

    var after_unshare: RecordingOperations = .{ .replace_root_on_source_call = 2 };
    try std.testing.expectError(error.RootReplaced, enter(&after_unshare));
    try expectEvents(
        &.{ .source, .mountpoint, .unshare, .private, .source },
        &after_unshare,
    );
}

test "live_root.test.mountpoint replacement fails before mounting" {
    var operations: RecordingOperations = .{ .replace_mountpoint_on_call = 1 };
    try std.testing.expectError(error.MountpointReplaced, enter(&operations));
    try expectEvents(&.{ .source, .mountpoint }, &operations);

    var after_unshare: RecordingOperations = .{ .replace_mountpoint_on_call = 2 };
    try std.testing.expectError(error.MountpointReplaced, enter(&after_unshare));
    try expectEvents(
        &.{ .source, .mountpoint, .unshare, .private, .source, .mountpoint },
        &after_unshare,
    );
}

test "live_root.test.interruption orders signal kill and reap" {
    var operations: RecordingSupervisor = .{};
    finishInterrupted(&operations);
    try std.testing.expectEqualSlices(
        Event,
        &.{ .signal, .kill, .reap },
        operations.events[0..operations.count],
    );

    var polite: RecordingSupervisor = .{ .exits_during_grace = true };
    finishInterrupted(&polite);
    try std.testing.expectEqualSlices(
        Event,
        &.{ .signal, .reap },
        polite.events[0..polite.count],
    );
}

fn integrationChild(_: ?*anyopaque, install_root: []const u8) anyerror!u8 {
    if (!std.mem.eql(u8, install_root, logical_root_path)) return error.BadRoot;
    return 0;
}

test "live_root.test.linux integration when namespace capabilities are available" {
    if (builtin.os.tag != .linux or linux.geteuid() != 0) return error.SkipZigTest;
    const result = try run(.{ .child = integrationChild });
    switch (result) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .setup_failed => |failure| switch (failure.stage) {
            .mount_namespace, .private_propagation, .pid_namespace => return error.SkipZigTest,
            else => return error.UnexpectedIntegrationFailure,
        },
        else => return error.UnexpectedIntegrationFailure,
    }
}
