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
//! interrupt signals are relayed parent -> supervisor -> namespace init. A
//! control pipe with a sole parent writer turns parent death into EOF; the
//! supervisor then kills and reaps namespace init before mount and lock cleanup.
//!
//! The `/run/debz` directory, lock, and empty mountpoint are root-owned,
//! no-follow opened, mode checked, and protected by an open-file-description
//! lock.  A detached clone of the pinned runtime directory is attached back to
//! its descriptor, making `/run/debz` a private-namespace mountpoint before the
//! source tree is attached to a descriptor opened beneath it. Source, runtime,
//! lock, mountpoint, and mounted-root identities are re-read around every
//! transition. Replacement or an unexpected host-visible mount fails closed.

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

pub const ProjectedChildFn = *const fn (
    context: ?*anyopaque,
    projection: *const Projection,
) anyerror!u8;

pub const ProjectedRequest = struct {
    context: ?*anyopaque = null,
    child: ProjectedChildFn,
    termination_grace_ms: u64 = 1_000,
};

/// Borrowed authority for this callback's exact private projection, not a
/// persistent permission or a way to authorize an arbitrary host-root alias.
pub const Projection = opaque {
    pub fn validateRoot(self: *const Projection, install_root: []const u8, root_fd: i32) Error!void {
        const authority: *const ProjectionAuthority = @ptrCast(@alignCast(self));
        if (!std.mem.eql(u8, install_root, logical_root_path))
            return error.InvalidProjection;
        if (linux.getpid() != authority.process_id or
            !(try namespaceIdentity("/proc/self/ns/pid", linux.CLONE.NEWPID)).eql(authority.pid_namespace) or
            !(try namespaceIdentity("/proc/self/ns/mnt", linux.CLONE.NEWNS)).eql(authority.mount_namespace))
            return error.InvalidProjection;
        try validateProjectedPaths(authority.lock, authority.expected);
        if (!(try identityOf(root_fd)).eql(authority.expected.mounted_root))
            return error.RootReplaced;
    }
};

const Invocation = struct {
    context: ?*anyopaque,
    callback: union(enum) {
        ordinary: ChildFn,
        projected: ProjectedChildFn,
    },
    termination_grace_ms: u64,
};

pub const SetupStage = enum(u8) {
    source_validation,
    runtime_validation,
    lock_validation,
    mountpoint_validation,
    mount_namespace,
    private_propagation,
    detached_propagation,
    runtime_pin,
    recursive_bind,
    bind_validation,
    parent_liveness,
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
    RuntimeReplaced,
    LockReplaced,
    MountpointReplaced,
    NamespaceUnavailable,
    PipeFailed,
    ForkFailed,
    SignalSetupFailed,
    WaitFailed,
    SystemCallFailed,
    InvalidProjection,
};

pub fn platformSupported(os: std.Target.Os.Tag) bool {
    return os == .linux;
}

pub const SignalMaskGuard = struct {
    previous: linux.sigset_t,
    active: bool = true,

    pub fn restore(self: *SignalMaskGuard) Error!void {
        if (!self.active) return;
        if (linux.errno(linux.sigprocmask(
            linux.SIG.SETMASK,
            &self.previous,
            null,
        )) != .SUCCESS) return error.SignalSetupFailed;
        self.active = false;
    }
};

pub const testing = struct {
    pub fn forkProcess() Error!i32 {
        if (!builtin.is_test) return error.ForkFailed;
        const forked = linux.fork();
        if (linux.errno(forked) != .SUCCESS) return error.ForkFailed;
        return @intCast(forked);
    }

    pub fn replaceMountNamespace() Error!void {
        if (!builtin.is_test) return error.NamespaceUnavailable;
        if (linux.errno(linux.unshare(linux.CLONE.NEWNS)) != .SUCCESS)
            return error.NamespaceUnavailable;
    }

    pub fn verifyProjection(projection: *const Projection) !void {
        if (!builtin.is_test) return error.InvalidProjection;
        const root_fd = try openDirectoryAbsolute(logical_root_path);
        defer closeRaw(root_fd);
        try projection.validateRoot(logical_root_path, root_fd);
        try std.testing.expectError(error.InvalidProjection, projection.validateRoot("/", root_fd));
        try std.testing.expectError(error.InvalidProjection, projection.validateRoot(logical_root_path ++ "/.", root_fd));
        const host_fd = try openDirectoryAbsolute("/");
        defer closeRaw(host_fd);
        try std.testing.expectError(error.RootReplaced, projection.validateRoot(logical_root_path, host_fd));
        const foreign_fd = try openDirectoryAbsolute(runtime_directory_path);
        defer closeRaw(foreign_fd);
        try std.testing.expectError(error.RootReplaced, projection.validateRoot(logical_root_path, foreign_fd));

        for ([_]bool{ false, true }) |nested_pid_namespace| {
            if (nested_pid_namespace and linux.errno(linux.unshare(linux.CLONE.NEWPID)) != .SUCCESS)
                return error.NamespaceUnavailable;
            const child = try forkProcess();
            if (child == 0) {
                if (nested_pid_namespace and linux.getpid() != 1) linux.exit_group(2);
                projection.validateRoot(logical_root_path, root_fd) catch |err|
                    linux.exit_group(if (err == error.InvalidProjection) 0 else 3);
                linux.exit_group(4);
            }
            const result = termination(try reapBlocking(child));
            if (result != .exited or result.exited != 0) return error.InvalidProjection;
        }
        try projection.validateRoot(logical_root_path, root_fd);
    }
};

/// Blocks every signal supervised by `run` in the calling thread. Threads
/// created while this guard is active inherit the blocked mask.
pub fn blockWatchedSignals() Error!SignalMaskGuard {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    var watched = interruptSet();
    var previous: linux.sigset_t = undefined;
    if (linux.errno(linux.sigprocmask(
        linux.SIG.BLOCK,
        &watched,
        &previous,
    )) != .SUCCESS) return error.SignalSetupFailed;
    return .{ .previous = previous };
}

/// Runs `request.child` with the host root available only at
/// `logical_root_path`.  The callback is trusted product code: it must not
/// change signal masks or attempt to join another PID or mount namespace.
pub fn run(request: Request) Error!Result {
    var signal_guard = try blockWatchedSignals();
    const result = runSignalsBlocked(request, &signal_guard) catch |err| {
        signal_guard.restore() catch return error.SignalSetupFailed;
        return err;
    };
    try signal_guard.restore();
    return result;
}

/// Runs with the watched signals already blocked by `blockWatchedSignals`.
/// The guard's original mask is restored in the privileged workload so relayed
/// signals keep their ordinary disposition there. The caller owns restoration.
pub fn runSignalsBlocked(
    request: Request,
    signal_guard: *const SignalMaskGuard,
) Error!Result {
    return runInvocation(.{
        .context = request.context,
        .callback = .{ .ordinary = request.child },
        .termination_grace_ms = request.termination_grace_ms,
    }, signal_guard);
}

/// Issues projection authority only inside the supervised namespace callback.
/// The authority must not escape that callback or be serialized for recovery.
pub fn runProjected(request: ProjectedRequest) Error!Result {
    var signal_guard = try blockWatchedSignals();
    const result = runProjectedSignalsBlocked(request, &signal_guard) catch |err| {
        signal_guard.restore() catch return error.SignalSetupFailed;
        return err;
    };
    try signal_guard.restore();
    return result;
}

pub fn runProjectedSignalsBlocked(
    request: ProjectedRequest,
    signal_guard: *const SignalMaskGuard,
) Error!Result {
    return runInvocation(.{
        .context = request.context,
        .callback = .{ .projected = request.child },
        .termination_grace_ms = request.termination_grace_ms,
    }, signal_guard);
}

fn runInvocation(
    request: Invocation,
    signal_guard: *const SignalMaskGuard,
) Error!Result {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
    if (!signal_guard.active) return error.SignalSetupFailed;
    var current_mask: linux.sigset_t = undefined;
    if (linux.errno(linux.sigprocmask(
        linux.SIG.SETMASK,
        null,
        &current_mask,
    )) != .SUCCESS) return error.SignalSetupFailed;
    inline for ([_]linux.SIG{ .INT, .QUIT, .HUP, .TERM }) |signal|
        if (!linux.sigismember(&current_mask, signal))
            return error.SignalSetupFailed;
    if (linux.geteuid() != 0) return error.NotPrivileged;

    var pinned = try PinnedPaths.open();
    defer pinned.close();

    var watched = interruptSet();

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

    var control_pipe: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&control_pipe, .{
        .CLOEXEC = true,
        .NONBLOCK = true,
    })) != .SUCCESS) return error.PipeFailed;
    defer {
        closeFd(&control_pipe[0]);
        closeFd(&control_pipe[1]);
    }

    const forked = linux.fork();
    switch (linux.errno(forked)) {
        .SUCCESS => {},
        else => return error.ForkFailed,
    }
    const pid: i32 = @intCast(forked);
    if (pid == 0)
        supervisorMain(
            request,
            pinned,
            signal_guard.previous,
            signal_fd,
            report_pipe,
            control_pipe,
        );

    closeFd(&report_pipe[1]);
    closeFd(&control_pipe[0]);
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

    fn samePinnedEntry(self: Identity, other: Identity) bool {
        return self.sameEntry(other) and
            self.uid == other.uid and self.gid == other.gid and
            self.mode == other.mode and self.kind == other.kind;
    }

    fn eql(self: Identity, other: Identity) bool {
        return self.samePinnedEntry(other) and self.mount_id == other.mount_id;
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
    lock: Identity,

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
        if (!privateRootFile(lock_identity) or
            lock_identity.mount_id != runtime.mount_id)
            return error.UnsafeLockFile;
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
            .lock = lock_identity,
        };
    }

    fn close(self: *PinnedPaths) void {
        closeFd(&self.mountpoint_fd);
        closeFd(&self.lock_fd);
        closeFd(&self.runtime_fd);
        closeFd(&self.source_fd);
    }

    fn closeNonLock(self: *PinnedPaths) void {
        closeFd(&self.mountpoint_fd);
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
    request: Invocation,
    pinned: PinnedPaths,
    old_mask: linux.sigset_t,
    parent_signal_fd: i32,
    report_pipe: [2]i32,
    control_pipe: [2]i32,
) noreturn {
    closeRaw(parent_signal_fd);
    closeRaw(report_pipe[0]);
    closeRaw(control_pipe[1]);
    _ = linux.setpgid(0, 0);
    ignoreBrokenPipe();

    var owned = pinned;
    var runtime_pinned = false;
    var root_mounted = false;
    if (!parentAlive(control_pipe[0]))
        parentDied(root_mounted, runtime_pinned);
    validateOriginalSource(owned) catch |err|
        childFail(report_pipe[1], .source_validation, errorNumber(err));
    validateUnpinnedPaths(owned) catch |err|
        childFail(report_pipe[1], stageForPathError(err), errorNumber(err));

    var runtime_tree = openTreeClone(owned.runtime_fd, false) catch |err|
        childFail(report_pipe[1], .runtime_pin, errorNumber(err));
    makeDetachedPrivate(runtime_tree) catch |err| {
        closeFd(&runtime_tree);
        childFail(report_pipe[1], .detached_propagation, errorNumber(err));
    };
    var source_tree = openTreeClone(owned.source_fd, true) catch |err| {
        closeFd(&runtime_tree);
        childFail(report_pipe[1], .recursive_bind, errorNumber(err));
    };
    makeDetachedPrivate(source_tree) catch |err| {
        closeFd(&source_tree);
        closeFd(&runtime_tree);
        childFail(report_pipe[1], .detached_propagation, errorNumber(err));
    };
    if (!parentAlive(control_pipe[0]))
        parentDied(root_mounted, runtime_pinned);

    switch (linux.errno(linux.unshare(linux.CLONE.NEWNS))) {
        .SUCCESS => {},
        else => |err| childFail(report_pipe[1], .mount_namespace, @intFromEnum(err)),
    }
    switch (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0))) {
        .SUCCESS => {},
        else => |err| childFail(report_pipe[1], .private_propagation, @intFromEnum(err)),
    }

    var namespace_targets = openNamespaceTargets(owned) catch |err|
        namespaceFail(
            report_pipe[1],
            stageForPathError(err),
            errorNumber(err),
            root_mounted,
            runtime_pinned,
        );
    switch (linux.errno(linux.move_mount(
        runtime_tree,
        "",
        namespace_targets.runtime_fd,
        "",
        descriptor_move,
    ))) {
        .SUCCESS => {
            closeFd(&runtime_tree);
            runtime_pinned = true;
        },
        else => |err| {
            namespace_targets.close();
            closeFd(&runtime_tree);
            closeFd(&source_tree);
            childFail(report_pipe[1], .runtime_pin, @intFromEnum(err));
        },
    }
    const namespace_source = namespace_targets.source;
    const namespace_runtime = namespace_targets.runtime;
    namespace_targets.close();
    if (!parentAlive(control_pipe[0]))
        parentDied(root_mounted, runtime_pinned);

    var attached = openAttachedRuntime(owned, namespace_runtime) catch |err|
        namespaceFail(
            report_pipe[1],
            stageForPathError(err),
            errorNumber(err),
            root_mounted,
            runtime_pinned,
        );
    switch (linux.errno(linux.move_mount(
        source_tree,
        "",
        attached.mountpoint_fd,
        "",
        descriptor_move,
    ))) {
        .SUCCESS => {
            closeFd(&source_tree);
            root_mounted = true;
        },
        else => |err| {
            attached.close();
            closeFd(&source_tree);
            namespaceFail(
                report_pipe[1],
                .recursive_bind,
                @intFromEnum(err),
                root_mounted,
                runtime_pinned,
            );
        },
    }
    const mounted_root = identityAbsolute(logical_root_path) catch |err| {
        attached.close();
        namespaceFail(
            report_pipe[1],
            .bind_validation,
            errorNumber(err),
            root_mounted,
            runtime_pinned,
        );
    };
    if (!mounted_root.samePinnedEntry(owned.source) or
        mounted_root.mount_id == namespace_source.mount_id or
        mounted_root.mount_id == attached.runtime.mount_id)
    {
        attached.close();
        namespaceFail(
            report_pipe[1],
            .bind_validation,
            0,
            root_mounted,
            runtime_pinned,
        );
    }
    const expected: NamespaceIdentity = .{
        .source = namespace_source,
        .runtime = attached.runtime,
        .mounted_root = mounted_root,
    };
    attached.close();
    validateCallbackPaths(owned, expected) catch |err|
        namespaceFail(
            report_pipe[1],
            stageForPathError(err),
            errorNumber(err),
            root_mounted,
            runtime_pinned,
        );
    if (!parentAlive(control_pipe[0]))
        parentDied(root_mounted, runtime_pinned);
    owned.closeNonLock();

    switch (linux.errno(linux.unshare(linux.CLONE.NEWPID))) {
        .SUCCESS => {},
        else => |err| {
            namespaceFail(
                report_pipe[1],
                .pid_namespace,
                @intFromEnum(err),
                root_mounted,
                runtime_pinned,
            );
        },
    }

    const worker_raw = linux.fork();
    switch (linux.errno(worker_raw)) {
        .SUCCESS => {},
        else => |err| {
            namespaceFail(
                report_pipe[1],
                .workload_fork,
                @intFromEnum(err),
                root_mounted,
                runtime_pinned,
            );
        },
    }
    const worker: i32 = @intCast(worker_raw);
    if (worker == 0)
        workloadMain(request, old_mask, report_pipe[1], control_pipe[0], owned.lock_fd, owned.lock, expected);

    const supervised = superviseWorkload(
        worker,
        request.termination_grace_ms,
        control_pipe[0],
    ) catch {
        _ = linux.kill(worker, .KILL);
        _ = reapBlocking(worker) catch null;
        namespaceFail(
            report_pipe[1],
            .cleanup,
            0,
            root_mounted,
            runtime_pinned,
        );
    };
    // Once namespace PID 1 has exited, Linux has killed every other process in
    // that PID namespace.  No descendant can retain this mount namespace.
    if (cleanupNamespaceStrict()) |errno|
        childFail(report_pipe[1], .cleanup, errno);
    closeRaw(control_pipe[0]);
    if (supervised.parent_died) {
        closeRaw(report_pipe[1]);
        linux.exit_group(125);
    }
    closeRaw(report_pipe[1]);
    exitStatus(supervised.status);
}

fn workloadMain(
    request: Invocation,
    old_mask: linux.sigset_t,
    report_fd: i32,
    control_fd: i32,
    lock_fd: i32,
    lock: Identity,
    expected: NamespaceIdentity,
) noreturn {
    closeRaw(control_fd);
    closeRaw(lock_fd);
    _ = linux.sigprocmask(linux.SIG.SETMASK, &old_mask, null);
    resetInterruptActions();
    const code = invokeCallback(request, lock, expected) catch |err| {
        if (builtin.is_test)
            std.debug.print("live-root callback failed: {s}\n", .{@errorName(err)});
        childFail(report_fd, .callback, 0);
    };
    closeRaw(report_fd);
    linux.exit_group(code);
}

fn invokeCallback(request: Invocation, lock: Identity, expected: NamespaceIdentity) !u8 {
    switch (request.callback) {
        .ordinary => |child| return child(request.context, logical_root_path),
        .projected => |child| {
            if (linux.getpid() != 1) return error.InvalidProjection;
            try validateProjectedPaths(lock, expected);
            const authority: ProjectionAuthority = .{
                .process_id = @intCast(linux.getpid()),
                .pid_namespace = try namespaceIdentity("/proc/self/ns/pid", linux.CLONE.NEWPID),
                .mount_namespace = try namespaceIdentity("/proc/self/ns/mnt", linux.CLONE.NEWNS),
                .lock = lock,
                .expected = expected,
            };
            return child(request.context, @ptrCast(&authority));
        },
    }
}

fn validateOriginalSource(pinned: PinnedPaths) Error!void {
    const descriptor = try identityOf(pinned.source_fd);
    const named_fd = try openDirectoryAbsolute("/");
    defer _ = linux.close(named_fd);
    const named = try identityOf(named_fd);
    if (!descriptor.eql(pinned.source) or !named.eql(pinned.source))
        return error.RootReplaced;
}

fn validateUnpinnedPaths(pinned: PinnedPaths) Error!void {
    const runtime = try identityAbsolute(runtime_directory_path);
    if (!runtime.eql(pinned.runtime)) return error.RuntimeReplaced;
    const lock = try identityAbsolute(lock_path);
    if (!lock.eql(pinned.lock)) return error.LockReplaced;
    const mountpoint = try identityAbsolute(logical_root_path);
    if (!mountpoint.eql(pinned.mountpoint)) return error.MountpointReplaced;
}

const NamespaceTargets = struct {
    runtime_fd: i32,
    mountpoint_fd: i32,
    source: Identity,
    runtime: Identity,

    fn close(self: *NamespaceTargets) void {
        closeFd(&self.mountpoint_fd);
        closeFd(&self.runtime_fd);
    }
};

fn openNamespaceTargets(pinned: PinnedPaths) Error!NamespaceTargets {
    const source = try identityAbsolute("/");
    if (!namespaceCloneMatches(pinned.source, source))
        return error.RootReplaced;
    const runtime = try identityAbsolute(runtime_directory_path);
    if (!namespaceCloneMatches(pinned.runtime, runtime))
        return error.RuntimeReplaced;
    const lock = try identityAbsolute(lock_path);
    if (!lock.samePinnedEntry(pinned.lock) or
        lock.link_count != 1 or lock.mount_id != runtime.mount_id)
        return error.LockReplaced;
    const mountpoint = try identityAbsolute(logical_root_path);
    if (!mountpoint.samePinnedEntry(pinned.mountpoint) or
        mountpoint.mount_id != runtime.mount_id)
        return error.MountpointReplaced;

    const runtime_fd = try openDirectoryAbsolute(runtime_directory_path);
    errdefer closeRaw(runtime_fd);
    if (!(try identityOf(runtime_fd)).eql(runtime)) return error.RuntimeReplaced;
    const mountpoint_fd = try openDirectoryAt(runtime_fd, "system-root");
    errdefer closeRaw(mountpoint_fd);
    if (!(try identityOf(mountpoint_fd)).eql(mountpoint))
        return error.MountpointReplaced;
    return .{
        .runtime_fd = runtime_fd,
        .mountpoint_fd = mountpoint_fd,
        .source = source,
        .runtime = runtime,
    };
}

const AttachedRuntime = struct {
    runtime_fd: i32,
    mountpoint_fd: i32,
    runtime: Identity,

    fn close(self: *AttachedRuntime) void {
        closeFd(&self.mountpoint_fd);
        closeFd(&self.runtime_fd);
    }
};

fn openAttachedRuntime(
    pinned: PinnedPaths,
    previous_runtime: Identity,
) Error!AttachedRuntime {
    const runtime = try identityAbsolute(runtime_directory_path);
    if (!attachedMountMatches(pinned.runtime, previous_runtime, runtime))
        return error.RuntimeReplaced;
    const lock = try identityAbsolute(lock_path);
    if (!lock.samePinnedEntry(pinned.lock) or
        lock.link_count != 1 or lock.mount_id != runtime.mount_id)
        return error.LockReplaced;
    const mountpoint = try identityAbsolute(logical_root_path);
    if (!mountpoint.samePinnedEntry(pinned.mountpoint) or
        mountpoint.mount_id != runtime.mount_id)
        return error.MountpointReplaced;

    const runtime_fd = try openDirectoryAbsolute(runtime_directory_path);
    errdefer closeRaw(runtime_fd);
    if (!(try identityOf(runtime_fd)).eql(runtime)) return error.RuntimeReplaced;
    const mountpoint_fd = try openDirectoryAt(runtime_fd, "system-root");
    errdefer closeRaw(mountpoint_fd);
    if (!(try identityOf(mountpoint_fd)).eql(mountpoint))
        return error.MountpointReplaced;
    return .{
        .runtime_fd = runtime_fd,
        .mountpoint_fd = mountpoint_fd,
        .runtime = runtime,
    };
}

fn namespaceCloneMatches(original: Identity, current: Identity) bool {
    return current.samePinnedEntry(original) and
        current.mount_id != original.mount_id;
}

fn attachedMountMatches(
    original: Identity,
    namespace_clone: Identity,
    attached: Identity,
) bool {
    return attached.samePinnedEntry(original) and
        attached.mount_id != original.mount_id and
        attached.mount_id != namespace_clone.mount_id;
}

const NamespaceIdentity = struct {
    source: Identity,
    runtime: Identity,
    mounted_root: Identity,
};

const ProjectionAuthority = struct {
    process_id: i32,
    pid_namespace: Identity,
    mount_namespace: Identity,
    lock: Identity,
    expected: NamespaceIdentity,
};

fn namespaceIdentity(path: [*:0]const u8, kind: u32) Error!Identity {
    // These intentional procfs magic-link opens must resolve to actual nsfs
    // descriptors of the requested type, not files in an untrusted source root.
    const fd = try fdResult(linux.open(path, .{ .CLOEXEC = true }, 0));
    defer closeRaw(fd);
    const ns_get_nstype = 0xb703;
    if (linux.ioctl(fd, ns_get_nstype, 0) != kind)
        return error.InvalidProjection;
    return identityOf(fd);
}

fn validateCallbackPaths(pinned: PinnedPaths, expected: NamespaceIdentity) Error!void {
    return validateProjectedPaths(pinned.lock, expected);
}

fn validateProjectedPaths(expected_lock: Identity, expected: NamespaceIdentity) Error!void {
    const source = try identityAbsolute("/");
    if (!source.eql(expected.source)) return error.RootReplaced;
    const runtime = try identityAbsolute(runtime_directory_path);
    if (!runtime.eql(expected.runtime)) return error.RuntimeReplaced;
    const lock = try identityAbsolute(lock_path);
    if (!lock.samePinnedEntry(expected_lock) or
        lock.link_count != 1 or lock.mount_id != runtime.mount_id)
        return error.LockReplaced;
    const mounted = try identityAbsolute(logical_root_path);
    if (!mounted.eql(expected.mounted_root)) return error.RootReplaced;
}

fn identityAbsolute(path: [*:0]const u8) Error!Identity {
    return identityAt(linux.AT.FDCWD, path);
}

const open_tree_clone: u32 = 1;
const open_tree_cloexec: u32 = 1 << @bitOffsetOf(linux.O, "CLOEXEC");

fn openTreeClone(fd: i32, recursive: bool) Error!i32 {
    return fdResult(cloneMountDescriptor(fd, recursive));
}

/// Allocation-free descriptor mount ABI shared by the audited child boundaries.
pub fn cloneMountDescriptor(fd: i32, recursive: bool) usize {
    const flags = open_tree_clone | open_tree_cloexec | linux.AT.EMPTY_PATH |
        @as(u32, if (recursive) linux.AT.RECURSIVE else 0);
    return linux.syscall3(
        .open_tree,
        @bitCast(@as(isize, fd)),
        @intFromPtr(@as([*:0]const u8, "")),
        flags,
    );
}

pub const MountAttribute = extern struct {
    attr_set: u64 = 0,
    attr_clear: u64 = 0,
    propagation: u64 = linux.MS.PRIVATE,
    user_namespace_fd: u64 = 0,
};

pub fn setMountAttributes(fd: i32, recursive: bool, attribute: *const MountAttribute) usize {
    return linux.syscall5(
        .mount_setattr,
        @bitCast(@as(isize, fd)),
        @intFromPtr(@as([*:0]const u8, "")),
        linux.AT.EMPTY_PATH | @as(u32, if (recursive) linux.AT.RECURSIVE else 0),
        @intFromPtr(attribute),
        @sizeOf(MountAttribute),
    );
}

fn makeDetachedPrivate(fd: i32) Error!void {
    const attribute: MountAttribute = .{};
    const raw = setMountAttributes(fd, true, &attribute);
    switch (linux.errno(raw)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.NotPrivileged,
        else => return error.SystemCallFailed,
    }
}

const descriptor_move: linux.MOVE_MOUNT = .{
    .F_SYMLINKS = false,
    .F_AUTOMOUNTS = false,
    .F_EMPTY_PATH = true,
    ._8 = false,
    .T_SYMLINKS = false,
    .T_AUTOMOUNTS = false,
    .T_EMPTY_PATH = true,
    ._80 = false,
    .SET_GROUP = false,
};

fn cleanupNamespaceStrict() ?u32 {
    switch (linux.errno(linux.umount2(
        logical_root_path,
        linux.MNT.DETACH | linux.UMOUNT_NOFOLLOW,
    ))) {
        .SUCCESS => {},
        else => |err| return @intFromEnum(err),
    }
    switch (linux.errno(linux.umount2(
        runtime_directory_path,
        linux.MNT.DETACH | linux.UMOUNT_NOFOLLOW,
    ))) {
        .SUCCESS => {},
        else => |err| return @intFromEnum(err),
    }
    return null;
}

fn cleanupNamespaceBestEffort(root_mounted: bool, runtime_pinned: bool) void {
    if (root_mounted)
        _ = linux.umount2(
            logical_root_path,
            linux.MNT.DETACH | linux.UMOUNT_NOFOLLOW,
        );
    if (runtime_pinned)
        _ = linux.umount2(
            runtime_directory_path,
            linux.MNT.DETACH | linux.UMOUNT_NOFOLLOW,
        );
}

fn namespaceFail(
    report_fd: i32,
    stage: SetupStage,
    errno: u32,
    root_mounted: bool,
    runtime_pinned: bool,
) noreturn {
    cleanupNamespaceBestEffort(root_mounted, runtime_pinned);
    childFail(report_fd, stage, errno);
}

fn parentDied(root_mounted: bool, runtime_pinned: bool) noreturn {
    cleanupNamespaceBestEffort(root_mounted, runtime_pinned);
    linux.exit_group(125);
}

fn stageForPathError(err: anyerror) SetupStage {
    return switch (err) {
        error.RuntimeReplaced => .runtime_validation,
        error.LockReplaced, error.UnsafeLockFile => .lock_validation,
        error.MountpointReplaced, error.UnsafeMountpoint, error.ActiveHostMount => .mountpoint_validation,
        error.RootReplaced => .bind_validation,
        else => .runtime_validation,
    };
}

fn ignoreBrokenPipe() void {
    const action: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.PIPE, &action, null);
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

const WorkloadResult = struct {
    status: u32,
    parent_died: bool,
};

fn superviseWorkload(pid: i32, grace_ms: u64, control_fd: i32) Error!WorkloadResult {
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
        if (!parentAlive(control_fd)) {
            _ = linux.kill(pid, .KILL);
            return .{
                .status = try reapBlocking(pid),
                .parent_died = true,
            };
        }
        if (readSignal(signal_fd)) |signal| {
            _ = linux.kill(pid, signal);
            if (!awaitExit(pid, grace_ms)) _ = linux.kill(pid, .KILL);
        }
        sleepMilliseconds(5);
    }
    return .{
        .status = try reapBlocking(pid),
        .parent_died = false,
    };
}

fn parentAlive(control_fd: i32) bool {
    var byte: [1]u8 = undefined;
    while (true) {
        const raw = linux.read(control_fd, &byte, byte.len);
        switch (linux.errno(raw)) {
            .SUCCESS => return raw != 0,
            .AGAIN => return true,
            .INTR => continue,
            else => return false,
        }
    }
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
        linux.exit_group(@intCast(128 + @intFromEnum(signal)));
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
    try operations.validateUnpinnedPaths();
    try operations.cloneRuntime();
    try operations.makeRuntimeTreePrivate();
    try operations.cloneSource();
    try operations.makeSourceTreePrivate();
    try operations.unshareMount();
    try operations.makePrivate();
    try operations.openNamespaceTargets();
    try operations.attachRuntime();
    errdefer operations.unpinRuntime();
    try operations.openAttachedRuntime();
    try operations.attachRoot();
    errdefer operations.unmountRoot();
    try operations.validateCallbackPaths();
}

const Event = enum {
    source,
    runtime,
    lock,
    mountpoint,
    clone_runtime,
    private_runtime_tree,
    clone_source,
    private_source_tree,
    unshare,
    private,
    attach_runtime,
    attach_root,
    callback_validation,
    child,
    unmount_root,
    unpin_runtime,
    parent_eof,
    unlock,
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
    replace_runtime_on_check: ?usize = null,
    replace_lock_on_check: ?usize = null,
    replace_mountpoint_on_check: ?usize = null,
    source_calls: usize = 0,
    path_checks: usize = 0,
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

    fn validatePaths(self: *RecordingOperations, callback: bool) !void {
        self.path_checks += 1;
        try self.record(.runtime);
        if (self.replace_runtime_on_check == self.path_checks)
            return error.RuntimeReplaced;
        try self.record(.lock);
        if (self.replace_lock_on_check == self.path_checks)
            return error.LockReplaced;
        try self.record(.mountpoint);
        if (self.replace_mountpoint_on_check == self.path_checks)
            return error.MountpointReplaced;
        if (callback) try self.record(.callback_validation);
    }

    fn validateUnpinnedPaths(self: *RecordingOperations) !void {
        try self.validatePaths(false);
    }

    fn cloneRuntime(self: *RecordingOperations) !void {
        try self.record(.clone_runtime);
    }

    fn cloneSource(self: *RecordingOperations) !void {
        try self.record(.clone_source);
    }

    fn makeRuntimeTreePrivate(self: *RecordingOperations) !void {
        try self.record(.private_runtime_tree);
    }

    fn makeSourceTreePrivate(self: *RecordingOperations) !void {
        try self.record(.private_source_tree);
    }

    fn openNamespaceTargets(self: *RecordingOperations) !void {
        try self.validateSource();
        try self.validatePaths(false);
    }

    fn openAttachedRuntime(self: *RecordingOperations) !void {
        try self.validatePaths(false);
    }

    fn validateCallbackPaths(self: *RecordingOperations) !void {
        try self.validateSource();
        try self.validatePaths(true);
    }

    fn unshareMount(self: *RecordingOperations) !void {
        try self.record(.unshare);
    }

    fn makePrivate(self: *RecordingOperations) !void {
        try self.record(.private);
    }

    fn attachRuntime(self: *RecordingOperations) !void {
        try self.record(.attach_runtime);
    }

    fn attachRoot(self: *RecordingOperations) !void {
        try self.record(.attach_root);
    }

    fn runChild(self: *RecordingOperations) !u8 {
        try self.record(.child);
        if (self.fail_child) return error.ChildFailed;
        return 0;
    }

    fn unmountRoot(self: *RecordingOperations) void {
        self.events[self.event_count] = .unmount_root;
        self.event_count += 1;
    }

    fn unpinRuntime(self: *RecordingOperations) void {
        self.events[self.event_count] = .unpin_runtime;
        self.event_count += 1;
    }
};

fn expectEvents(expected: []const Event, operations: *const RecordingOperations) !void {
    try std.testing.expectEqualSlices(Event, expected, operations.events[0..operations.event_count]);
}

fn exerciseLifecycle(operations: anytype) !u8 {
    try enter(operations);
    defer {
        operations.unmountRoot();
        operations.unpinRuntime();
    }
    return operations.runChild();
}

const RecordingSupervisor = struct {
    events: [8]Event = undefined,
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

    fn parentEof(self: *RecordingSupervisor) void {
        self.append(.parent_eof);
    }

    fn unmountRoot(self: *RecordingSupervisor) void {
        self.append(.unmount_root);
    }

    fn unpinRuntime(self: *RecordingSupervisor) void {
        self.append(.unpin_runtime);
    }

    fn unlock(self: *RecordingSupervisor) void {
        self.append(.unlock);
    }
};

fn finishInterrupted(operations: anytype) void {
    operations.signal();
    if (!operations.awaitExit()) operations.kill();
    operations.reap();
}

fn finishParentDeath(operations: anytype) void {
    operations.parentEof();
    operations.kill();
    operations.reap();
    operations.unmountRoot();
    operations.unpinRuntime();
    operations.unlock();
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
            .runtime,
            .lock,
            .mountpoint,
            .clone_runtime,
            .private_runtime_tree,
            .clone_source,
            .private_source_tree,
            .unshare,
            .private,
            .source,
            .runtime,
            .lock,
            .mountpoint,
            .attach_runtime,
            .runtime,
            .lock,
            .mountpoint,
            .attach_root,
            .source,
            .runtime,
            .lock,
            .mountpoint,
            .callback_validation,
        },
        &operations,
    );
}

test "live_root.test.cleanup covers every setup failure boundary" {
    for (1..25) |failure| {
        var operations: RecordingOperations = .{ .fail_call = failure };
        try std.testing.expectError(error.Injected, enter(&operations));
        if (failure >= 20) {
            try std.testing.expectEqual(
                Event.unmount_root,
                operations.events[operations.event_count - 2],
            );
            try std.testing.expectEqual(
                Event.unpin_runtime,
                operations.events[operations.event_count - 1],
            );
        } else if (failure >= 16) {
            try std.testing.expectEqual(
                Event.unpin_runtime,
                operations.events[operations.event_count - 1],
            );
        }
    }
}

test "live_root.test.normal and callback exits both unmount" {
    var success: RecordingOperations = .{};
    try std.testing.expectEqual(@as(u8, 0), try exerciseLifecycle(&success));
    try std.testing.expectEqual(
        Event.unmount_root,
        success.events[success.event_count - 2],
    );
    try std.testing.expectEqual(
        Event.unpin_runtime,
        success.events[success.event_count - 1],
    );

    var failure: RecordingOperations = .{ .fail_child = true };
    try std.testing.expectError(error.ChildFailed, exerciseLifecycle(&failure));
    try std.testing.expectEqual(
        Event.unmount_root,
        failure.events[failure.event_count - 2],
    );
    try std.testing.expectEqual(
        Event.unpin_runtime,
        failure.events[failure.event_count - 1],
    );
}

test "live_root.test.root replacement fails before mounting" {
    var operations: RecordingOperations = .{ .replace_root_on_source_call = 1 };
    try std.testing.expectError(error.RootReplaced, enter(&operations));
    try expectEvents(&.{.source}, &operations);

    var after_unshare: RecordingOperations = .{ .replace_root_on_source_call = 2 };
    try std.testing.expectError(error.RootReplaced, enter(&after_unshare));
    try expectEvents(
        &.{
            .source,
            .runtime,
            .lock,
            .mountpoint,
            .clone_runtime,
            .private_runtime_tree,
            .clone_source,
            .private_source_tree,
            .unshare,
            .private,
            .source,
        },
        &after_unshare,
    );
}

test "live_root.test.mount identities transition across unshare and attachment" {
    const original: Identity = .{
        .device = 4,
        .inode = 20,
        .mount_id = 100,
        .uid = 0,
        .gid = 0,
        .mode = linux.S.IFDIR | 0o700,
        .kind = linux.S.IFDIR,
        .link_count = 2,
    };
    var namespace_clone = original;
    namespace_clone.mount_id = 101;
    try std.testing.expect(namespaceCloneMatches(original, namespace_clone));
    try std.testing.expect(!namespaceCloneMatches(original, original));

    var attached = original;
    attached.mount_id = 102;
    try std.testing.expect(attachedMountMatches(original, namespace_clone, attached));
    try std.testing.expect(!attachedMountMatches(original, namespace_clone, namespace_clone));

    var replacement = namespace_clone;
    replacement.inode += 1;
    try std.testing.expect(!namespaceCloneMatches(original, replacement));
}

test "live_root.test.runtime replacement fails across attach and callback boundaries" {
    var before_attach: RecordingOperations = .{ .replace_runtime_on_check = 3 };
    try std.testing.expectError(error.RuntimeReplaced, enter(&before_attach));
    try std.testing.expectEqual(
        Event.unpin_runtime,
        before_attach.events[before_attach.event_count - 1],
    );

    var before_callback: RecordingOperations = .{ .replace_runtime_on_check = 4 };
    try std.testing.expectError(error.RuntimeReplaced, enter(&before_callback));
    try std.testing.expectEqual(
        Event.unmount_root,
        before_callback.events[before_callback.event_count - 2],
    );
    try std.testing.expectEqual(
        Event.unpin_runtime,
        before_callback.events[before_callback.event_count - 1],
    );
}

test "live_root.test.mountpoint replacement fails across attach and callback boundaries" {
    var operations: RecordingOperations = .{ .replace_mountpoint_on_check = 1 };
    try std.testing.expectError(error.MountpointReplaced, enter(&operations));

    var before_attach: RecordingOperations = .{ .replace_mountpoint_on_check = 3 };
    try std.testing.expectError(error.MountpointReplaced, enter(&before_attach));
    try std.testing.expectEqual(
        Event.unpin_runtime,
        before_attach.events[before_attach.event_count - 1],
    );

    var before_callback: RecordingOperations = .{ .replace_mountpoint_on_check = 4 };
    try std.testing.expectError(error.MountpointReplaced, enter(&before_callback));
    try std.testing.expectEqual(
        Event.unmount_root,
        before_callback.events[before_callback.event_count - 2],
    );
    try std.testing.expectEqual(
        Event.unpin_runtime,
        before_callback.events[before_callback.event_count - 1],
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

test "live_root.test.watched signal guard is inherited and restores caller mask" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var original: linux.sigset_t = undefined;
    try std.testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.sigprocmask(
            linux.SIG.SETMASK,
            null,
            &original,
        )),
    );
    var guard = try blockWatchedSignals();
    var inherited: linux.sigset_t = undefined;
    const thread = try std.Thread.spawn(.{}, struct {
        fn readMask(output: *linux.sigset_t) void {
            _ = linux.sigprocmask(linux.SIG.SETMASK, null, output);
        }
    }.readMask, .{&inherited});
    thread.join();
    inline for ([_]linux.SIG{ .INT, .QUIT, .HUP, .TERM }) |signal|
        try std.testing.expect(linux.sigismember(&inherited, signal));
    try guard.restore();
    var restored: linux.sigset_t = undefined;
    try std.testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.sigprocmask(
            linux.SIG.SETMASK,
            null,
            &restored,
        )),
    );
    try std.testing.expectEqualSlices(
        u8,
        std.mem.asBytes(&original),
        std.mem.asBytes(&restored),
    );
    try std.testing.expectError(
        error.SignalSetupFailed,
        runSignalsBlocked(.{ .child = integrationChild }, &guard),
    );
    try std.testing.expectError(
        error.SignalSetupFailed,
        runProjectedSignalsBlocked(.{ .child = projectedIntegrationChild }, &guard),
    );
}

test "live_root.test.parent EOF kills and reaps before mount and lock cleanup" {
    var operations: RecordingSupervisor = .{};
    finishParentDeath(&operations);
    try std.testing.expectEqualSlices(
        Event,
        &.{
            .parent_eof,
            .kill,
            .reap,
            .unmount_root,
            .unpin_runtime,
            .unlock,
        },
        operations.events[0..operations.count],
    );
}

test "live_root.test.control pipe EOF detects parent death without a signal race" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var control: [2]i32 = undefined;
    try std.testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.pipe2(&control, .{ .CLOEXEC = true, .NONBLOCK = true })),
    );
    defer {
        closeFd(&control[0]);
        closeFd(&control[1]);
    }
    try std.testing.expect(parentAlive(control[0]));
    closeFd(&control[1]);
    try std.testing.expect(!parentAlive(control[0]));
}

test "live_root.test.projection namespace identities require real namespace descriptors" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    _ = try namespaceIdentity("/proc/self/ns/pid", linux.CLONE.NEWPID);
    _ = try namespaceIdentity("/proc/self/ns/mnt", linux.CLONE.NEWNS);
    try std.testing.expectError(error.InvalidProjection, namespaceIdentity("/proc/self/ns/mnt", linux.CLONE.NEWPID));
    try std.testing.expectError(error.InvalidProjection, namespaceIdentity("/", linux.CLONE.NEWPID));
}

fn integrationChild(_: ?*anyopaque, install_root: []const u8) anyerror!u8 {
    if (!std.mem.eql(u8, install_root, logical_root_path)) return error.BadRoot;
    return 0;
}

fn projectedIntegrationChild(_: ?*anyopaque, projection: *const Projection) anyerror!u8 {
    try testing.verifyProjection(projection);
    const root_fd = try openDirectoryAbsolute(logical_root_path);
    defer closeRaw(root_fd);
    try testing.replaceMountNamespace();
    try std.testing.expectError(error.InvalidProjection, projection.validateRoot(logical_root_path, root_fd));
    return 0;
}

fn expectIntegrationAvailable(result: Result) !void {
    switch (result) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .setup_failed => |failure| switch (failure.stage) {
            .mount_namespace,
            .private_propagation,
            .detached_propagation,
            .runtime_pin,
            .recursive_bind,
            .pid_namespace,
            => return error.SkipZigTest,
            else => {
                std.debug.print(
                    "live-root integration setup failed at {s} errno={}\n",
                    .{ @tagName(failure.stage), failure.errno },
                );
                return error.UnexpectedIntegrationFailure;
            },
        },
        else => |value| {
            std.debug.print("live-root integration result: {any}\n", .{value});
            return error.UnexpectedIntegrationFailure;
        },
    }
}

test "live_root.test.linux integration when namespace capabilities are available" {
    if (builtin.os.tag != .linux or linux.geteuid() != 0) return error.SkipZigTest;
    try expectIntegrationAvailable(try run(.{ .child = integrationChild }));
    try expectIntegrationAvailable(try runProjected(.{ .child = projectedIntegrationChild }));
}

const ParentDeathContext = struct {
    ready_fd: i32,
    lifetime_fd: i32,
};

fn parentDeathChild(raw: ?*anyopaque, install_root: []const u8) anyerror!u8 {
    if (!std.mem.eql(u8, install_root, logical_root_path)) return error.BadRoot;
    const context: *ParentDeathContext = @ptrCast(@alignCast(raw.?));
    var byte: [1]u8 = .{1};
    if (linux.errno(linux.write(context.ready_fd, &byte, byte.len)) != .SUCCESS)
        return error.ReadyFailed;
    _ = context.lifetime_fd;
    while (true) sleepMilliseconds(1_000);
}

test "live_root.test.parent death terminates workload and releases lock" {
    if (builtin.os.tag != .linux or linux.geteuid() != 0) return error.SkipZigTest;
    try expectIntegrationAvailable(try run(.{ .child = integrationChild }));

    var ready: [2]i32 = undefined;
    try std.testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.pipe2(&ready, .{ .CLOEXEC = true, .NONBLOCK = true })),
    );
    defer {
        closeFd(&ready[0]);
        closeFd(&ready[1]);
    }
    var lifetime: [2]i32 = undefined;
    try std.testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.pipe2(&lifetime, .{ .CLOEXEC = true, .NONBLOCK = true })),
    );
    defer {
        closeFd(&lifetime[0]);
        closeFd(&lifetime[1]);
    }

    const parent_raw = linux.fork();
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(parent_raw));
    const parent: i32 = @intCast(parent_raw);
    if (parent == 0) {
        closeRaw(ready[0]);
        closeRaw(lifetime[0]);
        var context: ParentDeathContext = .{
            .ready_fd = ready[1],
            .lifetime_fd = lifetime[1],
        };
        const result = run(.{
            .context = &context,
            .child = parentDeathChild,
            .termination_grace_ms = 50,
        }) catch linux.exit_group(120);
        switch (result) {
            .exited => |code| linux.exit_group(code),
            else => linux.exit_group(121),
        }
    }

    closeFd(&ready[1]);
    closeFd(&lifetime[1]);
    var parent_live = true;
    defer if (parent_live) {
        _ = linux.kill(parent, .KILL);
        _ = reapBlocking(parent) catch null;
    };
    try std.testing.expect(try waitForPipeByte(ready[0], 5_000));
    _ = linux.kill(parent, .KILL);
    _ = try reapBlocking(parent);
    parent_live = false;

    try std.testing.expect(try waitForPipeEof(lifetime[0], 5_000));
    try std.testing.expect(try waitForLockRelease(5_000));
}

test "live_root.test.shared outer run never receives the live-root mount" {
    if (builtin.os.tag != .linux or linux.geteuid() != 0) return error.SkipZigTest;
    const outer_run = try mountInfoState("/run");
    if (!outer_run.found or !outer_run.shared) return error.SkipZigTest;

    var ready: [2]i32 = undefined;
    try std.testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.pipe2(&ready, .{ .CLOEXEC = true, .NONBLOCK = true })),
    );
    defer {
        closeFd(&ready[0]);
        closeFd(&ready[1]);
    }
    var lifetime: [2]i32 = undefined;
    try std.testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.pipe2(&lifetime, .{ .CLOEXEC = true, .NONBLOCK = true })),
    );
    defer {
        closeFd(&lifetime[0]);
        closeFd(&lifetime[1]);
    }

    const runner_raw = linux.fork();
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(runner_raw));
    const runner: i32 = @intCast(runner_raw);
    if (runner == 0) {
        closeRaw(ready[0]);
        closeRaw(lifetime[0]);
        var context: ParentDeathContext = .{
            .ready_fd = ready[1],
            .lifetime_fd = lifetime[1],
        };
        const result = run(.{
            .context = &context,
            .child = parentDeathChild,
            .termination_grace_ms = 50,
        }) catch linux.exit_group(120);
        switch (result) {
            .interrupted => linux.exit_group(0),
            else => linux.exit_group(121),
        }
    }

    closeFd(&ready[1]);
    closeFd(&lifetime[1]);
    var runner_live = true;
    defer if (runner_live) {
        _ = linux.kill(runner, .KILL);
        _ = reapBlocking(runner) catch null;
    };
    try std.testing.expect(try waitForPipeByte(ready[0], 5_000));
    const leaked = (try mountInfoState(logical_root_path)).found;
    _ = linux.kill(runner, .TERM);
    const status = try reapBlocking(runner);
    runner_live = false;
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
    try std.testing.expect(try waitForPipeEof(lifetime[0], 5_000));
    try std.testing.expect(try waitForLockRelease(5_000));
    try std.testing.expect(!leaked);
}

const MountInfoState = struct {
    found: bool = false,
    shared: bool = false,
};

fn mountInfoState(path: []const u8) !MountInfoState {
    const raw_fd = linux.open("/proc/self/mountinfo", .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(raw_fd) != .SUCCESS) return error.MountInfoUnavailable;
    const fd: i32 = @intCast(raw_fd);
    defer closeRaw(fd);

    var buffer: [256 * 1024]u8 = undefined;
    var filled: usize = 0;
    while (filled < buffer.len) {
        const raw = linux.read(fd, buffer[filled..].ptr, buffer.len - filled);
        switch (linux.errno(raw)) {
            .SUCCESS => {
                if (raw == 0) break;
                filled += raw;
            },
            .INTR => continue,
            else => return error.MountInfoUnavailable,
        }
    }
    if (filled == buffer.len) return error.MountInfoTooLarge;

    var lines = std.mem.splitScalar(u8, buffer[0..filled], '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ' ');
        var index: usize = 0;
        var mountpoint: ?[]const u8 = null;
        while (fields.next()) |field| : (index += 1) {
            if (index == 4) {
                mountpoint = field;
                break;
            }
        }
        if (mountpoint) |candidate| {
            if (std.mem.eql(u8, candidate, path)) return .{
                .found = true,
                .shared = std.mem.indexOf(u8, line, " shared:") != null,
            };
        }
    }
    return .{};
}

fn waitForPipeByte(fd: i32, timeout_ms: u64) !bool {
    const deadline = monotonicMilliseconds() + timeout_ms;
    var byte: [1]u8 = undefined;
    while (monotonicMilliseconds() < deadline) {
        const raw = linux.read(fd, &byte, byte.len);
        switch (linux.errno(raw)) {
            .SUCCESS => return raw == 1,
            .AGAIN => sleepMilliseconds(5),
            .INTR => continue,
            else => return error.PipeReadFailed,
        }
    }
    return false;
}

fn waitForPipeEof(fd: i32, timeout_ms: u64) !bool {
    const deadline = monotonicMilliseconds() + timeout_ms;
    var byte: [1]u8 = undefined;
    while (monotonicMilliseconds() < deadline) {
        const raw = linux.read(fd, &byte, byte.len);
        switch (linux.errno(raw)) {
            .SUCCESS => if (raw == 0) return true,
            .AGAIN => sleepMilliseconds(5),
            .INTR => continue,
            else => return error.PipeReadFailed,
        }
    }
    return false;
}

fn waitForLockRelease(timeout_ms: u64) !bool {
    const deadline = monotonicMilliseconds() + timeout_ms;
    while (monotonicMilliseconds() < deadline) {
        const runtime_fd = openDirectoryAbsolute(runtime_directory_path) catch {
            sleepMilliseconds(5);
            continue;
        };
        const lock_fd = openLock(runtime_fd) catch {
            closeRaw(runtime_fd);
            sleepMilliseconds(5);
            continue;
        };
        const result = linux.errno(linux.flock(lock_fd, 2 | 4));
        closeRaw(lock_fd);
        closeRaw(runtime_fd);
        switch (result) {
            .SUCCESS => return true,
            .AGAIN => sleepMilliseconds(5),
            else => return error.LockProbeFailed,
        }
    }
    return false;
}
