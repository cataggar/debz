const std = @import("std");
const absolute_path = @import("absolute_path.zig");
const solver = @import("solver.zig");
const deb_payload = @import("deb_payload.zig");
const dpkg_status = @import("dpkg_status.zig");
const recovery = @import("transaction_recovery.zig");
const exact_lock = @import("exact_lock.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const package_origin = @import("package_origin.zig");

pub const Phase = enum { bootstrap_extract, remove, unpack, configure_pending, configure, triggers, audit };
pub const ConffilePolicy = enum { keep_existing, use_package_version };

pub const ForceRisk = enum {
    depends,
    depends_version,
    break_replaces,
    overwrite,
    overwrite_dir,
    remove_reinstreq,
};

pub const RiskPolicy = struct {
    allow_host_root: bool = false,
    force: []const ForceRisk = &.{},
};

pub const LockPolicy = struct {
    wait_ms: u64 = 30_000,
};

pub const ExactLockVerification = enum {
    full_closure,
    locked_packages,
};

pub const Policy = struct {
    conffile: ConffilePolicy,
    locks: LockPolicy = .{},
    risk: RiskPolicy = .{},
    validation_limits: deb_payload.Limits = .{},
    maximum_diagnostic_bytes: usize = 64 * 1024,
    process_timeout_ms: u64 = 5 * 60 * 1000,
    exact_lock_verification: ExactLockVerification = .full_closure,
};

const maximum_diagnostic_limit = 1024 * 1024;

/// A cached archive bound to one archive-producing action in an owned plan.
/// The executor rereads and fully validates `path` immediately before dpkg.
pub const Artifact = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    path: []const u8,
};

pub const Request = struct {
    plan: *const solver.Plan,
    install_root: []const u8,
    artifacts: []const Artifact,
    policy: Policy,
    exact_lock: ?*const exact_lock.Lock = null,
    exact_lock_v2: ?*const exact_lock_v2.Lock = null,
};

pub const EnvironmentEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const audited_environment = [_]EnvironmentEntry{
    .{ .key = "DEBIAN_FRONTEND", .value = "noninteractive" },
    .{ .key = "DPKG_COLORS", .value = "never" },
    .{ .key = "DPKG_FRONTEND_LOCKED", .value = "true" },
    .{ .key = "HOME", .value = "/nonexistent" },
    .{ .key = "LC_ALL", .value = "C" },
    .{ .key = "PATH", .value = "/usr/sbin:/usr/bin:/sbin:/bin" },
};

pub const ProcessTermination = union(enum) {
    exited: u8,
    signaled: u32,
    cancelled,
};

pub const ProcessResult = struct {
    termination: ProcessTermination,
    stderr: []const u8 = "",
};

pub const Invocation = struct {
    argv: []const []const u8,
    environment: []const EnvironmentEntry,
    phase: Phase,
    package: ?[]const u8,
    timeout_ms: u64,
    cancellation: Cancellation,
};

pub const ProcessRunner = struct {
    context: *anyopaque,
    runFn: *const fn (*anyopaque, Invocation) anyerror!ProcessResult,

    pub fn run(self: ProcessRunner, invocation: Invocation) !ProcessResult {
        return self.runFn(self.context, invocation);
    }
};

pub const FileSystem = struct {
    context: *anyopaque,
    validateRootFn: *const fn (*anyopaque, []const u8) anyerror!void,
    normalizeBootstrapRootFn: *const fn (*anyopaque, []const u8) anyerror!void,
    validateArtifactPathFn: *const fn (*anyopaque, []const u8) anyerror!void,
    readArtifactFn: *const fn (*anyopaque, std.mem.Allocator, []const u8, usize) anyerror![]u8,

    pub fn validateRoot(self: FileSystem, root: []const u8) !void {
        return self.validateRootFn(self.context, root);
    }

    pub fn normalizeBootstrapRoot(self: FileSystem, root: []const u8) !void {
        return self.normalizeBootstrapRootFn(self.context, root);
    }

    pub fn readArtifact(
        self: FileSystem,
        allocator: std.mem.Allocator,
        path: []const u8,
        maximum: usize,
    ) ![]u8 {
        return self.readArtifactFn(self.context, allocator, path, maximum);
    }

    pub fn validateArtifactPath(self: FileSystem, path: []const u8) !void {
        return self.validateArtifactPathFn(self.context, path);
    }
};

pub const LockToken = *anyopaque;

pub const LockManager = struct {
    context: *anyopaque,
    acquireFn: *const fn (*anyopaque, []const u8, u64) anyerror!LockToken,
    heldFn: *const fn (*anyopaque, LockToken) bool,
    releaseFn: *const fn (*anyopaque, LockToken) void,

    pub fn acquire(self: LockManager, path: []const u8, wait_ms: u64) !LockToken {
        return self.acquireFn(self.context, path, wait_ms);
    }

    pub fn held(self: LockManager, token: LockToken) bool {
        return self.heldFn(self.context, token);
    }

    pub fn release(self: LockManager, token: LockToken) void {
        self.releaseFn(self.context, token);
    }
};

pub const Cancellation = struct {
    context: *anyopaque,
    cancelledFn: *const fn (*anyopaque) bool,

    pub fn cancelled(self: Cancellation) bool {
        return self.cancelledFn(self.context);
    }

    pub fn never() Cancellation {
        return .{ .context = @ptrCast(@constCast(&never_context)), .cancelledFn = neverCancelled };
    }

    fn neverCancelled(_: *anyopaque) bool {
        return false;
    }
};

const never_context: u8 = 0;

pub const Deadline = struct {
    context: ?*anyopaque,
    nowMsFn: *const fn (?*anyopaque) u64,
    expires_at_ms: u64,

    pub fn remainingMs(self: Deadline) !u64 {
        const now = self.nowMsFn(self.context);
        if (now >= self.expires_at_ms) return error.DeadlineExceeded;
        return self.expires_at_ms - now;
    }

    pub fn expired(self: Deadline) bool {
        _ = self.remainingMs() catch return true;
        return false;
    }
};

pub const Dependencies = struct {
    filesystem: FileSystem,
    locks: LockManager,
    process: ProcessRunner,
    journal: recovery.Store,
    status: recovery.StatusReader,
    cancellation: Cancellation = Cancellation.never(),
    deadline: ?Deadline = null,
    crash: recovery.CrashInjector = recovery.CrashInjector.none(),
};

pub const CommandProvenance = struct {
    phase: Phase,
    package: ?[]const u8,
    version: ?[]const u8,
    architecture: ?[]const u8,
    argv: []const []const u8 = &.{},
    environment: []const EnvironmentEntry = &.{},
    command_sha256: [32]u8,
    artifact_sha256: ?[32]u8,
};

pub const FailureCode = enum {
    invalid_plan,
    invalid_root,
    invalid_artifact,
    artifact_missing,
    artifact_digest_mismatch,
    artifact_identity_mismatch,
    unsupported_force_policy,
    lock_timeout,
    lock_error,
    lock_lost,
    process_spawn,
    process_timeout,
    dpkg_failed,
    interrupted,
    journal_missing,
    journal_corrupt,
    journal_mismatch,
    journal_io,
    invalid_recovery_transition,
    verification_failed,
    recovery_failed,
    out_of_memory,
};

pub const Failure = struct {
    code: FailureCode,
    phase: ?Phase = null,
    package: ?[]const u8 = null,
    lock_path: ?[]const u8 = null,
    exit_code: ?u8 = null,
    signal: ?u32 = null,
    diagnostic: []const u8 = "",
    completed_commands: usize = 0,
};

pub const Report = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    commands: []const CommandProvenance,
    plan_sha256: [32]u8,
    transaction_state: recovery.State,
    root_identity: [32]u8,
    policy_sha256: [32]u8,
    lock_sha256: ?[32]u8,
    failure: ?Failure,

    pub fn succeeded(self: Report) bool {
        return self.failure == null;
    }

    pub fn deinit(self: *Report) void {
        const allocator = self.allocator;
        self.arena.deinit();
        allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const RecoveryRequest = struct {
    plan: *const solver.Plan,
    install_root: []const u8,
    policy: Policy,
    exact_lock: ?*const exact_lock.Lock = null,
    exact_lock_v2: ?*const exact_lock_v2.Lock = null,
};

pub const RecoveryReport = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    state: recovery.State,
    commands: []const CommandProvenance,
    plan_sha256: [32]u8,
    root_identity: [32]u8,
    policy_sha256: [32]u8,
    lock_sha256: ?[32]u8,
    failure: ?Failure,

    pub fn succeeded(self: RecoveryReport) bool {
        return self.failure == null and self.state == .complete;
    }

    pub fn deinit(self: *RecoveryReport) void {
        const allocator = self.allocator;
        self.arena.deinit();
        allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn planDigest(plan: solver.Plan) [32]u8 {
    return hashPlan(plan);
}

const State = struct {
    arena: std.mem.Allocator,
    commands: std.ArrayList(CommandProvenance) = .empty,
    failure: ?Failure = null,
    transaction_state: recovery.State = .not_started,
    root_identity: [32]u8 = @splat(0),
    policy_sha256: [32]u8 = @splat(0),
    lock_sha256: ?[32]u8 = null,
};

pub fn execute(
    allocator: std.mem.Allocator,
    request: Request,
    dependencies: Dependencies,
) !Report {
    const arena_ptr = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena_ptr);
    arena_ptr.* = .init(allocator);
    errdefer arena_ptr.deinit();
    const arena = arena_ptr.allocator();

    var state: State = .{ .arena = arena };
    var cancellation_context: DeadlineCancellationContext = .{
        .base = dependencies.cancellation,
        .deadline = dependencies.deadline,
    };
    const cancellation = cancellation_context.interface();
    if (deadlineExpired(dependencies.deadline)) {
        state.failure = deadlineFailure(arena, null, null, 0);
        return finish(allocator, arena_ptr, &state, hashPlan(request.plan.*));
    }
    const plan_sha256 = hashPlan(request.plan.*);
    state.root_identity = recovery.rootIdentity(request.install_root);
    state.policy_sha256 = hashPolicy(request.policy);
    state.lock_sha256 = if (request.exact_lock) |lock|
        lock.digest_sha256
    else if (request.exact_lock_v2) |lock|
        lock.digest_sha256
    else
        null;

    preflight(arena, request, dependencies.filesystem) catch |err| {
        state.failure = .{
            .code = preflightCode(err),
            .diagnostic = try arena.dupe(u8, @errorName(err)),
        };
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };

    const root_flag = try std.fmt.allocPrint(arena, "--root={s}", .{request.install_root});
    const admin_path = try rootPath(arena, request.install_root, "var/lib/dpkg");
    const admin_flag = try std.fmt.allocPrint(arena, "--admindir={s}", .{admin_path});
    const lock_paths = [_][]const u8{
        try rootPath(arena, request.install_root, "var/lib/debz/transaction.lock"),
        try rootPath(arena, request.install_root, "var/lib/dpkg/lock-frontend"),
        try rootPath(arena, request.install_root, "var/lib/dpkg/lock"),
    };
    var held: [lock_paths.len]?LockToken = @splat(null);
    var bootstrap_normalized = !requiresRootBootstrap(request.plan.actions);
    defer for (held, 0..) |token, index| {
        if (token) |value| dependencies.locks.release(value);
        held[index] = null;
    };

    for (lock_paths, 0..) |path, index| {
        const wait_ms = remainingTimeout(
            dependencies.deadline,
            request.policy.locks.wait_ms,
        ) catch {
            state.failure = deadlineFailure(arena, null, null, 0);
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        held[index] = dependencies.locks.acquire(path, wait_ms) catch |err| {
            state.failure = .{
                .code = if (err == error.LockTimeout or err == error.WouldBlock) .lock_timeout else .lock_error,
                .lock_path = path,
                .diagnostic = try arena.dupe(u8, @errorName(err)),
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
    }
    // Dpkg must acquire its database lock itself. Probe it under the same
    // bounded policy, then release only that lock before spawning dpkg while
    // retaining debz's transaction lock and dpkg's frontend lock.
    dependencies.locks.release(held[2].?);
    held[2] = null;

    const existing_bytes = dependencies.journal.load(arena, request.install_root) catch |err| {
        state.failure = journalFailure(arena, err, .journal_io, "cannot inspect existing transaction journal");
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    if (existing_bytes) |bytes| {
        var existing = recovery.decode(arena, bytes) catch |err| {
            state.failure = journalFailure(arena, err, .journal_corrupt, "existing transaction journal is invalid");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        defer existing.deinit();
        if (existing.journal.state != .complete) {
            state.transaction_state = existing.journal.state;
            state.failure = .{
                .code = .invalid_recovery_transition,
                .diagnostic = "an unfinished transaction requires explicit recover",
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
    }

    const journal_commands = try buildJournalCommands(
        arena,
        request,
        root_flag,
        admin_flag,
    );
    var journal: recovery.Journal = .{
        .state = .not_started,
        .boundary = .prepared,
        .plan_sha256 = plan_sha256,
        .root_identity = state.root_identity,
        .policy_sha256 = state.policy_sha256,
        .lock_sha256 = state.lock_sha256,
        .next_command = 0,
        .commands = journal_commands,
    };
    dependencies.crash.hit(.before_initial_journal, 0) catch |err| {
        state.failure = journalFailure(arena, err, .journal_io, "crash before initial journal");
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    recovery.persist(arena, dependencies.journal, request.install_root, journal) catch |err| {
        state.failure = journalFailure(arena, err, .journal_io, "cannot create transaction journal");
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    dependencies.crash.hit(.after_initial_journal, 0) catch |err| {
        journal.state = .interrupted;
        journal.failure = @errorName(err);
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
        state.transaction_state = .interrupted;
        state.failure = journalFailure(arena, err, .interrupted, "interrupted after initial journal");
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };

    for (request.plan.ordered_actions, 0..) |ordered, command_index| {
        if (!bootstrap_normalized and ordered.kind != .bootstrap_extract) {
            dependencies.filesystem.normalizeBootstrapRoot(request.install_root) catch |err| {
                state.failure = .{
                    .code = .invalid_root,
                    .phase = try toPhase(ordered.kind),
                    .diagnostic = try arena.dupe(u8, @errorName(err)),
                    .completed_commands = state.commands.items.len,
                };
                return finish(allocator, arena_ptr, &state, plan_sha256);
            };
            bootstrap_normalized = true;
        }
        if (cancellation.cancelled()) {
            journal.state = .interrupted;
            journal.failure = "cancelled before dpkg invocation";
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = interruption(null, null, state.commands.items.len, "cancelled before dpkg invocation");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }

        if (!locksHeld(dependencies.locks, &held)) {
            state.failure = .{
                .code = .lock_lost,
                .phase = try toPhase(ordered.kind),
                .package = if (ordered.kind == .configure_pending) null else try arena.dupe(u8, ordered.package),
                .diagnostic = "transaction lock ownership was lost",
                .completed_commands = state.commands.items.len,
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
        dependencies.filesystem.validateRoot(request.install_root) catch |err| {
            state.failure = .{
                .code = .invalid_root,
                .phase = try toPhase(ordered.kind),
                .package = try arena.dupe(u8, ordered.package),
                .diagnostic = try arena.dupe(u8, @errorName(err)),
                .completed_commands = state.commands.items.len,
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };

        const phase = try toPhase(ordered.kind);
        const artifact = if (phase == .bootstrap_extract or phase == .unpack)
            findArtifact(request.artifacts, ordered.package, ordered.version, ordered.architecture).?
        else
            null;
        var artifact_digest: ?[32]u8 = null;
        if (artifact) |item| {
            const action = findPlanAction(request.plan.actions, item.package, item.version, item.architecture).?;
            artifact_digest = validateArtifact(arena, dependencies.filesystem, item, action, request.policy.validation_limits) catch |err| {
                state.failure = .{
                    .code = artifactCode(err),
                    .phase = phase,
                    .package = try arena.dupe(u8, ordered.package),
                    .diagnostic = try arena.dupe(u8, @errorName(err)),
                    .completed_commands = state.commands.items.len,
                };
                return finish(allocator, arena_ptr, &state, plan_sha256);
            };
        }

        const argv = try buildArgv(
            arena,
            request.install_root,
            root_flag,
            admin_flag,
            phase,
            ordered.package,
            ordered.architecture,
            if (artifact) |item| item.path else null,
            request.policy,
        );
        const provenance: CommandProvenance = .{
            .phase = phase,
            .package = try arena.dupe(u8, ordered.package),
            .version = try arena.dupe(u8, ordered.version),
            .architecture = try arena.dupe(u8, ordered.architecture),
            .argv = argv,
            .environment = &audited_environment,
            .command_sha256 = hashInvocation(argv, &audited_environment),
            .artifact_sha256 = artifact_digest,
        };
        journal.state = .in_progress;
        journal.boundary = .before_command;
        journal.next_command = command_index;
        journal.failure = null;
        state.transaction_state = .in_progress;
        dependencies.crash.hit(.before_command_journal, command_index) catch |err| {
            journal.state = .interrupted;
            journal.failure = @errorName(err);
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = journalFailure(arena, err, .interrupted, "interrupted before command journal");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch |err| {
            state.failure = journalFailure(arena, err, .journal_io, "cannot persist command boundary");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        const configured_before = if (phase == .configure_pending)
            configuredPackageCount(arena, dependencies.status, request.install_root) catch null
        else
            null;
        const result = dependencies.process.run(.{
            .argv = argv,
            .environment = &audited_environment,
            .phase = phase,
            .package = if (phase == .configure_pending) null else ordered.package,
            .timeout_ms = remainingTimeout(
                dependencies.deadline,
                request.policy.process_timeout_ms,
            ) catch {
                journal.state = .interrupted;
                journal.failure = "operation deadline expired before dpkg invocation";
                recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
                state.transaction_state = .interrupted;
                state.failure = deadlineFailure(
                    arena,
                    phase,
                    if (phase == .configure_pending) null else ordered.package,
                    state.commands.items.len,
                );
                return finish(allocator, arena_ptr, &state, plan_sha256);
            },
            .cancellation = cancellation,
        }) catch |err| {
            state.failure = .{
                .code = if (err == error.Timeout) .process_timeout else .process_spawn,
                .phase = phase,
                .package = if (phase == .configure_pending) null else try arena.dupe(u8, ordered.package),
                .diagnostic = try arena.dupe(u8, @errorName(err)),
                .completed_commands = state.commands.items.len,
            };
            journal.state = if (err == error.Timeout) .interrupted else .dpkg_failed;
            journal.failure = @errorName(err);
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = journal.state;
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        if (deadlineExpired(dependencies.deadline)) {
            journal.state = .interrupted;
            journal.failure = "operation deadline expired during dpkg invocation";
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = deadlineFailure(
                arena,
                phase,
                if (phase == .configure_pending) null else ordered.package,
                state.commands.items.len,
            );
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
        try state.commands.append(arena, provenance);
        const made_configuration_progress = if (!successful(result.termination) and configured_before != null)
            if (configuredPackageCount(arena, dependencies.status, request.install_root) catch null) |after|
                after > configured_before.?
            else
                false
        else
            false;
        if (!successful(result.termination) and !made_configuration_progress) {
            state.failure = try processFailure(arena, result, phase, ordered.package, request.policy.maximum_diagnostic_bytes, state.commands.items.len);
            journal.state = if (state.failure.?.code == .interrupted) .interrupted else .dpkg_failed;
            journal.failure = state.failure.?.diagnostic;
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = journal.state;
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
        journal.boundary = .after_command;
        journal.next_command = command_index + 1;
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch |err| {
            state.failure = journalFailure(arena, err, .journal_io, "cannot persist completed command");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        dependencies.crash.hit(.after_command_journal, command_index) catch |err| {
            journal.state = .interrupted;
            journal.failure = @errorName(err);
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = journalFailure(arena, err, .interrupted, "interrupted after command journal");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        if (!locksHeld(dependencies.locks, &held)) {
            state.failure = .{
                .code = .lock_lost,
                .phase = phase,
                .package = try arena.dupe(u8, ordered.package),
                .diagnostic = "transaction lock ownership was lost during dpkg",
                .completed_commands = state.commands.items.len,
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
    }

    if (request.plan.ordered_actions.len != 0) {
        if (cancellation.cancelled()) {
            journal.state = .interrupted;
            journal.failure = "cancelled before trigger processing";
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = interruption(.triggers, null, state.commands.items.len, "cancelled before trigger processing");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
        if (!locksHeld(dependencies.locks, &held)) {
            state.failure = .{
                .code = .lock_lost,
                .phase = .triggers,
                .diagnostic = "transaction lock ownership was lost",
                .completed_commands = state.commands.items.len,
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
        dependencies.filesystem.validateRoot(request.install_root) catch |err| {
            state.failure = .{
                .code = .invalid_root,
                .phase = .triggers,
                .diagnostic = try arena.dupe(u8, @errorName(err)),
                .completed_commands = state.commands.items.len,
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        const argv = try buildTriggerArgv(arena, root_flag, admin_flag, request.policy);
        const trigger_index = request.plan.ordered_actions.len;
        journal.state = .in_progress;
        journal.boundary = .before_command;
        journal.next_command = trigger_index;
        journal.failure = null;
        state.transaction_state = .in_progress;
        dependencies.crash.hit(.before_command_journal, trigger_index) catch |err| {
            journal.state = .interrupted;
            journal.failure = @errorName(err);
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = journalFailure(arena, err, .interrupted, "interrupted before trigger journal");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch |err| {
            state.failure = journalFailure(arena, err, .journal_io, "cannot persist trigger boundary");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        const result = dependencies.process.run(.{
            .argv = argv,
            .environment = &audited_environment,
            .phase = .triggers,
            .package = null,
            .timeout_ms = remainingTimeout(
                dependencies.deadline,
                request.policy.process_timeout_ms,
            ) catch {
                journal.state = .interrupted;
                journal.failure = "operation deadline expired before triggers";
                recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
                state.transaction_state = .interrupted;
                state.failure = deadlineFailure(
                    arena,
                    .triggers,
                    null,
                    state.commands.items.len,
                );
                return finish(allocator, arena_ptr, &state, plan_sha256);
            },
            .cancellation = cancellation,
        }) catch |err| {
            state.failure = .{
                .code = if (err == error.Timeout) .process_timeout else .process_spawn,
                .phase = .triggers,
                .diagnostic = try arena.dupe(u8, @errorName(err)),
                .completed_commands = state.commands.items.len,
            };
            journal.state = if (err == error.Timeout) .interrupted else .dpkg_failed;
            journal.failure = @errorName(err);
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = journal.state;
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        if (deadlineExpired(dependencies.deadline)) {
            journal.state = .interrupted;
            journal.failure = "operation deadline expired during triggers";
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = deadlineFailure(
                arena,
                .triggers,
                null,
                state.commands.items.len,
            );
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
        try state.commands.append(arena, .{
            .phase = .triggers,
            .package = null,
            .version = null,
            .architecture = null,
            .argv = argv,
            .environment = &audited_environment,
            .command_sha256 = hashInvocation(argv, &audited_environment),
            .artifact_sha256 = null,
        });
        if (!successful(result.termination)) {
            state.failure = try processFailure(arena, result, .triggers, null, request.policy.maximum_diagnostic_bytes, state.commands.items.len);
            journal.state = if (state.failure.?.code == .interrupted) .interrupted else .dpkg_failed;
            journal.failure = state.failure.?.diagnostic;
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = journal.state;
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
        journal.boundary = .after_command;
        journal.next_command = trigger_index + 1;
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch |err| {
            state.failure = journalFailure(arena, err, .journal_io, "cannot persist completed triggers");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        dependencies.crash.hit(.after_command_journal, trigger_index) catch |err| {
            journal.state = .interrupted;
            journal.failure = @errorName(err);
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = journalFailure(arena, err, .interrupted, "interrupted after trigger journal");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        if (!locksHeld(dependencies.locks, &held)) {
            state.failure = .{
                .code = .lock_lost,
                .phase = .triggers,
                .diagnostic = "transaction lock ownership was lost during dpkg",
                .completed_commands = state.commands.items.len,
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
    }

    const verification_wait_ms = remainingTimeout(
        dependencies.deadline,
        request.policy.locks.wait_ms,
    ) catch {
        journal.state = .interrupted;
        journal.failure = "operation deadline expired before verification lock";
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
        state.transaction_state = .interrupted;
        state.failure = deadlineFailure(arena, null, null, state.commands.items.len);
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    held[2] = dependencies.locks.acquire(lock_paths[2], verification_wait_ms) catch |err| {
        journal.state = .interrupted;
        journal.failure = "cannot establish stable verification lock";
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
        state.transaction_state = .interrupted;
        state.failure = .{
            .code = if (err == error.LockTimeout or err == error.WouldBlock) .lock_timeout else .lock_error,
            .lock_path = lock_paths[2],
            .diagnostic = try arena.dupe(u8, @errorName(err)),
            .completed_commands = state.commands.items.len,
        };
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    dependencies.filesystem.validateRoot(request.install_root) catch |err| {
        journal.state = .interrupted;
        journal.failure = "install root changed before verification";
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
        state.transaction_state = .interrupted;
        state.failure = .{
            .code = .invalid_root,
            .diagnostic = try arena.dupe(u8, @errorName(err)),
            .completed_commands = state.commands.items.len,
        };
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };

    journal.boundary = .verifying;
    dependencies.crash.hit(.before_verification_journal, journal.next_command) catch |err| {
        journal.state = .interrupted;
        journal.failure = @errorName(err);
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
        state.transaction_state = .interrupted;
        state.failure = journalFailure(arena, err, .interrupted, "interrupted before verification");
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    recovery.persist(arena, dependencies.journal, request.install_root, journal) catch |err| {
        state.failure = journalFailure(arena, err, .journal_io, "cannot persist verification boundary");
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    const verification = verifyFinal(
        arena,
        request.plan.*,
        request.exact_lock,
        request.exact_lock_v2,
        request.policy.exact_lock_verification,
        journal,
        request.install_root,
        dependencies.status,
    ) catch |err| {
        journal.state = .verification_failed;
        journal.failure = @errorName(err);
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
        state.transaction_state = .verification_failed;
        state.failure = journalFailure(arena, err, .verification_failed, "post-state verification failed");
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    if (!verification.succeeded()) {
        journal.state = .verification_failed;
        journal.failure = @tagName(verification.failure.?);
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
        state.transaction_state = .verification_failed;
        state.failure = .{
            .code = .verification_failed,
            .package = if (verification.package) |value| try arena.dupe(u8, value) else null,
            .diagnostic = try arena.dupe(u8, @tagName(verification.failure.?)),
            .completed_commands = state.commands.items.len,
        };
        return finish(allocator, arena_ptr, &state, plan_sha256);
    }
    journal.state = .complete;
    journal.failure = null;
    recovery.persist(arena, dependencies.journal, request.install_root, journal) catch |err| {
        state.failure = journalFailure(arena, err, .journal_io, "cannot persist verified completion");
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    dependencies.crash.hit(.after_verification_journal, journal.next_command) catch |err| {
        state.transaction_state = .complete;
        state.failure = journalFailure(arena, err, .journal_io, "completion persisted but archive interrupted");
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    dependencies.crash.hit(.before_archive, journal.next_command) catch |err| {
        state.transaction_state = .complete;
        state.failure = journalFailure(arena, err, .journal_io, "completion persisted but archive interrupted");
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    recovery.archive(arena, dependencies.journal, request.install_root, journal) catch |err| {
        state.transaction_state = .complete;
        state.failure = journalFailure(arena, err, .journal_io, "cannot archive completed journal");
        return finish(allocator, arena_ptr, &state, plan_sha256);
    };
    state.transaction_state = .complete;
    return finish(allocator, arena_ptr, &state, plan_sha256);
}

pub fn recover(
    allocator: std.mem.Allocator,
    request: RecoveryRequest,
    dependencies: Dependencies,
) !RecoveryReport {
    const arena_ptr = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena_ptr);
    arena_ptr.* = .init(allocator);
    errdefer arena_ptr.deinit();
    const arena = arena_ptr.allocator();
    var state: State = .{ .arena = arena };
    var cancellation_context: DeadlineCancellationContext = .{
        .base = dependencies.cancellation,
        .deadline = dependencies.deadline,
    };
    const cancellation = cancellation_context.interface();
    if (deadlineExpired(dependencies.deadline)) {
        state.failure = deadlineFailure(arena, null, null, 0);
        return finishRecovery(
            allocator,
            arena_ptr,
            &state,
            hashPlan(request.plan.*),
        );
    }
    const plan_sha256 = hashPlan(request.plan.*);
    state.root_identity = recovery.rootIdentity(request.install_root);
    state.policy_sha256 = hashPolicy(request.policy);
    state.lock_sha256 = if (request.exact_lock) |lock|
        lock.digest_sha256
    else if (request.exact_lock_v2) |lock|
        lock.digest_sha256
    else
        null;

    preflight(arena, .{
        .plan = request.plan,
        .install_root = request.install_root,
        .artifacts = &.{},
        .policy = request.policy,
        .exact_lock = request.exact_lock,
        .exact_lock_v2 = request.exact_lock_v2,
    }, dependencies.filesystem) catch |err| {
        // Recovery does not need package artifacts, so only retain root, plan,
        // and policy validation errors from the shared preflight.
        if (err != error.MissingArtifact) {
            state.failure = .{ .code = preflightCode(err), .diagnostic = try arena.dupe(u8, @errorName(err)) };
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        }
    };

    const encoded = dependencies.journal.load(arena, request.install_root) catch |err| {
        state.failure = journalFailure(arena, err, .journal_io, "cannot load transaction journal");
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    } orelse {
        state.failure = .{ .code = .journal_missing, .diagnostic = "no recoverable transaction journal" };
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    };
    var decoded = recovery.decode(arena, encoded) catch |err| {
        state.failure = journalFailure(arena, err, .journal_corrupt, "invalid transaction journal");
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    };
    defer decoded.deinit();
    var journal = decoded.journal;
    state.transaction_state = journal.state;
    if (!std.mem.eql(u8, &journal.plan_sha256, &plan_sha256) or
        !std.mem.eql(u8, &journal.root_identity, &state.root_identity) or
        !std.mem.eql(u8, &journal.policy_sha256, &state.policy_sha256) or
        !optionalDigestEqual(journal.lock_sha256, state.lock_sha256))
    {
        state.failure = .{ .code = .journal_mismatch, .diagnostic = "journal plan, root, executor policy, or exact lock does not match" };
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    }
    const root_flag = try std.fmt.allocPrint(arena, "--root={s}", .{request.install_root});
    const admin_path = try rootPath(arena, request.install_root, "var/lib/dpkg");
    const admin_flag = try std.fmt.allocPrint(arena, "--admindir={s}", .{admin_path});
    const lock_paths = [_][]const u8{
        try rootPath(arena, request.install_root, "var/lib/debz/transaction.lock"),
        try rootPath(arena, request.install_root, "var/lib/dpkg/lock-frontend"),
        try rootPath(arena, request.install_root, "var/lib/dpkg/lock"),
    };
    var held: [lock_paths.len]?LockToken = @splat(null);
    defer for (held, 0..) |token, index| {
        if (token) |value| dependencies.locks.release(value);
        held[index] = null;
    };
    for (lock_paths, 0..) |path, index| {
        const wait_ms = remainingTimeout(
            dependencies.deadline,
            request.policy.locks.wait_ms,
        ) catch {
            state.failure = deadlineFailure(arena, null, null, 0);
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        };
        held[index] = dependencies.locks.acquire(path, wait_ms) catch |err| {
            state.failure = .{
                .code = if (err == error.LockTimeout or err == error.WouldBlock) .lock_timeout else .lock_error,
                .lock_path = path,
                .diagnostic = try arena.dupe(u8, @errorName(err)),
            };
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        };
    }
    if (journal.state == .complete) {
        dependencies.filesystem.validateRoot(request.install_root) catch |err| {
            state.failure = .{ .code = .invalid_root, .diagnostic = try arena.dupe(u8, @errorName(err)) };
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        };
        const verification = try verifyFinal(
            arena,
            request.plan.*,
            request.exact_lock,
            request.exact_lock_v2,
            request.policy.exact_lock_verification,
            journal,
            request.install_root,
            dependencies.status,
        );
        if (!verification.succeeded()) {
            journal.state = .verification_failed;
            journal.failure = @tagName(verification.failure.?);
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch |err| {
                state.failure = journalFailure(arena, err, .journal_io, "cannot retain failed completion verification");
                return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
            };
            state.transaction_state = .verification_failed;
            state.failure = .{ .code = .verification_failed, .diagnostic = @tagName(verification.failure.?) };
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        }
        recovery.archive(arena, dependencies.journal, request.install_root, journal) catch |err| {
            state.failure = journalFailure(arena, err, .journal_io, "cannot archive completed journal");
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        };
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    }
    dependencies.locks.release(held[2].?);
    held[2] = null;
    if (requiresRootBootstrap(request.plan.actions)) {
        dependencies.filesystem.normalizeBootstrapRoot(request.install_root) catch |err| {
            state.failure = .{ .code = .invalid_root, .diagnostic = try arena.dupe(u8, @errorName(err)) };
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        };
    }

    journal.state = .in_progress;
    journal.boundary = .recovering;
    journal.failure = null;
    recovery.persist(arena, dependencies.journal, request.install_root, journal) catch |err| {
        state.failure = journalFailure(arena, err, .journal_io, "cannot persist recovery boundary");
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    };
    state.transaction_state = .in_progress;

    const recovery_commands = [_]struct { phase: Phase, argv: []const []const u8 }{
        .{ .phase = .audit, .argv = try buildRecoveryArgv(arena, root_flag, admin_flag, request.policy, .audit) },
        .{ .phase = .configure, .argv = try buildRecoveryArgv(arena, root_flag, admin_flag, request.policy, .configure) },
        .{ .phase = .triggers, .argv = try buildRecoveryArgv(arena, root_flag, admin_flag, request.policy, .triggers) },
    };
    for (recovery_commands) |command| {
        if (cancellation.cancelled()) {
            journal.state = .interrupted;
            journal.failure = "recovery cancelled";
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = interruption(command.phase, null, state.commands.items.len, "recovery cancelled");
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        }
        if (!locksHeld(dependencies.locks, &held)) {
            journal.state = .interrupted;
            journal.failure = "recovery lock ownership was lost";
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = .{
                .code = .lock_lost,
                .phase = command.phase,
                .diagnostic = "recovery lock ownership was lost",
                .completed_commands = state.commands.items.len,
            };
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        }
        dependencies.filesystem.validateRoot(request.install_root) catch |err| {
            journal.state = .interrupted;
            journal.failure = "install root changed during recovery";
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = .{
                .code = .invalid_root,
                .phase = command.phase,
                .diagnostic = try arena.dupe(u8, @errorName(err)),
                .completed_commands = state.commands.items.len,
            };
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        };
        const result = dependencies.process.run(.{
            .argv = command.argv,
            .environment = &audited_environment,
            .phase = command.phase,
            .package = null,
            .timeout_ms = remainingTimeout(
                dependencies.deadline,
                request.policy.process_timeout_ms,
            ) catch {
                journal.state = .interrupted;
                journal.failure = "operation deadline expired during recovery";
                recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
                state.transaction_state = .interrupted;
                state.failure = deadlineFailure(
                    arena,
                    command.phase,
                    null,
                    state.commands.items.len,
                );
                return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
            },
            .cancellation = cancellation,
        }) catch |err| {
            journal.state = .interrupted;
            journal.failure = @errorName(err);
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = journalFailure(arena, err, .recovery_failed, "recovery command could not complete");
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        };
        if (deadlineExpired(dependencies.deadline)) {
            journal.state = .interrupted;
            journal.failure = "operation deadline expired during recovery command";
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = deadlineFailure(
                arena,
                command.phase,
                null,
                state.commands.items.len,
            );
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        }
        try state.commands.append(arena, .{
            .phase = command.phase,
            .package = null,
            .version = null,
            .architecture = null,
            .argv = command.argv,
            .environment = &audited_environment,
            .command_sha256 = hashInvocation(command.argv, &audited_environment),
            .artifact_sha256 = null,
        });
        if (!successful(result.termination)) {
            state.failure = try processFailure(arena, result, command.phase, null, request.policy.maximum_diagnostic_bytes, state.commands.items.len);
            state.failure.?.code = .recovery_failed;
            journal.state = switch (result.termination) {
                .cancelled, .signaled => .interrupted,
                .exited => .dpkg_failed,
            };
            journal.failure = state.failure.?.diagnostic;
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = journal.state;
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        }
    }

    const verification_wait_ms = remainingTimeout(
        dependencies.deadline,
        request.policy.locks.wait_ms,
    ) catch {
        journal.state = .interrupted;
        journal.failure = "operation deadline expired before recovery verification lock";
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
        state.transaction_state = .interrupted;
        state.failure = deadlineFailure(arena, null, null, state.commands.items.len);
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    };
    held[2] = dependencies.locks.acquire(lock_paths[2], verification_wait_ms) catch |err| {
        journal.state = .interrupted;
        journal.failure = "cannot establish stable recovery verification lock";
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
        state.transaction_state = .interrupted;
        state.failure = .{
            .code = if (err == error.LockTimeout or err == error.WouldBlock) .lock_timeout else .lock_error,
            .lock_path = lock_paths[2],
            .diagnostic = try arena.dupe(u8, @errorName(err)),
            .completed_commands = state.commands.items.len,
        };
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    };
    dependencies.filesystem.validateRoot(request.install_root) catch |err| {
        journal.state = .interrupted;
        journal.failure = "install root changed before recovery verification";
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
        state.transaction_state = .interrupted;
        state.failure = .{
            .code = .invalid_root,
            .diagnostic = try arena.dupe(u8, @errorName(err)),
            .completed_commands = state.commands.items.len,
        };
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    };

    const verification = try verifyFinal(
        arena,
        request.plan.*,
        request.exact_lock,
        request.exact_lock_v2,
        request.policy.exact_lock_verification,
        journal,
        request.install_root,
        dependencies.status,
    );
    if (!verification.succeeded()) {
        journal.state = .verification_failed;
        journal.failure = @tagName(verification.failure.?);
        recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
        state.transaction_state = .verification_failed;
        state.failure = .{
            .code = .verification_failed,
            .package = if (verification.package) |value| try arena.dupe(u8, value) else null,
            .diagnostic = @tagName(verification.failure.?),
            .completed_commands = state.commands.items.len,
        };
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    }
    journal.state = .complete;
    journal.failure = null;
    recovery.persist(arena, dependencies.journal, request.install_root, journal) catch |err| {
        state.failure = journalFailure(arena, err, .journal_io, "cannot persist recovered completion");
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    };
    state.transaction_state = .complete;
    recovery.archive(arena, dependencies.journal, request.install_root, journal) catch |err| {
        state.failure = journalFailure(arena, err, .journal_io, "cannot archive recovered journal");
        return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
    };
    return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
}

fn finishRecovery(
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    state: *State,
    plan_sha256: [32]u8,
) !RecoveryReport {
    return .{
        .allocator = allocator,
        .arena = arena,
        .state = state.transaction_state,
        .commands = try state.commands.toOwnedSlice(state.arena),
        .plan_sha256 = plan_sha256,
        .root_identity = state.root_identity,
        .policy_sha256 = state.policy_sha256,
        .lock_sha256 = state.lock_sha256,
        .failure = state.failure,
    };
}

fn finish(
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    state: *State,
    plan_sha256: [32]u8,
) !Report {
    const commands = try state.commands.toOwnedSlice(state.arena);
    return .{
        .allocator = allocator,
        .arena = arena,
        .commands = commands,
        .plan_sha256 = plan_sha256,
        .transaction_state = state.transaction_state,
        .root_identity = state.root_identity,
        .policy_sha256 = state.policy_sha256,
        .lock_sha256 = state.lock_sha256,
        .failure = state.failure,
    };
}

fn verifyFinal(
    allocator: std.mem.Allocator,
    plan: solver.Plan,
    lock: ?*const exact_lock.Lock,
    lock_v2: ?*const exact_lock_v2.Lock,
    verification: ExactLockVerification,
    journal: recovery.Journal,
    root: []const u8,
    status: recovery.StatusReader,
) !recovery.Verification {
    if (lock) |closure|
        return recovery.verifyExactLock(allocator, closure.*, root, status, 64 * 1024 * 1024);
    if (lock_v2) |closure| return switch (verification) {
        .full_closure => recovery.verifyExactLockV2WithEvidence(
            allocator,
            closure.*,
            plan,
            journal,
            root,
            status,
            64 * 1024 * 1024,
        ),
        .locked_packages => recovery.verifyExactLockV2LockedPackagesWithEvidence(
            allocator,
            closure.*,
            plan,
            journal,
            root,
            status,
            64 * 1024 * 1024,
        ),
    };
    return recovery.verify(allocator, plan, root, status, .{});
}

fn buildJournalCommands(
    allocator: std.mem.Allocator,
    request: Request,
    root_flag: []const u8,
    admin_flag: []const u8,
) ![]recovery.Command {
    var commands: std.ArrayList(recovery.Command) = .empty;
    for (request.plan.ordered_actions) |ordered| {
        const phase = try toPhase(ordered.kind);
        const artifact = if (phase == .bootstrap_extract or phase == .unpack)
            findArtifact(request.artifacts, ordered.package, ordered.version, ordered.architecture).?
        else
            null;
        const argv = try buildArgv(
            allocator,
            request.install_root,
            root_flag,
            admin_flag,
            phase,
            ordered.package,
            ordered.architecture,
            if (artifact) |item| item.path else null,
            request.policy,
        );
        const action = findPlanAction(request.plan.actions, ordered.package, ordered.version, ordered.architecture).?;
        try commands.append(allocator, .{
            .phase = @tagName(phase),
            .package = try allocator.dupe(u8, ordered.package),
            .command_sha256 = hashInvocation(argv, &audited_environment),
            .artifact_sha256 = if (phase == .unpack) try parseHexDigest(action.sha256.?) else null,
        });
    }
    if (request.plan.ordered_actions.len != 0) {
        const argv = try buildTriggerArgv(allocator, root_flag, admin_flag, request.policy);
        try commands.append(allocator, .{
            .phase = "triggers",
            .package = null,
            .command_sha256 = hashInvocation(argv, &audited_environment),
            .artifact_sha256 = null,
        });
    }
    return commands.toOwnedSlice(allocator);
}

fn journalFailure(
    allocator: std.mem.Allocator,
    err: anyerror,
    code: FailureCode,
    context: []const u8,
) Failure {
    return .{
        .code = code,
        .diagnostic = std.fmt.allocPrint(allocator, "{s}: {s}", .{ context, @errorName(err) }) catch context,
    };
}

fn preflight(arena: std.mem.Allocator, request: Request, filesystem: FileSystem) !void {
    try validateRootLexical(request.install_root, request.policy.risk.allow_host_root);
    filesystem.validateRoot(request.install_root) catch return error.UnsafeInstallRoot;
    if (request.plan.schema_version != 2 and request.plan.schema_version != 3)
        return error.UnsupportedPlanVersion;
    if (request.plan.mode != .plan_only) return error.NonExecutablePlanMode;
    // Purge is a native-engine transition. The legacy dpkg program has no
    // authorized representation for it and must fail before any mutation.
    for (request.plan.actions) |action|
        if (action.kind == .purge) return error.UnsupportedPurgeAction;
    for (request.plan.ordered_actions) |ordered|
        if (ordered.kind == .purge) return error.UnsupportedPurgeAction;
    if (request.plan.actions.len > 100_000 or request.plan.ordered_actions.len > 300_000)
        return error.PlanTooLarge;
    if (request.exact_lock != null and request.exact_lock_v2 != null)
        return error.MultipleExactLocks;
    if (request.policy.exact_lock_verification == .locked_packages and
        request.exact_lock_v2 == null)
        return error.LockedPackageVerificationRequiresV2Lock;
    if (request.exact_lock) |lock| {
        if (!std.mem.eql(u8, lock.target_architecture, request.plan.target_architecture))
            return error.LockArchitectureMismatch;
        for (request.plan.actions) |action| {
            if (action.kind == .remove) continue;
            const locked = lock.findPackage(action.package, action.version, action.architecture) orelse
                return error.PlanOutsideLockedClosure;
            if (action.repository == null or action.sha256 == null or action.package_size == null)
                return error.MissingAuthenticatedArtifactMetadata;
            const digest = parseHexDigest(action.sha256.?) catch return error.InvalidAuthenticatedDigest;
            if (!std.mem.eql(u8, &locked.repository_id, &action.repository.?.id) or
                !std.mem.eql(u8, &locked.sha256, &digest) or
                locked.declared_size != action.package_size.?)
                return error.PlanLockEvidenceMismatch;
        }
    }
    if (request.exact_lock_v2) |lock| {
        if (!std.mem.eql(u8, lock.target_architecture, request.plan.target_architecture))
            return error.LockArchitectureMismatch;
        for (request.plan.actions) |action| {
            if (action.kind == .remove) continue;
            const locked = lock.findPackage(action.package, action.version, action.architecture) orelse
                return error.PlanOutsideLockedClosure;
            if (action.sha256 == null or action.package_size == null)
                return error.MissingAuthenticatedArtifactMetadata;
            const digest = parseHexDigest(action.sha256.?) catch
                return error.InvalidAuthenticatedDigest;
            if (!actionMatchesLockV2(action, locked) or
                !std.mem.eql(u8, &locked.sha256, &digest) or
                locked.declared_size != action.package_size.?)
                return error.PlanLockEvidenceMismatch;
        }
    }
    if (request.policy.process_timeout_ms == 0) return error.InvalidProcessTimeout;
    if (request.policy.maximum_diagnostic_bytes > maximum_diagnostic_limit)
        return error.DiagnosticLimitTooLarge;
    try validateForces(request.policy.risk.force);

    var expected_sequence: usize = 0;
    for (request.plan.ordered_actions) |ordered| {
        if (ordered.sequence != expected_sequence) return error.NonCanonicalSequence;
        expected_sequence += 1;
        try validateIdentity(ordered.package);
        try validateIdentity(ordered.version);
        try validateIdentity(ordered.architecture);
        const action = findPlanAction(request.plan.actions, ordered.package, ordered.version, ordered.architecture) orelse
            return error.OrderedActionMissingPlanAction;
        switch (ordered.kind) {
            .remove => if (action.kind != .remove) return error.InvalidRemoveOrdering,
            .purge => return error.UnsupportedPurgeAction,
            .bootstrap_extract, .unpack, .configure_pending => if (solver.isRemoval(action.kind)) return error.InvalidInstallOrdering,
        }
        if ((ordered.kind == .bootstrap_extract or ordered.kind == .unpack) and
            findArtifact(request.artifacts, ordered.package, ordered.version, ordered.architecture) == null)
            return error.MissingArtifact;
    }
    for (request.plan.actions, 0..) |action, action_index| {
        for (request.plan.actions[0..action_index]) |prior| {
            if (samePackageArchitecture(prior.package, prior.architecture, action.package, action.architecture))
                return error.DuplicatePlanAction;
        }
        var removes: usize = 0;
        var bootstrap_extracts: usize = 0;
        var unpacks: usize = 0;
        var configure_pending_count: usize = 0;
        var unpack_index: ?usize = null;
        for (request.plan.ordered_actions, 0..) |ordered, ordered_index| {
            if (!sameIdentity(action.package, action.version, action.architecture, ordered.package, ordered.version, ordered.architecture))
                continue;
            switch (ordered.kind) {
                .bootstrap_extract => bootstrap_extracts += 1,
                .remove => removes += 1,
                .unpack => {
                    unpacks += 1;
                    unpack_index = ordered_index;
                },
                .configure_pending => configure_pending_count += 1,
                .purge => return error.UnsupportedPurgeAction,
            }
        }
        if (action.kind == .remove) {
            if (bootstrap_extracts != 0 or removes != 1 or unpacks != 0 or configure_pending_count != 0) return error.IncompleteRemoveOrdering;
        } else if (removes != 0 or unpacks != 1) {
            return error.IncompleteInstallOrdering;
        } else {
            const expected_bootstrap: usize = if (requiresRootBootstrap(request.plan.actions) and action.prior_installed == null) 1 else 0;
            if (bootstrap_extracts != expected_bootstrap) return error.IncompleteInstallOrdering;
            if (action.sha256 == null or action.package_size == null)
                return error.MissingAuthenticatedArtifactMetadata;
            _ = parseHexDigest(action.sha256.?) catch return error.InvalidAuthenticatedDigest;
            try validateActionOrigin(request.plan.schema_version, action);
        }
    }
    var last_unpack: ?usize = null;
    var last_configure_pending: ?usize = null;
    for (request.plan.ordered_actions, 0..) |ordered, index| switch (ordered.kind) {
        .unpack => last_unpack = index,
        .configure_pending => last_configure_pending = index,
        else => {},
    };
    if (last_unpack != null and (last_configure_pending == null or last_configure_pending.? < last_unpack.?))
        return error.IncompleteInstallOrdering;

    for (request.artifacts, 0..) |artifact, index| {
        try validateIdentity(artifact.package);
        try validateIdentity(artifact.version);
        try validateIdentity(artifact.architecture);
        try validateAbsolutePath(artifact.path);
        filesystem.validateArtifactPath(artifact.path) catch return error.UnsafeArtifactPath;
        const action = findPlanAction(request.plan.actions, artifact.package, artifact.version, artifact.architecture) orelse
            return error.UnplannedArtifact;
        if (action.kind == .remove) return error.RemoveArtifact;
        for (request.artifacts[0..index]) |prior| {
            if (sameIdentity(prior.package, prior.version, prior.architecture, artifact.package, artifact.version, artifact.architecture))
                return error.DuplicateArtifact;
        }
    }

    _ = arena;
}

fn validateActionOrigin(schema_version: u32, action: solver.PlanAction) !void {
    if (schema_version == 2) {
        if (action.repository == null) return error.MissingAuthenticatedArtifactMetadata;
        return;
    }
    const origin = action.origin orelse return error.MissingPackageOrigin;
    switch (origin) {
        .authenticated_repository => |repository| {
            if (action.repository == null or
                !std.mem.eql(u8, &action.repository.?.id, &repository.id) or
                action.repository.?.priority != repository.priority)
                return error.PackageOriginMismatch;
        },
        .local_artifact => |local| {
            if (action.repository != null) return error.PackageOriginMismatch;
            package_origin.validateLocalArtifact(local.evidence) catch
                return error.InvalidLocalArtifactOrigin;
            const digest = parseHexDigest(action.sha256 orelse
                return error.MissingAuthenticatedDigest) catch
                return error.InvalidAuthenticatedDigest;
            if (!std.mem.eql(u8, action.package, local.evidence.package) or
                !std.mem.eql(u8, action.version, local.evidence.version) or
                !std.mem.eql(u8, action.architecture, local.evidence.architecture) or
                !std.mem.eql(u8, &digest, &local.evidence.sha256) or
                action.package_size != local.evidence.size)
                return error.PackageOriginMismatch;
        },
    }
}

fn actionMatchesLockV2(
    action: solver.PlanAction,
    locked: exact_lock_v2.Package,
) bool {
    const origin = action.origin orelse return false;
    return switch (locked.origin) {
        .authenticated_repository => |expected| switch (origin) {
            .authenticated_repository => |actual| std.mem.eql(u8, &actual.id, &expected.repository_id),
            .local_artifact => false,
        },
        .local_artifact => |expected| switch (origin) {
            .authenticated_repository => false,
            .local_artifact => |actual| package_origin.eqlLocalArtifact(actual.evidence, expected),
        },
    };
}

fn validateArtifact(
    allocator: std.mem.Allocator,
    filesystem: FileSystem,
    artifact: Artifact,
    action: solver.PlanAction,
    limits: deb_payload.Limits,
) ![32]u8 {
    const expected_size = action.package_size orelse return error.MissingAuthenticatedSize;
    const expected_hex = action.sha256 orelse return error.MissingAuthenticatedDigest;
    const expected_digest = parseHexDigest(expected_hex) catch return error.InvalidAuthenticatedDigest;
    const maximum = std.math.cast(usize, expected_size) orelse return error.ArtifactTooLarge;
    const bytes = try filesystem.readArtifact(allocator, artifact.path, maximum);
    defer allocator.free(bytes);
    if (bytes.len != expected_size) return error.SizeMismatch;
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    if (!std.mem.eql(u8, &actual, &expected_digest)) return error.DigestMismatch;

    const validation = if (isLocalArtifactAction(action))
        deb_payload.inspectLocal(allocator, bytes, .{
            .size = expected_size,
            .sha256 = expected_digest,
            .filename = std.fs.path.basename(artifact.path),
            .identity = .{
                .package = artifact.package,
                .version = artifact.version,
                .architecture = artifact.architecture,
            },
        }, limits)
    else blk: {
        var repository_hex: [64]u8 = @splat('0');
        if (action.repository) |repository| repository_hex = repository.id;
        break :blk deb_payload.validate(allocator, bytes, .{
            .repository = &repository_hex,
            .package = artifact.package,
            .version = artifact.version,
            .architecture = artifact.architecture,
            .requested_package = action.package,
            .requested_version = action.version,
            .requested_architecture = action.architecture,
            .filename = std.fs.path.basename(artifact.path),
            .size = expected_size,
            .sha256 = expected_digest,
            .require_conventional_filename = false,
        }, limits);
    };
    switch (validation) {
        .diagnostic => |diagnostic| switch (diagnostic.code) {
            .digest_mismatch, .size_mismatch => return error.DigestMismatch,
            .identity_mismatch, .request_mismatch => return error.IdentityMismatch,
            else => return error.InvalidDebPayload,
        },
        .validation => |value| {
            var owned = value;
            owned.deinit();
        },
    }
    return actual;
}

fn isLocalArtifactAction(action: solver.PlanAction) bool {
    const origin = action.origin orelse return false;
    return switch (origin) {
        .authenticated_repository => false,
        .local_artifact => true,
    };
}

fn buildArgv(
    allocator: std.mem.Allocator,
    install_root: []const u8,
    root_flag: []const u8,
    admin_flag: []const u8,
    phase: Phase,
    package: []const u8,
    architecture: []const u8,
    artifact_path: ?[]const u8,
    policy: Policy,
) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    if (phase == .bootstrap_extract) {
        try argv.append(allocator, "/usr/bin/dpkg-deb");
        try argv.append(allocator, "--extract");
        try argv.append(allocator, artifact_path.?);
        try argv.append(allocator, install_root);
        return argv.toOwnedSlice(allocator);
    }
    try argv.append(allocator, "/usr/bin/dpkg");
    try argv.append(allocator, root_flag);
    try argv.append(allocator, admin_flag);
    try argv.append(allocator, "--no-pager");
    if (phase != .configure_pending) try argv.append(allocator, "--abort-after=1");
    try argv.append(allocator, conffileArg(policy.conffile));
    for (policy.risk.force) |risk| try argv.append(allocator, forceArg(risk));
    try argv.append(allocator, "--no-triggers");
    switch (phase) {
        .remove => {
            try argv.append(allocator, "--remove");
            try argv.append(allocator, try packageSpec(allocator, package, architecture));
        },
        .unpack => {
            try argv.append(allocator, "--unpack");
            try argv.append(allocator, artifact_path.?);
        },
        .configure_pending => {
            try argv.append(allocator, "--configure");
            try argv.append(allocator, "--pending");
        },
        .configure => {
            try argv.append(allocator, "--configure");
            try argv.append(allocator, try packageSpec(allocator, package, architecture));
        },
        .bootstrap_extract, .triggers, .audit => unreachable,
    }
    return argv.toOwnedSlice(allocator);
}

fn buildTriggerArgv(
    allocator: std.mem.Allocator,
    root_flag: []const u8,
    admin_flag: []const u8,
    policy: Policy,
) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(allocator, "/usr/bin/dpkg");
    try argv.append(allocator, root_flag);
    try argv.append(allocator, admin_flag);
    try argv.append(allocator, "--no-pager");
    try argv.append(allocator, "--abort-after=1");
    try argv.append(allocator, conffileArg(policy.conffile));
    for (policy.risk.force) |risk| try argv.append(allocator, forceArg(risk));
    try argv.append(allocator, "--triggers-only");
    try argv.append(allocator, "--pending");
    return argv.toOwnedSlice(allocator);
}

fn buildRecoveryArgv(
    allocator: std.mem.Allocator,
    root_flag: []const u8,
    admin_flag: []const u8,
    policy: Policy,
    phase: Phase,
) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(allocator, "/usr/bin/dpkg");
    try argv.append(allocator, root_flag);
    try argv.append(allocator, admin_flag);
    try argv.append(allocator, "--no-pager");
    try argv.append(allocator, "--abort-after=1");
    try argv.append(allocator, conffileArg(policy.conffile));
    switch (phase) {
        .audit => try argv.append(allocator, "--audit"),
        .configure => {
            try argv.append(allocator, "--configure");
            try argv.append(allocator, "--pending");
        },
        .triggers => {
            try argv.append(allocator, "--triggers-only");
            try argv.append(allocator, "--pending");
        },
        else => unreachable,
    }
    return argv.toOwnedSlice(allocator);
}

fn processFailure(
    allocator: std.mem.Allocator,
    result: ProcessResult,
    phase: Phase,
    package: ?[]const u8,
    diagnostic_limit: usize,
    completed: usize,
) !Failure {
    const diagnostic = try allocator.dupe(u8, result.stderr[0..@min(result.stderr.len, diagnostic_limit)]);
    const owned_package = if (package) |value| try allocator.dupe(u8, value) else null;
    return switch (result.termination) {
        .exited => |code| .{
            .code = .dpkg_failed,
            .phase = phase,
            .package = owned_package,
            .exit_code = code,
            .diagnostic = diagnostic,
            .completed_commands = completed,
        },
        .signaled => |signal| .{
            .code = .interrupted,
            .phase = phase,
            .package = owned_package,
            .signal = signal,
            .diagnostic = diagnostic,
            .completed_commands = completed,
        },
        .cancelled => interruption(phase, owned_package, completed, diagnostic),
    };
}

fn configuredPackageCount(
    allocator: std.mem.Allocator,
    status: recovery.StatusReader,
    root: []const u8,
) !usize {
    const source = try status.read(allocator, root, 64 * 1024 * 1024);
    defer allocator.free(source);
    const parsed = try dpkg_status.parseOwned(allocator, source, .{});
    var database = switch (parsed) {
        .diagnostic => return error.InvalidDpkgStatus,
        .database => |value| value,
    };
    defer database.deinit();
    var count: usize = 0;
    for (database.database.packages) |package|
        if (package.status.isFullyInstalled()) {
            count += 1;
        };
    return count;
}

fn interruption(phase: ?Phase, package: ?[]const u8, completed: usize, diagnostic: []const u8) Failure {
    return .{
        .code = .interrupted,
        .phase = phase,
        .package = package,
        .diagnostic = diagnostic,
        .completed_commands = completed,
    };
}

fn successful(termination: ProcessTermination) bool {
    return switch (termination) {
        .exited => |code| code == 0,
        else => false,
    };
}

const DeadlineCancellationContext = struct {
    base: Cancellation,
    deadline: ?Deadline,

    fn interface(self: *DeadlineCancellationContext) Cancellation {
        return .{ .context = self, .cancelledFn = cancelled };
    }

    fn cancelled(context: *anyopaque) bool {
        const self: *DeadlineCancellationContext = @ptrCast(@alignCast(context));
        return self.base.cancelled() or deadlineExpired(self.deadline);
    }
};

fn deadlineExpired(deadline: ?Deadline) bool {
    return if (deadline) |value| value.expired() else false;
}

fn remainingTimeout(deadline: ?Deadline, requested_ms: u64) !u64 {
    if (requested_ms == 0) return error.DeadlineExceeded;
    const remaining = if (deadline) |value|
        try value.remainingMs()
    else
        requested_ms;
    const bounded = @min(requested_ms, remaining);
    if (bounded == 0) return error.DeadlineExceeded;
    return bounded;
}

fn deadlineFailure(
    allocator: std.mem.Allocator,
    phase: ?Phase,
    package: ?[]const u8,
    completed: usize,
) Failure {
    return .{
        .code = .process_timeout,
        .phase = phase,
        .package = if (package) |value|
            allocator.dupe(u8, value) catch value
        else
            null,
        .diagnostic = "overall operation deadline exceeded",
        .completed_commands = completed,
    };
}

fn locksHeld(manager: LockManager, held: []const ?LockToken) bool {
    for (held) |token| if (token) |value| {
        if (!manager.held(value)) return false;
    };
    return true;
}

fn validateRootLexical(root: []const u8, allow_host_root: bool) !void {
    try validateAbsolutePath(root);
    if (std.mem.eql(u8, root, "/") and !allow_host_root) return error.HostRootDenied;
    if (root.len > 1 and root[root.len - 1] == '/') return error.AmbiguousRoot;
}

fn validateAbsolutePath(path: []const u8) !void {
    if (!absolute_path.root(path)) return error.InvalidAbsolutePath;
}

fn validateIdentity(value: []const u8) !void {
    if (value.len == 0 or value.len > 4096) return error.InvalidIdentity;
    if (std.mem.findAny(u8, value, &.{ 0, '\n', '\r' }) != null) return error.InvalidIdentity;
    if (value[0] == '-') return error.OptionLikeIdentity;
}

fn requiresRootBootstrap(actions: []const solver.PlanAction) bool {
    for (actions) |action|
        if (action.kind != .remove and action.essential and action.prior_installed == null) return true;
    return false;
}

fn validateForces(forces: []const ForceRisk) !void {
    for (forces, 0..) |force, index| {
        for (forces[0..index]) |prior| if (prior == force) return error.DuplicateForceRisk;
    }
}

fn findArtifact(artifacts: []const Artifact, package: []const u8, version: []const u8, architecture: []const u8) ?Artifact {
    for (artifacts) |artifact| {
        if (sameIdentity(artifact.package, artifact.version, artifact.architecture, package, version, architecture))
            return artifact;
    }
    return null;
}

fn findPlanAction(actions: []const solver.PlanAction, package: []const u8, version: []const u8, architecture: []const u8) ?solver.PlanAction {
    for (actions) |action| {
        if (sameIdentity(action.package, action.version, action.architecture, package, version, architecture))
            return action;
    }
    return null;
}

fn sameIdentity(
    a_package: []const u8,
    a_version: []const u8,
    a_architecture: []const u8,
    b_package: []const u8,
    b_version: []const u8,
    b_architecture: []const u8,
) bool {
    return std.mem.eql(u8, a_package, b_package) and
        std.mem.eql(u8, a_version, b_version) and
        std.mem.eql(u8, a_architecture, b_architecture);
}

fn samePackageArchitecture(
    a_package: []const u8,
    a_architecture: []const u8,
    b_package: []const u8,
    b_architecture: []const u8,
) bool {
    return std.mem.eql(u8, a_package, b_package) and
        std.mem.eql(u8, a_architecture, b_architecture);
}

/// Legacy dpkg programs have no purge phase. Preflight rejects purge before
/// execution, and this mapping stays fail-closed rather than reinterpreting it
/// as a plain removal.
fn toPhase(kind: solver.OrderedActionKind) error{UnsupportedPurgeAction}!Phase {
    return switch (kind) {
        .bootstrap_extract => .bootstrap_extract,
        .remove => .remove,
        .unpack => .unpack,
        .configure_pending => .configure_pending,
        .purge => error.UnsupportedPurgeAction,
    };
}

fn conffileArg(policy: ConffilePolicy) []const u8 {
    return switch (policy) {
        .keep_existing => "--force-confold",
        .use_package_version => "--force-confnew",
    };
}

fn forceArg(risk: ForceRisk) []const u8 {
    return switch (risk) {
        .depends => "--force-depends",
        .depends_version => "--force-depends-version",
        .break_replaces => "--force-breaks",
        .overwrite => "--force-overwrite",
        .overwrite_dir => "--force-overwrite-dir",
        .remove_reinstreq => "--force-remove-reinstreq",
    };
}

fn packageSpec(allocator: std.mem.Allocator, package: []const u8, architecture: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}:{s}", .{ package, architecture });
}

fn rootPath(allocator: std.mem.Allocator, root: []const u8, suffix: []const u8) ![]const u8 {
    if (std.mem.eql(u8, root, "/")) return std.fmt.allocPrint(allocator, "/{s}", .{suffix});
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, suffix });
}

fn parseHexDigest(hex: [64]u8) ![32]u8 {
    var output: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&output, &hex);
    return output;
}

fn hashPlan(plan: solver.Plan) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-plan-execution-v1\x00");
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, @intCast(plan.schema_version), .little);
    hash.update(&number);
    hash.update(plan.target_architecture);
    hash.update("\x00");
    hash.update(@tagName(plan.mode));
    hash.update("\x00");
    for (plan.actions) |action| {
        hash.update(@tagName(action.kind));
        hash.update("\x00");
        hash.update(action.package);
        hash.update("\x00");
        hash.update(action.version);
        hash.update("\x00");
        hash.update(action.architecture);
        hash.update("\x00");
        if (action.repository) |repository| hash.update(&repository.id);
        hash.update("\x00");
        if (plan.schema_version == 3) hashPlanOrigin(&hash, action.origin);
        if (action.sha256) |digest| hash.update(&digest);
        hash.update("\x00");
        std.mem.writeInt(u64, &number, action.package_size orelse 0, .little);
        hash.update(&number);
    }
    hash.update("\xfe");
    for (plan.ordered_actions) |action| {
        std.mem.writeInt(u64, &number, @intCast(action.sequence), .little);
        hash.update(&number);
        hash.update(@tagName(action.kind));
        hash.update("\x00");
        hash.update(action.package);
        hash.update("\x00");
        hash.update(action.version);
        hash.update("\x00");
        hash.update(action.architecture);
        hash.update("\x00");
    }
    return hash.finalResult();
}

fn hashPlanOrigin(
    hash: *std.crypto.hash.sha2.Sha256,
    origin: ?solver.PlanOrigin,
) void {
    const value = origin orelse {
        hash.update(&.{0});
        return;
    };
    var number: [8]u8 = undefined;
    var priority: [4]u8 = undefined;
    switch (value) {
        .authenticated_repository => |repository| {
            hash.update(&.{1});
            hash.update(&repository.id);
            std.mem.writeInt(i32, &priority, repository.priority, .little);
            hash.update(&priority);
        },
        .local_artifact => |local| {
            const evidence = local.evidence;
            hash.update(&.{2});
            hash.update(&evidence.artifact_id);
            hash.update(&evidence.sha256);
            std.mem.writeInt(u64, &number, evidence.size, .little);
            hash.update(&number);
            hashPlanString(hash, evidence.package);
            hashPlanString(hash, evidence.version);
            hashPlanString(hash, evidence.architecture);
            hashPlanString(hash, evidence.acquisition_url);
            hashPlanString(hash, @tagName(evidence.trust_mode));
            std.mem.writeInt(i32, &priority, local.solver_priority, .little);
            hash.update(&priority);
        },
    }
}

fn hashPlanString(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, @intCast(value.len), .little);
    hash.update(&length);
    hash.update(value);
}

fn hashInvocation(argv: []const []const u8, environment: []const EnvironmentEntry) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-dpkg-command-v1\x00");
    for (argv) |arg| {
        hash.update(arg);
        hash.update("\x00");
    }

    hash.update("\xff");
    for (environment) |entry| {
        hash.update(entry.key);
        hash.update("=");
        hash.update(entry.value);
        hash.update("\x00");
    }
    return hash.finalResult();
}

pub fn policyDigest(policy: Policy) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-executor-policy-v1\x00");
    hash.update(@tagName(policy.conffile));
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, policy.locks.wait_ms, .little);
    hash.update(&number);
    std.mem.writeInt(u64, &number, policy.process_timeout_ms, .little);
    hash.update(&number);
    for (policy.risk.force) |force| {
        hash.update(@tagName(force));
        hash.update("\x00");
    }
    if (policy.exact_lock_verification != .full_closure) {
        hash.update("\xffexact-lock-verification\x00");
        hash.update(@tagName(policy.exact_lock_verification));
        hash.update("\x00");
    }
    return hash.finalResult();
}

fn hashPolicy(policy: Policy) [32]u8 {
    return policyDigest(policy);
}

fn optionalDigestEqual(left: ?[32]u8, right: ?[32]u8) bool {
    if (left == null or right == null) return left == null and right == null;
    return std.mem.eql(u8, &left.?, &right.?);
}

fn preflightCode(err: anyerror) FailureCode {
    return switch (err) {
        error.HostRootDenied, error.InvalidAbsolutePath, error.AmbiguousRoot, error.AmbiguousPath, error.UnsafeInstallRoot => .invalid_root,
        error.MissingArtifact => .artifact_missing,
        error.UnsafeArtifactPath => .invalid_artifact,
        error.DuplicateForceRisk => .unsupported_force_policy,
        error.OutOfMemory => .out_of_memory,
        else => .invalid_plan,
    };
}

fn artifactCode(err: anyerror) FailureCode {
    return switch (err) {
        error.FileNotFound => .artifact_missing,
        error.DigestMismatch, error.SizeMismatch => .artifact_digest_mismatch,
        error.IdentityMismatch => .artifact_identity_mismatch,
        else => .invalid_artifact,
    };
}

/// Production direct process adapter. It replaces, rather than inherits, the
/// environment and captures bounded diagnostics. No shell is involved.
pub const SystemProcessRunner = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stderr_limit: usize = 64 * 1024,
    last_stderr: ?[]u8 = null,

    pub fn interface(self: *SystemProcessRunner) ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    pub fn deinit(self: *SystemProcessRunner) void {
        if (self.last_stderr) |stderr| self.allocator.free(stderr);
        self.last_stderr = null;
    }

    fn run(context: *anyopaque, invocation: Invocation) !ProcessResult {
        const self: *SystemProcessRunner = @ptrCast(@alignCast(context));
        if (self.last_stderr) |stderr| self.allocator.free(stderr);
        self.last_stderr = null;
        var environment = std.process.Environ.Map.init(self.allocator);
        defer environment.deinit();
        for (invocation.environment) |entry| try environment.put(entry.key, entry.value);

        const Outcome = union(enum) {
            result: std.process.RunError!std.process.RunResult,
            cancelled,
        };
        var outcomes: [2]Outcome = undefined;
        var select = std.Io.Select(Outcome).init(self.io, &outcomes);
        select.async(.result, runChild, .{ self, invocation, &environment });
        select.async(.cancelled, waitCancellation, .{ self.io, invocation.cancellation });
        errdefer select.cancelDiscard();
        const result = switch (try select.await()) {
            .result => |result| result: {
                select.cancelDiscard();
                break :result try result;
            },
            .cancelled => {
                while (select.cancel()) |outcome| switch (outcome) {
                    .result => |result| if (result) |completed| {
                        self.allocator.free(completed.stdout);
                        self.allocator.free(completed.stderr);
                    } else |_| {},
                    .cancelled => {},
                };
                return .{ .termination = .cancelled };
            },
        };
        const diagnostics = try std.mem.concat(self.allocator, u8, &.{ result.stdout, result.stderr });
        self.allocator.free(result.stdout);
        self.allocator.free(result.stderr);
        self.last_stderr = diagnostics;
        const termination: ProcessTermination = switch (result.term) {
            .exited => |code| .{ .exited = code },
            .signal => |signal| .{ .signaled = @intFromEnum(signal) },
            .stopped => |signal| .{ .signaled = @intFromEnum(signal) },
            .unknown => |status| .{ .signaled = status },
        };
        return .{ .termination = termination, .stderr = diagnostics };
    }

    fn runChild(
        self: *SystemProcessRunner,
        invocation: Invocation,
        environment: *const std.process.Environ.Map,
    ) std.process.RunError!std.process.RunResult {
        return std.process.run(self.allocator, self.io, .{
            .argv = invocation.argv,
            .environ_map = environment,
            .stdout_limit = .limited(self.stderr_limit),
            .stderr_limit = .limited(self.stderr_limit),
            .timeout = .{ .duration = .{
                .raw = .fromMilliseconds(@intCast(@min(
                    invocation.timeout_ms,
                    @as(u64, std.math.maxInt(i64)),
                ))),
                .clock = .awake,
            } },
        });
    }

    fn waitCancellation(io: std.Io, cancellation: Cancellation) void {
        while (!cancellation.cancelled()) {
            io.sleep(.fromMilliseconds(10), .awake) catch return;
        }
    }
};

/// Production filesystem adapter. Every install-root component is opened with
/// symlink following disabled; artifact leaf symlinks are also rejected.
pub const SystemFileSystem = struct {
    allocator: std.mem.Allocator,
    io: std.Io,

    pub fn interface(self: *SystemFileSystem) FileSystem {
        return .{
            .context = self,
            .validateRootFn = validateRoot,
            .normalizeBootstrapRootFn = normalizeBootstrapRoot,
            .validateArtifactPathFn = validateArtifactPath,
            .readArtifactFn = readArtifact,
        };
    }

    fn validateRoot(context: *anyopaque, root: []const u8) !void {
        const self: *SystemFileSystem = @ptrCast(@alignCast(context));
        if (std.mem.eql(u8, root, "/")) {
            var root_dir = try std.Io.Dir.openDirAbsolute(self.io, "/", .{ .follow_symlinks = false });
            root_dir.close(self.io);
            return;
        }
        var current = try std.Io.Dir.openDirAbsolute(self.io, "/", .{ .follow_symlinks = false });
        defer current.close(self.io);
        var components = std.mem.splitScalar(u8, root[1..], '/');
        while (components.next()) |component| {
            const next = try current.openDir(self.io, component, .{ .follow_symlinks = false });
            current.close(self.io);
            current = next;
        }
    }

    /// Whether `name` names an existing directory under `directory`, used to
    /// tell a merged-usr target that is really there from one this
    /// architecture simply does not have.
    fn directoryExists(io: std.Io, directory: std.Io.Dir, name: []const u8) bool {
        var opened = directory.openDir(io, name, .{ .follow_symlinks = false }) catch return false;
        opened.close(io);
        return true;
    }

    fn normalizeBootstrapRoot(context: *anyopaque, root: []const u8) !void {
        const self: *SystemFileSystem = @ptrCast(@alignCast(context));
        var directory = try std.Io.Dir.openDirAbsolute(self.io, root, .{
            .iterate = true,
            .follow_symlinks = false,
        });
        defer directory.close(self.io);
        for ([_][2][]const u8{
            .{ "bin", "usr/bin" },
            .{ "sbin", "usr/sbin" },
            .{ "lib", "usr/lib" },
            .{ "lib64", "usr/lib64" },
        }) |mapping| {
            var target_buffer: [64]u8 = undefined;
            if (directory.readLink(self.io, mapping[0], &target_buffer)) |length| {
                if (!std.mem.eql(u8, target_buffer[0..length], mapping[1]))
                    return error.UnsafeMergedUsrLink;
                continue;
            } else |_| {}

            var legacy = directory.openDir(self.io, mapping[0], .{
                .iterate = true,
                .follow_symlinks = false,
            }) catch |err| switch (err) {
                error.FileNotFound => {
                    // A merged-usr link is only meaningful when the directory
                    // it merges into exists. /lib64 is architecture-specific --
                    // amd64 and s390x carry usr/lib64, arm64 has none -- so
                    // linking unconditionally left arm64 roots with a dangling
                    // /lib64, and base-files' preinst refuses to unpack against
                    // one ("cannot proceed with the upgrade"), which failed the
                    // bootstrap of every arm64 root at the first package.
                    if (directoryExists(self.io, directory, mapping[1]))
                        try directory.symLink(self.io, mapping[1], mapping[0], .{ .is_directory = true });
                    continue;
                },
                else => return err,
            };
            var merged = try directory.openDir(self.io, mapping[1], .{
                .iterate = true,
                .follow_symlinks = false,
            });
            mergeBootstrapDirectory(self.io, legacy, merged) catch |err| {
                merged.close(self.io);
                legacy.close(self.io);
                return err;
            };
            merged.close(self.io);
            legacy.close(self.io);
            try directory.deleteDir(self.io, mapping[0]);
            try directory.symLink(self.io, mapping[1], mapping[0], .{ .is_directory = true });
        }
        inline for (.{
            .{ "usr/share/base-passwd/passwd.master", "etc/passwd" },
            .{ "usr/share/base-passwd/group.master", "etc/group" },
        }) |mapping| {
            const bytes: ?[]u8 = directory.readFileAlloc(
                self.io,
                mapping[0],
                self.allocator,
                .limited(64 * 1024),
            ) catch |err| switch (err) {
                error.FileNotFound => null,
                else => return err,
            };
            if (bytes) |contents| {
                defer self.allocator.free(contents);
                try directory.writeFile(self.io, .{ .sub_path = mapping[1], .data = contents });
            }
        }
    }

    fn readArtifact(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        maximum: usize,
    ) ![]u8 {
        const self: *SystemFileSystem = @ptrCast(@alignCast(context));
        const parent = std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath;
        try validateRoot(context, parent);
        var file = try std.Io.Dir.openFileAbsolute(self.io, path, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
        });
        defer file.close(self.io);
        var reader_buffer: [8192]u8 = undefined;
        var reader = file.reader(self.io, &reader_buffer);
        const probe_limit = std.math.add(usize, maximum, 1) catch maximum;
        const bytes = try reader.interface.allocRemaining(allocator, .limited(probe_limit));
        if (bytes.len > maximum) {
            allocator.free(bytes);
            return error.StreamTooLong;
        }
        return bytes;
    }

    fn validateArtifactPath(context: *anyopaque, path: []const u8) !void {
        const self: *SystemFileSystem = @ptrCast(@alignCast(context));
        const parent = std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath;
        try validateRoot(context, parent);
        var file = try std.Io.Dir.openFileAbsolute(self.io, path, .{
            .mode = .read_only,
            .allow_directory = false,
            .path_only = true,
            .follow_symlinks = false,
        });
        file.close(self.io);
    }
};

fn mergeBootstrapDirectory(io: std.Io, source: std.Io.Dir, target: std.Io.Dir) !void {
    while (true) {
        var iterator = source.iterate();
        const entry = try iterator.next(io) orelse break;
        switch (entry.kind) {
            .directory => {
                var source_child = try source.openDir(io, entry.name, .{
                    .iterate = true,
                    .follow_symlinks = false,
                });
                var target_child = target.openDir(io, entry.name, .{
                    .iterate = true,
                    .follow_symlinks = false,
                }) catch |err| switch (err) {
                    error.FileNotFound => {
                        source_child.close(io);
                        try source.rename(entry.name, target, entry.name, io);
                        continue;
                    },
                    else => {
                        source_child.close(io);
                        return err;
                    },
                };
                mergeBootstrapDirectory(io, source_child, target_child) catch |err| {
                    target_child.close(io);
                    source_child.close(io);
                    return err;
                };
                target_child.close(io);
                source_child.close(io);
                try source.deleteDir(io, entry.name);
            },
            .file, .sym_link => {
                if (target.statFile(io, entry.name, .{})) |_| return error.BootstrapPathCollision else |err| switch (err) {
                    error.FileNotFound => {},
                    else => return err,
                }
                try source.rename(entry.name, target, entry.name, io);
            },
            else => return error.UnsafeBootstrapEntry,
        }
    }
}

/// Production bounded advisory lock adapter. A token owns an open-file-
/// description lock and its file descriptor until release.
pub const SystemLockManager = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    retry_ms: u64 = 10,

    const Token = struct {
        file: std.Io.File,
        held: bool = true,
    };

    pub fn interface(self: *SystemLockManager) LockManager {
        return .{
            .context = self,
            .acquireFn = acquire,
            .heldFn = held,
            .releaseFn = release,
        };
    }

    fn acquire(context: *anyopaque, path: []const u8, wait_ms: u64) !LockToken {
        const self: *SystemLockManager = @ptrCast(@alignCast(context));
        const started = std.Io.Clock.awake.now(self.io);
        while (true) {
            const file = try self.openLockFile(path);
            var record: std.os.linux.Flock = .{
                .type = std.os.linux.F.WRLCK,
                .whence = 0,
                .start = 0,
                .len = 0,
                .pid = 0,
                ._unused = {},
            };
            const lock_result = std.os.linux.fcntl(
                file.handle,
                // OFD locks conflict with dpkg's POSIX record locks, but are
                // scoped to this open file description instead of the whole
                // process. Independent managers in concurrent embedding
                // threads therefore serialize just like separate processes,
                // and closing another descriptor cannot release this token.
                std.os.linux.F.OFD_SETLK,
                @intFromPtr(&record),
            );
            const lock_errno = std.os.linux.errno(lock_result);
            if (lock_errno != .SUCCESS) {
                file.close(self.io);
                if (lock_errno == .ACCES or lock_errno == .AGAIN) {
                    const elapsed = started.durationTo(std.Io.Clock.awake.now(self.io)).toMilliseconds();
                    if (elapsed >= wait_ms) return error.LockTimeout;
                    try std.Io.sleep(
                        self.io,
                        .fromMilliseconds(@intCast(@min(self.retry_ms, wait_ms - @as(u64, @intCast(elapsed))))),
                        .awake,
                    );
                    continue;
                }
                return error.LockFailed;
            }
            const token = self.allocator.create(Token) catch |err| {
                file.close(self.io);
                return err;
            };
            token.* = .{ .file = file };
            return token;
        }
    }

    fn openLockFile(self: *SystemLockManager, path: []const u8) !std.Io.File {
        const parent = std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath;
        const basename = std.fs.path.basename(path);
        var current = try std.Io.Dir.openDirAbsolute(self.io, "/", .{ .follow_symlinks = false });
        defer current.close(self.io);
        var components = std.mem.splitScalar(u8, parent[1..], '/');
        while (components.next()) |component| {
            if (component.len == 0) continue;
            const next = current.openDir(self.io, component, .{ .follow_symlinks = false }) catch |err| switch (err) {
                // debz owns its transaction bookkeeping directory
                // (var/lib/debz) and must provision it rather than trusting the
                // caller's root to already carry it. An authenticated Ubuntu
                // root only ships var/lib/dpkg, so customizing into a staged
                // copy walked into a missing var/lib/debz and surfaced a bare
                // FileNotFound. Create the missing component in place without
                // following symlinks; losing the race to a concurrent creator
                // is fine because the directory is all we need.
                error.FileNotFound => blk: {
                    current.createDir(self.io, component, .default_dir) catch |create_err| switch (create_err) {
                        error.PathAlreadyExists => {},
                        else => return create_err,
                    };
                    break :blk try current.openDir(self.io, component, .{ .follow_symlinks = false });
                },
                else => return err,
            };
            current.close(self.io);
            current = next;
        }
        while (true) {
            return current.openFile(self.io, basename, .{
                .mode = .read_write,
                .allow_directory = false,
                .follow_symlinks = false,
                .resolve_beneath = true,
            }) catch |open_err| switch (open_err) {
                error.FileNotFound => current.createFile(self.io, basename, .{
                    .read = true,
                    .truncate = false,
                    .exclusive = true,
                    .resolve_beneath = true,
                }) catch |create_err| switch (create_err) {
                    error.PathAlreadyExists => continue,
                    else => return create_err,
                },
                else => return open_err,
            };
        }
    }

    fn held(_: *anyopaque, token_ptr: LockToken) bool {
        const token: *Token = @ptrCast(@alignCast(token_ptr));
        return token.held;
    }

    fn release(context: *anyopaque, token_ptr: LockToken) void {
        const self: *SystemLockManager = @ptrCast(@alignCast(context));
        const token: *Token = @ptrCast(@alignCast(token_ptr));
        if (token.held) token.file.close(self.io);
        token.held = false;
        self.allocator.destroy(token);
    }
};

const TestHarness = struct {
    bytes: []const u8,
    root_valid: bool = true,
    root_validate_count: usize = 0,
    root_fail_after: ?usize = null,
    corrupt_read: bool = false,
    lock_fail_at: ?usize = null,
    lock_acquires: usize = 0,
    lock_releases: usize = 0,
    lock_held: bool = true,
    invocations: [32]Invocation = undefined,
    invocation_count: usize = 0,
    fail_at: ?usize = null,
    fail_termination: ProcessTermination = .{ .exited = 1 },
    run_error: ?anyerror = null,
    stderr: []const u8 = "",
    cancelled_value: bool = false,
    journal_bytes: [64 * 1024]u8 = undefined,
    journal_len: usize = 0,
    journal_writes: usize = 0,
    journal_archived: bool = false,
    status_source: ?[]const u8 = null,
    status_source_after_first_read: ?[]const u8 = null,
    status_reads: usize = 0,
    crash_point: ?recovery.CrashPoint = null,
    crash_index: usize = 0,
    now_ms: u64 = 0,
    advance_ms_per_root_validation: u64 = 0,
    advance_ms_per_run: u64 = 0,
    saw_running_cancellation: bool = false,

    fn dependencies(self: *TestHarness) Dependencies {
        return .{
            .filesystem = .{
                .context = self,
                .validateRootFn = validateRoot,
                .normalizeBootstrapRootFn = normalizeBootstrapRoot,
                .validateArtifactPathFn = validateArtifactPath,
                .readArtifactFn = readArtifact,
            },
            .locks = .{
                .context = self,
                .acquireFn = acquire,
                .heldFn = held,
                .releaseFn = release,
            },
            .process = .{ .context = self, .runFn = run },
            .journal = .{
                .context = self,
                .loadFn = loadJournal,
                .writeAtomicFn = writeJournal,
                .archiveAtomicFn = archiveJournal,
            },
            .status = .{ .context = self, .readFn = readStatus },
            .cancellation = .{ .context = self, .cancelledFn = cancelled },
            .crash = .{ .context = self, .hitFn = crash },
        };
    }

    fn validateRoot(context: *anyopaque, _: []const u8) !void {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        const current = self.root_validate_count;
        self.root_validate_count += 1;
        self.now_ms +|= self.advance_ms_per_root_validation;
        if (!self.root_valid or self.root_fail_after == current) return error.SymlinkRoot;
    }

    fn normalizeBootstrapRoot(_: *anyopaque, _: []const u8) !void {}

    fn readArtifact(context: *anyopaque, allocator: std.mem.Allocator, _: []const u8, _: usize) ![]u8 {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        const result = try allocator.dupe(u8, self.bytes);
        if (self.corrupt_read and result.len != 0) result[result.len - 1] ^= 1;
        return result;
    }

    fn validateArtifactPath(_: *anyopaque, _: []const u8) !void {}

    fn acquire(context: *anyopaque, _: []const u8, _: u64) !LockToken {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        const current = self.lock_acquires;
        self.lock_acquires += 1;
        if (self.lock_fail_at == current) return error.LockTimeout;
        return self;
    }

    fn held(context: *anyopaque, _: LockToken) bool {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        return self.lock_held;
    }

    fn release(context: *anyopaque, _: LockToken) void {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        self.lock_releases += 1;
    }

    fn run(context: *anyopaque, invocation: Invocation) !ProcessResult {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        const current = self.invocation_count;
        self.invocations[current] = invocation;
        self.invocation_count += 1;
        self.now_ms +|= self.advance_ms_per_run;
        self.saw_running_cancellation =
            self.saw_running_cancellation or invocation.cancellation.cancelled();
        if (self.run_error) |err| return err;
        if (self.fail_at == current) return .{
            .termination = self.fail_termination,
            .stderr = self.stderr,
        };
        return .{ .termination = .{ .exited = 0 } };
    }

    fn cancelled(context: *anyopaque) bool {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        return self.cancelled_value;
    }

    fn nowMilliseconds(context: ?*anyopaque) u64 {
        const self: *TestHarness = @ptrCast(@alignCast(context.?));
        return self.now_ms;
    }

    fn loadJournal(context: *anyopaque, allocator: std.mem.Allocator, _: []const u8) !?[]u8 {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        if (self.journal_len == 0) return null;
        return try allocator.dupe(u8, self.journal_bytes[0..self.journal_len]);
    }

    fn writeJournal(context: *anyopaque, _: []const u8, bytes: []const u8) !void {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        if (bytes.len > self.journal_bytes.len) return error.JournalTooLarge;
        @memcpy(self.journal_bytes[0..bytes.len], bytes);
        self.journal_len = bytes.len;
        self.journal_writes += 1;
        self.journal_archived = false;
    }

    fn archiveJournal(context: *anyopaque, _: []const u8, bytes: []const u8) !void {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        try writeJournal(context, "", bytes);
        self.journal_archived = true;
    }

    fn readStatus(context: *anyopaque, allocator: std.mem.Allocator, _: []const u8, _: usize) ![]u8 {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        self.status_reads += 1;
        if (self.status_source_after_first_read) |source|
            if (self.status_reads > 1) return allocator.dupe(u8, source);
        if (self.status_source) |source| return allocator.dupe(u8, source);
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        const writer = &output.writer;
        for (self.invocations[0..self.invocation_count], 0..) |invocation, index| {
            if (invocation.phase == .unpack and invocation.package != null) {
                var configured = false;
                for (self.invocations[index + 1 .. self.invocation_count], index + 1..) |later, later_index|
                    if (later.phase == .configure_pending) {
                        if (self.fail_at == later_index) continue;
                        configured = true;
                        break;
                    };
                if (!configured) continue;
            } else if (invocation.phase != .configure or invocation.package == null) continue;
            try writer.print(
                "Package: {s}\nVersion: 1.0\nArchitecture: amd64\nStatus: install ok installed\n\n",
                .{invocation.package.?},
            );
        }
        return output.toOwnedSlice();
    }

    fn crash(context: *anyopaque, point: recovery.CrashPoint, index: usize) !void {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        if (self.crash_point == point and self.crash_index == index) return error.InjectedCrash;
    }
};

fn testPlan(actions: []solver.PlanAction, ordered: []solver.OrderedAction) solver.Plan {
    return .{
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = actions,
        .ordered_actions = ordered,
        .summary = .{},
        .download_bytes = 0,
        .installed_size_delta_bytes = 0,
        .backing_allocator = std.testing.allocator,
        .arena = undefined,
    };
}

fn testInstallAction(bytes: []const u8, package: []const u8) solver.PlanAction {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{
        .kind = .install,
        .package = package,
        .version = "1.0",
        .architecture = "amd64",
        .repository = .{ .id = @splat('0'), .priority = 500 },
        .sha256 = std.fmt.bytesToHex(digest, .lower),
        .package_size = bytes.len,
        .installed_size_delta_bytes = 0,
        .source_package = package,
        .prior_installed = null,
        .requested = true,
        .reason = .explicit_request,
        .selected_origin = null,
    };
}

fn testRemoveAction(package: []const u8) solver.PlanAction {
    return .{
        .kind = .remove,
        .package = package,
        .version = "1.0",
        .architecture = "amd64",
        .repository = null,
        .sha256 = null,
        .package_size = null,
        .installed_size_delta_bytes = 0,
        .source_package = package,
        .prior_installed = null,
        .requested = true,
        .reason = .explicit_request,
        .selected_origin = null,
    };
}

test "transaction_executor.test.exact lock scope is policy-bound without changing full closure digest" {
    const policy: Policy = .{ .conffile = .keep_existing };
    const legacy = recovery.policyDigest(
        "keep_existing",
        policy.locks.wait_ms,
        policy.process_timeout_ms,
        &.{},
    );
    const full_closure = policyDigest(policy);
    try std.testing.expectEqualSlices(u8, &legacy, &full_closure);
    var operation_policy = policy;
    operation_policy.exact_lock_verification = .locked_packages;
    const locked_packages = policyDigest(operation_policy);
    try std.testing.expect(!std.mem.eql(
        u8,
        &legacy,
        &locked_packages,
    ));
}

test "transaction_executor.test.local artifact preflight and reread require exact origin evidence" {
    const bytes = try testDeb(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var action = testInstallAction(bytes, "demo");
    action.repository = null;
    const digest = try parseHexDigest(action.sha256.?);
    const artifact_evidence: package_origin.LocalArtifactEvidence = .{
        .artifact_id = package_origin.artifactIdFromSha256(digest),
        .sha256 = digest,
        .size = bytes.len,
        .package = action.package,
        .version = action.version,
        .architecture = action.architecture,
        .acquisition_url = "file:///cache/demo.deb",
        .trust_mode = .pinned_sha256,
    };
    action.origin = .{ .local_artifact = .{
        .evidence = artifact_evidence,
        .solver_priority = 1000,
    } };
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .unpack, .package = "demo", .version = "1.0", .architecture = "amd64" },
        .{ .sequence = 1, .kind = .configure_pending, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var actions = [_]solver.PlanAction{action};
    var plan = testPlan(&actions, &ordered);
    plan.schema_version = 3;
    var harness: TestHarness = .{ .bytes = bytes };
    const artifact: Artifact = .{
        .package = "demo",
        .version = "1.0",
        .architecture = "amd64",
        .path = "/cache/demo.deb",
    };
    try preflight(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{artifact},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies().filesystem);
    const reread = try validateArtifact(
        std.testing.allocator,
        harness.dependencies().filesystem,
        artifact,
        action,
        .{},
    );
    try std.testing.expectEqualSlices(u8, &digest, &reread);

    const locked_package: exact_lock_v2.Package = .{
        .name = artifact_evidence.package,
        .version = artifact_evidence.version,
        .architecture = artifact_evidence.architecture,
        .origin = .{ .local_artifact = artifact_evidence },
        .sha256 = artifact_evidence.sha256,
        .declared_size = artifact_evidence.size,
        .retention = .requested,
        .dpkg_selection_hold = false,
    };
    var lock = try exact_lock_v2.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .policy_sha256 = @splat(2),
        .repositories = &.{},
        .local_artifacts = &.{artifact_evidence},
        .packages = &.{locked_package},
        .verified_origins = true,
    });
    defer lock.deinit();
    try preflight(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{artifact},
        .policy = .{ .conffile = .keep_existing },
        .exact_lock_v2 = &lock.lock,
    }, harness.dependencies().filesystem);

    actions[0].origin.?.local_artifact.evidence.acquisition_url =
        "file:///cache/substituted.deb";
    try std.testing.expectError(error.PlanLockEvidenceMismatch, preflight(
        std.testing.allocator,
        .{
            .plan = &plan,
            .install_root = "/target",
            .artifacts = &.{artifact},
            .policy = .{ .conffile = .keep_existing },
            .exact_lock_v2 = &lock.lock,
        },
        harness.dependencies().filesystem,
    ));
    actions[0].origin.?.local_artifact.evidence.acquisition_url =
        artifact_evidence.acquisition_url;
    actions[0].package_size.? += 1;
    try std.testing.expectError(error.PackageOriginMismatch, preflight(
        std.testing.allocator,
        .{
            .plan = &plan,
            .install_root = "/target",
            .artifacts = &.{artifact},
            .policy = .{ .conffile = .keep_existing },
        },
        harness.dependencies().filesystem,
    ));
}

fn testDeb(allocator: std.mem.Allocator) ![]u8 {
    var ar: std.ArrayList(u8) = .empty;
    errdefer ar.deinit(allocator);
    try ar.appendSlice(allocator, "!<arch>\n");
    try appendTestAr(allocator, &ar, "debian-binary/", "2.0\n");
    try appendTestAr(allocator, &ar, "control.tar/", @embedFile("fixtures/deb-payload/control.tar"));
    try appendTestAr(allocator, &ar, "data.tar/", @embedFile("fixtures/deb-payload/data.tar"));
    return ar.toOwnedSlice(allocator);
}

fn appendTestAr(allocator: std.mem.Allocator, ar: *std.ArrayList(u8), name: []const u8, content: []const u8) !void {
    var header: [60]u8 = @splat(' ');
    std.mem.copyForwards(u8, &header, name);
    header[16] = '0';
    header[28] = '0';
    header[34] = '0';
    std.mem.copyForwards(u8, header[40..], "100644");
    const size = try std.fmt.bufPrint(header[48..58], "{d}", .{content.len});
    @memset(header[48 + size.len .. 58], ' ');
    header[58] = '`';
    header[59] = '\n';
    try ar.appendSlice(allocator, &header);
    try ar.appendSlice(allocator, content);
    if (content.len % 2 != 0) try ar.append(allocator, '\n');
}

fn containsArg(argv: []const []const u8, expected: []const u8) bool {
    for (argv) |arg| if (std.mem.eql(u8, arg, expected)) return true;
    return false;
}

test "transaction_executor.test.argv environment conffile policy and no shell" {
    const bytes = try testDeb(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var actions = [_]solver.PlanAction{testInstallAction(bytes, "demo")};
    actions[0].essential = true;
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .bootstrap_extract, .package = "demo", .version = "1.0", .architecture = "amd64" },
        .{ .sequence = 1, .kind = .unpack, .package = "demo", .version = "1.0", .architecture = "amd64" },
        .{ .sequence = 2, .kind = .configure_pending, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = bytes };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{.{ .package = "demo", .version = "1.0", .architecture = "amd64", .path = "/cache/demo.deb" }},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer report.deinit();

    try std.testing.expect(report.succeeded());
    try std.testing.expectEqual(@as(usize, 4), harness.invocation_count);
    try std.testing.expectEqualStrings("/usr/bin/dpkg-deb", harness.invocations[0].argv[0]);
    try std.testing.expect(containsArg(harness.invocations[0].argv, "--extract"));
    try std.testing.expect(containsArg(harness.invocations[0].argv, "/target"));
    try std.testing.expectEqualStrings("/usr/bin/dpkg", harness.invocations[1].argv[0]);
    try std.testing.expect(containsArg(harness.invocations[1].argv, "--root=/target"));
    try std.testing.expect(containsArg(harness.invocations[1].argv, "--force-confold"));
    try std.testing.expect(containsArg(harness.invocations[1].argv, "--no-triggers"));
    try std.testing.expect(containsArg(harness.invocations[2].argv, "--no-triggers"));
    try std.testing.expect(!containsArg(harness.invocations[0].argv, "sh"));
    try std.testing.expectEqual(@as(usize, audited_environment.len), harness.invocations[0].environment.len);
    try std.testing.expectEqualStrings("DEBIAN_FRONTEND", harness.invocations[0].environment[0].key);
    try std.testing.expectEqual(@as(u64, 5 * 60 * 1000), harness.invocations[0].timeout_ms);
    try std.testing.expectEqualStrings("1.0", report.commands[0].version.?);
    try std.testing.expectEqualStrings("amd64", report.commands[0].architecture.?);
}

test "transaction_executor.test.plan order cycles and final triggers are deterministic" {
    var actions = [_]solver.PlanAction{ testRemoveAction("old"), testRemoveAction("cycle-a"), testRemoveAction("cycle-b") };
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "old", .version = "1.0", .architecture = "amd64" },
        .{ .sequence = 1, .kind = .remove, .package = "cycle-b", .version = "1.0", .architecture = "amd64" },
        .{ .sequence = 2, .kind = .remove, .package = "cycle-a", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = "" };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .use_package_version },
    }, harness.dependencies());
    defer report.deinit();

    try std.testing.expect(report.succeeded());
    try std.testing.expectEqual(@as(usize, 4), harness.invocation_count);
    try std.testing.expect(containsArg(harness.invocations[0].argv, "old:amd64"));
    try std.testing.expect(containsArg(harness.invocations[1].argv, "cycle-b:amd64"));
    try std.testing.expect(containsArg(harness.invocations[2].argv, "cycle-a:amd64"));
    try std.testing.expect(containsArg(harness.invocations[3].argv, "--triggers-only"));
    try std.testing.expect(containsArg(harness.invocations[3].argv, "--pending"));
    try std.testing.expect(!containsArg(harness.invocations[3].argv, "--configure"));
    try std.testing.expect(containsArg(harness.invocations[3].argv, "--force-confnew"));
}

test "transaction_executor.test.explicit typed force policy only" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = "" };
    var default_report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer default_report.deinit();
    try std.testing.expect(!containsArg(harness.invocations[0].argv, "--force-depends"));

    harness.invocation_count = 0;
    var forced_report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing, .risk = .{ .force = &.{.depends} } },
    }, harness.dependencies());
    defer forced_report.deinit();
    try std.testing.expect(containsArg(harness.invocations[0].argv, "--force-depends"));
}

test "transaction_executor.test.lock timeout happens before mutation and identifies lock" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = "", .lock_fail_at = 1 };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing, .locks = .{ .wait_ms = 17 } },
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expect(!report.succeeded());
    try std.testing.expectEqual(FailureCode.lock_timeout, report.failure.?.code);
    try std.testing.expectEqualStrings("/target/var/lib/dpkg/lock-frontend", report.failure.?.lock_path.?);
    try std.testing.expectEqual(@as(usize, 0), harness.invocation_count);
    try std.testing.expectEqual(@as(usize, 1), harness.lock_releases);
}

test "transaction_executor.test.digest mismatch is rechecked after locks before dpkg" {
    const bytes = try testDeb(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var actions = [_]solver.PlanAction{testInstallAction(bytes, "demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .unpack, .package = "demo", .version = "1.0", .architecture = "amd64" },
        .{ .sequence = 1, .kind = .configure_pending, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = bytes, .corrupt_read = true };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{.{ .package = "demo", .version = "1.0", .architecture = "amd64", .path = "/cache/demo.deb" }},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expectEqual(FailureCode.artifact_digest_mismatch, report.failure.?.code);
    try std.testing.expectEqual(@as(usize, 3), harness.lock_acquires);
    try std.testing.expectEqual(@as(usize, 0), harness.invocation_count);
}

test "transaction_executor.test.dpkg failure has package phase exit and never succeeds partially" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{
        .bytes = "",
        .fail_at = 0,
        .fail_termination = .{ .exited = 42 },
        .stderr = "demo postrm maintainer script returned error",
    };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expect(!report.succeeded());
    try std.testing.expectEqual(FailureCode.dpkg_failed, report.failure.?.code);
    try std.testing.expectEqual(Phase.remove, report.failure.?.phase.?);
    try std.testing.expectEqualStrings("demo", report.failure.?.package.?);
    try std.testing.expectEqual(@as(u8, 42), report.failure.?.exit_code.?);
    try std.testing.expectEqualStrings("demo postrm maintainer script returned error", report.failure.?.diagnostic);
    try std.testing.expectEqual(@as(usize, 1), report.failure.?.completed_commands);
    try std.testing.expectEqual(@as(usize, 1), report.commands.len);
}

test "transaction_executor.test.configure pending accepts only measured dpkg progress" {
    const bytes = try testDeb(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var actions = [_]solver.PlanAction{testInstallAction(bytes, "demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .unpack, .package = "demo", .version = "1.0", .architecture = "amd64" },
        .{ .sequence = 1, .kind = .configure_pending, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    const installed =
        "Package: demo\nVersion: 1.0\nArchitecture: amd64\nStatus: install ok installed\n\n";
    var harness: TestHarness = .{
        .bytes = bytes,
        .fail_at = 1,
        .fail_termination = .{ .exited = 1 },
        .stderr = "one pending package remains dependency-blocked",
        .status_source = "",
        .status_source_after_first_read = installed,
    };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{.{ .package = "demo", .version = "1.0", .architecture = "amd64", .path = "/cache/demo.deb" }},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expect(report.succeeded());
    try std.testing.expectEqual(@as(usize, 3), harness.invocation_count);
    try std.testing.expect(!containsArg(harness.invocations[1].argv, "--abort-after=1"));
}

test "transaction_executor.test.process timeout is bounded and structured" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = "", .run_error = error.Timeout };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing, .process_timeout_ms = 17 },
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expectEqual(FailureCode.process_timeout, report.failure.?.code);
    try std.testing.expectEqual(Phase.remove, report.failure.?.phase.?);
    try std.testing.expectEqualStrings("demo", report.failure.?.package.?);
    try std.testing.expectEqual(@as(usize, 0), report.failure.?.completed_commands);
    try std.testing.expectEqual(@as(u64, 17), harness.invocations[0].timeout_ms);
    try std.testing.expectEqual(@as(usize, 3), harness.lock_releases);
}

test "transaction_executor.test.absolute deadline expires between phases" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{.{
        .sequence = 0,
        .kind = .remove,
        .package = "demo",
        .version = "1.0",
        .architecture = "amd64",
    }};
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{
        .bytes = "",
        .advance_ms_per_root_validation = 10,
    };
    var dependencies = harness.dependencies();
    dependencies.deadline = .{
        .context = &harness,
        .nowMsFn = TestHarness.nowMilliseconds,
        .expires_at_ms = 10,
    };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, dependencies);
    defer report.deinit();
    try std.testing.expectEqual(FailureCode.process_timeout, report.failure.?.code);
    try std.testing.expectEqual(@as(usize, 0), harness.invocation_count);
}

test "transaction_executor.test.absolute deadline cancels a running dpkg command" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{.{
        .sequence = 0,
        .kind = .remove,
        .package = "demo",
        .version = "1.0",
        .architecture = "amd64",
    }};
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{
        .bytes = "",
        .advance_ms_per_run = 21,
    };
    var dependencies = harness.dependencies();
    dependencies.deadline = .{
        .context = &harness,
        .nowMsFn = TestHarness.nowMilliseconds,
        .expires_at_ms = 20,
    };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{
            .conffile = .keep_existing,
            .process_timeout_ms = 1_000,
        },
    }, dependencies);
    defer report.deinit();
    try std.testing.expectEqual(FailureCode.process_timeout, report.failure.?.code);
    try std.testing.expectEqual(@as(usize, 1), harness.invocation_count);
    try std.testing.expectEqual(@as(u64, 20), harness.invocations[0].timeout_ms);
    try std.testing.expect(harness.saw_running_cancellation);
}

test "transaction_executor.test.provenance is stable redacted and interruption is recovery ready" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var first: TestHarness = .{ .bytes = "" };
    var first_report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, first.dependencies());
    defer first_report.deinit();
    var second: TestHarness = .{ .bytes = "" };
    var second_report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, second.dependencies());
    defer second_report.deinit();
    try std.testing.expectEqualSlices(u8, &first_report.plan_sha256, &second_report.plan_sha256);
    try std.testing.expectEqualSlices(u8, &first_report.commands[0].command_sha256, &second_report.commands[0].command_sha256);

    var interrupted_harness: TestHarness = .{ .bytes = "", .cancelled_value = true };
    var interrupted = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, interrupted_harness.dependencies());
    defer interrupted.deinit();
    try std.testing.expectEqual(FailureCode.interrupted, interrupted.failure.?.code);
    try std.testing.expectEqual(@as(usize, 0), interrupted.failure.?.completed_commands);
    try std.testing.expectEqual(@as(usize, 0), interrupted_harness.invocation_count);
}

test "transaction_executor.test.host root symlink root malformed order and lock loss are refused" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = "" };
    var host = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer host.deinit();
    try std.testing.expectEqual(FailureCode.invalid_root, host.failure.?.code);

    harness.root_valid = false;
    var symlink = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer symlink.deinit();
    try std.testing.expectEqual(FailureCode.invalid_root, symlink.failure.?.code);

    harness.root_valid = true;
    harness.lock_held = false;
    var lost = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer lost.deinit();
    try std.testing.expectEqual(FailureCode.lock_lost, lost.failure.?.code);
    try std.testing.expectEqual(@as(usize, 0), harness.invocation_count);
}

test "transaction_executor.test.install root is revalidated after locking before mutation" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = "", .root_fail_after = 1 };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expectEqual(FailureCode.invalid_root, report.failure.?.code);
    try std.testing.expectEqual(Phase.remove, report.failure.?.phase.?);
    try std.testing.expectEqual(@as(usize, 0), harness.invocation_count);
    try std.testing.expectEqual(@as(usize, 3), harness.lock_releases);
}

test "transaction_executor.test.each durable boundary leaves explicit non-success state" {
    const points = [_]recovery.CrashPoint{
        .before_initial_journal,
        .after_initial_journal,
        .before_command_journal,
        .after_command_journal,
        .before_verification_journal,
        .after_verification_journal,
        .before_archive,
    };
    for (points) |point| {
        var actions = [_]solver.PlanAction{testRemoveAction("demo")};
        var ordered = [_]solver.OrderedAction{
            .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
        };
        var plan = testPlan(&actions, &ordered);
        var harness: TestHarness = .{
            .bytes = "",
            .crash_point = point,
            .crash_index = if (point == .after_command_journal) 0 else if (point == .before_command_journal) 0 else if (point == .before_initial_journal or point == .after_initial_journal) 0 else 2,
        };
        var report = try execute(std.testing.allocator, .{
            .plan = &plan,
            .install_root = "/target",
            .artifacts = &.{},
            .policy = .{ .conffile = .keep_existing },
        }, harness.dependencies());
        defer report.deinit();
        try std.testing.expect(!report.succeeded());
        if (point != .before_initial_journal) try std.testing.expect(harness.journal_len != 0);
    }
}

test "transaction_executor.test.explicit recovery audits repairs verifies archives and repeats idempotently" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{
        .bytes = "",
        .fail_at = 0,
        .fail_termination = .{ .signaled = 15 },
        .status_source = "",
    };
    var interrupted = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer interrupted.deinit();
    try std.testing.expectEqual(recovery.State.interrupted, interrupted.transaction_state);

    harness.fail_at = null;
    const before = harness.invocation_count;
    var repaired = try recover(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer repaired.deinit();
    try std.testing.expect(repaired.succeeded());
    try std.testing.expectEqual(@as(usize, before + 3), harness.invocation_count);
    try std.testing.expect(containsArg(harness.invocations[before].argv, "--audit"));
    try std.testing.expect(containsArg(harness.invocations[before + 1].argv, "--configure"));
    try std.testing.expect(containsArg(harness.invocations[before + 1].argv, "--pending"));
    try std.testing.expect(containsArg(harness.invocations[before + 2].argv, "--triggers-only"));
    try std.testing.expect(harness.journal_archived);

    const after = harness.invocation_count;
    var repeated = try recover(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer repeated.deinit();
    try std.testing.expect(repeated.succeeded());
    try std.testing.expectEqual(after, harness.invocation_count);
}

test "transaction_executor.test.absolute deadline cancels a running recovery command" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{.{
        .sequence = 0,
        .kind = .remove,
        .package = "demo",
        .version = "1.0",
        .architecture = "amd64",
    }};
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{
        .bytes = "",
        .fail_at = 0,
        .fail_termination = .{ .signaled = 15 },
        .status_source = "",
    };
    var interrupted = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{
            .conffile = .keep_existing,
            .process_timeout_ms = 1_000,
        },
    }, harness.dependencies());
    defer interrupted.deinit();
    try std.testing.expectEqual(recovery.State.interrupted, interrupted.transaction_state);

    harness.fail_at = null;
    harness.invocation_count = 0;
    harness.now_ms = 0;
    harness.advance_ms_per_run = 21;
    harness.saw_running_cancellation = false;
    var dependencies = harness.dependencies();
    dependencies.deadline = .{
        .context = &harness,
        .nowMsFn = TestHarness.nowMilliseconds,
        .expires_at_ms = 20,
    };
    var report = try recover(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .policy = .{
            .conffile = .keep_existing,
            .process_timeout_ms = 1_000,
        },
    }, dependencies);
    defer report.deinit();
    try std.testing.expectEqual(FailureCode.process_timeout, report.failure.?.code);
    try std.testing.expectEqual(@as(usize, 1), harness.invocation_count);
    try std.testing.expectEqual(@as(u64, 20), harness.invocations[0].timeout_ms);
    try std.testing.expect(harness.saw_running_cancellation);
}

test "transaction_executor.test.recovery rejects corrupt wrong-root lock contention and command failure" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = "", .cancelled_value = true, .status_source = "" };
    var interrupted = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    interrupted.deinit();

    harness.cancelled_value = false;
    harness.journal_bytes[10] ^= 1;
    var corrupt = try recover(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer corrupt.deinit();
    try std.testing.expectEqual(FailureCode.journal_corrupt, corrupt.failure.?.code);
    harness.journal_bytes[10] ^= 1;

    var wrong_root = try recover(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/other",
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer wrong_root.deinit();
    try std.testing.expectEqual(FailureCode.journal_mismatch, wrong_root.failure.?.code);

    harness.lock_acquires = 0;
    harness.lock_fail_at = 0;
    var contended = try recover(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer contended.deinit();
    try std.testing.expectEqual(FailureCode.lock_timeout, contended.failure.?.code);

    harness.lock_acquires = 0;
    harness.lock_fail_at = null;
    harness.invocation_count = 0;
    harness.fail_at = 0;
    harness.fail_termination = .{ .exited = 1 };
    var failed = try recover(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer failed.deinit();
    try std.testing.expectEqual(FailureCode.recovery_failed, failed.failure.?.code);
    try std.testing.expect(!failed.succeeded());
}

test "transaction_executor.test.unfinished journal blocks normal retry and binds package digest" {
    const bytes = try testDeb(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var actions = [_]solver.PlanAction{testInstallAction(bytes, "demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .unpack, .package = "demo", .version = "1.0", .architecture = "amd64" },
        .{ .sequence = 1, .kind = .configure_pending, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = bytes, .cancelled_value = true };
    var first = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{.{ .package = "demo", .version = "1.0", .architecture = "amd64", .path = "/cache/demo.deb" }},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer first.deinit();
    var decoded = try recovery.decode(std.testing.allocator, harness.journal_bytes[0..harness.journal_len]);
    defer decoded.deinit();
    try std.testing.expect(decoded.journal.commands[0].artifact_sha256 != null);
    try std.testing.expectEqual(recovery.State.interrupted, decoded.journal.state);

    harness.cancelled_value = false;
    const before = harness.invocation_count;
    var retry = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{.{ .package = "demo", .version = "1.0", .architecture = "amd64", .path = "/cache/demo.deb" }},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer retry.deinit();
    try std.testing.expectEqual(FailureCode.invalid_recovery_transition, retry.failure.?.code);
    try std.testing.expectEqual(before, harness.invocation_count);
}

test "transaction_executor.test.verification reacquires dpkg lock and never queries an unstable state" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = "", .lock_fail_at = 3, .status_source = "" };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expectEqual(FailureCode.lock_timeout, report.failure.?.code);
    try std.testing.expectEqual(recovery.State.interrupted, report.transaction_state);
    try std.testing.expectEqual(@as(usize, 2), harness.invocation_count);
    try std.testing.expectEqual(@as(usize, 0), harness.status_reads);
}

test "transaction_executor.test.recovery verification reacquires dpkg lock" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{
        .bytes = "",
        .fail_at = 0,
        .fail_termination = .{ .signaled = 15 },
        .status_source = "",
    };
    var interrupted = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    interrupted.deinit();

    harness.fail_at = null;
    harness.lock_acquires = 0;
    harness.lock_fail_at = 3;
    var report = try recover(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expectEqual(FailureCode.lock_timeout, report.failure.?.code);
    try std.testing.expectEqual(recovery.State.interrupted, report.state);
    try std.testing.expectEqual(@as(usize, 0), harness.status_reads);
}

test "transaction_executor.test.plan rejects multiple final versions for one package architecture" {
    var actions = [_]solver.PlanAction{ testRemoveAction("demo"), testRemoveAction("demo") };
    actions[1].version = "2.0";
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
        .{ .sequence = 1, .kind = .remove, .package = "demo", .version = "2.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = "" };
    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expectEqual(FailureCode.invalid_plan, report.failure.?.code);
    try std.testing.expectEqual(@as(usize, 0), harness.lock_acquires);
    try std.testing.expectEqual(@as(usize, 0), harness.invocation_count);
}

test "transaction_executor.test.completed recovery retains unhealthy-state evidence" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    var harness: TestHarness = .{ .bytes = "", .status_source = "" };
    var completed = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    completed.deinit();
    harness.status_source =
        \\Package: broken
        \\Version: 1
        \\Architecture: amd64
        \\Status: install ok unpacked
        \\
    ;
    harness.lock_acquires = 0;
    var report = try recover(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expectEqual(FailureCode.verification_failed, report.failure.?.code);
    try std.testing.expectEqual(recovery.State.verification_failed, report.state);
    try std.testing.expect(!harness.journal_archived);
    var decoded = try recovery.decode(std.testing.allocator, harness.journal_bytes[0..harness.journal_len]);
    defer decoded.deinit();
    try std.testing.expectEqual(recovery.State.verification_failed, decoded.journal.state);
}

const SystemLockThread = struct {
    manager: *SystemLockManager,
    path: []const u8,
    wait_ms: u64,
    started: std.atomic.Value(bool) = .init(false),
    acquired: std.atomic.Value(bool) = .init(false),
    finished: std.atomic.Value(bool) = .init(false),
    release_requested: std.atomic.Value(bool) = .init(false),
    failure: ?anyerror = null,

    fn run(self: *SystemLockThread) void {
        const locks = self.manager.interface();
        self.started.store(true, .release);
        const token = locks.acquire(self.path, self.wait_ms) catch |err| {
            self.failure = err;
            self.finished.store(true, .release);
            return;
        };
        self.acquired.store(true, .release);
        while (!self.release_requested.load(.acquire))
            std.atomic.spinLoopHint();
        locks.release(token);
        self.finished.store(true, .release);
    }
};

fn waitForSystemLockTestFlag(flag: *const std.atomic.Value(bool), wait_ms: u64) !void {
    const started = std.Io.Clock.awake.now(std.testing.io);
    while (!flag.load(.acquire)) {
        const elapsed = started.durationTo(
            std.Io.Clock.awake.now(std.testing.io),
        ).toMilliseconds();
        if (elapsed >= wait_ms) return error.TestTimedOut;
        try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    }
}

fn expectSystemLockTimeout(locks: LockManager, path: []const u8) !void {
    if (locks.acquire(path, 0)) |token| {
        locks.release(token);
        return error.TestUnexpectedLockAcquisition;
    } else |err| {
        try std.testing.expectEqual(error.LockTimeout, err);
    }
}

test "transaction_executor.test.production adapters expose injectable interfaces" {
    var filesystem: SystemFileSystem = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    var locks: SystemLockManager = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    var process: SystemProcessRunner = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    defer process.deinit();
    _ = filesystem.interface();
    _ = locks.interface();
    _ = process.interface();
}

test "transaction_executor.test.production filesystem accepts an exact-size artifact" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "artifact.deb", .data = "exact" });
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try tmp.dir.realPath(std.testing.io, &path_buffer);
    const path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/artifact.deb",
        .{path_buffer[0..root_length]},
    );
    defer std.testing.allocator.free(path);
    var filesystem: SystemFileSystem = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    const bytes = try filesystem.interface().readArtifact(std.testing.allocator, path, 5);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("exact", bytes);
    try std.testing.expectError(
        error.StreamTooLong,
        filesystem.interface().readArtifact(std.testing.allocator, path, 4),
    );
}

test "transaction_executor.test.bootstrap normalization restores empty merged-usr directories" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "root/usr/bin");
    try tmp.dir.createDirPath(std.testing.io, "root/usr/sbin");
    try tmp.dir.createDirPath(std.testing.io, "root/usr/lib");
    try tmp.dir.createDirPath(std.testing.io, "root/usr/lib64");
    try tmp.dir.createDirPath(std.testing.io, "root/usr/share/base-passwd");
    try tmp.dir.createDirPath(std.testing.io, "root/etc");
    try tmp.dir.createDirPath(std.testing.io, "root/lib");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/lib/bootstrap-file", .data = "safe" });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "root/usr/share/base-passwd/passwd.master",
        .data = "root:x:0:0:root:/root:/bin/sh\n",
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "root/usr/share/base-passwd/group.master",
        .data = "root:x:0:\nmail:x:8:\n",
    });
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try tmp.dir.realPath(std.testing.io, &path_buffer);
    const root = try std.fmt.allocPrint(std.testing.allocator, "{s}/root", .{path_buffer[0..root_length]});
    defer std.testing.allocator.free(root);
    var filesystem: SystemFileSystem = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    try filesystem.interface().normalizeBootstrapRoot(root);
    var target: [64]u8 = undefined;
    const length = try tmp.dir.readLink(std.testing.io, "root/lib", &target);
    try std.testing.expectEqualStrings("usr/lib", target[0..length]);
    var moved = try tmp.dir.openFile(std.testing.io, "root/usr/lib/bootstrap-file", .{});
    moved.close(std.testing.io);
    const group = try tmp.dir.readFileAlloc(
        std.testing.io,
        "root/etc/group",
        std.testing.allocator,
        .limited(1024),
    );
    defer std.testing.allocator.free(group);
    try std.testing.expectEqualStrings("root:x:0:\nmail:x:8:\n", group);
}

test "transaction_executor.test.bootstrap normalization leaves no dangling link for an absent merged-usr target" {
    // An arm64 root has usr/lib but no usr/lib64. Linking lib64 anyway left a
    // dangling /lib64, and base-files' preinst refuses to unpack against one,
    // which failed the bootstrap of every arm64 root at its first package.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "root/usr/bin");
    try tmp.dir.createDirPath(std.testing.io, "root/usr/sbin");
    try tmp.dir.createDirPath(std.testing.io, "root/usr/lib");
    try tmp.dir.createDirPath(std.testing.io, "root/usr/share/base-passwd");
    try tmp.dir.createDirPath(std.testing.io, "root/etc");
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "root/usr/share/base-passwd/passwd.master",
        .data = "root:x:0:0:root:/root:/bin/sh\n",
    });
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "root/usr/share/base-passwd/group.master",
        .data = "root:x:0:\n",
    });
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try tmp.dir.realPath(std.testing.io, &path_buffer);
    const root = try std.fmt.allocPrint(std.testing.allocator, "{s}/root", .{path_buffer[0..root_length]});
    defer std.testing.allocator.free(root);
    var filesystem: SystemFileSystem = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    try filesystem.interface().normalizeBootstrapRoot(root);

    // The architecture that has the target still gets its link.
    var target: [64]u8 = undefined;
    const length = try tmp.dir.readLink(std.testing.io, "root/lib", &target);
    try std.testing.expectEqualStrings("usr/lib", target[0..length]);

    // The one that does not is left alone rather than pointed at nothing.
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.readLink(std.testing.io, "root/lib64", &target),
    );
}

test "transaction_executor.test.production lock adapter refuses parent and leaf symlinks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "safe");
    try tmp.dir.symLink(std.testing.io, "safe", "linked", .{ .is_directory = true });
    var target = try tmp.dir.createFile(std.testing.io, "safe/target", .{});
    target.close(std.testing.io);
    try tmp.dir.symLink(std.testing.io, "target", "safe/linked-lock", .{});

    var real_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const real_length = try tmp.dir.realPath(std.testing.io, &real_buffer);
    const parent_link_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/linked/lock",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(parent_link_path);
    const leaf_link_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/safe/linked-lock",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(leaf_link_path);
    const safe_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/safe/lock",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(safe_path);

    var locks: SystemLockManager = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    try std.testing.expectError(error.NotDir, locks.openLockFile(parent_link_path));
    try std.testing.expectError(error.SymLinkLoop, locks.openLockFile(leaf_link_path));
    var safe_file = try locks.openLockFile(safe_path);
    safe_file.close(std.testing.io);
}

test "transaction_executor.test.system lock manager serializes independent managers in one process" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const lock_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/same.lock",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(lock_path);

    var first_manager: SystemLockManager = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    var second_manager: SystemLockManager = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    const first_locks = first_manager.interface();
    const first_token = try first_locks.acquire(lock_path, 100);
    var first_released = false;
    defer if (!first_released) first_locks.release(first_token);

    try expectSystemLockTimeout(second_manager.interface(), lock_path);

    var context: SystemLockThread = .{
        .manager = &second_manager,
        .path = lock_path,
        .wait_ms = 1_000,
    };
    const thread = try std.Thread.spawn(.{}, SystemLockThread.run, .{&context});
    var joined = false;
    defer if (!joined) {
        context.release_requested.store(true, .release);
        if (!first_released) {
            first_locks.release(first_token);
            first_released = true;
        }
        thread.join();
    };
    try waitForSystemLockTestFlag(&context.started, 500);
    try std.Io.sleep(std.testing.io, .fromMilliseconds(25), .awake);
    try std.testing.expect(!context.acquired.load(.acquire));
    try std.testing.expect(!context.finished.load(.acquire));

    context.release_requested.store(true, .release);
    first_locks.release(first_token);
    first_released = true;
    try waitForSystemLockTestFlag(&context.finished, 1_000);
    thread.join();
    joined = true;
    try std.testing.expect(context.failure == null);
    try std.testing.expect(context.acquired.load(.acquire));
}

test "transaction_executor.test.system lock manager same-path wait times out across threads" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const lock_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/timeout.lock",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(lock_path);

    var first_manager: SystemLockManager = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    var second_manager: SystemLockManager = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .retry_ms = 1,
    };
    const first_locks = first_manager.interface();
    const first_token = try first_locks.acquire(lock_path, 100);
    var first_released = false;
    defer if (!first_released) first_locks.release(first_token);

    var context: SystemLockThread = .{
        .manager = &second_manager,
        .path = lock_path,
        .wait_ms = 25,
    };
    const thread = try std.Thread.spawn(.{}, SystemLockThread.run, .{&context});
    var joined = false;
    defer if (!joined) {
        context.release_requested.store(true, .release);
        if (!first_released) {
            first_locks.release(first_token);
            first_released = true;
        }
        thread.join();
    };
    try waitForSystemLockTestFlag(&context.finished, 500);
    thread.join();
    joined = true;
    try std.testing.expect(!context.acquired.load(.acquire));
    try std.testing.expectEqual(error.LockTimeout, context.failure.?);
}

test "transaction_executor.test.system lock manager permits distinct paths concurrently" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const first_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/first.lock",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(first_path);
    const second_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/second.lock",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(second_path);

    var first_manager: SystemLockManager = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    var second_manager: SystemLockManager = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    const first_locks = first_manager.interface();
    const first_token = try first_locks.acquire(first_path, 100);
    defer first_locks.release(first_token);

    var context: SystemLockThread = .{
        .manager = &second_manager,
        .path = second_path,
        .wait_ms = 100,
    };
    context.release_requested.store(true, .release);
    const thread = try std.Thread.spawn(.{}, SystemLockThread.run, .{&context});
    var joined = false;
    defer if (!joined) {
        context.release_requested.store(true, .release);
        thread.join();
    };
    try waitForSystemLockTestFlag(&context.finished, 500);
    thread.join();
    joined = true;
    try std.testing.expect(context.failure == null);
    try std.testing.expect(context.acquired.load(.acquire));
    try std.testing.expect(first_locks.held(first_token));
}

test "transaction_executor.test.system lock survives closing an unrelated descriptor" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const lock_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/close.lock",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(lock_path);

    var first_manager: SystemLockManager = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    var second_manager: SystemLockManager = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    const first_locks = first_manager.interface();
    const first_token = try first_locks.acquire(lock_path, 100);
    var first_released = false;
    defer if (!first_released) first_locks.release(first_token);

    var unrelated = try first_manager.openLockFile(lock_path);
    unrelated.close(std.testing.io);
    try expectSystemLockTimeout(second_manager.interface(), lock_path);

    first_locks.release(first_token);
    first_released = true;
    const next_token = try second_manager.interface().acquire(lock_path, 100);
    second_manager.interface().release(next_token);
}

test "transaction_executor.test.system lock acquisition failure releases kernel state" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const lock_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/cleanup.lock",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(lock_path);

    var storage: [1]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var failing_manager: SystemLockManager = .{
        .allocator = fixed.allocator(),
        .io = std.testing.io,
    };
    try std.testing.expectError(
        error.OutOfMemory,
        failing_manager.interface().acquire(lock_path, 100),
    );

    var next_manager: SystemLockManager = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    const next_locks = next_manager.interface();
    const token = try next_locks.acquire(lock_path, 0);
    next_locks.release(token);
}

test "transaction_executor.test.production process adapter observes cancellation and reaps child" {
    var harness: TestHarness = .{ .bytes = "", .cancelled_value = true };
    var process: SystemProcessRunner = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer process.deinit();
    const result = try process.interface().run(.{
        .argv = &.{ "/usr/bin/sleep", "30" },
        .environment = &audited_environment,
        .phase = .configure,
        .package = "demo",
        .timeout_ms = 10_000,
        .cancellation = harness.dependencies().cancellation,
    });
    try std.testing.expectEqual(ProcessTermination.cancelled, result.termination);
}

test "transaction_executor.test.production process adapter enforces timeout and reaps child" {
    var process: SystemProcessRunner = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    defer process.deinit();
    try std.testing.expectError(error.Timeout, process.interface().run(.{
        .argv = &.{ "/usr/bin/sleep", "30" },
        .environment = &audited_environment,
        .phase = .configure,
        .package = "demo",
        .timeout_ms = 10,
        .cancellation = Cancellation.never(),
    }));
}

test "transaction_executor.test.system lock manager provisions missing debz state directory" {
    // Reproduces the aarch64 customize regression: an authenticated Ubuntu root
    // carries var/lib/dpkg but never a var/lib/debz directory, so acquiring the
    // debz transaction lock walked into a missing parent and surfaced a bare
    // FileNotFound with exit status 7. The production adapter must provision its
    // own bookkeeping directory before locking instead of trusting the caller.
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const root = real_buffer[0..real_length];
    const lock_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/root/var/lib/debz/transaction.lock",
        .{root},
    );
    defer std.testing.allocator.free(lock_path);

    var manager: SystemLockManager = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    const locks = manager.interface();
    const token = try locks.acquire(lock_path, 1_000);
    try std.testing.expect(locks.held(token));
    locks.release(token);

    var provisioned = try directory.dir.openDir(std.testing.io, "root/var/lib/debz", .{ .follow_symlinks = false });
    provisioned.close(std.testing.io);
}

test "transaction_executor.test.schema v2 plan hash and interrupted journal remain compatible" {
    var actions = [_]solver.PlanAction{testRemoveAction("demo")};
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .remove, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = testPlan(&actions, &ordered);
    const released_plan_sha256 = try parseHexDigest(
        "169c8fb07908a3e3fdcd626c950d5033ed32be2238ea658b66223e46ae0621c5".*,
    );
    try std.testing.expectEqual(@as(u32, 2), plan.schema_version);
    try std.testing.expectEqualSlices(u8, &released_plan_sha256, &hashPlan(plan));

    const policy: Policy = .{ .conffile = .keep_existing };
    const journal: recovery.Journal = .{
        .state = .interrupted,
        .boundary = .before_command,
        .plan_sha256 = released_plan_sha256,
        .root_identity = recovery.rootIdentity("/target"),
        .policy_sha256 = hashPolicy(policy),
        .next_command = 0,
        .commands = &.{},
        .failure = "released v0.2.0 interruption",
    };
    const fixture = try recovery.encode(std.testing.allocator, journal);
    defer std.testing.allocator.free(fixture);
    var harness: TestHarness = .{ .bytes = "", .status_source = "" };
    try TestHarness.writeJournal(&harness, "/target", fixture);

    var report = try recover(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .policy = policy,
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expect(report.succeeded());
    try std.testing.expectEqualSlices(u8, &released_plan_sha256, &report.plan_sha256);
    try std.testing.expect(harness.journal_archived);
}

test "transaction_executor.test.plan hash binds every tagged local origin field" {
    const digest: [32]u8 = @splat(0x11);
    const evidence: package_origin.LocalArtifactEvidence = .{
        .artifact_id = package_origin.artifactIdFromSha256(digest),
        .sha256 = digest,
        .size = 17,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .acquisition_url = "file:///demo.deb",
        .trust_mode = .pinned_sha256,
    };
    var actions = [_]solver.PlanAction{.{
        .kind = .install,
        .package = evidence.package,
        .version = evidence.version,
        .architecture = evidence.architecture,
        .repository = null,
        .sha256 = @splat('1'),
        .package_size = evidence.size,
        .installed_size_delta_bytes = 0,
        .source_package = evidence.package,
        .prior_installed = null,
        .requested = true,
        .reason = .explicit_request,
        .selected_origin = null,
        .origin = .{ .local_artifact = .{
            .evidence = evidence,
            .solver_priority = 500,
        } },
    }};
    const plan: solver.Plan = .{
        .schema_version = 3,
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = &actions,
        .ordered_actions = &.{},
        .summary = .{ .installs = 1, .download_bytes = evidence.size },
        .download_bytes = evidence.size,
        .installed_size_delta_bytes = 0,
        .backing_allocator = std.testing.allocator,
        .arena = undefined,
    };
    const expected = hashPlan(plan);
    const Mutation = enum {
        union_tag,
        artifact_id,
        sha256,
        size,
        package,
        version,
        architecture,
        acquisition_url,
        trust_mode,
        solver_priority,
    };
    inline for ([_]Mutation{
        .union_tag,
        .artifact_id,
        .sha256,
        .size,
        .package,
        .version,
        .architecture,
        .acquisition_url,
        .trust_mode,
        .solver_priority,
    }) |mutation| {
        var changed_actions = actions;
        if (mutation == .union_tag) {
            changed_actions[0].origin = .{ .authenticated_repository = .{
                .id = @splat('a'),
                .priority = 500,
            } };
        } else {
            var local = changed_actions[0].origin.?.local_artifact;
            switch (mutation) {
                .union_tag => unreachable,
                .artifact_id => local.evidence.artifact_id = @splat('b'),
                .sha256 => local.evidence.sha256 = @splat(0x22),
                .size => local.evidence.size += 1,
                .package => local.evidence.package = "other",
                .version => local.evidence.version = "2",
                .architecture => local.evidence.architecture = "arm64",
                .acquisition_url => local.evidence.acquisition_url = "file:///other.deb",
                .trust_mode => local.evidence.trust_mode = .verified_https,
                .solver_priority => local.solver_priority += 1,
            }
            changed_actions[0].origin = .{ .local_artifact = local };
        }
        var changed_plan = plan;
        changed_plan.actions = &changed_actions;
        try std.testing.expect(!std.mem.eql(
            u8,
            &expected,
            &hashPlan(changed_plan),
        ));
    }
}

test "transaction_executor.test.legacy execution rejects native purge actions" {
    const bytes = try testDeb(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var harness: TestHarness = .{ .bytes = bytes };
    var actions = [_]solver.PlanAction{testRemoveAction("legacy")};
    var ordered = [_]solver.OrderedAction{
        .{
            .sequence = 0,
            .kind = .remove,
            .package = "legacy",
            .version = "1.0",
            .architecture = "amd64",
        },
    };
    var plan = testPlan(&actions, &ordered);
    try preflight(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies().filesystem);

    actions[0].kind = .purge;
    try std.testing.expectError(error.UnsupportedPurgeAction, preflight(
        std.testing.allocator,
        .{
            .plan = &plan,
            .install_root = "/target",
            .artifacts = &.{},
            .policy = .{ .conffile = .keep_existing },
        },
        harness.dependencies().filesystem,
    ));
    try std.testing.expectEqual(FailureCode.invalid_plan, preflightCode(error.UnsupportedPurgeAction));

    actions[0].kind = .remove;
    ordered[0].kind = .purge;
    try std.testing.expectError(error.UnsupportedPurgeAction, preflight(
        std.testing.allocator,
        .{
            .plan = &plan,
            .install_root = "/target",
            .artifacts = &.{},
            .policy = .{ .conffile = .keep_existing },
        },
        harness.dependencies().filesystem,
    ));
    try std.testing.expectError(error.UnsupportedPurgeAction, toPhase(.purge));

    var report = try execute(std.testing.allocator, .{
        .plan = &plan,
        .install_root = "/target",
        .artifacts = &.{},
        .policy = .{ .conffile = .keep_existing },
    }, harness.dependencies());
    defer report.deinit();
    try std.testing.expect(!report.succeeded());
    try std.testing.expectEqual(FailureCode.invalid_plan, report.failure.?.code);
    try std.testing.expectEqual(@as(usize, 0), harness.invocation_count);
}
