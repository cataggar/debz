const std = @import("std");
const solver = @import("solver.zig");
const deb_payload = @import("deb_payload.zig");
const recovery = @import("transaction_recovery.zig");
const exact_lock = @import("exact_lock.zig");

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

pub const Policy = struct {
    conffile: ConffilePolicy,
    locks: LockPolicy = .{},
    risk: RiskPolicy = .{},
    validation_limits: deb_payload.Limits = .{},
    maximum_diagnostic_bytes: usize = 64 * 1024,
    process_timeout_ms: u64 = 5 * 60 * 1000,
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
    validateArtifactPathFn: *const fn (*anyopaque, []const u8) anyerror!void,
    readArtifactFn: *const fn (*anyopaque, std.mem.Allocator, []const u8, usize) anyerror![]u8,

    pub fn validateRoot(self: FileSystem, root: []const u8) !void {
        return self.validateRootFn(self.context, root);
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

pub const Dependencies = struct {
    filesystem: FileSystem,
    locks: LockManager,
    process: ProcessRunner,
    journal: recovery.Store,
    status: recovery.StatusReader,
    cancellation: Cancellation = Cancellation.never(),
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
    const plan_sha256 = hashPlan(request.plan.*);
    state.root_identity = recovery.rootIdentity(request.install_root);
    state.policy_sha256 = hashPolicy(request.policy);
    state.lock_sha256 = if (request.exact_lock) |lock| lock.digest_sha256 else null;

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
    defer for (held, 0..) |token, index| {
        if (token) |value| dependencies.locks.release(value);
        held[index] = null;
    };

    for (lock_paths, 0..) |path, index| {
        held[index] = dependencies.locks.acquire(path, request.policy.locks.wait_ms) catch |err| {
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
        if (dependencies.cancellation.cancelled()) {
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
                .phase = toPhase(ordered.kind),
                .package = if (ordered.kind == .configure_pending) null else try arena.dupe(u8, ordered.package),
                .diagnostic = "transaction lock ownership was lost",
                .completed_commands = state.commands.items.len,
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
        dependencies.filesystem.validateRoot(request.install_root) catch |err| {
            state.failure = .{
                .code = .invalid_root,
                .phase = toPhase(ordered.kind),
                .package = try arena.dupe(u8, ordered.package),
                .diagnostic = try arena.dupe(u8, @errorName(err)),
                .completed_commands = state.commands.items.len,
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };

        const phase = toPhase(ordered.kind);
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
        const result = dependencies.process.run(.{
            .argv = argv,
            .environment = &audited_environment,
            .phase = phase,
            .package = if (phase == .configure_pending) null else ordered.package,
            .timeout_ms = request.policy.process_timeout_ms,
            .cancellation = dependencies.cancellation,
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
        try state.commands.append(arena, provenance);
        if (!successful(result.termination)) {
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
        if (dependencies.cancellation.cancelled()) {
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
            .timeout_ms = request.policy.process_timeout_ms,
            .cancellation = dependencies.cancellation,
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

    held[2] = dependencies.locks.acquire(lock_paths[2], request.policy.locks.wait_ms) catch |err| {
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
    const verification = verifyFinal(arena, request.plan.*, request.exact_lock, request.install_root, dependencies.status) catch |err| {
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
    const plan_sha256 = hashPlan(request.plan.*);
    state.root_identity = recovery.rootIdentity(request.install_root);
    state.policy_sha256 = hashPolicy(request.policy);
    state.lock_sha256 = if (request.exact_lock) |lock| lock.digest_sha256 else null;

    preflight(arena, .{
        .plan = request.plan,
        .install_root = request.install_root,
        .artifacts = &.{},
        .policy = request.policy,
        .exact_lock = request.exact_lock,
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
        held[index] = dependencies.locks.acquire(path, request.policy.locks.wait_ms) catch |err| {
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
        const verification = try verifyFinal(arena, request.plan.*, request.exact_lock, request.install_root, dependencies.status);
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
        if (dependencies.cancellation.cancelled()) {
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
            .timeout_ms = request.policy.process_timeout_ms,
            .cancellation = dependencies.cancellation,
        }) catch |err| {
            journal.state = .interrupted;
            journal.failure = @errorName(err);
            recovery.persist(arena, dependencies.journal, request.install_root, journal) catch {};
            state.transaction_state = .interrupted;
            state.failure = journalFailure(arena, err, .recovery_failed, "recovery command could not complete");
            return finishRecovery(allocator, arena_ptr, &state, plan_sha256);
        };
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

    held[2] = dependencies.locks.acquire(lock_paths[2], request.policy.locks.wait_ms) catch |err| {
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

    const verification = try verifyFinal(arena, request.plan.*, request.exact_lock, request.install_root, dependencies.status);
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
    root: []const u8,
    status: recovery.StatusReader,
) !recovery.Verification {
    if (lock) |closure|
        return recovery.verifyExactLock(allocator, closure.*, root, status, 64 * 1024 * 1024);
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
        const phase = toPhase(ordered.kind);
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
    if (request.plan.schema_version != 2) return error.UnsupportedPlanVersion;
    if (request.plan.mode != .plan_only) return error.NonExecutablePlanMode;
    if (request.plan.actions.len > 100_000 or request.plan.ordered_actions.len > 300_000)
        return error.PlanTooLarge;
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
            .bootstrap_extract, .unpack, .configure_pending => if (action.kind == .remove) return error.InvalidInstallOrdering,
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
            }
        }
        if (action.kind == .remove) {
            if (bootstrap_extracts != 0 or removes != 1 or unpacks != 0 or configure_pending_count != 0) return error.IncompleteRemoveOrdering;
        } else if (removes != 0 or unpacks != 1) {
            return error.IncompleteInstallOrdering;
        } else {
            const expected_bootstrap: usize = if (requiresRootBootstrap(request.plan.actions) and action.prior_installed == null) 1 else 0;
            if (bootstrap_extracts != expected_bootstrap) return error.IncompleteInstallOrdering;
            if (action.repository == null or action.sha256 == null or action.package_size == null)
                return error.MissingAuthenticatedArtifactMetadata;
            _ = parseHexDigest(action.sha256.?) catch return error.InvalidAuthenticatedDigest;
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

    var repository_hex: [64]u8 = @splat('0');
    if (action.repository) |repository| repository_hex = repository.id;
    const validation = deb_payload.validate(allocator, bytes, .{
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
    try argv.append(allocator, "--abort-after=1");
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
    if (path.len == 0 or path[0] != '/' or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidAbsolutePath;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 and path.len != 1) return error.AmbiguousPath;
        if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.AmbiguousPath;
    }
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

fn toPhase(kind: solver.OrderedActionKind) Phase {
    return switch (kind) {
        .bootstrap_extract => .bootstrap_extract,
        .remove => .remove,
        .unpack => .unpack,
        .configure_pending => .configure_pending,
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

fn hashPolicy(policy: Policy) [32]u8 {
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
    return hash.finalResult();
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
    io: std.Io,

    pub fn interface(self: *SystemFileSystem) FileSystem {
        return .{
            .context = self,
            .validateRootFn = validateRoot,
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

/// Production bounded advisory lock adapter. A token owns the locked file
/// descriptor until release.
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
                std.os.linux.F.SETLK,
                @intFromPtr(&record),
            );
            if (std.posix.errno(lock_result) != .SUCCESS) {
                const errno = std.posix.errno(lock_result);
                file.close(self.io);
                if (errno == .ACCES or errno == .AGAIN) {
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
            const next = try current.openDir(self.io, component, .{ .follow_symlinks = false });
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
    status_reads: usize = 0,
    crash_point: ?recovery.CrashPoint = null,
    crash_index: usize = 0,

    fn dependencies(self: *TestHarness) Dependencies {
        return .{
            .filesystem = .{
                .context = self,
                .validateRootFn = validateRoot,
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
        if (!self.root_valid or self.root_fail_after == current) return error.SymlinkRoot;
    }

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
        if (self.status_source) |source| return allocator.dupe(u8, source);
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        const writer = &output.writer;
        for (self.invocations[0..self.invocation_count], 0..) |invocation, index| {
            if (invocation.phase == .unpack and invocation.package != null) {
                var configured = false;
                for (self.invocations[index + 1 .. self.invocation_count]) |later|
                    if (later.phase == .configure_pending) {
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

test "transaction_executor.test.production adapters expose injectable interfaces" {
    var filesystem: SystemFileSystem = .{ .io = std.testing.io };
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
    var filesystem: SystemFileSystem = .{ .io = std.testing.io };
    const bytes = try filesystem.interface().readArtifact(std.testing.allocator, path, 5);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("exact", bytes);
    try std.testing.expectError(
        error.StreamTooLong,
        filesystem.interface().readArtifact(std.testing.allocator, path, 4),
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
