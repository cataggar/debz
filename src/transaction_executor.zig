const std = @import("std");
const solver = @import("solver.zig");
const deb_payload = @import("deb_payload.zig");

pub const Phase = enum { remove, unpack, configure, triggers };
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
};

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
    cancellation: Cancellation = Cancellation.never(),
};

pub const CommandProvenance = struct {
    phase: Phase,
    package: ?[]const u8,
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
    dpkg_failed,
    interrupted,
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

const State = struct {
    arena: std.mem.Allocator,
    commands: std.ArrayList(CommandProvenance) = .empty,
    failure: ?Failure = null,
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

    for (request.plan.ordered_actions) |ordered| {
        if (dependencies.cancellation.cancelled()) {
            state.failure = interruption(null, null, state.commands.items.len, "cancelled before dpkg invocation");
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
        if (!locksHeld(dependencies.locks, &held)) {
            state.failure = .{
                .code = .lock_lost,
                .phase = toPhase(ordered.kind),
                .package = try arena.dupe(u8, ordered.package),
                .diagnostic = "transaction lock ownership was lost",
                .completed_commands = state.commands.items.len,
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }

        const phase = toPhase(ordered.kind);
        const artifact = if (phase == .unpack)
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
            .command_sha256 = hashInvocation(argv, &audited_environment),
            .artifact_sha256 = artifact_digest,
        };
        const result = dependencies.process.run(.{
            .argv = argv,
            .environment = &audited_environment,
            .phase = phase,
            .package = ordered.package,
        }) catch |err| {
            state.failure = .{
                .code = .process_spawn,
                .phase = phase,
                .package = try arena.dupe(u8, ordered.package),
                .diagnostic = try arena.dupe(u8, @errorName(err)),
                .completed_commands = state.commands.items.len,
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        try state.commands.append(arena, provenance);
        if (!successful(result.termination)) {
            state.failure = try processFailure(arena, result, phase, ordered.package, request.policy.maximum_diagnostic_bytes, state.commands.items.len);
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
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
        const argv = try buildTriggerArgv(arena, root_flag, admin_flag, request.policy);
        const result = dependencies.process.run(.{
            .argv = argv,
            .environment = &audited_environment,
            .phase = .triggers,
            .package = null,
        }) catch |err| {
            state.failure = .{
                .code = .process_spawn,
                .phase = .triggers,
                .diagnostic = try arena.dupe(u8, @errorName(err)),
                .completed_commands = state.commands.items.len,
            };
            return finish(allocator, arena_ptr, &state, plan_sha256);
        };
        try state.commands.append(arena, .{
            .phase = .triggers,
            .package = null,
            .command_sha256 = hashInvocation(argv, &audited_environment),
            .artifact_sha256 = null,
        });
        if (!successful(result.termination)) {
            state.failure = try processFailure(arena, result, .triggers, null, request.policy.maximum_diagnostic_bytes, state.commands.items.len);
            return finish(allocator, arena_ptr, &state, plan_sha256);
        }
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

    return finish(allocator, arena_ptr, &state, plan_sha256);
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
        .failure = state.failure,
    };
}

fn preflight(arena: std.mem.Allocator, request: Request, filesystem: FileSystem) !void {
    try validateRootLexical(request.install_root, request.policy.risk.allow_host_root);
    filesystem.validateRoot(request.install_root) catch return error.UnsafeInstallRoot;
    if (request.plan.schema_version != 2) return error.UnsupportedPlanVersion;
    if (request.plan.mode != .plan_only) return error.NonExecutablePlanMode;
    if (request.plan.actions.len > 100_000 or request.plan.ordered_actions.len > 300_000)
        return error.PlanTooLarge;
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
            .unpack, .configure => if (action.kind == .remove) return error.InvalidInstallOrdering,
        }
        if (ordered.kind == .unpack and
            findArtifact(request.artifacts, ordered.package, ordered.version, ordered.architecture) == null)
            return error.MissingArtifact;
    }
    for (request.plan.actions, 0..) |action, action_index| {
        for (request.plan.actions[0..action_index]) |prior| {
            if (sameIdentity(prior.package, prior.version, prior.architecture, action.package, action.version, action.architecture))
                return error.DuplicatePlanAction;
        }
        var removes: usize = 0;
        var unpacks: usize = 0;
        var configures: usize = 0;
        var unpack_index: ?usize = null;
        var configure_index: ?usize = null;
        for (request.plan.ordered_actions, 0..) |ordered, ordered_index| {
            if (!sameIdentity(action.package, action.version, action.architecture, ordered.package, ordered.version, ordered.architecture))
                continue;
            switch (ordered.kind) {
                .remove => removes += 1,
                .unpack => {
                    unpacks += 1;
                    unpack_index = ordered_index;
                },
                .configure => {
                    configures += 1;
                    configure_index = ordered_index;
                },
            }
        }
        if (action.kind == .remove) {
            if (removes != 1 or unpacks != 0 or configures != 0) return error.IncompleteRemoveOrdering;
        } else if (removes != 0 or unpacks != 1 or configures != 1) {
            return error.IncompleteInstallOrdering;
        } else {
            if (unpack_index.? >= configure_index.?) return error.ConfigureBeforeUnpack;
            if (action.repository == null or action.sha256 == null or action.package_size == null)
                return error.MissingAuthenticatedArtifactMetadata;
            _ = parseHexDigest(action.sha256.?) catch return error.InvalidAuthenticatedDigest;
        }
    }

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
    root_flag: []const u8,
    admin_flag: []const u8,
    phase: Phase,
    package: []const u8,
    architecture: []const u8,
    artifact_path: ?[]const u8,
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
    switch (phase) {
        .remove => {
            try argv.append(allocator, "--remove");
            try argv.append(allocator, try packageSpec(allocator, package, architecture));
        },
        .unpack => {
            try argv.append(allocator, "--unpack");
            try argv.append(allocator, artifact_path.?);
        },
        .configure => {
            try argv.append(allocator, "--no-triggers");
            try argv.append(allocator, "--configure");
            try argv.append(allocator, try packageSpec(allocator, package, architecture));
        },
        .triggers => unreachable,
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
    try argv.append(allocator, "--configure");
    try argv.append(allocator, "--pending");
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

fn toPhase(kind: solver.OrderedActionKind) Phase {
    return switch (kind) {
        .remove => .remove,
        .unpack => .unpack,
        .configure => .configure,
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
        var size_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &size_bytes, action.package_size orelse 0, .little);
        hash.update(&size_bytes);
    }
    hash.update("\xfe");
    for (plan.ordered_actions) |action| {
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
        const result = try std.process.run(self.allocator, self.io, .{
            .argv = invocation.argv,
            .environ_map = &environment,
            .stdout_limit = .limited(self.stderr_limit),
            .stderr_limit = .limited(self.stderr_limit),
        });
        self.allocator.free(result.stdout);
        self.last_stderr = result.stderr;
        const termination: ProcessTermination = switch (result.term) {
            .exited => |code| .{ .exited = code },
            .signal => |signal| .{ .signaled = @intFromEnum(signal) },
            .stopped => |signal| .{ .signaled = @intFromEnum(signal) },
            .unknown => |status| .{ .signaled = status },
        };
        return .{ .termination = termination, .stderr = result.stderr };
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
        return reader.interface.allocRemaining(allocator, .limited(maximum));
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
            const file = std.Io.Dir.createFileAbsolute(self.io, path, .{
                .read = true,
                .truncate = false,
            }) catch |err| return err;
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
            const token = try self.allocator.create(Token);
            token.* = .{ .file = file };
            return token;
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
    corrupt_read: bool = false,
    lock_fail_at: ?usize = null,
    lock_acquires: usize = 0,
    lock_releases: usize = 0,
    lock_held: bool = true,
    invocations: [32]Invocation = undefined,
    invocation_count: usize = 0,
    fail_at: ?usize = null,
    fail_termination: ProcessTermination = .{ .exited = 1 },
    stderr: []const u8 = "",
    cancelled_value: bool = false,

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
            .cancellation = .{ .context = self, .cancelledFn = cancelled },
        };
    }

    fn validateRoot(context: *anyopaque, _: []const u8) !void {
        const self: *TestHarness = @ptrCast(@alignCast(context));
        if (!self.root_valid) return error.SymlinkRoot;
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
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = .unpack, .package = "demo", .version = "1.0", .architecture = "amd64" },
        .{ .sequence = 1, .kind = .configure, .package = "demo", .version = "1.0", .architecture = "amd64" },
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
    try std.testing.expectEqual(@as(usize, 3), harness.invocation_count);
    try std.testing.expectEqualStrings("/usr/bin/dpkg", harness.invocations[0].argv[0]);
    try std.testing.expect(containsArg(harness.invocations[0].argv, "--root=/target"));
    try std.testing.expect(containsArg(harness.invocations[0].argv, "--force-confold"));
    try std.testing.expect(!containsArg(harness.invocations[0].argv, "sh"));
    try std.testing.expectEqual(@as(usize, audited_environment.len), harness.invocations[0].environment.len);
    try std.testing.expectEqualStrings("DEBIAN_FRONTEND", harness.invocations[0].environment[0].key);
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
    try std.testing.expect(containsArg(harness.invocations[3].argv, "--configure"));
    try std.testing.expect(containsArg(harness.invocations[3].argv, "--pending"));
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
        .{ .sequence = 1, .kind = .configure, .package = "demo", .version = "1.0", .architecture = "amd64" },
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

test "transaction_executor.test.production adapters expose injectable interfaces" {
    var filesystem: SystemFileSystem = .{ .io = std.testing.io };
    var locks: SystemLockManager = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    var process: SystemProcessRunner = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    defer process.deinit();
    _ = filesystem.interface();
    _ = locks.interface();
    _ = process.interface();
}
