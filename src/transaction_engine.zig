const std = @import("std");
const exact_lock = @import("exact_lock.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const native_authorization = @import("native_authorization.zig");
const solver = @import("solver.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_recovery = @import("transaction_recovery.zig");

pub const Kind = enum {
    legacy_dpkg,
    native,
};

pub const SelectionError = error{
    BackendUnavailable,
};

/// Native execution requires an explicit native transaction authorization.
/// Legacy execution keeps consuming exact-lock v1 and v2 documents and is
/// never treated as natively authorized.
pub const AuthorizationError = error{
    AuthorizationRequired,
    AuthorizationNotSupported,
    AuthorizationBackendMismatch,
    UnauthorizedLockVersion,
    AuthorizationLockMismatch,
    AuthorizationPlanMismatch,
    AuthorizationRootMismatch,
    AuthorizationPolicyMismatch,
    AuthorizationArchitectureMismatch,
    AuthorizationActionMismatch,
    AuthorizationArtifactMismatch,
};

/// Backend-neutral transaction entry point. The legacy implementation retains
/// its current request and report types until native step provenance lands.
pub const Executor = struct {
    context: *anyopaque,
    executeFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        transaction_executor.Request,
        transaction_executor.Dependencies,
    ) anyerror!transaction_executor.Report,
    recoverFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        transaction_executor.RecoveryRequest,
        transaction_executor.Dependencies,
    ) anyerror!transaction_executor.RecoveryReport,

    pub const legacy_dpkg: Executor = .{
        .context = @ptrCast(@constCast(&legacy_context)),
        .executeFn = executeLegacy,
        .recoverFn = recoverLegacy,
    };
    pub const system = legacy_dpkg;

    pub fn execute(
        self: Executor,
        allocator: std.mem.Allocator,
        request: transaction_executor.Request,
        dependencies: transaction_executor.Dependencies,
    ) !transaction_executor.Report {
        return self.executeFn(self.context, allocator, request, dependencies);
    }

    pub fn recover(
        self: Executor,
        allocator: std.mem.Allocator,
        request: transaction_executor.RecoveryRequest,
        dependencies: transaction_executor.Dependencies,
    ) !transaction_executor.RecoveryReport {
        return self.recoverFn(self.context, allocator, request, dependencies);
    }
};

var legacy_context: u8 = 0;

fn executeLegacy(
    _: *anyopaque,
    allocator: std.mem.Allocator,
    request: transaction_executor.Request,
    dependencies: transaction_executor.Dependencies,
) !transaction_executor.Report {
    return transaction_executor.execute(allocator, request, dependencies);
}

fn recoverLegacy(
    _: *anyopaque,
    allocator: std.mem.Allocator,
    request: transaction_executor.RecoveryRequest,
    dependencies: transaction_executor.Dependencies,
) !transaction_executor.RecoveryReport {
    return transaction_executor.recover(allocator, request, dependencies);
}

/// Selection never falls back. A requested native backend must be present
/// before callers perform acquisition, journal, database, or root mutation.
pub fn select(
    kind: Kind,
    legacy_dpkg: Executor,
    native: ?Executor,
) SelectionError!Executor {
    return switch (kind) {
        .legacy_dpkg => legacy_dpkg,
        .native => native orelse error.BackendUnavailable,
    };
}

/// Binds one reviewed request to the authorization the selected backend
/// requires. Native execution consumes exact-closure-lock v2 plus a native
/// authorization that covers every action, artifact, policy, root, and
/// architecture constraint. Older lock versions stay readable for the legacy
/// backend and are never reinterpreted as native authorization.
pub fn authorize(
    kind: Kind,
    request: transaction_executor.Request,
    authorization: ?*const native_authorization.Authorization,
) AuthorizationError!void {
    switch (kind) {
        .legacy_dpkg => if (authorization != null) return error.AuthorizationNotSupported,
        .native => {
            const authorized = authorization orelse return error.AuthorizationRequired;
            if (authorized.backend != .native) return error.AuthorizationBackendMismatch;
            if (request.exact_lock != null) return error.UnauthorizedLockVersion;
            const lock = request.exact_lock_v2 orelse return error.UnauthorizedLockVersion;
            if (!std.mem.eql(u8, authorized.exact_lock.schema, exact_lock_v2.schema_id) or
                authorized.exact_lock.version != exact_lock_v2.schema_version)
                return error.UnauthorizedLockVersion;
            if (!std.mem.eql(u8, &authorized.exact_lock.digest_sha256, &lock.digest_sha256) or
                !std.mem.eql(u8, &authorized.request_sha256, &lock.request_sha256) or
                !std.mem.eql(u8, &authorized.solver_policy_sha256, &lock.policy_sha256))
                return error.AuthorizationLockMismatch;
            if (!std.mem.eql(u8, authorized.target_architecture, lock.target_architecture) or
                !std.mem.eql(u8, authorized.target_architecture, request.plan.target_architecture))
                return error.AuthorizationArchitectureMismatch;
            if (!std.mem.eql(u8, authorized.install_root, request.install_root) or
                !std.mem.eql(
                    u8,
                    &authorized.root_identity_sha256,
                    &transaction_recovery.rootIdentity(request.install_root),
                )) return error.AuthorizationRootMismatch;
            if (!std.mem.eql(
                u8,
                &authorized.plan_sha256,
                &transaction_executor.planDigest(request.plan.*),
            )) return error.AuthorizationPlanMismatch;
            try authorizePolicy(authorized.*, request.policy);
            try authorizeActions(authorized.*, request.plan.*);
        },
    }
}

fn authorizePolicy(
    authorized: native_authorization.Authorization,
    policy: transaction_executor.Policy,
) AuthorizationError!void {
    if (authorized.policy.conffile != policy.conffile or
        authorized.policy.allow_host_root != policy.risk.allow_host_root or
        authorized.policy.force.len != policy.risk.force.len)
        return error.AuthorizationPolicyMismatch;
    for (policy.risk.force) |risk| {
        var authorized_risk = false;
        for (authorized.policy.force) |candidate| {
            if (candidate == risk) {
                authorized_risk = true;
                break;
            }
        }
        if (!authorized_risk) return error.AuthorizationPolicyMismatch;
    }
    if (!std.mem.eql(
        u8,
        &authorized.executor_policy_sha256,
        &transaction_executor.policyDigest(policy),
    )) return error.AuthorizationPolicyMismatch;
}

fn authorizeActions(
    authorized: native_authorization.Authorization,
    plan: solver.Plan,
) AuthorizationError!void {
    if (authorized.actions.len != plan.actions.len) return error.AuthorizationActionMismatch;
    for (plan.actions) |action| {
        const authorized_action = authorized.findAction(action.package, action.architecture) orelse
            return error.AuthorizationActionMismatch;
        if (authorized_action.kind != action.kind or
            !std.mem.eql(u8, authorized_action.version, action.version))
            return error.AuthorizationActionMismatch;
        const prior_version = if (action.prior_installed) |prior| prior.version else null;
        if ((prior_version == null) != (authorized_action.prior_version == null))
            return error.AuthorizationActionMismatch;
        if (prior_version) |version| {
            if (!std.mem.eql(u8, version, authorized_action.prior_version.?))
                return error.AuthorizationActionMismatch;
        }
        if (solver.isRemoval(action.kind)) {
            if (authorized_action.artifact != null) return error.AuthorizationArtifactMismatch;
            continue;
        }
        const artifact = authorized_action.artifact orelse
            return error.AuthorizationArtifactMismatch;
        const digest = action.sha256 orelse return error.AuthorizationArtifactMismatch;
        const size = action.package_size orelse return error.AuthorizationArtifactMismatch;
        if (!std.mem.eql(u8, &hex32(artifact.sha256), &digest) or artifact.size != size)
            return error.AuthorizationArtifactMismatch;
        try authorizeOrigin(artifact.origin, action);
    }
}

fn authorizeOrigin(
    origin: exact_lock_v2.PackageOrigin,
    action: solver.PlanAction,
) AuthorizationError!void {
    switch (origin) {
        .authenticated_repository => |repository| {
            const planned = action.origin orelse {
                const identity = action.repository orelse
                    return error.AuthorizationArtifactMismatch;
                if (!std.mem.eql(u8, &identity.id, &repository.repository_id))
                    return error.AuthorizationArtifactMismatch;
                return;
            };
            switch (planned) {
                .authenticated_repository => |identity| if (!std.mem.eql(
                    u8,
                    &identity.id,
                    &repository.repository_id,
                )) return error.AuthorizationArtifactMismatch,
                .local_artifact => return error.AuthorizationArtifactMismatch,
            }
        },
        .local_artifact => |artifact| {
            const planned = action.origin orelse return error.AuthorizationArtifactMismatch;
            switch (planned) {
                .authenticated_repository => return error.AuthorizationArtifactMismatch,
                .local_artifact => |local| {
                    const evidence = local.evidence;
                    if (!std.mem.eql(u8, &evidence.artifact_id, &artifact.artifact_id) or
                        !std.mem.eql(u8, &evidence.sha256, &artifact.sha256) or
                        evidence.size != artifact.size or
                        !std.mem.eql(u8, evidence.package, artifact.package) or
                        !std.mem.eql(u8, evidence.version, artifact.version) or
                        !std.mem.eql(u8, evidence.architecture, artifact.architecture) or
                        !std.mem.eql(u8, evidence.acquisition_url, artifact.acquisition_url) or
                        evidence.trust_mode != artifact.trust_mode)
                        return error.AuthorizationArtifactMismatch;
                },
            }
        },
    }
}

fn hex32(bytes: [32]u8) [64]u8 {
    const alphabet = "0123456789abcdef";
    var result: [64]u8 = undefined;
    for (bytes, 0..) |byte, index| {
        result[index * 2] = alphabet[byte >> 4];
        result[index * 2 + 1] = alphabet[byte & 15];
    }
    return result;
}

/// Selects, authorizes, and only then executes. Authorization failures happen
/// before the selected executor observes the request.
pub fn executeAuthorized(
    allocator: std.mem.Allocator,
    kind: Kind,
    legacy_dpkg: Executor,
    native: ?Executor,
    request: transaction_executor.Request,
    authorization: ?*const native_authorization.Authorization,
    dependencies: transaction_executor.Dependencies,
) !transaction_executor.Report {
    const executor = try select(kind, legacy_dpkg, native);
    try authorize(kind, request, authorization);
    return executor.execute(allocator, request, dependencies);
}

const SelectionHarness = struct {
    execute_calls: usize = 0,
    recover_calls: usize = 0,

    fn executor(self: *SelectionHarness) Executor {
        return .{
            .context = self,
            .executeFn = execute,
            .recoverFn = recover,
        };
    }

    fn execute(
        context: *anyopaque,
        _: std.mem.Allocator,
        _: transaction_executor.Request,
        _: transaction_executor.Dependencies,
    ) !transaction_executor.Report {
        const self: *SelectionHarness = @ptrCast(@alignCast(context));
        self.execute_calls += 1;
        return error.TestOnly;
    }

    fn recover(
        context: *anyopaque,
        _: std.mem.Allocator,
        _: transaction_executor.RecoveryRequest,
        _: transaction_executor.Dependencies,
    ) !transaction_executor.RecoveryReport {
        const self: *SelectionHarness = @ptrCast(@alignCast(context));
        self.recover_calls += 1;
        return error.TestOnly;
    }
};

test "transaction_engine.test.selection is explicit and never falls back" {
    var legacy: SelectionHarness = .{};
    var native: SelectionHarness = .{};

    const selected_legacy = try select(.legacy_dpkg, legacy.executor(), null);
    try std.testing.expectEqual(legacy.executor().context, selected_legacy.context);

    const selected_native = try select(.native, legacy.executor(), native.executor());
    try std.testing.expectEqual(native.executor().context, selected_native.context);

    try std.testing.expectError(
        error.BackendUnavailable,
        select(.native, legacy.executor(), null),
    );
    try std.testing.expectEqual(@as(usize, 0), legacy.execute_calls);
    try std.testing.expectEqual(@as(usize, 0), native.execute_calls);
}

const AuthorizationFixture = struct {
    actions: [2]solver.PlanAction,
    ordered: [2]solver.OrderedAction,
    plan: solver.Plan,
    lock: exact_lock_v2.OwnedLock,
    authorization: native_authorization.OwnedAuthorization,

    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(0x22);
    const archive_sha256: [32]u8 = @splat(0x31);
    const archive_size: u64 = 100;
    const policy: transaction_executor.Policy = .{ .conffile = .keep_existing };
    const install_root = "/srv/root";

    fn init(allocator: std.mem.Allocator) !*AuthorizationFixture {
        const self = try allocator.create(AuthorizationFixture);
        errdefer allocator.destroy(self);
        self.actions = .{
            .{
                .kind = .install,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
                .repository = .{ .id = repository_id, .priority = 500 },
                .sha256 = hex32(archive_sha256),
                .package_size = archive_size,
                .installed_size_delta_bytes = 0,
                .source_package = "app",
                .prior_installed = null,
                .requested = true,
                .reason = .explicit_request,
                .selected_origin = null,
                .origin = .{ .authenticated_repository = .{
                    .id = repository_id,
                    .priority = 500,
                } },
            },
            .{
                .kind = .remove,
                .package = "legacy",
                .version = "2.0",
                .architecture = "amd64",
                .repository = null,
                .sha256 = null,
                .package_size = null,
                .installed_size_delta_bytes = 0,
                .source_package = "legacy",
                .prior_installed = .{
                    .package = "legacy",
                    .version = "2.0",
                    .architecture = "amd64",
                    .installed_size_kib = null,
                },
                .requested = true,
                .reason = .explicit_request,
                .selected_origin = null,
            },
        };
        self.ordered = .{
            .{
                .sequence = 0,
                .kind = .remove,
                .package = "legacy",
                .version = "2.0",
                .architecture = "amd64",
            },
            .{
                .sequence = 1,
                .kind = .unpack,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
            },
        };
        self.plan = .{
            .schema_version = 3,
            .target_architecture = "amd64",
            .mode = .plan_only,
            .actions = &self.actions,
            .ordered_actions = &self.ordered,
            .summary = .{},
            .download_bytes = 0,
            .installed_size_delta_bytes = 0,
            .backing_allocator = allocator,
            .arena = undefined,
        };
        self.lock = try exact_lock_v2.create(allocator, .{
            .target_architecture = "amd64",
            .request_sha256 = @splat(7),
            .policy_sha256 = @splat(8),
            .repositories = &.{.{
                .id = repository_id,
                .snapshot_sha256 = snapshot,
                .release_sha256 = @splat(3),
                .index_sha256 = @splat(4),
                .signer_fingerprints = &.{@splat(5)},
            }},
            .local_artifacts = &.{},
            .packages = &.{.{
                .name = "app",
                .version = "1.2",
                .architecture = "amd64",
                .origin = .{ .authenticated_repository = .{
                    .repository_id = repository_id,
                    .repository_snapshot_sha256 = snapshot,
                } },
                .sha256 = archive_sha256,
                .declared_size = archive_size,
                .retention = .requested,
                .dpkg_selection_hold = false,
            }},
            .verified_origins = true,
        });
        errdefer self.lock.deinit();
        self.authorization = try native_authorization.create(allocator, self.input());
        return self;
    }

    fn input(self: *AuthorizationFixture) native_authorization.Input {
        return .{
            .backend = .native,
            .target_architecture = "amd64",
            .install_root = install_root,
            .request_sha256 = self.lock.lock.request_sha256,
            .solver_policy_sha256 = self.lock.lock.policy_sha256,
            .executor_policy_sha256 = transaction_executor.policyDigest(policy),
            .plan_sha256 = transaction_executor.planDigest(self.plan),
            .exact_lock = .{
                .schema = exact_lock_v2.schema_id,
                .version = exact_lock_v2.schema_version,
                .digest_sha256 = self.lock.lock.digest_sha256,
            },
            .policy = .{ .conffile = policy.conffile },
            .actions = &.{
                .{
                    .sequence = 0,
                    .kind = .remove,
                    .package = "legacy",
                    .version = "2.0",
                    .architecture = "amd64",
                    .prior_version = "2.0",
                    .artifact = null,
                },
                .{
                    .sequence = 1,
                    .kind = .install,
                    .package = "app",
                    .version = "1.2",
                    .architecture = "amd64",
                    .prior_version = null,
                    .artifact = .{
                        .sha256 = archive_sha256,
                        .size = archive_size,
                        .origin = .{ .authenticated_repository = .{
                            .repository_id = repository_id,
                            .repository_snapshot_sha256 = snapshot,
                        } },
                    },
                },
            },
            .final_state = &.{
                .{
                    .name = "app",
                    .version = "1.2",
                    .architecture = "amd64",
                    .state = .installed,
                    .dpkg_selection_hold = false,
                },
                .{
                    .name = "legacy",
                    .version = "2.0",
                    .architecture = "amd64",
                    .state = .config_files,
                    .dpkg_selection_hold = false,
                },
            },
        };
    }

    fn request(self: *AuthorizationFixture) transaction_executor.Request {
        return .{
            .plan = &self.plan,
            .install_root = install_root,
            .artifacts = &.{},
            .policy = policy,
            .exact_lock_v2 = &self.lock.lock,
        };
    }

    fn deinit(self: *AuthorizationFixture, allocator: std.mem.Allocator) void {
        self.authorization.deinit();
        self.lock.deinit();
        allocator.destroy(self);
    }
};

test "transaction_engine.test.native execution requires a bound native authorization" {
    const fixture = try AuthorizationFixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    const authorization = &fixture.authorization.authorization;

    try authorize(.native, fixture.request(), authorization);
    try authorize(.legacy_dpkg, fixture.request(), null);
    try std.testing.expectError(
        error.AuthorizationNotSupported,
        authorize(.legacy_dpkg, fixture.request(), authorization),
    );
    try std.testing.expectError(
        error.AuthorizationRequired,
        authorize(.native, fixture.request(), null),
    );

    var legacy_backend = authorization.*;
    legacy_backend.backend = .legacy_dpkg;
    try std.testing.expectError(
        error.AuthorizationBackendMismatch,
        authorize(.native, fixture.request(), &legacy_backend),
    );

    var lock_v1 = try exact_lock.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(7),
        .policy_sha256 = @splat(8),
        .repositories = &.{.{
            .id = AuthorizationFixture.repository_id,
            .snapshot_sha256 = AuthorizationFixture.snapshot,
            .release_sha256 = @splat(3),
            .index_sha256 = @splat(4),
            .signer_fingerprints = &.{@splat(5)},
        }},
        .packages = &.{.{
            .name = "app",
            .version = "1.2",
            .architecture = "amd64",
            .repository_id = AuthorizationFixture.repository_id,
            .repository_snapshot_sha256 = AuthorizationFixture.snapshot,
            .sha256 = AuthorizationFixture.archive_sha256,
            .declared_size = AuthorizationFixture.archive_size,
            .retention = .requested,
            .dpkg_selection_hold = false,
        }},
        .authenticated_metadata = true,
    });
    defer lock_v1.deinit();
    var legacy_lock_request = fixture.request();
    legacy_lock_request.exact_lock_v2 = null;
    legacy_lock_request.exact_lock = &lock_v1.lock;
    try std.testing.expectError(
        error.UnauthorizedLockVersion,
        authorize(.native, legacy_lock_request, authorization),
    );
    try authorize(.legacy_dpkg, legacy_lock_request, null);

    var unlocked = fixture.request();
    unlocked.exact_lock_v2 = null;
    try std.testing.expectError(
        error.UnauthorizedLockVersion,
        authorize(.native, unlocked, authorization),
    );

    var stale_lock = authorization.*;
    stale_lock.exact_lock.digest_sha256 = @splat(0xaa);
    try std.testing.expectError(
        error.AuthorizationLockMismatch,
        authorize(.native, fixture.request(), &stale_lock),
    );

    var stale_lock_schema = authorization.*;
    stale_lock_schema.exact_lock.version = 1;
    try std.testing.expectError(
        error.UnauthorizedLockVersion,
        authorize(.native, fixture.request(), &stale_lock_schema),
    );

    var stale_request = authorization.*;
    stale_request.request_sha256 = @splat(0xbb);
    try std.testing.expectError(
        error.AuthorizationLockMismatch,
        authorize(.native, fixture.request(), &stale_request),
    );

    var stale_architecture = authorization.*;
    stale_architecture.target_architecture = "arm64";
    try std.testing.expectError(
        error.AuthorizationArchitectureMismatch,
        authorize(.native, fixture.request(), &stale_architecture),
    );

    var other_root = fixture.request();
    other_root.install_root = "/srv/other";
    try std.testing.expectError(
        error.AuthorizationRootMismatch,
        authorize(.native, other_root, authorization),
    );

    var stale_plan = authorization.*;
    stale_plan.plan_sha256 = @splat(0xcc);
    try std.testing.expectError(
        error.AuthorizationPlanMismatch,
        authorize(.native, fixture.request(), &stale_plan),
    );

    var other_policy = fixture.request();
    other_policy.policy.conffile = .use_package_version;
    try std.testing.expectError(
        error.AuthorizationPolicyMismatch,
        authorize(.native, other_policy, authorization),
    );

    var forced = fixture.request();
    forced.policy.risk.force = &.{.depends};
    try std.testing.expectError(
        error.AuthorizationPolicyMismatch,
        authorize(.native, forced, authorization),
    );

    var stale_policy_digest = authorization.*;
    stale_policy_digest.executor_policy_sha256 = @splat(0xdd);
    try std.testing.expectError(
        error.AuthorizationPolicyMismatch,
        authorize(.native, fixture.request(), &stale_policy_digest),
    );
}

test "transaction_engine.test.native authorization covers every action and artifact" {
    const fixture = try AuthorizationFixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    const authorization = &fixture.authorization.authorization;

    var extra_actions = authorization.*;
    extra_actions.actions = authorization.actions[0..1];
    try std.testing.expectError(
        error.AuthorizationActionMismatch,
        authorize(.native, fixture.request(), &extra_actions),
    );

    {
        var mutated = fixture.actions;
        mutated[0].version = "9.9";
        var plan = fixture.plan;
        plan.actions = &mutated;
        var request = fixture.request();
        request.plan = &plan;
        var rebound = authorization.*;
        rebound.plan_sha256 = transaction_executor.planDigest(plan);
        try std.testing.expectError(
            error.AuthorizationActionMismatch,
            authorize(.native, request, &rebound),
        );
    }
    {
        var mutated = fixture.actions;
        mutated[1].prior_installed = null;
        var plan = fixture.plan;
        plan.actions = &mutated;
        var request = fixture.request();
        request.plan = &plan;
        var rebound = authorization.*;
        rebound.plan_sha256 = transaction_executor.planDigest(plan);
        try std.testing.expectError(
            error.AuthorizationActionMismatch,
            authorize(.native, request, &rebound),
        );
    }
    {
        var mutated = fixture.actions;
        mutated[0].sha256 = hex32(@splat(0x77));
        var plan = fixture.plan;
        plan.actions = &mutated;
        var request = fixture.request();
        request.plan = &plan;
        var rebound = authorization.*;
        rebound.plan_sha256 = transaction_executor.planDigest(plan);
        try std.testing.expectError(
            error.AuthorizationArtifactMismatch,
            authorize(.native, request, &rebound),
        );
    }
    {
        var mutated = fixture.actions;
        mutated[0].package_size = AuthorizationFixture.archive_size + 1;
        var plan = fixture.plan;
        plan.actions = &mutated;
        var request = fixture.request();
        request.plan = &plan;
        var rebound = authorization.*;
        rebound.plan_sha256 = transaction_executor.planDigest(plan);
        try std.testing.expectError(
            error.AuthorizationArtifactMismatch,
            authorize(.native, request, &rebound),
        );
    }
    {
        var mutated = fixture.actions;
        mutated[0].origin = .{ .authenticated_repository = .{
            .id = @splat('b'),
            .priority = 500,
        } };
        mutated[0].repository = .{ .id = @splat('b'), .priority = 500 };
        var plan = fixture.plan;
        plan.actions = &mutated;
        var request = fixture.request();
        request.plan = &plan;
        var rebound = authorization.*;
        rebound.plan_sha256 = transaction_executor.planDigest(plan);
        try std.testing.expectError(
            error.AuthorizationArtifactMismatch,
            authorize(.native, request, &rebound),
        );
    }
    {
        var mutated = fixture.actions;
        mutated[0].origin = .{ .local_artifact = .{
            .evidence = .{
                .artifact_id = @splat('c'),
                .sha256 = AuthorizationFixture.archive_sha256,
                .size = AuthorizationFixture.archive_size,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
                .acquisition_url = "file:///app.deb",
                .trust_mode = .pinned_sha256,
            },
            .solver_priority = 1000,
        } };
        var plan = fixture.plan;
        plan.actions = &mutated;
        var request = fixture.request();
        request.plan = &plan;
        var rebound = authorization.*;
        rebound.plan_sha256 = transaction_executor.planDigest(plan);
        try std.testing.expectError(
            error.AuthorizationArtifactMismatch,
            authorize(.native, request, &rebound),
        );
    }
}

test "transaction_engine.test.unauthorized native execution never reaches the executor" {
    const fixture = try AuthorizationFixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    var legacy: SelectionHarness = .{};
    var native: SelectionHarness = .{};
    const dependencies: transaction_executor.Dependencies = undefined;

    try std.testing.expectError(error.AuthorizationRequired, executeAuthorized(
        std.testing.allocator,
        .native,
        legacy.executor(),
        native.executor(),
        fixture.request(),
        null,
        dependencies,
    ));
    try std.testing.expectEqual(@as(usize, 0), native.execute_calls);
    try std.testing.expectEqual(@as(usize, 0), legacy.execute_calls);

    try std.testing.expectError(error.BackendUnavailable, executeAuthorized(
        std.testing.allocator,
        .native,
        legacy.executor(),
        null,
        fixture.request(),
        &fixture.authorization.authorization,
        dependencies,
    ));
    try std.testing.expectEqual(@as(usize, 0), native.execute_calls);

    try std.testing.expectError(error.TestOnly, executeAuthorized(
        std.testing.allocator,
        .native,
        legacy.executor(),
        native.executor(),
        fixture.request(),
        &fixture.authorization.authorization,
        dependencies,
    ));
    try std.testing.expectEqual(@as(usize, 1), native.execute_calls);
    try std.testing.expectEqual(@as(usize, 0), legacy.execute_calls);
}
