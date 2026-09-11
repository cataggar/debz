//! Pure production preparation for the native transaction runtime.
//!
//! Acquisition supplies validated archive evidence and root preflight supplies
//! the installed database. This adapter binds those inputs to the real solver
//! plan and exact-lock v2; it neither invents fixture bindings nor executes a
//! command. The runtime must revalidate the resulting program under its locks.
const std = @import("std");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const maintainer_script = @import("maintainer_script.zig");
const native_authorization = @import("native_authorization.zig");
const native_program = @import("native_program.zig");
const solver = @import("solver.zig");
const transaction_engine = @import("transaction_engine.zig");
const transaction_executor = @import("transaction_executor.zig");

pub const Request = struct {
    plan: *const solver.Plan,
    exact_lock: *const exact_lock_v2.Lock,
    install_root: []const u8,
    policy: transaction_executor.Policy,
    script_policy: maintainer_script.Policy,
    foreign_architectures: []const []const u8 = &.{},
    installed: native_program.InstalledDatabase,
    archives: []const native_program.Archive = &.{},
    trigger_authority: ?native_authorization.TriggerAuthority = null,
    ownership_conflicts: []const native_program.OwnershipConflict = &.{},
    unsupported_features: []const []const u8 = &.{},
    limits: native_program.Limits = .{},
};

pub const Prepared = struct {
    authorization: native_authorization.OwnedAuthorization,
    program: native_program.OwnedProgram,

    pub fn deinit(self: *Prepared) void {
        self.program.deinit();
        self.authorization.deinit();
        self.* = undefined;
    }
};

pub const OwnedDiagnostic = struct {
    diagnostic: native_program.Diagnostic,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedDiagnostic) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }

    fn copy(allocator: std.mem.Allocator, diagnostic: native_program.Diagnostic) !OwnedDiagnostic {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = .init(allocator);
        errdefer arena.deinit();
        const owned = arena.allocator();
        var result = diagnostic;
        result.detail = try owned.dupe(u8, diagnostic.detail);
        inline for (.{ "package", "architecture", "path" }) |field| {
            if (@field(diagnostic, field)) |text|
                @field(result, field) = try owned.dupe(u8, text);
        }
        return .{ .diagnostic = result, .arena = arena, .backing_allocator = allocator };
    }
};

pub const Result = union(enum) {
    prepared: Prepared,
    diagnostic: OwnedDiagnostic,

    pub fn deinit(self: *Result) void {
        switch (self.*) {
            inline else => |*value| value.deinit(),
        }
        self.* = undefined;
    }
};

const IdentityIndex = std.StringHashMapUnmanaged(usize);

fn identity(allocator: std.mem.Allocator, name: []const u8, architecture: []const u8) ![]const u8 {
    if (name.len == 0 or architecture.len == 0 or
        name.len > native_program.maximum_identity_bytes or
        architecture.len > native_program.maximum_identity_bytes or
        std.mem.indexOfScalar(u8, name, 0) != null or
        std.mem.indexOfScalar(u8, architecture, 0) != null)
        return error.InvalidIdentity;
    return std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ name, architecture });
}

fn sameText(left: []const u8, right: []const u8) bool {
    return std.mem.eql(u8, left, right);
}

fn retainsConfiguration(package: native_program.InstalledPackage) bool {
    if (package.conffiles.len != 0) return true;
    for (package.scripts) |script| if (script.kind == .postrm) return true;
    return false;
}

const Fixture = struct {
    actions: [2]solver.PlanAction,
    ordered: [3]solver.OrderedAction,
    installed: [3]native_program.InstalledPackage,
    archives: [1]native_program.Archive,
    plan: solver.Plan,
    lock: exact_lock_v2.OwnedLock,

    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(0x22);
    const archive_sha256: [32]u8 = @splat(0x31);
    const repository_origin: exact_lock_v2.PackageOrigin = .{
        .authenticated_repository = .{
            .repository_id = repository_id,
            .repository_snapshot_sha256 = snapshot,
        },
    };
    const local_origin: @import("package_origin.zig").LocalArtifactEvidence = .{
        .artifact_id = @splat('b'),
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
        .sha256 = archive_sha256,
        .size = 100,
        .acquisition_url = "https://packages.example.test/app.deb",
        .trust_mode = .pinned_sha256,
    };

    fn init(allocator: std.mem.Allocator, local: bool) !*Fixture {
        const self = try allocator.create(Fixture);
        errdefer allocator.destroy(self);
        self.actions = .{
            .{
                .kind = .install,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
                .repository = if (local) null else .{ .id = repository_id, .priority = 500 },
                .sha256 = @import("package_origin.zig").artifactIdFromSha256(archive_sha256),
                .package_size = 100,
                .installed_size_delta_bytes = 0,
                .source_package = "app",
                .prior_installed = null,
                .requested = true,
                .reason = .explicit_request,
                .selected_origin = null,
                .origin = if (local)
                    .{ .local_artifact = .{ .evidence = local_origin, .solver_priority = 500 } }
                else
                    .{ .authenticated_repository = .{ .id = repository_id, .priority = 500 } },
            },
            .{
                .kind = .remove,
                .package = "old",
                .version = "2.0",
                .architecture = "amd64",
                .repository = null,
                .sha256 = null,
                .package_size = null,
                .installed_size_delta_bytes = 0,
                .source_package = "old",
                .prior_installed = .{
                    .package = "old",
                    .version = "2.0",
                    .architecture = "amd64",
                    .installed_size_kib = null,
                },
                .requested = false,
                .reason = .replacement,
                .selected_origin = null,
            },
        };
        self.ordered = .{
            .{ .sequence = 0, .kind = .remove, .package = "old", .version = "2.0", .architecture = "amd64" },
            .{ .sequence = 1, .kind = .unpack, .package = "app", .version = "1.2", .architecture = "amd64" },
            .{ .sequence = 2, .kind = .configure_pending, .package = "app", .version = "1.2", .architecture = "amd64" },
        };
        self.installed = .{
            .{
                .name = "old",
                .version = "2.0",
                .architecture = "amd64",
                .state = .installed,
                .conffiles = &.{.{ .path = "/etc/old.conf", .recorded_md5 = @splat(0x44) }},
            },
            .{ .name = "held", .version = "3.0", .architecture = "amd64", .state = .installed, .hold = true },
            .{ .name = "residue", .version = "1.0", .architecture = "amd64", .state = .config_files },
        };
        self.archives = .{.{
            .package = "app",
            .version = "1.2",
            .architecture = "amd64",
            .sha256 = archive_sha256,
            .size = 100,
            .origin = if (local) .{ .local_artifact = local_origin } else repository_origin,
            .application_sha256 = @splat(0x56),
        }};
        self.plan = .{
            .schema_version = 3,
            .target_architecture = "amd64",
            .mode = .plan_only,
            .actions = &self.actions,
            .ordered_actions = &self.ordered,
            .summary = .{},
            .download_bytes = 100,
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
            .local_artifacts = if (local) &.{local_origin} else &.{},
            .packages = &.{
                .{
                    .name = "app",
                    .version = "1.2",
                    .architecture = "amd64",
                    .origin = self.archives[0].origin,
                    .sha256 = archive_sha256,
                    .declared_size = 100,
                    .retention = .requested,
                    .dpkg_selection_hold = false,
                },
                .{
                    .name = "held",
                    .version = "3.0",
                    .architecture = "amd64",
                    .origin = repository_origin,
                    .sha256 = @splat(0x62),
                    .declared_size = 123,
                    .retention = .retained,
                    .dpkg_selection_hold = true,
                },
            },
            .verified_origins = true,
        });
        return self;
    }

    fn request(self: *Fixture) Request {
        return .{
            .plan = &self.plan,
            .exact_lock = &self.lock.lock,
            .install_root = "/srv/native-root",
            .policy = .{ .conffile = .keep_existing },
            .script_policy = .{},
            .installed = .{ .generation_sha256 = @splat(0x63), .packages = &self.installed },
            .archives = &self.archives,
        };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.lock.deinit();
        allocator.destroy(self);
    }
};

fn preparedResult(result: *const Result) !*const Prepared {
    return switch (result.*) {
        .prepared => |*value| value,
        .diagnostic => |value| {
            std.debug.print("unexpected native preparation diagnostic: {s}: {s}\n", .{
                @tagName(value.diagnostic.code), value.diagnostic.detail,
            });
            return error.TestUnexpectedResult;
        },
    };
}

fn expectDiagnostic(request: Request, code: native_program.DiagnosticCode) !void {
    var result = try prepare(std.testing.allocator, request);
    defer result.deinit();
    switch (result) {
        .prepared => return error.TestUnexpectedResult,
        .diagnostic => |value| try std.testing.expectEqual(code, value.diagnostic.code),
    }
}

test "native_preparation.test.production hashes origins and mixed final closure remain distinct" {
    const fixture = try Fixture.init(std.testing.allocator, false);
    defer fixture.deinit(std.testing.allocator);
    var result = try prepare(std.testing.allocator, fixture.request());
    defer result.deinit();
    const prepared = try preparedResult(&result);
    const authorization = prepared.authorization.authorization;
    const program = prepared.program.program;
    try std.testing.expectEqual(fixture.lock.lock.request_sha256, authorization.request_sha256);
    try std.testing.expectEqual(fixture.lock.lock.policy_sha256, authorization.solver_policy_sha256);
    try std.testing.expectEqual(
        transaction_executor.policyDigest(fixture.request().policy),
        authorization.executor_policy_sha256,
    );
    try std.testing.expectEqual(transaction_executor.planDigest(fixture.plan), authorization.plan_sha256);
    try std.testing.expectEqual(fixture.lock.lock.digest_sha256, authorization.exact_lock.digest_sha256);
    try std.testing.expect(program.matchesAuthorization(authorization));
    try std.testing.expectEqual(@as(usize, 4), authorization.final_state.len);
    try std.testing.expectEqual(.installed, authorization.findFinalPackage("app", "amd64").?.state);
    try std.testing.expectEqual(.config_files, authorization.findFinalPackage("old", "amd64").?.state);
    try std.testing.expectEqual(.config_files, authorization.findFinalPackage("residue", "amd64").?.state);
    try std.testing.expect(authorization.findFinalPackage("held", "amd64").?.dpkg_selection_hold);
    const origin = authorization.findAction("app", "amd64").?.artifact.?.origin.authenticated_repository;
    try std.testing.expectEqual(Fixture.repository_id, origin.repository_id);
    try std.testing.expectEqual(Fixture.snapshot, origin.repository_snapshot_sha256);
    try std.testing.expectEqualStrings(
        &@import("package_origin.zig").artifactIdFromSha256(@splat(0x63)),
        &program.installed_database.generation_sha256,
    );
    const json = try program.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "fixture") == null);
}

test "native_preparation.test.purge and data-only remove do not retain configuration" {
    const fixture = try Fixture.init(std.testing.allocator, false);
    defer fixture.deinit(std.testing.allocator);
    fixture.actions[1].kind = .purge;
    fixture.ordered[0].kind = .purge;
    var purged = try prepare(std.testing.allocator, fixture.request());
    defer purged.deinit();
    try std.testing.expect((try preparedResult(&purged)).authorization.authorization.findFinalPackage("old", "amd64") == null);
    fixture.actions[1].kind = .remove;
    fixture.ordered[0].kind = .remove;
    fixture.installed[0].conffiles = &.{};
    var removed = try prepare(std.testing.allocator, fixture.request());
    defer removed.deinit();
    try std.testing.expect((try preparedResult(&removed)).authorization.authorization.findFinalPackage("old", "amd64") == null);
}

test "native_preparation.test.remove preserves an already residual record without metadata" {
    const fixture = try Fixture.init(std.testing.allocator, false);
    defer fixture.deinit(std.testing.allocator);
    fixture.installed[0].state = .config_files;
    fixture.installed[0].conffiles = &.{};
    var result = try prepare(std.testing.allocator, fixture.request());
    defer result.deinit();
    const authorization = (try preparedResult(&result)).authorization.authorization;
    try std.testing.expectEqual(.config_files, authorization.findFinalPackage("old", "amd64").?.state);
}

test "native_preparation.test.empty lock requires every removal and preserves residual configuration" {
    const fixture = try Fixture.init(std.testing.allocator, false);
    defer fixture.deinit(std.testing.allocator);
    var lock = try exact_lock_v2.create(std.testing.allocator, .{
        .target_architecture = fixture.lock.lock.target_architecture,
        .request_sha256 = fixture.lock.lock.request_sha256,
        .policy_sha256 = fixture.lock.lock.policy_sha256,
        .repositories = &.{},
        .local_artifacts = &.{},
        .packages = &.{},
        .verified_origins = true,
    });
    defer lock.deinit();
    fixture.plan.actions = fixture.actions[1..];
    fixture.plan.ordered_actions = fixture.ordered[0..1];
    fixture.plan.download_bytes = 0;
    var request = fixture.request();
    request.exact_lock = &lock.lock;
    request.archives = &.{};
    request.installed.packages = fixture.installed[0..1];
    for ([_]bool{ false, true }) |purge| {
        fixture.actions[1].kind = if (purge) .purge else .remove;
        fixture.ordered[0].kind = if (purge) .purge else .remove;
        var result = try prepare(std.testing.allocator, request);
        defer result.deinit();
        const prepared = try preparedResult(&result);
        const authorization = prepared.authorization.authorization;
        try std.testing.expectEqual(@as(usize, 1), authorization.actions.len);
        try std.testing.expectEqual(fixture.actions[1].kind, authorization.actions[0].kind);
        try std.testing.expect(authorization.actions[0].artifact == null);
        try std.testing.expectEqual(@as(usize, 0), prepared.program.program.artifacts.len);
        try std.testing.expectEqual(lock.lock.digest_sha256, authorization.exact_lock.digest_sha256);
        try std.testing.expect(prepared.program.program.matchesAuthorization(authorization));
        if (purge) {
            try std.testing.expectEqual(@as(usize, 0), authorization.final_state.len);
        } else {
            try std.testing.expectEqual(@as(usize, 1), authorization.final_state.len);
            try std.testing.expectEqual(.config_files, authorization.final_state[0].state);
        }
    }
    fixture.actions[1].kind = .remove;
    fixture.ordered[0].kind = .remove;
    fixture.installed[0].conffiles = &.{};
    var data_only = try prepare(std.testing.allocator, request);
    defer data_only.deinit();
    try std.testing.expectEqual(@as(usize, 0), (try preparedResult(&data_only)).authorization.authorization.final_state.len);

    request.installed.packages = &fixture.installed;
    try std.testing.expectError(error.LockClosureMismatch, prepare(std.testing.allocator, request));
    request.installed.packages = fixture.installed[0..1];
    fixture.plan.actions = &.{};
    fixture.plan.ordered_actions = &.{};
    try std.testing.expectError(error.LockClosureMismatch, prepare(std.testing.allocator, request));
    request.installed.packages = &.{};
    try std.testing.expectError(error.EmptyProgram, prepare(std.testing.allocator, request));
    fixture.plan.actions = fixture.actions[0..1];
    fixture.plan.ordered_actions = fixture.ordered[1..];
    try std.testing.expectError(error.LockClosureMismatch, prepare(std.testing.allocator, request));
}

test "native_preparation.test.local origins are preserved and not reinterpreted as repository origins" {
    const fixture = try Fixture.init(std.testing.allocator, true);
    defer fixture.deinit(std.testing.allocator);
    var result = try prepare(std.testing.allocator, fixture.request());
    defer result.deinit();
    const prepared = try preparedResult(&result);
    const origin = prepared.authorization.authorization.actions[0].artifact.?.origin.local_artifact;
    try std.testing.expect(@import("package_origin.zig").eqlLocalArtifact(Fixture.local_origin, origin));
    fixture.archives[0].origin = Fixture.repository_origin;
    try expectDiagnostic(fixture.request(), .archive_origin_mismatch);
}

test "native_preparation.test.lock contents must match their digest" {
    const fixture = try Fixture.init(std.testing.allocator, false);
    defer fixture.deinit(std.testing.allocator);
    fixture.lock.lock.digest_sha256[0] ^= 1;
    try std.testing.expectError(error.DigestMismatch, prepare(std.testing.allocator, fixture.request()));
}

test "native_preparation.test.plan artifact and prior identity substitutions are refused" {
    const fixture = try Fixture.init(std.testing.allocator, false);
    defer fixture.deinit(std.testing.allocator);
    const original = fixture.actions;
    fixture.actions[0].sha256 = @splat('0');
    try std.testing.expectError(error.AuthorizationArtifactMismatch, prepare(std.testing.allocator, fixture.request()));
    fixture.actions = original;
    fixture.actions[0].origin = .{ .authenticated_repository = .{ .id = @splat('c'), .priority = 500 } };
    try std.testing.expectError(error.AuthorizationArtifactMismatch, prepare(std.testing.allocator, fixture.request()));
    fixture.actions = original;
    fixture.actions[1].prior_installed.?.package = "another";
    try std.testing.expectError(error.InstalledPlanMismatch, prepare(std.testing.allocator, fixture.request()));
    fixture.actions = original;
    fixture.actions[1].prior_installed.?.version = "9.0";
    try std.testing.expectError(error.InstalledPlanMismatch, prepare(std.testing.allocator, fixture.request()));
}

test "native_preparation.test.omitted unrequested packages and changed holds refuse closure drift" {
    const fixture = try Fixture.init(std.testing.allocator, false);
    defer fixture.deinit(std.testing.allocator);
    fixture.installed[2].state = .installed;
    try std.testing.expectError(error.LockClosureMismatch, prepare(std.testing.allocator, fixture.request()));
    fixture.installed[2].state = .config_files;
    fixture.installed[1].hold = false;
    try std.testing.expectError(error.LockClosureMismatch, prepare(std.testing.allocator, fixture.request()));
    fixture.installed[1].hold = true;
    var request = fixture.request();
    request.installed.packages = fixture.installed[0..1];
    try std.testing.expectError(error.LockClosureMismatch, prepare(std.testing.allocator, request));
}

test "native_preparation.test.compiler retains missing archive and lifecycle diagnostics" {
    const fixture = try Fixture.init(std.testing.allocator, false);
    defer fixture.deinit(std.testing.allocator);
    var request = fixture.request();
    request.archives = &.{};
    try expectDiagnostic(request, .missing_archive);
    fixture.archives[0].sha256[0] ^= 1;
    try expectDiagnostic(fixture.request(), .archive_evidence_mismatch);
    fixture.archives[0].sha256[0] ^= 1;
    fixture.archives[0].origin.authenticated_repository.repository_snapshot_sha256[0] ^= 1;
    try expectDiagnostic(fixture.request(), .archive_origin_mismatch);
    fixture.archives[0].origin = Fixture.repository_origin;
    fixture.plan.ordered_actions = fixture.ordered[0..2];
    try expectDiagnostic(fixture.request(), .missing_configure_barrier);
}

test "native_preparation.test.trigger work cannot disappear without reviewed authority" {
    const fixture = try Fixture.init(std.testing.allocator, false);
    defer fixture.deinit(std.testing.allocator);
    fixture.archives[0].triggers = &.{.{ .kind = .activate, .name = "refresh" }};
    try std.testing.expectError(error.TriggerAuthorityRequired, prepare(std.testing.allocator, fixture.request()));
    fixture.archives[0].triggers = &.{};
    fixture.installed[1].triggers_pending = &.{"refresh"};
    try std.testing.expectError(error.TriggerAuthorityRequired, prepare(std.testing.allocator, fixture.request()));
}

test "native_preparation.test.outputs own text after caller input is released" {
    const fixture = try Fixture.init(std.testing.allocator, true);
    var app = [_]u8{ 'a', 'p', 'p' };
    fixture.actions[0].package = &app;
    fixture.archives[0].package = &app;
    var result = prepare(std.testing.allocator, fixture.request()) catch |err| {
        fixture.deinit(std.testing.allocator);
        return err;
    };
    defer result.deinit();
    @memset(&app, 'x');
    fixture.deinit(std.testing.allocator);
    const prepared = try preparedResult(&result);
    try std.testing.expectEqualStrings("app", prepared.authorization.authorization.actions[0].package);
    try std.testing.expectEqualStrings("app", prepared.program.program.artifacts[0].package.name);
}

test "native_preparation.test.diagnostics own text after temporary authorization is released" {
    const fixture = try Fixture.init(std.testing.allocator, false);
    defer fixture.deinit(std.testing.allocator);
    var request = fixture.request();
    request.archives = &.{};
    var result = try prepare(std.testing.allocator, request);
    defer result.deinit();
    switch (result) {
        .prepared => return error.TestUnexpectedResult,
        .diagnostic => |value| {
            try std.testing.expectEqual(.missing_archive, value.diagnostic.code);
            try std.testing.expectEqualStrings("app", value.diagnostic.package.?);
            try std.testing.expectEqualStrings("amd64", value.diagnostic.architecture.?);
        },
    }
}

fn allocationCase(allocator: std.mem.Allocator, request: Request, succeeds: bool) !void {
    var result = try prepare(allocator, request);
    defer result.deinit();
    try std.testing.expectEqual(succeeds, result == .prepared);
}

test "native_preparation.test.all preparation and diagnostic allocation failures are owned" {
    const fixture = try Fixture.init(std.testing.allocator, false);
    defer fixture.deinit(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{ fixture.request(), true });
    var request = fixture.request();
    request.archives = &.{};
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{ request, false });
}

/// Unlike the fixture compiler, every hash here has its production meaning:
/// lock request, solver policy, executor policy, plan, and archive origin.
pub fn prepare(allocator: std.mem.Allocator, request: Request) !Result {
    if (request.plan.actions.len > native_authorization.maximum_actions or
        request.plan.ordered_actions.len > native_program.maximum_steps or
        request.installed.packages.len > native_program.maximum_installed_packages or
        request.archives.len > native_program.maximum_artifacts or
        request.exact_lock.packages.len > exact_lock_v2.maximum_packages or
        request.exact_lock.repositories.len > exact_lock_v2.maximum_repositories or
        request.exact_lock.local_artifacts.len > exact_lock_v2.maximum_local_artifacts)
        return error.LimitExceeded;
    if (!sameText(request.plan.target_architecture, request.exact_lock.target_architecture))
        return error.AuthorizationArchitectureMismatch;

    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const temporary = scratch.allocator();

    // Validate the lock's contents and digest, not just its claimed digest.
    const lock_bytes = request.exact_lock.canonicalJson(temporary) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        else => return err,
    };
    var verified_lock = exact_lock_v2.decode(allocator, lock_bytes, exact_lock_v2.maximum_document_bytes) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        else => return err,
    };
    defer verified_lock.deinit();
    const lock = verified_lock.lock;
    var installed_index: IdentityIndex = .empty;
    for (request.installed.packages, 0..) |package, index| {
        const key = try identity(temporary, package.name, package.architecture);
        const entry = try installed_index.getOrPut(temporary, key);
        if (entry.found_existing) return error.DuplicateInstalledPackage;
        entry.value_ptr.* = index;
    }
    var action_index: IdentityIndex = .empty;
    const actions = try temporary.alloc(native_authorization.Action, request.plan.actions.len);
    for (request.plan.actions, 0..) |action, index| {
        const key = try identity(temporary, action.package, action.architecture);
        const entry = try action_index.getOrPut(temporary, key);
        if (entry.found_existing) return error.DuplicateAction;
        entry.value_ptr.* = index;
        const prior = if (installed_index.get(key)) |position|
            request.installed.packages[position]
        else
            null;
        if (action.prior_installed) |planned| {
            if (!sameText(planned.package, action.package) or
                !sameText(planned.architecture, action.architecture) or
                prior == null or !sameText(planned.version, prior.?.version))
                return error.InstalledPlanMismatch;
        } else if (action.kind != .install) {
            return error.InstalledPlanMismatch;
        }
        const selected = lock.findIdentity(action.package, action.architecture);
        actions[index] = .{
            .sequence = index,
            .kind = action.kind,
            .package = action.package,
            .version = action.version,
            .architecture = action.architecture,
            .prior_version = if (action.prior_installed) |value| value.version else null,
            .artifact = null,
        };
        if (solver.isRemoval(action.kind)) {
            if (selected != null) return error.LockClosureMismatch;
        } else {
            const package = selected orelse return error.LockClosureMismatch;
            if (!sameText(package.version, action.version))
                return error.LockClosureMismatch;
            actions[index].artifact = .{
                .sha256 = package.sha256,
                .size = package.declared_size,
                .origin = package.origin,
            };
        }
    }

    var final_state: std.ArrayList(native_authorization.FinalPackage) = .empty;
    for (lock.packages) |package| {
        const key = try identity(temporary, package.name, package.architecture);
        if (!action_index.contains(key)) {
            const position = installed_index.get(key) orelse return error.LockClosureMismatch;
            const prior = request.installed.packages[position];
            if (!sameText(package.version, prior.version) or
                package.dpkg_selection_hold != prior.hold)
                return error.LockClosureMismatch;
            switch (prior.state) {
                .installed, .triggers_pending, .triggers_awaited => {},
                else => return error.LockClosureMismatch,
            }
        }
        try final_state.append(temporary, .{
            .name = package.name,
            .version = package.version,
            .architecture = package.architecture,
            .state = .installed,
            .dpkg_selection_hold = package.dpkg_selection_hold,
        });
    }
    for (request.installed.packages) |package| {
        const key = try identity(temporary, package.name, package.architecture);
        if (lock.findIdentity(package.name, package.architecture) != null) continue;
        if (action_index.get(key)) |position| {
            const action = actions[position];
            if (!solver.isRemoval(action.kind)) return error.LockClosureMismatch;
            if (action.kind == .purge or
                (package.state != .config_files and !retainsConfiguration(package)))
                continue;
        } else if (package.state != .config_files) {
            return error.LockClosureMismatch;
        }
        try final_state.append(temporary, .{
            .name = package.name,
            .version = package.version,
            .architecture = package.architecture,
            .state = .config_files,
            .dpkg_selection_hold = if (action_index.contains(key)) false else package.hold,
        });
    }
    if (request.trigger_authority == null) {
        for (request.installed.packages) |package| {
            if (package.triggers_pending.len != 0 or package.triggers_awaited.len != 0 or
                package.triggers.len != 0)
                return error.TriggerAuthorityRequired;
        }
        for (request.archives) |archive| {
            if (archive.triggers.len != 0) return error.TriggerAuthorityRequired;
        }
    }
    var authorization = try native_authorization.create(allocator, .{
        .backend = .native,
        .target_architecture = lock.target_architecture,
        .foreign_architectures = request.foreign_architectures,
        .install_root = request.install_root,
        .request_sha256 = lock.request_sha256,
        .solver_policy_sha256 = lock.policy_sha256,
        .executor_policy_sha256 = transaction_executor.policyDigest(request.policy),
        .plan_sha256 = transaction_executor.planDigest(request.plan.*),
        .exact_lock = .{
            .schema = exact_lock_v2.schema_id,
            .version = exact_lock_v2.schema_version,
            .digest_sha256 = lock.digest_sha256,
        },
        .policy = .{
            .conffile = request.policy.conffile,
            .force = request.policy.risk.force,
            .allow_host_root = request.policy.risk.allow_host_root,
        },
        .actions = actions,
        .final_state = final_state.items,
        .trigger_authority = request.trigger_authority,
    });
    var authorization_transferred = false;
    defer if (!authorization_transferred) authorization.deinit();
    const execution_request: transaction_executor.Request = .{
        .plan = request.plan,
        .install_root = request.install_root,
        .artifacts = &.{},
        .policy = request.policy,
        .exact_lock_v2 = &lock,
    };
    try transaction_engine.authorize(.native, execution_request, &authorization.authorization);
    switch (native_program.compile(allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = request.plan.ordered_actions,
        .installed = request.installed,
        .archives = request.archives,
        .script_policy = request.script_policy,
        .ownership_conflicts = request.ownership_conflicts,
        .unsupported_features = request.unsupported_features,
        .limits = request.limits,
    })) {
        .diagnostic => |diagnostic| {
            if (diagnostic.code == .out_of_memory) return error.OutOfMemory;
            return .{ .diagnostic = try OwnedDiagnostic.copy(allocator, diagnostic) };
        },
        .program => |value| {
            var program = value;
            errdefer program.deinit();
            try transaction_engine.authorizeProgram(
                .native,
                execution_request,
                &authorization.authorization,
                &program.program,
                null,
            );
            authorization_transferred = true;
            return .{ .prepared = .{ .authorization = authorization, .program = program } };
        },
    }
}
