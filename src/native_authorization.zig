//! Native transaction authorization schema version 1.
//!
//! An authorization is the complete, canonically serialized contract that the
//! native transaction engine must hold before it mutates a root. It binds the
//! selected backend, the exact closure lock generation, the reviewed request
//! and policy digests, the compiled plan digest, the selected root and
//! architecture constraints, every ordered install/remove/purge/reinstall/
//! downgrade action with its authenticated artifact evidence, and the exact
//! intended final closure. The compiler that produces authorizations and the
//! mutation engine that consumes them are separate work; this module owns only
//! the contract, its canonical bytes, and its validation.
const std = @import("std");
const absolute_path = @import("absolute_path.zig");
const debian_version = @import("debian_version.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const package_origin = @import("package_origin.zig");
const solver = @import("solver.zig");
const transaction_engine = @import("transaction_engine.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_recovery = @import("transaction_recovery.zig");

pub const schema_id = "https://debz.dev/schema/native-transaction-authorization-v1";
pub const schema_version: u32 = 1;
pub const maximum_document_bytes: usize = 16 * 1024 * 1024;
pub const maximum_actions: usize = 100_000;
pub const maximum_final_packages: usize = 200_000;
pub const maximum_foreign_architectures: usize = 256;
pub const maximum_identity_bytes: usize = 256;
pub const maximum_root_bytes: usize = 4096;
pub const maximum_validation_items: usize = 400_000;

/// The authorization is bound to one backend. Only the native engine consumes
/// it; legacy documents can never be reinterpreted as native authorization.
pub const Backend = transaction_engine.Kind;

/// Exact closure lock generation authorized for this transaction. Only
/// exact-closure-lock v2 carries tagged authenticated origins, so older lock
/// versions remain readable for the legacy backend and are never authorized
/// here.
pub const LockBinding = struct {
    schema: []const u8,
    version: u32,
    digest_sha256: [32]u8,
};

/// Mutation policy that the engine must apply exactly as reviewed.
pub const PolicyBinding = struct {
    conffile: transaction_executor.ConffilePolicy,
    force: []const transaction_executor.ForceRisk = &.{},
    allow_host_root: bool = false,
};

/// Authenticated archive bound to one archive-producing action.
pub const Artifact = struct {
    sha256: [32]u8,
    size: u64,
    origin: exact_lock_v2.PackageOrigin,
};

/// One authorized package mutation. `sequence` is the dense canonical program
/// order the engine must follow.
pub const Action = struct {
    sequence: usize,
    kind: solver.ActionKind,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    /// Exact installed version replaced or removed by this action. Absent for
    /// `install`, required for every other kind.
    prior_version: ?[]const u8,
    /// Present exactly for archive-producing actions.
    artifact: ?Artifact,
};

/// Exact package state required after the transaction completes. Packages that
/// must not remain in the database are absent from the final closure.
pub const FinalState = enum { installed, config_files };

pub const FinalPackage = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    state: FinalState,
    dpkg_selection_hold: bool,
};

pub const Input = struct {
    backend: Backend,
    target_architecture: []const u8,
    foreign_architectures: []const []const u8 = &.{},
    install_root: []const u8,
    request_sha256: [32]u8,
    solver_policy_sha256: [32]u8,
    executor_policy_sha256: [32]u8,
    plan_sha256: [32]u8,
    exact_lock: LockBinding,
    policy: PolicyBinding,
    actions: []const Action,
    final_state: []const FinalPackage,
};

pub const Authorization = struct {
    backend: Backend,
    target_architecture: []const u8,
    foreign_architectures: []const []const u8,
    install_root: []const u8,
    root_identity_sha256: [32]u8,
    request_sha256: [32]u8,
    solver_policy_sha256: [32]u8,
    executor_policy_sha256: [32]u8,
    plan_sha256: [32]u8,
    exact_lock: LockBinding,
    policy: PolicyBinding,
    actions: []const Action,
    final_state: []const FinalPackage,
    final_state_sha256: [32]u8,
    digest_sha256: [32]u8,

    pub fn canonicalJson(self: Authorization, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeDocument(self, &output.writer);
        return output.toOwnedSlice();
    }

    /// Authorized actions are unique per package identity, so lookup answers
    /// what the engine may do to one installed identity.
    pub fn findAction(
        self: Authorization,
        name: []const u8,
        architecture: []const u8,
    ) ?Action {
        for (self.actions) |action| {
            if (std.mem.eql(u8, action.package, name) and
                std.mem.eql(u8, action.architecture, architecture))
                return action;
        }
        return null;
    }

    pub fn findFinalPackage(
        self: Authorization,
        name: []const u8,
        architecture: []const u8,
    ) ?FinalPackage {
        const index = findFinalIndex(self.final_state, name, architecture) orelse return null;
        return self.final_state[index];
    }

    pub fn architectureSelected(self: Authorization, architecture: []const u8) bool {
        if (std.mem.eql(u8, architecture, self.target_architecture)) return true;
        if (std.mem.eql(u8, architecture, "all")) return true;
        for (self.foreign_architectures) |foreign|
            if (std.mem.eql(u8, architecture, foreign)) return true;
        return false;
    }
};

pub const OwnedAuthorization = struct {
    authorization: Authorization,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedAuthorization) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const ValidationError = error{
    UnsupportedBackend,
    UnsupportedLockVersion,
    EmptyArchitecture,
    EmptyProgram,
    InvalidIdentity,
    InvalidVersion,
    InvalidRoot,
    HostRootNotAuthorized,
    ArchitectureNotSelected,
    DuplicateArchitecture,
    DuplicateForceRisk,
    NonCanonicalSequence,
    DuplicateAction,
    DuplicateArtifact,
    DuplicateFinalPackage,
    MissingArtifact,
    UnexpectedArtifact,
    MissingPriorVersion,
    UnexpectedPriorVersion,
    ContradictoryAction,
    ArtifactEvidenceMismatch,
    MissingFinalPackage,
    ContradictoryFinalState,
    TooManyActions,
    TooManyFinalPackages,
    TooManyArchitectures,
    RootTooLong,
    ValidationWorkLimitExceeded,
    UnsupportedSchema,
    NonCanonicalDocument,
    DigestMismatch,
    FinalStateDigestMismatch,
    DocumentTooLarge,
    InvalidDigest,
};

pub fn create(
    allocator: std.mem.Allocator,
    input: Input,
) (std.mem.Allocator.Error || ValidationError || package_origin.ValidationError)!OwnedAuthorization {
    switch (input.backend) {
        .native => {},
        .legacy_dpkg => return error.UnsupportedBackend,
    }
    if (!std.mem.eql(u8, input.exact_lock.schema, exact_lock_v2.schema_id) or
        input.exact_lock.version != exact_lock_v2.schema_version)
        return error.UnsupportedLockVersion;
    if (input.target_architecture.len == 0) return error.EmptyArchitecture;
    if (!validIdentity(input.target_architecture)) return error.InvalidIdentity;
    if (input.actions.len == 0) return error.EmptyProgram;
    if (input.actions.len > maximum_actions) return error.TooManyActions;
    if (input.final_state.len > maximum_final_packages) return error.TooManyFinalPackages;
    if (input.foreign_architectures.len > maximum_foreign_architectures)
        return error.TooManyArchitectures;
    const validation_items = std.math.add(
        usize,
        input.actions.len,
        input.final_state.len,
    ) catch return error.ValidationWorkLimitExceeded;
    if (validation_items > maximum_validation_items)
        return error.ValidationWorkLimitExceeded;
    if (input.install_root.len > maximum_root_bytes) return error.RootTooLong;
    if (!absolute_path.root(input.install_root)) return error.InvalidRoot;
    if (std.mem.eql(u8, input.install_root, "/") and !input.policy.allow_host_root)
        return error.HostRootNotAuthorized;

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const target_architecture = try owned.dupe(u8, input.target_architecture);
    const foreign_architectures = try owned.alloc(
        []const u8,
        input.foreign_architectures.len,
    );
    for (input.foreign_architectures, 0..) |architecture, index| {
        if (!validIdentity(architecture)) return error.InvalidIdentity;
        foreign_architectures[index] = try owned.dupe(u8, architecture);
    }
    std.mem.sort([]const u8, foreign_architectures, {}, lessString);
    for (foreign_architectures, 0..) |architecture, index| {
        if (std.mem.eql(u8, architecture, target_architecture) or
            std.mem.eql(u8, architecture, "all"))
            return error.DuplicateArchitecture;
        if (index != 0 and
            std.mem.eql(u8, architecture, foreign_architectures[index - 1]))
            return error.DuplicateArchitecture;
    }

    const force = try owned.dupe(transaction_executor.ForceRisk, input.policy.force);
    std.mem.sort(transaction_executor.ForceRisk, force, {}, lessForce);
    for (force, 0..) |risk, index|
        if (index != 0 and risk == force[index - 1]) return error.DuplicateForceRisk;

    const final_state = try owned.alloc(FinalPackage, input.final_state.len);
    for (input.final_state, 0..) |package, index| {
        if (!validIdentity(package.name) or !validIdentity(package.architecture))
            return error.InvalidIdentity;
        try validateVersion(package.version);
        final_state[index] = .{
            .name = try owned.dupe(u8, package.name),
            .version = try owned.dupe(u8, package.version),
            .architecture = try owned.dupe(u8, package.architecture),
            .state = package.state,
            .dpkg_selection_hold = package.dpkg_selection_hold,
        };
    }
    std.mem.sort(FinalPackage, final_state, {}, lessFinalPackage);
    for (final_state, 0..) |package, index| {
        if (index != 0 and sameIdentity(
            package.name,
            package.architecture,
            final_state[index - 1].name,
            final_state[index - 1].architecture,
        )) return error.DuplicateFinalPackage;
    }

    const actions = try owned.alloc(Action, input.actions.len);
    for (input.actions, 0..) |action, index| {
        if (!validIdentity(action.package) or !validIdentity(action.architecture))
            return error.InvalidIdentity;
        try validateVersion(action.version);
        actions[index] = .{
            .sequence = action.sequence,
            .kind = action.kind,
            .package = try owned.dupe(u8, action.package),
            .version = try owned.dupe(u8, action.version),
            .architecture = try owned.dupe(u8, action.architecture),
            .prior_version = null,
            .artifact = null,
        };
        if (action.prior_version) |prior| {
            try validateVersion(prior);
            actions[index].prior_version = try owned.dupe(u8, prior);
        }
        if (action.artifact) |artifact| {
            var copied = artifact;
            switch (artifact.origin) {
                .authenticated_repository => |origin| {
                    if (!validLowerHex(&origin.repository_id)) return error.InvalidIdentity;
                },
                .local_artifact => |origin| {
                    try package_origin.validateLocalArtifact(origin);
                    if (!std.mem.eql(u8, origin.package, action.package) or
                        !std.mem.eql(u8, origin.version, action.version) or
                        !std.mem.eql(u8, origin.architecture, action.architecture) or
                        !std.mem.eql(u8, &origin.sha256, &artifact.sha256) or
                        origin.size != artifact.size)
                        return error.ArtifactEvidenceMismatch;
                    copied.origin = .{
                        .local_artifact = try dupeLocalArtifact(owned, origin),
                    };
                },
            }
            actions[index].artifact = copied;
        }
    }
    std.mem.sort(Action, actions, {}, lessAction);
    for (actions, 0..) |action, index| {
        if (action.sequence != index) return error.NonCanonicalSequence;
        for (actions[0..index]) |prior| {
            if (sameIdentity(
                prior.package,
                prior.architecture,
                action.package,
                action.architecture,
            )) return error.DuplicateAction;
            if (prior.artifact != null and action.artifact != null and
                std.mem.eql(
                    u8,
                    &prior.artifact.?.sha256,
                    &action.artifact.?.sha256,
                )) return error.DuplicateArtifact;
        }
        try validateActionSemantics(action, target_architecture, foreign_architectures);
        try validateActionFinalState(action, final_state);
    }

    var authorization: Authorization = .{
        .backend = input.backend,
        .target_architecture = target_architecture,
        .foreign_architectures = foreign_architectures,
        .install_root = try owned.dupe(u8, input.install_root),
        .root_identity_sha256 = transaction_recovery.rootIdentity(input.install_root),
        .request_sha256 = input.request_sha256,
        .solver_policy_sha256 = input.solver_policy_sha256,
        .executor_policy_sha256 = input.executor_policy_sha256,
        .plan_sha256 = input.plan_sha256,
        .exact_lock = .{
            .schema = try owned.dupe(u8, input.exact_lock.schema),
            .version = input.exact_lock.version,
            .digest_sha256 = input.exact_lock.digest_sha256,
        },
        .policy = .{
            .conffile = input.policy.conffile,
            .force = force,
            .allow_host_root = input.policy.allow_host_root,
        },
        .actions = actions,
        .final_state = final_state,
        .final_state_sha256 = undefined,
        .digest_sha256 = undefined,
    };
    authorization.final_state_sha256 = digestFinalState(final_state);
    authorization.digest_sha256 = digestPayload(authorization);
    return .{
        .authorization = authorization,
        .arena = arena,
        .backing_allocator = allocator,
    };
}

/// Every action kind states exactly one intended transition. Missing,
/// contradictory, or unauthorized-architecture transitions fail closed.
fn validateActionSemantics(
    action: Action,
    target_architecture: []const u8,
    foreign_architectures: []const []const u8,
) ValidationError!void {
    if (!std.mem.eql(u8, action.architecture, target_architecture) and
        !std.mem.eql(u8, action.architecture, "all"))
    {
        var selected = false;
        for (foreign_architectures) |architecture| {
            if (std.mem.eql(u8, action.architecture, architecture)) {
                selected = true;
                break;
            }
        }
        if (!selected) return error.ArchitectureNotSelected;
    }
    switch (action.kind) {
        .install, .upgrade, .downgrade, .reinstall => {
            if (action.artifact == null) return error.MissingArtifact;
        },
        .remove, .purge => {
            if (action.artifact != null) return error.UnexpectedArtifact;
        },
    }
    switch (action.kind) {
        .install => if (action.prior_version != null) return error.UnexpectedPriorVersion,
        else => if (action.prior_version == null) return error.MissingPriorVersion,
    }
    const prior = action.prior_version orelse return;
    const order = try compareVersions(action.version, prior);
    switch (action.kind) {
        .install => unreachable,
        .upgrade => if (order != .gt) return error.ContradictoryAction,
        .downgrade => if (order != .lt) return error.ContradictoryAction,
        .reinstall => if (order != .eq) return error.ContradictoryAction,
        .remove, .purge => if (order != .eq) return error.ContradictoryAction,
    }
}

fn validateActionFinalState(
    action: Action,
    final_state: []const FinalPackage,
) ValidationError!void {
    const index = findFinalIndex(final_state, action.package, action.architecture);
    switch (action.kind) {
        .install, .upgrade, .downgrade, .reinstall => {
            const final = final_state[index orelse return error.MissingFinalPackage];
            if (final.state != .installed or
                !std.mem.eql(u8, final.version, action.version))
                return error.ContradictoryFinalState;
        },
        .remove => {
            const final = final_state[index orelse return error.MissingFinalPackage];
            if (final.state != .config_files or
                !std.mem.eql(u8, final.version, action.version))
                return error.ContradictoryFinalState;
        },
        .purge => if (index != null) return error.ContradictoryFinalState,
    }
}

const WireIdentity = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
};

const WireLocalArtifact = struct {
    artifact_id: []const u8,
    sha256: []const u8,
    size: u64,
    package: WireIdentity,
    acquisition_url: []const u8,
    trust_mode: package_origin.LocalArtifactTrustMode,
};

const OriginType = enum { authenticated_repository, local_artifact };

const WireOrigin = struct {
    type: OriginType,
    repository_id: ?[]const u8 = null,
    repository_snapshot_sha256: ?[]const u8 = null,
    artifact_id: ?[]const u8 = null,
    sha256: ?[]const u8 = null,
    size: ?u64 = null,
    package: ?WireIdentity = null,
    acquisition_url: ?[]const u8 = null,
    trust_mode: ?package_origin.LocalArtifactTrustMode = null,
};

const WireArtifact = struct {
    sha256: []const u8,
    size: u64,
    origin: WireOrigin,
};

const WireAction = struct {
    sequence: usize,
    kind: solver.ActionKind,
    package: WireIdentity,
    prior_version: ?[]const u8,
    artifact: ?WireArtifact,
};

const WireFinalPackage = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    state: FinalState,
    dpkg_selection_hold: bool,
};

const WireLockBinding = struct {
    schema: []const u8,
    version: u32,
    digest_sha256: []const u8,
};

const WirePolicy = struct {
    conffile: transaction_executor.ConffilePolicy,
    force: []const transaction_executor.ForceRisk,
    allow_host_root: bool,
};

const WireAuthorization = struct {
    schema: []const u8,
    version: u32,
    backend: Backend,
    target_architecture: []const u8,
    foreign_architectures: []const []const u8,
    install_root: []const u8,
    root_identity_sha256: []const u8,
    request_sha256: []const u8,
    solver_policy_sha256: []const u8,
    executor_policy_sha256: []const u8,
    plan_sha256: []const u8,
    exact_lock: WireLockBinding,
    policy: WirePolicy,
    actions: []const WireAction,
    final_state: []const WireFinalPackage,
    final_state_sha256: []const u8,
    digest_sha256: []const u8,
};

pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !OwnedAuthorization {
    if (source.len > maximum_bytes or source.len > maximum_document_bytes)
        return error.DocumentTooLarge;
    var parsed = try std.json.parseFromSlice(WireAuthorization, allocator, source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.schema, schema_id) or
        parsed.value.version != schema_version)
        return error.UnsupportedSchema;
    if (parsed.value.actions.len > maximum_actions) return error.TooManyActions;
    if (parsed.value.final_state.len > maximum_final_packages)
        return error.TooManyFinalPackages;
    if (parsed.value.foreign_architectures.len > maximum_foreign_architectures)
        return error.TooManyArchitectures;

    const actions = try allocator.alloc(Action, parsed.value.actions.len);
    defer allocator.free(actions);
    for (parsed.value.actions, 0..) |action, index| {
        actions[index] = .{
            .sequence = action.sequence,
            .kind = action.kind,
            .package = action.package.name,
            .version = action.package.version,
            .architecture = action.package.architecture,
            .prior_version = action.prior_version,
            .artifact = if (action.artifact) |artifact| .{
                .sha256 = try parseHex(32, artifact.sha256),
                .size = artifact.size,
                .origin = try parseOrigin(artifact.origin),
            } else null,
        };
    }

    const final_state = try allocator.alloc(FinalPackage, parsed.value.final_state.len);
    defer allocator.free(final_state);
    for (parsed.value.final_state, 0..) |package, index| {
        final_state[index] = .{
            .name = package.name,
            .version = package.version,
            .architecture = package.architecture,
            .state = package.state,
            .dpkg_selection_hold = package.dpkg_selection_hold,
        };
    }

    var result = try create(allocator, .{
        .backend = parsed.value.backend,
        .target_architecture = parsed.value.target_architecture,
        .foreign_architectures = parsed.value.foreign_architectures,
        .install_root = parsed.value.install_root,
        .request_sha256 = try parseHex(32, parsed.value.request_sha256),
        .solver_policy_sha256 = try parseHex(32, parsed.value.solver_policy_sha256),
        .executor_policy_sha256 = try parseHex(32, parsed.value.executor_policy_sha256),
        .plan_sha256 = try parseHex(32, parsed.value.plan_sha256),
        .exact_lock = .{
            .schema = parsed.value.exact_lock.schema,
            .version = parsed.value.exact_lock.version,
            .digest_sha256 = try parseHex(32, parsed.value.exact_lock.digest_sha256),
        },
        .policy = .{
            .conffile = parsed.value.policy.conffile,
            .force = parsed.value.policy.force,
            .allow_host_root = parsed.value.policy.allow_host_root,
        },
        .actions = actions,
        .final_state = final_state,
    });
    errdefer result.deinit();
    const root_identity = try parseHex(32, parsed.value.root_identity_sha256);
    if (!std.mem.eql(u8, &root_identity, &result.authorization.root_identity_sha256))
        return error.DigestMismatch;
    const final_digest = try parseHex(32, parsed.value.final_state_sha256);
    if (!std.mem.eql(u8, &final_digest, &result.authorization.final_state_sha256))
        return error.FinalStateDigestMismatch;
    const expected = try parseHex(32, parsed.value.digest_sha256);
    if (!std.mem.eql(u8, &expected, &result.authorization.digest_sha256))
        return error.DigestMismatch;
    const canonical = try result.authorization.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return result;
}

/// No-follow authorization publication bound to one directory entry.
pub const Store = struct {
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,

    pub fn init(io: std.Io, dir: std.Io.Dir, name: []const u8) !Store {
        if (!safeLeaf(name)) return error.AmbiguousPath;
        return .{ .io = io, .dir = dir, .name = name };
    }

    pub fn read(
        self: Store,
        allocator: std.mem.Allocator,
        maximum_bytes: usize,
    ) !OwnedAuthorization {
        if (maximum_bytes > maximum_document_bytes) return error.DocumentTooLarge;
        var file = try self.dir.openFile(self.io, self.name, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        const bytes = try reader.interface.allocRemaining(allocator, .limited(maximum_bytes));
        defer allocator.free(bytes);
        return decode(allocator, bytes, maximum_bytes);
    }

    pub fn writeAtomic(
        self: Store,
        allocator: std.mem.Allocator,
        authorization: Authorization,
    ) !void {
        const bytes = try authorization.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
        const stage = ".debz-native-authorization-v1.new";
        self.dir.deleteFile(self.io, stage) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        {
            var file = try self.dir.createFile(self.io, stage, .{
                .exclusive = true,
                .permissions = if (@import("builtin").os.tag == .windows)
                    .default_file
                else
                    .fromMode(0o600),
                .resolve_beneath = true,
            });
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, bytes);
            try file.sync(self.io);
        }
        try self.dir.rename(stage, self.dir, self.name, self.io);
        switch (@import("builtin").os.tag) {
            .linux => if (std.posix.errno(std.os.linux.fsync(self.dir.handle)) != .SUCCESS)
                return error.Unexpected,
            else => {},
        }
    }
};

fn parseOrigin(origin: WireOrigin) ValidationError!exact_lock_v2.PackageOrigin {
    return switch (origin.type) {
        .authenticated_repository => blk: {
            if (origin.repository_id == null or
                origin.repository_snapshot_sha256 == null or
                origin.artifact_id != null or
                origin.sha256 != null or
                origin.size != null or
                origin.package != null or
                origin.acquisition_url != null or
                origin.trust_mode != null)
                return error.InvalidIdentity;
            break :blk .{ .authenticated_repository = .{
                .repository_id = try parseId(origin.repository_id.?),
                .repository_snapshot_sha256 = try parseHex(
                    32,
                    origin.repository_snapshot_sha256.?,
                ),
            } };
        },
        .local_artifact => blk: {
            if (origin.repository_id != null or
                origin.repository_snapshot_sha256 != null or
                origin.artifact_id == null or
                origin.sha256 == null or
                origin.size == null or
                origin.package == null or
                origin.acquisition_url == null or
                origin.trust_mode == null)
                return error.InvalidIdentity;
            const identity = origin.package.?;
            break :blk .{ .local_artifact = .{
                .artifact_id = try parseId(origin.artifact_id.?),
                .sha256 = try parseHex(32, origin.sha256.?),
                .size = origin.size.?,
                .package = identity.name,
                .version = identity.version,
                .architecture = identity.architecture,
                .acquisition_url = origin.acquisition_url.?,
                .trust_mode = origin.trust_mode.?,
            } };
        },
    };
}

fn dupeLocalArtifact(
    allocator: std.mem.Allocator,
    artifact: package_origin.LocalArtifactEvidence,
) !package_origin.LocalArtifactEvidence {
    var result = artifact;
    result.package = try allocator.dupe(u8, artifact.package);
    result.version = try allocator.dupe(u8, artifact.version);
    result.architecture = try allocator.dupe(u8, artifact.architecture);
    result.acquisition_url = try allocator.dupe(u8, artifact.acquisition_url);
    return result;
}

fn digestPayload(authorization: Authorization) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writePayload(authorization, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn digestFinalState(final_state: []const FinalPackage) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-native-authorization-final-state-v1\x00") catch unreachable;
    writeFinalState(final_state, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn writeDocument(authorization: Authorization, writer: *std.Io.Writer) !void {
    try writePayload(authorization, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHexString(writer, &authorization.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(authorization: Authorization, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeJsonString(writer, schema_id);
    try writer.print(",\"version\":{},\"backend\":", .{schema_version});
    try writeJsonString(writer, @tagName(authorization.backend));
    try writer.writeAll(",\"target_architecture\":");
    try writeJsonString(writer, authorization.target_architecture);
    try writer.writeAll(",\"foreign_architectures\":[");
    for (authorization.foreign_architectures, 0..) |architecture, index| {
        if (index != 0) try writer.writeByte(',');
        try writeJsonString(writer, architecture);
    }
    try writer.writeAll("],\"install_root\":");
    try writeJsonString(writer, authorization.install_root);
    try writer.writeAll(",\"root_identity_sha256\":");
    try writeHexString(writer, &authorization.root_identity_sha256);
    try writer.writeAll(",\"request_sha256\":");
    try writeHexString(writer, &authorization.request_sha256);
    try writer.writeAll(",\"solver_policy_sha256\":");
    try writeHexString(writer, &authorization.solver_policy_sha256);
    try writer.writeAll(",\"executor_policy_sha256\":");
    try writeHexString(writer, &authorization.executor_policy_sha256);
    try writer.writeAll(",\"plan_sha256\":");
    try writeHexString(writer, &authorization.plan_sha256);
    try writer.writeAll(",\"exact_lock\":{\"schema\":");
    try writeJsonString(writer, authorization.exact_lock.schema);
    try writer.print(",\"version\":{},\"digest_sha256\":", .{authorization.exact_lock.version});
    try writeHexString(writer, &authorization.exact_lock.digest_sha256);
    try writer.writeAll("},\"policy\":{\"conffile\":");
    try writeJsonString(writer, @tagName(authorization.policy.conffile));
    try writer.writeAll(",\"force\":[");
    for (authorization.policy.force, 0..) |risk, index| {
        if (index != 0) try writer.writeByte(',');
        try writeJsonString(writer, @tagName(risk));
    }
    try writer.print("],\"allow_host_root\":{}}}", .{authorization.policy.allow_host_root});
    try writer.writeAll(",\"actions\":[");
    for (authorization.actions, 0..) |action, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{{\"sequence\":{},\"kind\":", .{action.sequence});
        try writeJsonString(writer, @tagName(action.kind));
        try writer.writeAll(",\"package\":");
        try writeIdentity(
            writer,
            action.package,
            action.version,
            action.architecture,
        );
        try writer.writeAll(",\"prior_version\":");
        if (action.prior_version) |prior|
            try writeJsonString(writer, prior)
        else
            try writer.writeAll("null");
        try writer.writeAll(",\"artifact\":");
        if (action.artifact) |artifact| {
            try writer.writeAll("{\"sha256\":");
            try writeHexString(writer, &artifact.sha256);
            try writer.print(",\"size\":{},\"origin\":", .{artifact.size});
            try writeOrigin(writer, artifact.origin);
            try writer.writeByte('}');
        } else try writer.writeAll("null");
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"final_state\":");
    try writeFinalState(authorization.final_state, writer);
    try writer.writeAll(",\"final_state_sha256\":");
    try writeHexString(writer, &authorization.final_state_sha256);
    try writer.writeByte('}');
}

fn writeFinalState(final_state: []const FinalPackage, writer: *std.Io.Writer) !void {
    try writer.writeByte('[');
    for (final_state, 0..) |package, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":");
        try writeJsonString(writer, package.name);
        try writer.writeAll(",\"version\":");
        try writeJsonString(writer, package.version);
        try writer.writeAll(",\"architecture\":");
        try writeJsonString(writer, package.architecture);
        try writer.writeAll(",\"state\":");
        try writeJsonString(writer, @tagName(package.state));
        try writer.print(
            ",\"dpkg_selection_hold\":{}}}",
            .{package.dpkg_selection_hold},
        );
    }
    try writer.writeByte(']');
}

fn writeOrigin(writer: *std.Io.Writer, origin: exact_lock_v2.PackageOrigin) !void {
    switch (origin) {
        .authenticated_repository => |repository| {
            try writer.writeAll("{\"type\":\"authenticated_repository\",\"repository_id\":");
            try writeJsonString(writer, &repository.repository_id);
            try writer.writeAll(",\"repository_snapshot_sha256\":");
            try writeHexString(writer, &repository.repository_snapshot_sha256);
            try writer.writeByte('}');
        },
        .local_artifact => |artifact| {
            try writer.writeAll("{\"type\":\"local_artifact\",\"artifact_id\":");
            try writeJsonString(writer, &artifact.artifact_id);
            try writer.writeAll(",\"sha256\":");
            try writeHexString(writer, &artifact.sha256);
            try writer.print(",\"size\":{},\"package\":", .{artifact.size});
            try writeIdentity(
                writer,
                artifact.package,
                artifact.version,
                artifact.architecture,
            );
            try writer.writeAll(",\"acquisition_url\":");
            try writeJsonString(writer, artifact.acquisition_url);
            try writer.writeAll(",\"trust_mode\":");
            try writeJsonString(writer, @tagName(artifact.trust_mode));
            try writer.writeByte('}');
        },
    }
}

fn writeIdentity(
    writer: *std.Io.Writer,
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
) !void {
    try writer.writeAll("{\"name\":");
    try writeJsonString(writer, name);
    try writer.writeAll(",\"version\":");
    try writeJsonString(writer, version);
    try writer.writeAll(",\"architecture\":");
    try writeJsonString(writer, architecture);
    try writer.writeByte('}');
}

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...8, 11, 12, 14...31 => try writer.print("\\u00{x:0>2}", .{byte}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

fn writeHexString(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
    try writer.writeByte('"');
}

fn parseHex(comptime size: usize, value: []const u8) ValidationError![size]u8 {
    if (value.len != size * 2) return error.InvalidDigest;
    var result: [size]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidDigest;
    return result;
}

fn parseId(value: []const u8) ValidationError![64]u8 {
    if (value.len != 64 or !validLowerHex(value)) return error.InvalidIdentity;
    var result: [64]u8 = undefined;
    @memcpy(&result, value);
    return result;
}

fn validLowerHex(value: []const u8) bool {
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return false;
    }
    return true;
}

fn validIdentity(value: []const u8) bool {
    if (value.len == 0 or value.len > maximum_identity_bytes) return false;
    for (value) |byte| if (byte <= 0x1f or byte == 0x7f) return false;
    return true;
}

fn validateVersion(value: []const u8) ValidationError!void {
    if (!validIdentity(value)) return error.InvalidIdentity;
    _ = debian_version.DebianVersion.parse(value) catch return error.InvalidVersion;
}

fn compareVersions(left: []const u8, right: []const u8) ValidationError!std.math.Order {
    const parsed_left = debian_version.DebianVersion.parse(left) catch
        return error.InvalidVersion;
    const parsed_right = debian_version.DebianVersion.parse(right) catch
        return error.InvalidVersion;
    return parsed_left.order(parsed_right);
}

fn findFinalIndex(
    final_state: []const FinalPackage,
    name: []const u8,
    architecture: []const u8,
) ?usize {
    var low: usize = 0;
    var high = final_state.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const package = final_state[middle];
        const name_order = std.mem.order(u8, package.name, name);
        const order = if (name_order == .eq)
            std.mem.order(u8, package.architecture, architecture)
        else
            name_order;
        switch (order) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return middle,
        }
    }
    return null;
}

fn sameIdentity(
    left_name: []const u8,
    left_architecture: []const u8,
    right_name: []const u8,
    right_architecture: []const u8,
) bool {
    return std.mem.eql(u8, left_name, right_name) and
        std.mem.eql(u8, left_architecture, right_architecture);
}

fn lessAction(_: void, left: Action, right: Action) bool {
    return left.sequence < right.sequence;
}

fn lessFinalPackage(_: void, left: FinalPackage, right: FinalPackage) bool {
    const name = std.mem.order(u8, left.name, right.name);
    if (name != .eq) return name == .lt;
    return std.mem.order(u8, left.architecture, right.architecture) == .lt;
}

fn lessString(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn lessForce(
    _: void,
    left: transaction_executor.ForceRisk,
    right: transaction_executor.ForceRisk,
) bool {
    return @intFromEnum(left) < @intFromEnum(right);
}

fn safeLeaf(name: []const u8) bool {
    return name.len != 0 and
        !std.mem.eql(u8, name, ".") and
        !std.mem.eql(u8, name, "..") and
        std.mem.indexOfScalar(u8, name, '/') == null and
        std.mem.indexOfScalar(u8, name, '\\') == null;
}

fn testLockBinding() LockBinding {
    return .{
        .schema = exact_lock_v2.schema_id,
        .version = exact_lock_v2.schema_version,
        .digest_sha256 = @splat(0x11),
    };
}

fn testRepositoryArtifact(digest: u8, size: u64) Artifact {
    return .{
        .sha256 = @splat(digest),
        .size = size,
        .origin = .{ .authenticated_repository = .{
            .repository_id = @splat('a'),
            .repository_snapshot_sha256 = @splat(0x22),
        } },
    };
}

fn testLocalArtifact(
    digest: u8,
    size: u64,
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
) Artifact {
    const sha256: [32]u8 = @splat(digest);
    return .{
        .sha256 = sha256,
        .size = size,
        .origin = .{ .local_artifact = .{
            .artifact_id = package_origin.artifactIdFromSha256(sha256),
            .sha256 = sha256,
            .size = size,
            .package = name,
            .version = version,
            .architecture = architecture,
            .acquisition_url = "file:///vendor.deb",
            .trust_mode = .pinned_sha256,
        } },
    };
}

const test_actions = [_]Action{
    .{
        .sequence = 0,
        .kind = .purge,
        .package = "obsolete",
        .version = "0.9",
        .architecture = "amd64",
        .prior_version = "0.9",
        .artifact = null,
    },
    .{
        .sequence = 1,
        .kind = .remove,
        .package = "legacy",
        .version = "2.0",
        .architecture = "amd64",
        .prior_version = "2.0",
        .artifact = null,
    },
    .{
        .sequence = 2,
        .kind = .install,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
        .prior_version = null,
        .artifact = testRepositoryArtifact(0x31, 100),
    },
    .{
        .sequence = 3,
        .kind = .upgrade,
        .package = "lib",
        .version = "2.0",
        .architecture = "amd64",
        .prior_version = "1.0",
        .artifact = testRepositoryArtifact(0x32, 200),
    },
    .{
        .sequence = 4,
        .kind = .downgrade,
        .package = "tool",
        .version = "1.0",
        .architecture = "i386",
        .prior_version = "2.0",
        .artifact = testRepositoryArtifact(0x33, 300),
    },
    .{
        .sequence = 5,
        .kind = .reinstall,
        .package = "vendor",
        .version = "3.0",
        .architecture = "all",
        .prior_version = "3.0",
        .artifact = testLocalArtifact(0x34, 400, "vendor", "3.0", "all"),
    },
};

const test_final_state = [_]FinalPackage{
    .{
        .name = "app",
        .version = "1.2",
        .architecture = "amd64",
        .state = .installed,
        .dpkg_selection_hold = false,
    },
    .{
        .name = "base",
        .version = "1.0",
        .architecture = "amd64",
        .state = .installed,
        .dpkg_selection_hold = true,
    },
    .{
        .name = "legacy",
        .version = "2.0",
        .architecture = "amd64",
        .state = .config_files,
        .dpkg_selection_hold = false,
    },
    .{
        .name = "lib",
        .version = "2.0",
        .architecture = "amd64",
        .state = .installed,
        .dpkg_selection_hold = false,
    },
    .{
        .name = "tool",
        .version = "1.0",
        .architecture = "i386",
        .state = .installed,
        .dpkg_selection_hold = false,
    },
    .{
        .name = "vendor",
        .version = "3.0",
        .architecture = "all",
        .state = .installed,
        .dpkg_selection_hold = false,
    },
};

fn testInput() Input {
    return .{
        .backend = .native,
        .target_architecture = "amd64",
        .foreign_architectures = &.{"i386"},
        .install_root = "/srv/root",
        .request_sha256 = @splat(1),
        .solver_policy_sha256 = @splat(2),
        .executor_policy_sha256 = @splat(3),
        .plan_sha256 = @splat(4),
        .exact_lock = testLockBinding(),
        .policy = .{
            .conffile = .keep_existing,
            .force = &.{ .overwrite, .depends },
            .allow_host_root = false,
        },
        .actions = &test_actions,
        .final_state = &test_final_state,
    };
}

test "native_authorization.test.canonical document binds program artifacts and final closure" {
    var owned = try create(std.testing.allocator, testInput());
    defer owned.deinit();
    const authorization = owned.authorization;
    try std.testing.expectEqual(Backend.native, authorization.backend);
    try std.testing.expectEqualSlices(
        u8,
        &transaction_recovery.rootIdentity("/srv/root"),
        &authorization.root_identity_sha256,
    );
    try std.testing.expectEqual(
        @as(usize, test_actions.len),
        authorization.actions.len,
    );
    for (authorization.actions, 0..) |action, index|
        try std.testing.expectEqual(index, action.sequence);
    try std.testing.expectEqual(
        transaction_executor.ForceRisk.depends,
        authorization.policy.force[0],
    );
    try std.testing.expect(authorization.architectureSelected("i386"));
    try std.testing.expect(authorization.architectureSelected("all"));
    try std.testing.expect(!authorization.architectureSelected("arm64"));
    try std.testing.expectEqual(
        FinalState.config_files,
        authorization.findFinalPackage("legacy", "amd64").?.state,
    );
    try std.testing.expect(authorization.findFinalPackage("obsolete", "amd64") == null);
    try std.testing.expectEqual(
        solver.ActionKind.purge,
        authorization.findAction("obsolete", "amd64").?.kind,
    );

    const document = try authorization.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(document);
    try std.testing.expect(std.mem.indexOf(u8, document, "\"backend\":\"native\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, document, "\"kind\":\"purge\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, document, "\"type\":\"local_artifact\"") != null);

    var decoded = try decode(std.testing.allocator, document, maximum_document_bytes);
    defer decoded.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &authorization.digest_sha256,
        &decoded.authorization.digest_sha256,
    );
    try std.testing.expectEqualSlices(
        u8,
        &authorization.final_state_sha256,
        &decoded.authorization.final_state_sha256,
    );

    var second = try create(std.testing.allocator, testInput());
    defer second.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &authorization.digest_sha256,
        &second.authorization.digest_sha256,
    );

    try std.testing.expectError(
        error.DocumentTooLarge,
        decode(std.testing.allocator, document, document.len - 1),
    );

    const unknown_field = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s},\"unknown\":1}}",
        .{document[0 .. document.len - 1]},
    );
    defer std.testing.allocator.free(unknown_field);
    try std.testing.expectError(
        error.UnknownField,
        decode(std.testing.allocator, unknown_field, maximum_document_bytes),
    );

    const noncanonical = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{ {s}",
        .{document[1..]},
    );
    defer std.testing.allocator.free(noncanonical);
    try std.testing.expectError(
        error.NonCanonicalDocument,
        decode(std.testing.allocator, noncanonical, maximum_document_bytes),
    );

    {
        var tampered = try std.testing.allocator.dupe(u8, document);
        defer std.testing.allocator.free(tampered);
        const root = std.mem.indexOf(u8, tampered, "/srv/root").?;
        tampered[root + 1] = 'x';
        try std.testing.expectError(
            error.DigestMismatch,
            decode(std.testing.allocator, tampered, maximum_document_bytes),
        );
    }
    {
        var tampered = try std.testing.allocator.dupe(u8, document);
        defer std.testing.allocator.free(tampered);
        const digest = std.mem.indexOf(u8, tampered, "\"digest_sha256\":\"").? +
            "\"digest_sha256\":\"".len;
        tampered[digest] = if (tampered[digest] == 'a') 'b' else 'a';
        try std.testing.expectError(
            error.DigestMismatch,
            decode(std.testing.allocator, tampered, maximum_document_bytes),
        );
    }
    {
        var tampered = try std.testing.allocator.dupe(u8, document);
        defer std.testing.allocator.free(tampered);
        const final_digest = std.mem.indexOf(u8, tampered, "\"final_state_sha256\":\"").? +
            "\"final_state_sha256\":\"".len;
        tampered[final_digest] = if (tampered[final_digest] == 'a') 'b' else 'a';
        try std.testing.expectError(
            error.FinalStateDigestMismatch,
            decode(std.testing.allocator, tampered, maximum_document_bytes),
        );
    }
    {
        var tampered = try std.testing.allocator.dupe(u8, document);
        defer std.testing.allocator.free(tampered);
        const identity = std.mem.indexOf(u8, tampered, "\"root_identity_sha256\":\"").? +
            "\"root_identity_sha256\":\"".len;
        tampered[identity] = if (tampered[identity] == 'a') 'b' else 'a';
        try std.testing.expectError(
            error.DigestMismatch,
            decode(std.testing.allocator, tampered, maximum_document_bytes),
        );
    }
}

test "native_authorization.test.rejects contradictory duplicate and unauthorized programs" {
    const Case = struct {
        name: []const u8,
        expected: anyerror,
        mutate: *const fn (*Input, *[test_actions.len]Action, *[test_final_state.len]FinalPackage) void,
    };
    const cases = [_]Case{
        .{
            .name = "legacy backend is never natively authorized",
            .expected = error.UnsupportedBackend,
            .mutate = struct {
                fn apply(input: *Input, _: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    input.backend = .legacy_dpkg;
                }
            }.apply,
        },
        .{
            .name = "exact lock v1 is never natively authorized",
            .expected = error.UnsupportedLockVersion,
            .mutate = struct {
                fn apply(input: *Input, _: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    input.exact_lock.schema = "https://debz.dev/schema/exact-closure-lock-v1";
                    input.exact_lock.version = 1;
                }
            }.apply,
        },
        .{
            .name = "lock version drift",
            .expected = error.UnsupportedLockVersion,
            .mutate = struct {
                fn apply(input: *Input, _: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    input.exact_lock.version = 3;
                }
            }.apply,
        },
        .{
            .name = "empty program",
            .expected = error.EmptyProgram,
            .mutate = struct {
                fn apply(input: *Input, _: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    input.actions = &.{};
                }
            }.apply,
        },
        .{
            .name = "non-dense sequence",
            .expected = error.NonCanonicalSequence,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[3].sequence = 9;
                }
            }.apply,
        },
        .{
            .name = "duplicate package action",
            .expected = error.DuplicateAction,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[3].package = actions[2].package;
                    actions[3].version = actions[2].version;
                    actions[3].kind = .install;
                    actions[3].prior_version = null;
                }
            }.apply,
        },
        .{
            .name = "duplicate artifact digest",
            .expected = error.DuplicateArtifact,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[3].artifact.?.sha256 = actions[2].artifact.?.sha256;
                }
            }.apply,
        },
        .{
            .name = "install without artifact",
            .expected = error.MissingArtifact,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[2].artifact = null;
                }
            }.apply,
        },
        .{
            .name = "purge with artifact",
            .expected = error.UnexpectedArtifact,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[0].artifact = testRepositoryArtifact(0x41, 1);
                }
            }.apply,
        },
        .{
            .name = "install with prior version",
            .expected = error.UnexpectedPriorVersion,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[2].prior_version = "1.0";
                }
            }.apply,
        },
        .{
            .name = "remove without prior version",
            .expected = error.MissingPriorVersion,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[1].prior_version = null;
                }
            }.apply,
        },
        .{
            .name = "upgrade to an older version",
            .expected = error.ContradictoryAction,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[3].prior_version = "3.0";
                }
            }.apply,
        },
        .{
            .name = "downgrade to a newer version",
            .expected = error.ContradictoryAction,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[4].prior_version = "0.5";
                }
            }.apply,
        },
        .{
            .name = "reinstall across versions",
            .expected = error.ContradictoryAction,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[5].prior_version = "2.0";
                }
            }.apply,
        },
        .{
            .name = "remove across versions",
            .expected = error.ContradictoryAction,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[1].prior_version = "1.0";
                }
            }.apply,
        },
        .{
            .name = "unselected architecture",
            .expected = error.ArchitectureNotSelected,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, final_state: *[test_final_state.len]FinalPackage) void {
                    actions[4].architecture = "arm64";
                    final_state[4].architecture = "arm64";
                }
            }.apply,
        },
        .{
            .name = "duplicate foreign architecture",
            .expected = error.DuplicateArchitecture,
            .mutate = struct {
                fn apply(input: *Input, _: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    input.foreign_architectures = &.{ "i386", "i386" };
                }
            }.apply,
        },
        .{
            .name = "target architecture repeated as foreign",
            .expected = error.DuplicateArchitecture,
            .mutate = struct {
                fn apply(input: *Input, _: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    input.foreign_architectures = &.{ "amd64", "i386" };
                }
            }.apply,
        },
        .{
            .name = "duplicate force risk",
            .expected = error.DuplicateForceRisk,
            .mutate = struct {
                fn apply(input: *Input, _: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    input.policy.force = &.{ .depends, .depends };
                }
            }.apply,
        },
        .{
            .name = "host root without policy",
            .expected = error.HostRootNotAuthorized,
            .mutate = struct {
                fn apply(input: *Input, _: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    input.install_root = "/";
                }
            }.apply,
        },
        .{
            .name = "traversing root",
            .expected = error.InvalidRoot,
            .mutate = struct {
                fn apply(input: *Input, _: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    input.install_root = "/srv/../root";
                }
            }.apply,
        },
        .{
            .name = "invalid version spelling",
            .expected = error.InvalidVersion,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, final_state: *[test_final_state.len]FinalPackage) void {
                    actions[2].version = "not a version";
                    final_state[0].version = "not a version";
                }
            }.apply,
        },
        .{
            .name = "artifact evidence substitution",
            .expected = error.ArtifactEvidenceMismatch,
            .mutate = struct {
                fn apply(_: *Input, actions: *[test_actions.len]Action, _: *[test_final_state.len]FinalPackage) void {
                    actions[5].artifact.?.size += 1;
                }
            }.apply,
        },
        .{
            .name = "missing final package",
            .expected = error.MissingFinalPackage,
            .mutate = struct {
                fn apply(input: *Input, _: *[test_actions.len]Action, final_state: *[test_final_state.len]FinalPackage) void {
                    input.final_state = final_state[1..];
                }
            }.apply,
        },
        .{
            .name = "installed state after remove",
            .expected = error.ContradictoryFinalState,
            .mutate = struct {
                fn apply(_: *Input, _: *[test_actions.len]Action, final_state: *[test_final_state.len]FinalPackage) void {
                    final_state[2].state = .installed;
                }
            }.apply,
        },
        .{
            .name = "final version drift",
            .expected = error.ContradictoryFinalState,
            .mutate = struct {
                fn apply(_: *Input, _: *[test_actions.len]Action, final_state: *[test_final_state.len]FinalPackage) void {
                    final_state[3].version = "9.0";
                }
            }.apply,
        },
        .{
            .name = "purged package retained in final state",
            .expected = error.ContradictoryFinalState,
            .mutate = struct {
                fn apply(_: *Input, _: *[test_actions.len]Action, final_state: *[test_final_state.len]FinalPackage) void {
                    final_state[1].name = "obsolete";
                    final_state[1].version = "0.9";
                }
            }.apply,
        },
        .{
            .name = "duplicate final package",
            .expected = error.DuplicateFinalPackage,
            .mutate = struct {
                fn apply(_: *Input, _: *[test_actions.len]Action, final_state: *[test_final_state.len]FinalPackage) void {
                    final_state[1].name = "app";
                    final_state[1].version = "1.2";
                }
            }.apply,
        },
    };

    for (cases) |case| {
        var actions = test_actions;
        var final_state = test_final_state;
        var input = testInput();
        input.actions = &actions;
        input.final_state = &final_state;
        case.mutate(&input, &actions, &final_state);
        try std.testing.expectError(case.expected, create(std.testing.allocator, input));
    }
}

test "native_authorization.test.schema and enums stay synchronized with the contract" {
    const source = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "schema/native-transaction-authorization-v1.json",
        std.testing.allocator,
        .limited(maximum_document_bytes),
    );
    defer std.testing.allocator.free(source);
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        source,
        .{},
    );
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings(schema_id, root.get("$id").?.string);
    try std.testing.expectEqualStrings(
        schema_id,
        root.get("properties").?.object.get("schema").?.object.get("const").?.string,
    );
    try std.testing.expectEqual(
        @as(i64, schema_version),
        root.get("properties").?.object.get("version").?.object.get("const").?.integer,
    );
    try std.testing.expectEqualStrings(
        @tagName(Backend.native),
        root.get("properties").?.object.get("backend").?.object.get("const").?.string,
    );
    const definitions = root.get("$defs").?.object;
    try std.testing.expectEqualStrings(
        absolute_path.schema_pattern,
        definitions.get("absolutePath").?.object.get("pattern").?.string,
    );
    const lock_binding = definitions.get("lockBinding").?.object.get("properties").?.object;
    try std.testing.expectEqualStrings(
        exact_lock_v2.schema_id,
        lock_binding.get("schema").?.object.get("const").?.string,
    );
    try std.testing.expectEqual(
        @as(i64, exact_lock_v2.schema_version),
        lock_binding.get("version").?.object.get("const").?.integer,
    );

    var owned = try create(std.testing.allocator, testInput());
    defer owned.deinit();
    const document = try owned.authorization.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(document);
    var serialized = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        document,
        .{},
    );
    defer serialized.deinit();
    const required = root.get("required").?.array.items;
    const properties = root.get("properties").?.object;
    try std.testing.expectEqual(required.len, properties.count());
    try std.testing.expectEqual(required.len, serialized.value.object.count());
    for (required) |name| {
        try std.testing.expect(properties.contains(name.string));
        try std.testing.expect(serialized.value.object.contains(name.string));
    }

    try expectEnumMatchesSchema(
        solver.ActionKind,
        definitions.get("action").?.object
            .get("properties").?.object
            .get("kind").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        FinalState,
        definitions.get("finalPackage").?.object
            .get("properties").?.object
            .get("state").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        transaction_executor.ConffilePolicy,
        definitions.get("policy").?.object
            .get("properties").?.object
            .get("conffile").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        transaction_executor.ForceRisk,
        definitions.get("policy").?.object
            .get("properties").?.object
            .get("force").?.object
            .get("items").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        package_origin.LocalArtifactTrustMode,
        definitions.get("localOrigin").?.object
            .get("properties").?.object
            .get("trust_mode").?.object
            .get("enum").?.array.items,
    );
}

fn expectEnumMatchesSchema(comptime Enum: type, values: []const std.json.Value) !void {
    try std.testing.expectEqual(std.meta.fields(Enum).len, values.len);
    inline for (std.meta.fields(Enum)) |field| {
        var matches: usize = 0;
        for (values) |value| {
            if (value == .string and std.mem.eql(u8, field.name, value.string))
                matches += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), matches);
    }
}

test "native_authorization.test.origin encoding matches exact closure lock v2" {
    const digest: [32]u8 = @splat(0x34);
    const evidence: package_origin.LocalArtifactEvidence = .{
        .artifact_id = package_origin.artifactIdFromSha256(digest),
        .sha256 = digest,
        .size = 400,
        .package = "vendor",
        .version = "3.0",
        .architecture = "all",
        .acquisition_url = "file:///vendor.deb",
        .trust_mode = .pinned_sha256,
    };
    var lock = try exact_lock_v2.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .policy_sha256 = @splat(2),
        .repositories = &.{},
        .local_artifacts = &.{evidence},
        .packages = &.{.{
            .name = evidence.package,
            .version = evidence.version,
            .architecture = evidence.architecture,
            .origin = .{ .local_artifact = evidence },
            .sha256 = evidence.sha256,
            .declared_size = evidence.size,
            .retention = .requested,
            .dpkg_selection_hold = false,
        }},
        .verified_origins = true,
    });
    defer lock.deinit();
    const lock_document = try lock.lock.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(lock_document);

    var owned = try create(std.testing.allocator, testInput());
    defer owned.deinit();
    const document = try owned.authorization.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(document);

    const marker = "{\"type\":\"local_artifact\",";
    const lock_start = std.mem.indexOf(u8, lock_document, marker).?;
    const lock_end = std.mem.indexOfScalarPos(u8, lock_document, lock_start, '}').? + 1;
    const authorization_start = std.mem.indexOf(u8, document, marker).?;
    const authorization_end =
        std.mem.indexOfScalarPos(u8, document, authorization_start, '}').? + 1;
    try std.testing.expectEqualStrings(
        lock_document[lock_start..lock_end],
        document[authorization_start..authorization_end],
    );
}

test "native_authorization.test.store publishes and rereads canonical bytes" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const store = try Store.init(std.testing.io, directory.dir, "authorization.json");
    try std.testing.expectError(
        error.AmbiguousPath,
        Store.init(std.testing.io, directory.dir, "nested/authorization.json"),
    );

    var owned = try create(std.testing.allocator, testInput());
    defer owned.deinit();
    try store.writeAtomic(std.testing.allocator, owned.authorization);
    var reread = try store.read(std.testing.allocator, maximum_document_bytes);
    defer reread.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &owned.authorization.digest_sha256,
        &reread.authorization.digest_sha256,
    );
    try std.testing.expectEqual(
        @as(usize, test_actions.len),
        reread.authorization.actions.len,
    );
}
