const std = @import("std");
const dpkg_status = @import("dpkg_status.zig");
const packages_index = @import("packages_index.zig");
const relation = @import("relation.zig");
const repository_refresh = @import("repository_refresh.zig");
const source = @import("source.zig");
const exact_lock_module = @import("exact_lock.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const package_origin = @import("package_origin.zig");

const libsolv = @cImport({
    @cDefine("LIBSOLV_INTERNAL", "1");
    @cInclude("solv/evr.h");
    @cInclude("solv/pool.h");
    @cInclude("solv/poolarch.h");
    @cInclude("solv/problems.h");
    @cInclude("solv/queue.h");
    @cInclude("solv/repo.h");
    @cInclude("solv/rules.h");
    @cInclude("solv/solver.h");
    @cInclude("solv/solvable.h");
    @cInclude("solv/transaction.h");
});

pub const InstallReason = enum {
    manual,
    automatic,
};

pub const HoldAuthority = enum {
    status_want,
    explicit_policy,
};

pub const InstalledPolicy = struct {
    name: []const u8,
    architecture: []const u8,
    install_reason: InstallReason,
    held: ?bool = null,
};

pub const ImportInput = struct {
    records: []const dpkg_status.Package,
    native_architecture: []const u8,
    foreign_architectures: []const []const u8 = &.{},
    policies: []const InstalledPolicy,
    hold_authority: HoldAuthority = .status_want,
};

pub const BlockerKind = enum {
    repair_required,
    incomplete_install,
    requested_but_absent,
    pending_removal,
};

pub const Blocker = struct {
    record_index: usize,
    kind: BlockerKind,
};

pub const InstalledMetadata = struct {
    essential: ?bool,
    protected: ?bool,
    held: bool,
    install_reason: InstallReason,
};

pub const ImportSummary = struct {
    installed: usize,
    blockers: usize,
    config_files_only: usize,
    absent: usize,
};

pub const DiagnosticCode = enum {
    already_imported,
    invalid_native_architecture,
    invalid_foreign_architecture,
    duplicate_allowed_architecture,
    duplicate_identity,
    incompatible_architecture,
    malformed_state,
    duplicate_policy,
    missing_policy,
    policy_for_non_installed,
    missing_explicit_hold,
    unexpected_explicit_hold,
};

pub const Diagnostic = struct {
    code: DiagnosticCode,
    record_index: ?usize = null,
    policy_index: ?usize = null,
};

pub const ImportResult = union(enum) {
    imported: ImportSummary,
    diagnostic: Diagnostic,
};

pub const Eligibility = enum {
    untrusted,
    verified_refresh,
    verified_local_artifact,
    trusted_test,
};

pub const Limits = struct {
    max_repositories: usize = 1_024,
    max_packages_per_repository: usize = 250_000,
    max_dependency_groups_per_package: usize = 16_384,
    max_dependency_alternatives_per_package: usize = 65_536,
};

pub const RepositoryInput = struct {
    repository_id: source.RepositoryId,
    priority: i32,
    eligibility: Eligibility,
    packages: *const packages_index.Index,
    authenticated_snapshot_sha256: ?[32]u8 = null,
    local_artifact: ?package_origin.LocalArtifactEvidence = null,

    pub fn fromRefresh(
        result: *const repository_refresh.AuthenticatedResult,
        priority: i32,
    ) RepositoryInput {
        return .{
            .repository_id = result.snapshot.provenance.repository_id,
            .priority = priority,
            .eligibility = .verified_refresh,
            .packages = &result.snapshot.packages,
            .authenticated_snapshot_sha256 = repository_refresh.snapshotDigest(result),
        };
    }

    pub fn trustedTest(
        repository_id: source.RepositoryId,
        priority: i32,
        packages: *const packages_index.Index,
    ) RepositoryInput {
        return .{
            .repository_id = repository_id,
            .priority = priority,
            .eligibility = .trusted_test,
            .packages = packages,
        };
    }

    pub fn fromLocalArtifact(
        packages: *const packages_index.Index,
        priority: i32,
        evidence: package_origin.LocalArtifactEvidence,
    ) RepositoryInput {
        return .{
            .repository_id = packages.context.repository_id,
            .priority = priority,
            .eligibility = .verified_local_artifact,
            .packages = packages,
            .local_artifact = evidence,
        };
    }
};

pub const AuthenticatedRepositoryPackageOrigin = struct {
    repository_id: source.RepositoryId,
    repository_priority: i32,
    record_index: usize,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    source_location: []const u8,
};

pub const LocalArtifactPackageOrigin = struct {
    evidence: package_origin.LocalArtifactEvidence,
    solver_priority: i32,
    record_index: usize,
    source_location: []const u8,
};

pub const PackageOrigin = union(enum) {
    authenticated_repository: AuthenticatedRepositoryPackageOrigin,
    local_artifact: LocalArtifactPackageOrigin,
};

pub const AvailableImportError = std.mem.Allocator.Error || error{
    PoolAllocationFailed,
    UntrustedRepository,
    RepositoryIdentityMismatch,
    InvalidLocalArtifact,
    DuplicateRepository,
    TooManyRepositories,
    TooManyPackages,
    TooManyDependencyGroups,
    TooManyDependencyAlternatives,
    UnsupportedArchitectureQualifier,
    UnsupportedProvidesAlternative,
    UnsupportedProvidesPredicate,
};

const Mapping = struct {
    solvable_id: libsolv.Id,
    record_index: usize,
    metadata: InstalledMetadata,
};

const OriginOwned = struct {
    repository_id: source.RepositoryId,
    repository_priority: i32,
    record_index: usize,
    package: []u8,
    version: []u8,
    architecture: []u8,
    source_location: []u8,
    local_artifact: ?package_origin.LocalArtifactEvidence,
    solvable_id: libsolv.Id,

    fn init(
        allocator: std.mem.Allocator,
        input: RepositoryInput,
        record: packages_index.PackageRecord,
        record_index: usize,
        solvable_id: libsolv.Id,
    ) !OriginOwned {
        const package_name = try allocator.dupe(u8, record.control.package.text);
        errdefer allocator.free(package_name);
        const version = try allocator.dupe(u8, record.control.version.value.original);
        errdefer allocator.free(version);
        const architecture = try allocator.dupe(u8, record.control.architecture.text);
        errdefer allocator.free(architecture);
        const source_location = try allocator.dupe(
            u8,
            if (input.local_artifact) |artifact|
                artifact.acquisition_url
            else
                record.location.source,
        );
        errdefer allocator.free(source_location);
        var local_artifact = input.local_artifact;
        if (local_artifact) |*artifact| {
            artifact.package = package_name;
            artifact.version = version;
            artifact.architecture = architecture;
            artifact.acquisition_url = try allocator.dupe(u8, artifact.acquisition_url);
        }
        return .{
            .repository_id = input.repository_id,
            .repository_priority = input.priority,
            .record_index = record_index,
            .package = package_name,
            .version = version,
            .architecture = architecture,
            .source_location = source_location,
            .local_artifact = local_artifact,
            .solvable_id = solvable_id,
        };
    }

    fn deinit(self: *OriginOwned, allocator: std.mem.Allocator) void {
        allocator.free(self.package);
        allocator.free(self.version);
        allocator.free(self.architecture);
        allocator.free(self.source_location);
        if (self.local_artifact) |artifact| allocator.free(artifact.acquisition_url);
        self.* = undefined;
    }

    fn public(self: *const OriginOwned) PackageOrigin {
        if (self.local_artifact) |artifact| return .{ .local_artifact = .{
            .evidence = artifact,
            .solver_priority = self.repository_priority,
            .record_index = self.record_index,
            .source_location = self.source_location,
        } };
        return .{ .authenticated_repository = .{
            .repository_id = self.repository_id,
            .repository_priority = self.repository_priority,
            .record_index = self.record_index,
            .package = self.package,
            .version = self.version,
            .architecture = self.architecture,
            .source_location = self.source_location,
        } };
    }
};

const Internal = struct {
    allocator: std.mem.Allocator,
    pool: *libsolv.Pool,
    solver: *libsolv.Solver,
    installed_repo: ?*libsolv.Repo = null,
    source_records: []const dpkg_status.Package = &.{},
    mappings: []Mapping = &.{},
    blockers: []Blocker = &.{},
    summary: ?ImportSummary = null,
    available_repositories: std.ArrayList(source.RepositoryId) = .empty,
    origins: std.ArrayList(OriginOwned) = .empty,
    target_architecture: []u8 = &.{},

    fn deinit(self: *Internal) void {
        if (self.mappings.len != 0) self.allocator.free(self.mappings);
        if (self.blockers.len != 0) self.allocator.free(self.blockers);
        for (self.origins.items) |*origin| origin.deinit(self.allocator);
        self.origins.deinit(self.allocator);
        self.available_repositories.deinit(self.allocator);
        if (self.target_architecture.len != 0) self.allocator.free(self.target_architecture);
        libsolv.solver_free(self.solver);
        libsolv.pool_free(self.pool);
        const allocator = self.allocator;
        allocator.destroy(self);
    }
};

pub const Context = opaque {
    pub fn create() *Context {
        return createWithAllocator(std.heap.c_allocator) catch unreachable;
    }

    pub fn createWithAllocator(allocator: std.mem.Allocator) std.mem.Allocator.Error!*Context {
        const pool = libsolv.pool_create() orelse return error.OutOfMemory;
        errdefer libsolv.pool_free(pool);
        const solver = libsolv.solver_create(pool) orelse return error.OutOfMemory;
        errdefer libsolv.solver_free(solver);
        const state = try allocator.create(Internal);
        state.* = .{
            .allocator = allocator,
            .pool = pool,
            .solver = solver,
        };
        return @ptrCast(state);
    }

    pub fn createForArchitecture(
        allocator: std.mem.Allocator,
        architecture: []const u8,
    ) std.mem.Allocator.Error!*Context {
        const context = try createWithAllocator(allocator);
        errdefer context.destroy();
        const architecture_z = try allocator.dupeZ(u8, architecture);
        defer allocator.free(architecture_z);
        libsolv.pool_setarch(internal(context).pool, architecture_z);
        internal(context).target_architecture = try allocator.dupe(u8, architecture);
        return context;
    }

    pub fn destroy(self: *Context) void {
        internal(self).deinit();
    }

    /// Imports caller-owned parsed records. The records must outlive this context.
    pub fn importInstalled(
        self: *Context,
        input: ImportInput,
    ) std.mem.Allocator.Error!ImportResult {
        const state = internal(self);
        if (state.summary != null) return .{ .diagnostic = .{ .code = .already_imported } };

        if (!validArchitecture(input.native_architecture) or
            std.mem.eql(u8, input.native_architecture, "all"))
        {
            return .{ .diagnostic = .{ .code = .invalid_native_architecture } };
        }
        for (input.foreign_architectures, 0..) |architecture, index| {
            if (!validArchitecture(architecture) or std.mem.eql(u8, architecture, "all")) {
                return .{ .diagnostic = .{
                    .code = .invalid_foreign_architecture,
                    .policy_index = index,
                } };
            }
            if (std.mem.eql(u8, architecture, input.native_architecture)) {
                return .{ .diagnostic = .{
                    .code = .duplicate_allowed_architecture,
                    .policy_index = index,
                } };
            }
            for (input.foreign_architectures[0..index]) |previous| {
                if (std.mem.eql(u8, architecture, previous)) {
                    return .{ .diagnostic = .{
                        .code = .duplicate_allowed_architecture,
                        .policy_index = index,
                    } };
                }
            }
        }

        for (input.records, 0..) |record, index| {
            for (input.records[0..index]) |previous| {
                if (sameIdentity(record.name.value, record.architecture.value, previous.name.value, previous.architecture.value)) {
                    return .{ .diagnostic = .{ .code = .duplicate_identity, .record_index = index } };
                }
            }
            if (!architectureAllowed(record.architecture.value, input)) {
                return .{ .diagnostic = .{ .code = .incompatible_architecture, .record_index = index } };
            }
            if (classify(record.status) == .malformed) {
                return .{ .diagnostic = .{ .code = .malformed_state, .record_index = index } };
            }
        }

        for (input.policies, 0..) |policy, index| {
            for (input.policies[0..index]) |previous| {
                if (sameIdentity(policy.name, policy.architecture, previous.name, previous.architecture)) {
                    return .{ .diagnostic = .{ .code = .duplicate_policy, .policy_index = index } };
                }
            }
            if (input.hold_authority == .explicit_policy and policy.held == null) {
                return .{ .diagnostic = .{ .code = .missing_explicit_hold, .policy_index = index } };
            }
            if (input.hold_authority == .status_want and policy.held != null) {
                return .{ .diagnostic = .{ .code = .unexpected_explicit_hold, .policy_index = index } };
            }
            const record_index = findRecord(input.records, policy.name, policy.architecture) orelse
                return .{ .diagnostic = .{ .code = .policy_for_non_installed, .policy_index = index } };
            if (classify(input.records[record_index].status) != .installed) {
                return .{ .diagnostic = .{ .code = .policy_for_non_installed, .policy_index = index } };
            }
        }

        var installed_count: usize = 0;
        var blocker_count: usize = 0;
        var config_count: usize = 0;
        var absent_count: usize = 0;
        for (input.records, 0..) |record, index| {
            switch (classify(record.status)) {
                .installed => {
                    installed_count += 1;
                    if (findPolicy(input.policies, record.name.value, record.architecture.value) == null) {
                        return .{ .diagnostic = .{ .code = .missing_policy, .record_index = index } };
                    }
                },
                .blocker => blocker_count += 1,
                .config_files => config_count += 1,
                .absent => absent_count += 1,
                .malformed => unreachable,
            }
        }

        const mappings = try state.allocator.alloc(Mapping, installed_count);
        errdefer state.allocator.free(mappings);
        const blockers = try state.allocator.alloc(Blocker, blocker_count);
        errdefer state.allocator.free(blockers);

        var architecture_policy: std.ArrayList(u8) = .empty;
        defer architecture_policy.deinit(state.allocator);
        try architecture_policy.appendSlice(state.allocator, input.native_architecture);
        for (input.foreign_architectures) |architecture| {
            try architecture_policy.append(state.allocator, ':');
            try architecture_policy.appendSlice(state.allocator, architecture);
        }
        try architecture_policy.append(state.allocator, 0);
        libsolv.pool_setarchpolicy(state.pool, architecture_policy.items.ptr);

        const repo = libsolv.repo_create(state.pool, "installed") orelse return error.OutOfMemory;
        errdefer libsolv.repo_free(repo, 1);

        var mapping_index: usize = 0;
        var blocker_index: usize = 0;
        for (input.records, 0..) |record, record_index| {
            switch (classify(record.status)) {
                .installed => {
                    const policy = findPolicy(input.policies, record.name.value, record.architecture.value).?;
                    const solvable_id = libsolv.repo_add_solvable(repo);
                    const solvable = &state.pool.*.solvables[@intCast(solvable_id)];
                    solvable.*.name = stringId(state.pool, record.name.value);
                    solvable.*.arch = stringId(state.pool, record.architecture.value);
                    solvable.*.evr = stringId(state.pool, record.version.spelling.value);
                    solvable.*.provides = libsolv.repo_addid_dep(
                        repo,
                        solvable.*.provides,
                        libsolv.pool_rel2id(state.pool, solvable.*.name, solvable.*.evr, libsolv.REL_EQ, 1),
                        0,
                    );
                    addRelations(state.pool, repo, solvable, record, input.native_architecture);
                    setMultiArch(repo, solvable_id, record.multi_arch);
                    addQualifiedSelfProvide(state.pool, repo, solvable, record.name.value, record.architecture.value);
                    if (std.mem.eql(u8, record.architecture.value, "all"))
                        addQualifiedSelfProvide(state.pool, repo, solvable, record.name.value, input.native_architecture);
                    mappings[mapping_index] = .{
                        .solvable_id = solvable_id,
                        .record_index = record_index,
                        .metadata = .{
                            .essential = record.essential,
                            .protected = record.protected,
                            .held = switch (input.hold_authority) {
                                .status_want => record.status.want == .hold,
                                .explicit_policy => policy.held.?,
                            },
                            .install_reason = policy.install_reason,
                        },
                    };
                    mapping_index += 1;
                },
                .blocker => {
                    blockers[blocker_index] = .{
                        .record_index = record_index,
                        .kind = blockerKind(record.status),
                    };
                    blocker_index += 1;
                },
                .config_files, .absent => {},
                .malformed => unreachable,
            }
        }

        libsolv.pool_set_installed(state.pool, repo);
        libsolv.pool_createwhatprovides(state.pool);

        const summary: ImportSummary = .{
            .installed = installed_count,
            .blockers = blocker_count,
            .config_files_only = config_count,
            .absent = absent_count,
        };
        state.installed_repo = repo;
        state.source_records = input.records;
        state.mappings = mappings;
        state.blockers = blockers;
        state.summary = summary;
        return .{ .imported = summary };
    }

    pub fn importAvailable(
        self: *Context,
        input: RepositoryInput,
        limits: Limits,
    ) AvailableImportError!void {
        const state = internal(self);
        if (input.eligibility == .untrusted) return error.UntrustedRepository;
        if (!std.mem.eql(
            u8,
            input.repository_id.slice(),
            input.packages.context.repository_id.slice(),
        )) return error.RepositoryIdentityMismatch;
        switch (input.eligibility) {
            .verified_refresh => {
                if (input.authenticated_snapshot_sha256 == null or input.local_artifact != null)
                    return error.RepositoryIdentityMismatch;
            },
            .verified_local_artifact => {
                const artifact = input.local_artifact orelse return error.InvalidLocalArtifact;
                package_origin.validateLocalArtifact(artifact) catch
                    return error.InvalidLocalArtifact;
                if (!std.mem.eql(u8, input.repository_id.slice(), &artifact.artifact_id) or
                    input.authenticated_snapshot_sha256 != null or
                    input.packages.records.len != 1)
                    return error.InvalidLocalArtifact;
                const record = input.packages.records[0];
                if (!std.mem.eql(u8, record.control.package.text, artifact.package) or
                    !std.mem.eql(u8, record.control.version.value.original, artifact.version) or
                    !std.mem.eql(u8, record.control.architecture.text, artifact.architecture) or
                    !std.mem.eql(u8, &record.transport.sha256.bytes, &artifact.sha256) or
                    record.transport.size.value != artifact.size)
                    return error.InvalidLocalArtifact;
            },
            .trusted_test => if (input.local_artifact != null)
                return error.InvalidLocalArtifact,
            .untrusted => unreachable,
        }
        if (state.available_repositories.items.len >= limits.max_repositories)
            return error.TooManyRepositories;
        if (input.packages.records.len > limits.max_packages_per_repository)
            return error.TooManyPackages;
        for (state.available_repositories.items) |repository_id| {
            if (std.mem.eql(u8, repository_id.slice(), input.repository_id.slice()))
                return error.DuplicateRepository;
        }
        try validateAvailableRecords(input.packages.records, limits);

        const repository_name = try state.allocator.dupeZ(u8, input.repository_id.slice());
        defer state.allocator.free(repository_name);
        const repo = libsolv.repo_create(state.pool, repository_name) orelse
            return error.PoolAllocationFailed;
        var keep_repo = false;
        errdefer if (!keep_repo) libsolv.repo_free(repo, 1);
        repo.*.priority = input.priority;
        repo.*.subpriority = input.priority;

        const origins_start = state.origins.items.len;
        errdefer {
            for (state.origins.items[origins_start..]) |*origin|
                origin.deinit(state.allocator);
            state.origins.shrinkRetainingCapacity(origins_start);
        }

        const record_order = try state.allocator.alloc(usize, input.packages.records.len);
        defer state.allocator.free(record_order);
        for (record_order, 0..) |*slot, index| slot.* = index;
        std.mem.sort(usize, record_order, input.packages.records, lessAvailableRecordIndex);
        for (record_order) |record_index| {
            const record = input.packages.records[record_index];
            const solvable_id = libsolv.repo_add_solvable(repo);
            if (solvable_id == 0) return error.PoolAllocationFailed;
            const solvable = libsolv.pool_id2solvable(state.pool, solvable_id);
            const control = record.control;
            solvable.*.name = stringId(state.pool, control.package.text);
            solvable.*.evr = stringId(state.pool, control.version.value.original);
            solvable.*.arch = stringId(state.pool, control.architecture.text);
            setMultiArch(repo, solvable_id, control.multi_arch);

            addAvailableRelation(state.pool, solvable, control.pre_depends, .requires_pre, state.target_architecture);
            addAvailableRelation(state.pool, solvable, control.depends, .requires, state.target_architecture);
            addAvailableRelation(state.pool, solvable, control.recommends, .recommends, state.target_architecture);
            addAvailableRelation(state.pool, solvable, control.provides, .provides, state.target_architecture);
            addAvailableRelation(state.pool, solvable, control.conflicts, .conflicts, state.target_architecture);
            addAvailableRelation(state.pool, solvable, control.breaks, .conflicts, state.target_architecture);
            addDebianObsoletes(
                state.pool,
                solvable,
                if (control.replaces) |value| value.value else null,
                if (control.conflicts) |value| value.value else null,
                state.target_architecture,
            );

            const self_provide = libsolv.pool_rel2id(
                state.pool,
                solvable.*.name,
                solvable.*.evr,
                libsolv.REL_EQ,
                1,
            );
            libsolv.solvable_add_deparray(solvable, libsolv.SOLVABLE_PROVIDES, self_provide, 0);
            addQualifiedSelfProvide(state.pool, repo, solvable, control.package.text, control.architecture.text);
            if (std.mem.eql(u8, control.architecture.text, "all"))
                addQualifiedSelfProvide(state.pool, repo, solvable, control.package.text, state.target_architecture);

            var origin = try OriginOwned.init(
                state.allocator,
                input,
                record,
                record_index,
                solvable_id,
            );
            errdefer origin.deinit(state.allocator);
            try state.origins.append(state.allocator, origin);
        }

        libsolv.repo_internalize(repo);
        try state.available_repositories.append(state.allocator, input.repository_id);
        keep_repo = true;
        libsolv.pool_createwhatprovides(state.pool);
    }

    pub fn originCount(self: *const Context) usize {
        return internalConst(self).origins.items.len;
    }

    pub fn originAt(self: *const Context, index: usize) ?PackageOrigin {
        const origins = internalConst(self).origins.items;
        if (index >= origins.len) return null;
        return origins[index].public();
    }

    pub fn installedCount(self: *const Context) usize {
        return internalConst(self).mappings.len;
    }

    pub fn installedRecord(self: *const Context, index: usize) *const dpkg_status.Package {
        const state = internalConst(self);
        return &state.source_records[state.mappings[index].record_index];
    }

    pub fn installedMetadata(self: *const Context, index: usize) InstalledMetadata {
        return internalConst(self).mappings[index].metadata;
    }

    pub fn blockerCount(self: *const Context) usize {
        return internalConst(self).blockers.len;
    }

    pub fn blocker(self: *const Context, index: usize) Blocker {
        return internalConst(self).blockers[index];
    }

    pub fn compareInstalledVersion(
        self: *Context,
        index: usize,
        candidate: []const u8,
    ) std.math.Order {
        const state = internal(self);
        const solvable = &state.pool.*.solvables[@intCast(state.mappings[index].solvable_id)];
        const result = libsolv.pool_evrcmp(
            state.pool,
            solvable.*.evr,
            stringId(state.pool, candidate),
            libsolv.EVRCMP_COMPARE,
        );
        return std.math.order(result, 0);
    }
};

fn lessAvailableRecordIndex(
    records: []const packages_index.PackageRecord,
    a: usize,
    b: usize,
) bool {
    const a_record = records[a];
    const b_record = records[b];
    const name_order = std.mem.order(u8, a_record.control.package.text, b_record.control.package.text);
    if (name_order != .eq) return name_order == .lt;
    const arch_order = std.mem.order(u8, a_record.control.architecture.text, b_record.control.architecture.text);
    if (arch_order != .eq) return arch_order == .lt;
    const version_order = std.mem.order(
        u8,
        a_record.control.version.value.original,
        b_record.control.version.value.original,
    );
    if (version_order != .eq) return version_order == .lt;
    return std.mem.order(u8, a_record.location.source, b_record.location.source) == .lt;
}

fn lessInstalledRecord(_: void, left: dpkg_status.Package, right: dpkg_status.Package) bool {
    const name_order = std.mem.order(u8, left.name.value, right.name.value);
    if (name_order != .eq) return name_order == .lt;
    const architecture_order = std.mem.order(u8, left.architecture.value, right.architecture.value);
    if (architecture_order != .eq) return architecture_order == .lt;
    return std.mem.order(u8, left.version.spelling.value, right.version.spelling.value) == .lt;
}

/// Transaction planning is pure: it does not download package archives and
/// never invokes dpkg or any other package executor.
pub const PlanRequest = union(enum) {
    install: PackageSelector,
    remove: PackageSelector,
    upgrade: []const PackageSelector,
    upgrade_all,
    reinstall: PackageSelector,
};

pub const PackageSelector = struct {
    name: []const u8,
    version: ?[]const u8 = null,
    architecture: ?[]const u8 = null,
};

pub const OperationMode = enum { plan_only, download_only };

pub const PhasedUpdatePolicy = union(enum) {
    disabled,
    include_all,
    deterministic_percentage: u8,
};

pub const PhasedCandidate = struct {
    name: []const u8,
    architecture: []const u8,
    version: []const u8,
    percentage: u8,
};

pub const SolvePolicy = struct {
    recommends: bool = false,
    allow_downgrade: bool = false,
    allow_remove_dependencies: bool = false,
    allow_remove_essential: bool = false,
    allow_remove_protected: bool = false,
    allow_change_held: bool = false,
    allow_replacements: bool = false,
    strict_repository_priority: bool = true,
    phased_updates: PhasedUpdatePolicy = .disabled,
};

pub const PlanLimits = struct {
    import: Limits = .{},
    max_actions: usize = 100_000,
    max_problems: usize = 1_000,
};

pub const ProtectedIdentity = struct {
    name: []const u8,
    architecture: []const u8,
};

pub const PlanInput = struct {
    repositories: []const RepositoryInput,
    installed: ImportInput,
    /// Explicit policy in addition to dpkg's parsed Essential/Protected fields.
    protected: []const ProtectedIdentity = &.{},
    /// Complete explicit set of unrequested removals a caller authorizes.
    authorized_removals: []const ProtectedIdentity = &.{},
    /// Identities retained side-by-side across upgrades (for example kernels).
    install_only: []const ProtectedIdentity = &.{},
    phased_candidates: []const PhasedCandidate = &.{},
    target_architecture: []const u8,
    mode: OperationMode = .plan_only,
    request: PlanRequest,
    policy: SolvePolicy = .{},
    limits: PlanLimits = .{},
    /// Exact final closure constraint. This is independent from dpkg selection
    /// holds carried by `installed.policies`.
    exact_lock: ?*const exact_lock_module.Lock = null,
    exact_lock_v2: ?*const exact_lock_v2.Lock = null,
};

pub const ActionKind = enum { install, remove, upgrade, downgrade, reinstall };
pub const ActionReason = enum {
    explicit_request,
    dependency,
    recommends,
    replacement,
    upgrade,
};

pub const OrderedActionKind = enum { bootstrap_extract, remove, unpack, configure_pending };

pub const OrderedAction = struct {
    sequence: usize,
    kind: OrderedActionKind,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
};

pub const PlanSummary = struct {
    installs: usize = 0,
    removals: usize = 0,
    upgrades: usize = 0,
    downgrades: usize = 0,
    reinstalls: usize = 0,
    download_bytes: u64 = 0,
    installed_size_delta_bytes: i128 = 0,
};

pub const RepositoryIdentity = struct {
    id: [64]u8,
    priority: i32,
};

pub const PlanLocalArtifactOrigin = struct {
    evidence: package_origin.LocalArtifactEvidence,
    solver_priority: i32,
};

pub const PlanOrigin = union(enum) {
    authenticated_repository: RepositoryIdentity,
    local_artifact: PlanLocalArtifactOrigin,
};

pub const PriorInstalled = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    installed_size_kib: ?u64,
};

pub const PlanAction = struct {
    kind: ActionKind,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    repository: ?RepositoryIdentity,
    sha256: ?[64]u8,
    package_size: ?u64,
    installed_size_delta_bytes: i128,
    source_package: []const u8,
    prior_installed: ?PriorInstalled,
    requested: bool,
    reason: ActionReason,
    essential: bool = false,
    has_pre_depends: bool = false,
    /// Present for archive-producing actions. Repository selections are
    /// consumed by package acquisition; local selections retain their
    /// separately verified artifact evidence.
    selected_origin: ?PackageOrigin,
    /// Tagged production identity. Schema v2 continues serializing
    /// `repository`; schema v3 serializes this field as `origin`.
    origin: ?PlanOrigin = null,
};

pub const Plan = struct {
    schema_version: u32 = 2,
    target_architecture: []const u8,
    mode: OperationMode,
    actions: []PlanAction,
    ordered_actions: []OrderedAction,
    summary: PlanSummary,
    download_bytes: u64,
    installed_size_delta_bytes: i128,
    backing_allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *Plan) void {
        const backing = self.backing_allocator;
        self.arena.deinit();
        backing.destroy(self.arena);
        self.* = undefined;
    }

    pub fn canonicalJson(self: Plan, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writePlanJson(self, &output.writer);
        return output.toOwnedSlice();
    }
};

pub const ProblemKind = enum {
    unhealthy_installed_state,
    unauthenticated_repository,
    duplicate_repository,
    unsatisfied_dependency,
    conflict,
    protected_violation,
    held_violation,
    essential_violation,
    no_candidate,
    architecture_mismatch,
    version_mismatch,
    unsupported_feature,
    invalid_policy,
    reverse_dependency,
    policy_exclusion,
    phased_update_excluded,
    replacement_violation,
    limit_exceeded,
    lock_repository_missing,
    lock_repository_mismatch,
    lock_package_missing,
    lock_package_mismatch,
    lock_closure_drift,
    invalid_local_artifact,
    invalid_solver_state,
};

pub const CandidateRejectionReason = enum {
    wrong_architecture,
    wrong_version,
    repository_priority,
    held,
    protected,
    essential,
    downgrade_forbidden,
    replacement_forbidden,
    phased_update,
    unsatisfied_relation,
    conflict,
};

pub const CandidateRejection = struct {
    package: []const u8,
    version: ?[]const u8 = null,
    architecture: ?[]const u8 = null,
    reason: CandidateRejectionReason,
    detail: []const u8,
};

pub const ProblemNode = struct {
    id: usize = 0,
    kind: ProblemKind,
    package: ?[]const u8 = null,
    dependency: ?[]const u8 = null,
    detail: []const u8,
    candidate_rejections: []const CandidateRejection = &.{},
    related_problem_ids: []const usize = &.{},
};

pub const PlanFailure = struct {
    schema_version: u32 = 2,
    problems: []ProblemNode,
    backing_allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *PlanFailure) void {
        const backing = self.backing_allocator;
        self.arena.deinit();
        backing.destroy(self.arena);
        self.* = undefined;
    }

    pub fn canonicalJson(self: PlanFailure, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeFailureJson(self, &output.writer);
        return output.toOwnedSlice();
    }
};

pub const PlanningResult = union(enum) {
    plan: Plan,
    failure: PlanFailure,
};

pub const PlanningError = std.mem.Allocator.Error || error{PoolAllocationFailed};

/// Builds an owned deterministic transaction plan. All returned strings and
/// records are detached from libsolv and from the caller's parsed inputs.
pub fn planTransaction(
    allocator: std.mem.Allocator,
    input: PlanInput,
) PlanningError!PlanningResult {
    var arena_ptr = try allocator.create(std.heap.ArenaAllocator);
    arena_ptr.* = .init(allocator);
    errdefer {
        arena_ptr.deinit();
        allocator.destroy(arena_ptr);
    }
    const owned = arena_ptr.allocator();

    if (!std.mem.eql(u8, input.target_architecture, input.installed.native_architecture)) {
        return failureOne(allocator, arena_ptr, .architecture_mismatch, null, null, "target architecture differs from installed-state native architecture");
    }
    if (validatePlanPolicy(input)) |detail| {
        return failureOne(allocator, arena_ptr, .invalid_policy, null, null, detail);
    }
    if (input.installed.hold_authority != .explicit_policy) {
        return failureOne(allocator, arena_ptr, .unsupported_feature, null, null, "planning requires explicit hold policy");
    }
    if (input.exact_lock != null and input.exact_lock_v2 != null) {
        return failureOne(allocator, arena_ptr, .invalid_policy, null, null, "only one exact lock version may be supplied");
    }
    if (input.exact_lock) |lock| {
        if (!std.mem.eql(u8, lock.target_architecture, input.target_architecture))
            return failureOne(allocator, arena_ptr, .architecture_mismatch, null, null, "exact lock target architecture differs from planning architecture");
        if (try validateExactLockInput(allocator, arena_ptr, input.repositories, lock)) |failure|
            return .{ .failure = failure };
    }
    if (input.exact_lock_v2) |lock| {
        if (!std.mem.eql(u8, lock.target_architecture, input.target_architecture))
            return failureOne(allocator, arena_ptr, .architecture_mismatch, null, null, "exact lock target architecture differs from planning architecture");
        if (try validateExactLockV2Input(allocator, arena_ptr, input.repositories, lock)) |failure|
            return .{ .failure = failure };
    }
    for (input.repositories) |repository| {
        if (repository.eligibility == .untrusted) {
            return failureOne(allocator, arena_ptr, .unauthenticated_repository, null, null, "repository snapshot is not authenticated");
        }
    }
    for (input.repositories, 0..) |repository, index| {
        for (input.repositories[0..index]) |previous| {
            if (std.mem.eql(u8, repository.repository_id.slice(), previous.repository_id.slice())) {
                return failureOne(allocator, arena_ptr, .duplicate_repository, null, null, "repository identity is repeated");
            }
        }
    }

    const context = try Context.createForArchitecture(allocator, input.target_architecture);
    defer context.destroy();
    const installed_records = try allocator.dupe(dpkg_status.Package, input.installed.records);
    defer allocator.free(installed_records);
    std.mem.sort(dpkg_status.Package, installed_records, {}, lessInstalledRecord);
    var installed_input = input.installed;
    installed_input.records = installed_records;
    const imported = try context.importInstalled(installed_input);
    switch (imported) {
        .diagnostic => |diagnostic| {
            const detail = try std.fmt.allocPrint(owned, "installed state rejected: {s}", .{@tagName(diagnostic.code)});
            return failureOneOwned(allocator, arena_ptr, .unhealthy_installed_state, null, null, detail);
        },
        .imported => |summary| if (summary.blockers != 0) {
            return failureOne(allocator, arena_ptr, .unhealthy_installed_state, null, null, "installed state contains incomplete or repair-required packages");
        },
    }

    const repository_order = try allocator.alloc(usize, input.repositories.len);
    defer allocator.free(repository_order);
    for (repository_order, 0..) |*slot, index| slot.* = index;
    std.mem.sort(usize, repository_order, input.repositories, lessRepositoryIndex);
    for (repository_order) |repository_index| {
        const repository = input.repositories[repository_index];
        context.importAvailable(repository, input.limits.import) catch |err| {
            const kind: ProblemKind = switch (err) {
                error.UntrustedRepository => .unauthenticated_repository,
                error.DuplicateRepository => .duplicate_repository,
                error.UnsupportedArchitectureQualifier,
                error.UnsupportedProvidesAlternative,
                error.UnsupportedProvidesPredicate,
                error.RepositoryIdentityMismatch,
                => .unsupported_feature,
                error.InvalidLocalArtifact => .invalid_local_artifact,
                error.TooManyRepositories,
                error.TooManyPackages,
                error.TooManyDependencyGroups,
                error.TooManyDependencyAlternatives,
                => .limit_exceeded,
                error.PoolAllocationFailed => return error.PoolAllocationFailed,
                error.OutOfMemory => return error.OutOfMemory,
            };
            const detail = try std.fmt.allocPrint(owned, "repository import failed: {s}", .{@errorName(err)});
            return failureOneOwned(allocator, arena_ptr, kind, null, null, detail);
        };
    }

    const state = internal(context);
    try recreateSolver(state);
    configureSolver(state.solver, input.policy);
    var jobs: libsolv.Queue = undefined;
    libsolv.queue_init(&jobs);
    defer libsolv.queue_free(&jobs);

    if (try preflightRequest(allocator, arena_ptr, context, input, &jobs)) |failure|
        return .{ .failure = failure };
    if (input.exact_lock) |lock| {
        if (try addExactLockJobs(allocator, arena_ptr, context, input, lock, &jobs)) |failure|
            return .{ .failure = failure };
    }
    if (input.exact_lock_v2) |lock| {
        if (try addExactLockV2Jobs(allocator, arena_ptr, context, input, lock, &jobs)) |failure|
            return .{ .failure = failure };
    }
    addEssentialJobs(context, input, &jobs);
    addSafetyLocks(context, input, &jobs);
    addInstallOnlyJobs(context, input, &jobs);
    addPhasedLocks(context, input, &jobs);

    if (libsolv.solver_solve(state.solver, &jobs) != 0) {
        return .{ .failure = try materializeProblems(allocator, arena_ptr, context, input.limits.max_problems) };
    }
    const transaction = libsolv.solver_create_transaction(state.solver) orelse
        return error.PoolAllocationFailed;
    defer libsolv.transaction_free(transaction);
    libsolv.transaction_order(transaction, 0);

    const transaction_step_count: usize = @intCast(transaction.*.steps.count);
    if (transaction_step_count != 0) {
        const transaction_steps = transaction.*.steps.elements[0..transaction_step_count];
        for (transaction_steps) |solvable_id| {
            const action_type = libsolv.transaction_type(
                transaction,
                solvable_id,
                libsolv.SOLVER_TRANSACTION_SHOW_ACTIVE,
            );
            if (action_type == libsolv.SOLVER_TRANSACTION_OBSOLETED and !input.policy.allow_replacements) {
                return failureOne(allocator, arena_ptr, .replacement_violation, null, null, "transaction requires an explicitly forbidden replacement");
            }
            if ((action_type == libsolv.SOLVER_TRANSACTION_ERASE or
                action_type == libsolv.SOLVER_TRANSACTION_OBSOLETED) and
                !requestedRemoval(input.request, context, solvable_id) and
                (!input.policy.allow_remove_dependencies or
                    !authorizedRemoval(input, context, solvable_id)))
            {
                return failureOne(allocator, arena_ptr, .reverse_dependency, null, null, "unrequested removal is absent from the complete authorized removal set");
            }
        }
    }

    var actions: std.ArrayList(PlanAction) = .empty;
    defer actions.deinit(owned);
    var download_bytes: u64 = 0;
    var size_delta: i128 = 0;
    const step_count: usize = @intCast(transaction.*.steps.count);
    if (step_count > input.limits.max_actions) {
        return failureOne(allocator, arena_ptr, .limit_exceeded, null, null, "transaction contains more actions than the configured limit");
    }

    const steps = if (step_count == 0)
        @as([]const libsolv.Id, &.{})
    else
        transaction.*.steps.elements[0..step_count];
    for (steps) |solvable_id| {
        if (libsolv.transaction_type(
            transaction,
            solvable_id,
            libsolv.SOLVER_TRANSACTION_SHOW_ACTIVE,
        ) == libsolv.SOLVER_TRANSACTION_IGNORE) continue;
        const action = try materializeAction(owned, context, transaction, solvable_id, input);
        download_bytes = std.math.add(u64, download_bytes, action.package_size orelse 0) catch
            return failureOne(allocator, arena_ptr, .limit_exceeded, null, null, "download byte total overflowed");
        size_delta += action.installed_size_delta_bytes;
        try actions.append(owned, action);
    }
    if (try validateNamedInstallAction(allocator, arena_ptr, context, input, actions.items)) |failure|
        return .{ .failure = failure };
    if (input.exact_lock) |lock| {
        for (actions.items) |action| {
            if (action.kind == .remove) continue;
            const locked = lock.findPackage(action.package, action.version, action.architecture) orelse
                return failureOne(allocator, arena_ptr, .lock_closure_drift, action.package, null, "solver selected a package outside the exact locked closure");
            if (action.repository == null or action.sha256 == null or action.package_size == null or
                !std.mem.eql(u8, &action.repository.?.id, &locked.repository_id) or
                !std.mem.eql(u8, &action.sha256.?, &hex32(locked.sha256)) or
                action.package_size.? != locked.declared_size)
                return failureOne(allocator, arena_ptr, .lock_package_mismatch, action.package, null, "planned package evidence differs from the exact lock");
        }
    }
    if (input.exact_lock_v2) |lock| {
        for (actions.items) |action| {
            if (action.kind == .remove) continue;
            const locked = lock.findPackage(action.package, action.version, action.architecture) orelse
                return failureOne(allocator, arena_ptr, .lock_closure_drift, action.package, null, "solver selected a package outside the exact locked closure");
            if (action.sha256 == null or action.package_size == null or
                !planActionMatchesLockV2(action, locked) or
                !std.mem.eql(u8, &action.sha256.?, &hex32(locked.sha256)) or
                action.package_size.? != locked.declared_size)
                return failureOne(allocator, arena_ptr, .lock_package_mismatch, action.package, null, "planned package evidence differs from the exact lock");
        }
    }
    const ordered_actions = try materializeOrdering(owned, actions.items);
    std.mem.sort(PlanAction, actions.items, {}, lessAction);
    const action_slice = try actions.toOwnedSlice(owned);
    const summary = summarizeActions(action_slice, download_bytes, size_delta);
    const target = try owned.dupe(u8, input.target_architecture);
    return .{ .plan = .{
        .schema_version = if (hasLocalArtifactAction(action_slice)) 3 else 2,
        .target_architecture = target,
        .mode = input.mode,
        .actions = action_slice,
        .ordered_actions = ordered_actions,
        .summary = summary,
        .download_bytes = download_bytes,
        .installed_size_delta_bytes = size_delta,
        .backing_allocator = allocator,
        .arena = arena_ptr,
    } };
}

fn authorizedRemoval(input: PlanInput, context: *Context, solvable_id: libsolv.Id) bool {
    const installed_index = findInstalledBySolvable(context, solvable_id) orelse return false;
    const state = internal(context);
    const record = state.source_records[state.mappings[installed_index].record_index];
    for (input.authorized_removals) |identity| {
        if (sameIdentity(identity.name, identity.architecture, record.name.value, record.architecture.value))
            return true;
    }
    return false;
}

fn lessRepositoryIndex(repositories: []const RepositoryInput, a: usize, b: usize) bool {
    if (repositories[a].priority != repositories[b].priority)
        return repositories[a].priority > repositories[b].priority;
    return std.mem.order(
        u8,
        repositories[a].repository_id.slice(),
        repositories[b].repository_id.slice(),
    ) == .lt;
}

fn validatePlanPolicy(input: PlanInput) ?[]const u8 {
    switch (input.policy.phased_updates) {
        .deterministic_percentage => |value| if (value > 100)
            return "deterministic phased-update value must be between 0 and 100",
        else => {},
    }
    for (input.phased_candidates) |candidate| {
        if (candidate.percentage > 100)
            return "candidate phased-update percentage must be between 0 and 100";
    }
    for (input.phased_candidates, 0..) |candidate, index| {
        for (input.phased_candidates[0..index]) |previous| {
            if (sameIdentity(candidate.name, candidate.architecture, previous.name, previous.architecture) and
                std.mem.eql(u8, candidate.version, previous.version))
                return "phased-update candidate identities and versions must be unique";
        }
    }
    if (input.limits.max_problems == 0)
        return "problem limit must permit at least one diagnostic";
    for (input.install_only, 0..) |identity, index| {
        for (input.install_only[0..index]) |previous| {
            if (sameIdentity(identity.name, identity.architecture, previous.name, previous.architecture))
                return "install-only identities must be unique";
        }
    }
    return null;
}

fn failureOne(
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    kind: ProblemKind,
    package: ?[]const u8,
    dependency: ?[]const u8,
    detail: []const u8,
) PlanningError!PlanningResult {
    const owned = arena.allocator();
    return failureOneOwned(
        backing,
        arena,
        kind,
        if (package) |value| try owned.dupe(u8, value) else null,
        if (dependency) |value| try owned.dupe(u8, value) else null,
        try owned.dupe(u8, detail),
    );
}

fn failureOneOwned(
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    kind: ProblemKind,
    package: ?[]const u8,
    dependency: ?[]const u8,
    detail: []const u8,
) PlanningError!PlanningResult {
    const problems = try arena.allocator().alloc(ProblemNode, 1);
    problems[0] = .{
        .kind = kind,
        .package = package,
        .dependency = dependency,
        .detail = detail,
    };
    return .{ .failure = .{
        .problems = problems,
        .backing_allocator = backing,
        .arena = arena,
    } };
}

fn configureSolver(solver_handle: *libsolv.Solver, policy: SolvePolicy) void {
    _ = libsolv.solver_set_flag(solver_handle, libsolv.SOLVER_FLAG_IGNORE_RECOMMENDED, @intFromBool(!policy.recommends));
    _ = libsolv.solver_set_flag(solver_handle, libsolv.SOLVER_FLAG_STRONG_RECOMMENDS, @intFromBool(policy.recommends));
    _ = libsolv.solver_set_flag(solver_handle, libsolv.SOLVER_FLAG_ALLOW_DOWNGRADE, @intFromBool(policy.allow_downgrade));
    _ = libsolv.solver_set_flag(solver_handle, libsolv.SOLVER_FLAG_DUP_ALLOW_DOWNGRADE, @intFromBool(policy.allow_downgrade));
    _ = libsolv.solver_set_flag(solver_handle, libsolv.SOLVER_FLAG_ALLOW_UNINSTALL, @intFromBool(policy.allow_remove_dependencies));
    _ = libsolv.solver_set_flag(solver_handle, libsolv.SOLVER_FLAG_STRICT_REPO_PRIORITY, @intFromBool(policy.strict_repository_priority));
    _ = libsolv.solver_set_flag(solver_handle, libsolv.SOLVER_FLAG_FOCUS_BEST, 1);
}

fn validateExactLockInput(
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    repositories: []const RepositoryInput,
    lock: *const exact_lock_module.Lock,
) PlanningError!?PlanFailure {
    for (lock.repositories) |locked_repository| {
        var matched: ?RepositoryInput = null;
        for (repositories) |repository| {
            if (std.mem.eql(u8, repository.repository_id.slice(), &locked_repository.id)) {
                matched = repository;
                break;
            }
        }
        const repository = matched orelse
            return (try failureOne(backing, arena, .lock_repository_missing, null, null, "exact lock repository is unavailable")).failure;
        if (repository.eligibility != .verified_refresh)
            return (try failureOne(backing, arena, .unauthenticated_repository, null, null, "exact lock reproduction requires authenticated refresh metadata")).failure;
        const snapshot = repository.authenticated_snapshot_sha256 orelse
            return (try failureOne(backing, arena, .lock_repository_mismatch, null, null, "repository has no authenticated snapshot identity")).failure;
        if (!std.mem.eql(u8, &snapshot, &locked_repository.snapshot_sha256))
            return (try failureOne(backing, arena, .lock_repository_mismatch, null, null, "repository snapshot differs from the exact lock")).failure;
    }
    return null;
}

fn validateExactLockV2Input(
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    repositories: []const RepositoryInput,
    lock: *const exact_lock_v2.Lock,
) PlanningError!?PlanFailure {
    for (lock.repositories) |locked_repository| {
        var matched: ?RepositoryInput = null;
        for (repositories) |repository| {
            if (std.mem.eql(u8, repository.repository_id.slice(), &locked_repository.id)) {
                matched = repository;
                break;
            }
        }
        const repository = matched orelse
            return (try failureOne(backing, arena, .lock_repository_missing, null, null, "exact lock repository is unavailable")).failure;
        if (repository.eligibility != .verified_refresh)
            return (try failureOne(backing, arena, .unauthenticated_repository, null, null, "repository lock reproduction requires authenticated refresh metadata")).failure;
        const snapshot = repository.authenticated_snapshot_sha256 orelse
            return (try failureOne(backing, arena, .lock_repository_mismatch, null, null, "repository has no authenticated snapshot identity")).failure;
        if (!std.mem.eql(u8, &snapshot, &locked_repository.snapshot_sha256))
            return (try failureOne(backing, arena, .lock_repository_mismatch, null, null, "repository snapshot differs from the exact lock")).failure;
    }
    for (lock.local_artifacts) |locked_artifact| {
        var matched = false;
        for (repositories) |repository| {
            if (repository.eligibility != .verified_local_artifact) continue;
            const artifact = repository.local_artifact orelse continue;
            if (std.mem.eql(u8, &artifact.artifact_id, &locked_artifact.artifact_id) and
                package_origin.eqlLocalArtifact(artifact, locked_artifact))
            {
                matched = true;
                break;
            }
        }
        if (!matched)
            return (try failureOne(backing, arena, .lock_package_mismatch, locked_artifact.package, null, "verified local artifact evidence differs from the exact lock")).failure;
    }
    return null;
}

fn addExactLockJobs(
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    context: *Context,
    input: PlanInput,
    lock: *const exact_lock_module.Lock,
    jobs: *libsolv.Queue,
) PlanningError!?PlanFailure {
    const state = internal(context);
    for (lock.packages) |locked| {
        var candidate: ?libsolv.Id = null;
        var identity_seen = false;
        for (state.origins.items) |origin| {
            if (!std.mem.eql(u8, origin.package, locked.name) or
                !std.mem.eql(u8, origin.version, locked.version) or
                !std.mem.eql(u8, origin.architecture, locked.architecture))
                continue;
            identity_seen = true;
            if (!std.mem.eql(u8, origin.repository_id.slice(), &locked.repository_id)) continue;
            const repository_index = findRepositoryIndex(input.repositories, origin.repository_id) orelse continue;
            const record = input.repositories[repository_index].packages.records[origin.record_index];
            if (!std.mem.eql(u8, &record.transport.sha256.bytes, &locked.sha256) or
                record.transport.size.value != locked.declared_size)
                continue;
            candidate = origin.solvable_id;
            break;
        }
        if (candidate == null) {
            return (try failureOne(
                backing,
                arena,
                if (identity_seen) .lock_package_mismatch else .lock_package_missing,
                locked.name,
                null,
                if (identity_seen)
                    "exact lock package repository, digest, or declared size differs"
                else
                    "exact lock package version and architecture are unavailable",
            )).failure;
        }
        if (findInstalledSelector(context, .{
            .name = locked.name,
            .version = locked.version,
            .architecture = locked.architecture,
        })) |installed_index| {
            const mapping = state.mappings[installed_index];
            if (state.source_records[mapping.record_index].status.isFullyInstalled()) continue;
        }
        libsolv.queue_push2(jobs, libsolv.SOLVER_INSTALL | libsolv.SOLVER_SOLVABLE, candidate.?);
    }

    for (state.mappings, 0..) |mapping, installed_index| {
        const installed = state.source_records[mapping.record_index];
        if (!installed.status.isFullyInstalled()) continue;
        if (lock.findIdentity(installed.name.value, installed.architecture.value) != null) continue;
        if (isHeld(context, installed_index) and !input.policy.allow_change_held)
            return (try failureOne(backing, arena, .held_violation, installed.name.value, null, "dpkg selection hold prevents exact lock closure reproduction")).failure;
        if (removalViolation(context, input, installed_index)) |kind|
            return (try failureOne(backing, arena, kind, installed.name.value, null, "safe removal policy prevents exact lock closure reproduction")).failure;
        libsolv.queue_push2(jobs, libsolv.SOLVER_ERASE | libsolv.SOLVER_SOLVABLE, mapping.solvable_id);
    }
    return null;
}

fn addExactLockV2Jobs(
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    context: *Context,
    input: PlanInput,
    lock: *const exact_lock_v2.Lock,
    jobs: *libsolv.Queue,
) PlanningError!?PlanFailure {
    const state = internal(context);
    for (lock.packages) |locked| {
        var candidate: ?libsolv.Id = null;
        var identity_seen = false;
        for (state.origins.items) |origin| {
            if (!std.mem.eql(u8, origin.package, locked.name) or
                !std.mem.eql(u8, origin.version, locked.version) or
                !std.mem.eql(u8, origin.architecture, locked.architecture))
                continue;
            identity_seen = true;
            const repository_index = findRepositoryIndex(input.repositories, origin.repository_id) orelse
                continue;
            const record = input.repositories[repository_index].packages.records[origin.record_index];
            if (!std.mem.eql(u8, &record.transport.sha256.bytes, &locked.sha256) or
                record.transport.size.value != locked.declared_size or
                !originMatchesLockV2(origin, locked.origin))
                continue;
            candidate = origin.solvable_id;
            break;
        }
        if (candidate == null) {
            return (try failureOne(
                backing,
                arena,
                if (identity_seen) .lock_package_mismatch else .lock_package_missing,
                locked.name,
                null,
                if (identity_seen)
                    "exact lock package origin, digest, or declared size differs"
                else
                    "exact lock package version and architecture are unavailable",
            )).failure;
        }
        if (findInstalledSelector(context, .{
            .name = locked.name,
            .version = locked.version,
            .architecture = locked.architecture,
        })) |installed_index| {
            const mapping = state.mappings[installed_index];
            if (state.source_records[mapping.record_index].status.isFullyInstalled()) continue;
        }
        libsolv.queue_push2(jobs, libsolv.SOLVER_INSTALL | libsolv.SOLVER_SOLVABLE, candidate.?);
    }

    for (state.mappings, 0..) |mapping, installed_index| {
        const installed = state.source_records[mapping.record_index];
        if (!installed.status.isFullyInstalled()) continue;
        if (lock.findIdentity(installed.name.value, installed.architecture.value) != null) continue;
        if (isHeld(context, installed_index) and !input.policy.allow_change_held)
            return (try failureOne(backing, arena, .held_violation, installed.name.value, null, "exact lock excludes a held installed package")).failure;
        if (removalViolation(context, input, installed_index)) |kind|
            return (try failureOne(backing, arena, kind, installed.name.value, null, "safe removal policy prevents exact lock closure reproduction")).failure;
        libsolv.queue_push2(jobs, libsolv.SOLVER_ERASE | libsolv.SOLVER_SOLVABLE, mapping.solvable_id);
    }
    return null;
}

fn originMatchesLockV2(
    origin: OriginOwned,
    locked: exact_lock_v2.PackageOrigin,
) bool {
    return switch (locked) {
        .authenticated_repository => |repository| origin.local_artifact == null and
            std.mem.eql(u8, origin.repository_id.slice(), &repository.repository_id),
        .local_artifact => |artifact| if (origin.local_artifact) |observed|
            package_origin.eqlLocalArtifact(observed, artifact)
        else
            false,
    };
}

fn preflightRequest(
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    context: *Context,
    input: PlanInput,
    jobs: *libsolv.Queue,
) PlanningError!?PlanFailure {
    switch (input.request) {
        .install => |selector| {
            if (selector.version != null or selector.architecture != null) {
                const candidate = findAvailableCandidate(context, selector) orelse {
                    return (try selectorFailure(backing, arena, context, selector)).failure;
                };
                if (!candidatePolicyAllowed(context, candidate, input)) {
                    return (try failureOne(backing, arena, .phased_update_excluded, selector.name, null, "exact candidate is excluded by deterministic phased-update policy")).failure;
                }
                if (downgradesInstalled(context, candidate) and !input.policy.allow_downgrade) {
                    return (try failureOne(backing, arena, .unsupported_feature, selector.name, null, "requested version is a downgrade and allow_downgrade is false")).failure;
                }
                libsolv.queue_push2(jobs, libsolv.SOLVER_INSTALL | libsolv.SOLVER_SOLVABLE, candidate);
            } else {
                const candidate = findAvailableCandidate(context, selector) orelse {
                    return (try failureOne(backing, arena, .no_candidate, selector.name, null, "no available package or provider matches the requested name")).failure;
                };
                if (!candidatePolicyAllowed(context, candidate, input)) {
                    return (try failureOne(backing, arena, .phased_update_excluded, selector.name, null, "selected candidate is excluded by deterministic phased-update policy")).failure;
                }
                libsolv.queue_push2(jobs, libsolv.SOLVER_INSTALL | libsolv.SOLVER_SOLVABLE | libsolv.SOLVER_FORCEBEST, candidate);
            }
        },
        .remove => |selector| {
            if (installedSelectorAmbiguous(context, selector)) {
                return (try failureOne(backing, arena, .invalid_policy, selector.name, null, "installed package selector is ambiguous; specify an architecture")).failure;
            }
            const installed_index = findInstalledSelector(context, selector) orelse {
                return (try failureOne(backing, arena, .no_candidate, selector.name, null, "requested package is not installed with the selected version and architecture")).failure;
            };
            const violation = removalViolation(context, input, installed_index);
            if (violation) |kind| {
                return (try failureOne(backing, arena, kind, selector.name, null, "safe policy forbids removing the selected installed package")).failure;
            }
            libsolv.queue_push2(
                jobs,
                libsolv.SOLVER_ERASE | libsolv.SOLVER_SOLVABLE,
                internal(context).mappings[installed_index].solvable_id,
            );
            if (hasRequiredInstalledDependent(context, installed_index)) {
                if (!input.policy.allow_remove_dependencies) {
                    return (try failureOne(backing, arena, .unsatisfied_dependency, selector.name, selector.name, "an installed package requires the selected package")).failure;
                }
                if (try addAuthorizedReverseRemovalJobs(arena.allocator(), context, input, installed_index, jobs)) |dependent| {
                    return (try failureOne(backing, arena, .reverse_dependency, dependent, selector.name, "reverse dependency is absent from the complete authorized removal set")).failure;
                }
            }
        },
        .upgrade => |selectors| {
            if (selectors.len == 0) {
                return (try failureOne(backing, arena, .unsupported_feature, null, null, "named upgrade requires at least one package")).failure;
            }

            for (selectors) |selector| {
                if (installedSelectorAmbiguous(context, .{
                    .name = selector.name,
                    .architecture = selector.architecture,
                })) {
                    return (try failureOne(backing, arena, .invalid_policy, selector.name, null, "installed package selector is ambiguous; specify an architecture")).failure;
                }
                const installed_index = findInstalledSelector(context, .{
                    .name = selector.name,
                    .architecture = selector.architecture,
                }) orelse {
                    return (try failureOne(backing, arena, .no_candidate, selector.name, null, "named upgrade package is not installed")).failure;
                };
                if (isHeld(context, installed_index) and !input.policy.allow_change_held) {
                    return (try failureOne(backing, arena, .held_violation, selector.name, null, "safe policy forbids changing a held package")).failure;
                }
                if (selector.version) |_| {
                    const candidate = findAvailableCandidate(context, selector) orelse {
                        return (try selectorFailure(backing, arena, context, selector)).failure;
                    };
                    if (!candidatePolicyAllowed(context, candidate, input)) {
                        return (try failureOne(backing, arena, .phased_update_excluded, selector.name, null, "exact candidate is excluded by deterministic phased-update policy")).failure;
                    }
                    if (downgradesInstalled(context, candidate) and !input.policy.allow_downgrade) {
                        return (try failureOne(backing, arena, .unsupported_feature, selector.name, null, "requested upgrade target is a downgrade and allow_downgrade is false")).failure;
                    }
                    libsolv.queue_push2(jobs, libsolv.SOLVER_INSTALL | libsolv.SOLVER_SOLVABLE, candidate);
                } else {
                    if (findBestUpgradeCandidate(context, installed_index, input)) |candidate|
                        libsolv.queue_push2(jobs, libsolv.SOLVER_INSTALL | libsolv.SOLVER_SOLVABLE, candidate);
                }
            }
        },
        .upgrade_all => {
            for (internal(context).mappings, 0..) |_, installed_index| {
                if (isHeld(context, installed_index) and !input.policy.allow_change_held) continue;
                if (findBestUpgradeCandidate(context, installed_index, input)) |candidate|
                    libsolv.queue_push2(jobs, libsolv.SOLVER_INSTALL | libsolv.SOLVER_SOLVABLE, candidate);
            }
        },
        .reinstall => |selector| {
            if (installedSelectorAmbiguous(context, selector)) {
                return (try failureOne(backing, arena, .invalid_policy, selector.name, null, "installed package selector is ambiguous; specify an architecture")).failure;
            }
            const installed_index = findInstalledSelector(context, selector) orelse {
                return (try failureOne(backing, arena, .no_candidate, selector.name, null, "reinstall requires an exactly matching installed package")).failure;
            };
            if (isHeld(context, installed_index) and !input.policy.allow_change_held) {
                return (try failureOne(backing, arena, .held_violation, selector.name, null, "safe policy forbids reinstalling a held package")).failure;
            }
            const record = internal(context).source_records[internal(context).mappings[installed_index].record_index];
            const candidate = findAvailableCandidate(context, .{
                .name = record.name.value,
                .version = record.version.spelling.value,
                .architecture = record.architecture.value,
            }) orelse {
                return (try failureOne(backing, arena, .no_candidate, selector.name, null, "no authenticated repository contains the installed version and architecture")).failure;
            };
            if (!candidatePolicyAllowed(context, candidate, input)) {
                return (try failureOne(backing, arena, .phased_update_excluded, selector.name, null, "reinstall candidate is excluded by deterministic phased-update policy")).failure;
            }
            libsolv.queue_push2(
                jobs,
                libsolv.SOLVER_INSTALL | libsolv.SOLVER_SOLVABLE | libsolv.SOLVER_FORCEBEST,
                candidate,
            );
        },
    }
    return null;
}

fn addAuthorizedReverseRemovalJobs(
    allocator: std.mem.Allocator,
    context: *Context,
    input: PlanInput,
    removed_index: usize,
    jobs: *libsolv.Queue,
) !?[]const u8 {
    const state = internal(context);
    const removed = try allocator.alloc(bool, state.mappings.len);
    @memset(removed, false);
    removed[removed_index] = true;
    var changed = true;
    while (changed) {
        changed = false;
        for (state.mappings, 0..) |mapping, dependent_index| {
            if (removed[dependent_index]) continue;
            const dependent = state.source_records[mapping.record_index];
            var must_remove = false;
            for (dependent.relations) |dependency| {
                if (dependency.kind != .depends and dependency.kind != .pre_depends) continue;
                for (dependency.relation.groups) |group| {
                    var references_removed = false;
                    var surviving_alternative = false;
                    for (group.alternatives) |alternative| {
                        if (findInstalledSelector(context, .{ .name = alternative.package.name.text })) |alternative_index| {
                            if (removed[alternative_index])
                                references_removed = true
                            else
                                surviving_alternative = true;
                        }
                    }
                    if (references_removed and !surviving_alternative) must_remove = true;
                }
            }
            if (!must_remove) continue;
            if (!identityAuthorized(input.authorized_removals, dependent.name.value, dependent.architecture.value))
                return dependent.name.value;
            removed[dependent_index] = true;
            changed = true;
            libsolv.queue_push2(jobs, libsolv.SOLVER_ERASE | libsolv.SOLVER_SOLVABLE, mapping.solvable_id);
        }
    }
    return null;
}

fn identityAuthorized(
    identities: []const ProtectedIdentity,
    name: []const u8,
    architecture: []const u8,
) bool {
    for (identities) |identity| {
        if (sameIdentity(identity.name, identity.architecture, name, architecture)) return true;
    }
    return false;
}

fn addInstallOnlyJobs(context: *Context, input: PlanInput, jobs: *libsolv.Queue) void {
    const state = internal(context);
    for (input.install_only) |identity| {
        for (state.mappings) |mapping| {
            const record = state.source_records[mapping.record_index];
            if (sameIdentity(identity.name, identity.architecture, record.name.value, record.architecture.value))
                libsolv.queue_push2(jobs, libsolv.SOLVER_MULTIVERSION | libsolv.SOLVER_SOLVABLE, mapping.solvable_id);
        }
        for (state.origins.items) |origin| {
            if (sameIdentity(identity.name, identity.architecture, origin.package, origin.architecture))
                libsolv.queue_push2(jobs, libsolv.SOLVER_MULTIVERSION | libsolv.SOLVER_SOLVABLE, origin.solvable_id);
        }
    }
}

fn phasedCandidate(input: PlanInput, origin: OriginOwned) ?PhasedCandidate {
    for (input.phased_candidates) |candidate| {
        if (std.mem.eql(u8, candidate.name, origin.package) and
            std.mem.eql(u8, candidate.architecture, origin.architecture) and
            std.mem.eql(u8, candidate.version, origin.version)) return candidate;
    }
    return null;
}

fn phasedAllowed(input: PlanInput, candidate: PhasedCandidate) bool {
    return switch (input.policy.phased_updates) {
        .disabled => false,
        .include_all => true,
        .deterministic_percentage => |phase| phase < candidate.percentage,
    };
}

fn addPhasedLocks(context: *Context, input: PlanInput, jobs: *libsolv.Queue) void {
    for (internal(context).origins.items) |origin| {
        const candidate = phasedCandidate(input, origin) orelse continue;
        if (!phasedAllowed(input, candidate))
            libsolv.queue_push2(jobs, libsolv.SOLVER_LOCK | libsolv.SOLVER_SOLVABLE, origin.solvable_id);
    }
}

fn selectorFailure(
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    context: *Context,
    selector: PackageSelector,
) PlanningError!PlanningResult {
    const owned = arena.allocator();
    var rejections: std.ArrayList(CandidateRejection) = .empty;
    defer rejections.deinit(owned);
    for (internal(context).origins.items) |origin| {
        if (!std.mem.eql(u8, origin.package, selector.name)) continue;
        const reason: CandidateRejectionReason = if (selector.architecture) |architecture|
            if (!std.mem.eql(u8, origin.architecture, architecture) and
                !std.mem.eql(u8, origin.architecture, "all")) .wrong_architecture else .wrong_version
        else
            .wrong_version;
        try rejections.append(owned, .{
            .package = try owned.dupe(u8, origin.package),
            .version = try owned.dupe(u8, origin.version),
            .architecture = try owned.dupe(u8, origin.architecture),
            .reason = reason,
            .detail = if (reason == .wrong_architecture)
                "candidate architecture does not match the exact request"
            else
                "candidate version does not match the exact request",
        });
    }
    if (!hasAvailableName(context, selector.name))
        return failureOne(backing, arena, .no_candidate, selector.name, null, "package has no available candidate");
    const problems = try owned.alloc(ProblemNode, 1);
    problems[0] = .{
        .kind = if (selector.architecture != null and
            !hasAvailableNameArchitecture(context, selector.name, selector.architecture.?))
            .architecture_mismatch
        else
            .version_mismatch,
        .package = try owned.dupe(u8, selector.name),
        .detail = if (selector.architecture != null and
            !hasAvailableNameArchitecture(context, selector.name, selector.architecture.?))
            "package exists but not for the requested architecture"
        else
            "package exists but not at the requested exact version",
        .candidate_rejections = try rejections.toOwnedSlice(owned),
    };
    return .{ .failure = .{
        .problems = problems,
        .backing_allocator = backing,
        .arena = arena,
    } };
}

fn findAvailableCandidate(context: *Context, selector: PackageSelector) ?libsolv.Id {
    const state = internal(context);
    var best: ?libsolv.Id = null;
    for (state.origins.items) |origin| {
        if (!std.mem.eql(u8, origin.package, selector.name)) continue;
        if (selector.version) |version| if (!std.mem.eql(u8, origin.version, version)) continue;
        if (selector.architecture) |architecture| {
            if (!std.mem.eql(u8, origin.architecture, architecture) and
                !std.mem.eql(u8, origin.architecture, "all")) continue;
        } else if (!std.mem.eql(u8, origin.architecture, state.target_architecture) and
            !std.mem.eql(u8, origin.architecture, "all"))
        {
            continue;
        }
        if (best == null or betterCandidate(state, origin.solvable_id, best.?))
            best = origin.solvable_id;
    }
    return best;
}

fn betterCandidate(state: *Internal, a: libsolv.Id, b: libsolv.Id) bool {
    const a_origin = findOrigin(state, a).?;
    const b_origin = findOrigin(state, b).?;
    if (a_origin.repository_priority != b_origin.repository_priority)
        return a_origin.repository_priority > b_origin.repository_priority;
    const cmp = libsolv.pool_evrcmp(
        state.pool,
        libsolv.pool_id2solvable(state.pool, a).*.evr,
        libsolv.pool_id2solvable(state.pool, b).*.evr,
        libsolv.EVRCMP_COMPARE,
    );
    if (cmp != 0) return cmp > 0;
    const arch_order = std.mem.order(u8, a_origin.architecture, b_origin.architecture);
    if (arch_order != .eq) return arch_order == .lt;
    return std.mem.order(u8, a_origin.repository_id.slice(), b_origin.repository_id.slice()) == .lt;
}

fn findBestUpgradeCandidate(context: *Context, installed_index: usize, input: PlanInput) ?libsolv.Id {
    const state = internal(context);
    const mapping = state.mappings[installed_index];
    const installed = libsolv.pool_id2solvable(state.pool, mapping.solvable_id);
    var best: ?libsolv.Id = null;
    for (state.origins.items) |origin| {
        if (!candidatePolicyAllowed(context, origin.solvable_id, input)) continue;
        const candidate = libsolv.pool_id2solvable(state.pool, origin.solvable_id);
        if (candidate.*.name != installed.*.name) continue;
        if (candidate.*.arch != installed.*.arch and
            !std.mem.eql(u8, origin.architecture, "all")) continue;
        if (libsolv.pool_evrcmp(state.pool, candidate.*.evr, installed.*.evr, libsolv.EVRCMP_COMPARE) <= 0)
            continue;
        if (best == null or betterCandidate(state, origin.solvable_id, best.?))
            best = origin.solvable_id;
    }

    return best;
}

fn candidatePolicyAllowed(context: *Context, solvable_id: libsolv.Id, input: PlanInput) bool {
    const origin = findOrigin(internal(context), solvable_id) orelse return true;
    const phased = phasedCandidate(input, origin.*) orelse return true;
    return phasedAllowed(input, phased);
}

fn hasAvailableName(context: *Context, name: []const u8) bool {
    for (internal(context).origins.items) |origin|
        if (std.mem.eql(u8, origin.package, name)) return true;
    return false;
}

fn hasAvailableNameArchitecture(context: *Context, name: []const u8, architecture: []const u8) bool {
    for (internal(context).origins.items) |origin| {
        if (std.mem.eql(u8, origin.package, name) and
            (std.mem.eql(u8, origin.architecture, architecture) or std.mem.eql(u8, origin.architecture, "all")))
            return true;
    }
    return false;
}

fn findInstalledSelector(context: *Context, selector: PackageSelector) ?usize {
    const state = internal(context);
    for (state.mappings, 0..) |mapping, index| {
        const record = state.source_records[mapping.record_index];
        if (!std.mem.eql(u8, record.name.value, selector.name)) continue;
        if (selector.version) |version| if (!std.mem.eql(u8, record.version.spelling.value, version)) continue;
        if (selector.architecture) |architecture| if (!std.mem.eql(u8, record.architecture.value, architecture)) continue;
        return index;
    }
    return null;
}

fn installedSelectorAmbiguous(context: *Context, selector: PackageSelector) bool {
    if (selector.architecture != null) return false;
    const state = internal(context);
    var matches: usize = 0;
    for (state.mappings) |mapping| {
        const record = state.source_records[mapping.record_index];
        if (!std.mem.eql(u8, record.name.value, selector.name)) continue;
        if (selector.version) |version|
            if (!std.mem.eql(u8, record.version.spelling.value, version)) continue;
        matches += 1;
        if (matches > 1) return true;
    }
    return false;
}

fn findInstalledBySolvable(context: *Context, solvable_id: libsolv.Id) ?usize {
    for (internal(context).mappings, 0..) |mapping, index|
        if (mapping.solvable_id == solvable_id) return index;
    return null;
}

fn findInstalledSameNameArch(context: *Context, solvable_id: libsolv.Id) ?usize {
    const state = internal(context);
    const solvable = libsolv.pool_id2solvable(state.pool, solvable_id);
    for (state.mappings, 0..) |mapping, index| {
        const installed = libsolv.pool_id2solvable(state.pool, mapping.solvable_id);
        if (installed.*.name == solvable.*.name and installed.*.arch == solvable.*.arch) return index;
    }
    return null;
}

fn downgradesInstalled(context: *Context, candidate: libsolv.Id) bool {
    const installed_index = findInstalledSameNameArch(context, candidate) orelse return false;
    const state = internal(context);
    const installed = libsolv.pool_id2solvable(state.pool, state.mappings[installed_index].solvable_id);
    const available = libsolv.pool_id2solvable(state.pool, candidate);
    return libsolv.pool_evrcmp(state.pool, available.*.evr, installed.*.evr, libsolv.EVRCMP_COMPARE) < 0;
}

fn isExplicitProtected(input: PlanInput, name: []const u8, architecture: []const u8) bool {
    for (input.protected) |identity| {
        if (std.mem.eql(u8, identity.name, name) and std.mem.eql(u8, identity.architecture, architecture))
            return true;
    }
    return false;
}

fn isHeld(context: *Context, installed_index: usize) bool {
    return internal(context).mappings[installed_index].metadata.held;
}

fn removalViolation(context: *Context, input: PlanInput, installed_index: usize) ?ProblemKind {
    const state = internal(context);
    const mapping = state.mappings[installed_index];
    const record = state.source_records[mapping.record_index];
    if (mapping.metadata.held and !input.policy.allow_change_held) return .held_violation;
    if (mapping.metadata.essential == true and !input.policy.allow_remove_essential) return .essential_violation;
    if ((mapping.metadata.protected == true or
        isExplicitProtected(input, record.name.value, record.architecture.value)) and
        !input.policy.allow_remove_protected) return .protected_violation;
    return null;
}

fn hasRequiredInstalledDependent(context: *Context, removed_index: usize) bool {
    const state = internal(context);
    const removed = state.source_records[state.mappings[removed_index].record_index];
    for (state.mappings, 0..) |mapping, dependent_index| {
        if (dependent_index == removed_index) continue;
        const dependent = state.source_records[mapping.record_index];
        for (dependent.relations) |dependency| {
            if (dependency.kind != .depends and dependency.kind != .pre_depends) continue;
            for (dependency.relation.groups) |group| {
                var references_removed = false;
                var alternative_installed = false;
                for (group.alternatives) |alternative| {
                    if (std.mem.eql(u8, alternative.package.name.text, removed.name.value)) {
                        references_removed = true;
                    } else if (findInstalledSelector(context, .{ .name = alternative.package.name.text }) != null) {
                        alternative_installed = true;
                    }
                }
                if (references_removed and !alternative_installed) return true;
            }
        }
    }
    return false;
}

fn addEssentialJobs(context: *Context, input: PlanInput, jobs: *libsolv.Queue) void {
    switch (input.request) {
        .remove => return,
        else => {},
    }
    const state = internal(context);
    for (state.origins.items) |origin| {
        const repository_index = findRepositoryIndex(input.repositories, origin.repository_id) orelse continue;
        const record = input.repositories[repository_index].packages.records[origin.record_index];
        if (record.control.essential != true) continue;
        const candidate = findAvailableCandidate(context, .{ .name = origin.package }) orelse continue;
        if (candidate != origin.solvable_id or !candidatePolicyAllowed(context, candidate, input)) continue;
        if (hasInstalledOrigin(context, origin) or hasInstallJob(jobs, candidate))
            continue;
        libsolv.queue_push2(
            jobs,
            libsolv.SOLVER_INSTALL | libsolv.SOLVER_SOLVABLE | libsolv.SOLVER_ESSENTIAL,
            candidate,
        );
    }
}

fn hasInstalledOrigin(context: *Context, origin: OriginOwned) bool {
    const state = internal(context);
    for (state.mappings) |mapping| {
        const installed = state.source_records[mapping.record_index];
        if (sameIdentity(
            origin.package,
            origin.architecture,
            installed.name.value,
            installed.architecture.value,
        )) return true;
    }
    return false;
}

fn hasInstallJob(jobs: *const libsolv.Queue, candidate: libsolv.Id) bool {
    if (jobs.*.count < 0) return false;
    const count: usize = @intCast(jobs.*.count);
    var index: usize = 0;
    while (index + 1 < count) : (index += 2) {
        const how = jobs.*.elements[index];
        const what = jobs.*.elements[index + 1];
        if ((how & libsolv.SOLVER_JOBMASK) == libsolv.SOLVER_INSTALL and
            (how & libsolv.SOLVER_SELECTMASK) == libsolv.SOLVER_SOLVABLE and
            what == candidate)
            return true;
    }
    return false;
}

fn addSafetyLocks(context: *Context, input: PlanInput, jobs: *libsolv.Queue) void {
    const state = internal(context);
    for (state.mappings, 0..) |mapping, index| {
        if (removalViolation(context, input, index) != null) {
            libsolv.queue_push2(jobs, libsolv.SOLVER_LOCK | libsolv.SOLVER_SOLVABLE, mapping.solvable_id);
        }
    }
}

fn validateNamedInstallAction(
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    context: *Context,
    input: PlanInput,
    actions: []const PlanAction,
) PlanningError!?PlanFailure {
    const selector = switch (input.request) {
        .install => |value| value,
        else => return null,
    };
    const candidate_id = findAvailableCandidate(context, selector) orelse return null;
    const origin = findOrigin(internal(context), candidate_id).?;
    if (findInstalledSelector(context, .{
        .name = origin.package,
        .version = origin.version,
        .architecture = origin.architecture,
    }) != null) return null;
    for (actions) |action| {
        if (action.kind != .remove and
            std.mem.eql(u8, action.package, origin.package) and
            std.mem.eql(u8, action.version, origin.version) and
            std.mem.eql(u8, action.architecture, origin.architecture))
            return null;
    }
    return (try failureOne(
        backing,
        arena,
        .unsatisfied_dependency,
        selector.name,
        null,
        "solver did not materialize the selected named package",
    )).failure;
}

fn materializeProblems(
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    context: *Context,
    max_problems: usize,
) PlanningError!PlanFailure {
    const owned = arena.allocator();
    const state = internal(context);
    var problems: std.ArrayList(ProblemNode) = .empty;
    defer problems.deinit(owned);
    var problem: libsolv.Id = 0;
    while (true) {
        problem = libsolv.solver_next_problem(state.solver, problem);
        if (problem == 0 or problems.items.len == max_problems) break;
        const rule = validatedProblemRule(state, problem) orelse {
            try problems.append(owned, .{
                .kind = .invalid_solver_state,
                .detail = "solver problem trace failed validated rule and range checks",
            });
            break;
        };
        var source_id: libsolv.Id = 0;
        var target_id: libsolv.Id = 0;
        var dependency_id: libsolv.Id = 0;
        const info = libsolv.solver_ruleinfo(state.solver, rule, &source_id, &target_id, &dependency_id);
        const solvable_count: libsolv.Id = @intCast(state.pool.*.nsolvables);
        if (source_id < 0 or source_id >= solvable_count or target_id < 0 or target_id >= solvable_count) {
            try problems.append(owned, .{
                .kind = .invalid_solver_state,
                .detail = "solver rule produced an out-of-range solvable identifier",
            });
            break;
        }
        const kind: ProblemKind = switch (info) {
            libsolv.SOLVER_RULE_PKG_NOTHING_PROVIDES_DEP,
            libsolv.SOLVER_RULE_PKG_REQUIRES,
            libsolv.SOLVER_RULE_JOB_NOTHING_PROVIDES_DEP,
            => .unsatisfied_dependency,
            libsolv.SOLVER_RULE_PKG_CONFLICTS,
            libsolv.SOLVER_RULE_PKG_SELF_CONFLICT,
            libsolv.SOLVER_RULE_PKG_OBSOLETES,
            => .conflict,
            libsolv.SOLVER_RULE_INFARCH => .architecture_mismatch,
            libsolv.SOLVER_RULE_JOB_UNKNOWN_PACKAGE => .no_candidate,
            else => .conflict,
        };
        const package = if (source_id > 0)
            try owned.dupe(u8, std.mem.span(libsolv.pool_solvid2str(state.pool, source_id)))
        else
            null;
        const dependency = if (dependency_id > 0)
            try owned.dupe(u8, std.mem.span(libsolv.pool_dep2str(state.pool, dependency_id)))
        else
            null;
        const detail = try owned.dupe(u8, std.mem.span(libsolv.solver_problemruleinfo2str(
            state.solver,
            info,
            source_id,
            target_id,
            dependency_id,
        )));
        try problems.append(owned, .{
            .kind = kind,
            .package = package,
            .dependency = dependency,
            .detail = detail,
        });
    }
    if (problems.items.len == 0) {
        try problems.append(owned, .{ .kind = .conflict, .detail = "solver reported an unclassified contradiction" });
    }
    std.mem.sort(ProblemNode, problems.items, {}, lessProblem);
    for (problems.items, 0..) |*item, index| item.id = index;
    return .{
        .problems = try problems.toOwnedSlice(owned),
        .backing_allocator = backing,
        .arena = arena,
    };
}

fn validatedProblemRule(state: *Internal, problem: libsolv.Id) ?libsolv.Id {
    const solver_handle = state.solver;
    if (problem <= 0) return null;
    const problem_count: usize = @intCast(libsolv.solver_problem_count(solver_handle));
    const problem_index: usize = @intCast(problem);
    if (problem_index > problem_count or solver_handle.*.problems.count < 0 or
        @as(usize, @intCast(solver_handle.*.problems.count)) != problem_count * 2)
        return null;
    if (!solverRuleRangesValid(solver_handle)) return null;
    const trace_slot = (problem_index - 1) * 2;
    const trace_index = solver_handle.*.problems.elements[trace_slot];
    var budget: usize = @intCast(solver_handle.*.learnt_pool.count);
    if (!validatedLearntTrace(solver_handle, trace_index, 0, &budget)) return null;
    const rule = libsolv.solver_findproblemrule(solver_handle, problem);
    if (rule <= 0 or rule >= solver_handle.*.nrules) return null;
    return rule;
}

fn solverRuleRangesValid(solver_handle: *libsolv.Solver) bool {
    const end = solver_handle.*.nrules;
    if (end <= 0) return false;
    const ranges = [_]libsolv.Id{
        solver_handle.*.pkgrules_end,
        solver_handle.*.featurerules,
        solver_handle.*.featurerules_end,
        solver_handle.*.updaterules,
        solver_handle.*.updaterules_end,
        solver_handle.*.jobrules,
        solver_handle.*.jobrules_end,
        solver_handle.*.infarchrules,
        solver_handle.*.infarchrules_end,
        solver_handle.*.duprules,
        solver_handle.*.duprules_end,
        solver_handle.*.bestrules,
        solver_handle.*.bestrules_up,
        solver_handle.*.bestrules_end,
        solver_handle.*.yumobsrules,
        solver_handle.*.yumobsrules_end,
        solver_handle.*.blackrules,
        solver_handle.*.blackrules_end,
        solver_handle.*.strictrepopriorules,
        solver_handle.*.strictrepopriorules_end,
        solver_handle.*.learntrules,
    };
    for (ranges) |value| if (value < 0 or value > end) return false;
    return true;
}

fn validatedLearntTrace(
    solver_handle: *libsolv.Solver,
    start: libsolv.Id,
    depth: usize,
    budget: *usize,
) bool {
    if (depth > 64 or start < 0 or solver_handle.*.learnt_pool.count < 0) return false;
    const count: usize = @intCast(solver_handle.*.learnt_pool.count);
    var index: usize = @intCast(start);
    if (index >= count) return false;
    while (index < count) : (index += 1) {
        if (budget.* == 0) return false;
        budget.* -= 1;
        const rule = solver_handle.*.learnt_pool.elements[index];
        if (rule == 0) return true;
        if (rule <= 0 or rule >= solver_handle.*.nrules) return false;
        if (rule >= solver_handle.*.learntrules) {
            const learnt_index: usize = @intCast(rule - solver_handle.*.learntrules);
            if (solver_handle.*.learnt_why.count < 0 or
                learnt_index >= @as(usize, @intCast(solver_handle.*.learnt_why.count)))
                return false;
            const nested = solver_handle.*.learnt_why.elements[learnt_index];
            if (!validatedLearntTrace(solver_handle, nested, depth + 1, budget)) return false;
        }
    }
    return false;
}

fn lessProblem(_: void, a: ProblemNode, b: ProblemNode) bool {
    if (@intFromEnum(a.kind) != @intFromEnum(b.kind))
        return @intFromEnum(a.kind) < @intFromEnum(b.kind);
    const package_order = std.mem.order(u8, a.package orelse "", b.package orelse "");
    if (package_order != .eq) return package_order == .lt;
    const dependency_order = std.mem.order(u8, a.dependency orelse "", b.dependency orelse "");
    if (dependency_order != .eq) return dependency_order == .lt;
    return std.mem.order(u8, a.detail, b.detail) == .lt;
}

fn materializeAction(
    allocator: std.mem.Allocator,
    context: *Context,
    transaction: *libsolv.Transaction,
    solvable_id: libsolv.Id,
    input: PlanInput,
) !PlanAction {
    const state = internal(context);
    const action_type = libsolv.transaction_type(
        transaction,
        solvable_id,
        libsolv.SOLVER_TRANSACTION_SHOW_ACTIVE,
    );
    const origin = findOrigin(state, solvable_id);
    const installed_index = if (origin == null)
        findInstalledBySolvable(context, solvable_id)
    else if (isInstallOnly(input, origin.?.package, origin.?.architecture))
        null
    else
        findInstalledSameNameArch(context, solvable_id);
    const prior = if (installed_index) |index| try ownedPrior(allocator, context, index) else null;
    var kind: ActionKind = switch (action_type) {
        libsolv.SOLVER_TRANSACTION_ERASE,
        libsolv.SOLVER_TRANSACTION_OBSOLETED,
        => .remove,
        libsolv.SOLVER_TRANSACTION_UPGRADE,
        libsolv.SOLVER_TRANSACTION_UPGRADED,
        => .upgrade,
        libsolv.SOLVER_TRANSACTION_DOWNGRADE,
        libsolv.SOLVER_TRANSACTION_DOWNGRADED,
        => .downgrade,
        libsolv.SOLVER_TRANSACTION_REINSTALL,
        libsolv.SOLVER_TRANSACTION_REINSTALLED,
        => .reinstall,
        else => if (origin != null) .install else .remove,
    };
    if (origin != null and installed_index != null and kind != .remove) {
        const installed_solvable = libsolv.pool_id2solvable(
            state.pool,
            state.mappings[installed_index.?].solvable_id,
        );
        const candidate_solvable = libsolv.pool_id2solvable(state.pool, solvable_id);
        const comparison = libsolv.pool_evrcmp(
            state.pool,
            candidate_solvable.*.evr,
            installed_solvable.*.evr,
            libsolv.EVRCMP_COMPARE,
        );
        kind = if (comparison > 0) .upgrade else if (comparison < 0) .downgrade else .reinstall;
    }

    var package_size: ?u64 = null;
    var sha256: ?[64]u8 = null;
    var repository: ?RepositoryIdentity = null;
    var plan_origin: ?PlanOrigin = null;
    var installed_size: u64 = 0;
    var source_name: []const u8 = undefined;
    var package_name: []const u8 = undefined;
    var version: []const u8 = undefined;
    var architecture: []const u8 = undefined;
    var essential = false;
    var has_pre_depends = false;
    if (origin) |available| {
        const record = input.repositories[findRepositoryIndex(input.repositories, available.repository_id).?]
            .packages.records[available.record_index];
        package_name = record.control.package.text;
        version = record.control.version.value.original;
        architecture = record.control.architecture.text;
        essential = record.control.essential == true;
        has_pre_depends = record.control.pre_depends != null;
        package_size = record.transport.size.value;
        sha256 = hex32(record.transport.sha256.bytes);
        installed_size = record.control.installed_size orelse 0;
        source_name = if (record.control.source) |source_value| source_value.package.text else package_name;
        if (available.local_artifact) |artifact| {
            var owned_artifact = artifact;
            owned_artifact.package = try allocator.dupe(u8, artifact.package);
            owned_artifact.version = try allocator.dupe(u8, artifact.version);
            owned_artifact.architecture = try allocator.dupe(u8, artifact.architecture);
            owned_artifact.acquisition_url = try allocator.dupe(u8, artifact.acquisition_url);
            plan_origin = .{ .local_artifact = .{
                .evidence = owned_artifact,
                .solver_priority = available.repository_priority,
            } };
        } else {
            repository = .{
                .id = available.repository_id.bytes,
                .priority = available.repository_priority,
            };
            plan_origin = .{ .authenticated_repository = repository.? };
        }
    } else {
        const index = installed_index.?;
        const record = state.source_records[state.mappings[index].record_index];
        package_name = record.name.value;
        version = record.version.spelling.value;
        architecture = record.architecture.value;
        essential = record.essential == true;
        source_name = package_name;
    }
    const prior_bytes: i128 = if (prior) |value| @as(i128, @intCast(value.installed_size_kib orelse 0)) * 1024 else 0;
    const new_bytes: i128 = if (kind == .remove) 0 else @as(i128, @intCast(installed_size)) * 1024;
    return .{
        .kind = kind,
        .package = try allocator.dupe(u8, package_name),
        .version = try allocator.dupe(u8, version),
        .architecture = try allocator.dupe(u8, architecture),
        .repository = repository,
        .sha256 = sha256,
        .package_size = if (kind == .remove) null else package_size,
        .installed_size_delta_bytes = new_bytes - prior_bytes,
        .source_package = try allocator.dupe(u8, source_name),
        .prior_installed = prior,
        .requested = requestedIdentity(input.request, package_name, version, architecture),
        .reason = actionReason(context, solvable_id, kind, input, package_name, version, architecture),
        .essential = essential,
        .has_pre_depends = has_pre_depends,
        .selected_origin = if (origin) |available|
            try ownedPackageOrigin(allocator, available)
        else
            null,
        .origin = plan_origin,
    };
}

fn ownedPackageOrigin(
    allocator: std.mem.Allocator,
    available: *const OriginOwned,
) !PackageOrigin {
    if (available.local_artifact) |artifact| {
        var owned_artifact = artifact;
        owned_artifact.package = try allocator.dupe(u8, artifact.package);
        owned_artifact.version = try allocator.dupe(u8, artifact.version);
        owned_artifact.architecture = try allocator.dupe(u8, artifact.architecture);
        owned_artifact.acquisition_url = try allocator.dupe(u8, artifact.acquisition_url);
        return .{ .local_artifact = .{
            .evidence = owned_artifact,
            .solver_priority = available.repository_priority,
            .record_index = available.record_index,
            .source_location = try allocator.dupe(u8, available.source_location),
        } };
    }
    return .{ .authenticated_repository = .{
        .repository_id = available.repository_id,
        .repository_priority = available.repository_priority,
        .record_index = available.record_index,
        .package = try allocator.dupe(u8, available.package),
        .version = try allocator.dupe(u8, available.version),
        .architecture = try allocator.dupe(u8, available.architecture),
        .source_location = try allocator.dupe(u8, available.source_location),
    } };
}

fn isInstallOnly(input: PlanInput, name: []const u8, architecture: []const u8) bool {
    for (input.install_only) |identity| {
        if (sameIdentity(identity.name, identity.architecture, name, architecture)) return true;
    }
    return false;
}

fn ownedPrior(allocator: std.mem.Allocator, context: *Context, index: usize) !PriorInstalled {
    const state = internal(context);
    const record = state.source_records[state.mappings[index].record_index];
    return .{
        .package = try allocator.dupe(u8, record.name.value),
        .version = try allocator.dupe(u8, record.version.spelling.value),
        .architecture = try allocator.dupe(u8, record.architecture.value),
        .installed_size_kib = record.installed_size_kib,
    };
}

fn actionReason(
    context: *Context,
    solvable_id: libsolv.Id,
    kind: ActionKind,
    input: PlanInput,
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
) ActionReason {
    const state = internal(context);
    if (requestedIdentity(input.request, name, version, architecture))
        return if (kind == .upgrade or kind == .downgrade) .upgrade else .explicit_request;
    if (kind == .upgrade or kind == .downgrade) return .upgrade;
    var info: libsolv.Id = 0;
    const reason = libsolv.solver_describe_decision(state.solver, solvable_id, &info);
    if (reason == libsolv.SOLVER_REASON_WEAKDEP) return .recommends;
    if (kind == .remove) return .replacement;
    return .dependency;
}

fn selectorMatches(
    selector: PackageSelector,
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
) bool {
    if (!std.mem.eql(u8, selector.name, name)) return false;
    if (selector.version) |selected_version|
        if (!std.mem.eql(u8, selected_version, version)) return false;
    if (selector.architecture) |selected_architecture|
        if (!std.mem.eql(u8, selected_architecture, architecture) and
            !std.mem.eql(u8, architecture, "all")) return false;
    return true;
}

fn requestedIdentity(
    request: PlanRequest,
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
) bool {
    return switch (request) {
        .install, .remove, .reinstall => |selector| selectorMatches(selector, name, version, architecture),
        .upgrade => |selectors| blk: {
            for (selectors) |selector|
                if (selectorMatches(selector, name, version, architecture)) break :blk true;
            break :blk false;
        },
        .upgrade_all => false,
    };
}

fn summarizeActions(
    actions: []const PlanAction,
    download_bytes: u64,
    installed_size_delta_bytes: i128,
) PlanSummary {
    var summary: PlanSummary = .{
        .download_bytes = download_bytes,
        .installed_size_delta_bytes = installed_size_delta_bytes,
    };
    for (actions) |action| switch (action.kind) {
        .install => summary.installs += 1,
        .remove => summary.removals += 1,
        .upgrade => summary.upgrades += 1,
        .downgrade => summary.downgrades += 1,
        .reinstall => summary.reinstalls += 1,
    };
    return summary;
}

fn materializeOrdering(
    allocator: std.mem.Allocator,
    actions: []const PlanAction,
) ![]OrderedAction {
    var ordered: std.ArrayList(OrderedAction) = .empty;
    defer ordered.deinit(allocator);
    var bootstrap_root = false;
    for (actions) |action| {
        if (action.kind != .remove and action.essential and action.prior_installed == null) {
            bootstrap_root = true;
            break;
        }
    }
    for (actions) |action| {
        if (!bootstrap_root or action.kind == .remove or action.prior_installed != null) continue;
        try ordered.append(allocator, .{
            .sequence = ordered.items.len,
            .kind = .bootstrap_extract,
            .package = action.package,
            .version = action.version,
            .architecture = action.architecture,
        });
    }
    var pending_unpacks: usize = 0;
    var last_install: ?PlanAction = null;
    for (actions) |action| {
        if (action.kind == .remove) {
            try ordered.append(allocator, .{
                .sequence = ordered.items.len,
                .kind = .remove,
                .package = action.package,
                .version = action.version,
                .architecture = action.architecture,
            });
        } else {
            if (action.has_pre_depends and pending_unpacks != 0) {
                try ordered.append(allocator, .{
                    .sequence = ordered.items.len,
                    .kind = .configure_pending,
                    .package = action.package,
                    .version = action.version,
                    .architecture = action.architecture,
                });
                pending_unpacks = 0;
            }
            try ordered.append(allocator, .{
                .sequence = ordered.items.len,
                .kind = .unpack,
                .package = action.package,
                .version = action.version,
                .architecture = action.architecture,
            });
            pending_unpacks += 1;
            last_install = action;
        }
    }
    if (pending_unpacks != 0) {
        const action = last_install.?;
        try ordered.append(allocator, .{
            .sequence = ordered.items.len,
            .kind = .configure_pending,
            .package = action.package,
            .version = action.version,
            .architecture = action.architecture,
        });
    }
    return ordered.toOwnedSlice(allocator);
}

fn requestedRemoval(request: PlanRequest, context: *Context, solvable_id: libsolv.Id) bool {
    const selector = switch (request) {
        .remove => |value| value,
        else => return false,
    };
    const installed_index = findInstalledBySolvable(context, solvable_id) orelse return false;
    const state = internal(context);
    const record = state.source_records[state.mappings[installed_index].record_index];
    if (!std.mem.eql(u8, selector.name, record.name.value)) return false;
    if (selector.version) |version|
        if (!std.mem.eql(u8, version, record.version.spelling.value)) return false;
    if (selector.architecture) |architecture|
        if (!std.mem.eql(u8, architecture, record.architecture.value)) return false;
    return true;
}

fn findOrigin(state: *Internal, solvable_id: libsolv.Id) ?*const OriginOwned {
    for (state.origins.items) |*origin| if (origin.solvable_id == solvable_id) return origin;
    return null;
}

fn findRepositoryIndex(repositories: []const RepositoryInput, id: source.RepositoryId) ?usize {
    for (repositories, 0..) |repository, index|
        if (std.mem.eql(u8, repository.repository_id.slice(), id.slice())) return index;
    return null;
}

fn hex32(bytes: [32]u8) [64]u8 {
    const digits = "0123456789abcdef";
    var output: [64]u8 = undefined;
    for (bytes, 0..) |byte, index| {
        output[index * 2] = digits[byte >> 4];
        output[index * 2 + 1] = digits[byte & 0x0f];
    }
    return output;
}

fn lessAction(_: void, a: PlanAction, b: PlanAction) bool {
    const rank_a = @intFromEnum(a.kind);
    const rank_b = @intFromEnum(b.kind);
    if (rank_a != rank_b) return rank_a < rank_b;
    const name_order = std.mem.order(u8, a.package, b.package);
    if (name_order != .eq) return name_order == .lt;
    const arch_order = std.mem.order(u8, a.architecture, b.architecture);
    if (arch_order != .eq) return arch_order == .lt;
    const version_order = std.mem.order(u8, a.version, b.version);
    if (version_order != .eq) return version_order == .lt;
    if (a.repository != null and b.repository != null)
        return std.mem.order(u8, &a.repository.?.id, &b.repository.?.id) == .lt;
    return a.repository != null;
}

fn hasLocalArtifactAction(actions: []const PlanAction) bool {
    for (actions) |action| if (action.origin) |origin| switch (origin) {
        .authenticated_repository => {},
        .local_artifact => return true,
    };
    return false;
}

fn planActionMatchesLockV2(action: PlanAction, locked: exact_lock_v2.Package) bool {
    const origin = action.origin orelse return false;
    return switch (locked.origin) {
        .authenticated_repository => |repository| switch (origin) {
            .authenticated_repository => |observed| std.mem.eql(u8, &observed.id, &repository.repository_id),
            .local_artifact => false,
        },
        .local_artifact => |artifact| switch (origin) {
            .authenticated_repository => false,
            .local_artifact => |observed| package_origin.eqlLocalArtifact(observed.evidence, artifact),
        },
    };
}

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| {
        if (byte <= 0x1f) {
            switch (byte) {
                '\n' => try writer.writeAll("\\n"),
                '\r' => try writer.writeAll("\\r"),
                '\t' => try writer.writeAll("\\t"),
                else => try writer.print("\\u00{x:0>2}", .{byte}),
            }
        } else switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            else => try writer.writeByte(byte),
        }
    }
    try writer.writeByte('"');
}

fn writePlanJson(plan: Plan, writer: *std.Io.Writer) !void {
    try writer.print("{{\"schema_version\":{},\"target_architecture\":", .{plan.schema_version});
    try writeJsonString(writer, plan.target_architecture);
    try writer.writeAll(",\"mode\":");
    try writeJsonString(writer, @tagName(plan.mode));
    try writer.writeAll(",\"actions\":[");
    for (plan.actions, 0..) |action, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"kind\":");
        try writeJsonString(writer, @tagName(action.kind));
        try writer.writeAll(",\"package\":");
        try writeJsonString(writer, action.package);
        try writer.writeAll(",\"version\":");
        try writeJsonString(writer, action.version);
        try writer.writeAll(",\"architecture\":");
        try writeJsonString(writer, action.architecture);
        if (plan.schema_version == 2) {
            try writer.writeAll(",\"repository\":");
            if (action.repository) |repository| {
                try writer.writeAll("{\"id\":");
                try writeJsonString(writer, &repository.id);
                try writer.print(",\"priority\":{}}}", .{repository.priority});
            } else try writer.writeAll("null");
        } else {
            try writer.writeAll(",\"origin\":");
            if (action.origin) |origin| try writePlanOrigin(writer, origin) else try writer.writeAll("null");
        }
        try writer.writeAll(",\"sha256\":");
        if (action.sha256) |sha| try writeJsonString(writer, &sha) else try writer.writeAll("null");
        try writer.writeAll(",\"package_size\":");
        if (action.package_size) |size| try writer.print("{}", .{size}) else try writer.writeAll("null");
        try writer.print(",\"installed_size_delta_bytes\":{},\"source_package\":", .{action.installed_size_delta_bytes});
        try writeJsonString(writer, action.source_package);
        try writer.writeAll(",\"prior_installed\":");
        if (action.prior_installed) |prior| {
            try writer.writeAll("{\"package\":");
            try writeJsonString(writer, prior.package);
            try writer.writeAll(",\"version\":");
            try writeJsonString(writer, prior.version);
            try writer.writeAll(",\"architecture\":");
            try writeJsonString(writer, prior.architecture);
            try writer.writeAll(",\"installed_size_kib\":");
            if (prior.installed_size_kib) |size| try writer.print("{}", .{size}) else try writer.writeAll("null");
            try writer.writeByte('}');
        } else try writer.writeAll("null");
        try writer.print(",\"requested\":{}", .{action.requested});
        try writer.writeAll(",\"reason\":");
        try writeJsonString(writer, @tagName(action.reason));
        try writer.print(",\"essential\":{}", .{action.essential});
        try writer.print(",\"has_pre_depends\":{}", .{action.has_pre_depends});
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"ordered_actions\":[");
    for (plan.ordered_actions, 0..) |action, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{{\"sequence\":{},\"kind\":", .{action.sequence});
        try writeJsonString(writer, @tagName(action.kind));
        try writer.writeAll(",\"package\":");
        try writeJsonString(writer, action.package);
        try writer.writeAll(",\"version\":");
        try writeJsonString(writer, action.version);
        try writer.writeAll(",\"architecture\":");
        try writeJsonString(writer, action.architecture);
        try writer.writeByte('}');
    }
    try writer.print("],\"summary\":{{\"installs\":{},\"removals\":{},\"upgrades\":{},\"downgrades\":{},\"reinstalls\":{},\"download_bytes\":{},\"installed_size_delta_bytes\":{}}},\"download_bytes\":{},\"installed_size_delta_bytes\":{}}}", .{
        plan.summary.installs,
        plan.summary.removals,
        plan.summary.upgrades,
        plan.summary.downgrades,
        plan.summary.reinstalls,
        plan.summary.download_bytes,
        plan.summary.installed_size_delta_bytes,
        plan.download_bytes,
        plan.installed_size_delta_bytes,
    });
}

fn writePlanOrigin(writer: *std.Io.Writer, origin: PlanOrigin) !void {
    switch (origin) {
        .authenticated_repository => |repository| {
            try writer.writeAll("{\"type\":\"authenticated_repository\",\"id\":");
            try writeJsonString(writer, &repository.id);
            try writer.print(",\"priority\":{}}}", .{repository.priority});
        },
        .local_artifact => |local| {
            const artifact = local.evidence;
            const digest_hex = hex32(artifact.sha256);
            try writer.writeAll("{\"type\":\"local_artifact\",\"artifact_id\":");
            try writeJsonString(writer, &artifact.artifact_id);
            try writer.writeAll(",\"sha256\":");
            try writeJsonString(writer, &digest_hex);
            try writer.print(",\"size\":{},\"package\":{{\"name\":", .{artifact.size});
            try writeJsonString(writer, artifact.package);
            try writer.writeAll(",\"version\":");
            try writeJsonString(writer, artifact.version);
            try writer.writeAll(",\"architecture\":");
            try writeJsonString(writer, artifact.architecture);
            try writer.writeAll("},\"acquisition_url\":");
            try writeJsonString(writer, artifact.acquisition_url);
            try writer.writeAll(",\"trust_mode\":");
            try writeJsonString(writer, @tagName(artifact.trust_mode));
            try writer.print(",\"solver_priority\":{}}}", .{local.solver_priority});
        },
    }
}

fn writeFailureJson(failure: PlanFailure, writer: *std.Io.Writer) !void {
    try writer.print("{{\"schema_version\":{},\"problems\":[", .{failure.schema_version});
    for (failure.problems, 0..) |problem, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{{\"id\":{},\"kind\":", .{problem.id});
        try writeJsonString(writer, @tagName(problem.kind));
        try writer.writeAll(",\"package\":");
        if (problem.package) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
        try writer.writeAll(",\"dependency\":");
        if (problem.dependency) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
        try writer.writeAll(",\"detail\":");
        try writeJsonString(writer, problem.detail);
        try writer.writeAll(",\"candidate_rejections\":[");
        for (problem.candidate_rejections, 0..) |rejection, rejection_index| {
            if (rejection_index != 0) try writer.writeByte(',');
            try writer.writeAll("{\"package\":");
            try writeJsonString(writer, rejection.package);
            try writer.writeAll(",\"version\":");
            if (rejection.version) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
            try writer.writeAll(",\"architecture\":");
            if (rejection.architecture) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
            try writer.writeAll(",\"reason\":");
            try writeJsonString(writer, @tagName(rejection.reason));
            try writer.writeAll(",\"detail\":");
            try writeJsonString(writer, rejection.detail);
            try writer.writeByte('}');
        }
        try writer.writeAll("],\"related_problem_ids\":[");
        for (problem.related_problem_ids, 0..) |related, related_index| {
            if (related_index != 0) try writer.writeByte(',');
            try writer.print("{}", .{related});
        }
        try writer.writeByte(']');
        try writer.writeByte('}');
    }
    try writer.writeAll("]}");
}

const Classification = enum { installed, blocker, config_files, absent, malformed };

fn classify(status: dpkg_status.Status) Classification {
    if (status.error_state == .reinst_required) return .blocker;
    return switch (status.current) {
        .installed => switch (status.want) {
            .install, .hold => .installed,
            .deinstall, .purge => .blocker,
            .unknown => .malformed,
        },
        .half_installed, .unpacked, .half_configured, .triggers_awaited, .triggers_pending => .blocker,
        .config_files => switch (status.want) {
            .deinstall, .purge => .config_files,
            .install, .hold => .blocker,
            .unknown => .malformed,
        },
        .not_installed => switch (status.want) {
            .unknown, .deinstall, .purge => .absent,
            .install, .hold => .blocker,
        },
    };
}

fn blockerKind(status: dpkg_status.Status) BlockerKind {
    if (status.error_state == .reinst_required) return .repair_required;
    return switch (status.current) {
        .half_installed, .unpacked, .half_configured, .triggers_awaited, .triggers_pending => .incomplete_install,
        .not_installed, .config_files => .requested_but_absent,
        .installed => .pending_removal,
    };
}

fn architectureAllowed(architecture: []const u8, input: ImportInput) bool {
    if (std.mem.eql(u8, architecture, "all") or
        std.mem.eql(u8, architecture, input.native_architecture)) return true;
    for (input.foreign_architectures) |allowed| {
        if (std.mem.eql(u8, architecture, allowed)) return true;
    }
    return false;
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (!(std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-')) return false;
    }
    return true;
}

fn sameIdentity(a_name: []const u8, a_arch: []const u8, b_name: []const u8, b_arch: []const u8) bool {
    return std.mem.eql(u8, a_name, b_name) and std.mem.eql(u8, a_arch, b_arch);
}

fn findRecord(records: []const dpkg_status.Package, name: []const u8, architecture: []const u8) ?usize {
    for (records, 0..) |record, index| {
        if (sameIdentity(name, architecture, record.name.value, record.architecture.value)) return index;
    }
    return null;
}

fn findPolicy(policies: []const InstalledPolicy, name: []const u8, architecture: []const u8) ?InstalledPolicy {
    for (policies) |policy| {
        if (sameIdentity(name, architecture, policy.name, policy.architecture)) return policy;
    }
    return null;
}

fn internal(context: *Context) *Internal {
    return @ptrCast(@alignCast(context));
}

fn internalConst(context: *const Context) *const Internal {
    return @ptrCast(@alignCast(context));
}

fn recreateSolver(state: *Internal) error{PoolAllocationFailed}!void {
    const replacement = libsolv.solver_create(state.pool) orelse
        return error.PoolAllocationFailed;
    libsolv.solver_free(state.solver);
    state.solver = replacement;
}

fn stringId(pool: *libsolv.Pool, value: []const u8) libsolv.Id {
    return libsolv.pool_strn2id(pool, value.ptr, @intCast(value.len), 1);
}

fn addRelations(
    pool: *libsolv.Pool,
    repo: *libsolv.Repo,
    solvable: *allowzero libsolv.Solvable,
    record: dpkg_status.Package,
    target_architecture: []const u8,
) void {
    for (record.relations) |dependency| {
        switch (dependency.kind) {
            .pre_depends => for (dependency.relation.groups) |group| {
                solvable.*.requires = libsolv.repo_addid_dep(
                    repo,
                    solvable.*.requires,
                    groupId(pool, group),
                    libsolv.SOLVABLE_PREREQMARKER,
                );
            },
            .depends => for (dependency.relation.groups) |group| {
                solvable.*.requires = libsolv.repo_addid_dep(
                    repo,
                    solvable.*.requires,
                    groupId(pool, group),
                    -libsolv.SOLVABLE_PREREQMARKER,
                );
            },
            .recommends => for (dependency.relation.groups) |group| {
                solvable.*.recommends = libsolv.repo_addid_dep(repo, solvable.*.recommends, groupId(pool, group), 0);
            },
            .suggests => for (dependency.relation.groups) |group| {
                solvable.*.suggests = libsolv.repo_addid_dep(repo, solvable.*.suggests, groupId(pool, group), 0);
            },
            .enhances => for (dependency.relation.groups) |group| {
                solvable.*.enhances = libsolv.repo_addid_dep(repo, solvable.*.enhances, groupId(pool, group), 0);
            },
            .breaks, .conflicts => for (dependency.relation.groups) |group| {
                for (group.alternatives) |alternative| {
                    solvable.*.conflicts = libsolv.repo_addid_dep(repo, solvable.*.conflicts, alternativeId(pool, alternative), 0);
                }
            },
            .replaces => {},
            .provides => for (dependency.relation.groups) |group| {
                for (group.alternatives) |alternative| {
                    solvable.*.provides = libsolv.repo_addid_dep(repo, solvable.*.provides, alternativeId(pool, alternative), 0);
                }
            },
        }
    }
    addDebianObsoletes(
        pool,
        solvable,
        if (record.relation(.replaces)) |value| value.relation else null,
        if (record.relation(.conflicts)) |value| value.relation else null,
        target_architecture,
    );
}

fn groupId(pool: *libsolv.Pool, group: relation.DependencyGroup) libsolv.Id {
    var id = alternativeId(pool, group.alternatives[0]);
    for (group.alternatives[1..]) |alternative| {
        id = libsolv.pool_rel2id(pool, id, alternativeId(pool, alternative), libsolv.REL_OR, 1);
    }
    return id;
}

fn alternativeId(pool: *libsolv.Pool, alternative: relation.Alternative) libsolv.Id {
    var id = stringId(pool, alternative.package.name.text);
    if (alternative.package.architecture_qualifier) |qualifier| {
        if (std.mem.eql(u8, qualifier.text, "any")) {
            id = libsolv.pool_rel2id(pool, id, libsolv.ARCH_ANY, libsolv.REL_MULTIARCH, 1);
        } else {
            var buffer: [384]u8 = undefined;
            const qualified = std.fmt.bufPrint(&buffer, "{s}:{s}", .{
                alternative.package.name.text,
                qualifier.text,
            }) catch unreachable;
            id = stringId(pool, qualified);
        }
    }
    if (alternative.version) |constraint| {
        id = libsolv.pool_rel2id(
            pool,
            id,
            stringId(pool, constraint.version.text),
            versionFlags(constraint.operator),
            1,
        );
    }
    return id;
}

fn versionFlags(operator: relation.VersionOperator) c_int {
    return switch (operator) {
        .less_than => libsolv.REL_LT,
        .less_than_or_equal => libsolv.REL_LT | libsolv.REL_EQ,
        .equal => libsolv.REL_EQ,
        .greater_than_or_equal => libsolv.REL_GT | libsolv.REL_EQ,
        .greater_than => libsolv.REL_GT,
    };
}

const AvailableRelationTarget = enum {
    requires_pre,
    requires,
    recommends,
    provides,
    conflicts,
    obsoletes,
};

fn validateAvailableRecords(
    records: []const packages_index.PackageRecord,
    limits: Limits,
) AvailableImportError!void {
    for (records) |record| {
        var groups: usize = 0;
        var alternatives: usize = 0;
        inline for (.{
            record.control.pre_depends,
            record.control.depends,
            record.control.recommends,
            record.control.provides,
            record.control.conflicts,
            record.control.breaks,
            record.control.replaces,
        }) |value| {
            if (value) |relation_value| {
                groups = std.math.add(usize, groups, relation_value.value.groups.len) catch
                    return error.TooManyDependencyGroups;
                for (relation_value.value.groups) |group| {
                    alternatives = std.math.add(usize, alternatives, group.alternatives.len) catch
                        return error.TooManyDependencyAlternatives;
                }
            }
        }
        if (groups > limits.max_dependency_groups_per_package)
            return error.TooManyDependencyGroups;
        if (alternatives > limits.max_dependency_alternatives_per_package)
            return error.TooManyDependencyAlternatives;

        if (record.control.provides) |provides| {
            for (provides.value.groups) |group| {
                if (group.alternatives.len != 1)
                    return error.UnsupportedProvidesAlternative;
                if (group.alternatives[0].version) |version| {
                    if (version.operator != .equal)
                        return error.UnsupportedProvidesPredicate;
                }
            }
        }
    }
}

fn addAvailableRelation(
    pool: *libsolv.Pool,
    solvable: *allowzero libsolv.Solvable,
    value: ?@import("control_record.zig").RelationValue,
    target: AvailableRelationTarget,
    target_architecture: []const u8,
) void {
    const relation_value = value orelse return;
    for (relation_value.value.groups) |group| {
        const dependency = activeGroupId(pool, group, target_architecture) orelse continue;
        const key: libsolv.Id = switch (target) {
            .requires_pre, .requires => libsolv.SOLVABLE_REQUIRES,
            .recommends => libsolv.SOLVABLE_RECOMMENDS,
            .provides => libsolv.SOLVABLE_PROVIDES,
            .conflicts => libsolv.SOLVABLE_CONFLICTS,
            .obsoletes => libsolv.SOLVABLE_OBSOLETES,
        };
        const marker: libsolv.Id = switch (target) {
            .requires_pre => libsolv.SOLVABLE_PREREQMARKER,
            .requires => -libsolv.SOLVABLE_PREREQMARKER,
            else => 0,
        };
        libsolv.solvable_add_deparray(solvable, key, dependency, marker);
    }
}

fn activeGroupId(
    pool: *libsolv.Pool,
    group: relation.DependencyGroup,
    target_architecture: []const u8,
) ?libsolv.Id {
    var result: ?libsolv.Id = null;
    for (group.alternatives) |alternative| {
        if (!alternativeActive(alternative, target_architecture)) continue;
        const id = alternativeIdForArchitecture(pool, alternative, target_architecture);
        result = if (result) |current|
            libsolv.pool_rel2id(pool, current, id, libsolv.REL_OR, 1)
        else
            id;
    }
    return result;
}

fn alternativeActive(alternative: relation.Alternative, architecture: []const u8) bool {
    if (alternative.restrictions.architectures) |list| {
        var has_positive = false;
        var positive_match = false;
        for (list.restrictions) |restriction| {
            const matches = architectureRestrictionMatches(restriction.name.text, architecture);
            if (restriction.negated) {
                if (matches) return false;
            } else {
                has_positive = true;
                positive_match = positive_match or matches;
            }
        }
        if (has_positive and !positive_match) return false;
    }
    if (alternative.restrictions.build_profiles.len != 0) {
        for (alternative.restrictions.build_profiles) |list| {
            var list_matches = true;
            for (list.restrictions) |restriction| {
                // Binary transactions have an explicit empty active-profile set.
                list_matches = list_matches and restriction.negated;
            }
            if (list_matches) return true;
        }
        return false;
    }
    return true;
}

fn architectureRestrictionMatches(restriction: []const u8, architecture: []const u8) bool {
    if (std.mem.eql(u8, restriction, "any")) return true;
    if (std.mem.eql(u8, restriction, architecture)) return true;
    if (std.mem.endsWith(u8, restriction, "-any")) {
        const prefix = restriction[0 .. restriction.len - 4];
        if (std.mem.eql(u8, prefix, "linux"))
            return std.mem.indexOfScalar(u8, architecture, '-') == null or
                std.mem.startsWith(u8, architecture, "linux-");
        return std.mem.startsWith(u8, architecture, prefix) and
            architecture.len > prefix.len and architecture[prefix.len] == '-';
    }
    if (std.mem.startsWith(u8, restriction, "any-")) {
        const suffix = restriction[4..];
        return std.mem.endsWith(u8, architecture, suffix);
    }
    return false;
}

fn alternativeIdForArchitecture(
    pool: *libsolv.Pool,
    alternative: relation.Alternative,
    target_architecture: []const u8,
) libsolv.Id {
    if (alternative.package.architecture_qualifier) |qualifier| {
        if (std.mem.eql(u8, qualifier.text, "native")) {
            var adjusted = alternative;
            adjusted.package.architecture_qualifier = .{
                .text = target_architecture,
                .span = qualifier.span,
            };
            return alternativeId(pool, adjusted);
        }
    }
    return alternativeId(pool, alternative);
}

fn addDebianObsoletes(
    pool: *libsolv.Pool,
    solvable: *allowzero libsolv.Solvable,
    replaces: ?relation.Relation,
    conflicts: ?relation.Relation,
    target_architecture: []const u8,
) void {
    const replace_relation = replaces orelse return;
    const conflict_relation = conflicts orelse return;
    for (replace_relation.groups) |replace_group| {
        for (replace_group.alternatives) |replace| {
            if (!alternativeActive(replace, target_architecture)) continue;
            for (conflict_relation.groups) |conflict_group| {
                for (conflict_group.alternatives) |conflict| {
                    if (!alternativeActive(conflict, target_architecture) or
                        !samePackageReference(replace.package, conflict.package, target_architecture))
                        continue;
                    const replace_id = alternativeIdForArchitecture(pool, replace, target_architecture);
                    const conflict_id = alternativeIdForArchitecture(pool, conflict, target_architecture);
                    const obsolete = if (replace_id == conflict_id)
                        replace_id
                    else
                        libsolv.pool_rel2id(pool, replace_id, conflict_id, libsolv.REL_AND, 1);
                    libsolv.solvable_add_deparray(solvable, libsolv.SOLVABLE_OBSOLETES, obsolete, 0);
                }
            }
        }
    }
}

fn samePackageReference(
    left: relation.PackageReference,
    right: relation.PackageReference,
    target_architecture: []const u8,
) bool {
    if (!std.mem.eql(u8, left.name.text, right.name.text)) return false;
    const left_architecture = normalizedQualifier(left.architecture_qualifier, target_architecture);
    const right_architecture = normalizedQualifier(right.architecture_qualifier, target_architecture);
    if (left_architecture == null or right_architecture == null)
        return left_architecture == null and right_architecture == null;
    return std.mem.eql(u8, left_architecture.?, right_architecture.?);
}

fn normalizedQualifier(
    qualifier: ?relation.Token,
    target_architecture: []const u8,
) ?[]const u8 {
    const value = qualifier orelse return null;
    return if (std.mem.eql(u8, value.text, "native")) target_architecture else value.text;
}

fn setMultiArch(repo: *libsolv.Repo, solvable_id: libsolv.Id, value: anytype) void {
    const multi_arch = value orelse return;
    const text: [*:0]const u8 = switch (multi_arch) {
        .no => "no",
        .same => "same",
        .foreign => "foreign",
        .allowed => "allowed",
    };
    libsolv.repo_set_str(repo, solvable_id, libsolv.SOLVABLE_MULTIARCH, text);
}

fn addQualifiedSelfProvide(
    pool: *libsolv.Pool,
    repo: *libsolv.Repo,
    solvable: *allowzero libsolv.Solvable,
    name: []const u8,
    architecture: []const u8,
) void {
    var buffer: [384]u8 = undefined;
    const qualified = std.fmt.bufPrint(&buffer, "{s}:{s}", .{ name, architecture }) catch return;
    const provide = libsolv.pool_rel2id(
        pool,
        stringId(pool, qualified),
        solvable.*.evr,
        libsolv.REL_EQ,
        1,
    );
    solvable.*.provides = libsolv.repo_addid_dep(repo, solvable.*.provides, provide, 0);
}

fn parsedDatabase(input_bytes: []const u8) !dpkg_status.Database {
    const result = try dpkg_status.parseBorrowed(std.testing.allocator, input_bytes, .{});
    return switch (result) {
        .database => |database| database,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
}

test "context pool uses Debian version semantics" {
    const context = try Context.createWithAllocator(std.testing.allocator);
    defer context.destroy();

    const pool = internal(context).pool;
    try std.testing.expectEqual(@as(c_int, libsolv.DISTTYPE_DEB), pool.*.disttype);
    try std.testing.expect(libsolv.pool_evrcmp_str(pool, "1+1", "1.1", libsolv.EVRCMP_COMPARE) < 0);
}

test "installed records preserve dependencies, provides, conflicts, and source mapping" {
    var database = try parsedDatabase(
        "Package: provider\nVersion: 2\nArchitecture: amd64\nStatus: install ok installed\nProvides: virtual-api (= 2)\n\n" ++
            "Package: consumer\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\nPre-Depends: bootstrap\nDepends: virtual-api (>= 2) | fallback\nConflicts: obsolete-api\n",
    );
    defer database.deinit();
    const policies = [_]InstalledPolicy{
        .{ .name = "provider", .architecture = "amd64", .install_reason = .automatic },
        .{ .name = "consumer", .architecture = "amd64", .install_reason = .manual },
    };
    const context = try Context.createWithAllocator(std.testing.allocator);
    defer context.destroy();
    const result = try context.importInstalled(.{
        .records = database.packages,
        .native_architecture = "amd64",
        .policies = &policies,
    });
    try std.testing.expectEqual(@as(usize, 2), result.imported.installed);
    try std.testing.expectEqualStrings("consumer", context.installedRecord(1).name.value);

    const state = internal(context);
    const consumer = &state.pool.*.solvables[@intCast(state.mappings[1].solvable_id)];
    try std.testing.expect(consumer.*.requires != 0);
    try std.testing.expect(consumer.*.conflicts != 0);
    var dependency_offset = consumer.*.requires;
    var saw_prerequisite_marker = false;
    while (state.installed_repo.?.*.idarraydata[dependency_offset] != 0) : (dependency_offset += 1) {
        if (state.installed_repo.?.*.idarraydata[dependency_offset] == libsolv.SOLVABLE_PREREQMARKER)
            saw_prerequisite_marker = true;
    }
    try std.testing.expect(saw_prerequisite_marker);
    const provider = &state.pool.*.solvables[@intCast(state.mappings[0].solvable_id)];
    try std.testing.expect(provider.*.provides != 0);
    const virtual_requirement = libsolv.pool_rel2id(
        state.pool,
        stringId(state.pool, "virtual-api"),
        stringId(state.pool, "2"),
        libsolv.REL_GT | libsolv.REL_EQ,
        1,
    );
    const providers = libsolv.pool_whatprovides_ptr(state.pool, virtual_requirement);
    try std.testing.expectEqual(state.mappings[0].solvable_id, providers[0]);
}

test "installed versions support upgrade and downgrade comparisons without closure locks" {
    var database = try parsedDatabase(
        "Package: app\nVersion: 2.0-1\nArchitecture: amd64\nStatus: install ok installed\n",
    );
    defer database.deinit();
    const policies = [_]InstalledPolicy{
        .{ .name = "app", .architecture = "amd64", .install_reason = .manual },
    };
    const context = try Context.createWithAllocator(std.testing.allocator);
    defer context.destroy();
    _ = try context.importInstalled(.{
        .records = database.packages,
        .native_architecture = "amd64",
        .policies = &policies,
    });
    try std.testing.expectEqual(std.math.Order.lt, context.compareInstalledVersion(0, "3.0"));
    try std.testing.expectEqual(std.math.Order.gt, context.compareInstalledVersion(0, "1.0"));
    try std.testing.expectEqual(@as(c_int, 0), internal(context).pool.*.pooljobs.count);
}

test "essential protected held and install reason remain policy metadata" {
    var database = try parsedDatabase(
        "Package: base\nVersion: 1\nArchitecture: amd64\nStatus: hold ok installed\nEssential: yes\nProtected: yes\n",
    );
    defer database.deinit();
    const policies = [_]InstalledPolicy{
        .{ .name = "base", .architecture = "amd64", .install_reason = .automatic },
    };
    const context = try Context.createWithAllocator(std.testing.allocator);
    defer context.destroy();
    _ = try context.importInstalled(.{
        .records = database.packages,
        .native_architecture = "amd64",
        .policies = &policies,
    });
    const metadata = context.installedMetadata(0);
    try std.testing.expectEqual(true, metadata.essential.?);
    try std.testing.expectEqual(true, metadata.protected.?);
    try std.testing.expect(metadata.held);
    try std.testing.expectEqual(InstallReason.automatic, metadata.install_reason);
    try std.testing.expectEqual(@as(c_int, 0), internal(context).pool.*.pooljobs.count);
}

test "explicit hold authority is required when status is not authoritative" {
    var database = try parsedDatabase(
        "Package: app\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n",
    );
    defer database.deinit();
    const missing = [_]InstalledPolicy{
        .{ .name = "app", .architecture = "amd64", .install_reason = .manual },
    };
    const context = try Context.createWithAllocator(std.testing.allocator);
    defer context.destroy();
    const failed = try context.importInstalled(.{
        .records = database.packages,
        .native_architecture = "amd64",
        .policies = &missing,
        .hold_authority = .explicit_policy,
    });
    try std.testing.expectEqual(DiagnosticCode.missing_explicit_hold, failed.diagnostic.code);
    try std.testing.expectEqual(@as(usize, 0), context.installedCount());

    const explicit = [_]InstalledPolicy{
        .{ .name = "app", .architecture = "amd64", .install_reason = .manual, .held = true },
    };
    _ = try context.importInstalled(.{
        .records = database.packages,
        .native_architecture = "amd64",
        .policies = &explicit,
        .hold_authority = .explicit_policy,
    });
    try std.testing.expect(context.installedMetadata(0).held);
}

test "broken states block while config-files and absent records are explicit" {
    var database = try parsedDatabase(
        "Package: half\nVersion: 1\nArchitecture: amd64\nStatus: install ok unpacked\n\n" ++
            "Package: trigger\nVersion: 1\nArchitecture: amd64\nStatus: install ok triggers-pending\n\n" ++
            "Package: repair\nVersion: 1\nArchitecture: amd64\nStatus: install reinstreq installed\n\n" ++
            "Package: config\nVersion: 1\nArchitecture: amd64\nStatus: deinstall ok config-files\n\n" ++
            "Package: gone\nVersion: 1\nArchitecture: amd64\nStatus: unknown ok not-installed\n",
    );
    defer database.deinit();
    const context = try Context.createWithAllocator(std.testing.allocator);
    defer context.destroy();
    const result = try context.importInstalled(.{
        .records = database.packages,
        .native_architecture = "amd64",
        .policies = &.{},
    });
    try std.testing.expectEqual(@as(usize, 3), result.imported.blockers);
    try std.testing.expectEqual(@as(usize, 1), result.imported.config_files_only);
    try std.testing.expectEqual(@as(usize, 1), result.imported.absent);
    try std.testing.expectEqual(BlockerKind.incomplete_install, context.blocker(0).kind);
    try std.testing.expectEqual(BlockerKind.repair_required, context.blocker(2).kind);
}

test "multiarch identities import independently and incompatible architectures fail cleanly" {
    var database = try parsedDatabase(
        "Package: library\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\nMulti-Arch: same\n\n" ++
            "Package: library\nVersion: 1\nArchitecture: arm64\nStatus: install ok installed\nMulti-Arch: same\n",
    );
    defer database.deinit();
    const policies = [_]InstalledPolicy{
        .{ .name = "library", .architecture = "amd64", .install_reason = .automatic },
        .{ .name = "library", .architecture = "arm64", .install_reason = .automatic },
    };
    const context = try Context.createWithAllocator(std.testing.allocator);
    defer context.destroy();
    const failed = try context.importInstalled(.{
        .records = database.packages,
        .native_architecture = "amd64",
        .policies = &policies,
    });
    try std.testing.expectEqual(DiagnosticCode.incompatible_architecture, failed.diagnostic.code);
    try std.testing.expectEqual(@as(usize, 0), context.installedCount());

    const result = try context.importInstalled(.{
        .records = database.packages,
        .native_architecture = "amd64",
        .foreign_architectures = &.{"arm64"},
        .policies = &policies,
    });
    try std.testing.expectEqual(@as(usize, 2), result.imported.installed);
    try std.testing.expectEqualStrings("amd64", context.installedRecord(0).architecture.value);
    try std.testing.expectEqualStrings("arm64", context.installedRecord(1).architecture.value);
}

test "duplicate identities and malformed states fail before repository mutation" {
    var database = try parsedDatabase(
        "Package: app\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n",
    );
    defer database.deinit();
    var duplicate = [_]dpkg_status.Package{ database.packages[0], database.packages[0] };
    const policy = [_]InstalledPolicy{
        .{ .name = "app", .architecture = "amd64", .install_reason = .manual },
    };
    const context = try Context.createWithAllocator(std.testing.allocator);
    defer context.destroy();
    const duplicate_result = try context.importInstalled(.{
        .records = &duplicate,
        .native_architecture = "amd64",
        .policies = &policy,
    });
    try std.testing.expectEqual(DiagnosticCode.duplicate_identity, duplicate_result.diagnostic.code);
    try std.testing.expect(internal(context).installed_repo == null);

    duplicate[0].status.want = .unknown;
    const malformed_result = try context.importInstalled(.{
        .records = duplicate[0..1],
        .native_architecture = "amd64",
        .policies = &policy,
    });
    try std.testing.expectEqual(DiagnosticCode.malformed_state, malformed_result.diagnostic.code);
    try std.testing.expect(internal(context).installed_repo == null);
}

fn testRepositoryId(byte: u8) source.RepositoryId {
    return .{ .bytes = @splat(byte) };
}

fn availableIndex(
    id: source.RepositoryId,
    text: []const u8,
) !packages_index.Index {
    return availableIndexForArchitecture(id, "amd64", text);
}

fn availableIndexForArchitecture(
    id: source.RepositoryId,
    architecture: []const u8,
    text: []const u8,
) !packages_index.Index {
    const result = try packages_index.parseBorrowed(std.testing.allocator, text, .{
        .repository_id = id,
        .component = "main",
        .architecture = architecture,
        .source_location = "test/Packages",
    }, .{});
    return switch (result) {
        .index => |index| index,
        .diagnostic => return error.UnexpectedPackagesDiagnostic,
    };
}

fn solveAvailable(context: *Context, name: []const u8) ![]PackageOrigin {
    const state = internal(context);
    try recreateSolver(state);
    var job: libsolv.Queue = undefined;
    libsolv.queue_init(&job);
    defer libsolv.queue_free(&job);
    libsolv.queue_push2(
        &job,
        libsolv.SOLVER_INSTALL | libsolv.SOLVER_SOLVABLE_NAME,
        stringId(state.pool, name),
    );
    if (libsolv.solver_solve(state.solver, &job) != 0) return error.Unsolvable;

    var selected: std.ArrayList(PackageOrigin) = .empty;
    defer selected.deinit(std.testing.allocator);
    for (state.origins.items) |*origin| {
        if (libsolv.solver_get_decisionlevel(state.solver, origin.solvable_id) > 0)
            try selected.append(std.testing.allocator, origin.public());
    }
    return selected.toOwnedSlice(std.testing.allocator);
}

fn hasSelected(selected: []const PackageOrigin, name: []const u8) bool {
    for (selected) |origin| {
        const package = switch (origin) {
            .authenticated_repository => |repository| repository.package,
            .local_artifact => |artifact| artifact.evidence.package,
        };
        if (std.mem.eql(u8, package, name)) return true;
    }
    return false;
}

fn hasAction(actions: []const PlanAction, name: []const u8) bool {
    for (actions) |action| {
        if (std.mem.eql(u8, action.package, name) and action.kind != .remove) return true;
    }
    return false;
}

fn minimizedUbuntuMetadata(allocator: std.mem.Allocator, architecture: []const u8) ![]u8 {
    const hash = "1111111111111111111111111111111111111111111111111111111111111111";
    return std.fmt.allocPrint(
        allocator,
        "Package: ubuntu-minimal\nVersion: 1.570\nArchitecture: {s}\nDepends: apt, python3:any, sudo, sudo-rs\nFilename: pool/ubuntu-minimal.deb\nSize: 1\nSHA256: {s}\n\n" ++
            "Package: apt\nVersion: 3.2.0\nArchitecture: {s}\nProvides: apt-transport-https (= 3.2.0)\nDepends: base-passwd, gpgv, libapt-pkg7.0 (>= 3.2.0), libc6 (>= 2.38)\nReplaces: apt-transport-https (<< 1.5~)\nFilename: pool/apt.deb\nSize: 1\nSHA256: {s}\n\n" ++
            "Package: base-files\nVersion: 14ubuntu1\nArchitecture: {s}\nEssential: yes\nPre-Depends: libc6 (>= 2.38)\nFilename: pool/base-files.deb\nSize: 1\nSHA256: {s}\n\n" ++
            "Package: base-passwd\nVersion: 3.6.8\nArchitecture: {s}\nEssential: yes\nPre-Depends: libc6 (>= 2.38)\nFilename: pool/base-passwd.deb\nSize: 1\nSHA256: {s}\n\n" ++
            "Package: gpgv\nVersion: 2.4.8\nArchitecture: {s}\nMulti-Arch: foreign\nDepends: libc6 (>= 2.38)\nFilename: pool/gpgv.deb\nSize: 1\nSHA256: {s}\n\n" ++
            "Package: libapt-pkg7.0\nVersion: 3.2.0\nArchitecture: {s}\nMulti-Arch: same\nProvides: libapt-pkg (= 3.2.0)\nDepends: libc6 (>= 2.38)\nFilename: pool/libapt-pkg.deb\nSize: 1\nSHA256: {s}\n\n" ++
            "Package: libc6\nVersion: 2.43\nArchitecture: {s}\nEssential: yes\nMulti-Arch: same\nFilename: pool/libc6.deb\nSize: 1\nSHA256: {s}\n\n" ++
            "Package: python3\nVersion: 3.14\nArchitecture: {s}\nMulti-Arch: allowed\nDepends: libc6 (>= 2.38)\nFilename: pool/python3.deb\nSize: 1\nSHA256: {s}\n\n" ++
            "Package: sudo\nVersion: 1.9.17\nArchitecture: {s}\nPre-Depends: sudo-common\nDepends: libc6 (>= 2.38)\nRecommends: sudo-rs\nConflicts: sudo-ldap\nReplaces: sudo-ldap\nFilename: pool/sudo.deb\nSize: 1\nSHA256: {s}\n\n" ++
            "Package: sudo-common\nVersion: 1.2ubuntu\nArchitecture: all\nBreaks: sudo (<< 1.9.16)\nReplaces: sudo (<< 1.9.16)\nFilename: pool/sudo-common.deb\nSize: 1\nSHA256: {s}\n\n" ++
            "Package: sudo-rs\nVersion: 0.2.13\nArchitecture: {s}\nDepends: python3:any, sudo-common, libc6 (>= 2.38)\nFilename: pool/sudo-rs.deb\nSize: 1\nSHA256: {s}\n",
        .{
            architecture, hash,
            architecture, hash,
            architecture, hash,
            architecture, hash,
            architecture, hash,
            architecture, hash,
            architecture, hash,
            architecture, hash,
            architecture, hash,
            hash,         architecture,
            hash,
        },
    );
}

test "available import requires explicit trust and owns identities" {
    const text =
        "Package: base\nVersion: 1:2.0-3\nArchitecture: amd64\nFilename: pool/base.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n";
    const id = testRepositoryId('a');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const context = try Context.createForArchitecture(std.testing.allocator, "amd64");
    defer context.destroy();

    var input = RepositoryInput.trustedTest(id, 500, &index);
    input.eligibility = .untrusted;
    try std.testing.expectError(error.UntrustedRepository, context.importAvailable(input, .{}));
    try context.importAvailable(RepositoryInput.trustedTest(id, 500, &index), .{});
    const origin = switch (context.originAt(0).?) {
        .authenticated_repository => |value| value,
        .local_artifact => unreachable,
    };
    try std.testing.expectEqualStrings("base", origin.package);
    try std.testing.expectEqualStrings("1:2.0-3", origin.version);
    try std.testing.expectEqualStrings("amd64", origin.architecture);
    try std.testing.expectEqual(@as(i32, 500), origin.repository_priority);
}

test "available solve handles alternatives and versioned provides" {
    const text =
        "Package: root\nVersion: 1\nArchitecture: amd64\nDepends: missing | virtual-api (>= 2)\nFilename: pool/root.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n" ++
        "Package: old-provider\nVersion: 1\nArchitecture: amd64\nProvides: virtual-api (= 1)\nFilename: pool/old.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n" ++
        "Package: new-provider\nVersion: 1\nArchitecture: amd64\nProvides: virtual-api (= 2)\nFilename: pool/new.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n";
    const id = testRepositoryId('b');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const context = try Context.createForArchitecture(std.testing.allocator, "amd64");
    defer context.destroy();
    try context.importAvailable(RepositoryInput.trustedTest(id, 500, &index), .{});

    const selected = try solveAvailable(context, "root");
    defer std.testing.allocator.free(selected);
    try std.testing.expect(hasSelected(selected, "new-provider"));
    try std.testing.expect(!hasSelected(selected, "old-provider"));
}

test "available solve enforces pre-depends conflicts breaks and replaces" {
    const text =
        "Package: root\nVersion: 1\nArchitecture: amd64\nPre-Depends: new\nDepends: old\nFilename: pool/root.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n" ++
        "Package: old\nVersion: 1\nArchitecture: amd64\nFilename: pool/old.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n" ++
        "Package: new\nVersion: 2\nArchitecture: amd64\nConflicts: old\nBreaks: old (<= 1)\nReplaces: old (<= 1)\nFilename: pool/new.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n";
    const id = testRepositoryId('c');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const context = try Context.createForArchitecture(std.testing.allocator, "amd64");
    defer context.destroy();
    try context.importAvailable(RepositoryInput.trustedTest(id, 500, &index), .{});

    try std.testing.expectError(error.Unsolvable, solveAvailable(context, "root"));
    const state = internal(context);
    var replacement_id: libsolv.Id = 0;
    for (state.origins.items) |origin| {
        if (std.mem.eql(u8, origin.package, "new")) replacement_id = origin.solvable_id;
    }
    const replacement = libsolv.pool_id2solvable(state.pool, replacement_id);
    try std.testing.expect(replacement.*.obsoletes != 0);
}

test "Debian Replaces without Conflicts does not obsolete packages" {
    const text =
        "Package: common\nVersion: 2\nArchitecture: all\nBreaks: app (<< 2)\nReplaces: app (<< 2)\nFilename: pool/common.deb\nSize: 1\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n\n" ++
        "Package: app\nVersion: 2\nArchitecture: amd64\nFilename: pool/app.deb\nSize: 1\n" ++
        "SHA256: 2222222222222222222222222222222222222222222222222222222222222222\n";
    const id = testRepositoryId('r');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const context = try Context.createForArchitecture(std.testing.allocator, "amd64");
    defer context.destroy();
    try context.importAvailable(RepositoryInput.trustedTest(id, 500, &index), .{});
    for (internal(context).origins.items) |origin| {
        if (!std.mem.eql(u8, origin.package, "common")) continue;
        const package = libsolv.pool_id2solvable(internal(context).pool, origin.solvable_id);
        try std.testing.expectEqual(@as(libsolv.Offset, 0), package.*.obsoletes);
    }
}

test "architecture all and recommends retain distinct solver semantics" {
    const text =
        "Package: root\nVersion: 1\nArchitecture: amd64\nDepends: data\nRecommends: optional\nFilename: pool/root.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n" ++
        "Package: data\nVersion: 1\nArchitecture: all\nFilename: pool/data.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n" ++
        "Package: optional\nVersion: 1\nArchitecture: amd64\nFilename: pool/optional.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n";
    const id = testRepositoryId('d');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const context = try Context.createForArchitecture(std.testing.allocator, "amd64");
    defer context.destroy();
    try context.importAvailable(RepositoryInput.trustedTest(id, 500, &index), .{});

    const selected = try solveAvailable(context, "root");
    defer std.testing.allocator.free(selected);
    try std.testing.expect(hasSelected(selected, "data"));
    var root_id: libsolv.Id = 0;
    for (internal(context).origins.items) |origin| {
        if (std.mem.eql(u8, origin.package, "root")) root_id = origin.solvable_id;
    }
    const root = libsolv.pool_id2solvable(internal(context).pool, root_id);
    try std.testing.expect(root.*.requires != 0);
    try std.testing.expect(root.*.recommends != 0);
}

test "repository priority gives stable provider ordering" {
    const low_text =
        "Package: low\nVersion: 1\nArchitecture: amd64\nProvides: virtual\nFilename: pool/low.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n";
    const high_text =
        "Package: high\nVersion: 1\nArchitecture: amd64\nProvides: virtual\nFilename: pool/high.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n";
    const root_text =
        "Package: root\nVersion: 1\nArchitecture: amd64\nDepends: virtual\nFilename: pool/root.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n";
    var low = try availableIndex(testRepositoryId('e'), low_text);
    defer low.deinit();
    var high = try availableIndex(testRepositoryId('f'), high_text);
    defer high.deinit();
    var root = try availableIndex(testRepositoryId('g'), root_text);
    defer root.deinit();
    const context = try Context.createForArchitecture(std.testing.allocator, "amd64");
    defer context.destroy();
    try context.importAvailable(RepositoryInput.trustedTest(testRepositoryId('e'), 100, &low), .{});
    try context.importAvailable(RepositoryInput.trustedTest(testRepositoryId('f'), 900, &high), .{});
    try context.importAvailable(RepositoryInput.trustedTest(testRepositoryId('g'), 500, &root), .{});

    const selected = try solveAvailable(context, "root");
    defer std.testing.allocator.free(selected);
    try std.testing.expect(hasSelected(selected, "high"));
    try std.testing.expect(!hasSelected(selected, "low"));
}

test "available relations support any architecture qualifier and Multi-Arch metadata" {
    const text =
        "Package: root\nVersion: 1\nArchitecture: amd64\nDepends: helper:any\nFilename: pool/root.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n" ++
        "Package: helper\nVersion: 1\nArchitecture: amd64\nMulti-Arch: allowed\nFilename: pool/helper.deb\nSize: 1\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n";
    const id = testRepositoryId('h');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const context = try Context.createForArchitecture(std.testing.allocator, "amd64");
    defer context.destroy();
    try context.importAvailable(RepositoryInput.trustedTest(id, 500, &index), .{});
    const selected = try solveAvailable(context, "root");
    defer std.testing.allocator.free(selected);
    try std.testing.expect(hasSelected(selected, "helper"));
}

test "all Multi-Arch modes are preserved at the opaque libsolv boundary" {
    const text =
        "Package: mode-no\nVersion: 1\nArchitecture: amd64\nMulti-Arch: no\nFilename: pool/no.deb\nSize: 1\nSHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n" ++
        "Package: mode-same\nVersion: 1\nArchitecture: amd64\nMulti-Arch: same\nFilename: pool/same.deb\nSize: 1\nSHA256: 1111111111111111111111111111111111111111111111111111111111111111\n\n" ++
        "Package: mode-foreign\nVersion: 1\nArchitecture: amd64\nMulti-Arch: foreign\nFilename: pool/foreign.deb\nSize: 1\nSHA256: 2222222222222222222222222222222222222222222222222222222222222222\n\n" ++
        "Package: mode-allowed\nVersion: 1\nArchitecture: amd64\nMulti-Arch: allowed\nFilename: pool/allowed.deb\nSize: 1\nSHA256: 3333333333333333333333333333333333333333333333333333333333333333\n";
    const id = testRepositoryId('t');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const context = try Context.createForArchitecture(std.testing.allocator, "amd64");
    defer context.destroy();
    try context.importAvailable(RepositoryInput.trustedTest(id, 500, &index), .{});
    const state = internal(context);
    for (state.origins.items) |origin| {
        const value = std.mem.span(libsolv.solvable_lookup_str(
            libsolv.pool_id2solvable(state.pool, origin.solvable_id),
            libsolv.SOLVABLE_MULTIARCH,
        ));
        const expected = origin.package["mode-".len..];
        try std.testing.expectEqualStrings(expected, value);
    }
}

test "planner materializes owned install closure and stable canonical JSON" {
    const text =
        "Package: app\nVersion: 2\nArchitecture: amd64\nProvides: app-virtual (= 2)\nDepends: lib\nInstalled-Size: 10\nSource: app-src (2)\nFilename: pool/app.deb\nSize: 20\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n\n" ++
        "Package: lib\nVersion: 1\nArchitecture: amd64\nEssential: yes\nInstalled-Size: 3\nFilename: pool/lib.deb\nSize: 7\n" ++
        "SHA256: 2222222222222222222222222222222222222222222222222222222222222222\n";
    const id = testRepositoryId('i');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const repositories = [_]RepositoryInput{RepositoryInput.trustedTest(id, 500, &index)};
    const result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "app" } },
    });
    var plan = result.plan;
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 2), plan.actions.len);
    try std.testing.expectEqualStrings("app", plan.actions[0].package);
    try std.testing.expectEqualStrings("lib", plan.actions[1].package);
    try std.testing.expectEqual(@as(u64, 27), plan.download_bytes);
    try std.testing.expectEqualStrings("lib", plan.ordered_actions[0].package);
    try std.testing.expectEqual(OrderedActionKind.bootstrap_extract, plan.ordered_actions[0].kind);
    try std.testing.expectEqualStrings("app", plan.ordered_actions[1].package);
    try std.testing.expectEqual(OrderedActionKind.bootstrap_extract, plan.ordered_actions[1].kind);
    try std.testing.expectEqual(OrderedActionKind.unpack, plan.ordered_actions[2].kind);
    try std.testing.expectEqual(OrderedActionKind.unpack, plan.ordered_actions[3].kind);
    try std.testing.expectEqualStrings("app", plan.ordered_actions[3].package);
    try std.testing.expectEqual(OrderedActionKind.configure_pending, plan.ordered_actions[4].kind);
    var saw_source = false;
    for (plan.actions) |action| {
        if (std.mem.eql(u8, action.package, "app")) {
            try std.testing.expectEqualStrings("app-src", action.source_package);
            saw_source = true;
        }
    }
    try std.testing.expect(saw_source);

    const first = try plan.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(first);
    const second = try plan.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualStrings(first, second);
    try std.testing.expect(std.mem.indexOf(u8, first, "\"schema_version\":2") != null);
}

test "solver.test.mixed authenticated repository and verified local artifact produce plan v3" {
    const repository_text =
        "Package: ca-certificates\nVersion: 1\nArchitecture: amd64\nFilename: pool/ca-certificates.deb\nSize: 7\n" ++
        "SHA256: 2222222222222222222222222222222222222222222222222222222222222222\n\n" ++
        "Package: installed-base\nVersion: 1\nArchitecture: amd64\nFilename: pool/installed-base.deb\nSize: 8\n" ++
        "SHA256: 8888888888888888888888888888888888888888888888888888888888888888\n";
    const repository_id = testRepositoryId('a');
    var repository_index = try availableIndex(repository_id, repository_text);
    defer repository_index.deinit();
    var repository = RepositoryInput.trustedTest(repository_id, 500, &repository_index);
    repository.eligibility = .verified_refresh;
    repository.authenticated_snapshot_sha256 = @splat(1);
    var database = try parsedDatabase(
        "Package: installed-base\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n",
    );
    defer database.deinit();
    const installed_policies = [_]InstalledPolicy{.{
        .name = "installed-base",
        .architecture = "amd64",
        .install_reason = .manual,
        .held = false,
    }};

    const local_text =
        "Package: vendor-repo\nVersion: 1.0\nArchitecture: amd64\nDepends: ca-certificates\nFilename: vendor-repo.deb\nSize: 42\n" ++
        "SHA256: 3333333333333333333333333333333333333333333333333333333333333333\n";
    const artifact_id = testRepositoryId('3');
    var local_index = try availableIndex(artifact_id, local_text);
    defer local_index.deinit();
    const artifact: package_origin.LocalArtifactEvidence = .{
        .artifact_id = artifact_id.bytes,
        .sha256 = @splat(0x33),
        .size = 42,
        .package = "vendor-repo",
        .version = "1.0",
        .architecture = "amd64",
        .acquisition_url = "https://example.test/vendor-repo.deb?REDACTED",
        .trust_mode = .verified_https,
    };
    const local = RepositoryInput.fromLocalArtifact(&local_index, 1000, artifact);
    const repositories = [_]RepositoryInput{ local, repository };
    const result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &installed_policies,
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "vendor-repo" } },
    });
    var plan = result.plan;
    defer plan.deinit();
    try std.testing.expectEqual(@as(u32, 3), plan.schema_version);
    try std.testing.expectEqual(@as(usize, 2), plan.actions.len);
    try std.testing.expectEqualStrings("ca-certificates", plan.actions[0].package);
    try std.testing.expectEqualStrings("vendor-repo", plan.actions[1].package);
    try std.testing.expect(plan.actions[0].repository != null);
    try std.testing.expect(plan.actions[1].repository == null);
    switch (plan.actions[1].origin.?) {
        .authenticated_repository => return error.TestExpectedLocalArtifact,
        .local_artifact => |origin| try std.testing.expect(
            package_origin.eqlLocalArtifact(origin.evidence, artifact),
        ),
    }
    const json = try plan.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(
        u8,
        json,
        "\"origin\":{\"type\":\"local_artifact\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"repository\":") == null);

    const locked_packages = [_]exact_lock_v2.Package{
        .{
            .name = "ca-certificates",
            .version = "1",
            .architecture = "amd64",
            .origin = .{ .authenticated_repository = .{
                .repository_id = repository_id.bytes,
                .repository_snapshot_sha256 = @splat(1),
            } },
            .sha256 = @splat(0x22),
            .declared_size = 7,
            .retention = .dependency,
            .dpkg_selection_hold = false,
        },
        .{
            .name = artifact.package,
            .version = artifact.version,
            .architecture = artifact.architecture,
            .origin = .{ .local_artifact = artifact },
            .sha256 = artifact.sha256,
            .declared_size = artifact.size,
            .retention = .requested,
            .dpkg_selection_hold = false,
        },
        .{
            .name = "installed-base",
            .version = "1",
            .architecture = "amd64",
            .origin = .{ .authenticated_repository = .{
                .repository_id = repository_id.bytes,
                .repository_snapshot_sha256 = @splat(1),
            } },
            .sha256 = @splat(0x88),
            .declared_size = 8,
            .retention = .retained,
            .dpkg_selection_hold = false,
        },
    };
    var lock = try exact_lock_v2.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(5),
        .policy_sha256 = @splat(6),
        .repositories = &.{.{
            .id = repository_id.bytes,
            .snapshot_sha256 = @splat(1),
            .release_sha256 = @splat(7),
            .index_sha256 = @splat(8),
            .signer_fingerprints = &.{@splat(9)},
        }},
        .local_artifacts = &.{artifact},
        .packages = &locked_packages,
        .verified_origins = true,
    });
    defer lock.deinit();
    const replay_result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &installed_policies,
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "vendor-repo" } },
        .exact_lock_v2 = &lock.lock,
    });
    var replay_plan = replay_result.plan;
    defer replay_plan.deinit();
    const replay_json = try replay_plan.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(replay_json);
    try std.testing.expectEqualStrings(json, replay_json);

    const reversed = [_]RepositoryInput{ repository, local };
    const reversed_result = try planTransaction(std.testing.allocator, .{
        .repositories = &reversed,
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &installed_policies,
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "vendor-repo" } },
    });
    var reversed_plan = reversed_result.plan;
    defer reversed_plan.deinit();
    const reversed_json = try reversed_plan.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(reversed_json);
    try std.testing.expectEqualStrings(json, reversed_json);

    var substituted = local;
    substituted.eligibility = .verified_refresh;
    substituted.authenticated_snapshot_sha256 = @splat(1);
    substituted.local_artifact = null;
    const substituted_repositories = [_]RepositoryInput{ substituted, repository };
    const substituted_result = try planTransaction(std.testing.allocator, .{
        .repositories = &substituted_repositories,
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &installed_policies,
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "vendor-repo" } },
        .exact_lock_v2 = &lock.lock,
    });
    var substitution_failure = substituted_result.failure;
    defer substitution_failure.deinit();
    try std.testing.expectEqual(
        ProblemKind.lock_package_mismatch,
        substitution_failure.problems[0].kind,
    );

    var forbidden = local;
    forbidden.eligibility = .trusted_test;
    const context = try Context.createForArchitecture(std.testing.allocator, "amd64");
    defer context.destroy();
    try std.testing.expectError(
        error.InvalidLocalArtifact,
        context.importAvailable(forbidden, .{}),
    );
}

test "solver.test.v1 exact lock replay remains repository-only schema v2" {
    const text =
        "Package: app\nVersion: 1\nArchitecture: amd64\nFilename: pool/app.deb\nSize: 5\n" ++
        "SHA256: 5555555555555555555555555555555555555555555555555555555555555555\n";
    const repository_id = testRepositoryId('a');
    var index = try availableIndex(repository_id, text);
    defer index.deinit();
    var repository = RepositoryInput.trustedTest(repository_id, 500, &index);
    repository.eligibility = .verified_refresh;
    repository.authenticated_snapshot_sha256 = @splat(1);
    const lock_repository: exact_lock_module.Repository = .{
        .id = repository_id.bytes,
        .snapshot_sha256 = @splat(1),
        .release_sha256 = @splat(2),
        .index_sha256 = @splat(3),
        .signer_fingerprints = &.{@splat(4)},
    };
    const lock_package: exact_lock_module.Package = .{
        .name = "app",
        .version = "1",
        .architecture = "amd64",
        .repository_id = repository_id.bytes,
        .repository_snapshot_sha256 = @splat(1),
        .sha256 = @splat(0x55),
        .declared_size = 5,
        .retention = .requested,
        .dpkg_selection_hold = false,
    };
    var lock = try exact_lock_module.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(6),
        .policy_sha256 = @splat(7),
        .repositories = &.{lock_repository},
        .packages = &.{lock_package},
        .authenticated_metadata = true,
    });
    defer lock.deinit();
    const result = try planTransaction(std.testing.allocator, .{
        .repositories = &.{repository},
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "app" } },
        .exact_lock = &lock.lock,
    });
    var plan = result.plan;
    defer plan.deinit();
    try std.testing.expectEqual(@as(u32, 2), plan.schema_version);
    try std.testing.expectEqual(@as(usize, 1), plan.actions.len);
    const json = try plan.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"repository\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"origin\":") == null);
}

test "planner installs a named package with Debian replacement metadata" {
    const text =
        "Package: apt\nVersion: 3.2.0\nArchitecture: amd64\nProvides: apt-transport-https (= 3.2.0)\nDepends: dep\nConflicts: old (<< 2)\nBreaks: older (<< 2)\nReplaces: apt-transport-https (<< 1.5~)\nFilename: pool/apt.deb\nSize: 2\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n\n" ++
        "Package: dep\nVersion: 1\nArchitecture: amd64\nFilename: pool/dep.deb\nSize: 1\n" ++
        "SHA256: 2222222222222222222222222222222222222222222222222222222222222222\n";
    const id = testRepositoryId('x');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const repositories = [_]RepositoryInput{RepositoryInput.trustedTest(id, 500, &index)};
    const result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "apt" } },
    });
    var plan = result.plan;
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 2), plan.actions.len);
}

test "real metadata facts produce ubuntu-minimal closures on native architectures" {
    for ([_][]const u8{ "amd64", "arm64" }) |architecture| {
        const text = try minimizedUbuntuMetadata(std.testing.allocator, architecture);
        defer std.testing.allocator.free(text);
        const id = testRepositoryId(if (std.mem.eql(u8, architecture, "amd64")) 'm' else 'n');
        var index = try availableIndexForArchitecture(id, architecture, text);
        defer index.deinit();
        const repositories = [_]RepositoryInput{RepositoryInput.trustedTest(id, 500, &index)};
        const result = try planTransaction(std.testing.allocator, .{
            .repositories = &repositories,
            .installed = .{
                .records = &.{},
                .native_architecture = architecture,
                .policies = &.{},
                .hold_authority = .explicit_policy,
            },
            .target_architecture = architecture,
            .request = .{ .install = .{ .name = "ubuntu-minimal" } },
        });
        var plan = result.plan;
        defer plan.deinit();
        try std.testing.expect(plan.actions.len != 0);
        try std.testing.expect(hasAction(plan.actions, "ubuntu-minimal"));
        try std.testing.expect(hasAction(plan.actions, "base-files"));
        try std.testing.expectEqual(OrderedActionKind.configure_pending, plan.ordered_actions[plan.ordered_actions.len - 1].kind);
        var saw_bootstrap = false;
        var saw_pre_depends_barrier = false;
        for (plan.ordered_actions, 0..) |ordered, ordered_index| {
            if (ordered.kind == .bootstrap_extract) saw_bootstrap = true;
            if (ordered.kind == .unpack and std.mem.eql(u8, ordered.package, "base-files")) {
                try std.testing.expect(ordered_index != 0);
                saw_pre_depends_barrier = plan.ordered_actions[ordered_index - 1].kind == .configure_pending;
            }
        }
        try std.testing.expect(saw_bootstrap);
        try std.testing.expect(saw_pre_depends_barrier);
    }
}

test "problem traces are range checked before libsolv materialization" {
    const text =
        "Package: root\nVersion: 1\nArchitecture: amd64\nDepends: absent\nFilename: pool/root.deb\nSize: 1\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n";
    const id = testRepositoryId('q');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const context = try Context.createForArchitecture(std.testing.allocator, "amd64");
    defer context.destroy();
    try context.importAvailable(RepositoryInput.trustedTest(id, 500, &index), .{});
    const state = internal(context);
    try recreateSolver(state);
    var jobs: libsolv.Queue = undefined;
    libsolv.queue_init(&jobs);
    defer libsolv.queue_free(&jobs);
    libsolv.queue_push2(
        &jobs,
        libsolv.SOLVER_INSTALL | libsolv.SOLVER_SOLVABLE,
        state.origins.items[0].solvable_id,
    );
    try std.testing.expect(libsolv.solver_solve(state.solver, &jobs) != 0);
    try std.testing.expect(validatedProblemRule(state, 1) != null);
    const original = state.solver.*.problems.elements[0];
    state.solver.*.problems.elements[0] = state.solver.*.learnt_pool.count + 1;
    defer state.solver.*.problems.elements[0] = original;
    try std.testing.expectEqual(@as(?libsolv.Id, null), validatedProblemRule(state, 1));
}

test "planner rejects untrusted duplicate and unhealthy inputs before solve" {
    const text =
        "Package: app\nVersion: 1\nArchitecture: amd64\nFilename: pool/app.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n";
    const id = testRepositoryId('j');
    var index = try availableIndex(id, text);
    defer index.deinit();
    var untrusted = RepositoryInput.trustedTest(id, 1, &index);
    untrusted.eligibility = .untrusted;
    var result = try planTransaction(std.testing.allocator, .{
        .repositories = &.{untrusted},
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "app" } },
    });
    var failure = result.failure;
    try std.testing.expectEqual(ProblemKind.unauthenticated_repository, failure.problems[0].kind);
    failure.deinit();

    const duplicate_repositories = [_]RepositoryInput{
        RepositoryInput.trustedTest(id, 1, &index),
        RepositoryInput.trustedTest(id, 2, &index),
    };
    result = try planTransaction(std.testing.allocator, .{
        .repositories = &duplicate_repositories,
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "app" } },
    });
    failure = result.failure;
    try std.testing.expectEqual(ProblemKind.duplicate_repository, failure.problems[0].kind);
    failure.deinit();

    var database = try parsedDatabase(
        "Package: broken\nVersion: 1\nArchitecture: amd64\nStatus: install ok unpacked\n",
    );
    defer database.deinit();
    result = try planTransaction(std.testing.allocator, .{
        .repositories = &.{},
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .upgrade_all = {} },
    });
    failure = result.failure;
    defer failure.deinit();
    try std.testing.expectEqual(ProblemKind.unhealthy_installed_state, failure.problems[0].kind);
}

test "planner enforces exact selection downgrade and protected held essential policy" {
    var database = try parsedDatabase(
        "Package: app\nVersion: 2\nArchitecture: amd64\nStatus: install ok installed\nInstalled-Size: 8\n\n" ++
            "Package: base\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\nEssential: yes\nProtected: yes\n",
    );
    defer database.deinit();
    const policies = [_]InstalledPolicy{
        .{ .name = "app", .architecture = "amd64", .install_reason = .manual, .held = true },
        .{ .name = "base", .architecture = "amd64", .install_reason = .manual, .held = false },
    };
    const text =
        "Package: app\nVersion: 1\nArchitecture: amd64\nFilename: pool/app.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n";
    const id = testRepositoryId('k');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const repositories = [_]RepositoryInput{RepositoryInput.trustedTest(id, 500, &index)};

    var result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &policies,
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "app", .version = "1", .architecture = "amd64" } },
    });
    var failure = result.failure;
    try std.testing.expectEqual(ProblemKind.unsupported_feature, failure.problems[0].kind);
    failure.deinit();

    result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &policies,
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .remove = .{ .name = "base" } },
    });
    failure = result.failure;
    try std.testing.expectEqual(ProblemKind.essential_violation, failure.problems[0].kind);
    failure.deinit();

    result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &policies,
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .upgrade = &.{.{ .name = "app" }} },
    });
    failure = result.failure;
    defer failure.deinit();
    try std.testing.expectEqual(ProblemKind.held_violation, failure.problems[0].kind);
}

test "planner recommends policy and repository priority are deterministic" {
    const low_text =
        "Package: provider-low\nVersion: 1\nArchitecture: amd64\nProvides: virtual\nFilename: pool/low.deb\nSize: 1\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n";
    const high_text =
        "Package: root\nVersion: 1\nArchitecture: amd64\nDepends: virtual\nRecommends: optional\nFilename: pool/root.deb\nSize: 1\n" ++
        "SHA256: 2222222222222222222222222222222222222222222222222222222222222222\n\n" ++
        "Package: provider-high\nVersion: 1\nArchitecture: amd64\nProvides: virtual\nFilename: pool/high.deb\nSize: 1\n" ++
        "SHA256: 3333333333333333333333333333333333333333333333333333333333333333\n\n" ++
        "Package: optional\nVersion: 1\nArchitecture: amd64\nFilename: pool/optional.deb\nSize: 1\n" ++
        "SHA256: 4444444444444444444444444444444444444444444444444444444444444444\n";
    var low = try availableIndex(testRepositoryId('l'), low_text);
    defer low.deinit();
    var high = try availableIndex(testRepositoryId('m'), high_text);
    defer high.deinit();
    const repositories = [_]RepositoryInput{
        RepositoryInput.trustedTest(testRepositoryId('l'), 100, &low),
        RepositoryInput.trustedTest(testRepositoryId('m'), 900, &high),
    };
    const result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "root" } },
        .policy = .{ .recommends = true },
    });
    var plan = result.plan;
    defer plan.deinit();
    var saw_high = false;
    var saw_low = false;
    var saw_optional = false;
    for (plan.actions) |action| {
        saw_high = saw_high or std.mem.eql(u8, action.package, "provider-high");
        saw_low = saw_low or std.mem.eql(u8, action.package, "provider-low");
        saw_optional = saw_optional or std.mem.eql(u8, action.package, "optional");
    }
    try std.testing.expect(saw_high);
    try std.testing.expect(!saw_low);
    try std.testing.expect(saw_optional);
}

test "planner protects reverse dependencies and returns typed unsat graph" {
    var database = try parsedDatabase(
        "Package: app\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\nDepends: lib\n\n" ++
            "Package: lib\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n",
    );
    defer database.deinit();
    const policies = [_]InstalledPolicy{
        .{ .name = "app", .architecture = "amd64", .install_reason = .manual, .held = false },
        .{ .name = "lib", .architecture = "amd64", .install_reason = .automatic, .held = false },
    };
    const result = try planTransaction(std.testing.allocator, .{
        .repositories = &.{},
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &policies,
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .remove = .{ .name = "lib" } },
    });
    var failure = result.failure;
    defer failure.deinit();
    try std.testing.expect(failure.problems.len != 0);
    try std.testing.expect(failure.problems[0].kind == .unsatisfied_dependency or
        failure.problems[0].kind == .conflict or
        failure.problems[0].kind == .protected_violation);
    const json = try failure.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"problems\":[") != null);
}

test "planner supports named upgrade upgrade-all and explicitly allowed downgrade" {
    var database = try parsedDatabase(
        "Package: app\nVersion: 2\nArchitecture: amd64\nStatus: install ok installed\nInstalled-Size: 4\n",
    );
    defer database.deinit();
    const policies = [_]InstalledPolicy{
        .{ .name = "app", .architecture = "amd64", .install_reason = .manual, .held = false },
    };
    const text =
        "Package: app\nVersion: 3\nArchitecture: amd64\nInstalled-Size: 6\nFilename: pool/app3.deb\nSize: 3\n" ++
        "SHA256: 3333333333333333333333333333333333333333333333333333333333333333\n\n" ++
        "Package: app\nVersion: 1\nArchitecture: amd64\nInstalled-Size: 2\nFilename: pool/app1.deb\nSize: 1\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n";
    const id = testRepositoryId('n');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const repositories = [_]RepositoryInput{RepositoryInput.trustedTest(id, 500, &index)};
    const installed: ImportInput = .{
        .records = database.packages,
        .native_architecture = "amd64",
        .policies = &policies,
        .hold_authority = .explicit_policy,
    };

    const named_result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = installed,
        .target_architecture = "amd64",
        .request = .{ .upgrade = &.{.{ .name = "app" }} },
    });
    var named = named_result.plan;
    defer named.deinit();
    try std.testing.expect(named.actions.len != 0);
    try std.testing.expectEqualStrings("3", named.actions[0].version);
    try std.testing.expectEqual(ActionKind.upgrade, named.actions[0].kind);

    const all_result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = installed,
        .target_architecture = "amd64",
        .request = .{ .upgrade_all = {} },
    });
    var all = all_result.plan;
    defer all.deinit();
    try std.testing.expect(all.actions.len != 0);
    try std.testing.expectEqualStrings("3", all.actions[0].version);

    const down_result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = installed,
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "app", .version = "1", .architecture = "amd64" } },
        .policy = .{ .allow_downgrade = true },
    });
    var down = down_result.plan;
    defer down.deinit();
    try std.testing.expect(down.actions.len != 0);
    try std.testing.expectEqual(ActionKind.downgrade, down.actions[0].kind);
    try std.testing.expectEqualStrings("1", down.actions[0].version);
}

test "planner reports exact architecture version and conflict failures" {
    const text =
        "Package: root\nVersion: 1\nArchitecture: amd64\nDepends: left, right\nFilename: pool/root.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n" ++
        "Package: left\nVersion: 1\nArchitecture: amd64\nConflicts: right\nFilename: pool/left.deb\nSize: 1\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n\n" ++
        "Package: right\nVersion: 1\nArchitecture: amd64\nFilename: pool/right.deb\nSize: 1\n" ++
        "SHA256: 2222222222222222222222222222222222222222222222222222222222222222\n";
    const id = testRepositoryId('o');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const repositories = [_]RepositoryInput{RepositoryInput.trustedTest(id, 500, &index)};
    const installed: ImportInput = .{
        .records = &.{},
        .native_architecture = "amd64",
        .policies = &.{},
        .hold_authority = .explicit_policy,
    };
    var result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = installed,
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "root", .architecture = "arm64" } },
    });
    var failure = result.failure;
    try std.testing.expectEqual(ProblemKind.architecture_mismatch, failure.problems[0].kind);
    failure.deinit();

    result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = installed,
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "root", .version = "9" } },
    });
    failure = result.failure;
    try std.testing.expectEqual(ProblemKind.version_mismatch, failure.problems[0].kind);
    failure.deinit();

    result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = installed,
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "root" } },
    });
    failure = result.failure;
    defer failure.deinit();
    try std.testing.expect(failure.problems[0].kind == .conflict or
        failure.problems[0].kind == .unsatisfied_dependency);
}

test "architecture restrictions and inactive build profiles are evaluated explicitly" {
    const text =
        "Package: root\nVersion: 1\nArchitecture: amd64\nDepends: missing [arm64], ignored <stage1>, also-ignored <stage1 !cross>, helper:native [linux-any] <!stage1>, data:amd64 <stage1> <!cross>\nFilename: pool/root.deb\nSize: 1\n" ++
        "SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n\n" ++
        "Package: helper\nVersion: 1\nArchitecture: amd64\nFilename: pool/helper.deb\nSize: 1\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n\n" ++
        "Package: data\nVersion: 1\nArchitecture: all\nFilename: pool/data.deb\nSize: 1\n" ++
        "SHA256: 2222222222222222222222222222222222222222222222222222222222222222\n";
    const id = testRepositoryId('o');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const context = try Context.createForArchitecture(std.testing.allocator, "amd64");
    defer context.destroy();
    try context.importAvailable(RepositoryInput.trustedTest(id, 500, &index), .{});
    const selected = try solveAvailable(context, "root");
    defer std.testing.allocator.free(selected);
    try std.testing.expect(hasSelected(selected, "helper"));
    try std.testing.expect(hasSelected(selected, "data"));
}

test "planner reinstall is exact and summaries include ordered execution" {
    var database = try parsedDatabase(
        "Package: app\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\nInstalled-Size: 4\n\n" ++
            "Package: essential-core\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\nEssential: yes\n",
    );
    defer database.deinit();
    const policies = [_]InstalledPolicy{
        .{ .name = "app", .architecture = "amd64", .install_reason = .manual, .held = false },
        .{ .name = "essential-core", .architecture = "amd64", .install_reason = .automatic, .held = false },
    };
    const text =
        "Package: app\nVersion: 1\nArchitecture: amd64\nInstalled-Size: 4\nFilename: pool/app.deb\nSize: 9\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n\n" ++
        "Package: essential-core\nVersion: 1\nArchitecture: amd64\nEssential: yes\nFilename: pool/essential.deb\nSize: 1\n" ++
        "SHA256: 2222222222222222222222222222222222222222222222222222222222222222\n";
    const id = testRepositoryId('p');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const repositories = [_]RepositoryInput{RepositoryInput.trustedTest(id, 500, &index)};
    const result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &policies,
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .mode = .download_only,
        .request = .{ .reinstall = .{ .name = "app", .version = "1", .architecture = "amd64" } },
    });
    var plan = result.plan;
    defer plan.deinit();
    try std.testing.expectEqual(OperationMode.download_only, plan.mode);
    try std.testing.expectEqual(@as(usize, 1), plan.summary.reinstalls);
    try std.testing.expectEqual(@as(u64, 9), plan.summary.download_bytes);
    try std.testing.expectEqual(OrderedActionKind.unpack, plan.ordered_actions[0].kind);
    try std.testing.expectEqual(OrderedActionKind.configure_pending, plan.ordered_actions[1].kind);
}

test "phased updates require deterministic explicit opt in" {
    const text =
        "Package: app\nVersion: 2\nArchitecture: amd64\nFilename: pool/app.deb\nSize: 1\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n";
    const id = testRepositoryId('q');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const repositories = [_]RepositoryInput{RepositoryInput.trustedTest(id, 500, &index)};
    const phased = [_]PhasedCandidate{.{
        .name = "app",
        .architecture = "amd64",
        .version = "2",
        .percentage = 50,
    }};
    var result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .phased_candidates = &phased,
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "app" } },
    });
    var failure = result.failure;
    failure.deinit();

    result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .phased_candidates = &phased,
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "app" } },
        .policy = .{ .phased_updates = .include_all },
    });
    var plan = result.plan;
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), plan.actions.len);
}

test "candidate enumeration permutations produce byte-identical plans" {
    const first_text =
        "Package: app\nVersion: 1\nArchitecture: amd64\nDepends: zlib | alib\nFilename: pool/app.deb\nSize: 1\nSHA256: 1111111111111111111111111111111111111111111111111111111111111111\n\n" ++
        "Package: alib\nVersion: 1\nArchitecture: amd64\nFilename: pool/a.deb\nSize: 1\nSHA256: 2222222222222222222222222222222222222222222222222222222222222222\n\n" ++
        "Package: zlib\nVersion: 1\nArchitecture: amd64\nFilename: pool/z.deb\nSize: 1\nSHA256: 3333333333333333333333333333333333333333333333333333333333333333\n";
    const second_text =
        "Package: zlib\nVersion: 1\nArchitecture: amd64\nFilename: pool/z.deb\nSize: 1\nSHA256: 3333333333333333333333333333333333333333333333333333333333333333\n\n" ++
        "Package: app\nVersion: 1\nArchitecture: amd64\nDepends: zlib | alib\nFilename: pool/app.deb\nSize: 1\nSHA256: 1111111111111111111111111111111111111111111111111111111111111111\n\n" ++
        "Package: alib\nVersion: 1\nArchitecture: amd64\nFilename: pool/a.deb\nSize: 1\nSHA256: 2222222222222222222222222222222222222222222222222222222222222222\n";
    const id = testRepositoryId('r');
    var first_index = try availableIndex(id, first_text);
    defer first_index.deinit();
    var second_index = try availableIndex(id, second_text);
    defer second_index.deinit();
    const base_installed: ImportInput = .{
        .records = &.{},
        .native_architecture = "amd64",
        .policies = &.{},
        .hold_authority = .explicit_policy,
    };
    const first_repositories = [_]RepositoryInput{RepositoryInput.trustedTest(id, 500, &first_index)};
    const second_repositories = [_]RepositoryInput{RepositoryInput.trustedTest(id, 500, &second_index)};
    const first_result = try planTransaction(std.testing.allocator, .{
        .repositories = &first_repositories,
        .installed = base_installed,
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "app" } },
    });
    var first = first_result.plan;
    defer first.deinit();
    const second_result = try planTransaction(std.testing.allocator, .{
        .repositories = &second_repositories,
        .installed = base_installed,
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "app" } },
    });
    var second = second_result.plan;
    defer second.deinit();
    const first_json = try first.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(first_json);
    const second_json = try second.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(second_json);
    try std.testing.expectEqualStrings(first_json, second_json);
}

test "install-only policy retains installed version and installs exact new version" {
    var database = try parsedDatabase(
        "Package: kernel\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n",
    );
    defer database.deinit();
    const policies = [_]InstalledPolicy{
        .{ .name = "kernel", .architecture = "amd64", .install_reason = .manual, .held = false },
    };
    const text =
        "Package: kernel\nVersion: 2\nArchitecture: amd64\nFilename: pool/kernel.deb\nSize: 1\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n";
    const id = testRepositoryId('s');
    var index = try availableIndex(id, text);
    defer index.deinit();
    const repositories = [_]RepositoryInput{RepositoryInput.trustedTest(id, 500, &index)};
    const install_only = [_]ProtectedIdentity{.{ .name = "kernel", .architecture = "amd64" }};
    const result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &policies,
            .hold_authority = .explicit_policy,
        },
        .install_only = &install_only,
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "kernel", .version = "2", .architecture = "amd64" } },
    });
    var plan = result.plan;
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), plan.actions.len);
    try std.testing.expectEqual(ActionKind.install, plan.actions[0].kind);
    try std.testing.expect(plan.actions[0].prior_installed == null);
}

test "reverse dependency removal requires complete explicit authorization" {
    var database = try parsedDatabase(
        "Package: app\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\nDepends: lib\n\n" ++
            "Package: lib\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n",
    );
    defer database.deinit();
    const policies = [_]InstalledPolicy{
        .{ .name = "app", .architecture = "amd64", .install_reason = .manual, .held = false },
        .{ .name = "lib", .architecture = "amd64", .install_reason = .automatic, .held = false },
    };
    const authorized = [_]ProtectedIdentity{.{ .name = "app", .architecture = "amd64" }};
    const result = try planTransaction(std.testing.allocator, .{
        .repositories = &.{},
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .policies = &policies,
            .hold_authority = .explicit_policy,
        },
        .authorized_removals = &authorized,
        .target_architecture = "amd64",
        .request = .{ .remove = .{ .name = "lib" } },
        .policy = .{ .allow_remove_dependencies = true },
    });
    var plan = result.plan;
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 2), plan.summary.removals);
}

test "exact unqualified selection prefers native architecture and request identity is exact" {
    const native_text =
        "Package: app\nVersion: 1\nArchitecture: amd64\nDepends: app-data:arm64\nFilename: pool/app-amd64.deb\nSize: 1\n" ++
        "SHA256: 2222222222222222222222222222222222222222222222222222222222222222\n\n" ++
        "Package: app-data\nVersion: 1\nArchitecture: amd64\nMulti-Arch: foreign\nFilename: pool/data-amd64.deb\nSize: 1\n" ++
        "SHA256: 4444444444444444444444444444444444444444444444444444444444444444\n";
    const foreign_text =
        "Package: app\nVersion: 1\nArchitecture: arm64\nFilename: pool/app-arm64.deb\nSize: 1\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n\n" ++
        "Package: app-data\nVersion: 1\nArchitecture: arm64\nMulti-Arch: foreign\nFilename: pool/data-arm64.deb\nSize: 1\n" ++
        "SHA256: 3333333333333333333333333333333333333333333333333333333333333333\n";
    const native_id = testRepositoryId('t');
    const foreign_id = testRepositoryId('u');
    var native_index = try availableIndex(native_id, native_text);
    defer native_index.deinit();
    var foreign_index = try availableIndexForArchitecture(foreign_id, "arm64", foreign_text);
    defer foreign_index.deinit();
    const repositories = [_]RepositoryInput{
        RepositoryInput.trustedTest(native_id, 500, &native_index),
        RepositoryInput.trustedTest(foreign_id, 500, &foreign_index),
    };
    const result = try planTransaction(std.testing.allocator, .{
        .repositories = &repositories,
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .foreign_architectures = &.{"arm64"},
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .install = .{ .name = "app", .version = "1" } },
    });
    var plan = result.plan;
    defer plan.deinit();
    var saw_native = false;
    var saw_automatic_foreign = false;
    for (plan.actions) |action| {
        if (std.mem.eql(u8, action.package, "app")) {
            try std.testing.expectEqualStrings("amd64", action.architecture);
            try std.testing.expect(action.requested);
            saw_native = true;
        }
        if (std.mem.eql(u8, action.package, "app-data")) {
            try std.testing.expectEqualStrings("arm64", action.architecture);
            try std.testing.expect(!action.requested);
            saw_automatic_foreign = true;
        }
    }
    try std.testing.expect(saw_native);
    try std.testing.expect(saw_automatic_foreign);
}

test "ambiguous installed multiarch requests and contradictory limits fail explicitly" {
    var database = try parsedDatabase(
        "Package: app\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n\n" ++
            "Package: app\nVersion: 1\nArchitecture: arm64\nStatus: install ok installed\n",
    );
    defer database.deinit();
    const policies = [_]InstalledPolicy{
        .{ .name = "app", .architecture = "amd64", .install_reason = .manual, .held = false },
        .{ .name = "app", .architecture = "arm64", .install_reason = .manual, .held = false },
    };
    var result = try planTransaction(std.testing.allocator, .{
        .repositories = &.{},
        .installed = .{
            .records = database.packages,
            .native_architecture = "amd64",
            .foreign_architectures = &.{"arm64"},
            .policies = &policies,
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .remove = .{ .name = "app" } },
    });
    var failure = result.failure;
    try std.testing.expectEqual(ProblemKind.invalid_policy, failure.problems[0].kind);
    failure.deinit();

    result = try planTransaction(std.testing.allocator, .{
        .repositories = &.{},
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .target_architecture = "amd64",
        .request = .{ .upgrade_all = {} },
        .limits = .{ .max_problems = 0 },
    });
    failure = result.failure;
    defer failure.deinit();
    try std.testing.expectEqual(ProblemKind.invalid_policy, failure.problems[0].kind);
}

test "duplicate phased candidate policy fails explicitly" {
    const phased = [_]PhasedCandidate{
        .{ .name = "app", .architecture = "amd64", .version = "2", .percentage = 10 },
        .{ .name = "app", .architecture = "amd64", .version = "2", .percentage = 90 },
    };
    const result = try planTransaction(std.testing.allocator, .{
        .repositories = &.{},
        .installed = .{
            .records = &.{},
            .native_architecture = "amd64",
            .policies = &.{},
            .hold_authority = .explicit_policy,
        },
        .phased_candidates = &phased,
        .target_architecture = "amd64",
        .request = .{ .upgrade_all = {} },
    });
    var failure = result.failure;
    defer failure.deinit();
    try std.testing.expectEqual(ProblemKind.invalid_policy, failure.problems[0].kind);
}
