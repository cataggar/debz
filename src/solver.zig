const std = @import("std");
const dpkg_status = @import("dpkg_status.zig");
const relation = @import("relation.zig");

const libsolv = @cImport({
    @cInclude("solv/evr.h");
    @cInclude("solv/pool.h");
    @cInclude("solv/poolarch.h");
    @cInclude("solv/repo.h");
    @cInclude("solv/solver.h");
    @cInclude("solv/solvable.h");
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

const Mapping = struct {
    solvable_id: libsolv.Id,
    record_index: usize,
    metadata: InstalledMetadata,
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

    fn deinit(self: *Internal) void {
        if (self.mappings.len != 0) self.allocator.free(self.mappings);
        if (self.blockers.len != 0) self.allocator.free(self.blockers);
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
                    addRelations(state.pool, repo, solvable, record);
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

fn stringId(pool: *libsolv.Pool, value: []const u8) libsolv.Id {
    return libsolv.pool_strn2id(pool, value.ptr, @intCast(value.len), 1);
}

fn addRelations(
    pool: *libsolv.Pool,
    repo: *libsolv.Repo,
    solvable: *allowzero libsolv.Solvable,
    record: dpkg_status.Package,
) void {
    for (record.relations) |dependency| {
        switch (dependency.kind) {
            .pre_depends, .depends => for (dependency.relation.groups) |group| {
                solvable.*.requires = libsolv.repo_addid_dep(repo, solvable.*.requires, groupId(pool, group), 0);
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
            .replaces => for (dependency.relation.groups) |group| {
                for (group.alternatives) |alternative| {
                    solvable.*.obsoletes = libsolv.repo_addid_dep(repo, solvable.*.obsoletes, alternativeId(pool, alternative), 0);
                }
            },
            .provides => for (dependency.relation.groups) |group| {
                for (group.alternatives) |alternative| {
                    solvable.*.provides = libsolv.repo_addid_dep(repo, solvable.*.provides, alternativeId(pool, alternative), 0);
                }
            },
        }
    }
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

fn parsedDatabase(source: []const u8) !dpkg_status.Database {
    const result = try dpkg_status.parseBorrowed(std.testing.allocator, source, .{});
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
            "Package: consumer\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\nDepends: virtual-api (>= 2) | fallback\nConflicts: obsolete-api\n",
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
