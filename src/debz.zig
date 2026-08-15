const std = @import("std");
const solver = @import("solver.zig");

pub const version = "0.1.0";
pub const DebianVersion = @import("debian_version.zig").DebianVersion;
pub const DebianVersionParseError = @import("debian_version.zig").ParseError;
pub const SolverContext = solver.Context;
pub const SolverImportInput = solver.ImportInput;
pub const SolverInstalledPolicy = solver.InstalledPolicy;
pub const SolverInstallReason = solver.InstallReason;
pub const SolverHoldAuthority = solver.HoldAuthority;
pub const SolverImportResult = solver.ImportResult;
pub const SolverImportSummary = solver.ImportSummary;
pub const SolverImportDiagnostic = solver.Diagnostic;
pub const SolverImportDiagnosticCode = solver.DiagnosticCode;
pub const SolverInstalledMetadata = solver.InstalledMetadata;
pub const SolverInstalledBlocker = solver.Blocker;
pub const SolverInstalledBlockerKind = solver.BlockerKind;
pub const SolverEligibility = solver.Eligibility;
pub const SolverRepositoryInput = solver.RepositoryInput;
pub const SolverImportLimits = solver.Limits;
pub const SolverPackageOrigin = solver.PackageOrigin;
pub const SolverAvailableImportError = solver.AvailableImportError;
/// Pure transaction planning API. It does not download archives or execute
/// dpkg; callers must separately review and execute returned actions.
pub const planTransaction = solver.planTransaction;
pub const SolverPlanInput = solver.PlanInput;
pub const SolverPlanRequest = solver.PlanRequest;
pub const SolverPackageSelector = solver.PackageSelector;
pub const SolverSolvePolicy = solver.SolvePolicy;
pub const SolverPlanLimits = solver.PlanLimits;
pub const SolverProtectedIdentity = solver.ProtectedIdentity;
pub const SolverPlanningResult = solver.PlanningResult;
pub const SolverPlan = solver.Plan;
pub const SolverPlanAction = solver.PlanAction;
pub const SolverPlanActionKind = solver.ActionKind;
pub const SolverPlanActionReason = solver.ActionReason;
pub const SolverPlanFailure = solver.PlanFailure;
pub const SolverProblemNode = solver.ProblemNode;
pub const SolverProblemKind = solver.ProblemKind;
pub const deb822 = @import("deb822.zig");
pub const relation = @import("relation.zig");
pub const deb_archive = @import("deb_archive.zig");
pub const dpkg_status = @import("dpkg_status.zig");
pub const control_record = @import("control_record.zig");
pub const source = @import("source.zig");
pub const release_metadata = @import("release_metadata.zig");
pub const metadata_cache = @import("metadata_cache.zig");
pub const repository_acquisition = @import("repository_acquisition.zig");
pub const packages_index = @import("packages_index.zig");
pub const metadata_decompression = @import("metadata_decompression.zig");
pub const repository_refresh = @import("repository_refresh.zig");
pub const signed_release_envelope = @import("signed_release_envelope.zig");
pub const openpgp_verifier = @import("openpgp_verifier.zig");

pub const Architecture = enum {
    amd64,
    arm64,
};

pub const RecommendsPolicy = enum {
    exclude,
    include,
};

pub const Config = struct {
    install_root: []const u8,
    architecture: Architecture,
    recommends: RecommendsPolicy = .exclude,
    offline: bool = false,
};

pub const Operation = enum {
    refresh,
    install,
    remove,
    upgrade,
    upgrade_all,
    reinstall,
    download,
    plan,
    list_installed,
    list_available,
    info,
    provides,
    why,
    clean,
    recover,
};

pub const Request = struct {
    operation: Operation,
    packages: []const []const u8 = &.{},
};

pub fn parseOperation(name: []const u8) ?Operation {
    const names = std.StaticStringMap(Operation).initComptime(.{
        .{ "refresh", .refresh },
        .{ "install", .install },
        .{ "remove", .remove },
        .{ "upgrade", .upgrade },
        .{ "upgrade-all", .upgrade_all },
        .{ "reinstall", .reinstall },
        .{ "download", .download },
        .{ "plan", .plan },
        .{ "list-installed", .list_installed },
        .{ "list-available", .list_available },
        .{ "info", .info },
        .{ "provides", .provides },
        .{ "why", .why },
        .{ "clean", .clean },
        .{ "recover", .recover },
    });
    return names.get(name);
}

test "configuration defaults are explicit" {
    const config: Config = .{
        .install_root = "/",
        .architecture = .amd64,
    };

    try std.testing.expectEqual(RecommendsPolicy.exclude, config.recommends);
    try std.testing.expect(!config.offline);
}

test "CLI operations use stable spellings" {
    try std.testing.expectEqual(Operation.upgrade_all, parseOperation("upgrade-all").?);
    try std.testing.expect(parseOperation("unknown") == null);
}

test "empty solver context can be created and destroyed" {
    const context = SolverContext.create();
    context.destroy();
}

test {
    _ = deb822;
    _ = relation;
    _ = dpkg_status;
    _ = release_metadata;
    _ = metadata_cache;
    _ = repository_acquisition;
    _ = packages_index;
    _ = metadata_decompression;
    _ = repository_refresh;
    _ = signed_release_envelope;
    _ = openpgp_verifier;
}
