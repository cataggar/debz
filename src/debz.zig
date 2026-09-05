const std = @import("std");
const solver = @import("solver.zig");
const build_options = @import("debz_build_options");

pub const version = build_options.version;
pub const product_api = @import("product_api.zig");
pub const repository_api = @import("repository_api.zig");
pub const repository_state = @import("repository_state.zig");
pub const repository_backend = @import("repository_backend.zig");
pub const RepositoryApiVersion = repository_api.api_version;
pub const RepositoryOperation = repository_api.Operation;
pub const RepositoryTrustMode = repository_api.TrustMode;
pub const RepositoryPhaseState = repository_api.PhaseState;
pub const RepositoryRequest = repository_api.Request;
pub const RepositoryNetworkPolicy = repository_api.NetworkPolicy;
pub const RepositoryCachePolicy = repository_api.CachePolicy;
pub const RepositoryStatePolicy = repository_api.StatePolicy;
pub const RepositoryResourcePolicy = repository_api.ResourcePolicy;
pub const RepositoryDescriptorIdentity = repository_api.DescriptorIdentity;
pub const RepositoryEvidencePaths = repository_api.EvidencePaths;
pub const RepositoryResult = repository_api.Result;
pub const RepositoryOwnedResult = repository_api.OwnedResult;
pub const RepositoryDiagnostic = repository_api.Diagnostic;
pub const RepositoryDiagnosticId = repository_api.DiagnosticId;
pub const RepositoryExitStatus = repository_api.ExitStatus;
pub const RepositoryBackend = repository_api.Backend;
pub const ProductionRepositoryBackend = repository_backend.Backend;
pub const executeRepositoryRequest = repository_api.execute;
pub const decodeRepositoryResult = repository_api.decode;
pub const ApiVersion = product_api.api_version;
pub const ProductOperation = product_api.Operation;
pub const ProductCommonOptions = product_api.CommonOptions;
pub const ProductRequest = product_api.Request;
pub const ProductResult = product_api.Result;
pub const ProductDiagnostic = product_api.Diagnostic;
pub const ProductErrorId = product_api.ErrorId;
pub const ProductExitStatus = product_api.ExitStatus;
pub const ProductBackend = product_api.Backend;
pub const executeProductRequest = product_api.execute;
pub const production_backend = @import("production_backend.zig");
pub const ProductionBackend = production_backend.Backend;
pub const system_product = @import("system_product.zig");
pub const system_operation_lock = @import("system_operation_lock.zig");
pub const executeSystemProductRequest = system_product.execute;
pub const package_family_backend = @import("package_family_backend.zig");
pub const PackageFamilyBackend = package_family_backend.Backend;
pub const PackageFamilyRequest = package_family_backend.Request;
pub const PackageFamilyResult = package_family_backend.Result;
pub const PackageFamilyCapabilities = package_family_backend.Capabilities;
pub const packageFamilyCapabilities = package_family_backend.capabilities;
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
pub const SolverAuthenticatedRepositoryPackageOrigin = solver.AuthenticatedRepositoryPackageOrigin;
pub const SolverTaggedPackageOrigin = solver.TaggedPackageOrigin;
pub const SolverPackageOriginV2 = solver.PackageOriginV2;
pub const SolverLocalArtifactPackageOrigin = solver.LocalArtifactPackageOrigin;
pub const SolverAvailableImportError = solver.AvailableImportError;
/// Pure transaction planning API. It does not download archives or execute
/// dpkg; callers must separately review and execute returned actions.
pub const planTransaction = solver.planTransaction;
pub const SolverPlanInput = solver.PlanInput;
pub const SolverPlanRequest = solver.PlanRequest;
pub const SolverPackageSelector = solver.PackageSelector;
pub const SolverSolvePolicy = solver.SolvePolicy;
pub const SolverOperationMode = solver.OperationMode;
pub const SolverPhasedUpdatePolicy = solver.PhasedUpdatePolicy;
pub const SolverPhasedCandidate = solver.PhasedCandidate;
pub const SolverPlanLimits = solver.PlanLimits;
pub const SolverProtectedIdentity = solver.ProtectedIdentity;
pub const SolverPlanningResult = solver.PlanningResult;
pub const SolverPlan = solver.Plan;
pub const SolverPlanAction = solver.PlanAction;
pub const SolverPlanOrigin = solver.PlanOrigin;
pub const SolverPlanActionKind = solver.ActionKind;
pub const SolverPlanActionReason = solver.ActionReason;
pub const SolverOrderedAction = solver.OrderedAction;
pub const SolverOrderedActionKind = solver.OrderedActionKind;
pub const SolverPlanSummary = solver.PlanSummary;
pub const SolverPlanFailure = solver.PlanFailure;
pub const SolverProblemNode = solver.ProblemNode;
pub const SolverProblemKind = solver.ProblemKind;
pub const SolverCandidateRejection = solver.CandidateRejection;
pub const SolverCandidateRejectionReason = solver.CandidateRejectionReason;
pub const deb822 = @import("deb822.zig");
pub const relation = @import("relation.zig");
pub const deb_archive = @import("deb_archive.zig");
pub const deb_payload = @import("deb_payload.zig");
pub const dpkg_status = @import("dpkg_status.zig");
pub const control_record = @import("control_record.zig");
pub const source = @import("source.zig");
pub const release_metadata = @import("release_metadata.zig");
pub const metadata_cache = @import("metadata_cache.zig");
pub const repository_acquisition = @import("repository_acquisition.zig");
pub const package_acquisition = @import("package_acquisition.zig");
pub const local_artifact = @import("local_artifact.zig");
pub const package_origin = @import("package_origin.zig");
pub const LocalArtifactEvidence = package_origin.LocalArtifactEvidence;
pub const LocalArtifactOriginTrustMode = package_origin.LocalArtifactTrustMode;
pub const acquirePackage = package_acquisition.acquirePackage;
pub const PackageSelectedRecord = package_acquisition.SelectedPackage;
pub const PackageAcquisitionRequest = package_acquisition.Request;
pub const PackageAcquisitionPolicy = package_acquisition.Policy;
pub const VerifiedPackage = package_acquisition.VerifiedPackage;
pub const PackageCache = package_acquisition.Cache;
pub const acquireLocalArtifact = local_artifact.acquire;
pub const LocalArtifactRequest = local_artifact.Request;
pub const LocalArtifactPolicy = local_artifact.Policy;
pub const LocalArtifact = local_artifact.Artifact;
pub const LocalArtifactTrustMode = local_artifact.TrustMode;
pub const packages_index = @import("packages_index.zig");
pub const metadata_decompression = @import("metadata_decompression.zig");
pub const repository_refresh = @import("repository_refresh.zig");
pub const repository_policy = @import("repository_policy.zig");
pub const target_apt_config = @import("target_apt_config.zig");
pub const signed_release_envelope = @import("signed_release_envelope.zig");
pub const openpgp_verifier = @import("openpgp_verifier.zig");
pub const transaction_executor = @import("transaction_executor.zig");
pub const transaction_recovery = @import("transaction_recovery.zig");
pub const exact_lock = @import("exact_lock.zig");
pub const exact_lock_v2 = @import("exact_lock_v2.zig");
pub const transaction_provenance = @import("transaction_provenance.zig");
pub const transaction_provenance_v2 = @import("transaction_provenance_v2.zig");
pub const transaction_provenance_v3 = @import("transaction_provenance_v3.zig");
pub const ExactClosureLock = exact_lock.Lock;
pub const OwnedExactClosureLock = exact_lock.OwnedLock;
pub const ExactClosureLockInput = exact_lock.Input;
pub const createExactClosureLock = exact_lock.create;
pub const decodeExactClosureLock = exact_lock.decode;
pub const ExactClosureLockStore = exact_lock.Store;
pub const ExactClosureLockV1 = exact_lock.Lock;
pub const ExactClosureLockV1Input = exact_lock.Input;
pub const ExactClosureLockV2 = exact_lock_v2.Lock;
pub const OwnedExactClosureLockV2 = exact_lock_v2.OwnedLock;
pub const ExactClosureLockV2Input = exact_lock_v2.Input;
pub const createExactClosureLockV2 = exact_lock_v2.create;
pub const decodeExactClosureLockV2 = exact_lock_v2.decode;
pub const ExactClosureLockV2Store = exact_lock_v2.Store;
pub const TransactionProvenanceResult = transaction_provenance.Result;
pub const OwnedTransactionProvenanceResult = transaction_provenance.OwnedResult;
pub const TransactionProvenanceInput = transaction_provenance.Input;
pub const createTransactionProvenance = transaction_provenance.create;
pub const createTransactionProvenanceFromExecution = transaction_provenance.createFromExecution;
pub const createTransactionProvenanceFromRecovery = transaction_provenance.createFromRecovery;
pub const validateTransactionProvenance = transaction_provenance.validateDocument;
pub const TransactionProvenanceStore = transaction_provenance.Store;
pub const TransactionProvenanceResultV1 = transaction_provenance.Result;
pub const TransactionProvenanceResultV2 = transaction_provenance_v2.Result;
pub const OwnedTransactionProvenanceResultV2 = transaction_provenance_v2.OwnedResult;
pub const TransactionProvenanceInputV2 = transaction_provenance_v2.Input;
pub const createTransactionProvenanceV2 = transaction_provenance_v2.create;
pub const createTransactionProvenanceV2FromExecution = transaction_provenance_v2.createFromExecution;
pub const createTransactionProvenanceV2FromRecovery = transaction_provenance_v2.createFromRecovery;
pub const validateTransactionProvenanceV2 = transaction_provenance_v2.validateDocument;
pub const TransactionProvenanceV2Store = transaction_provenance_v2.Store;
pub const TransactionProvenanceResultV3 = transaction_provenance_v3.Result;
pub const OwnedTransactionProvenanceResultV3 = transaction_provenance_v3.OwnedResult;
pub const createTransactionProvenanceV3 = transaction_provenance_v3.create;
pub const validateTransactionProvenanceV3 = transaction_provenance_v3.validateDocument;
pub const TransactionProvenanceV3Store = transaction_provenance_v3.Store;
pub const executeTransaction = transaction_executor.execute;
pub const TransactionExecutionRequest = transaction_executor.Request;
pub const TransactionExecutionPolicy = transaction_executor.Policy;
pub const TransactionArtifact = transaction_executor.Artifact;
pub const TransactionExecutionReport = transaction_executor.Report;
pub const TransactionExecutionDependencies = transaction_executor.Dependencies;
pub const recoverTransaction = transaction_executor.recover;
pub const TransactionRecoveryRequest = transaction_executor.RecoveryRequest;
pub const TransactionRecoveryReport = transaction_executor.RecoveryReport;
pub const TransactionJournalState = transaction_recovery.State;
pub const TransactionJournalStore = transaction_recovery.Store;
pub const TransactionStatusReader = transaction_recovery.StatusReader;
pub const TransactionSystemJournalStore = transaction_recovery.SystemJournalStore;
pub const TransactionSystemStatusFileReader = transaction_recovery.SystemStatusFileReader;
pub const TransactionVerificationPolicy = transaction_recovery.VerificationPolicy;
pub const TransactionVerification = transaction_recovery.Verification;

/// OpenPGP repository fixtures (signed InRelease/Packages plus keyrings) shared
/// with out-of-tree regression tests such as production_backend_customize_test.zig,
/// which exercises the product backend exclusively through this public package.
/// Analyzed lazily, so builds that never reference it incur no cost.
pub const test_fixtures = struct {
    pub const openpgp = @import("fixtures/openpgp.zig");
};

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

pub const Operation = product_api.Operation;

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
    _ = deb_payload;
    _ = deb822;
    _ = relation;
    _ = dpkg_status;
    _ = release_metadata;
    _ = metadata_cache;
    _ = repository_acquisition;
    _ = package_acquisition;
    _ = local_artifact;
    _ = package_origin;
    _ = packages_index;
    _ = metadata_decompression;
    _ = repository_refresh;
    _ = repository_policy;
    _ = target_apt_config;
    _ = signed_release_envelope;
    _ = openpgp_verifier;
    _ = transaction_executor;
    _ = transaction_recovery;
    _ = exact_lock;
    _ = exact_lock_v2;
    _ = transaction_provenance;
    _ = transaction_provenance_v2;
    _ = transaction_provenance_v3;
    _ = package_family_backend;
    _ = repository_api;
    _ = repository_state;
    _ = repository_backend;
    _ = system_product;
    _ = system_operation_lock;
}
