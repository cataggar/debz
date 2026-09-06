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
pub const package_cache_archive = @import("package_cache_archive.zig");
pub const package_cache_workflow = @import("package_cache_workflow.zig");
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
pub const PackageCacheArchiveLimits = package_cache_archive.Limits;
pub const PackageCacheArchiveImportPolicy = package_cache_archive.ImportPolicy;
pub const PackageCacheArchiveImportResult = package_cache_archive.ImportResult;
pub const PackageCacheArchiveExportResult = package_cache_archive.ExportResult;
pub const importPackageCacheArchive = package_cache_archive.importFile;
pub const exportPackageCacheArchive = package_cache_archive.exportFile;
pub const PackageCacheRequest = package_cache_workflow.Request;
pub const PackageCachePolicy = package_cache_workflow.Policy;
pub const PackageCacheLimits = package_cache_workflow.Limits;
pub const PackageCacheRepositoryPolicy = package_cache_workflow.RepositoryPolicy;
pub const PackageCacheCorruptPolicy = package_cache_workflow.CorruptCachePolicy;
pub const PackageCacheRestoredState = package_cache_workflow.RestoredCache;
pub const PackageCacheRepositoryView = package_cache_workflow.RepositoryView;
pub const PackageCacheFingerprint = package_cache_workflow.Fingerprint;
pub const PackageCachePreflightResult = package_cache_workflow.PreflightResult;
pub const PackageCachePrepareRequest = package_cache_workflow.PrepareRequest;
pub const PackageCachePrepareResult = package_cache_workflow.PrepareResult;
pub const createPackageCacheFingerprint = package_cache_workflow.createFingerprint;
pub const preflightPackageCache = package_cache_workflow.preflight;
pub const preparePackageCache = package_cache_workflow.prepare;
pub const preparePackageCacheWithWriterLock = package_cache_workflow.prepareWithWriterLock;
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
pub const maintainer_script = @import("maintainer_script.zig");
pub const transaction_executor = @import("transaction_executor.zig");
pub const transaction_engine = @import("transaction_engine.zig");
pub const root_fs = @import("root_fs.zig");
pub const transaction_recovery = @import("transaction_recovery.zig");
pub const exact_lock = @import("exact_lock.zig");
pub const exact_lock_v2 = @import("exact_lock_v2.zig");
pub const native_authorization = @import("native_authorization.zig");
pub const transaction_provenance = @import("transaction_provenance.zig");
pub const transaction_provenance_v2 = @import("transaction_provenance_v2.zig");
pub const transaction_result_summary = @import("transaction_result_summary.zig");
pub const MaintainerScriptKind = maintainer_script.Kind;
pub const MaintainerScriptIdentity = maintainer_script.Identity;
pub const MaintainerScriptPolicy = maintainer_script.Policy;
pub const MaintainerScriptLimits = maintainer_script.Limits;
pub const MaintainerScriptCapture = maintainer_script.Capture;
pub const MaintainerScriptDescendantPolicy = maintainer_script.DescendantPolicy;
pub const MaintainerScriptRequest = maintainer_script.Request;
pub const MaintainerScriptVariable = maintainer_script.Variable;
pub const MaintainerScriptOutcome = maintainer_script.Outcome;
pub const MaintainerScriptRejectionReason = maintainer_script.RejectionReason;
pub const MaintainerScriptSetupFailure = maintainer_script.SetupFailure;
pub const MaintainerScriptReport = maintainer_script.Report;
pub const MaintainerScriptEvidence = maintainer_script.Evidence;
pub const MaintainerScriptLauncher = maintainer_script.Launcher;
pub const MaintainerScriptDependencies = maintainer_script.Dependencies;
pub const SystemMaintainerScriptLauncher = maintainer_script.SystemLauncher;
pub const runMaintainerScript = maintainer_script.run;
pub const validateMaintainerScriptRequest = maintainer_script.validate;
pub const TransactionEngineKind = transaction_engine.Kind;
pub const TransactionEngineExecutor = transaction_engine.Executor;
pub const RootFilesystem = root_fs.Root;
pub const OwnedRootFilesystem = root_fs.OwnedRoot;
pub const RootRelativePath = root_fs.Path;
pub const RootPathMetadata = root_fs.Metadata;
pub const RootPublishOptions = root_fs.PublishOptions;
pub const RootOverwritePolicy = root_fs.OverwritePolicy;
pub const RootStagedFile = root_fs.StagedFile;
pub const openAbsoluteRootFilesystem = root_fs.openAbsoluteRoot;
pub const authorizeTransactionEngine = transaction_engine.authorize;
pub const executeAuthorizedTransaction = transaction_engine.executeAuthorized;
pub const TransactionEngineAuthorizationError = transaction_engine.AuthorizationError;
pub const NativeTransactionAuthorization = native_authorization.Authorization;
pub const OwnedNativeTransactionAuthorization = native_authorization.OwnedAuthorization;
pub const NativeTransactionAuthorizationInput = native_authorization.Input;
pub const NativeAuthorizationAction = native_authorization.Action;
pub const NativeAuthorizationArtifact = native_authorization.Artifact;
pub const NativeAuthorizationFinalPackage = native_authorization.FinalPackage;
pub const NativeAuthorizationFinalState = native_authorization.FinalState;
pub const NativeAuthorizationLockBinding = native_authorization.LockBinding;
pub const NativeAuthorizationPolicyBinding = native_authorization.PolicyBinding;
pub const createNativeTransactionAuthorization = native_authorization.create;
pub const decodeNativeTransactionAuthorization = native_authorization.decode;
pub const NativeTransactionAuthorizationStore = native_authorization.Store;
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
    _ = maintainer_script;
    _ = transaction_executor;
    _ = transaction_recovery;
    _ = root_fs;
    _ = exact_lock;
    _ = exact_lock_v2;
    _ = native_authorization;
    _ = transaction_engine;
    _ = transaction_provenance;
    _ = transaction_provenance_v2;
    _ = package_family_backend;
    _ = repository_api;
    _ = repository_state;
    _ = repository_backend;
}
