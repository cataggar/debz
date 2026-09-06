//! Native transaction program version 1.
//!
//! A program is the complete low-level transaction the native engine will
//! execute against one root. It is compiled once, before any mutation, from a
//! reviewed native authorization, the solver's ordered lifecycle, the consumed
//! installed-database generation, and the validated package archives selected
//! for the transaction. Compilation either returns a fully validated program
//! with a stable digest or a typed diagnostic; it never returns a partially
//! compiled program and never touches a filesystem, a package database, or a
//! maintainer script.
//!
//! The compiled document is the durable authority for execution and recovery.
//! Every step carries a dense sequence, an explicit phase, an explicit typed
//! operation, and explicit prerequisite step sequences, so an interrupted
//! transaction can be resumed or refused deterministically. No step contains a
//! shell command; maintainer-script work is expressed as an exact script
//! identity, argument vector, environment-policy identity, failure state, and
//! compensating unwind call.
//!
//! Conffile decisions reproduce dpkg's two-dimensional table over the packaged,
//! recorded, and observed digests, so the reviewed policy decides only what
//! dpkg would prompt for. Deferred trigger work is the only place a package
//! outside the authorized actions is touched, so it is accepted only for a
//! completely installed package. Diagnostics never own memory: compilation
//! frees its arena before returning one, so every reported string references
//! caller input or static text.
//!
//! Filesystem and package-database work that only later modules can enumerate
//! is expressed as a typed forward reference (an artifact index plus the
//! application digest of its validated inventory, or the digest of the
//! installed ownership set), never as an unvalidated instruction. The unpack,
//! database, and trigger engines consume those references; they cannot weaken
//! the bindings this module validates.
const std = @import("std");
const absolute_path = @import("absolute_path.zig");
const debian_version = @import("debian_version.zig");
const dpkg_status = @import("dpkg_status.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const maintainer_script = @import("maintainer_script.zig");
const native_authorization = @import("native_authorization.zig");
const package_origin = @import("package_origin.zig");
const solver = @import("solver.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_recovery = @import("transaction_recovery.zig");

pub const schema_id = "https://debz.dev/schema/native-transaction-program-v1";
pub const schema_version: u32 = 1;

/// Absolute resource ceilings. `Limits` may tighten them; nothing may raise
/// them, so a hostile or defective caller cannot enlarge the compiler's
/// working set.
pub const maximum_document_bytes: usize = 64 * 1024 * 1024;
pub const maximum_steps: usize = 2_000_000;
pub const maximum_artifacts: usize = native_authorization.maximum_actions;
pub const maximum_installed_packages: usize = native_authorization.maximum_final_packages;
pub const maximum_conffiles: usize = 400_000;
pub const maximum_triggers: usize = 400_000;
pub const maximum_ownership_conflicts: usize = 100_000;
pub const maximum_compile_work: usize = 16_000_000;
pub const maximum_step_dependencies: usize = 8;
pub const maximum_script_arguments: usize = 8;
pub const maximum_argument_bytes: usize = 512;
pub const maximum_identity_bytes: usize = 256;
pub const maximum_path_bytes: usize = 4096;
pub const maximum_trigger_bytes: usize = 4096;
pub const maximum_replaces: usize = 4096;
pub const maximum_unsupported_features: usize = 256;
/// Deferred trigger sets are small in practice. Bounding them keeps pending
/// membership checks and interested-package expansion linear in the compiled
/// output instead of quadratic in the transaction.
pub const maximum_pending_triggers: usize = 256;
pub const maximum_interested_packages: usize = 4096;

/// Caller-tightened ceilings. Every field must be positive and no larger than
/// the module maximum of the same name.
pub const Limits = struct {
    steps: usize = maximum_steps,
    artifacts: usize = maximum_artifacts,
    installed_packages: usize = maximum_installed_packages,
    conffiles: usize = maximum_conffiles,
    triggers: usize = maximum_triggers,
    ownership_conflicts: usize = maximum_ownership_conflicts,
    compile_work: usize = maximum_compile_work,
};

/// Lowercase hexadecimal SHA-256. Digests are hexadecimal in the model so the
/// canonical document, the compiled program, and every consumer compare the
/// same bytes.
pub const Digest = [64]u8;
/// Lowercase hexadecimal MD5, matching the digest dpkg records for conffiles.
pub const Md5Digest = [32]u8;

/// Modeled dpkg package state. The program reuses the database's state model
/// so recorded transitions are exactly the states a compatible database can
/// publish.
pub const PackageState = dpkg_status.CurrentState;

pub const PackageRef = struct {
    name: []const u8,
    architecture: []const u8,
};

pub const PackageIdentity = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,

    pub fn ref(self: PackageIdentity) PackageRef {
        return .{ .name = self.name, .architecture = self.architecture };
    }
};

pub const TriggerKind = enum {
    interest,
    interest_await,
    interest_noawait,
    activate,
    activate_await,
    activate_noawait,

    pub fn isInterest(self: TriggerKind) bool {
        return switch (self) {
            .interest, .interest_await, .interest_noawait => true,
            .activate, .activate_await, .activate_noawait => false,
        };
    }

    /// Whether the declaring package waits for the trigger to be processed
    /// before it is considered fully configured.
    pub fn awaits(self: TriggerKind) bool {
        return switch (self) {
            .interest, .interest_await, .activate, .activate_await => true,
            .interest_noawait, .activate_noawait => false,
        };
    }
};

pub const TriggerDeclaration = struct {
    kind: TriggerKind,
    /// Trigger name, or the absolute path of a file trigger.
    name: []const u8,
};

/// Which validated bytes a maintainer-script call must execute: the script
/// recorded for the installed package, or the script carried by the package
/// being unpacked.
pub const ScriptSource = enum { installed_package, new_package };

/// The exact compensating call dpkg performs when a lifecycle script fails.
pub const Unwind = struct {
    kind: maintainer_script.Kind,
    source: ScriptSource,
    script_sha256: Digest,
    arguments: []const []const u8,
};

pub const ScriptFailure = struct {
    /// Package state the database must record if the call fails.
    state: PackageState,
    unwind: ?Unwind,
    /// A failure that cannot be compensated automatically and must publish a
    /// durable recovery requirement.
    recovery_required: bool,
};

pub const ScriptCall = struct {
    package: PackageIdentity,
    kind: maintainer_script.Kind,
    source: ScriptSource,
    script_sha256: Digest,
    arguments: []const []const u8,
    /// Identity of the maintainer-script environment and isolation policy the
    /// runner must apply, as produced by `maintainer_script.policyDigest`.
    environment_policy_sha256: Digest,
    failure: ScriptFailure,
};

/// One dpkg-compatible conffile outcome. The compiler decides it from three
/// digests — the digest the package ships, the digest the database recorded
/// when the installed version was configured, and the digest observed in the
/// root — plus the reviewed policy, exactly like dpkg's two-dimensional
/// (user edited x maintainer edited) decision table.
pub const ConffileAction = enum {
    /// The package introduces a conffile the database does not record, so the
    /// packaged file is installed. v1 evidence carries an observed digest only
    /// for recorded conffiles, so a file created locally beforehand cannot be
    /// distinguished here.
    install_new,
    /// The package no longer ships the conffile because it declares
    /// `remove-on-upgrade`, and there is nothing recorded or present to
    /// remove.
    skip_not_shipped,
    /// The observed digest already equals the packaged digest, so the file is
    /// left untouched and only the recorded digest is refreshed.
    identical_no_op,
    /// The recorded conffile is absent from the root, the maintainer changed
    /// it, and `use_package_version` reinstalls it. There is no local file to
    /// preserve, so no `.dpkg-old` is written.
    restore_missing,
    /// The on-disk file matches the recorded digest and is replaced silently.
    replace_unmodified,
    /// The local file was edited but the packaged digest equals the recorded
    /// digest, so dpkg keeps the local file and writes no conflict artifact,
    /// whatever the policy is.
    keep_user_modified,
    /// The local file was deleted and the packaged digest equals the recorded
    /// digest, so the deletion is preserved and no conflict artifact is
    /// written, whatever the policy is.
    keep_user_deleted,
    /// Locally modified or deleted while the maintainer also changed the
    /// file, `keep_existing` policy: the local state is kept and the package
    /// version published as `.dpkg-dist`.
    keep_existing_stage_dist,
    /// Locally modified while the maintainer also changed the file,
    /// `use_package_version` policy: local file preserved as `.dpkg-old`.
    install_stage_old,
    /// The package declares `remove-on-upgrade` for a recorded, unmodified
    /// conffile, which is deleted.
    remove_on_upgrade,
    /// The package declares `remove-on-upgrade` for a recorded conffile the
    /// administrator modified, which is preserved as `.dpkg-old`.
    remove_on_upgrade_stage_old,
    /// The database records a conffile the new package no longer ships.
    mark_obsolete,
    /// Remove retains conffiles and their database records.
    retain_on_remove,
    /// Purge deletes conffiles and their database records.
    delete_on_purge,
};

pub const ConffileDecision = struct {
    package: PackageIdentity,
    path: []const u8,
    policy: transaction_executor.ConffilePolicy,
    action: ConffileAction,
    /// Digest of the conffile shipped by the package being unpacked.
    packaged_md5: ?Md5Digest,
    /// Digest the installed database records for the conffile.
    recorded_md5: ?Md5Digest,
    /// Digest observed in the root during preflight; absent when the file is
    /// missing.
    on_disk_md5: ?Md5Digest,
};

pub const OwnershipResolution = enum {
    /// The claimant is a newer generation of the package that owns the path.
    same_package,
    /// The claimant declares `Replaces` for the current owner.
    replaces,
    /// The reviewed policy authorizes an overwrite of a foreign owner.
    forced_overwrite,
};

pub const AuthorizationAssertion = struct {
    authorization_sha256: Digest,
    plan_sha256: Digest,
    request_sha256: Digest,
    exact_lock_sha256: Digest,
    final_state_sha256: Digest,
};

pub const RootAssertion = struct {
    install_root: []const u8,
    root_identity_sha256: Digest,
    target_architecture: []const u8,
    foreign_architectures: []const []const u8,
};

pub const DatabaseAssertion = struct {
    generation_sha256: Digest,
    evidence_sha256: Digest,
    package_count: u64,
    updates_pending: bool,
};

pub const InstalledAssertion = struct {
    package: PackageIdentity,
    state: PackageState,
    hold: bool,
    essential: bool,
    owned_paths_sha256: Digest,
    conffiles_sha256: Digest,
    scripts_sha256: Digest,
};

pub const AbsenceAssertion = struct {
    package: PackageRef,
};

pub const OwnershipAssertion = struct {
    path: []const u8,
    holder: PackageRef,
    claimant: PackageRef,
    resolution: OwnershipResolution,
};

pub const ArtifactAssertion = struct {
    artifact: u32,
    package: PackageIdentity,
    sha256: Digest,
    size: u64,
    application_sha256: Digest,
};

pub const MaterializeIntent = struct {
    package: PackageIdentity,
    artifact: u32,
    application_sha256: Digest,
};

pub const UnpackIntent = struct {
    package: PackageIdentity,
    prior_version: ?[]const u8,
    artifact: u32,
    application_sha256: Digest,
    /// The payload was already materialized by an essential bootstrap step.
    bootstrapped: bool,
    /// Digest of the ownership set the replaced generation published, when a
    /// generation is being replaced.
    prior_owned_paths_sha256: ?Digest,
};

pub const RemoveIntent = struct {
    package: PackageIdentity,
    owned_paths_sha256: Digest,
    retain_conffiles: bool,
};

pub const PurgeIntent = struct {
    package: PackageIdentity,
    conffiles_sha256: Digest,
};

pub const TriggerInterestRecord = struct {
    package: PackageIdentity,
    declarations: []const TriggerDeclaration,
    declarations_sha256: Digest,
};

pub const TriggerActivation = struct {
    source: PackageRef,
    trigger: []const u8,
    kind: TriggerKind,
    awaiting: bool,
    interested: []const PackageRef,
};

pub const PendingTrigger = struct {
    package: PackageRef,
    triggers: []const []const u8,
    awaiting: bool,
};

pub const DeferredTriggerWork = struct {
    pending: []const PendingTrigger,
    pending_sha256: Digest,
};

pub const BarrierReason = enum {
    /// A `Pre-Depends` barrier: pending packages must be configured before the
    /// next unpack.
    pre_depends,
    /// The final configure barrier of the transaction.
    final,
};

pub const ConfigureBarrier = struct {
    reason: BarrierReason,
    packages: []const PackageRef,
};

pub const StateRecord = struct {
    package: PackageIdentity,
    state: PackageState,
    hold: bool,
    /// `not_installed` removes the status record instead of publishing one.
    remove_entry: bool,
};

pub const DatabasePublication = struct {
    final_state_sha256: Digest,
    package_count: u64,
};

pub const FinalVerification = struct {
    final_state_sha256: Digest,
    installed_count: u64,
    config_files_count: u64,
};

pub const ProvenanceRequirement = struct {
    authorization_sha256: Digest,
    database_generation_sha256: Digest,
    /// A crash while a script may have been running publishes ambiguous
    /// outcome evidence and blocks another mutation.
    record_script_outcome_unknown: bool,
};

pub const StepKind = enum {
    assert_authorization,
    assert_root_state,
    assert_database_generation,
    assert_installed_package,
    assert_package_absent,
    assert_path_ownership,
    revalidate_artifact,
    materialize_bootstrap_payload,
    unpack_package,
    remove_package_files,
    purge_package_files,
    run_maintainer_script,
    apply_conffile_decision,
    record_trigger_interests,
    activate_trigger,
    configure_barrier,
    process_deferred_triggers,
    record_package_state,
    publish_database_generation,
    verify_final_state,
    publish_provenance,
};

pub const Operation = union(StepKind) {
    assert_authorization: AuthorizationAssertion,
    assert_root_state: RootAssertion,
    assert_database_generation: DatabaseAssertion,
    assert_installed_package: InstalledAssertion,
    assert_package_absent: AbsenceAssertion,
    assert_path_ownership: OwnershipAssertion,
    revalidate_artifact: ArtifactAssertion,
    materialize_bootstrap_payload: MaterializeIntent,
    unpack_package: UnpackIntent,
    remove_package_files: RemoveIntent,
    purge_package_files: PurgeIntent,
    run_maintainer_script: ScriptCall,
    apply_conffile_decision: ConffileDecision,
    record_trigger_interests: TriggerInterestRecord,
    activate_trigger: TriggerActivation,
    configure_barrier: ConfigureBarrier,
    process_deferred_triggers: DeferredTriggerWork,
    record_package_state: StateRecord,
    publish_database_generation: DatabasePublication,
    verify_final_state: FinalVerification,
    publish_provenance: ProvenanceRequirement,
};

pub const Phase = enum {
    preflight,
    bootstrap,
    remove,
    unpack,
    configure,
    trigger,
    verify,
};

pub const Step = struct {
    sequence: u32,
    phase: Phase,
    /// Sequences of steps that must have completed before this step runs.
    /// Every entry is strictly smaller than `sequence`, so the step graph is
    /// acyclic by construction.
    requires: []const u32,
    operation: Operation,
};

pub const LockBinding = struct {
    schema: []const u8,
    version: u32,
    digest_sha256: Digest,
};

pub const PolicyBinding = struct {
    conffile: transaction_executor.ConffilePolicy,
    force: []const transaction_executor.ForceRisk,
    allow_host_root: bool,
};

pub const DatabaseBinding = struct {
    generation_sha256: Digest,
    evidence_sha256: Digest,
    package_count: u64,
};

pub const RepositoryOrigin = struct {
    repository_id: [64]u8,
    repository_snapshot_sha256: Digest,
};

pub const LocalArtifactOrigin = struct {
    artifact_id: [64]u8,
    sha256: Digest,
    size: u64,
    package: PackageIdentity,
    acquisition_url: []const u8,
    trust_mode: package_origin.LocalArtifactTrustMode,
};

pub const Origin = union(enum) {
    authenticated_repository: RepositoryOrigin,
    local_artifact: LocalArtifactOrigin,
};

pub const ProgramArtifact = struct {
    index: u32,
    package: PackageIdentity,
    sha256: Digest,
    size: u64,
    /// Digest of the validated application inventory the unpack engine must
    /// reproduce from the revalidated archive.
    application_sha256: Digest,
    origin: Origin,
};

/// Canonical program document. Field order is the canonical serialization
/// order; `digest_sha256` covers the whole document with its own field set to
/// 64 ASCII zeros, so no field can change without changing the digest.
pub const Program = struct {
    schema: []const u8,
    version: u32,
    backend: native_authorization.Backend,
    install_root: []const u8,
    root_identity_sha256: Digest,
    target_architecture: []const u8,
    foreign_architectures: []const []const u8,
    request_sha256: Digest,
    solver_policy_sha256: Digest,
    executor_policy_sha256: Digest,
    plan_sha256: Digest,
    exact_lock: LockBinding,
    authorization_sha256: Digest,
    final_state_sha256: Digest,
    policy: PolicyBinding,
    script_policy_sha256: Digest,
    installed_database: DatabaseBinding,
    artifacts: []const ProgramArtifact,
    artifacts_sha256: Digest,
    steps: []const Step,
    steps_sha256: Digest,
    digest_sha256: Digest,

    pub fn canonicalJson(self: Program, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeDocument(self, &output.writer);
        return output.toOwnedSlice();
    }

    pub fn step(self: Program, sequence: u32) ?Step {
        if (sequence >= self.steps.len) return null;
        return self.steps[sequence];
    }

    /// True when the program was compiled for exactly this authorization.
    pub fn matchesAuthorization(
        self: Program,
        authorization: native_authorization.Authorization,
    ) bool {
        return self.backend == authorization.backend and
            std.mem.eql(u8, &self.authorization_sha256, &hex(32, authorization.digest_sha256)) and
            std.mem.eql(u8, &self.final_state_sha256, &hex(32, authorization.final_state_sha256)) and
            std.mem.eql(u8, &self.plan_sha256, &hex(32, authorization.plan_sha256)) and
            std.mem.eql(u8, &self.request_sha256, &hex(32, authorization.request_sha256)) and
            std.mem.eql(u8, &self.root_identity_sha256, &hex(32, authorization.root_identity_sha256)) and
            std.mem.eql(u8, self.install_root, authorization.install_root) and
            std.mem.eql(
                u8,
                &self.exact_lock.digest_sha256,
                &hex(32, authorization.exact_lock.digest_sha256),
            );
    }

    pub fn countSteps(self: Program, kind: StepKind) usize {
        var total: usize = 0;
        for (self.steps) |item| {
            if (item.operation == kind) total += 1;
        }
        return total;
    }
};

pub const OwnedProgram = struct {
    program: Program,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedProgram) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

/// Compiler inputs. Every input is evidence a caller already validated: the
/// reviewed authorization, the solver's ordered lifecycle, the consumed
/// installed database, and the validated archives. The compiler revalidates
/// every relationship between them and never trusts one input to excuse
/// another.
pub const InstalledScript = struct {
    kind: maintainer_script.Kind,
    sha256: [32]u8,
};

pub const InstalledConffile = struct {
    /// Absolute path recorded by the database.
    path: []const u8,
    /// Digest the database records for the conffile.
    recorded_md5: [16]u8,
    /// Digest observed in the root during preflight, or null when the file is
    /// absent.
    on_disk_md5: ?[16]u8 = null,
    obsolete: bool = false,
};

pub const InstalledPackage = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    state: PackageState,
    hold: bool = false,
    essential: bool = false,
    /// Digest of the published owned-path set for this package.
    owned_paths_sha256: [32]u8 = @splat(0),
    scripts: []const InstalledScript = &.{},
    conffiles: []const InstalledConffile = &.{},
    triggers: []const TriggerDeclaration = &.{},
};

/// The exact installed-database generation the transaction consumed. The
/// engine may not mutate a root whose generation digest has changed.
pub const InstalledDatabase = struct {
    generation_sha256: [32]u8,
    packages: []const InstalledPackage = &.{},
    /// Nonempty `var/lib/dpkg/updates` is interrupted publication and requires
    /// explicit recovery before another mutation.
    updates_pending: bool = false,
};

pub const ArchiveScript = struct {
    kind: maintainer_script.Kind,
    sha256: [32]u8,
    size: u64 = 0,
};

pub const ArchiveConffile = struct {
    path: []const u8,
    /// Digest of the file the package ships. `remove-on-upgrade` conffiles
    /// must not be shipped, so they carry no digest and every other conffile
    /// must carry one.
    md5: ?[16]u8,
    remove_on_upgrade: bool = false,
};

/// One validated package archive bound to one archive-producing authorized
/// action. `application_sha256` is the digest of the validated application
/// inventory; the unpack engine must reproduce exactly that inventory from the
/// revalidated archive bytes.
pub const Archive = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    sha256: [32]u8,
    size: u64,
    origin: exact_lock_v2.PackageOrigin,
    application_sha256: [32]u8,
    scripts: []const ArchiveScript = &.{},
    conffiles: []const ArchiveConffile = &.{},
    triggers: []const TriggerDeclaration = &.{},
    /// `Replaces` package names, used to resolve path ownership conflicts.
    replaces: []const []const u8 = &.{},
    essential: bool = false,
};

/// A path claimed by a package being unpacked that another package currently
/// owns, as found by preflight before any mutation.
pub const OwnershipConflict = struct {
    path: []const u8,
    holder: PackageRef,
    claimant: PackageRef,
};

pub const Input = struct {
    authorization: *const native_authorization.Authorization,
    /// The reviewed plan's ordered lifecycle. It must cover every authorized
    /// action exactly once; nothing may be dropped or invented.
    ordered_actions: []const solver.OrderedAction,
    installed: InstalledDatabase,
    archives: []const Archive = &.{},
    /// Maintainer-script environment and isolation policy the runner applies.
    script_policy: maintainer_script.Policy = .{},
    ownership_conflicts: []const OwnershipConflict = &.{},
    /// Root features preflight classified as outside the v1 contract. A
    /// nonempty list fails closed.
    unsupported_features: []const []const u8 = &.{},
    /// A crash while a script may have been running publishes ambiguous
    /// outcome evidence instead of continuing.
    record_script_outcome_unknown: bool = true,
    limits: Limits = .{},
};

/// Fail-closed compilation taxonomy. Every rejection names one reason; no
/// code means "unknown" and none is recoverable by retrying compilation with
/// the same inputs.
pub const DiagnosticCode = enum {
    out_of_memory,
    invalid_limits,
    unsupported_backend,
    unsupported_lock_generation,
    unsupported_feature,
    policy_mismatch,
    limit_exceeded,
    work_limit_exceeded,
    empty_program,
    invalid_identity,
    invalid_version,
    invalid_path,
    invalid_digest,
    duplicate_installed_package,
    invalid_installed_metadata,
    database_not_quiescent,
    installed_state_contradiction,
    missing_installed_package,
    unexpected_installed_package,
    missing_archive,
    duplicate_archive,
    extra_archive,
    archive_identity_mismatch,
    archive_evidence_mismatch,
    archive_origin_mismatch,
    invalid_archive_metadata,
    missing_ordered_action,
    duplicate_ordered_action,
    unsupported_ordered_action,
    ordering_mismatch,
    ordering_cycle,
    missing_configure_barrier,
    invalid_script_metadata,
    missing_script_evidence,
    invalid_conffile_metadata,
    duplicate_conffile,
    invalid_trigger_metadata,
    duplicate_trigger,
    invalid_ownership_conflict,
    unresolved_ownership_conflict,
    missing_final_package,
    final_state_contradiction,
    program_too_large,
    invalid_step_graph,
};

/// Diagnostics borrow input strings and static detail text; they never own
/// memory, so a failed compilation allocates nothing the caller must release.
///
/// The invariant is a lifetime requirement, not a convenience: `compile`
/// destroys the compiler arena before it returns a diagnostic, so any field
/// that pointed into the arena would be freed memory. Every compiler-internal
/// view (prepared conffiles, trigger declarations, `Replaces` names) therefore
/// keeps aliasing caller memory, and only emission copies into the arena.
pub const Diagnostic = struct {
    code: DiagnosticCode,
    detail: []const u8 = "",
    package: ?[]const u8 = null,
    architecture: ?[]const u8 = null,
    path: ?[]const u8 = null,
    sequence: ?usize = null,
};

pub const Result = union(enum) {
    program: OwnedProgram,
    diagnostic: Diagnostic,
};

pub const DecodeError = error{
    DocumentTooLarge,
    UnsupportedSchema,
    UnsupportedBackend,
    NonCanonicalDocument,
    DigestMismatch,
    ArtifactsDigestMismatch,
    StepsDigestMismatch,
    InvalidDigest,
    InvalidIdentity,
    InvalidPath,
    InvalidStepGraph,
    NonCanonicalSequence,
    TooManySteps,
    TooManyArtifacts,
    UnsupportedLockVersion,
    InvalidProgram,
};

const PackageRefContext = struct {
    pub fn hash(_: PackageRefContext, key: PackageRef) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(key.name);
        hasher.update("\x00");
        hasher.update(key.architecture);
        return hasher.final();
    }

    pub fn eql(_: PackageRefContext, left: PackageRef, right: PackageRef) bool {
        return std.mem.eql(u8, left.name, right.name) and
            std.mem.eql(u8, left.architecture, right.architecture);
    }
};

const PackageMap = std.HashMapUnmanaged(
    PackageRef,
    u32,
    PackageRefContext,
    std.hash_map.default_max_load_percentage,
);

const CompileError = error{ OutOfMemory, Rejected };

/// One package the program reasons about: every installed package plus every
/// package an authorized action introduces.
const Modeled = struct {
    name: []const u8,
    architecture: []const u8,
    /// Version currently recorded by the database, if any.
    installed_version: ?[]const u8,
    installed: ?usize,
    action: ?usize,
    archive: ?usize,
    artifact: ?u32,
    state: PackageState,
    hold: bool,
    assert_step: u32,
    bootstrap_step: ?u32 = null,
    unpack_step: ?u32 = null,
    configured: bool = false,
    awaiting_trigger: bool = false,
    /// Another package waits for this package's deferred trigger processing.
    awaited: bool = false,
    pending_triggers: std.ArrayList([]const u8) = .empty,

    fn ref(self: Modeled) PackageRef {
        return .{ .name = self.name, .architecture = self.architecture };
    }
};

const OrderedKindCounts = struct {
    bootstrap: bool = false,
    lifecycle: bool = false,
};

/// Archive metadata normalized into canonical order once, so emission and
/// validation never re-sort and never depend on caller order.
const PreparedArchive = struct {
    scripts: []const ArchiveScript = &.{},
    conffiles: []const ArchiveConffile = &.{},
    triggers: []const TriggerDeclaration = &.{},
    replaces: []const []const u8 = &.{},

    fn script(self: PreparedArchive, kind: maintainer_script.Kind) ?ArchiveScript {
        for (self.scripts) |item| {
            if (item.kind == kind) return item;
        }
        return null;
    }

    fn replacesPackage(self: PreparedArchive, name: []const u8) bool {
        var low: usize = 0;
        var high = self.replaces.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            switch (std.mem.order(u8, self.replaces[middle], name)) {
                .lt => low = middle + 1,
                .gt => high = middle,
                .eq => return true,
            }
        }
        return false;
    }

    fn conffile(self: PreparedArchive, path: []const u8) ?ArchiveConffile {
        var low: usize = 0;
        var high = self.conffiles.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            switch (std.mem.order(u8, self.conffiles[middle].path, path)) {
                .lt => low = middle + 1,
                .gt => high = middle,
                .eq => return self.conffiles[middle],
            }
        }
        return null;
    }
};

const Compiler = struct {
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    input: Input,
    limits: Limits,
    diagnostic: Diagnostic = .{ .code = .out_of_memory },
    work: usize = 0,
    steps: std.ArrayList(Step) = .empty,
    artifacts: std.ArrayList(ProgramArtifact) = .empty,
    installed: []InstalledPackage = &.{},
    prepared: []PreparedArchive = &.{},
    modeled: []Modeled = &.{},
    modeled_index: PackageMap = .empty,
    installed_index: PackageMap = .empty,
    archive_index: PackageMap = .empty,
    action_index: PackageMap = .empty,
    artifact_steps: []u32 = &.{},
    artifact_of_action: []?u32 = &.{},
    ordered_action_index: []usize = &.{},
    final_barrier: ?usize = null,
    interests: std.StringHashMapUnmanaged(std.ArrayList(u32)) = .empty,
    authorization_step: u32 = 0,
    database_step: u32 = 0,
    script_policy_sha256: Digest = @splat('0'),

    fn reject(self: *Compiler, diagnostic: Diagnostic) CompileError {
        self.diagnostic = diagnostic;
        return error.Rejected;
    }

    fn charge(self: *Compiler, units: usize) CompileError!void {
        self.work = std.math.add(usize, self.work, units) catch
            return self.reject(.{ .code = .work_limit_exceeded });
        if (self.work > self.limits.compile_work)
            return self.reject(.{ .code = .work_limit_exceeded, .detail = "compile work" });
    }

    fn addStep(
        self: *Compiler,
        phase: Phase,
        requires: []const u32,
        operation: Operation,
    ) CompileError!u32 {
        try self.charge(1);
        if (self.steps.items.len >= self.limits.steps)
            return self.reject(.{ .code = .limit_exceeded, .detail = "steps" });
        if (requires.len > maximum_step_dependencies)
            return self.reject(.{ .code = .invalid_step_graph, .detail = "dependencies" });
        const sequence: u32 = @intCast(self.steps.items.len);
        for (requires) |required| {
            if (required >= sequence)
                return self.reject(.{ .code = .invalid_step_graph, .detail = "forward dependency" });
        }
        try self.steps.append(self.arena, .{
            .sequence = sequence,
            .phase = phase,
            .requires = try self.arena.dupe(u32, requires),
            .operation = operation,
        });
        return sequence;
    }

    fn identity(
        self: *Compiler,
        name: []const u8,
        version: []const u8,
        architecture: []const u8,
    ) CompileError!PackageIdentity {
        return .{
            .name = try self.arena.dupe(u8, name),
            .version = try self.arena.dupe(u8, version),
            .architecture = try self.arena.dupe(u8, architecture),
        };
    }

    fn ref(self: *Compiler, value: PackageRef) CompileError!PackageRef {
        return .{
            .name = try self.arena.dupe(u8, value.name),
            .architecture = try self.arena.dupe(u8, value.architecture),
        };
    }

    /// Copies trigger declarations, including their names, into the arena.
    /// Compiler-internal views alias caller memory so every diagnostic stays
    /// borrowable; published output must own its bytes, so emission copies.
    fn declarations(
        self: *Compiler,
        values: []const TriggerDeclaration,
    ) CompileError![]const TriggerDeclaration {
        const owned = try self.arena.dupe(TriggerDeclaration, values);
        for (owned) |*declaration|
            declaration.name = try self.arena.dupe(u8, declaration.name);
        return owned;
    }

    fn triggerNames(self: *Compiler, values: []const []const u8) CompileError![]const []const u8 {
        const owned = try self.arena.alloc([]const u8, values.len);
        for (values, 0..) |value, index| owned[index] = try self.arena.dupe(u8, value);
        return owned;
    }

    fn arguments(self: *Compiler, values: []const []const u8) CompileError![]const []const u8 {
        if (values.len > maximum_script_arguments)
            return self.reject(.{ .code = .invalid_script_metadata, .detail = "argument count" });
        const owned = try self.arena.alloc([]const u8, values.len);
        for (values, 0..) |value, index| {
            if (value.len > maximum_argument_bytes)
                return self.reject(.{ .code = .invalid_script_metadata, .detail = "argument bytes" });
            for (value) |byte| {
                if (byte <= 0x1f or byte == 0x7f)
                    return self.reject(.{
                        .code = .invalid_script_metadata,
                        .detail = "argument bytes",
                    });
            }
            owned[index] = try self.arena.dupe(u8, value);
        }
        return owned;
    }
};

fn hex(comptime size: usize, bytes: [size]u8) [size * 2]u8 {
    const alphabet = "0123456789abcdef";
    var result: [size * 2]u8 = undefined;
    for (bytes, 0..) |byte, index| {
        result[index * 2] = alphabet[byte >> 4];
        result[index * 2 + 1] = alphabet[byte & 15];
    }
    return result;
}

fn validIdentity(value: []const u8) bool {
    if (value.len == 0 or value.len > maximum_identity_bytes) return false;
    for (value) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return false;
    }
    return true;
}

fn validVersion(value: []const u8) bool {
    if (!validIdentity(value)) return false;
    _ = debian_version.DebianVersion.parse(value) catch return false;
    return true;
}

/// Trigger names, including file triggers, are whitespace-delimited wherever
/// dpkg records or passes them, so no name may contain a space, control byte,
/// or non-ASCII byte. Otherwise one package's trigger path could inject extra
/// trigger tokens into another package's `postinst triggered` argument.
fn validTrigger(value: []const u8) bool {
    if (value.len == 0 or value.len > maximum_trigger_bytes) return false;
    for (value) |byte| {
        if (byte <= ' ' or byte >= 0x7f) return false;
    }
    if (value[0] == '/') return absolute_path.nonRoot(value);
    if (!std.ascii.isAlphanumeric(value[0])) return false;
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '-', '+', '.', '_' => {},
            else => return false,
        }
    }
    return true;
}

fn lessRef(_: void, left: PackageRef, right: PackageRef) bool {
    const name = std.mem.order(u8, left.name, right.name);
    if (name != .eq) return name == .lt;
    return std.mem.order(u8, left.architecture, right.architecture) == .lt;
}

fn lessInstalled(_: void, left: InstalledPackage, right: InstalledPackage) bool {
    const name = std.mem.order(u8, left.name, right.name);
    if (name != .eq) return name == .lt;
    return std.mem.order(u8, left.architecture, right.architecture) == .lt;
}

fn lessConffile(_: void, left: ArchiveConffile, right: ArchiveConffile) bool {
    return std.mem.order(u8, left.path, right.path) == .lt;
}

fn lessInstalledConffile(_: void, left: InstalledConffile, right: InstalledConffile) bool {
    return std.mem.order(u8, left.path, right.path) == .lt;
}

fn lessTrigger(_: void, left: TriggerDeclaration, right: TriggerDeclaration) bool {
    const name = std.mem.order(u8, left.name, right.name);
    if (name != .eq) return name == .lt;
    return @intFromEnum(left.kind) < @intFromEnum(right.kind);
}

fn lessConflict(_: void, left: OwnershipConflict, right: OwnershipConflict) bool {
    const path = std.mem.order(u8, left.path, right.path);
    if (path != .eq) return path == .lt;
    if (!PackageRefContext.eql(.{}, left.claimant, right.claimant))
        return lessRef({}, left.claimant, right.claimant);
    return lessRef({}, left.holder, right.holder);
}

fn lessString(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn sameOrigin(left: exact_lock_v2.PackageOrigin, right: exact_lock_v2.PackageOrigin) bool {
    return switch (left) {
        .authenticated_repository => |value| switch (right) {
            .authenticated_repository => |other| std.mem.eql(u8, &value.repository_id, &other.repository_id) and
                std.mem.eql(
                    u8,
                    &value.repository_snapshot_sha256,
                    &other.repository_snapshot_sha256,
                ),
            .local_artifact => false,
        },
        .local_artifact => |value| switch (right) {
            .authenticated_repository => false,
            .local_artifact => |other| std.mem.eql(u8, &value.artifact_id, &other.artifact_id) and
                std.mem.eql(u8, &value.sha256, &other.sha256) and
                value.size == other.size and
                std.mem.eql(u8, value.package, other.package) and
                std.mem.eql(u8, value.version, other.version) and
                std.mem.eql(u8, value.architecture, other.architecture) and
                std.mem.eql(u8, value.acquisition_url, other.acquisition_url) and
                value.trust_mode == other.trust_mode,
        },
    };
}

const Sha256 = std.crypto.hash.sha2.Sha256;

fn updateString(hasher: *Sha256, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, value.len, .little);
    hasher.update(&length);
    hasher.update(value);
}

fn updateByte(hasher: *Sha256, value: u8) void {
    hasher.update(&[_]u8{value});
}

fn scriptsDigest(scripts: []const InstalledScript) [32]u8 {
    var hasher = Sha256.init(.{});
    hasher.update("debz-native-transaction-program-scripts-v1\x00");
    for (scripts) |script| {
        updateByte(&hasher, @intFromEnum(script.kind));
        hasher.update(&script.sha256);
    }
    return hasher.finalResult();
}

fn conffilesDigest(conffiles: []const InstalledConffile) [32]u8 {
    var hasher = Sha256.init(.{});
    hasher.update("debz-native-transaction-program-conffiles-v1\x00");
    for (conffiles) |conffile| {
        updateString(&hasher, conffile.path);
        hasher.update(&conffile.recorded_md5);
        if (conffile.on_disk_md5) |digest| {
            updateByte(&hasher, 1);
            hasher.update(&digest);
        } else updateByte(&hasher, 0);
        updateByte(&hasher, @intFromBool(conffile.obsolete));
    }
    return hasher.finalResult();
}

fn declarationsDigest(declarations: []const TriggerDeclaration) [32]u8 {
    var hasher = Sha256.init(.{});
    hasher.update("debz-native-transaction-program-trigger-declarations-v1\x00");
    for (declarations) |declaration| {
        updateByte(&hasher, @intFromEnum(declaration.kind));
        updateString(&hasher, declaration.name);
    }
    return hasher.finalResult();
}

fn pendingDigest(pending: []const PendingTrigger) [32]u8 {
    var hasher = Sha256.init(.{});
    hasher.update("debz-native-transaction-program-deferred-triggers-v1\x00");
    for (pending) |entry| {
        updateString(&hasher, entry.package.name);
        updateString(&hasher, entry.package.architecture);
        updateByte(&hasher, @intFromBool(entry.awaiting));
        for (entry.triggers) |trigger| updateString(&hasher, trigger);
    }
    return hasher.finalResult();
}

fn installedEvidenceDigest(packages: []const InstalledPackage) [32]u8 {
    var hasher = Sha256.init(.{});
    hasher.update("debz-native-transaction-program-installed-evidence-v1\x00");
    for (packages) |package| {
        updateString(&hasher, package.name);
        updateString(&hasher, package.version);
        updateString(&hasher, package.architecture);
        updateByte(&hasher, @intFromEnum(package.state));
        updateByte(&hasher, @intFromBool(package.hold));
        updateByte(&hasher, @intFromBool(package.essential));
        hasher.update(&package.owned_paths_sha256);
        hasher.update(&scriptsDigest(package.scripts));
        hasher.update(&conffilesDigest(package.conffiles));
        hasher.update(&declarationsDigest(package.triggers));
    }
    return hasher.finalResult();
}

/// Compiles one deterministic native transaction program. The compiler is
/// pure: it reads no filesystem, opens no database, and runs no script. It
/// returns either a completely validated program or one typed diagnostic.
pub fn compile(allocator: std.mem.Allocator, input: Input) Result {
    const arena = allocator.create(std.heap.ArenaAllocator) catch
        return .{ .diagnostic = .{ .code = .out_of_memory } };
    arena.* = .init(allocator);
    var compiler: Compiler = .{
        .allocator = allocator,
        .arena = arena.allocator(),
        .input = input,
        .limits = input.limits,
    };
    const program = run(&compiler) catch |err| {
        arena.deinit();
        allocator.destroy(arena);
        return switch (err) {
            error.OutOfMemory => .{ .diagnostic = .{ .code = .out_of_memory } },
            error.Rejected => .{ .diagnostic = compiler.diagnostic },
        };
    };
    return .{ .program = .{
        .program = program,
        .arena = arena,
        .backing_allocator = allocator,
    } };
}

fn run(self: *Compiler) CompileError!Program {
    try validateLimits(self);
    try validateBinding(self);
    try buildInstalled(self);
    try buildArtifacts(self);
    try buildModeled(self);
    try validateOrdering(self);
    try buildInterests(self);
    try emitPreflight(self);
    try emitLifecycle(self);
    try emitTriggerWork(self);
    try emitVerification(self);
    try validateFinalState(self);
    return assemble(self);
}

fn validateLimits(self: *Compiler) CompileError!void {
    const limits = self.limits;
    if (limits.steps == 0 or limits.steps > maximum_steps or
        limits.artifacts > maximum_artifacts or
        limits.installed_packages > maximum_installed_packages or
        limits.conffiles > maximum_conffiles or
        limits.triggers > maximum_triggers or
        limits.ownership_conflicts > maximum_ownership_conflicts or
        limits.compile_work == 0 or limits.compile_work > maximum_compile_work)
        return self.reject(.{ .code = .invalid_limits });
}

fn validateBinding(self: *Compiler) CompileError!void {
    const authorization = self.input.authorization;
    switch (authorization.backend) {
        .native => {},
        .legacy_dpkg => return self.reject(.{ .code = .unsupported_backend }),
    }
    if (!std.mem.eql(u8, authorization.exact_lock.schema, exact_lock_v2.schema_id) or
        authorization.exact_lock.version != exact_lock_v2.schema_version)
        return self.reject(.{ .code = .unsupported_lock_generation });
    if (authorization.actions.len == 0) return self.reject(.{ .code = .empty_program });
    if (!std.mem.eql(
        u8,
        &authorization.root_identity_sha256,
        &transaction_recovery.rootIdentity(authorization.install_root),
    )) return self.reject(.{ .code = .policy_mismatch, .detail = "root identity" });
    if (self.input.script_policy.allow_host_root != authorization.policy.allow_host_root)
        return self.reject(.{ .code = .policy_mismatch, .detail = "host root" });
    if (self.input.unsupported_features.len > maximum_unsupported_features)
        return self.reject(.{ .code = .limit_exceeded, .detail = "unsupported features" });
    if (self.input.unsupported_features.len != 0)
        return self.reject(.{
            .code = .unsupported_feature,
            .detail = self.input.unsupported_features[0],
        });
    if (self.input.installed.updates_pending)
        return self.reject(.{ .code = .database_not_quiescent });
    if (self.input.installed.packages.len > self.limits.installed_packages)
        return self.reject(.{ .code = .limit_exceeded, .detail = "installed packages" });
    if (self.input.archives.len > self.limits.artifacts)
        return self.reject(.{ .code = .limit_exceeded, .detail = "archives" });
    if (self.input.ownership_conflicts.len > self.limits.ownership_conflicts)
        return self.reject(.{ .code = .limit_exceeded, .detail = "ownership conflicts" });
    if (self.input.ordered_actions.len > self.limits.steps)
        return self.reject(.{ .code = .limit_exceeded, .detail = "ordered actions" });
}

fn buildInstalled(self: *Compiler) CompileError!void {
    const source = self.input.installed.packages;
    const packages = try self.arena.alloc(InstalledPackage, source.len);
    var conffile_total: usize = 0;
    var trigger_total: usize = 0;
    for (source, 0..) |package, index| {
        try self.charge(1);
        if (!validIdentity(package.name) or !validIdentity(package.architecture))
            return self.reject(.{
                .code = .invalid_identity,
                .package = package.name,
                .architecture = package.architecture,
            });
        if (!validVersion(package.version))
            return self.reject(.{ .code = .invalid_version, .package = package.name });
        packages[index] = package;
        packages[index].scripts = try prepareScripts(self, package);
        packages[index].conffiles = try prepareInstalledConffiles(self, package);
        packages[index].triggers = try prepareDeclarations(
            self,
            package.name,
            package.triggers,
        );
        conffile_total = std.math.add(usize, conffile_total, package.conffiles.len) catch
            return self.reject(.{ .code = .limit_exceeded, .detail = "conffiles" });
        trigger_total = std.math.add(usize, trigger_total, package.triggers.len) catch
            return self.reject(.{ .code = .limit_exceeded, .detail = "triggers" });
        if (conffile_total > self.limits.conffiles)
            return self.reject(.{ .code = .limit_exceeded, .detail = "conffiles" });
        if (trigger_total > self.limits.triggers)
            return self.reject(.{ .code = .limit_exceeded, .detail = "triggers" });
        try self.charge(package.conffiles.len + package.triggers.len);
    }
    std.mem.sort(InstalledPackage, packages, {}, lessInstalled);
    try self.installed_index.ensureTotalCapacity(self.arena, @intCast(packages.len));
    for (packages, 0..) |package, index| {
        const key: PackageRef = .{ .name = package.name, .architecture = package.architecture };
        if (self.installed_index.get(key) != null)
            return self.reject(.{
                .code = .duplicate_installed_package,
                .package = package.name,
                .architecture = package.architecture,
            });
        self.installed_index.putAssumeCapacity(key, @intCast(index));
    }
    self.installed = packages;
}

fn prepareScripts(self: *Compiler, package: InstalledPackage) CompileError![]const InstalledScript {
    if (package.scripts.len > 4)
        return self.reject(.{
            .code = .invalid_installed_metadata,
            .detail = "script count",
            .package = package.name,
        });
    const scripts = try self.arena.dupe(InstalledScript, package.scripts);
    std.mem.sort(InstalledScript, scripts, {}, struct {
        fn less(_: void, left: InstalledScript, right: InstalledScript) bool {
            return @intFromEnum(left.kind) < @intFromEnum(right.kind);
        }
    }.less);
    for (scripts, 0..) |script, index| {
        if (index != 0 and script.kind == scripts[index - 1].kind)
            return self.reject(.{
                .code = .invalid_installed_metadata,
                .detail = "duplicate script",
                .package = package.name,
            });
    }
    return scripts;
}

fn prepareInstalledConffiles(
    self: *Compiler,
    package: InstalledPackage,
) CompileError![]const InstalledConffile {
    const conffiles = try self.arena.dupe(InstalledConffile, package.conffiles);
    for (conffiles) |conffile| {
        if (conffile.path.len > maximum_path_bytes or !absolute_path.nonRoot(conffile.path))
            return self.reject(.{
                .code = .invalid_conffile_metadata,
                .detail = "path",
                .package = package.name,
                .path = conffile.path,
            });
    }
    std.mem.sort(InstalledConffile, conffiles, {}, lessInstalledConffile);
    for (conffiles, 0..) |conffile, index| {
        if (index != 0 and std.mem.eql(u8, conffile.path, conffiles[index - 1].path))
            return self.reject(.{
                .code = .duplicate_conffile,
                .package = package.name,
                .path = conffile.path,
            });
    }
    return conffiles;
}

fn prepareDeclarations(
    self: *Compiler,
    package: []const u8,
    declarations: []const TriggerDeclaration,
) CompileError![]const TriggerDeclaration {
    const owned = try self.arena.dupe(TriggerDeclaration, declarations);
    for (owned) |declaration| {
        if (!validTrigger(declaration.name))
            return self.reject(.{
                .code = .invalid_trigger_metadata,
                .package = package,
                .path = declaration.name,
            });
    }
    std.mem.sort(TriggerDeclaration, owned, {}, lessTrigger);
    for (owned, 0..) |declaration, index| {
        if (index == 0) continue;
        const previous = owned[index - 1];
        if (std.mem.eql(u8, declaration.name, previous.name) and
            declaration.kind.isInterest() == previous.kind.isInterest())
            return self.reject(.{
                .code = .duplicate_trigger,
                .package = package,
                .path = declaration.name,
            });
    }
    // Names keep pointing at caller memory: every diagnostic this module can
    // return must outlive the compiler arena, and the arena is destroyed
    // before a rejection reaches the caller. Emission copies each name into
    // the arena instead, so the compiled program still owns every byte it
    // publishes and never aliases evidence the caller may free.
    return owned;
}

fn prepareArchiveScripts(
    self: *Compiler,
    archive: Archive,
) CompileError![]const ArchiveScript {
    if (archive.scripts.len > 4)
        return self.reject(.{
            .code = .invalid_archive_metadata,
            .detail = "script count",
            .package = archive.package,
        });
    const scripts = try self.arena.dupe(ArchiveScript, archive.scripts);
    std.mem.sort(ArchiveScript, scripts, {}, struct {
        fn less(_: void, left: ArchiveScript, right: ArchiveScript) bool {
            return @intFromEnum(left.kind) < @intFromEnum(right.kind);
        }
    }.less);
    for (scripts, 0..) |script, index| {
        if (index != 0 and script.kind == scripts[index - 1].kind)
            return self.reject(.{
                .code = .invalid_archive_metadata,
                .detail = "duplicate script",
                .package = archive.package,
            });
    }
    return scripts;
}

fn prepareArchiveConffiles(
    self: *Compiler,
    archive: Archive,
) CompileError![]const ArchiveConffile {
    const conffiles = try self.arena.dupe(ArchiveConffile, archive.conffiles);
    for (conffiles) |conffile| {
        if (conffile.path.len > maximum_path_bytes or !absolute_path.nonRoot(conffile.path))
            return self.reject(.{
                .code = .invalid_conffile_metadata,
                .detail = "path",
                .package = archive.package,
                .path = conffile.path,
            });
        // A `remove-on-upgrade` conffile must not be shipped, so a digest for
        // one is evidence the archive inventory disagrees with the control
        // metadata; every other conffile must carry the digest the decision
        // table compares.
        if (conffile.remove_on_upgrade != (conffile.md5 == null))
            return self.reject(.{
                .code = .invalid_conffile_metadata,
                .detail = if (conffile.remove_on_upgrade)
                    "remove-on-upgrade digest"
                else
                    "missing packaged digest",
                .package = archive.package,
                .path = conffile.path,
            });
    }
    std.mem.sort(ArchiveConffile, conffiles, {}, lessConffile);
    for (conffiles, 0..) |conffile, index| {
        if (index != 0 and std.mem.eql(u8, conffile.path, conffiles[index - 1].path))
            return self.reject(.{
                .code = .duplicate_conffile,
                .package = archive.package,
                .path = conffile.path,
            });
    }
    return conffiles;
}

fn prepareReplaces(self: *Compiler, archive: Archive) CompileError![]const []const u8 {
    if (archive.replaces.len > maximum_replaces)
        return self.reject(.{
            .code = .limit_exceeded,
            .detail = "replaces",
            .package = archive.package,
        });
    const replaces = try self.arena.alloc([]const u8, archive.replaces.len);
    for (archive.replaces, 0..) |name, index| {
        if (!validIdentity(name))
            return self.reject(.{
                .code = .invalid_archive_metadata,
                .detail = "replaces",
                .package = archive.package,
            });
        replaces[index] = name;
    }
    std.mem.sort([]const u8, replaces, {}, lessString);
    return replaces;
}

fn buildArtifacts(self: *Compiler) CompileError!void {
    const authorization = self.input.authorization;
    const archives = self.input.archives;
    self.prepared = try self.arena.alloc(PreparedArchive, archives.len);
    try self.archive_index.ensureTotalCapacity(self.arena, @intCast(archives.len));
    var conffile_total: usize = 0;
    var trigger_total: usize = 0;
    for (archives, 0..) |archive, index| {
        try self.charge(1);
        if (!validIdentity(archive.package) or !validIdentity(archive.architecture))
            return self.reject(.{
                .code = .invalid_identity,
                .package = archive.package,
                .architecture = archive.architecture,
            });
        if (!validVersion(archive.version))
            return self.reject(.{ .code = .invalid_version, .package = archive.package });
        conffile_total = std.math.add(usize, conffile_total, archive.conffiles.len) catch
            return self.reject(.{ .code = .limit_exceeded, .detail = "conffiles" });
        trigger_total = std.math.add(usize, trigger_total, archive.triggers.len) catch
            return self.reject(.{ .code = .limit_exceeded, .detail = "triggers" });
        if (conffile_total > self.limits.conffiles)
            return self.reject(.{ .code = .limit_exceeded, .detail = "conffiles" });
        if (trigger_total > self.limits.triggers)
            return self.reject(.{ .code = .limit_exceeded, .detail = "triggers" });
        try self.charge(archive.conffiles.len + archive.triggers.len + archive.replaces.len);
        self.prepared[index] = .{
            .scripts = try prepareArchiveScripts(self, archive),
            .conffiles = try prepareArchiveConffiles(self, archive),
            .triggers = try prepareDeclarations(self, archive.package, archive.triggers),
            .replaces = try prepareReplaces(self, archive),
        };
        const key: PackageRef = .{
            .name = archive.package,
            .architecture = archive.architecture,
        };
        if (self.archive_index.get(key) != null)
            return self.reject(.{
                .code = .duplicate_archive,
                .package = archive.package,
                .architecture = archive.architecture,
            });
        self.archive_index.putAssumeCapacity(key, @intCast(index));
    }

    const used = try self.arena.alloc(bool, archives.len);
    @memset(used, false);
    self.artifact_of_action = try self.arena.alloc(?u32, authorization.actions.len);
    @memset(self.artifact_of_action, null);
    try self.action_index.ensureTotalCapacity(self.arena, @intCast(authorization.actions.len));
    for (authorization.actions, 0..) |action, action_index| {
        try self.charge(1);
        const key: PackageRef = .{
            .name = action.package,
            .architecture = action.architecture,
        };
        if (self.action_index.get(key) != null)
            return self.reject(.{
                .code = .ordering_mismatch,
                .detail = "duplicate action",
                .package = action.package,
            });
        self.action_index.putAssumeCapacity(key, @intCast(action_index));
        const evidence = action.artifact orelse {
            if (self.archive_index.get(key) != null)
                return self.reject(.{
                    .code = .extra_archive,
                    .package = action.package,
                    .architecture = action.architecture,
                });
            continue;
        };
        const archive_index = self.archive_index.get(key) orelse
            return self.reject(.{
                .code = .missing_archive,
                .package = action.package,
                .architecture = action.architecture,
            });
        const archive = archives[archive_index];
        used[archive_index] = true;
        if (!std.mem.eql(u8, archive.version, action.version))
            return self.reject(.{
                .code = .archive_identity_mismatch,
                .package = action.package,
                .architecture = action.architecture,
            });
        if (!std.mem.eql(u8, &archive.sha256, &evidence.sha256) or archive.size != evidence.size)
            return self.reject(.{
                .code = .archive_evidence_mismatch,
                .package = action.package,
                .architecture = action.architecture,
            });
        if (!sameOrigin(archive.origin, evidence.origin))
            return self.reject(.{
                .code = .archive_origin_mismatch,
                .package = action.package,
                .architecture = action.architecture,
            });
        const index: u32 = @intCast(self.artifacts.items.len);
        if (index >= self.limits.artifacts)
            return self.reject(.{ .code = .limit_exceeded, .detail = "artifacts" });
        self.artifact_of_action[action_index] = index;
        try self.artifacts.append(self.arena, .{
            .index = index,
            .package = try self.identity(archive.package, archive.version, archive.architecture),
            .sha256 = hex(32, archive.sha256),
            .size = archive.size,
            .application_sha256 = hex(32, archive.application_sha256),
            .origin = try ownedOrigin(self, archive.origin),
        });
    }
    for (used, 0..) |consumed, index| {
        if (consumed) continue;
        return self.reject(.{
            .code = .extra_archive,
            .package = archives[index].package,
            .architecture = archives[index].architecture,
        });
    }
}

fn ownedOrigin(self: *Compiler, origin: exact_lock_v2.PackageOrigin) CompileError!Origin {
    return switch (origin) {
        .authenticated_repository => |value| .{ .authenticated_repository = .{
            .repository_id = value.repository_id,
            .repository_snapshot_sha256 = hex(32, value.repository_snapshot_sha256),
        } },
        .local_artifact => |value| .{ .local_artifact = .{
            .artifact_id = value.artifact_id,
            .sha256 = hex(32, value.sha256),
            .size = value.size,
            .package = try self.identity(value.package, value.version, value.architecture),
            .acquisition_url = try self.arena.dupe(u8, value.acquisition_url),
            .trust_mode = value.trust_mode,
        } },
    };
}

/// Builds the modeled package table: every installed package plus every
/// package an action introduces, in one deterministic order, and validates
/// each action against the installed evidence it claims to transform.
fn buildModeled(self: *Compiler) CompileError!void {
    const authorization = self.input.authorization;
    var entries: std.ArrayList(Modeled) = .empty;
    try entries.ensureTotalCapacity(
        self.arena,
        self.installed.len + authorization.actions.len,
    );
    for (self.installed, 0..) |package, index| {
        entries.appendAssumeCapacity(.{
            .name = package.name,
            .architecture = package.architecture,
            .installed_version = package.version,
            .installed = index,
            .action = null,
            .archive = null,
            .artifact = null,
            .state = package.state,
            .hold = package.hold,
            .assert_step = 0,
        });
    }
    for (authorization.actions) |action| {
        try self.charge(1);
        const key: PackageRef = .{
            .name = action.package,
            .architecture = action.architecture,
        };
        if (self.installed_index.get(key) != null) continue;
        entries.appendAssumeCapacity(.{
            .name = action.package,
            .architecture = action.architecture,
            .installed_version = null,
            .installed = null,
            .action = null,
            .archive = null,
            .artifact = null,
            .state = .not_installed,
            .hold = false,
            .assert_step = 0,
        });
    }
    const modeled = try entries.toOwnedSlice(self.arena);
    std.mem.sort(Modeled, modeled, {}, struct {
        fn less(_: void, left: Modeled, right: Modeled) bool {
            return lessRef({}, left.ref(), right.ref());
        }
    }.less);
    try self.modeled_index.ensureTotalCapacity(self.arena, @intCast(modeled.len));
    for (modeled, 0..) |entry, index| {
        if (self.modeled_index.get(entry.ref()) != null)
            return self.reject(.{
                .code = .duplicate_installed_package,
                .package = entry.name,
                .architecture = entry.architecture,
            });
        self.modeled_index.putAssumeCapacity(entry.ref(), @intCast(index));
    }
    self.modeled = modeled;

    for (authorization.actions) |action| {
        try self.charge(1);
        const key: PackageRef = .{
            .name = action.package,
            .architecture = action.architecture,
        };
        const index = self.modeled_index.get(key).?;
        const entry = &self.modeled[index];
        entry.action = action.sequence;
        if (self.archive_index.get(key)) |archive_index| {
            entry.archive = archive_index;
            entry.artifact = self.artifact_of_action[action.sequence];
        }
        try validateActionEvidence(self, action, entry.*);
    }
}

fn validateActionEvidence(
    self: *Compiler,
    action: native_authorization.Action,
    entry: Modeled,
) CompileError!void {
    const state = entry.state;
    switch (action.kind) {
        .install => {
            if (entry.installed == null) return;
            if (state != .config_files)
                return self.reject(.{
                    .code = .installed_state_contradiction,
                    .detail = "install over installed package",
                    .package = action.package,
                    .architecture = action.architecture,
                });
        },
        .upgrade, .downgrade, .reinstall => {
            const prior = action.prior_version orelse
                return self.reject(.{
                    .code = .installed_state_contradiction,
                    .detail = "missing prior version",
                    .package = action.package,
                });
            if (entry.installed == null)
                return self.reject(.{
                    .code = .missing_installed_package,
                    .package = action.package,
                    .architecture = action.architecture,
                });
            if (!std.mem.eql(u8, entry.installed_version.?, prior))
                return self.reject(.{
                    .code = .installed_state_contradiction,
                    .detail = "prior version",
                    .package = action.package,
                    .architecture = action.architecture,
                });
            switch (state) {
                .installed, .triggers_awaited, .triggers_pending => {},
                else => return self.reject(.{
                    .code = .installed_state_contradiction,
                    .detail = "unhealthy installed state",
                    .package = action.package,
                    .architecture = action.architecture,
                }),
            }
        },
        .remove, .purge => {
            const prior = action.prior_version orelse
                return self.reject(.{
                    .code = .installed_state_contradiction,
                    .detail = "missing prior version",
                    .package = action.package,
                });
            if (entry.installed == null)
                return self.reject(.{
                    .code = .missing_installed_package,
                    .package = action.package,
                    .architecture = action.architecture,
                });
            if (!std.mem.eql(u8, entry.installed_version.?, prior))
                return self.reject(.{
                    .code = .installed_state_contradiction,
                    .detail = "prior version",
                    .package = action.package,
                    .architecture = action.architecture,
                });
            switch (state) {
                .installed, .triggers_awaited, .triggers_pending => {},
                .config_files => if (action.kind == .remove) return self.reject(.{
                    .code = .installed_state_contradiction,
                    .detail = "remove of config-files package",
                    .package = action.package,
                    .architecture = action.architecture,
                }),
                else => return self.reject(.{
                    .code = .installed_state_contradiction,
                    .detail = "unhealthy installed state",
                    .package = action.package,
                    .architecture = action.architecture,
                }),
            }
        },
    }
}

fn lastStep(self: *Compiler) u32 {
    return @intCast(self.steps.items.len - 1);
}

fn validateOrdering(self: *Compiler) CompileError!void {
    const authorization = self.input.authorization;
    const ordered = self.input.ordered_actions;
    if (ordered.len == 0)
        return self.reject(.{ .code = .missing_ordered_action, .detail = "empty lifecycle" });
    self.ordered_action_index = try self.arena.alloc(usize, ordered.len);
    const bootstrapped = try self.arena.alloc(bool, authorization.actions.len);
    const unpacked = try self.arena.alloc(bool, authorization.actions.len);
    const removed = try self.arena.alloc(bool, authorization.actions.len);
    const configured = try self.arena.alloc(bool, authorization.actions.len);
    @memset(bootstrapped, false);
    @memset(unpacked, false);
    @memset(removed, false);
    @memset(configured, false);
    var pending: std.ArrayList(usize) = .empty;
    defer pending.deinit(self.arena);
    var counts: OrderedKindCounts = .{};
    for (ordered, 0..) |entry, index| {
        try self.charge(1);
        if (entry.sequence != index)
            return self.reject(.{
                .code = .ordering_mismatch,
                .detail = "sequence",
                .sequence = index,
            });
        const key: PackageRef = .{
            .name = entry.package,
            .architecture = entry.architecture,
        };
        const action_index = self.action_index.get(key) orelse
            return self.reject(.{
                .code = .ordering_mismatch,
                .detail = "unauthorized package",
                .package = entry.package,
                .architecture = entry.architecture,
                .sequence = index,
            });
        const action = authorization.actions[action_index];
        if (!std.mem.eql(u8, entry.version, action.version))
            return self.reject(.{
                .code = .ordering_mismatch,
                .detail = "version",
                .package = entry.package,
                .sequence = index,
            });
        self.ordered_action_index[index] = action_index;
        switch (entry.kind) {
            .bootstrap_extract => {
                if (counts.lifecycle)
                    return self.reject(.{
                        .code = .ordering_mismatch,
                        .detail = "bootstrap after lifecycle",
                        .package = entry.package,
                        .sequence = index,
                    });
                if (action.kind != .install)
                    return self.reject(.{
                        .code = .unsupported_ordered_action,
                        .detail = "bootstrap of non-install action",
                        .package = entry.package,
                        .sequence = index,
                    });
                if (bootstrapped[action_index])
                    return self.reject(.{
                        .code = .duplicate_ordered_action,
                        .package = entry.package,
                        .sequence = index,
                    });
                bootstrapped[action_index] = true;
                counts.bootstrap = true;
            },
            .unpack => {
                counts.lifecycle = true;
                if (solver.isRemoval(action.kind))
                    return self.reject(.{
                        .code = .ordering_mismatch,
                        .detail = "unpack of removal action",
                        .package = entry.package,
                        .sequence = index,
                    });
                if (configured[action_index])
                    return self.reject(.{
                        .code = .ordering_cycle,
                        .detail = "unpack after configure",
                        .package = entry.package,
                        .sequence = index,
                    });
                if (unpacked[action_index])
                    return self.reject(.{
                        .code = .duplicate_ordered_action,
                        .package = entry.package,
                        .sequence = index,
                    });
                unpacked[action_index] = true;
                try pending.append(self.arena, action_index);
            },
            .remove, .purge => {
                counts.lifecycle = true;
                const expected: solver.OrderedActionKind =
                    if (action.kind == .purge) .purge else .remove;
                if (!solver.isRemoval(action.kind) or entry.kind != expected)
                    return self.reject(.{
                        .code = .ordering_mismatch,
                        .detail = "removal kind",
                        .package = entry.package,
                        .sequence = index,
                    });
                if (removed[action_index])
                    return self.reject(.{
                        .code = .duplicate_ordered_action,
                        .package = entry.package,
                        .sequence = index,
                    });
                removed[action_index] = true;
            },
            .configure_pending => {
                counts.lifecycle = true;
                if (pending.items.len == 0)
                    return self.reject(.{
                        .code = .ordering_mismatch,
                        .detail = "configure barrier without pending unpack",
                        .package = entry.package,
                        .sequence = index,
                    });
                for (pending.items) |pending_index| configured[pending_index] = true;
                pending.clearRetainingCapacity();
                self.final_barrier = index;
            },
        }
    }
    if (pending.items.len != 0)
        return self.reject(.{ .code = .missing_configure_barrier });
    for (authorization.actions, 0..) |action, index| {
        try self.charge(1);
        if (solver.isRemoval(action.kind)) {
            if (!removed[index])
                return self.reject(.{
                    .code = .missing_ordered_action,
                    .detail = "removal",
                    .package = action.package,
                    .architecture = action.architecture,
                });
        } else if (!unpacked[index]) {
            return self.reject(.{
                .code = .missing_ordered_action,
                .detail = "unpack",
                .package = action.package,
                .architecture = action.architecture,
            });
        }
    }
}

fn buildInterests(self: *Compiler) CompileError!void {
    for (self.modeled, 0..) |entry, index| {
        try self.charge(1);
        const declarations = if (entry.archive) |archive|
            self.prepared[archive].triggers
        else if (entry.installed) |installed| block: {
            if (entry.action) |action_index| {
                if (solver.isRemoval(self.input.authorization.actions[action_index].kind))
                    break :block &[_]TriggerDeclaration{};
            }
            break :block self.installed[installed].triggers;
        } else &[_]TriggerDeclaration{};
        for (declarations) |declaration| {
            try self.charge(1);
            if (!declaration.kind.isInterest()) continue;
            const found = try self.interests.getOrPut(self.arena, declaration.name);
            if (!found.found_existing) found.value_ptr.* = .empty;
            try found.value_ptr.append(self.arena, @intCast(index));
        }
    }
}

fn emitPreflight(self: *Compiler) CompileError!void {
    const authorization = self.input.authorization;
    self.script_policy_sha256 = hex(32, maintainer_script.policyDigest(self.input.script_policy));
    self.authorization_step = try self.addStep(.preflight, &.{}, .{ .assert_authorization = .{
        .authorization_sha256 = hex(32, authorization.digest_sha256),
        .plan_sha256 = hex(32, authorization.plan_sha256),
        .request_sha256 = hex(32, authorization.request_sha256),
        .exact_lock_sha256 = hex(32, authorization.exact_lock.digest_sha256),
        .final_state_sha256 = hex(32, authorization.final_state_sha256),
    } });
    const foreign = try self.arena.alloc([]const u8, authorization.foreign_architectures.len);
    for (authorization.foreign_architectures, 0..) |architecture, index|
        foreign[index] = try self.arena.dupe(u8, architecture);
    const root_step = try self.addStep(
        .preflight,
        &.{self.authorization_step},
        .{ .assert_root_state = .{
            .install_root = try self.arena.dupe(u8, authorization.install_root),
            .root_identity_sha256 = hex(32, authorization.root_identity_sha256),
            .target_architecture = try self.arena.dupe(u8, authorization.target_architecture),
            .foreign_architectures = foreign,
        } },
    );
    self.database_step = try self.addStep(
        .preflight,
        &.{root_step},
        .{ .assert_database_generation = .{
            .generation_sha256 = hex(32, self.input.installed.generation_sha256),
            .evidence_sha256 = hex(32, installedEvidenceDigest(self.installed)),
            .package_count = self.installed.len,
            .updates_pending = false,
        } },
    );
    for (self.modeled) |*entry| entry.assert_step = self.database_step;
    for (authorization.actions) |action| {
        const key: PackageRef = .{
            .name = action.package,
            .architecture = action.architecture,
        };
        const entry = &self.modeled[self.modeled_index.get(key).?];
        if (entry.installed) |installed_index| {
            const package = self.installed[installed_index];
            entry.assert_step = try self.addStep(
                .preflight,
                &.{self.database_step},
                .{ .assert_installed_package = .{
                    .package = try self.identity(
                        package.name,
                        package.version,
                        package.architecture,
                    ),
                    .state = package.state,
                    .hold = package.hold,
                    .essential = package.essential,
                    .owned_paths_sha256 = hex(32, package.owned_paths_sha256),
                    .conffiles_sha256 = hex(32, conffilesDigest(package.conffiles)),
                    .scripts_sha256 = hex(32, scriptsDigest(package.scripts)),
                } },
            );
        } else {
            entry.assert_step = try self.addStep(
                .preflight,
                &.{self.database_step},
                .{ .assert_package_absent = .{ .package = try self.ref(entry.ref()) } },
            );
        }
    }
    self.artifact_steps = try self.arena.alloc(u32, self.artifacts.items.len);
    for (self.artifacts.items, 0..) |artifact, index| {
        self.artifact_steps[index] = try self.addStep(
            .preflight,
            &.{self.authorization_step},
            .{ .revalidate_artifact = .{
                .artifact = artifact.index,
                .package = artifact.package,
                .sha256 = artifact.sha256,
                .size = artifact.size,
                .application_sha256 = artifact.application_sha256,
            } },
        );
    }
    try emitOwnership(self);
}

fn emitOwnership(self: *Compiler) CompileError!void {
    const conflicts = try self.arena.dupe(OwnershipConflict, self.input.ownership_conflicts);
    for (conflicts) |conflict| {
        if (conflict.path.len > maximum_path_bytes or !absolute_path.nonRoot(conflict.path))
            return self.reject(.{
                .code = .invalid_ownership_conflict,
                .detail = "path",
                .path = conflict.path,
            });
        if (!validIdentity(conflict.holder.name) or
            !validIdentity(conflict.holder.architecture) or
            !validIdentity(conflict.claimant.name) or
            !validIdentity(conflict.claimant.architecture))
            return self.reject(.{ .code = .invalid_ownership_conflict, .detail = "identity" });
    }
    std.mem.sort(OwnershipConflict, conflicts, {}, lessConflict);
    for (conflicts, 0..) |conflict, index| {
        try self.charge(1);
        if (index != 0 and
            std.mem.eql(u8, conflict.path, conflicts[index - 1].path) and
            PackageRefContext.eql(.{}, conflict.holder, conflicts[index - 1].holder) and
            PackageRefContext.eql(.{}, conflict.claimant, conflicts[index - 1].claimant))
            return self.reject(.{
                .code = .invalid_ownership_conflict,
                .detail = "duplicate",
                .path = conflict.path,
            });
        const claimant_index = self.modeled_index.get(conflict.claimant) orelse
            return self.reject(.{
                .code = .invalid_ownership_conflict,
                .detail = "unknown claimant",
                .package = conflict.claimant.name,
                .path = conflict.path,
            });
        const claimant = self.modeled[claimant_index];
        const archive_index = claimant.archive orelse
            return self.reject(.{
                .code = .invalid_ownership_conflict,
                .detail = "claimant does not unpack",
                .package = conflict.claimant.name,
                .path = conflict.path,
            });
        const holder_index = self.modeled_index.get(conflict.holder) orelse
            return self.reject(.{
                .code = .invalid_ownership_conflict,
                .detail = "unknown holder",
                .package = conflict.holder.name,
                .path = conflict.path,
            });
        const holder = self.modeled[holder_index];
        if (holder.installed == null)
            return self.reject(.{
                .code = .invalid_ownership_conflict,
                .detail = "holder is not installed",
                .package = conflict.holder.name,
                .path = conflict.path,
            });
        const resolution: OwnershipResolution = if (claimant_index == holder_index)
            .same_package
        else if (self.prepared[archive_index].replacesPackage(conflict.holder.name))
            .replaces
        else if (forceAuthorized(self.input.authorization.policy.force, .overwrite))
            .forced_overwrite
        else
            return self.reject(.{
                .code = .unresolved_ownership_conflict,
                .package = conflict.claimant.name,
                .architecture = conflict.claimant.architecture,
                .path = conflict.path,
            });
        _ = try self.addStep(
            .preflight,
            &.{ self.artifact_steps[claimant.artifact.?], holder.assert_step },
            .{ .assert_path_ownership = .{
                .path = try self.arena.dupe(u8, conflict.path),
                .holder = try self.ref(conflict.holder),
                .claimant = try self.ref(conflict.claimant),
                .resolution = resolution,
            } },
        );
    }
}

fn forceAuthorized(
    force: []const transaction_executor.ForceRisk,
    risk: transaction_executor.ForceRisk,
) bool {
    for (force) |authorized| {
        if (authorized == risk) return true;
    }
    return false;
}

fn installedScript(
    self: *Compiler,
    entry: Modeled,
    kind: maintainer_script.Kind,
) ?[32]u8 {
    const index = entry.installed orelse return null;
    for (self.installed[index].scripts) |script| {
        if (script.kind == kind) return script.sha256;
    }
    return null;
}

fn findConffile(
    conffiles: []const InstalledConffile,
    path: []const u8,
) ?InstalledConffile {
    var low: usize = 0;
    var high = conffiles.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        switch (std.mem.order(u8, conffiles[middle].path, path)) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return conffiles[middle],
        }
    }
    return null;
}

fn makeUnwind(
    self: *Compiler,
    digest: ?[32]u8,
    kind: maintainer_script.Kind,
    source: ScriptSource,
    args: []const []const u8,
) CompileError!?Unwind {
    const found = digest orelse return null;
    return .{
        .kind = kind,
        .source = source,
        .script_sha256 = hex(32, found),
        .arguments = try self.arguments(args),
    };
}

fn emitScript(
    self: *Compiler,
    phase: Phase,
    requires: []const u32,
    package: PackageIdentity,
    kind: maintainer_script.Kind,
    source: ScriptSource,
    digest: [32]u8,
    args: []const []const u8,
    failure: ScriptFailure,
) CompileError!u32 {
    return self.addStep(phase, requires, .{ .run_maintainer_script = .{
        .package = package,
        .kind = kind,
        .source = source,
        .script_sha256 = hex(32, digest),
        .arguments = try self.arguments(args),
        .environment_policy_sha256 = self.script_policy_sha256,
        .failure = failure,
    } });
}

fn archiveScriptDigest(prepared: PreparedArchive, kind: maintainer_script.Kind) ?[32]u8 {
    const script = prepared.script(kind) orelse return null;
    return script.sha256;
}

fn emitLifecycle(self: *Compiler) CompileError!void {
    var pending: std.ArrayList(u32) = .empty;
    defer pending.deinit(self.arena);
    for (self.input.ordered_actions, 0..) |ordered, index| {
        const action_index = self.ordered_action_index[index];
        switch (ordered.kind) {
            .bootstrap_extract => try emitBootstrap(self, action_index),
            .remove, .purge => try emitRemoval(self, action_index, ordered.kind == .purge),
            .unpack => {
                const entry_index = try emitUnpack(self, action_index);
                try pending.append(self.arena, entry_index);
            },
            .configure_pending => {
                const reason: BarrierReason =
                    if (self.final_barrier.? == index) .final else .pre_depends;
                try emitConfigure(self, pending.items, reason);
                pending.clearRetainingCapacity();
            },
        }
    }
}

fn modeledIndexOf(self: *Compiler, action: native_authorization.Action) u32 {
    return self.modeled_index.get(.{
        .name = action.package,
        .architecture = action.architecture,
    }).?;
}

fn emitBootstrap(self: *Compiler, action_index: usize) CompileError!void {
    const action = self.input.authorization.actions[action_index];
    const entry = &self.modeled[modeledIndexOf(self, action)];
    const artifact = entry.artifact orelse
        return self.reject(.{
            .code = .missing_archive,
            .package = action.package,
            .architecture = action.architecture,
        });
    const record = self.artifacts.items[artifact];
    entry.bootstrap_step = try self.addStep(
        .bootstrap,
        &.{ self.artifact_steps[artifact], entry.assert_step },
        .{ .materialize_bootstrap_payload = .{
            .package = record.package,
            .artifact = artifact,
            .application_sha256 = record.application_sha256,
        } },
    );
}

fn emitRemoval(self: *Compiler, action_index: usize, purge: bool) CompileError!void {
    const action = self.input.authorization.actions[action_index];
    const entry_index = modeledIndexOf(self, action);
    const entry = &self.modeled[entry_index];
    const installed_index = entry.installed orelse
        return self.reject(.{
            .code = .missing_installed_package,
            .package = action.package,
            .architecture = action.architecture,
        });
    const package = self.installed[installed_index];
    const package_identity = try self.identity(
        package.name,
        package.version,
        package.architecture,
    );
    var last = entry.assert_step;
    if (entry.state != .config_files) {
        if (installedScript(self, entry.*, .prerm)) |digest| {
            last = try emitScript(
                self,
                .remove,
                &.{last},
                package_identity,
                .prerm,
                .installed_package,
                digest,
                &.{"remove"},
                .{
                    .state = .half_configured,
                    .unwind = try makeUnwind(
                        self,
                        installedScript(self, entry.*, .postinst),
                        .postinst,
                        .installed_package,
                        &.{"abort-remove"},
                    ),
                    .recovery_required = false,
                },
            );
        }
        last = try self.addStep(.remove, &.{last}, .{ .record_package_state = .{
            .package = package_identity,
            .state = .half_installed,
            .hold = entry.hold,
            .remove_entry = false,
        } });
        last = try self.addStep(.remove, &.{last}, .{ .remove_package_files = .{
            .package = package_identity,
            .owned_paths_sha256 = hex(32, package.owned_paths_sha256),
            .retain_conffiles = !purge,
        } });
        if (!purge) {
            for (package.conffiles) |conffile| {
                try self.charge(1);
                last = try self.addStep(.remove, &.{last}, .{ .apply_conffile_decision = .{
                    .package = package_identity,
                    .path = try self.arena.dupe(u8, conffile.path),
                    .policy = self.input.authorization.policy.conffile,
                    .action = .retain_on_remove,
                    .packaged_md5 = null,
                    .recorded_md5 = hex(16, conffile.recorded_md5),
                    .on_disk_md5 = if (conffile.on_disk_md5) |digest| hex(16, digest) else null,
                } });
            }
        }
        if (installedScript(self, entry.*, .postrm)) |digest| {
            last = try emitScript(
                self,
                .remove,
                &.{last},
                package_identity,
                .postrm,
                .installed_package,
                digest,
                &.{"remove"},
                .{ .state = .half_installed, .unwind = null, .recovery_required = true },
            );
        }
        last = try self.addStep(.remove, &.{last}, .{ .record_package_state = .{
            .package = package_identity,
            .state = .config_files,
            .hold = entry.hold,
            .remove_entry = false,
        } });
        entry.state = .config_files;
    }
    if (!purge) return;
    if (installedScript(self, entry.*, .postrm)) |digest| {
        last = try emitScript(
            self,
            .remove,
            &.{last},
            package_identity,
            .postrm,
            .installed_package,
            digest,
            &.{"purge"},
            .{ .state = .config_files, .unwind = null, .recovery_required = true },
        );
    }
    for (package.conffiles) |conffile| {
        try self.charge(1);
        last = try self.addStep(.remove, &.{last}, .{ .apply_conffile_decision = .{
            .package = package_identity,
            .path = try self.arena.dupe(u8, conffile.path),
            .policy = self.input.authorization.policy.conffile,
            .action = .delete_on_purge,
            .packaged_md5 = null,
            .recorded_md5 = hex(16, conffile.recorded_md5),
            .on_disk_md5 = if (conffile.on_disk_md5) |digest| hex(16, digest) else null,
        } });
    }
    last = try self.addStep(.remove, &.{last}, .{ .purge_package_files = .{
        .package = package_identity,
        .conffiles_sha256 = hex(32, conffilesDigest(package.conffiles)),
    } });
    _ = try self.addStep(.remove, &.{last}, .{ .record_package_state = .{
        .package = package_identity,
        .state = .not_installed,
        .hold = entry.hold,
        .remove_entry = true,
    } });
    entry.state = .not_installed;
}

fn emitUnpack(self: *Compiler, action_index: usize) CompileError!u32 {
    const action = self.input.authorization.actions[action_index];
    const entry_index = modeledIndexOf(self, action);
    const entry = &self.modeled[entry_index];
    const archive_index = entry.archive orelse
        return self.reject(.{
            .code = .missing_archive,
            .package = action.package,
            .architecture = action.architecture,
        });
    const prepared = self.prepared[archive_index];
    const artifact = entry.artifact.?;
    const record = self.artifacts.items[artifact];
    const package_identity = record.package;
    const prior_version = entry.installed_version;
    var last = self.artifact_steps[artifact];
    switch (action.kind) {
        .install => {
            if (archiveScriptDigest(prepared, .preinst)) |digest| {
                const args: []const []const u8 = if (prior_version) |version|
                    &.{ "install", version }
                else
                    &.{"install"};
                const unwind_args: []const []const u8 = if (prior_version) |version|
                    &.{ "abort-install", version }
                else
                    &.{"abort-install"};
                last = try emitScript(
                    self,
                    .unpack,
                    &.{ last, entry.assert_step },
                    package_identity,
                    .preinst,
                    .new_package,
                    digest,
                    args,
                    .{
                        .state = .half_installed,
                        .unwind = try makeUnwind(
                            self,
                            archiveScriptDigest(prepared, .postrm),
                            .postrm,
                            .new_package,
                            unwind_args,
                        ),
                        .recovery_required = false,
                    },
                );
            }
        },
        .upgrade, .downgrade, .reinstall => {
            const prior = action.prior_version.?;
            if (installedScript(self, entry.*, .prerm)) |digest| {
                last = try emitScript(
                    self,
                    .unpack,
                    &.{ last, entry.assert_step },
                    package_identity,
                    .prerm,
                    .installed_package,
                    digest,
                    &.{ "upgrade", action.version },
                    .{
                        .state = .half_configured,
                        .unwind = try makeUnwind(
                            self,
                            archiveScriptDigest(prepared, .prerm),
                            .prerm,
                            .new_package,
                            &.{ "failed-upgrade", prior },
                        ),
                        .recovery_required = false,
                    },
                );
            }
            if (archiveScriptDigest(prepared, .preinst)) |digest| {
                last = try emitScript(
                    self,
                    .unpack,
                    &.{ last, entry.assert_step },
                    package_identity,
                    .preinst,
                    .new_package,
                    digest,
                    &.{ "upgrade", prior },
                    .{
                        .state = .half_installed,
                        .unwind = try makeUnwind(
                            self,
                            archiveScriptDigest(prepared, .postrm),
                            .postrm,
                            .new_package,
                            &.{ "abort-upgrade", prior },
                        ),
                        .recovery_required = false,
                    },
                );
            }
        },
        .remove, .purge => unreachable,
    }
    var requires: [3]u32 = undefined;
    var required: usize = 0;
    requires[required] = last;
    required += 1;
    if (entry.bootstrap_step) |bootstrap| {
        requires[required] = bootstrap;
        required += 1;
    }
    last = try self.addStep(.unpack, requires[0..required], .{ .unpack_package = .{
        .package = package_identity,
        .prior_version = if (prior_version) |version|
            try self.arena.dupe(u8, version)
        else
            null,
        .artifact = artifact,
        .application_sha256 = record.application_sha256,
        .bootstrapped = entry.bootstrap_step != null,
        .prior_owned_paths_sha256 = if (entry.installed) |index|
            hex(32, self.installed[index].owned_paths_sha256)
        else
            null,
    } });
    entry.unpack_step = last;
    switch (action.kind) {
        .upgrade, .downgrade, .reinstall => {
            if (installedScript(self, entry.*, .postrm)) |digest| {
                last = try emitScript(
                    self,
                    .unpack,
                    &.{last},
                    package_identity,
                    .postrm,
                    .installed_package,
                    digest,
                    &.{ "upgrade", action.version },
                    .{
                        .state = .half_installed,
                        .unwind = try makeUnwind(
                            self,
                            archiveScriptDigest(prepared, .postrm),
                            .postrm,
                            .new_package,
                            &.{ "failed-upgrade", action.prior_version.? },
                        ),
                        .recovery_required = true,
                    },
                );
            }
        },
        else => {},
    }
    last = try emitConffiles(self, entry_index, package_identity, last);
    if (prepared.triggers.len != 0) {
        last = try self.addStep(.unpack, &.{last}, .{ .record_trigger_interests = .{
            .package = package_identity,
            .declarations = try self.declarations(prepared.triggers),
            .declarations_sha256 = hex(32, declarationsDigest(prepared.triggers)),
        } });
    }
    _ = try self.addStep(.unpack, &.{last}, .{ .record_package_state = .{
        .package = package_identity,
        .state = .unpacked,
        .hold = entry.hold,
        .remove_entry = false,
    } });
    entry.state = .unpacked;
    return entry_index;
}

/// dpkg's conffile decision table, reproduced from `src/main/configure.c` and
/// `src/main/unpack.c`. Three digests drive it: the digest the package ships,
/// the digest the database recorded for the installed version, and the digest
/// observed in the root (absent when the administrator deleted the file).
///
/// | on disk | maintainer | outcome |
/// |---|---|---|
/// | equals packaged | any | `identical_no_op` |
/// | equals recorded | changed | `replace_unmodified` |
/// | edited | unchanged | `keep_user_modified` |
/// | deleted | unchanged | `keep_user_deleted` |
/// | edited or deleted | changed | reviewed policy decides |
///
/// A `remove-on-upgrade` conffile is not shipped, so it takes precedence and
/// never installs anything: it deletes an unmodified recorded file, preserves
/// a modified one as `.dpkg-old`, and does nothing when nothing is recorded or
/// nothing is present, including on a fresh install.
fn conffileDecision(
    policy: transaction_executor.ConffilePolicy,
    packaged: ArchiveConffile,
    recorded: ?InstalledConffile,
) ConffileAction {
    if (packaged.remove_on_upgrade) {
        const record = recorded orelse return .skip_not_shipped;
        const on_disk = record.on_disk_md5 orelse return .skip_not_shipped;
        return if (std.mem.eql(u8, &on_disk, &record.recorded_md5))
            .remove_on_upgrade
        else
            .remove_on_upgrade_stage_old;
    }
    const record = recorded orelse return .install_new;
    const shipped = packaged.md5.?;
    const maintainer_edited = !std.mem.eql(u8, &shipped, &record.recorded_md5);
    const on_disk = record.on_disk_md5 orelse {
        if (!maintainer_edited) return .keep_user_deleted;
        return switch (policy) {
            .keep_existing => .keep_existing_stage_dist,
            .use_package_version => .restore_missing,
        };
    };
    if (std.mem.eql(u8, &on_disk, &shipped)) return .identical_no_op;
    if (std.mem.eql(u8, &on_disk, &record.recorded_md5)) return .replace_unmodified;
    if (!maintainer_edited) return .keep_user_modified;
    return switch (policy) {
        .keep_existing => .keep_existing_stage_dist,
        .use_package_version => .install_stage_old,
    };
}

fn emitConffiles(
    self: *Compiler,
    entry_index: u32,
    package_identity: PackageIdentity,
    unpack_step: u32,
) CompileError!u32 {
    const entry = self.modeled[entry_index];
    const prepared = self.prepared[entry.archive.?];
    const recorded_conffiles: []const InstalledConffile = if (entry.installed) |index|
        self.installed[index].conffiles
    else
        &.{};
    const policy = self.input.authorization.policy.conffile;
    var last = unpack_step;
    for (prepared.conffiles) |conffile| {
        try self.charge(1);
        const recorded = findConffile(recorded_conffiles, conffile.path);
        last = try self.addStep(.unpack, &.{last}, .{ .apply_conffile_decision = .{
            .package = package_identity,
            .path = try self.arena.dupe(u8, conffile.path),
            .policy = policy,
            .action = conffileDecision(policy, conffile, recorded),
            .packaged_md5 = if (conffile.md5) |digest| hex(16, digest) else null,
            .recorded_md5 = if (recorded) |value| hex(16, value.recorded_md5) else null,
            .on_disk_md5 = if (recorded) |value|
                if (value.on_disk_md5) |digest| hex(16, digest) else null
            else
                null,
        } });
    }
    for (recorded_conffiles) |conffile| {
        try self.charge(1);
        if (prepared.conffile(conffile.path) != null) continue;
        last = try self.addStep(.unpack, &.{last}, .{ .apply_conffile_decision = .{
            .package = package_identity,
            .path = try self.arena.dupe(u8, conffile.path),
            .policy = policy,
            .action = .mark_obsolete,
            .packaged_md5 = null,
            .recorded_md5 = hex(16, conffile.recorded_md5),
            .on_disk_md5 = if (conffile.on_disk_md5) |digest| hex(16, digest) else null,
        } });
    }
    return last;
}

fn emitConfigure(
    self: *Compiler,
    pending: []const u32,
    reason: BarrierReason,
) CompileError!void {
    if (pending.len == 0)
        return self.reject(.{ .code = .ordering_mismatch, .detail = "empty barrier" });
    const packages = try self.arena.alloc(PackageRef, pending.len);
    for (pending, 0..) |entry_index, index|
        packages[index] = try self.ref(self.modeled[entry_index].ref());
    const barrier = try self.addStep(
        .configure,
        &.{lastStep(self)},
        .{ .configure_barrier = .{ .reason = reason, .packages = packages } },
    );
    for (pending) |entry_index| {
        try self.charge(1);
        const entry = &self.modeled[entry_index];
        if (entry.configured)
            return self.reject(.{
                .code = .ordering_cycle,
                .detail = "configured twice",
                .package = entry.name,
                .architecture = entry.architecture,
            });
        const action = self.input.authorization.actions[entry.action.?];
        const prepared = self.prepared[entry.archive.?];
        const package_identity = self.artifacts.items[entry.artifact.?].package;
        var last = barrier;
        if (archiveScriptDigest(prepared, .postinst)) |digest| {
            const args: []const []const u8 = if (entry.installed_version) |version|
                &.{ "configure", version }
            else
                &.{"configure"};
            last = try emitScript(
                self,
                .configure,
                &.{ barrier, entry.unpack_step.? },
                package_identity,
                .postinst,
                .new_package,
                digest,
                args,
                .{ .state = .half_configured, .unwind = null, .recovery_required = false },
            );
        }
        last = try emitActivations(self, entry_index, last);
        const state: PackageState = if (entry.awaiting_trigger) .triggers_awaited else .installed;
        _ = try self.addStep(.configure, &.{last}, .{ .record_package_state = .{
            .package = package_identity,
            .state = state,
            .hold = entry.hold,
            .remove_entry = false,
        } });
        entry.state = state;
        entry.configured = true;
        std.debug.assert(std.mem.eql(u8, package_identity.version, action.version));
    }
}

fn emitActivations(self: *Compiler, entry_index: u32, previous: u32) CompileError!u32 {
    const entry = &self.modeled[entry_index];
    const prepared = self.prepared[entry.archive.?];
    var last = previous;
    for (prepared.triggers) |declaration| {
        try self.charge(1);
        if (declaration.kind.isInterest()) continue;
        const listeners: []const u32 = if (self.interests.get(declaration.name)) |list|
            list.items
        else
            &.{};
        if (listeners.len > maximum_interested_packages)
            return self.reject(.{
                .code = .limit_exceeded,
                .detail = "interested packages",
                .package = entry.name,
                .path = declaration.name,
            });
        try self.charge(listeners.len);
        const interested = try self.arena.alloc(PackageRef, listeners.len);
        for (listeners, 0..) |listener, index|
            interested[index] = try self.ref(self.modeled[listener].ref());
        const awaiting = declaration.kind.awaits() and listeners.len != 0;
        last = try self.addStep(.trigger, &.{last}, .{ .activate_trigger = .{
            .source = try self.ref(entry.ref()),
            .trigger = try self.arena.dupe(u8, declaration.name),
            .kind = declaration.kind,
            .awaiting = awaiting,
            .interested = interested,
        } });
        for (listeners) |listener| {
            try self.charge(1);
            const target = &self.modeled[listener];
            var present = false;
            for (target.pending_triggers.items) |name| {
                if (std.mem.eql(u8, name, declaration.name)) {
                    present = true;
                    break;
                }
            }
            if (!present) {
                if (target.pending_triggers.items.len >= maximum_pending_triggers or
                    target.pending_triggers.items.len >= self.limits.triggers)
                    return self.reject(.{ .code = .limit_exceeded, .detail = "pending triggers" });
                try target.pending_triggers.append(self.arena, declaration.name);
            }
            if (declaration.kind.awaits()) target.awaited = true;
        }
        if (awaiting) entry.awaiting_trigger = true;
    }
    return last;
}

fn joinTriggers(self: *Compiler, triggers: []const []const u8) CompileError![]const u8 {
    var total: usize = 0;
    for (triggers, 0..) |trigger, index| {
        total = std.math.add(usize, total, trigger.len + @intFromBool(index != 0)) catch
            return self.reject(.{ .code = .limit_exceeded, .detail = "trigger arguments" });
    }
    if (total > maximum_argument_bytes)
        return self.reject(.{ .code = .limit_exceeded, .detail = "trigger arguments" });
    const joined = try self.arena.alloc(u8, total);
    var cursor: usize = 0;
    for (triggers, 0..) |trigger, index| {
        if (index != 0) {
            joined[cursor] = ' ';
            cursor += 1;
        }
        @memcpy(joined[cursor..][0..trigger.len], trigger);
        cursor += trigger.len;
    }
    return joined;
}

/// Whether a trigger-interested package may be driven through `triggers-pending`,
/// `postinst triggered`, and back to `installed`.
///
/// dpkg only processes triggers for a package whose installation is complete.
/// Anything else — `half-installed`, `half-configured`, `unpacked`,
/// `config-files`, absent — must be repaired first, so accepting it here would
/// let deferred trigger work promote a broken package to `installed` without
/// ever configuring it.
///
/// A recorded `triggers-pending` or `triggers-awaited` state is refused as
/// well: that package carries trigger work from an earlier run which the v1
/// installed-database evidence does not enumerate, so this program cannot
/// preserve it and would silently drop it when it records `installed`. The
/// only accepted awaited state is the one this compilation created itself,
/// when a package activated an awaited trigger while it was configured, and
/// whose transition back to `installed` this program does contain.
fn triggerCapable(entry: Modeled) bool {
    return switch (entry.state) {
        .installed => true,
        .triggers_awaited => entry.configured,
        else => false,
    };
}

fn emitTriggerWork(self: *Compiler) CompileError!void {
    var indices: std.ArrayList(u32) = .empty;
    defer indices.deinit(self.arena);
    var pending: std.ArrayList(PendingTrigger) = .empty;
    defer pending.deinit(self.arena);
    for (self.modeled, 0..) |*entry, index| {
        try self.charge(1);
        if (entry.pending_triggers.items.len == 0) continue;
        std.mem.sort([]const u8, entry.pending_triggers.items, {}, lessString);
        try indices.append(self.arena, @intCast(index));
        try pending.append(self.arena, .{
            .package = try self.ref(entry.ref()),
            .triggers = try self.triggerNames(entry.pending_triggers.items),
            .awaiting = entry.awaited,
        });
    }
    if (pending.items.len == 0) {
        for (self.modeled) |entry| {
            if (entry.awaiting_trigger)
                return self.reject(.{
                    .code = .invalid_trigger_metadata,
                    .detail = "awaited trigger without work",
                    .package = entry.name,
                });
        }
        return;
    }
    var last = lastStep(self);
    for (indices.items) |index| {
        const entry = &self.modeled[index];
        if (entry.state == .not_installed or entry.state == .config_files)
            return self.reject(.{
                .code = .invalid_trigger_metadata,
                .detail = "trigger on removed package",
                .package = entry.name,
                .architecture = entry.architecture,
            });
        if (!triggerCapable(entry.*))
            return self.reject(.{
                .code = .invalid_trigger_metadata,
                .detail = "trigger on unhealthy package",
                .package = entry.name,
                .architecture = entry.architecture,
            });
        const pending_version = currentVersion(self, entry.*) orelse
            return self.reject(.{
                .code = .invalid_trigger_metadata,
                .detail = "trigger on unknown version",
                .package = entry.name,
            });
        last = try self.addStep(.trigger, &.{last}, .{ .record_package_state = .{
            .package = try self.identity(entry.name, pending_version, entry.architecture),
            .state = .triggers_pending,
            .hold = entry.hold,
            .remove_entry = false,
        } });
        entry.state = .triggers_pending;
    }
    const work = try self.arena.dupe(PendingTrigger, pending.items);
    last = try self.addStep(.trigger, &.{last}, .{ .process_deferred_triggers = .{
        .pending = work,
        .pending_sha256 = hex(32, pendingDigest(work)),
    } });
    const barrier = last;
    for (indices.items) |index| {
        const entry = &self.modeled[index];
        const version = currentVersion(self, entry.*) orelse
            return self.reject(.{
                .code = .invalid_trigger_metadata,
                .detail = "trigger on unknown version",
                .package = entry.name,
            });
        const package_identity = try self.identity(entry.name, version, entry.architecture);
        const digest = if (entry.archive) |archive|
            archiveScriptDigest(self.prepared[archive], .postinst)
        else
            installedScript(self, entry.*, .postinst);
        const script = digest orelse
            return self.reject(.{
                .code = .missing_script_evidence,
                .detail = "triggered postinst",
                .package = entry.name,
                .architecture = entry.architecture,
            });
        const joined = try joinTriggers(self, entry.pending_triggers.items);
        last = try emitScript(
            self,
            .trigger,
            &.{barrier},
            package_identity,
            .postinst,
            if (entry.archive != null) .new_package else .installed_package,
            script,
            &.{ "triggered", joined },
            .{ .state = .triggers_pending, .unwind = null, .recovery_required = true },
        );
        last = try self.addStep(.trigger, &.{last}, .{ .record_package_state = .{
            .package = package_identity,
            .state = .installed,
            .hold = entry.hold,
            .remove_entry = false,
        } });
        entry.state = .installed;
    }
    for (self.modeled) |*entry| {
        if (!entry.awaiting_trigger or entry.state != .triggers_awaited) continue;
        const version = currentVersion(self, entry.*) orelse
            return self.reject(.{
                .code = .invalid_trigger_metadata,
                .detail = "awaited trigger on unknown version",
                .package = entry.name,
            });
        last = try self.addStep(.trigger, &.{last}, .{ .record_package_state = .{
            .package = try self.identity(entry.name, version, entry.architecture),
            .state = .installed,
            .hold = entry.hold,
            .remove_entry = false,
        } });
        entry.state = .installed;
    }
}

/// Version the package holds after its authorized action, or the recorded
/// version when the transaction does not replace it.
fn currentVersion(self: *Compiler, entry: Modeled) ?[]const u8 {
    if (entry.action) |action_index| {
        const action = self.input.authorization.actions[action_index];
        if (!solver.isRemoval(action.kind)) return action.version;
    }
    return entry.installed_version;
}

fn emitVerification(self: *Compiler) CompileError!void {
    const authorization = self.input.authorization;
    var installed_count: u64 = 0;
    var config_files_count: u64 = 0;
    for (authorization.final_state) |package| switch (package.state) {
        .installed => installed_count += 1,
        .config_files => config_files_count += 1,
    };
    const publish = try self.addStep(
        .verify,
        &.{lastStep(self)},
        .{ .publish_database_generation = .{
            .final_state_sha256 = hex(32, authorization.final_state_sha256),
            .package_count = authorization.final_state.len,
        } },
    );
    const verify = try self.addStep(.verify, &.{publish}, .{ .verify_final_state = .{
        .final_state_sha256 = hex(32, authorization.final_state_sha256),
        .installed_count = installed_count,
        .config_files_count = config_files_count,
    } });
    _ = try self.addStep(.verify, &.{verify}, .{ .publish_provenance = .{
        .authorization_sha256 = hex(32, authorization.digest_sha256),
        .database_generation_sha256 = hex(32, self.input.installed.generation_sha256),
        .record_script_outcome_unknown = self.input.record_script_outcome_unknown,
    } });
}

fn validateFinalState(self: *Compiler) CompileError!void {
    const authorization = self.input.authorization;
    for (self.modeled) |entry| {
        try self.charge(1);
        const final = authorization.findFinalPackage(entry.name, entry.architecture);
        switch (entry.state) {
            .not_installed => if (final != null) return self.reject(.{
                .code = .final_state_contradiction,
                .detail = "purged package remains in final closure",
                .package = entry.name,
                .architecture = entry.architecture,
            }),
            .installed, .config_files => {
                const package = final orelse return self.reject(.{
                    .code = .missing_final_package,
                    .package = entry.name,
                    .architecture = entry.architecture,
                });
                const expected: native_authorization.FinalState =
                    if (entry.state == .installed) .installed else .config_files;
                if (package.state != expected)
                    return self.reject(.{
                        .code = .final_state_contradiction,
                        .detail = "state",
                        .package = entry.name,
                        .architecture = entry.architecture,
                    });
                const version = currentVersion(self, entry) orelse
                    return self.reject(.{
                        .code = .final_state_contradiction,
                        .detail = "version",
                        .package = entry.name,
                    });
                if (!std.mem.eql(u8, package.version, version))
                    return self.reject(.{
                        .code = .final_state_contradiction,
                        .detail = "version",
                        .package = entry.name,
                        .architecture = entry.architecture,
                    });
                if (package.dpkg_selection_hold != entry.hold)
                    return self.reject(.{
                        .code = .final_state_contradiction,
                        .detail = "hold",
                        .package = entry.name,
                        .architecture = entry.architecture,
                    });
            },
            else => return self.reject(.{
                .code = .final_state_contradiction,
                .detail = "unhealthy final state",
                .package = entry.name,
                .architecture = entry.architecture,
            }),
        }
    }
    for (authorization.final_state) |package| {
        try self.charge(1);
        if (self.modeled_index.get(.{
            .name = package.name,
            .architecture = package.architecture,
        }) == null)
            return self.reject(.{
                .code = .unexpected_installed_package,
                .detail = "final closure package is neither installed nor authorized",
                .package = package.name,
                .architecture = package.architecture,
            });
    }
}

fn assemble(self: *Compiler) CompileError!Program {
    const authorization = self.input.authorization;
    if (self.steps.items.len == 0) return self.reject(.{ .code = .empty_program });
    if (self.steps.items.len > self.limits.steps)
        return self.reject(.{ .code = .program_too_large });
    const foreign = try self.arena.alloc([]const u8, authorization.foreign_architectures.len);
    for (authorization.foreign_architectures, 0..) |architecture, index|
        foreign[index] = try self.arena.dupe(u8, architecture);
    var program: Program = .{
        .schema = schema_id,
        .version = schema_version,
        .backend = authorization.backend,
        .install_root = try self.arena.dupe(u8, authorization.install_root),
        .root_identity_sha256 = hex(32, authorization.root_identity_sha256),
        .target_architecture = try self.arena.dupe(u8, authorization.target_architecture),
        .foreign_architectures = foreign,
        .request_sha256 = hex(32, authorization.request_sha256),
        .solver_policy_sha256 = hex(32, authorization.solver_policy_sha256),
        .executor_policy_sha256 = hex(32, authorization.executor_policy_sha256),
        .plan_sha256 = hex(32, authorization.plan_sha256),
        .exact_lock = .{
            .schema = try self.arena.dupe(u8, authorization.exact_lock.schema),
            .version = authorization.exact_lock.version,
            .digest_sha256 = hex(32, authorization.exact_lock.digest_sha256),
        },
        .authorization_sha256 = hex(32, authorization.digest_sha256),
        .final_state_sha256 = hex(32, authorization.final_state_sha256),
        .policy = .{
            .conffile = authorization.policy.conffile,
            .force = try self.arena.dupe(
                transaction_executor.ForceRisk,
                authorization.policy.force,
            ),
            .allow_host_root = authorization.policy.allow_host_root,
        },
        .script_policy_sha256 = self.script_policy_sha256,
        .installed_database = .{
            .generation_sha256 = hex(32, self.input.installed.generation_sha256),
            .evidence_sha256 = hex(32, installedEvidenceDigest(self.installed)),
            .package_count = self.installed.len,
        },
        .artifacts = try self.artifacts.toOwnedSlice(self.arena),
        .artifacts_sha256 = @splat('0'),
        .steps = try self.steps.toOwnedSlice(self.arena),
        .steps_sha256 = @splat('0'),
        .digest_sha256 = @splat('0'),
    };
    program.artifacts_sha256 = hex(32, hashValue(
        "debz-native-transaction-program-artifacts-v1\x00",
        program.artifacts,
    ));
    program.steps_sha256 = hex(32, hashValue(
        "debz-native-transaction-program-steps-v1\x00",
        program.steps,
    ));
    program.digest_sha256 = hex(32, documentDigest(program));
    return program;
}

fn hashValue(domain: []const u8, value: anytype) [32]u8 {
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(Sha256) = .init(&buffer);
    sink.writer.writeAll(domain) catch unreachable;
    std.json.Stringify.value(value, .{ .whitespace = .minified }, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

/// The digest covers the complete canonical document with `digest_sha256`
/// replaced by 64 ASCII zeros, so every other field is bound.
fn documentDigest(program: Program) [32]u8 {
    var payload = program;
    payload.digest_sha256 = @splat('0');
    return hashValue("debz-native-transaction-program-v1\x00", payload);
}

fn writeDocument(program: Program, writer: *std.Io.Writer) !void {
    try std.json.Stringify.value(program, .{ .whitespace = .minified }, writer);
}

fn validLowerHex(value: []const u8) bool {
    for (value) |byte| {
        if (std.ascii.isDigit(byte)) continue;
        if (byte >= 'a' and byte <= 'f') continue;
        return false;
    }
    return true;
}

/// Structural validation of every modeled value: fixed-size digest fields must
/// be lowercase hexadecimal and every package identity must be well formed.
/// Reflection keeps the walk exhaustive as the model grows.
fn validateModel(comptime T: type, value: T) bool {
    if (T == PackageIdentity) {
        return validIdentity(value.name) and validVersion(value.version) and
            validIdentity(value.architecture);
    }
    if (T == PackageRef) {
        return validIdentity(value.name) and validIdentity(value.architecture);
    }
    switch (@typeInfo(T)) {
        .array => |info| {
            if (info.child != u8) {
                for (value) |item| {
                    if (!validateModel(info.child, item)) return false;
                }
                return true;
            }
            if (info.len != 32 and info.len != 64) return true;
            return validLowerHex(&value);
        },
        .optional => |info| {
            const inner = value orelse return true;
            return validateModel(info.child, inner);
        },
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (!validateModel(field.type, @field(value, field.name))) return false;
            }
            return true;
        },
        .@"union" => {
            switch (value) {
                inline else => |payload| return validateModel(@TypeOf(payload), payload),
            }
        },
        .pointer => |info| {
            if (info.size != .slice or info.child == u8) return true;
            for (value) |item| {
                if (!validateModel(info.child, item)) return false;
            }
            return true;
        },
        else => return true,
    }
}

/// Revalidates a decoded document exactly as strictly as compilation validated
/// the program it published.
pub fn validateDocument(program: Program) DecodeError!void {
    if (!std.mem.eql(u8, program.schema, schema_id) or program.version != schema_version)
        return error.UnsupportedSchema;
    switch (program.backend) {
        .native => {},
        .legacy_dpkg => return error.UnsupportedBackend,
    }
    if (!std.mem.eql(u8, program.exact_lock.schema, exact_lock_v2.schema_id) or
        program.exact_lock.version != exact_lock_v2.schema_version)
        return error.UnsupportedLockVersion;
    if (program.steps.len == 0 or program.steps.len > maximum_steps)
        return error.TooManySteps;
    if (program.artifacts.len > maximum_artifacts) return error.TooManyArtifacts;
    if (program.install_root.len > native_authorization.maximum_root_bytes or
        !absolute_path.root(program.install_root)) return error.InvalidPath;
    if (!std.mem.eql(
        u8,
        &program.root_identity_sha256,
        &hex(32, transaction_recovery.rootIdentity(program.install_root)),
    )) return error.InvalidProgram;
    if (!validIdentity(program.target_architecture)) return error.InvalidIdentity;
    for (program.foreign_architectures) |architecture| {
        if (!validIdentity(architecture)) return error.InvalidIdentity;
    }
    for (program.artifacts, 0..) |artifact, index| {
        if (artifact.index != index) return error.NonCanonicalSequence;
        if (!validateModel(ProgramArtifact, artifact)) return error.InvalidDigest;
    }
    var seen_lifecycle = false;
    var seen_verify = false;
    for (program.steps, 0..) |step, index| {
        if (step.sequence != index) return error.NonCanonicalSequence;
        if (step.requires.len > maximum_step_dependencies) return error.InvalidStepGraph;
        for (step.requires) |required| {
            if (required >= step.sequence) return error.InvalidStepGraph;
        }
        if (!validateModel(Operation, step.operation)) return error.InvalidDigest;
        switch (step.phase) {
            .preflight => if (seen_lifecycle) return error.InvalidStepGraph,
            .verify => seen_verify = true,
            else => {
                seen_lifecycle = true;
                if (seen_verify) return error.InvalidStepGraph;
            },
        }
        switch (step.operation) {
            .revalidate_artifact => |assertion| if (assertion.artifact >= program.artifacts.len)
                return error.InvalidProgram,
            .materialize_bootstrap_payload => |intent| if (intent.artifact >= program.artifacts.len)
                return error.InvalidProgram,
            .unpack_package => |intent| if (intent.artifact >= program.artifacts.len)
                return error.InvalidProgram,
            .run_maintainer_script => |call| {
                if (call.arguments.len > maximum_script_arguments) return error.InvalidProgram;
                for (call.arguments) |argument| {
                    if (argument.len > maximum_argument_bytes) return error.InvalidProgram;
                }
                if (call.failure.unwind) |unwind| {
                    if (unwind.arguments.len > maximum_script_arguments)
                        return error.InvalidProgram;
                }
            },
            .apply_conffile_decision => |decision| if (decision.path.len > maximum_path_bytes or
                !absolute_path.nonRoot(decision.path)) return error.InvalidPath,
            .assert_path_ownership => |assertion| if (assertion.path.len > maximum_path_bytes or
                !absolute_path.nonRoot(assertion.path)) return error.InvalidPath,
            .record_trigger_interests => |record| for (record.declarations) |declaration| {
                if (!validTrigger(declaration.name)) return error.InvalidProgram;
            },
            .activate_trigger => |activation| if (!validTrigger(activation.trigger))
                return error.InvalidProgram,
            .process_deferred_triggers => |work| for (work.pending) |entry| {
                for (entry.triggers) |trigger| {
                    if (!validTrigger(trigger)) return error.InvalidProgram;
                }
            },
            else => {},
        }
    }
    if (program.steps[0].operation != .assert_authorization) return error.InvalidStepGraph;
    if (program.steps[program.steps.len - 1].operation != .publish_provenance)
        return error.InvalidStepGraph;
    if (!std.mem.eql(u8, &program.artifacts_sha256, &hex(32, hashValue(
        "debz-native-transaction-program-artifacts-v1\x00",
        program.artifacts,
    )))) return error.ArtifactsDigestMismatch;
    if (!std.mem.eql(u8, &program.steps_sha256, &hex(32, hashValue(
        "debz-native-transaction-program-steps-v1\x00",
        program.steps,
    )))) return error.StepsDigestMismatch;
    if (!validLowerHex(&program.digest_sha256)) return error.InvalidDigest;
    if (!std.mem.eql(u8, &program.digest_sha256, &hex(32, documentDigest(program))))
        return error.DigestMismatch;
}

/// Strictly decodes one canonical program document. Unknown fields, duplicate
/// fields, missing fields, non-canonical serializations, and any digest
/// mismatch fail closed.
pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !OwnedProgram {
    if (source.len > maximum_bytes or source.len > maximum_document_bytes)
        return error.DocumentTooLarge;
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const program = try std.json.parseFromSliceLeaky(Program, arena.allocator(), source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    try validateDocument(program);
    const canonical = try program.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return .{
        .program = program,
        .arena = arena,
        .backing_allocator = allocator,
    };
}

/// No-follow publication of the compiled program bound to one directory entry.
/// The published document is the authority a later recovery reads.
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
    ) !OwnedProgram {
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
        program: Program,
    ) !void {
        const bytes = try program.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
        const stage = ".debz-native-program-v1.new";
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

fn safeLeaf(name: []const u8) bool {
    return name.len != 0 and
        !std.mem.eql(u8, name, ".") and
        !std.mem.eql(u8, name, "..") and
        std.mem.indexOfScalar(u8, name, '/') == null and
        std.mem.indexOfScalar(u8, name, '\\') == null;
}

const testing = std.testing;

fn testLock() native_authorization.LockBinding {
    return .{
        .schema = exact_lock_v2.schema_id,
        .version = exact_lock_v2.schema_version,
        .digest_sha256 = @splat(0x11),
    };
}

fn testArtifact(digest: u8, size: u64) native_authorization.Artifact {
    return .{
        .sha256 = @splat(digest),
        .size = size,
        .origin = .{ .authenticated_repository = .{
            .repository_id = @splat('a'),
            .repository_snapshot_sha256 = @splat(0x22),
        } },
    };
}

fn testAuthorization(
    allocator: std.mem.Allocator,
    actions: []const native_authorization.Action,
    final_state: []const native_authorization.FinalPackage,
) !native_authorization.OwnedAuthorization {
    return native_authorization.create(allocator, .{
        .backend = .native,
        .target_architecture = "amd64",
        .foreign_architectures = &.{},
        .install_root = "/srv/root",
        .request_sha256 = @splat(1),
        .solver_policy_sha256 = @splat(2),
        .executor_policy_sha256 = @splat(3),
        .plan_sha256 = @splat(4),
        .exact_lock = testLock(),
        .policy = .{ .conffile = .keep_existing, .force = &.{}, .allow_host_root = false },
        .actions = actions,
        .final_state = final_state,
    });
}

fn expectDiagnostic(result: Result, code: DiagnosticCode) !void {
    switch (result) {
        .program => |value| {
            var owned = value;
            owned.deinit();
            std.debug.print("expected diagnostic {s}, compiled a program\n", .{@tagName(code)});
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| {
            if (diagnostic.code != code) {
                std.debug.print("expected {s}, found {s} ({s})\n", .{
                    @tagName(code),
                    @tagName(diagnostic.code),
                    diagnostic.detail,
                });
                return error.TestUnexpectedResult;
            }
        },
    }
}

fn expectProgram(result: Result) !OwnedProgram {
    switch (result) {
        .program => |value| return value,
        .diagnostic => |diagnostic| {
            std.debug.print("unexpected diagnostic {s} ({s})\n", .{
                @tagName(diagnostic.code),
                diagnostic.detail,
            });
            return error.TestUnexpectedResult;
        },
    }
}

const install_actions = [_]native_authorization.Action{
    .{
        .sequence = 0,
        .kind = .install,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
        .prior_version = null,
        .artifact = testArtifact(0x31, 100),
    },
};

const install_final = [_]native_authorization.FinalPackage{
    .{
        .name = "app",
        .version = "1.2",
        .architecture = "amd64",
        .state = .installed,
        .dpkg_selection_hold = false,
    },
};

const install_ordered = [_]solver.OrderedAction{
    .{
        .sequence = 0,
        .kind = .unpack,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
    },
    .{
        .sequence = 1,
        .kind = .configure_pending,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
    },
};

fn installArchive() Archive {
    return .{
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
        .sha256 = @splat(0x31),
        .size = 100,
        .origin = .{ .authenticated_repository = .{
            .repository_id = @splat('a'),
            .repository_snapshot_sha256 = @splat(0x22),
        } },
        .application_sha256 = @splat(0x41),
        .scripts = &.{
            .{ .kind = .postinst, .sha256 = @splat(0x51), .size = 40 },
            .{ .kind = .preinst, .sha256 = @splat(0x52), .size = 30 },
        },
        .conffiles = &.{
            .{ .path = "/etc/app.conf", .md5 = @splat(0x61) },
        },
    };
}

test "native_program.test.fresh install compiles a complete deterministic program" {
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        &install_final,
    );
    defer authorization.deinit();
    const archives = [_]Archive{installArchive()};
    const input: Input = .{
        .authorization = &authorization.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71) },
        .archives = &archives,
    };
    var owned = try expectProgram(compile(testing.allocator, input));
    defer owned.deinit();
    const program = owned.program;

    try testing.expectEqualStrings(schema_id, program.schema);
    try testing.expect(program.matchesAuthorization(authorization.authorization));
    try testing.expectEqual(@as(usize, 1), program.artifacts.len);
    try testing.expect(program.steps[0].operation == .assert_authorization);
    try testing.expect(
        program.steps[program.steps.len - 1].operation == .publish_provenance,
    );
    try testing.expectEqual(@as(usize, 1), program.countSteps(.unpack_package));
    try testing.expectEqual(@as(usize, 1), program.countSteps(.apply_conffile_decision));
    try testing.expectEqual(@as(usize, 2), program.countSteps(.run_maintainer_script));
    try testing.expectEqual(@as(usize, 1), program.countSteps(.configure_barrier));

    var saw_preinst = false;
    var saw_postinst = false;
    for (program.steps) |step| switch (step.operation) {
        .run_maintainer_script => |call| {
            switch (call.kind) {
                .preinst => {
                    saw_preinst = true;
                    try testing.expectEqual(ScriptSource.new_package, call.source);
                    try testing.expectEqual(@as(usize, 1), call.arguments.len);
                    try testing.expectEqualStrings("install", call.arguments[0]);
                    try testing.expectEqual(PackageState.half_installed, call.failure.state);
                    try testing.expect(call.failure.unwind == null);
                },
                .postinst => {
                    saw_postinst = true;
                    try testing.expectEqualStrings("configure", call.arguments[0]);
                    try testing.expectEqual(PackageState.half_configured, call.failure.state);
                },
                else => return error.TestUnexpectedResult,
            }
            try testing.expectEqualSlices(
                u8,
                &hex(32, maintainer_script.policyDigest(.{})),
                &call.environment_policy_sha256,
            );
        },
        .apply_conffile_decision => |decision| {
            try testing.expectEqual(ConffileAction.install_new, decision.action);
            try testing.expectEqualStrings("/etc/app.conf", decision.path);
            try testing.expect(decision.recorded_md5 == null);
        },
        else => {},
    };
    try testing.expect(saw_preinst and saw_postinst);

    const document = try program.canonicalJson(testing.allocator);
    defer testing.allocator.free(document);
    var decoded = try decode(testing.allocator, document, maximum_document_bytes);
    defer decoded.deinit();
    try testing.expectEqualSlices(
        u8,
        &program.digest_sha256,
        &decoded.program.digest_sha256,
    );

    var second = try expectProgram(compile(testing.allocator, input));
    defer second.deinit();
    try testing.expectEqualSlices(
        u8,
        &program.digest_sha256,
        &second.program.digest_sha256,
    );
}

fn testAuthorizationWithPolicy(
    allocator: std.mem.Allocator,
    actions: []const native_authorization.Action,
    final_state: []const native_authorization.FinalPackage,
    policy: native_authorization.PolicyBinding,
) !native_authorization.OwnedAuthorization {
    return native_authorization.create(allocator, .{
        .backend = .native,
        .target_architecture = "amd64",
        .foreign_architectures = &.{},
        .install_root = "/srv/root",
        .request_sha256 = @splat(1),
        .solver_policy_sha256 = @splat(2),
        .executor_policy_sha256 = @splat(3),
        .plan_sha256 = @splat(4),
        .exact_lock = testLock(),
        .policy = policy,
        .actions = actions,
        .final_state = final_state,
    });
}

fn scriptCallAt(program: Program, index: usize) ?ScriptCall {
    var seen: usize = 0;
    for (program.steps) |step| switch (step.operation) {
        .run_maintainer_script => |call| {
            if (seen == index) return call;
            seen += 1;
        },
        else => {},
    };
    return null;
}

fn conffileDecisionFor(program: Program, path: []const u8) ?ConffileDecision {
    for (program.steps) |step| switch (step.operation) {
        .apply_conffile_decision => |decision| {
            if (std.mem.eql(u8, decision.path, path)) return decision;
        },
        else => {},
    };
    return null;
}

const upgrade_actions = [_]native_authorization.Action{
    .{
        .sequence = 0,
        .kind = .upgrade,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
        .prior_version = "1.0",
        .artifact = testArtifact(0x31, 100),
    },
};

const upgrade_final = [_]native_authorization.FinalPackage{
    .{
        .name = "app",
        .version = "1.2",
        .architecture = "amd64",
        .state = .installed,
        .dpkg_selection_hold = false,
    },
};

fn upgradeInstalled() []const InstalledPackage {
    const packages = struct {
        const value = [_]InstalledPackage{
            .{
                .name = "app",
                .version = "1.0",
                .architecture = "amd64",
                .state = .installed,
                .owned_paths_sha256 = @splat(0x81),
                .scripts = &.{
                    .{ .kind = .prerm, .sha256 = @splat(0x91) },
                    .{ .kind = .postrm, .sha256 = @splat(0x92) },
                    .{ .kind = .postinst, .sha256 = @splat(0x93) },
                },
                .conffiles = &.{
                    .{
                        .path = "/etc/app.conf",
                        .recorded_md5 = @splat(0x60),
                        .on_disk_md5 = @splat(0x6f),
                    },
                    .{
                        .path = "/etc/app-obsolete.conf",
                        .recorded_md5 = @splat(0x62),
                        .on_disk_md5 = @splat(0x62),
                    },
                },
            },
        };
    };
    return &packages.value;
}

fn upgradeArchive() Archive {
    var archive = installArchive();
    archive.scripts = &.{
        .{ .kind = .preinst, .sha256 = @splat(0x52) },
        .{ .kind = .postinst, .sha256 = @splat(0x51) },
        .{ .kind = .prerm, .sha256 = @splat(0x53) },
        .{ .kind = .postrm, .sha256 = @splat(0x54) },
    };
    return archive;
}

test "native_program.test.upgrade orders old and new scripts with exact unwind calls" {
    var authorization = try testAuthorization(
        testing.allocator,
        &upgrade_actions,
        &upgrade_final,
    );
    defer authorization.deinit();
    const archives = [_]Archive{upgradeArchive()};
    var owned = try expectProgram(compile(testing.allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{
            .generation_sha256 = @splat(0x71),
            .packages = upgradeInstalled(),
        },
        .archives = &archives,
    }));
    defer owned.deinit();
    const program = owned.program;

    const old_prerm = scriptCallAt(program, 0).?;
    try testing.expectEqual(maintainer_script.Kind.prerm, old_prerm.kind);
    try testing.expectEqual(ScriptSource.installed_package, old_prerm.source);
    try testing.expectEqualStrings("upgrade", old_prerm.arguments[0]);
    try testing.expectEqualStrings("1.2", old_prerm.arguments[1]);
    try testing.expectEqual(maintainer_script.Kind.prerm, old_prerm.failure.unwind.?.kind);
    try testing.expectEqual(ScriptSource.new_package, old_prerm.failure.unwind.?.source);
    try testing.expectEqualStrings("failed-upgrade", old_prerm.failure.unwind.?.arguments[0]);
    try testing.expectEqualStrings("1.0", old_prerm.failure.unwind.?.arguments[1]);

    const new_preinst = scriptCallAt(program, 1).?;
    try testing.expectEqual(maintainer_script.Kind.preinst, new_preinst.kind);
    try testing.expectEqual(ScriptSource.new_package, new_preinst.source);
    try testing.expectEqualStrings("upgrade", new_preinst.arguments[0]);
    try testing.expectEqualStrings("1.0", new_preinst.arguments[1]);
    try testing.expectEqualStrings("abort-upgrade", new_preinst.failure.unwind.?.arguments[0]);

    const old_postrm = scriptCallAt(program, 2).?;
    try testing.expectEqual(maintainer_script.Kind.postrm, old_postrm.kind);
    try testing.expectEqual(ScriptSource.installed_package, old_postrm.source);
    try testing.expectEqualStrings("upgrade", old_postrm.arguments[0]);
    try testing.expect(old_postrm.failure.recovery_required);

    const new_postinst = scriptCallAt(program, 3).?;
    try testing.expectEqual(maintainer_script.Kind.postinst, new_postinst.kind);
    try testing.expectEqualStrings("configure", new_postinst.arguments[0]);
    try testing.expectEqualStrings("1.0", new_postinst.arguments[1]);
    try testing.expect(scriptCallAt(program, 4) == null);

    const modified = conffileDecisionFor(program, "/etc/app.conf").?;
    try testing.expectEqual(ConffileAction.keep_existing_stage_dist, modified.action);
    try testing.expectEqual(
        transaction_executor.ConffilePolicy.keep_existing,
        modified.policy,
    );
    const obsolete = conffileDecisionFor(program, "/etc/app-obsolete.conf").?;
    try testing.expectEqual(ConffileAction.mark_obsolete, obsolete.action);

    var unpack_seen = false;
    for (program.steps) |step| switch (step.operation) {
        .unpack_package => |intent| {
            unpack_seen = true;
            try testing.expectEqualStrings("1.0", intent.prior_version.?);
            try testing.expect(!intent.bootstrapped);
            try testing.expectEqualSlices(
                u8,
                &hex(32, @as([32]u8, @splat(0x81))),
                &intent.prior_owned_paths_sha256.?,
            );
        },
        else => {},
    };
    try testing.expect(unpack_seen);
}

/// Every conffile decision the compiler can reach, keyed by the three digests
/// dpkg compares plus the reviewed policy. `null` digests mean "not recorded"
/// for `recorded` and "deleted from the root" for `on_disk`.
const ConffileCase = struct {
    name: []const u8,
    packaged: ?u8,
    recorded: ?u8,
    on_disk: ?u8,
    remove_on_upgrade: bool = false,
    keep_existing: ConffileAction,
    use_package_version: ConffileAction,
};

const conffile_cases = [_]ConffileCase{
    .{
        .name = "fresh install ships a new conffile",
        .packaged = 0x61,
        .recorded = null,
        .on_disk = null,
        .keep_existing = .install_new,
        .use_package_version = .install_new,
    },
    .{
        .name = "fresh install does not ship a remove-on-upgrade conffile",
        .packaged = null,
        .recorded = null,
        .on_disk = null,
        .remove_on_upgrade = true,
        .keep_existing = .skip_not_shipped,
        .use_package_version = .skip_not_shipped,
    },
    .{
        .name = "remove-on-upgrade deletes an unmodified recorded conffile",
        .packaged = null,
        .recorded = 0x60,
        .on_disk = 0x60,
        .remove_on_upgrade = true,
        .keep_existing = .remove_on_upgrade,
        .use_package_version = .remove_on_upgrade,
    },
    .{
        .name = "remove-on-upgrade preserves a locally modified conffile",
        .packaged = null,
        .recorded = 0x60,
        .on_disk = 0x6f,
        .remove_on_upgrade = true,
        .keep_existing = .remove_on_upgrade_stage_old,
        .use_package_version = .remove_on_upgrade_stage_old,
    },
    .{
        .name = "remove-on-upgrade has nothing to remove when the file is gone",
        .packaged = null,
        .recorded = 0x60,
        .on_disk = null,
        .remove_on_upgrade = true,
        .keep_existing = .skip_not_shipped,
        .use_package_version = .skip_not_shipped,
    },
    .{
        .name = "nothing changed anywhere",
        .packaged = 0x60,
        .recorded = 0x60,
        .on_disk = 0x60,
        .keep_existing = .identical_no_op,
        .use_package_version = .identical_no_op,
    },
    .{
        .name = "the root already holds the packaged bytes",
        .packaged = 0x61,
        .recorded = 0x60,
        .on_disk = 0x61,
        .keep_existing = .identical_no_op,
        .use_package_version = .identical_no_op,
    },
    .{
        .name = "unmodified locally, maintainer shipped an update",
        .packaged = 0x61,
        .recorded = 0x60,
        .on_disk = 0x60,
        .keep_existing = .replace_unmodified,
        .use_package_version = .replace_unmodified,
    },
    .{
        .name = "modified locally, maintainer changed nothing",
        .packaged = 0x60,
        .recorded = 0x60,
        .on_disk = 0x6f,
        .keep_existing = .keep_user_modified,
        .use_package_version = .keep_user_modified,
    },
    .{
        .name = "deleted locally, maintainer changed nothing",
        .packaged = 0x60,
        .recorded = 0x60,
        .on_disk = null,
        .keep_existing = .keep_user_deleted,
        .use_package_version = .keep_user_deleted,
    },
    .{
        .name = "modified locally and by the maintainer",
        .packaged = 0x61,
        .recorded = 0x60,
        .on_disk = 0x6f,
        .keep_existing = .keep_existing_stage_dist,
        .use_package_version = .install_stage_old,
    },
    .{
        .name = "deleted locally, maintainer shipped an update",
        .packaged = 0x61,
        .recorded = 0x60,
        .on_disk = null,
        .keep_existing = .keep_existing_stage_dist,
        .use_package_version = .restore_missing,
    },
};

fn conffilePolicies() [2]transaction_executor.ConffilePolicy {
    return .{ .keep_existing, .use_package_version };
}

fn expectedConffileAction(
    case: ConffileCase,
    policy: transaction_executor.ConffilePolicy,
) ConffileAction {
    return switch (policy) {
        .keep_existing => case.keep_existing,
        .use_package_version => case.use_package_version,
    };
}

test "native_program.test.conffile decisions follow the dpkg digest table" {
    for (conffile_cases) |case| {
        const packaged: ArchiveConffile = .{
            .path = "/etc/app.conf",
            .md5 = if (case.packaged) |value| @splat(value) else null,
            .remove_on_upgrade = case.remove_on_upgrade,
        };
        const recorded: ?InstalledConffile = if (case.recorded) |value| .{
            .path = "/etc/app.conf",
            .recorded_md5 = @splat(value),
            .on_disk_md5 = if (case.on_disk) |observed| @splat(observed) else null,
        } else null;
        for (conffilePolicies()) |policy| {
            const decision = conffileDecision(policy, packaged, recorded);
            const expected = expectedConffileAction(case, policy);
            if (decision != expected) {
                std.debug.print("{s} ({s}): expected {s}, found {s}\n", .{
                    case.name,
                    @tagName(policy),
                    @tagName(expected),
                    @tagName(decision),
                });
                return error.TestUnexpectedResult;
            }
        }
    }
}

// The decision table is only trustworthy if the compiler reaches it with the
// same evidence, so every case is compiled end to end and the emitted step is
// compared against the packaged, recorded, and observed digests it decided
// from.
test "native_program.test.compiled conffile steps carry the deciding digests" {
    for (conffile_cases) |case| {
        for (conffilePolicies()) |policy| {
            var authorization = try testAuthorizationWithPolicy(
                testing.allocator,
                &upgrade_actions,
                &upgrade_final,
                .{ .conffile = policy, .force = &.{}, .allow_host_root = false },
            );
            defer authorization.deinit();
            var archive = upgradeArchive();
            var packaged = [_]ArchiveConffile{.{
                .path = "/etc/app.conf",
                .md5 = if (case.packaged) |value| @splat(value) else null,
                .remove_on_upgrade = case.remove_on_upgrade,
            }};
            archive.conffiles = &packaged;
            const archives = [_]Archive{archive};
            var recorded = [_]InstalledConffile{.{
                .path = "/etc/app.conf",
                .recorded_md5 = if (case.recorded) |value| @splat(value) else @splat(0),
                .on_disk_md5 = if (case.on_disk) |observed| @splat(observed) else null,
            }};
            var installed = [_]InstalledPackage{.{
                .name = "app",
                .version = "1.0",
                .architecture = "amd64",
                .state = .installed,
                .conffiles = if (case.recorded == null) &.{} else &recorded,
            }};
            var owned = try expectProgram(compile(testing.allocator, .{
                .authorization = &authorization.authorization,
                .ordered_actions = &install_ordered,
                .installed = .{
                    .generation_sha256 = @splat(0x71),
                    .packages = &installed,
                },
                .archives = &archives,
            }));
            defer owned.deinit();
            const decision = conffileDecisionFor(owned.program, "/etc/app.conf").?;
            const expected = expectedConffileAction(case, policy);
            if (decision.action != expected) {
                std.debug.print("compiled {s} ({s}): expected {s}, found {s}\n", .{
                    case.name,
                    @tagName(policy),
                    @tagName(expected),
                    @tagName(decision.action),
                });
                return error.TestUnexpectedResult;
            }
            try testing.expectEqual(policy, decision.policy);
            try expectOptionalMd5(case.packaged, decision.packaged_md5);
            try expectOptionalMd5(case.recorded, decision.recorded_md5);
            try expectOptionalMd5(
                if (case.recorded == null) null else case.on_disk,
                decision.on_disk_md5,
            );
        }
    }
}

fn expectOptionalMd5(expected: ?u8, found: ?Md5Digest) !void {
    if (expected) |value| {
        try testing.expectEqualSlices(
            u8,
            &hex(16, @as([16]u8, @splat(value))),
            &(found orelse return error.TestUnexpectedResult),
        );
    } else {
        try testing.expect(found == null);
    }
}

// Every digest the decision reads must change the program, otherwise a
// tampered conffile record could reuse an authorized program digest.
test "native_program.test.conffile digests change the compiled decision and digest" {
    const Mutation = struct {
        packaged: ?u8,
        recorded: ?u8,
        on_disk: ?u8,
        expected: ConffileAction,
    };
    const mutations = [_]Mutation{
        .{ .packaged = 0x61, .recorded = 0x60, .on_disk = 0x60, .expected = .replace_unmodified },
        .{ .packaged = 0x61, .recorded = 0x60, .on_disk = 0x61, .expected = .identical_no_op },
        .{ .packaged = 0x60, .recorded = 0x60, .on_disk = 0x6f, .expected = .keep_user_modified },
        .{
            .packaged = 0x61,
            .recorded = 0x60,
            .on_disk = 0x6f,
            .expected = .keep_existing_stage_dist,
        },
    };
    var digests: std.ArrayList(Digest) = .empty;
    defer digests.deinit(testing.allocator);
    for (mutations) |mutation| {
        var authorization = try testAuthorization(
            testing.allocator,
            &upgrade_actions,
            &upgrade_final,
        );
        defer authorization.deinit();
        var archive = upgradeArchive();
        var packaged = [_]ArchiveConffile{.{
            .path = "/etc/app.conf",
            .md5 = if (mutation.packaged) |value| @splat(value) else null,
        }};
        archive.conffiles = &packaged;
        const archives = [_]Archive{archive};
        var recorded = [_]InstalledConffile{.{
            .path = "/etc/app.conf",
            .recorded_md5 = @splat(mutation.recorded.?),
            .on_disk_md5 = if (mutation.on_disk) |observed| @splat(observed) else null,
        }};
        var installed = [_]InstalledPackage{.{
            .name = "app",
            .version = "1.0",
            .architecture = "amd64",
            .state = .installed,
            .conffiles = &recorded,
        }};
        var owned = try expectProgram(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
        }));
        defer owned.deinit();
        try testing.expectEqual(
            mutation.expected,
            conffileDecisionFor(owned.program, "/etc/app.conf").?.action,
        );
        for (digests.items) |seen| {
            try testing.expect(!std.mem.eql(u8, &seen, &owned.program.digest_sha256));
        }
        try digests.append(testing.allocator, owned.program.digest_sha256);
    }
}

test "native_program.test.packaged conffile digests must match the shipped contract" {
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        &install_final,
    );
    defer authorization.deinit();
    const cases = [_]ArchiveConffile{
        .{ .path = "/etc/app.conf", .md5 = null, .remove_on_upgrade = false },
        .{ .path = "/etc/app.conf", .md5 = @splat(0x61), .remove_on_upgrade = true },
    };
    for (cases) |conffile| {
        var archive = installArchive();
        var conffiles = [_]ArchiveConffile{conffile};
        archive.conffiles = &conffiles;
        const archives = [_]Archive{archive};
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71) },
            .archives = &archives,
        }), .invalid_conffile_metadata);
    }
}

test "native_program.test.obsolete conffiles stay recorded when the package stops shipping them" {
    var authorization = try testAuthorization(
        testing.allocator,
        &upgrade_actions,
        &upgrade_final,
    );
    defer authorization.deinit();
    const archives = [_]Archive{upgradeArchive()};
    var owned = try expectProgram(compile(testing.allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{
            .generation_sha256 = @splat(0x71),
            .packages = upgradeInstalled(),
        },
        .archives = &archives,
    }));
    defer owned.deinit();
    const obsolete = conffileDecisionFor(owned.program, "/etc/app-obsolete.conf").?;
    try testing.expectEqual(ConffileAction.mark_obsolete, obsolete.action);
    try testing.expect(obsolete.packaged_md5 == null);
    try testing.expectEqualSlices(
        u8,
        &hex(16, @as([16]u8, @splat(0x62))),
        &obsolete.recorded_md5.?,
    );
}

const removal_installed = [_]InstalledPackage{
    .{
        .name = "legacy",
        .version = "2.0",
        .architecture = "amd64",
        .state = .installed,
        .owned_paths_sha256 = @splat(0x82),
        .scripts = &.{
            .{ .kind = .prerm, .sha256 = @splat(0x94) },
            .{ .kind = .postrm, .sha256 = @splat(0x95) },
            .{ .kind = .postinst, .sha256 = @splat(0x96) },
        },
        .conffiles = &.{
            .{
                .path = "/etc/legacy.conf",
                .recorded_md5 = @splat(0x63),
                .on_disk_md5 = @splat(0x63),
            },
        },
    },
};

fn removalOrdered(kind: solver.OrderedActionKind) [1]solver.OrderedAction {
    return .{.{
        .sequence = 0,
        .kind = kind,
        .package = "legacy",
        .version = "2.0",
        .architecture = "amd64",
    }};
}

test "native_program.test.remove retains conffiles and publishes the config-files state" {
    const actions = [_]native_authorization.Action{.{
        .sequence = 0,
        .kind = .remove,
        .package = "legacy",
        .version = "2.0",
        .architecture = "amd64",
        .prior_version = "2.0",
        .artifact = null,
    }};
    const final = [_]native_authorization.FinalPackage{.{
        .name = "legacy",
        .version = "2.0",
        .architecture = "amd64",
        .state = .config_files,
        .dpkg_selection_hold = false,
    }};
    var authorization = try testAuthorization(testing.allocator, &actions, &final);
    defer authorization.deinit();
    const ordered = removalOrdered(.remove);
    var owned = try expectProgram(compile(testing.allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = &ordered,
        .installed = .{
            .generation_sha256 = @splat(0x71),
            .packages = &removal_installed,
        },
    }));
    defer owned.deinit();
    const program = owned.program;
    try testing.expectEqual(@as(usize, 0), program.artifacts.len);

    const prerm = scriptCallAt(program, 0).?;
    try testing.expectEqual(maintainer_script.Kind.prerm, prerm.kind);
    try testing.expectEqualStrings("remove", prerm.arguments[0]);
    try testing.expectEqual(
        maintainer_script.Kind.postinst,
        prerm.failure.unwind.?.kind,
    );
    try testing.expectEqualStrings("abort-remove", prerm.failure.unwind.?.arguments[0]);
    const postrm = scriptCallAt(program, 1).?;
    try testing.expectEqualStrings("remove", postrm.arguments[0]);
    try testing.expect(postrm.failure.recovery_required);
    try testing.expect(scriptCallAt(program, 2) == null);

    try testing.expectEqual(
        ConffileAction.retain_on_remove,
        conffileDecisionFor(program, "/etc/legacy.conf").?.action,
    );
    var retained = false;
    var final_state: ?PackageState = null;
    for (program.steps) |step| switch (step.operation) {
        .remove_package_files => |intent| retained = intent.retain_conffiles,
        .record_package_state => |record| final_state = record.state,
        else => {},
    };
    try testing.expect(retained);
    try testing.expectEqual(PackageState.config_files, final_state.?);
    try testing.expectEqual(@as(usize, 0), program.countSteps(.purge_package_files));
}

test "native_program.test.purge removes conffiles and the database record" {
    const actions = [_]native_authorization.Action{.{
        .sequence = 0,
        .kind = .purge,
        .package = "legacy",
        .version = "2.0",
        .architecture = "amd64",
        .prior_version = "2.0",
        .artifact = null,
    }};
    var authorization = try testAuthorization(testing.allocator, &actions, &.{});
    defer authorization.deinit();
    const ordered = removalOrdered(.purge);
    var owned = try expectProgram(compile(testing.allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = &ordered,
        .installed = .{
            .generation_sha256 = @splat(0x71),
            .packages = &removal_installed,
        },
    }));
    defer owned.deinit();
    const program = owned.program;
    try testing.expectEqualStrings("remove", scriptCallAt(program, 1).?.arguments[0]);
    const purge = scriptCallAt(program, 2).?;
    try testing.expectEqual(maintainer_script.Kind.postrm, purge.kind);
    try testing.expectEqualStrings("purge", purge.arguments[0]);
    try testing.expectEqual(
        ConffileAction.delete_on_purge,
        conffileDecisionFor(program, "/etc/legacy.conf").?.action,
    );
    try testing.expectEqual(@as(usize, 1), program.countSteps(.purge_package_files));
    var removed_entry = false;
    for (program.steps) |step| switch (step.operation) {
        .record_package_state => |record| if (record.state == .not_installed) {
            removed_entry = record.remove_entry;
        },
        else => {},
    };
    try testing.expect(removed_entry);
}

test "native_program.test.purge of a config-files package skips file removal" {
    const actions = [_]native_authorization.Action{.{
        .sequence = 0,
        .kind = .purge,
        .package = "legacy",
        .version = "2.0",
        .architecture = "amd64",
        .prior_version = "2.0",
        .artifact = null,
    }};
    var authorization = try testAuthorization(testing.allocator, &actions, &.{});
    defer authorization.deinit();
    var installed = removal_installed;
    installed[0].state = .config_files;
    const ordered = removalOrdered(.purge);
    var owned = try expectProgram(compile(testing.allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = &ordered,
        .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
    }));
    defer owned.deinit();
    const program = owned.program;
    try testing.expectEqual(@as(usize, 0), program.countSteps(.remove_package_files));
    const purge = scriptCallAt(program, 0).?;
    try testing.expectEqualStrings("purge", purge.arguments[0]);
    try testing.expect(scriptCallAt(program, 1) == null);
}

const bootstrap_actions = [_]native_authorization.Action{
    .{
        .sequence = 0,
        .kind = .install,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
        .prior_version = null,
        .artifact = testArtifact(0x31, 100),
    },
    .{
        .sequence = 1,
        .kind = .install,
        .package = "lib",
        .version = "2.0",
        .architecture = "amd64",
        .prior_version = null,
        .artifact = testArtifact(0x32, 200),
    },
};

const bootstrap_final = [_]native_authorization.FinalPackage{
    .{
        .name = "app",
        .version = "1.2",
        .architecture = "amd64",
        .state = .installed,
        .dpkg_selection_hold = false,
    },
    .{
        .name = "lib",
        .version = "2.0",
        .architecture = "amd64",
        .state = .installed,
        .dpkg_selection_hold = false,
    },
};

fn libArchive() Archive {
    return .{
        .package = "lib",
        .version = "2.0",
        .architecture = "amd64",
        .sha256 = @splat(0x32),
        .size = 200,
        .origin = .{ .authenticated_repository = .{
            .repository_id = @splat('a'),
            .repository_snapshot_sha256 = @splat(0x22),
        } },
        .application_sha256 = @splat(0x42),
        .scripts = &.{.{ .kind = .postinst, .sha256 = @splat(0x55) }},
    };
}

const bootstrap_ordered = [_]solver.OrderedAction{
    .{
        .sequence = 0,
        .kind = .bootstrap_extract,
        .package = "lib",
        .version = "2.0",
        .architecture = "amd64",
    },
    .{
        .sequence = 1,
        .kind = .bootstrap_extract,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
    },
    .{
        .sequence = 2,
        .kind = .unpack,
        .package = "lib",
        .version = "2.0",
        .architecture = "amd64",
    },
    .{
        .sequence = 3,
        .kind = .configure_pending,
        .package = "lib",
        .version = "2.0",
        .architecture = "amd64",
    },
    .{
        .sequence = 4,
        .kind = .unpack,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
    },
    .{
        .sequence = 5,
        .kind = .configure_pending,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
    },
};

test "native_program.test.bootstrap and pre-depends barriers keep solver ordering" {
    var authorization = try testAuthorization(
        testing.allocator,
        &bootstrap_actions,
        &bootstrap_final,
    );
    defer authorization.deinit();
    const archives = [_]Archive{ installArchive(), libArchive() };
    var owned = try expectProgram(compile(testing.allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = &bootstrap_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71) },
        .archives = &archives,
    }));
    defer owned.deinit();
    const program = owned.program;
    try testing.expectEqual(
        @as(usize, 2),
        program.countSteps(.materialize_bootstrap_payload),
    );
    var barriers: [2]BarrierReason = undefined;
    var barrier_count: usize = 0;
    var bootstrap_before_unpack = true;
    var saw_unpack = false;
    for (program.steps) |step| switch (step.operation) {
        .materialize_bootstrap_payload => {
            if (saw_unpack) bootstrap_before_unpack = false;
        },
        .unpack_package => |intent| {
            saw_unpack = true;
            try testing.expect(intent.bootstrapped);
        },
        .configure_barrier => |barrier| {
            barriers[barrier_count] = barrier.reason;
            barrier_count += 1;
            try testing.expectEqual(@as(usize, 1), barrier.packages.len);
        },
        else => {},
    };
    try testing.expect(bootstrap_before_unpack);
    try testing.expectEqual(@as(usize, 2), barrier_count);
    try testing.expectEqual(BarrierReason.pre_depends, barriers[0]);
    try testing.expectEqual(BarrierReason.final, barriers[1]);
}

test "native_program.test.dependency cycles configure together at one barrier" {
    var authorization = try testAuthorization(
        testing.allocator,
        &bootstrap_actions,
        &bootstrap_final,
    );
    defer authorization.deinit();
    const archives = [_]Archive{ installArchive(), libArchive() };
    const ordered = [_]solver.OrderedAction{
        .{
            .sequence = 0,
            .kind = .unpack,
            .package = "lib",
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
        .{
            .sequence = 2,
            .kind = .configure_pending,
            .package = "app",
            .version = "1.2",
            .architecture = "amd64",
        },
    };
    var owned = try expectProgram(compile(testing.allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = &ordered,
        .installed = .{ .generation_sha256 = @splat(0x71) },
        .archives = &archives,
    }));
    defer owned.deinit();
    for (owned.program.steps) |step| switch (step.operation) {
        .configure_barrier => |barrier| {
            try testing.expectEqual(BarrierReason.final, barrier.reason);
            try testing.expectEqual(@as(usize, 2), barrier.packages.len);
            try testing.expectEqualStrings("lib", barrier.packages[0].name);
            try testing.expectEqualStrings("app", barrier.packages[1].name);
        },
        else => {},
    };
}

test "native_program.test.triggers defer work and publish awaited processing" {
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        &install_final,
    );
    defer authorization.deinit();
    var archive = installArchive();
    archive.triggers = &.{
        .{ .kind = .activate_await, .name = "update-menus" },
    };
    const archives = [_]Archive{archive};
    const installed = [_]InstalledPackage{
        .{
            .name = "menu",
            .version = "3.0",
            .architecture = "amd64",
            .state = .installed,
            .scripts = &.{.{ .kind = .postinst, .sha256 = @splat(0x97) }},
            .triggers = &.{.{ .kind = .interest_await, .name = "update-menus" }},
        },
    };
    const final = [_]native_authorization.FinalPackage{
        .{
            .name = "app",
            .version = "1.2",
            .architecture = "amd64",
            .state = .installed,
            .dpkg_selection_hold = false,
        },
        .{
            .name = "menu",
            .version = "3.0",
            .architecture = "amd64",
            .state = .installed,
            .dpkg_selection_hold = false,
        },
    };
    var full = try testAuthorization(testing.allocator, &install_actions, &final);
    defer full.deinit();
    var owned = try expectProgram(compile(testing.allocator, .{
        .authorization = &full.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
        .archives = &archives,
    }));
    defer owned.deinit();
    const program = owned.program;
    try testing.expectEqual(@as(usize, 1), program.countSteps(.activate_trigger));
    try testing.expectEqual(@as(usize, 1), program.countSteps(.record_trigger_interests));
    try testing.expectEqual(@as(usize, 1), program.countSteps(.process_deferred_triggers));
    var triggered: ?ScriptCall = null;
    var awaited_state = false;
    for (program.steps) |step| switch (step.operation) {
        .activate_trigger => |activation| {
            try testing.expectEqualStrings("update-menus", activation.trigger);
            try testing.expect(activation.awaiting);
            try testing.expectEqual(@as(usize, 1), activation.interested.len);
            try testing.expectEqualStrings("menu", activation.interested[0].name);
        },
        .process_deferred_triggers => |work| {
            try testing.expectEqual(@as(usize, 1), work.pending.len);
            try testing.expectEqualStrings("menu", work.pending[0].package.name);
            try testing.expect(work.pending[0].awaiting);
        },
        .run_maintainer_script => |call| {
            if (call.arguments.len == 2 and
                std.mem.eql(u8, call.arguments[0], "triggered")) triggered = call;
        },
        .record_package_state => |record| {
            if (record.state == .triggers_awaited) awaited_state = true;
        },
        else => {},
    };
    try testing.expectEqualStrings("update-menus", triggered.?.arguments[1]);
    try testing.expectEqual(ScriptSource.installed_package, triggered.?.source);
    try testing.expect(triggered.?.failure.recovery_required);
    try testing.expect(awaited_state);
    try testing.expect(
        program.steps[program.steps.len - 1].operation == .publish_provenance,
    );
}

// Trigger processing is the one place a package that is not part of the
// authorized actions still receives a maintainer-script call and a state
// record, so every state a database can publish is exercised here: only a
// completely installed package may be driven through `triggers-pending`,
// `postinst triggered`, and back to `installed`.
test "native_program.test.deferred triggers refuse every unhealthy interested state" {
    const listener_states = std.enums.values(PackageState);
    for (listener_states) |state| {
        var archive = installArchive();
        archive.triggers = &.{.{ .kind = .activate_noawait, .name = "update-menus" }};
        const archives = [_]Archive{archive};
        const installed = [_]InstalledPackage{
            .{
                .name = "menu",
                .version = "3.0",
                .architecture = "amd64",
                .state = state,
                .scripts = &.{.{ .kind = .postinst, .sha256 = @splat(0x97) }},
                .triggers = &.{.{ .kind = .interest_noawait, .name = "update-menus" }},
            },
        };
        const final = [_]native_authorization.FinalPackage{
            .{
                .name = "app",
                .version = "1.2",
                .architecture = "amd64",
                .state = .installed,
                .dpkg_selection_hold = false,
            },
            .{
                .name = "menu",
                .version = "3.0",
                .architecture = "amd64",
                .state = if (state == .config_files) .config_files else .installed,
                .dpkg_selection_hold = false,
            },
        };
        var full = try testAuthorization(testing.allocator, &install_actions, &final);
        defer full.deinit();
        const input: Input = .{
            .authorization = &full.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
        };
        if (state == .installed) {
            var owned = try expectProgram(compile(testing.allocator, input));
            defer owned.deinit();
            try testing.expectEqual(
                @as(usize, 1),
                owned.program.countSteps(.process_deferred_triggers),
            );
            var promoted = false;
            for (owned.program.steps) |step| switch (step.operation) {
                .record_package_state => |record| {
                    if (std.mem.eql(u8, record.package.name, "menu") and
                        record.state == .installed) promoted = true;
                },
                else => {},
            };
            try testing.expect(promoted);
            continue;
        }
        switch (compile(testing.allocator, input)) {
            .program => |value| {
                var owned = value;
                owned.deinit();
                std.debug.print(
                    "listener state {s} compiled a program\n",
                    .{@tagName(state)},
                );
                return error.TestUnexpectedResult;
            },
            .diagnostic => |diagnostic| {
                try testing.expectEqual(
                    DiagnosticCode.invalid_trigger_metadata,
                    diagnostic.code,
                );
                try testing.expectEqualStrings("menu", diagnostic.package.?);
            },
        }
    }
}

// A package whose recorded state is `triggers-pending` or `triggers-awaited`
// carries trigger work from an earlier run that v1 installed evidence does not
// enumerate. The transition this program would record is `installed`, which
// would drop it, so those roots must fail before a program exists at all.
test "native_program.test.recorded pending trigger work is never promoted to installed" {
    for ([_]PackageState{ .triggers_pending, .triggers_awaited }) |state| {
        var archive = installArchive();
        archive.triggers = &.{.{ .kind = .activate_noawait, .name = "update-menus" }};
        const archives = [_]Archive{archive};
        const installed = [_]InstalledPackage{
            .{
                .name = "menu",
                .version = "3.0",
                .architecture = "amd64",
                .state = state,
                .scripts = &.{.{ .kind = .postinst, .sha256 = @splat(0x97) }},
                .triggers = &.{.{ .kind = .interest_noawait, .name = "update-menus" }},
            },
        };
        const final = [_]native_authorization.FinalPackage{
            .{
                .name = "app",
                .version = "1.2",
                .architecture = "amd64",
                .state = .installed,
                .dpkg_selection_hold = false,
            },
            .{
                .name = "menu",
                .version = "3.0",
                .architecture = "amd64",
                .state = .installed,
                .dpkg_selection_hold = false,
            },
        };
        var full = try testAuthorization(testing.allocator, &install_actions, &final);
        defer full.deinit();
        switch (compile(testing.allocator, .{
            .authorization = &full.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
        })) {
            .program => |value| {
                var owned = value;
                owned.deinit();
                return error.TestUnexpectedResult;
            },
            .diagnostic => |diagnostic| {
                try testing.expectEqual(
                    DiagnosticCode.invalid_trigger_metadata,
                    diagnostic.code,
                );
                try testing.expectEqualStrings("trigger on unhealthy package", diagnostic.detail);
            },
        }
    }
}

// The awaited state this compilation creates itself is the one exception: a
// package that activated an awaited trigger is parked in `triggers-awaited`
// while it is configured, and the same program records its return to
// `installed` after the deferred work runs.
test "native_program.test.mutual trigger interests keep the awaited flow" {
    var archive = installArchive();
    archive.triggers = &.{
        .{ .kind = .activate_await, .name = "update-menus" },
        .{ .kind = .interest_await, .name = "refresh-cache" },
    };
    const archives = [_]Archive{archive};
    const installed = [_]InstalledPackage{
        .{
            .name = "menu",
            .version = "3.0",
            .architecture = "amd64",
            .state = .installed,
            .scripts = &.{.{ .kind = .postinst, .sha256 = @splat(0x97) }},
            .triggers = &.{
                .{ .kind = .interest_await, .name = "update-menus" },
                .{ .kind = .activate_await, .name = "refresh-cache" },
            },
        },
    };
    const final = [_]native_authorization.FinalPackage{
        .{
            .name = "app",
            .version = "1.2",
            .architecture = "amd64",
            .state = .installed,
            .dpkg_selection_hold = false,
        },
        .{
            .name = "menu",
            .version = "3.0",
            .architecture = "amd64",
            .state = .installed,
            .dpkg_selection_hold = false,
        },
    };
    var full = try testAuthorization(testing.allocator, &install_actions, &final);
    defer full.deinit();
    var owned = try expectProgram(compile(testing.allocator, .{
        .authorization = &full.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
        .archives = &archives,
    }));
    defer owned.deinit();
    const program = owned.program;
    try testing.expectEqual(@as(usize, 1), program.countSteps(.process_deferred_triggers));
    var app_awaited = false;
    var app_installed = false;
    var menu_pending = false;
    var menu_installed = false;
    for (program.steps) |step| switch (step.operation) {
        .record_package_state => |record| {
            const app = std.mem.eql(u8, record.package.name, "app");
            switch (record.state) {
                .triggers_awaited => if (app) {
                    app_awaited = true;
                },
                .triggers_pending => if (!app) {
                    menu_pending = true;
                },
                .installed => if (app) {
                    app_installed = true;
                } else {
                    menu_installed = true;
                },
                else => {},
            }
        },
        else => {},
    };
    try testing.expect(app_awaited and app_installed and menu_pending and menu_installed);
}

test "native_program.test.trigger metadata and interested evidence fail closed" {
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        &install_final,
    );
    defer authorization.deinit();
    const base: Input = .{
        .authorization = &authorization.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71) },
        .archives = &.{},
    };
    {
        var archive = installArchive();
        archive.triggers = &.{.{ .kind = .interest, .name = "bad name" }};
        const archives = [_]Archive{archive};
        var input = base;
        input.archives = &archives;
        try expectDiagnostic(
            compile(testing.allocator, input),
            .invalid_trigger_metadata,
        );
    }
    {
        var archive = installArchive();
        archive.triggers = &.{
            .{ .kind = .interest, .name = "update-menus" },
            .{ .kind = .interest_noawait, .name = "update-menus" },
        };
        const archives = [_]Archive{archive};
        var input = base;
        input.archives = &archives;
        try expectDiagnostic(compile(testing.allocator, input), .duplicate_trigger);
    }
    {
        var archive = installArchive();
        archive.triggers = &.{.{ .kind = .activate, .name = "update-menus" }};
        const archives = [_]Archive{archive};
        const installed = [_]InstalledPackage{
            .{
                .name = "menu",
                .version = "3.0",
                .architecture = "amd64",
                .state = .installed,
                .triggers = &.{.{ .kind = .interest, .name = "update-menus" }},
            },
        };
        const final = [_]native_authorization.FinalPackage{
            .{
                .name = "app",
                .version = "1.2",
                .architecture = "amd64",
                .state = .installed,
                .dpkg_selection_hold = false,
            },
            .{
                .name = "menu",
                .version = "3.0",
                .architecture = "amd64",
                .state = .installed,
                .dpkg_selection_hold = false,
            },
        };
        var full = try testAuthorization(testing.allocator, &install_actions, &final);
        defer full.deinit();
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &full.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
        }), .missing_script_evidence);
    }
}

test "native_program.test.ownership conflicts resolve only with replaces or reviewed force" {
    const conflict = [_]OwnershipConflict{.{
        .path = "/usr/bin/app",
        .holder = .{ .name = "legacy", .architecture = "amd64" },
        .claimant = .{ .name = "app", .architecture = "amd64" },
    }};
    const installed = [_]InstalledPackage{.{
        .name = "legacy",
        .version = "2.0",
        .architecture = "amd64",
        .state = .installed,
    }};
    const final = [_]native_authorization.FinalPackage{
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
            .state = .installed,
            .dpkg_selection_hold = false,
        },
    };
    {
        var authorization = try testAuthorization(
            testing.allocator,
            &install_actions,
            &final,
        );
        defer authorization.deinit();
        const archives = [_]Archive{installArchive()};
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
            .ownership_conflicts = &conflict,
        }), .unresolved_ownership_conflict);
    }
    {
        var authorization = try testAuthorization(
            testing.allocator,
            &install_actions,
            &final,
        );
        defer authorization.deinit();
        var archive = installArchive();
        archive.replaces = &.{"legacy"};
        const archives = [_]Archive{archive};
        var owned = try expectProgram(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
            .ownership_conflicts = &conflict,
        }));
        defer owned.deinit();
        for (owned.program.steps) |step| switch (step.operation) {
            .assert_path_ownership => |assertion| {
                try testing.expectEqual(OwnershipResolution.replaces, assertion.resolution);
                try testing.expectEqualStrings("/usr/bin/app", assertion.path);
                try testing.expectEqual(Phase.preflight, step.phase);
            },
            else => {},
        };
    }
    {
        var authorization = try testAuthorizationWithPolicy(
            testing.allocator,
            &install_actions,
            &final,
            .{
                .conffile = .keep_existing,
                .force = &.{.overwrite},
                .allow_host_root = false,
            },
        );
        defer authorization.deinit();
        const archives = [_]Archive{installArchive()};
        var owned = try expectProgram(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
            .ownership_conflicts = &conflict,
        }));
        defer owned.deinit();
        try testing.expectEqual(
            @as(usize, 1),
            owned.program.countSteps(.assert_path_ownership),
        );
    }
    {
        var authorization = try testAuthorization(
            testing.allocator,
            &install_actions,
            &final,
        );
        defer authorization.deinit();
        const archives = [_]Archive{installArchive()};
        const unknown = [_]OwnershipConflict{.{
            .path = "/usr/bin/app",
            .holder = .{ .name = "ghost", .architecture = "amd64" },
            .claimant = .{ .name = "app", .architecture = "amd64" },
        }};
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
            .ownership_conflicts = &unknown,
        }), .invalid_ownership_conflict);
    }
}

test "native_program.test.preflight evidence must be complete and quiescent" {
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        &install_final,
    );
    defer authorization.deinit();
    const archives = [_]Archive{installArchive()};
    const base: Input = .{
        .authorization = &authorization.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71) },
        .archives = &archives,
    };
    {
        var input = base;
        input.installed.updates_pending = true;
        try expectDiagnostic(compile(testing.allocator, input), .database_not_quiescent);
    }
    {
        var input = base;
        input.unsupported_features = &.{"var/lib/dpkg/parts"};
        try expectDiagnostic(compile(testing.allocator, input), .unsupported_feature);
    }
    {
        var input = base;
        input.script_policy = .{ .allow_host_root = true };
        try expectDiagnostic(compile(testing.allocator, input), .policy_mismatch);
    }
    {
        var input = base;
        const duplicated = [_]InstalledPackage{
            .{
                .name = "menu",
                .version = "3.0",
                .architecture = "amd64",
                .state = .installed,
            },
            .{
                .name = "menu",
                .version = "3.0",
                .architecture = "amd64",
                .state = .installed,
            },
        };
        input.installed.packages = &duplicated;
        try expectDiagnostic(
            compile(testing.allocator, input),
            .duplicate_installed_package,
        );
    }
    {
        var input = base;
        const invalid = [_]InstalledPackage{.{
            .name = "menu",
            .version = "not a version!",
            .architecture = "amd64",
            .state = .installed,
        }};
        input.installed.packages = &invalid;
        try expectDiagnostic(compile(testing.allocator, input), .invalid_version);
    }
    {
        var input = base;
        const invalid = [_]InstalledPackage{.{
            .name = "menu",
            .version = "3.0",
            .architecture = "amd64",
            .state = .installed,
            .conffiles = &.{.{ .path = "etc/relative.conf", .recorded_md5 = @splat(0) }},
        }};
        input.installed.packages = &invalid;
        try expectDiagnostic(
            compile(testing.allocator, input),
            .invalid_conffile_metadata,
        );
    }
}

test "native_program.test.artifact evidence must match every archive-producing action" {
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        &install_final,
    );
    defer authorization.deinit();
    const base: Input = .{
        .authorization = &authorization.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71) },
        .archives = &.{},
    };
    try expectDiagnostic(compile(testing.allocator, base), .missing_archive);
    {
        var mismatched = installArchive();
        mismatched.sha256 = @splat(0x39);
        const archives = [_]Archive{mismatched};
        var input = base;
        input.archives = &archives;
        try expectDiagnostic(
            compile(testing.allocator, input),
            .archive_evidence_mismatch,
        );
    }
    {
        var mismatched = installArchive();
        mismatched.size = 101;
        const archives = [_]Archive{mismatched};
        var input = base;
        input.archives = &archives;
        try expectDiagnostic(
            compile(testing.allocator, input),
            .archive_evidence_mismatch,
        );
    }
    {
        var mismatched = installArchive();
        mismatched.origin = .{ .authenticated_repository = .{
            .repository_id = @splat('b'),
            .repository_snapshot_sha256 = @splat(0x22),
        } };
        const archives = [_]Archive{mismatched};
        var input = base;
        input.archives = &archives;
        try expectDiagnostic(compile(testing.allocator, input), .archive_origin_mismatch);
    }
    {
        var mismatched = installArchive();
        mismatched.version = "9.9";
        const archives = [_]Archive{mismatched};
        var input = base;
        input.archives = &archives;
        try expectDiagnostic(
            compile(testing.allocator, input),
            .archive_identity_mismatch,
        );
    }
    {
        const archives = [_]Archive{ installArchive(), libArchive() };
        var input = base;
        input.archives = &archives;
        try expectDiagnostic(compile(testing.allocator, input), .extra_archive);
    }
    {
        const archives = [_]Archive{ installArchive(), installArchive() };
        var input = base;
        input.archives = &archives;
        try expectDiagnostic(compile(testing.allocator, input), .duplicate_archive);
    }
    {
        const actions = [_]native_authorization.Action{.{
            .sequence = 0,
            .kind = .remove,
            .package = "legacy",
            .version = "2.0",
            .architecture = "amd64",
            .prior_version = "2.0",
            .artifact = null,
        }};
        const final = [_]native_authorization.FinalPackage{.{
            .name = "legacy",
            .version = "2.0",
            .architecture = "amd64",
            .state = .config_files,
            .dpkg_selection_hold = false,
        }};
        var removal = try testAuthorization(testing.allocator, &actions, &final);
        defer removal.deinit();
        var archive = installArchive();
        archive.package = "legacy";
        archive.version = "2.0";
        const archives = [_]Archive{archive};
        const ordered = removalOrdered(.remove);
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &removal.authorization,
            .ordered_actions = &ordered,
            .installed = .{
                .generation_sha256 = @splat(0x71),
                .packages = &removal_installed,
            },
            .archives = &archives,
        }), .extra_archive);
    }
}

test "native_program.test.installed evidence must agree with every authorized action" {
    const archives = [_]Archive{installArchive()};
    {
        var authorization = try testAuthorization(
            testing.allocator,
            &install_actions,
            &install_final,
        );
        defer authorization.deinit();
        const installed = [_]InstalledPackage{.{
            .name = "app",
            .version = "1.0",
            .architecture = "amd64",
            .state = .installed,
        }};
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
        }), .installed_state_contradiction);
    }
    {
        var authorization = try testAuthorization(
            testing.allocator,
            &upgrade_actions,
            &upgrade_final,
        );
        defer authorization.deinit();
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71) },
            .archives = &archives,
        }), .missing_installed_package);
    }
    {
        var authorization = try testAuthorization(
            testing.allocator,
            &upgrade_actions,
            &upgrade_final,
        );
        defer authorization.deinit();
        const installed = [_]InstalledPackage{.{
            .name = "app",
            .version = "0.9",
            .architecture = "amd64",
            .state = .installed,
        }};
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
        }), .installed_state_contradiction);
    }
    {
        var authorization = try testAuthorization(
            testing.allocator,
            &upgrade_actions,
            &upgrade_final,
        );
        defer authorization.deinit();
        const installed = [_]InstalledPackage{.{
            .name = "app",
            .version = "1.0",
            .architecture = "amd64",
            .state = .half_installed,
        }};
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
        }), .installed_state_contradiction);
    }
    {
        var authorization = try testAuthorization(
            testing.allocator,
            &install_actions,
            &install_final,
        );
        defer authorization.deinit();
        const installed = [_]InstalledPackage{.{
            .name = "orphan",
            .version = "1.0",
            .architecture = "amd64",
            .state = .installed,
        }};
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
        }), .missing_final_package);
    }
    {
        const final = [_]native_authorization.FinalPackage{
            .{
                .name = "app",
                .version = "1.2",
                .architecture = "amd64",
                .state = .installed,
                .dpkg_selection_hold = false,
            },
            .{
                .name = "ghost",
                .version = "1.0",
                .architecture = "amd64",
                .state = .installed,
                .dpkg_selection_hold = false,
            },
        };
        var authorization = try testAuthorization(
            testing.allocator,
            &install_actions,
            &final,
        );
        defer authorization.deinit();
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71) },
            .archives = &archives,
        }), .unexpected_installed_package);
    }
    {
        const final = [_]native_authorization.FinalPackage{.{
            .name = "app",
            .version = "1.2",
            .architecture = "amd64",
            .state = .installed,
            .dpkg_selection_hold = true,
        }};
        var authorization = try testAuthorization(
            testing.allocator,
            &install_actions,
            &final,
        );
        defer authorization.deinit();
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71) },
            .archives = &archives,
        }), .final_state_contradiction);
    }
}

test "native_program.test.ordering must cover the authorized plan exactly" {
    var authorization = try testAuthorization(
        testing.allocator,
        &bootstrap_actions,
        &bootstrap_final,
    );
    defer authorization.deinit();
    const archives = [_]Archive{ installArchive(), libArchive() };
    const base: Input = .{
        .authorization = &authorization.authorization,
        .ordered_actions = &bootstrap_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71) },
        .archives = &archives,
    };
    {
        var input = base;
        input.ordered_actions = &.{};
        try expectDiagnostic(compile(testing.allocator, input), .missing_ordered_action);
    }
    {
        var input = base;
        const ordered = [_]solver.OrderedAction{.{
            .sequence = 0,
            .kind = .unpack,
            .package = "app",
            .version = "1.2",
            .architecture = "amd64",
        }};
        input.ordered_actions = &ordered;
        try expectDiagnostic(compile(testing.allocator, input), .missing_configure_barrier);
    }
    {
        var input = base;
        const ordered = [_]solver.OrderedAction{
            .{
                .sequence = 0,
                .kind = .unpack,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
            },
            .{
                .sequence = 1,
                .kind = .configure_pending,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
            },
        };
        input.ordered_actions = &ordered;
        try expectDiagnostic(compile(testing.allocator, input), .missing_ordered_action);
    }
    {
        var input = base;
        const ordered = [_]solver.OrderedAction{
            .{
                .sequence = 0,
                .kind = .unpack,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
            },
            .{
                .sequence = 1,
                .kind = .unpack,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
            },
            .{
                .sequence = 2,
                .kind = .configure_pending,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
            },
        };
        input.ordered_actions = &ordered;
        try expectDiagnostic(compile(testing.allocator, input), .duplicate_ordered_action);
    }
    {
        var input = base;
        const ordered = [_]solver.OrderedAction{
            .{
                .sequence = 0,
                .kind = .unpack,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
            },
            .{
                .sequence = 1,
                .kind = .configure_pending,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
            },
            .{
                .sequence = 2,
                .kind = .unpack,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
            },
            .{
                .sequence = 3,
                .kind = .configure_pending,
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
            },
        };
        input.ordered_actions = &ordered;
        try expectDiagnostic(compile(testing.allocator, input), .ordering_cycle);
    }
    {
        var input = base;
        var ordered = bootstrap_ordered;
        ordered[0].kind = .unpack;
        ordered[2].kind = .bootstrap_extract;
        input.ordered_actions = &ordered;
        try expectDiagnostic(compile(testing.allocator, input), .ordering_mismatch);
    }
    {
        var input = base;
        var ordered = bootstrap_ordered;
        ordered[1].package = "ghost";
        input.ordered_actions = &ordered;
        try expectDiagnostic(compile(testing.allocator, input), .ordering_mismatch);
    }
    {
        var input = base;
        var ordered = bootstrap_ordered;
        ordered[1].version = "9.9";
        input.ordered_actions = &ordered;
        try expectDiagnostic(compile(testing.allocator, input), .ordering_mismatch);
    }
    {
        var input = base;
        var ordered = bootstrap_ordered;
        ordered[3].sequence = 9;
        input.ordered_actions = &ordered;
        try expectDiagnostic(compile(testing.allocator, input), .ordering_mismatch);
    }
    {
        const actions = [_]native_authorization.Action{.{
            .sequence = 0,
            .kind = .remove,
            .package = "legacy",
            .version = "2.0",
            .architecture = "amd64",
            .prior_version = "2.0",
            .artifact = null,
        }};
        const final = [_]native_authorization.FinalPackage{.{
            .name = "legacy",
            .version = "2.0",
            .architecture = "amd64",
            .state = .config_files,
            .dpkg_selection_hold = false,
        }};
        var removal = try testAuthorization(testing.allocator, &actions, &final);
        defer removal.deinit();
        const ordered = removalOrdered(.purge);
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &removal.authorization,
            .ordered_actions = &ordered,
            .installed = .{
                .generation_sha256 = @splat(0x71),
                .packages = &removal_installed,
            },
        }), .ordering_mismatch);
    }
}

test "native_program.test.install over config files replays the recorded version" {
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        &install_final,
    );
    defer authorization.deinit();
    const installed = [_]InstalledPackage{.{
        .name = "app",
        .version = "1.0",
        .architecture = "amd64",
        .state = .config_files,
        .conffiles = &.{
            .{
                .path = "/etc/app.conf",
                .recorded_md5 = @splat(0x60),
                .on_disk_md5 = @splat(0x60),
            },
        },
    }};
    const archives = [_]Archive{upgradeArchive()};
    var owned = try expectProgram(compile(testing.allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
        .archives = &archives,
    }));
    defer owned.deinit();
    const preinst = scriptCallAt(owned.program, 0).?;
    try testing.expectEqualStrings("install", preinst.arguments[0]);
    try testing.expectEqualStrings("1.0", preinst.arguments[1]);
    try testing.expectEqualStrings(
        "abort-install",
        preinst.failure.unwind.?.arguments[0],
    );
    const postinst = scriptCallAt(owned.program, 1).?;
    try testing.expectEqualStrings("configure", postinst.arguments[0]);
    try testing.expectEqualStrings("1.0", postinst.arguments[1]);
    try testing.expectEqual(
        ConffileAction.replace_unmodified,
        conffileDecisionFor(owned.program, "/etc/app.conf").?.action,
    );
}

test "native_program.test.downgrade and reinstall keep the upgrade script contract" {
    const cases = [_]struct {
        kind: solver.ActionKind,
        version: []const u8,
        prior: []const u8,
    }{
        .{ .kind = .downgrade, .version = "1.2", .prior = "1.3" },
        .{ .kind = .reinstall, .version = "1.2", .prior = "1.2" },
    };
    for (cases) |case| {
        const actions = [_]native_authorization.Action{.{
            .sequence = 0,
            .kind = case.kind,
            .package = "app",
            .version = case.version,
            .architecture = "amd64",
            .prior_version = case.prior,
            .artifact = testArtifact(0x31, 100),
        }};
        var authorization = try testAuthorization(
            testing.allocator,
            &actions,
            &install_final,
        );
        defer authorization.deinit();
        const installed = [_]InstalledPackage{.{
            .name = "app",
            .version = case.prior,
            .architecture = "amd64",
            .state = .installed,
            .scripts = &.{
                .{ .kind = .prerm, .sha256 = @splat(0x91) },
                .{ .kind = .postrm, .sha256 = @splat(0x92) },
            },
        }};
        const archives = [_]Archive{upgradeArchive()};
        var owned = try expectProgram(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
            .archives = &archives,
        }));
        defer owned.deinit();
        try testing.expectEqualStrings("upgrade", scriptCallAt(owned.program, 0).?.arguments[0]);
        try testing.expectEqualStrings(case.prior, scriptCallAt(owned.program, 1).?.arguments[1]);
        try testing.expectEqualStrings("configure", scriptCallAt(owned.program, 3).?.arguments[0]);
    }
}

test "native_program.test.limits and work budgets fail closed" {
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        &install_final,
    );
    defer authorization.deinit();
    var archive = installArchive();
    archive.triggers = &.{.{ .kind = .interest, .name = "update-menus" }};
    const archives = [_]Archive{archive};
    const installed = [_]InstalledPackage{.{
        .name = "menu",
        .version = "3.0",
        .architecture = "amd64",
        .state = .installed,
    }};
    const final = [_]native_authorization.FinalPackage{
        .{
            .name = "app",
            .version = "1.2",
            .architecture = "amd64",
            .state = .installed,
            .dpkg_selection_hold = false,
        },
        .{
            .name = "menu",
            .version = "3.0",
            .architecture = "amd64",
            .state = .installed,
            .dpkg_selection_hold = false,
        },
    };
    var full = try testAuthorization(testing.allocator, &install_actions, &final);
    defer full.deinit();
    const base: Input = .{
        .authorization = &full.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed },
        .archives = &archives,
        .ownership_conflicts = &.{},
    };
    const cases = [_]struct {
        limits: Limits,
        code: DiagnosticCode,
    }{
        .{ .limits = .{ .steps = 0 }, .code = .invalid_limits },
        .{ .limits = .{ .steps = maximum_steps + 1 }, .code = .invalid_limits },
        .{ .limits = .{ .compile_work = 0 }, .code = .invalid_limits },
        .{
            .limits = .{ .artifacts = maximum_artifacts + 1 },
            .code = .invalid_limits,
        },
        .{ .limits = .{ .compile_work = 2 }, .code = .work_limit_exceeded },
        .{ .limits = .{ .artifacts = 0 }, .code = .limit_exceeded },
        .{ .limits = .{ .installed_packages = 0 }, .code = .limit_exceeded },
        .{ .limits = .{ .conffiles = 0 }, .code = .limit_exceeded },
        .{ .limits = .{ .triggers = 0 }, .code = .limit_exceeded },
        .{ .limits = .{ .steps = 4 }, .code = .limit_exceeded },
    };
    for (cases) |case| {
        var input = base;
        input.limits = case.limits;
        try expectDiagnostic(compile(testing.allocator, input), case.code);
    }
    {
        var input = base;
        input.limits = .{ .ownership_conflicts = 0 };
        const conflicts = [_]OwnershipConflict{.{
            .path = "/usr/bin/app",
            .holder = .{ .name = "menu", .architecture = "amd64" },
            .claimant = .{ .name = "app", .architecture = "amd64" },
        }};
        input.ownership_conflicts = &conflicts;
        try expectDiagnostic(compile(testing.allocator, input), .limit_exceeded);
    }
}

const wide_actions = [_]native_authorization.Action{
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
        .kind = .upgrade,
        .package = "base",
        .version = "2.0",
        .architecture = "amd64",
        .prior_version = "1.0",
        .artifact = testArtifact(0x33, 300),
    },
    .{
        .sequence = 3,
        .kind = .install,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
        .prior_version = null,
        .artifact = testArtifact(0x31, 100),
    },
};

const wide_final = [_]native_authorization.FinalPackage{
    .{
        .name = "app",
        .version = "1.2",
        .architecture = "amd64",
        .state = .installed,
        .dpkg_selection_hold = false,
    },
    .{
        .name = "base",
        .version = "2.0",
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
    .{
        .name = "menu",
        .version = "3.0",
        .architecture = "amd64",
        .state = .installed,
        .dpkg_selection_hold = false,
    },
};

const wide_ordered = [_]solver.OrderedAction{
    .{
        .sequence = 0,
        .kind = .purge,
        .package = "obsolete",
        .version = "0.9",
        .architecture = "amd64",
    },
    .{
        .sequence = 1,
        .kind = .remove,
        .package = "legacy",
        .version = "2.0",
        .architecture = "amd64",
    },
    .{
        .sequence = 2,
        .kind = .unpack,
        .package = "base",
        .version = "2.0",
        .architecture = "amd64",
    },
    .{
        .sequence = 3,
        .kind = .unpack,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
    },
    .{
        .sequence = 4,
        .kind = .configure_pending,
        .package = "app",
        .version = "1.2",
        .architecture = "amd64",
    },
};

const WideScenario = struct {
    app_scripts: [4]ArchiveScript = .{
        .{ .kind = .preinst, .sha256 = @splat(0x52) },
        .{ .kind = .postinst, .sha256 = @splat(0x51) },
        .{ .kind = .prerm, .sha256 = @splat(0x53) },
        .{ .kind = .postrm, .sha256 = @splat(0x54) },
    },
    app_conffiles: [2]ArchiveConffile = .{
        .{ .path = "/etc/app.conf", .md5 = @splat(0x61) },
        .{ .path = "/etc/app-extra.conf", .md5 = @splat(0x64) },
    },
    app_triggers: [2]TriggerDeclaration = .{
        .{ .kind = .activate_noawait, .name = "update-menus" },
        .{ .kind = .interest, .name = "/usr/share/app" },
    },
    app_replaces: [2][]const u8 = .{ "legacy", "obsolete" },
    base_scripts: [1]ArchiveScript = .{
        .{ .kind = .postinst, .sha256 = @splat(0x55) },
    },
    base_conffiles: [1]ArchiveConffile = .{
        // The maintainer shipped a new version of a locally modified conffile,
        // so the reviewed policy decides and the scenario keeps exercising the
        // staging branch of the decision table.
        .{ .path = "/etc/base.conf", .md5 = @splat(0x68) },
    },
    installed_base_scripts: [3]InstalledScript = .{
        .{ .kind = .prerm, .sha256 = @splat(0x91) },
        .{ .kind = .postrm, .sha256 = @splat(0x92) },
        .{ .kind = .postinst, .sha256 = @splat(0x93) },
    },
    installed_base_conffiles: [2]InstalledConffile = .{
        .{
            .path = "/etc/base.conf",
            .recorded_md5 = @splat(0x65),
            .on_disk_md5 = @splat(0x66),
        },
        .{
            .path = "/etc/base-old.conf",
            .recorded_md5 = @splat(0x67),
            .on_disk_md5 = @splat(0x67),
        },
    },
    legacy_scripts: [2]InstalledScript = .{
        .{ .kind = .prerm, .sha256 = @splat(0x94) },
        .{ .kind = .postrm, .sha256 = @splat(0x95) },
    },
    legacy_conffiles: [1]InstalledConffile = .{
        .{
            .path = "/etc/legacy.conf",
            .recorded_md5 = @splat(0x63),
            .on_disk_md5 = @splat(0x63),
        },
    },
    obsolete_scripts: [1]InstalledScript = .{
        .{ .kind = .postrm, .sha256 = @splat(0x98) },
    },
    menu_triggers: [1]TriggerDeclaration = .{
        .{ .kind = .interest_noawait, .name = "update-menus" },
    },
    menu_scripts: [1]InstalledScript = .{
        .{ .kind = .postinst, .sha256 = @splat(0x97) },
    },
    archives: [2]Archive = undefined,
    installed: [4]InstalledPackage = undefined,
    conflicts: [2]OwnershipConflict = undefined,

    fn init(self: *WideScenario) void {
        self.archives = .{
            .{
                .package = "app",
                .version = "1.2",
                .architecture = "amd64",
                .sha256 = @splat(0x31),
                .size = 100,
                .origin = .{ .authenticated_repository = .{
                    .repository_id = @splat('a'),
                    .repository_snapshot_sha256 = @splat(0x22),
                } },
                .application_sha256 = @splat(0x41),
                .scripts = &self.app_scripts,
                .conffiles = &self.app_conffiles,
                .triggers = &self.app_triggers,
                .replaces = &self.app_replaces,
            },
            .{
                .package = "base",
                .version = "2.0",
                .architecture = "amd64",
                .sha256 = @splat(0x33),
                .size = 300,
                .origin = .{ .authenticated_repository = .{
                    .repository_id = @splat('a'),
                    .repository_snapshot_sha256 = @splat(0x22),
                } },
                .application_sha256 = @splat(0x43),
                .scripts = &self.base_scripts,
                .conffiles = &self.base_conffiles,
            },
        };
        self.installed = .{
            .{
                .name = "base",
                .version = "1.0",
                .architecture = "amd64",
                .state = .installed,
                .owned_paths_sha256 = @splat(0x83),
                .scripts = &self.installed_base_scripts,
                .conffiles = &self.installed_base_conffiles,
            },
            .{
                .name = "legacy",
                .version = "2.0",
                .architecture = "amd64",
                .state = .installed,
                .owned_paths_sha256 = @splat(0x82),
                .scripts = &self.legacy_scripts,
                .conffiles = &self.legacy_conffiles,
            },
            .{
                .name = "obsolete",
                .version = "0.9",
                .architecture = "amd64",
                .state = .config_files,
                .scripts = &self.obsolete_scripts,
            },
            .{
                .name = "menu",
                .version = "3.0",
                .architecture = "amd64",
                .state = .installed,
                .scripts = &self.menu_scripts,
                .triggers = &self.menu_triggers,
            },
        };
        self.conflicts = .{
            .{
                .path = "/usr/bin/app",
                .holder = .{ .name = "legacy", .architecture = "amd64" },
                .claimant = .{ .name = "app", .architecture = "amd64" },
            },
            .{
                .path = "/usr/share/app/data",
                .holder = .{ .name = "legacy", .architecture = "amd64" },
                .claimant = .{ .name = "app", .architecture = "amd64" },
            },
        };
    }

    fn shuffle(self: *WideScenario) void {
        std.mem.reverse(ArchiveScript, &self.app_scripts);
        std.mem.reverse(ArchiveConffile, &self.app_conffiles);
        std.mem.reverse(TriggerDeclaration, &self.app_triggers);
        std.mem.reverse([]const u8, &self.app_replaces);
        std.mem.reverse(InstalledScript, &self.installed_base_scripts);
        std.mem.reverse(InstalledConffile, &self.installed_base_conffiles);
        std.mem.reverse(InstalledScript, &self.legacy_scripts);
        std.mem.reverse(Archive, &self.archives);
        std.mem.reverse(InstalledPackage, &self.installed);
        std.mem.reverse(OwnershipConflict, &self.conflicts);
    }

    fn input(
        self: *WideScenario,
        authorization: *const native_authorization.Authorization,
    ) Input {
        return .{
            .authorization = authorization,
            .ordered_actions = &wide_ordered,
            .installed = .{
                .generation_sha256 = @splat(0x71),
                .packages = &self.installed,
            },
            .archives = &self.archives,
            .ownership_conflicts = &self.conflicts,
        };
    }
};

test "native_program.test.compilation is independent of input order" {
    var authorization = try testAuthorization(testing.allocator, &wide_actions, &wide_final);
    defer authorization.deinit();
    var scenario: WideScenario = .{};
    scenario.init();
    var first = try expectProgram(compile(
        testing.allocator,
        scenario.input(&authorization.authorization),
    ));
    defer first.deinit();
    try testing.expect(first.program.steps.len > 20);
    try testing.expectEqual(@as(usize, 2), first.program.artifacts.len);
    try testing.expectEqualStrings("base", first.program.artifacts[0].package.name);
    try testing.expectEqual(
        @as(usize, 2),
        first.program.countSteps(.assert_path_ownership),
    );

    var shuffled: WideScenario = .{};
    shuffled.init();
    shuffled.shuffle();
    var second = try expectProgram(compile(
        testing.allocator,
        shuffled.input(&authorization.authorization),
    ));
    defer second.deinit();
    try testing.expectEqualSlices(
        u8,
        &first.program.digest_sha256,
        &second.program.digest_sha256,
    );
    const first_document = try first.program.canonicalJson(testing.allocator);
    defer testing.allocator.free(first_document);
    const second_document = try second.program.canonicalJson(testing.allocator);
    defer testing.allocator.free(second_document);
    try testing.expectEqualStrings(first_document, second_document);
}

test "native_program.test.every security relevant field changes the program digest" {
    var authorization = try testAuthorization(testing.allocator, &wide_actions, &wide_final);
    defer authorization.deinit();
    var alternate = try testAuthorizationWithPolicy(
        testing.allocator,
        &wide_actions,
        &wide_final,
        .{
            .conffile = .use_package_version,
            .force = &.{},
            .allow_host_root = false,
        },
    );
    defer alternate.deinit();

    var digests: std.ArrayList(Digest) = .empty;
    defer digests.deinit(testing.allocator);
    const Mutation = enum {
        none,
        database_generation,
        application_digest,
        archive_script_digest,
        packaged_conffile_digest,
        recorded_conffile_digest,
        on_disk_conffile_digest,
        installed_owned_paths,
        installed_script_digest,
        trigger_declaration,
        ownership_conflict_path,
        script_policy,
        script_outcome_unknown,
        authorization_policy,
    };
    for (std.enums.values(Mutation)) |mutation| {
        var scenario: WideScenario = .{};
        scenario.init();
        var input = scenario.input(&authorization.authorization);
        switch (mutation) {
            .none => {},
            .database_generation => input.installed.generation_sha256 = @splat(0x72),
            .application_digest => scenario.archives[0].application_sha256 = @splat(0x4f),
            .archive_script_digest => scenario.app_scripts[0].sha256 = @splat(0x5f),
            .packaged_conffile_digest => scenario.app_conffiles[0].md5 = @splat(0x6a),
            .recorded_conffile_digest => scenario.installed_base_conffiles[0].recorded_md5 =
                @splat(0x6b),
            .on_disk_conffile_digest => scenario.installed_base_conffiles[0].on_disk_md5 =
                @splat(0x6c),
            .installed_owned_paths => scenario.installed[1].owned_paths_sha256 = @splat(0x8f),
            .installed_script_digest => scenario.legacy_scripts[0].sha256 = @splat(0x9f),
            .trigger_declaration => scenario.app_triggers[0].kind = .activate_await,
            .ownership_conflict_path => scenario.conflicts[0].path = "/usr/bin/other",
            .script_policy => input.script_policy = .{ .capture = .combined },
            .script_outcome_unknown => input.record_script_outcome_unknown = false,
            .authorization_policy => input.authorization = &alternate.authorization,
        }
        var owned = try expectProgram(compile(testing.allocator, input));
        defer owned.deinit();
        for (digests.items) |seen| {
            if (std.mem.eql(u8, &seen, &owned.program.digest_sha256)) {
                std.debug.print("mutation {s} did not change the digest\n", .{
                    @tagName(mutation),
                });
                return error.TestUnexpectedResult;
            }
        }
        try digests.append(testing.allocator, owned.program.digest_sha256);
    }
}

test "native_program.test.canonical documents decode strictly and reject tampering" {
    var authorization = try testAuthorization(testing.allocator, &wide_actions, &wide_final);
    defer authorization.deinit();
    var scenario: WideScenario = .{};
    scenario.init();
    var owned = try expectProgram(compile(
        testing.allocator,
        scenario.input(&authorization.authorization),
    ));
    defer owned.deinit();
    const document = try owned.program.canonicalJson(testing.allocator);
    defer testing.allocator.free(document);

    var decoded = try decode(testing.allocator, document, maximum_document_bytes);
    defer decoded.deinit();
    try testing.expectEqual(owned.program.steps.len, decoded.program.steps.len);
    try testing.expect(decoded.program.matchesAuthorization(authorization.authorization));

    try testing.expectError(
        error.DocumentTooLarge,
        decode(testing.allocator, document, document.len - 1),
    );

    const unknown_field = try std.fmt.allocPrint(
        testing.allocator,
        "{s},\"unknown\":1}}",
        .{document[0 .. document.len - 1]},
    );
    defer testing.allocator.free(unknown_field);
    try testing.expectError(
        error.UnknownField,
        decode(testing.allocator, unknown_field, maximum_document_bytes),
    );

    const spaced = try std.fmt.allocPrint(testing.allocator, "{{ {s}", .{document[1..]});
    defer testing.allocator.free(spaced);
    try testing.expectError(
        error.NonCanonicalDocument,
        decode(testing.allocator, spaced, maximum_document_bytes),
    );

    {
        const tampered = try testing.allocator.dupe(u8, document);
        defer testing.allocator.free(tampered);
        const marker = "\"install_root\":\"/srv/root\"";
        const index = std.mem.indexOf(u8, tampered, marker).? + marker.len - 2;
        tampered[index] = 'x';
        try testing.expectError(
            error.InvalidProgram,
            decode(testing.allocator, tampered, maximum_document_bytes),
        );
    }
    {
        const tampered = try testing.allocator.dupe(u8, document);
        defer testing.allocator.free(tampered);
        const marker = "\"target_architecture\":\"amd64\"";
        const index = std.mem.indexOf(u8, tampered, marker).? + marker.len - 2;
        tampered[index] = '5';
        try testing.expectError(
            error.DigestMismatch,
            decode(testing.allocator, tampered, maximum_document_bytes),
        );
    }
    {
        const tampered = try testing.allocator.dupe(u8, document);
        defer testing.allocator.free(tampered);
        const marker = "\"steps_sha256\":\"";
        const index = std.mem.indexOf(u8, tampered, marker).? + marker.len;
        tampered[index] = if (tampered[index] == 'a') 'b' else 'a';
        try testing.expectError(
            error.StepsDigestMismatch,
            decode(testing.allocator, tampered, maximum_document_bytes),
        );
    }
    {
        const tampered = try testing.allocator.dupe(u8, document);
        defer testing.allocator.free(tampered);
        const marker = "\"artifacts_sha256\":\"";
        const index = std.mem.indexOf(u8, tampered, marker).? + marker.len;
        tampered[index] = if (tampered[index] == 'a') 'b' else 'a';
        try testing.expectError(
            error.ArtifactsDigestMismatch,
            decode(testing.allocator, tampered, maximum_document_bytes),
        );
    }
    {
        const tampered = try testing.allocator.dupe(u8, document);
        defer testing.allocator.free(tampered);
        const marker = "\"digest_sha256\":\"";
        const index = std.mem.lastIndexOf(u8, tampered, marker).? + marker.len;
        tampered[index] = 'z';
        try testing.expectError(
            error.InvalidDigest,
            decode(testing.allocator, tampered, maximum_document_bytes),
        );
    }
    {
        const tampered = try testing.allocator.dupe(u8, document);
        defer testing.allocator.free(tampered);
        const marker = "\"version\":1,";
        const index = std.mem.indexOf(u8, tampered, marker).? + "\"version\":".len;
        tampered[index] = '2';
        try testing.expectError(
            error.UnsupportedSchema,
            decode(testing.allocator, tampered, maximum_document_bytes),
        );
    }
    const authorization_document =
        \\{"schema":"https://debz.dev/schema/native-transaction-authorization-v1","version":1,"backend":"native"}
    ;
    try testing.expect(std.meta.isError(
        decode(testing.allocator, authorization_document, maximum_document_bytes),
    ));
    for ([_][]const u8{ "", "{", "null", "[]", "{\"schema\":1}" }) |invalid| {
        try testing.expect(std.meta.isError(
            decode(testing.allocator, invalid, maximum_document_bytes),
        ));
    }
}

test "native_program.test.compilation fails closed under allocation failure" {
    var authorization = try testAuthorization(testing.allocator, &wide_actions, &wide_final);
    defer authorization.deinit();
    var scenario: WideScenario = .{};
    scenario.init();
    const input = scenario.input(&authorization.authorization);
    var reference = try expectProgram(compile(testing.allocator, input));
    defer reference.deinit();

    var index: usize = 0;
    var compiled = false;
    while (index < 256) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{
            .fail_index = index,
        });
        switch (compile(failing.allocator(), input)) {
            .program => |value| {
                var owned = value;
                defer owned.deinit();
                compiled = true;
                try testing.expectEqualSlices(
                    u8,
                    &reference.program.digest_sha256,
                    &owned.program.digest_sha256,
                );
            },
            .diagnostic => |diagnostic| try testing.expectEqual(
                DiagnosticCode.out_of_memory,
                diagnostic.code,
            ),
        }
    }
    try testing.expect(compiled);
}

fn expectEnumMatchesSchema(comptime Enum: type, values: []const std.json.Value) !void {
    try testing.expectEqual(std.meta.fields(Enum).len, values.len);
    inline for (std.meta.fields(Enum)) |field| {
        var matches: usize = 0;
        for (values) |value| {
            if (value == .string and std.mem.eql(u8, field.name, value.string))
                matches += 1;
        }
        try testing.expectEqual(@as(usize, 1), matches);
    }
}

test "native_program.test.schema stays synchronized with the compiled contract" {
    const source = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "schema/native-transaction-program-v1.json",
        testing.allocator,
        .limited(maximum_document_bytes),
    );
    defer testing.allocator.free(source);
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, source, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings(schema_id, root.get("$id").?.string);
    const properties = root.get("properties").?.object;
    try testing.expectEqualStrings(
        schema_id,
        properties.get("schema").?.object.get("const").?.string,
    );
    try testing.expectEqual(
        @as(i64, schema_version),
        properties.get("version").?.object.get("const").?.integer,
    );
    try testing.expectEqualStrings(
        @tagName(native_authorization.Backend.native),
        properties.get("backend").?.object.get("const").?.string,
    );
    const definitions = root.get("$defs").?.object;
    try testing.expectEqualStrings(
        absolute_path.schema_pattern,
        definitions.get("absolutePath").?.object.get("pattern").?.string,
    );
    const lock_binding = definitions.get("lockBinding").?.object.get("properties").?.object;
    try testing.expectEqualStrings(
        exact_lock_v2.schema_id,
        lock_binding.get("schema").?.object.get("const").?.string,
    );
    try testing.expectEqual(
        @as(i64, exact_lock_v2.schema_version),
        lock_binding.get("version").?.object.get("const").?.integer,
    );

    var authorization = try testAuthorization(testing.allocator, &wide_actions, &wide_final);
    defer authorization.deinit();
    var scenario: WideScenario = .{};
    scenario.init();
    var owned = try expectProgram(compile(
        testing.allocator,
        scenario.input(&authorization.authorization),
    ));
    defer owned.deinit();
    const document = try owned.program.canonicalJson(testing.allocator);
    defer testing.allocator.free(document);
    var serialized = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        document,
        .{},
    );
    defer serialized.deinit();
    const required = root.get("required").?.array.items;
    try testing.expectEqual(required.len, properties.count());
    try testing.expectEqual(required.len, serialized.value.object.count());
    try testing.expectEqual(std.meta.fields(Program).len, required.len);
    for (required) |name| {
        try testing.expect(properties.contains(name.string));
        try testing.expect(serialized.value.object.contains(name.string));
    }

    const operations = definitions.get("operations").?.object;
    try testing.expectEqual(std.meta.fields(StepKind).len, operations.count());
    inline for (std.meta.fields(StepKind)) |field| {
        try testing.expect(operations.contains(field.name));
    }
    const variants = definitions.get("operation").?.object.get("oneOf").?.array.items;
    try testing.expectEqual(std.meta.fields(StepKind).len, variants.len);

    try expectEnumMatchesSchema(
        Phase,
        definitions.get("step").?.object
            .get("properties").?.object
            .get("phase").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        PackageState,
        operations.get("record_package_state").?.object
            .get("properties").?.object
            .get("state").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        ConffileAction,
        operations.get("apply_conffile_decision").?.object
            .get("properties").?.object
            .get("action").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        transaction_executor.ConffilePolicy,
        operations.get("apply_conffile_decision").?.object
            .get("properties").?.object
            .get("policy").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        maintainer_script.Kind,
        operations.get("run_maintainer_script").?.object
            .get("properties").?.object
            .get("kind").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        ScriptSource,
        operations.get("run_maintainer_script").?.object
            .get("properties").?.object
            .get("source").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        TriggerKind,
        operations.get("activate_trigger").?.object
            .get("properties").?.object
            .get("kind").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        OwnershipResolution,
        operations.get("assert_path_ownership").?.object
            .get("properties").?.object
            .get("resolution").?.object
            .get("enum").?.array.items,
    );
    try expectEnumMatchesSchema(
        BarrierReason,
        operations.get("configure_barrier").?.object
            .get("properties").?.object
            .get("reason").?.object
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

test "native_program.test.store publishes and rereads the recovery authority" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const store = try Store.init(std.testing.io, directory.dir, "program.json");
    try testing.expectError(
        error.AmbiguousPath,
        Store.init(std.testing.io, directory.dir, "nested/program.json"),
    );

    var authorization = try testAuthorization(testing.allocator, &wide_actions, &wide_final);
    defer authorization.deinit();
    var scenario: WideScenario = .{};
    scenario.init();
    var owned = try expectProgram(compile(
        testing.allocator,
        scenario.input(&authorization.authorization),
    ));
    defer owned.deinit();
    try store.writeAtomic(testing.allocator, owned.program);
    var reread = try store.read(testing.allocator, maximum_document_bytes);
    defer reread.deinit();
    try testing.expectEqualSlices(
        u8,
        &owned.program.digest_sha256,
        &reread.program.digest_sha256,
    );
    try testing.expectEqual(owned.program.steps.len, reread.program.steps.len);
    try testing.expect(reread.program.matchesAuthorization(authorization.authorization));
}

test "native_program.test.preflight binds the authorization, root, database, and artifacts" {
    var authorization = try testAuthorization(testing.allocator, &wide_actions, &wide_final);
    defer authorization.deinit();
    var scenario: WideScenario = .{};
    scenario.init();
    var owned = try expectProgram(compile(
        testing.allocator,
        scenario.input(&authorization.authorization),
    ));
    defer owned.deinit();
    const program = owned.program;

    switch (program.steps[0].operation) {
        .assert_authorization => |assertion| {
            try testing.expectEqualSlices(
                u8,
                &hex(32, authorization.authorization.digest_sha256),
                &assertion.authorization_sha256,
            );
            try testing.expectEqualSlices(
                u8,
                &hex(32, authorization.authorization.exact_lock.digest_sha256),
                &assertion.exact_lock_sha256,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    switch (program.steps[1].operation) {
        .assert_root_state => |assertion| {
            try testing.expectEqualStrings("/srv/root", assertion.install_root);
            try testing.expectEqualSlices(
                u8,
                &hex(32, transaction_recovery.rootIdentity("/srv/root")),
                &assertion.root_identity_sha256,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    switch (program.steps[2].operation) {
        .assert_database_generation => |assertion| {
            try testing.expectEqualSlices(
                u8,
                &hex(32, @as([32]u8, @splat(0x71))),
                &assertion.generation_sha256,
            );
            try testing.expectEqual(@as(u64, 4), assertion.package_count);
            try testing.expect(!assertion.updates_pending);
            try testing.expectEqualSlices(
                u8,
                &program.installed_database.evidence_sha256,
                &assertion.evidence_sha256,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 3), program.countSteps(.assert_installed_package));
    try testing.expectEqual(@as(usize, 1), program.countSteps(.assert_package_absent));
    try testing.expectEqual(@as(usize, 2), program.countSteps(.revalidate_artifact));
    try testing.expectEqual(@as(usize, 1), program.countSteps(.verify_final_state));
    try testing.expectEqual(@as(usize, 1), program.countSteps(.publish_database_generation));
    for (program.steps) |step| switch (step.operation) {
        .publish_provenance => |requirement| {
            try testing.expect(requirement.record_script_outcome_unknown);
            try testing.expectEqualSlices(
                u8,
                &hex(32, authorization.authorization.digest_sha256),
                &requirement.authorization_sha256,
            );
        },
        .verify_final_state => |verification| {
            try testing.expectEqual(@as(u64, 3), verification.installed_count);
            try testing.expectEqual(@as(u64, 1), verification.config_files_count);
        },
        else => {},
    };
}

test "native_program.test.rejects whitespace and control bytes in trigger names" {
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        &install_final,
    );
    defer authorization.deinit();
    for ([_][]const u8{
        "/usr/share/app data",
        "update menus",
        "update\tmenus",
        "update\x7fmenus",
        "update\xc3\xa9menus",
        "",
    }) |name| {
        var archive = installArchive();
        const declarations = [_]TriggerDeclaration{.{ .kind = .interest, .name = name }};
        archive.triggers = &declarations;
        const archives = [_]Archive{archive};
        try expectDiagnostic(compile(testing.allocator, .{
            .authorization = &authorization.authorization,
            .ordered_actions = &install_ordered,
            .installed = .{ .generation_sha256 = @splat(0x71) },
            .archives = &archives,
        }), .invalid_trigger_metadata);
    }
}

/// Records every byte range `compile` obtained from its backing allocator.
/// The compiler allocates only through the arena it destroys before returning
/// a diagnostic, so any diagnostic field pointing inside a recorded range
/// would be freed memory by the time the caller reads it.
const ArenaWatchdog = struct {
    backing: std.mem.Allocator,
    ranges: std.ArrayList(Range) = .empty,
    exhausted: bool = false,

    const Range = struct { start: usize, end: usize };

    fn allocator(self: *ArenaWatchdog) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn deinit(self: *ArenaWatchdog) void {
        self.ranges.deinit(self.backing);
    }

    fn record(self: *ArenaWatchdog, pointer: [*]u8, len: usize) void {
        const start = @intFromPtr(pointer);
        self.ranges.append(self.backing, .{ .start = start, .end = start + len }) catch {
            self.exhausted = true;
        };
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *ArenaWatchdog = @ptrCast(@alignCast(context));
        const result = self.backing.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.record(result, len);
        return result;
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        const self: *ArenaWatchdog = @ptrCast(@alignCast(context));
        if (!self.backing.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.record(memory.ptr, new_len);
        return true;
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *ArenaWatchdog = @ptrCast(@alignCast(context));
        const result = self.backing.rawRemap(memory, alignment, new_len, ret_addr) orelse
            return null;
        self.record(result, new_len);
        return result;
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self: *ArenaWatchdog = @ptrCast(@alignCast(context));
        self.backing.rawFree(memory, alignment, ret_addr);
    }

    fn owns(self: ArenaWatchdog, text: []const u8) bool {
        if (text.len == 0) return false;
        const start = @intFromPtr(text.ptr);
        for (self.ranges.items) |range| {
            if (start >= range.start and start < range.end) return true;
        }
        return false;
    }

    fn expectBorrowed(self: ArenaWatchdog, diagnostic: Diagnostic) !void {
        try testing.expect(!self.exhausted);
        const fields = [_]?[]const u8{
            diagnostic.detail,
            diagnostic.package,
            diagnostic.architecture,
            diagnostic.path,
        };
        for (fields) |field| {
            const text = field orelse continue;
            if (self.owns(text)) {
                std.debug.print(
                    "diagnostic {s} returned compiler-owned text '{s}'\n",
                    .{ @tagName(diagnostic.code), text },
                );
                return error.TestUnexpectedResult;
            }
        }
    }
};

/// Compiles under a watchdog and proves the rejection borrows only memory the
/// caller still owns.
fn expectBorrowedDiagnostic(input: Input, code: DiagnosticCode) !void {
    var watchdog: ArenaWatchdog = .{ .backing = testing.allocator };
    defer watchdog.deinit();
    switch (compile(watchdog.allocator(), input)) {
        .program => |value| {
            var owned = value;
            owned.deinit();
            std.debug.print("expected diagnostic {s}, compiled a program\n", .{@tagName(code)});
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| {
            try testing.expectEqual(code, diagnostic.code);
            try watchdog.expectBorrowed(diagnostic);
        },
    }
}

// `compile` destroys its arena before it returns, so a diagnostic that names a
// package, architecture, path, or detail must reference caller input or static
// text. Every rejection path that reports evidence is audited here.
test "native_program.test.every rejection borrows only caller owned text" {
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        &install_final,
    );
    defer authorization.deinit();
    const base: Input = .{
        .authorization = &authorization.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71) },
        .archives = &.{},
    };

    {
        var input = base;
        const features = [_][]const u8{"unsupported-root"};
        input.unsupported_features = &features;
        try expectBorrowedDiagnostic(input, .unsupported_feature);
    }
    {
        var archive = installArchive();
        const triggers = [_]TriggerDeclaration{.{ .kind = .interest, .name = "bad name" }};
        archive.triggers = &triggers;
        const archives = [_]Archive{archive};
        var input = base;
        input.archives = &archives;
        try expectBorrowedDiagnostic(input, .invalid_trigger_metadata);
    }
    {
        var archive = installArchive();
        const triggers = [_]TriggerDeclaration{
            .{ .kind = .interest, .name = "update-menus" },
            .{ .kind = .interest_noawait, .name = "update-menus" },
        };
        archive.triggers = &triggers;
        const archives = [_]Archive{archive};
        var input = base;
        input.archives = &archives;
        try expectBorrowedDiagnostic(input, .duplicate_trigger);
    }
    {
        var archive = installArchive();
        var conffiles = [_]ArchiveConffile{
            .{ .path = "/etc/app.conf", .md5 = @splat(0x61) },
            .{ .path = "/etc/app.conf", .md5 = @splat(0x62) },
        };
        archive.conffiles = &conffiles;
        const archives = [_]Archive{archive};
        var input = base;
        input.archives = &archives;
        try expectBorrowedDiagnostic(input, .duplicate_conffile);
    }
    {
        var archive = installArchive();
        var conffiles = [_]ArchiveConffile{.{ .path = "etc/app.conf", .md5 = @splat(0x61) }};
        archive.conffiles = &conffiles;
        const archives = [_]Archive{archive};
        var input = base;
        input.archives = &archives;
        try expectBorrowedDiagnostic(input, .invalid_conffile_metadata);
    }
    {
        var archive = installArchive();
        var replaces = [_][]const u8{"not a name"};
        archive.replaces = &replaces;
        const archives = [_]Archive{archive};
        var input = base;
        input.archives = &archives;
        try expectBorrowedDiagnostic(input, .invalid_archive_metadata);
    }
    {
        const archives = [_]Archive{installArchive()};
        const installed = [_]InstalledPackage{
            .{
                .name = "menu",
                .version = "3.0",
                .architecture = "amd64",
                .state = .installed,
                .conffiles = &.{
                    .{ .path = "/etc/menu.conf", .recorded_md5 = @splat(0x60) },
                    .{ .path = "/etc/menu.conf", .recorded_md5 = @splat(0x61) },
                },
            },
        };
        var input = base;
        input.archives = &archives;
        input.installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed };
        try expectBorrowedDiagnostic(input, .duplicate_conffile);
    }
    {
        const archives = [_]Archive{installArchive()};
        const installed = [_]InstalledPackage{
            .{
                .name = "menu",
                .version = "3.0",
                .architecture = "amd64",
                .state = .installed,
                .triggers = &.{
                    .{ .kind = .interest, .name = "update menus" },
                },
            },
        };
        var input = base;
        input.archives = &archives;
        input.installed = .{ .generation_sha256 = @splat(0x71), .packages = &installed };
        try expectBorrowedDiagnostic(input, .invalid_trigger_metadata);
    }
    {
        const conflicts = [_]OwnershipConflict{.{
            .path = "/usr/bin/app",
            .holder = .{ .name = "legacy", .architecture = "amd64" },
            .claimant = .{ .name = "app", .architecture = "amd64" },
        }};
        const archives = [_]Archive{installArchive()};
        var input = base;
        input.archives = &archives;
        input.ownership_conflicts = &conflicts;
        try expectBorrowedDiagnostic(input, .invalid_ownership_conflict);
    }
}

/// Builds one activating package plus `listeners` installed packages that all
/// declare interest in the same trigger, which is the only way to reach the
/// interested-package ceiling.
const InterestScenario = struct {
    allocator: std.mem.Allocator,
    trigger: []u8,
    names: [][]u8,
    installed: []InstalledPackage,
    final: []native_authorization.FinalPackage,
    declarations: []TriggerDeclaration,
    activation: [1]TriggerDeclaration = undefined,
    archives: [1]Archive = undefined,

    fn init(allocator: std.mem.Allocator, listeners: usize) !InterestScenario {
        const trigger = try allocator.dupe(u8, "update-menus");
        errdefer allocator.free(trigger);
        const names = try allocator.alloc([]u8, listeners);
        errdefer allocator.free(names);
        for (names, 0..) |*name, index|
            name.* = try std.fmt.allocPrint(allocator, "listener-{d}", .{index});
        const declarations = try allocator.alloc(TriggerDeclaration, listeners);
        errdefer allocator.free(declarations);
        const installed = try allocator.alloc(InstalledPackage, listeners);
        errdefer allocator.free(installed);
        const final = try allocator.alloc(native_authorization.FinalPackage, listeners + 1);
        errdefer allocator.free(final);
        for (names, 0..) |name, index| {
            declarations[index] = .{ .kind = .interest_noawait, .name = trigger };
            installed[index] = .{
                .name = name,
                .version = "1.0",
                .architecture = "amd64",
                .state = .installed,
                .triggers = declarations[index .. index + 1],
                .scripts = &.{},
            };
            final[index] = .{
                .name = name,
                .version = "1.0",
                .architecture = "amd64",
                .state = .installed,
                .dpkg_selection_hold = false,
            };
        }
        final[listeners] = install_final[0];
        var scenario: InterestScenario = .{
            .allocator = allocator,
            .trigger = trigger,
            .names = names,
            .installed = installed,
            .final = final,
            .declarations = declarations,
        };
        scenario.activation = .{.{ .kind = .activate_noawait, .name = trigger }};
        return scenario;
    }

    fn deinit(self: *InterestScenario) void {
        for (self.names) |name| self.allocator.free(name);
        self.allocator.free(self.names);
        self.allocator.free(self.declarations);
        self.allocator.free(self.installed);
        self.allocator.free(self.final);
        self.allocator.free(self.trigger);
    }

    fn input(
        self: *InterestScenario,
        authorization: *const native_authorization.Authorization,
    ) Input {
        self.archives = .{installArchive()};
        self.archives[0].triggers = &self.activation;
        return .{
            .authorization = authorization,
            .ordered_actions = &install_ordered,
            .installed = .{
                .generation_sha256 = @splat(0x71),
                .packages = self.installed,
            },
            .archives = &self.archives,
        };
    }
};

// The interested-package ceiling is reachable, and the diagnostic it returns
// names the activating package and the trigger. Both must survive the arena
// the compiler frees on its way out, so the trigger name is compared by
// pointer against caller memory and reread after the freed arena has been
// churned over by unrelated allocations.
test "native_program.test.the interested package ceiling returns a durable diagnostic" {
    var scenario = try InterestScenario.init(testing.allocator, maximum_interested_packages + 1);
    defer scenario.deinit();
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        scenario.final,
    );
    defer authorization.deinit();

    var watchdog: ArenaWatchdog = .{ .backing = testing.allocator };
    defer watchdog.deinit();
    const result = compile(watchdog.allocator(), scenario.input(&authorization.authorization));
    const diagnostic = switch (result) {
        .program => |value| {
            var owned = value;
            owned.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |value| value,
    };
    try testing.expectEqual(DiagnosticCode.limit_exceeded, diagnostic.code);
    try testing.expectEqualStrings("interested packages", diagnostic.detail);
    try testing.expectEqualStrings("app", diagnostic.package.?);
    try testing.expectEqualStrings(scenario.trigger, diagnostic.path.?);
    try testing.expectEqual(scenario.trigger.ptr, diagnostic.path.?.ptr);
    try watchdog.expectBorrowed(diagnostic);

    var churn: std.ArrayList([]u8) = .empty;
    defer {
        for (churn.items) |block| testing.allocator.free(block);
        churn.deinit(testing.allocator);
    }
    var round: usize = 0;
    while (round < 64) : (round += 1) {
        const block = try testing.allocator.alloc(u8, 4096);
        @memset(block, 0xa5);
        try churn.append(testing.allocator, block);
    }
    try testing.expectEqualStrings("interested packages", diagnostic.detail);
    try testing.expectEqualStrings("app", diagnostic.package.?);
    try testing.expectEqualStrings("update-menus", diagnostic.path.?);
    try testing.expectEqualStrings("app", diagnostic.package.?);
}

test "native_program.test.the interested package ceiling fails closed without memory" {
    var scenario = try InterestScenario.init(testing.allocator, maximum_interested_packages + 1);
    defer scenario.deinit();
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        scenario.final,
    );
    defer authorization.deinit();
    const input = scenario.input(&authorization.authorization);

    var index: usize = 0;
    var rejected = false;
    while (index < 64) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{
            .fail_index = index,
        });
        switch (compile(failing.allocator(), input)) {
            .program => |value| {
                var owned = value;
                owned.deinit();
                return error.TestUnexpectedResult;
            },
            .diagnostic => |diagnostic| switch (diagnostic.code) {
                .out_of_memory => {},
                .limit_exceeded => {
                    rejected = true;
                    try testing.expectEqualStrings(scenario.trigger, diagnostic.path.?);
                    try testing.expectEqual(scenario.trigger.ptr, diagnostic.path.?.ptr);
                },
                else => return error.TestUnexpectedResult,
            },
        }
    }
    try testing.expect(rejected);
}

test "native_program.test.the compiled program owns every published byte" {
    var authorization = try testAuthorization(
        testing.allocator,
        &install_actions,
        &install_final,
    );
    defer authorization.deinit();
    const trigger = try testing.allocator.dupe(u8, "update-menus");
    defer testing.allocator.free(trigger);
    const path = try testing.allocator.dupe(u8, "/etc/app.conf");
    defer testing.allocator.free(path);

    var archive = installArchive();
    const declarations = [_]TriggerDeclaration{
        .{ .kind = .interest, .name = trigger },
        .{ .kind = .activate_noawait, .name = trigger },
    };
    var conffiles = [_]ArchiveConffile{.{ .path = path, .md5 = @splat(0x61) }};
    archive.triggers = &declarations;
    archive.conffiles = &conffiles;
    const archives = [_]Archive{archive};
    var owned = try expectProgram(compile(testing.allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = &install_ordered,
        .installed = .{ .generation_sha256 = @splat(0x71) },
        .archives = &archives,
    }));
    defer owned.deinit();
    const before = try owned.program.canonicalJson(testing.allocator);
    defer testing.allocator.free(before);

    @memset(trigger, 'z');
    @memset(path, 'z');
    const after = try owned.program.canonicalJson(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualStrings(before, after);
    try testing.expectEqualSlices(
        u8,
        &owned.program.digest_sha256,
        &hex(32, documentDigest(owned.program)),
    );
    try testing.expect(std.mem.indexOf(u8, after, "update-menus") != null);
    try testing.expect(std.mem.indexOf(u8, after, "zzzz") == null);
}
