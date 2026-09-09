//! Root-scoped operation coordination version 1.
//!
//! Every debz mutation of a selected root — repository bootstrap and package
//! transactions alike — passes through exactly one root mutation lock and one
//! durable active-attempt record. Both live in the root's own `var/lib/debz`
//! namespace and are reached only through `root_fs`, so no component of the
//! path is ever resolved through a symbolic link and nothing is written
//! outside the selected root.
//!
//! The record is the durable answer to one question: may another mutation of
//! this root start? It is reserved before any mutation, advanced at every
//! authorization, preflight, mutation, script, trigger, database,
//! verification, and provenance boundary, and cleared only after the
//! operation's provenance has been published. An interrupted attempt therefore
//! leaves either proof that nothing was mutated (safely abandoned) or a typed
//! recovery requirement that blocks the next mutation until it is resolved.
//!
//! Evidence is only ever read as evidence about the run that produced it. A
//! record that already sits at the executor bridge was handed over by an
//! earlier run, so a later run may adopt it but can never prove what that
//! hand-over did, and a record whose provenance is already published describes
//! an operation that is over, so it is reclaimed into a fresh attempt rather
//! than continued.
//!
//! Advancing is monotonic and compare-and-set: a writer must present the
//! attempt identifier, generation, and digest it last published, and the
//! generation and step must strictly increase. A stale writer that resumed
//! from an older view is rejected instead of overwriting newer evidence. The
//! record digest covers the whole payload, decoding is bounded and strict, and
//! an unknown, non-canonical, corrupt, or foreign-root record fails closed.
//!
//! This module owns coordination only. It never writes a package database,
//! never applies an archive, and never runs a maintainer script.
const std = @import("std");
const builtin = @import("builtin");
const absolute_path = @import("absolute_path.zig");
const product_api = @import("product_api.zig");
const repository_api = @import("repository_api.zig");
const root_fs = @import("root_fs.zig");
const transaction_engine = @import("transaction_engine.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_recovery = @import("transaction_recovery.zig");

pub const schema_id = "https://debz.dev/schema/root-operation-record-v1";
pub const schema_version: u32 = 1;

/// The record is small and fixed-shape. The ceiling exists so a hostile or
/// damaged root cannot force an unbounded read before validation.
pub const maximum_document_bytes: usize = 64 * 1024;
pub const maximum_root_bytes: usize = root_fs.maximum_path_bytes;
pub const maximum_architectures: usize = 64;
pub const maximum_architecture_bytes: usize = 64;
pub const maximum_schema_bytes: usize = 256;

/// Root-relative namespace. Repository bootstrap and package transactions
/// share it, so a single root can only ever carry one active attempt.
pub const namespace_path = "var/lib/debz";
pub const lock_name = "root-operation.lock";
pub const record_name = "root-operation-v1.json";
pub const deferred_ack_name = "root-operation-deferred-ack-v1.json";
pub const recovery_review_name = deferred_ack_name;
pub const record_path = namespace_path ++ "/" ++ record_name;
pub const deferred_ack_path = namespace_path ++ "/" ++ deferred_ack_name;
pub const recovery_review_path = deferred_ack_path;
pub const lock_path = namespace_path ++ "/" ++ lock_name;

/// Transaction backend the attempt is bound to. A record written for one
/// backend is never reinterpreted as another backend's evidence.
pub const Backend = transaction_engine.Kind;

/// The two mutation surfaces that share this root namespace.
pub const Surface = enum { package_transaction, repository_bootstrap };

/// Exact operation behind the surface. Each surface keeps its own API's
/// spelling so a record can never be replayed as the other surface.
pub const Operation = union(Surface) {
    package_transaction: product_api.Operation,
    repository_bootstrap: repository_api.Operation,

    pub fn eql(self: Operation, other: Operation) bool {
        return switch (self) {
            .package_transaction => |value| switch (other) {
                .package_transaction => |compare| value == compare,
                .repository_bootstrap => false,
            },
            .repository_bootstrap => |value| switch (other) {
                .package_transaction => false,
                .repository_bootstrap => |compare| value == compare,
            },
        };
    }

    pub fn spelling(self: Operation) []const u8 {
        return switch (self) {
            .package_transaction => |value| @tagName(value),
            .repository_bootstrap => |value| @tagName(value),
        };
    }
};

/// Durable lifecycle of one attempt.
///
/// `mutation_pending` is the explicit bridge for the current command-oriented
/// executor: control has been handed to an engine that may mutate, but no
/// mutation has been witnessed yet. It is never treated as safely abandoned;
/// only an explicit witness resolves it.
pub const State = enum {
    reserved,
    preflight,
    mutation_pending,
    mutating,
    verifying,
    recovery_required,
    recovering,
    completed,

    /// True while the attempt may have mutated the root, so a second mutation
    /// must not start.
    pub fn blocksMutation(self: State) bool {
        return switch (self) {
            .reserved, .preflight, .completed => false,
            .mutation_pending, .mutating, .verifying, .recovery_required, .recovering => true,
        };
    }

    /// True when the attempt is durably proven not to have mutated the root.
    pub fn provenPreMutation(self: State) bool {
        return switch (self) {
            .reserved, .preflight => true,
            else => false,
        };
    }
};

/// Durable boundary inside the attempt. The boundary is explicit rather than
/// derived so an interrupted attempt reports where it stopped.
pub const Phase = enum {
    reserved,
    authorization,
    preflight,
    mutation,
    script,
    trigger,
    database,
    verification,
    provenance,
};

pub const Outcome = enum {
    pending,
    succeeded,
    abandoned_before_mutation,
    failed_after_mutation,
    recovered,
};

pub const ProvenanceState = enum {
    /// Provenance is owed before the record may be cleared.
    pending,
    /// Nothing was mutated, so there is no execution to attest.
    not_required,
    published,
};

pub const LockBinding = struct {
    schema: []const u8,
    version: u32,
    digest_sha256: [32]u8,

    pub fn eql(self: LockBinding, other: LockBinding) bool {
        return self.version == other.version and
            std.mem.eql(u8, self.schema, other.schema) and
            std.mem.eql(u8, &self.digest_sha256, &other.digest_sha256);
    }
};

/// Digests bound into the attempt. Each one is sticky: once published it can
/// never be replaced, so a later writer cannot rebind an attempt to different
/// authorization, plan, or artifact evidence.
pub const Evidence = struct {
    authorization_sha256: ?[32]u8 = null,
    program_sha256: ?[32]u8 = null,
    /// Absent until the reviewed plan exists. Reserving the root happens
    /// before planning, so the plan digest is bound at the first boundary that
    /// has one.
    plan_sha256: ?[32]u8 = null,
    exact_lock: ?LockBinding = null,
    database_generation_sha256: ?[32]u8 = null,
    artifact_evidence_sha256: ?[32]u8 = null,
};

pub const Record = struct {
    attempt_id: [32]u8,
    generation: u64,
    install_root: []const u8,
    root_identity_sha256: [32]u8,
    backend: Backend,
    operation: Operation,
    state: State,
    phase: Phase,
    step: u64,
    mutation_started: bool,
    outcome: Outcome,
    provenance: ProvenanceState,
    provenance_sha256: ?[32]u8,
    authorization_sha256: ?[32]u8,
    program_sha256: ?[32]u8,
    plan_sha256: ?[32]u8,
    exact_lock: ?LockBinding,
    database_generation_sha256: ?[32]u8,
    artifact_evidence_sha256: ?[32]u8,
    request_sha256: [32]u8,
    policy_sha256: [32]u8,
    target_architecture: []const u8,
    foreign_architectures: []const []const u8,
    /// Evidence only. Neither timestamp expires an attempt: a lock that timed
    /// out is never stolen because its holder looks old.
    reserved_unix: i64,
    updated_unix: i64,
    digest_sha256: [32]u8,

    /// An allocating writer can only fail by running out of memory, so the
    /// generic write error is translated into the exact one.
    pub fn canonicalJson(
        self: Record,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        writeDocument(self, &output.writer) catch return error.OutOfMemory;
        return output.toOwnedSlice() catch error.OutOfMemory;
    }

    pub fn evidence(self: Record) Evidence {
        return .{
            .authorization_sha256 = self.authorization_sha256,
            .program_sha256 = self.program_sha256,
            .plan_sha256 = self.plan_sha256,
            .exact_lock = self.exact_lock,
            .database_generation_sha256 = self.database_generation_sha256,
            .artifact_evidence_sha256 = self.artifact_evidence_sha256,
        };
    }

    /// True when the record may be removed: the attempt finished and its
    /// provenance obligation is discharged.
    pub fn clearable(self: Record) bool {
        return self.state == .completed and self.provenance != .pending;
    }
};

pub const OwnedRecord = struct {
    record: Record,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedRecord) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const deferred_ack_schema_id =
    "https://debz.dev/schema/root-operation-deferred-ack-v1";
pub const deferred_ack_schema_version: u32 = 1;
pub const deferred_ack_v2_schema_id =
    "https://debz.dev/schema/root-operation-deferred-ack-v2";
pub const deferred_ack_v2_schema_version: u32 = 2;
pub const recovery_review_schema_id =
    "https://debz.dev/schema/root-operation-recovery-review-v1";
pub const recovery_review_schema_version: u32 = 1;

pub const RecoveryReviewMutationStatus = enum {
    unchanged,
    changed,
};

pub const RecoveryReviewClaim = struct {
    outer_attempt_id: [32]u8,
    outer_generation: u64,
    outer_state_sha256: [32]u8,
    profile_sha256: [32]u8,
    profile_reference_sha256: [32]u8,
    exact_lock_sha256: [32]u8,
    semantic_request_sha256: [32]u8,
    outer_transaction_sha256: ?[32]u8 = null,
    mutation_status: RecoveryReviewMutationStatus,
    nonce: [32]u8,
    marker_sha256: ?[32]u8 = null,
    prior_marker: ?DeferredAcknowledgment = null,
    record_sha256: ?[32]u8 = null,
    completion_sha256: ?[32]u8 = null,
    digest_sha256: [32]u8 = @splat(0),

    pub fn canonicalJson(
        self: RecoveryReviewClaim,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        if (!validRecoveryReviewClaim(self)) return error.InvalidDocument;
        if (!std.mem.eql(
            u8,
            &self.digest_sha256,
            &recoveryReviewClaimDigest(self),
        )) return error.DigestMismatch;
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeRecoveryReviewClaim(self, &output.writer);
        const bytes = try output.toOwnedSlice();
        if (bytes.len > maximum_document_bytes) {
            allocator.free(bytes);
            return error.DocumentTooLarge;
        }
        return bytes;
    }
};

pub fn createRecoveryReviewClaim(
    input: RecoveryReviewClaim,
) !RecoveryReviewClaim {
    if (!validRecoveryReviewClaim(input)) return error.InvalidDocument;
    var result = input;
    result.digest_sha256 = recoveryReviewClaimDigest(result);
    return result;
}

fn validRecoveryReviewClaim(claim: RecoveryReviewClaim) bool {
    if (claim.outer_generation == 0) return false;
    if ((claim.prior_marker == null) != (claim.marker_sha256 == null))
        return false;
    if (claim.prior_marker) |marker|
        if (!validDeferredAcknowledgment(marker) or !std.mem.eql(
            u8,
            &marker.digest_sha256,
            &claim.marker_sha256.?,
        ) or !std.mem.eql(
            u8,
            &marker.digest_sha256,
            &deferredAcknowledgmentDigest(marker),
        )) return false;
    return switch (claim.mutation_status) {
        .unchanged => claim.outer_transaction_sha256 == null and
            claim.completion_sha256 == null and
            (claim.record_sha256 == null or claim.marker_sha256 != null),
        .changed => claim.outer_transaction_sha256 != null or
            (claim.marker_sha256 != null and
                claim.record_sha256 != null) or
            (claim.marker_sha256 == null and
                claim.record_sha256 == null and
                claim.completion_sha256 != null),
    };
}

pub const DeferredAcknowledgmentState = enum {
    bound,
    released,
    abandoned,
    pending,
    acknowledged,
    pre_mutation_reconciliation_claim,
};

pub const PreMutationReconciliationClaimBinding = struct {
    outer_attempt_id: [32]u8,
    outer_generation: u64,
    outer_state_sha256: [32]u8,
    profile_sha256: [32]u8,
    profile_reference_sha256: [32]u8,
    exact_lock_sha256: [32]u8,
    semantic_request_sha256: [32]u8,
};

/// Root-local ownership binding and non-reclaimable hand-off for an exact
/// outer orchestrator attempt.
pub const DeferredAcknowledgment = struct {
    document_version: u32 = deferred_ack_schema_version,
    state: DeferredAcknowledgmentState = .bound,
    attempt_id: [32]u8,
    completion_sha256: ?[32]u8 = null,
    provenance_sha256: ?[32]u8 = null,
    pre_mutation_claim: ?PreMutationReconciliationClaimBinding = null,
    acknowledgment_id: [32]u8,
    recovery_review_claim_sha256: ?[32]u8 = null,
    recovery_review_binding_sha256: ?[32]u8 = null,
    digest_sha256: [32]u8 = @splat(0),

    pub fn canonicalJson(
        self: DeferredAcknowledgment,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        if (!validDeferredAcknowledgment(self))
            return error.InvalidDocument;
        if (!std.mem.eql(
            u8,
            &self.digest_sha256,
            &deferredAcknowledgmentDigest(self),
        )) return error.DigestMismatch;
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeDeferredAcknowledgment(self, &output.writer);
        const bytes = try output.toOwnedSlice();
        if (bytes.len > maximum_document_bytes) {
            allocator.free(bytes);
            return error.DocumentTooLarge;
        }
        return bytes;
    }
};

pub const OwnershipCleanupPoint = enum {
    before_terminal_publish,
    after_terminal_publish,
    before_record_clear,
    after_record_clear,
    before_binding_clear,
    after_binding_clear,
};

pub const OwnershipCleanupObserver = struct {
    context: *anyopaque,
    hitFn: *const fn (*anyopaque, OwnershipCleanupPoint) anyerror!void,

    pub fn hit(
        self: OwnershipCleanupObserver,
        point: OwnershipCleanupPoint,
    ) !void {
        return self.hitFn(self.context, point);
    }
};

pub const OwnershipCleanup = struct {
    attempt_id: [32]u8,
    acknowledgment_id: [32]u8,
    terminal_state: DeferredAcknowledgmentState,
    expected_marker_sha256: ?[32]u8 = null,
    observer: ?OwnershipCleanupObserver = null,
};

pub fn createDeferredAcknowledgment(
    input: DeferredAcknowledgment,
) !DeferredAcknowledgment {
    var result = input;
    if (result.state == .pre_mutation_reconciliation_claim or
        result.recovery_review_claim_sha256 != null or
        result.recovery_review_binding_sha256 != null)
        result.document_version = deferred_ack_v2_schema_version;
    result.digest_sha256 = deferredAcknowledgmentDigest(result);
    result.recovery_review_binding_sha256 =
        recoveryReviewBindingDigest(result);
    if (!validDeferredAcknowledgment(result))
        return error.InvalidDocument;
    return result;
}

fn validDeferredAcknowledgment(marker: DeferredAcknowledgment) bool {
    switch (marker.document_version) {
        deferred_ack_schema_version => {
            if (marker.recovery_review_claim_sha256 != null or
                marker.recovery_review_binding_sha256 != null)
                return false;
        },
        deferred_ack_v2_schema_version => {
            if ((marker.recovery_review_claim_sha256 == null) !=
                (marker.recovery_review_binding_sha256 == null))
                return false;
            if (marker.recovery_review_binding_sha256) |binding|
                if (!std.mem.eql(
                    u8,
                    &binding,
                    &(recoveryReviewBindingDigest(marker) orelse return false),
                )) return false;
        },
        else => return false,
    }
    return switch (marker.state) {
        .bound,
        .released,
        .abandoned,
        => marker.completion_sha256 == null and
            marker.provenance_sha256 == null and
            marker.pre_mutation_claim == null,
        .pre_mutation_reconciliation_claim => marker.completion_sha256 == null and
            marker.provenance_sha256 == null and
            marker.pre_mutation_claim != null and
            std.mem.eql(
                u8,
                &marker.attempt_id,
                &preMutationReconciliationClaimId(
                    marker.pre_mutation_claim.?,
                ),
            ) and
            std.mem.eql(
                u8,
                &marker.acknowledgment_id,
                &marker.pre_mutation_claim.?.outer_attempt_id,
            ),
        .pending, .acknowledged => marker.completion_sha256 != null and
            marker.provenance_sha256 != null and
            marker.pre_mutation_claim == null,
    };
}

pub fn preMutationReconciliationClaimId(
    binding: PreMutationReconciliationClaimBinding,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-root-pre-mutation-reconciliation-claim-v1\x00");
    hash.update(&binding.outer_attempt_id);
    var generation: [8]u8 = undefined;
    std.mem.writeInt(u64, &generation, binding.outer_generation, .little);
    hash.update(&generation);
    hash.update(&binding.outer_state_sha256);
    hash.update(&binding.profile_sha256);
    hash.update(&binding.profile_reference_sha256);
    hash.update(&binding.exact_lock_sha256);
    hash.update(&binding.semantic_request_sha256);
    return hash.finalResult();
}

pub fn matchesPreMutationReconciliationClaim(
    marker: DeferredAcknowledgment,
    binding: PreMutationReconciliationClaimBinding,
) bool {
    return marker.state == .pre_mutation_reconciliation_claim and
        marker.pre_mutation_claim != null and
        preMutationClaimBindingEqual(marker.pre_mutation_claim.?, binding) and
        std.mem.eql(
            u8,
            &marker.acknowledgment_id,
            &binding.outer_attempt_id,
        ) and
        std.mem.eql(
            u8,
            &marker.attempt_id,
            &preMutationReconciliationClaimId(binding),
        );
}

pub const DeferredRecordCompatibility = enum {
    incompatible,
    pre_mutation_reconciliation_claim,
    bound_pre_mutation,
    bound_ambiguous,
    bound_mutating,
    bound_completed_pending,
    bound_completed_success,
    bound_completed_abandoned,
    released_without_record,
    abandoned_without_record,
    released_completed,
    abandoned_pre_mutation,
    pending_prepublication,
    pending_published,
    acknowledged_published,
};

pub fn deferredRecordCompatibility(
    record: ?Record,
    marker: DeferredAcknowledgment,
    allow_pending_provenance: bool,
) DeferredRecordCompatibility {
    if (!validDeferredAcknowledgment(marker)) return .incompatible;
    if (marker.state == .pre_mutation_reconciliation_claim)
        return if (record == null)
            .pre_mutation_reconciliation_claim
        else
            .incompatible;
    const value = record orelse return switch (marker.state) {
        .released => .released_without_record,
        .abandoned => .abandoned_without_record,
        else => .incompatible,
    };
    if (!std.mem.eql(u8, &value.attempt_id, &marker.attempt_id))
        return .incompatible;
    return switch (marker.state) {
        .bound => if (value.state == .completed)
            if (!value.mutation_started and
                value.outcome == .abandoned_before_mutation and
                value.provenance == .not_required and
                value.provenance_sha256 == null)
                .bound_completed_abandoned
            else if (value.mutation_started and
                (value.outcome == .succeeded or value.outcome == .recovered) and
                value.provenance == .published and
                value.provenance_sha256 != null)
                .bound_completed_success
            else if (value.mutation_started and
                (value.outcome == .succeeded or
                    value.outcome == .recovered or
                    value.outcome == .failed_after_mutation) and
                value.provenance == .pending and
                value.provenance_sha256 == null)
                .bound_completed_pending
            else
                .incompatible
        else if (value.state == .mutation_pending)
            .bound_ambiguous
        else if (value.mutation_started)
            .bound_mutating
        else if (value.state.provenPreMutation())
            .bound_pre_mutation
        else
            .incompatible,
        .released => if (value.state == .completed and
            value.mutation_started and
            (value.outcome == .succeeded or value.outcome == .recovered) and
            value.provenance == .published and
            value.provenance_sha256 != null)
            .released_completed
        else
            .incompatible,
        .abandoned => if (value.state == .completed and
            !value.mutation_started and
            value.outcome == .abandoned_before_mutation and
            value.provenance == .not_required and
            value.provenance_sha256 == null)
            .abandoned_pre_mutation
        else
            .incompatible,
        .pending => switch (value.provenance) {
            .published => if (value.state == .completed and
                value.mutation_started and
                (value.outcome == .succeeded or value.outcome == .recovered) and
                value.provenance_sha256 != null and
                marker.provenance_sha256 != null and
                std.mem.eql(
                    u8,
                    &value.provenance_sha256.?,
                    &marker.provenance_sha256.?,
                ))
                .pending_published
            else
                .incompatible,
            .pending => if (allow_pending_provenance and
                value.state == .completed and
                value.mutation_started and
                (value.outcome == .succeeded or value.outcome == .recovered))
                .pending_prepublication
            else
                .incompatible,
            .not_required => .incompatible,
        },
        .acknowledged => if (value.state == .completed and
            value.mutation_started and
            (value.outcome == .succeeded or value.outcome == .recovered) and
            value.provenance == .published and
            value.provenance_sha256 != null and
            marker.provenance_sha256 != null and
            std.mem.eql(
                u8,
                &value.provenance_sha256.?,
                &marker.provenance_sha256.?,
            ))
            .acknowledged_published
        else
            .incompatible,
        .pre_mutation_reconciliation_claim => unreachable,
    };
}

fn preMutationClaimBindingEqual(
    left: PreMutationReconciliationClaimBinding,
    right: PreMutationReconciliationClaimBinding,
) bool {
    return left.outer_generation == right.outer_generation and
        std.mem.eql(u8, &left.outer_attempt_id, &right.outer_attempt_id) and
        std.mem.eql(
            u8,
            &left.outer_state_sha256,
            &right.outer_state_sha256,
        ) and
        std.mem.eql(u8, &left.profile_sha256, &right.profile_sha256) and
        std.mem.eql(
            u8,
            &left.profile_reference_sha256,
            &right.profile_reference_sha256,
        ) and
        std.mem.eql(
            u8,
            &left.exact_lock_sha256,
            &right.exact_lock_sha256,
        ) and
        std.mem.eql(
            u8,
            &left.semantic_request_sha256,
            &right.semantic_request_sha256,
        );
}

const WirePreMutationReconciliationClaim = struct {
    outer_attempt_id: []const u8,
    outer_generation: u64,
    outer_state_sha256: []const u8,
    profile_sha256: []const u8,
    profile_reference_sha256: []const u8,
    exact_lock_sha256: []const u8,
    semantic_request_sha256: []const u8,
};

const WireDeferredAcknowledgment = struct {
    schema: []const u8,
    version: u32,
    state: DeferredAcknowledgmentState,
    attempt_id: []const u8,
    completion_sha256: ?[]const u8,
    provenance_sha256: ?[]const u8,
    pre_mutation_claim: ?WirePreMutationReconciliationClaim = null,
    acknowledgment_id: []const u8,
    recovery_review_claim_sha256: ?[]const u8 = null,
    recovery_review_binding_sha256: ?[]const u8 = null,
    digest_sha256: []const u8,
};

const WireRecoveryReviewClaim = struct {
    schema: []const u8,
    version: u32,
    outer_attempt_id: []const u8,
    outer_generation: u64,
    outer_state_sha256: []const u8,
    profile_sha256: []const u8,
    profile_reference_sha256: []const u8,
    exact_lock_sha256: []const u8,
    semantic_request_sha256: []const u8,
    outer_transaction_sha256: ?[]const u8,
    mutation_status: RecoveryReviewMutationStatus,
    nonce: []const u8,
    marker_sha256: ?[]const u8,
    prior_marker: ?WireDeferredAcknowledgment = null,
    record_sha256: ?[]const u8,
    completion_sha256: ?[]const u8,
    digest_sha256: []const u8,
};

pub fn decodeDeferredAcknowledgment(
    allocator: std.mem.Allocator,
    source: []const u8,
) !DeferredAcknowledgment {
    if (source.len > maximum_document_bytes) return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(
        WireDeferredAcknowledgment,
        allocator,
        source,
        .{ .allocate = .alloc_always, .ignore_unknown_fields = false },
    ) catch return error.NonCanonicalDocument;
    defer parsed.deinit();
    const wire = parsed.value;
    const document_version: u32 =
        if (std.mem.eql(u8, wire.schema, deferred_ack_schema_id) and
        wire.version == deferred_ack_schema_version)
            deferred_ack_schema_version
        else if (std.mem.eql(u8, wire.schema, deferred_ack_v2_schema_id) and
        wire.version == deferred_ack_v2_schema_version)
            deferred_ack_v2_schema_version
        else
            return error.UnsupportedSchema;
    const decoded: DeferredAcknowledgment = .{
        .document_version = document_version,
        .state = wire.state,
        .attempt_id = try parseHex(32, wire.attempt_id),
        .completion_sha256 = try parseOptionalHex(wire.completion_sha256),
        .provenance_sha256 = try parseOptionalHex(wire.provenance_sha256),
        .pre_mutation_claim = if (wire.pre_mutation_claim) |claim| .{
            .outer_attempt_id = try parseHex(32, claim.outer_attempt_id),
            .outer_generation = claim.outer_generation,
            .outer_state_sha256 = try parseHex(32, claim.outer_state_sha256),
            .profile_sha256 = try parseHex(32, claim.profile_sha256),
            .profile_reference_sha256 = try parseHex(32, claim.profile_reference_sha256),
            .exact_lock_sha256 = try parseHex(32, claim.exact_lock_sha256),
            .semantic_request_sha256 = try parseHex(32, claim.semantic_request_sha256),
        } else null,
        .acknowledgment_id = try parseHex(32, wire.acknowledgment_id),
        .recovery_review_claim_sha256 = try parseOptionalHex(
            wire.recovery_review_claim_sha256,
        ),
        .recovery_review_binding_sha256 = try parseOptionalHex(
            wire.recovery_review_binding_sha256,
        ),
        .digest_sha256 = try parseHex(32, wire.digest_sha256),
    };
    if (!validDeferredAcknowledgment(decoded))
        return error.InvalidDocument;
    if (!std.mem.eql(
        u8,
        &decoded.digest_sha256,
        &deferredAcknowledgmentDigest(decoded),
    )) return error.DigestMismatch;
    const canonical = try decoded.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return decoded;
}

pub fn decodeRecoveryReviewClaim(
    allocator: std.mem.Allocator,
    source: []const u8,
) !RecoveryReviewClaim {
    if (source.len > maximum_document_bytes) return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(
        WireRecoveryReviewClaim,
        allocator,
        source,
        .{ .allocate = .alloc_always, .ignore_unknown_fields = false },
    ) catch return error.NonCanonicalDocument;
    defer parsed.deinit();
    const wire = parsed.value;
    if (!std.mem.eql(u8, wire.schema, recovery_review_schema_id) or
        wire.version != recovery_review_schema_version)
        return error.UnsupportedSchema;
    const decoded: RecoveryReviewClaim = .{
        .outer_attempt_id = try parseHex(32, wire.outer_attempt_id),
        .outer_generation = wire.outer_generation,
        .outer_state_sha256 = try parseHex(32, wire.outer_state_sha256),
        .profile_sha256 = try parseHex(32, wire.profile_sha256),
        .profile_reference_sha256 = try parseHex(
            32,
            wire.profile_reference_sha256,
        ),
        .exact_lock_sha256 = try parseHex(32, wire.exact_lock_sha256),
        .semantic_request_sha256 = try parseHex(
            32,
            wire.semantic_request_sha256,
        ),
        .outer_transaction_sha256 = try parseOptionalHex(
            wire.outer_transaction_sha256,
        ),
        .mutation_status = wire.mutation_status,
        .nonce = try parseHex(32, wire.nonce),
        .marker_sha256 = try parseOptionalHex(wire.marker_sha256),
        .prior_marker = if (wire.prior_marker) |marker| .{
            .document_version = if (std.mem.eql(
                u8,
                marker.schema,
                deferred_ack_schema_id,
            ) and marker.version == deferred_ack_schema_version)
                deferred_ack_schema_version
            else if (std.mem.eql(
                u8,
                marker.schema,
                deferred_ack_v2_schema_id,
            ) and marker.version == deferred_ack_v2_schema_version)
                deferred_ack_v2_schema_version
            else
                return error.UnsupportedSchema,
            .state = marker.state,
            .attempt_id = try parseHex(32, marker.attempt_id),
            .completion_sha256 = try parseOptionalHex(
                marker.completion_sha256,
            ),
            .provenance_sha256 = try parseOptionalHex(
                marker.provenance_sha256,
            ),
            .pre_mutation_claim = if (marker.pre_mutation_claim) |claim| .{
                .outer_attempt_id = try parseHex(32, claim.outer_attempt_id),
                .outer_generation = claim.outer_generation,
                .outer_state_sha256 = try parseHex(
                    32,
                    claim.outer_state_sha256,
                ),
                .profile_sha256 = try parseHex(32, claim.profile_sha256),
                .profile_reference_sha256 = try parseHex(
                    32,
                    claim.profile_reference_sha256,
                ),
                .exact_lock_sha256 = try parseHex(
                    32,
                    claim.exact_lock_sha256,
                ),
                .semantic_request_sha256 = try parseHex(
                    32,
                    claim.semantic_request_sha256,
                ),
            } else null,
            .acknowledgment_id = try parseHex(32, marker.acknowledgment_id),
            .recovery_review_claim_sha256 = try parseOptionalHex(
                marker.recovery_review_claim_sha256,
            ),
            .recovery_review_binding_sha256 = try parseOptionalHex(
                marker.recovery_review_binding_sha256,
            ),
            .digest_sha256 = try parseHex(32, marker.digest_sha256),
        } else null,
        .record_sha256 = try parseOptionalHex(wire.record_sha256),
        .completion_sha256 = try parseOptionalHex(wire.completion_sha256),
        .digest_sha256 = try parseHex(32, wire.digest_sha256),
    };
    if (!validRecoveryReviewClaim(decoded)) return error.InvalidDocument;
    if (!std.mem.eql(
        u8,
        &decoded.digest_sha256,
        &recoveryReviewClaimDigest(decoded),
    )) return error.DigestMismatch;
    const canonical = try decoded.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return decoded;
}

pub const Input = struct {
    attempt_id: [32]u8,
    generation: u64,
    install_root: []const u8,
    backend: Backend,
    operation: Operation,
    state: State,
    phase: Phase,
    step: u64,
    mutation_started: bool,
    outcome: Outcome,
    provenance: ProvenanceState,
    provenance_sha256: ?[32]u8 = null,
    evidence: Evidence = .{},
    request_sha256: [32]u8,
    policy_sha256: [32]u8,
    target_architecture: []const u8,
    foreign_architectures: []const []const u8 = &.{},
    reserved_unix: i64,
    updated_unix: i64,
};

pub const ValidationError = error{
    InvalidRoot,
    RootTooLong,
    InvalidArchitecture,
    DuplicateArchitecture,
    TooManyArchitectures,
    InvalidGeneration,
    InvalidState,
    InvalidPhase,
    InvalidOutcome,
    InvalidProvenance,
    InvalidMutationEvidence,
    InvalidLockBinding,
    InvalidDigest,
    UnsupportedSchema,
    NonCanonicalDocument,
    DigestMismatch,
    DocumentTooLarge,
};

/// Builds a validated record. Every combination of state, phase, outcome,
/// provenance, and mutation evidence is checked here, so no caller can publish
/// an internally contradictory record.
pub fn create(allocator: std.mem.Allocator, input: Input) (ValidationError || error{OutOfMemory})!OwnedRecord {
    if (!absolute_path.root(input.install_root)) return error.InvalidRoot;
    if (input.install_root.len > maximum_root_bytes) return error.RootTooLong;
    if (input.generation == 0) return error.InvalidGeneration;
    if (!validArchitecture(input.target_architecture)) return error.InvalidArchitecture;
    if (input.foreign_architectures.len > maximum_architectures) return error.TooManyArchitectures;
    try validateConsistency(
        input.state,
        input.phase,
        input.outcome,
        input.provenance,
        input.mutation_started,
        input.provenance_sha256,
    );
    if (input.evidence.exact_lock) |binding| {
        // The schema identifier is the one record string a caller supplies
        // verbatim, and the record is a canonical JSON document, so text the
        // encoder would write but the decoder could not read back is refused
        // before the record exists rather than after it is durable.
        if (binding.schema.len == 0 or binding.schema.len > maximum_schema_bytes or
            !std.unicode.utf8ValidateSlice(binding.schema) or
            binding.version == 0) return error.InvalidLockBinding;
    }

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const foreign = try owned.alloc([]const u8, input.foreign_architectures.len);
    for (input.foreign_architectures, 0..) |architecture, index| {
        if (!validArchitecture(architecture)) return error.InvalidArchitecture;
        foreign[index] = try owned.dupe(u8, architecture);
    }
    std.mem.sort([]const u8, foreign, {}, lessText);
    for (foreign, 0..) |architecture, index| {
        if (index != 0 and std.mem.eql(u8, architecture, foreign[index - 1]))
            return error.DuplicateArchitecture;
        if (std.mem.eql(u8, architecture, input.target_architecture))
            return error.DuplicateArchitecture;
    }

    var record: Record = .{
        .attempt_id = input.attempt_id,
        .generation = input.generation,
        .install_root = try owned.dupe(u8, input.install_root),
        .root_identity_sha256 = transaction_recovery.rootIdentity(input.install_root),
        .backend = input.backend,
        .operation = input.operation,
        .state = input.state,
        .phase = input.phase,
        .step = input.step,
        .mutation_started = input.mutation_started,
        .outcome = input.outcome,
        .provenance = input.provenance,
        .provenance_sha256 = input.provenance_sha256,
        .authorization_sha256 = input.evidence.authorization_sha256,
        .program_sha256 = input.evidence.program_sha256,
        .plan_sha256 = input.evidence.plan_sha256,
        .exact_lock = null,
        .database_generation_sha256 = input.evidence.database_generation_sha256,
        .artifact_evidence_sha256 = input.evidence.artifact_evidence_sha256,
        .request_sha256 = input.request_sha256,
        .policy_sha256 = input.policy_sha256,
        .target_architecture = try owned.dupe(u8, input.target_architecture),
        .foreign_architectures = foreign,
        .reserved_unix = input.reserved_unix,
        .updated_unix = input.updated_unix,
        .digest_sha256 = undefined,
    };
    if (input.evidence.exact_lock) |binding| record.exact_lock = .{
        .schema = try owned.dupe(u8, binding.schema),
        .version = binding.version,
        .digest_sha256 = binding.digest_sha256,
    };
    record.digest_sha256 = digestPayload(record);
    return .{ .record = record, .arena = arena, .backing_allocator = allocator };
}

/// The complete state/phase/outcome/provenance table. It is a table rather
/// than a set of scattered assertions so every rejected combination has one
/// place to read.
fn validateConsistency(
    state: State,
    phase: Phase,
    outcome: Outcome,
    provenance: ProvenanceState,
    mutation_started: bool,
    provenance_sha256: ?[32]u8,
) ValidationError!void {
    if (!allowedPhase(state, phase)) return error.InvalidPhase;
    if (state.blocksMutation() and state != .mutation_pending and !mutation_started)
        return error.InvalidMutationEvidence;
    if (state.provenPreMutation() and mutation_started) return error.InvalidMutationEvidence;
    if (state == .mutation_pending and mutation_started) return error.InvalidMutationEvidence;
    switch (outcome) {
        .pending => if (state == .completed) return error.InvalidOutcome,
        .succeeded, .failed_after_mutation, .recovered, .abandoned_before_mutation => {
            if (state != .completed) return error.InvalidOutcome;
        },
    }
    switch (outcome) {
        .abandoned_before_mutation => if (mutation_started) return error.InvalidOutcome,
        .failed_after_mutation, .recovered => if (!mutation_started) return error.InvalidOutcome,
        .pending, .succeeded => {},
    }
    switch (provenance) {
        .pending => if (provenance_sha256 != null) return error.InvalidProvenance,
        .not_required => {
            if (mutation_started) return error.InvalidProvenance;
            if (provenance_sha256 != null) return error.InvalidProvenance;
        },
        .published => {
            if (state != .completed) return error.InvalidProvenance;
            if (provenance_sha256 == null) return error.InvalidProvenance;
        },
    }
}

fn allowedPhase(state: State, phase: Phase) bool {
    return switch (state) {
        .reserved => phase == .reserved,
        .preflight => phase == .authorization or phase == .preflight,
        .mutation_pending => phase == .preflight or phase == .mutation,
        .mutating => switch (phase) {
            .mutation, .script, .trigger, .database => true,
            else => false,
        },
        .verifying => phase == .verification,
        .recovery_required, .recovering => switch (phase) {
            .mutation, .script, .trigger, .database, .verification => true,
            else => false,
        },
        .completed => phase == .provenance,
    };
}

/// Allowed lifecycle edges. Nothing ever moves back to a pre-mutation state
/// once mutation evidence exists, and `completed` is terminal.
pub fn canTransition(from: State, to: State) bool {
    return switch (from) {
        .reserved => switch (to) {
            .reserved, .preflight, .mutation_pending, .completed => true,
            else => false,
        },
        .preflight => switch (to) {
            .preflight, .mutation_pending, .mutating, .completed => true,
            else => false,
        },
        .mutation_pending => switch (to) {
            .mutation_pending, .mutating, .recovery_required, .completed => true,
            else => false,
        },
        .mutating => switch (to) {
            .mutating, .verifying, .recovery_required => true,
            else => false,
        },
        .verifying => switch (to) {
            .verifying, .recovery_required, .completed => true,
            else => false,
        },
        .recovery_required => switch (to) {
            .recovery_required, .recovering => true,
            else => false,
        },
        .recovering => switch (to) {
            .recovering, .recovery_required, .completed => true,
            else => false,
        },
        .completed => to == .completed,
    };
}

fn lessText(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0 or value.len > maximum_architecture_bytes) return false;
    for (value) |byte| switch (byte) {
        'a'...'z', '0'...'9', '-' => {},
        else => return false,
    };
    return true;
}

fn digestPayload(record: Record) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writePayload(record, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn writeDocument(record: Record, writer: *std.Io.Writer) !void {
    try writePayload(record, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHexString(writer, &record.digest_sha256);
    try writer.writeByte('}');
}

fn deferredAcknowledgmentDigest(
    marker: DeferredAcknowledgment,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(deferred_ack_schema_id);
    hash.update("\x001");
    hash.update(@tagName(marker.state));
    hash.update("\x00");
    hash.update(&marker.attempt_id);
    if (marker.completion_sha256) |digest|
        hash.update(&digest)
    else
        hash.update("\x00");
    if (marker.provenance_sha256) |digest|
        hash.update(&digest)
    else
        hash.update("\x00");
    if (marker.pre_mutation_claim) |claim| {
        hash.update(&claim.outer_attempt_id);
        var generation: [8]u8 = undefined;
        std.mem.writeInt(u64, &generation, claim.outer_generation, .little);
        hash.update(&generation);
        hash.update(&claim.outer_state_sha256);
        hash.update(&claim.profile_sha256);
        hash.update(&claim.profile_reference_sha256);
        hash.update(&claim.exact_lock_sha256);
        hash.update(&claim.semantic_request_sha256);
    }
    hash.update(&marker.acknowledgment_id);
    return hash.finalResult();
}

fn recoveryReviewBindingDigest(
    marker: DeferredAcknowledgment,
) ?[32]u8 {
    const claim = marker.recovery_review_claim_sha256 orelse return null;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-root-operation-recovery-review-binding-v2\x00");
    hash.update(deferred_ack_v2_schema_id);
    hash.update("\x002");
    hash.update(&marker.digest_sha256);
    hash.update(&claim);
    return hash.finalResult();
}

fn recoveryReviewClaimDigest(claim: RecoveryReviewClaim) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(recovery_review_schema_id);
    hash.update("\x001");
    hash.update(&claim.outer_attempt_id);
    var generation: [8]u8 = undefined;
    std.mem.writeInt(u64, &generation, claim.outer_generation, .little);
    hash.update(&generation);
    hash.update(&claim.outer_state_sha256);
    hash.update(&claim.profile_sha256);
    hash.update(&claim.profile_reference_sha256);
    hash.update(&claim.exact_lock_sha256);
    hash.update(&claim.semantic_request_sha256);
    if (claim.outer_transaction_sha256) |digest| {
        hash.update("\x01");
        hash.update(&digest);
    } else hash.update("\x00");
    hash.update(@tagName(claim.mutation_status));
    hash.update("\x00");
    hash.update(&claim.nonce);
    if (claim.marker_sha256) |digest| {
        hash.update("\x01");
        hash.update(&digest);
    } else hash.update("\x00");
    if (claim.record_sha256) |digest| {
        hash.update("\x01");
        hash.update(&digest);
    } else hash.update("\x00");
    if (claim.completion_sha256) |digest| {
        hash.update("\x01");
        hash.update(&digest);
    } else hash.update("\x00");
    return hash.finalResult();
}

fn writeRecoveryReviewClaim(
    claim: RecoveryReviewClaim,
    writer: *std.Io.Writer,
) !void {
    try writer.writeAll("{\"schema\":");
    try writeJsonString(writer, recovery_review_schema_id);
    try writer.print(",\"version\":{},\"outer_attempt_id\":", .{
        recovery_review_schema_version,
    });
    try writeHexString(writer, &claim.outer_attempt_id);
    try writer.print(",\"outer_generation\":{}", .{claim.outer_generation});
    try writer.writeAll(",\"outer_state_sha256\":");
    try writeHexString(writer, &claim.outer_state_sha256);
    try writer.writeAll(",\"profile_sha256\":");
    try writeHexString(writer, &claim.profile_sha256);
    try writer.writeAll(",\"profile_reference_sha256\":");
    try writeHexString(writer, &claim.profile_reference_sha256);
    try writer.writeAll(",\"exact_lock_sha256\":");
    try writeHexString(writer, &claim.exact_lock_sha256);
    try writer.writeAll(",\"semantic_request_sha256\":");
    try writeHexString(writer, &claim.semantic_request_sha256);
    try writer.writeAll(",\"outer_transaction_sha256\":");
    try writeOptionalHex(writer, claim.outer_transaction_sha256);
    try writer.writeAll(",\"mutation_status\":");
    try writeJsonString(writer, @tagName(claim.mutation_status));
    try writer.writeAll(",\"nonce\":");
    try writeHexString(writer, &claim.nonce);
    try writer.writeAll(",\"marker_sha256\":");
    try writeOptionalHex(writer, claim.marker_sha256);
    try writer.writeAll(",\"prior_marker\":");
    if (claim.prior_marker) |marker|
        try writeDeferredAcknowledgment(marker, writer)
    else
        try writer.writeAll("null");
    try writer.writeAll(",\"record_sha256\":");
    try writeOptionalHex(writer, claim.record_sha256);
    try writer.writeAll(",\"completion_sha256\":");
    try writeOptionalHex(writer, claim.completion_sha256);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHexString(writer, &claim.digest_sha256);
    try writer.writeByte('}');
}

fn writeDeferredAcknowledgment(
    marker: DeferredAcknowledgment,
    writer: *std.Io.Writer,
) !void {
    try writer.writeAll("{\"schema\":");
    try writeJsonString(
        writer,
        if (marker.document_version == deferred_ack_schema_version)
            deferred_ack_schema_id
        else
            deferred_ack_v2_schema_id,
    );
    try writer.print(",\"version\":{},\"state\":", .{
        marker.document_version,
    });
    try writeJsonString(writer, @tagName(marker.state));
    try writer.writeAll(",\"attempt_id\":");
    try writeHexString(writer, &marker.attempt_id);
    try writer.writeAll(",\"completion_sha256\":");
    try writeOptionalHex(writer, marker.completion_sha256);
    try writer.writeAll(",\"provenance_sha256\":");
    try writeOptionalHex(writer, marker.provenance_sha256);
    if (marker.pre_mutation_claim) |claim| {
        try writer.writeAll(",\"pre_mutation_claim\":{\"outer_attempt_id\":");
        try writeHexString(writer, &claim.outer_attempt_id);
        try writer.print(",\"outer_generation\":{}", .{
            claim.outer_generation,
        });
        try writer.writeAll(",\"outer_state_sha256\":");
        try writeHexString(writer, &claim.outer_state_sha256);
        try writer.writeAll(",\"profile_sha256\":");
        try writeHexString(writer, &claim.profile_sha256);
        try writer.writeAll(",\"profile_reference_sha256\":");
        try writeHexString(writer, &claim.profile_reference_sha256);
        try writer.writeAll(",\"exact_lock_sha256\":");
        try writeHexString(writer, &claim.exact_lock_sha256);
        try writer.writeAll(",\"semantic_request_sha256\":");
        try writeHexString(writer, &claim.semantic_request_sha256);
        try writer.writeByte('}');
    }
    try writer.writeAll(",\"acknowledgment_id\":");
    try writeHexString(writer, &marker.acknowledgment_id);
    if (marker.document_version == deferred_ack_v2_schema_version) {
        try writer.writeAll(",\"recovery_review_claim_sha256\":");
        try writeOptionalHex(writer, marker.recovery_review_claim_sha256);
        try writer.writeAll(",\"recovery_review_binding_sha256\":");
        try writeOptionalHex(writer, marker.recovery_review_binding_sha256);
    }
    try writer.writeAll(",\"digest_sha256\":");
    try writeHexString(writer, &marker.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(record: Record, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeJsonString(writer, schema_id);
    try writer.print(",\"version\":{},\"attempt_id\":", .{schema_version});
    try writeHexString(writer, &record.attempt_id);
    try writer.print(",\"generation\":{},\"install_root\":", .{record.generation});
    try writeJsonString(writer, record.install_root);
    try writer.writeAll(",\"root_identity_sha256\":");
    try writeHexString(writer, &record.root_identity_sha256);
    try writer.writeAll(",\"backend\":");
    try writeJsonString(writer, @tagName(record.backend));
    try writer.writeAll(",\"surface\":");
    try writeJsonString(writer, @tagName(std.meta.activeTag(record.operation)));
    try writer.writeAll(",\"operation\":");
    try writeJsonString(writer, record.operation.spelling());
    try writer.writeAll(",\"state\":");
    try writeJsonString(writer, @tagName(record.state));
    try writer.writeAll(",\"phase\":");
    try writeJsonString(writer, @tagName(record.phase));
    try writer.print(",\"step\":{},\"mutation_started\":{}", .{ record.step, record.mutation_started });
    try writer.writeAll(",\"outcome\":");
    try writeJsonString(writer, @tagName(record.outcome));
    try writer.writeAll(",\"provenance\":");
    try writeJsonString(writer, @tagName(record.provenance));
    try writer.writeAll(",\"provenance_sha256\":");
    try writeOptionalHex(writer, record.provenance_sha256);
    try writer.writeAll(",\"authorization_sha256\":");
    try writeOptionalHex(writer, record.authorization_sha256);
    try writer.writeAll(",\"program_sha256\":");
    try writeOptionalHex(writer, record.program_sha256);
    try writer.writeAll(",\"plan_sha256\":");
    try writeOptionalHex(writer, record.plan_sha256);
    try writer.writeAll(",\"exact_lock\":");
    if (record.exact_lock) |binding| {
        try writer.writeAll("{\"schema\":");
        try writeJsonString(writer, binding.schema);
        try writer.print(",\"version\":{},\"digest_sha256\":", .{binding.version});
        try writeHexString(writer, &binding.digest_sha256);
        try writer.writeByte('}');
    } else try writer.writeAll("null");
    try writer.writeAll(",\"database_generation_sha256\":");
    try writeOptionalHex(writer, record.database_generation_sha256);
    try writer.writeAll(",\"artifact_evidence_sha256\":");
    try writeOptionalHex(writer, record.artifact_evidence_sha256);
    try writer.writeAll(",\"request_sha256\":");
    try writeHexString(writer, &record.request_sha256);
    try writer.writeAll(",\"policy_sha256\":");
    try writeHexString(writer, &record.policy_sha256);
    try writer.writeAll(",\"target_architecture\":");
    try writeJsonString(writer, record.target_architecture);
    try writer.writeAll(",\"foreign_architectures\":[");
    for (record.foreign_architectures, 0..) |architecture, index| {
        if (index != 0) try writer.writeByte(',');
        try writeJsonString(writer, architecture);
    }
    try writer.print("],\"reserved_unix\":{},\"updated_unix\":{}}}", .{
        record.reserved_unix,
        record.updated_unix,
    });
}

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        0x00...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
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

fn writeOptionalHex(writer: *std.Io.Writer, value: ?[32]u8) !void {
    if (value) |bytes| try writeHexString(writer, &bytes) else try writer.writeAll("null");
}

fn parseHex(comptime size: usize, value: []const u8) ValidationError![size]u8 {
    if (value.len != size * 2) return error.InvalidDigest;
    var result: [size]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidDigest;
    return result;
}

fn parseOptionalHex(value: ?[]const u8) ValidationError!?[32]u8 {
    const text = value orelse return null;
    return try parseHex(32, text);
}

const WireLockBinding = struct {
    schema: []const u8,
    version: u32,
    digest_sha256: []const u8,
};

const WireRecord = struct {
    schema: []const u8,
    version: u32,
    attempt_id: []const u8,
    generation: u64,
    install_root: []const u8,
    root_identity_sha256: []const u8,
    backend: Backend,
    surface: Surface,
    operation: []const u8,
    state: State,
    phase: Phase,
    step: u64,
    mutation_started: bool,
    outcome: Outcome,
    provenance: ProvenanceState,
    provenance_sha256: ?[]const u8,
    authorization_sha256: ?[]const u8,
    program_sha256: ?[]const u8,
    plan_sha256: ?[]const u8,
    exact_lock: ?WireLockBinding,
    database_generation_sha256: ?[]const u8,
    artifact_evidence_sha256: ?[]const u8,
    request_sha256: []const u8,
    policy_sha256: []const u8,
    target_architecture: []const u8,
    foreign_architectures: []const []const u8,
    reserved_unix: i64,
    updated_unix: i64,
    digest_sha256: []const u8,
};

/// Strict bounded decode. Unknown fields, missing fields, an unsupported
/// schema, a mismatched digest, and any byte sequence that is not the exact
/// canonical encoding are all rejected.
pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !OwnedRecord {
    if (source.len > maximum_bytes or source.len > maximum_document_bytes)
        return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(WireRecord, allocator, source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.NonCanonicalDocument,
    };
    defer parsed.deinit();
    const wire = parsed.value;
    if (!std.mem.eql(u8, wire.schema, schema_id) or wire.version != schema_version)
        return error.UnsupportedSchema;
    const operation = try parseOperation(wire.surface, wire.operation);
    var result = try create(allocator, .{
        .attempt_id = try parseHex(32, wire.attempt_id),
        .generation = wire.generation,
        .install_root = wire.install_root,
        .backend = wire.backend,
        .operation = operation,
        .state = wire.state,
        .phase = wire.phase,
        .step = wire.step,
        .mutation_started = wire.mutation_started,
        .outcome = wire.outcome,
        .provenance = wire.provenance,
        .provenance_sha256 = try parseOptionalHex(wire.provenance_sha256),
        .evidence = .{
            .authorization_sha256 = try parseOptionalHex(wire.authorization_sha256),
            .program_sha256 = try parseOptionalHex(wire.program_sha256),
            .plan_sha256 = try parseOptionalHex(wire.plan_sha256),
            .exact_lock = if (wire.exact_lock) |binding| .{
                .schema = binding.schema,
                .version = binding.version,
                .digest_sha256 = try parseHex(32, binding.digest_sha256),
            } else null,
            .database_generation_sha256 = try parseOptionalHex(wire.database_generation_sha256),
            .artifact_evidence_sha256 = try parseOptionalHex(wire.artifact_evidence_sha256),
        },
        .request_sha256 = try parseHex(32, wire.request_sha256),
        .policy_sha256 = try parseHex(32, wire.policy_sha256),
        .target_architecture = wire.target_architecture,
        .foreign_architectures = wire.foreign_architectures,
        .reserved_unix = wire.reserved_unix,
        .updated_unix = wire.updated_unix,
    });
    errdefer result.deinit();
    const identity = try parseHex(32, wire.root_identity_sha256);
    if (!std.mem.eql(u8, &identity, &result.record.root_identity_sha256))
        return error.DigestMismatch;
    const expected = try parseHex(32, wire.digest_sha256);
    if (!std.mem.eql(u8, &expected, &result.record.digest_sha256))
        return error.DigestMismatch;
    const canonical = try result.record.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return result;
}

fn parseOperation(surface: Surface, spelling: []const u8) ValidationError!Operation {
    return switch (surface) {
        .package_transaction => .{
            .package_transaction = std.meta.stringToEnum(product_api.Operation, spelling) orelse
                return error.NonCanonicalDocument,
        },
        .repository_bootstrap => .{
            .repository_bootstrap = std.meta.stringToEnum(repository_api.Operation, spelling) orelse
                return error.NonCanonicalDocument,
        },
    };
}

fn documentHasSchema(source: []const u8, comptime schema: []const u8) bool {
    const prefix = "{\"schema\":\"" ++ schema ++ "\"";
    return std.mem.startsWith(u8, source, prefix);
}

/// Root-anchored durable store. Reads never follow a symbolic link and never
/// accept a directory or special file; writes publish atomically through a
/// private staging entry and fsync the destination directory.
pub const Store = struct {
    root: root_fs.Root,

    pub fn init(root: root_fs.Root) Store {
        return .{ .root = root };
    }

    /// Creates the shared namespace. Every existing component must already be
    /// a real directory; a symbolic link fails closed.
    pub fn ensureNamespace(self: Store) !void {
        try self.root.createDirectoryPath(
            try root_fs.Path.init(namespace_path),
            root_fs.default_directory_permissions,
        );
    }

    /// `null` only when no record exists. A record that cannot be decoded is
    /// an error, never an absent record.
    pub fn read(self: Store, allocator: std.mem.Allocator) !?OwnedRecord {
        const path = try root_fs.Path.init(record_path);
        const bytes = self.root.readFileAlloc(allocator, path, maximum_document_bytes) catch |err|
            switch (err) {
                error.FileNotFound => return null,
                else => return err,
            };
        defer allocator.free(bytes);
        return try decode(allocator, bytes, maximum_document_bytes);
    }

    pub fn writeAtomic(self: Store, allocator: std.mem.Allocator, record: Record) !void {
        const bytes = try record.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
        try self.root.publishFile(try root_fs.Path.init(record_path), bytes, .{
            .permissions = record_permissions,
            .overwrite = .replace,
            .durable = true,
        });
    }

    pub fn readDeferredAcknowledgment(
        self: Store,
        allocator: std.mem.Allocator,
    ) !?DeferredAcknowledgment {
        const path = try root_fs.Path.init(deferred_ack_path);
        const bytes = self.root.readFileAlloc(
            allocator,
            path,
            maximum_document_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer allocator.free(bytes);
        if (documentHasSchema(bytes, recovery_review_schema_id)) {
            const claim = try decodeRecoveryReviewClaim(allocator, bytes);
            return claim.prior_marker;
        }
        return try decodeDeferredAcknowledgment(allocator, bytes);
    }

    pub fn readRecoveryReviewClaim(
        self: Store,
        allocator: std.mem.Allocator,
    ) !?RecoveryReviewClaim {
        const path = try root_fs.Path.init(recovery_review_path);
        const bytes = self.root.readFileAlloc(
            allocator,
            path,
            maximum_document_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer allocator.free(bytes);
        if (documentHasSchema(bytes, deferred_ack_schema_id) or
            documentHasSchema(bytes, deferred_ack_v2_schema_id))
            return null;
        return try decodeRecoveryReviewClaim(allocator, bytes);
    }

    pub fn publishRecoveryReviewClaim(
        self: Store,
        allocator: std.mem.Allocator,
        claim: RecoveryReviewClaim,
    ) !void {
        if (try self.readRecoveryReviewClaim(allocator)) |existing| {
            if (std.mem.eql(
                u8,
                &existing.digest_sha256,
                &claim.digest_sha256,
            )) return;
            return error.RecoveryReviewClaimPresent;
        }
        const marker = try self.readDeferredAcknowledgment(allocator);
        if (!optionalDigestEqual(
            claim.marker_sha256,
            if (marker) |value| value.digest_sha256 else null,
        )) return error.DeferredAcknowledgmentMismatch;
        const bytes = try claim.canonicalJson(allocator);
        defer allocator.free(bytes);
        try self.root.publishFile(
            try root_fs.Path.init(recovery_review_path),
            bytes,
            .{
                .permissions = record_permissions,
                .overwrite = if (marker == null)
                    .fail_if_exists
                else
                    .replace,
                .durable = true,
            },
        );
    }

    pub fn clearRecoveryReviewClaim(
        self: Store,
        allocator: std.mem.Allocator,
        expected_digest: [32]u8,
    ) !void {
        const observed = try self.readRecoveryReviewClaim(allocator) orelse
            return;
        if (!std.mem.eql(
            u8,
            &observed.digest_sha256,
            &expected_digest,
        )) return error.RecoveryReviewClaimMismatch;
        if (observed.prior_marker) |marker| {
            const bytes = try marker.canonicalJson(allocator);
            defer allocator.free(bytes);
            try self.root.publishFile(
                try root_fs.Path.init(recovery_review_path),
                bytes,
                .{
                    .permissions = record_permissions,
                    .overwrite = .replace,
                    .durable = true,
                },
            );
        } else {
            self.root.removeFile(
                try root_fs.Path.init(recovery_review_path),
            ) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
            try self.root.syncDirectory(
                try root_fs.Path.init(namespace_path),
            );
        }
    }

    pub const RecoveryReviewExchangePoint = enum {
        before_owner_publish,
        after_owner_publish,
        before_claim_clear,
        after_claim_clear,
    };

    pub const RecoveryReviewExchangeObserver = struct {
        context: *anyopaque,
        hitFn: *const fn (
            *anyopaque,
            RecoveryReviewExchangePoint,
        ) anyerror!void,

        pub fn hit(
            self: RecoveryReviewExchangeObserver,
            point: RecoveryReviewExchangePoint,
        ) !void {
            try self.hitFn(self.context, point);
        }
    };

    pub const RecoveryReviewExchange = struct {
        claim_sha256: [32]u8,
        outer_attempt_id: [32]u8,
        expected_marker_sha256: ?[32]u8,
        expected_record_sha256: ?[32]u8,
        replacement_marker: ?DeferredAcknowledgment = null,
        owner_publish_observer: ?root_fs.PublishObserver = null,
        observer: ?RecoveryReviewExchangeObserver = null,
    };

    fn optionalDigestEqual(left: ?[32]u8, right: ?[32]u8) bool {
        if (left == null or right == null)
            return left == null and right == null;
        return std.mem.eql(u8, &left.?, &right.?);
    }

    /// Exchanges a reviewed capability for an already-verified lower owner,
    /// or durably publishes its replacement owner before removing the claim.
    /// The caller must hold the root-operation lock.
    pub fn exchangeRecoveryReviewClaimForOwnership(
        self: Store,
        allocator: std.mem.Allocator,
        exchange: RecoveryReviewExchange,
    ) !void {
        const claim = try self.readRecoveryReviewClaim(allocator) orelse {
            const transferred = try self.readDeferredAcknowledgment(
                allocator,
            ) orelse return error.RecoveryReviewClaimMissing;
            if (!std.mem.eql(
                u8,
                &transferred.acknowledgment_id,
                &exchange.outer_attempt_id,
            ) or transferred.recovery_review_claim_sha256 == null or
                !std.mem.eql(
                    u8,
                    &transferred.recovery_review_claim_sha256.?,
                    &exchange.claim_sha256,
                ))
                return error.RecoveryReviewClaimMissing;
            return;
        };
        if (!std.mem.eql(
            u8,
            &claim.digest_sha256,
            &exchange.claim_sha256,
        ) or !std.mem.eql(
            u8,
            &claim.outer_attempt_id,
            &exchange.outer_attempt_id,
        )) return error.RecoveryReviewClaimMismatch;

        const marker = claim.prior_marker;
        if (!optionalDigestEqual(
            exchange.expected_marker_sha256,
            if (marker) |value| value.digest_sha256 else null,
        )) return error.DeferredAcknowledgmentMismatch;
        var record = try self.read(allocator);
        defer if (record) |*owned| owned.deinit();
        if (!optionalDigestEqual(
            exchange.expected_record_sha256,
            if (record) |owned| owned.record.digest_sha256 else null,
        )) return error.RecordMismatch;

        var replacement = exchange.replacement_marker orelse
            marker orelse return error.NoDeferredAcknowledgment;
        if (!std.mem.eql(
            u8,
            &replacement.acknowledgment_id,
            &exchange.outer_attempt_id,
        )) return error.InvalidDocument;
        replacement.document_version = deferred_ack_v2_schema_version;
        replacement.recovery_review_claim_sha256 = claim.digest_sha256;
        replacement.digest_sha256 = deferredAcknowledgmentDigest(replacement);
        replacement.recovery_review_binding_sha256 =
            recoveryReviewBindingDigest(replacement);
        if (exchange.observer) |observer|
            try observer.hit(.before_owner_publish);
        const bytes = try replacement.canonicalJson(allocator);
        defer allocator.free(bytes);
        try self.root.publishFile(
            try root_fs.Path.init(recovery_review_path),
            bytes,
            .{
                .permissions = record_permissions,
                .overwrite = .replace,
                .durable = true,
                .observer = exchange.owner_publish_observer,
            },
        );
        if (exchange.observer) |observer|
            try observer.hit(.after_owner_publish);
        if (exchange.observer) |observer|
            try observer.hit(.before_claim_clear);
        if (exchange.observer) |observer|
            try observer.hit(.after_claim_clear);
    }

    pub fn publishDeferredAcknowledgment(
        self: Store,
        allocator: std.mem.Allocator,
        marker: DeferredAcknowledgment,
    ) !void {
        if (try self.readRecoveryReviewClaim(allocator) != null)
            return error.RecoveryReviewClaimPresent;
        if (try self.readDeferredAcknowledgment(allocator)) |existing| {
            if (std.mem.eql(
                u8,
                &existing.digest_sha256,
                &marker.digest_sha256,
            )) return;
            if (existing.state != .bound or marker.state != .pending or
                !std.mem.eql(
                    u8,
                    &existing.attempt_id,
                    &marker.attempt_id,
                ) or
                !std.mem.eql(
                    u8,
                    &existing.acknowledgment_id,
                    &marker.acknowledgment_id,
                ))
                return error.DeferredAcknowledgmentPresent;
            const bytes = try marker.canonicalJson(allocator);
            defer allocator.free(bytes);
            try self.root.publishFile(
                try root_fs.Path.init(deferred_ack_path),
                bytes,
                .{
                    .permissions = record_permissions,
                    .overwrite = .replace,
                    .durable = true,
                },
            );
            return;
        }
        const bytes = try marker.canonicalJson(allocator);
        defer allocator.free(bytes);
        try self.root.publishFile(
            try root_fs.Path.init(deferred_ack_path),
            bytes,
            .{
                .permissions = record_permissions,
                .overwrite = .fail_if_exists,
                .durable = true,
            },
        );
    }

    /// Atomically replaces an exact owner's retryable marker while no record
    /// exists. The old marker remains durable until the new bound attempt is
    /// published, so process death cannot create a markerless retry window.
    pub fn rotateDeferredAcknowledgment(
        self: Store,
        allocator: std.mem.Allocator,
        marker: DeferredAcknowledgment,
    ) !void {
        if (try self.readRecoveryReviewClaim(allocator) != null)
            return error.RecoveryReviewClaimPresent;
        if (marker.state != .bound) return error.InvalidDocument;
        const existing = try self.readDeferredAcknowledgment(allocator) orelse
            return error.NoDeferredAcknowledgment;
        if ((existing.state != .bound and existing.state != .abandoned) or
            !std.mem.eql(
                u8,
                &existing.acknowledgment_id,
                &marker.acknowledgment_id,
            ))
            return error.DeferredAcknowledgmentMismatch;
        var record = try self.read(allocator);
        defer if (record) |*owned| owned.deinit();
        if (record != null) return error.DeferredAcknowledgmentMismatch;
        const bytes = try marker.canonicalJson(allocator);
        defer allocator.free(bytes);
        try self.root.publishFile(
            try root_fs.Path.init(deferred_ack_path),
            bytes,
            .{
                .permissions = record_permissions,
                .overwrite = .replace,
                .durable = true,
            },
        );
    }

    pub fn acknowledgeDeferredAcknowledgment(
        self: Store,
        allocator: std.mem.Allocator,
        expected_digest: [32]u8,
    ) !DeferredAcknowledgment {
        if (try self.readRecoveryReviewClaim(allocator) != null)
            return error.RecoveryReviewClaimPresent;
        const observed = try self.readDeferredAcknowledgment(allocator) orelse
            return error.NoDeferredAcknowledgment;
        if (observed.state != .pending or !std.mem.eql(
            u8,
            &observed.digest_sha256,
            &expected_digest,
        )) return error.DeferredAcknowledgmentMismatch;
        var next = observed;
        next.state = .acknowledged;
        next.digest_sha256 = deferredAcknowledgmentDigest(next);
        next.recovery_review_binding_sha256 =
            recoveryReviewBindingDigest(next);
        const bytes = try next.canonicalJson(allocator);
        defer allocator.free(bytes);
        try self.root.publishFile(
            try root_fs.Path.init(deferred_ack_path),
            bytes,
            .{
                .permissions = record_permissions,
                .overwrite = .replace,
                .durable = true,
            },
        );
        return next;
    }

    pub fn terminalizeDeferredAcknowledgment(
        self: Store,
        allocator: std.mem.Allocator,
        expected_digest: [32]u8,
        terminal_state: DeferredAcknowledgmentState,
    ) !DeferredAcknowledgment {
        if (try self.readRecoveryReviewClaim(allocator) != null)
            return error.RecoveryReviewClaimPresent;
        if (terminal_state != .released and terminal_state != .abandoned)
            return error.InvalidDocument;
        const observed = try self.readDeferredAcknowledgment(allocator) orelse
            return error.NoDeferredAcknowledgment;
        if (observed.state != .bound or !std.mem.eql(
            u8,
            &observed.digest_sha256,
            &expected_digest,
        )) return error.DeferredAcknowledgmentMismatch;
        var next = observed;
        next.state = terminal_state;
        next.digest_sha256 = deferredAcknowledgmentDigest(next);
        next.recovery_review_binding_sha256 =
            recoveryReviewBindingDigest(next);
        const bytes = try next.canonicalJson(allocator);
        defer allocator.free(bytes);
        try self.root.publishFile(
            try root_fs.Path.init(deferred_ack_path),
            bytes,
            .{
                .permissions = record_permissions,
                .overwrite = .replace,
                .durable = true,
            },
        );
        return next;
    }

    pub fn cleanupOwned(
        self: Store,
        allocator: std.mem.Allocator,
        cleanup: OwnershipCleanup,
    ) !void {
        if (try self.readRecoveryReviewClaim(allocator) != null)
            return error.RecoveryReviewClaimPresent;
        if (try self.readDeferredAcknowledgment(allocator) == null) {
            var record = try self.read(allocator);
            defer if (record) |*owned| owned.deinit();
            if (record != null) return error.NoDeferredAcknowledgment;
            return;
        }
        const terminal = try self.retainOwnedTerminal(allocator, cleanup);
        var reopened = try self.read(allocator);
        defer if (reopened) |*owned| owned.deinit();
        if (reopened != null) return error.DeferredAcknowledgmentMismatch;
        if (cleanup.observer) |observer|
            try observer.hit(.before_binding_clear);
        try self.clearDeferredAcknowledgment(
            allocator,
            terminal.digest_sha256,
        );
        if (cleanup.observer) |observer|
            try observer.hit(.after_binding_clear);
    }

    /// Durably settles the exact owned record while retaining its terminal
    /// owner marker. This is the retry hand-off: a process may die after any
    /// write and the root still carries continuous exact-owner proof.
    pub fn retainOwnedTerminal(
        self: Store,
        allocator: std.mem.Allocator,
        cleanup: OwnershipCleanup,
    ) !DeferredAcknowledgment {
        if (try self.readRecoveryReviewClaim(allocator) != null)
            return error.RecoveryReviewClaimPresent;
        const marker = try self.readDeferredAcknowledgment(allocator);
        var record = try self.read(allocator);
        defer if (record) |*owned| owned.deinit();
        if (marker == null) return error.NoDeferredAcknowledgment;
        const observed = marker.?;
        if (cleanup.expected_marker_sha256) |expected|
            if (!std.mem.eql(
                u8,
                &observed.digest_sha256,
                &expected,
            )) return error.DeferredAcknowledgmentMismatch;
        if (!std.mem.eql(
            u8,
            &observed.attempt_id,
            &cleanup.attempt_id,
        ) or !std.mem.eql(
            u8,
            &observed.acknowledgment_id,
            &cleanup.acknowledgment_id,
        )) return error.DeferredAcknowledgmentMismatch;
        if (record) |owned| {
            var expected_terminal = observed;
            expected_terminal.state = cleanup.terminal_state;
            if (!owned.record.clearable() or
                !recordMatchesDeferredAcknowledgment(
                    owned.record,
                    expected_terminal,
                    false,
                ))
                return error.DeferredAcknowledgmentMismatch;
        }
        var terminal = observed;
        if (observed.state == .bound) {
            if (cleanup.observer) |observer|
                try observer.hit(.before_terminal_publish);
            terminal = try self.terminalizeDeferredAcknowledgment(
                allocator,
                observed.digest_sha256,
                cleanup.terminal_state,
            );
            if (cleanup.observer) |observer|
                try observer.hit(.after_terminal_publish);
        } else if (observed.state != cleanup.terminal_state) {
            return error.DeferredAcknowledgmentMismatch;
        }
        if (record) |*owned| {
            if (cleanup.observer) |observer|
                try observer.hit(.before_record_clear);
            try self.clear();
            if (cleanup.observer) |observer|
                try observer.hit(.after_record_clear);
            owned.deinit();
            record = null;
        }
        var reopened = try self.read(allocator);
        defer if (reopened) |*owned| owned.deinit();
        if (reopened != null) return error.DeferredAcknowledgmentMismatch;
        return terminal;
    }

    pub fn clearDeferredAcknowledgment(
        self: Store,
        allocator: std.mem.Allocator,
        expected_digest: [32]u8,
    ) !void {
        if (try self.readRecoveryReviewClaim(allocator) != null)
            return error.RecoveryReviewClaimPresent;
        const observed = try self.readDeferredAcknowledgment(allocator) orelse
            return;
        if (!std.mem.eql(
            u8,
            &observed.digest_sha256,
            &expected_digest,
        )) return error.DeferredAcknowledgmentMismatch;
        self.root.removeFile(
            try root_fs.Path.init(deferred_ack_path),
        ) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try self.root.syncDirectory(try root_fs.Path.init(namespace_path));
    }

    /// Removes the active record and fsyncs the namespace so the removal
    /// survives power loss.
    pub fn clear(self: Store) !void {
        const path = try root_fs.Path.init(record_path);
        self.root.removeFile(path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try self.root.syncDirectory(try root_fs.Path.init(namespace_path));
    }
};

const record_permissions: std.Io.File.Permissions =
    if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);

/// Total lock order for every debz mutation of a selected root. Locks are
/// always taken in increasing rank and released in decreasing rank, so no two
/// call paths can deadlock against each other.
pub const Rank = enum(u8) {
    /// `<root>/var/lib/debz/root-operation.lock`. Always first.
    root_operation = 0,
    /// The repository backend's `repo-add.lock` in the state tree.
    repository_operation = 1,
    /// The package cache writer lock.
    package_cache = 2,
    /// The transaction journal and state directory locks.
    transaction_state = 3,
    /// The dpkg/target database locks inside the selected root.
    target_database = 4,
};

pub const LockError = error{
    LockTimeout,
    LockUnavailable,
    LockCanceled,
    LockOrderViolation,
    LockLost,
    LockFailed,
};

pub const LockToken = *anyopaque;

/// Identity of the selected root. `inode` distinguishes distinct roots even
/// when they are reached through different path spellings; the digest binds
/// the canonical absolute spelling recorded in durable evidence.
pub const Identity = struct {
    install_root_sha256: [32]u8,
    inode: std.Io.File.INode,
};

pub const AcquireLock = struct {
    rank: Rank,
    root: root_fs.Root,
    identity: Identity,
    /// Root-relative lock path. Always resolved through `root_fs`.
    path: []const u8,
    wait_ms: u64,
    cancellation: transaction_executor.Cancellation,
};

/// Injectable lock backend. Tests supply an in-process implementation; the
/// production adapter takes an OFD write lock on a root-anchored file.
pub const LockBackend = struct {
    context: *anyopaque,
    acquireFn: *const fn (*anyopaque, AcquireLock) LockError!LockToken,
    heldFn: *const fn (*anyopaque, LockToken) bool,
    releaseFn: *const fn (*anyopaque, LockToken) void,

    pub fn acquire(self: LockBackend, request: AcquireLock) LockError!LockToken {
        return self.acquireFn(self.context, request);
    }

    pub fn held(self: LockBackend, token: LockToken) bool {
        return self.heldFn(self.context, token);
    }

    pub fn release(self: LockBackend, token: LockToken) void {
        self.releaseFn(self.context, token);
    }
};

/// Production adapter. The lock file is opened through `root_fs`, so every
/// prefix component is resolved without following a symbolic link and the leaf
/// is opened `O_NOFOLLOW`. The lock itself is an open-file-description write
/// lock, which conflicts with dpkg's POSIX record locks while remaining scoped
/// to this descriptor.
pub const SystemLockBackend = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    retry_ms: u64 = 10,

    const Token = struct {
        file: std.Io.File,
        held: bool,
    };

    pub fn interface(self: *SystemLockBackend) LockBackend {
        return .{
            .context = self,
            .acquireFn = acquireLock,
            .heldFn = heldLock,
            .releaseFn = releaseLock,
        };
    }

    fn acquireLock(context: *anyopaque, request: AcquireLock) LockError!LockToken {
        const self: *SystemLockBackend = @ptrCast(@alignCast(context));
        if (builtin.os.tag != .linux) return error.LockUnavailable;
        if (request.cancellation.cancelled()) return error.LockCanceled;
        const started = std.Io.Clock.awake.now(self.io);
        while (true) {
            const file = self.openLockFile(request) catch return error.LockUnavailable;
            var record: std.os.linux.Flock = .{
                .type = std.os.linux.F.WRLCK,
                .whence = 0,
                .start = 0,
                .len = 0,
                .pid = 0,
                ._unused = {},
            };
            const result = std.os.linux.fcntl(
                file.handle,
                std.os.linux.F.OFD_SETLK,
                @intFromPtr(&record),
            );
            const code = std.os.linux.errno(result);
            if (code == .SUCCESS) {
                const token = self.allocator.create(Token) catch {
                    file.close(self.io);
                    return error.LockFailed;
                };
                token.* = .{ .file = file, .held = true };
                return @ptrCast(token);
            }
            file.close(self.io);
            if (code != .ACCES and code != .AGAIN) return error.LockFailed;
            if (request.cancellation.cancelled()) return error.LockCanceled;
            const elapsed = started.durationTo(std.Io.Clock.awake.now(self.io)).toMilliseconds();
            if (elapsed < 0) return error.LockFailed;
            const waited: u64 = @intCast(elapsed);
            if (waited >= request.wait_ms) return error.LockTimeout;
            std.Io.sleep(
                self.io,
                .fromMilliseconds(@intCast(@min(self.retry_ms, request.wait_ms - waited))),
                .awake,
            ) catch return error.LockCanceled;
        }
    }

    fn openLockFile(self: *SystemLockBackend, request: AcquireLock) !std.Io.File {
        const path = try root_fs.Path.init(request.path);
        var parent = try request.root.openParent(path);
        defer parent.close(self.io);
        var attempt: usize = 0;
        while (attempt < 2) : (attempt += 1) {
            return parent.dir.openFile(self.io, parent.leaf, .{
                .mode = .read_write,
                .allow_directory = false,
                .follow_symlinks = false,
                .resolve_beneath = true,
            }) catch |err| switch (err) {
                error.FileNotFound => parent.dir.createFile(self.io, parent.leaf, .{
                    .read = true,
                    .truncate = false,
                    .exclusive = true,
                    .permissions = record_permissions,
                    .resolve_beneath = true,
                }) catch |create_err| switch (create_err) {
                    error.PathAlreadyExists => continue,
                    else => return create_err,
                },
                else => return err,
            };
        }
        return error.LockContended;
    }

    fn heldLock(_: *anyopaque, token: LockToken) bool {
        const value: *Token = @ptrCast(@alignCast(token));
        return value.held;
    }

    fn releaseLock(context: *anyopaque, token: LockToken) void {
        const self: *SystemLockBackend = @ptrCast(@alignCast(context));
        const value: *Token = @ptrCast(@alignCast(token));
        if (value.held) {
            value.file.close(self.io);
            value.held = false;
        }
        self.allocator.destroy(value);
    }
};

pub const Error = LockError || ValidationError || error{
    OutOfMemory,
    RecordCorrupt,
    RootIdentityMismatch,
    OperationInProgress,
    RecoveryRequired,
    ProvenancePending,
    ResolvedAttemptPresent,
    NoActiveAttempt,
    StaleAttempt,
    InvalidTransition,
    MutationEvidenceRequired,
    ProvenanceRequired,
    NamespaceUnavailable,
    StoreFailed,
    AttemptMismatch,
};

/// What the caller intends to do with the root.
pub const Intent = enum {
    /// Start a new mutation. Any active or unrecovered evidence blocks it.
    mutation,
    /// Continue the operation the record already binds. Evidence is adopted
    /// only when the record binds exactly this backend, surface, operation,
    /// request, policy, architecture set, and evidence; anything else falls
    /// back to the plain mutation rules, so an unrelated operation can never
    /// adopt another attempt's evidence and is still refused whenever that
    /// evidence requires recovery.
    same_operation,
    /// Continue or resolve a previous attempt. Existing evidence is adopted
    /// instead of blocking.
    recovery,
};

/// What to do with a record that is durably proven not to require recovery.
pub const ExistingPolicy = enum {
    /// Report the leftover record. Callers that cannot reason about it fail.
    fail,
    /// Take the root over, continuing the generation sequence.
    reclaim_resolved,
};

pub const AcquisitionPoint = enum {
    after_lock_acquired,
    before_retry_terminal_publish,
    after_retry_terminal_publish,
    before_retry_record_clear,
    after_retry_record_clear,
    before_binding_published,
    after_binding_published,
};

pub const AcquisitionObserver = struct {
    context: *anyopaque,
    hitFn: *const fn (*anyopaque, AcquisitionPoint) anyerror!void,

    pub fn hit(self: AcquisitionObserver, point: AcquisitionPoint) !void {
        return self.hitFn(self.context, point);
    }
};

const AcquisitionCleanupForwarder = struct {
    observer: AcquisitionObserver,

    fn interface(self: *AcquisitionCleanupForwarder) OwnershipCleanupObserver {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(context: *anyopaque, point: OwnershipCleanupPoint) !void {
        const self: *AcquisitionCleanupForwarder =
            @ptrCast(@alignCast(context));
        switch (point) {
            .before_terminal_publish => try self.observer.hit(
                .before_retry_terminal_publish,
            ),
            .after_terminal_publish => try self.observer.hit(
                .after_retry_terminal_publish,
            ),
            .before_record_clear => try self.observer.hit(
                .before_retry_record_clear,
            ),
            .after_record_clear => try self.observer.hit(
                .after_retry_record_clear,
            ),
            .before_binding_clear, .after_binding_clear => unreachable,
        }
    }
};

pub const Request = struct {
    intent: Intent = .mutation,
    existing: ExistingPolicy = .fail,
    backend: Backend,
    operation: Operation,
    request_sha256: [32]u8,
    policy_sha256: [32]u8,
    evidence: Evidence = .{},
    target_architecture: []const u8,
    foreign_architectures: []const []const u8 = &.{},
    wait_ms: u64 = 0,
    cancellation: transaction_executor.Cancellation = transaction_executor.Cancellation.never(),
    /// Internal hand-off: recovery may adopt an exact settled/published
    /// record so its completion can be returned to an outer coordinator
    /// without reclaiming it into a new attempt.
    adopt_settled_for_acknowledgment: bool = false,
    /// Optional internal outer-attempt identity. Initial acquisition binds it
    /// durably before mutation and recovery must present the same identity.
    orchestration_id: ?[32]u8 = null,
    /// Exact durable recovery review claim consumed under the root lock before
    /// a confirmed recovery may adopt or create lower ownership.
    recovery_review_claim_sha256: ?[32]u8 = null,
    acquisition_observer: ?AcquisitionObserver = null,
    /// Test seam. Production callers leave it null and receive a random
    /// identifier from the system CSPRNG.
    attempt_id: ?[32]u8 = null,
};

pub const Transition = struct {
    state: State,
    phase: Phase,
    /// Absent means "one past the current step", which is the common case.
    step: ?u64 = null,
    evidence: Evidence = .{},
    outcome: ?Outcome = null,
    provenance: ?ProvenanceState = null,
    provenance_sha256: ?[32]u8 = null,
};

/// Witness for the command-oriented executor bridge. `mutation_observed` is
/// the only way out of `mutation_pending` towards mutation evidence, and
/// `proved_not_started` is the only way to call an interrupted legacy attempt
/// safely abandoned. Derive it with `reportWitness`/`recoveryReportWitness`
/// rather than from a command count, which is never proof on its own.
pub const Witness = enum { proved_not_started, mutation_observed };

/// Where the executor bridge in the record an attempt owns came from.
///
/// This is deliberately not part of the durable record: it is a fact about the
/// hand-over *this* process performed, and no record can carry it across a
/// crash. A `proved_not_started` witness is evidence about that hand-over
/// only, so it may discharge a bridge this invocation published and nothing
/// else.
pub const BridgeOrigin = enum {
    /// The record carries no executor bridge.
    none,
    /// This invocation published the bridge, so its executor's own report
    /// describes exactly the hand-over the record refers to.
    published_here,
    /// The bridge was already durable when this attempt adopted the record.
    /// Some earlier run handed control to an engine that may have mutated the
    /// root, and nothing this run observes can speak for what that engine did.
    inherited,
};

/// The witness that may actually be acted on for a bridge of this origin. A
/// no-start report is conservatively downgraded to observed mutation for a
/// bridge this invocation did not publish, which can only keep a root blocked
/// — never clear one that was mutated.
pub fn witnessForBridge(bridge: BridgeOrigin, observed: Witness) Witness {
    return switch (observed) {
        .mutation_observed => .mutation_observed,
        .proved_not_started => switch (bridge) {
            .published_here => .proved_not_started,
            .none, .inherited => .mutation_observed,
        },
    };
}

/// Conservative classification of the command-oriented executor's own
/// evidence.
///
/// The executor appends a command's provenance only *after* that command has
/// completed, so a first command that timed out, hit the operation deadline,
/// lost a lock, or failed to spawn returns zero commands while `dpkg` may
/// already have been started and may already have mutated the root. A command
/// count is therefore never proof by itself, and neither is a success-shaped
/// report: only a durable `not_started` transaction state *together with* an
/// empty command list proves that nothing ran. Every other transaction state
/// is treated as observed mutation, which can only ever block a root that was
/// not touched — never clear one that was.
pub fn observedMutation(state: transaction_recovery.State, commands: usize) Witness {
    if (commands != 0) return .mutation_observed;
    return switch (state) {
        .not_started => .proved_not_started,
        .in_progress,
        .dpkg_failed,
        .interrupted,
        .verification_failed,
        .complete,
        => .mutation_observed,
    };
}

/// The witness a transaction report justifies. Every product and repository
/// observation site must derive its witness here so no call path can fall back
/// to a bare command count.
pub fn reportWitness(report: transaction_executor.Report) Witness {
    return observedMutation(report.transaction_state, report.commands.len);
}

/// The witness a recovery report justifies. A recovery that decoded a journal
/// at all has durable evidence that an earlier transaction reached the root,
/// so only a recovery that never found one can be proven not to have started.
///
/// A recovery that could not read the journal, or read it and could not decode
/// it, never learned that transaction's state at all: its report still says
/// `not_started` because the decoded state was never published, not because
/// nothing ran. Those two failures are therefore classified as observed
/// mutation, so the evidence recovery exists to resolve is never discharged by
/// the failure to read it.
pub fn recoveryReportWitness(report: transaction_executor.RecoveryReport) Witness {
    if (report.failure) |failure| switch (failure.code) {
        .journal_io, .journal_corrupt => return .mutation_observed,
        else => {},
    };
    return observedMutation(report.state, report.commands.len);
}

/// Owns the root mutation lock and the active record for one root.
pub const Coordinator = struct {
    io: std.Io,
    root: root_fs.Root,
    install_root: []const u8,
    identity: Identity,
    locks: LockBackend,
    now_unix: ?i64 = null,

    /// Validates the selected root, binds its identity, and provisions the
    /// shared namespace. Nothing else in this module touches the filesystem
    /// before this succeeds.
    pub fn open(
        io: std.Io,
        root: root_fs.Root,
        install_root: []const u8,
        locks: LockBackend,
    ) Error!Coordinator {
        if (!absolute_path.root(install_root)) return error.InvalidRoot;
        if (install_root.len > maximum_root_bytes) return error.RootTooLong;
        const metadata = root.metadataOfRoot() catch return error.NamespaceUnavailable;
        if (!metadata.isDirectory()) return error.InvalidRoot;
        const namespace: Store = .init(root);
        namespace.ensureNamespace() catch return error.NamespaceUnavailable;
        return .{
            .io = io,
            .root = root,
            .install_root = install_root,
            .identity = .{
                .install_root_sha256 = transaction_recovery.rootIdentity(install_root),
                .inode = metadata.inode,
            },
            .locks = locks,
        };
    }

    pub fn store(self: Coordinator) Store {
        return .init(self.root);
    }

    /// Read-only view of the active record. It takes no lock, so it is only
    /// for diagnostics and must never gate a mutation.
    pub fn inspect(self: Coordinator, allocator: std.mem.Allocator) !?OwnedRecord {
        return self.store().read(allocator);
    }

    fn now(self: Coordinator) i64 {
        if (self.now_unix) |value| return value;
        const instant = std.Io.Clock.real.now(self.io);
        return @intCast(@divFloor(instant.nanoseconds, std.time.ns_per_s));
    }

    /// Takes the root mutation lock and reserves a durable attempt. On success
    /// the caller holds rank 0 of the lock order and every later mutation
    /// boundary must be published through the returned attempt.
    pub fn acquire(
        self: *Coordinator,
        allocator: std.mem.Allocator,
        request: Request,
    ) Error!Attempt {
        const token = try self.locks.acquire(.{
            .rank = .root_operation,
            .root = self.root,
            .identity = self.identity,
            .path = lock_path,
            .wait_ms = request.wait_ms,
            .cancellation = request.cancellation,
        });
        errdefer self.locks.release(token);
        if (request.acquisition_observer) |observer|
            observer.hit(.after_lock_acquired) catch return error.StoreFailed;

        const store_handle = self.store();
        var recovery_review = store_handle.readRecoveryReviewClaim(
            allocator,
        ) catch |err|
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.RecordCorrupt,
            };
        if (recovery_review) |review| {
            const expected = request.recovery_review_claim_sha256 orelse
                return error.RecoveryRequired;
            const orchestration_id = request.orchestration_id orelse
                return error.RecoveryRequired;
            if (!std.mem.eql(
                u8,
                &review.digest_sha256,
                &expected,
            ) or !std.mem.eql(
                u8,
                &review.outer_attempt_id,
                &orchestration_id,
            )) return error.RecoveryRequired;
        } else if (request.recovery_review_claim_sha256 != null) {
            return error.RecoveryRequired;
        }
        var cleanup_forwarder: AcquisitionCleanupForwarder = undefined;
        const retry_cleanup_observer: ?OwnershipCleanupObserver =
            if (request.acquisition_observer) |observer| blk: {
                cleanup_forwarder = .{ .observer = observer };
                break :blk cleanup_forwarder.interface();
            } else null;
        var prior: ?OwnedRecord = store_handle.read(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.RecordCorrupt,
        };
        errdefer if (prior) |*value| value.deinit();

        if (prior) |value| {
            if (!std.mem.eql(
                u8,
                &value.record.root_identity_sha256,
                &self.identity.install_root_sha256,
            )) return error.RootIdentityMismatch;
        }

        const deferred = store_handle.readDeferredAcknowledgment(
            allocator,
        ) catch return error.RecordCorrupt;
        if (recovery_review) |review| {
            if (!Store.optionalDigestEqual(
                review.marker_sha256,
                if (deferred) |marker| marker.digest_sha256 else null,
            ) or !Store.optionalDigestEqual(
                review.record_sha256,
                if (prior) |owned| owned.record.digest_sha256 else null,
            )) return error.RecoveryRequired;
            if (deferred != null) {
                store_handle.exchangeRecoveryReviewClaimForOwnership(
                    allocator,
                    .{
                        .claim_sha256 = review.digest_sha256,
                        .outer_attempt_id = review.outer_attempt_id,
                        .expected_marker_sha256 = review.marker_sha256,
                        .expected_record_sha256 = review.record_sha256,
                    },
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.StoreFailed,
                };
                recovery_review = null;
            } else if (prior != null) {
                return error.RecoveryRequired;
            }
        }
        if (deferred) |marker| switch (marker.state) {
            .acknowledged => return error.RecoveryRequired,
            .pre_mutation_reconciliation_claim => return error.RecoveryRequired,
            .released => {
                const orchestration_id =
                    request.orchestration_id orelse
                    return error.RecoveryRequired;
                if (!std.mem.eql(
                    u8,
                    &orchestration_id,
                    &marker.acknowledgment_id,
                )) return error.RecoveryRequired;
                store_handle.cleanupOwned(allocator, .{
                    .attempt_id = marker.attempt_id,
                    .acknowledgment_id = orchestration_id,
                    .terminal_state = marker.state,
                }) catch return error.StoreFailed;
                if (prior) |*value| {
                    value.deinit();
                    prior = null;
                }
                return error.ResolvedAttemptPresent;
            },
            .abandoned => {
                const orchestration_id =
                    request.orchestration_id orelse
                    return error.RecoveryRequired;
                if (!std.mem.eql(
                    u8,
                    &orchestration_id,
                    &marker.acknowledgment_id,
                )) return error.RecoveryRequired;
                if (prior) |*value| {
                    if (!recordMatchesDeferredAcknowledgment(
                        value.record,
                        marker,
                        false,
                    ) or
                        (!value.record.state.provenPreMutation() and
                            value.record.outcome !=
                                .abandoned_before_mutation))
                        return error.RecoveryRequired;
                    _ = store_handle.retainOwnedTerminal(allocator, .{
                        .attempt_id = marker.attempt_id,
                        .acknowledgment_id = orchestration_id,
                        .terminal_state = .abandoned,
                        .observer = retry_cleanup_observer,
                    }) catch return error.StoreFailed;
                    value.deinit();
                    prior = null;
                }
            },
            .bound => {
                const orchestration_id =
                    request.orchestration_id orelse
                    return error.RecoveryRequired;
                if (!std.mem.eql(
                    u8,
                    &orchestration_id,
                    &marker.acknowledgment_id,
                )) return error.RecoveryRequired;
                if (prior == null) {
                    // Keep the exact-owner marker continuously present. A
                    // fresh binding replaces it atomically in publishNew.
                } else if (!recordMatchesDeferredAcknowledgment(
                    prior.?.record,
                    marker,
                    true,
                ))
                    return error.RecoveryRequired;
                if (prior != null and prior.?.record.clearable()) {
                    const abandoned =
                        prior.?.record.outcome == .abandoned_before_mutation;
                    if (!abandoned) {
                        store_handle.cleanupOwned(allocator, .{
                            .attempt_id = marker.attempt_id,
                            .acknowledgment_id = orchestration_id,
                            .terminal_state = .released,
                        }) catch return error.StoreFailed;
                    } else _ = store_handle.retainOwnedTerminal(allocator, .{
                        .attempt_id = marker.attempt_id,
                        .acknowledgment_id = orchestration_id,
                        .terminal_state = .abandoned,
                        .observer = retry_cleanup_observer,
                    }) catch return error.StoreFailed;
                    prior.?.deinit();
                    prior = null;
                    if (!abandoned)
                        return error.ResolvedAttemptPresent;
                }
                if (prior != null and prior.?.record.state.provenPreMutation()) {
                    const adopted = prior.?;
                    prior = null;
                    return .{
                        .coordinator = self,
                        .token = token,
                        .owned = adopted,
                        .entered = .initEmpty(),
                        .highest = .root_operation,
                        .adopted = true,
                        .bridge = .none,
                    };
                }
            },
            .pending => {
                const orchestration_id =
                    request.orchestration_id orelse
                    return error.RecoveryRequired;
                if (!std.mem.eql(
                    u8,
                    &orchestration_id,
                    &marker.acknowledgment_id,
                ) or
                    prior == null or
                    !recordMatchesDeferredAcknowledgment(
                        prior.?.record,
                        marker,
                        true,
                    ))
                    return error.RecoveryRequired;
                if (!request.adopt_settled_for_acknowledgment)
                    return error.RecoveryRequired;
            },
        };
        if (deferred == null and request.orchestration_id != null and
            prior != null)
            return error.RecoveryRequired;

        // A durably settled record — completed with its provenance obligation
        // discharged — describes an operation that is over. No intent may
        // adopt it: continuing under a record that already says the mutation
        // finished would run a second mutation with no reserved attempt, no
        // executor bridge, and a terminal outcome that a crash would leave
        // behind as proof the rerun never happened. Settling it here, before
        // any adoption, keeps one rule for every intent: reclaim it into a
        // fresh attempt, or report it, exactly as the plain mutation rules do.
        if (prior) |*value| {
            if (request.intent == .recovery and
                request.adopt_settled_for_acknowledgment and
                value.record.clearable() and
                value.record.provenance == .published)
            {
                const adopted = value.*;
                prior = null;
                return .{
                    .coordinator = self,
                    .token = token,
                    .owned = adopted,
                    .entered = .initEmpty(),
                    .highest = .root_operation,
                    .adopted = true,
                    .bridge = adoptedBridge(adopted.record.state),
                };
            }
        }
        var reclaimed: ?u64 = null;
        if (prior) |*value| {
            if (value.record.clearable()) {
                if (request.existing == .fail) return error.ResolvedAttemptPresent;
                reclaimed = std.math.add(u64, value.record.generation, 1) catch
                    return error.InvalidGeneration;
                value.deinit();
                prior = null;
            }
        }

        if (request.intent == .recovery) {
            if (prior) |*value| {
                const adopted = value.*;
                prior = null;
                return .{
                    .coordinator = self,
                    .token = token,
                    .owned = adopted,
                    .entered = .initEmpty(),
                    .highest = .root_operation,
                    .adopted = true,
                    .bridge = adoptedBridge(adopted.record.state),
                };
            }
            // A recovery that finds no evidence still reserves the root, but
            // it starts pre-mutation. The executor bridge is published only
            // when control is actually handed over, so an early return on a
            // healthy root cannot strand it.
            var publish_request = request;
            if (recovery_review == null)
                publish_request.recovery_review_claim_sha256 = null;
            const created = try self.publishNew(allocator, publish_request, reclaimed orelse 1, .{
                .state = .preflight,
                .phase = .preflight,
            });
            return .{
                .coordinator = self,
                .token = token,
                .owned = created,
                .entered = .initEmpty(),
                .highest = .root_operation,
                .adopted = false,
                .bridge = .none,
            };
        }

        // Continuing the operation the record already binds is the only way a
        // rerun of one request may pick its own evidence back up. The binding
        // is compared before anything is adopted, so an unrelated operation,
        // request, descriptor, or architecture set falls through to the plain
        // mutation rules below and is refused exactly as before.
        if (request.intent == .same_operation) {
            if (prior) |*value| {
                if (bindsSameOperation(value.record, request)) {
                    const adopted = value.*;
                    prior = null;
                    return .{
                        .coordinator = self,
                        .token = token,
                        .owned = adopted,
                        .entered = .initEmpty(),
                        .highest = .root_operation,
                        .adopted = true,
                        .bridge = adoptedBridge(adopted.record.state),
                    };
                }
                // A record that still carries mutation evidence belongs to
                // whoever left it. Reporting the mismatch keeps it exactly as
                // published instead of letting a different request overwrite
                // it. Anything durably settled — proven pre-mutation, or
                // completed with its provenance discharged — falls through to
                // the plain mutation rules, so an unrelated leftover never
                // locks the root out.
                if (value.record.state.blocksMutation() or
                    (value.record.state == .completed and
                        value.record.provenance == .pending))
                    return error.AttemptMismatch;
            }
        }

        var generation: u64 = reclaimed orelse 1;
        if (prior) |*value| {
            const record = value.record;
            if (record.state.blocksMutation()) return error.RecoveryRequired;
            if (record.state == .completed and record.provenance == .pending)
                return error.ProvenancePending;
            if (request.existing == .fail) return switch (record.state) {
                .completed => error.ResolvedAttemptPresent,
                else => error.OperationInProgress,
            };
            generation = std.math.add(u64, record.generation, 1) catch
                return error.InvalidGeneration;
            value.deinit();
            prior = null;
        }
        var publish_request = request;
        if (recovery_review == null)
            publish_request.recovery_review_claim_sha256 = null;
        const created = try self.publishNew(allocator, publish_request, generation, .{
            .state = .reserved,
            .phase = .reserved,
        });
        return .{
            .coordinator = self,
            .token = token,
            .owned = created,
            .entered = .initEmpty(),
            .highest = .root_operation,
            .adopted = false,
            .bridge = .none,
        };
    }

    const Start = struct { state: State, phase: Phase };

    fn publishNew(
        self: *Coordinator,
        allocator: std.mem.Allocator,
        request: Request,
        generation: u64,
        start: Start,
    ) Error!OwnedRecord {
        const timestamp = self.now();
        var attempt_id: [32]u8 = undefined;
        if (request.attempt_id) |value|
            attempt_id = value
        else
            std.Io.randomSecure(self.io, &attempt_id) catch return error.NamespaceUnavailable;
        var created = try create(allocator, .{
            .attempt_id = attempt_id,
            .generation = generation,
            .install_root = self.install_root,
            .backend = request.backend,
            .operation = request.operation,
            .state = start.state,
            .phase = start.phase,
            .step = 0,
            .mutation_started = false,
            .outcome = .pending,
            .provenance = .pending,
            .evidence = request.evidence,
            .request_sha256 = request.request_sha256,
            .policy_sha256 = request.policy_sha256,
            .target_architecture = request.target_architecture,
            .foreign_architectures = request.foreign_architectures,
            .reserved_unix = timestamp,
            .updated_unix = timestamp,
        });
        errdefer created.deinit();
        if (request.orchestration_id) |orchestration_id| {
            const binding = createDeferredAcknowledgment(.{
                .state = .bound,
                .attempt_id = attempt_id,
                .acknowledgment_id = orchestration_id,
            }) catch return error.StoreFailed;
            const store_handle = self.store();
            if (request.acquisition_observer) |observer|
                observer.hit(.before_binding_published) catch
                    return error.StoreFailed;
            if (request.recovery_review_claim_sha256) |claim_sha256|
                store_handle.exchangeRecoveryReviewClaimForOwnership(
                    allocator,
                    .{
                        .claim_sha256 = claim_sha256,
                        .outer_attempt_id = orchestration_id,
                        .expected_marker_sha256 = null,
                        .expected_record_sha256 = null,
                        .replacement_marker = binding,
                    },
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.StoreFailed,
                }
            else if (store_handle.readDeferredAcknowledgment(allocator) catch
                return error.StoreFailed) |_|
                store_handle.rotateDeferredAcknowledgment(
                    allocator,
                    binding,
                ) catch return error.StoreFailed
            else
                store_handle.publishDeferredAcknowledgment(
                    allocator,
                    binding,
                ) catch return error.StoreFailed;
            if (request.acquisition_observer) |observer|
                observer.hit(.after_binding_published) catch
                    return error.StoreFailed;
        }
        self.store().writeAtomic(allocator, created.record) catch
            return error.StoreFailed;
        return created;
    }
};

/// One reserved attempt. It owns rank 0 of the lock order and is the only way
/// to publish a durable boundary for this root.
pub const Attempt = struct {
    coordinator: *Coordinator,
    token: LockToken,
    owned: OwnedRecord,
    entered: std.EnumSet(Rank),
    highest: Rank,
    /// True when this attempt continued a previous durable record instead of
    /// reserving a new one.
    adopted: bool,
    /// Where the executor bridge in the owned record came from. It is process
    /// state, never durable evidence: only this invocation can know whether it
    /// performed the hand-over the record refers to.
    bridge: BridgeOrigin,

    pub fn record(self: *const Attempt) Record {
        return self.owned.record;
    }

    pub fn attemptId(self: *const Attempt) [32]u8 {
        return self.owned.record.attempt_id;
    }

    pub fn bridgeOrigin(self: *const Attempt) BridgeOrigin {
        return self.bridge;
    }

    /// The witness this attempt may act on for the evidence it was given. A
    /// report that proves *this* run started nothing says nothing about a
    /// bridge an earlier run published, so no-start evidence against an
    /// inherited bridge is downgraded to observed mutation.
    pub fn effectiveWitness(self: *const Attempt, observed: Witness) Witness {
        return witnessForBridge(self.bridge, observed);
    }

    /// True while the root mutation lock is still owned. A lost lock must
    /// never be treated as a successful mutation boundary.
    pub fn locked(self: *const Attempt) bool {
        return self.coordinator.locks.held(self.token);
    }

    /// Records that a lower-priority lock is about to be taken. It enforces
    /// the total lock order for locks this module does not own, such as the
    /// repository operation lock and the executor's target locks.
    pub fn enterRank(self: *Attempt, rank: Rank) LockError!void {
        if (@intFromEnum(rank) <= @intFromEnum(self.highest)) return error.LockOrderViolation;
        if (self.entered.contains(rank)) return error.LockOrderViolation;
        self.entered.insert(rank);
        self.highest = rank;
    }

    pub fn exitRank(self: *Attempt, rank: Rank) void {
        if (!self.entered.contains(rank)) return;
        self.entered.remove(rank);
        var highest: Rank = .root_operation;
        var iterator = self.entered.iterator();
        while (iterator.next()) |value| {
            if (@intFromEnum(value) > @intFromEnum(highest)) highest = value;
        }
        self.highest = highest;
    }

    /// Durably publishes the next boundary. The write is compare-and-set
    /// against the record currently on disk, so a stale writer that resumed
    /// from an older view cannot overwrite newer evidence.
    pub fn advance(
        self: *Attempt,
        allocator: std.mem.Allocator,
        transition: Transition,
    ) Error!void {
        const current = self.owned.record;
        if (!self.locked()) return error.LockLost;

        const step = transition.step orelse (std.math.add(u64, current.step, 1) catch
            return error.InvalidTransition);
        const mutation_started = current.mutation_started or startsMutation(transition.state);
        const outcome = transition.outcome orelse current.outcome;
        const provenance = transition.provenance orelse current.provenance;
        const provenance_sha256 = transition.provenance_sha256 orelse current.provenance_sha256;
        const evidence = try mergeEvidence(current.evidence(), transition.evidence);

        if (idempotent(
            current,
            transition.state,
            transition.phase,
            step,
            mutation_started,
            outcome,
            provenance,
        )) return;
        if (!canTransition(current.state, transition.state)) return error.InvalidTransition;
        if (step <= current.step) return error.InvalidTransition;
        if (transition.state == .completed and outcome == .pending)
            return error.InvalidTransition;
        if (transition.state == .completed and outcome == .abandoned_before_mutation and
            current.state == .mutating) return error.InvalidTransition;

        const generation = std.math.add(u64, current.generation, 1) catch
            return error.InvalidTransition;
        var next = try create(allocator, .{
            .attempt_id = current.attempt_id,
            .generation = generation,
            .install_root = current.install_root,
            .backend = current.backend,
            .operation = current.operation,
            .state = transition.state,
            .phase = transition.phase,
            .step = step,
            .mutation_started = mutation_started,
            .outcome = outcome,
            .provenance = provenance,
            .provenance_sha256 = provenance_sha256,
            .evidence = evidence,
            .request_sha256 = current.request_sha256,
            .policy_sha256 = current.policy_sha256,
            .target_architecture = current.target_architecture,
            .foreign_architectures = current.foreign_architectures,
            .reserved_unix = current.reserved_unix,
            .updated_unix = self.coordinator.now(),
        });
        errdefer next.deinit();
        try self.compareAndSet(allocator, next.record);
        // The hand-over the bridge stands for is this invocation's exactly
        // when this invocation published it. Re-publishing a bridge that was
        // already durable never makes another run's hand-over ours.
        if (transition.state == .mutation_pending and current.state != .mutation_pending)
            self.bridge = .published_here;
        self.owned.deinit();
        self.owned = next;
    }

    /// Publishes the point of no return. After this the root may have been
    /// mutated, so no later reader can call the attempt safely abandoned.
    pub fn markMutationStarted(
        self: *Attempt,
        allocator: std.mem.Allocator,
        phase: Phase,
    ) Error!void {
        try self.advance(allocator, .{ .state = .mutating, .phase = phase });
    }

    /// Resolves the command-oriented executor bridge from explicit evidence
    /// and returns the witness that was actually applied.
    ///
    /// The caller's evidence describes what its own executor did, so it can
    /// only discharge a bridge this invocation published. A no-start report
    /// against a bridge inherited from an earlier run is coerced to
    /// `mutation_observed` here — not at the call site — so no observation
    /// path can discharge another run's hand-over by passing the witness its
    /// own executor justified.
    pub fn witness(
        self: *Attempt,
        allocator: std.mem.Allocator,
        observed: Witness,
    ) Error!Witness {
        if (self.owned.record.state != .mutation_pending) return error.InvalidTransition;
        const applied = self.effectiveWitness(observed);
        switch (applied) {
            .mutation_observed => try self.advance(allocator, .{
                .state = .mutating,
                .phase = .mutation,
            }),
            .proved_not_started => try self.advance(allocator, .{
                .state = .completed,
                .phase = .provenance,
                .outcome = .abandoned_before_mutation,
                .provenance = .not_required,
            }),
        }
        return applied;
    }

    /// Durably requires recovery. A second mutation cannot start until the
    /// attempt is explicitly recovered.
    pub fn requireRecovery(
        self: *Attempt,
        allocator: std.mem.Allocator,
        phase: Phase,
    ) Error!void {
        if (!self.owned.record.mutation_started and
            self.owned.record.state != .mutation_pending)
            return error.MutationEvidenceRequired;
        try self.advance(allocator, .{ .state = .recovery_required, .phase = phase });
    }

    /// Walks the exact edges from wherever the attempt stopped to `recovering`
    /// so a resumed attempt never skips the durable recovery-required
    /// boundary. A pending legacy bridge is left alone; only an explicit
    /// witness may resolve it.
    pub fn beginRecovery(
        self: *Attempt,
        allocator: std.mem.Allocator,
        phase: Phase,
    ) Error!void {
        switch (self.owned.record.state) {
            .mutating, .verifying => {
                try self.requireRecovery(allocator, phase);
                try self.advance(allocator, .{ .state = .recovering, .phase = phase });
            },
            .recovery_required => try self.advance(allocator, .{
                .state = .recovering,
                .phase = phase,
            }),
            .recovering, .mutation_pending => {},
            .reserved, .preflight, .completed => return error.MutationEvidenceRequired,
        }
    }

    /// Publishes the attempt's provenance digest. Required before the record
    /// may be cleared whenever the root was mutated.
    pub fn publishProvenance(
        self: *Attempt,
        allocator: std.mem.Allocator,
        digest: [32]u8,
    ) Error!void {
        if (self.owned.record.state != .completed) return error.InvalidTransition;
        try self.advance(allocator, .{
            .state = .completed,
            .phase = .provenance,
            .provenance = .published,
            .provenance_sha256 = digest,
        });
    }

    /// Terminal boundary for the attempt. Mutating outcomes still owe
    /// provenance; a never-mutated attempt is explicitly marked as owing none.
    pub fn complete(
        self: *Attempt,
        allocator: std.mem.Allocator,
        outcome: Outcome,
    ) Error!void {
        // A handed-over attempt is never completed directly: only an explicit
        // witness may decide whether the engine mutated the root.
        if (self.owned.record.state == .mutation_pending)
            return error.MutationEvidenceRequired;
        const provenance: ProvenanceState = if (self.owned.record.mutation_started)
            .pending
        else
            .not_required;
        try self.advance(allocator, .{
            .state = .completed,
            .phase = .provenance,
            .outcome = outcome,
            .provenance = provenance,
        });
    }

    /// Release valve for a caller that gives up before mutating. Only a state
    /// that is durably proven pre-mutation is completed and cleared; anything
    /// at or past the executor bridge is refused and stays exactly as
    /// published.
    pub fn abandonIfPreMutation(self: *Attempt, allocator: std.mem.Allocator) Error!void {
        if (!self.owned.record.state.provenPreMutation()) return error.MutationEvidenceRequired;
        try self.complete(allocator, .abandoned_before_mutation);
        try self.clear();
    }

    /// Removes the active intent. Refused while the attempt is unfinished or
    /// while it still owes provenance.
    pub fn clear(self: *Attempt) Error!void {
        const current = self.owned.record;
        if (!self.locked()) return error.LockLost;
        if (current.state != .completed) return error.InvalidTransition;
        if (current.provenance == .pending) return error.ProvenanceRequired;
        self.coordinator.store().clear() catch return error.StoreFailed;
    }

    /// Releases the root mutation lock. The durable record, if any, stays
    /// exactly as it was last published.
    pub fn release(self: *Attempt) void {
        self.coordinator.locks.release(self.token);
        self.owned.deinit();
        self.* = undefined;
    }

    fn compareAndSet(self: *Attempt, allocator: std.mem.Allocator, next: Record) Error!void {
        const store_handle = self.coordinator.store();
        var observed = store_handle.read(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.RecordCorrupt,
        } orelse return error.NoActiveAttempt;
        defer observed.deinit();
        const current = self.owned.record;
        if (!std.mem.eql(u8, &observed.record.attempt_id, &current.attempt_id) or
            observed.record.generation != current.generation or
            !std.mem.eql(u8, &observed.record.digest_sha256, &current.digest_sha256))
            return error.StaleAttempt;
        store_handle.writeAtomic(allocator, next) catch return error.StoreFailed;
    }
};

/// Evidence the caller published for the attempt before clearing it. The
/// legacy backend's durable evidence is its archived journal; newer backends
/// additionally publish a provenance document.
pub const ProvenanceEvidence = struct {
    outcome: Outcome,
    document_sha256: ?[32]u8 = null,
    journal_archived: bool = false,
};

/// Stable digest binding one attempt to the provenance published for it. It is
/// what `publishProvenance` records, so clearing the active intent always
/// leaves a verifiable link between the attempt and its published evidence.
pub fn provenanceDigest(record: Record, evidence: ProvenanceEvidence) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-root-operation-provenance-v1\x00");
    hash.update(&record.attempt_id);
    hash.update(&record.root_identity_sha256);
    hash.update(&record.request_sha256);
    if (record.plan_sha256) |digest| {
        hash.update("\x01");
        hash.update(&digest);
    } else hash.update("\x00");
    hash.update(@tagName(evidence.outcome));
    hash.update("\x00");
    if (evidence.document_sha256) |digest| {
        hash.update("\x01");
        hash.update(&digest);
    } else hash.update("\x00");
    hash.update(if (evidence.journal_archived) "\x01" else "\x00");
    return hash.finalResult();
}

fn startsMutation(state: State) bool {
    return switch (state) {
        .mutating, .verifying, .recovery_required, .recovering => true,
        .reserved, .preflight, .mutation_pending, .completed => false,
    };
}

/// The bridge origin an adopted record implies. A record that already sits at
/// the executor bridge was handed over by some earlier run, so this one
/// inherits it and can never prove what that hand-over did.
fn recordMatchesDeferredAcknowledgment(
    record: Record,
    marker: DeferredAcknowledgment,
    allow_pending_provenance: bool,
) bool {
    return deferredRecordCompatibility(
        record,
        marker,
        allow_pending_provenance,
    ) != .incompatible;
}

fn adoptedBridge(state: State) BridgeOrigin {
    return if (state == .mutation_pending) .inherited else .none;
}

/// A crash between publishing a boundary and continuing leaves the caller
/// replaying the same explicit boundary. Replaying the exact published
/// boundary is a success, not a transition.
fn idempotent(
    current: Record,
    state: State,
    phase: Phase,
    step: u64,
    mutation_started: bool,
    outcome: Outcome,
    provenance: ProvenanceState,
) bool {
    return current.state == state and current.phase == phase and current.step == step and
        current.mutation_started == mutation_started and current.outcome == outcome and
        current.provenance == provenance;
}

/// Whether a durable record binds exactly the operation the caller is about to
/// continue. Adoption is refused unless every identifying field agrees, so an
/// unrelated operation, request, descriptor, policy, or architecture set can
/// never pick up — or overwrite — another attempt's evidence. The root
/// identity is compared before this is reached.
fn bindsSameOperation(record: Record, request: Request) bool {
    if (record.backend != request.backend) return false;
    if (!record.operation.eql(request.operation)) return false;
    if (!std.mem.eql(u8, &record.request_sha256, &request.request_sha256)) return false;
    if (!std.mem.eql(u8, &record.policy_sha256, &request.policy_sha256)) return false;
    if (!std.mem.eql(u8, record.target_architecture, request.target_architecture)) return false;
    if (!architectureSetEqual(record.foreign_architectures, request.foreign_architectures))
        return false;
    // Evidence stays write-once across a resumption: a rerun that already
    // carries a different plan, authorization, program, lock, database
    // generation, or artifact digest is a different operation.
    _ = mergeEvidence(record.evidence(), request.evidence) catch return false;
    return true;
}

/// Set equality between the record's canonical architecture list and the
/// caller's raw one, so ordering and duplicates in the request never decide
/// whether an attempt may be resumed.
fn architectureSetEqual(canonical: []const []const u8, requested: []const []const u8) bool {
    for (requested) |value| if (!containsText(canonical, value)) return false;
    for (canonical) |value| if (!containsText(requested, value)) return false;
    return true;
}

fn containsText(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |value| if (std.mem.eql(u8, value, needle)) return true;
    return false;
}

/// Evidence is write-once. Rebinding an attempt to a different authorization,
/// program, lock, database generation, or artifact set is refused.
fn mergeEvidence(current: Evidence, next: Evidence) Error!Evidence {
    return .{
        .authorization_sha256 = try mergeDigest(
            current.authorization_sha256,
            next.authorization_sha256,
        ),
        .program_sha256 = try mergeDigest(current.program_sha256, next.program_sha256),
        .plan_sha256 = try mergeDigest(current.plan_sha256, next.plan_sha256),
        .exact_lock = try mergeLock(current.exact_lock, next.exact_lock),
        .database_generation_sha256 = try mergeDigest(
            current.database_generation_sha256,
            next.database_generation_sha256,
        ),
        .artifact_evidence_sha256 = try mergeDigest(
            current.artifact_evidence_sha256,
            next.artifact_evidence_sha256,
        ),
    };
}

fn mergeDigest(current: ?[32]u8, next: ?[32]u8) Error!?[32]u8 {
    const value = next orelse return current;
    const existing = current orelse return value;
    if (!std.mem.eql(u8, &existing, &value)) return error.InvalidTransition;
    return existing;
}

fn mergeLock(current: ?LockBinding, next: ?LockBinding) Error!?LockBinding {
    const value = next orelse return current;
    const existing = current orelse return value;
    if (!existing.eql(value)) return error.InvalidTransition;
    return existing;
}

/// In-process lock backend for hermetic tests. Roots are distinguished by
/// inode, so the same root reached through two different path spellings
/// serializes exactly as it does in production, while genuinely different
/// roots proceed in parallel.
pub const TestLockBackend = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    /// Fails the next `wait_ms`-bounded acquisition instead of blocking.
    fail_with: ?LockError = null,
    acquisitions: usize = 0,

    const Entry = struct {
        inode: std.Io.File.INode,
        rank: Rank,
        token: *Token,
    };

    const Token = struct {
        inode: std.Io.File.INode,
        rank: Rank,
        held: bool,
    };

    /// Simulates losing every held lock without freeing its token, which is
    /// what a caller observes when the owning descriptor goes away.
    pub fn loseAll(self: *TestLockBackend) void {
        for (self.entries.items) |entry| entry.token.held = false;
    }

    pub fn deinit(self: *TestLockBackend) void {
        for (self.entries.items) |entry| self.allocator.destroy(entry.token);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn interface(self: *TestLockBackend) LockBackend {
        return .{
            .context = self,
            .acquireFn = acquireLock,
            .heldFn = heldLock,
            .releaseFn = releaseLock,
        };
    }

    fn acquireLock(context: *anyopaque, request: AcquireLock) LockError!LockToken {
        const self: *TestLockBackend = @ptrCast(@alignCast(context));
        self.acquisitions += 1;
        if (self.fail_with) |err| return err;
        if (request.cancellation.cancelled()) return error.LockCanceled;
        for (self.entries.items) |entry| {
            if (entry.inode == request.identity.inode and entry.rank == request.rank)
                return error.LockTimeout;
        }
        const token = self.allocator.create(Token) catch return error.LockFailed;
        token.* = .{ .inode = request.identity.inode, .rank = request.rank, .held = true };
        self.entries.append(self.allocator, .{
            .inode = request.identity.inode,
            .rank = request.rank,
            .token = token,
        }) catch {
            self.allocator.destroy(token);
            return error.LockFailed;
        };
        return @ptrCast(token);
    }

    fn heldLock(_: *anyopaque, token: LockToken) bool {
        const value: *Token = @ptrCast(@alignCast(token));
        return value.held;
    }

    fn releaseLock(context: *anyopaque, token: LockToken) void {
        const self: *TestLockBackend = @ptrCast(@alignCast(context));
        const value: *Token = @ptrCast(@alignCast(token));
        value.held = false;
        var index: usize = 0;
        while (index < self.entries.items.len) : (index += 1) {
            if (self.entries.items[index].token == value) {
                _ = self.entries.swapRemove(index);
                break;
            }
        }
        self.allocator.destroy(value);
    }
};

const testing = std.testing;

const test_root = "/target";
const test_other_root = "/other";

const FailingPublishObserver = struct {
    fail_at: root_fs.PublishPoint,

    fn interface(self: *FailingPublishObserver) root_fs.PublishObserver {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(context: *anyopaque, point: root_fs.PublishPoint) !void {
        const self: *FailingPublishObserver = @ptrCast(@alignCast(context));
        if (point == self.fail_at) return error.InjectedCrash;
    }
};

fn testRequest(operation: Operation) Request {
    return .{
        .backend = .legacy_dpkg,
        .operation = operation,
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .evidence = .{ .plan_sha256 = @splat(0x33) },
        .target_architecture = "amd64",
        .attempt_id = @splat(0x44),
    };
}

fn packageRequest() Request {
    return testRequest(.{ .package_transaction = .install });
}

fn repositoryRequest() Request {
    return testRequest(.{ .repository_bootstrap = .add });
}

fn openTestCoordinator(
    tmp: *std.testing.TmpDir,
    locks: LockBackend,
    install_root: []const u8,
) !Coordinator {
    var coordinator = try Coordinator.open(
        testing.io,
        .init(testing.io, tmp.dir),
        install_root,
        locks,
    );
    coordinator.now_unix = 1_700_000_000;
    return coordinator;
}

fn testInput() Input {
    return .{
        .attempt_id = @splat(0x44),
        .generation = 1,
        .install_root = test_root,
        .backend = .legacy_dpkg,
        .operation = .{ .package_transaction = .install },
        .state = .reserved,
        .phase = .reserved,
        .step = 0,
        .mutation_started = false,
        .outcome = .pending,
        .provenance = .pending,
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .evidence = .{ .plan_sha256 = @splat(0x33) },
        .target_architecture = "amd64",
        .reserved_unix = 1_700_000_000,
        .updated_unix = 1_700_000_000,
    };
}

test "root_operation.test.record round trips through its canonical encoding" {
    var input = testInput();
    input.foreign_architectures = &.{ "riscv64", "i386" };
    input.evidence = .{
        .plan_sha256 = @splat(0x33),
        .authorization_sha256 = @splat(0x55),
        .program_sha256 = @splat(0x66),
        .exact_lock = .{
            .schema = "https://debz.dev/schema/exact-closure-lock-v2",
            .version = 2,
            .digest_sha256 = @splat(0x77),
        },
        .database_generation_sha256 = @splat(0x88),
        .artifact_evidence_sha256 = @splat(0x99),
    };
    var created = try create(testing.allocator, input);
    defer created.deinit();

    // Foreign architectures are canonically sorted regardless of input order.
    try testing.expectEqualStrings("i386", created.record.foreign_architectures[0]);
    try testing.expectEqualStrings("riscv64", created.record.foreign_architectures[1]);

    const bytes = try created.record.canonicalJson(testing.allocator);
    defer testing.allocator.free(bytes);
    var decoded = try decode(testing.allocator, bytes, maximum_document_bytes);
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, &created.record.digest_sha256, &decoded.record.digest_sha256);
    try testing.expect(decoded.record.operation.eql(created.record.operation));
    try testing.expectEqual(@as(u32, 2), decoded.record.exact_lock.?.version);

    const tampered = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(tampered);
    const marker = "\"step\":0";
    const index = std.mem.indexOf(u8, tampered, marker).?;
    tampered[index + marker.len - 1] = '1';
    try testing.expectError(
        error.DigestMismatch,
        decode(testing.allocator, tampered, maximum_document_bytes),
    );

    const reordered = try std.fmt.allocPrint(testing.allocator, " {s}", .{bytes});
    defer testing.allocator.free(reordered);
    try testing.expectError(
        error.NonCanonicalDocument,
        decode(testing.allocator, reordered, maximum_document_bytes),
    );

    const unknown = try std.mem.replaceOwned(
        u8,
        testing.allocator,
        bytes,
        "\"step\":0",
        "\"step\":0,\"extra\":1",
    );
    defer testing.allocator.free(unknown);
    try testing.expectError(
        error.NonCanonicalDocument,
        decode(testing.allocator, unknown, maximum_document_bytes),
    );

    const other_schema = try std.mem.replaceOwned(
        u8,
        testing.allocator,
        bytes,
        schema_id,
        "https://debz.dev/schema/root-operation-record-v9",
    );
    defer testing.allocator.free(other_schema);
    try testing.expectError(
        error.UnsupportedSchema,
        decode(testing.allocator, other_schema, maximum_document_bytes),
    );

    try testing.expectError(
        error.DocumentTooLarge,
        decode(testing.allocator, bytes, bytes.len - 1),
    );
    try testing.expectError(
        error.NonCanonicalDocument,
        decode(testing.allocator, bytes[0 .. bytes.len / 2], maximum_document_bytes),
    );
}

test "root_operation.test.deferred marker and record compatibility matrix is exhaustive" {
    const Shape = enum {
        absent,
        reserved,
        mutation_pending,
        mutating,
        completed_success_pending,
        completed_success_published,
        completed_recovered_published,
        completed_abandoned,
        foreign_completed_success,
    };
    const claim: PreMutationReconciliationClaimBinding = .{
        .outer_attempt_id = @splat(0xa0),
        .outer_generation = 7,
        .outer_state_sha256 = @splat(0xa1),
        .profile_sha256 = @splat(0xa2),
        .profile_reference_sha256 = @splat(0xa3),
        .exact_lock_sha256 = @splat(0xa4),
        .semantic_request_sha256 = @splat(0xa5),
    };
    for (std.enums.values(DeferredAcknowledgmentState)) |marker_state| {
        for (std.enums.values(Shape)) |shape| {
            var input = testInput();
            switch (shape) {
                .absent => {},
                .reserved => {},
                .mutation_pending => {
                    input.state = .mutation_pending;
                    input.phase = .mutation;
                },
                .mutating => {
                    input.state = .mutating;
                    input.phase = .mutation;
                    input.mutation_started = true;
                },
                .completed_success_pending => {
                    input.state = .completed;
                    input.phase = .provenance;
                    input.mutation_started = true;
                    input.outcome = .succeeded;
                },
                .completed_success_published,
                .foreign_completed_success,
                => {
                    input.state = .completed;
                    input.phase = .provenance;
                    input.mutation_started = true;
                    input.outcome = .succeeded;
                    input.provenance = .published;
                    input.provenance_sha256 = @splat(0x91);
                    if (shape == .foreign_completed_success)
                        input.attempt_id = @splat(0x45);
                },
                .completed_recovered_published => {
                    input.state = .completed;
                    input.phase = .provenance;
                    input.mutation_started = true;
                    input.outcome = .recovered;
                    input.provenance = .published;
                    input.provenance_sha256 = @splat(0x91);
                },
                .completed_abandoned => {
                    input.state = .completed;
                    input.phase = .provenance;
                    input.outcome = .abandoned_before_mutation;
                    input.provenance = .not_required;
                },
            }
            var owned: ?OwnedRecord = if (shape == .absent)
                null
            else
                try create(testing.allocator, input);
            defer if (owned) |*record| record.deinit();
            const marker = try createDeferredAcknowledgment(.{
                .state = marker_state,
                .attempt_id = if (marker_state ==
                    .pre_mutation_reconciliation_claim)
                    preMutationReconciliationClaimId(claim)
                else
                    @splat(0x44),
                .completion_sha256 = if (marker_state == .pending or
                    marker_state == .acknowledged)
                    @splat(0x92)
                else
                    null,
                .provenance_sha256 = if (marker_state == .pending or
                    marker_state == .acknowledged)
                    @splat(0x91)
                else
                    null,
                .pre_mutation_claim = if (marker_state ==
                    .pre_mutation_reconciliation_claim)
                    claim
                else
                    null,
                .acknowledgment_id = if (marker_state ==
                    .pre_mutation_reconciliation_claim)
                    claim.outer_attempt_id
                else
                    @splat(0xb0),
            });
            const expected: DeferredRecordCompatibility =
                if (shape == .foreign_completed_success)
                    .incompatible
                else switch (marker_state) {
                    .pre_mutation_reconciliation_claim => if (shape == .absent)
                        .pre_mutation_reconciliation_claim
                    else
                        .incompatible,
                    .bound => switch (shape) {
                        .reserved => .bound_pre_mutation,
                        .mutation_pending => .bound_ambiguous,
                        .mutating => .bound_mutating,
                        .completed_success_published,
                        .completed_recovered_published,
                        => .bound_completed_success,
                        .completed_success_pending => .bound_completed_pending,
                        .completed_abandoned => .bound_completed_abandoned,
                        else => .incompatible,
                    },
                    .released => switch (shape) {
                        .absent => .released_without_record,
                        .completed_success_published,
                        .completed_recovered_published,
                        => .released_completed,
                        else => .incompatible,
                    },
                    .abandoned => if (shape == .absent)
                        .abandoned_without_record
                    else if (shape == .completed_abandoned)
                        .abandoned_pre_mutation
                    else
                        .incompatible,
                    .pending => switch (shape) {
                        .completed_success_pending => .pending_prepublication,
                        .completed_success_published,
                        .completed_recovered_published,
                        => .pending_published,
                        else => .incompatible,
                    },
                    .acknowledged => switch (shape) {
                        .completed_success_published,
                        .completed_recovered_published,
                        => .acknowledged_published,
                        else => .incompatible,
                    },
                };
            try testing.expectEqual(
                expected,
                deferredRecordCompatibility(
                    if (owned) |record| record.record else null,
                    marker,
                    true,
                ),
            );
            if (marker_state == .pending and
                shape == .completed_success_pending)
                try testing.expectEqual(
                    DeferredRecordCompatibility.incompatible,
                    deferredRecordCompatibility(
                        owned.?.record,
                        marker,
                        false,
                    ),
                );
        }
    }
}

test "root_operation.test.pre-mutation reconciliation claim round trips exact binding" {
    const claim: PreMutationReconciliationClaimBinding = .{
        .outer_attempt_id = @splat(0xc0),
        .outer_generation = 42,
        .outer_state_sha256 = @splat(0xc1),
        .profile_sha256 = @splat(0xc2),
        .profile_reference_sha256 = @splat(0xc3),
        .exact_lock_sha256 = @splat(0xc4),
        .semantic_request_sha256 = @splat(0xc5),
    };
    const marker = try createDeferredAcknowledgment(.{
        .state = .pre_mutation_reconciliation_claim,
        .attempt_id = preMutationReconciliationClaimId(claim),
        .pre_mutation_claim = claim,
        .acknowledgment_id = claim.outer_attempt_id,
    });
    const source = try marker.canonicalJson(testing.allocator);
    defer testing.allocator.free(source);
    const decoded = try decodeDeferredAcknowledgment(
        testing.allocator,
        source,
    );
    try testing.expect(matchesPreMutationReconciliationClaim(
        decoded,
        claim,
    ));
}

test "root_operation.test.recovery review claim canonicalizes exact clean and completion evidence" {
    const cases = [_]RecoveryReviewClaim{
        .{
            .outer_attempt_id = @splat(0xd0),
            .outer_generation = 7,
            .outer_state_sha256 = @splat(0xd1),
            .profile_sha256 = @splat(0xd2),
            .profile_reference_sha256 = @splat(0xd3),
            .exact_lock_sha256 = @splat(0xd4),
            .semantic_request_sha256 = @splat(0xd5),
            .mutation_status = .unchanged,
            .nonce = @splat(0xd6),
        },
        .{
            .outer_attempt_id = @splat(0xe0),
            .outer_generation = 8,
            .outer_state_sha256 = @splat(0xe1),
            .profile_sha256 = @splat(0xe2),
            .profile_reference_sha256 = @splat(0xe3),
            .exact_lock_sha256 = @splat(0xe4),
            .semantic_request_sha256 = @splat(0xe5),
            .mutation_status = .changed,
            .nonce = @splat(0xe6),
            .completion_sha256 = @splat(0xe7),
        },
    };
    for (cases) |input| {
        const claim = try createRecoveryReviewClaim(input);
        const source = try claim.canonicalJson(testing.allocator);
        defer testing.allocator.free(source);
        const decoded = try decodeRecoveryReviewClaim(
            testing.allocator,
            source,
        );
        try testing.expectEqualDeep(claim, decoded);
    }

    try testing.expectError(error.InvalidDocument, createRecoveryReviewClaim(.{
        .outer_attempt_id = @splat(0xf0),
        .outer_generation = 9,
        .outer_state_sha256 = @splat(0xf1),
        .profile_sha256 = @splat(0xf2),
        .profile_reference_sha256 = @splat(0xf3),
        .exact_lock_sha256 = @splat(0xf4),
        .semantic_request_sha256 = @splat(0xf5),
        .mutation_status = .changed,
        .nonce = @splat(0xf6),
    }));
}

test "root_operation.test.frozen main deferred acknowledgment v1 fixtures remain byte exact" {
    const fixtures = [_][]const u8{
        "{\"schema\":\"https://debz.dev/schema/root-operation-deferred-ack-v1\",\"version\":1,\"state\":\"bound\",\"attempt_id\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"completion_sha256\":null,\"provenance_sha256\":null,\"acknowledgment_id\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"digest_sha256\":\"9ebc1e5a301ad8861e813b590c60e96e18728b38a32fb5e6e2a8cf5a80b64db7\"}",
        "{\"schema\":\"https://debz.dev/schema/root-operation-deferred-ack-v1\",\"version\":1,\"state\":\"released\",\"attempt_id\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"completion_sha256\":null,\"provenance_sha256\":null,\"acknowledgment_id\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"digest_sha256\":\"0458d25d816074fc6148e0c14cb334e033df62d89f765c2b26aa719a45b1b6c5\"}",
        "{\"schema\":\"https://debz.dev/schema/root-operation-deferred-ack-v1\",\"version\":1,\"state\":\"abandoned\",\"attempt_id\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"completion_sha256\":null,\"provenance_sha256\":null,\"acknowledgment_id\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"digest_sha256\":\"ef47268cb544cd653bf0694704424a291ae95db2b847ad6ceec60a1f727c34d6\"}",
        "{\"schema\":\"https://debz.dev/schema/root-operation-deferred-ack-v1\",\"version\":1,\"state\":\"pending\",\"attempt_id\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"completion_sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",\"provenance_sha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"acknowledgment_id\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"digest_sha256\":\"4aa48a83b79e06c2a850aa81c955e31588162fdb7fd0f7ab10e20eca70fe4992\"}",
        "{\"schema\":\"https://debz.dev/schema/root-operation-deferred-ack-v1\",\"version\":1,\"state\":\"acknowledged\",\"attempt_id\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"completion_sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",\"provenance_sha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"acknowledgment_id\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"digest_sha256\":\"57ccdec9d5fef63c77929b99157347caa15442a87fae1e823da73dfbdd343cb6\"}",
    };
    for (fixtures) |fixture| {
        const decoded = try decodeDeferredAcknowledgment(
            testing.allocator,
            fixture,
        );
        try testing.expectEqual(
            deferred_ack_schema_version,
            decoded.document_version,
        );
        const encoded = try decoded.canonicalJson(testing.allocator);
        defer testing.allocator.free(encoded);
        try testing.expectEqualStrings(fixture, encoded);
        try testing.expect(
            std.mem.indexOf(u8, encoded, "recovery_review_") == null,
        );
    }
}

test "root_operation.test.upgrade finalizes frozen v1 ownership without rewriting it as v2" {
    const pending_source =
        "{\"schema\":\"https://debz.dev/schema/root-operation-deferred-ack-v1\",\"version\":1,\"state\":\"pending\",\"attempt_id\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"completion_sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",\"provenance_sha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"acknowledgment_id\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"digest_sha256\":\"4aa48a83b79e06c2a850aa81c955e31588162fdb7fd0f7ab10e20eca70fe4992\"}";
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root: root_fs.Root = .init(testing.io, tmp.dir);
    const store = Store.init(root);
    try store.ensureNamespace();
    try root.publishFile(
        try root_fs.Path.init(deferred_ack_path),
        pending_source,
        .{},
    );
    const pending = (try store.readDeferredAcknowledgment(
        testing.allocator,
    )).?;
    const acknowledged = try store.acknowledgeDeferredAcknowledgment(
        testing.allocator,
        pending.digest_sha256,
    );
    try testing.expectEqual(
        deferred_ack_schema_version,
        acknowledged.document_version,
    );
    const source = try acknowledged.canonicalJson(testing.allocator);
    defer testing.allocator.free(source);
    try testing.expect(
        std.mem.indexOf(u8, source, "recovery_review_") == null,
    );
    try store.cleanupOwned(testing.allocator, .{
        .attempt_id = acknowledged.attempt_id,
        .acknowledgment_id = acknowledged.acknowledgment_id,
        .terminal_state = .acknowledged,
    });
    try testing.expect(
        (try store.readDeferredAcknowledgment(testing.allocator)) == null,
    );
}

test "root_operation.test.recovery review exchange survives every durable publication boundary" {
    inline for (std.enums.values(root_fs.PublishPoint)) |fail_at| {
        var tmp = testing.tmpDir(.{ .iterate = true });
        defer tmp.cleanup();
        const root: root_fs.Root = .init(testing.io, tmp.dir);
        const store = Store.init(root);
        try store.ensureNamespace();
        const claim = try createRecoveryReviewClaim(.{
            .outer_attempt_id = @splat(0xa1),
            .outer_generation = 9,
            .outer_state_sha256 = @splat(0xa2),
            .profile_sha256 = @splat(0xa3),
            .profile_reference_sha256 = @splat(0xa4),
            .exact_lock_sha256 = @splat(0xa5),
            .semantic_request_sha256 = @splat(0xa6),
            .mutation_status = .unchanged,
            .nonce = @splat(0xa7),
        });
        try store.publishRecoveryReviewClaim(testing.allocator, claim);
        const replacement = try createDeferredAcknowledgment(.{
            .attempt_id = @splat(0xb1),
            .acknowledgment_id = claim.outer_attempt_id,
        });
        const transferred = try createDeferredAcknowledgment(.{
            .attempt_id = replacement.attempt_id,
            .acknowledgment_id = replacement.acknowledgment_id,
            .recovery_review_claim_sha256 = claim.digest_sha256,
        });
        var observer: FailingPublishObserver = .{ .fail_at = fail_at };
        try testing.expectError(
            error.InjectedCrash,
            store.exchangeRecoveryReviewClaimForOwnership(
                testing.allocator,
                .{
                    .claim_sha256 = claim.digest_sha256,
                    .outer_attempt_id = claim.outer_attempt_id,
                    .expected_marker_sha256 = null,
                    .expected_record_sha256 = null,
                    .replacement_marker = replacement,
                    .owner_publish_observer = observer.interface(),
                },
            ),
        );

        const reopened = Store.init(.init(testing.io, tmp.dir));
        const retained_claim =
            try reopened.readRecoveryReviewClaim(testing.allocator);
        const retained_owner =
            try reopened.readDeferredAcknowledgment(testing.allocator);
        switch (fail_at) {
            .before_stage_sync,
            .after_stage_sync,
            .before_rename,
            => {
                try testing.expect(retained_claim != null);
                try testing.expect(retained_owner == null);
            },
            .after_rename,
            .before_directory_sync,
            .after_directory_sync,
            => {
                try testing.expect(retained_claim == null);
                try testing.expectEqualDeep(transferred, retained_owner.?);
            },
        }

        try reopened.exchangeRecoveryReviewClaimForOwnership(
            testing.allocator,
            .{
                .claim_sha256 = claim.digest_sha256,
                .outer_attempt_id = claim.outer_attempt_id,
                .expected_marker_sha256 = null,
                .expected_record_sha256 = null,
                .replacement_marker = replacement,
            },
        );
        try testing.expect(
            (try reopened.readRecoveryReviewClaim(testing.allocator)) == null,
        );
        try testing.expectEqualDeep(
            transferred,
            (try reopened.readDeferredAcknowledgment(testing.allocator)).?,
        );
    }
}

test "root_operation.test.recovery review cancellation restores the exact prior owner" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const store = Store.init(.init(testing.io, tmp.dir));
    try store.ensureNamespace();
    const prior = try createDeferredAcknowledgment(.{
        .state = .pending,
        .attempt_id = @splat(0xc1),
        .completion_sha256 = @splat(0xc2),
        .provenance_sha256 = @splat(0xc3),
        .acknowledgment_id = @splat(0xc4),
    });
    try store.publishDeferredAcknowledgment(testing.allocator, prior);
    const claim = try createRecoveryReviewClaim(.{
        .outer_attempt_id = prior.acknowledgment_id,
        .outer_generation = 10,
        .outer_state_sha256 = @splat(0xc5),
        .profile_sha256 = @splat(0xc6),
        .profile_reference_sha256 = @splat(0xc7),
        .exact_lock_sha256 = @splat(0xc8),
        .semantic_request_sha256 = @splat(0xc9),
        .mutation_status = .changed,
        .nonce = @splat(0xca),
        .marker_sha256 = prior.digest_sha256,
        .prior_marker = prior,
        .record_sha256 = @splat(0xcb),
    });
    try store.publishRecoveryReviewClaim(testing.allocator, claim);
    try testing.expectEqualDeep(
        prior,
        (try store.readDeferredAcknowledgment(testing.allocator)).?,
    );
    try testing.expectError(
        error.RecoveryReviewClaimPresent,
        store.acknowledgeDeferredAcknowledgment(
            testing.allocator,
            prior.digest_sha256,
        ),
    );
    try testing.expectError(
        error.RecoveryReviewClaimPresent,
        store.clearDeferredAcknowledgment(
            testing.allocator,
            prior.digest_sha256,
        ),
    );
    try testing.expectError(
        error.RecoveryReviewClaimMismatch,
        store.clearRecoveryReviewClaim(
            testing.allocator,
            @splat(0xff),
        ),
    );
    try testing.expect(
        (try store.readRecoveryReviewClaim(testing.allocator)) != null,
    );
    try store.clearRecoveryReviewClaim(
        testing.allocator,
        claim.digest_sha256,
    );
    try testing.expect(
        (try store.readRecoveryReviewClaim(testing.allocator)) == null,
    );
    try testing.expectEqualDeep(
        prior,
        (try store.readDeferredAcknowledgment(testing.allocator)).?,
    );
}

test "root_operation.test.deferred acknowledgment v2 is canonical bounded and tamper evident" {
    const marker = try createDeferredAcknowledgment(.{
        .attempt_id = @splat(0xd1),
        .acknowledgment_id = @splat(0xd2),
        .recovery_review_claim_sha256 = @splat(0xd3),
    });
    try testing.expectEqual(
        deferred_ack_v2_schema_version,
        marker.document_version,
    );
    const source = try marker.canonicalJson(testing.allocator);
    defer testing.allocator.free(source);
    try testing.expect(source.len <= maximum_document_bytes);
    try testing.expect(
        documentHasSchema(source, deferred_ack_v2_schema_id),
    );
    const decoded = try decodeDeferredAcknowledgment(
        testing.allocator,
        source,
    );
    try testing.expectEqualDeep(marker, decoded);

    const tampered = try testing.allocator.dupe(u8, source);
    defer testing.allocator.free(tampered);
    const binding = std.mem.indexOf(
        u8,
        tampered,
        "\"recovery_review_binding_sha256\":\"",
    ).?;
    tampered[binding + "\"recovery_review_binding_sha256\":\"".len] =
        if (tampered[binding + "\"recovery_review_binding_sha256\":\"".len] == '0')
            '1'
        else
            '0';
    try testing.expectError(
        error.InvalidDocument,
        decodeDeferredAcknowledgment(testing.allocator, tampered),
    );

    const v1_with_v2_fields =
        "{\"schema\":\"https://debz.dev/schema/root-operation-deferred-ack-v1\",\"version\":1,\"state\":\"bound\",\"attempt_id\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"completion_sha256\":null,\"provenance_sha256\":null,\"acknowledgment_id\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"recovery_review_claim_sha256\":null,\"recovery_review_binding_sha256\":null,\"digest_sha256\":\"9ebc1e5a301ad8861e813b590c60e96e18728b38a32fb5e6e2a8cf5a80b64db7\"}";
    try testing.expectError(
        error.NonCanonicalDocument,
        decodeDeferredAcknowledgment(
            testing.allocator,
            v1_with_v2_fields,
        ),
    );
}

test "root_operation.test.records reject contradictory lifecycle combinations" {
    var mutating = testInput();
    mutating.state = .mutating;
    mutating.phase = .mutation;
    try testing.expectError(error.InvalidMutationEvidence, create(testing.allocator, mutating));

    var reserved_mutation = testInput();
    reserved_mutation.mutation_started = true;
    try testing.expectError(
        error.InvalidMutationEvidence,
        create(testing.allocator, reserved_mutation),
    );

    var wrong_phase = testInput();
    wrong_phase.phase = .database;
    try testing.expectError(error.InvalidPhase, create(testing.allocator, wrong_phase));

    var pending_completion = testInput();
    pending_completion.state = .completed;
    pending_completion.phase = .provenance;
    try testing.expectError(error.InvalidOutcome, create(testing.allocator, pending_completion));

    var published_without_digest = testInput();
    published_without_digest.state = .completed;
    published_without_digest.phase = .provenance;
    published_without_digest.outcome = .abandoned_before_mutation;
    published_without_digest.provenance = .published;
    try testing.expectError(
        error.InvalidProvenance,
        create(testing.allocator, published_without_digest),
    );

    var relative_root = testInput();
    relative_root.install_root = "target";
    try testing.expectError(error.InvalidRoot, create(testing.allocator, relative_root));

    var zero_generation = testInput();
    zero_generation.generation = 0;
    try testing.expectError(error.InvalidGeneration, create(testing.allocator, zero_generation));

    var duplicate = testInput();
    duplicate.foreign_architectures = &.{ "i386", "i386" };
    try testing.expectError(error.DuplicateArchitecture, create(testing.allocator, duplicate));

    var shadowed = testInput();
    shadowed.foreign_architectures = &.{"amd64"};
    try testing.expectError(error.DuplicateArchitecture, create(testing.allocator, shadowed));

    var invalid_architecture = testInput();
    invalid_architecture.target_architecture = "AMD64";
    try testing.expectError(
        error.InvalidArchitecture,
        create(testing.allocator, invalid_architecture),
    );

    // The lock schema is the one record string a caller supplies verbatim, and
    // the record is canonical JSON: text that is not valid UTF-8 has no JSON
    // spelling, so a record carrying it could never be decoded again. Every
    // way UTF-8 can be malformed is refused before the record exists.
    for ([_][]const u8{
        "\x80",
        "\xc0\xaf",
        "\xed\xa0\x80",
        "\xf5\x80\x80\x80",
        "\xe2\x82",
    }) |schema| {
        var unencodable = testInput();
        unencodable.evidence = .{
            .plan_sha256 = @splat(0x33),
            .exact_lock = .{ .schema = schema, .version = 1, .digest_sha256 = @splat(0x77) },
        };
        try testing.expectError(
            error.InvalidLockBinding,
            create(testing.allocator, unencodable),
        );
    }
}

test "root_operation.test.reserving publishes durable pre-mutation evidence" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var attempt = try coordinator.acquire(testing.allocator, packageRequest());
    defer attempt.release();
    try testing.expectEqual(State.reserved, attempt.record().state);
    try testing.expectEqual(Phase.reserved, attempt.record().phase);
    try testing.expect(!attempt.record().mutation_started);
    try testing.expectEqual(@as(u64, 1), attempt.record().generation);
    try testing.expect(attempt.locked());

    var persisted = (try coordinator.inspect(testing.allocator)).?;
    defer persisted.deinit();
    try testing.expectEqualSlices(
        u8,
        &attempt.record().digest_sha256,
        &persisted.record.digest_sha256,
    );

    const metadata = try coordinator.root.metadata(try root_fs.Path.init(record_path));
    try testing.expect(metadata.isRegularFile());
    if (builtin.os.tag != .windows)
        try testing.expectEqual(@as(std.posix.mode_t, 0o600), metadata.permissions.toMode() & 0o7777);
}

test "root_operation.test.a second product mutation is refused while an attempt is active" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var first = try coordinator.acquire(testing.allocator, packageRequest());
    defer first.release();

    var second = testRequest(.{ .package_transaction = .remove });
    second.attempt_id = @splat(0x55);
    try testing.expectError(
        error.LockTimeout,
        coordinator.acquire(testing.allocator, second),
    );
}

test "root_operation.test.repository bootstrap and package transactions share one root lock" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var package_coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);
    var repository_coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var repository = try repository_coordinator.acquire(testing.allocator, repositoryRequest());
    try testing.expectError(
        error.LockTimeout,
        package_coordinator.acquire(testing.allocator, packageRequest()),
    );

    // A repository attempt that never mutated still blocks an unqualified
    // second mutation once the lock is released.
    repository.release();
    try testing.expectError(
        error.OperationInProgress,
        package_coordinator.acquire(testing.allocator, packageRequest()),
    );
}

test "root_operation.test.the same root reached through two spellings serializes" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();

    var first_coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);
    var alias_dir = try tmp.dir.openDir(testing.io, ".", .{ .iterate = true });
    defer alias_dir.close(testing.io);
    var alias_coordinator = try Coordinator.open(
        testing.io,
        .init(testing.io, alias_dir),
        test_root,
        locks.interface(),
    );
    alias_coordinator.now_unix = 1_700_000_000;
    try testing.expectEqual(first_coordinator.identity.inode, alias_coordinator.identity.inode);

    var attempt = try first_coordinator.acquire(testing.allocator, packageRequest());
    defer attempt.release();
    try testing.expectError(
        error.LockTimeout,
        alias_coordinator.acquire(testing.allocator, packageRequest()),
    );
}

test "root_operation.test.a record written for another root fails closed" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var foreign = testInput();
    foreign.install_root = test_other_root;
    var created = try create(testing.allocator, foreign);
    defer created.deinit();
    try coordinator.store().writeAtomic(testing.allocator, created.record);

    try testing.expectError(
        error.RootIdentityMismatch,
        coordinator.acquire(testing.allocator, packageRequest()),
    );
}

test "root_operation.test.different roots proceed independently" {
    var first_tmp = testing.tmpDir(.{ .iterate = true });
    defer first_tmp.cleanup();
    var second_tmp = testing.tmpDir(.{ .iterate = true });
    defer second_tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var first_coordinator = try openTestCoordinator(&first_tmp, locks.interface(), test_root);
    var second_coordinator = try openTestCoordinator(
        &second_tmp,
        locks.interface(),
        test_other_root,
    );

    var first = try first_coordinator.acquire(testing.allocator, packageRequest());
    defer first.release();
    var second = try second_coordinator.acquire(testing.allocator, packageRequest());
    defer second.release();
    try testing.expect(first.locked());
    try testing.expect(second.locked());
}

test "root_operation.test.an attempt abandoned before mutation is explicitly reclaimable" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var interrupted = try coordinator.acquire(testing.allocator, packageRequest());
    try interrupted.advance(testing.allocator, .{ .state = .preflight, .phase = .authorization });
    // Power loss: the lock disappears with the process, the record stays.
    interrupted.release();

    try testing.expectError(
        error.OperationInProgress,
        coordinator.acquire(testing.allocator, packageRequest()),
    );

    var request = packageRequest();
    request.existing = .reclaim_resolved;
    request.attempt_id = @splat(0x66);
    var reclaimed = try coordinator.acquire(testing.allocator, request);
    defer reclaimed.release();
    try testing.expectEqual(State.reserved, reclaimed.record().state);
    try testing.expectEqual(@as(u64, 3), reclaimed.record().generation);
    try testing.expectEqualSlices(u8, &@as([32]u8, @splat(0x66)), &reclaimed.record().attempt_id);
}

test "root_operation.test.mutation evidence requires recovery and blocks a second mutation" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var interrupted = try coordinator.acquire(testing.allocator, packageRequest());
    try interrupted.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight });
    try interrupted.markMutationStarted(testing.allocator, .mutation);
    try testing.expect(interrupted.record().mutation_started);
    interrupted.release();

    var request = packageRequest();
    request.existing = .reclaim_resolved;
    try testing.expectError(
        error.RecoveryRequired,
        coordinator.acquire(testing.allocator, request),
    );

    var recovery = packageRequest();
    recovery.intent = .recovery;
    var recovered = try coordinator.acquire(testing.allocator, recovery);
    try testing.expect(recovered.adopted);
    try testing.expectEqual(State.mutating, recovered.record().state);
    try recovered.advance(testing.allocator, .{
        .state = .recovery_required,
        .phase = .database,
    });
    try recovered.advance(testing.allocator, .{ .state = .recovering, .phase = .database });
    try recovered.complete(testing.allocator, .recovered);
    try testing.expectEqual(ProvenanceState.pending, recovered.record().provenance);
    try testing.expectError(error.ProvenanceRequired, recovered.clear());
    try recovered.publishProvenance(testing.allocator, @splat(0xab));
    try recovered.clear();
    recovered.release();

    var next = try coordinator.acquire(testing.allocator, packageRequest());
    defer next.release();
    try testing.expectEqual(State.reserved, next.record().state);
    try testing.expectEqual(@as(u64, 1), next.record().generation);
}

test "root_operation.test.crash at every durable boundary keeps the next mutation blocked" {
    const boundaries = [_]Transition{
        .{ .state = .preflight, .phase = .authorization },
        .{ .state = .preflight, .phase = .preflight },
        .{ .state = .mutation_pending, .phase = .mutation },
        .{ .state = .mutating, .phase = .mutation },
        .{ .state = .mutating, .phase = .script },
        .{ .state = .mutating, .phase = .trigger },
        .{ .state = .mutating, .phase = .database },
        .{ .state = .verifying, .phase = .verification },
    };
    for (0..boundaries.len) |index| {
        var tmp = testing.tmpDir(.{ .iterate = true });
        defer tmp.cleanup();
        var locks: TestLockBackend = .{ .allocator = testing.allocator };
        defer locks.deinit();
        var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

        var attempt = try coordinator.acquire(testing.allocator, packageRequest());
        for (boundaries[0 .. index + 1]) |transition| {
            attempt.advance(testing.allocator, transition) catch |err| switch (err) {
                error.InvalidTransition => continue,
                else => return err,
            };
        }
        const state = attempt.record().state;
        const mutation_started = attempt.record().mutation_started;
        attempt.release();

        var request = packageRequest();
        request.existing = .reclaim_resolved;
        if (state.blocksMutation()) {
            try testing.expectError(
                error.RecoveryRequired,
                coordinator.acquire(testing.allocator, request),
            );
            var recovery = packageRequest();
            recovery.intent = .recovery;
            var resumed = try coordinator.acquire(testing.allocator, recovery);
            try testing.expectEqual(state, resumed.record().state);
            resumed.release();
        } else {
            try testing.expect(!mutation_started);
            var reclaimed = try coordinator.acquire(testing.allocator, request);
            try testing.expectEqual(State.reserved, reclaimed.record().state);
            reclaimed.release();
        }
    }
}

test "root_operation.test.a stale writer cannot overwrite newer evidence" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var attempt = try coordinator.acquire(testing.allocator, packageRequest());
    defer attempt.release();

    var newer = testInput();
    newer.generation = 9;
    newer.state = .preflight;
    newer.phase = .preflight;
    newer.step = 4;
    var published = try create(testing.allocator, newer);
    defer published.deinit();
    try coordinator.store().writeAtomic(testing.allocator, published.record);

    try testing.expectError(
        error.StaleAttempt,
        attempt.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight }),
    );

    try coordinator.store().clear();
    try testing.expectError(
        error.NoActiveAttempt,
        attempt.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight }),
    );
}

test "root_operation.test.transitions are monotonic and idempotent" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var attempt = try coordinator.acquire(testing.allocator, packageRequest());
    defer attempt.release();
    try attempt.advance(testing.allocator, .{
        .state = .preflight,
        .phase = .authorization,
        .step = 1,
    });
    const generation = attempt.record().generation;
    // Replaying the exact published boundary after a crash is a success.
    try attempt.advance(testing.allocator, .{
        .state = .preflight,
        .phase = .authorization,
        .step = 1,
    });
    try testing.expectEqual(generation, attempt.record().generation);

    try testing.expectError(error.InvalidTransition, attempt.advance(testing.allocator, .{
        .state = .reserved,
        .phase = .reserved,
    }));
    try testing.expectError(error.InvalidTransition, attempt.advance(testing.allocator, .{
        .state = .preflight,
        .phase = .preflight,
        .step = 0,
    }));
    try testing.expectError(error.InvalidTransition, attempt.advance(testing.allocator, .{
        .state = .recovering,
        .phase = .database,
    }));
    try testing.expectError(
        error.MutationEvidenceRequired,
        attempt.requireRecovery(testing.allocator, .mutation),
    );

    try attempt.markMutationStarted(testing.allocator, .mutation);
    try testing.expectError(error.InvalidTransition, attempt.advance(testing.allocator, .{
        .state = .preflight,
        .phase = .preflight,
    }));
    try testing.expect(attempt.record().mutation_started);
}

test "root_operation.test.evidence is write-once" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var attempt = try coordinator.acquire(testing.allocator, packageRequest());
    defer attempt.release();
    try attempt.advance(testing.allocator, .{
        .state = .preflight,
        .phase = .authorization,
        .evidence = .{ .authorization_sha256 = @splat(0xcd) },
    });
    try attempt.advance(testing.allocator, .{
        .state = .preflight,
        .phase = .preflight,
        .evidence = .{ .authorization_sha256 = @splat(0xcd) },
    });
    try testing.expectError(error.InvalidTransition, attempt.advance(testing.allocator, .{
        .state = .mutation_pending,
        .phase = .mutation,
        .evidence = .{ .authorization_sha256 = @splat(0xce) },
    }));
    try testing.expectEqualSlices(
        u8,
        &@as([32]u8, @splat(0xcd)),
        &attempt.record().authorization_sha256.?,
    );
}

test "root_operation.test.the legacy bridge resolves pending mutation from an explicit witness" {
    for ([_]Witness{ .proved_not_started, .mutation_observed }) |observed| {
        var tmp = testing.tmpDir(.{ .iterate = true });
        defer tmp.cleanup();
        var locks: TestLockBackend = .{ .allocator = testing.allocator };
        defer locks.deinit();
        var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

        var attempt = try coordinator.acquire(testing.allocator, packageRequest());
        try testing.expectEqual(BridgeOrigin.none, attempt.bridgeOrigin());
        try attempt.advance(testing.allocator, .{
            .state = .mutation_pending,
            .phase = .mutation,
        });
        // A pending bridge is never treated as safely abandoned.
        try testing.expect(attempt.record().state.blocksMutation());
        try testing.expect(!attempt.record().mutation_started);
        // This invocation performed the hand-over, so its own executor's
        // evidence is the evidence about it and is applied as reported.
        try testing.expectEqual(BridgeOrigin.published_here, attempt.bridgeOrigin());
        try testing.expectEqual(observed, attempt.effectiveWitness(observed));
        try testing.expectEqual(observed, try attempt.witness(testing.allocator, observed));
        switch (observed) {
            .proved_not_started => {
                try testing.expectEqual(State.completed, attempt.record().state);
                try testing.expectEqual(
                    Outcome.abandoned_before_mutation,
                    attempt.record().outcome,
                );
                try testing.expectEqual(
                    ProvenanceState.not_required,
                    attempt.record().provenance,
                );
                try attempt.clear();
            },
            .mutation_observed => {
                try testing.expectEqual(State.mutating, attempt.record().state);
                try testing.expect(attempt.record().mutation_started);
                try testing.expectError(error.InvalidTransition, attempt.clear());
            },
        }
        attempt.release();
    }
}

test "root_operation.test.an inherited bridge is never discharged by this run's evidence" {
    // A rerun of the same operation, and an explicit recovery, may adopt a
    // record an earlier run left at the executor bridge. That run handed
    // control to an engine that may already have mutated the root and never
    // came back, so nothing this run's executor reports is evidence about it.
    // Before the bridge's origin was tracked, this run's own pre-spawn failure
    // — an expired deadline, a refused preflight, a lock it could not take, a
    // journal it could not decode — reported `not_started` with no commands,
    // discharged the inherited bridge as proved-not-started, and cleared the
    // only record that was blocking the root.
    for ([_]Intent{ .same_operation, .recovery }) |intent| {
        var tmp = testing.tmpDir(.{ .iterate = true });
        defer tmp.cleanup();
        var locks: TestLockBackend = .{ .allocator = testing.allocator };
        defer locks.deinit();
        var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

        var stranded = try coordinator.acquire(testing.allocator, repositoryRequest());
        try stranded.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight });
        try stranded.advance(testing.allocator, .{
            .state = .mutation_pending,
            .phase = .mutation,
        });
        // Power loss between the hand-over and any witness.
        stranded.release();

        var request = repositoryRequest();
        request.intent = intent;
        request.existing = .reclaim_resolved;
        var resumed = try coordinator.acquire(testing.allocator, request);
        try testing.expect(resumed.adopted);
        try testing.expectEqual(State.mutation_pending, resumed.record().state);
        try testing.expectEqual(BridgeOrigin.inherited, resumed.bridgeOrigin());
        try testing.expectEqual(
            Witness.mutation_observed,
            resumed.effectiveWitness(.proved_not_started),
        );

        // The coercion lives in the attempt, so an observation site that
        // faithfully passes the witness its own executor justified still
        // cannot discharge another run's hand-over.
        try testing.expectEqual(
            Witness.mutation_observed,
            try resumed.witness(testing.allocator, .proved_not_started),
        );
        try testing.expectEqual(State.mutating, resumed.record().state);
        try testing.expect(resumed.record().mutation_started);
        try testing.expect(!resumed.record().clearable());
        try testing.expectError(
            error.MutationEvidenceRequired,
            resumed.abandonIfPreMutation(testing.allocator),
        );
        try testing.expectError(error.InvalidTransition, resumed.clear());
        try resumed.requireRecovery(testing.allocator, .mutation);
        resumed.release();

        // The record still blocks the root and still owes its provenance:
        // nothing about the inherited hand-over was waived.
        var observed = (try coordinator.inspect(testing.allocator)).?;
        defer observed.deinit();
        try testing.expectEqual(State.recovery_required, observed.record.state);
        try testing.expect(observed.record.state.blocksMutation());
        try testing.expect(observed.record.mutation_started);
        try testing.expectEqual(ProvenanceState.pending, observed.record.provenance);
        try testing.expectEqual(Outcome.pending, observed.record.outcome);
        try testing.expect(!observed.record.clearable());
        try testing.expectError(
            error.RecoveryRequired,
            coordinator.acquire(testing.allocator, packageRequest()),
        );
    }
}

test "root_operation.test.a bridge published by this run still clears on proven no-start" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    // The earlier run stopped before the hand-over, which is durable proof
    // that it mutated nothing.
    var interrupted = try coordinator.acquire(testing.allocator, repositoryRequest());
    try interrupted.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight });
    interrupted.release();

    var request = repositoryRequest();
    request.intent = .same_operation;
    request.existing = .reclaim_resolved;
    var resumed = try coordinator.acquire(testing.allocator, request);
    try testing.expect(resumed.adopted);
    try testing.expectEqual(BridgeOrigin.none, resumed.bridgeOrigin());

    // This run performs the hand-over itself, so this run's executor evidence
    // really is evidence about it and the root is released rather than blocked.
    try resumed.advance(testing.allocator, .{ .state = .mutation_pending, .phase = .mutation });
    try testing.expectEqual(BridgeOrigin.published_here, resumed.bridgeOrigin());
    try testing.expectEqual(
        Witness.proved_not_started,
        try resumed.witness(testing.allocator, .proved_not_started),
    );
    try testing.expectEqual(Outcome.abandoned_before_mutation, resumed.record().outcome);
    try testing.expectEqual(ProvenanceState.not_required, resumed.record().provenance);
    try resumed.clear();
    resumed.release();
    try testing.expect((try coordinator.inspect(testing.allocator)) == null);
}

test "root_operation.test.a settled record is reclaimed as a new attempt, never adopted" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    // A bootstrap that ran to the end and crashed between publishing its
    // provenance and clearing the intent. The record is durable evidence that
    // the operation is over.
    var first = try coordinator.acquire(testing.allocator, repositoryRequest());
    try first.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight });
    try first.advance(testing.allocator, .{ .state = .mutation_pending, .phase = .mutation });
    _ = try first.witness(testing.allocator, .mutation_observed);
    try first.advance(testing.allocator, .{ .state = .verifying, .phase = .verification });
    try first.complete(testing.allocator, .succeeded);
    try first.publishProvenance(testing.allocator, @splat(0xab));
    const settled = first.record();
    try testing.expect(settled.clearable());
    first.release();

    // Adopting it would let the rerun mutate the root under a record that
    // already says the mutation finished, so the rerun reserves its own
    // attempt instead.
    var request = repositoryRequest();
    request.intent = .same_operation;
    request.existing = .reclaim_resolved;
    request.attempt_id = @splat(0x6b);
    var rerun = try coordinator.acquire(testing.allocator, request);
    try testing.expect(!rerun.adopted);
    try testing.expectEqual(State.reserved, rerun.record().state);
    try testing.expectEqual(Phase.reserved, rerun.record().phase);
    try testing.expectEqual(BridgeOrigin.none, rerun.bridgeOrigin());
    try testing.expectEqual(Outcome.pending, rerun.record().outcome);
    try testing.expectEqual(ProvenanceState.pending, rerun.record().provenance);
    try testing.expect(!rerun.record().mutation_started);
    // A fresh identifier and a strictly higher generation, so the settled
    // attempt's evidence can never be confused with the rerun's and a stale
    // writer still loses the compare-and-set.
    try testing.expectEqualSlices(u8, &@as([32]u8, @splat(0x6b)), &rerun.attemptId());
    try testing.expect(!std.mem.eql(u8, &settled.attempt_id, &rerun.attemptId()));
    try testing.expectEqual(settled.generation + 1, rerun.record().generation);

    // While the rerun is active nothing else may mutate this root.
    var alias_dir = try tmp.dir.openDir(testing.io, ".", .{ .iterate = true });
    defer alias_dir.close(testing.io);
    var other_coordinator = try Coordinator.open(
        testing.io,
        .init(testing.io, alias_dir),
        test_root,
        locks.interface(),
    );
    other_coordinator.now_unix = 1_700_000_000;
    try testing.expectError(
        error.LockTimeout,
        other_coordinator.acquire(testing.allocator, packageRequest()),
    );

    // Crash after the fresh reserve: the rerun's own record is what the next
    // package mutation reports, rather than the settled one it replaced.
    rerun.release();
    try testing.expectError(
        error.OperationInProgress,
        coordinator.acquire(testing.allocator, packageRequest()),
    );
    var observed = (try coordinator.inspect(testing.allocator)).?;
    defer observed.deinit();
    try testing.expectEqual(State.reserved, observed.record.state);
    try testing.expectEqualSlices(u8, &@as([32]u8, @splat(0x6b)), &observed.record.attempt_id);
}

test "root_operation.test.settled evidence stays reportable for every intent" {
    // Whether the settled record binds this very operation or an unrelated
    // one, it is never adopted. `reclaim_resolved` takes the root over with a
    // new attempt; `fail` reports it instead of silently continuing under it.
    const operations = [_]Operation{
        .{ .repository_bootstrap = .add },
        .{ .package_transaction = .install },
    };
    for (operations) |settled_operation| {
        for ([_]Intent{ .mutation, .same_operation, .recovery }) |intent| {
            var tmp = testing.tmpDir(.{ .iterate = true });
            defer tmp.cleanup();
            var locks: TestLockBackend = .{ .allocator = testing.allocator };
            defer locks.deinit();
            var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

            var input = testInput();
            input.operation = settled_operation;
            input.generation = 7;
            input.state = .completed;
            input.phase = .provenance;
            input.step = 5;
            input.mutation_started = true;
            input.outcome = .succeeded;
            input.provenance = .published;
            input.provenance_sha256 = @splat(0xcd);
            var staged = try create(testing.allocator, input);
            defer staged.deinit();
            try testing.expect(staged.record.clearable());
            try coordinator.store().writeAtomic(testing.allocator, staged.record);

            var reported = repositoryRequest();
            reported.intent = intent;
            try testing.expectError(
                error.ResolvedAttemptPresent,
                coordinator.acquire(testing.allocator, reported),
            );

            var request = repositoryRequest();
            request.intent = intent;
            request.existing = .reclaim_resolved;
            request.attempt_id = @splat(0x6c);
            var reclaimed = try coordinator.acquire(testing.allocator, request);
            defer reclaimed.release();
            try testing.expect(!reclaimed.adopted);
            try testing.expectEqual(BridgeOrigin.none, reclaimed.bridgeOrigin());
            // A recovery still starts at its own pre-mutation boundary; every
            // other intent reserves.
            try testing.expectEqual(
                @as(State, if (intent == .recovery) .preflight else .reserved),
                reclaimed.record().state,
            );
            try testing.expectEqual(@as(u64, 8), reclaimed.record().generation);
            try testing.expectEqualSlices(
                u8,
                &@as([32]u8, @splat(0x6c)),
                &reclaimed.attemptId(),
            );
            try testing.expectEqual(Outcome.pending, reclaimed.record().outcome);
            try testing.expect(!reclaimed.record().mutation_started);
        }
    }
}

test "root_operation.test.recovery reserves a bridge record when no evidence exists" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var request = testRequest(.{ .package_transaction = .recover });
    request.intent = .recovery;
    var attempt = try coordinator.acquire(testing.allocator, request);
    defer attempt.release();
    try testing.expect(!attempt.adopted);
    // A recovery that finds nothing starts pre-mutation, so giving up before
    // the executor never strands a healthy root.
    try testing.expectEqual(State.preflight, attempt.record().state);
    try testing.expect(attempt.record().state.provenPreMutation());
    try attempt.advance(testing.allocator, .{ .state = .mutation_pending, .phase = .mutation });
    try testing.expectError(
        error.MutationEvidenceRequired,
        attempt.complete(testing.allocator, .abandoned_before_mutation),
    );
    try testing.expectEqual(
        Witness.proved_not_started,
        try attempt.witness(testing.allocator, .proved_not_started),
    );
    try attempt.clear();
    try testing.expect((try coordinator.inspect(testing.allocator)) == null);
}

test "root_operation.test.the witness never trusts a command count alone" {
    // Every state but `not_started` is durable evidence that control already
    // reached dpkg, so only an empty command list on a `not_started`
    // transaction may be called safely abandoned. A success-shaped report with
    // no commands is still a mutation, and a command list is always evidence.
    const cases = [_]struct {
        state: transaction_recovery.State,
        expected: Witness,
    }{
        .{ .state = .not_started, .expected = .proved_not_started },
        .{ .state = .in_progress, .expected = .mutation_observed },
        .{ .state = .dpkg_failed, .expected = .mutation_observed },
        .{ .state = .interrupted, .expected = .mutation_observed },
        .{ .state = .verification_failed, .expected = .mutation_observed },
        .{ .state = .complete, .expected = .mutation_observed },
    };
    for (cases) |case| {
        try testing.expectEqual(case.expected, observedMutation(case.state, 0));
        // A command that did complete is unconditional evidence.
        try testing.expectEqual(Witness.mutation_observed, observedMutation(case.state, 1));

        const arena = try testing.allocator.create(std.heap.ArenaAllocator);
        arena.* = .init(testing.allocator);
        var report: transaction_executor.Report = .{
            .allocator = testing.allocator,
            .arena = arena,
            .commands = &.{},
            .plan_sha256 = @splat(0),
            .transaction_state = case.state,
            .root_identity = @splat(0),
            .policy_sha256 = @splat(0),
            .lock_sha256 = null,
            .failure = null,
        };
        defer report.deinit();
        try testing.expectEqual(case.expected, reportWitness(report));

        const recovery_arena = try testing.allocator.create(std.heap.ArenaAllocator);
        recovery_arena.* = .init(testing.allocator);
        var recovery_report: transaction_executor.RecoveryReport = .{
            .allocator = testing.allocator,
            .arena = recovery_arena,
            .state = case.state,
            .commands = &.{},
            .plan_sha256 = @splat(0),
            .root_identity = @splat(0),
            .policy_sha256 = @splat(0),
            .lock_sha256 = null,
            .failure = null,
        };
        defer recovery_report.deinit();
        try testing.expectEqual(case.expected, recoveryReportWitness(recovery_report));
    }
}

test "root_operation.test.a recovery that cannot read its journal never proves no start" {
    // The recovery report only carries a transaction state once the journal
    // has been decoded. A journal that cannot be loaded, or that loads and
    // cannot be decoded, therefore reports `not_started` with no commands
    // while a durable journal — the very evidence recovery exists to resolve —
    // says an earlier transaction already reached this root. Only a recovery
    // that found no journal at all really proves that nothing started.
    const cases = [_]struct {
        code: transaction_executor.FailureCode,
        expected: Witness,
    }{
        .{ .code = .journal_io, .expected = .mutation_observed },
        .{ .code = .journal_corrupt, .expected = .mutation_observed },
        .{ .code = .journal_missing, .expected = .proved_not_started },
        .{ .code = .lock_timeout, .expected = .proved_not_started },
        .{ .code = .invalid_root, .expected = .proved_not_started },
    };
    for (cases) |case| {
        const arena = try testing.allocator.create(std.heap.ArenaAllocator);
        arena.* = .init(testing.allocator);
        var report: transaction_executor.RecoveryReport = .{
            .allocator = testing.allocator,
            .arena = arena,
            .state = .not_started,
            .commands = &.{},
            .plan_sha256 = @splat(0),
            .root_identity = @splat(0),
            .policy_sha256 = @splat(0),
            .lock_sha256 = null,
            .failure = .{ .code = case.code, .diagnostic = "injected" },
        };
        defer report.deinit();
        try testing.expectEqual(case.expected, recoveryReportWitness(report));
        // Whatever the failure code says, none of it may discharge a bridge
        // this run did not publish.
        try testing.expectEqual(
            Witness.mutation_observed,
            witnessForBridge(.inherited, recoveryReportWitness(report)),
        );
    }
}

test "root_operation.test.an unwitnessed hand-over is never cleared as abandoned" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    // The executor returned no report at all, which is what an allocation
    // failure or a propagated error inside the engine looks like.
    var attempt = try coordinator.acquire(testing.allocator, packageRequest());
    try attempt.advance(testing.allocator, .{ .state = .mutation_pending, .phase = .mutation });
    try testing.expect(!attempt.record().state.provenPreMutation());
    try testing.expect(!attempt.record().clearable());
    try testing.expectError(
        error.MutationEvidenceRequired,
        attempt.abandonIfPreMutation(testing.allocator),
    );
    try testing.expectError(error.InvalidTransition, attempt.clear());
    attempt.release();

    // The evidence survives the guard tearing down, so the next mutation is
    // refused until it is explicitly recovered.
    try testing.expectError(
        error.RecoveryRequired,
        coordinator.acquire(testing.allocator, packageRequest()),
    );
    var leftover = (try coordinator.inspect(testing.allocator)).?;
    defer leftover.deinit();
    try testing.expectEqual(State.mutation_pending, leftover.record.state);
}

test "root_operation.test.only the same operation may adopt an unresolved attempt" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    // A bootstrap that mutated the root and then failed after the executor.
    var first = try coordinator.acquire(testing.allocator, repositoryRequest());
    try first.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight });
    try first.advance(testing.allocator, .{ .state = .mutation_pending, .phase = .mutation });
    _ = try first.witness(testing.allocator, .mutation_observed);
    try first.advance(testing.allocator, .{ .state = .verifying, .phase = .verification });
    const stranded = first.record();
    first.release();

    // A generic mutation intent is still refused: post-executor evidence is
    // never cleared just because someone asked for the root again.
    try testing.expectError(
        error.RecoveryRequired,
        coordinator.acquire(testing.allocator, repositoryRequest()),
    );

    // Neither a different surface, a different request, a different policy, a
    // different backend, nor a different architecture may adopt it, and none
    // of them overwrite the evidence.
    const mismatches = [_]Request{
        blk: {
            var request = packageRequest();
            request.intent = .same_operation;
            break :blk request;
        },
        blk: {
            var request = repositoryRequest();
            request.intent = .same_operation;
            request.request_sha256 = @splat(0x77);
            break :blk request;
        },
        blk: {
            var request = repositoryRequest();
            request.intent = .same_operation;
            request.policy_sha256 = @splat(0x78);
            break :blk request;
        },
        blk: {
            var request = repositoryRequest();
            request.intent = .same_operation;
            request.backend = .native;
            break :blk request;
        },
        blk: {
            var request = repositoryRequest();
            request.intent = .same_operation;
            request.target_architecture = "arm64";
            break :blk request;
        },
        blk: {
            var request = repositoryRequest();
            request.intent = .same_operation;
            request.foreign_architectures = &.{"i386"};
            break :blk request;
        },
        blk: {
            var request = repositoryRequest();
            request.intent = .same_operation;
            request.evidence = .{ .plan_sha256 = @splat(0x79) };
            break :blk request;
        },
    };
    for (mismatches) |request| {
        try testing.expectError(
            error.AttemptMismatch,
            coordinator.acquire(testing.allocator, request),
        );
        var observed = (try coordinator.inspect(testing.allocator)).?;
        defer observed.deinit();
        try testing.expectEqualSlices(
            u8,
            &stranded.digest_sha256,
            &observed.record.digest_sha256,
        );
    }

    // The same request adopts its own evidence, resumes through the durable
    // recovery edges, and only then discharges the intent.
    var resumed_request = repositoryRequest();
    resumed_request.intent = .same_operation;
    resumed_request.attempt_id = @splat(0x5a);
    var resumed = try coordinator.acquire(testing.allocator, resumed_request);
    try testing.expect(resumed.adopted);
    // The adopted attempt keeps the original identifier, so the evidence chain
    // is continuous rather than restarted.
    try testing.expectEqualSlices(u8, &stranded.attempt_id, &resumed.attemptId());
    try testing.expectEqual(State.verifying, resumed.record().state);
    try resumed.beginRecovery(testing.allocator, .verification);
    try resumed.complete(testing.allocator, .recovered);
    try resumed.publishProvenance(testing.allocator, @splat(0xab));
    try resumed.clear();
    resumed.release();
    try testing.expect((try coordinator.inspect(testing.allocator)) == null);
}

test "root_operation.test.same-operation adoption still reclaims a settled record" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    // A leftover pre-mutation record from an unrelated operation is durable
    // proof that nothing was touched, so a different request is not locked out
    // by it. Availability never comes at the price of evidence.
    var abandoned = try coordinator.acquire(testing.allocator, packageRequest());
    try abandoned.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight });
    abandoned.release();

    var request = repositoryRequest();
    request.intent = .same_operation;
    request.existing = .reclaim_resolved;
    request.attempt_id = @splat(0x61);
    var reclaimed = try coordinator.acquire(testing.allocator, request);
    defer reclaimed.release();
    try testing.expect(!reclaimed.adopted);
    try testing.expectEqual(State.reserved, reclaimed.record().state);
    // The generation keeps climbing, so a stale writer that resumed from the
    // reclaimed view still loses the compare-and-set.
    try testing.expectEqual(@as(u64, 3), reclaimed.record().generation);
}

test "root_operation.test.a stale same-operation writer cannot overwrite newer evidence" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var request = repositoryRequest();
    request.intent = .same_operation;
    var first = try coordinator.acquire(testing.allocator, request);
    try first.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight });
    try first.advance(testing.allocator, .{ .state = .mutation_pending, .phase = .mutation });
    first.release();

    // The rerun adopts the record and moves it forward.
    var second = try coordinator.acquire(testing.allocator, request);
    _ = try second.witness(testing.allocator, .mutation_observed);
    try second.advance(testing.allocator, .{ .state = .verifying, .phase = .verification });
    second.release();

    // A writer that still holds the older view is refused rather than allowed
    // to roll the attempt back to the bridge.
    var stale = try coordinator.acquire(testing.allocator, request);
    defer stale.release();
    stale.owned.record.generation -= 2;
    try testing.expectError(
        error.StaleAttempt,
        stale.advance(testing.allocator, .{ .state = .verifying, .phase = .verification }),
    );
}

test "root_operation.test.provenance is published before the active intent is cleared" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var attempt = try coordinator.acquire(testing.allocator, packageRequest());
    try attempt.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight });
    try attempt.markMutationStarted(testing.allocator, .mutation);
    try attempt.advance(testing.allocator, .{ .state = .mutating, .phase = .database });
    try attempt.advance(testing.allocator, .{ .state = .verifying, .phase = .verification });
    try attempt.complete(testing.allocator, .succeeded);
    try testing.expectError(error.ProvenanceRequired, attempt.clear());

    var owed = (try coordinator.inspect(testing.allocator)).?;
    defer owed.deinit();
    try testing.expect(!owed.record.clearable());

    try attempt.publishProvenance(testing.allocator, @splat(0xee));
    try testing.expect(attempt.record().clearable());
    try attempt.clear();
    attempt.release();
    try testing.expect((try coordinator.inspect(testing.allocator)) == null);
}

test "root_operation.test.an attempt that owes provenance blocks the next mutation" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var attempt = try coordinator.acquire(testing.allocator, packageRequest());
    try attempt.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight });
    try attempt.markMutationStarted(testing.allocator, .mutation);
    try attempt.advance(testing.allocator, .{ .state = .verifying, .phase = .verification });
    try attempt.complete(testing.allocator, .failed_after_mutation);
    attempt.release();

    var request = packageRequest();
    request.existing = .reclaim_resolved;
    try testing.expectError(
        error.ProvenancePending,
        coordinator.acquire(testing.allocator, request),
    );
}

test "root_operation.test.corrupt, truncated, symlinked, and special records fail closed" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);
    const path = try root_fs.Path.init(record_path);

    try coordinator.root.publishFile(path, "{\"schema\":", .{});
    try testing.expectError(
        error.RecordCorrupt,
        coordinator.acquire(testing.allocator, packageRequest()),
    );

    var valid = try create(testing.allocator, testInput());
    defer valid.deinit();
    const bytes = try valid.record.canonicalJson(testing.allocator);
    defer testing.allocator.free(bytes);
    try coordinator.root.publishFile(path, bytes[0 .. bytes.len - 8], .{});
    try testing.expectError(
        error.RecordCorrupt,
        coordinator.acquire(testing.allocator, packageRequest()),
    );

    try coordinator.root.removeFile(path);
    try coordinator.root.publishFile(
        try root_fs.Path.init(namespace_path ++ "/decoy.json"),
        bytes,
        .{},
    );
    try coordinator.root.createSymbolicLink(path, "decoy.json");
    try testing.expectError(
        error.RecordCorrupt,
        coordinator.acquire(testing.allocator, packageRequest()),
    );
    try coordinator.root.removeFile(path);

    try coordinator.root.createDirectory(path, root_fs.default_directory_permissions);
    try testing.expectError(
        error.RecordCorrupt,
        coordinator.acquire(testing.allocator, packageRequest()),
    );
    try coordinator.root.removeDirectory(path);

    const oversized = try testing.allocator.alloc(u8, maximum_document_bytes + 1);
    defer testing.allocator.free(oversized);
    @memset(oversized, ' ');
    try coordinator.root.publishFile(path, oversized, .{});
    try testing.expectError(
        error.RecordCorrupt,
        coordinator.acquire(testing.allocator, packageRequest()),
    );
}

test "root_operation.test.a symlinked namespace never becomes a root escape" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    const root: root_fs.Root = .init(testing.io, tmp.dir);
    try root.createDirectoryPath(
        try root_fs.Path.init("var/lib"),
        root_fs.default_directory_permissions,
    );
    try root.createDirectory(
        try root_fs.Path.init("elsewhere"),
        root_fs.default_directory_permissions,
    );
    try root.createSymbolicLink(try root_fs.Path.init(namespace_path), "../../elsewhere");
    try testing.expectError(
        error.NamespaceUnavailable,
        Coordinator.open(testing.io, root, test_root, locks.interface()),
    );
}

test "root_operation.test.lock timeout and cancellation stay typed" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    locks.fail_with = error.LockTimeout;
    try testing.expectError(
        error.LockTimeout,
        coordinator.acquire(testing.allocator, packageRequest()),
    );
    locks.fail_with = error.LockCanceled;
    try testing.expectError(
        error.LockCanceled,
        coordinator.acquire(testing.allocator, packageRequest()),
    );
    locks.fail_with = null;

    var cancelled: CancelledContext = .{};
    var request = packageRequest();
    request.cancellation = cancelled.interface();
    try testing.expectError(
        error.LockCanceled,
        coordinator.acquire(testing.allocator, request),
    );
    // A refused acquisition never publishes a record.
    try testing.expect((try coordinator.inspect(testing.allocator)) == null);
}

const CancelledContext = struct {
    fn interface(self: *CancelledContext) transaction_executor.Cancellation {
        return .{ .context = self, .cancelledFn = cancelled };
    }

    fn cancelled(_: *anyopaque) bool {
        return true;
    }
};

test "root_operation.test.the lock order is total and enforced" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var attempt = try coordinator.acquire(testing.allocator, packageRequest());
    defer attempt.release();
    try attempt.enterRank(.repository_operation);
    try attempt.enterRank(.transaction_state);
    try testing.expectError(error.LockOrderViolation, attempt.enterRank(.package_cache));
    try testing.expectError(error.LockOrderViolation, attempt.enterRank(.root_operation));
    try testing.expectError(error.LockOrderViolation, attempt.enterRank(.transaction_state));
    attempt.exitRank(.transaction_state);
    try attempt.enterRank(.package_cache);
    attempt.exitRank(.package_cache);
    attempt.exitRank(.repository_operation);
    // Rank 0 is already held by the attempt itself and is never re-entered.
    try testing.expectError(error.LockOrderViolation, attempt.enterRank(.root_operation));
}

test "root_operation.test.the production lock backend serializes one root" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var first_backend: SystemLockBackend = .{ .allocator = testing.allocator, .io = testing.io };
    var second_backend: SystemLockBackend = .{ .allocator = testing.allocator, .io = testing.io };
    var first_coordinator = try openTestCoordinator(&tmp, first_backend.interface(), test_root);
    var second_coordinator = try openTestCoordinator(&tmp, second_backend.interface(), test_root);

    var attempt = try first_coordinator.acquire(testing.allocator, packageRequest());
    try testing.expectError(
        error.LockTimeout,
        second_coordinator.acquire(testing.allocator, packageRequest()),
    );
    try attempt.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight });
    try attempt.complete(testing.allocator, .abandoned_before_mutation);
    try attempt.clear();
    attempt.release();

    var request = packageRequest();
    request.attempt_id = @splat(0x77);
    var second = try second_coordinator.acquire(testing.allocator, request);
    defer second.release();
    try testing.expect(second.locked());

    const metadata = try second_coordinator.root.metadata(try root_fs.Path.init(lock_path));
    try testing.expect(metadata.isRegularFile());
}

test "root_operation.test.allocation failure never leaks or half-publishes" {
    var input = testInput();
    input.foreign_architectures = &.{ "i386", "riscv64" };
    input.evidence = .{
        .plan_sha256 = @splat(0x33),
        .exact_lock = .{
            .schema = "https://debz.dev/schema/exact-closure-lock-v2",
            .version = 2,
            .digest_sha256 = @splat(0x77),
        },
    };
    var reference = try create(testing.allocator, input);
    defer reference.deinit();
    const bytes = try reference.record.canonicalJson(testing.allocator);
    defer testing.allocator.free(bytes);

    var index: usize = 0;
    while (index < 64) : (index += 1) {
        var failing: std.testing.FailingAllocator = .init(testing.allocator, .{
            .fail_index = index,
        });
        if (create(failing.allocator(), input)) |value| {
            var owned = value;
            owned.deinit();
        } else |err| try testing.expectEqual(error.OutOfMemory, err);

        var decoding: std.testing.FailingAllocator = .init(testing.allocator, .{
            .fail_index = index,
        });
        if (decode(decoding.allocator(), bytes, maximum_document_bytes)) |value| {
            var owned = value;
            owned.deinit();
        } else |err| switch (err) {
            error.OutOfMemory, error.NonCanonicalDocument => {},
            else => return err,
        }
    }
}

test "root_operation.test.tests never resolve the recorded root spelling" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    // The recorded spelling is evidence, not a path the coordinator opens: all
    // access goes through the injected root descriptor, so no test can reach
    // the host root even when it records `/target`.
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);
    var attempt = try coordinator.acquire(testing.allocator, packageRequest());
    defer attempt.release();
    try testing.expectEqualStrings(test_root, attempt.record().install_root);
    try testing.expect(
        (try tmp.dir.statFile(testing.io, namespace_path, .{})).kind == .directory,
    );
}

test "root_operation.test.a lost root lock stops every durable boundary" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var locks: TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try openTestCoordinator(&tmp, locks.interface(), test_root);

    var attempt = try coordinator.acquire(testing.allocator, packageRequest());
    defer attempt.release();
    locks.loseAll();
    try testing.expect(!attempt.locked());
    try testing.expectError(
        error.LockLost,
        attempt.advance(testing.allocator, .{ .state = .preflight, .phase = .preflight }),
    );
    try testing.expectError(error.LockLost, attempt.clear());
}
