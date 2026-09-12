const std = @import("std");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const live_root = @import("live_root.zig");
const native_authorization = @import("native_authorization.zig");
const native_execution_request = @import("native_execution_request.zig");
const native_operation = @import("native_operation.zig");
const native_program = @import("native_program.zig");
const native_provenance = @import("native_provenance.zig");
const native_recovery = @import("native_recovery.zig");
const native_runtime = @import("native_unpack.zig").Runtime;
const native_trigger = @import("native_trigger.zig");
const package_origin = @import("package_origin.zig");
const product_api = @import("product_api.zig");
const root_fs = @import("root_fs.zig");
const root_mutation = @import("root_mutation.zig");
const root_operation = @import("root_operation.zig");
const root_operation_completion = @import("root_operation_completion.zig");
const transaction_recovery = @import("transaction_recovery.zig");

pub const schema_id = "io.github.cataggar.debz.transaction-result-summary.v2";
pub const api_version: u32 = 2;
pub const capability_schema_id = "io.github.cataggar.debz.transaction-result-capability.v1";
pub const capability = "native-transaction-result-v1";

pub fn capabilitiesJson(allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    std.json.Stringify.value(.{
        .schema = capability_schema_id,
        .api_version = @as(u32, 1),
        .backend = "native",
        .capability = capability,
        .summary_schema = schema_id,
        .summary_api_version = api_version,
        .transaction_schema = native_provenance.schema_id,
        .transaction_schema_version = native_provenance.schema_version,
        .completion_schema = root_operation_completion.schema_id,
        .completion_schema_version = root_operation_completion.schema_version,
        .lock_schema = exact_lock_v2.schema_id,
        .lock_schema_version = exact_lock_v2.schema_version,
        .read_only = true,
    }, .{ .whitespace = .minified }, &output.writer) catch return error.OutOfMemory;
    output.writer.writeByte('\n') catch return error.OutOfMemory;
    return output.toOwnedSlice();
}

pub const Summary = struct {
    target_architecture: []const u8,
    install_root: []const u8,
    operation: product_api.Operation,
    request_sha256: [32]u8,
    solver_policy_sha256: [32]u8,
    caller_request_sha256: [32]u8,
    caller_policy_sha256: [32]u8,
    lock_sha256: [32]u8,
    transaction_digest_sha256: [32]u8,
    completion_digest_sha256: [32]u8,
    program_sha256: [32]u8,
    package_count: usize,

    pub fn canonicalJson(self: Summary, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        std.json.Stringify.value(.{
            .schema = schema_id,
            .api_version = api_version,
            .backend = "native",
            .transaction_schema = native_provenance.schema_id,
            .transaction_schema_version = native_provenance.schema_version,
            .completion_schema = root_operation_completion.schema_id,
            .completion_schema_version = root_operation_completion.schema_version,
            .target_architecture = self.target_architecture,
            .install_root = self.install_root,
            .operation = self.operation.spelling(),
            .request_sha256 = @as([]const u8, &native_recovery.hexDigest(self.request_sha256)),
            .solver_policy_sha256 = @as([]const u8, &native_recovery.hexDigest(self.solver_policy_sha256)),
            .caller_request_sha256 = @as([]const u8, &native_recovery.hexDigest(self.caller_request_sha256)),
            .caller_policy_sha256 = @as([]const u8, &native_recovery.hexDigest(self.caller_policy_sha256)),
            .lock_sha256 = @as([]const u8, &native_recovery.hexDigest(self.lock_sha256)),
            .transaction_digest_sha256 = @as([]const u8, &native_recovery.hexDigest(self.transaction_digest_sha256)),
            .completion_digest_sha256 = @as([]const u8, &native_recovery.hexDigest(self.completion_digest_sha256)),
            .program_sha256 = @as([]const u8, &native_recovery.hexDigest(self.program_sha256)),
            .package_count = self.package_count,
            .outcome = "succeeded",
            .final_verification_status = "exact_match",
            .lock_evidence = "exact_match",
            .receipt_evidence = "exact_match",
            .root_operation_status = "cleared",
        }, .{ .whitespace = .minified }, &output.writer) catch return error.OutOfMemory;
        output.writer.writeByte('\n') catch return error.OutOfMemory;
        return output.toOwnedSlice();
    }
};

/// Uses the existing root lock without creating an attempt, namespace, or lock
/// file. Verification neither acknowledges native evidence nor runs recovery.
pub fn verify(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    lock: exact_lock_v2.Lock,
    expected_architecture: []const u8,
    locks: root_operation.LockBackend,
) !Summary {
    var held = try VerificationLock.acquire(root, install_root, locks, null);
    defer held.deinit();
    if (try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) != null or
        try root.entryIfExists(try root_fs.Path.init(root_operation.deferred_ack_path)) != null or
        try native_runtime.hasActiveEvidence(allocator, root))
        return error.OperationNotSettled;

    var completion = try root_operation_completion.Store.init(root).read(allocator) orelse
        return error.CompletionMissing;
    defer completion.deinit();
    var receipt = try native_provenance.read(allocator, root) orelse return error.ReceiptMissing;
    defer receipt.deinit();
    const proof = receipt.document;
    const outer = completion.document;
    try verifyEvidence(allocator, root, install_root, held.inode, lock, expected_architecture, outer, proof, .succeeded);
    try held.validate();
    return .{
        .target_architecture = expected_architecture,
        .install_root = install_root,
        .operation = outer.operation.package_transaction,
        .request_sha256 = lock.request_sha256,
        .solver_policy_sha256 = lock.policy_sha256,
        .caller_request_sha256 = outer.request_sha256,
        .caller_policy_sha256 = outer.policy_sha256,
        .lock_sha256 = lock.digest_sha256,
        .transaction_digest_sha256 = try parseDigest(proof.digest_sha256),
        .completion_digest_sha256 = outer.digest_sha256,
        .program_sha256 = try parseDigest(proof.program_sha256),
        .package_count = lock.packages.len,
    };
}

pub const OwnedRequest = struct {
    /// Independently retained caller authority, never discovered from this root.
    owner: root_operation.DeferredAcknowledgment,
    operation: product_api.Operation,
    caller_request_sha256: [32]u8,
    caller_policy_sha256: [32]u8,
    projection: ?*const live_root.Projection = null,
};

const TerminalOutcome = enum { succeeded, failed };

fn OwnedResult(comptime expected_outcome: TerminalOutcome) type {
    return struct {
        pub const outcome = expected_outcome;
        owner: root_operation.DeferredAcknowledgment,
        receipt: native_provenance.OwnedDocument,
        completion: root_operation_completion.OwnedDocument,

        pub fn deinit(self: *@This()) void {
            self.receipt.deinit();
            self.completion.deinit();
            self.* = undefined;
        }
    };
}

/// Owns verified documents, but does not assert that the root has been cleared.
pub const OwnedSuccess = OwnedResult(.succeeded);
pub const PendingFailure = OwnedResult(.failed);
pub const PendingRequest = OwnedRequest;
pub const PendingSuccess = OwnedSuccess;
const OwnershipState = enum { pending, released };

/// Verifies a published successful completion before its exact owner acknowledges
/// it. No attempt is opened/adopted and no recovery or cleanup is performed.
pub fn verifyPendingSuccess(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    lock: exact_lock_v2.Lock,
    expected_architecture: []const u8,
    expected: PendingRequest,
    locks: root_operation.LockBackend,
) !PendingSuccess {
    return verifyOwned(allocator, root, install_root, lock, expected_architecture, expected, locks, .pending, .succeeded);
}

/// Confirms a known terminal failure and its recorded database, not the desired
/// final closure. Unknown outcomes are not failures that this entry point accepts.
pub fn verifyPendingFailure(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    lock: exact_lock_v2.Lock,
    expected_architecture: []const u8,
    expected: OwnedRequest,
    locks: root_operation.LockBackend,
) !PendingFailure {
    return verifyOwned(allocator, root, install_root, lock, expected_architecture, expected, locks, .pending, .failed);
}

/// Native execution has acknowledged its evidence, but the caller still owns the
/// released marker. Verification does not finalize that owner or clear its record.
pub fn verifyReleasedSuccess(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    lock: exact_lock_v2.Lock,
    expected_architecture: []const u8,
    expected: OwnedRequest,
    locks: root_operation.LockBackend,
) !OwnedSuccess {
    return verifyOwned(allocator, root, install_root, lock, expected_architecture, expected, locks, .released, .succeeded);
}

fn verifyOwned(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    lock: exact_lock_v2.Lock,
    expected_architecture: []const u8,
    expected: OwnedRequest,
    locks: root_operation.LockBackend,
    state: OwnershipState,
    comptime expected_outcome: TerminalOutcome,
) !OwnedResult(expected_outcome) {
    return verifyOwnedInternal(
        allocator,
        root,
        install_root,
        lock,
        expected_architecture,
        expected,
        locks,
        state,
        expected_outcome,
    ) catch |err| switch (err) {
        // This read-only path writes only to allocating canonical encoders.
        error.WriteFailed => error.OutOfMemory,
        else => err,
    };
}

fn verifyOwnedInternal(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    lock: exact_lock_v2.Lock,
    expected_architecture: []const u8,
    expected: OwnedRequest,
    locks: root_operation.LockBackend,
    state: OwnershipState,
    comptime expected_outcome: TerminalOutcome,
) !OwnedResult(expected_outcome) {
    if (expected_outcome == .failed and state != .pending)
        return error.PendingOwnerRequired;
    const owner_bytes = try expected.owner.canonicalJson(allocator);
    defer allocator.free(owner_bytes);
    const required_state: root_operation.DeferredAcknowledgmentState = switch (state) {
        .pending => .pending,
        .released => .released,
    };
    const missing_owner = if (state == .pending) error.PendingOwnerRequired else error.ReleasedOwnerRequired;
    if (expected.owner.state != required_state) return missing_owner;
    var held = try VerificationLock.acquire(root, install_root, locks, expected.projection);
    defer held.deinit();
    const store = root_operation.Store.init(root);
    if (try store.readRecoveryReviewClaim(allocator) != null)
        return error.RecoveryReviewClaimPresent;
    const observed = try store.readDeferredAcknowledgment(allocator) orelse
        return missing_owner;
    if (!root_operation.deferredAcknowledgmentExactEqual(observed, expected.owner))
        return error.OwnershipMismatch;
    var record = try store.read(allocator);
    defer if (record) |*owned| owned.deinit();
    if (state == .pending and record == null) return error.CompletionMissing;
    const compatibility = root_operation.deferredRecordCompatibility(
        if (record) |owned| owned.record else null,
        observed,
        false,
    );
    const compatible = switch (state) {
        .pending => compatibility == .pending_published,
        .released => compatibility == .released_without_record or compatibility == .released_completed,
    };
    if (!compatible)
        return error.InvalidCompletion;
    var completion = try root_operation_completion.Store.init(root).read(allocator) orelse
        return error.CompletionMissing;
    errdefer completion.deinit();
    const outer = completion.document;
    if (record) |owned| {
        if (!outer.bindsRecord(owned.record) or
            !textsEqual(outer.foreign_architectures, owned.record.foreign_architectures) or
            !std.mem.eql(u8, &outer.digest_sha256, &owned.record.provenance_sha256.?))
            return error.InvalidCompletion;
    }
    if (outer.operation != .package_transaction or
        outer.operation.package_transaction != expected.operation or
        !std.mem.eql(u8, &outer.attempt_id, &observed.attempt_id) or
        !std.mem.eql(u8, &outer.request_sha256, &expected.caller_request_sha256) or
        !std.mem.eql(u8, &outer.policy_sha256, &expected.caller_policy_sha256))
        return error.InvalidCompletion;
    if (state == .pending and
        (!std.mem.eql(u8, &outer.digest_sha256, &observed.completion_sha256.?) or
            !std.mem.eql(u8, &outer.digest_sha256, &observed.provenance_sha256.?)))
        return error.InvalidCompletion;
    if (state == .released and try native_runtime.hasActiveEvidence(allocator, root))
        return error.OperationNotSettled;
    var receipt = try native_provenance.read(allocator, root) orelse return error.ReceiptMissing;
    errdefer receipt.deinit();
    try verifyEvidence(allocator, root, install_root, held.inode, lock, expected_architecture, outer, receipt.document, expected_outcome);
    if (state == .pending)
        try verifyPendingEvidence(allocator, root, receipt.document);
    try held.validate();
    return .{ .owner = observed, .receipt = receipt, .completion = completion };
}

const VerificationLock = struct {
    named: root_fs.OwnedRoot,
    backend: root_operation.LockBackend,
    token: root_operation.LockToken,
    inode: u64,
    root_fd: i32,
    projection: ?*const live_root.Projection,

    fn acquire(
        root: root_fs.Root,
        install_root: []const u8,
        locks: root_operation.LockBackend,
        projection: ?*const live_root.Projection,
    ) !VerificationLock {
        if (std.mem.eql(u8, install_root, "/")) return error.HostRootNotSupported;
        if (projection) |authority|
            try authority.validateRoot(install_root, root.dir.handle);
        var named = try root_fs.openAbsoluteRoot(root.io, install_root);
        errdefer named.close();
        const held = try root.rootEntry();
        const resolved = try named.root.rootEntry();
        if (held.inode != resolved.inode or held.device != resolved.device)
            return error.RootIdentityMismatch;
        var host = try root_fs.openAbsoluteRoot(root.io, "/");
        defer host.close();
        const host_entry = try host.root.rootEntry();
        if (projection == null and held.inode == host_entry.inode and held.device == host_entry.device)
            return error.HostRootNotSupported;
        const lock_entry = (try root.entryIfExists(try root_fs.Path.init(root_operation.lock_path))) orelse
            return error.CompletionMissing;
        if (lock_entry.kind != .file) return error.InvalidCompletion;
        const token = try locks.acquire(.{
            .rank = .root_operation,
            .root = root,
            .identity = .{
                .install_root_sha256 = transaction_recovery.rootIdentity(install_root),
                .inode = held.inode,
            },
            .path = root_operation.lock_path,
            .wait_ms = 0,
            .cancellation = .never(),
            .create_if_missing = false,
        });
        errdefer locks.release(token);
        const result: VerificationLock = .{
            .named = named,
            .backend = locks,
            .token = token,
            .inode = held.inode,
            .root_fd = root.dir.handle,
            .projection = projection,
        };
        try result.validate();
        return result;
    }

    fn validate(self: VerificationLock) !void {
        if (!self.backend.held(self.token)) return error.LockLost;
        if (self.projection) |authority| {
            try authority.validateRoot(live_root.logical_root_path, self.root_fd);
            try authority.validateRoot(live_root.logical_root_path, self.named.root.dir.handle);
        }
    }

    fn deinit(self: *VerificationLock) void {
        self.backend.release(self.token);
        self.named.close();
        self.* = undefined;
    }
};

fn verifyEvidence(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    root_inode: u64,
    lock: exact_lock_v2.Lock,
    expected_architecture: []const u8,
    outer: root_operation_completion.Document,
    proof: native_provenance.Document,
    expected_outcome: TerminalOutcome,
) !void {
    const lock_bytes = try lock.canonicalJson(allocator);
    defer allocator.free(lock_bytes);
    var validated_lock = try exact_lock_v2.decode(allocator, lock_bytes, exact_lock_v2.maximum_document_bytes);
    defer validated_lock.deinit();
    if (!std.mem.eql(u8, lock.target_architecture, expected_architecture))
        return error.ArchitectureMismatch;
    try verifyTerminalOutcome(expected_outcome, proof.outcome, outer.outcome);
    if (outer.backend != .native or !outer.mutation_started or
        outer.operation != .package_transaction or
        outer.transaction_provenance.status == .unavailable or
        !std.mem.eql(u8, outer.transaction_provenance.schema, native_provenance.schema_id) or
        outer.journal.status != .absent or outer.journal.document_sha256 != null or
        !std.mem.eql(u8, outer.install_root, install_root) or
        !std.mem.eql(u8, proof.install_root, install_root) or proof.root_inode != root_inode or
        !std.mem.eql(u8, outer.target_architecture, expected_architecture) or
        !outer.operation.eql(proof.operation))
        return error.InvalidCompletion;
    switch (outer.operation.package_transaction) {
        .install, .remove, .upgrade, .upgrade_all, .reinstall => {},
        else => return error.InvalidCompletion,
    }
    try equalDigest(proof.attempt_id, native_recovery.hexDigest(outer.attempt_id));
    try equalDigest(proof.request_sha256, native_recovery.hexDigest(outer.request_sha256));
    try equalDigest(proof.policy_sha256, native_recovery.hexDigest(outer.policy_sha256));
    try equalDigest(proof.root_identity_sha256, native_recovery.hexDigest(outer.root_identity_sha256));
    try optionalDigest(outer.transaction_provenance.document_sha256, proof.digest_sha256);
    try native_provenance.verifyEvidence(allocator, root, proof);

    const authorization_bytes = try readEvidence(allocator, root, proof, .authorization, native_authorization.maximum_document_bytes);
    defer allocator.free(authorization_bytes);
    var authorization = try native_authorization.decode(allocator, authorization_bytes, native_authorization.maximum_document_bytes);
    defer authorization.deinit();
    const authorized = authorization.authorization;
    try evidenceDigest(proof, .authorization, native_recovery.hexDigest(authorized.digest_sha256));
    const program_bytes = try readEvidence(allocator, root, proof, .program, native_program.maximum_document_bytes);
    defer allocator.free(program_bytes);
    var program = try native_program.decode(allocator, program_bytes, native_program.maximum_document_bytes);
    defer program.deinit();
    try evidenceDigest(proof, .program, program.program.digest_sha256);
    if (!program.program.matchesAuthorization(authorized))
        return error.AuthorizationMismatch;
    try verifyLock(authorized, program.program, lock);
    const expected_evidence = try native_operation.evidence(program.program);
    inline for (.{
        "authorization_sha256",       "program_sha256",           "plan_sha256",
        "database_generation_sha256", "artifact_evidence_sha256",
    }) |field| {
        const actual = @field(outer, field) orelse return error.InvalidCompletion;
        if (!std.mem.eql(u8, &actual, &@field(expected_evidence, field).?))
            return error.InvalidCompletion;
    }
    if (outer.exact_lock == null or !outer.exact_lock.?.eql(expected_evidence.exact_lock.?))
        return error.LockEvidenceMismatch;
    if (!textsEqual(outer.foreign_architectures, program.program.foreign_architectures) or
        !textsEqual(authorized.foreign_architectures, program.program.foreign_architectures))
        return error.ArchitectureMismatch;
    try equalDigest(proof.authorization_sha256, program.program.authorization_sha256);
    try equalDigest(proof.program_sha256, program.program.digest_sha256);
    try equalDigest(proof.exact_lock_sha256, native_recovery.hexDigest(lock.digest_sha256));
    try equalDigest(proof.artifact_evidence_sha256, program.program.artifacts_sha256);
    try equalDigest(proof.initial_database_generation_sha256, program.program.installed_database.generation_sha256);

    const request_bytes = try readEvidence(allocator, root, proof, .execution_request, native_execution_request.maximum_document_bytes);
    defer allocator.free(request_bytes);
    var request = try native_execution_request.decodePersisted(allocator, request_bytes);
    defer request.deinit();
    try evidenceDigest(proof, .execution_request, request.documentDigest());
    const execution = request.execution();
    try native_execution_request.validateProgram(execution, program.program);
    if (execution.root_inode != root_inode or
        !std.mem.eql(u8, execution.install_root, install_root) or
        !execution.caller.operation.eql(outer.operation))
        return error.InvalidCompletion;
    try equalDigest(execution.caller.attempt_id, proof.attempt_id);
    try equalDigest(execution.caller.request_sha256, proof.request_sha256);
    try equalDigest(execution.caller.policy_sha256, proof.policy_sha256);
    const helper = request.helper() orelse return error.NativeHelperBindingRequired;
    const helper_bytes = try readEvidence(allocator, root, proof, .helper_binary, native_provenance.maximum_evidence_file_bytes);
    defer allocator.free(helper_bytes);
    var helper_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(helper_bytes, &helper_sha256, .{});
    try helper.matches(.{ .bytes = helper_bytes, .sha256 = helper_sha256 });

    const intent_bytes = try readEvidence(allocator, root, proof, .intent, native_recovery.maximum_intent_bytes);
    defer allocator.free(intent_bytes);
    var intent = try native_recovery.decodeIntent(allocator, intent_bytes);
    defer intent.deinit();
    try evidenceDigest(proof, .intent, intent.intent.digest_sha256);
    try native_execution_request.validateIntent(execution, intent.intent);
    try equalDigest(intent.intent.digest_sha256, proof.execution_intent_sha256);
    const progress_bytes = try readEvidence(allocator, root, proof, .progress, native_provenance.maximum_evidence_file_bytes);
    defer allocator.free(progress_bytes);
    var progress = try native_recovery.decodeProgress(allocator, progress_bytes);
    defer progress.deinit();
    try evidenceDigest(proof, .progress, progress.document.digest_sha256);
    try equalDigest(progress.document.intent_sha256, proof.execution_intent_sha256);
    try equalDigest(progress.document.head_sha256, proof.progress_head_sha256);
    if (progress.document.records.len != proof.progress_record_count)
        return error.InvalidRecoveryProgress;
    const terminal = native_recovery.latest(progress.document, .{
        .kind = .provenance,
        .program_step = std.math.maxInt(u32),
        .substep = 0,
        .ordinal = 0,
    }) orelse return error.InvalidRecoveryProgress;
    const terminal_matches = terminal.stage == .terminal and switch (expected_outcome) {
        .succeeded => terminal.result == .succeeded or terminal.result == .recovered,
        .failed => terminal.result == .failed,
    };
    if (!terminal_matches)
        return if (expected_outcome == .succeeded) error.TransactionNotSuccessful else error.TransactionNotFailed;
    const progress_summary = native_recovery.summarizeProgress(progress.document);
    try equalDigest(native_recovery.hexDigest(progress_summary.script_outcomes_sha256), proof.script_outcomes_sha256);
    if (progress_summary.recovered_phase_count != proof.recovered_phase_count)
        return error.InvalidRecoveryProgress;
    const trigger_bytes = try readEvidence(allocator, root, proof, .trigger_events, native_recovery.maximum_progress_bytes);
    defer allocator.free(trigger_bytes);
    var triggers = try native_recovery.decodeTriggerEvents(allocator, trigger_bytes);
    defer triggers.deinit();
    try evidenceDigest(proof, .trigger_events, triggers.document.digest_sha256);
    try equalDigest(triggers.document.intent_sha256, proof.execution_intent_sha256);
    try equalDigest(triggers.document.digest_sha256, proof.trigger_evidence_sha256);
    const managed_bytes = try readEvidence(allocator, root, proof, .managed_state, native_recovery.maximum_managed_state_bytes);
    defer allocator.free(managed_bytes);
    var managed = try native_recovery.decodeManagedState(allocator, managed_bytes);
    defer managed.deinit();
    try evidenceDigest(proof, .managed_state, managed.document.digest_sha256);
    try equalDigest(managed.document.intent_sha256, proof.execution_intent_sha256);
    if (managed.document.transient != null) return error.InvalidManagedState;
    switch (expected_outcome) {
        .succeeded => try native_runtime.verifyCompletedState(allocator, root, authorized, proof),
        .failed => try native_runtime.verifyFailedState(allocator, root, authorized, proof),
    }
}

fn verifyTerminalOutcome(
    expected: TerminalOutcome,
    receipt: native_provenance.Outcome,
    completion: root_operation.Outcome,
) !void {
    switch (expected) {
        .succeeded => if (receipt != .succeeded or completion != .succeeded)
            return error.TransactionNotSuccessful,
        .failed => if (receipt != .failed or completion != .failed_after_mutation)
            return error.TransactionNotFailed,
    }
}

fn verifyPendingEvidence(allocator: std.mem.Allocator, root: root_fs.Root, proof: native_provenance.Document) !void {
    for ([_][]const u8{
        native_trigger.script_record_path, native_trigger.authority_path,
        root_mutation.journal_path,        root_mutation.progress_path,
    }) |path| {
        if (try root.entryIfExists(try root_fs.Path.init(path)) != null)
            return error.UnresolvedNativeEvidence;
    }
    var namespace = try root.pinDirectory(try root_fs.Path.init(root_operation.namespace_path));
    defer namespace.close();
    var observed = try namespace.observeAlloc(allocator, native_recovery.maximum_records, 64 * 1024 * 1024);
    defer observed.deinit();
    for (observed.members) |member| {
        if (std.mem.startsWith(u8, member.name, ".debz-native-"))
            return error.UnresolvedNativeEvidence;
        if (!std.mem.startsWith(u8, member.name, native_recovery.script_outcome_prefix)) continue;
        var matched = false;
        for (proof.evidence_files) |file| {
            if (file.kind != .script_outcome) continue;
            var path_buffer: [128]u8 = undefined;
            const path = try activeScriptOutcomePath(file, &path_buffer);
            if (std.mem.eql(u8, member.name, std.fs.path.basename(path))) {
                matched = true;
                break;
            }
        }
        if (!matched) return error.UnresolvedNativeEvidence;
    }
    inline for (.{
        .{ .authorization, root_operation.namespace_path ++ "/" ++ native_recovery.authorization_name },
        .{ .program, root_operation.namespace_path ++ "/" ++ native_recovery.program_name },
        .{ .intent, native_recovery.intent_path },
        .{ .progress, native_recovery.progress_path },
        .{ .managed_state, native_recovery.managed_state_path },
        .{ .trigger_events, native_recovery.trigger_events_path },
    }) |entry| {
        const file = try evidenceFile(proof, entry[0]);
        try verifyRemainingFile(allocator, root, entry[1], file.sha256, file.size);
    }
    for (proof.evidence_files) |file| {
        if (file.kind != .script_outcome) continue;
        var path_buffer: [128]u8 = undefined;
        const path = try activeScriptOutcomePath(file, &path_buffer);
        try verifyRemainingFile(allocator, root, path, file.sha256, file.size);
    }
}

fn activeScriptOutcomePath(file: native_provenance.EvidenceFile, buffer: *[128]u8) ![]const u8 {
    const action = file.action orelse return error.EvidenceMissing;
    return native_recovery.scriptOutcomePath(.{
        .kind = action.kind,
        .program_step = action.program_step,
        .substep = action.substep,
        .ordinal = action.ordinal,
    }, buffer);
}

fn verifyRemainingFile(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: []const u8,
    expected_sha256: native_provenance.Digest,
    expected_size: u64,
) !void {
    // Acknowledgment can be interrupted between removals. Missing active copies
    // are fine; retained evidence remains mandatory and every surviving copy agrees.
    const bytes = root.readFileAlloc(
        allocator,
        try root_fs.Path.init(path),
        std.math.cast(usize, expected_size) orelse return error.EvidenceTooLarge,
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer allocator.free(bytes);
    if (bytes.len != expected_size) return error.EvidenceChanged;
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &sha256, .{});
    try equalDigest(native_recovery.hexDigest(sha256), expected_sha256);
}

fn verifyLock(authorization: native_authorization.Authorization, program: native_program.Program, lock: exact_lock_v2.Lock) !void {
    if (!std.mem.eql(u8, authorization.target_architecture, lock.target_architecture) or
        !std.mem.eql(u8, program.target_architecture, lock.target_architecture))
        return error.ArchitectureMismatch;
    if (!std.mem.eql(u8, authorization.exact_lock.schema, exact_lock_v2.schema_id) or
        authorization.exact_lock.version != exact_lock_v2.schema_version or
        !std.mem.eql(u8, program.exact_lock.schema, exact_lock_v2.schema_id) or
        program.exact_lock.version != exact_lock_v2.schema_version or
        !std.mem.eql(u8, &authorization.exact_lock.digest_sha256, &lock.digest_sha256) or
        !std.mem.eql(u8, &authorization.request_sha256, &lock.request_sha256) or
        !std.mem.eql(u8, &authorization.solver_policy_sha256, &lock.policy_sha256))
        return error.LockEvidenceMismatch;
    try equalDigest(program.solver_policy_sha256, native_recovery.hexDigest(authorization.solver_policy_sha256));
    try equalDigest(program.executor_policy_sha256, native_recovery.hexDigest(authorization.executor_policy_sha256));
    if (program.policy.conffile != authorization.policy.conffile or
        program.policy.allow_host_root != authorization.policy.allow_host_root or
        program.policy.force.len != authorization.policy.force.len)
        return error.AuthorizationMismatch;
    for (program.policy.force, authorization.policy.force) |left, right|
        if (left != right) return error.AuthorizationMismatch;
    try verifyFinalClosure(authorization.final_state, lock);
    for (authorization.actions) |action| {
        const artifact = action.artifact orelse continue;
        const locked = lock.findPackage(action.package, action.version, action.architecture) orelse
            return error.LockEvidenceMismatch;
        if (!std.mem.eql(u8, &artifact.sha256, &locked.sha256) or
            artifact.size != locked.declared_size or !originsEqual(artifact.origin, locked.origin))
            return error.LockEvidenceMismatch;
    }
    for (program.artifacts) |artifact| {
        const locked = lock.findPackage(artifact.package.name, artifact.package.version, artifact.package.architecture) orelse
            return error.LockEvidenceMismatch;
        try equalDigest(artifact.sha256, native_recovery.hexDigest(locked.sha256));
        const origin: exact_lock_v2.PackageOrigin = switch (artifact.origin) {
            .authenticated_repository => |value| .{ .authenticated_repository = .{
                .repository_id = value.repository_id,
                .repository_snapshot_sha256 = try parseDigest(value.repository_snapshot_sha256),
            } },
            .local_artifact => |value| .{ .local_artifact = .{
                .artifact_id = value.artifact_id,
                .sha256 = try parseDigest(value.sha256),
                .size = value.size,
                .package = value.package.name,
                .version = value.package.version,
                .architecture = value.package.architecture,
                .acquisition_url = value.acquisition_url,
                .trust_mode = value.trust_mode,
            } },
        };
        if (artifact.size != locked.declared_size or !originsEqual(origin, locked.origin))
            return error.LockEvidenceMismatch;
    }
}

fn verifyFinalClosure(final_state: []const native_authorization.FinalPackage, lock: exact_lock_v2.Lock) !void {
    var installed: usize = 0;
    for (final_state) |package| {
        switch (package.state) {
            .installed => {
                const locked = lock.findPackage(package.name, package.version, package.architecture) orelse
                    return error.LockEvidenceMismatch;
                if (locked.dpkg_selection_hold != package.dpkg_selection_hold)
                    return error.LockEvidenceMismatch;
                installed += 1;
            },
            .config_files => if (lock.findIdentity(package.name, package.architecture) != null)
                return error.LockEvidenceMismatch,
            .triggers_pending, .triggers_awaited => return error.TransactionNotSuccessful,
        }
    }
    if (installed != lock.packages.len) return error.LockEvidenceMismatch;
}

fn originsEqual(left: exact_lock_v2.PackageOrigin, right: exact_lock_v2.PackageOrigin) bool {
    return switch (left) {
        .authenticated_repository => |value| right == .authenticated_repository and
            std.meta.eql(value, right.authenticated_repository),
        .local_artifact => |value| right == .local_artifact and
            package_origin.eqlLocalArtifact(value, right.local_artifact),
    };
}

fn textsEqual(left: []const []const u8, right: []const []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.mem.eql(u8, a, b)) return false;
    return true;
}

fn parseDigest(value: native_provenance.Digest) ![32]u8 {
    return native_recovery.parseDigest(value) orelse error.InvalidDigest;
}

fn equalDigest(left: native_provenance.Digest, right: native_provenance.Digest) !void {
    if (!std.mem.eql(u8, &left, &right)) return error.EvidenceMismatch;
}

fn optionalDigest(value: ?[32]u8, expected: native_provenance.Digest) !void {
    try equalDigest(native_recovery.hexDigest(value orelse return error.EvidenceMissing), expected);
}

fn evidenceFile(receipt: native_provenance.Document, kind: native_provenance.EvidenceKind) !native_provenance.EvidenceFile {
    for (receipt.evidence_files) |file| if (file.kind == kind) return file;
    return error.EvidenceMissing;
}

fn evidenceDigest(receipt: native_provenance.Document, kind: native_provenance.EvidenceKind, expected: native_provenance.Digest) !void {
    const file = try evidenceFile(receipt, kind);
    try equalDigest(file.document_sha256 orelse return error.EvidenceMissing, expected);
}

fn readEvidence(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    receipt: native_provenance.Document,
    kind: native_provenance.EvidenceKind,
    maximum_bytes: usize,
) ![]u8 {
    const file = try evidenceFile(receipt, kind);
    if (file.size > maximum_bytes) return error.EvidenceTooLarge;
    const bytes = try root.readFileAlloc(allocator, try root_fs.Path.init(file.path), maximum_bytes);
    errdefer allocator.free(bytes);
    if (bytes.len != file.size) return error.EvidenceChanged;
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &sha256, .{});
    try equalDigest(native_recovery.hexDigest(sha256), file.sha256);
    return bytes;
}

fn testSummaries(allocator: std.mem.Allocator) !void {
    const summary: Summary = .{
        .target_architecture = "arm64",
        .install_root = "/fixture/root",
        .operation = .install,
        .request_sha256 = @splat(1),
        .solver_policy_sha256 = @splat(2),
        .caller_request_sha256 = @splat(3),
        .caller_policy_sha256 = @splat(4),
        .lock_sha256 = @splat(5),
        .transaction_digest_sha256 = @splat(6),
        .completion_digest_sha256 = @splat(7),
        .program_sha256 = @splat(8),
        .package_count = 0,
    };
    const bytes = try summary.canonicalJson(allocator);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const fields = parsed.value.object;
    try std.testing.expectEqualStrings(schema_id, fields.get("schema").?.string);
    try std.testing.expectEqualStrings(native_provenance.schema_id, fields.get("transaction_schema").?.string);
    try std.testing.expectEqualStrings("native", fields.get("backend").?.string);
    try std.testing.expectEqualStrings("arm64", fields.get("target_architecture").?.string);
    try std.testing.expectEqualStrings("01" ** 32, fields.get("request_sha256").?.string);
    try std.testing.expectEqualStrings("03" ** 32, fields.get("caller_request_sha256").?.string);
    try std.testing.expectEqualStrings("06" ** 32, fields.get("transaction_digest_sha256").?.string);
    try std.testing.expectEqualStrings("07" ** 32, fields.get("completion_digest_sha256").?.string);
    try std.testing.expectEqual(@as(i64, 0), fields.get("package_count").?.integer);
    try std.testing.expectEqual(@as(?usize, bytes.len - 1), std.mem.indexOfScalar(u8, bytes, '\n'));
    const capabilities = try capabilitiesJson(allocator);
    defer allocator.free(capabilities);
    var supported = try std.json.parseFromSlice(std.json.Value, allocator, capabilities, .{});
    defer supported.deinit();
    try std.testing.expectEqualStrings(capability_schema_id, supported.value.object.get("schema").?.string);
    try std.testing.expectEqualStrings(capability, supported.value.object.get("capability").?.string);
    try std.testing.expectEqualStrings(schema_id, supported.value.object.get("summary_schema").?.string);
    try std.testing.expectEqualStrings(exact_lock_v2.schema_id, supported.value.object.get("lock_schema").?.string);
    try std.testing.expect(supported.value.object.get("read_only").?.bool);
}

test "native_transaction_result.test.projected root external fixture" {
    std.testing.refAllDecls(@import("apt_system_orchestrator.zig"));
    const enabled = std.c.getenv("DEBZ_NATIVE_PROJECTION_FIXTURE") orelse return error.SkipZigTest;
    if (!std.mem.eql(u8, std.mem.span(enabled), "1")) return error.InvalidProjectionFixture;
    var root = try root_fs.openAbsoluteRoot(std.testing.io, "/");
    defer root.close();
    const marker = try root.root.readFileAlloc(
        std.testing.allocator,
        try root_fs.Path.init(".debz-native-projection"),
        128,
    );
    defer std.testing.allocator.free(marker);
    if (!std.mem.eql(u8, marker, "debz native projection fixture v1\n"))
        return error.InvalidProjectionFixture;
    const Callback = struct {
        fn run(_: ?*anyopaque, projection: *const live_root.Projection) !u8 {
            try live_root.testing.verifyProjection(projection);
            const io = std.testing.io;
            const allocator = std.testing.allocator;
            var named = try root_fs.openAbsoluteRoot(io, live_root.logical_root_path);
            defer named.close();
            const projected = named.root;
            var system_locks: root_operation.SystemLockBackend = .{ .io = io, .allocator = allocator };
            const locks = system_locks.interface();
            try std.testing.expectError(
                error.HostRootNotSupported,
                VerificationLock.acquire(projected, live_root.logical_root_path, locks, null),
            );
            try std.testing.expectError(
                error.HostRootNotSupported,
                VerificationLock.acquire(projected, "/", locks, projection),
            );
            var lock = try exact_lock_v2.create(allocator, .{
                .target_architecture = "amd64",
                .request_sha256 = @splat(1),
                .policy_sha256 = @splat(2),
                .repositories = &.{},
                .local_artifacts = &.{},
                .packages = &.{},
                .verified_origins = true,
            });
            defer lock.deinit();
            try std.testing.expectError(
                error.HostRootNotSupported,
                verify(allocator, projected, live_root.logical_root_path, lock.lock, "amd64", locks),
            );
            for ([_]OwnershipState{ .pending, .released }) |state| {
                const owner = try root_operation.createDeferredAcknowledgment(.{
                    .state = if (state == .pending) .pending else .released,
                    .attempt_id = @splat(3),
                    .acknowledgment_id = @splat(4),
                    .completion_sha256 = if (state == .pending) @splat(5) else null,
                    .provenance_sha256 = if (state == .pending) @splat(5) else null,
                });
                const expected: OwnedRequest = .{
                    .owner = owner,
                    .operation = .install,
                    .caller_request_sha256 = @splat(6),
                    .caller_policy_sha256 = @splat(7),
                    .projection = projection,
                };
                const missing_owner = if (state == .pending) error.PendingOwnerRequired else error.ReleasedOwnerRequired;
                try testOwnedRefusal(allocator, projected, live_root.logical_root_path, lock.lock, expected, locks, missing_owner, state);
                if (state == .pending)
                    try std.testing.expectError(
                        error.PendingOwnerRequired,
                        verifyPendingFailure(allocator, projected, live_root.logical_root_path, lock.lock, "amd64", expected, locks),
                    );
            }
            var held = try VerificationLock.acquire(projected, live_root.logical_root_path, locks, projection);
            defer held.deinit();
            try held.validate();
            try live_root.testing.replaceMountNamespace();
            try std.testing.expectError(error.InvalidProjection, held.validate());
            return 0;
        }
    };
    const result = try live_root.runProjected(.{ .child = Callback.run });
    if (result != .exited or result.exited != 0) {
        std.debug.print("native projection fixture failed: {any}\n", .{result});
        return error.InvalidProjectionFixture;
    }
}

test "native_transaction_result.test.summary preserves distinct request domains and native empty counts" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testSummaries, .{});
}

test "native_transaction_result.test.empty closures retain only authorized residual configurations" {
    var lock = try exact_lock_v2.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .policy_sha256 = @splat(2),
        .repositories = &.{},
        .local_artifacts = &.{},
        .packages = &.{},
        .verified_origins = true,
    });
    defer lock.deinit();
    try verifyFinalClosure(&.{}, lock.lock);
    var residual: native_authorization.FinalPackage = .{
        .name = "config-only",
        .version = "1",
        .architecture = "amd64",
        .state = .config_files,
        .dpkg_selection_hold = false,
    };
    try verifyFinalClosure(&.{residual}, lock.lock);
    residual.state = .installed;
    try std.testing.expectError(error.LockEvidenceMismatch, verifyFinalClosure(&.{residual}, lock.lock));
    residual.state = .triggers_pending;
    try std.testing.expectError(error.TransactionNotSuccessful, verifyFinalClosure(&.{residual}, lock.lock));
}

fn testOwnedRefusal(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: []const u8,
    lock: exact_lock_v2.Lock,
    expected: PendingRequest,
    locks: root_operation.LockBackend,
    expected_error: anyerror,
    state: OwnershipState,
) !void {
    var result = verifyOwned(allocator, root, path, lock, "amd64", expected, locks, state, .succeeded) catch |err| {
        if (err == expected_error) return;
        return err;
    };
    defer result.deinit();
    return error.TestExpectedError;
}

test "native_transaction_result.test.owned verification preserves exact owners and never provisions locks" {
    try testOwnedBoundaries(.pending);
    try testOwnedBoundaries(.released);
}

test "native_transaction_result.test.known failure cannot become success or accept unknown outcomes" {
    try std.testing.expect(OwnedSuccess != PendingFailure);
    try verifyTerminalOutcome(.succeeded, .succeeded, .succeeded);
    try verifyTerminalOutcome(.failed, .failed, .failed_after_mutation);
    for ([_]native_provenance.Outcome{ .succeeded, .failed, .recovery_required }) |receipt| {
        for (std.meta.tags(root_operation.Outcome)) |completion| {
            if (receipt != .succeeded or completion != .succeeded)
                try std.testing.expectError(error.TransactionNotSuccessful, verifyTerminalOutcome(.succeeded, receipt, completion));
            if (receipt != .failed or completion != .failed_after_mutation)
                try std.testing.expectError(error.TransactionNotFailed, verifyTerminalOutcome(.failed, receipt, completion));
        }
    }
}

fn testOwnedBoundaries(comptime state: OwnershipState) !void {
    const testing = std.testing;
    const allocator = testing.allocator;
    const verify_success = if (state == .pending) verifyPendingSuccess else verifyReleasedSuccess;
    const missing_owner = if (state == .pending) error.PendingOwnerRequired else error.ReleasedOwnerRequired;
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = path_buffer[0..try temporary.dir.realPath(testing.io, &path_buffer)];
    var lock = try exact_lock_v2.create(allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .policy_sha256 = @splat(2),
        .repositories = &.{},
        .local_artifacts = &.{},
        .packages = &.{},
        .verified_origins = true,
    });
    defer lock.deinit();
    const Locks = struct {
        acquisitions: usize = 0,
        releases: usize = 0,
        live: bool = false,
        lost: bool = false,

        fn acquire(context: *anyopaque, request: root_operation.AcquireLock) root_operation.LockError!root_operation.LockToken {
            const self: *@This() = @ptrCast(@alignCast(context));
            std.debug.assert(!request.create_if_missing and request.rank == .root_operation and !self.live);
            self.acquisitions += 1;
            self.live = true;
            return context;
        }
        fn held(context: *anyopaque, _: root_operation.LockToken) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            return self.live and !self.lost;
        }
        fn release(context: *anyopaque, _: root_operation.LockToken) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.live = false;
            self.releases += 1;
        }
    };
    var observer: Locks = .{};
    const locks: root_operation.LockBackend = .{
        .context = &observer,
        .acquireFn = Locks.acquire,
        .heldFn = Locks.held,
        .releaseFn = Locks.release,
    };
    const base = try root_operation.createDeferredAcknowledgment(.{
        .state = if (state == .pending) .pending else .released,
        .attempt_id = @splat(3),
        .acknowledgment_id = @splat(4),
        .completion_sha256 = if (state == .pending) @splat(5) else null,
        .provenance_sha256 = if (state == .pending) @splat(5) else null,
    });
    var expected: PendingRequest = .{
        .owner = base,
        .operation = .install,
        .caller_request_sha256 = @splat(6),
        .caller_policy_sha256 = @splat(7),
    };
    try testing.expectError(error.HostRootNotSupported, verify_success(allocator, root, "/", lock.lock, "amd64", expected, locks));
    try testOwnedRefusal(allocator, root, path, lock.lock, expected, locks, error.CompletionMissing, state);
    try testing.expectEqual(@as(usize, 0), observer.acquisitions);
    try testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.namespace_path)) == null);
    const store = root_operation.Store.init(root);
    try store.ensureNamespace();
    try root.publishFile(try root_fs.Path.init(root_operation.lock_path), "", .{});
    try testing.expectError(missing_owner, verify_success(allocator, root, path, lock.lock, "amd64", expected, locks));
    try store.publishDeferredAcknowledgment(allocator, base);
    try testing.checkAllAllocationFailures(
        allocator,
        testOwnedRefusal,
        .{ root, path, lock.lock, expected, locks, error.CompletionMissing, state },
    );
    var claim = try root_operation.createRecoveryReviewClaim(.{
        .outer_attempt_id = base.acknowledgment_id,
        .outer_generation = 1,
        .outer_state_sha256 = @splat(8),
        .profile_sha256 = @splat(9),
        .profile_reference_sha256 = @splat(10),
        .exact_lock_sha256 = lock.lock.digest_sha256,
        .semantic_request_sha256 = lock.lock.request_sha256,
        .mutation_status = .changed,
        .outer_transaction_sha256 = @splat(11),
        .nonce = @splat(12),
    });
    const reviewed = try root_operation.bindDeferredAcknowledgmentToRecoveryReview(base, claim);
    const reviewed_bytes = try reviewed.canonicalJson(allocator);
    defer allocator.free(reviewed_bytes);
    try root.publishFile(try root_fs.Path.init(root_operation.deferred_ack_path), reviewed_bytes, .{ .overwrite = .replace });
    try testing.expectError(error.OwnershipMismatch, verify_success(allocator, root, path, lock.lock, "amd64", expected, locks));
    expected.owner = reviewed;
    try testing.checkAllAllocationFailures(
        allocator,
        testOwnedRefusal,
        .{ root, path, lock.lock, expected, locks, error.CompletionMissing, state },
    );
    claim.nonce = @splat(13);
    claim = try root_operation.createRecoveryReviewClaim(claim);
    expected.owner = try root_operation.bindDeferredAcknowledgmentToRecoveryReview(base, claim);
    try testing.expectEqualSlices(u8, &reviewed.digest_sha256, &expected.owner.digest_sha256);
    try testing.expectError(error.OwnershipMismatch, verify_success(allocator, root, path, lock.lock, "amd64", expected, locks));
    expected.owner = reviewed;
    expected.owner.exact_identity_sha256 = @splat(14);
    try testing.expectError(error.ExactIdentityMismatch, verify_success(allocator, root, path, lock.lock, "amd64", expected, locks));
    expected.owner = reviewed;
    observer.lost = true;
    try testing.expectError(error.LockLost, verify_success(allocator, root, path, lock.lock, "amd64", expected, locks));
    observer.lost = false;
    const claim_bytes = try claim.canonicalJson(allocator);
    defer allocator.free(claim_bytes);
    try root.publishFile(try root_fs.Path.init(root_operation.deferred_ack_path), claim_bytes, .{ .overwrite = .replace });
    try testing.checkAllAllocationFailures(
        allocator,
        testOwnedRefusal,
        .{ root, path, lock.lock, expected, locks, error.RecoveryReviewClaimPresent, state },
    );
    try testing.expectEqual(observer.acquisitions, observer.releases);
    try testing.expect(!observer.live);
    try testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) == null);
}
