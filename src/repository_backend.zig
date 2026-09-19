const std = @import("std");
const absolute_path = @import("absolute_path.zig");
const archive_application = @import("archive_application.zig");
const api = @import("repository_api.zig");
const state_module = @import("repository_state.zig");
const local_artifact = @import("local_artifact.zig");
const live_root = @import("live_root.zig");
const deb_payload = @import("deb_payload.zig");
const dpkg_status = @import("dpkg_status.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const metadata_cache = @import("metadata_cache.zig");
const native_operation = @import("native_operation.zig");
const native_preparation = @import("native_preparation.zig");
const native_provenance = @import("native_provenance.zig");
const native_recovery = @import("native_recovery.zig");
const native_runtime = @import("native_unpack.zig").Runtime;
const native_transaction_result = @import("native_transaction_result.zig");
const openpgp = @import("openpgp_verifier.zig");
const package_acquisition = @import("package_acquisition.zig");
const package_origin = @import("package_origin.zig");
const packages_index = @import("packages_index.zig");
const repository_acquisition = @import("repository_acquisition.zig");
const repository_policy = @import("repository_policy.zig");
const repository_plan = @import("repository_plan.zig");
const repository_refresh = @import("repository_refresh.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const root_operation_completion = @import("root_operation_completion.zig");
const solver = @import("solver.zig");
const source = @import("source.zig");
const target_apt_config = @import("target_apt_config.zig");
const transaction_engine = @import("transaction_engine.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_provenance_v2 = @import("transaction_provenance_v2.zig");
const transaction_recovery = @import("transaction_recovery.zig");

const operation_directory_name = "repository";
const operations_directory_name = "operations";
const operation_state_name = "repo-add-state-v1.json";
const operation_lock_name = "repo-add.lock";
const exact_lock_name = "exact-lock-v2.json";
const exact_plan_name = "transaction-plan-v3.json";
const provenance_name = "transaction-result-v2.json";
const native_provenance_name = "native-transaction-provenance-v1.json";
const manifest_name = "apt-config-snapshot-v1.json";

pub const Executor = transaction_engine.Executor;

pub const NativePreparationRequest = struct {
    repository: api.Request,
    attempt: *root_operation.Attempt,
    plan: *const solver.Plan,
    exact_lock: *const exact_lock_v2.Lock,
    archives: []const []const u8,
};

pub const NativeCachePreparationRequest = struct {
    repository: api.Request,
    attempt: *root_operation.Attempt,
    plan: *const solver.Plan,
    exact_lock: *const exact_lock_v2.Lock,
    cache: *package_acquisition.Cache,
    /// Package buffers still owned by the caller, including the descriptor.
    /// These count against retained memory but are not reused or transferred.
    retained_archives: []const []const u8,
    /// The existing operation deadline, never a new timeout for this phase.
    deadline: transaction_executor.Deadline,
};

pub const NativeCachedPreparation = struct {
    preparation: native_preparation.ResultWithNoChanges,
    archives: []const []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *NativeCachedPreparation) void {
        self.preparation.deinit();
        for (self.archives) |bytes| self.allocator.free(bytes);
        self.allocator.free(self.archives);
        self.* = undefined;
    }
};

pub const NativeExecutionResult = union(enum) {
    unchanged,
    diagnostic: native_preparation.OwnedDiagnostic,
    execution: native_runtime.Report,

    pub fn deinit(self: *NativeExecutionResult) void {
        switch (self.*) {
            .unchanged => {},
            inline else => |*value| value.deinit(),
        }
        self.* = undefined;
    }
};

/// Executes the verified closure under the original repository caller. Package
/// completion is not repository completion and never acknowledges the receipt.
pub fn executeNativeFromCache(
    allocator: std.mem.Allocator,
    input: NativeCachePreparationRequest,
) !NativeExecutionResult {
    var cached = try prepareNativeFromCache(allocator, input);
    defer cached.deinit();
    switch (cached.preparation) {
        .unchanged => return .unchanged,
        .diagnostic => |diagnostic| {
            cached.preparation = .unchanged;
            return .{ .diagnostic = diagnostic };
        },
        .prepared => |*prepared| return .{ .execution = try native_runtime.execute(allocator, .{
            .attempt = input.attempt,
            .prepared = prepared,
            .archives = cached.archives,
            .operation = .install,
            .deadline = input.deadline,
        }) },
    }
}

pub const NativeRecoveryRequest = struct {
    repository: api.Request,
    attempt: *root_operation.Attempt,
    deadline: transaction_executor.Deadline,

    fn validate(self: @This()) !void {
        _ = try self.deadline.remainingMs();
        try validateNativeRepositoryCaller(self.repository, self.attempt);
        try self.attempt.coordinator.validateProjection();
        _ = try native_runtime.validateAttempt(self.attempt);
    }
};

/// The request authenticates the original repository caller; recovery work
/// comes only from native persisted inputs, never a new plan, lock or cache.
pub fn recoverNative(
    allocator: std.mem.Allocator,
    input: NativeRecoveryRequest,
) !native_runtime.Report {
    try validateNativeRepositoryCaller(input.repository, input.attempt);
    return native_runtime.recoverWithDeadline(allocator, input.attempt, input.deadline);
}

pub const NativeReceiptRequest = struct {
    repository: api.Request,
    attempt: *root_operation.Attempt,
    expected_receipt_sha256: native_provenance.Digest,
    /// The invocation's original budget, shared with execution or recovery.
    deadline: transaction_executor.Deadline,

    fn validate(self: NativeReceiptRequest) !void {
        try self.recoveryRequest().validate();
    }

    fn recoveryRequest(self: @This()) NativeRecoveryRequest {
        return .{ .repository = self.repository, .attempt = self.attempt, .deadline = self.deadline };
    }
};

pub const NativeRetainedReceipt = struct {
    logical_path: []const u8,
    receipt: native_provenance.OwnedDocument,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *NativeRetainedReceipt) void {
        self.allocator.free(self.logical_path);
        self.receipt.deinit();
        self.* = undefined;
    }
};

/// Retains exact terminal package evidence, not repository completion. The
/// caller still owes durable outer state before acknowledgment or cleanup.
pub fn retainNativeReceipt(allocator: std.mem.Allocator, input: NativeReceiptRequest) !NativeRetainedReceipt {
    return nativeRepositoryReceipt(allocator, input, true, null);
}

/// Reads already-bound retention without recreating missing or corrupt bytes.
/// Fresh caller-owned runtime evidence remains necessary; this is not history
/// verification after the original caller has been completed and cleared.
pub fn readRetainedNativeReceipt(allocator: std.mem.Allocator, input: NativeReceiptRequest) !NativeRetainedReceipt {
    return nativeRepositoryReceipt(allocator, input, false, null);
}

pub const NativePackageState = union(enum) {
    succeeded: NativeRetainedReceipt,
    failed: NativeRetainedReceipt,

    pub fn deinit(self: *NativePackageState) void {
        switch (self.*) {
            inline else => |*value| value.deinit(),
        }
        self.* = undefined;
    }
};

/// Verifies retained evidence and the current package database under the
/// original caller. A known failure never becomes successful installation;
/// neither result completes repository bootstrap or permits early cleanup.
pub fn verifyNativePackageState(allocator: std.mem.Allocator, input: NativeReceiptRequest) !NativePackageState {
    var retained = try readRetainedNativeReceipt(allocator, input);
    errdefer retained.deinit();
    switch (retained.receipt.document.outcome) {
        .succeeded => {
            var verified = try native_transaction_result.verifyCallerSuccess(allocator, input.attempt, input.expected_receipt_sha256);
            defer verified.deinit();
            try input.validate();
            return .{ .succeeded = retained };
        },
        .failed => {
            var verified = try native_transaction_result.verifyCallerFailure(allocator, input.attempt, input.expected_receipt_sha256);
            defer verified.deinit();
            try input.validate();
            return .{ .failed = retained };
        },
        .recovery_required => return error.InvalidRecoveryProvenance,
    }
}

pub const NativeRepositoryCheckpoint = struct {
    state: state_module.OwnedState,
    package_state: NativePackageState,

    pub fn deinit(self: *NativeRepositoryCheckpoint) void {
        self.state.deinit();
        self.package_state.deinit();
        self.* = undefined;
    }
};

pub const NativePackageCheckpoint = NativeRepositoryCheckpoint;

pub const NativeImportRefreshDependencies = struct {
    acquisition: repository_acquisition.Dependencies,
    now_unix: i64,
    result_progress: ?*NativeDispatchProgress = null,
};

pub const NativeRepositoryCompletion = struct {
    checkpoint: NativeRepositoryCheckpoint,
    completion: root_operation_completion.OwnedDocument,

    pub fn deinit(self: *@This()) void {
        self.checkpoint.deinit();
        self.completion.deinit();
        self.* = undefined;
    }
};

pub const NativeRepositoryResume = union(enum) {
    not_started,
    pending: native_runtime.Report,
    completed: NativeRepositoryCompletion,
    historical: NativeRepositoryHistory,
    unchanged: NativeRepositoryUnchanged,

    pub fn deinit(self: *@This()) void {
        switch (self.*) {
            .not_started => {},
            inline else => |*value| value.deinit(),
        }
        self.* = undefined;
    }
};

/// Resumes an original held caller from persisted inputs through repository
/// completion. A clean caller is not evidence of an unchanged bootstrap.
pub fn resumeNativeRepository(
    allocator: std.mem.Allocator,
    input: NativeRecoveryRequest,
    dependencies: NativeImportRefreshDependencies,
) !NativeRepositoryResume {
    return resumeNativeRepositoryObserved(allocator, input, dependencies, null);
}

fn resumeNativeRepositoryObserved(
    allocator: std.mem.Allocator,
    input: NativeRecoveryRequest,
    dependencies: NativeImportRefreshDependencies,
    observer: ?NativeCompletionObserver,
) !NativeRepositoryResume {
    try input.validate();
    try validateNativeCallerRecord(allocator, input.attempt);
    if (input.attempt.record().outcome == .abandoned_before_mutation)
        return .{ .unchanged = try completeUnchangedNative(allocator, .{ .recovery = input }, dependencies) };
    if (try native_runtime.canAbandon(allocator, input.attempt)) {
        var paths = try ResolvedPaths.init(allocator, input.repository, .native);
        defer paths.deinit();
        const unchanged_text = try joinLogical(allocator, paths.operation_logical, native_unchanged_evidence_name);
        defer allocator.free(unchanged_text);
        const root = input.attempt.coordinator.root;
        const state_path = try root_fs.Path.init(paths.operation_state_logical[1..]);
        if (try pinNativeCompletion(root, state_path)) |value| {
            var pin = value;
            defer pin.close();
            const observed = try pin.observeStableAlloc(allocator, input.repository.state.maximum_operation_state_bytes);
            defer allocator.free(observed.bytes);
            var state = try state_module.decode(allocator, observed.bytes, input.repository.state.maximum_operation_state_bytes);
            defer state.deinit();
            if (!std.mem.eql(u8, state.state.root, input.repository.root) or
                !std.mem.eql(u8, state.state.architecture, input.attempt.record().target_architecture) or
                state.state.no_refresh != input.repository.no_refresh)
                return error.RepositoryStateMismatch;
            if (state.state.provenance_path != null or state.state.installed or state.state.refreshed or
                state.state.manifest_path != null or phaseAtLeast(state.state.phase, .installed))
                return if (state.state.provenance_path == null or std.mem.eql(u8, state.state.provenance_path.?, unchanged_text))
                    .{ .unchanged = try completeUnchangedNative(allocator, .{ .recovery = input }, dependencies) }
                else
                    .{ .historical = try readNativeRepositoryHistory(allocator, input) };
            _ = try pin.metadata();
        }
        const completion_text = try joinLogical(allocator, paths.operation_logical, root_operation_completion.document_name);
        defer allocator.free(completion_text);
        for ([_][]const u8{ paths.provenance_logical, completion_text, paths.manifest_logical }) |path| {
            if (try root.entryIfExists(try root_fs.Path.init(path[1..])) != null)
                return .{ .historical = try readNativeRepositoryHistory(allocator, input) };
        }
        const descriptor_text = try joinLogical(allocator, paths.operation_logical, native_unchanged_descriptor_name);
        defer allocator.free(descriptor_text);
        if (try root.entryIfExists(try root_fs.Path.init(descriptor_text[1..])) != null or
            try root.entryIfExists(try root_fs.Path.init(unchanged_text[1..])) != null)
            return .{ .unchanged = try completeUnchangedNative(allocator, .{ .recovery = input }, dependencies) };
        try input.validate();
        try validateNativeCallerRecord(allocator, input.attempt);
        return .not_started;
    }
    var context: NativeCompletionContext = .{ .observer = observer };
    errdefer if (context.document) |*document| document.deinit();
    const stage: NativeRepositoryStage = .{ .resume_pipeline = .{ .dependencies = dependencies, .completion = &context } };
    var original = try NativeRepositoryInputs.read(allocator, input, stage);
    defer original.deinit();
    try input.validate();
    try validateNativeCallerRecord(allocator, input.attempt);
    var report = try recoverNative(allocator, input);
    if (report.receipt == null) return .{ .pending = report };
    defer report.deinit();
    try input.validate();
    try original.validate();
    const checkpoint = try nativeRepositoryCheckpointLoaded(allocator, .{
        .repository = input.repository,
        .attempt = input.attempt,
        .expected_receipt_sha256 = report.receipt.?.document.digest_sha256,
        .deadline = input.deadline,
    }, null, stage, &original);
    return .{ .completed = .{ .checkpoint = checkpoint, .completion = context.document.? } };
}

pub const NativeRepositoryHistory = struct {
    state: state_module.OwnedState,
    completion: root_operation_completion.OwnedDocument,
    receipt: native_provenance.OwnedDocument,

    pub fn deinit(self: *@This()) void {
        self.state.deinit();
        self.completion.deinit();
        self.receipt.deinit();
        self.* = undefined;
    }
};

/// Reads the latest matching repository completion under fresh clean exclusion.
/// This never adopts the old attempt or publishes new completion bookkeeping.
pub fn readNativeRepositoryHistory(allocator: std.mem.Allocator, input: NativeRecoveryRequest) !NativeRepositoryHistory {
    return readNativeRepositoryHistoryObserved(allocator, input, null);
}

const NativeHistoryPoint = enum { before_package_verification, after_package_verification };
const NativeHistoryObserver = struct {
    context: *anyopaque,
    hitFn: *const fn (*anyopaque, NativeHistoryPoint) anyerror!void,
};

fn readNativeRepositoryHistoryObserved(
    allocator: std.mem.Allocator,
    input: NativeRecoveryRequest,
    observer: ?NativeHistoryObserver,
) !NativeRepositoryHistory {
    try input.validate();
    try native_transaction_result.validateRepositoryHistoryCaller(allocator, input.attempt);
    const root = input.attempt.coordinator.root;
    var paths = try ResolvedPaths.init(allocator, input.repository, .native);
    defer paths.deinit();
    const completion_path = try joinLogical(allocator, paths.operation_logical, root_operation_completion.document_name);
    defer allocator.free(completion_path);
    var local_completion = try root.pinRegularFile(try root_fs.Path.init(completion_path[1..]));
    defer local_completion.close();
    var shared_completion = try root.pinRegularFile(try root_fs.Path.init(root_operation_completion.document_path));
    defer shared_completion.close();
    var completion = try decodeNativeCompletion(allocator, &local_completion);
    errdefer completion.deinit();
    const completion_bytes = try completion.document.canonicalJson(allocator);
    defer allocator.free(completion_bytes);
    const shared_bytes = try shared_completion.observeStableAlloc(allocator, root_operation_completion.maximum_document_bytes);
    defer allocator.free(shared_bytes.bytes);
    if (!std.mem.eql(u8, completion_bytes, shared_bytes.bytes)) return error.NativeCompletionMismatch;
    const caller = input.attempt.record();
    const outer = completion.document;
    if (!outer.operation.eql(.{ .repository_bootstrap = .add }) or
        std.mem.eql(u8, &outer.attempt_id, &caller.attempt_id) or
        !std.mem.eql(u8, &outer.request_sha256, &caller.request_sha256) or
        !std.mem.eql(u8, &outer.policy_sha256, &caller.policy_sha256))
        return error.NativeCompletionMismatch;
    var original = try NativeRepositoryInputs.readBound(allocator, input, .completion, outer);
    defer original.deinit();
    var local_receipt = try root.pinRegularFile(try root_fs.Path.init(paths.provenance_logical[1..]));
    defer local_receipt.close();
    var shared_receipt = try root.pinRegularFile(try root_fs.Path.init(native_provenance.document_path));
    defer shared_receipt.close();
    const receipt_bytes = try local_receipt.observeStableAlloc(allocator, native_provenance.maximum_document_bytes);
    defer allocator.free(receipt_bytes.bytes);
    var receipt = try native_provenance.decode(allocator, receipt_bytes.bytes);
    errdefer receipt.deinit();
    const current_receipt = try shared_receipt.observeStableAlloc(allocator, native_provenance.maximum_document_bytes);
    defer allocator.free(current_receipt.bytes);
    if (!std.mem.eql(u8, receipt_bytes.bytes, current_receipt.bytes)) return error.NativeReceiptMismatch;
    const failed = switch (receipt.document.outcome) {
        .succeeded => false,
        .failed => true,
        .recovery_required => return error.NativeReceiptMismatch,
    };
    const stored = original.state.state;
    if (stored.phase != (if (failed) state_module.Phase.failed else .complete) or
        stored.diagnostic_id != (if (failed) api.DiagnosticId.transaction_failed else null) or
        (!failed and (!stored.installed or (!input.repository.no_refresh and !stored.refreshed))))
        return error.RepositoryStateMismatch;
    var files: target_apt_config.ProductionFileSystem = .{ .io = root.io, .root = root.dir, .host_root = false };
    if (try descriptorIdentityInstalled(allocator, files.interface(), original.descriptor) != stored.installed)
        return error.RepositoryStateMismatch;
    const receipt_input: NativeReceiptRequest = .{
        .repository = input.repository,
        .attempt = input.attempt,
        .expected_receipt_sha256 = receipt.document.digest_sha256,
        .deadline = input.deadline,
    };
    var manifest = if (failed) null else try NativeRepositoryManifest.read(allocator, input, original.descriptor, stored, paths);
    defer if (manifest) |*value| value.deinit();
    const manifest_sha256 = if (manifest) |value| value.sha256 else null;
    if (!std.mem.eql(u8, &outer.discharge.request_sha256, &nativeCompletionRequestDigest(receipt_input, outer.attempt_id, stored, manifest_sha256)))
        return error.NativeCompletionMismatch;
    const lock_bytes = try original.lock_file.observeStableAlloc(allocator, exact_lock_v2.maximum_document_bytes);
    defer allocator.free(lock_bytes.bytes);
    var lock = try exact_lock_v2.decode(allocator, lock_bytes.bytes, exact_lock_v2.maximum_document_bytes);
    defer lock.deinit();
    if (observer) |value| try value.hitFn(value.context, .before_package_verification);
    try input.validate();
    try native_transaction_result.verifyRepositoryHistory(allocator, input.attempt, lock.lock, repositoryExecutionPolicy(input.repository), outer, receipt.document);
    if (observer) |value| try value.hitFn(value.context, .after_package_verification);
    var state = try state_module.create(allocator, stored);
    errdefer state.deinit();
    var bindings: NativeCheckpointPublication = .{
        .allocator = allocator,
        .input = receipt_input.recoveryRequest(),
        .pins = .{ &original.state_file, &original.plan_file, &original.lock_file },
        .observer = null,
        .manifest_file = if (manifest) |*value| &value.file else null,
        .manifest_sha256 = manifest_sha256,
    };
    try bindings.validate();
    for ([_]*root_fs.PinnedRegularFile{ &local_completion, &shared_completion, &local_receipt, &shared_receipt }) |pin|
        _ = try pin.metadata();
    try native_transaction_result.validateRepositoryHistoryCaller(allocator, input.attempt);
    try input.validate();
    return .{ .state = state, .completion = completion, .receipt = receipt };
}

const native_unchanged_descriptor_name = "native-unchanged-descriptor.deb";
const native_unchanged_evidence_name = "native-repository-unchanged-v1.json";
const maximum_native_unchanged_evidence_bytes = 64 * 1024;

fn nativeUnchangedEvidenceBytes(
    allocator: std.mem.Allocator,
    input: NativeRecoveryRequest,
    original_attempt: [32]u8,
    plan: solver.Plan,
    lock: exact_lock_v2.Lock,
    descriptor: api.DescriptorIdentity,
    database: native_runtime.UnchangedState,
) ![]u8 {
    const caller = input.attempt.record();
    const payload = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = "https://debz.dev/schema/native-repository-unchanged-v1",
        .version = @as(u32, 1),
        .backend = "native",
        .surface = "repository_bootstrap",
        .operation = "add",
        .changed = false,
        .receipt = @as(?u8, null),
        .action_count = @as(u32, 0),
        .install_root = input.repository.root,
        .root_inode = (try input.attempt.coordinator.root.rootEntry()).inode,
        .target_architecture = caller.target_architecture,
        .foreign_architectures = caller.foreign_architectures,
        .caller_attempt_id = @as([]const u8, &native_recovery.hexDigest(original_attempt)),
        .caller_request_sha256 = @as([]const u8, &native_recovery.hexDigest(caller.request_sha256)),
        .caller_policy_sha256 = @as([]const u8, &native_recovery.hexDigest(caller.policy_sha256)),
        .plan_sha256 = @as([]const u8, &native_recovery.hexDigest(transaction_executor.planDigest(plan))),
        .exact_lock_sha256 = @as([]const u8, &native_recovery.hexDigest(lock.digest_sha256)),
        .descriptor_sha256 = @as([]const u8, &native_recovery.hexDigest(descriptor.sha256)),
        .database_generation_sha256 = @as([]const u8, &native_recovery.hexDigest(database.database_generation_sha256)),
        .final_state_sha256 = @as([]const u8, &native_recovery.hexDigest(database.final_state_sha256)),
    }, .{});
    defer allocator.free(payload);
    return std.fmt.allocPrint(allocator, "{s},\"digest_sha256\":\"{s}\"}}\n", .{
        payload[0 .. payload.len - 1], native_recovery.hexDigest(sha256(payload)),
    });
}

pub const NativeUnchangedRequest = struct {
    recovery: NativeRecoveryRequest,
    /// Original acquired descriptor; omitted only when its retained pin exists.
    descriptor_archive: ?[]const u8 = null,
};

pub const NativeRepositoryUnchanged = struct {
    state: state_module.OwnedState,
    database: native_runtime.UnchangedState,
    caller_attempt_id: [32]u8,

    pub fn deinit(self: *@This()) void {
        self.state.deinit();
        self.* = undefined;
    }
};

const NativeUnchangedPoint = enum {
    after_descriptor,
    after_installed,
    after_import_refresh,
    after_complete,
    after_caller_completion,
    after_clear,
    after_evidence,
};
const NativeUnchangedObserver = struct {
    context: *anyopaque,
    hitFn: *const fn (*anyopaque, NativeUnchangedPoint) anyerror!void,
};

/// Completes bootstrap after genuine no-execution preparation, without a native
/// receipt or mutated-caller completion. The unexecuted caller keeps its lock.
pub fn completeUnchangedNative(
    allocator: std.mem.Allocator,
    input: NativeUnchangedRequest,
    dependencies: NativeImportRefreshDependencies,
) !NativeRepositoryUnchanged {
    return completeUnchangedNativeObserved(allocator, input, dependencies, null);
}

const NativeUnchangedGuard = struct {
    allocator: std.mem.Allocator,
    input: NativeRecoveryRequest,
    preparation: native_runtime.PrepareRequest,
    database: native_runtime.UnchangedState,
    caller_sha256: [32]u8,
    provenance_path: root_fs.Path,
    completion_path: root_fs.Path,
    descriptor_file: ?*root_fs.PinnedRegularFile = null,
    evidence_file: ?*root_fs.PinnedRegularFile = null,

    fn validate(self: *@This()) !void {
        try self.input.validate();
        const attempt = self.input.attempt;
        try validateNativeCallerRecord(self.allocator, attempt);
        if (!std.mem.eql(u8, &self.caller_sha256, &attempt.record().digest_sha256))
            return error.StaleAttempt;
        const root = attempt.coordinator.root;
        for ([_]root_fs.Path{ self.provenance_path, self.completion_path, try root_fs.Path.init(root_operation.deferred_ack_path) }) |path| {
            if (try root.entryIfExists(path) != null) return error.OperationNotSettled;
        }
        if (self.descriptor_file) |pin| _ = try pin.metadata();
        if (self.evidence_file) |pin| _ = try pin.metadata();
        if (!self.database.eql(try native_runtime.verifyUnchanged(self.allocator, self.preparation)))
            return error.FinalStateMismatch;
        try self.input.validate();
        if (!std.mem.eql(u8, &self.caller_sha256, &attempt.record().digest_sha256))
            return error.StaleAttempt;
    }
};

fn completeUnchangedNativeObserved(
    allocator: std.mem.Allocator,
    request: NativeUnchangedRequest,
    dependencies: NativeImportRefreshDependencies,
    observer: ?NativeUnchangedObserver,
) !NativeRepositoryUnchanged {
    const input = request.recovery;
    try input.validate();
    try validateNativeCallerRecord(allocator, input.attempt);
    var original = try NativeRepositoryInputs.readUnchanged(allocator, input);
    defer original.deinit();
    const root = input.attempt.coordinator.root;
    const paths = original.paths;
    const descriptor = original.descriptor;
    const plan_bytes = try original.plan_file.observeStableAlloc(allocator, repository_plan.maximum_document_bytes);
    defer allocator.free(plan_bytes.bytes);
    var plan = try repository_plan.decode(allocator, plan_bytes.bytes);
    defer plan.deinit();
    const lock_bytes = try original.lock_file.observeStableAlloc(allocator, exact_lock_v2.maximum_document_bytes);
    defer allocator.free(lock_bytes.bytes);
    var lock = try exact_lock_v2.decode(allocator, lock_bytes.bytes, exact_lock_v2.maximum_document_bytes);
    defer lock.deinit();
    const preparation: native_runtime.PrepareRequest = .{
        .attempt = input.attempt,
        .plan = &plan,
        .exact_lock = &lock.lock,
        .archives = &.{},
        .policy = repositoryExecutionPolicy(input.repository),
    };
    const completion_text = try joinLogical(allocator, paths.operation_logical, root_operation_completion.document_name);
    defer allocator.free(completion_text);
    var guard: NativeUnchangedGuard = .{
        .allocator = allocator,
        .input = input,
        .preparation = preparation,
        .database = try native_runtime.verifyUnchanged(allocator, preparation),
        .caller_sha256 = input.attempt.record().digest_sha256,
        .provenance_path = try root_fs.Path.init(paths.provenance_logical[1..]),
        .completion_path = try root_fs.Path.init(completion_text[1..]),
    };
    try guard.validate();
    if (input.attempt.record().state == .completed and original.state.state.phase != .complete)
        return error.RepositoryStateMismatch;
    try validateNativeArchiveSize(input.repository, descriptor.size);
    if (descriptor.size > input.repository.network.maximum_descriptor_bytes or
        descriptor.size > input.repository.resources.maximum_total_package_bytes)
        return error.ResourceBudgetExceeded;
    var retained_bytes: u64 = 0;
    try OperationBudget.charge(&retained_bytes, descriptor.size, input.repository.resources.maximum_retained_package_bytes);
    if (request.descriptor_archive) |bytes| {
        try OperationBudget.charge(&retained_bytes, bytes.len, input.repository.resources.maximum_retained_package_bytes);
        if (bytes.len != descriptor.size or !std.mem.eql(u8, &sha256(bytes), &descriptor.sha256))
            return error.DescriptorIdentityMismatch;
    }
    if (input.repository.expected_sha256) |expected| {
        if (!std.mem.eql(u8, &expected, &descriptor.sha256)) return error.DescriptorIdentityMismatch;
    }
    const evidence_text = try joinLogical(allocator, paths.operation_logical, native_unchanged_evidence_name);
    defer allocator.free(evidence_text);
    const evidence_path = try root_fs.Path.init(evidence_text[1..]);
    const descriptor_text = try joinLogical(allocator, paths.operation_logical, native_unchanged_descriptor_name);
    defer allocator.free(descriptor_text);
    const descriptor_path = try root_fs.Path.init(descriptor_text[1..]);
    var retained = try pinNativeCompletion(root, descriptor_path);
    defer if (retained) |*pin| pin.close();
    const bytes = if (retained) |*pin|
        (try pin.observeStableAlloc(allocator, input.repository.network.maximum_descriptor_bytes)).bytes
    else blk: {
        if (original.state.state.phase != .locked or try root.entryIfExists(evidence_path) != null)
            return error.FileNotFound;
        break :blk try allocator.dupe(u8, request.descriptor_archive orelse return error.NativeDescriptorMissing);
    };
    var material = try inspectNativeDescriptorMaterial(allocator, input, descriptor, bytes, original.state.state);
    defer material.deinit();
    var files: target_apt_config.ProductionFileSystem = .{ .io = root.io, .root = root.dir, .host_root = false };
    try verifyInstalledDescriptor(allocator, files.interface(), descriptor, material.material.evidence);
    var current = try state_module.create(allocator, original.state.state);
    errdefer current.deinit();
    var publication: NativeCheckpointPublication = .{
        .allocator = allocator,
        .input = input,
        .pins = .{ &original.state_file, &original.plan_file, &original.lock_file },
        .observer = null,
        .unchanged = &guard,
        .result_progress = dependencies.result_progress,
    };
    if (retained == null) {
        try retainNativeReceiptBytes(allocator, root, descriptor_path, material.bytes, .{ .context = &publication, .hitFn = NativeCheckpointPublication.hit });
        retained = try root.pinRegularFile(descriptor_path);
    }
    guard.descriptor_file = &retained.?;
    if (observer) |value| try value.hitFn(value.context, .after_descriptor);
    try publication.validate();
    var evidence_file = try pinNativeCompletion(root, evidence_path);
    defer if (evidence_file) |*pin| pin.close();
    var original_attempt = input.attempt.attemptId();
    if (evidence_file) |*pin| {
        const observed = try pin.observeStableAlloc(allocator, maximum_native_unchanged_evidence_bytes);
        defer allocator.free(observed.bytes);
        var envelope = try std.json.parseFromSlice(struct { caller_attempt_id: []const u8 }, allocator, observed.bytes, .{ .ignore_unknown_fields = true });
        defer envelope.deinit();
        if (envelope.value.caller_attempt_id.len != 64) return error.NativeUnchangedEvidenceMismatch;
        _ = std.fmt.hexToBytes(&original_attempt, envelope.value.caller_attempt_id) catch return error.NativeUnchangedEvidenceMismatch;
        const expected = try nativeUnchangedEvidenceBytes(allocator, input, original_attempt, plan, lock.lock, descriptor, guard.database);
        defer allocator.free(expected);
        if (!std.mem.eql(u8, observed.bytes, expected)) return error.NativeUnchangedEvidenceMismatch;
    } else {
        if (current.state.phase != .locked) return error.FileNotFound;
        const expected = try nativeUnchangedEvidenceBytes(allocator, input, original_attempt, plan, lock.lock, descriptor, guard.database);
        defer allocator.free(expected);
        if (expected.len > maximum_native_unchanged_evidence_bytes) return error.DocumentTooLarge;
        try retainNativeReceiptBytes(allocator, root, evidence_path, expected, .{ .context = &publication, .hitFn = NativeCheckpointPublication.hit });
        evidence_file = try root.pinRegularFile(evidence_path);
    }
    guard.evidence_file = &evidence_file.?;
    if (observer) |value| try value.hitFn(value.context, .after_evidence);
    try publication.validate();
    if (current.state.phase == .locked) {
        var installed = current.state;
        installed.phase = .installed;
        installed.installed = true;
        installed.provenance_path = evidence_text;
        installed.diagnostic_id = null;
        installed.diagnostic = "";
        try publication.advance(allocator, &current, paths, installed);
    } else if (!current.state.installed) return error.RepositoryStateMismatch;
    if (observer) |value| try value.hitFn(value.context, .after_installed);
    try publication.validate();
    if (current.state.phase != .complete)
        try importNativeDescriptorMaterial(allocator, &publication, &current, paths, descriptor, &material, dependencies);
    if (observer) |value| try value.hitFn(value.context, .after_import_refresh);
    try publication.validate();
    if (current.state.diagnostic_id != null or (!input.repository.no_refresh and !current.state.refreshed))
        return error.RepositoryPostInstallIncomplete;
    var manifest = try NativeRepositoryManifest.read(allocator, input, descriptor, current.state, paths);
    defer manifest.deinit();
    publication.manifest_file = &manifest.file;
    publication.manifest_sha256 = manifest.sha256;
    if (current.state.phase != .complete) {
        var completed = current.state;
        completed.phase = .complete;
        try publication.advance(allocator, &current, paths, completed);
    }
    if (observer) |value| try value.hitFn(value.context, .after_complete);
    try publication.validate();
    if (input.attempt.record().state != .completed) {
        try input.attempt.complete(allocator, .abandoned_before_mutation);
        guard.caller_sha256 = input.attempt.record().digest_sha256;
    }
    if (observer) |value| try value.hitFn(value.context, .after_caller_completion);
    try publication.validate();
    if (try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) != null)
        try input.attempt.clear();
    if (observer) |value| try value.hitFn(value.context, .after_clear);
    try publication.validate();
    return .{ .state = current, .database = guard.database, .caller_attempt_id = input.attempt.attemptId() };
}

/// Publishes terminal repository state and caller completion before native
/// acknowledgment and root-record cleanup. The caller still owns its lock.
pub fn completeNative(allocator: std.mem.Allocator, input: NativeReceiptRequest) !NativeRepositoryCompletion {
    return completeNativeObserved(allocator, input, null);
}

fn completeNativeObserved(
    allocator: std.mem.Allocator,
    input: NativeReceiptRequest,
    observer: ?NativeCompletionObserver,
) !NativeRepositoryCompletion {
    var context: NativeCompletionContext = .{ .observer = observer };
    errdefer if (context.document) |*document| document.deinit();
    const checkpoint = try nativeRepositoryCheckpoint(allocator, input, null, .{ .completion = &context });
    return .{ .checkpoint = checkpoint, .completion = context.document.? };
}

const NativeRepositoryStage = union(enum) {
    package,
    post_install: NativeImportRefreshDependencies,
    completion: *NativeCompletionContext,
    resume_pipeline: struct {
        dependencies: NativeImportRefreshDependencies,
        completion: *NativeCompletionContext,
    },
};

/// Resumes only post-package work from original persisted evidence. Successful
/// import/refresh is not outer completion and leaves native ownership pending.
pub fn importAndRefreshNative(
    allocator: std.mem.Allocator,
    input: NativeReceiptRequest,
    dependencies: NativeImportRefreshDependencies,
) !NativeRepositoryCheckpoint {
    return nativeRepositoryCheckpoint(allocator, input, null, .{ .post_install = dependencies });
}

/// Publishes package-stage bookkeeping from the original persisted inputs and
/// live native outcome. Import, refresh and outer completion remain separate;
/// this never acknowledges execution or releases the repository caller.
pub fn persistNativePackageState(allocator: std.mem.Allocator, input: NativeReceiptRequest) !NativePackageCheckpoint {
    return persistNativePackageStateObserved(allocator, input, null);
}

fn persistNativePackageStateObserved(
    allocator: std.mem.Allocator,
    input: NativeReceiptRequest,
    observer: ?root_fs.PublishObserver,
) !NativePackageCheckpoint {
    return nativeRepositoryCheckpoint(allocator, input, observer, .package);
}

fn nativeRepositoryCheckpoint(
    allocator: std.mem.Allocator,
    input: NativeReceiptRequest,
    observer: ?root_fs.PublishObserver,
    stage: NativeRepositoryStage,
) !NativeRepositoryCheckpoint {
    var original = try NativeRepositoryInputs.read(allocator, input.recoveryRequest(), stage);
    defer original.deinit();
    return nativeRepositoryCheckpointLoaded(allocator, input, observer, stage, &original);
}

const NativeRepositoryInputs = struct {
    paths: ResolvedPaths,
    state_file: root_fs.PinnedRegularFile,
    plan_file: root_fs.PinnedRegularFile,
    lock_file: root_fs.PinnedRegularFile,
    state: state_module.OwnedState,
    descriptor: api.DescriptorIdentity,

    fn deinit(self: *@This()) void {
        self.state.deinit();
        self.lock_file.close();
        self.plan_file.close();
        self.state_file.close();
        self.paths.deinit();
        self.* = undefined;
    }

    fn validate(self: *@This()) !void {
        _ = try self.state_file.metadata();
        _ = try self.plan_file.metadata();
        _ = try self.lock_file.metadata();
    }

    fn read(allocator: std.mem.Allocator, input: NativeRecoveryRequest, stage: NativeRepositoryStage) !@This() {
        try input.validate();
        return readValidated(allocator, input, std.meta.activeTag(stage), input.attempt.record(), false);
    }

    fn readBound(allocator: std.mem.Allocator, input: NativeRecoveryRequest, stage: std.meta.Tag(NativeRepositoryStage), record: anytype) !@This() {
        try input.validate();
        return readValidated(allocator, input, stage, record, false);
    }

    fn readUnchanged(allocator: std.mem.Allocator, input: NativeRecoveryRequest) !@This() {
        try input.validate();
        return readValidated(allocator, input, .completion, input.attempt.record(), true);
    }

    fn readValidated(allocator: std.mem.Allocator, input: NativeRecoveryRequest, stage: std.meta.Tag(NativeRepositoryStage), record: anytype, unchanged: bool) !@This() {
        var paths = try ResolvedPaths.init(allocator, input.repository, .native);
        errdefer paths.deinit();
        const unchanged_text = if (unchanged) try joinLogical(allocator, paths.operation_logical, native_unchanged_evidence_name) else null;
        defer if (unchanged_text) |text| allocator.free(text);
        const root = input.attempt.coordinator.root;
        const state_path = try root_fs.Path.init(paths.operation_state_logical[1..]);
        var state_file = try root.pinRegularFile(state_path);
        errdefer state_file.close();
        const state_bytes = try state_file.observeStableAlloc(allocator, input.repository.state.maximum_operation_state_bytes);
        defer allocator.free(state_bytes.bytes);
        var prior = try state_module.decode(allocator, state_bytes.bytes, input.repository.state.maximum_operation_state_bytes);
        errdefer prior.deinit();
        const state = prior.state;
        if (!std.mem.eql(u8, state.root, input.repository.root) or
            !std.mem.eql(u8, state.architecture, record.target_architecture) or
            state.no_refresh != input.repository.no_refresh or
            state.managed_files.len == 0 or
            !std.mem.eql(u8, state.plan_path orelse return error.RepositoryStateMismatch, paths.exact_plan_logical) or
            !std.mem.eql(u8, state.exact_lock_path orelse return error.RepositoryStateMismatch, paths.exact_lock_logical))
            return error.RepositoryStateMismatch;
        switch (state.phase) {
            .locked => {},
            .installed, .failed, .imported, .refreshed, .complete => {
                if ((stage == .package and (state.phase == .imported or state.phase == .refreshed)) or
                    (state.phase == .complete and stage != .completion and stage != .resume_pipeline))
                    return error.RepositoryPackageStageAlreadyAdvanced;
                if (unchanged) {
                    if (state.provenance_path == null or !std.mem.eql(u8, state.provenance_path.?, unchanged_text.?) or state.phase == .failed)
                        return error.RepositoryStateMismatch;
                } else if (!std.mem.eql(u8, state.provenance_path orelse return error.RepositoryStateMismatch, paths.provenance_logical) or
                    (state.phase == .failed and state.diagnostic_id != .transaction_failed)) return error.RepositoryStateMismatch;
                if (state.phase == .imported or state.phase == .refreshed or state.phase == .complete) {
                    if (!std.mem.eql(u8, state.manifest_path orelse return error.RepositoryStateMismatch, paths.manifest_logical))
                        return error.RepositoryStateMismatch;
                } else if (state.manifest_path != null or state.refreshed) return error.RepositoryStateMismatch;
            },
            else => return error.RepositoryStateMismatch,
        }
        const descriptor_state = state.descriptor orelse return error.RepositoryStateMismatch;
        const descriptor: api.DescriptorIdentity = .{
            .package = descriptor_state.package,
            .version = descriptor_state.version,
            .architecture = descriptor_state.architecture,
            .sha256 = descriptor_state.sha256,
            .size = descriptor_state.size,
            .effective_url = descriptor_state.effective_url,
            .trust_mode = descriptor_state.trust_mode,
        };
        var plan_file = try root.pinRegularFile(try root_fs.Path.init(paths.exact_plan_logical[1..]));
        errdefer plan_file.close();
        const plan_bytes = try plan_file.observeStableAlloc(allocator, repository_plan.maximum_document_bytes);
        defer allocator.free(plan_bytes.bytes);
        var plan = try repository_plan.decode(allocator, plan_bytes.bytes);
        defer plan.deinit();
        const plan_sha256 = transaction_executor.planDigest(plan);
        if (!std.mem.eql(u8, &plan_sha256, &(state.plan_sha256 orelse return error.PlanEvidenceMismatch)) or
            !std.mem.eql(u8, plan.target_architecture, record.target_architecture))
            return error.PlanEvidenceMismatch;
        if (record.plan_sha256) |expected| {
            if (!std.mem.eql(u8, &plan_sha256, &expected)) return error.PlanEvidenceMismatch;
        } else if (!unchanged) return error.PlanEvidenceMismatch;
        if (unchanged and (plan.actions.len != 0 or plan.ordered_actions.len != 0))
            return error.InvalidUnchangedRequest;
        var lock_file = try root.pinRegularFile(try root_fs.Path.init(paths.exact_lock_logical[1..]));
        errdefer lock_file.close();
        const lock_bytes = try lock_file.observeStableAlloc(allocator, exact_lock_v2.maximum_document_bytes);
        defer allocator.free(lock_bytes.bytes);
        var lock = try exact_lock_v2.decode(allocator, lock_bytes.bytes, exact_lock_v2.maximum_document_bytes);
        defer lock.deinit();
        if (record.exact_lock) |expected| {
            if (!expected.eql(.{
                .schema = exact_lock_v2.schema_id,
                .version = exact_lock_v2.schema_version,
                .digest_sha256 = lock.lock.digest_sha256,
            })) return error.LockEvidenceMismatch;
        } else if (!unchanged) return error.LockEvidenceMismatch;
        if (plan.actions.len > input.repository.resources.maximum_actions or
            lock.lock.packages.len > input.repository.resources.maximum_actions or
            lock.lock.repositories.len > input.repository.resources.maximum_repositories)
            return error.ResourceBudgetExceeded;
        try validateLockPolicy(lock.lock, .native);
        try validateLockRequest(allocator, lock.lock, input.repository, plan, .native);
        try validateLockDescriptor(lock.lock, descriptor);
        try input.validate();
        var result: @This() = .{
            .paths = paths,
            .state_file = state_file,
            .plan_file = plan_file,
            .lock_file = lock_file,
            .state = prior,
            .descriptor = descriptor,
        };
        try result.validate();
        return result;
    }
};

fn nativeRepositoryCheckpointLoaded(
    allocator: std.mem.Allocator,
    input: NativeReceiptRequest,
    observer: ?root_fs.PublishObserver,
    stage: NativeRepositoryStage,
    original: *NativeRepositoryInputs,
) !NativeRepositoryCheckpoint {
    try input.validate();
    try original.validate();
    const state = original.state.state;
    const paths = original.paths;
    const root = input.attempt.coordinator.root;
    const descriptor = original.descriptor;
    if (state.provenance_path == null) {
        var retained = try retainNativeReceipt(allocator, input);
        defer retained.deinit();
    }
    var package_state = try verifyNativePackageState(allocator, input);
    errdefer package_state.deinit();
    // Borrow the already-admitted root; this adapter does not own its descriptor.
    var filesystem: target_apt_config.ProductionFileSystem = .{ .io = root.io, .root = root.dir, .host_root = false };
    const installed = try descriptorIdentityInstalled(allocator, filesystem.interface(), descriptor);
    var next = if (state.phase == .imported or state.phase == .refreshed or state.phase == .complete) blk: {
        if (package_state != .succeeded or !installed or !state.installed)
            return error.RepositoryStateMismatch;
        break :blk try state_module.create(allocator, state);
    } else try nativePackageCheckpointState(allocator, state, package_state == .failed, installed, paths.provenance_logical);
    errdefer next.deinit();
    var publication: NativeCheckpointPublication = .{
        .allocator = allocator,
        .input = input.recoveryRequest(),
        .pins = .{ &original.state_file, &original.plan_file, &original.lock_file },
        .observer = observer,
        .result_progress = switch (stage) {
            .post_install => |dependencies| dependencies.result_progress,
            .resume_pipeline => |pipeline| pipeline.dependencies.result_progress,
            else => null,
        },
    };
    try publication.persist(allocator, next.state, paths);
    switch (stage) {
        .package => {},
        .post_install => |dependencies| if (package_state == .succeeded)
            try resumeNativeImportRefresh(allocator, &publication, &next, paths, descriptor, package_state.succeeded.receipt.document, dependencies),
        .completion => |context| try finishNativeRepository(allocator, &publication, &next, paths, descriptor, package_state, context),
        .resume_pipeline => |pipeline| {
            if (package_state == .succeeded and next.state.phase != .complete)
                try resumeNativeImportRefresh(allocator, &publication, &next, paths, descriptor, package_state.succeeded.receipt.document, pipeline.dependencies);
            try finishNativeRepository(allocator, &publication, &next, paths, descriptor, package_state, pipeline.completion);
        },
    }
    try validateNativeRepositoryCaller(input.repository, input.attempt);
    try input.attempt.coordinator.validateProjection();
    return .{ .state = next, .package_state = package_state };
}

const NativeCheckpointPublication = struct {
    allocator: std.mem.Allocator,
    input: NativeRecoveryRequest,
    pins: [3]*root_fs.PinnedRegularFile,
    observer: ?root_fs.PublishObserver,
    manifest_file: ?*const root_fs.PinnedRegularFile = null,
    manifest_sha256: ?[32]u8 = null,
    unchanged: ?*NativeUnchangedGuard = null,
    result_progress: ?*NativeDispatchProgress = null,

    fn validate(self: *const @This()) !void {
        try self.input.validate();
        if (self.unchanged) |guard| try guard.validate();
        for (self.pins) |pin| _ = try pin.metadata();
        if (self.manifest_file) |pin| _ = try pin.metadata();
        if (self.manifest_sha256) |expected| {
            var snapshot = try nativeRepositorySnapshot(self.allocator, self.input);
            defer snapshot.deinit();
            if (!std.mem.eql(u8, &expected, &snapshot.manifest.manifest.digest_sha256))
                return error.ImportedDigestMismatch;
            try self.input.validate();
        }
    }

    fn persist(self: *@This(), allocator: std.mem.Allocator, state: state_module.State, paths: ResolvedPaths) !void {
        const bytes = try state.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > self.input.repository.state.maximum_operation_state_bytes) return error.DocumentTooLarge;
        const root = self.input.attempt.coordinator.root;
        const pin = self.pins[0];
        const prior = try pin.observeStableAlloc(allocator, self.input.repository.state.maximum_operation_state_bytes);
        defer allocator.free(prior.bytes);
        try self.validate();
        if (self.result_progress) |progress| try progress.capture(allocator, state);
        if (std.mem.eql(u8, bytes, prior.bytes)) {
            // Finish durability if an earlier checkpoint stopped after rename.
            try pin.file.sync(root.io);
            try root.syncDirectory(try root_fs.Path.init(paths.operation_logical[1..]));
            _ = try pin.metadata();
        } else {
            const path = try root_fs.Path.init(paths.operation_state_logical[1..]);
            try root.publishFile(path, bytes, .{
                .permissions = .fromMode(0o600),
                .overwrite = .replace,
                .durable = true,
                .observer = .{ .context = self, .hitFn = hit },
            });
            var replacement = try root.pinRegularFile(path);
            errdefer replacement.close();
            const observed = try replacement.observeStableAlloc(allocator, self.input.repository.state.maximum_operation_state_bytes);
            defer allocator.free(observed.bytes);
            if (!std.mem.eql(u8, bytes, observed.bytes)) return error.RepositoryStateMismatch;
            pin.close();
            pin.* = replacement;
        }
    }

    fn advance(self: *@This(), allocator: std.mem.Allocator, current: *state_module.OwnedState, paths: ResolvedPaths, state: state_module.State) !void {
        var next = try state_module.create(allocator, state);
        errdefer next.deinit();
        try self.persist(allocator, next.state, paths);
        current.deinit();
        current.* = next;
    }

    fn fail(self: *@This(), allocator: std.mem.Allocator, current: *state_module.OwnedState, paths: ResolvedPaths, id: api.DiagnosticId, err: anyerror) anyerror {
        return self.failMessage(allocator, current, paths, id, err, @errorName(err));
    }

    fn failMessage(self: *@This(), allocator: std.mem.Allocator, current: *state_module.OwnedState, paths: ResolvedPaths, id: api.DiagnosticId, err: anyerror, message: []const u8) anyerror {
        var failed = current.state;
        failed.diagnostic_id = id;
        failed.diagnostic = message;
        self.advance(allocator, current, paths, failed) catch |publication_error| return publication_error;
        return err;
    }

    fn hit(raw: *anyopaque, point: root_fs.PublishPoint) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (self.observer) |observer| try observer.hit(point);
        if (point == .before_rename) try self.validate();
    }
};

fn nativePackageCheckpointState(
    allocator: std.mem.Allocator,
    prior: state_module.State,
    failed: bool,
    installed: bool,
    provenance_path: []const u8,
) !state_module.OwnedState {
    if (!failed and !installed) return error.DescriptorIdentityMismatch;
    var next = prior;
    switch (prior.phase) {
        .locked => {
            next.phase = if (failed) .failed else .installed;
            next.installed = installed;
            next.provenance_path = provenance_path;
            next.diagnostic_id = if (failed) .transaction_failed else null;
            next.diagnostic = if (failed) "native repository package transaction failed" else "";
        },
        .installed, .failed => {
            if ((prior.phase == .failed) != failed or prior.installed != installed)
                return error.RepositoryStateMismatch;
        },
        else => return error.RepositoryPackageStageAlreadyAdvanced,
    }
    return state_module.create(allocator, next);
}

fn nativeRepositorySnapshot(allocator: std.mem.Allocator, input: NativeRecoveryRequest) !target_apt_config.Snapshot {
    try input.validate();
    const root = input.attempt.coordinator.root;
    var filesystem: target_apt_config.ProductionFileSystem = .{ .io = root.io, .root = root.dir, .host_root = false };
    var snapshot = try target_apt_config.snapshot(allocator, .{
        .root_path = input.repository.root,
        .architecture_override = input.attempt.record().target_architecture,
        .limits = targetLimits(input.repository.resources),
        .dependencies = .{ .filesystem = filesystem.interface(), .process = null },
    });
    errdefer snapshot.deinit();
    if (RootOperationGuard.checkArchitecture(input.attempt.record(), .{
        .native = snapshot.manifest.manifest.native_architecture,
        .foreign = snapshot.manifest.manifest.foreign_architectures,
    }) != null) return error.RepositoryArchitectureMismatch;
    try input.validate();
    return snapshot;
}

fn nativeDescriptorBytes(
    allocator: std.mem.Allocator,
    input: NativeReceiptRequest,
    descriptor: api.DescriptorIdentity,
    receipt: native_provenance.Document,
) ![]u8 {
    try input.validate();
    try validateNativeArchiveSize(input.repository, descriptor.size);
    if (descriptor.size > input.repository.network.maximum_descriptor_bytes or
        descriptor.size > input.repository.resources.maximum_retained_package_bytes)
        return error.ResourceBudgetExceeded;
    const root = input.attempt.coordinator.root;
    var intent = try native_recovery.readIntent(allocator, root);
    defer intent.deinit();
    if (!std.mem.eql(u8, &intent.intent.digest_sha256, &receipt.execution_intent_sha256))
        return error.NativeReceiptMismatch;
    var found: ?native_recovery.Blob = null;
    const digest = native_recovery.hexDigest(descriptor.sha256);
    for (intent.intent.blobs) |blob| {
        if (blob.kind != .artifact or !std.mem.eql(u8, &blob.sha256, &digest)) continue;
        if (found != null or blob.size != descriptor.size) return error.DescriptorIdentityMismatch;
        found = blob;
    }
    const bytes = try native_recovery.verifyBlob(allocator, root, found orelse return error.DescriptorMissingFromIntent);
    errdefer allocator.free(bytes);
    try input.validate();
    return bytes;
}

const NativeDescriptorMaterial = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    validation: deb_payload.Validation,
    material: DescriptorMaterial,

    fn deinit(self: *@This()) void {
        self.material.deinit();
        self.validation.deinit();
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn readNativeDescriptorMaterial(
    allocator: std.mem.Allocator,
    input: NativeReceiptRequest,
    descriptor: api.DescriptorIdentity,
    receipt: native_provenance.Document,
    state: state_module.State,
) !NativeDescriptorMaterial {
    const bytes = try nativeDescriptorBytes(allocator, input, descriptor, receipt);
    return inspectNativeDescriptorMaterial(allocator, input.recoveryRequest(), descriptor, bytes, state);
}

fn inspectNativeDescriptorMaterial(
    allocator: std.mem.Allocator,
    input: NativeRecoveryRequest,
    descriptor: api.DescriptorIdentity,
    bytes: []u8,
    state: state_module.State,
) !NativeDescriptorMaterial {
    errdefer allocator.free(bytes);
    if (bytes.len != descriptor.size or !std.mem.eql(u8, &sha256(bytes), &descriptor.sha256))
        return error.DescriptorIdentityMismatch;
    var validation = switch (deb_payload.inspectLocal(allocator, bytes, .{
        .source = "repository-descriptor",
        .filename = std.fs.path.basename(descriptor.effective_url),
        .size = descriptor.size,
        .sha256 = descriptor.sha256,
        .profile = .repository_descriptor,
    }, .{})) {
        .diagnostic => |diagnostic| return if (diagnostic.code == .out_of_memory) error.OutOfMemory else error.InvalidRepositoryDescriptor,
        .validation => |value| value,
    };
    errdefer validation.deinit();
    if (!std.mem.eql(u8, validation.package, descriptor.package) or
        !std.mem.eql(u8, validation.version, descriptor.version) or
        !std.mem.eql(u8, validation.architecture, descriptor.architecture))
        return error.DescriptorIdentityMismatch;
    var material = try inspectDescriptorMaterial(allocator, &validation, state.architecture, input.repository.network, input.repository.resources);
    errdefer material.deinit();
    if (material.evidence.len != state.managed_files.len) return error.RepositoryStateMismatch;
    for (material.evidence, state.managed_files) |actual, expected| {
        if (!std.mem.eql(u8, actual.logical_path, expected.logical_path) or actual.size != expected.size or
            !std.mem.eql(u8, &actual.sha256, &expected.sha256)) return error.RepositoryStateMismatch;
    }
    return .{ .allocator = allocator, .bytes = bytes, .validation = validation, .material = material };
}

fn resumeNativeImportRefresh(
    allocator: std.mem.Allocator,
    publication: *NativeCheckpointPublication,
    current: *state_module.OwnedState,
    paths: ResolvedPaths,
    descriptor: api.DescriptorIdentity,
    receipt: native_provenance.Document,
    dependencies: NativeImportRefreshDependencies,
) !void {
    const input: NativeReceiptRequest = .{
        .repository = publication.input.repository,
        .attempt = publication.input.attempt,
        .deadline = publication.input.deadline,
        .expected_receipt_sha256 = receipt.digest_sha256,
    };
    var original = try readNativeDescriptorMaterial(allocator, input, descriptor, receipt, current.state);
    defer original.deinit();
    try importNativeDescriptorMaterial(allocator, publication, current, paths, descriptor, &original, dependencies);
}

fn importNativeDescriptorMaterial(
    allocator: std.mem.Allocator,
    publication: *NativeCheckpointPublication,
    current: *state_module.OwnedState,
    paths: ResolvedPaths,
    descriptor: api.DescriptorIdentity,
    original: *NativeDescriptorMaterial,
    dependencies: NativeImportRefreshDependencies,
) !void {
    const input = publication.input;
    const root = input.attempt.coordinator.root;
    const material = &original.material;
    var filesystem: target_apt_config.ProductionFileSystem = .{ .io = root.io, .root = root.dir, .host_root = false };
    verifyInstalledDescriptor(allocator, filesystem.interface(), descriptor, material.evidence) catch |err|
        return publication.fail(allocator, current, paths, .installed_verification_failed, err);
    var snapshot = nativeRepositorySnapshot(allocator, input) catch |err|
        return publication.fail(allocator, current, paths, .target_import_failed, err);
    defer snapshot.deinit();
    verifyImportedMaterial(snapshot, material.evidence) catch |err|
        return publication.fail(allocator, current, paths, .target_import_failed, err);
    const manifest_bytes = try snapshot.manifest.manifest.canonicalJson(allocator);
    defer allocator.free(manifest_bytes);
    publication.manifest_sha256 = snapshot.manifest.manifest.digest_sha256;
    defer publication.manifest_sha256 = null;
    const manifest_path = try root_fs.Path.init(paths.manifest_logical[1..]);
    try publication.validate();
    if (current.state.manifest_path == null) {
        retainNativeReceiptBytes(allocator, root, manifest_path, manifest_bytes, .{
            .context = publication,
            .hitFn = NativeCheckpointPublication.hit,
        }) catch |err| switch (err) {
            error.NativeReceiptMismatch => return error.ImportedDigestMismatch,
            else => return err,
        };
    }
    var manifest_file = try root.pinRegularFile(manifest_path);
    defer manifest_file.close();
    const retained = try manifest_file.observeStableAlloc(allocator, target_apt_config.maximum_document_bytes);
    defer allocator.free(retained.bytes);
    if (!std.mem.eql(u8, manifest_bytes, retained.bytes)) return error.ImportedDigestMismatch;
    publication.manifest_file = &manifest_file;
    defer publication.manifest_file = null;
    var imported = current.state;
    if (imported.phase == .installed) imported.phase = .imported;
    imported.manifest_path = paths.manifest_logical;
    // A prior refresh diagnostic survives until refresh itself succeeds.
    if (imported.diagnostic_id != .refresh_failed) {
        imported.diagnostic_id = null;
        imported.diagnostic = "";
    }
    try publication.advance(allocator, current, paths, imported);
    if (input.repository.no_refresh or current.state.refreshed) return;

    var acquisition = dependencies.acquisition;
    var clock: NativeInvocationClock = .{
        .input = input,
        .deadline = input.deadline,
        .original = acquisition.clock,
    };
    acquisition.clock = clock.interface();
    var budget = OperationBudget.init(acquisition.clock, input.repository.resources, try input.deadline.remainingMs(), allocator);
    budget.deadline_ms = input.deadline.expires_at_ms;
    budget.native_input = input;
    budget.descriptor_bytes = descriptor.size;
    try publication.validate();
    const cache_path = try root_fs.Path.init(paths.cache_logical[1..]);
    try root.createDirectoryPath(cache_path, .fromMode(0o700));
    var cache_directory = try root.openDirectory(cache_path);
    defer cache_directory.close(root.io);
    var cache = try metadata_cache.Cache.initFromDir(root.io, cache_directory, .{});
    defer cache.deinit();
    try publication.validate();
    var refreshed = refreshDescriptor(allocator, material, &material.configuration, &cache, acquisition, input.repository.network, &budget, dependencies.now_unix) catch |err|
        return publication.fail(allocator, current, paths, .refresh_failed, err);
    defer refreshed.deinit(allocator);
    switch (refreshed) {
        .failed => |diagnostics| return publication.failMessage(
            allocator,
            current,
            paths,
            .refresh_failed,
            error.RepositoryRefreshFailed,
            if (diagnostics.len == 0) "installed repository refresh failed" else diagnostics[0].error_name,
        ),
        .published => |*result| try budget.chargeMetadata(result),
    }
    var next = current.state;
    next.phase = .refreshed;
    next.refreshed = true;
    next.diagnostic_id = null;
    next.diagnostic = "";
    try publication.advance(allocator, current, paths, next);
}

const NativeRepositoryManifest = struct {
    file: root_fs.PinnedRegularFile,
    sha256: [32]u8,

    fn deinit(self: *@This()) void {
        self.file.close();
        self.* = undefined;
    }

    fn read(
        allocator: std.mem.Allocator,
        input: NativeRecoveryRequest,
        descriptor: api.DescriptorIdentity,
        state: state_module.State,
        paths: ResolvedPaths,
    ) !@This() {
        const root = input.attempt.coordinator.root;
        var filesystem: target_apt_config.ProductionFileSystem = .{ .io = root.io, .root = root.dir, .host_root = false };
        try verifyInstalledDescriptor(allocator, filesystem.interface(), descriptor, state.managed_files);
        var snapshot = try nativeRepositorySnapshot(allocator, input);
        defer snapshot.deinit();
        try verifyImportedMaterial(snapshot, state.managed_files);
        const bytes = try snapshot.manifest.manifest.canonicalJson(allocator);
        defer allocator.free(bytes);
        var pin = try root.pinRegularFile(try root_fs.Path.init(paths.manifest_logical[1..]));
        errdefer pin.close();
        const observed = try pin.observeStableAlloc(allocator, target_apt_config.maximum_document_bytes);
        defer allocator.free(observed.bytes);
        if (!std.mem.eql(u8, bytes, observed.bytes)) return error.ImportedDigestMismatch;
        return .{ .file = pin, .sha256 = snapshot.manifest.manifest.digest_sha256 };
    }
};

const NativeCompletionPoint = enum {
    after_final_state,
    after_completed_record,
    before_completion_rename,
    after_completion_rename,
    after_local_completion,
    after_root_completion,
    after_provenance,
    before_native_acknowledgment,
    after_native_acknowledgment,
    before_clear,
};

const NativeCompletionObserver = struct {
    context: *anyopaque,
    hitFn: *const fn (*anyopaque, NativeCompletionPoint) anyerror!void,
};

const NativeCompletionContext = struct {
    observer: ?NativeCompletionObserver,
    document: ?root_operation_completion.OwnedDocument = null,

    fn hit(self: *@This(), point: NativeCompletionPoint) !void {
        if (self.observer) |observer| try observer.hitFn(observer.context, point);
    }
};

fn nativeCompletionRequestDigest(
    input: NativeReceiptRequest,
    attempt_id: [32]u8,
    state: state_module.State,
    manifest_sha256: ?[32]u8,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-native-repository-completion-request-v1\x00");
    hash.update(&attempt_id);
    hash.update(&repositoryRequestDigest(input.repository, .native));
    hash.update(&repositoryPolicyDigest(input.repository, .native));
    hash.update(&input.expected_receipt_sha256);
    hash.update(&state.digest_sha256);
    hash.update(&.{@intFromBool(manifest_sha256 != null)});
    if (manifest_sha256) |digest| hash.update(&digest);
    return hash.finalResult();
}

fn pinNativeCompletion(root: root_fs.Root, path: root_fs.Path) !?root_fs.PinnedRegularFile {
    return root.pinRegularFile(path) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

fn decodeNativeCompletion(
    allocator: std.mem.Allocator,
    pin: *const root_fs.PinnedRegularFile,
) !root_operation_completion.OwnedDocument {
    const observed = try pin.observeStableAlloc(allocator, root_operation_completion.maximum_document_bytes);
    defer allocator.free(observed.bytes);
    return root_operation_completion.decode(allocator, observed.bytes, root_operation_completion.maximum_document_bytes);
}

const NativeCompletionPublication = struct {
    checkpoint: *NativeCheckpointPublication,
    context: *NativeCompletionContext,
    local: ?*const root_fs.PinnedRegularFile = null,
    global: ?*const root_fs.PinnedRegularFile = null,

    fn validate(self: *@This()) !void {
        try self.checkpoint.validate();
        if (self.local) |pin| _ = try pin.metadata();
        if (self.global) |pin| _ = try pin.metadata();
        try validateNativeCallerRecord(self.checkpoint.allocator, self.checkpoint.input.attempt);
    }

    fn boundary(self: *@This(), point: NativeCompletionPoint) !void {
        try self.context.hit(point);
        try self.validate();
    }

    fn hit(raw: *anyopaque, point: root_fs.PublishPoint) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (point == .before_rename) try self.boundary(.before_completion_rename);
        if (point == .after_rename) try self.context.hit(.after_completion_rename);
    }
};

fn validateNativeCallerRecord(allocator: std.mem.Allocator, attempt: *root_operation.Attempt) !void {
    var active = try attempt.coordinator.store().read(allocator);
    defer if (active) |*value| value.deinit();
    if (active) |value| {
        if (!std.mem.eql(u8, &value.record.digest_sha256, &attempt.record().digest_sha256))
            return error.StaleAttempt;
    } else if (!attempt.record().clearable() or
        (attempt.record().provenance != .published and attempt.record().outcome != .abandoned_before_mutation))
        return error.NoActiveAttempt;
}

fn validateNativeCompletion(
    input: NativeReceiptRequest,
    document: root_operation_completion.Document,
    discharge: [32]u8,
    outcome: root_operation.Outcome,
) !void {
    const record = input.attempt.record();
    const receipt_digest = native_recovery.parseDigest(input.expected_receipt_sha256) orelse return error.NativeReceiptMismatch;
    if (record.state != .completed or record.outcome != outcome or
        !document.bindsRecord(record) or document.outcome != outcome or
        document.transaction_provenance.status != .already_present or
        !std.mem.eql(u8, document.transaction_provenance.schema, native_provenance.schema_id) or
        !std.mem.eql(u8, &(document.transaction_provenance.document_sha256 orelse return error.NativeCompletionMismatch), &receipt_digest) or
        document.journal.status != .absent or document.journal.document_sha256 != null or
        document.discharge.surface != .repository_bootstrap or !std.mem.eql(u8, document.discharge.operation, "add") or
        !std.mem.eql(u8, &document.discharge.request_sha256, &discharge) or
        !(target_apt_config.Architecture{ .native = document.target_architecture, .foreign = document.foreign_architectures }).eql(.{
            .native = record.target_architecture,
            .foreign = record.foreign_architectures,
        })) return error.NativeCompletionMismatch;
    switch (record.provenance) {
        .pending => {
            if (document.record_generation != record.generation or
                !std.mem.eql(u8, &document.record_digest_sha256, &record.digest_sha256))
                return error.NativeCompletionMismatch;
        },
        .published => if (!std.mem.eql(u8, &(record.provenance_sha256 orelse return error.NativeCompletionMismatch), &document.digest_sha256))
            return error.NativeCompletionMismatch,
        .not_required => return error.NativeCompletionMismatch,
    }
}

fn finishNativeRepository(
    allocator: std.mem.Allocator,
    publication: *NativeCheckpointPublication,
    current: *state_module.OwnedState,
    paths: ResolvedPaths,
    descriptor: api.DescriptorIdentity,
    package_state: NativePackageState,
    context: *NativeCompletionContext,
) !void {
    const receipt = switch (package_state) {
        inline else => |value| value.receipt.document,
    };
    const input: NativeReceiptRequest = .{
        .repository = publication.input.repository,
        .attempt = publication.input.attempt,
        .deadline = publication.input.deadline,
        .expected_receipt_sha256 = receipt.digest_sha256,
    };
    const attempt = input.attempt;
    const root = attempt.coordinator.root;
    const failed = package_state == .failed;
    if (!attempt.record().mutation_started) return error.NativeCompletionMismatch;
    if (failed) {
        if (current.state.phase != .failed or current.state.diagnostic_id != .transaction_failed)
            return error.RepositoryStateMismatch;
    } else if (current.state.diagnostic_id != null or
        (current.state.phase != .refreshed and current.state.phase != .complete and
            !(current.state.phase == .imported and input.repository.no_refresh)) or
        (!input.repository.no_refresh and !current.state.refreshed))
        return error.RepositoryPostInstallIncomplete;

    const local_path_text = try joinLogical(allocator, paths.operation_logical, root_operation_completion.document_name);
    defer allocator.free(local_path_text);
    const local_path = try root_fs.Path.init(local_path_text[1..]);
    const global_path = try root_fs.Path.init(root_operation_completion.document_path);
    var local_pin = try pinNativeCompletion(root, local_path);
    defer if (local_pin) |*pin| pin.close();
    var global_pin = try pinNativeCompletion(root, global_path);
    defer if (global_pin) |*pin| pin.close();
    var local_document = if (local_pin) |*pin| try decodeNativeCompletion(allocator, pin) else null;
    defer if (local_document) |*document| document.deinit();
    var global_document = if (global_pin) |*pin| try decodeNativeCompletion(allocator, pin) else null;
    defer if (global_document) |*document| document.deinit();
    if (local_document == null and (attempt.record().provenance == .published or
        (global_document != null and std.mem.eql(u8, &global_document.?.document.attempt_id, &attempt.attemptId()))))
        return error.NativeCompletionMissing;
    if (attempt.record().provenance == .published and global_document == null)
        return error.NativeCompletionMissing;

    var completion_publication: NativeCompletionPublication = .{
        .checkpoint = publication,
        .context = context,
        .local = if (local_pin) |*pin| pin else null,
        .global = if (global_pin) |*pin| pin else null,
    };
    var manifest: ?NativeRepositoryManifest = null;
    defer if (manifest) |*value| value.deinit();
    defer {
        publication.manifest_file = null;
        publication.manifest_sha256 = null;
    }
    if (!failed) {
        if (local_document == null) {
            var original = try readNativeDescriptorMaterial(allocator, input, descriptor, package_state.succeeded.receipt.document, current.state);
            defer original.deinit();
        } else if (current.state.phase != .complete) return error.NativeCompletionMismatch;
        manifest = try NativeRepositoryManifest.read(allocator, input.recoveryRequest(), descriptor, current.state, paths);
        publication.manifest_file = &manifest.?.file;
        publication.manifest_sha256 = manifest.?.sha256;
    }
    try completion_publication.validate();
    const outcome: root_operation.Outcome = if (failed) .failed_after_mutation else .succeeded;
    if (local_document == null) {
        if (attempt.record().state == .completed and attempt.record().outcome != outcome)
            return error.NativeCompletionMismatch;
        var final_state = current.state;
        if (!failed) final_state.phase = .complete;
        try publication.advance(allocator, current, paths, final_state);
    }
    const discharge = nativeCompletionRequestDigest(input, attempt.attemptId(), current.state, publication.manifest_sha256);
    if (local_document) |document| try validateNativeCompletion(input, document.document, discharge, outcome);
    try completion_publication.boundary(.after_final_state);
    if (attempt.record().state != .completed) {
        switch (attempt.record().state) {
            .mutating => try attempt.advance(allocator, .{ .state = .verifying, .phase = .verification }),
            .recovery_required => try attempt.beginRecovery(allocator, .verification),
            .verifying, .recovering => {},
            else => return error.NativeCompletionMismatch,
        }
        try completion_publication.validate();
        try attempt.complete(allocator, outcome);
    }
    try completion_publication.boundary(.after_completed_record);
    if (local_document == null) local_document = try root_operation_completion.create(allocator, .{
        .record = attempt.record(),
        .transaction_provenance = .{
            .status = .already_present,
            .schema = native_provenance.schema_id,
            .document_sha256 = native_recovery.parseDigest(input.expected_receipt_sha256) orelse return error.NativeReceiptMismatch,
            .detail = "verified terminal native repository package receipt",
        },
        .journal = .{ .status = .absent, .detail = "native phase evidence; no command journal" },
        .discharge = .{ .surface = .repository_bootstrap, .operation = "add", .request_sha256 = discharge },
    });
    try validateNativeCompletion(input, local_document.?.document, discharge, outcome);
    const completion_bytes = try local_document.?.document.canonicalJson(allocator);
    defer allocator.free(completion_bytes);
    if (local_pin == null) {
        try retainNativeReceiptBytes(allocator, root, local_path, completion_bytes, .{
            .context = &completion_publication,
            .hitFn = NativeCompletionPublication.hit,
        });
        local_pin = try root.pinRegularFile(local_path);
        completion_publication.local = &local_pin.?;
    }
    try verifyNativeReceiptBytes(allocator, root, local_path, completion_bytes, true);
    try completion_publication.boundary(.after_local_completion);
    if (global_document) |document| {
        if (std.mem.eql(u8, &document.document.attempt_id, &attempt.attemptId()) or attempt.record().provenance == .published) {
            if (!std.mem.eql(u8, &document.document.digest_sha256, &local_document.?.document.digest_sha256))
                return error.NativeCompletionMismatch;
        }
    }
    if (global_document == null or !std.mem.eql(u8, &global_document.?.document.attempt_id, &attempt.attemptId())) {
        try root.publishFile(global_path, completion_bytes, .{
            .permissions = .fromMode(0o600),
            .overwrite = .replace,
            .durable = true,
            .observer = .{ .context = &completion_publication, .hitFn = NativeCompletionPublication.hit },
        });
        if (global_pin) |*pin| pin.close();
        global_pin = null;
        global_pin = try root.pinRegularFile(global_path);
        completion_publication.global = &global_pin.?;
    }
    try verifyNativeReceiptBytes(allocator, root, global_path, completion_bytes, true);
    try completion_publication.boundary(.after_root_completion);
    if (attempt.record().provenance == .pending)
        try attempt.publishProvenance(allocator, local_document.?.document.digest_sha256);
    try validateNativeCompletion(input, local_document.?.document, discharge, outcome);
    try completion_publication.boundary(.after_provenance);
    try completion_publication.boundary(.before_native_acknowledgment);
    {
        var live = try verifyNativePackageState(allocator, input);
        defer live.deinit();
        if ((live == .failed) != failed) return error.NativeReceiptMismatch;
    }
    try completion_publication.validate();
    try native_runtime.acknowledge(allocator, attempt, input.expected_receipt_sha256);
    try completion_publication.boundary(.after_native_acknowledgment);
    try completion_publication.boundary(.before_clear);
    try attempt.clear();
    context.document = local_document;
    local_document = null;
}

const NativeInvocationClock = struct {
    input: ?NativeRecoveryRequest = null,
    deadline: transaction_executor.Deadline,
    original: repository_acquisition.Clock,

    fn interface(self: *@This()) repository_acquisition.Clock {
        return .{ .context = self, .nowMsFn = now, .sleepMsFn = sleep };
    }

    fn now(raw: ?*anyopaque) u64 {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        return self.deadline.nowMsFn(self.deadline.context);
    }

    fn sleep(raw: ?*anyopaque, milliseconds: u64) !void {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        if (self.input) |input| try input.validate();
        try self.original.sleepMs(@min(milliseconds, try self.deadline.remainingMs()));
        if (self.input) |input| try input.validate();
        _ = try self.deadline.remainingMs();
    }
};

fn nativeRepositoryReceipt(
    allocator: std.mem.Allocator,
    input: NativeReceiptRequest,
    publish: bool,
    observer: ?root_fs.PublishObserver,
) !NativeRetainedReceipt {
    try input.validate();
    var receipt = try native_runtime.readCompletion(allocator, input.attempt) orelse return error.NativeReceiptMissing;
    errdefer receipt.deinit();
    if (!std.mem.eql(u8, &receipt.document.digest_sha256, &input.expected_receipt_sha256))
        return error.NativeReceiptMismatch;
    var paths = try ResolvedPaths.init(allocator, input.repository, .native);
    defer paths.deinit();
    const logical_path = try allocator.dupe(u8, paths.provenance_logical);
    errdefer allocator.free(logical_path);
    const bytes = try receipt.document.canonicalJson(allocator);
    defer allocator.free(bytes);
    const root = input.attempt.coordinator.root;
    const path = try root_fs.Path.init(logical_path[1..]);
    try input.validate();
    if (publish) {
        var publication: NativeReceiptPublication = .{ .input = input, .observer = observer };
        try retainNativeReceiptBytes(allocator, root, path, bytes, .{
            .context = &publication,
            .hitFn = NativeReceiptPublication.hit,
        });
        try validateNativeRepositoryCaller(input.repository, input.attempt);
        try input.attempt.coordinator.validateProjection();
    } else {
        try verifyNativeReceiptBytes(allocator, root, path, bytes, false);
        try input.validate();
    }
    return .{ .logical_path = logical_path, .receipt = receipt, .allocator = allocator };
}

const NativeReceiptPublication = struct {
    input: NativeReceiptRequest,
    observer: ?root_fs.PublishObserver,

    fn hit(raw: *anyopaque, point: root_fs.PublishPoint) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (self.observer) |observer| try observer.hit(point);
        if (point == .before_rename) try self.input.validate();
    }
};

fn retainNativeReceiptBytes(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: root_fs.Path,
    bytes: []const u8,
    observer: ?root_fs.PublishObserver,
) !void {
    if (try root.entryIfExists(path) != null)
        return verifyNativeReceiptBytes(allocator, root, path, bytes, true);
    var parent: ?root_fs.Path = null;
    for (path.text, 0..) |byte, index| {
        if (byte != '/') continue;
        const directory = try root_fs.Path.init(path.text[0..index]);
        try root.ensureDirectory(directory, .fromMode(0o700));
        if (parent) |value| try root.syncDirectory(value) else try root.syncRoot();
        parent = directory;
    }
    root.publishFile(path, bytes, .{
        .permissions = .fromMode(0o600),
        .overwrite = .fail_if_exists,
        .durable = true,
        .observer = observer,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => try verifyNativeReceiptBytes(allocator, root, path, bytes, true),
        else => return err,
    };
}

fn verifyNativeReceiptBytes(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: root_fs.Path,
    bytes: []const u8,
    durable: bool,
) !void {
    var pinned = root.pinRegularFile(path) catch |err| switch (err) {
        error.FileNotFound => return error.NativeReceiptMissing,
        else => return err,
    };
    defer pinned.close();
    const observed = try pinned.observeStableAlloc(allocator, native_provenance.maximum_document_bytes);
    defer allocator.free(observed.bytes);
    if (!std.mem.eql(u8, observed.bytes, bytes)) return error.NativeReceiptMismatch;
    if (durable) {
        // A prior publication may have stopped after rename but before sync.
        try pinned.file.sync(root.io);
        if (std.mem.lastIndexOfScalar(u8, path.text, '/')) |index|
            try root.syncDirectory(try root_fs.Path.init(path.text[0..index]))
        else
            try root.syncRoot();
    }
    _ = try pinned.metadata();
}

/// Owns the complete verified CAS closure through preparation and subsequent
/// execution, independently of cache eviction or the caller's package buffers.
/// Cache misses and corruption refuse; this never downloads or repairs objects.
pub fn prepareNativeFromCache(
    allocator: std.mem.Allocator,
    input: NativeCachePreparationRequest,
) !NativeCachedPreparation {
    _ = try input.deadline.remainingMs();
    var preparation: NativePreparationRequest = .{
        .repository = input.repository,
        .attempt = input.attempt,
        .plan = input.plan,
        .exact_lock = input.exact_lock,
        .archives = &.{},
    };
    try validateNativePreparationCaller(preparation);
    const request = input.repository;
    if (input.retained_archives.len > request.resources.maximum_actions or
        input.exact_lock.packages.len > @import("native_program.zig").maximum_artifacts)
        return error.ResourceBudgetExceeded;
    var retained_bytes: u64 = 0;
    for (input.retained_archives) |bytes|
        try OperationBudget.charge(&retained_bytes, bytes.len, request.resources.maximum_retained_package_bytes);
    var package_bytes: u64 = 0;
    for (input.exact_lock.packages) |package| {
        try validateNativeArchiveSize(request, package.declared_size);
        if (package.declared_size > input.cache.limits.maximum_object_bytes)
            return error.ResourceBudgetExceeded;
        try OperationBudget.charge(&package_bytes, package.declared_size, request.resources.maximum_total_package_bytes);
        try OperationBudget.charge(&retained_bytes, package.declared_size, request.resources.maximum_retained_package_bytes);
    }
    try validateNativePreparationEvidence(allocator, preparation);
    const lock_bytes = try input.exact_lock.canonicalJson(allocator);
    defer allocator.free(lock_bytes);
    var verified_lock = try exact_lock_v2.decode(allocator, lock_bytes, exact_lock_v2.maximum_document_bytes);
    defer verified_lock.deinit();
    preparation.exact_lock = &verified_lock.lock;
    _ = try input.deadline.remainingMs();
    const archives = try allocator.alloc([]const u8, verified_lock.lock.packages.len);
    var initialized: usize = 0;
    errdefer {
        for (archives[0..initialized]) |bytes| allocator.free(bytes);
        allocator.free(archives);
    }
    for (verified_lock.lock.packages, archives) |package, *bytes| {
        _ = try input.deadline.remainingMs();
        bytes.* = try input.cache.lookup(allocator, .{ .bytes = package.sha256 }, package.declared_size, .verify_sha256);
        initialized += 1;
        _ = try input.deadline.remainingMs();
    }
    preparation.archives = archives;
    var result = try prepareNative(allocator, preparation);
    errdefer result.deinit();
    _ = try input.deadline.remainingMs();
    try validateNativePreparationCaller(preparation);
    return .{ .preparation = result, .archives = archives, .allocator = allocator };
}

/// Prepares already acquired repository inputs under their original caller.
/// Does not execute, publish intent, release ownership, or complete bootstrap.
pub fn prepareNative(
    allocator: std.mem.Allocator,
    input: NativePreparationRequest,
) !native_preparation.ResultWithNoChanges {
    try validateNativePreparationCaller(input);
    var retained_bytes: u64 = 0;
    for (input.archives) |bytes| {
        try validateNativeArchiveSize(input.repository, bytes.len);
        try OperationBudget.charge(&retained_bytes, bytes.len, input.repository.resources.maximum_retained_package_bytes);
    }
    if (retained_bytes > input.repository.resources.maximum_total_package_bytes)
        return error.ResourceBudgetExceeded;
    try validateNativePreparationEvidence(allocator, input);
    const record = input.attempt.record();
    var result = try native_runtime.prepare(allocator, .{
        .attempt = input.attempt,
        .plan = input.plan,
        .exact_lock = input.exact_lock,
        .archives = input.archives,
        .policy = repositoryExecutionPolicy(input.repository),
    });
    errdefer result.deinit();
    switch (result) {
        .prepared => |prepared| {
            const evidence = try native_operation.evidence(prepared.program.program);
            inline for (.{
                "authorization_sha256",       "program_sha256",
                "database_generation_sha256", "artifact_evidence_sha256",
            }) |field| {
                if (@field(record, field)) |bound| {
                    if (!std.mem.eql(u8, &bound, &@field(evidence, field).?))
                        return error.OperationEvidenceMismatch;
                }
            }
        },
        .unchanged => {
            if (record.authorization_sha256 != null or record.program_sha256 != null)
                return error.OperationEvidenceMismatch;
        },
        .diagnostic => {},
    }
    return result;
}

fn validateNativeArchiveSize(request: api.Request, size: u64) !void {
    if (size > request.network.maximum_package_bytes or
        size > request.cache.maximum_object_bytes)
        return error.ResourceBudgetExceeded;
}

fn validateNativePreparationCaller(input: NativePreparationRequest) !void {
    const request = input.repository;
    try validateNativeRepositoryCaller(request, input.attempt);
    const record = input.attempt.record();
    if (!record.state.provenPreMutation()) return error.OperationNotMutable;
    if (!std.mem.eql(u8, record.target_architecture, input.plan.target_architecture))
        return error.OperationArchitectureMismatch;
    if (input.plan.actions.len > request.resources.maximum_actions or
        input.exact_lock.packages.len > request.resources.maximum_actions or
        input.exact_lock.repositories.len > request.resources.maximum_repositories or
        input.archives.len > request.resources.maximum_actions)
        return error.ResourceBudgetExceeded;
}

fn validateNativeRepositoryCaller(request: api.Request, attempt: *root_operation.Attempt) !void {
    if (api.validateRequest(request) != null) return error.InvalidRepositoryRequest;
    if (!attempt.locked()) return error.LockLost;
    const record = attempt.record();
    if (record.backend != .native) return error.OperationBackendMismatch;
    if (!record.operation.eql(.{ .repository_bootstrap = .add }) or
        !std.mem.eql(u8, record.install_root, request.root) or
        !std.mem.eql(u8, &record.request_sha256, &repositoryRequestDigest(request, .native)) or
        !std.mem.eql(u8, &record.policy_sha256, &repositoryPolicyDigest(request, .native)))
        return error.RepositoryCallerMismatch;
    if (request.architecture) |architecture| {
        if (!std.mem.eql(u8, architecture, record.target_architecture))
            return error.OperationArchitectureMismatch;
    }
}

fn validateNativePreparationEvidence(allocator: std.mem.Allocator, input: NativePreparationRequest) !void {
    const request = input.repository;
    const attempt = input.attempt;
    const record = attempt.record();
    try validateLockPolicy(input.exact_lock.*, .native);
    try validateLockRequest(allocator, input.exact_lock.*, request, input.plan.*, .native);
    if (record.plan_sha256) |digest| {
        if (!std.mem.eql(u8, &digest, &transaction_executor.planDigest(input.plan.*)))
            return error.PlanEvidenceMismatch;
    }
    if (record.exact_lock) |binding| {
        const expected: root_operation.LockBinding = .{
            .schema = exact_lock_v2.schema_id,
            .version = exact_lock_v2.schema_version,
            .digest_sha256 = input.exact_lock.digest_sha256,
        };
        if (!binding.eql(expected)) return error.LockEvidenceMismatch;
    }
    if (!try native_runtime.canAbandon(allocator, attempt))
        return error.RecoveryRequired;
}

pub const Backend = struct {
    io: std.Io,
    transaction_backend: transaction_engine.Kind = .legacy_dpkg,
    executor: Executor = .legacy_dpkg,
    native_executor: ?Executor = null,
    /// Borrowed only for this native invocation; never request or state data.
    root_projection: ?*const live_root.Projection = null,
    native_deadline: ?transaction_executor.Deadline = null,
    process_runner: ?transaction_executor.ProcessRunner = null,
    operation_locks: ?transaction_executor.LockManager = null,
    target_locks: ?transaction_executor.LockManager = null,
    status_reader: ?transaction_recovery.StatusReader = null,
    acquisition_dependencies: ?repository_acquisition.Dependencies = null,
    now_unix: ?i64 = null,
    state_write_hooks: state_module.WriteHooks = .{},

    pub fn interface(self: *Backend) api.Backend {
        return .{ .context = self, .executeFn = executeOpaque };
    }

    /// Typed request dispatch inside the current supervised native callback.
    /// The ordinary interface and CLI keep their separate activation gate.
    pub fn nativeInterface(self: *Backend) api.Backend {
        return .{ .context = self, .executeFn = executeNativeOpaque };
    }

    fn executeNativeOpaque(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: api.Request,
    ) !api.Result {
        const self: *Backend = @ptrCast(@alignCast(context));
        return self.executeAdd(allocator, request, .native_runtime);
    }

    fn executeOpaque(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: api.Request,
    ) !api.Result {
        const self: *Backend = @ptrCast(@alignCast(context));
        return self.execute(allocator, request);
    }

    pub fn execute(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: api.Request,
    ) !api.Result {
        return self.executeAdd(allocator, request, .selected_executor) catch |err|
            api.failure(.internal, .internal_error, "internal", @errorName(err));
    }

    const ExecutionPath = enum { selected_executor, native_runtime };

    fn executeAdd(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: api.Request,
        execution_path: ExecutionPath,
    ) !api.Result {
        const transaction_backend = self.transaction_backend;
        const native = execution_path == .native_runtime;
        if (native and (transaction_backend != .native or self.root_projection == null or self.native_executor != null))
            return api.failure(
                .unavailable,
                .transaction_backend_unavailable,
                "transaction",
                "native request dispatch requires explicit native selection and current projection authority",
            );
        const executor: ?Executor = if (native) null else transaction_engine.select(
            transaction_backend,
            self.executor,
            self.native_executor,
        ) catch return api.failure(
            .unavailable,
            .transaction_backend_unavailable,
            "transaction",
            "selected transaction backend is unavailable",
        );
        var paths = try ResolvedPaths.init(allocator, request, transaction_backend);
        defer paths.deinit();
        var production_acquisition = repository_acquisition.Production{ .io = self.io };
        var acquisition_dependencies = self.acquisition_dependencies orelse production_acquisition.dependencies();
        var invocation_clock: NativeInvocationClock = undefined;
        if (native) if (self.native_deadline) |deadline| {
            invocation_clock = .{ .deadline = deadline, .original = acquisition_dependencies.clock };
            acquisition_dependencies.clock = invocation_clock.interface();
        };
        var budget: OperationBudget = undefined;
        if (native) {
            budget = OperationBudget.init(
                acquisition_dependencies.clock,
                request.resources,
                request.network.overall_timeout_ms,
                allocator,
            );
            if (self.native_deadline) |deadline| budget.retainDeadline(deadline);
        }
        var native_progress: NativeDispatchProgress = .{};
        defer native_progress.deinit();

        // Rank 0 of the total lock order. Repository bootstrap shares the
        // root's operation namespace with package transactions, so neither can
        // start while the other holds an unresolved attempt. The transaction
        // backend was already selected above, so an unavailable native
        // selection still fails before any root access.
        var guard: RootOperationGuard = .{
            .io = self.io,
            .allocator = allocator,
            .root_projection = self.root_projection,
            .native_resume_completion = native,
            .deadline = if (native) budget.executionDeadline() else null,
        };
        defer guard.deinit();
        if (guard.open(request, transaction_backend, self.now_unix)) |failure| return failure;

        if (!native) budget = OperationBudget.init(
            acquisition_dependencies.clock,
            request.resources,
            request.network.overall_timeout_ms,
            allocator,
        );
        const native_input: ?NativeRecoveryRequest = if (native) .{
            .repository = request,
            .attempt = guard.active().?,
            .deadline = budget.executionDeadline(),
        } else null;
        budget.native_input = native_input;
        const native_dependencies: NativeImportRefreshDependencies = .{
            .acquisition = acquisition_dependencies,
            .now_unix = if (native) self.now_unix orelse realNow(self.io) else 0,
            .result_progress = &native_progress,
        };

        var cache_root = openOrCreateAbsoluteDirectory(self.io, paths.cache_physical) catch
            return api.failure(.usage, .invalid_root, "paths", "cache path is unsafe or unavailable");
        defer cache_root.close(self.io);
        var state_root = openOrCreateAbsoluteDirectory(self.io, paths.state_physical) catch
            return api.failure(.usage, .invalid_root, "paths", "state path is unsafe or unavailable");
        defer state_root.close(self.io);
        var repository_dir = openOrCreateAbsoluteDirectory(
            self.io,
            paths.repository_physical,
        ) catch
            return api.failure(.usage, .invalid_root, "paths", "repository state path is unsafe or unavailable");
        defer repository_dir.close(self.io);
        const operation_lock_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}",
            .{ paths.repository_physical, operation_lock_name },
        );
        defer allocator.free(operation_lock_path);
        var operation_lock_manager = transaction_executor.SystemLockManager{
            .allocator = allocator,
            .io = self.io,
        };

        const operation_locks = self.operation_locks orelse
            operation_lock_manager.interface();
        guard.enterRank(.repository_operation) catch return api.failure(
            .internal,
            .internal_error,
            "lock",
            "repository operation lock was requested out of order",
        );
        const operation_lock_wait = budget.remainingTime() catch |err|
            return api.failure(
                .unavailable,
                .resource_limit_exceeded,
                "lock",
                @errorName(err),
            );
        const operation_lock = operation_locks.acquire(
            operation_lock_path,
            @min(request.state.lock_wait_ms, operation_lock_wait),
        ) catch |err| {
            budget.checkTime() catch |deadline_err| return api.failure(
                .unavailable,
                .resource_limit_exceeded,
                "lock",
                @errorName(deadline_err),
            );
            return api.failure(
                .recovery,
                .recovery_required,
                "state",
                @errorName(err),
            );
        };
        defer operation_locks.release(operation_lock);
        budget.checkTime() catch |err| return api.failure(
            .unavailable,
            .resource_limit_exceeded,
            "lock",
            @errorName(err),
        );
        var operation_dir = openOrCreateAbsoluteDirectory(self.io, paths.operation_physical) catch
            return api.failure(.usage, .invalid_root, "paths", "repository operation path is unsafe or unavailable");
        defer operation_dir.close(self.io);
        var state_store = try state_module.Store.init(self.io, operation_dir, operation_state_name);
        var preflight_publication: NativePreflightPublication = .{
            .input = native_input,
            .original = self.state_write_hooks,
        };
        state_store.write_hooks = if (native)
            .{ .context = &preflight_publication, .runFn = NativePreflightPublication.hit }
        else
            self.state_write_hooks;

        var prior_state: ?state_module.OwnedState = state_store.read(
            allocator,
            request.state.maximum_operation_state_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return api.failure(.recovery, .state_corrupt, "state", @errorName(err)),
        };
        defer if (prior_state) |*value| value.deinit();

        if (native_input) |input| {
            var resumed = resumeNativeRepository(allocator, input, native_dependencies) catch |err|
                return native_progress.failure(allocator, input, err, null);
            defer resumed.deinit();
            if (try nativeResumeResult(allocator, input, &resumed, &native_progress)) |result|
                return result;
        }

        var target_files = target_apt_config.ProductionFileSystem.init(self.io, request.root) catch
            return api.failure(.usage, .invalid_root, "target", "target root is unsafe or unavailable");
        defer target_files.deinit();
        var architecture_process = target_apt_config.SystemProcessRunner{ .io = self.io };
        var before_snapshot = target_apt_config.snapshot(allocator, .{
            .root_path = request.root,
            .architecture_override = if (transaction_backend == .native)
                guard.active().?.record().target_architecture
            else
                request.architecture,
            .limits = targetLimits(request.resources),
            .dependencies = .{
                .filesystem = target_files.interface(),
                .process = if (transaction_backend == .legacy_dpkg)
                    architecture_process.interface()
                else
                    null,
            },
        }) catch |err| return api.failure(
            .usage,
            if (err == error.NativeArchitectureUnavailable)
                .architecture_unavailable
            else
                .target_configuration_failed,
            "target",
            @errorName(err),
        );
        defer before_snapshot.deinit();
        const architecture = before_snapshot.manifest.manifest.native_architecture;
        if (guard.preflight(.{
            .native = architecture,
            .foreign = before_snapshot.manifest.manifest.foreign_architectures,
        })) |failure| return failure;
        if (prior_state) |*prior| {
            if (!std.mem.eql(u8, prior.state.root, request.root) or
                !std.mem.eql(u8, prior.state.architecture, architecture) or
                prior.state.no_refresh != request.no_refresh)
                return api.failure(
                    .recovery,
                    .state_corrupt,
                    "state",
                    "repository operation state does not match the target root and architecture",
                );
        }

        var progress: Progress = .{
            .root = request.root,
            .architecture = architecture,
            .no_refresh = request.no_refresh,
            .maximum_state_bytes = request.state.maximum_operation_state_bytes,
            .paths = paths.logicalEvidence(),
            .native_input = native_input,
        };
        if (prior_state) |*prior| {
            progress.restore(prior.state);
        } else {
            progress.persist(
                state_store,
                allocator,
                .initialized,
                null,
                &.{},
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                .unavailable,
                .state_persistence_failed,
                "state",
                @errorName(err),
            );
        }

        var package_cache = package_acquisition.Cache.initFromDir(self.io, cache_root, .{
            .maximum_object_bytes = request.cache.maximum_object_bytes,
        }) catch |err| return progress.fail(
            state_store,
            allocator,
            .unavailable,
            .acquisition_failed,
            "acquire",
            @errorName(err),
        );
        defer package_cache.deinit();
        const descriptor_limit = budget.descriptorLimit(request.network.maximum_descriptor_bytes) catch |err|
            return progress.fail(
                state_store,
                allocator,
                .unavailable,
                .resource_limit_exceeded,
                "acquire",
                @errorName(err),
            );
        const persisted_descriptor: ?state_module.Descriptor =
            if (prior_state) |*prior|
                if (phaseAtLeast(prior.state.phase, .validated))
                    prior.state.descriptor
                else
                    null
            else
                null;
        if (persisted_descriptor) |descriptor| {
            const persisted_uri = repository_acquisition.Uri.parse(
                descriptor.effective_url,
            ) catch return progress.fail(
                state_store,
                allocator,
                .recovery,
                .recovery_required,
                "acquire",
                "persisted descriptor URL is invalid",
            );
            if (descriptor.trust_mode == .verified_https and
                !std.ascii.eqlIgnoreCase(persisted_uri.scheme, "https"))
                return progress.fail(
                    state_store,
                    allocator,
                    .recovery,
                    .recovery_required,
                    "acquire",
                    "persisted HTTPS descriptor trust evidence is inconsistent",
                );
        }
        var artifact = local_artifact.acquire(allocator, &package_cache, .{
            .uri = repository_acquisition.Uri.parse(request.descriptor_url) catch
                return progress.fail(
                    state_store,
                    allocator,
                    .usage,
                    .invalid_descriptor_url,
                    "acquire",
                    "descriptor URL is invalid",
                ),
            .expected_sha256 = if (persisted_descriptor) |value|
                .{ .bytes = value.sha256 }
            else if (request.expected_sha256) |digest|
                .{ .bytes = digest }
            else
                null,
            .expected_size = if (persisted_descriptor) |value|
                value.size
            else
                null,
            .require_https = if (persisted_descriptor) |value|
                value.trust_mode == .verified_https
            else
                false,
            .policy = .{
                .maximum_artifact_bytes = descriptor_limit,
                .proxy = proxyPolicy(request.network.proxy_url) catch
                    return progress.fail(
                        state_store,
                        allocator,
                        .usage,
                        .invalid_request,
                        "acquire",
                        "proxy policy is invalid",
                    ),
                .deadlines = budget.acquisitionDeadlines(request.network),
                .redirect_limit = request.network.redirect_limit,
                .retry = retryPolicy(request.network),
            },
        }, acquisition_dependencies) catch |err| return progress.fail(
            state_store,
            allocator,
            if (err == error.ArtifactTooLarge and
                descriptor_limit < request.network.maximum_descriptor_bytes)
                .unavailable
            else
                .download,
            if (err == error.ArtifactTooLarge and
                descriptor_limit < request.network.maximum_descriptor_bytes)
                .resource_limit_exceeded
            else
                .acquisition_failed,
            "acquire",
            @errorName(err),
        );
        defer artifact.deinit();
        if (persisted_descriptor) |expected| {
            if (!std.mem.eql(
                u8,
                &artifact.provenance.sha256.bytes,
                &expected.sha256,
            ) or artifact.provenance.size != expected.size)
                return progress.fail(
                    state_store,
                    allocator,
                    .recovery,
                    .recovery_required,
                    "acquire",
                    "persisted descriptor content identity changed",
                );
            if (artifact.provenance.outcome == .acquired and
                !std.mem.eql(
                    u8,
                    artifact.provenance.effective_uri,
                    expected.effective_url,
                ))
                return progress.fail(
                    state_store,
                    allocator,
                    .recovery,
                    .recovery_required,
                    "acquire",
                    "persisted descriptor transport origin changed",
                );
            const effective_url = try allocator.dupe(u8, expected.effective_url);
            allocator.free(artifact.provenance.effective_uri);
            artifact.provenance.effective_uri = effective_url;
            artifact.provenance.trust_mode = switch (expected.trust_mode) {
                .verified_https => .https,
                .pinned_sha256 => .sha256,
            };
        }
        budget.chargeDescriptor(artifact.provenance) catch |err| return progress.fail(
            state_store,
            allocator,
            .unavailable,
            .resource_limit_exceeded,
            "acquire",
            @errorName(err),
        );
        progress.acquired = .complete;

        if (prior_state) |*prior| {
            if (prior.state.installed and
                (prior.state.descriptor == null or !std.mem.eql(
                    u8,
                    &prior.state.descriptor.?.sha256,
                    &artifact.provenance.sha256.bytes,
                )))
                return progress.fail(
                    state_store,
                    allocator,
                    if (prior.state.phase == .complete) .planning else .recovery,
                    if (prior.state.phase == .complete)
                        .existing_descriptor_conflict
                    else
                        .recovery_required,
                    "conflict",
                    if (prior.state.phase == .complete)
                        "a different descriptor artifact is already managed by this add-only operation"
                    else
                        "an installed incomplete repository operation must be recovered before another descriptor is added",
                );
        }
        progress.persist(state_store, allocator, .acquired, null, &.{}) catch |err|
            return progress.fail(
                state_store,
                allocator,
                .unavailable,
                .state_persistence_failed,
                "state",
                @errorName(err),
            );

        const inspected = deb_payload.inspectLocal(allocator, artifact.bytes, .{
            .source = "repository-descriptor",
            .filename = std.fs.path.basename(artifact.provenance.effective_uri),
            .size = artifact.provenance.size,
            .sha256 = artifact.provenance.sha256.bytes,
            .profile = .repository_descriptor,
        }, .{});
        var validation = switch (inspected) {
            .diagnostic => |diagnostic| return progress.fail(
                state_store,
                allocator,
                .download,
                .descriptor_invalid,
                "validate",
                diagnostic.message(),
            ),
            .validation => |value| value,
        };
        defer validation.deinit();
        const descriptor: api.DescriptorIdentity = .{
            .package = validation.package,
            .version = validation.version,
            .architecture = validation.architecture,
            .sha256 = artifact.provenance.sha256.bytes,
            .size = artifact.provenance.size,
            .effective_url = artifact.provenance.effective_uri,
            .trust_mode = switch (artifact.provenance.trust_mode) {
                .https => .verified_https,
                .sha256 => .pinned_sha256,
            },
        };
        progress.descriptor = descriptor;

        var material = inspectDescriptorMaterial(
            allocator,
            &validation,
            architecture,
            request.network,
            request.resources,
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            if (err == error.ResourceBudgetExceeded) .unavailable else .usage,
            if (err == error.ResourceBudgetExceeded)
                .resource_limit_exceeded
            else switch (err) {
                error.MissingPayloadKeyring, error.UnsignedRepository => .descriptor_trust_unresolved,
                error.DynamicRepositoryMaterial => .descriptor_dynamic,
                else => .descriptor_invalid,
            },
            "validate",
            @errorName(err),
        );
        defer material.deinit();
        progress.validated = .complete;
        progress.managed_files = material.evidence;
        var resume_refresh = if (prior_state) |*prior|
            prior.state.installed and
                !prior.state.refreshed and
                prior.state.phase != .complete
        else
            false;
        const repository_material_changed = !snapshotContainsManagedMaterial(
            before_snapshot,
            material.evidence,
        );
        progress.persist(
            state_store,
            allocator,
            .validated,
            descriptor,
            material.evidence,
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            .unavailable,
            .state_persistence_failed,
            "state",
            @errorName(err),
        );

        var metadata = metadata_cache.Cache.initFromDir(self.io, cache_root, .{}) catch |err|
            return progress.fail(
                state_store,
                allocator,
                .unavailable,
                .repository_authentication_failed,
                "preflight",
                @errorName(err),
            );
        defer metadata.deinit();
        const now = if (native) native_dependencies.now_unix else self.now_unix orelse realNow(self.io);
        {
            var descriptor_refresh = refreshDescriptor(
                allocator,
                &material,
                &material.configuration,
                &metadata,
                acquisition_dependencies,
                request.network,
                &budget,
                now,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                if (err == error.ResourceBudgetExceeded) .unavailable else .authentication,
                if (err == error.ResourceBudgetExceeded)
                    .resource_limit_exceeded
                else
                    .repository_authentication_failed,
                "preflight",
                @errorName(err),
            );
            defer descriptor_refresh.deinit(allocator);
            budget.checkTime() catch |err| return progress.fail(
                state_store,
                allocator,
                .unavailable,
                .resource_limit_exceeded,
                "preflight",
                @errorName(err),
            );
            switch (descriptor_refresh) {
                .failed => |diagnostics| return progress.fail(
                    state_store,
                    allocator,
                    .authentication,
                    .repository_authentication_failed,
                    "preflight",
                    if (diagnostics.len == 0)
                        "repository authentication failed"
                    else
                        diagnostics[0].error_name,
                ),
                .published => |*published| budget.chargeMetadata(published) catch |err|
                    return progress.fail(
                        state_store,
                        allocator,
                        .unavailable,
                        .resource_limit_exceeded,
                        "preflight",
                        @errorName(err),
                    ),
            }
        }
        progress.authenticated = .complete;
        progress.persist(
            state_store,
            allocator,
            .preflight_authenticated,
            descriptor,
            material.evidence,
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            .unavailable,
            .state_persistence_failed,
            "state",
            @errorName(err),
        );

        var installed = loadInstalled(
            allocator,
            target_files.interface(),
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            .unavailable,
            .target_configuration_failed,
            "installed-state",
            @errorName(err),
        );
        defer installed.deinit();
        const existing = findInstalledPackage(
            installed.database.packages,
            validation.package,
        );
        var skip_install = false;
        var incomplete_descriptor = false;
        if (existing) |package| {
            const recoverable_incomplete = if (prior_state) |*prior|
                phaseAtLeast(prior.state.phase, .locked) and
                    prior.state.phase != .complete and
                    prior.state.descriptor != null and
                    std.mem.eql(
                        u8,
                        &prior.state.descriptor.?.sha256,
                        &artifact.provenance.sha256.bytes,
                    )
            else
                false;
            if (!package.status.isFullyInstalled() and !recoverable_incomplete)
                return progress.fail(
                    state_store,
                    allocator,
                    .recovery,
                    .existing_descriptor_conflict,
                    "conflict",
                    "descriptor package is present in an incomplete dpkg state",
                );
            if (!package.status.isFullyInstalled()) {
                // The durable plan and journal, not the now-incomplete dpkg
                // database, define the only safe recovery transition.
                incomplete_descriptor = true;
            } else {
                if (!std.mem.eql(u8, package.version.spelling.value, validation.version) or
                    !std.mem.eql(u8, package.architecture.value, validation.architecture))
                    return progress.fail(
                        state_store,
                        allocator,
                        .planning,
                        .existing_descriptor_conflict,
                        "conflict",
                        "same descriptor package name is already installed with different identity",
                    );
                const prior = if (prior_state) |*value| value.state.descriptor else null;
                if (!native and (prior == null or
                    !std.mem.eql(u8, &prior.?.sha256, &artifact.provenance.sha256.bytes)))
                    return progress.fail(
                        state_store,
                        allocator,
                        .planning,
                        .existing_descriptor_conflict,
                        "conflict",
                        "installed descriptor is not bound to this exact acquired artifact",
                    );
                verifyManagedFiles(
                    allocator,
                    target_files.interface(),
                    material.evidence,
                ) catch |err| return progress.fail(
                    state_store,
                    allocator,
                    .planning,
                    .managed_file_conflict,
                    "conflict",
                    @errorName(err),
                );
                skip_install = true;
                if (!native) {
                    progress.installed = true;
                    progress.installed_phase = .complete;
                }
                if (prior_state) |value| {
                    if (!value.state.refreshed and value.state.phase != .complete)
                        resume_refresh = true;
                }
            }
        } else if (progress.installed) {
            return progress.fail(
                state_store,
                allocator,
                .recovery,
                .recovery_required,
                "resume",
                "operation state records installation but dpkg state does not",
            );
        }

        const installed_policies = try makeInstalledPolicies(
            allocator,
            installed.database.packages,
        );
        defer allocator.free(installed_policies);
        const local_index_text = try localIndexText(
            allocator,
            validation,
            artifact.provenance.sha256.bytes,
            artifact.provenance.size,
        );
        defer allocator.free(local_index_text);
        const local_evidence = artifact.provenance.originEvidence(
            validation.package,
            validation.version,
            validation.architecture,
        );
        const local_index_result = try packages_index.parseBorrowed(allocator, local_index_text, .{
            .repository_id = .{ .bytes = local_evidence.artifact_id },
            .component = "local",
            .architecture = architecture,
            .source_location = artifact.provenance.effective_uri,
        }, .{});
        var local_index = switch (local_index_result) {
            .diagnostic => return progress.fail(
                state_store,
                allocator,
                .planning,
                .descriptor_invalid,
                "plan",
                "descriptor control metadata cannot form a solver input",
            ),
            .index => |value| value,
        };
        defer local_index.deinit();
        const local_repository = solver.RepositoryInput.fromLocalArtifact(
            &local_index,
            1000,
            local_evidence,
        );

        var dependency_refresh: ?repository_policy.RefreshOutcome = null;
        defer if (dependency_refresh) |*value| value.deinit(allocator);
        const plan_store = try repository_plan.Store.init(
            self.io,
            operation_dir,
            exact_plan_name,
        );
        const persisted_plan_required = if (prior_state) |*prior|
            phaseAtLeast(prior.state.phase, .planned)
        else
            false;
        var plan = if (persisted_plan_required)
            plan_store.read(allocator) catch |err| return progress.fail(
                state_store,
                allocator,
                .recovery,
                .recovery_required,
                "plan",
                @errorName(err),
            )
        else if (native and skip_install)
            try unchangedDescriptorPlan(allocator, architecture)
        else blk: {
            var planning = try planDescriptor(
                allocator,
                &.{local_repository},
                installed.database.packages,
                installed_policies,
                architecture,
                validation.package,
                validation.version,
                skip_install and !native,
                request.resources,
            );
            if (planning == .failure) {
                var first_failure = planning.failure;
                defer first_failure.deinit();
                const refresh_needed = dependencyFailureNeedsRefresh(first_failure);
                if (!refresh_needed or before_snapshot.configuration.repositories.len == 0)
                    return progress.fail(
                        state_store,
                        allocator,
                        .planning,
                        .dependency_planning_failed,
                        "plan",
                        if (first_failure.problems.len == 0)
                            "descriptor dependency closure is not satisfiable from installed state"
                        else
                            first_failure.problems[0].detail,
                    );
                dependency_refresh = refreshTarget(
                    allocator,
                    &before_snapshot,
                    &metadata,
                    acquisition_dependencies,
                    request.network,
                    &budget,
                    now,
                ) catch |err| return progress.fail(
                    state_store,
                    allocator,
                    if (err == error.ResourceBudgetExceeded) .unavailable else .authentication,
                    if (err == error.ResourceBudgetExceeded)
                        .resource_limit_exceeded
                    else
                        .dependency_refresh_failed,
                    "dependency-refresh",
                    @errorName(err),
                );
                budget.checkTime() catch |err| return progress.fail(
                    state_store,
                    allocator,
                    .unavailable,
                    .resource_limit_exceeded,
                    "dependency-refresh",
                    @errorName(err),
                );
                const published = switch (dependency_refresh.?) {
                    .failed => |diagnostics| return progress.fail(
                        state_store,
                        allocator,
                        .authentication,
                        .dependency_refresh_failed,
                        "dependency-refresh",
                        if (diagnostics.len == 0)
                            "existing repository refresh failed"
                        else
                            diagnostics[0].error_name,
                    ),
                    .published => |*value| blk_published: {
                        budget.chargeMetadata(value) catch |err| return progress.fail(
                            state_store,
                            allocator,
                            .unavailable,
                            .resource_limit_exceeded,
                            "dependency-refresh",
                            @errorName(err),
                        );
                        break :blk_published value;
                    },
                };
                const repositories = try allocator.alloc(
                    solver.RepositoryInput,
                    published.universe.repositories.len + 1,
                );
                defer allocator.free(repositories);
                repositories[0] = local_repository;
                @memcpy(repositories[1..], published.universe.repositories);
                planning = try planDescriptor(
                    allocator,
                    repositories,
                    installed.database.packages,
                    installed_policies,
                    architecture,
                    validation.package,
                    validation.version,
                    skip_install and !native,
                    request.resources,
                );
            }
            break :blk switch (planning) {
                .failure => |failure_value| {
                    var failure = failure_value;
                    defer failure.deinit();
                    return progress.fail(
                        state_store,
                        allocator,
                        .planning,
                        .dependency_planning_failed,
                        "plan",
                        if (failure.problems.len == 0)
                            "descriptor dependency planning failed"
                        else
                            failure.problems[0].detail,
                    );
                },
                .plan => |value| value,
            };
        };
        defer plan.deinit();
        budget.validatePlan(plan) catch |err| return progress.fail(
            state_store,
            allocator,
            .planning,
            .resource_limit_exceeded,
            "plan",
            @errorName(err),
        );
        const plan_json = try plan.canonicalJson(allocator);
        defer allocator.free(plan_json);
        const executable_plan_sha256 = transaction_executor.planDigest(plan);
        const plan_sha256 = if (native) executable_plan_sha256 else sha256(plan_json);
        if (persisted_plan_required) {
            const prior = &prior_state.?.state;
            if (prior.plan_path == null or prior.plan_sha256 == null or
                !std.mem.eql(u8, prior.plan_path.?, paths.exact_plan_logical) or
                !std.mem.eql(u8, &prior.plan_sha256.?, &plan_sha256))
                return progress.fail(
                    state_store,
                    allocator,
                    .recovery,
                    .recovery_required,
                    "plan",
                    "persisted executable plan does not match operation state",
                );
        } else {
            if (native_input) |input| try input.validate();
            plan_store.writeAtomic(allocator, plan) catch |err| return progress.fail(
                state_store,
                allocator,
                .planning,
                .lock_publication_failed,
                "plan",
                @errorName(err),
            );
            if (native_input) |input| try input.validate();
        }
        progress.plan_path = paths.exact_plan_logical;
        progress.plan_sha256 = plan_sha256;
        progress.planned = .complete;
        progress.persist(
            state_store,
            allocator,
            .planned,
            descriptor,
            material.evidence,
        ) catch |err| {
            if (skip_install and !native) {
                progress.installed = true;
                progress.installed_phase = .complete;
            }
            return progress.fail(
                state_store,
                allocator,
                if (progress.installed) .post_install else .unavailable,
                .state_persistence_failed,
                "state",
                @errorName(err),
            );
        };

        const lock_store = try exact_lock_v2.Store.init(
            self.io,
            operation_dir,
            exact_lock_name,
        );
        const persisted_lock_required = (!native and skip_install) or
            if (prior_state) |*prior|
                phaseAtLeast(prior.state.phase, .locked)
            else
                false;
        const execution_policy = repositoryExecutionPolicy(request);
        if (native or !persisted_lock_required) {
            const journal_state = inspectTransactionJournal(
                allocator,
                self.io,
                paths.state_physical,
                request.root,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                .recovery,
                .recovery_required,
                "journal",
                @errorName(err),
            );
            if (journal_state == .incomplete)
                return progress.fail(
                    state_store,
                    allocator,
                    .recovery,
                    .recovery_required,
                    "journal",
                    "an unrelated incomplete transaction journal blocks repository execution",
                );
        }
        if (!persisted_lock_required and
            persisted_plan_required and
            planHasAuthenticatedPackages(plan) and
            dependency_refresh == null)
        {
            dependency_refresh = refreshTarget(
                allocator,
                &before_snapshot,
                &metadata,
                acquisition_dependencies,
                request.network,
                &budget,
                now,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                if (err == error.ResourceBudgetExceeded) .unavailable else .authentication,
                if (err == error.ResourceBudgetExceeded)
                    .resource_limit_exceeded
                else
                    .dependency_refresh_failed,
                "dependency-refresh",
                @errorName(err),
            );
            const refreshed = switch (dependency_refresh.?) {
                .failed => |diagnostics| return progress.fail(
                    state_store,
                    allocator,
                    .authentication,
                    .dependency_refresh_failed,
                    "dependency-refresh",
                    if (diagnostics.len == 0)
                        "persisted dependency snapshot is unavailable"
                    else
                        diagnostics[0].error_name,
                ),
                .published => |*value| value,
            };
            budget.chargeMetadata(refreshed) catch |err| return progress.fail(
                state_store,
                allocator,
                .unavailable,
                .resource_limit_exceeded,
                "dependency-refresh",
                @errorName(err),
            );
        }
        var dependency_published: ?*repository_policy.RefreshResult =
            if (dependency_refresh) |*outcome| switch (outcome.*) {
                .published => |*value| value,
                .failed => null,
            } else null;
        var lock = if (persisted_lock_required)
            lock_store.read(allocator, exact_lock_v2.maximum_document_bytes) catch |err|
                return progress.fail(
                    state_store,
                    allocator,
                    .recovery,
                    .recovery_required,
                    "lock",
                    @errorName(err),
                )
        else if (native and plan.actions.len == 0)
            createUnchangedOperationLock(allocator, plan, local_evidence, existing orelse return error.DescriptorIdentityMismatch, request) catch |err|
                return progress.fail(state_store, allocator, .planning, .lock_publication_failed, "lock", @errorName(err))
        else
            createOperationLock(
                allocator,
                plan,
                local_evidence,
                dependency_published,
                request,
                transaction_backend,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                .planning,
                .lock_publication_failed,
                "lock",
                @errorName(err),
            );
        defer lock.deinit();
        budget.validateLock(lock.lock) catch |err| return progress.fail(
            state_store,
            allocator,
            .planning,
            .resource_limit_exceeded,
            "lock",
            @errorName(err),
        );
        validateLockDescriptor(lock.lock, descriptor) catch |err| return progress.fail(
            state_store,
            allocator,
            .recovery,
            .recovery_required,
            "lock",
            @errorName(err),
        );
        validateLockPolicy(lock.lock, transaction_backend) catch |err| return progress.fail(
            state_store,
            allocator,
            .recovery,
            .recovery_required,
            "lock",
            @errorName(err),
        );
        validateLockRequest(allocator, lock.lock, request, plan, transaction_backend) catch |err|
            return progress.fail(
                state_store,
                allocator,
                .recovery,
                .recovery_required,
                "lock",
                @errorName(err),
            );
        if (!persisted_lock_required) {
            if (native_input) |input| try input.validate();
            lock_store.writeAtomic(allocator, lock.lock) catch |err|
                return progress.fail(
                    state_store,
                    allocator,
                    .planning,
                    .lock_publication_failed,
                    "lock",
                    @errorName(err),
                );
            if (native_input) |input| try input.validate();
        }
        var recovery_needed = incomplete_descriptor;
        if (!native and persisted_lock_required) {
            const journal = classifyTransactionJournal(
                allocator,
                self.io,
                paths.state_physical,
                request.root,
                plan,
                execution_policy,
                lock.lock,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                .recovery,
                .recovery_required,
                "journal",
                @errorName(err),
            );
            switch (journal) {
                .none, .unrelated_completed => {},
                .matching_current => recovery_needed = true,
                .mismatched_incomplete => return progress.fail(
                    state_store,
                    allocator,
                    .recovery,
                    .recovery_required,
                    "journal",
                    "an incomplete transaction journal belongs to another plan, policy, or lock",
                ),
            }
        }
        if (persisted_lock_required and
            !recovery_needed and
            planHasAuthenticatedPackages(plan) and
            dependency_refresh == null)
        {
            dependency_refresh = refreshTarget(
                allocator,
                &before_snapshot,
                &metadata,
                acquisition_dependencies,
                request.network,
                &budget,
                now,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                if (err == error.ResourceBudgetExceeded) .unavailable else .authentication,
                if (err == error.ResourceBudgetExceeded)
                    .resource_limit_exceeded
                else
                    .dependency_refresh_failed,
                "dependency-refresh",
                @errorName(err),
            );
            const refreshed = switch (dependency_refresh.?) {
                .failed => |diagnostics| return progress.fail(
                    state_store,
                    allocator,
                    .authentication,
                    .dependency_refresh_failed,
                    "dependency-refresh",
                    if (diagnostics.len == 0)
                        "persisted dependency snapshot is unavailable"
                    else
                        diagnostics[0].error_name,
                ),
                .published => |*value| value,
            };
            budget.chargeMetadata(refreshed) catch |err| return progress.fail(
                state_store,
                allocator,
                .unavailable,
                .resource_limit_exceeded,
                "dependency-refresh",
                @errorName(err),
            );
            dependency_published = refreshed;
        }
        if (dependency_published) |published|
            validateLockSnapshots(lock.lock, published) catch |err|
                return progress.fail(
                    state_store,
                    allocator,
                    .recovery,
                    .recovery_required,
                    "lock",
                    @errorName(err),
                );
        progress.exact_lock_path = paths.exact_lock_logical;
        progress.persist(
            state_store,
            allocator,
            .locked,
            descriptor,
            material.evidence,
        ) catch |err| {
            if (skip_install and !native) {
                progress.installed = true;
                progress.installed_phase = .complete;
            }
            return progress.fail(
                state_store,
                allocator,
                if (progress.installed) .post_install else .unavailable,
                .state_persistence_failed,
                "state",
                @errorName(err),
            );
        };
        var artifacts: std.ArrayList(transaction_executor.Artifact) = .empty;
        defer {
            for (artifacts.items) |item| allocator.free(item.path);
            artifacts.deinit(allocator);
        }
        if (!skip_install and !recovery_needed) acquirePlanArtifacts(
            allocator,
            request,
            paths.cache_physical,
            &package_cache,
            acquisition_dependencies,
            plan,
            dependency_published,
            &before_snapshot.configuration,
            &budget,
            &artifacts,
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            if (err == error.ResourceBudgetExceeded) .unavailable else .download,
            if (err == error.ResourceBudgetExceeded)
                .resource_limit_exceeded
            else
                .dependency_acquisition_failed,
            "dependency-acquire",
            @errorName(err),
        );

        if (native_input) |input| {
            if (plan.actions.len == 0) {
                var unchanged = completeUnchangedNative(allocator, .{
                    .recovery = input,
                    .descriptor_archive = artifact.bytes,
                }, native_dependencies) catch |err|
                    return native_progress.failure(allocator, input, err, &progress);
                defer unchanged.deinit();
                return nativeStateResult(allocator, input.repository, unchanged.state.state, false);
            }
            var execution = executeNativeFromCache(allocator, .{
                .repository = request,
                .attempt = input.attempt,
                .plan = &plan,
                .exact_lock = &lock.lock,
                .cache = &package_cache,
                .retained_archives = &.{artifact.bytes},
                .deadline = input.deadline,
            }) catch |err| return native_progress.failure(allocator, input, err, &progress);
            defer execution.deinit();
            switch (execution) {
                .unchanged => return error.NativeExecutionRequired,
                .diagnostic => |diagnostic| return progress.reportFailure(
                    allocator,
                    .planning,
                    .dependency_planning_failed,
                    "native-preparation",
                    diagnostic.diagnostic.detail,
                ),
                .execution => |report_value| {
                    native_progress.runtime_detail = report_value.detail;
                    if (report_value.receipt == null)
                        return native_progress.failure(allocator, input, nativePendingError(report_value), &progress);
                    native_progress.package_installed = report_value.receipt.?.document.outcome == .succeeded;
                    native_progress.runtime_detail = null;
                },
            }
            var resumed = resumeNativeRepository(allocator, input, native_dependencies) catch |err|
                return native_progress.failure(allocator, input, err, &progress);
            defer resumed.deinit();
            return (try nativeResumeResult(allocator, input, &resumed, &native_progress)) orelse error.NativeExecutionRequired;
        }

        var report: ?transaction_executor.Report = null;
        defer if (report) |*value| value.deinit();
        var recovery_report: ?transaction_executor.RecoveryReport = null;
        defer if (recovery_report) |*value| value.deinit();
        if (skip_install) {
            validateRecoveryEvidence(
                allocator,
                self.io,
                operation_dir,
                descriptor,
            ) catch |err| {
                if (prior_state.?.state.phase == .complete)
                    return progress.fail(
                        state_store,
                        allocator,
                        .recovery,
                        .recovery_required,
                        "resume",
                        @errorName(err),
                    );
                recovery_needed = true;
            };
            if (!recovery_needed) {
                // Verification only. The target locks are still taken beneath
                // the root operation lock, so the established order holds.
                guard.enterRank(.target_database) catch return api.failure(
                    .internal,
                    .internal_error,
                    "lock",
                    "target locks were requested out of order",
                );
                defer guard.exitRank(.target_database);
                const transaction_lock_path = try rootPath(
                    allocator,
                    request.root,
                    "/var/lib/debz/transaction.lock",
                );
                defer allocator.free(transaction_lock_path);
                const frontend_lock_path = try rootPath(
                    allocator,
                    request.root,
                    "/var/lib/dpkg/lock-frontend",
                );
                defer allocator.free(frontend_lock_path);
                const dpkg_lock_path = try rootPath(
                    allocator,
                    request.root,
                    "/var/lib/dpkg/lock",
                );
                defer allocator.free(dpkg_lock_path);
                const target_lock_paths = [_][]const u8{
                    transaction_lock_path,
                    frontend_lock_path,
                    dpkg_lock_path,
                };
                var system_target_locks = transaction_executor.SystemLockManager{
                    .allocator = allocator,
                    .io = self.io,
                };
                const target_locks = self.target_locks orelse
                    system_target_locks.interface();
                // The repository-operation lock is already held. Keep the
                // established install/recovery order beneath it so repository
                // paths never invert the target transaction lock hierarchy.
                var held_target_locks: [target_lock_paths.len]?transaction_executor.LockToken =
                    @splat(null);
                defer {
                    var index = held_target_locks.len;
                    while (index > 0) {
                        index -= 1;
                        if (held_target_locks[index]) |value|
                            target_locks.release(value);
                        held_target_locks[index] = null;
                    }
                }
                for (target_lock_paths, 0..) |path, index| {
                    const remaining = budget.remainingTime() catch |err|
                        return progress.fail(
                            state_store,
                            allocator,
                            .unavailable,
                            .resource_limit_exceeded,
                            "resume-current-state-lock",
                            @errorName(err),
                        );
                    held_target_locks[index] = target_locks.acquire(
                        path,
                        @min(request.state.lock_wait_ms, remaining),
                    ) catch |err| {
                        budget.checkTime() catch |deadline_err|
                            return progress.fail(
                                state_store,
                                allocator,
                                .unavailable,
                                .resource_limit_exceeded,
                                "resume-current-state-lock",
                                @errorName(deadline_err),
                            );
                        return progress.fail(
                            state_store,
                            allocator,
                            .recovery,
                            .recovery_required,
                            "resume-current-state-lock",
                            @errorName(err),
                        );
                    };
                    budget.checkTime() catch |err| return progress.fail(
                        state_store,
                        allocator,
                        .unavailable,
                        .resource_limit_exceeded,
                        "resume-current-state-lock",
                        @errorName(err),
                    );
                }
                var system_status_reader =
                    transaction_recovery.SystemStatusFileReader{
                        .io = self.io,
                        .expected_root = request.root,
                    };
                const status_reader = self.status_reader orelse
                    system_status_reader.interface();
                const verification =
                    transaction_recovery.verifyExactLockV2LockedPackages(
                        allocator,
                        lock.lock,
                        request.root,
                        status_reader,
                        64 * 1024 * 1024,
                    ) catch |err| {
                        budget.checkTime() catch |deadline_err|
                            return progress.fail(
                                state_store,
                                allocator,
                                .unavailable,
                                .resource_limit_exceeded,
                                "resume-current-state",
                                @errorName(deadline_err),
                            );
                        return progress.fail(
                            state_store,
                            allocator,
                            .recovery,
                            .recovery_required,
                            "resume-current-state",
                            @errorName(err),
                        );
                    };
                budget.checkTime() catch |err| return progress.fail(
                    state_store,
                    allocator,
                    .unavailable,
                    .resource_limit_exceeded,
                    "resume-current-state",
                    @errorName(err),
                );
                switch (verification) {
                    .success => {},
                    .failure => |failure| return progress.fail(
                        state_store,
                        allocator,
                        .recovery,
                        .recovery_required,
                        "resume-current-state",
                        @tagName(failure.kind),
                    ),
                }
                progress.exact_lock_path = paths.exact_lock_logical;
                progress.provenance_path = paths.provenance_logical;
            }
        }
        if (!skip_install or recovery_needed) {
            // Handing control to the command-oriented executor is the point
            // after which this backend can no longer prove that the root was
            // untouched. The durable bridge is published before the executor
            // takes any target lock and is resolved from the executor's own
            // command evidence below.
            if (guard.enterExecutor()) |failure| return progress.fail(
                state_store,
                allocator,
                failure.exit_status,
                failure.diagnostics[0].id,
                "root-operation",
                failure.diagnostics[0].message,
            );
            var system_process = transaction_executor.SystemProcessRunner{
                .allocator = allocator,
                .io = self.io,
            };
            defer system_process.deinit();
            var system_files = transaction_executor.SystemFileSystem{
                .allocator = allocator,
                .io = self.io,
            };
            var system_locks = transaction_executor.SystemLockManager{
                .allocator = allocator,
                .io = self.io,
            };
            var journal = transaction_recovery.SystemJournalStore.init(
                self.io,
                paths.state_physical,
                request.root,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                .transaction,
                .transaction_failed,
                "install",
                @errorName(err),
            );
            defer journal.deinit();
            var status_reader = transaction_recovery.SystemStatusFileReader{
                .io = self.io,
                .expected_root = request.root,
            };
            const dependencies: transaction_executor.Dependencies = .{
                .filesystem = system_files.interface(),
                .locks = system_locks.interface(),
                .process = self.process_runner orelse system_process.interface(),
                .journal = journal.interface(),
                .status = self.status_reader orelse status_reader.interface(),
                .deadline = .{
                    .context = budget.clock.context,
                    .nowMsFn = budget.clock.nowMsFn,
                    .expires_at_ms = budget.deadline_ms,
                },
            };
            if (recovery_needed) {
                recovery_report = executor.?.recover(
                    allocator,
                    .{
                        .plan = &plan,
                        .install_root = request.root,
                        .policy = execution_policy,
                        .exact_lock_v2 = &lock.lock,
                    },
                    dependencies,
                ) catch |err| return progress.fail(
                    state_store,
                    allocator,
                    .transaction,
                    .transaction_failed,
                    "recover",
                    @errorName(err),
                );
            } else {
                report = executor.?.execute(allocator, .{
                    .plan = &plan,
                    .install_root = request.root,
                    .artifacts = artifacts.items,
                    .policy = execution_policy,
                    .exact_lock_v2 = &lock.lock,
                }, dependencies) catch |err| return progress.fail(
                    state_store,
                    allocator,
                    .transaction,
                    .transaction_failed,
                    "install",
                    @errorName(err),
                );
                if (!report.?.succeeded() and
                    report.?.failure != null and
                    report.?.failure.?.code == .invalid_recovery_transition)
                {
                    report.?.deinit();
                    report = null;
                    recovery_report = executor.?.recover(
                        allocator,
                        .{
                            .plan = &plan,
                            .install_root = request.root,
                            .policy = execution_policy,
                            .exact_lock_v2 = &lock.lock,
                        },
                        dependencies,
                    ) catch |err| return progress.fail(
                        state_store,
                        allocator,
                        .transaction,
                        .transaction_failed,
                        "recover",
                        @errorName(err),
                    );
                }
            }
            const succeeded = if (recovery_report) |value|
                value.succeeded()
            else
                report.?.succeeded();
            // The executor's own transaction state decides the witness. A
            // report that ran no command is only proof that nothing started
            // when the transaction state is still `not_started`; a spawn that
            // timed out or hit the deadline reports zero commands after dpkg
            // may already have mutated the root.
            const observed = if (recovery_report) |value|
                root_operation.recoveryReportWitness(value)
            else
                root_operation.reportWitness(report.?);
            if (guard.observe(observed, succeeded)) |failure| return progress.fail(
                state_store,
                allocator,
                failure.exit_status,
                failure.diagnostics[0].id,
                "root-operation",
                failure.diagnostics[0].message,
            );
            if (!succeeded) {
                if (descriptorIdentityInstalled(
                    allocator,
                    target_files.interface(),
                    descriptor,
                ) catch false) {
                    progress.changed = true;
                    progress.installed = true;
                    progress.installed_phase = .complete;
                }
                return progress.fail(
                    state_store,
                    allocator,
                    .transaction,
                    .transaction_failed,
                    if (recovery_report != null) "recover" else "install",
                    if (recovery_report) |value| if (value.failure) |failure|
                        failure.diagnostic
                    else
                        "dpkg transaction recovery failed" else if (report.?.failure) |failure|
                        failure.diagnostic
                    else
                        "dpkg transaction failed",
                );
            }
            progress.changed = !skip_install;
            progress.installed = true;
            progress.installed_phase = .complete;
            const reported_plan_sha256 = if (recovery_report) |value|
                value.plan_sha256
            else
                report.?.plan_sha256;
            const reported_policy_sha256 = if (recovery_report) |value|
                value.policy_sha256
            else
                report.?.policy_sha256;
            const expected_policy_sha256 =
                transaction_executor.policyDigest(execution_policy);
            if (!std.mem.eql(
                u8,
                &reported_plan_sha256,
                &executable_plan_sha256,
            ) or !std.mem.eql(
                u8,
                &reported_policy_sha256,
                &expected_policy_sha256,
            )) return progress.fail(
                state_store,
                allocator,
                .recovery,
                .recovery_required,
                "provenance",
                "executor report does not match the persisted plan and verification policy",
            );

            progress.provenance_sha256 = if (recovery_report) |value|
                publishRecoveryProvenance(
                    allocator,
                    self.io,
                    operation_dir,
                    request.root,
                    &lock.lock,
                    value,
                    dependency_published,
                ) catch |err| return progress.fail(
                    state_store,
                    allocator,
                    .post_install,
                    .provenance_publication_failed,
                    "provenance",
                    @errorName(err),
                )
            else
                publishProvenance(
                    allocator,
                    self.io,
                    operation_dir,
                    request.root,
                    &lock.lock,
                    report.?,
                    dependency_published,
                ) catch |err| return progress.fail(
                    state_store,
                    allocator,
                    .post_install,
                    .provenance_publication_failed,
                    "provenance",
                    @errorName(err),
                );
            progress.provenance_path = paths.provenance_logical;
            progress.persist(
                state_store,
                allocator,
                .installed,
                descriptor,
                material.evidence,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                .post_install,
                .state_persistence_failed,
                "state",
                @errorName(err),
            );
        }
        budget.checkTime() catch |err| return progress.fail(
            state_store,
            allocator,
            .post_install,
            .resource_limit_exceeded,
            "install",
            @errorName(err),
        );

        verifyInstalledDescriptor(
            allocator,
            target_files.interface(),
            descriptor,
            material.evidence,
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            .post_install,
            .installed_verification_failed,
            "verify-installed",
            @errorName(err),
        );

        var after_snapshot = target_apt_config.snapshot(allocator, .{
            .root_path = request.root,
            .architecture_override = architecture,
            .limits = targetLimits(request.resources),
            .dependencies = .{
                .filesystem = target_files.interface(),
                .process = if (transaction_backend == .legacy_dpkg)
                    architecture_process.interface()
                else
                    null,
            },
        }) catch |err| return progress.fail(
            state_store,
            allocator,
            .post_install,
            .target_import_failed,
            "import",
            @errorName(err),
        );
        defer after_snapshot.deinit();
        if (transaction_backend == .native) {
            if (RootOperationGuard.checkArchitecture(guard.active().?.record(), .{
                .native = after_snapshot.manifest.manifest.native_architecture,
                .foreign = after_snapshot.manifest.manifest.foreign_architectures,
            })) |failure| return progress.fail(
                state_store,
                allocator,
                failure.exit_status,
                failure.diagnostics[0].id,
                "import",
                failure.diagnostics[0].message,
            );
        }
        verifyImportedMaterial(after_snapshot, material.evidence) catch |err|
            return progress.fail(
                state_store,
                allocator,
                .post_install,
                .target_import_failed,
                "import",
                @errorName(err),
            );
        const manifest_store = target_apt_config.Store.init(
            self.io,
            operation_dir,
            manifest_name,
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            .post_install,
            .target_import_failed,
            "manifest",
            @errorName(err),
        );
        manifest_store.writeAtomic(allocator, after_snapshot.manifest.manifest) catch |err|
            return progress.fail(
                state_store,
                allocator,
                .post_install,
                .target_import_failed,
                "manifest",
                @errorName(err),
            );
        progress.manifest_path = paths.manifest_logical;
        progress.imported = .complete;
        progress.persist(
            state_store,
            allocator,
            .imported,
            descriptor,
            material.evidence,
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            .post_install,
            .state_persistence_failed,
            "state",
            @errorName(err),
        );
        budget.checkTime() catch |err| return progress.fail(
            state_store,
            allocator,
            .post_install,
            .resource_limit_exceeded,
            "import",
            @errorName(err),
        );

        if (request.no_refresh) {
            progress.refreshed_phase = if (progress.refreshed) .complete else .skipped;
        } else if (!progress.refreshed and
            (resume_refresh or repository_material_changed))
        {
            var changed_configuration: ?repository_policy.Configuration = null;
            defer if (changed_configuration) |*value| value.deinit();
            if (!resume_refresh) changed_configuration = changedDescriptorConfiguration(
                allocator,
                &material,
                before_snapshot,
                architecture,
                request.network,
                request.resources,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                .post_install,
                if (err == error.ResourceBudgetExceeded)
                    .resource_limit_exceeded
                else
                    .refresh_failed,
                "refresh",
                @errorName(err),
            );
            const refresh_configuration: ?*const repository_policy.Configuration =
                if (resume_refresh)
                    &material.configuration
                else if (changed_configuration) |*value|
                    value
                else
                    null;
            if (refresh_configuration) |configuration| {
                var final_refresh = refreshDescriptor(
                    allocator,
                    &material,
                    configuration,
                    &metadata,
                    acquisition_dependencies,
                    request.network,
                    &budget,
                    now,
                ) catch |err| return progress.fail(
                    state_store,
                    allocator,
                    if (err == error.ResourceBudgetExceeded) .unavailable else .post_install,
                    if (err == error.ResourceBudgetExceeded)
                        .resource_limit_exceeded
                    else
                        .refresh_failed,
                    "refresh",
                    @errorName(err),
                );
                defer final_refresh.deinit(allocator);
                budget.checkTime() catch |err| return progress.fail(
                    state_store,
                    allocator,
                    .unavailable,
                    .resource_limit_exceeded,
                    "refresh",
                    @errorName(err),
                );
                switch (final_refresh) {
                    .failed => |diagnostics| return progress.fail(
                        state_store,
                        allocator,
                        .post_install,
                        .refresh_failed,
                        "refresh",
                        if (diagnostics.len == 0)
                            "installed repository refresh failed"
                        else
                            diagnostics[0].error_name,
                    ),
                    .published => |*published| budget.chargeMetadata(published) catch |err|
                        return progress.fail(
                            state_store,
                            allocator,
                            .unavailable,
                            .resource_limit_exceeded,
                            "refresh",
                            @errorName(err),
                        ),
                }
                progress.refreshed = true;
                progress.refreshed_phase = .complete;
                progress.persist(
                    state_store,
                    allocator,
                    .refreshed,
                    descriptor,
                    material.evidence,
                ) catch |err| return progress.fail(
                    state_store,
                    allocator,
                    .post_install,
                    .state_persistence_failed,
                    "state",
                    @errorName(err),
                );
            } else {
                progress.refreshed_phase = .skipped;
            }
        } else if (progress.refreshed) {
            progress.refreshed_phase = .complete;
        } else {
            progress.refreshed_phase = .skipped;
        }

        budget.checkTime() catch |err| return progress.fail(
            state_store,
            allocator,
            .post_install,
            .resource_limit_exceeded,
            "complete",
            @errorName(err),
        );
        progress.persist(
            state_store,
            allocator,
            .complete,
            descriptor,
            material.evidence,
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            .post_install,
            .state_persistence_failed,
            "state",
            @errorName(err),
        );
        budget.checkTime() catch |err| return progress.fail(
            state_store,
            allocator,
            .post_install,
            .resource_limit_exceeded,
            "complete",
            @errorName(err),
        );
        if (guard.finish(progress.provenanceDigest())) |failure| return progress.fail(
            state_store,
            allocator,
            failure.exit_status,
            failure.diagnostics[0].id,
            "root-operation",
            failure.diagnostics[0].message,
        );
        return progress.success(allocator);
    }
};

const NativeDispatchProgress = struct {
    state: ?state_module.OwnedState = null,
    package_installed: bool = false,
    runtime_detail: ?[]const u8 = null,

    fn deinit(self: *@This()) void {
        if (self.state) |*state| state.deinit();
        self.* = .{};
    }

    fn capture(self: *@This(), allocator: std.mem.Allocator, state: state_module.State) !void {
        const owned = try state_module.create(allocator, state);
        if (self.state) |*prior| prior.deinit();
        self.state = owned;
    }

    fn failure(
        self: *@This(),
        allocator: std.mem.Allocator,
        input: NativeRecoveryRequest,
        err: anyerror,
        fallback: ?*const Progress,
    ) !api.Result {
        if (err == error.OutOfMemory) return err;
        var paths = try ResolvedPaths.init(allocator, input.repository, .native);
        defer paths.deinit();
        var progress = if (fallback) |value| value.* else Progress{
            .root = input.repository.root,
            .architecture = input.attempt.record().target_architecture,
            .no_refresh = input.repository.no_refresh,
            .maximum_state_bytes = input.repository.state.maximum_operation_state_bytes,
            .paths = paths.logicalEvidence(),
        };
        if (self.state) |state| progress.restore(state.state);
        if (self.package_installed) {
            progress.installed = true;
            progress.installed_phase = .complete;
        }
        progress.changed = progress.installed and input.attempt.record().mutation_started;
        if (progress.imported == .complete and input.repository.no_refresh)
            progress.refreshed_phase = .skipped;
        const limited = err == error.DeadlineExceeded or err == error.ResourceBudgetExceeded;
        const id = progress.diagnostic_id orelse if (limited)
            api.DiagnosticId.resource_limit_exceeded
        else
            api.DiagnosticId.recovery_required;
        return progress.reportFailure(
            allocator,
            if (progress.installed) .post_install else if (limited) .unavailable else .recovery,
            id,
            "native",
            if (progress.diagnostic_id != null) progress.diagnostic else self.runtime_detail orelse @errorName(err),
        );
    }
};

const NativePreflightPublication = struct {
    input: ?NativeRecoveryRequest,
    original: state_module.WriteHooks,

    fn hit(raw: ?*anyopaque, point: state_module.WriteBoundary) !void {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        if (self.original.runFn) |run| try run(self.original.context, point);
        if (self.input) |input| try input.validate();
    }
};

fn nativeStateResult(
    allocator: std.mem.Allocator,
    request: api.Request,
    state: state_module.State,
    changed: bool,
) !api.Result {
    if (state.phase != .complete and state.phase != .failed) return error.RepositoryStateMismatch;
    var paths = try ResolvedPaths.init(allocator, request, .native);
    defer paths.deinit();
    var progress: Progress = .{
        .root = request.root,
        .architecture = state.architecture,
        .no_refresh = request.no_refresh,
        .maximum_state_bytes = request.state.maximum_operation_state_bytes,
        .paths = paths.logicalEvidence(),
    };
    progress.restore(state);
    progress.changed = changed and progress.installed;
    if (progress.imported == .complete and request.no_refresh)
        progress.refreshed_phase = .skipped;
    if (state.phase == .failed)
        return progress.reportFailure(allocator, .transaction, .transaction_failed, "native", state.diagnostic);
    return progress.success(allocator);
}

fn nativeResumeResult(
    allocator: std.mem.Allocator,
    input: NativeRecoveryRequest,
    resumed: *const NativeRepositoryResume,
    progress: *NativeDispatchProgress,
) !?api.Result {
    return switch (resumed.*) {
        .not_started => null,
        .pending => |report| blk: {
            progress.runtime_detail = report.detail;
            break :blk try progress.failure(allocator, input, nativePendingError(report), null);
        },
        .completed => |value| try nativeStateResult(allocator, input.repository, value.checkpoint.state.state, true),
        .historical => |value| try nativeStateResult(allocator, input.repository, value.state.state, false),
        .unchanged => |value| try nativeStateResult(allocator, input.repository, value.state.state, false),
    };
}

fn nativePendingError(report: native_runtime.Report) anyerror {
    return if (std.mem.eql(u8, report.detail, "deadline_exceeded"))
        error.DeadlineExceeded
    else
        error.NativeRecoveryRequired;
}

/// Owns rank 0 of the total lock order for one repository bootstrap. It
/// reserves the shared root attempt before the repository operation lock, so
/// a repository add and a package transaction can never mutate one root at the
/// same time, and it resolves the command-oriented executor bridge from the
/// executor's own evidence rather than assuming a mutation happened.
const RootOperationGuard = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    owned_root: ?root_fs.OwnedRoot = null,
    locks: root_operation.SystemLockBackend = undefined,
    coordinator: root_operation.Coordinator = undefined,
    attempt: ?root_operation.Attempt = null,
    acquisition_observer: ?root_operation.AcquisitionObserver = null,
    root_projection: ?*const live_root.Projection = null,
    native_completion_only: bool = false,
    native_resume_completion: bool = false,
    deadline: ?transaction_executor.Deadline = null,

    fn open(
        self: *RootOperationGuard,
        request: api.Request,
        backend: transaction_engine.Kind,
        now_unix: ?i64,
    ) ?api.Result {
        if (self.deadline) |deadline| _ = deadline.remainingMs() catch |err| return mapRootOperationError(err);
        self.owned_root = root_fs.openAbsoluteRoot(self.io, request.root) catch
            return api.failure(
                .usage,
                .invalid_root,
                "target",
                "target root is unsafe or unavailable",
            );
        if (backend == .native) native_operation.validateInstallRoot(
            self.io,
            self.owned_root.?.root,
            request.root,
            self.root_projection,
        ) catch |err| return mapRootOperationError(err);
        self.locks = .{ .allocator = self.allocator, .io = self.io };
        self.coordinator = root_operation.Coordinator.open(
            self.io,
            self.owned_root.?.root,
            request.root,
            self.locks.interface(),
        ) catch |err| return mapRootOperationError(err);
        self.coordinator.root_projection = if (backend == .native) self.root_projection else null;
        self.coordinator.now_unix = now_unix;
        const request_digest = repositoryRequestDigest(request, backend);
        const policy_digest = repositoryPolicyDigest(request, backend);
        var native_architecture = request.architecture orelse "all";
        var foreign_architectures: []const []const u8 = &.{};
        var prior: ?root_operation.OwnedRecord = null;
        defer if (prior) |*value| value.deinit();
        var discovered: ?target_apt_config.OwnedArchitecture = null;
        defer if (discovered) |*value| value.deinit();
        if (backend == .native) {
            prior = self.coordinator.inspect(self.allocator) catch |err|
                return mapRootOperationError(err);
            if (self.native_resume_completion) {
                if (prior) |value| {
                    const record = value.record;
                    if (record.backend == .native and record.state == .completed and
                        record.mutation_started and record.program_sha256 != null)
                        self.native_completion_only = true;
                }
            }
            if (self.native_completion_only) {
                const record = if (prior) |value| value.record else return mapRootOperationError(error.NoActiveAttempt);
                if (record.backend != .native or !record.operation.eql(.{ .repository_bootstrap = .add }) or
                    !record.mutation_started or record.program_sha256 == null or
                    !std.mem.eql(u8, &record.request_sha256, &request_digest) or
                    !std.mem.eql(u8, &record.policy_sha256, &policy_digest))
                    return mapRootOperationError(error.AttemptMismatch);
            }
            const retain_architecture = if (prior) |value| blk: {
                const record = value.record;
                break :blk record.state.blocksMutation() or
                    (record.state == .completed and record.provenance == .pending) or
                    (record.backend == .native and record.program_sha256 != null and
                        record.outcome != .abandoned_before_mutation) or
                    (!record.clearable() and record.backend == .native and
                        record.operation.eql(.{ .repository_bootstrap = .add }) and
                        std.mem.eql(u8, &record.request_sha256, &request_digest) and
                        std.mem.eql(u8, &record.policy_sha256, &policy_digest));
            } else false;
            if (retain_architecture) {
                native_architecture = prior.?.record.target_architecture;
                foreign_architectures = prior.?.record.foreign_architectures;
            } else {
                discovered = self.inspectNativeArchitecture(request) catch |err|
                    return architectureFailure(err);
                native_architecture = discovered.?.architecture.native;
                foreign_architectures = discovered.?.architecture.foreign;
            }
        }
        var completion_acquisition: NativeCompletionAcquisition = .{
            .guard = self,
            .expected_sha256 = if (prior) |value| value.record.digest_sha256 else @splat(0),
        };
        self.attempt = self.coordinator.acquire(self.allocator, .{
            // Repository bootstrap is resumable by construction: its durable
            // operation state already replays acquisition, planning, install,
            // import, and refresh. The root attempt is bound to the same
            // request before anything is acquired, so a rerun of exactly this
            // request adopts its own evidence and finishes it, while a
            // different descriptor, architecture, policy, or package
            // operation is still refused and leaves the evidence untouched.
            .intent = if (self.native_completion_only and backend == .native) .recovery else .same_operation,
            .adopt_settled_for_acknowledgment = self.native_completion_only and backend == .native,
            .existing = .reclaim_resolved,
            .backend = backend,
            .operation = .{ .repository_bootstrap = .add },
            .request_sha256 = request_digest,
            .policy_sha256 = policy_digest,
            .target_architecture = native_architecture,
            .foreign_architectures = foreign_architectures,
            .wait_ms = if (self.deadline) |deadline|
                @min(request.state.lock_wait_ms, deadline.remainingMs() catch |err| return mapRootOperationError(err))
            else
                request.state.lock_wait_ms,
            .acquisition_observer = if (backend == .native and (self.native_completion_only or self.deadline != null))
                .{ .context = &completion_acquisition, .hitFn = NativeCompletionAcquisition.hit }
            else
                self.acquisition_observer,
        }) catch |err| return mapRootOperationError(err);
        if (backend == .native) {
            if (self.native_completion_only) {
                validateNativeRepositoryCaller(request, &self.attempt.?) catch |err| return mapRootOperationError(err);
                if (!std.mem.eql(u8, &self.attempt.?.record().digest_sha256, &prior.?.record.digest_sha256))
                    return mapRootOperationError(error.AttemptMismatch);
            }
            const clean = native_runtime.canAbandon(self.allocator, &self.attempt.?) catch |err|
                return mapRootOperationError(err);
            if (!self.attempt.?.adopted and !clean)
                return mapRootOperationError(error.RecoveryRequired);
            if (clean) {
                // Recheck under exclusion, including an adopted reservation
                // that never started. Recovery-bearing callers keep their
                // original architecture instead of inferring from partial state.
                var current = self.inspectNativeArchitecture(request) catch |err|
                    return architectureFailure(err);
                defer current.deinit();
                if (checkArchitecture(self.attempt.?.record(), current.architecture)) |failure|
                    return failure;
            }
        }
        return null;
    }

    fn inspectNativeArchitecture(
        self: *RootOperationGuard,
        request: api.Request,
    ) !target_apt_config.OwnedArchitecture {
        // This view borrows the guard's pinned root; only the guard closes it.
        var files: target_apt_config.ProductionFileSystem = .{
            .io = self.io,
            .root = self.owned_root.?.root.dir,
            .host_root = std.mem.eql(u8, request.root, "/"),
        };
        return target_apt_config.inspectArchitecture(self.allocator, .{
            .root_path = request.root,
            .architecture_override = request.architecture,
            .limits = targetLimits(request.resources),
            .dependencies = .{ .filesystem = files.interface() },
        });
    }

    fn architectureFailure(err: anyerror) api.Result {
        return api.failure(
            if (err == error.OutOfMemory) .internal else .usage,
            if (err == error.OutOfMemory)
                .internal_error
            else if (err == error.NativeArchitectureUnavailable)
                .architecture_unavailable
            else
                .target_configuration_failed,
            "target",
            @errorName(err),
        );
    }

    fn checkArchitecture(record: root_operation.Record, actual: target_apt_config.Architecture) ?api.Result {
        const expected: target_apt_config.Architecture = .{
            .native = record.target_architecture,
            .foreign = record.foreign_architectures,
        };
        if (expected.eql(actual)) return null;
        return api.failure(
            .recovery,
            .recovery_required,
            "target",
            "native target architecture no longer matches the original root caller",
        );
    }

    /// Pointer to the live attempt, never a copy: every boundary must be
    /// published on the record this guard owns.
    fn active(self: *RootOperationGuard) ?*root_operation.Attempt {
        if (self.attempt) |*value| return value;
        return null;
    }

    fn enterRank(self: *RootOperationGuard, rank: root_operation.Rank) !void {
        var attempt = self.active() orelse return;
        try attempt.enterRank(rank);
    }

    fn preflight(self: *RootOperationGuard, architecture: target_apt_config.Architecture) ?api.Result {
        var attempt = self.active() orelse return null;
        if (attempt.record().backend == .native) {
            if (checkArchitecture(attempt.record(), architecture)) |failure| return failure;
        }
        if (attempt.record().state != .reserved) return null;
        attempt.advance(self.allocator, .{
            .state = .preflight,
            .phase = .preflight,
        }) catch |err| return mapRootOperationError(err);
        return null;
    }

    /// Publishes the executor bridge, or resumes an adopted attempt through
    /// the durable recovery boundary. An attempt that already carries mutation
    /// evidence never pretends to be a fresh hand-over.
    fn enterExecutor(self: *RootOperationGuard) ?api.Result {
        var attempt = self.active() orelse return null;
        switch (attempt.record().state) {
            // Nothing was mutated yet, so publish the bridge.
            .reserved, .preflight => attempt.advance(self.allocator, .{
                .state = .mutation_pending,
                .phase = .mutation,
            }) catch |err| return mapRootOperationError(err),
            // The bridge an earlier run published stays exactly as it is, so
            // this run's own executor evidence can never discharge another
            // run's hand-over as never having started.
            .mutation_pending => {},
            // An adopted attempt already carries mutation evidence. Resuming
            // it walks the exact recovery edges instead of moving backwards
            // into the bridge, which the edge table would refuse anyway.
            .mutating, .verifying, .recovery_required, .recovering => attempt.beginRecovery(
                self.allocator,
                .mutation,
            ) catch |err| return mapRootOperationError(err),
            // The attempt already finished; only its provenance is owed.
            .completed => {},
        }
        attempt.enterRank(.target_database) catch |err| return mapRootOperationError(err);
        return null;
    }

    fn exitRank(self: *RootOperationGuard, rank: root_operation.Rank) void {
        var attempt = self.active() orelse return;
        attempt.exitRank(rank);
    }

    /// Resolves the bridge from the executor's own transaction evidence. The
    /// witness is derived by `root_operation`, never from a command count, and
    /// the attempt itself decides which witness may be applied: evidence that
    /// this run started nothing says nothing about a bridge an earlier run
    /// published, so an inherited bridge resolves as observed mutation and
    /// keeps the root blocked until it is recovered.
    fn observe(
        self: *RootOperationGuard,
        observed: root_operation.Witness,
        succeeded: bool,
    ) ?api.Result {
        var attempt = self.active() orelse return null;
        // Already finished; `finish` still owes its provenance.
        if (attempt.record().state == .completed) return null;
        if (attempt.record().state == .mutation_pending) {
            const applied = attempt.witness(self.allocator, observed) catch |err|
                return mapRootOperationError(err);
            if (applied == .proved_not_started) return null;
        }
        if (!attempt.record().mutation_started) return null;
        if (!succeeded) {
            attempt.requireRecovery(self.allocator, .mutation) catch |err|
                return mapRootOperationError(err);
            return null;
        }
        if (attempt.record().state == .mutating) attempt.advance(self.allocator, .{
            .state = .verifying,
            .phase = .verification,
        }) catch |err| return mapRootOperationError(err);
        return null;
    }

    /// Completes the attempt from wherever it durably stopped and only then
    /// publishes provenance and clears the active intent. It is reached only
    /// once the bootstrap itself has succeeded, so every state that carries
    /// mutation evidence is finished rather than left blocking the root.
    fn finish(self: *RootOperationGuard, document_sha256: ?[32]u8) ?api.Result {
        var attempt = self.active() orelse return null;
        switch (attempt.record().state) {
            .completed => {},
            .reserved, .preflight => attempt.complete(
                self.allocator,
                .abandoned_before_mutation,
            ) catch |err| return mapRootOperationError(err),
            // The bootstrap succeeded but the bridge was never witnessed,
            // because the executor was skipped on this run. Nothing here can
            // prove the root was untouched, so the conservative witness is
            // taken and the attempt is finished with its evidence intact.
            .mutation_pending => {
                _ = attempt.witness(self.allocator, .mutation_observed) catch |err|
                    return mapRootOperationError(err);
                if (self.completeMutated(.succeeded)) |failure| return failure;
            },
            .mutating, .verifying => if (self.completeMutated(.succeeded)) |failure|
                return failure,
            // A resumed attempt that had to walk the recovery edges finishes
            // as recovered, which keeps its mutation evidence and still
            // discharges the intent.
            .recovery_required, .recovering => if (self.completeMutated(.recovered)) |failure|
                return failure,
        }
        const record = attempt.record();
        if (record.provenance == .pending) attempt.publishProvenance(
            self.allocator,
            root_operation.provenanceDigest(record, .{
                .outcome = record.outcome,
                .document_sha256 = document_sha256,
                .journal_archived = true,
            }),
        ) catch |err| return mapRootOperationError(err);
        attempt.clear() catch |err| return mapRootOperationError(err);
        return null;
    }

    /// Walks the exact edges from an attempt that carries mutation evidence to
    /// `completed`, so no boundary between the executor and the terminal
    /// outcome is ever skipped.
    fn completeMutated(
        self: *RootOperationGuard,
        outcome: root_operation.Outcome,
    ) ?api.Result {
        var attempt = self.active() orelse return null;
        switch (outcome) {
            .succeeded => {
                if (attempt.record().state == .mutating) attempt.advance(self.allocator, .{
                    .state = .verifying,
                    .phase = .verification,
                }) catch |err| return mapRootOperationError(err);
            },
            .recovered => attempt.beginRecovery(self.allocator, .verification) catch |err|
                return mapRootOperationError(err),
            else => {},
        }
        attempt.complete(self.allocator, outcome) catch |err|
            return mapRootOperationError(err);
        return null;
    }

    fn deinit(self: *RootOperationGuard) void {
        if (self.attempt) |*value| {
            // An attempt that is durably proven never to have mutated the root
            // is released rather than left behind. Anything at or past the
            // executor bridge stays exactly as published, so the next mutation
            // is refused until it is explicitly recovered. A failure here
            // simply leaves the pre-mutation record, which the next attempt
            // reports as an unresolved attempt.
            if (value.locked()) cleanup: {
                if (value.record().state.provenPreMutation()) {
                    if (value.record().backend == .native) {
                        const clean = native_runtime.canAbandon(self.allocator, value) catch |err| {
                            std.log.warn("native repository ownership retained after cleanup inspection failed: {s}", .{@errorName(err)});
                            break :cleanup;
                        };
                        if (!clean) break :cleanup;
                    }
                    value.abandonIfPreMutation(self.allocator) catch {};
                } else if (value.record().backend != .native and value.record().clearable()) value.clear() catch {};
            }
            value.release();
        }
        self.attempt = null;
        if (self.owned_root) |*value| value.close();
        self.owned_root = null;
    }
};

const NativeCompletionAcquisition = struct {
    guard: *RootOperationGuard,
    expected_sha256: [32]u8,

    fn hit(raw: *anyopaque, point: root_operation.AcquisitionPoint) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (self.guard.acquisition_observer) |observer| try observer.hit(point);
        if (self.guard.deadline) |deadline| _ = try deadline.remainingMs();
        if (!self.guard.native_completion_only or point != .after_lock_acquired) return;
        try self.guard.coordinator.validateProjection();
        // Recovery adoption is deliberately broad in core. Authenticate the
        // exact original caller under exclusion before core can reclaim it.
        var current = try self.guard.coordinator.store().read(self.guard.allocator) orelse return error.NoActiveAttempt;
        defer current.deinit();
        if (!std.mem.eql(u8, &current.record.digest_sha256, &self.expected_sha256))
            return error.AttemptMismatch;
    }
};

fn mapRootOperationError(err: anyerror) api.Result {
    return switch (err) {
        error.DeadlineExceeded => api.failure(
            .unavailable,
            .resource_limit_exceeded,
            "root-operation",
            "repository invocation deadline expired while acquiring root ownership",
        ),
        error.LockTimeout, error.LockUnavailable, error.LockCanceled => api.failure(
            .unavailable,
            .recovery_required,
            "root-operation",
            "another debz operation holds the root mutation lock",
        ),
        error.OperationInProgress, error.ResolvedAttemptPresent, error.AttemptMismatch => api.failure(
            .recovery,
            .recovery_required,
            "root-operation",
            "an interrupted debz operation left an unresolved root attempt",
        ),
        error.RecoveryRequired, error.ProvenancePending, error.RootIdentityMismatch => api.failure(
            .recovery,
            .recovery_required,
            "root-operation",
            "a previous debz operation mutated this root and requires recovery",
        ),
        error.RecordCorrupt, error.UnsupportedSchema => api.failure(
            .recovery,
            .state_corrupt,
            "root-operation",
            "the active root attempt record is unreadable",
        ),
        error.InvalidRoot,
        error.RootTooLong,
        error.NamespaceUnavailable,
        error.HostRootNotSupported,
        error.OperationRootMismatch,
        error.InvalidProjection,
        error.RootReplaced,
        error.RuntimeReplaced,
        error.LockReplaced,
        error.MountpointReplaced,
        => api.failure(
            .usage,
            .invalid_root,
            "target",
            "target root cannot host the debz operation namespace",
        ),
        else => api.failure(
            .internal,
            .internal_error,
            "root-operation",
            "root operation coordination failed",
        ),
    };
}

/// Bounded digest of the reviewed repository request.
fn repositoryRequestDigest(request: api.Request, backend: transaction_engine.Kind) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(switch (backend) {
        .legacy_dpkg => "debz-repository-request-v1\x00",
        .native => "debz-native-repository-request-v1\x00",
    });
    if (backend == .native) {
        hashInt(&hash, request.api_version);
        hashField(&hash, @tagName(request.operation));
        hashExecutableRequestFields(&hash, request);
        return hash.finalResult();
    }
    hash.update(@tagName(request.operation));
    hash.update("\x00");
    hash.update(request.root);
    hash.update("\x00");
    hash.update(request.descriptor_url);
    hash.update("\x00");
    hash.update(request.architecture orelse "");
    hash.update("\x00");
    if (request.expected_sha256) |digest| {
        hash.update("\x01");
        hash.update(&digest);
    } else hash.update("\x00");
    hash.update(if (request.no_refresh) "\x01" else "\x00");
    return hash.finalResult();
}

fn repositoryPolicyDigest(request: api.Request, backend: transaction_engine.Kind) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(switch (backend) {
        .legacy_dpkg => "debz-repository-policy-v1\x00",
        .native => "debz-native-repository-policy-v1\x00",
    });
    if (backend == .native)
        hash.update(&transaction_executor.policyDigest(repositoryExecutionPolicy(request)));
    hash.update(if (request.no_refresh) "\x01" else "\x00");
    hash.update(if (request.state.path) |value| value else "");
    hash.update("\x00");
    hash.update(if (request.cache.path) |value| value else "");
    hash.update("\x00");
    hash.update(if (request.network.proxy_url) |value| value else "");
    return hash.finalResult();
}

const Progress = struct {
    root: []const u8,
    architecture: []const u8,
    no_refresh: bool,
    maximum_state_bytes: usize,
    paths: api.EvidencePaths,
    acquired: api.PhaseState = .pending,
    validated: api.PhaseState = .pending,
    authenticated: api.PhaseState = .pending,
    planned: api.PhaseState = .pending,
    installed_phase: api.PhaseState = .pending,
    imported: api.PhaseState = .pending,
    refreshed_phase: api.PhaseState = .pending,
    changed: bool = false,
    installed: bool = false,
    refreshed: bool = false,
    descriptor: ?api.DescriptorIdentity = null,
    plan_path: ?[]const u8 = null,
    plan_sha256: ?[32]u8 = null,
    exact_lock_path: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
    provenance_sha256: ?[32]u8 = null,
    manifest_path: ?[]const u8 = null,
    managed_files: []const state_module.FileEvidence = &.{},
    durable_phase: state_module.Phase = .initialized,
    diagnostic_id: ?api.DiagnosticId = null,
    diagnostic: []const u8 = "",
    native_input: ?NativeRecoveryRequest = null,

    fn restore(self: *Progress, state: state_module.State) void {
        self.durable_phase = state.phase;
        self.acquired = if (phaseAtLeast(state.phase, .acquired)) .complete else .pending;
        self.validated = if (phaseAtLeast(state.phase, .validated)) .complete else .pending;
        self.authenticated = if (phaseAtLeast(state.phase, .preflight_authenticated)) .complete else .pending;
        self.planned = if (phaseAtLeast(state.phase, .planned)) .complete else .pending;
        if (state.descriptor) |value| self.descriptor = .{
            .package = value.package,
            .version = value.version,
            .architecture = value.architecture,
            .sha256 = value.sha256,
            .size = value.size,
            .effective_url = value.effective_url,
            .trust_mode = value.trust_mode,
        };
        self.managed_files = state.managed_files;
        self.plan_path = state.plan_path;
        self.plan_sha256 = state.plan_sha256;
        self.exact_lock_path = state.exact_lock_path;
        self.provenance_path = state.provenance_path;
        self.manifest_path = state.manifest_path;
        self.diagnostic_id = state.diagnostic_id;
        self.diagnostic = state.diagnostic;
        self.installed = state.installed;
        self.installed_phase = if (state.installed) .complete else .pending;
        self.imported = if (state.installed and state.phase != .failed and phaseAtLeast(state.phase, .imported)) .complete else .pending;
        self.refreshed = state.refreshed;
        self.refreshed_phase = if (state.refreshed) .complete else .pending;
    }

    /// Digest of the transaction provenance document published for this
    /// operation, when one exists.
    fn provenanceDigest(self: *const Progress) ?[32]u8 {
        return self.provenance_sha256;
    }

    fn persist(
        self: *Progress,
        store: state_module.Store,
        allocator: std.mem.Allocator,
        phase: state_module.Phase,
        descriptor: ?api.DescriptorIdentity,
        files: []const state_module.FileEvidence,
    ) !void {
        if (self.native_input) |input| try input.validate();
        var state_descriptor: ?state_module.Descriptor = null;
        if (descriptor orelse self.descriptor) |value| state_descriptor = .{
            .package = value.package,
            .version = value.version,
            .architecture = value.architecture,
            .sha256 = value.sha256,
            .size = value.size,
            .effective_url = value.effective_url,
            .trust_mode = value.trust_mode,
        };
        const durable_phase = if (phaseAtLeast(self.durable_phase, phase))
            self.durable_phase
        else
            phase;
        const retain_diagnostic = phaseOrder(self.durable_phase) > phaseOrder(phase) and
            self.diagnostic_id != null;
        const persist_installed = self.installed and
            phaseAtLeast(durable_phase, .installed);
        const persist_refreshed = self.refreshed and
            phaseAtLeast(durable_phase, .refreshed);
        var state = try state_module.create(allocator, .{
            .root = self.root,
            .architecture = self.architecture,
            .no_refresh = self.no_refresh,
            .phase = durable_phase,
            .descriptor = state_descriptor,
            .managed_files = if (files.len != 0) files else self.managed_files,
            .installed = persist_installed,
            .refreshed = persist_refreshed,
            .plan_path = self.plan_path,
            .plan_sha256 = self.plan_sha256,
            .exact_lock_path = self.exact_lock_path,
            .provenance_path = self.provenance_path,
            .manifest_path = self.manifest_path,
            .diagnostic_id = if (retain_diagnostic) self.diagnostic_id else null,
            .diagnostic = if (retain_diagnostic) self.diagnostic else "",
        });
        defer state.deinit();
        try store.writeAtomic(allocator, state.state, self.maximum_state_bytes);
        self.durable_phase = durable_phase;
        if (!retain_diagnostic) {
            self.diagnostic_id = null;
            self.diagnostic = "";
        }
    }

    fn fail(
        self: *Progress,
        store: state_module.Store,
        allocator: std.mem.Allocator,
        status: api.ExitStatus,
        id: api.DiagnosticId,
        phase: []const u8,
        message: []const u8,
    ) !api.Result {
        if (self.native_input != null)
            return self.reportFailure(allocator, status, id, phase, message);
        var completed_phase: state_module.Phase = .initialized;
        if (self.acquired == .complete) completed_phase = .acquired;
        if (self.validated == .complete) completed_phase = .validated;
        if (self.authenticated == .complete) completed_phase = .preflight_authenticated;
        if (self.planned == .complete) completed_phase = .planned;
        if (self.exact_lock_path != null) completed_phase = .locked;
        if (self.installed) completed_phase = .installed;
        if (self.imported == .complete) completed_phase = .imported;
        if (self.refreshed) completed_phase = .refreshed;
        if (phaseAtLeast(self.durable_phase, completed_phase))
            completed_phase = self.durable_phase;
        var state_descriptor: ?state_module.Descriptor = null;
        if (self.descriptor) |value| state_descriptor = .{
            .package = value.package,
            .version = value.version,
            .architecture = value.architecture,
            .sha256 = value.sha256,
            .size = value.size,
            .effective_url = value.effective_url,
            .trust_mode = value.trust_mode,
        };
        var state = state_module.create(allocator, .{
            .root = self.root,
            .architecture = self.architecture,
            .no_refresh = self.no_refresh,
            .phase = completed_phase,
            .descriptor = state_descriptor,
            .managed_files = self.managed_files,
            .installed = self.installed,
            .refreshed = self.refreshed,
            .plan_path = self.plan_path,
            .plan_sha256 = self.plan_sha256,
            .exact_lock_path = self.exact_lock_path,
            .provenance_path = self.provenance_path,
            .manifest_path = self.manifest_path,
            .diagnostic_id = id,
            .diagnostic = message,
        }) catch null;
        if (state) |*owned| {
            store.writeAtomic(
                allocator,
                owned.state,
                self.maximum_state_bytes,
            ) catch {};
            owned.deinit();
        }
        return self.reportFailure(allocator, status, id, phase, message);
    }

    fn reportFailure(
        self: *const Progress,
        allocator: std.mem.Allocator,
        status: api.ExitStatus,
        id: api.DiagnosticId,
        phase: []const u8,
        message: []const u8,
    ) !api.Result {
        var result = api.failure(status, id, phase, message);
        result.acquired = self.acquired;
        result.validated = self.validated;
        result.authenticated = self.authenticated;
        result.planned = self.planned;
        result.installed_phase = self.installed_phase;
        result.imported = self.imported;
        result.refreshed_phase = self.refreshed_phase;
        result.changed = self.changed;
        result.installed = self.installed;
        result.refreshed = self.refreshed;
        result.descriptor = self.descriptor;
        result.paths = .{
            .exact_lock = self.exact_lock_path,
            .provenance = self.provenance_path,
            .target_manifest = self.manifest_path,
            .operation_state = self.paths.operation_state,
        };
        switch (id) {
            .acquisition_failed => {
                if (result.acquired != .complete) result.acquired = .failed;
            },
            .descriptor_invalid, .descriptor_dynamic, .descriptor_trust_unresolved => {
                if (result.validated != .complete) result.validated = .failed;
            },
            .repository_authentication_failed => {
                if (result.authenticated != .complete) result.authenticated = .failed;
            },
            .dependency_planning_failed, .dependency_refresh_failed, .dependency_acquisition_failed => {
                if (result.planned != .complete) result.planned = .failed;
            },
            .transaction_failed => {
                if (!result.installed) result.installed_phase = .failed;
            },
            .installed_verification_failed, .target_import_failed => {
                if (result.imported != .complete) result.imported = .failed;
            },
            .refresh_failed => {
                if (!result.refreshed) result.refreshed_phase = .failed;
            },
            else => {},
        }
        result.digest_sha256 = @splat(0);
        return api.ownResult(allocator, try api.complete(result));
    }

    fn success(self: Progress, allocator: std.mem.Allocator) !api.Result {
        return api.ownResult(allocator, try api.complete(.{
            .acquired = self.acquired,
            .validated = self.validated,
            .authenticated = self.authenticated,
            .planned = self.planned,
            .installed_phase = self.installed_phase,
            .imported = self.imported,
            .refreshed_phase = self.refreshed_phase,
            .changed = self.changed,
            .installed = self.installed,
            .refreshed = self.refreshed,
            .descriptor = self.descriptor,
            .paths = .{
                .exact_lock = self.exact_lock_path,
                .provenance = self.provenance_path,
                .target_manifest = self.manifest_path,
                .operation_state = self.paths.operation_state,
            },
            .exit_status = .success,
            .summary = if (self.changed) "repository added" else "repository already added",
        }));
    }
};

const ResolvedPaths = struct {
    allocator: std.mem.Allocator,
    operation_id: [64]u8,
    cache_logical: []u8,
    state_logical: []u8,
    repository_logical: []u8,
    operations_logical: []u8,
    operation_logical: []u8,
    exact_plan_logical: []u8,
    exact_lock_logical: []u8,
    provenance_logical: []u8,
    manifest_logical: []u8,
    operation_state_logical: []u8,
    cache_physical: []u8,
    state_physical: []u8,
    repository_physical: []u8,
    operation_physical: []u8,

    fn init(
        allocator: std.mem.Allocator,
        request: api.Request,
        backend: transaction_engine.Kind,
    ) !ResolvedPaths {
        const cache_logical = try allocator.dupe(
            u8,
            request.cache.path orelse "/var/cache/debz",
        );
        errdefer allocator.free(cache_logical);
        const state_logical = try allocator.dupe(
            u8,
            request.state.path orelse "/var/lib/debz",
        );
        errdefer allocator.free(state_logical);
        const repository_logical = try joinLogical(
            allocator,
            state_logical,
            operation_directory_name,
        );
        errdefer allocator.free(repository_logical);
        const operations_logical = try joinLogical(
            allocator,
            repository_logical,
            operations_directory_name,
        );
        errdefer allocator.free(operations_logical);
        const operation_id = requestOperationId(request, backend);
        const operation_logical = try joinLogical(
            allocator,
            operations_logical,
            &operation_id,
        );
        errdefer allocator.free(operation_logical);
        const exact_lock_logical = try joinLogical(allocator, operation_logical, exact_lock_name);
        errdefer allocator.free(exact_lock_logical);
        const exact_plan_logical = try joinLogical(allocator, operation_logical, exact_plan_name);
        errdefer allocator.free(exact_plan_logical);
        const provenance_logical = try joinLogical(allocator, operation_logical, switch (backend) {
            .legacy_dpkg => provenance_name,
            .native => native_provenance_name,
        });
        errdefer allocator.free(provenance_logical);
        const manifest_logical = try joinLogical(allocator, operation_logical, manifest_name);
        errdefer allocator.free(manifest_logical);
        const operation_state_logical = try joinLogical(
            allocator,
            operation_logical,
            operation_state_name,
        );
        errdefer allocator.free(operation_state_logical);
        const cache_physical = try rootPath(allocator, request.root, cache_logical);
        errdefer allocator.free(cache_physical);
        const state_physical = try rootPath(allocator, request.root, state_logical);
        errdefer allocator.free(state_physical);
        const repository_physical = try rootPath(
            allocator,
            request.root,
            repository_logical,
        );
        errdefer allocator.free(repository_physical);
        const operation_physical = try rootPath(allocator, request.root, operation_logical);
        return .{
            .allocator = allocator,
            .operation_id = operation_id,
            .cache_logical = cache_logical,
            .state_logical = state_logical,
            .repository_logical = repository_logical,
            .operations_logical = operations_logical,
            .operation_logical = operation_logical,
            .exact_plan_logical = exact_plan_logical,
            .exact_lock_logical = exact_lock_logical,
            .provenance_logical = provenance_logical,
            .manifest_logical = manifest_logical,
            .operation_state_logical = operation_state_logical,
            .cache_physical = cache_physical,
            .state_physical = state_physical,
            .repository_physical = repository_physical,
            .operation_physical = operation_physical,
        };
    }

    fn logicalEvidence(self: ResolvedPaths) api.EvidencePaths {
        return .{ .operation_state = self.operation_state_logical };
    }

    fn deinit(self: *ResolvedPaths) void {
        inline for (.{
            self.cache_logical,
            self.state_logical,
            self.repository_logical,
            self.operations_logical,
            self.operation_logical,
            self.exact_plan_logical,
            self.exact_lock_logical,
            self.provenance_logical,
            self.manifest_logical,
            self.operation_state_logical,
            self.cache_physical,
            self.state_physical,
            self.repository_physical,
            self.operation_physical,
        }) |value| self.allocator.free(value);
        self.* = undefined;
    }
};

fn requestOperationId(request: api.Request, backend: transaction_engine.Kind) [64]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(switch (backend) {
        .legacy_dpkg => "debz-repository-add-operation-v1\x00",
        .native => "debz-native-repository-add-operation-v1\x00",
    });
    hash.update(request.descriptor_url);
    hash.update("\x00");
    if (request.expected_sha256) |digest| {
        hash.update("\x01");
        hash.update(&digest);
    } else {
        hash.update("\x00");
    }
    hash.update(if (request.no_refresh) "\x01" else "\x00");
    var result: [64]u8 = undefined;
    const digest = hash.finalResult();
    formatHex(&result, &digest);
    return result;
}

fn operationRequestDigest(
    allocator: std.mem.Allocator,
    request: api.Request,
    plan: solver.Plan,
    backend: transaction_engine.Kind,
) ![32]u8 {
    const plan_json = try plan.canonicalJson(allocator);
    defer allocator.free(plan_json);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(switch (backend) {
        .legacy_dpkg => "debz-repository-add-executable-request-v1\x00",
        .native => "debz-native-repository-add-executable-request-v1\x00",
    });
    hashExecutableRequestFields(&hash, request);
    hashField(&hash, plan_json);
    return hash.finalResult();
}

fn hashExecutableRequestFields(hash: *std.crypto.hash.sha2.Sha256, request: api.Request) void {
    hashField(hash, request.root);
    hashField(hash, request.descriptor_url);
    if (request.expected_sha256) |digest| {
        hash.update("\x01");
        hash.update(&digest);
    } else hash.update("\x00");
    hash.update(if (request.no_refresh) "\x01" else "\x00");
    hashOptionalField(hash, request.architecture);
    hashOptionalField(hash, request.cache.path);
    hashInt(hash, request.cache.maximum_object_bytes);
    hashOptionalField(hash, request.state.path);
    hashInt(hash, request.state.lock_wait_ms);
    hashInt(hash, request.state.maximum_operation_state_bytes);
    hashOptionalField(hash, request.network.proxy_url);
    inline for (.{
        request.network.connect_timeout_ms,
        request.network.read_timeout_ms,
        request.network.overall_timeout_ms,
        request.network.redirect_limit,
        request.network.retry_attempts,
        request.network.retry_backoff_ms,
        request.network.maximum_descriptor_bytes,
        request.network.maximum_package_bytes,
        request.network.maximum_release_bytes,
        request.network.maximum_compressed_index_bytes,
        request.network.maximum_decompressed_index_bytes,
        request.network.maximum_decoder_memory,
        request.resources.maximum_repositories,
        request.resources.maximum_actions,
        request.resources.maximum_total_metadata_bytes,
        request.resources.maximum_total_package_bytes,
        request.resources.maximum_retained_package_bytes,
        request.resources.maximum_cache_growth_bytes,
    }) |value| hashInt(hash, value);
}

fn validateLockRequest(
    allocator: std.mem.Allocator,
    lock: exact_lock_v2.Lock,
    request: api.Request,
    plan: solver.Plan,
    backend: transaction_engine.Kind,
) !void {
    const expected = try operationRequestDigest(allocator, request, plan, backend);
    if (!std.mem.eql(u8, &expected, &lock.request_sha256))
        return error.RequestEvidenceMismatch;
}

fn hashField(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    var size: [8]u8 = undefined;
    std.mem.writeInt(u64, &size, @intCast(value.len), .little);
    hash.update(&size);
    hash.update(value);
}

fn hashOptionalField(
    hash: *std.crypto.hash.sha2.Sha256,
    value: ?[]const u8,
) void {
    if (value) |bytes| {
        hash.update("\x01");
        hashField(hash, bytes);
    } else hash.update("\x00");
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    var number: [16]u8 = @splat(0);
    std.mem.writeInt(u128, &number, @intCast(value), .little);
    hash.update(&number);
}

const OperationBudget = struct {
    allocator: std.mem.Allocator,
    clock: repository_acquisition.Clock,
    policy: api.ResourcePolicy,
    started_ms: u64,
    overall_timeout_ms: u64,
    deadline_ms: u64,
    descriptor_bytes: u64 = 0,
    metadata_bytes: u64 = 0,
    cache_growth_bytes: u64 = 0,
    metadata_reserved_bytes: u64 = 0,
    cache_reserved_bytes: u64 = 0,
    native_input: ?NativeRecoveryRequest = null,

    fn init(
        clock: repository_acquisition.Clock,
        policy: api.ResourcePolicy,
        overall_timeout_ms: u64,
        allocator: std.mem.Allocator,
    ) OperationBudget {
        const started_ms = clock.nowMs();
        return .{
            .allocator = allocator,
            .clock = clock,
            .policy = policy,
            .started_ms = started_ms,
            .overall_timeout_ms = overall_timeout_ms,
            .deadline_ms = started_ms +| overall_timeout_ms,
        };
    }

    fn checkTime(self: OperationBudget) !void {
        if (self.native_input) |input| try input.validate();
        const now = self.clock.nowMs();
        if (now >= self.deadline_ms or now -| self.started_ms >= self.overall_timeout_ms)
            return error.ResourceBudgetExceeded;
    }

    fn executionDeadline(self: OperationBudget) transaction_executor.Deadline {
        return .{
            .context = self.clock.context,
            .nowMsFn = self.clock.nowMsFn,
            .expires_at_ms = self.deadline_ms,
        };
    }

    fn retainDeadline(self: *OperationBudget, deadline: transaction_executor.Deadline) void {
        self.deadline_ms = @min(self.deadline_ms, deadline.expires_at_ms);
    }

    fn remainingTime(self: OperationBudget) !u64 {
        try self.checkTime();
        const now = self.clock.nowMs();
        const spent = now -| self.started_ms;
        if (now >= self.deadline_ms or spent >= self.overall_timeout_ms) return error.ResourceBudgetExceeded;
        return @min(self.overall_timeout_ms - spent, self.deadline_ms - now);
    }

    fn descriptorLimit(self: OperationBudget, requested: usize) !usize {
        try self.checkTime();
        const bounded = @min(
            @as(u64, requested),
            @min(
                self.policy.maximum_total_package_bytes,
                @min(
                    self.policy.maximum_retained_package_bytes,
                    self.policy.maximum_cache_growth_bytes,
                ),
            ),
        );
        if (bounded == 0) return error.ResourceBudgetExceeded;
        return std.math.cast(usize, bounded) orelse error.ResourceBudgetExceeded;
    }

    fn chargeDescriptor(
        self: *OperationBudget,
        provenance: local_artifact.Provenance,
    ) !void {
        self.descriptor_bytes = provenance.size;
        if (self.descriptor_bytes > self.policy.maximum_total_package_bytes or
            self.descriptor_bytes > self.policy.maximum_retained_package_bytes)
            return error.ResourceBudgetExceeded;
        try charge(
            &self.cache_growth_bytes,
            provenance.cache_growth_bytes,
            self.policy.maximum_cache_growth_bytes,
        );
        try self.checkTime();
    }

    fn validatePlan(self: OperationBudget, plan: solver.Plan) !void {
        if (plan.actions.len > self.policy.maximum_actions)
            return error.ResourceBudgetExceeded;
        try self.checkTime();
    }

    fn validateLock(self: OperationBudget, lock: exact_lock_v2.Lock) !void {
        if (lock.repositories.len > self.policy.maximum_repositories or
            lock.packages.len > self.policy.maximum_actions)
            return error.ResourceBudgetExceeded;
        var total: u64 = 0;
        var largest_dependency: u64 = 0;
        for (lock.packages) |package| {
            total = std.math.add(u64, total, package.declared_size) catch
                return error.ResourceBudgetExceeded;
            switch (package.origin) {
                .local_artifact => {},
                .authenticated_repository => largest_dependency =
                    @max(largest_dependency, package.declared_size),
            }
        }
        if (total > self.policy.maximum_total_package_bytes)
            return error.ResourceBudgetExceeded;
        const retained = std.math.add(
            u64,
            self.descriptor_bytes,
            largest_dependency,
        ) catch return error.ResourceBudgetExceeded;
        if (retained > self.policy.maximum_retained_package_bytes)
            return error.ResourceBudgetExceeded;
        try self.checkTime();
    }

    fn packageLimit(self: OperationBudget, requested: usize) !usize {
        try self.checkTime();
        const retained_remaining = self.policy.maximum_retained_package_bytes -|
            self.descriptor_bytes;
        const bounded = @min(
            @as(u64, requested),
            @min(self.policy.maximum_total_package_bytes, retained_remaining),
        );
        if (bounded == 0) return error.ResourceBudgetExceeded;
        return std.math.cast(usize, bounded) orelse error.ResourceBudgetExceeded;
    }

    fn reserveCacheGrowth(
        self: *OperationBudget,
        desired_size: u64,
        existing_size: ?u64,
    ) !void {
        const growth = desired_size -| (existing_size orelse 0);
        try charge(
            &self.cache_growth_bytes,
            growth,
            self.policy.maximum_cache_growth_bytes,
        );
    }

    fn boundedTime(
        self: OperationBudget,
        network: api.NetworkPolicy,
    ) !api.NetworkPolicy {
        var bounded = network;
        bounded.overall_timeout_ms = @min(network.overall_timeout_ms, try self.remainingTime());
        bounded.connect_timeout_ms = @min(
            network.connect_timeout_ms,
            bounded.overall_timeout_ms,
        );
        bounded.read_timeout_ms = @min(
            network.read_timeout_ms,
            bounded.overall_timeout_ms,
        );
        return bounded;
    }

    fn acquisitionDeadlines(
        self: OperationBudget,
        network: api.NetworkPolicy,
    ) repository_acquisition.Deadlines {
        return deadlines(network, self.deadline_ms);
    }

    fn boundedNetwork(
        self: OperationBudget,
        network: api.NetworkPolicy,
        repository_count: usize,
    ) !api.NetworkPolicy {
        if (repository_count == 0 or
            repository_count > self.policy.maximum_repositories)
            return error.ResourceBudgetExceeded;
        const remaining_metadata = self.policy.maximum_total_metadata_bytes -|
            self.metadata_bytes;
        const remaining_cache = self.policy.maximum_cache_growth_bytes -|
            self.cache_growth_bytes;
        const available = @min(remaining_metadata, remaining_cache);
        const share = available / repository_count;
        if (share < 2) return error.ResourceBudgetExceeded;
        const release_share = @max(@as(u64, 1), share / 8);
        const index_share = share - release_share;
        var bounded = try self.boundedTime(network);
        bounded.maximum_release_bytes = @min(
            network.maximum_release_bytes,
            std.math.cast(usize, release_share) orelse network.maximum_release_bytes,
        );
        bounded.maximum_compressed_index_bytes = @min(
            network.maximum_compressed_index_bytes,
            std.math.cast(usize, index_share) orelse
                network.maximum_compressed_index_bytes,
        );
        bounded.maximum_decompressed_index_bytes = @min(
            network.maximum_decompressed_index_bytes,
            std.math.cast(usize, index_share) orelse
                network.maximum_decompressed_index_bytes,
        );
        if (bounded.maximum_release_bytes == 0 or
            bounded.maximum_compressed_index_bytes == 0 or
            bounded.maximum_decompressed_index_bytes == 0)
            return error.ResourceBudgetExceeded;
        return bounded;
    }

    fn chargeMetadata(
        self: *OperationBudget,
        result: *const repository_policy.RefreshResult,
    ) !void {
        _ = result;
        try self.checkTime();
    }

    fn retainedReservation(self: *OperationBudget) metadata_cache.Reservation {
        return .{
            .context = self,
            .reserveFn = reserveRetained,
            .finishFn = finishRetained,
        };
    }

    fn cacheReservation(self: *OperationBudget) metadata_cache.Reservation {
        return .{
            .context = self,
            .reserveFn = reserveCache,
            .finishFn = finishCache,
        };
    }

    fn publicationHooks(self: *OperationBudget) metadata_cache.Hooks {
        return .{ .context = self, .runFn = validateNativePublication };
    }

    fn validateNativePublication(raw: ?*anyopaque, _: metadata_cache.HookPoint) !void {
        const self: *OperationBudget = @ptrCast(@alignCast(raw.?));
        if (self.native_input != null) try self.checkTime();
    }

    const ReservationToken = struct {
        allocator: std.mem.Allocator,
        requested: u64,
    };

    fn reserveRetained(context: *anyopaque, bytes: u64) !*anyopaque {
        const self: *OperationBudget = @ptrCast(@alignCast(context));
        try self.reserve(
            self.metadata_bytes,
            &self.metadata_reserved_bytes,
            bytes,
            self.policy.maximum_total_metadata_bytes,
        );
        return self.newToken(bytes) catch |err| {
            self.metadata_reserved_bytes -= bytes;
            return err;
        };
    }

    fn finishRetained(context: *anyopaque, reservation: *anyopaque, committed: u64) void {
        const self: *OperationBudget = @ptrCast(@alignCast(context));
        const token: *ReservationToken = @ptrCast(@alignCast(reservation));
        self.metadata_reserved_bytes -= token.requested;
        self.metadata_bytes += @min(committed, token.requested);
        token.allocator.destroy(token);
    }

    fn reserveCache(context: *anyopaque, bytes: u64) !*anyopaque {
        const self: *OperationBudget = @ptrCast(@alignCast(context));
        try self.reserve(
            self.cache_growth_bytes,
            &self.cache_reserved_bytes,
            bytes,
            self.policy.maximum_cache_growth_bytes,
        );
        return self.newToken(bytes) catch |err| {
            self.cache_reserved_bytes -= bytes;
            return err;
        };
    }

    fn finishCache(context: *anyopaque, reservation: *anyopaque, committed: u64) void {
        const self: *OperationBudget = @ptrCast(@alignCast(context));
        const token: *ReservationToken = @ptrCast(@alignCast(reservation));
        self.cache_reserved_bytes -= token.requested;
        self.cache_growth_bytes += @min(committed, token.requested);
        token.allocator.destroy(token);
    }

    fn reserve(
        self: *OperationBudget,
        committed: u64,
        reserved: *u64,
        bytes: u64,
        limit: u64,
    ) !void {
        try self.checkTime();
        const used = std.math.add(u64, committed, reserved.*) catch
            return error.ResourceBudgetExceeded;
        const total = std.math.add(u64, used, bytes) catch
            return error.ResourceBudgetExceeded;
        if (total > limit) return error.ResourceBudgetExceeded;
        reserved.* = std.math.add(u64, reserved.*, bytes) catch
            return error.ResourceBudgetExceeded;
    }

    fn newToken(self: *OperationBudget, bytes: u64) !*ReservationToken {
        const token = try self.allocator.create(ReservationToken);
        token.* = .{ .allocator = self.allocator, .requested = bytes };
        return token;
    }

    fn charge(counter: *u64, amount: u64, limit: u64) !void {
        const total = std.math.add(u64, counter.*, amount) catch
            return error.ResourceBudgetExceeded;
        if (total > limit) return error.ResourceBudgetExceeded;
        counter.* = total;
    }
};

fn repositoryLimits(resources: api.ResourcePolicy) repository_policy.Limits {
    return .{
        .source = .{ .max_sources = resources.maximum_repositories },
        .max_documents = resources.maximum_repositories,
        .max_repositories = resources.maximum_repositories,
    };
}

fn targetLimits(resources: api.ResourcePolicy) target_apt_config.Limits {
    return .{
        .source = .{ .max_sources = resources.maximum_repositories },
        .repository = repositoryLimits(resources),
        .max_sources = resources.maximum_repositories,
    };
}

const MaterialFile = struct {
    logical_path: []u8,
    bytes: []const u8,
    sha256: [32]u8,
    kind: enum { source, keyring },
};

const DescriptorMaterial = struct {
    allocator: std.mem.Allocator,
    configuration: repository_policy.Configuration,
    files: []MaterialFile,
    evidence: []state_module.FileEvidence,

    fn deinit(self: *DescriptorMaterial) void {
        self.configuration.deinit();
        for (self.files) |file| self.allocator.free(file.logical_path);
        self.allocator.free(self.files);
        self.allocator.free(self.evidence);
        self.* = undefined;
    }

    fn find(self: DescriptorMaterial, path: []const u8) ?MaterialFile {
        for (self.files) |file| {
            if (std.mem.eql(u8, file.logical_path, path)) return file;
        }
        return null;
    }
};

fn inspectDescriptorMaterial(
    allocator: std.mem.Allocator,
    validation: *const deb_payload.Validation,
    architecture: []const u8,
    network: api.NetworkPolicy,
    resources: api.ResourcePolicy,
) !DescriptorMaterial {
    var source_files: std.ArrayList(MaterialFile) = .empty;
    defer {
        for (source_files.items) |file| {
            if (file.logical_path.len != 0) allocator.free(file.logical_path);
        }
        source_files.deinit(allocator);
    }
    for (validation.data.entries) |entry| {
        if (entry.kind != .regular or
            (!std.mem.endsWith(u8, entry.path, ".list") and
                !std.mem.endsWith(u8, entry.path, ".sources")))
            continue;
        if (!std.mem.startsWith(u8, entry.path, "etc/apt/sources.list.d/"))
            return error.DynamicRepositoryMaterial;
        if (source_files.items.len == resources.maximum_repositories)
            return error.ResourceBudgetExceeded;
        const logical_path = try std.fmt.allocPrint(allocator, "/{s}", .{entry.path});
        errdefer allocator.free(logical_path);
        const bytes = try validation.regularPayloadBytes(
            entry.path,
            1024 * 1024,
        );
        try source_files.append(allocator, .{
            .logical_path = logical_path,
            .bytes = bytes,
            .sha256 = sha256(bytes),
            .kind = .source,
        });
    }
    if (source_files.items.len == 0) return error.DynamicRepositoryMaterial;
    std.mem.sort(MaterialFile, source_files.items, {}, lessMaterialFile);

    const documents = try allocator.alloc(
        repository_policy.SourceDocument,
        source_files.items.len,
    );
    defer allocator.free(documents);
    for (source_files.items, 0..) |file, index| {
        documents[index] = .{
            .bytes = file.bytes,
            .format = if (std.mem.endsWith(u8, file.logical_path, ".sources"))
                .deb822
            else
                .legacy,
            .policy = .{
                .proxy = if (network.proxy_url != null)
                    .{ .declared = .{ .id = "repository-api-proxy" } }
                else
                    .direct,
                .deadlines = deadlines(network, null),
            },
        };
    }
    const normalized = try repository_policy.normalizeBinaryRefresh(
        allocator,
        documents,
        architecture,
        repositoryLimits(resources),
    );
    var configuration = switch (normalized) {
        .diagnostic => return error.MalformedRepositorySource,
        .configuration => |value| value,
    };
    errdefer configuration.deinit();
    if (configuration.repositories.len == 0) return error.DynamicRepositoryMaterial;

    var files: std.ArrayList(MaterialFile) = .empty;
    errdefer {
        for (files.items) |file| allocator.free(file.logical_path);
        files.deinit(allocator);
    }
    for (source_files.items) |*file| {
        try files.append(allocator, file.*);
        file.logical_path = &.{};
    }
    var seen_keyrings = std.StringHashMap(void).init(allocator);
    defer seen_keyrings.deinit();
    for (configuration.repositories) |repository| {
        if (repository.signed_by.len == 0) return error.UnsignedRepository;
        for (repository.signed_by) |logical_path| {
            if (seen_keyrings.contains(logical_path)) continue;
            if (!validLogicalPath(logical_path)) return error.MissingPayloadKeyring;
            const archive_path = logical_path[1..];
            const bytes = validation.regularPayloadBytes(
                archive_path,
                16 * 1024 * 1024,
            ) catch return error.MissingPayloadKeyring;
            var inspected = openpgp.inspectKeyring(allocator, bytes, .{}) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return error.MalformedPayloadKeyring,
            };
            defer inspected.deinit(allocator);
            if (inspected.primary_fingerprints.len == 0)
                return error.MalformedPayloadKeyring;
            try seen_keyrings.put(logical_path, {});
            try files.append(allocator, .{
                .logical_path = try allocator.dupe(u8, logical_path),
                .bytes = bytes,
                .sha256 = sha256(bytes),
                .kind = .keyring,
            });
        }
    }
    std.mem.sort(MaterialFile, files.items, {}, lessMaterialFile);
    const owned_files = try files.toOwnedSlice(allocator);
    errdefer {
        for (owned_files) |file| allocator.free(file.logical_path);
        allocator.free(owned_files);
    }
    const evidence = try allocator.alloc(state_module.FileEvidence, owned_files.len);
    for (owned_files, 0..) |file, index| evidence[index] = .{
        .logical_path = file.logical_path,
        .sha256 = file.sha256,
        .size = file.bytes.len,
    };
    return .{
        .allocator = allocator,
        .configuration = configuration,
        .files = owned_files,
        .evidence = evidence,
    };
}

fn refreshDescriptor(
    allocator: std.mem.Allocator,
    material: *const DescriptorMaterial,
    configuration: *const repository_policy.Configuration,
    cache: *metadata_cache.Cache,
    acquisition: repository_acquisition.Dependencies,
    network: api.NetworkPolicy,
    budget: *OperationBudget,
    now: i64,
) !repository_policy.RefreshOutcome {
    const bounded_network = try budget.boundedNetwork(
        network,
        configuration.repositories.len,
    );
    const runtimes = try allocator.alloc(
        repository_policy.Runtime,
        configuration.repositories.len,
    );
    defer allocator.free(runtimes);
    var keyring_sets: std.ArrayList([]openpgp.Keyring) = .empty;
    defer {
        for (keyring_sets.items) |set| allocator.free(set);
        keyring_sets.deinit(allocator);
    }
    for (configuration.repositories, 0..) |repository, index| {
        const keyrings = try allocator.alloc(openpgp.Keyring, repository.signed_by.len);
        errdefer allocator.free(keyrings);
        for (repository.signed_by, 0..) |path, key_index| {
            const file = material.find(path) orelse return error.MissingPayloadKeyring;
            keyrings[key_index] = .{ .bytes = file.bytes };
        }
        try keyring_sets.append(allocator, keyrings);
        runtimes[index] = runtimeForRepository(
            repository,
            keyrings,
            bounded_network,
            budget,
            now,
        );
    }
    var fixed_now = now;
    return repository_policy.refreshAll(allocator, .{
        .configuration = configuration,
        .runtimes = runtimes,
        .mode = .online,
        .failure_policy = .all_or_nothing,
        .aggregate_publish = .{
            .reservation = budget.cacheReservation(),
            .hooks = budget.publicationHooks(),
        },
        .retained_reservation = budget.retainedReservation(),
        .dependencies = .{
            .acquisition = acquisition,
            .cache = cache,
            .clock = .{ .context = &fixed_now, .nowUnixFn = fixedNow },
            .io = cache.io,
        },
    });
}

fn changedDescriptorConfiguration(
    allocator: std.mem.Allocator,
    material: *const DescriptorMaterial,
    snapshot: target_apt_config.Snapshot,
    architecture: []const u8,
    network: api.NetworkPolicy,
    resources: api.ResourcePolicy,
) !?repository_policy.Configuration {
    var changed_documents: std.ArrayList(repository_policy.SourceDocument) = .empty;
    defer changed_documents.deinit(allocator);
    for (material.files) |file| {
        if (file.kind != .source) continue;
        const document: repository_policy.SourceDocument = .{
            .bytes = file.bytes,
            .format = if (std.mem.endsWith(u8, file.logical_path, ".sources"))
                .deb822
            else
                .legacy,
            .policy = .{
                .proxy = if (network.proxy_url != null)
                    .{ .declared = .{ .id = "repository-api-proxy" } }
                else
                    .direct,
                .deadlines = deadlines(network, null),
            },
        };
        const normalized = try repository_policy.normalizeBinaryRefresh(
            allocator,
            &.{document},
            architecture,
            repositoryLimits(resources),
        );
        var configuration = switch (normalized) {
            .diagnostic => return error.MalformedRepositorySource,
            .configuration => |value| value,
        };
        defer configuration.deinit();
        if (configuration.repositories.len == 0) continue;

        var changed = !snapshotContainsEvidence(snapshot, .{
            .logical_path = file.logical_path,
            .sha256 = file.sha256,
            .size = file.bytes.len,
        });
        if (!changed) {
            for (configuration.repositories) |repository| {
                for (repository.signed_by) |keyring_path| {
                    const keyring = material.find(keyring_path) orelse
                        return error.MissingPayloadKeyring;
                    if (!snapshotContainsEvidence(snapshot, .{
                        .logical_path = keyring.logical_path,
                        .sha256 = keyring.sha256,
                        .size = keyring.bytes.len,
                    })) {
                        changed = true;
                        break;
                    }
                }
                if (changed) break;
            }
        }
        if (changed) try changed_documents.append(allocator, document);
    }
    if (changed_documents.items.len == 0) return null;
    const normalized = try repository_policy.normalizeBinaryRefresh(
        allocator,
        changed_documents.items,
        architecture,
        repositoryLimits(resources),
    );
    return switch (normalized) {
        .diagnostic => error.MalformedRepositorySource,
        .configuration => |configuration| configuration,
    };
}

fn refreshTarget(
    allocator: std.mem.Allocator,
    snapshot: *const target_apt_config.Snapshot,
    cache: *metadata_cache.Cache,
    acquisition: repository_acquisition.Dependencies,
    network: api.NetworkPolicy,
    budget: *OperationBudget,
    now: i64,
) !repository_policy.RefreshOutcome {
    const bounded_network = try budget.boundedNetwork(
        network,
        snapshot.configuration.repositories.len,
    );
    const runtimes = try allocator.alloc(
        repository_policy.Runtime,
        snapshot.configuration.repositories.len,
    );
    defer allocator.free(runtimes);
    const trusts = try allocator.alloc(
        target_apt_config.RuntimeTrust,
        snapshot.configuration.repositories.len,
    );
    var initialized: usize = 0;
    defer {
        for (trusts[0..initialized]) |*trust| trust.deinit();
        allocator.free(trusts);
    }
    for (snapshot.configuration.repositories, 0..) |repository, index| {
        trusts[index] = try snapshot.runtimeTrust(allocator, repository);
        initialized += 1;
        runtimes[index] = runtimeForRepository(
            repository,
            trusts[index].keyrings,
            bounded_network,
            budget,
            now,
        );
        runtimes[index].authentication = trusts[index].authentication(now);
    }
    var fixed_now = now;
    return repository_policy.refreshAll(allocator, .{
        .configuration = &snapshot.configuration,
        .runtimes = runtimes,
        .mode = .online,
        .failure_policy = .allow_stale_authenticated,
        .aggregate_publish = .{
            .reservation = budget.cacheReservation(),
        },
        .retained_reservation = budget.retainedReservation(),
        .dependencies = .{
            .acquisition = acquisition,
            .cache = cache,
            .clock = .{ .context = &fixed_now, .nowUnixFn = fixedNow },
            .io = cache.io,
        },
    });
}

fn runtimeForRepository(
    repository: repository_policy.NormalizedRepository,
    keyrings: []const openpgp.Keyring,
    network: api.NetworkPolicy,
    budget: *OperationBudget,
    now: i64,
) repository_policy.Runtime {
    return .{
        .repository_id = repository.id,
        .declared_proxy = switch (repository.proxy) {
            .direct => null,
            .declared => |reference| reference,
        },
        .declared_keyrings = repository.signed_by,
        .authentication = .{ .in_release = .{
            .keyrings = .{ .many = keyrings },
            .accepted_primary_fingerprints = &.{},
            .verification_time = now,
        } },
        .acquisition = .{
            .proxy = switch (repository.proxy) {
                .direct => .direct,
                .declared => proxyPolicy(network.proxy_url) catch .direct,
            },
            .deadlines = .{
                .connect_ms = @min(
                    network.connect_timeout_ms,
                    repository.deadlines.connect_ms,
                ),
                .read_ms = @min(
                    network.read_timeout_ms,
                    repository.deadlines.read_ms,
                ),
                .overall_ms = @min(
                    network.overall_timeout_ms,
                    repository.deadlines.overall_ms,
                ),
                .absolute_ms = budget.deadline_ms,
            },
            .redirect_limit = network.redirect_limit,
            .retry = retryPolicy(network),
            .maximum_release_bytes = network.maximum_release_bytes,
        },
        .refresh = .{
            .mode = .online,
            .compression_order = &.{ .xz, .gzip, .zstd, .uncompressed },
            .by_hash_fallback = .not_found_only,
            .maximum_future_seconds = 300,
            .expiry_policy = repository.freshness,
            .maximum_compressed_bytes = network.maximum_compressed_index_bytes,
            .maximum_decompressed_bytes = network.maximum_decompressed_index_bytes,
            .maximum_decoder_memory = network.maximum_decoder_memory,
            .cache_publish_options = .{
                .reservation = budget.cacheReservation(),
                .hooks = budget.publicationHooks(),
            },
            .retained_reservation = budget.retainedReservation(),
        },
    };
}

fn loadInstalled(
    allocator: std.mem.Allocator,
    filesystem: target_apt_config.FileSystem,
) !dpkg_status.OwnedDatabase {
    const bytes = filesystem.readFile(
        allocator,
        "/var/lib/dpkg/status",
        64 * 1024 * 1024,
    ) catch |err| switch (err) {
        error.FileNotFound => try allocator.dupe(u8, ""),
        else => return err,
    };
    defer allocator.free(bytes);
    const parsed = try dpkg_status.parseOwned(allocator, bytes, .{});
    return switch (parsed) {
        .diagnostic => error.InvalidInstalledState,
        .database => |value| value,
    };
}

fn findInstalledPackage(
    packages: []const dpkg_status.Package,
    name: []const u8,
) ?dpkg_status.Package {
    for (packages) |package| {
        if (std.mem.eql(u8, package.name.value, name)) return package;
    }
    return null;
}

fn makeInstalledPolicies(
    allocator: std.mem.Allocator,
    packages: []const dpkg_status.Package,
) ![]solver.InstalledPolicy {
    var policies: std.ArrayList(solver.InstalledPolicy) = .empty;
    for (packages) |package| {
        if (!package.status.isFullyInstalled()) continue;
        try policies.append(allocator, .{
            .name = package.name.value,
            .architecture = package.architecture.value,
            .install_reason = .manual,
            .held = package.status.want == .hold,
        });
    }
    return policies.toOwnedSlice(allocator);
}

fn localIndexText(
    allocator: std.mem.Allocator,
    validation: deb_payload.Validation,
    digest: [32]u8,
    size: u64,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;
    try writer.writeAll("Package: ");
    try writer.writeAll(validation.package);
    try writer.writeAll("\nVersion: ");
    try writer.writeAll(validation.version);
    try writer.writeAll("\nArchitecture: ");
    try writer.writeAll(validation.architecture);
    if (validation.relationships.depends) |depends| {
        try writer.writeAll("\nDepends: ");
        try writer.writeAll(depends);
    }
    if (validation.relationships.pre_depends) |pre_depends| {
        try writer.writeAll("\nPre-Depends: ");
        try writer.writeAll(pre_depends);
    }
    try writer.writeAll("\nFilename: descriptor.deb\nSize: ");
    try writer.print("{}", .{size});
    try writer.writeAll("\nSHA256: ");
    try writeHexRaw(writer, &digest);
    try writer.writeByte('\n');
    return output.toOwnedSlice();
}

fn planDescriptor(
    allocator: std.mem.Allocator,
    repositories: []const solver.RepositoryInput,
    installed: []const dpkg_status.Package,
    installed_policies: []const solver.InstalledPolicy,
    architecture: []const u8,
    package: []const u8,
    version: []const u8,
    reinstall: bool,
    resources: api.ResourcePolicy,
) !solver.PlanningResult {
    return solver.planTransaction(allocator, .{
        .repositories = repositories,
        .installed = .{
            .records = installed,
            .native_architecture = architecture,
            .policies = installed_policies,
            .hold_authority = .explicit_policy,
        },
        .target_architecture = architecture,
        .request = if (reinstall) .{ .reinstall = .{
            .name = package,
            .version = version,
        } } else .{ .install = &.{.{
            .name = package,
            .version = version,
        }} },
        .policy = .{
            .recommends = false,
            .allow_downgrade = false,
            .allow_remove_dependencies = false,
            .allow_remove_essential = false,
            .allow_remove_protected = false,
            .allow_change_held = false,
            .allow_replacements = false,
            .strict_repository_priority = true,
            .phased_updates = .disabled,
        },
        .limits = .{
            .import = .{
                .max_repositories = resources.maximum_repositories,
            },
            .max_actions = resources.maximum_actions,
        },
    });
}

fn unchangedDescriptorPlan(allocator: std.mem.Allocator, architecture: []const u8) !solver.Plan {
    // Exact installed identity and material were already checked. This plans
    // no package work; only Runtime.verifyUnchanged can prove that it is safe.
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    return .{
        .schema_version = 3,
        .target_architecture = try arena.allocator().dupe(u8, architecture),
        .mode = .plan_only,
        .actions = &.{},
        .ordered_actions = &.{},
        .summary = .{},
        .download_bytes = 0,
        .installed_size_delta_bytes = 0,
        .backing_allocator = allocator,
        .arena = arena,
    };
}

fn createUnchangedOperationLock(
    allocator: std.mem.Allocator,
    plan: solver.Plan,
    evidence: package_origin.LocalArtifactEvidence,
    installed: dpkg_status.Package,
    request: api.Request,
) !exact_lock_v2.OwnedLock {
    if (plan.actions.len != 0 or plan.ordered_actions.len != 0 or
        !installed.status.isFullyInstalled() or
        !std.mem.eql(u8, installed.name.value, evidence.package) or
        !std.mem.eql(u8, installed.version.spelling.value, evidence.version) or
        !std.mem.eql(u8, installed.architecture.value, evidence.architecture))
        return error.DescriptorIdentityMismatch;
    return exact_lock_v2.create(allocator, .{
        .target_architecture = plan.target_architecture,
        .request_sha256 = try operationRequestDigest(allocator, request, plan, .native),
        .policy_sha256 = repositoryLockPolicyDigest(.native),
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
            .dpkg_selection_hold = installed.status.want == .hold,
        }},
        .verified_origins = true,
    });
}

fn createOperationLock(
    allocator: std.mem.Allocator,
    plan: solver.Plan,
    local_evidence: @import("package_origin.zig").LocalArtifactEvidence,
    refreshed: ?*repository_policy.RefreshResult,
    request: api.Request,
    backend: transaction_engine.Kind,
) !exact_lock_v2.OwnedLock {
    var packages: std.ArrayList(exact_lock_v2.Package) = .empty;
    defer packages.deinit(allocator);
    var repository_ids: std.ArrayList([64]u8) = .empty;
    defer repository_ids.deinit(allocator);
    for (plan.actions) |action| {
        if (action.kind == .remove) continue;
        const origin = action.origin orelse return error.MissingPackageOrigin;
        const digest = try parsePlanDigest(
            action.sha256 orelse return error.MissingPackageDigest,
        );
        const declared_size = action.package_size orelse
            return error.MissingPackageSize;
        switch (origin) {
            .local_artifact => |local| {
                if (!package_origin.eqlLocalArtifact(
                    local.evidence,
                    local_evidence,
                ) or
                    !std.mem.eql(u8, &digest, &local.evidence.sha256) or
                    declared_size != local.evidence.size or
                    local.solver_priority != 1000)
                    return error.LocalArtifactMismatch;
                try packages.append(allocator, .{
                    .name = action.package,
                    .version = action.version,
                    .architecture = action.architecture,
                    .origin = .{ .local_artifact = local.evidence },
                    .sha256 = digest,
                    .declared_size = declared_size,
                    .retention = if (action.requested) .requested else .dependency,
                    .dpkg_selection_hold = false,
                });
            },
            .authenticated_repository => |repository_identity| {
                const published = refreshed orelse return error.MissingRepository;
                const repository = findRepositoryInput(
                    published.universe.repositories,
                    .{ .bytes = repository_identity.id },
                ) orelse return error.MissingRepository;
                if (repository.priority != repository_identity.priority or
                    action.repository == null or
                    !std.mem.eql(
                        u8,
                        &action.repository.?.id,
                        &repository_identity.id,
                    ) or
                    action.repository.?.priority != repository_identity.priority)
                    return error.RepositoryOriginMismatch;
                _ = findPlanRecord(repository, action) orelse
                    return error.MissingRepositoryPackage;
                const snapshot_digest = repository.authenticated_snapshot_sha256 orelse
                    return error.MissingRepository;
                try packages.append(allocator, .{
                    .name = action.package,
                    .version = action.version,
                    .architecture = action.architecture,
                    .origin = .{ .authenticated_repository = .{
                        .repository_id = repository_identity.id,
                        .repository_snapshot_sha256 = snapshot_digest,
                    } },
                    .sha256 = digest,
                    .declared_size = declared_size,
                    .retention = if (action.requested) .requested else .dependency,
                    .dpkg_selection_hold = false,
                });
                if (!containsId(repository_ids.items, repository_identity.id))
                    try repository_ids.append(
                        allocator,
                        repository_identity.id,
                    );
            },
        }
    }
    var repositories: std.ArrayList(exact_lock_v2.Repository) = .empty;
    defer repositories.deinit(allocator);
    var signer_storage: std.ArrayList([][20]u8) = .empty;
    defer {
        for (signer_storage.items) |signers| allocator.free(signers);
        signer_storage.deinit(allocator);
    }
    for (repository_ids.items) |id| {
        const published = refreshed orelse return error.MissingRepository;
        const snapshot = findSnapshot(published.snapshots, id) orelse
            return error.MissingRepository;
        const evidence = snapshot.snapshot.provenance.authentication_evidence;
        const signers = try allocator.alloc([20]u8, evidence.signatures.len);
        var signer_count: usize = 0;
        for (evidence.signatures) |signature| {
            if (signature.primary_fingerprint) |fingerprint| {
                signers[signer_count] = fingerprint;
                signer_count += 1;
            }
        }
        if (signer_count == 0) {
            allocator.free(signers);
            return error.MissingRepositorySigner;
        }
        try signer_storage.append(allocator, signers);
        try repositories.append(allocator, .{
            .id = id,
            .snapshot_sha256 = repository_refresh.snapshotDigest(snapshot),
            .release_sha256 = snapshot.snapshot.provenance.release_digest.bytes,
            .index_sha256 = snapshot.snapshot.provenance.index_digest.bytes,
            .signer_fingerprints = signers[0..signer_count],
        });
    }
    return exact_lock_v2.create(allocator, .{
        .target_architecture = plan.target_architecture,
        .request_sha256 = try operationRequestDigest(allocator, request, plan, backend),
        .policy_sha256 = repositoryLockPolicyDigest(backend),
        .repositories = repositories.items,
        .local_artifacts = &.{local_evidence},
        .packages = packages.items,
        .verified_origins = true,
    });
}

fn acquirePlanArtifacts(
    allocator: std.mem.Allocator,
    request: api.Request,
    cache_path: []const u8,
    cache: *package_acquisition.Cache,
    acquisition: repository_acquisition.Dependencies,
    plan: solver.Plan,
    refreshed: ?*repository_policy.RefreshResult,
    configuration: *const repository_policy.Configuration,
    budget: *OperationBudget,
    artifacts: *std.ArrayList(transaction_executor.Artifact),
) !void {
    try budget.checkTime();
    for (plan.actions) |action| {
        if (action.kind == .remove) continue;
        const origin = action.origin orelse return error.MissingPackageOrigin;
        switch (origin) {
            .local_artifact => |local| {
                var hex: [64]u8 = undefined;
                formatHex(&hex, &local.evidence.sha256);
                try artifacts.append(allocator, .{
                    .package = action.package,
                    .version = action.version,
                    .architecture = action.architecture,
                    .path = try std.fmt.allocPrint(
                        allocator,
                        "{s}/packages-v1/objects/{s}",
                        .{ cache_path, &hex },
                    ),
                });
            },
            .authenticated_repository => |repository_identity| {
                const repository_id: source.RepositoryId = .{
                    .bytes = repository_identity.id,
                };
                const published = refreshed orelse return error.MissingRepository;
                const repository = findRepositoryInput(
                    published.universe.repositories,
                    repository_id,
                ) orelse return error.MissingRepository;
                const normalized = findNormalized(
                    configuration.repositories,
                    repository_id,
                ) orelse return error.MissingRepository;
                const record_index = findPlanRecord(repository, action) orelse
                    return error.MissingRepositoryPackage;
                const record = repository.packages.records[record_index];
                const repository_origin: solver.PackageOrigin = .{
                    .repository_id = repository_id,
                    .repository_priority = repository_identity.priority,
                    .record_index = record_index,
                    .package = action.package,
                    .version = action.version,
                    .architecture = action.architecture,
                    .source_location = record.location.source,
                };
                const selected = try package_acquisition.SelectedPackage.fromSolverSelection(
                    repository,
                    repository_origin,
                    try repository_acquisition.Uri.parse(normalized.uri),
                );
                const digest: metadata_cache.Digest = .{
                    .bytes = selected.record.transport.sha256.bytes,
                };
                const existing_size = try cache.objectSize(digest);
                try budget.reserveCacheGrowth(
                    selected.record.transport.size.value,
                    existing_size,
                );
                const package_network = try budget.boundedTime(request.network);
                const package_limit = try budget.packageLimit(
                    package_network.maximum_package_bytes,
                );
                var package = try package_acquisition.acquirePackage(
                    allocator,
                    cache,
                    .{
                        .selected = selected,
                        .policy = .{
                            .mode = .online,
                            .workflow = .transaction,
                            .maximum_package_bytes = package_limit,
                            .proxy = try proxyPolicy(package_network.proxy_url),
                            .deadlines = budget.acquisitionDeadlines(package_network),
                            .redirect_limit = package_network.redirect_limit,
                            .retry = retryPolicy(package_network),
                        },
                    },
                    acquisition,
                );
                defer package.deinit();
                var payload = deb_payload.validate(allocator, package.bytes, .{
                    .repository = repository_id.slice(),
                    .package = action.package,
                    .version = action.version,
                    .architecture = action.architecture,
                    .requested_package = action.package,
                    .requested_version = action.version,
                    .requested_architecture = action.architecture,
                    .filename = selected.record.transport.filename.value,
                    .size = package.provenance.declared_size,
                    .sha256 = package.provenance.expected_sha256.bytes,
                }, .{});
                switch (payload) {
                    .diagnostic => return error.InvalidPackagePayload,
                    .validation => |*value| value.deinit(),
                }
                const path = try std.fmt.allocPrint(
                    allocator,
                    "{s}/packages-v1/objects/{s}",
                    .{ cache_path, &package.provenance.cache_key },
                );
                errdefer allocator.free(path);
                try artifacts.append(allocator, .{
                    .package = action.package,
                    .version = action.version,
                    .architecture = action.architecture,
                    .path = path,
                });
            },
        }
        try budget.checkTime();
    }
}

fn publishProvenance(
    allocator: std.mem.Allocator,
    io: std.Io,
    operation_dir: std.Io.Dir,
    root: []const u8,
    lock: *const exact_lock_v2.Lock,
    report: transaction_executor.Report,
    refreshed: ?*repository_policy.RefreshResult,
) ![32]u8 {
    return publishBoundProvenance(
        allocator,
        io,
        operation_dir,
        root,
        lock,
        .{ .execution = report },
        refreshed,
    );
}

fn publishRecoveryProvenance(
    allocator: std.mem.Allocator,
    io: std.Io,
    operation_dir: std.Io.Dir,
    root: []const u8,
    lock: *const exact_lock_v2.Lock,
    report: transaction_executor.RecoveryReport,
    refreshed: ?*repository_policy.RefreshResult,
) ![32]u8 {
    return publishBoundProvenance(
        allocator,
        io,
        operation_dir,
        root,
        lock,
        .{ .recovery = report },
        refreshed,
    );
}

const ProvenanceReport = union(enum) {
    execution: transaction_executor.Report,
    recovery: transaction_executor.RecoveryReport,
};

fn publishBoundProvenance(
    allocator: std.mem.Allocator,
    io: std.Io,
    operation_dir: std.Io.Dir,
    root: []const u8,
    lock: *const exact_lock_v2.Lock,
    report: ProvenanceReport,
    refreshed: ?*repository_policy.RefreshResult,
) ![32]u8 {
    _ = refreshed;
    const repositories = try allocator.alloc(
        transaction_provenance_v2.RepositoryEvidence,
        lock.repositories.len,
    );
    defer allocator.free(repositories);
    var signer_storage: std.ArrayList([][20]u8) = .empty;
    defer {
        for (signer_storage.items) |signers| allocator.free(signers);
        signer_storage.deinit(allocator);
    }
    for (lock.repositories, 0..) |repository, index| {
        const signers = try allocator.dupe(
            [20]u8,
            repository.signer_fingerprints,
        );
        if (signers.len == 0) return error.MissingRepositorySigner;
        try signer_storage.append(allocator, signers);
        repositories[index] = .{
            .source_config_id = repository.id,
            .snapshot_sha256 = repository.snapshot_sha256,
            .release_sha256 = repository.release_sha256,
            .signature_sha256 = null,
            .metadata_sha256 = repository.index_sha256,
            .signer_fingerprints = signers,
            .signature_verified = true,
        };
    }
    const packages = try allocator.alloc(
        transaction_provenance_v2.PackageEvidence,
        lock.packages.len,
    );
    defer allocator.free(packages);
    for (lock.packages, 0..) |package, index| packages[index] = .{
        .name = package.name,
        .version = package.version,
        .architecture = package.architecture,
        .origin = package.origin,
        .package_sha256 = package.sha256,
        .cas_sha256 = package.sha256,
        .declared_size = package.declared_size,
    };
    var status_reader = transaction_recovery.SystemStatusFileReader{
        .io = io,
        .expected_root = root,
    };
    const status_bytes = try status_reader.interface().read(
        allocator,
        root,
        64 * 1024 * 1024,
    );
    defer allocator.free(status_bytes);
    const status_digest = sha256(status_bytes);
    const input: transaction_provenance_v2.ExecutionInput = .{
        .exact_lock = lock,
        .target_architecture = lock.target_architecture,
        .request_sha256 = lock.request_sha256,
        .solver_policy_sha256 = lock.policy_sha256,
        .repositories = repositories,
        .packages = packages,
        .journal_steps = &.{},
        .final_verification = .{
            .status = .exact_match,
            .installed_state_sha256 = status_digest,
            .package_origins_sha256 = lock.digest_sha256,
            .detail = "repository locked package identities and origin evidence verified",
        },
    };
    var provenance = switch (report) {
        .execution => |value| try transaction_provenance_v2.createFromExecution(
            allocator,
            input,
            value,
        ),
        .recovery => |value| try transaction_provenance_v2.createFromRecovery(
            allocator,
            input,
            value,
        ),
    };
    defer provenance.deinit();
    const store = try transaction_provenance_v2.Store.init(
        io,
        operation_dir,
        provenance_name,
    );
    try store.writeAtomic(allocator, provenance.result);
    return provenance.result.digest_sha256;
}

fn verifyInstalledDescriptor(
    allocator: std.mem.Allocator,
    filesystem: target_apt_config.FileSystem,
    descriptor: api.DescriptorIdentity,
    files: []const state_module.FileEvidence,
) !void {
    if (!try descriptorIdentityInstalled(allocator, filesystem, descriptor))
        return error.DescriptorIdentityMismatch;
    try verifyManagedFiles(allocator, filesystem, files);
}

fn descriptorIdentityInstalled(
    allocator: std.mem.Allocator,
    filesystem: target_apt_config.FileSystem,
    descriptor: api.DescriptorIdentity,
) !bool {
    var installed = try loadInstalled(allocator, filesystem);
    defer installed.deinit();
    const package = findInstalledPackage(
        installed.database.packages,
        descriptor.package,
    ) orelse return false;
    return package.status.isFullyInstalled() and
        std.mem.eql(u8, package.version.spelling.value, descriptor.version) and
        std.mem.eql(u8, package.architecture.value, descriptor.architecture);
}

fn verifyManagedFiles(
    allocator: std.mem.Allocator,
    filesystem: target_apt_config.FileSystem,
    files: []const state_module.FileEvidence,
) !void {
    for (files) |expected| {
        const maximum = std.math.cast(usize, expected.size) orelse
            return error.ManagedFileTooLarge;
        const bytes = filesystem.readFile(
            allocator,
            expected.logical_path,
            maximum,
        ) catch |err| switch (err) {
            error.FileNotFound => return error.ManagedFileMissing,
            error.Symlink => return error.ManagedFileSymlink,
            error.NotRegular => return error.ManagedFileNotRegular,
            error.UnsafePath => return error.ManagedFileUnsafe,
            else => return err,
        };
        defer allocator.free(bytes);
        if (bytes.len != expected.size or
            !std.mem.eql(u8, &sha256(bytes), &expected.sha256))
            return error.ManagedFileMismatch;
    }
}

fn validateRecoveryEvidence(
    allocator: std.mem.Allocator,
    io: std.Io,
    operation_dir: std.Io.Dir,
    descriptor: api.DescriptorIdentity,
) !void {
    const lock_store = try exact_lock_v2.Store.init(
        io,
        operation_dir,
        exact_lock_name,
    );
    var lock = try lock_store.read(
        allocator,
        exact_lock_v2.maximum_document_bytes,
    );
    defer lock.deinit();
    try validateLockDescriptor(lock.lock, descriptor);

    var file = try operation_dir.openFile(io, provenance_name, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    const source_bytes = try reader.interface.allocRemaining(
        allocator,
        .limited(transaction_provenance_v2.maximum_document_bytes),
    );
    defer allocator.free(source_bytes);
    var document = try transaction_provenance_v2.validateDocument(
        allocator,
        source_bytes,
        transaction_provenance_v2.maximum_document_bytes,
    );
    defer document.deinit();
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        document.bytes,
        .{ .allocate = .alloc_always },
    );
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |value| value,
        else => return error.InvalidProvenance,
    };
    var lock_digest: [64]u8 = undefined;
    formatHex(&lock_digest, &lock.lock.digest_sha256);
    try expectJsonString(object, "target_architecture", lock.lock.target_architecture);
    try expectJsonString(object, "lock_sha256", &lock_digest);
    try expectJsonString(object, "outcome", "succeeded");
    const verification_value = object.get("final_verification") orelse
        return error.InvalidProvenance;
    const verification = switch (verification_value) {
        .object => |value| value,
        else => return error.InvalidProvenance,
    };
    try expectJsonString(verification, "status", "exact_match");
    try expectJsonString(
        verification,
        "package_origins_sha256",
        &lock_digest,
    );
}

fn validateLockDescriptor(
    lock: exact_lock_v2.Lock,
    descriptor: api.DescriptorIdentity,
) !void {
    const locked = lock.findPackage(
        descriptor.package,
        descriptor.version,
        descriptor.architecture,
    ) orelse return error.DescriptorMissingFromLock;
    if (!std.mem.eql(u8, &locked.sha256, &descriptor.sha256) or
        locked.declared_size != descriptor.size)
        return error.DescriptorLockMismatch;
    switch (locked.origin) {
        .authenticated_repository => return error.DescriptorLockMismatch,
        .local_artifact => |local| {
            const expected_trust: package_origin.LocalArtifactTrustMode =
                switch (descriptor.trust_mode) {
                    .verified_https => .verified_https,
                    .pinned_sha256 => .pinned_sha256,
                };
            const expected_artifact_id =
                package_origin.artifactIdFromSha256(descriptor.sha256);
            if (!std.mem.eql(u8, &local.artifact_id, &expected_artifact_id) or
                !std.mem.eql(u8, &local.sha256, &descriptor.sha256) or
                local.size != descriptor.size or
                !std.mem.eql(u8, local.package, descriptor.package) or
                !std.mem.eql(u8, local.version, descriptor.version) or
                !std.mem.eql(u8, local.architecture, descriptor.architecture) or
                !std.mem.eql(u8, local.acquisition_url, descriptor.effective_url) or
                local.trust_mode != expected_trust)
                return error.DescriptorLockMismatch;
        },
    }
}

fn validateLockPolicy(lock: exact_lock_v2.Lock, backend: transaction_engine.Kind) !void {
    const expected = repositoryLockPolicyDigest(backend);
    if (!std.mem.eql(u8, &lock.policy_sha256, &expected))
        return error.LockPolicyMismatch;
}

fn repositoryLockPolicyDigest(backend: transaction_engine.Kind) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(switch (backend) {
        .legacy_dpkg => "debz-repository-add-solver-policy-v1\x00",
        .native => "debz-native-repository-add-solver-policy-v1\x00",
    });
    hash.update("no-recommends\x00no-downgrade\x00strict-priority\x00");
    hash.update("exact-lock-verification:locked-packages\x00");
    return hash.finalResult();
}

fn expectJsonString(
    object: std.json.ObjectMap,
    field: []const u8,
    expected: []const u8,
) !void {
    const value = object.get(field) orelse return error.InvalidProvenance;
    if (value != .string or !std.mem.eql(u8, value.string, expected))
        return error.InvalidProvenance;
}

fn verifyImportedMaterial(
    snapshot: target_apt_config.Snapshot,
    files: []const state_module.FileEvidence,
) !void {
    if (!snapshotContainsManagedMaterial(snapshot, files))
        return error.ImportedDigestMismatch;
}

fn snapshotContainsManagedMaterial(
    snapshot: target_apt_config.Snapshot,
    files: []const state_module.FileEvidence,
) bool {
    for (files) |expected|
        if (!snapshotContainsEvidence(snapshot, expected)) return false;
    return true;
}

fn snapshotContainsEvidence(
    snapshot: target_apt_config.Snapshot,
    expected: state_module.FileEvidence,
) bool {
    for (snapshot.manifest.manifest.sources) |record| {
        if (std.mem.eql(u8, record.logical_path, expected.logical_path))
            return std.mem.eql(u8, &record.sha256, &expected.sha256);
    }
    for (snapshot.manifest.manifest.keyrings) |record| {
        if (std.mem.eql(u8, record.logical_path, expected.logical_path))
            return std.mem.eql(u8, &record.sha256, &expected.sha256);
    }
    return false;
}

fn findRepositoryInput(
    repositories: []const solver.RepositoryInput,
    id: source.RepositoryId,
) ?solver.RepositoryInput {
    for (repositories) |repository| {
        if (std.mem.eql(u8, repository.repository_id.slice(), id.slice()))
            return repository;
    }
    return null;
}

fn findPlanRecord(
    repository: solver.RepositoryInput,
    action: solver.PlanAction,
) ?usize {
    const expected_digest = action.sha256 orelse return null;
    const expected_size = action.package_size orelse return null;
    for (repository.packages.records, 0..) |record, index| {
        var digest_hex: [64]u8 = undefined;
        formatHex(&digest_hex, &record.transport.sha256.bytes);
        if (std.mem.eql(u8, record.control.package.text, action.package) and
            std.mem.eql(u8, record.control.version.value.original, action.version) and
            std.mem.eql(u8, record.control.architecture.text, action.architecture) and
            std.mem.eql(u8, &digest_hex, &expected_digest) and
            record.transport.size.value == expected_size)
            return index;
    }
    return null;
}

fn parsePlanDigest(hex: [64]u8) ![32]u8 {
    var output: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&output, &hex);
    return output;
}

fn planHasAuthenticatedPackages(plan: solver.Plan) bool {
    for (plan.actions) |action| {
        if (action.origin) |origin| switch (origin) {
            .authenticated_repository => return true,
            .local_artifact => {},
        };
    }
    return false;
}

fn validateLockSnapshots(
    lock: exact_lock_v2.Lock,
    refreshed: *const repository_policy.RefreshResult,
) !void {
    for (lock.repositories) |repository| {
        const snapshot = findSnapshot(refreshed.snapshots, repository.id) orelse
            return error.RepositorySnapshotMissing;
        if (!std.mem.eql(
            u8,
            &repository.snapshot_sha256,
            &repository_refresh.snapshotDigest(snapshot),
        ) or
            !std.mem.eql(
                u8,
                &repository.release_sha256,
                &snapshot.snapshot.provenance.release_digest.bytes,
            ) or
            !std.mem.eql(
                u8,
                &repository.index_sha256,
                &snapshot.snapshot.provenance.index_digest.bytes,
            ))
            return error.RepositorySnapshotMismatch;
        const signatures =
            snapshot.snapshot.provenance.authentication_evidence.signatures;
        for (repository.signer_fingerprints) |expected| {
            var found = false;
            for (signatures) |signature| {
                const fingerprint = signature.primary_fingerprint orelse continue;
                if (std.mem.eql(u8, &fingerprint, &expected)) {
                    found = true;
                    break;
                }
            }
            if (!found) return error.RepositorySignerMismatch;
        }
    }
}

const JournalState = enum {
    none,
    completed,
    incomplete,
};

fn inspectTransactionJournal(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_path: []const u8,
    root: []const u8,
) !JournalState {
    var journal = try transaction_recovery.SystemJournalStore.init(
        io,
        state_path,
        root,
    );
    defer journal.deinit();
    const bytes = try journal.interface().load(allocator, root) orelse
        return .none;
    defer allocator.free(bytes);
    var decoded = try transaction_recovery.decode(allocator, bytes);
    defer decoded.deinit();
    return if (decoded.journal.state == .complete)
        .completed
    else
        .incomplete;
}

const JournalClassification = enum {
    none,
    matching_current,
    mismatched_incomplete,
    unrelated_completed,
};

fn classifyTransactionJournal(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_path: []const u8,
    root: []const u8,
    plan: solver.Plan,
    policy: transaction_executor.Policy,
    lock: exact_lock_v2.Lock,
) !JournalClassification {
    var journal_store = try transaction_recovery.SystemJournalStore.init(
        io,
        state_path,
        root,
    );
    defer journal_store.deinit();
    const bytes = try journal_store.interface().load(allocator, root) orelse
        return .none;
    defer allocator.free(bytes);
    var decoded = try transaction_recovery.decode(allocator, bytes);
    defer decoded.deinit();
    const journal = decoded.journal;
    const plan_sha256 = transaction_executor.planDigest(plan);
    const root_identity = transaction_recovery.rootIdentity(root);
    const policy_sha256 = transaction_executor.policyDigest(policy);
    const matches =
        std.mem.eql(u8, &journal.plan_sha256, &plan_sha256) and
        std.mem.eql(u8, &journal.root_identity, &root_identity) and
        std.mem.eql(u8, &journal.policy_sha256, &policy_sha256) and
        journal.lock_sha256 != null and
        std.mem.eql(u8, &journal.lock_sha256.?, &lock.digest_sha256);
    if (matches) return .matching_current;
    return if (journal.state == .complete)
        .unrelated_completed
    else
        .mismatched_incomplete;
}

fn findNormalized(
    repositories: []const repository_policy.NormalizedRepository,
    id: source.RepositoryId,
) ?repository_policy.NormalizedRepository {
    for (repositories) |repository| {
        if (std.mem.eql(u8, repository.id.slice(), id.slice()))
            return repository;
    }
    return null;
}

fn findSnapshot(
    snapshots: []const repository_refresh.AuthenticatedResult,
    id: [64]u8,
) ?*const repository_refresh.AuthenticatedResult {
    for (snapshots) |*snapshot| {
        if (std.mem.eql(
            u8,
            snapshot.snapshot.provenance.repository_id.slice(),
            &id,
        )) return snapshot;
    }
    return null;
}

fn containsId(ids: []const [64]u8, wanted: [64]u8) bool {
    for (ids) |id| if (std.mem.eql(u8, &id, &wanted)) return true;
    return false;
}

fn proxyPolicy(value: ?[]const u8) !repository_acquisition.ProxyPolicy {
    const text = value orelse return .direct;
    const uri = try repository_acquisition.Uri.parse(text);
    if (uri.user != null or uri.password != null)
        return error.CredentialBearingProxy;
    const endpoint: repository_acquisition.ProxyEndpoint = .{ .uri = uri };
    return .{ .http = endpoint, .https = endpoint };
}

fn deadlines(
    network: api.NetworkPolicy,
    absolute_ms: ?u64,
) repository_acquisition.Deadlines {
    return .{
        .connect_ms = network.connect_timeout_ms,
        .read_ms = network.read_timeout_ms,
        .overall_ms = network.overall_timeout_ms,
        .absolute_ms = absolute_ms,
    };
}

fn retryPolicy(network: api.NetworkPolicy) repository_acquisition.RetryPolicy {
    return .{
        .max_attempts = network.retry_attempts,
        .linear_backoff_base_ms = network.retry_backoff_ms,
    };
}

fn repositoryExecutionPolicy(request: api.Request) transaction_executor.Policy {
    return .{
        .conffile = .keep_existing,
        .locks = .{ .wait_ms = request.state.lock_wait_ms },
        .risk = .{ .allow_host_root = std.mem.eql(u8, request.root, "/") },
        .process_timeout_ms = request.network.overall_timeout_ms,
        .exact_lock_verification = .locked_packages,
    };
}

fn fixedNow(context: ?*anyopaque) i64 {
    return @as(*const i64, @ptrCast(@alignCast(context.?))).*;
}

fn realNow(io: std.Io) i64 {
    const instant = std.Io.Clock.real.now(io);
    return @intCast(@divFloor(instant.nanoseconds, std.time.ns_per_s));
}

fn phaseAtLeast(observed: state_module.Phase, expected: state_module.Phase) bool {
    return phaseOrder(observed) >= phaseOrder(expected);
}

fn phaseOrder(phase: state_module.Phase) u8 {
    return switch (phase) {
        .initialized => 0,
        .acquired => 1,
        .validated => 2,
        .preflight_authenticated => 3,
        .planned => 4,
        .locked => 5,
        .installed => 6,
        .imported => 7,
        .refreshed => 8,
        .complete => 9,
        .failed => 10,
    };
}

fn sha256(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn formatHex(output: *[64]u8, digest: *const [32]u8) void {
    const alphabet = "0123456789abcdef";
    for (digest, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 15];
    }
}

fn writeHexRaw(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
}

fn lessMaterialFile(_: void, left: MaterialFile, right: MaterialFile) bool {
    return std.mem.order(u8, left.logical_path, right.logical_path) == .lt;
}

fn validLogicalPath(path: []const u8) bool {
    return absolute_path.nonRoot(path);
}

fn rootPath(
    allocator: std.mem.Allocator,
    root: []const u8,
    logical: []const u8,
) ![]u8 {
    if (std.mem.eql(u8, root, "/")) return allocator.dupe(u8, logical);
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ root, logical });
}

fn joinLogical(
    allocator: std.mem.Allocator,
    parent: []const u8,
    leaf: []const u8,
) ![]u8 {
    if (parent.len == 1)
        return std.fmt.allocPrint(allocator, "/{s}", .{leaf});
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ parent, leaf });
}

fn openOrCreateAbsoluteDirectory(io: std.Io, path: []const u8) !std.Io.Dir {
    if (!absolute_path.root(path)) return error.InvalidAbsolutePath;
    var current = try std.Io.Dir.openDirAbsolute(io, "/", .{
        .iterate = true,
        .follow_symlinks = false,
    });
    errdefer current.close(io);
    if (std.mem.eql(u8, path, "/")) return current;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return error.InvalidAbsolutePath;
        current.createDir(io, component, .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const next = try current.openDir(io, component, .{
            .iterate = true,
            .follow_symlinks = false,
        });
        current.close(io);
        current = next;
    }
    return current;
}

fn dependencyFailureNeedsRefresh(failure: solver.PlanFailure) bool {
    for (failure.problems) |problem| switch (problem.kind) {
        .unsatisfied_dependency, .no_candidate => return true,
        else => {},
    };
    return false;
}

const BindingFixture = struct {
    const request: api.Request = .{
        .root = "/srv/roots/repository",
        .descriptor_url = "https://packages.example.test/descriptor.deb",
        .expected_sha256 = @splat(0x33),
        .architecture = "amd64",
        .cache = .{ .path = "/cache" },
        .state = .{ .path = "/state" },
        .network = .{ .proxy_url = "https://proxy.example.test" },
    };
    const artifact: package_origin.LocalArtifactEvidence = .{
        .artifact_id = @splat('3'),
        .sha256 = @splat(0x33),
        .size = 42,
        .package = "repo-config",
        .version = "1.0",
        .architecture = "all",
        .acquisition_url = request.descriptor_url,
        .trust_mode = .pinned_sha256,
    };

    actions: [1]solver.PlanAction,
    ordered_actions: [2]solver.OrderedAction,

    fn init(evidence: package_origin.LocalArtifactEvidence) BindingFixture {
        return .{
            .actions = .{.{
                .kind = .install,
                .package = evidence.package,
                .version = evidence.version,
                .architecture = evidence.architecture,
                .repository = null,
                .sha256 = evidence.artifact_id,
                .package_size = evidence.size,
                .installed_size_delta_bytes = 0,
                .source_package = evidence.package,
                .prior_installed = null,
                .requested = true,
                .reason = .explicit_request,
                .selected_origin = null,
                .origin = .{ .local_artifact = .{
                    .evidence = evidence,
                    .solver_priority = 1000,
                } },
            }},
            .ordered_actions = .{
                .{ .sequence = 0, .kind = .unpack, .package = evidence.package, .version = evidence.version, .architecture = evidence.architecture },
                .{ .sequence = 1, .kind = .configure_pending, .package = evidence.package, .version = evidence.version, .architecture = evidence.architecture },
            },
        };
    }

    fn plan(self: *BindingFixture) solver.Plan {
        return .{
            .schema_version = 3,
            .target_architecture = "amd64",
            .mode = .plan_only,
            .actions = &self.actions,
            .ordered_actions = &self.ordered_actions,
            .summary = .{ .installs = 1, .download_bytes = self.actions[0].package_size.? },
            .download_bytes = self.actions[0].package_size.?,
            .installed_size_delta_bytes = 0,
            .backing_allocator = std.testing.allocator,
            .arena = undefined,
        };
    }
};

test "repository backend native invocation preserves the outer clock and remaining budget" {
    const Clock = struct {
        value: u64,
        fn now(raw: ?*anyopaque) u64 {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            return self.value;
        }
        fn sleep(raw: ?*anyopaque, milliseconds: u64) !void {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            self.value += milliseconds;
        }
    };
    var outer: Clock = .{ .value = 100 };
    var acquisition: Clock = .{ .value = 9_000 };
    const deadline: transaction_executor.Deadline = .{
        .context = &outer,
        .nowMsFn = Clock.now,
        .expires_at_ms = 125,
    };
    var clock: NativeInvocationClock = .{
        .deadline = deadline,
        .original = .{ .context = &acquisition, .nowMsFn = Clock.now, .sleepMsFn = Clock.sleep },
    };
    var budget = OperationBudget.init(clock.interface(), .{}, 500, std.testing.allocator);
    budget.retainDeadline(deadline);
    try std.testing.expectEqual(@as(u64, 25), try budget.remainingTime());
    try std.testing.expectEqual(@as(u64, 25), try budget.executionDeadline().remainingMs());
    try clock.interface().sleepMs(1_000);
    try std.testing.expectEqual(@as(u64, 9_025), acquisition.value);
    outer.value = 125;
    try std.testing.expectError(error.ResourceBudgetExceeded, budget.remainingTime());
    try std.testing.expectError(error.DeadlineExceeded, clock.interface().sleepMs(1));
    try std.testing.expectEqual(@as(u64, 9_025), acquisition.value);
}

test "repository backend native caller binds every executable request policy field" {
    const request = BindingFixture.request;
    const original = repositoryRequestDigest(request, .native);
    inline for (.{ "cache", "state", "network", "resources" }) |group| {
        inline for (std.meta.fields(@TypeOf(@field(request, group)))) |field| {
            var changed = request;
            const value = &@field(@field(changed, group), field.name);
            switch (@typeInfo(field.type)) {
                .int => value.* += 1,
                .optional => value.* = if (std.mem.eql(u8, field.name, "proxy_url"))
                    "https://different.example.test"
                else
                    "/different",
                else => @compileError("add coverage for the new repository policy field"),
            }
            try std.testing.expect(!std.mem.eql(u8, &original, &repositoryRequestDigest(changed, .native)));
        }
    }
}

const NativePreparationCase = enum {
    prepared,
    discovered_architecture,
    changed_foreign_architecture,
    duplicate_foreign_architecture,
    unchanged,
    unchanged_active_intent,
    unchanged_sticky_program,
    invalid_request,
    legacy_caller,
    different_surface,
    changed_request,
    wrong_architecture,
    legacy_lock,
    changed_plan,
    sticky_plan,
    sticky_lock,
    sticky_program,
    missing_archive,
    active_intent,
    not_mutable,
    lost_lock,
    retained_limit,
    total_limit,
    aggregate_retained_limit,
    package_limit,
    cache_limit,
    action_limit,
    archive_count,
};

const native_preparation_held_status = "Package: held\nStatus: hold ok installed\nArchitecture: amd64\nVersion: 3.0\n\n";

fn stageNativePreparationDatabase(root: root_fs.Root, status: []const u8) !void {
    try root.publishFile(try root_fs.Path.init("var/lib/dpkg/status"), status, .{});
    try root.dir.createDirPath(root.io, "var/lib/dpkg/info");
    try root.dir.createDirPath(root.io, "var/lib/dpkg/triggers");
    try root.dir.createDirPath(root.io, "var/lib/dpkg/updates");
    const package_database = @import("package_database.zig");
    try root.publishFile(
        try root_fs.Path.init("var/lib/dpkg/info/" ++ package_database.info_format_name),
        package_database.supported_info_format ++ "\n",
        .{},
    );
    try root.publishFile(
        try root_fs.Path.init("var/lib/dpkg/info/held.list"),
        "/.\n/usr\n/usr/share\n/usr/share/held\n",
        .{},
    );
    try root.dir.createDirPath(root.io, "usr/share");
    try root.publishFile(try root_fs.Path.init("usr/share/held"), "untouched\n", .{});
}

fn testNativePreparation(case: NativePreparationCase) !void {
    const allocator = std.testing.allocator;
    const discovered_architecture = case == .discovered_architecture or
        case == .changed_foreign_architecture or case == .duplicate_foreign_architecture;
    const empty = case == .unchanged or case == .unchanged_active_intent or
        case == .unchanged_sticky_program;
    const bytes = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var model = switch (archive_application.prepare(allocator, bytes, .{ .local = .{} }, .{})) {
        .model => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer model.deinit();
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
    defer root_dir.close(std.testing.io);
    const root = root_fs.Root.init(std.testing.io, root_dir);
    const status = if (discovered_architecture)
        native_architecture_status ++ native_preparation_held_status
    else
        native_preparation_held_status;
    try stageNativePreparationDatabase(root, status);
    if (discovered_architecture) {
        try root.publishFile(try root_fs.Path.init("var/lib/dpkg/arch"), "amd64\ni386\narm64\n", .{});
        try root.publishFile(try root_fs.Path.init("var/lib/dpkg/info/dpkg.list"), "/.\n", .{});
    }
    const root_path = try repositoryTestRoot(allocator, directory.dir);
    defer allocator.free(root_path);
    var request: api.Request = .{
        .root = root_path,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(bytes),
        .architecture = "amd64",
    };
    request.resources.maximum_retained_package_bytes = bytes.len;
    if (discovered_architecture) request.architecture = null;
    switch (case) {
        .retained_limit => request.resources.maximum_retained_package_bytes -= 1,
        .total_limit => request.resources.maximum_total_package_bytes = bytes.len - 1,
        .package_limit => request.network.maximum_package_bytes = bytes.len - 1,
        .cache_limit => request.cache.maximum_object_bytes = bytes.len - 1,
        .action_limit => request.resources.maximum_actions = 1,
        .archive_count => {
            request.resources.maximum_actions = 1;
            request.resources.maximum_retained_package_bytes = 2 * bytes.len;
        },
        else => {},
    }
    const artifact: package_origin.LocalArtifactEvidence = .{
        .artifact_id = package_origin.artifactIdFromSha256(sha256(bytes)),
        .sha256 = sha256(bytes),
        .size = bytes.len,
        .package = model.facts.package,
        .version = model.facts.version,
        .architecture = model.facts.architecture,
        .acquisition_url = request.descriptor_url,
        .trust_mode = .pinned_sha256,
    };
    var fixture = BindingFixture.init(artifact);
    var plan = fixture.plan();
    if (empty) {
        plan.actions = &.{};
        plan.ordered_actions = &.{};
        plan.summary = .{};
        plan.download_bytes = 0;
    }
    var lock = if (empty)
        try exact_lock_v2.create(allocator, .{
            .target_architecture = plan.target_architecture,
            .request_sha256 = try operationRequestDigest(allocator, request, plan, .native),
            .policy_sha256 = repositoryLockPolicyDigest(.native),
            .repositories = &.{},
            .local_artifacts = &.{},
            .packages = &.{},
            .verified_origins = true,
        })
    else
        try createOperationLock(
            allocator,
            plan,
            artifact,
            null,
            request,
            if (case == .legacy_lock) .legacy_dpkg else .native,
        );
    defer lock.deinit();
    var extra_actions = [_]solver.PlanAction{ fixture.actions[0], fixture.actions[0] };
    var guard: RootOperationGuard = .{ .io = std.testing.io, .allocator = allocator };
    defer guard.deinit();
    var locks: root_operation.SystemLockBackend = .{ .allocator = allocator, .io = std.testing.io };
    var lost_locks: root_operation.TestLockBackend = .{ .allocator = allocator };
    defer lost_locks.deinit();
    var coordinator = try root_operation.Coordinator.open(
        std.testing.io,
        root,
        root_path,
        if (case == .lost_lock) lost_locks.interface() else locks.interface(),
    );
    const wrong_digest: [32]u8 = @splat(0x11);
    var attempt = if (discovered_architecture) blk: {
        try std.testing.expect(guard.open(request, .native, 1_700_000_000) == null);
        const reserved = guard.attempt.?;
        guard.attempt = null;
        break :blk reserved;
    } else try coordinator.acquire(allocator, .{
        .backend = if (case == .legacy_caller) .legacy_dpkg else .native,
        .operation = if (case == .different_surface)
            .{ .package_transaction = .install }
        else
            .{ .repository_bootstrap = .add },
        .request_sha256 = repositoryRequestDigest(request, .native),
        .policy_sha256 = repositoryPolicyDigest(request, .native),
        .target_architecture = if (case == .wrong_architecture) "arm64" else "amd64",
        .evidence = .{
            .plan_sha256 = if (case == .sticky_plan) wrong_digest else null,
            .exact_lock = if (case == .sticky_lock) .{
                .schema = exact_lock_v2.schema_id,
                .version = exact_lock_v2.schema_version,
                .digest_sha256 = wrong_digest,
            } else null,
            .program_sha256 = if (case == .sticky_program or case == .unchanged_sticky_program) wrong_digest else null,
        },
    });
    defer attempt.release();
    if (case == .not_mutable)
        try attempt.advance(allocator, .{ .state = .mutation_pending, .phase = .mutation });
    var before = attempt.record().digest_sha256;
    var input: NativePreparationRequest = .{
        .repository = request,
        .attempt = &attempt,
        .plan = &plan,
        .exact_lock = &lock.lock,
        .archives = if (empty or case == .missing_archive)
            &.{}
        else if (case == .aggregate_retained_limit or case == .archive_count)
            &.{ bytes, bytes }
        else
            &.{bytes},
    };
    switch (case) {
        .invalid_request => input.repository.api_version += 1,
        .changed_request => input.repository.resources.maximum_actions += 1,
        .changed_plan => fixture.actions[0].requested = false,
        .action_limit => plan.actions = &extra_actions,
        .changed_foreign_architecture => try root.publishFile(
            try root_fs.Path.init("var/lib/dpkg/arch"),
            "amd64\narm64\n",
            .{},
        ),
        .duplicate_foreign_architecture => try root.publishFile(
            try root_fs.Path.init("var/lib/dpkg/arch"),
            "amd64\ni386\narm64\ni386\n",
            .{},
        ),
        .active_intent, .unchanged_active_intent => try root.publishFile(
            try root_fs.Path.init(@import("native_recovery.zig").intent_path),
            "incomplete native evidence",
            .{},
        ),
        .lost_lock => lost_locks.loseAll(),
        else => {},
    }
    const expected_error: ?anyerror = switch (case) {
        .invalid_request => error.InvalidRepositoryRequest,
        .legacy_caller => error.OperationBackendMismatch,
        .different_surface, .changed_request => error.RepositoryCallerMismatch,
        .wrong_architecture => error.OperationArchitectureMismatch,
        .changed_foreign_architecture => error.OperationArchitectureMismatch,
        .duplicate_foreign_architecture => error.InvalidNativeDatabase,
        .legacy_lock => error.LockPolicyMismatch,
        .changed_plan => error.RequestEvidenceMismatch,
        .sticky_plan => error.PlanEvidenceMismatch,
        .sticky_lock => error.LockEvidenceMismatch,
        .sticky_program, .unchanged_sticky_program => error.OperationEvidenceMismatch,
        .active_intent, .unchanged_active_intent => error.RecoveryRequired,
        .not_mutable => error.OperationNotMutable,
        .lost_lock => error.LockLost,
        .retained_limit,
        .total_limit,
        .aggregate_retained_limit,
        .package_limit,
        .cache_limit,
        .action_limit,
        .archive_count,
        => error.ResourceBudgetExceeded,
        else => null,
    };
    switch (case) {
        .prepared, .invalid_request, .legacy_caller, .different_surface, .changed_request, .wrong_architecture, .lost_lock => {
            var clock: RepositoryExecutionClock = .{ .root = root };
            const receipt_input: NativeReceiptRequest = .{
                .repository = input.repository,
                .attempt = &attempt,
                .expected_receipt_sha256 = @splat('0'),
                .deadline = clock.deadline(),
            };
            inline for (.{ retainNativeReceipt, readRetainedNativeReceipt, verifyNativePackageState }) |function|
                try std.testing.expectError(expected_error orelse error.NativeReceiptMissing, function(allocator, receipt_input));
            try std.testing.expectError(expected_error orelse error.FileNotFound, persistNativePackageState(allocator, receipt_input));
            try std.testing.expect(try root.entryIfExists(try root_fs.Path.init("var/lib/debz/repository")) == null);
        },
        else => {},
    }
    if (expected_error) |expected| {
        try std.testing.expectError(expected, prepareNative(allocator, input));
    } else {
        var result = try prepareNative(allocator, input);
        defer result.deinit();
        switch (case) {
            .unchanged => try std.testing.expect(result == .unchanged),
            .missing_archive => {
                try std.testing.expect(result == .diagnostic);
                try std.testing.expectEqual(.missing_archive, result.diagnostic.diagnostic.code);
            },
            .prepared, .discovered_architecture => {
                try std.testing.expect(result == .prepared);
                const authorization = result.prepared.authorization.authorization;
                const held = authorization.findFinalPackage("held", "amd64").?;
                try std.testing.expectEqualStrings("3.0", held.version);
                try std.testing.expect(held.dpkg_selection_hold);
                try std.testing.expect(authorization.findAction("held", "amd64") == null);
                try std.testing.expectEqual(@as(usize, 1), result.prepared.program.program.artifacts.len);
                try std.testing.expectEqualStrings(
                    &std.fmt.bytesToHex(transaction_executor.policyDigest(repositoryExecutionPolicy(request)), .lower),
                    &result.prepared.program.program.executor_policy_sha256,
                );
                try std.testing.expectEqual(before, attempt.record().digest_sha256);
                if (case == .discovered_architecture) {
                    try std.testing.expectEqualDeep(native_architecture_foreign, authorization.foreign_architectures);
                    try std.testing.expectEqualDeep(native_architecture_foreign, attempt.record().foreign_architectures);
                }
                try native_operation.bind(allocator, root, &attempt, result.prepared.program.program);
                before = attempt.record().digest_sha256;
                var repeated = try prepareNative(allocator, input);
                defer repeated.deinit();
                try std.testing.expect(repeated == .prepared);
                try std.testing.expectEqualStrings(
                    &result.prepared.program.program.digest_sha256,
                    &repeated.prepared.program.program.digest_sha256,
                );
            },
            else => return error.TestUnexpectedResult,
        }
    }
    var observed = (try root_operation.Store.init(root).read(allocator)).?;
    defer observed.deinit();
    try std.testing.expectEqual(before, observed.record.digest_sha256);
    try std.testing.expectEqual(case != .lost_lock, attempt.locked());
    const observed_status = try root.readFileAlloc(allocator, try root_fs.Path.init("var/lib/dpkg/status"), 4096);
    defer allocator.free(observed_status);
    try std.testing.expectEqualStrings(status, observed_status);
    const retained = try root.readFileAlloc(allocator, try root_fs.Path.init("usr/share/held"), 4096);
    defer allocator.free(retained);
    try std.testing.expectEqualStrings("untouched\n", retained);
    try std.testing.expect((try root.entryIfExists(try root_fs.Path.init(@import("native_recovery.zig").intent_path)) != null) ==
        (case == .active_intent or case == .unchanged_active_intent));
}

test "repository backend prepares genuine native inputs without mutating caller or installed packages" {
    try testNativePreparation(.prepared);
    try testNativePreparation(.unchanged);
    try testNativePreparation(.missing_archive);
}

test "repository backend native preparation preserves discovered multiarch callers" {
    try testNativePreparation(.discovered_architecture);
    try testNativePreparation(.changed_foreign_architecture);
    try testNativePreparation(.duplicate_foreign_architecture);
}

const NativeReceiptTestCrash = struct {
    point: root_fs.PublishPoint,

    fn hit(raw: *anyopaque, point: root_fs.PublishPoint) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (point == self.point) return error.InjectedNativeReceiptPublicationFailure;
    }

    fn observer(self: *@This()) root_fs.PublishObserver {
        return .{ .context = self, .hitFn = hit };
    }
};

test "repository backend native receipt storage converges at every durable publication boundary" {
    const allocator = std.testing.allocator;
    const bytes = try native_provenance.testDocument().canonicalJson(allocator);
    defer allocator.free(bytes);
    const path = try root_fs.Path.init("repository/operations/caller/" ++ native_provenance_name);
    for (std.enums.values(root_fs.PublishPoint)) |point| {
        var directory = std.testing.tmpDir(.{ .iterate = true });
        defer directory.cleanup();
        const root = root_fs.Root.init(std.testing.io, directory.dir);
        var crash: NativeReceiptTestCrash = .{ .point = point };
        try std.testing.expectError(
            error.InjectedNativeReceiptPublicationFailure,
            retainNativeReceiptBytes(allocator, root, path, bytes, crash.observer()),
        );
        const before = try root.entryIfExists(path);
        try std.testing.expectEqual(switch (point) {
            .before_stage_sync, .after_stage_sync, .before_rename => false,
            .after_rename, .before_directory_sync, .after_directory_sync => true,
        }, before != null);
        try retainNativeReceiptBytes(allocator, root, path, bytes, null);
        const published = try root.entry(path);
        if (before) |entry| try std.testing.expectEqual(entry.inode, published.inode);
        try retainNativeReceiptBytes(allocator, root, path, bytes, null);
        try std.testing.expectEqual(published.inode, (try root.entry(path)).inode);
        try std.testing.expectEqual(@as(u32, 0o600), (try root.metadata(path)).permissions.toMode() & 0o7777);
        try verifyNativeReceiptBytes(allocator, root, path, bytes, false);
        try std.testing.checkAllAllocationFailures(allocator, verifyNativeReceiptBytes, .{ root, path, bytes, false });
        try std.testing.expectError(error.NativeReceiptMismatch, retainNativeReceiptBytes(allocator, root, path, "different receipt", null));
        try verifyNativeReceiptBytes(allocator, root, path, bytes, false);
        try root.removeFile(path);
        try std.testing.expectError(error.NativeReceiptMissing, verifyNativeReceiptBytes(allocator, root, path, bytes, false));
        try std.testing.expect(try root.entryIfExists(path) == null);
    }
}

test "repository backend native receipt storage refuses leaf and ancestor symlinks" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    const root = root_fs.Root.init(std.testing.io, directory.dir);
    const path = try root_fs.Path.init("receipt.json");
    try root.publishFile(try root_fs.Path.init("untouched"), "untouched", .{});
    try root.createSymbolicLink(path, "untouched");
    try std.testing.expectError(error.NotRegularFile, retainNativeReceiptBytes(std.testing.allocator, root, path, "receipt", null));
    try root.createDirectory(try root_fs.Path.init("actual"), .fromMode(0o700));
    try root.createSymbolicLink(try root_fs.Path.init("parent"), "actual");
    try std.testing.expectError(
        error.SymbolicLinkComponent,
        retainNativeReceiptBytes(std.testing.allocator, root, try root_fs.Path.init("parent/receipt.json"), "receipt", null),
    );
    const bytes = try root.readFileAlloc(std.testing.allocator, try root_fs.Path.init("untouched"), 128);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("untouched", bytes);
    try std.testing.expect(try root.entryIfExists(try root_fs.Path.init("actual/receipt.json")) == null);
}

test "repository backend native package checkpoints preserve installed failure and later diagnostics" {
    const allocator = std.testing.allocator;
    const prior: state_module.State = .{
        .root = "/target",
        .architecture = "amd64",
        .no_refresh = false,
        .phase = .locked,
        .descriptor = .{
            .package = "descriptor",
            .version = "1",
            .architecture = "all",
            .sha256 = @splat(1),
            .size = 1,
            .effective_url = "file:///descriptor.deb",
            .trust_mode = .pinned_sha256,
        },
        .managed_files = &.{.{ .logical_path = "/etc/repository.list", .sha256 = @splat(2), .size = 1 }},
        .plan_path = "/state/transaction-plan-v3.json",
        .plan_sha256 = @splat(3),
        .exact_lock_path = "/state/exact-lock-v2.json",
    };
    const path = "/state/native-transaction-provenance-v1.json";
    const Allocation = struct {
        fn run(backing: std.mem.Allocator, state: state_module.State, failed: bool, receipt_path: []const u8) !void {
            var checkpoint = try nativePackageCheckpointState(backing, state, failed, true, receipt_path);
            defer checkpoint.deinit();
            if (failed) {
                var result = try nativeStateResult(backing, .{
                    .root = state.root,
                    .descriptor_url = state.descriptor.?.effective_url,
                }, checkpoint.state, true);
                defer result.deinit();
                try std.testing.expectEqual(api.ExitStatus.transaction, result.exit_status);
                try std.testing.expect(result.installed and result.changed);
                try std.testing.expectEqual(api.PhaseState.pending, result.imported);
                try std.testing.expectEqual(api.PhaseState.pending, result.refreshed_phase);
            }
        }
    };
    inline for (.{ false, true }) |failed|
        try std.testing.checkAllAllocationFailures(allocator, Allocation.run, .{ prior, failed, path });
    for ([_]bool{ false, true }) |installed| {
        var failed = try nativePackageCheckpointState(allocator, prior, true, installed, path);
        defer failed.deinit();
        try std.testing.expectEqual(state_module.Phase.failed, failed.state.phase);
        try std.testing.expectEqual(installed, failed.state.installed);
        try std.testing.expectEqual(api.DiagnosticId.transaction_failed, failed.state.diagnostic_id.?);
        var repeated = try nativePackageCheckpointState(allocator, failed.state, true, installed, path);
        defer repeated.deinit();
        try std.testing.expectEqual(failed.state.digest_sha256, repeated.state.digest_sha256);
        try std.testing.expectError(error.RepositoryStateMismatch, nativePackageCheckpointState(allocator, failed.state, false, true, path));
    }
    try std.testing.expectError(error.DescriptorIdentityMismatch, nativePackageCheckpointState(allocator, prior, false, false, path));
    var succeeded = try nativePackageCheckpointState(allocator, prior, false, true, path);
    defer succeeded.deinit();
    try std.testing.expectEqual(state_module.Phase.installed, succeeded.state.phase);
    var import_failed = succeeded.state;
    import_failed.diagnostic_id = .target_import_failed;
    import_failed.diagnostic = "import refused";
    var observed = try nativePackageCheckpointState(allocator, import_failed, false, true, path);
    defer observed.deinit();
    try std.testing.expectEqual(api.DiagnosticId.target_import_failed, observed.state.diagnostic_id.?);
    try std.testing.expectEqualStrings("import refused", observed.state.diagnostic);
    try std.testing.expectError(error.RepositoryStateMismatch, nativePackageCheckpointState(allocator, succeeded.state, true, true, path));
}

const ProjectedRepositoryCase = enum { prepare, adopt, after_lock, cleanup };

const RepositoryExecutionCase = enum { success, known_failure, interrupted, missing_helper, unchanged, diagnostic, expired };
const RepositoryReceiptScope = enum { retain, read, verify, checkpoint };
const repository_execution_source_path = "etc/apt/sources.list.d/microsoft-prod.list";

const RepositoryExecutionClock = struct {
    root: root_fs.Root,
    stop_on_intent: bool = false,
    expired: bool = false,
    calls: usize = 0,
    expire_on_call: ?usize = null,
    revoke_on_call: ?usize = null,
    inspection_error: ?anyerror = null,

    fn now(context: ?*anyopaque) u64 {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        if (self.expire_on_call == self.calls) self.expired = true;
        if (self.revoke_on_call == self.calls)
            live_root.testing.replaceMountNamespace() catch |err| {
                self.inspection_error = err;
            };
        if (!self.expired and self.stop_on_intent) {
            const found = self.root.entryIfExists(root_fs.Path.init(root_operation.native_intent_path) catch unreachable) catch |err| blk: {
                self.inspection_error = err;
                break :blk null;
            };
            self.expired = found != null or self.inspection_error != null;
        }
        return @intFromBool(self.expired);
    }

    fn deadline(self: *RepositoryExecutionClock) transaction_executor.Deadline {
        return .{ .context = self, .nowMsFn = now, .expires_at_ms = 1 };
    }
};

fn stageRepositoryNativeLockedInputs(
    root: root_fs.Root,
    request: api.Request,
    plan: solver.Plan,
    lock: exact_lock_v2.Lock,
    artifact: package_origin.LocalArtifactEvidence,
) !void {
    const allocator = std.testing.allocator;
    var paths = try ResolvedPaths.init(allocator, request, .native);
    defer paths.deinit();
    try root.createDirectoryPath(try root_fs.Path.init(paths.operation_logical[1..]), .fromMode(0o700));
    const plan_bytes = try plan.canonicalJson(allocator);
    defer allocator.free(plan_bytes);
    const lock_bytes = try lock.canonicalJson(allocator);
    defer allocator.free(lock_bytes);
    try root.publishFile(try root_fs.Path.init(paths.exact_plan_logical[1..]), plan_bytes, .{ .overwrite = .fail_if_exists });
    try root.publishFile(try root_fs.Path.init(paths.exact_lock_logical[1..]), lock_bytes, .{ .overwrite = .fail_if_exists });
    var state = try state_module.create(allocator, .{
        .root = request.root,
        .architecture = plan.target_architecture,
        .no_refresh = request.no_refresh,
        .phase = .locked,
        .descriptor = .{
            .package = artifact.package,
            .version = artifact.version,
            .architecture = artifact.architecture,
            .sha256 = artifact.sha256,
            .size = artifact.size,
            .effective_url = artifact.acquisition_url,
            .trust_mode = .pinned_sha256,
        },
        .managed_files = &.{
            .{
                .logical_path = "/" ++ repository_execution_source_path,
                .sha256 = sha256(test_repository_source),
                .size = test_repository_source.len,
            },
            .{
                .logical_path = "/usr/share/keyrings/microsoft-prod.gpg",
                .sha256 = sha256(&@import("fixtures/openpgp.zig").keyring),
                .size = @import("fixtures/openpgp.zig").keyring.len,
            },
        },
        .plan_path = paths.exact_plan_logical,
        .plan_sha256 = transaction_executor.planDigest(plan),
        .exact_lock_path = paths.exact_lock_logical,
    });
    defer state.deinit();
    const bytes = try state.state.canonicalJson(allocator);
    defer allocator.free(bytes);
    try root.publishFile(try root_fs.Path.init(paths.operation_state_logical[1..]), bytes, .{ .permissions = .fromMode(0o600) });
    try root.publishFile(try root_fs.Path.init("fixture/repository-original-locked-state.json"), bytes, .{ .overwrite = .fail_if_exists });
}

const NativeCheckpointTestBoundary = struct {
    root: root_fs.Root,
    state_path: root_fs.Path,
    clock: ?*RepositoryExecutionClock = null,

    fn hit(raw: *anyopaque, point: root_fs.PublishPoint) !void {
        if (point != .before_rename) return;
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (self.clock) |clock| {
            clock.expired = true;
        } else {
            try self.root.rename(self.state_path, try root_fs.Path.init("fixture/replaced-checkpoint-state"), .fail_if_exists);
            try self.root.publishFile(self.state_path, "changed during verification", .{ .overwrite = .fail_if_exists });
        }
    }

    fn observer(self: *@This()) root_fs.PublishObserver {
        return .{ .context = self, .hitFn = hit };
    }
};

fn testRepositoryNativeCheckpoint(
    root: root_fs.Root,
    input: NativeReceiptRequest,
    failed: bool,
    first: bool,
) !void {
    const allocator = std.testing.allocator;
    var paths = try ResolvedPaths.init(allocator, input.repository, .native);
    defer paths.deinit();
    const path = try root_fs.Path.init(paths.operation_state_logical[1..]);
    const caller_before = input.attempt.record().digest_sha256;
    if (first) {
        const unbound_receipt = try root_fs.Path.init(paths.provenance_logical[1..]);
        try root.removeFile(unbound_receipt);
        const original = try root.readFileAlloc(allocator, path, state_module.maximum_document_bytes);
        defer allocator.free(original);
        var locked = try state_module.decode(allocator, original, state_module.maximum_document_bytes);
        defer locked.deinit();
        try std.testing.expectEqual(state_module.Phase.locked, locked.state.phase);
        for (0..6) |case| {
            var changed = locked.state;
            switch (case) {
                0 => changed.root = "/different",
                1 => changed.no_refresh = !changed.no_refresh,
                2 => changed.plan_sha256.?[0] ^= 1,
                3 => changed.descriptor.?.version = "different",
                4 => {
                    changed.phase = .installed;
                    changed.installed = true;
                    changed.provenance_path = "/legacy/transaction-result-v2.json";
                },
                5 => {
                    changed.phase = .imported;
                    changed.installed = true;
                    changed.provenance_path = paths.provenance_logical;
                    changed.manifest_path = paths.manifest_logical;
                },
                else => unreachable,
            }
            var owned = try state_module.create(allocator, changed);
            defer owned.deinit();
            const bytes = try owned.state.canonicalJson(allocator);
            defer allocator.free(bytes);
            try root.publishFile(path, bytes, .{ .permissions = .fromMode(0o600) });
            try std.testing.expectError(switch (case) {
                2 => error.PlanEvidenceMismatch,
                3 => error.DescriptorMissingFromLock,
                5 => error.RepositoryPackageStageAlreadyAdvanced,
                else => error.RepositoryStateMismatch,
            }, persistNativePackageState(allocator, input));
            const after = try root.readFileAlloc(allocator, path, state_module.maximum_document_bytes);
            defer allocator.free(after);
            try std.testing.expectEqualSlices(u8, bytes, after);
        }
        try root.publishFile(path, original, .{ .permissions = .fromMode(0o600) });
        const plan_path = try root_fs.Path.init(paths.exact_plan_logical[1..]);
        const original_plan = try root.readFileAlloc(allocator, plan_path, repository_plan.maximum_document_bytes);
        defer allocator.free(original_plan);
        var different_plan = try repository_plan.decode(allocator, original_plan);
        defer different_plan.deinit();
        different_plan.actions[0].requested = !different_plan.actions[0].requested;
        const changed_plan = try different_plan.canonicalJson(allocator);
        defer allocator.free(changed_plan);
        try root.publishFile(plan_path, changed_plan, .{});
        try std.testing.expectError(error.RequestEvidenceMismatch, persistNativePackageState(allocator, input));
        try root.publishFile(plan_path, original_plan, .{});
        const lock_path = try root_fs.Path.init(paths.exact_lock_logical[1..]);
        const original_lock = try root.readFileAlloc(allocator, lock_path, exact_lock_v2.maximum_document_bytes);
        defer allocator.free(original_lock);
        var decoded_lock = try exact_lock_v2.decode(allocator, original_lock, exact_lock_v2.maximum_document_bytes);
        defer decoded_lock.deinit();
        var wrong_request = decoded_lock.lock.request_sha256;
        wrong_request[0] ^= 1;
        var different_lock = try exact_lock_v2.create(allocator, .{
            .target_architecture = decoded_lock.lock.target_architecture,
            .request_sha256 = wrong_request,
            .policy_sha256 = decoded_lock.lock.policy_sha256,
            .repositories = decoded_lock.lock.repositories,
            .local_artifacts = decoded_lock.lock.local_artifacts,
            .packages = decoded_lock.lock.packages,
            .verified_origins = true,
        });
        defer different_lock.deinit();
        const changed_lock = try different_lock.lock.canonicalJson(allocator);
        defer allocator.free(changed_lock);
        try root.publishFile(lock_path, changed_lock, .{});
        try std.testing.expectError(error.LockEvidenceMismatch, persistNativePackageState(allocator, input));
        try root.publishFile(lock_path, original_lock, .{});
        for ([_][]const u8{ paths.operation_state_logical, paths.exact_plan_logical, paths.exact_lock_logical }) |logical| {
            const missing = try root_fs.Path.init(logical[1..]);
            const saved = try root_fs.Path.init("fixture/missing-checkpoint-input");
            try root.rename(missing, saved, .fail_if_exists);
            try std.testing.expectError(error.FileNotFound, persistNativePackageState(allocator, input));
            try std.testing.expect(try root.entryIfExists(missing) == null);
            try root.createSymbolicLink(missing, "/fixture/missing-checkpoint-input");
            try std.testing.expectError(error.NotRegularFile, persistNativePackageState(allocator, input));
            try root.removeFile(missing);
            try root.rename(saved, missing, .fail_if_exists);
        }
        var clock: RepositoryExecutionClock = .{ .root = root };
        var bounded = input;
        bounded.deadline = clock.deadline();
        var expiration: NativeCheckpointTestBoundary = .{ .root = root, .state_path = path, .clock = &clock };
        try std.testing.expectError(error.DeadlineExceeded, persistNativePackageStateObserved(allocator, bounded, expiration.observer()));
        const observed = try root.readFileAlloc(allocator, path, state_module.maximum_document_bytes);
        defer allocator.free(observed);
        try std.testing.expectEqualSlices(u8, original, observed);
        try std.testing.expect(try root.entryIfExists(unbound_receipt) != null);
        var replacement: NativeCheckpointTestBoundary = .{ .root = root, .state_path = path };
        try std.testing.expectError(error.PathChanged, persistNativePackageStateObserved(allocator, input, replacement.observer()));
        const changed = try root.readFileAlloc(allocator, path, 128);
        defer allocator.free(changed);
        try std.testing.expectEqualStrings("changed during verification", changed);
        try root.removeFile(path);
        try root.rename(try root_fs.Path.init("fixture/replaced-checkpoint-state"), path, .fail_if_exists);
        var crash: NativeReceiptTestCrash = .{ .point = .after_rename };
        try std.testing.expectError(
            error.InjectedNativeReceiptPublicationFailure,
            persistNativePackageStateObserved(allocator, input, crash.observer()),
        );
    }
    const before = try root.entry(path);
    var checkpoint = try persistNativePackageState(allocator, input);
    defer checkpoint.deinit();
    try std.testing.expectEqual(before.inode, (try root.entry(path)).inode);
    try std.testing.expectEqual(if (failed) state_module.Phase.failed else .installed, checkpoint.state.state.phase);
    try std.testing.expectEqual(!failed, checkpoint.state.state.installed);
    try std.testing.expectEqual(failed, checkpoint.package_state == .failed);
    try std.testing.expectEqualStrings(paths.provenance_logical, checkpoint.state.state.provenance_path.?);
    try std.testing.expect(!checkpoint.state.state.refreshed and checkpoint.state.state.manifest_path == null);
    if (first) {
        const receipt_path = try root_fs.Path.init(paths.provenance_logical[1..]);
        const saved_receipt = try root_fs.Path.init("fixture/checkpoint-retained-receipt");
        try root.rename(receipt_path, saved_receipt, .fail_if_exists);
        try std.testing.expectError(error.NativeReceiptMissing, persistNativePackageState(allocator, input));
        try std.testing.expect(try root.entryIfExists(receipt_path) == null);
        try root.rename(saved_receipt, receipt_path, .fail_if_exists);
        try std.testing.expectEqual(before.inode, (try root.entry(path)).inode);
    }
    try std.testing.expectEqual(caller_before, input.attempt.record().digest_sha256);
    try std.testing.expect(input.attempt.locked());
    try std.testing.expectEqual(root_operation.Outcome.pending, input.attempt.record().outcome);
}

fn testRepositoryNativePackageState(
    root: root_fs.Root,
    input: NativeReceiptRequest,
    failed: bool,
    exercise_refusals: bool,
) !void {
    const allocator = std.testing.allocator;
    const before = input.attempt.record().digest_sha256;
    {
        var result = try verifyNativePackageState(allocator, input);
        defer result.deinit();
        try std.testing.expect(if (failed) result == .failed else result == .succeeded);
        const retained = switch (result) {
            inline else => |value| value,
        };
        try std.testing.expectEqualSlices(u8, &input.expected_receipt_sha256, &retained.receipt.document.digest_sha256);
    }
    if (exercise_refusals) {
        if (!input.attempt.adopted) {
            var retention_allocations = std.testing.FailingAllocator.init(allocator, .{});
            {
                var retained = try readRetainedNativeReceipt(retention_allocations.allocator(), input);
                defer retained.deinit();
            }
            try std.testing.expectEqual(retention_allocations.allocated_bytes, retention_allocations.freed_bytes);
            var verification_allocations = std.testing.FailingAllocator.init(allocator, .{});
            {
                var result = try verifyNativePackageState(verification_allocations.allocator(), input);
                defer result.deinit();
            }
            try std.testing.expectEqual(verification_allocations.allocated_bytes, verification_allocations.freed_bytes);
            try std.testing.expect(verification_allocations.alloc_index > retention_allocations.alloc_index);
            // Exercise ownership handoffs without repeatedly hashing the helper
            // for every allocation in the underlying evidence decoders.
            for ([_]usize{ 0, retention_allocations.alloc_index, verification_allocations.alloc_index - 1 }) |fail_index| {
                var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
                if (verifyNativePackageState(failing.allocator(), input)) |value| {
                    var result = value;
                    defer result.deinit();
                    return error.TestUnexpectedResult;
                } else |_| {
                    // Canonical writers can report allocation failure as WriteFailed.
                    try std.testing.expect(failing.has_induced_failure);
                }
                try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            }
        }
        if (failed) {
            try std.testing.expectError(
                error.TransactionNotSuccessful,
                native_transaction_result.verifyCallerSuccess(allocator, input.attempt, input.expected_receipt_sha256),
            );
        } else {
            try std.testing.expectError(
                error.TransactionNotFailed,
                native_transaction_result.verifyCallerFailure(allocator, input.attempt, input.expected_receipt_sha256),
            );
        }
        var late: RepositoryExecutionClock = .{ .root = root, .expire_on_call = 4 };
        var bounded = input;
        bounded.deadline = late.deadline();
        try std.testing.expectError(error.DeadlineExceeded, verifyNativePackageState(allocator, bounded));
        try std.testing.expectEqual(@as(usize, 4), late.calls);

        const status_path = try root_fs.Path.init("var/lib/dpkg/status");
        const saved_status = try root_fs.Path.init("fixture/package-state-original-status");
        const status = try root.readFileAlloc(allocator, status_path, 64 * 1024);
        defer allocator.free(status);
        const changed = try std.mem.replaceOwned(u8, allocator, status, "Version: 3.0\n", "Version: 4.0\n");
        defer allocator.free(changed);
        try std.testing.expect(!std.mem.eql(u8, status, changed));
        try root.rename(status_path, saved_status, .fail_if_exists);
        try root.publishFile(status_path, changed, .{ .overwrite = .fail_if_exists });
        {
            var retained = try readRetainedNativeReceipt(allocator, input);
            defer retained.deinit();
        }
        try std.testing.expectError(error.FinalStateMismatch, verifyNativePackageState(allocator, input));
        const unchanged = try root.readFileAlloc(allocator, status_path, 64 * 1024);
        defer allocator.free(unchanged);
        try std.testing.expectEqualStrings(changed, unchanged);
        try root.removeFile(status_path);
        try root.rename(saved_status, status_path, .fail_if_exists);

        const unresolved = try root_fs.Path.init("var/lib/debz/.debz-native-unresolved-package-state");
        try root.publishFile(unresolved, "unresolved", .{ .overwrite = .fail_if_exists });
        try std.testing.expectError(error.UnresolvedNativeEvidence, verifyNativePackageState(allocator, input));
        try std.testing.expect(try root.entryIfExists(unresolved) != null);
        try root.removeFile(unresolved);

        var retained = try readRetainedNativeReceipt(allocator, input);
        defer retained.deinit();
        var inconsistent = retained.receipt.document;
        inconsistent.progress_record_count += 1;
        native_provenance.seal(&inconsistent);
        const inconsistent_bytes = try inconsistent.canonicalJson(allocator);
        defer allocator.free(inconsistent_bytes);
        const shared_path = try root_fs.Path.init(native_provenance.document_path);
        const retained_path = try root_fs.Path.init(retained.logical_path[1..]);
        const saved_shared = try root_fs.Path.init("fixture/package-state-original-shared-receipt");
        const saved_retained = try root_fs.Path.init("fixture/package-state-original-retained-receipt");
        try root.rename(shared_path, saved_shared, .fail_if_exists);
        try root.rename(retained_path, saved_retained, .fail_if_exists);
        try root.publishFile(shared_path, inconsistent_bytes, .{ .permissions = .fromMode(0o600), .overwrite = .fail_if_exists });
        try root.publishFile(retained_path, inconsistent_bytes, .{ .permissions = .fromMode(0o600), .overwrite = .fail_if_exists });
        var inconsistent_input = input;
        inconsistent_input.expected_receipt_sha256 = inconsistent.digest_sha256;
        {
            var readable = try readRetainedNativeReceipt(allocator, inconsistent_input);
            defer readable.deinit();
        }
        try std.testing.expectError(error.InvalidRecoveryProgress, verifyNativePackageState(allocator, inconsistent_input));
        try root.removeFile(shared_path);
        try root.removeFile(retained_path);
        try root.rename(saved_shared, shared_path, .fail_if_exists);
        try root.rename(saved_retained, retained_path, .fail_if_exists);
    }
    var verified = try verifyNativePackageState(allocator, input);
    defer verified.deinit();
    try std.testing.expect(if (failed) verified == .failed else verified == .succeeded);
    try std.testing.expectEqual(before, input.attempt.record().digest_sha256);
    try std.testing.expect(input.attempt.locked());
}

fn testRepositoryNativeReceipt(
    root: root_fs.Root,
    repository: api.Request,
    attempt: *root_operation.Attempt,
    report: native_runtime.Report,
    failed: bool,
) !void {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(if (failed) native_runtime.Outcome.failed else .succeeded, report.outcome);
    const receipt = report.receipt orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(live_root.logical_root_path, receipt.document.install_root);
    try std.testing.expectEqualStrings(
        &std.fmt.bytesToHex(attempt.attemptId(), .lower),
        &receipt.document.attempt_id,
    );
    try std.testing.expectEqualStrings(
        &std.fmt.bytesToHex(attempt.record().program_sha256.?, .lower),
        &receipt.document.program_sha256,
    );
    try std.testing.expect(attempt.locked());
    try std.testing.expectEqual(root_operation.Outcome.pending, attempt.record().outcome);
    try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.native_intent_path)) != null);
    try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(@import("root_operation_completion.zig").document_path)) == null);
    const bytes = try receipt.document.canonicalJson(allocator);
    defer allocator.free(bytes);
    const caller_before = attempt.record().digest_sha256;
    var clock: RepositoryExecutionClock = .{ .root = root };
    const input: NativeReceiptRequest = .{
        .repository = repository,
        .attempt = attempt,
        .expected_receipt_sha256 = receipt.document.digest_sha256,
        .deadline = clock.deadline(),
    };
    const path = try root_fs.Path.init("fixture/repository-native-receipt.json");
    const first_receipt = try root.entryIfExists(path) == null;
    if (!first_receipt) {
        var retained = try readRetainedNativeReceipt(allocator, input);
        defer retained.deinit();
        try std.testing.expectEqualSlices(u8, &receipt.document.digest_sha256, &retained.receipt.document.digest_sha256);
        const previous = try root.readFileAlloc(allocator, path, native_provenance.maximum_document_bytes);
        defer allocator.free(previous);
        try std.testing.expectEqualSlices(u8, previous, bytes);
    } else {
        var paths = try ResolvedPaths.init(allocator, repository, .native);
        defer paths.deinit();
        const retained_path = try root_fs.Path.init(paths.provenance_logical[1..]);
        try std.testing.expectError(error.NativeReceiptMissing, readRetainedNativeReceipt(allocator, input));
        var changed = input;
        changed.repository.no_refresh = !repository.no_refresh;
        try std.testing.expectError(error.RepositoryCallerMismatch, retainNativeReceipt(allocator, changed));
        changed = input;
        changed.expected_receipt_sha256[0] = if (input.expected_receipt_sha256[0] == '0') '1' else '0';
        try std.testing.expectError(error.NativeReceiptMismatch, retainNativeReceipt(allocator, changed));
        clock.expired = true;
        try std.testing.expectError(error.DeadlineExceeded, retainNativeReceipt(allocator, input));
        clock.expired = false;
        try std.testing.expect(try root.entryIfExists(retained_path) == null);
        var late: RepositoryExecutionClock = .{ .root = root, .expire_on_call = 3 };
        changed = input;
        changed.deadline = late.deadline();
        try std.testing.expectError(error.DeadlineExceeded, retainNativeReceipt(allocator, changed));
        try std.testing.expectEqual(@as(usize, 3), late.calls);
        try std.testing.expect(try root.entryIfExists(retained_path) == null);
        var crash: NativeReceiptTestCrash = .{ .point = .after_rename };
        try std.testing.expectError(
            error.InjectedNativeReceiptPublicationFailure,
            nativeRepositoryReceipt(allocator, input, true, crash.observer()),
        );
        const published = try root.entry(retained_path);
        var retained = try retainNativeReceipt(allocator, input);
        defer retained.deinit();
        try std.testing.expectEqual(published.inode, (try root.entry(retained_path)).inode);
        try std.testing.expectEqualSlices(u8, &receipt.document.digest_sha256, &retained.receipt.document.digest_sha256);
        try std.testing.expectEqualStrings(paths.provenance_logical, retained.logical_path);
        try root.publishFile(retained_path, "corrupt receipt", .{ .permissions = .fromMode(0o600) });
        inline for (.{ retainNativeReceipt, readRetainedNativeReceipt, verifyNativePackageState }) |function|
            try std.testing.expectError(error.NativeReceiptMismatch, function(allocator, input));
        const corrupt = try root.readFileAlloc(allocator, retained_path, 128);
        defer allocator.free(corrupt);
        try std.testing.expectEqualStrings("corrupt receipt", corrupt);
        try root.removeFile(retained_path);
        try std.testing.expectError(error.NativeReceiptMissing, readRetainedNativeReceipt(allocator, input));
        try std.testing.expect(try root.entryIfExists(retained_path) == null);
        try root.publishFile(retained_path, bytes, .{ .permissions = .fromMode(0o600), .overwrite = .fail_if_exists });
        try root.publishFile(try root_fs.Path.init("fixture/repository-retained-receipt-path"), retained.logical_path, .{});
        try root.publishFile(path, bytes, .{ .overwrite = .fail_if_exists });
    }
    var retained = try readRetainedNativeReceipt(allocator, input);
    defer retained.deinit();
    const retained_path = try root_fs.Path.init(retained.logical_path[1..]);
    const retained_inode = (try root.entry(retained_path)).inode;
    var repeated = try retainNativeReceipt(allocator, input);
    defer repeated.deinit();
    try std.testing.expectEqual(retained_inode, (try root.entry(retained_path)).inode);
    try testRepositoryNativePackageState(root, input, failed, first_receipt);
    try std.testing.expectEqual(retained_inode, (try root.entry(retained_path)).inode);
    try testRepositoryNativeCheckpoint(root, input, failed, first_receipt);
    try std.testing.expectEqual(caller_before, attempt.record().digest_sha256);
    const trace = try root.readFileAlloc(allocator, try root_fs.Path.init("repository-trace"), 1024);
    defer allocator.free(trace);
    try std.testing.expectEqualStrings("preinst\npostinst\n", trace);
    const payload = try root.readFileAlloc(allocator, try root_fs.Path.init("usr/share/doc/debz-native-repository/README"), 1024);
    defer allocator.free(payload);
    try std.testing.expectEqualStrings("native repository execution\n", payload);
}

fn repositoryExecutionArchive(allocator: std.mem.Allocator, case: RepositoryExecutionCase) ![]u8 {
    return archive_application.test_fixtures.build(allocator, .{
        .package = "debz-native-repository",
        .architecture = "all",
        .control = &.{
            .{ .path = "preinst", .mode = 0o755, .content = "#!/bin/sh\nprintf 'preinst\\n' >> /repository-trace\n" },
            .{
                .path = "postinst",
                .mode = 0o755,
                .content = if (case == .known_failure)
                    "#!/bin/sh\nprintf 'postinst\\n' >> /repository-trace\nexit 12\n"
                else
                    "#!/bin/sh\nprintf 'postinst\\n' >> /repository-trace\n",
            },
        },
        .data = &.{
            .{ .path = "etc", .kind = '5', .mode = 0o755 },
            .{ .path = "etc/apt", .kind = '5', .mode = 0o755 },
            .{ .path = "etc/apt/sources.list.d", .kind = '5', .mode = 0o755 },
            .{ .path = repository_execution_source_path, .content = test_repository_source },
            .{ .path = "usr", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/share", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/share/keyrings", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/share/keyrings/microsoft-prod.gpg", .content = &@import("fixtures/openpgp.zig").keyring },
            .{ .path = "usr/share/doc", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/share/doc/debz-native-repository", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/share/doc/debz-native-repository/README", .content = "native repository execution\n" },
        },
    });
}

fn executeProjectedRepositoryCase(case: RepositoryExecutionCase, projection: *const live_root.Projection) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var named = try root_fs.openAbsoluteRoot(io, live_root.logical_root_path);
    defer named.close();
    const root = named.root;
    try stageNativePreparationDatabase(root, native_architecture_status ++ native_preparation_held_status);
    try root.publishFile(try root_fs.Path.init("var/lib/dpkg/arch"), "amd64\n", .{});
    try root.publishFile(try root_fs.Path.init("var/lib/dpkg/info/dpkg.list"), "/.\n", .{});
    const bytes = try repositoryExecutionArchive(allocator, case);
    defer allocator.free(bytes);
    if (case == .unchanged and try root.entryIfExists(try root_fs.Path.init("fixture/repository-unchanged-bootstrap")) != null)
        try root.publishFile(try root_fs.Path.init("fixture/unchanged-descriptor.deb"), bytes, .{});
    const request: api.Request = .{
        .root = live_root.logical_root_path,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(bytes),
        .no_refresh = case == .interrupted,
    };
    const request_bytes = try std.json.Stringify.valueAlloc(allocator, request, .{});
    defer allocator.free(request_bytes);
    try root.publishFile(try root_fs.Path.init("fixture/repository-original-request.json"), request_bytes, .{});
    const artifact: package_origin.LocalArtifactEvidence = .{
        .artifact_id = package_origin.artifactIdFromSha256(sha256(bytes)),
        .sha256 = sha256(bytes),
        .size = bytes.len,
        .package = "debz-native-repository",
        .version = "1.0",
        .architecture = "all",
        .acquisition_url = request.descriptor_url,
        .trust_mode = .pinned_sha256,
    };
    var fixture = BindingFixture.init(artifact);
    var plan = fixture.plan();
    if (case == .unchanged) {
        plan.actions = &.{};
        plan.ordered_actions = &.{};
        plan.summary = .{};
        plan.download_bytes = 0;
    } else if (case == .diagnostic) plan.ordered_actions = fixture.ordered_actions[0..1];
    var lock = if (case == .unchanged)
        try exact_lock_v2.create(allocator, .{
            .target_architecture = plan.target_architecture,
            .request_sha256 = try operationRequestDigest(allocator, request, plan, .native),
            .policy_sha256 = repositoryLockPolicyDigest(.native),
            .repositories = &.{},
            .local_artifacts = &.{},
            .packages = &.{},
            .verified_origins = true,
        })
    else
        try createOperationLock(allocator, plan, artifact, null, request, .native);
    defer lock.deinit();
    try root.dir.createDirPath(io, "fixture/package-cache");
    var cache_dir = try root.openDirectory(try root_fs.Path.init("fixture/package-cache"));
    defer cache_dir.close(io);
    var cache = try package_acquisition.Cache.initFromDir(io, cache_dir, .{
        .maximum_object_bytes = request.cache.maximum_object_bytes,
    });
    defer cache.deinit();
    if (case != .unchanged)
        try cache.publish(allocator, .{ .bytes = sha256(bytes) }, bytes.len, bytes, .fail_fast, .{});
    var guard: RootOperationGuard = .{ .io = io, .allocator = allocator, .root_projection = projection };
    defer guard.deinit();
    try std.testing.expect(guard.open(request, .native, 1_700_000_000) == null);
    const attempt = guard.active().?;
    const before = attempt.record().digest_sha256;
    const original_attempt = attempt.attemptId();
    if (case == .success or case == .known_failure or case == .interrupted)
        try stageRepositoryNativeLockedInputs(root, request, plan, lock.lock, artifact);
    var clock: RepositoryExecutionClock = .{
        .root = root,
        .stop_on_intent = case == .interrupted,
        .expired = case == .expired,
    };
    const input: NativeCachePreparationRequest = .{
        .repository = request,
        .attempt = attempt,
        .plan = &plan,
        .exact_lock = &lock.lock,
        .cache = &cache,
        .retained_archives = &.{bytes},
        .deadline = clock.deadline(),
    };
    if (case == .expired or case == .missing_helper) {
        try std.testing.expectError(
            if (case == .expired) error.DeadlineExceeded else error.NativeHelperTargetMissing,
            executeNativeFromCache(allocator, input),
        );
    } else {
        var result = try executeNativeFromCache(allocator, input);
        defer result.deinit();
        switch (case) {
            .unchanged => try std.testing.expect(result == .unchanged),
            .diagnostic => {
                try std.testing.expect(result == .diagnostic);
                try std.testing.expectEqual(.missing_configure_barrier, result.diagnostic.diagnostic.code);
            },
            .interrupted => {
                try std.testing.expect(result == .execution);
                try std.testing.expectEqual(native_runtime.Outcome.recovery_required, result.execution.outcome);
                try std.testing.expectEqualStrings("deadline_exceeded", result.execution.detail);
                try std.testing.expect(result.execution.receipt == null);
                try std.testing.expect(!attempt.record().mutation_started);
                try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.native_intent_path)) != null);
            },
            .success, .known_failure => {
                try std.testing.expect(result == .execution);
                try testRepositoryNativeReceipt(root, request, attempt, result.execution, case == .known_failure);
            },
            else => unreachable,
        }
    }
    try std.testing.expect(clock.inspection_error == null);
    try std.testing.expect(attempt.locked());
    try std.testing.expectEqual(original_attempt, attempt.attemptId());
    try std.testing.expectEqualSlices(u8, &repositoryRequestDigest(request, .native), &attempt.record().request_sha256);
    try std.testing.expectEqualSlices(u8, &repositoryPolicyDigest(request, .native), &attempt.record().policy_sha256);
    if (case != .success and case != .known_failure) {
        var receipt_clock: RepositoryExecutionClock = .{ .root = root };
        const receipt_input: NativeReceiptRequest = .{
            .repository = request,
            .attempt = attempt,
            .expected_receipt_sha256 = @splat('0'),
            .deadline = receipt_clock.deadline(),
        };
        inline for (.{ retainNativeReceipt, readRetainedNativeReceipt, verifyNativePackageState }) |function|
            try std.testing.expectError(error.NativeReceiptMissing, function(allocator, receipt_input));
        if (case == .interrupted) {
            try std.testing.expectError(error.NativeReceiptMissing, persistNativePackageState(allocator, receipt_input));
        } else {
            try std.testing.expectError(error.FileNotFound, persistNativePackageState(allocator, receipt_input));
            try std.testing.expect(try root.entryIfExists(try root_fs.Path.init("var/lib/debz/repository")) == null);
        }
    }
    if (case == .unchanged or case == .diagnostic or case == .expired or case == .missing_helper) {
        if (case != .missing_helper) try std.testing.expectEqual(before, attempt.record().digest_sha256);
        try std.testing.expect(attempt.record().state.provenPreMutation());
        try std.testing.expect(!attempt.record().mutation_started);
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.native_intent_path)) == null);
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(@import("native_helper.zig").directory)) == null);
    }
    if (case != .unchanged)
        try cache.objects.deleteFile(io, &std.fmt.bytesToHex(sha256(bytes), .lower));
    try std.testing.expect(try cache.objectSize(.{ .bytes = sha256(bytes) }) == null);
}

fn recoverProjectedRepositoryCase(
    case: RepositoryExecutionCase,
    projection: *const live_root.Projection,
    revoke_scope: ?RepositoryReceiptScope,
) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var named = try root_fs.openAbsoluteRoot(io, live_root.logical_root_path);
    defer named.close();
    const root = named.root;
    const bytes = try root.readFileAlloc(allocator, try root_fs.Path.init("fixture/repository-original-request.json"), api.maximum_document_bytes);
    defer allocator.free(bytes);
    var request = try std.json.parseFromSlice(api.Request, allocator, bytes, .{ .ignore_unknown_fields = false });
    defer request.deinit();
    var guard: RootOperationGuard = .{ .io = io, .allocator = allocator, .root_projection = projection };
    defer guard.deinit();
    try std.testing.expect(guard.open(request.value, .native, 1_700_000_000) == null);
    const attempt = guard.active().?;
    try std.testing.expect(attempt.adopted);
    const before = attempt.record().digest_sha256;
    var clock: RepositoryExecutionClock = .{ .root = root };
    var input: NativeRecoveryRequest = .{
        .repository = request.value,
        .attempt = attempt,
        .deadline = clock.deadline(),
    };
    input.repository.no_refresh = !input.repository.no_refresh;
    try std.testing.expectError(error.RepositoryCallerMismatch, recoverNative(allocator, input));
    input.repository = request.value;
    input.repository.resources.maximum_actions += 1;
    try std.testing.expectError(error.RepositoryCallerMismatch, recoverNative(allocator, input));
    input.repository = request.value;
    if (case == .interrupted and !attempt.record().mutation_started) {
        input.deadline.expires_at_ms = 0;
        var expired = try recoverNative(allocator, input);
        defer expired.deinit();
        try std.testing.expectEqual(native_runtime.Outcome.recovery_required, expired.outcome);
        try std.testing.expectEqualStrings("deadline_exceeded", expired.detail);
        input.deadline = clock.deadline();
    }
    try std.testing.expectEqual(before, attempt.record().digest_sha256);
    var report = try recoverNative(allocator, input);
    defer report.deinit();
    try testRepositoryNativeReceipt(root, request.value, attempt, report, case == .known_failure);
    if (revoke_scope) |route| {
        const before_retention = attempt.record().digest_sha256;
        var revoked: RepositoryExecutionClock = .{ .root = root, .revoke_on_call = if (route == .verify) 4 else 2 };
        var receipt_input: NativeReceiptRequest = .{
            .repository = request.value,
            .attempt = attempt,
            .expected_receipt_sha256 = report.receipt.?.document.digest_sha256,
            .deadline = revoked.deadline(),
        };
        if (route == .checkpoint) {
            var counter: RepositoryExecutionClock = .{ .root = root };
            receipt_input.deadline = counter.deadline();
            var measured = try persistNativePackageState(allocator, receipt_input);
            defer measured.deinit();
            revoked.revoke_on_call = counter.calls;
            receipt_input.deadline = revoked.deadline();
        }
        switch (route) {
            .retain => try std.testing.expectError(error.InvalidRoot, retainNativeReceipt(allocator, receipt_input)),
            .read => try std.testing.expectError(error.InvalidRoot, readRetainedNativeReceipt(allocator, receipt_input)),
            .verify => try std.testing.expectError(error.InvalidRoot, verifyNativePackageState(allocator, receipt_input)),
            .checkpoint => try std.testing.expectError(error.InvalidRoot, persistNativePackageState(allocator, receipt_input)),
        }
        try std.testing.expect(revoked.inspection_error == null);
        try std.testing.expectEqual(revoked.revoke_on_call.?, revoked.calls);
        try std.testing.expectEqual(before_retention, attempt.record().digest_sha256);
        try std.testing.expect(attempt.locked());
    }
}

fn testProjectedNativeImport(case: RepositoryExecutionCase, projection: *const live_root.Projection, pass: usize) !void {
    const allocator = std.testing.allocator;
    var named = try root_fs.openAbsoluteRoot(std.testing.io, live_root.logical_root_path);
    defer named.close();
    const root = named.root;
    const request_bytes = try root.readFileAlloc(allocator, try root_fs.Path.init("fixture/repository-original-request.json"), api.maximum_document_bytes);
    defer allocator.free(request_bytes);
    var request = try std.json.parseFromSlice(api.Request, allocator, request_bytes, .{ .ignore_unknown_fields = false });
    defer request.deinit();
    var guard: RootOperationGuard = .{ .io = std.testing.io, .allocator = allocator, .root_projection = projection };
    defer guard.deinit();
    try std.testing.expect(guard.open(request.value, .native, 1_700_000_000) == null);
    const attempt = guard.active().?;
    const caller = attempt.record().digest_sha256;
    var receipt = (try native_runtime.readCompletion(allocator, attempt)).?;
    defer receipt.deinit();
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = &.{}, .descriptor_available = false };
    const dependencies: NativeImportRefreshDependencies = .{
        .acquisition = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const input: NativeReceiptRequest = .{
        .repository = request.value,
        .attempt = attempt,
        .expected_receipt_sha256 = receipt.document.digest_sha256,
        .deadline = .{ .context = &acquisition, .nowMsFn = RepositoryTestAcquisition.nowMilliseconds, .expires_at_ms = 1000 },
    };
    var paths = try ResolvedPaths.init(allocator, request.value, .native);
    defer paths.deinit();
    const state_path = try root_fs.Path.init(paths.operation_state_logical[1..]);
    const manifest_path = try root_fs.Path.init(paths.manifest_logical[1..]);
    if (case == .success and pass == 0) {
        try std.testing.expectError(error.RepositoryPostInstallIncomplete, completeNative(allocator, input));
        var expired = input;
        expired.deadline.expires_at_ms = 0;
        try std.testing.expectError(error.DeadlineExceeded, importAndRefreshNative(allocator, expired, dependencies));
        var intent = try native_recovery.readIntent(allocator, root);
        defer intent.deinit();
        const blob = for (intent.intent.blobs) |value| {
            if (value.kind == .artifact) break value;
        } else return error.InvalidProjectionFixture;
        const blob_path = try root_fs.Path.init(blob.storage_path);
        const saved = try root_fs.Path.init("fixture/import-missing-input");
        try root.rename(blob_path, saved, .fail_if_exists);
        try std.testing.expectError(error.FileNotFound, importAndRefreshNative(allocator, input, dependencies));
        try std.testing.expect(try root.entryIfExists(blob_path) == null);
        try root.rename(saved, blob_path, .fail_if_exists);
        const original = try root.readFileAlloc(allocator, state_path, state_module.maximum_document_bytes);
        defer allocator.free(original);
        var state = try state_module.decode(allocator, original, state_module.maximum_document_bytes);
        defer state.deinit();
        const evidence = try allocator.dupe(state_module.FileEvidence, state.state.managed_files);
        defer allocator.free(evidence);
        evidence[0].sha256[0] ^= 1;
        var changed = state.state;
        changed.managed_files = evidence;
        var altered = try state_module.create(allocator, changed);
        defer altered.deinit();
        const altered_bytes = try altered.state.canonicalJson(allocator);
        defer allocator.free(altered_bytes);
        try root.publishFile(state_path, altered_bytes, .{ .permissions = .fromMode(0o600) });
        try std.testing.expectError(error.RepositoryStateMismatch, importAndRefreshNative(allocator, input, dependencies));
        try root.publishFile(state_path, original, .{ .permissions = .fromMode(0o600) });
        const source_path = try root_fs.Path.init(state.state.managed_files[0].logical_path[1..]);
        try root.rename(source_path, saved, .fail_if_exists);
        try std.testing.expectError(error.ManagedFileMissing, importAndRefreshNative(allocator, input, dependencies));
        try root.rename(saved, source_path, .fail_if_exists);
        const failed_bytes = try root.readFileAlloc(allocator, state_path, state_module.maximum_document_bytes);
        defer allocator.free(failed_bytes);
        var failed = try state_module.decode(allocator, failed_bytes, state_module.maximum_document_bytes);
        defer failed.deinit();
        try std.testing.expect(failed.state.installed);
        try std.testing.expectEqual(state_module.Phase.installed, failed.state.phase);
        try std.testing.expectEqual(api.DiagnosticId.installed_verification_failed, failed.state.diagnostic_id.?);
        var crash: NativeReceiptTestCrash = .{ .point = .after_rename };
        try std.testing.expectError(error.InjectedNativeReceiptPublicationFailure, nativeRepositoryCheckpoint(allocator, input, crash.observer(), .{ .post_install = dependencies }));
        try std.testing.expect(try root.entryIfExists(manifest_path) != null);
        var clock: RepositoryExecutionClock = .{ .root = root };
        var bounded = input;
        bounded.deadline = clock.deadline();
        var expiration: NativeCheckpointTestBoundary = .{ .root = root, .state_path = state_path, .clock = &clock };
        try std.testing.expectError(error.DeadlineExceeded, nativeRepositoryCheckpoint(allocator, bounded, expiration.observer(), .{ .post_install = dependencies }));
        var replacement: NativeCheckpointTestBoundary = .{ .root = root, .state_path = state_path };
        try std.testing.expectError(error.PathChanged, nativeRepositoryCheckpoint(allocator, input, replacement.observer(), .{ .post_install = dependencies }));
        const replaced = try root.readFileAlloc(allocator, state_path, 128);
        defer allocator.free(replaced);
        try std.testing.expectEqualStrings("changed during verification", replaced);
        try root.removeFile(state_path);
        try root.rename(try root_fs.Path.init("fixture/replaced-checkpoint-state"), state_path, .fail_if_exists);
        const ChangeMaterial = struct {
            root: root_fs.Root,
            path: root_fs.Path,
            fn hit(raw: *anyopaque, point: root_fs.PublishPoint) !void {
                if (point != .before_rename) return;
                const self: *@This() = @ptrCast(@alignCast(raw));
                try self.root.rename(self.path, try root_fs.Path.init("fixture/import-changed-source"), .fail_if_exists);
                try self.root.publishFile(self.path, test_repository_source ++ "# changed\n", .{});
            }
        };
        var change_material: ChangeMaterial = .{ .root = root, .path = source_path };
        try std.testing.expectError(error.ImportedDigestMismatch, nativeRepositoryCheckpoint(allocator, input, .{ .context = &change_material, .hitFn = ChangeMaterial.hit }, .{ .post_install = dependencies }));
        try root.removeFile(source_path);
        try root.rename(try root_fs.Path.init("fixture/import-changed-source"), source_path, .fail_if_exists);
        try std.testing.expectError(error.InjectedNativeReceiptPublicationFailure, nativeRepositoryCheckpoint(allocator, input, crash.observer(), .{ .post_install = dependencies }));
        acquisition.advance_ms_per_read = 1000;
        try std.testing.expectError(error.DeadlineExceeded, importAndRefreshNative(allocator, input, dependencies));
        acquisition.advance_ms_per_read = 0;
        acquisition.now_ms = 0;
        acquisition.fail_in_release_request = acquisition.in_release_requests + 1;
        try std.testing.expectError(error.RepositoryRefreshFailed, importAndRefreshNative(allocator, input, dependencies));
        const refresh_failed_bytes = try root.readFileAlloc(allocator, state_path, state_module.maximum_document_bytes);
        defer allocator.free(refresh_failed_bytes);
        var refresh_failed = try state_module.decode(allocator, refresh_failed_bytes, state_module.maximum_document_bytes);
        defer refresh_failed.deinit();
        try std.testing.expectEqual(state_module.Phase.imported, refresh_failed.state.phase);
        try std.testing.expect(refresh_failed.state.installed and !refresh_failed.state.refreshed);
        try std.testing.expectEqual(api.DiagnosticId.refresh_failed, refresh_failed.state.diagnostic_id.?);
        try std.testing.expectError(error.RepositoryPostInstallIncomplete, completeNative(allocator, input));
    } else if (case == .success and pass == 1) {
        const saved = try root_fs.Path.init("fixture/import-missing-manifest");
        try root.rename(manifest_path, saved, .fail_if_exists);
        try std.testing.expectError(error.FileNotFound, importAndRefreshNative(allocator, input, dependencies));
        try std.testing.expect(try root.entryIfExists(manifest_path) == null);
        try root.publishFile(manifest_path, "corrupt", .{});
        try std.testing.expectError(error.ImportedDigestMismatch, importAndRefreshNative(allocator, input, dependencies));
        try root.removeFile(manifest_path);
        try root.rename(saved, manifest_path, .fail_if_exists);
        const Revoke = struct {
            fn hit(_: *anyopaque, point: root_fs.PublishPoint) !void {
                if (point == .before_rename) try live_root.testing.replaceMountNamespace();
            }
        };
        var unused: u8 = 0;
        try std.testing.expectError(error.InvalidRoot, nativeRepositoryCheckpoint(allocator, input, .{ .context = &unused, .hitFn = Revoke.hit }, .{ .post_install = dependencies }));
    } else {
        var checkpoint = try importAndRefreshNative(allocator, input, dependencies);
        defer checkpoint.deinit();
        const failed = case == .known_failure;
        const expected_phase: state_module.Phase = if (failed) .failed else if (request.value.no_refresh) .imported else .refreshed;
        try std.testing.expectEqual(expected_phase, checkpoint.state.state.phase);
        try std.testing.expectEqual(failed, checkpoint.package_state == .failed);
        try std.testing.expectEqual(!failed, checkpoint.state.state.installed);
        try std.testing.expectEqual(!failed and !request.value.no_refresh, checkpoint.state.state.refreshed);
        if (failed) try std.testing.expect(try root.entryIfExists(manifest_path) == null);
        const inode = (try root.entry(state_path)).inode;
        const reads = acquisition.in_release_requests;
        var repeated = try importAndRefreshNative(allocator, input, dependencies);
        defer repeated.deinit();
        try std.testing.expectEqual(checkpoint.state.state.digest_sha256, repeated.state.state.digest_sha256);
        try std.testing.expectEqual(inode, (try root.entry(state_path)).inode);
        try std.testing.expectEqual(reads, acquisition.in_release_requests);
        if (failed or request.value.no_refresh) try std.testing.expectEqual(@as(usize, 0), reads);
        if (!failed) try std.testing.expectError(error.RepositoryPackageStageAlreadyAdvanced, persistNativePackageState(allocator, input));
        if (case == .success and pass == 2) {
            var counting = std.testing.FailingAllocator.init(allocator, .{});
            {
                var counted = try importAndRefreshNative(counting.allocator(), input, dependencies);
                defer counted.deinit();
            }
            try std.testing.expectEqual(counting.allocated_bytes, counting.freed_bytes);
            for ([_]usize{ 0, counting.alloc_index - 1 }) |index| {
                var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = index });
                try std.testing.expectError(error.OutOfMemory, importAndRefreshNative(failing.allocator(), input, dependencies));
                try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
                try std.testing.expectEqual(inode, (try root.entry(state_path)).inode);
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), acquisition.descriptor_reads);
    try std.testing.expectEqual(@as(usize, 0), acquisition.network_requests);
    try std.testing.expectEqual(caller, attempt.record().digest_sha256);
    try std.testing.expectEqual(root_operation.Outcome.pending, attempt.record().outcome);
    try std.testing.expect(attempt.locked());
}

fn testNativeCompletionRefusals(input: NativeReceiptRequest) !void {
    const allocator = std.testing.allocator;
    const root = input.attempt.coordinator.root;
    const caller = input.attempt.record().digest_sha256;
    var paths = try ResolvedPaths.init(allocator, input.repository, .native);
    defer paths.deinit();
    const state_path = try root_fs.Path.init(paths.operation_state_logical[1..]);
    const manifest_path = try root_fs.Path.init(paths.manifest_logical[1..]);
    const local_text = try joinLogical(allocator, paths.operation_logical, root_operation_completion.document_name);
    defer allocator.free(local_text);
    const local_path = try root_fs.Path.init(local_text[1..]);
    const global_path = try root_fs.Path.init(root_operation_completion.document_path);
    const saved = try root_fs.Path.init("fixture/saved-completion-input");
    const state_inode = (try root.entry(state_path)).inode;
    var pin = try root.pinRegularFile(local_path);
    defer pin.close();
    var completion = try decodeNativeCompletion(allocator, &pin);
    defer completion.deinit();
    var wrong_request = completion.document.discharge;
    wrong_request.request_sha256[0] ^= 1;
    var different = try root_operation_completion.create(allocator, .{
        .record = input.attempt.record(),
        .transaction_provenance = completion.document.transaction_provenance,
        .journal = completion.document.journal,
        .discharge = wrong_request,
    });
    defer different.deinit();
    const wrong_bytes = try different.document.canonicalJson(allocator);
    defer allocator.free(wrong_bytes);
    for ([_]root_fs.Path{ local_path, global_path }) |path| {
        const inode = (try root.entry(path)).inode;
        try root.rename(path, saved, .fail_if_exists);
        try std.testing.expectError(error.NativeCompletionMissing, completeNative(allocator, input));
        try std.testing.expect(try root.entryIfExists(path) == null);
        try root.createSymbolicLink(path, "/fixture/saved-completion-input");
        try std.testing.expectError(error.NotRegularFile, completeNative(allocator, input));
        try root.removeFile(path);
        try root.publishFile(path, "not a completion", .{});
        try std.testing.expectError(error.NonCanonicalDocument, completeNative(allocator, input));
        try root.publishFile(path, wrong_bytes, .{ .overwrite = .replace });
        try std.testing.expectError(error.NativeCompletionMismatch, completeNative(allocator, input));
        try root.removeFile(path);
        try root.rename(saved, path, .fail_if_exists);
        try std.testing.expectEqual(inode, (try root.entry(path)).inode);
    }
    try root.rename(manifest_path, saved, .fail_if_exists);
    try std.testing.expectError(error.FileNotFound, completeNative(allocator, input));
    try root.publishFile(manifest_path, "changed manifest", .{});
    try std.testing.expectError(error.ImportedDigestMismatch, completeNative(allocator, input));
    try root.removeFile(manifest_path);
    try root.rename(saved, manifest_path, .fail_if_exists);
    const state_bytes = try root.readFileAlloc(allocator, state_path, state_module.maximum_document_bytes);
    defer allocator.free(state_bytes);
    var current = try state_module.decode(allocator, state_bytes, state_module.maximum_document_bytes);
    defer current.deinit();
    var downgraded = current.state;
    downgraded.phase = .refreshed;
    var changed = try state_module.create(allocator, downgraded);
    defer changed.deinit();
    const changed_bytes = try changed.state.canonicalJson(allocator);
    defer allocator.free(changed_bytes);
    try root.rename(state_path, saved, .fail_if_exists);
    try root.publishFile(state_path, changed_bytes, .{});
    try std.testing.expectError(error.NativeCompletionMismatch, completeNative(allocator, input));
    try root.removeFile(state_path);
    try root.rename(saved, state_path, .fail_if_exists);
    const discharge = completion.document.discharge.request_sha256;
    var changed_state = current.state;
    changed_state.digest_sha256[0] ^= 1;
    var snapshot = try nativeRepositorySnapshot(allocator, input.recoveryRequest());
    defer snapshot.deinit();
    try std.testing.expect(!std.mem.eql(u8, &discharge, &nativeCompletionRequestDigest(input, input.attempt.attemptId(), changed_state, snapshot.manifest.manifest.digest_sha256)));
    var changed_manifest = snapshot.manifest.manifest.digest_sha256;
    changed_manifest[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &discharge, &nativeCompletionRequestDigest(input, input.attempt.attemptId(), current.state, changed_manifest)));
    var wrong = completion.document;
    wrong.outcome = .failed_after_mutation;
    try std.testing.expectError(error.NativeCompletionMismatch, validateNativeCompletion(input, wrong, discharge, .succeeded));
    wrong = completion.document;
    wrong.foreign_architectures = &.{"riscv64"};
    try std.testing.expectError(error.NativeCompletionMismatch, validateNativeCompletion(input, wrong, discharge, .succeeded));
    wrong = completion.document;
    wrong.transaction_provenance.document_sha256.?[0] ^= 1;
    try std.testing.expectError(error.NativeCompletionMismatch, validateNativeCompletion(input, wrong, discharge, .succeeded));
    try std.testing.expectEqual(state_inode, (try root.entry(state_path)).inode);
    try std.testing.expectEqual(caller, input.attempt.record().digest_sha256);
}

fn testProjectedNativeCompletion(case: RepositoryExecutionCase, projection: *const live_root.Projection, pass: usize) !void {
    const allocator = std.testing.allocator;
    var named = try root_fs.openAbsoluteRoot(std.testing.io, live_root.logical_root_path);
    defer named.close();
    const root = named.root;
    const request_bytes = try root.readFileAlloc(allocator, try root_fs.Path.init("fixture/repository-original-request.json"), api.maximum_document_bytes);
    defer allocator.free(request_bytes);
    var request = try std.json.parseFromSlice(api.Request, allocator, request_bytes, .{ .ignore_unknown_fields = false });
    defer request.deinit();
    if (case == .success and pass == 0) {
        for (0..2) |index| {
            var other = request.value;
            if (index == 0) other.no_refresh = !other.no_refresh else other.resources.maximum_actions += 1;
            var refused: RootOperationGuard = .{ .io = std.testing.io, .allocator = allocator, .root_projection = projection, .native_completion_only = true };
            defer refused.deinit();
            try std.testing.expect(refused.open(other, .native, 1_700_000_000) != null);
            try std.testing.expect(refused.active() == null);
        }
        const RemoveCaller = struct {
            fn hit(raw: *anyopaque, point: root_operation.AcquisitionPoint) !void {
                if (point != .after_lock_acquired) return;
                const target: *const root_fs.Root = @ptrCast(@alignCast(raw));
                try target.rename(try root_fs.Path.init(root_operation.record_path), try root_fs.Path.init("fixture/saved-completion-caller"), .fail_if_exists);
            }
        };
        var target = root;
        var refused: RootOperationGuard = .{
            .io = std.testing.io,
            .allocator = allocator,
            .root_projection = projection,
            .native_completion_only = true,
            .acquisition_observer = .{ .context = &target, .hitFn = RemoveCaller.hit },
        };
        defer refused.deinit();
        try std.testing.expect(refused.open(request.value, .native, 1_700_000_000) != null);
        try std.testing.expect(refused.active() == null);
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) == null);
        try root.rename(try root_fs.Path.init("fixture/saved-completion-caller"), try root_fs.Path.init(root_operation.record_path), .fail_if_exists);
    }
    var guard: RootOperationGuard = .{
        .io = std.testing.io,
        .allocator = allocator,
        .root_projection = projection,
        .native_completion_only = true,
    };
    defer guard.deinit();
    if (guard.open(request.value, .native, 1_700_000_000)) |failure| {
        std.debug.print("native completion adoption refused: {s}\n", .{failure.summary});
        return error.TestUnexpectedResult;
    }
    const attempt = guard.active().?;
    const original_id = attempt.attemptId();
    var receipt = (try native_runtime.readCompletion(allocator, attempt)).?;
    defer receipt.deinit();
    var clock: RepositoryExecutionClock = .{ .root = root };
    const input: NativeReceiptRequest = .{
        .repository = request.value,
        .attempt = attempt,
        .expected_receipt_sha256 = receipt.document.digest_sha256,
        .deadline = clock.deadline(),
    };
    if (pass == 0) {
        const pending = try attempt.record().canonicalJson(allocator);
        defer allocator.free(pending);
        try root.publishFile(try root_fs.Path.init("fixture/repository-pending-caller.json"), pending, .{ .permissions = .fromMode(0o600) });
        var changed = input;
        changed.repository.no_refresh = !changed.repository.no_refresh;
        try std.testing.expectError(error.RepositoryCallerMismatch, completeNative(allocator, changed));
    }
    const points: []const NativeCompletionPoint = if (case == .success) &.{
        .after_final_state,           .after_completed_record, .before_completion_rename, .after_completion_rename,
        .after_local_completion,      .after_root_completion,  .after_provenance,         .before_native_acknowledgment,
        .after_native_acknowledgment, .before_clear,
    } else &.{ .after_completed_record, .after_provenance, .after_native_acknowledgment };
    const Observer = struct {
        point: NativeCompletionPoint,
        root: root_fs.Root,
        attempt: *root_operation.Attempt,
        clock: *RepositoryExecutionClock,
        record_only: bool = false,

        fn hit(raw: *anyopaque, point: NativeCompletionPoint) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (point != self.point) return;
            if (self.record_only) {
                const bytes = try self.attempt.record().canonicalJson(std.testing.allocator);
                defer std.testing.allocator.free(bytes);
                try self.root.publishFile(try root_fs.Path.init("fixture/repository-completed-caller.json"), bytes, .{ .permissions = .fromMode(0o600) });
                return;
            }
            if (point == .before_completion_rename) {
                const original = try self.root.readFileAlloc(std.testing.allocator, try root_fs.Path.init("fixture/repository-retained-receipt-path"), root_fs.maximum_path_bytes);
                defer std.testing.allocator.free(original);
                const path_text = try std.fmt.allocPrint(std.testing.allocator, "{s}/apt-config-snapshot-v1.json", .{std.fs.path.dirname(original[1..]).?});
                defer std.testing.allocator.free(path_text);
                const path = try root_fs.Path.init(path_text);
                const bytes = try self.root.readFileAlloc(std.testing.allocator, path, target_apt_config.maximum_document_bytes);
                defer std.testing.allocator.free(bytes);
                try self.root.rename(path, try root_fs.Path.init("fixture/replaced-completion-manifest"), .fail_if_exists);
                try self.root.publishFile(path, bytes, .{ .permissions = .fromMode(0o600) });
                return;
            }
            if (point == .before_native_acknowledgment) {
                try live_root.testing.replaceMountNamespace();
                return;
            }
            if (point == .after_root_completion) {
                self.clock.expired = true;
                return;
            }
            if (point == .after_provenance) {
                var intent = try native_recovery.readIntent(std.testing.allocator, self.root);
                defer intent.deinit();
                const blob = for (intent.intent.blobs) |value| {
                    if (value.kind == .artifact) break value;
                } else return error.InvalidProjectionFixture;
                try self.root.removeFile(try root_fs.Path.init(blob.storage_path));
            }
            return error.InjectedNativeCompletionFailure;
        }

        fn interface(self: *@This()) NativeCompletionObserver {
            return .{ .context = self, .hitFn = hit };
        }
    };
    if (pass < points.len) {
        var observer: Observer = .{ .point = points[pass], .root = root, .attempt = attempt, .clock = &clock };
        try std.testing.expectError(switch (points[pass]) {
            .before_completion_rename => error.PathChanged,
            .before_native_acknowledgment => error.InvalidRoot,
            .after_root_completion => error.DeadlineExceeded,
            else => error.InjectedNativeCompletionFailure,
        }, completeNativeObserved(allocator, input, observer.interface()));
        if (points[pass] == .before_completion_rename) {
            var paths = try ResolvedPaths.init(allocator, input.repository, .native);
            defer paths.deinit();
            const path = try root_fs.Path.init(paths.manifest_logical[1..]);
            try root.removeFile(path);
            try root.rename(try root_fs.Path.init("fixture/replaced-completion-manifest"), path, .fail_if_exists);
        }
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) != null);
        if (points[pass] == .after_native_acknowledgment or points[pass] == .before_clear)
            try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) == null);
    } else {
        if (case == .success) try testNativeCompletionRefusals(input);
        var observer: Observer = .{ .point = .before_clear, .root = root, .attempt = attempt, .clock = &clock, .record_only = true };
        var result = try completeNativeObserved(allocator, input, observer.interface());
        defer result.deinit();
        const failed = case == .known_failure;
        try std.testing.expectEqual(if (failed) state_module.Phase.failed else .complete, result.checkpoint.state.state.phase);
        try std.testing.expectEqual(failed, result.checkpoint.package_state == .failed);
        try std.testing.expectEqual(if (failed) root_operation.Outcome.failed_after_mutation else .succeeded, result.completion.document.outcome);
        try std.testing.expectEqual(result.completion.document.digest_sha256, attempt.record().provenance_sha256.?);
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) == null);
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) == null);
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(native_recovery.progress_path)) == null);
        const inode = (try root.entry(try root_fs.Path.init(root_operation_completion.document_path))).inode;
        var counting = std.testing.FailingAllocator.init(allocator, .{});
        var repeated = try completeNative(counting.allocator(), input);
        defer repeated.deinit();
        try std.testing.expectEqual(result.completion.document.digest_sha256, repeated.completion.document.digest_sha256);
        try std.testing.expectEqual(result.checkpoint.state.state.digest_sha256, repeated.checkpoint.state.state.digest_sha256);
        try std.testing.expectEqual(inode, (try root.entry(try root_fs.Path.init(root_operation_completion.document_path))).inode);
        for ([_]usize{ 0, counting.alloc_index - 1 }) |index| {
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = index });
            try std.testing.expectError(error.OutOfMemory, completeNative(failing.allocator(), input));
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            try std.testing.expectEqual(inode, (try root.entry(try root_fs.Path.init(root_operation_completion.document_path))).inode);
        }
    }
    try std.testing.expectEqual(original_id, attempt.attemptId());
    try std.testing.expect(attempt.locked());
    const trace = try root.readFileAlloc(allocator, try root_fs.Path.init("repository-trace"), 1024);
    defer allocator.free(trace);
    try std.testing.expectEqualStrings("preinst\npostinst\n", trace);
}

fn testNativeHistoryRefusals(input: NativeRecoveryRequest, dependencies: NativeImportRefreshDependencies) !void {
    const allocator = std.testing.allocator;
    const root = input.attempt.coordinator.root;
    const caller = input.attempt.record().digest_sha256;
    var paths = try ResolvedPaths.init(allocator, input.repository, .native);
    defer paths.deinit();
    const local_text = try joinLogical(allocator, paths.operation_logical, root_operation_completion.document_name);
    defer allocator.free(local_text);
    const history_paths = [_][]const u8{
        paths.operation_state_logical[1..], paths.exact_plan_logical[1..],           paths.exact_lock_logical[1..],
        local_text[1..],                    root_operation_completion.document_path, paths.provenance_logical[1..],
        native_provenance.document_path,    paths.manifest_logical[1..],
    };
    var snapshots: [history_paths.len]struct { path: []const u8, inode: u64, sha256: [32]u8 } = undefined;
    for (history_paths, &snapshots) |text, *snapshot| {
        const path = try root_fs.Path.init(text);
        const bytes = try root.readFileAlloc(allocator, path, exact_lock_v2.maximum_document_bytes);
        defer allocator.free(bytes);
        snapshot.* = .{ .path = text, .inode = (try root.entry(path)).inode, .sha256 = sha256(bytes) };
    }
    const snapshot_bytes = try std.json.Stringify.valueAlloc(allocator, snapshots, .{});
    defer allocator.free(snapshot_bytes);
    try root.publishFile(try root_fs.Path.init("fixture/repository-history-preserved.json"), snapshot_bytes, .{});
    const saved = try root_fs.Path.init("fixture/history-saved-input");
    for (history_paths) |text| {
        const path = try root_fs.Path.init(text);
        try root.rename(path, saved, .fail_if_exists);
        try std.testing.expectError(error.FileNotFound, readNativeRepositoryHistory(allocator, input));
        try std.testing.expectError(error.FileNotFound, resumeNativeRepository(allocator, input, dependencies));
        try std.testing.expect(try root.entryIfExists(path) == null);
        try root.createSymbolicLink(path, "/fixture/history-saved-input");
        try std.testing.expectError(error.NotRegularFile, readNativeRepositoryHistory(allocator, input));
        try root.removeFile(path);
        try root.rename(saved, path, .fail_if_exists);
    }
    var changed_input = input;
    changed_input.repository.resources.maximum_actions += 1;
    try std.testing.expectError(error.RepositoryCallerMismatch, readNativeRepositoryHistory(allocator, changed_input));
    changed_input = input;
    changed_input.deadline.expires_at_ms = 0;
    try std.testing.expectError(error.DeadlineExceeded, readNativeRepositoryHistory(allocator, changed_input));
    for ([_][]const u8{ native_recovery.intent_path, root_operation.deferred_ack_path }) |text| {
        const path = try root_fs.Path.init(text);
        try std.testing.expect(try root.entryIfExists(path) == null);
        try root.publishFile(path, "foreign ownership", .{});
        try std.testing.expectError(
            if (std.mem.eql(u8, text, native_recovery.intent_path)) error.HistoricalCallerNotClean else error.OperationNotSettled,
            readNativeRepositoryHistory(allocator, input),
        );
        try root.removeFile(path);
    }
    const completed_bytes = try root.readFileAlloc(allocator, try root_fs.Path.init("fixture/repository-completed-caller.json"), root_operation.maximum_document_bytes);
    defer allocator.free(completed_bytes);
    var completed = try root_operation.decode(allocator, completed_bytes, root_operation.maximum_document_bytes);
    defer completed.deinit();
    const active_path = try root_fs.Path.init(root_operation.record_path);
    try root.rename(active_path, saved, .fail_if_exists);
    try root.publishFile(active_path, completed_bytes, .{});
    try std.testing.expectError(error.OperationEvidenceMismatch, readNativeRepositoryHistory(allocator, input));
    try root.removeFile(active_path);
    try root.rename(saved, active_path, .fail_if_exists);
    var history = try readNativeRepositoryHistory(allocator, input);
    defer history.deinit();
    const local_completion = try root_fs.Path.init(local_text[1..]);
    const shared_completion = try root_fs.Path.init(root_operation_completion.document_path);
    const saved_shared = try root_fs.Path.init("fixture/history-saved-shared");
    const Alteration = enum { discharge, request, policy, foreign, same_caller, outcome };
    for (std.enums.values(Alteration)) |alteration| {
        var record = completed.record;
        var discharge = history.completion.document.discharge;
        switch (alteration) {
            .discharge => discharge.request_sha256[0] ^= 1,
            .request => record.request_sha256[0] ^= 1,
            .policy => record.policy_sha256[0] ^= 1,
            .foreign => record.foreign_architectures = &.{"riscv64"},
            .same_caller => record.attempt_id = input.attempt.attemptId(),
            .outcome => record.outcome = .failed_after_mutation,
        }
        var different = try root_operation_completion.create(allocator, .{
            .record = record,
            .transaction_provenance = history.completion.document.transaction_provenance,
            .journal = history.completion.document.journal,
            .discharge = discharge,
        });
        defer different.deinit();
        const bytes = try different.document.canonicalJson(allocator);
        defer allocator.free(bytes);
        try root.rename(local_completion, saved, .fail_if_exists);
        try root.publishFile(local_completion, bytes, .{});
        try std.testing.expectError(error.NativeCompletionMismatch, readNativeRepositoryHistory(allocator, input));
        try root.rename(shared_completion, saved_shared, .fail_if_exists);
        try root.publishFile(shared_completion, bytes, .{});
        try std.testing.expectError(
            switch (alteration) {
                .foreign => error.InvalidCompletion,
                .outcome => error.TransactionNotSuccessful,
                else => error.NativeCompletionMismatch,
            },
            readNativeRepositoryHistory(allocator, input),
        );
        try root.removeFile(shared_completion);
        try root.rename(saved_shared, shared_completion, .fail_if_exists);
        try root.removeFile(local_completion);
        try root.rename(saved, local_completion, .fail_if_exists);
    }
    for ([_]root_fs.Path{ local_completion, shared_completion }, 0..) |path, index| {
        try root.rename(path, saved, .fail_if_exists);
        try root.publishFile(path, "{}", .{});
        try std.testing.expectError(
            if (index == 0) error.NonCanonicalDocument else error.NativeCompletionMismatch,
            readNativeRepositoryHistory(allocator, input),
        );
        try root.removeFile(path);
        try root.rename(saved, path, .fail_if_exists);
    }
    const state_path = try root_fs.Path.init(paths.operation_state_logical[1..]);
    var changed_state = history.state.state;
    changed_state.phase = .refreshed;
    var downgraded = try state_module.create(allocator, changed_state);
    defer downgraded.deinit();
    const downgraded_bytes = try downgraded.state.canonicalJson(allocator);
    defer allocator.free(downgraded_bytes);
    try root.rename(state_path, saved, .fail_if_exists);
    try root.publishFile(state_path, downgraded_bytes, .{});
    try std.testing.expectError(error.RepositoryStateMismatch, readNativeRepositoryHistory(allocator, input));
    try root.removeFile(state_path);
    try root.rename(saved, state_path, .fail_if_exists);
    const plan_path = try root_fs.Path.init(paths.exact_plan_logical[1..]);
    const plan_bytes = try root.readFileAlloc(allocator, plan_path, repository_plan.maximum_document_bytes);
    defer allocator.free(plan_bytes);
    var plan = try repository_plan.decode(allocator, plan_bytes);
    defer plan.deinit();
    plan.target_architecture = "riscv64";
    const changed_plan = try plan.canonicalJson(allocator);
    defer allocator.free(changed_plan);
    try root.rename(plan_path, saved, .fail_if_exists);
    try root.publishFile(plan_path, changed_plan, .{});
    try std.testing.expectError(error.PlanEvidenceMismatch, readNativeRepositoryHistory(allocator, input));
    try root.removeFile(plan_path);
    try root.rename(saved, plan_path, .fail_if_exists);
    const lock_path = try root_fs.Path.init(paths.exact_lock_logical[1..]);
    const lock_bytes = try root.readFileAlloc(allocator, lock_path, exact_lock_v2.maximum_document_bytes);
    defer allocator.free(lock_bytes);
    var lock = try exact_lock_v2.decode(allocator, lock_bytes, exact_lock_v2.maximum_document_bytes);
    defer lock.deinit();
    var policy_digest = lock.lock.policy_sha256;
    policy_digest[0] ^= 1;
    var different_lock = try exact_lock_v2.create(allocator, .{
        .target_architecture = lock.lock.target_architecture,
        .request_sha256 = lock.lock.request_sha256,
        .policy_sha256 = policy_digest,
        .repositories = lock.lock.repositories,
        .local_artifacts = lock.lock.local_artifacts,
        .packages = lock.lock.packages,
        .verified_origins = true,
    });
    defer different_lock.deinit();
    const changed_lock = try different_lock.lock.canonicalJson(allocator);
    defer allocator.free(changed_lock);
    try root.rename(lock_path, saved, .fail_if_exists);
    try root.publishFile(lock_path, changed_lock, .{});
    try std.testing.expectError(error.LockEvidenceMismatch, readNativeRepositoryHistory(allocator, input));
    try root.removeFile(lock_path);
    try root.rename(saved, lock_path, .fail_if_exists);
    var policy = repositoryExecutionPolicy(input.repository);
    policy.exact_lock_verification = .full_closure;
    try std.testing.expectError(error.InvalidCompletion, native_transaction_result.verifyRepositoryHistory(allocator, input.attempt, lock.lock, policy, history.completion.document, history.receipt.document));
    policy = repositoryExecutionPolicy(input.repository);
    policy.risk.allow_host_root = !policy.risk.allow_host_root;
    try std.testing.expectError(error.AuthorizationMismatch, native_transaction_result.verifyRepositoryHistory(allocator, input.attempt, lock.lock, policy, history.completion.document, history.receipt.document));
    policy = repositoryExecutionPolicy(input.repository);
    policy.process_timeout_ms += 1;
    try std.testing.expectError(error.AuthorizationMismatch, native_transaction_result.verifyRepositoryHistory(allocator, input.attempt, lock.lock, policy, history.completion.document, history.receipt.document));
    var changed_receipt = history.receipt.document;
    changed_receipt.detail = "different historical receipt";
    native_provenance.seal(&changed_receipt);
    const different_receipt = try changed_receipt.canonicalJson(allocator);
    defer allocator.free(different_receipt);
    for ([_][]const u8{ paths.provenance_logical[1..], native_provenance.document_path }) |text| {
        const path = try root_fs.Path.init(text);
        try root.rename(path, saved, .fail_if_exists);
        try root.publishFile(path, "{}", .{});
        try std.testing.expectError(error.MissingField, readNativeRepositoryHistory(allocator, input));
        try root.publishFile(path, different_receipt, .{ .overwrite = .replace });
        try std.testing.expectError(error.NativeReceiptMismatch, readNativeRepositoryHistory(allocator, input));
        try root.removeFile(path);
        try root.rename(saved, path, .fail_if_exists);
    }
    for ([_][]const u8{ repository_execution_source_path, "usr/share/keyrings/microsoft-prod.gpg", paths.manifest_logical[1..] }, 0..) |text, index| {
        const path = try root_fs.Path.init(text);
        try root.rename(path, saved, .fail_if_exists);
        try root.publishFile(path, "changed history input", .{});
        try std.testing.expectError(if (index == 2) error.ImportedDigestMismatch else error.ManagedFileMismatch, readNativeRepositoryHistory(allocator, input));
        try root.removeFile(path);
        try root.rename(saved, path, .fail_if_exists);
    }
    const status_path = try root_fs.Path.init("var/lib/dpkg/status");
    const status = try root.readFileAlloc(allocator, status_path, 1024 * 1024);
    defer allocator.free(status);
    try std.testing.expect(std.mem.indexOf(u8, status, "Status: hold ok installed") != null);
    const unheld = try std.mem.replaceOwned(u8, allocator, status, "Status: hold ok installed", "Status: install ok installed");
    defer allocator.free(unheld);
    try root.rename(status_path, saved, .fail_if_exists);
    try root.publishFile(status_path, unheld, .{});
    try std.testing.expectError(error.FinalStateMismatch, readNativeRepositoryHistory(allocator, input));
    try root.removeFile(status_path);
    try root.rename(saved, status_path, .fail_if_exists);
    const Observer = struct {
        input: NativeRecoveryRequest,
        point: NativeHistoryPoint,
        path: ?root_fs.Path = null,
        clock: ?*RepositoryExecutionClock = null,

        fn hit(raw: *anyopaque, point: NativeHistoryPoint) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (point != self.point) return;
            if (self.clock) |clock| clock.expired = true;
            if (self.path) |path| {
                const target = self.input.attempt.coordinator.root;
                const bytes = try target.readFileAlloc(std.testing.allocator, path, exact_lock_v2.maximum_document_bytes);
                defer std.testing.allocator.free(bytes);
                try target.rename(path, try root_fs.Path.init("fixture/history-saved-input"), .fail_if_exists);
                try target.publishFile(path, bytes, .{});
            }
        }
    };
    for (std.enums.values(NativeHistoryPoint)) |point| {
        var clock: RepositoryExecutionClock = .{ .root = root };
        var deadline_input = input;
        deadline_input.deadline = clock.deadline();
        var observer: Observer = .{ .input = input, .point = point, .clock = &clock };
        try std.testing.expectError(error.DeadlineExceeded, readNativeRepositoryHistoryObserved(allocator, deadline_input, .{ .context = &observer, .hitFn = Observer.hit }));
    }
    for (history_paths) |text| {
        const path = try root_fs.Path.init(text);
        var observer: Observer = .{ .input = input, .point = .after_package_verification, .path = path };
        try std.testing.expectError(error.PathChanged, readNativeRepositoryHistoryObserved(allocator, input, .{ .context = &observer, .hitFn = Observer.hit }));
        try root.removeFile(path);
        try root.rename(saved, path, .fail_if_exists);
    }
    for (snapshots) |snapshot| {
        const path = try root_fs.Path.init(snapshot.path);
        const bytes = try root.readFileAlloc(allocator, path, exact_lock_v2.maximum_document_bytes);
        defer allocator.free(bytes);
        try std.testing.expectEqual(snapshot.inode, (try root.entry(path)).inode);
        try std.testing.expectEqual(snapshot.sha256, sha256(bytes));
    }
    try std.testing.expectEqual(caller, input.attempt.record().digest_sha256);
}

fn testProjectedNativeResume(case: RepositoryExecutionCase, projection: *const live_root.Projection, pass: usize) !void {
    const allocator = std.testing.allocator;
    var named = try root_fs.openAbsoluteRoot(std.testing.io, live_root.logical_root_path);
    defer named.close();
    const root = named.root;
    const bytes = try root.readFileAlloc(allocator, try root_fs.Path.init("fixture/repository-original-request.json"), api.maximum_document_bytes);
    defer allocator.free(bytes);
    var request = try std.json.parseFromSlice(api.Request, allocator, bytes, .{ .ignore_unknown_fields = false });
    defer request.deinit();
    const refresh_retry = case == .success and pass == 0;
    const step = pass - @intFromBool(case == .success and pass != 0);
    var guard: RootOperationGuard = .{
        .io = std.testing.io,
        .allocator = allocator,
        .root_projection = projection,
        .native_completion_only = case != .unchanged and !refresh_retry and (step == 1 or step == 2),
    };
    defer guard.deinit();
    try std.testing.expect(guard.open(request.value, .native, 1_700_000_000) == null);
    const attempt = guard.active().?;
    const caller = attempt.record().digest_sha256;
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = &.{}, .descriptor_available = false };
    const dependencies: NativeImportRefreshDependencies = .{
        .acquisition = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const input: NativeRecoveryRequest = .{
        .repository = request.value,
        .attempt = attempt,
        .deadline = .{ .context = &acquisition, .nowMsFn = RepositoryTestAcquisition.nowMilliseconds, .expires_at_ms = 1000 },
    };
    if (case == .unchanged) {
        var result = try resumeNativeRepository(allocator, input, dependencies);
        defer result.deinit();
        try std.testing.expect(result == .not_started);
        try std.testing.expectEqual(caller, attempt.record().digest_sha256);
    } else if (step >= 3) {
        if (case == .success and (step == 4 or step == 5)) {
            const Revoke = struct {
                point: NativeHistoryPoint,
                fn hit(raw: *anyopaque, point: NativeHistoryPoint) !void {
                    const self: *@This() = @ptrCast(@alignCast(raw));
                    if (self.point == point) try live_root.testing.replaceMountNamespace();
                }
            };
            var observer: Revoke = .{ .point = if (step == 4) .before_package_verification else .after_package_verification };
            try std.testing.expectError(error.InvalidRoot, readNativeRepositoryHistoryObserved(allocator, input, .{ .context = &observer, .hitFn = Revoke.hit }));
            try std.testing.expectEqual(caller, attempt.record().digest_sha256);
            try std.testing.expect(attempt.locked());
            return;
        }
        if (case == .success and step == 3) try testNativeHistoryRefusals(input, dependencies);
        const completion_inode = (try root.entry(try root_fs.Path.init(root_operation_completion.document_path))).inode;
        var result = try resumeNativeRepository(allocator, input, dependencies);
        defer result.deinit();
        try std.testing.expect(result == .historical);
        try std.testing.expectEqual(case == .known_failure, result.historical.receipt.document.outcome == .failed);
        try std.testing.expect(!std.mem.eql(u8, &result.historical.completion.document.attempt_id, &attempt.attemptId()));
        try std.testing.expectEqual(caller, attempt.record().digest_sha256);
        try std.testing.expectEqual(completion_inode, (try root.entry(try root_fs.Path.init(root_operation_completion.document_path))).inode);
        const current = try attempt.record().canonicalJson(allocator);
        defer allocator.free(current);
        try root.publishFile(try root_fs.Path.init("fixture/repository-history-caller.json"), current, .{ .overwrite = .replace });
        var counting = std.testing.FailingAllocator.init(allocator, .{});
        {
            var repeated = try readNativeRepositoryHistory(counting.allocator(), input);
            defer repeated.deinit();
            try std.testing.expectEqual(result.historical.completion.document.digest_sha256, repeated.completion.document.digest_sha256);
        }
        try std.testing.expectEqual(counting.allocated_bytes, counting.freed_bytes);
        for ([_]usize{ 0, counting.alloc_index - 1 }) |index| {
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = index });
            try std.testing.expectError(error.OutOfMemory, readNativeRepositoryHistory(failing.allocator(), input));
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        }
        try std.testing.expectEqual(caller, attempt.record().digest_sha256);
    } else {
        if (pass == 0) {
            var changed = input;
            changed.repository.resources.maximum_actions += 1;
            try std.testing.expectError(error.RepositoryCallerMismatch, resumeNativeRepository(allocator, changed, dependencies));
            changed = input;
            changed.deadline.expires_at_ms = 0;
            try std.testing.expectError(error.DeadlineExceeded, resumeNativeRepository(allocator, changed, dependencies));
            var paths = try ResolvedPaths.init(allocator, input.repository, .native);
            defer paths.deinit();
            const saved = try root_fs.Path.init("fixture/saved-resume-input");
            for ([_][]const u8{ paths.operation_state_logical, paths.exact_plan_logical, paths.exact_lock_logical }) |path_text| {
                const path = try root_fs.Path.init(path_text[1..]);
                try root.rename(path, saved, .fail_if_exists);
                try std.testing.expectError(error.FileNotFound, resumeNativeRepository(allocator, input, dependencies));
                try std.testing.expect(try root.entryIfExists(path) == null);
                try root.rename(saved, path, .fail_if_exists);
            }
            try std.testing.expectEqual(caller, attempt.record().digest_sha256);
            if (case == .success) {
                var fail_index: usize = 0;
                while (true) : (fail_index += 1) {
                    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
                    if (NativeRepositoryInputs.read(failing.allocator(), input, .package)) |value| {
                        var original = value;
                        original.deinit();
                        try std.testing.expect(!failing.has_induced_failure);
                        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
                        break;
                    } else |_| {
                        // Existing document codecs may classify an allocation
                        // failure as invalid input instead of OutOfMemory.
                        try std.testing.expect(failing.has_induced_failure);
                    }
                    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
                }
            }
            if (case == .interrupted) {
                var clock: RepositoryExecutionClock = .{ .root = root, .expire_on_call = 5 };
                changed = input;
                changed.deadline = clock.deadline();
                var pending = try resumeNativeRepository(allocator, changed, dependencies);
                defer pending.deinit();
                try std.testing.expect(pending == .pending);
                try std.testing.expectEqualStrings("deadline_exceeded", pending.pending.detail);
                try std.testing.expect(pending.pending.receipt == null);
                try std.testing.expect(try root.entryIfExists(try root_fs.Path.init("repository-trace")) == null);
            }
        }
        if (refresh_retry) {
            acquisition.advance_ms_per_read = 1000;
            try std.testing.expectError(error.DeadlineExceeded, resumeNativeRepository(allocator, input, dependencies));
            try std.testing.expectEqual(caller, attempt.record().digest_sha256);
            try std.testing.expectEqual(root_operation.Outcome.pending, attempt.record().outcome);
        } else {
            const Observer = struct {
                input: NativeRecoveryRequest,
                fail_at: ?NativeCompletionPoint,

                fn hit(raw: *anyopaque, point: NativeCompletionPoint) !void {
                    const self: *@This() = @ptrCast(@alignCast(raw));
                    const target = self.input.attempt.coordinator.root;
                    if (point == .after_final_state and
                        try target.entryIfExists(try root_fs.Path.init("fixture/repository-pending-caller.json")) == null)
                    {
                        const pending = try self.input.attempt.record().canonicalJson(std.testing.allocator);
                        defer std.testing.allocator.free(pending);
                        try target.publishFile(try root_fs.Path.init("fixture/repository-pending-caller.json"), pending, .{});
                        var receipt = (try native_runtime.readCompletion(std.testing.allocator, self.input.attempt)).?;
                        defer receipt.deinit();
                        const receipt_bytes = try receipt.document.canonicalJson(std.testing.allocator);
                        defer std.testing.allocator.free(receipt_bytes);
                        try target.publishFile(try root_fs.Path.init("fixture/repository-native-receipt.json"), receipt_bytes, .{ .overwrite = .replace });
                        var paths = try ResolvedPaths.init(std.testing.allocator, self.input.repository, .native);
                        defer paths.deinit();
                        try target.publishFile(try root_fs.Path.init("fixture/repository-retained-receipt-path"), paths.provenance_logical, .{ .overwrite = .replace });
                    }
                    if (point == .before_clear) {
                        const completed = try self.input.attempt.record().canonicalJson(std.testing.allocator);
                        defer std.testing.allocator.free(completed);
                        try target.publishFile(try root_fs.Path.init("fixture/repository-completed-caller.json"), completed, .{});
                    }
                    if (self.fail_at == point) return error.InjectedNativeCompletionFailure;
                }
            };
            var observer: Observer = .{
                .input = input,
                .fail_at = switch (step) {
                    0 => .after_provenance,
                    1 => .after_native_acknowledgment,
                    else => null,
                },
            };
            const hooks: NativeCompletionObserver = .{ .context = &observer, .hitFn = Observer.hit };
            if (observer.fail_at != null) {
                try std.testing.expectError(error.InjectedNativeCompletionFailure, resumeNativeRepositoryObserved(allocator, input, dependencies, hooks));
                try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) != null);
            } else {
                var result = try resumeNativeRepositoryObserved(allocator, input, dependencies, hooks);
                defer result.deinit();
                try std.testing.expect(result == .completed);
                try std.testing.expectError(error.HistoricalCallerNotClean, readNativeRepositoryHistory(allocator, input));
                try std.testing.expectEqual(case == .known_failure, result.completed.checkpoint.package_state == .failed);
                try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) == null);
                var counting = std.testing.FailingAllocator.init(allocator, .{});
                {
                    var repeated = try resumeNativeRepository(counting.allocator(), input, dependencies);
                    defer repeated.deinit();
                    try std.testing.expect(repeated == .completed);
                    try std.testing.expectEqual(result.completed.completion.document.digest_sha256, repeated.completed.completion.document.digest_sha256);
                }
                try std.testing.expectEqual(counting.allocated_bytes, counting.freed_bytes);
                for ([_]usize{ 0, counting.alloc_index - 1 }) |index| {
                    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = index });
                    try std.testing.expectError(error.OutOfMemory, resumeNativeRepository(failing.allocator(), input, dependencies));
                    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
                }
            }
            if (step != 0 or case != .success)
                try std.testing.expectEqual(@as(usize, 0), acquisition.in_release_requests);
        }
    }
    try std.testing.expect(attempt.locked());
    try std.testing.expectEqual(@as(usize, 0), acquisition.descriptor_reads);
    try std.testing.expectEqual(@as(usize, 0), acquisition.network_requests);
}

fn testNativeUnchangedRefusals(input: NativeUnchangedRequest, dependencies: NativeImportRefreshDependencies) !void {
    const allocator = std.testing.allocator;
    const root = input.recovery.attempt.coordinator.root;
    const caller = input.recovery.attempt.record().digest_sha256;
    var paths = try ResolvedPaths.init(allocator, input.recovery.repository, .native);
    defer paths.deinit();
    const descriptor_text = try joinLogical(allocator, paths.operation_logical, native_unchanged_descriptor_name);
    defer allocator.free(descriptor_text);
    const evidence_text = try joinLogical(allocator, paths.operation_logical, native_unchanged_evidence_name);
    defer allocator.free(evidence_text);
    const saved = try root_fs.Path.init("fixture/unchanged-saved-input");
    const state_path = try root_fs.Path.init(paths.operation_state_logical[1..]);
    const descriptor_path = try root_fs.Path.init(descriptor_text[1..]);
    const locked = try root.readFileAlloc(allocator, try root_fs.Path.init("fixture/repository-original-locked-state.json"), state_module.maximum_document_bytes);
    defer allocator.free(locked);
    const descriptor = try root.readFileAlloc(allocator, descriptor_path, 1024 * 1024);
    defer allocator.free(descriptor);
    const saved_state = try root_fs.Path.init("fixture/unchanged-saved-state");
    try root.rename(state_path, saved_state, .fail_if_exists);
    try root.publishFile(state_path, locked, .{});
    try root.rename(descriptor_path, saved, .fail_if_exists);
    var offered = input;
    offered.descriptor_archive = descriptor;
    try std.testing.expectError(error.FileNotFound, completeUnchangedNative(allocator, offered, dependencies));
    try std.testing.expect(try root.entryIfExists(descriptor_path) == null);
    try root.rename(saved, descriptor_path, .fail_if_exists);
    try root.removeFile(state_path);
    try root.rename(saved_state, state_path, .fail_if_exists);
    const originals = [_][]const u8{
        paths.operation_state_logical, paths.exact_plan_logical, paths.exact_lock_logical,
        descriptor_text,               evidence_text,            paths.manifest_logical,
    };
    for (originals) |text| {
        const path = try root_fs.Path.init(text[1..]);
        const inode = (try root.entry(path)).inode;
        try root.rename(path, saved, .fail_if_exists);
        try std.testing.expectError(error.FileNotFound, completeUnchangedNative(allocator, input, dependencies));
        try std.testing.expectError(error.FileNotFound, resumeNativeRepository(allocator, input.recovery, dependencies));
        try std.testing.expect(try root.entryIfExists(path) == null);
        try root.createSymbolicLink(path, "/fixture/unchanged-saved-input");
        try std.testing.expectError(error.NotRegularFile, completeUnchangedNative(allocator, input, dependencies));
        try root.removeFile(path);
        try root.rename(saved, path, .fail_if_exists);
        try std.testing.expectEqual(inode, (try root.entry(path)).inode);
    }
    for ([_]struct { path: []const u8, err: anyerror }{
        .{ .path = descriptor_text[1..], .err = error.DescriptorIdentityMismatch },
        .{ .path = evidence_text[1..], .err = error.MissingField },
        .{ .path = repository_execution_source_path, .err = error.ManagedFileMismatch },
        .{ .path = "usr/share/keyrings/microsoft-prod.gpg", .err = error.ManagedFileMismatch },
        .{ .path = paths.manifest_logical[1..], .err = error.ImportedDigestMismatch },
    }) |item| {
        const path = try root_fs.Path.init(item.path);
        try root.rename(path, saved, .fail_if_exists);
        try root.publishFile(path, "{}", .{});
        try std.testing.expectError(item.err, completeUnchangedNative(allocator, input, dependencies));
        try root.removeFile(path);
        try root.rename(saved, path, .fail_if_exists);
    }
    for ([_]struct { path: []const u8, err: anyerror }{
        .{ .path = native_recovery.intent_path, .err = error.RecoveryRequired },
        .{ .path = root_operation.deferred_ack_path, .err = error.OperationNotSettled },
        .{ .path = paths.provenance_logical[1..], .err = error.OperationNotSettled },
    }) |item| {
        const path = try root_fs.Path.init(item.path);
        try std.testing.expect(try root.entryIfExists(path) == null);
        try root.publishFile(path, "foreign evidence", .{});
        try std.testing.expectError(item.err, completeUnchangedNative(allocator, input, dependencies));
        try root.removeFile(path);
    }
    var changed = input;
    changed.recovery.repository.resources.maximum_actions += 1;
    try std.testing.expectError(error.RepositoryCallerMismatch, completeUnchangedNative(allocator, changed, dependencies));
    const status_path = try root_fs.Path.init("var/lib/dpkg/status");
    const status = try root.readFileAlloc(allocator, status_path, 64 * 1024);
    defer allocator.free(status);
    const unheld = try std.mem.replaceOwned(u8, allocator, status, "Status: hold ok installed", "Status: install ok installed");
    defer allocator.free(unheld);
    try std.testing.expect(!std.mem.eql(u8, status, unheld));
    try root.rename(status_path, saved, .fail_if_exists);
    try root.publishFile(status_path, unheld, .{});
    try std.testing.expectError(error.NativeUnchangedEvidenceMismatch, completeUnchangedNative(allocator, input, dependencies));
    try root.removeFile(status_path);
    try root.rename(saved, status_path, .fail_if_exists);
    const Observer = struct {
        root: root_fs.Root,
        path: root_fs.Path,
        point: NativeUnchangedPoint,
        fn hit(raw: *anyopaque, point: NativeUnchangedPoint) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (point != self.point) return;
            const bytes = try self.root.readFileAlloc(std.testing.allocator, self.path, exact_lock_v2.maximum_document_bytes);
            defer std.testing.allocator.free(bytes);
            try self.root.rename(self.path, try root_fs.Path.init("fixture/unchanged-saved-input"), .fail_if_exists);
            try self.root.publishFile(self.path, bytes, .{});
        }
    };
    for (originals, 0..) |text, index| {
        const path = try root_fs.Path.init(text[1..]);
        var observer: Observer = .{ .root = root, .path = path, .point = if (index == originals.len - 1) .after_complete else .after_installed };
        try std.testing.expectError(error.PathChanged, completeUnchangedNativeObserved(allocator, input, dependencies, .{ .context = &observer, .hitFn = Observer.hit }));
        try root.removeFile(path);
        try root.rename(saved, path, .fail_if_exists);
    }
    const Expire = struct {
        clock: RepositoryExecutionClock,
        fn hit(raw: *anyopaque, point: NativeUnchangedPoint) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (point == .after_complete) self.clock.expired = true;
        }
    };
    var expiry: Expire = .{ .clock = .{ .root = root } };
    changed = input;
    changed.recovery.deadline = expiry.clock.deadline();
    try std.testing.expectError(error.DeadlineExceeded, completeUnchangedNativeObserved(allocator, changed, dependencies, .{ .context = &expiry, .hitFn = Expire.hit }));
    try std.testing.expectEqual(caller, input.recovery.attempt.record().digest_sha256);
}

fn testProjectedNativeUnchanged(projection: *const live_root.Projection, no_refresh: bool, pass: usize) !void {
    const allocator = std.testing.allocator;
    if (pass == 0) try executeProjectedRepositoryCase(.unchanged, projection);
    var named = try root_fs.openAbsoluteRoot(std.testing.io, live_root.logical_root_path);
    defer named.close();
    const root = named.root;
    const request_path = try root_fs.Path.init("fixture/repository-original-request.json");
    const request_bytes = try root.readFileAlloc(allocator, request_path, api.maximum_document_bytes);
    defer allocator.free(request_bytes);
    var request = try std.json.parseFromSlice(api.Request, allocator, request_bytes, .{});
    defer request.deinit();
    request.value.no_refresh = no_refresh;
    var archive: ?[]u8 = null;
    defer if (archive) |bytes| allocator.free(bytes);
    if (pass == 0) {
        archive = try root.readFileAlloc(allocator, try root_fs.Path.init("fixture/unchanged-descriptor.deb"), 1024 * 1024);
        const original = try std.json.Stringify.valueAlloc(allocator, request.value, .{});
        defer allocator.free(original);
        try root.publishFile(request_path, original, .{ .overwrite = .replace });
        try stageNativePreparationDatabase(root, native_architecture_status ++ native_preparation_held_status ++
            "Package: debz-native-repository\nStatus: install ok installed\nArchitecture: all\nVersion: 1.0\nDescription: repository descriptor\n\n");
        try root.createDirectoryPath(try root_fs.Path.init("etc/apt/sources.list.d"), .fromMode(0o755));
        try root.createDirectoryPath(try root_fs.Path.init("usr/share/keyrings"), .fromMode(0o755));
        try root.createDirectoryPath(try root_fs.Path.init("usr/share/doc/debz-native-repository"), .fromMode(0o755));
        try root.publishFile(try root_fs.Path.init(repository_execution_source_path), test_repository_source, .{});
        try root.publishFile(try root_fs.Path.init("usr/share/keyrings/microsoft-prod.gpg"), &@import("fixtures/openpgp.zig").keyring, .{});
        try root.publishFile(try root_fs.Path.init("usr/share/doc/debz-native-repository/README"), "native repository execution\n", .{});
        try root.publishFile(try root_fs.Path.init("var/lib/dpkg/info/debz-native-repository.list"), "/.\n/" ++ repository_execution_source_path ++ "\n/usr/share/keyrings/microsoft-prod.gpg\n/usr/share/doc/debz-native-repository/README\n", .{});
        try root.publishFile(try root_fs.Path.init("var/lib/dpkg/info/debz-native-repository.preinst"), "#!/bin/sh\nprintf 'preinst\\n' >> /repository-trace\n", .{ .permissions = .fromMode(0o755) });
        try root.publishFile(try root_fs.Path.init("var/lib/dpkg/info/debz-native-repository.postinst"), "#!/bin/sh\nprintf 'postinst\\n' >> /repository-trace\n", .{ .permissions = .fromMode(0o755) });
        const artifact: package_origin.LocalArtifactEvidence = .{
            .artifact_id = package_origin.artifactIdFromSha256(sha256(archive.?)),
            .sha256 = sha256(archive.?),
            .size = archive.?.len,
            .package = "debz-native-repository",
            .version = "1.0",
            .architecture = "all",
            .acquisition_url = request.value.descriptor_url,
            .trust_mode = .pinned_sha256,
        };
        var fixture = BindingFixture.init(artifact);
        var plan = fixture.plan();
        plan.actions = &.{};
        plan.ordered_actions = &.{};
        plan.summary = .{};
        plan.download_bytes = 0;
        var lock = try exact_lock_v2.create(allocator, .{
            .target_architecture = plan.target_architecture,
            .request_sha256 = try operationRequestDigest(allocator, request.value, plan, .native),
            .policy_sha256 = repositoryLockPolicyDigest(.native),
            .repositories = &.{},
            .local_artifacts = &.{artifact},
            .verified_origins = true,
            .packages = &.{.{
                .name = artifact.package,
                .version = artifact.version,
                .architecture = artifact.architecture,
                .origin = .{ .local_artifact = artifact },
                .sha256 = artifact.sha256,
                .declared_size = artifact.size,
                .retention = .requested,
                .dpkg_selection_hold = false,
            }},
        });
        defer lock.deinit();
        try stageRepositoryNativeLockedInputs(root, request.value, plan, lock.lock, artifact);
        const status = try root.readFileAlloc(allocator, try root_fs.Path.init("var/lib/dpkg/status"), 64 * 1024);
        defer allocator.free(status);
        try root.publishFile(try root_fs.Path.init("fixture/unchanged-original-status"), status, .{});
    }
    var guard: RootOperationGuard = .{ .io = std.testing.io, .allocator = allocator, .root_projection = projection };
    defer guard.deinit();
    try std.testing.expect(guard.open(request.value, .native, 1_700_000_000) == null);
    const attempt = guard.active().?;
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = &.{}, .descriptor_available = false };
    const input: NativeUnchangedRequest = .{
        .recovery = .{
            .repository = request.value,
            .attempt = attempt,
            .deadline = .{ .context = &acquisition, .nowMsFn = RepositoryTestAcquisition.nowMilliseconds, .expires_at_ms = 1000 },
        },
        .descriptor_archive = archive,
    };
    const dependencies: NativeImportRefreshDependencies = .{
        .acquisition = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    if (pass == 6) try testNativeUnchangedRefusals(input, dependencies);
    if (pass == 8 or pass == 9) {
        const Revoke = struct {
            point: NativeUnchangedPoint,
            fn hit(raw: *anyopaque, point: NativeUnchangedPoint) !void {
                const self: *@This() = @ptrCast(@alignCast(raw));
                if (point == self.point) try live_root.testing.replaceMountNamespace();
            }
        };
        var observer: Revoke = .{ .point = if (pass == 8) .after_descriptor else .after_complete };
        try std.testing.expectError(error.InvalidRoot, completeUnchangedNativeObserved(allocator, input, dependencies, .{ .context = &observer, .hitFn = Revoke.hit }));
        try std.testing.expect(attempt.locked() and !attempt.record().mutation_started);
        return;
    }
    if (pass == 0) {
        var missing = input;
        missing.descriptor_archive = null;
        try std.testing.expectError(error.NativeDescriptorMissing, completeUnchangedNative(allocator, missing, dependencies));
        missing = input;
        missing.descriptor_archive = "not the descriptor";
        try std.testing.expectError(error.DescriptorIdentityMismatch, completeUnchangedNative(allocator, missing, dependencies));
        missing = input;
        missing.recovery.deadline.expires_at_ms = 0;
        try std.testing.expectError(error.DeadlineExceeded, completeUnchangedNative(allocator, missing, dependencies));
    }
    if (pass < 6) {
        if (pass == 2 and !no_refresh) {
            acquisition.fail_in_release_request = 1;
            try std.testing.expectError(error.RepositoryRefreshFailed, completeUnchangedNative(allocator, input, dependencies));
            acquisition.fail_in_release_request = null;
        }
        const Observer = struct {
            point: NativeUnchangedPoint,
            fn hit(raw: *anyopaque, point: NativeUnchangedPoint) !void {
                const self: *@This() = @ptrCast(@alignCast(raw));
                if (point == self.point) return error.InjectedNativeUnchangedFailure;
            }
        };
        var observer: Observer = .{ .point = std.enums.values(NativeUnchangedPoint)[pass] };
        if (pass == 1) {
            observer.point = .after_evidence;
            try std.testing.expectError(error.InjectedNativeUnchangedFailure, completeUnchangedNativeObserved(allocator, input, dependencies, .{ .context = &observer, .hitFn = Observer.hit }));
            observer.point = .after_installed;
        }
        try std.testing.expectError(error.InjectedNativeUnchangedFailure, completeUnchangedNativeObserved(allocator, input, dependencies, .{ .context = &observer, .hitFn = Observer.hit }));
        if (pass == 0) try root.removeFile(try root_fs.Path.init("fixture/unchanged-descriptor.deb"));
        if (pass == 1) {
            const publisher = try attempt.record().canonicalJson(allocator);
            defer allocator.free(publisher);
            try root.publishFile(try root_fs.Path.init("fixture/unchanged-proof-caller.json"), publisher, .{});
        }
    } else {
        var result = try resumeNativeRepository(allocator, input.recovery, dependencies);
        defer result.deinit();
        try std.testing.expect(result == .unchanged);
        try std.testing.expectEqual(state_module.Phase.complete, result.unchanged.state.state.phase);
        try std.testing.expect(result.unchanged.state.state.installed);
        try std.testing.expectEqual(!no_refresh, result.unchanged.state.state.refreshed);
        try std.testing.expect(std.mem.endsWith(u8, result.unchanged.state.state.provenance_path.?, native_unchanged_evidence_name));
        try std.testing.expectEqual(root_operation.Outcome.abandoned_before_mutation, attempt.record().outcome);
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) == null);
        var repeated = try resumeNativeRepository(allocator, input.recovery, dependencies);
        defer repeated.deinit();
        try std.testing.expect(repeated == .unchanged);
        try std.testing.expectEqual(result.unchanged.state.state.digest_sha256, repeated.unchanged.state.state.digest_sha256);
        try std.testing.expect(result.unchanged.database.eql(repeated.unchanged.database));
        var counting = std.testing.FailingAllocator.init(allocator, .{});
        {
            var measured = try completeUnchangedNative(counting.allocator(), input, dependencies);
            defer measured.deinit();
        }
        try std.testing.expectEqual(counting.allocated_bytes, counting.freed_bytes);
        for ([_]usize{ 0, counting.alloc_index - 1 }) |index| {
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = index });
            if (completeUnchangedNative(failing.allocator(), input, dependencies)) |value| {
                var unexpected = value;
                unexpected.deinit();
                return error.TestExpectedError;
            } else |_| try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        }
        const caller = try attempt.record().canonicalJson(allocator);
        defer allocator.free(caller);
        try root.publishFile(try root_fs.Path.init("fixture/repository-unchanged-caller.json"), caller, .{ .overwrite = .replace });
    }
    try std.testing.expect(!attempt.record().mutation_started and attempt.record().program_sha256 == null);
    try std.testing.expect(attempt.locked());
    try std.testing.expectEqual(@as(usize, 0), acquisition.descriptor_reads);
    try std.testing.expectEqual(@as(usize, 0), acquisition.network_requests);
    try std.testing.expectEqual(@as(usize, if (!no_refresh and pass == 2) 2 else 0), acquisition.in_release_requests);
}

const NativeDispatchCase = enum {
    success,
    no_refresh,
    unchanged,
    unchanged_no_refresh,
    known_failure,
    interrupted,
    completion_interrupted,
    locked_interrupted,
    scope_lost,
    refresh_failure,
    expired,
};

const NativeDispatchClock = struct {
    root: root_fs.Root,
    original: repository_acquisition.Clock,
    stop_on_intent: bool,
    stop_on_completion: bool = false,
    expired: bool = false,
    inspection_error: ?anyerror = null,

    fn now(raw: ?*anyopaque) u64 {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        if (self.stop_on_intent and !self.expired) {
            const entry = self.root.entryIfExists(root_fs.Path.init(native_recovery.intent_path) catch unreachable) catch |err| {
                self.inspection_error = err;
                self.expired = true;
                return std.math.maxInt(u64);
            };
            self.expired = entry != null;
        }
        if (self.stop_on_completion and !self.expired) {
            const bytes = self.root.readFileAlloc(std.testing.allocator, root_fs.Path.init(root_operation.record_path) catch unreachable, root_operation.maximum_document_bytes) catch |err| switch (err) {
                error.FileNotFound => return self.original.nowMs(),
                else => {
                    self.inspection_error = err;
                    self.expired = true;
                    return std.math.maxInt(u64);
                },
            };
            defer std.testing.allocator.free(bytes);
            var record = root_operation.decode(std.testing.allocator, bytes, root_operation.maximum_document_bytes) catch |err| {
                self.inspection_error = err;
                self.expired = true;
                return std.math.maxInt(u64);
            };
            defer record.deinit();
            self.expired = record.record.state == .completed and record.record.mutation_started;
        }
        return if (self.expired) std.math.maxInt(u64) else self.original.nowMs();
    }
};

const NativeDispatchInterruption = struct {
    root: root_fs.Root,
    state_path: root_fs.Path,
    scope_lost: bool,
    locked_interrupted: bool,
    fired: bool = false,

    fn hit(raw: ?*anyopaque, boundary: state_module.WriteBoundary) !void {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        if (self.fired or boundary != .after_rename) return;
        if (self.scope_lost) {
            self.fired = true;
            return live_root.testing.replaceMountNamespace();
        }
        if (self.locked_interrupted) {
            const bytes = try self.root.readFileAlloc(std.testing.allocator, self.state_path, state_module.maximum_document_bytes);
            defer std.testing.allocator.free(bytes);
            var state = try state_module.decode(std.testing.allocator, bytes, state_module.maximum_document_bytes);
            defer state.deinit();
            if (state.state.phase == .locked) {
                self.fired = true;
                return error.InterruptedNativeLockedState;
            }
        }
    }
};

fn testProjectedNativeDispatch(projection: *const live_root.Projection, case: NativeDispatchCase, pass: usize) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var named = try root_fs.openAbsoluteRoot(io, live_root.logical_root_path);
    defer named.close();
    const root = named.root;
    const unchanged = case == .unchanged or case == .unchanged_no_refresh;
    const archive = try repositoryExecutionArchive(allocator, if (case == .known_failure) .known_failure else .success);
    defer allocator.free(archive);
    const request: api.Request = .{
        .root = live_root.logical_root_path,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(archive),
        .no_refresh = case == .no_refresh or case == .unchanged_no_refresh,
        .network = .{ .overall_timeout_ms = 120_000 },
    };
    if (pass == 0) {
        try stageNativePreparationDatabase(root, if (unchanged)
            native_architecture_status ++ native_preparation_held_status ++
                "Package: debz-native-repository\nStatus: hold ok installed\nArchitecture: all\nVersion: 1.0\nDescription: repository descriptor\n\n"
        else
            native_architecture_status ++ native_preparation_held_status);
        try root.publishFile(try root_fs.Path.init("var/lib/dpkg/arch"), "amd64\n", .{});
        try root.publishFile(try root_fs.Path.init("var/lib/dpkg/info/dpkg.list"), "/.\n", .{});
        if (unchanged) {
            try root.createDirectoryPath(try root_fs.Path.init("etc/apt/sources.list.d"), .fromMode(0o755));
            try root.createDirectoryPath(try root_fs.Path.init("usr/share/keyrings"), .fromMode(0o755));
            try root.createDirectoryPath(try root_fs.Path.init("usr/share/doc/debz-native-repository"), .fromMode(0o755));
            try root.publishFile(try root_fs.Path.init(repository_execution_source_path), test_repository_source, .{});
            try root.publishFile(try root_fs.Path.init("usr/share/keyrings/microsoft-prod.gpg"), &@import("fixtures/openpgp.zig").keyring, .{});
            try root.publishFile(try root_fs.Path.init("usr/share/doc/debz-native-repository/README"), "native repository execution\n", .{});
            try root.publishFile(try root_fs.Path.init("var/lib/dpkg/info/debz-native-repository.list"), "/.\n/" ++ repository_execution_source_path ++ "\n/usr/share/keyrings/microsoft-prod.gpg\n/usr/share/doc/debz-native-repository/README\n", .{});
        }
        const before = try root.readFileAlloc(allocator, try root_fs.Path.init("var/lib/dpkg/status"), 64 * 1024);
        defer allocator.free(before);
        try root.publishFile(try root_fs.Path.init("fixture/dispatch-original-status"), before, .{});
    }
    const reacquire = pass == 0 or (pass == 1 and
        (case == .expired or case == .scope_lost or case == .locked_interrupted));
    var acquisition: RepositoryTestAcquisition = .{
        .descriptor = if (reacquire) archive else &.{},
        .descriptor_available = reacquire,
        .fail_in_release_request = if (case == .refresh_failure and pass == 0) 2 else null,
        .advance_ms_per_read = if (case == .expired and pass == 0) request.network.overall_timeout_ms else 0,
    };
    var clock: NativeDispatchClock = .{
        .root = root,
        .original = acquisition.dependencies().clock,
        .stop_on_intent = case == .interrupted and pass == 0,
        .stop_on_completion = case == .completion_interrupted and pass == 0,
    };
    var dependencies = acquisition.dependencies();
    dependencies.clock.context = &clock;
    dependencies.clock.nowMsFn = NativeDispatchClock.now;
    var paths = try ResolvedPaths.init(allocator, request, .native);
    defer paths.deinit();
    var interruption: NativeDispatchInterruption = .{
        .root = root,
        .state_path = try root_fs.Path.init(paths.operation_state_logical[1..]),
        .scope_lost = case == .scope_lost and pass == 0,
        .locked_interrupted = case == .locked_interrupted and pass == 0,
    };
    var forbidden: struct {
        fn run(_: *anyopaque, _: transaction_executor.Invocation) !transaction_executor.ProcessResult {
            return error.LegacyProcessForbidden;
        }
    } = .{};
    var backend: Backend = .{
        .io = io,
        .transaction_backend = .native,
        .root_projection = projection,
        .process_runner = .{ .context = &forbidden, .runFn = @TypeOf(forbidden).run },
        .acquisition_dependencies = dependencies,
        .now_unix = 1_700_000_000,
        .state_write_hooks = .{ .context = &interruption, .runFn = NativeDispatchInterruption.hit },
    };
    var result = try api.execute(allocator, request, backend.nativeInterface());
    defer result.deinit();
    const expected_failure = case == .known_failure or
        (pass == 0 and (case == .interrupted or case == .completion_interrupted or
            case == .locked_interrupted or case == .scope_lost or case == .refresh_failure or case == .expired));
    if ((result.exit_status == .success) == expected_failure) {
        std.debug.print("native dispatch {t} pass={d}: {s}\n", .{ case, pass, result.summary });
        return error.UnexpectedNativeDispatchResult;
    }
    try std.testing.expect(clock.inspection_error == null);
    try std.testing.expectEqual(@as(usize, 0), acquisition.network_requests);
    try std.testing.expectEqual(@as(usize, @intFromBool(reacquire and !(case == .scope_lost and pass == 0))), acquisition.descriptor_reads);
    try std.testing.expectEqual(pass == 0 and (case == .scope_lost or case == .locked_interrupted), interruption.fired);
    if (case == .refresh_failure and pass == 0) {
        try std.testing.expect(result.installed and result.changed);
        try std.testing.expectEqual(api.DiagnosticId.refresh_failed, result.diagnostics[0].id);
    }
    if (!expected_failure) {
        try std.testing.expect(result.installed);
        try std.testing.expectEqual(!request.no_refresh, result.refreshed);
        try std.testing.expectEqual(!unchanged and
            (pass == 0 or (pass == 1 and (case == .interrupted or case == .completion_interrupted or
                case == .locked_interrupted or case == .scope_lost or case == .refresh_failure or case == .expired))), result.changed);
    }
    const result_name = try std.fmt.allocPrint(allocator, "fixture/native-dispatch-{d}.json", .{pass});
    defer allocator.free(result_name);
    const result_bytes = try result.canonicalJson(allocator);
    defer allocator.free(result_bytes);
    try root.publishFile(try root_fs.Path.init(result_name), result_bytes, .{});
    if (case == .scope_lost and pass == 0) return;
    const cache_path = try root_fs.Path.init("var/cache/debz/packages-v1/objects");
    var objects = try root.openDirectory(cache_path);
    defer objects.close(io);
    const object = std.fmt.bytesToHex(request.expected_sha256.?, .lower);
    objects.deleteFile(io, &object) catch |err| switch (err) {
        error.FileNotFound => if (case != .expired and pass == 0) return err,
        else => return err,
    };
    if (pass != 0 or (case != .interrupted and case != .completion_interrupted and case != .refresh_failure))
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) == null);
}

test "repository backend typed native dispatch requires scoped explicit selection" {
    const request: api.Request = .{ .root = "/does-not-exist-native-dispatch", .descriptor_url = "https://example.test/descriptor.deb" };
    inline for (.{ transaction_engine.Kind.legacy_dpkg, transaction_engine.Kind.native }) |kind| {
        var backend: Backend = .{ .io = std.testing.io, .transaction_backend = kind };
        var result = try api.execute(std.testing.allocator, request, backend.nativeInterface());
        defer result.deinit();
        try std.testing.expectEqual(api.ExitStatus.unavailable, result.exit_status);
        try std.testing.expectEqual(api.DiagnosticId.transaction_backend_unavailable, result.diagnostics[0].id);
    }
}

fn testUnchangedDescriptorPlan(allocator: std.mem.Allocator) !void {
    var plan = try unchangedDescriptorPlan(allocator, "amd64");
    defer plan.deinit();
    const bytes = plan.canonicalJson(allocator) catch |err|
        return if (err == error.WriteFailed) error.OutOfMemory else err;
    defer allocator.free(bytes);
    var restored = try repository_plan.decode(allocator, bytes);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 0), restored.actions.len);
    try std.testing.expectEqual(@as(usize, 0), restored.ordered_actions.len);
    try std.testing.expectEqual(transaction_executor.planDigest(plan), transaction_executor.planDigest(restored));
}

test "repository backend unchanged descriptor planning owns its empty executable inputs" {
    try testUnchangedDescriptorPlan(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testUnchangedDescriptorPlan, .{});
}

test "repository backend native execution external fixture" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const enabled = std.c.getenv("DEBZ_NATIVE_REPOSITORY_EXECUTION_FIXTURE") orelse return error.SkipZigTest;
    if (!std.mem.eql(u8, std.mem.span(enabled), "1") or std.os.linux.getpid() != 1)
        return error.InvalidProjectionFixture;
    var root = try root_fs.openAbsoluteRoot(std.testing.io, "/");
    defer root.close();
    const marker = try root.root.readFileAlloc(std.testing.allocator, try root_fs.Path.init(".debz-native-projection"), 128);
    defer std.testing.allocator.free(marker);
    if (!std.mem.eql(u8, marker, "debz native projection fixture v1\n")) return error.InvalidProjectionFixture;
    const case_bytes = try root.root.readFileAlloc(std.testing.allocator, try root_fs.Path.init("fixture/repository-execution-case"), 128);
    defer std.testing.allocator.free(case_bytes);
    const case = std.meta.stringToEnum(RepositoryExecutionCase, case_bytes) orelse return error.InvalidProjectionFixture;
    if (try root.root.entryIfExists(try root_fs.Path.init("fixture/repository-dispatch")) != null) {
        const mode = try root.root.readFileAlloc(std.testing.allocator, try root_fs.Path.init("fixture/repository-dispatch"), 64);
        defer std.testing.allocator.free(mode);
        const dispatch_case = std.meta.stringToEnum(NativeDispatchCase, mode) orelse return error.InvalidProjectionFixture;
        const Callback = struct {
            case: NativeDispatchCase,
            pass: usize,
            fn run(raw: ?*anyopaque, projection: *const live_root.Projection) !u8 {
                const self: *@This() = @ptrCast(@alignCast(raw.?));
                try testProjectedNativeDispatch(projection, self.case, self.pass);
                return 0;
            }
        };
        for (0..3) |pass| {
            var callback: Callback = .{ .case = dispatch_case, .pass = pass };
            const result = try live_root.runProjected(.{ .context = &callback, .child = Callback.run });
            if (result != .exited or result.exited != 0) {
                std.debug.print("repository dispatch {t} pass={d}: {any}\n", .{ dispatch_case, pass, result });
                return error.InvalidProjectionFixture;
            }
        }
        try root.root.publishFile(try root_fs.Path.init("fixture/repository-execution-complete"), mode, .{});
        return;
    }
    if (try root.root.entryIfExists(try root_fs.Path.init("fixture/repository-unchanged-bootstrap")) != null) {
        const mode = try root.root.readFileAlloc(std.testing.allocator, try root_fs.Path.init("fixture/repository-unchanged-bootstrap"), 32);
        defer std.testing.allocator.free(mode);
        const Callback = struct {
            no_refresh: bool,
            pass: usize,
            fn run(raw: ?*anyopaque, projection: *const live_root.Projection) !u8 {
                const self: *@This() = @ptrCast(@alignCast(raw.?));
                try testProjectedNativeUnchanged(projection, self.no_refresh, self.pass);
                return 0;
            }
        };
        for (0..11) |pass| {
            var callback: Callback = .{ .no_refresh = std.mem.eql(u8, mode, "no-refresh"), .pass = pass };
            const result = try live_root.runProjected(.{ .context = &callback, .child = Callback.run });
            if (result != .exited or result.exited != 0) {
                std.debug.print("repository unchanged pass={d}: {any}\n", .{ pass, result });
                return error.InvalidProjectionFixture;
            }
        }
        try root.root.publishFile(try root_fs.Path.init("fixture/repository-execution-complete"), case_bytes, .{});
        return;
    }
    const resume_repository = try root.root.entryIfExists(try root_fs.Path.init("fixture/repository-resume")) != null;
    const Callback = struct {
        case: RepositoryExecutionCase,
        recover: bool,
        revoke_scope: ?RepositoryReceiptScope,
        fn run(raw: ?*anyopaque, projection: *const live_root.Projection) !u8 {
            const self: *const @This() = @ptrCast(@alignCast(raw.?));
            if (self.recover)
                try recoverProjectedRepositoryCase(self.case, projection, self.revoke_scope)
            else
                try executeProjectedRepositoryCase(self.case, projection);
            return 0;
        }
    };
    const terminal = case == .success or case == .known_failure or case == .interrupted;
    for (0..if (resume_repository) @as(usize, 1) else if (case == .success) @as(usize, 8) else if (terminal) @as(usize, 3) else 1) |index| {
        var callback: Callback = .{
            .case = case,
            .recover = index != 0,
            .revoke_scope = if (case == .success) switch (index) {
                3 => .retain,
                4 => .read,
                5 => .verify,
                6 => .checkpoint,
                else => null,
            } else null,
        };
        const result = try live_root.runProjected(.{ .context = &callback, .child = Callback.run });
        if (result != .exited or result.exited != 0) {
            std.debug.print("repository execution case {t}, recovery={}: {any}\n", .{ case, callback.recover, result });
            return error.InvalidProjectionFixture;
        }
    }
    if (resume_repository) {
        const ResumeCallback = struct {
            case: RepositoryExecutionCase,
            pass: usize,
            fn run(raw: ?*anyopaque, projection: *const live_root.Projection) !u8 {
                const self: *const @This() = @ptrCast(@alignCast(raw.?));
                try testProjectedNativeResume(self.case, projection, self.pass);
                return 0;
            }
        };
        for (0..if (case == .success) @as(usize, 8) else if (terminal) @as(usize, 4) else 1) |pass| {
            var callback: ResumeCallback = .{ .case = case, .pass = pass };
            const result = try live_root.runProjected(.{ .context = &callback, .child = ResumeCallback.run });
            if (result != .exited or result.exited != 0) {
                std.debug.print("repository resume case {t}, pass={d}: {any}\n", .{ case, pass, result });
                return error.InvalidProjectionFixture;
            }
        }
    } else if (terminal) {
        const ImportCallback = struct {
            case: RepositoryExecutionCase,
            pass: usize,
            fn run(raw: ?*anyopaque, projection: *const live_root.Projection) !u8 {
                const self: *const @This() = @ptrCast(@alignCast(raw.?));
                try testProjectedNativeImport(self.case, projection, self.pass);
                return 0;
            }
        };
        for (0..if (case == .success) @as(usize, 3) else 2) |pass| {
            var callback: ImportCallback = .{ .case = case, .pass = pass };
            const result = try live_root.runProjected(.{ .context = &callback, .child = ImportCallback.run });
            if (result != .exited or result.exited != 0) {
                std.debug.print("repository import case {t}, pass={d}: {any}\n", .{ case, pass, result });
                return error.InvalidProjectionFixture;
            }
        }
        const CompletionCallback = struct {
            case: RepositoryExecutionCase,
            pass: usize,
            fn run(raw: ?*anyopaque, projection: *const live_root.Projection) !u8 {
                const self: *const @This() = @ptrCast(@alignCast(raw.?));
                try testProjectedNativeCompletion(self.case, projection, self.pass);
                return 0;
            }
        };
        for (0..if (case == .success) @as(usize, 11) else 4) |pass| {
            var callback: CompletionCallback = .{ .case = case, .pass = pass };
            const result = try live_root.runProjected(.{ .context = &callback, .child = CompletionCallback.run });
            if (result != .exited or result.exited != 0) {
                std.debug.print("repository completion case {t}, pass={d}: {any}\n", .{ case, pass, result });
                return error.InvalidProjectionFixture;
            }
        }
    }
    try root.root.publishFile(try root_fs.Path.init("fixture/repository-execution-complete"), case_bytes, .{});
}

fn projectedRepositoryCaller(case: ProjectedRepositoryCase, projection: *const live_root.Projection) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var named = try root_fs.openAbsoluteRoot(io, live_root.logical_root_path);
    defer named.close();
    const root = named.root;
    const bytes = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const request: api.Request = .{
        .root = live_root.logical_root_path,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(bytes),
    };
    if (case == .prepare) {
        var backend: Backend = .{ .io = io, .transaction_backend = .native, .root_projection = projection };
        var gated = try backend.execute(allocator, request);
        defer gated.deinit();
        try std.testing.expectEqual(api.DiagnosticId.transaction_backend_unavailable, gated.diagnostics[0].id);
        try std.testing.expect(backend.root_projection == projection);
        for ([_]struct { path: []const u8, authority: ?*const live_root.Projection }{
            .{ .path = live_root.logical_root_path, .authority = null },
            .{ .path = "/", .authority = projection },
            .{ .path = "/fixture", .authority = projection },
        }) |invalid| {
            var rejected: RootOperationGuard = .{
                .io = io,
                .allocator = allocator,
                .root_projection = invalid.authority,
            };
            defer rejected.deinit();
            var changed = request;
            changed.root = invalid.path;
            var failure = rejected.open(changed, .native, 1_700_000_000) orelse return error.TestUnexpectedResult;
            defer failure.deinit();
            try std.testing.expectEqual(api.DiagnosticId.invalid_root, failure.diagnostics[0].id);
            try std.testing.expect(rejected.active() == null);
        }
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.namespace_path)) == null);
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init("fixture/var/lib/debz")) == null);
        try stageNativePreparationDatabase(root, native_architecture_status ++ native_preparation_held_status);
        try root.publishFile(try root_fs.Path.init("var/lib/dpkg/arch"), "amd64\ni386\narm64\n", .{});
        try root.publishFile(try root_fs.Path.init("var/lib/dpkg/info/dpkg.list"), "/.\n", .{});

        try root.dir.createDirPath(io, "fixture/legacy");
        var legacy: RootOperationGuard = .{ .io = io, .allocator = allocator, .root_projection = projection };
        defer legacy.deinit();
        var legacy_request = request;
        legacy_request.root = "/fixture/legacy";
        try std.testing.expect(legacy.open(legacy_request, .legacy_dpkg, 1_700_000_000) == null);
        try std.testing.expect(legacy.coordinator.root_projection == null);
    }
    var guard: RootOperationGuard = .{ .io = io, .allocator = allocator, .root_projection = projection };
    defer guard.deinit();
    var observer_context: u8 = 0;
    if (case == .after_lock) {
        const Observer = struct {
            fn hit(_: *anyopaque, _: root_operation.AcquisitionPoint) !void {
                try live_root.testing.replaceMountNamespace();
            }
        };
        guard.acquisition_observer = .{ .context = &observer_context, .hitFn = Observer.hit };
        var failure = guard.open(request, .native, 1_700_000_000) orelse return error.TestUnexpectedResult;
        defer failure.deinit();
        try std.testing.expectEqual(api.DiagnosticId.invalid_root, failure.diagnostics[0].id);
        try std.testing.expect(guard.active() == null);
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) == null);
        return;
    }
    try std.testing.expect(guard.open(request, .native, 1_700_000_000) == null);
    const attempt = guard.active().?;
    try std.testing.expect(guard.coordinator.root_projection == projection);
    try std.testing.expectEqual(case == .adopt, attempt.adopted);
    if (case == .adopt) {
        const expected = try root.readFileAlloc(allocator, try root_fs.Path.init("fixture/repository-caller-digest"), 32);
        defer allocator.free(expected);
        try std.testing.expectEqualSlices(u8, expected, &attempt.record().digest_sha256);
    }
    var model = switch (archive_application.prepare(allocator, bytes, .{ .local = .{} }, .{})) {
        .model => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer model.deinit();
    const artifact: package_origin.LocalArtifactEvidence = .{
        .artifact_id = package_origin.artifactIdFromSha256(sha256(bytes)),
        .sha256 = sha256(bytes),
        .size = bytes.len,
        .package = model.facts.package,
        .version = model.facts.version,
        .architecture = model.facts.architecture,
        .acquisition_url = request.descriptor_url,
        .trust_mode = .pinned_sha256,
    };
    var fixture = BindingFixture.init(artifact);
    var plan = fixture.plan();
    var lock = try createOperationLock(allocator, plan, artifact, null, request, .native);
    defer lock.deinit();
    const input: NativePreparationRequest = .{
        .repository = request,
        .attempt = attempt,
        .plan = &plan,
        .exact_lock = &lock.lock,
        .archives = &.{bytes},
    };
    const before = attempt.record().digest_sha256;
    var prepared = try prepareNative(allocator, input);
    defer prepared.deinit();
    try std.testing.expect(prepared == .prepared);
    try std.testing.expectEqual(before, attempt.record().digest_sha256);
    try std.testing.expectEqualDeep(native_architecture_foreign, attempt.record().foreign_architectures);
    try std.testing.expectEqualSlices(u8, &repositoryRequestDigest(request, .native), &attempt.record().request_sha256);
    try std.testing.expectEqualSlices(u8, &repositoryPolicyDigest(request, .native), &attempt.record().policy_sha256);
    if (case == .adopt) {
        try std.testing.expectEqual(
            transaction_executor.planDigest(plan),
            try native_operation.boundPlan(root, attempt, prepared.prepared.program.program),
        );
    } else try native_operation.bind(allocator, root, attempt, prepared.prepared.program.program);
    const bound = attempt.record().digest_sha256;
    if (case != .adopt)
        try root.publishFile(try root_fs.Path.init("fixture/repository-caller-digest"), &bound, .{});
    if (case == .prepare) {
        // Leave the genuine reservation for a separate callback to adopt.
        attempt.release();
        guard.attempt = null;
    } else if (case == .cleanup) {
        try live_root.testing.replaceMountNamespace();
        try std.testing.expectError(error.InvalidProjection, prepareNative(allocator, input));
        guard.deinit();
        var retained = (try root_operation.Store.init(root).read(allocator)).?;
        defer retained.deinit();
        try std.testing.expectEqual(bound, retained.record.digest_sha256);
    } else {
        try std.testing.expectEqual(before, bound);
        guard.deinit();
        try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) == null);
    }
    try std.testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.native_intent_path)) == null);
    const status = try root.readFileAlloc(allocator, try root_fs.Path.init("var/lib/dpkg/status"), 4096);
    defer allocator.free(status);
    try std.testing.expectEqualStrings(native_architecture_status ++ native_preparation_held_status, status);
}

test "repository backend native projected caller external fixture" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const enabled = std.c.getenv("DEBZ_NATIVE_REPOSITORY_PROJECTION_FIXTURE") orelse return error.SkipZigTest;
    if (!std.mem.eql(u8, std.mem.span(enabled), "1") or std.os.linux.getpid() != 1)
        return error.InvalidProjectionFixture;
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
        case: ProjectedRepositoryCase,
        fn run(raw: ?*anyopaque, projection: *const live_root.Projection) !u8 {
            const self: *const @This() = @ptrCast(@alignCast(raw.?));
            try projectedRepositoryCaller(self.case, projection);
            return 0;
        }
    };
    for ([_]ProjectedRepositoryCase{ .prepare, .adopt, .after_lock, .cleanup, .adopt }) |case| {
        var callback: Callback = .{ .case = case };
        const result = try live_root.runProjected(.{ .context = &callback, .child = Callback.run });
        if (result != .exited or result.exited != 0) {
            std.debug.print("repository projection case {t}: {any}\n", .{ case, result });
            return error.InvalidProjectionFixture;
        }
    }
    try root.root.publishFile(
        try root_fs.Path.init("fixture/repository-projection-complete"),
        "native repository projection fixture complete\n",
        .{},
    );
}

test "repository backend native preparation refuses changed caller lock plan and active evidence" {
    for ([_]NativePreparationCase{
        .invalid_request,         .legacy_caller,            .different_surface, .changed_request,
        .wrong_architecture,      .legacy_lock,              .changed_plan,      .sticky_plan,
        .sticky_lock,             .sticky_program,           .active_intent,     .lost_lock,
        .unchanged_active_intent, .unchanged_sticky_program, .not_mutable,
    }) |case| {
        errdefer std.debug.print("native repository preparation case: {t}\n", .{case});
        try testNativePreparation(case);
    }
}

test "repository backend native preparation bounds all simultaneously retained archive bytes" {
    for ([_]NativePreparationCase{
        .retained_limit, .total_limit, .aggregate_retained_limit,
        .package_limit,  .cache_limit, .action_limit,
        .archive_count,
    }) |case| {
        errdefer std.debug.print("native repository budget case: {t}\n", .{case});
        try testNativePreparation(case);
    }
}

const NativeCacheCase = enum {
    execution_unchanged,
    execution_diagnostic,
    local,
    mixed,
    empty,
    retained_limit,
    total_limit,
    package_limit,
    cache_limit,
    declared_overflow,
    changed_request,
    changed_plan,
    legacy_caller,
    legacy_lock,
    invalid_lock_digest,
    active_evidence,
    missing_object,
    corrupt_object,
    invalid_payload,
    expired_before,
    expired_during,
    expired_after,
    lost_lock_after,
    allocation_failures,
};

const NativeCacheClock = struct {
    calls: usize = 0,
    expire_on: ?usize = null,
    lose_on: ?usize = null,
    locks: *root_operation.TestLockBackend,

    fn now(context: ?*anyopaque) u64 {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        if (self.lose_on == self.calls) self.locks.loseAll();
        return if (self.expire_on) |call| (if (self.calls >= call) 10 else 0) else 0;
    }
};

fn testNativeCacheAllocation(input: NativeCachePreparationRequest) !void {
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        if (prepareNativeFromCache(failing.allocator(), input)) |value| {
            var result = value;
            defer result.deinit();
            if (result.preparation == .diagnostic) {
                try std.testing.expect(failing.has_induced_failure);
            } else {
                try std.testing.expect(!failing.has_induced_failure);
                try std.testing.expect(result.preparation == .prepared);
                try std.testing.expectEqual(@as(usize, 2), result.archives.len);
            }
        } else |_| {
            // Lower serializers and preparation can surface allocation failure
            // as writer errors or diagnostics, not only error.OutOfMemory.
            try std.testing.expect(failing.has_induced_failure);
        }
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        if (!failing.has_induced_failure) break;
    }
}

fn testNativeNoExecutionAllocation(input: NativeCachePreparationRequest, diagnostic: bool) !void {
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        if (executeNativeFromCache(failing.allocator(), input)) |value| {
            var result = value;
            defer result.deinit();
            try std.testing.expect(result != .execution);
            if (failing.has_induced_failure) {
                try std.testing.expect(result == .diagnostic);
            } else if (diagnostic) {
                try std.testing.expect(result == .diagnostic);
                try std.testing.expectEqual(.missing_configure_barrier, result.diagnostic.diagnostic.code);
            } else try std.testing.expect(result == .unchanged);
        } else |_| try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        if (!failing.has_induced_failure) break;
    }
}

fn testNativeCachePreparation(case: NativeCacheCase) !void {
    const allocator = std.testing.allocator;
    const descriptor_bytes = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const dependency = try archive_application.test_fixtures.build(allocator, .{
        .data = &.{
            .{ .path = "usr", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/share", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/share/demo", .content = "native dependency\n" },
        },
    });
    defer allocator.free(dependency);
    const dependency_bytes: []const u8 = if (case == .invalid_payload) "invalid deb" else dependency;
    var descriptor_model = switch (archive_application.prepare(allocator, descriptor_bytes, .{ .local = .{} }, .{})) {
        .model => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer descriptor_model.deinit();
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
    defer root_dir.close(std.testing.io);
    const root = root_fs.Root.init(std.testing.io, root_dir);
    try stageNativePreparationDatabase(root, native_preparation_held_status);
    const root_path = try repositoryTestRoot(allocator, directory.dir);
    defer allocator.free(root_path);
    const empty = case == .empty or case == .execution_unchanged;
    const package_count: usize = if (empty) 0 else if (case == .local or case == .execution_diagnostic) 1 else 2;
    const total = descriptor_bytes.len + (if (package_count == 2) dependency_bytes.len else @as(usize, 0));
    const maximum_package = @max(descriptor_bytes.len, dependency_bytes.len);
    var request: api.Request = .{
        .root = root_path,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor_bytes),
        .architecture = "amd64",
        .cache = .{ .maximum_object_bytes = maximum_package },
        .network = .{ .maximum_package_bytes = maximum_package },
        .resources = .{
            .maximum_total_package_bytes = total,
            .maximum_retained_package_bytes = total + descriptor_bytes.len,
        },
    };
    switch (case) {
        .retained_limit => request.resources.maximum_retained_package_bytes -= 1,
        .total_limit => request.resources.maximum_total_package_bytes -= 1,
        .package_limit => request.network.maximum_package_bytes -= 1,
        .declared_overflow => {
            request.cache.maximum_object_bytes = std.math.maxInt(usize);
            request.network.maximum_package_bytes = std.math.maxInt(usize);
            request.resources.maximum_total_package_bytes = std.math.maxInt(u64);
            request.resources.maximum_retained_package_bytes = std.math.maxInt(u64);
        },
        else => {},
    }
    const local: package_origin.LocalArtifactEvidence = .{
        .artifact_id = package_origin.artifactIdFromSha256(sha256(descriptor_bytes)),
        .sha256 = sha256(descriptor_bytes),
        .size = descriptor_bytes.len,
        .package = descriptor_model.facts.package,
        .version = descriptor_model.facts.version,
        .architecture = descriptor_model.facts.architecture,
        .acquisition_url = request.descriptor_url,
        .trust_mode = .pinned_sha256,
    };
    var fixture = BindingFixture.init(local);
    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(0x11);
    var actions = [_]solver.PlanAction{ fixture.actions[0], .{
        .kind = .install,
        .package = "demo",
        .version = "1.0",
        .architecture = "amd64",
        .repository = .{ .id = repository_id, .priority = 500 },
        .sha256 = package_origin.artifactIdFromSha256(sha256(dependency_bytes)),
        .package_size = dependency_bytes.len,
        .installed_size_delta_bytes = 0,
        .source_package = "demo",
        .prior_installed = null,
        .requested = false,
        .reason = .dependency,
        .selected_origin = null,
        .origin = .{ .authenticated_repository = .{ .id = repository_id, .priority = 500 } },
    } };
    var ordered = [_]solver.OrderedAction{
        fixture.ordered_actions[0],
        .{ .sequence = 1, .kind = .unpack, .package = "demo", .version = "1.0", .architecture = "amd64" },
        .{ .sequence = 2, .kind = .configure_pending, .package = "demo", .version = "1.0", .architecture = "amd64" },
    };
    var plan = fixture.plan();
    plan.actions = actions[0..package_count];
    plan.ordered_actions = if (package_count == 0) &.{} else if (package_count == 1) &fixture.ordered_actions else &ordered;
    plan.download_bytes = if (package_count == 0) 0 else total;
    plan.summary = .{ .installs = package_count, .download_bytes = plan.download_bytes };
    if (case == .execution_diagnostic) plan.ordered_actions = fixture.ordered_actions[0..1];
    const packages = [_]exact_lock_v2.Package{
        .{
            .name = local.package,
            .version = local.version,
            .architecture = local.architecture,
            .origin = .{ .local_artifact = local },
            .sha256 = local.sha256,
            .declared_size = local.size,
            .retention = .requested,
            .dpkg_selection_hold = false,
        },
        .{
            .name = "demo",
            .version = "1.0",
            .architecture = "amd64",
            .origin = .{ .authenticated_repository = .{
                .repository_id = repository_id,
                .repository_snapshot_sha256 = snapshot,
            } },
            .sha256 = sha256(dependency_bytes),
            .declared_size = dependency_bytes.len,
            .retention = .dependency,
            .dpkg_selection_hold = false,
        },
    };
    const lock_backend: transaction_engine.Kind = if (case == .legacy_lock) .legacy_dpkg else .native;
    var lock = try exact_lock_v2.create(allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = try operationRequestDigest(allocator, request, plan, lock_backend),
        .policy_sha256 = repositoryLockPolicyDigest(lock_backend),
        .repositories = if (package_count == 2) &.{.{
            .id = repository_id,
            .snapshot_sha256 = snapshot,
            .release_sha256 = @splat(2),
            .index_sha256 = @splat(3),
            .signer_fingerprints = &.{@splat(4)},
        }} else &.{},
        .local_artifacts = if (package_count == 0) &.{} else &.{local},
        .packages = packages[0..package_count],
        .verified_origins = true,
    });
    defer lock.deinit();
    var cache = try package_acquisition.Cache.initFromDir(std.testing.io, directory.dir, .{
        .maximum_object_bytes = request.cache.maximum_object_bytes,
    });
    defer cache.deinit();
    if (package_count != 0 and case != .missing_object)
        try cache.publish(allocator, .{ .bytes = local.sha256 }, local.size, descriptor_bytes, .fail_fast, .{});
    if (package_count == 2)
        try cache.publish(allocator, .{ .bytes = sha256(dependency_bytes) }, dependency_bytes.len, dependency_bytes, .fail_fast, .{});
    var locks: root_operation.TestLockBackend = .{ .allocator = allocator };
    defer locks.deinit();
    var coordinator = try root_operation.Coordinator.open(std.testing.io, root, root_path, locks.interface());
    var attempt = try coordinator.acquire(allocator, .{
        .backend = if (case == .legacy_caller) .legacy_dpkg else .native,
        .operation = .{ .repository_bootstrap = .add },
        .request_sha256 = repositoryRequestDigest(request, .native),
        .policy_sha256 = repositoryPolicyDigest(request, .native),
        .target_architecture = "amd64",
    });
    defer attempt.release();
    const before = attempt.record().digest_sha256;
    var clock: NativeCacheClock = .{
        .locks = &locks,
        .expire_on = switch (case) {
            .expired_before => 1,
            .expired_during => 4,
            .expired_after => 7,
            else => null,
        },
        .lose_on = if (case == .lost_lock_after) 7 else null,
    };
    var input: NativeCachePreparationRequest = .{
        .repository = request,
        .attempt = &attempt,
        .plan = &plan,
        .exact_lock = &lock.lock,
        .cache = &cache,
        .retained_archives = &.{descriptor_bytes},
        .deadline = .{ .context = &clock, .nowMsFn = NativeCacheClock.now, .expires_at_ms = 10 },
    };
    var oversized = packages;
    const key = std.fmt.bytesToHex(local.sha256, .lower);
    switch (case) {
        .changed_request => input.repository.no_refresh = true,
        .changed_plan => actions[0].requested = false,
        .invalid_lock_digest => lock.lock.digest_sha256[0] ^= 1,
        .cache_limit => cache.limits.maximum_object_bytes -= 1,
        .declared_overflow => {
            oversized[0].declared_size = std.math.maxInt(u64);
            lock.lock.packages = &oversized;
        },
        .corrupt_object => try cache.objects.writeFile(std.testing.io, .{ .sub_path = &key, .data = "corrupt" }),
        .active_evidence => try root.publishFile(
            try root_fs.Path.init(@import("native_recovery.zig").intent_path),
            "active native evidence",
            .{},
        ),
        else => {},
    }
    const expected_error: ?anyerror = switch (case) {
        .retained_limit, .total_limit, .package_limit, .cache_limit, .declared_overflow => error.ResourceBudgetExceeded,
        .changed_request => error.RepositoryCallerMismatch,
        .changed_plan => error.RequestEvidenceMismatch,
        .legacy_caller => error.OperationBackendMismatch,
        .legacy_lock => error.LockPolicyMismatch,
        .invalid_lock_digest => error.DigestMismatch,
        .active_evidence => error.RecoveryRequired,
        .missing_object => error.CacheMiss,
        .corrupt_object => error.CorruptObject,
        .invalid_payload => error.InvalidNativeArchive,
        .expired_before, .expired_during, .expired_after => error.DeadlineExceeded,
        .lost_lock_after => error.LockLost,
        else => null,
    };
    if (expected_error) |expected| {
        try std.testing.expectError(expected, prepareNativeFromCache(allocator, input));
        if (expected == error.ResourceBudgetExceeded) {
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
            try std.testing.expectError(expected, prepareNativeFromCache(failing.allocator(), input));
        }
    } else if (case == .allocation_failures) {
        try testNativeCacheAllocation(input);
    } else if (case == .execution_unchanged or case == .execution_diagnostic) {
        try testNativeNoExecutionAllocation(input, case == .execution_diagnostic);
    } else {
        var result = try prepareNativeFromCache(allocator, input);
        defer result.deinit();
        try std.testing.expectEqual(package_count, result.archives.len);
        if (case == .empty) {
            try std.testing.expect(result.preparation == .unchanged);
        } else {
            try std.testing.expect(result.preparation == .prepared);
            const authorization = result.preparation.prepared.authorization.authorization;
            try std.testing.expect(authorization.findFinalPackage("held", "amd64").?.dpkg_selection_hold);
            try std.testing.expect(authorization.findAction("held", "amd64") == null);
            for (lock.lock.packages, result.archives) |package, bytes| {
                try std.testing.expectEqual(package.sha256, sha256(bytes));
                const object_key = std.fmt.bytesToHex(package.sha256, .lower);
                try cache.objects.deleteFile(std.testing.io, &object_key);
                try std.testing.expectEqual(package.sha256, sha256(bytes));
            }
            try native_operation.bind(allocator, root, &attempt, result.preparation.prepared.program.program);
            try std.testing.expectEqualDeep(
                try native_operation.evidence(result.preparation.prepared.program.program),
                attempt.record().evidence(),
            );
            var repeated = try prepareNative(allocator, .{
                .repository = request,
                .attempt = &attempt,
                .plan = &plan,
                .exact_lock = &lock.lock,
                .archives = result.archives,
            });
            defer repeated.deinit();
            try std.testing.expect(repeated == .prepared);
            try std.testing.expectEqualStrings(
                &result.preparation.prepared.program.program.digest_sha256,
                &repeated.prepared.program.program.digest_sha256,
            );
            const bound = attempt.record().digest_sha256;
            var retained: [3][]const u8 = undefined;
            retained[0] = descriptor_bytes;
            @memcpy(retained[1 .. 1 + result.archives.len], result.archives);
            var retry = input;
            retry.retained_archives = retained[0 .. 1 + result.archives.len];
            try std.testing.expectError(error.ResourceBudgetExceeded, prepareNativeFromCache(allocator, retry));
            try std.testing.expectEqual(bound, attempt.record().digest_sha256);
        }
    }
    if (expected_error != null or empty or case == .allocation_failures or case == .execution_diagnostic)
        try std.testing.expectEqual(before, attempt.record().digest_sha256);
    try std.testing.expectEqual(case != .lost_lock_after, attempt.locked());
    const status = try root.readFileAlloc(allocator, try root_fs.Path.init("var/lib/dpkg/status"), 4096);
    defer allocator.free(status);
    try std.testing.expectEqualStrings(native_preparation_held_status, status);
    try std.testing.expect((try root.entryIfExists(try root_fs.Path.init(@import("native_recovery.zig").intent_path)) != null) ==
        (case == .active_evidence));
}

test "repository backend native cached preparation owns local mixed and empty closures" {
    for ([_]NativeCacheCase{ .local, .mixed, .empty }) |case| {
        errdefer std.debug.print("native cached preparation case: {t}\n", .{case});
        try testNativeCachePreparation(case);
    }
}

test "repository backend native cached preparation preflights complete retained budgets" {
    for ([_]NativeCacheCase{ .retained_limit, .total_limit, .package_limit, .cache_limit, .declared_overflow }) |case| {
        errdefer std.debug.print("native cached preparation case: {t}\n", .{case});
        try testNativeCachePreparation(case);
    }
}

test "repository backend native cached preparation refuses foreign authority and invalid cache evidence" {
    for ([_]NativeCacheCase{
        .changed_request,     .changed_plan,    .legacy_caller,  .legacy_lock,
        .invalid_lock_digest, .active_evidence, .missing_object, .corrupt_object,
        .invalid_payload,
    }) |case| {
        errdefer std.debug.print("native cached preparation case: {t}\n", .{case});
        try testNativeCachePreparation(case);
    }
}

test "repository backend native cached preparation preserves cumulative deadlines and ownership" {
    for ([_]NativeCacheCase{ .expired_before, .expired_during, .expired_after, .lost_lock_after }) |case| {
        errdefer std.debug.print("native cached preparation case: {t}\n", .{case});
        try testNativeCachePreparation(case);
    }
}

test "repository backend native cached preparation cleans up allocation failures" {
    try testNativeCachePreparation(.allocation_failures);
}

test "repository backend native execution owns unchanged and diagnostic allocation paths" {
    try testNativeCachePreparation(.execution_unchanged);
    try testNativeCachePreparation(.execution_diagnostic);
}

test "repository backend legacy binding byte identities" {
    const request = BindingFixture.request;
    var fixture = BindingFixture.init(BindingFixture.artifact);
    try std.testing.expectEqualStrings(
        "caea06507df178c8c7587c881eb63f50a0c5a2fdd47470f7e0227061cfe67d00",
        &requestOperationId(request, .legacy_dpkg),
    );
    const cases = [_]struct { expected: []const u8, actual: [32]u8 }{
        .{
            .expected = "b72b80bda946c7cd579aae95a5736a027321345fa3b7f09180aa496af0cda426",
            .actual = repositoryRequestDigest(request, .legacy_dpkg),
        },
        .{
            .expected = "42c8799c19d1700dbbebf7f850b219730c7e1cdde334b46577ccb256a0553a59",
            .actual = repositoryPolicyDigest(request, .legacy_dpkg),
        },
        .{
            .expected = "77dea43d7c7b14ed4f2bc4b1d585f6e48ed46147586c18c9d2257daaa4e88acd",
            .actual = try operationRequestDigest(std.testing.allocator, request, fixture.plan(), .legacy_dpkg),
        },
        .{
            .expected = "16ea683d1a0e738e5d956a8f652acdc9e53f89b567f4aa37184ffae384f86e55",
            .actual = repositoryLockPolicyDigest(.legacy_dpkg),
        },
    };
    for (cases) |case| {
        var actual: [64]u8 = undefined;
        formatHex(&actual, &case.actual);
        try std.testing.expectEqualStrings(case.expected, &actual);
    }
}

test "repository backend separates history without partitioning shared exclusion paths" {
    for ([_]bool{ false, true }) |no_refresh| {
        var request = BindingFixture.request;
        request.no_refresh = no_refresh;
        var legacy = try ResolvedPaths.init(std.testing.allocator, request, .legacy_dpkg);
        defer legacy.deinit();
        var native = try ResolvedPaths.init(std.testing.allocator, request, .native);
        defer native.deinit();
        inline for (.{
            "cache_logical",      "cache_physical",      "state_logical",      "state_physical",
            "repository_logical", "repository_physical", "operations_logical",
        }) |field| {
            try std.testing.expectEqualStrings(@field(legacy, field), @field(native, field));
        }
        try std.testing.expect(!std.mem.eql(u8, &legacy.operation_id, &native.operation_id));
        try std.testing.expectEqualStrings(provenance_name, std.fs.path.basename(legacy.provenance_logical));
        try std.testing.expectEqualStrings(native_provenance_name, std.fs.path.basename(native.provenance_logical));
        inline for (.{
            "operation_logical",       "operation_physical", "exact_plan_logical",
            "exact_lock_logical",      "provenance_logical", "manifest_logical",
            "operation_state_logical",
        }) |field| {
            try std.testing.expect(!std.mem.eql(u8, @field(legacy, field), @field(native, field)));
        }
    }
}

test "repository backend lock domains retain exact origins and reject the other backend" {
    const allocator = std.testing.allocator;
    const request = BindingFixture.request;
    var fixture = BindingFixture.init(BindingFixture.artifact);
    const plan = fixture.plan();
    for ([_]transaction_engine.Kind{ .legacy_dpkg, .native }) |backend| {
        const other: transaction_engine.Kind = if (backend == .native) .legacy_dpkg else .native;
        var created = try createOperationLock(
            allocator,
            plan,
            BindingFixture.artifact,
            null,
            request,
            backend,
        );
        defer created.deinit();
        const bytes = try created.lock.canonicalJson(allocator);
        defer allocator.free(bytes);
        var decoded = try exact_lock_v2.decode(allocator, bytes, exact_lock_v2.maximum_document_bytes);
        defer decoded.deinit();
        const lock = decoded.lock;
        try std.testing.expectEqualSlices(u8, &created.lock.digest_sha256, &lock.digest_sha256);
        try std.testing.expectEqual(@as(usize, 1), lock.packages.len);
        try std.testing.expectEqual(@as(usize, 1), lock.local_artifacts.len);
        try std.testing.expectEqual(@as(usize, 0), lock.repositories.len);
        try std.testing.expect(package_origin.eqlLocalArtifact(BindingFixture.artifact, lock.local_artifacts[0]));
        try std.testing.expect(package_origin.eqlLocalArtifact(BindingFixture.artifact, lock.packages[0].origin.local_artifact));

        try validateLockPolicy(lock, backend);
        try validateLockRequest(allocator, lock, request, plan, backend);
        try std.testing.expectError(error.LockPolicyMismatch, validateLockPolicy(lock, other));
        try std.testing.expectError(error.RequestEvidenceMismatch, validateLockRequest(allocator, lock, request, plan, other));

        var changed_request = request;
        changed_request.resources.maximum_actions -= 1;
        try std.testing.expectError(error.RequestEvidenceMismatch, validateLockRequest(allocator, lock, changed_request, plan, backend));
        fixture.actions[0].requested = false;
        try std.testing.expectError(error.RequestEvidenceMismatch, validateLockRequest(allocator, lock, request, plan, backend));
        fixture.actions[0].requested = true;
    }
}

const native_architecture_status = "Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n";
const native_architecture_foreign: []const []const u8 = &.{ "arm64", "i386" };

fn stageNativeArchitecture(directory: std.Io.Dir) !void {
    try stageRepositoryTestRoot(directory);
    try directory.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = native_architecture_status,
    });
    try directory.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/arch",
        .data = "i386\namd64\narm64\n",
    });
}

test "repository backend native reservation binds discovered architecture without changing request authority" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try stageNativeArchitecture(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "https://packages.example.test/descriptor.deb",
    };
    var guard: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
    defer guard.deinit();
    try std.testing.expect(guard.open(request, .native, 1_700_000_000) == null);
    const record = guard.active().?.record();
    try std.testing.expectEqualStrings("amd64", record.target_architecture);
    try std.testing.expectEqualDeep(native_architecture_foreign, record.foreign_architectures);
    try std.testing.expectEqualSlices(u8, &repositoryRequestDigest(request, .native), &record.request_sha256);
    try std.testing.expect(request.architecture == null);
    for ([_]target_apt_config.Architecture{
        .{ .native = "arm64", .foreign = native_architecture_foreign },
        .{ .native = "amd64", .foreign = &.{} },
    }) |changed| {
        var refused = guard.preflight(changed) orelse return error.TestUnexpectedResult;
        defer refused.deinit();
        try std.testing.expectEqual(api.DiagnosticId.recovery_required, refused.diagnostics[0].id);
        try std.testing.expectEqual(record.digest_sha256, guard.active().?.record().digest_sha256);
    }
    try std.testing.expect(guard.preflight(.{
        .native = "amd64",
        .foreign = native_architecture_foreign,
    }) == null);
}

test "repository backend native reservation preserves interrupted architecture instead of rediscovering it" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try stageNativeArchitecture(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "https://packages.example.test/descriptor.deb",
    };
    {
        var guard: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
        defer guard.deinit();
        try std.testing.expect(guard.open(request, .native, 1_700_000_000) == null);
        try std.testing.expect(guard.preflight(.{ .native = "amd64", .foreign = native_architecture_foreign }) == null);
        try guard.active().?.markMutationStarted(std.testing.allocator, .database);
    }
    var original = (try readRootAttempt(directory.dir)).?;
    defer original.deinit();
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "invalid interrupted status",
    });
    try directory.dir.deleteFile(std.testing.io, "root/var/lib/dpkg/arch");
    {
        var resumed: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
        defer resumed.deinit();
        try std.testing.expect(resumed.open(request, .native, 1_700_000_001) == null);
        try std.testing.expect(resumed.active().?.adopted);
        try std.testing.expectEqual(original.record.digest_sha256, resumed.active().?.record().digest_sha256);
        try std.testing.expectEqualDeep(native_architecture_foreign, resumed.active().?.record().foreign_architectures);
    }
    var changed = request;
    changed.no_refresh = true;
    var contender: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
    defer contender.deinit();
    var refused = contender.open(changed, .native, 1_700_000_002) orelse return error.TestUnexpectedResult;
    defer refused.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, refused.exit_status);
    try std.testing.expectEqual(api.DiagnosticId.recovery_required, refused.diagnostics[0].id);
    var observed = (try readRootAttempt(directory.dir)).?;
    defer observed.deinit();
    try std.testing.expectEqual(original.record.digest_sha256, observed.record.digest_sha256);
}

test "repository backend native unstarted adoption rechecks architecture without rebinding" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try stageNativeArchitecture(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "https://packages.example.test/descriptor.deb",
    };
    {
        var guard: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
        defer guard.deinit();
        try std.testing.expect(guard.open(request, .native, 1_700_000_000) == null);
        guard.active().?.release();
        guard.attempt = null;
    }
    var original = (try readRootAttempt(directory.dir)).?;
    defer original.deinit();
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "Package: dpkg\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1\n\n",
    });
    {
        var resumed: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
        defer resumed.deinit();
        var refused = resumed.open(request, .native, 1_700_000_001) orelse return error.TestUnexpectedResult;
        defer refused.deinit();
        try std.testing.expectEqual(api.DiagnosticId.recovery_required, refused.diagnostics[0].id);
        try std.testing.expect(resumed.active().?.adopted);
        try std.testing.expectEqual(original.record.digest_sha256, resumed.active().?.record().digest_sha256);
    }
    try std.testing.expect((try readRootAttempt(directory.dir)) == null);
}

test "repository backend native reservation rechecks architecture after acquiring exclusion" {
    const Race = struct {
        directory: std.Io.Dir,
        calls: usize = 0,

        fn hit(context: *anyopaque, point: root_operation.AcquisitionPoint) !void {
            if (point != .after_lock_acquired) return;
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            try self.directory.writeFile(std.testing.io, .{
                .sub_path = "root/var/lib/dpkg/status",
                .data = "Package: dpkg\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1\n\n",
            });
        }
    };
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try stageNativeArchitecture(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var race: Race = .{ .directory = directory.dir };
    {
        var guard: RootOperationGuard = .{
            .io = std.testing.io,
            .allocator = std.testing.allocator,
            .acquisition_observer = .{ .context = &race, .hitFn = Race.hit },
        };
        defer guard.deinit();
        var refused = guard.open(.{
            .root = root,
            .descriptor_url = "https://packages.example.test/descriptor.deb",
        }, .native, 1_700_000_000) orelse return error.TestUnexpectedResult;
        defer refused.deinit();
        try std.testing.expectEqual(api.ExitStatus.recovery, refused.exit_status);
        try std.testing.expectEqual(api.DiagnosticId.recovery_required, refused.diagnostics[0].id);
        try std.testing.expect(!guard.active().?.record().mutation_started);
        try std.testing.expectEqualStrings("amd64", guard.active().?.record().target_architecture);
    }
    try std.testing.expectEqual(@as(usize, 1), race.calls);
    try std.testing.expect((try readRootAttempt(directory.dir)) == null);
}

test "repository backend native reservation needs target evidence or explicit architecture" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var request: api.Request = .{
        .root = root,
        .descriptor_url = "https://packages.example.test/descriptor.deb",
    };
    {
        var guard: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
        defer guard.deinit();
        var refused = guard.open(request, .native, 1_700_000_000) orelse return error.TestUnexpectedResult;
        defer refused.deinit();
        try std.testing.expectEqual(api.DiagnosticId.architecture_unavailable, refused.diagnostics[0].id);
        try std.testing.expect(guard.active() == null);
    }
    try std.testing.expect((try readRootAttempt(directory.dir)) == null);
    request.architecture = "amd64";
    var guard: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
    defer guard.deinit();
    try std.testing.expect(guard.open(request, .native, 1_700_000_000) == null);
    try std.testing.expectEqualStrings("amd64", guard.active().?.record().target_architecture);
}

test "repository backend native cleanup never abandons active pre-mutation evidence" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var before: [32]u8 = undefined;
    {
        var guard: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
        defer guard.deinit();
        try std.testing.expect(guard.open(.{
            .root = root,
            .descriptor_url = "https://packages.example.test/descriptor.deb",
            .architecture = "amd64",
        }, .native, 1_700_000_000) == null);
        before = guard.active().?.record().digest_sha256;
        try guard.owned_root.?.root.publishFile(
            try root_fs.Path.init(@import("native_recovery.zig").intent_path),
            "incomplete native execution",
            .{},
        );
    }
    var observed = (try readRootAttempt(directory.dir)).?;
    defer observed.deinit();
    try std.testing.expectEqual(before, observed.record.digest_sha256);
    try std.testing.expectEqual(root_operation.Outcome.pending, observed.record.outcome);
}

test "repository backend binds root callers while sharing live and unresolved exclusion" {
    for ([_]transaction_engine.Kind{ .legacy_dpkg, .native }) |backend| {
        const other: transaction_engine.Kind = if (backend == .native) .legacy_dpkg else .native;
        var directory = std.testing.tmpDir(.{ .iterate = true });
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        var request = BindingFixture.request;
        request.root = root;
        request.state.lock_wait_ms = 0;
        const request_digest = repositoryRequestDigest(request, backend);
        const policy_digest = repositoryPolicyDigest(request, backend);
        try std.testing.expect(!std.mem.eql(u8, &request_digest, &repositoryRequestDigest(request, other)));
        try std.testing.expect(!std.mem.eql(u8, &policy_digest, &repositoryPolicyDigest(request, other)));
        {
            var owner: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
            defer owner.deinit();
            try std.testing.expect(owner.open(request, backend, 1_700_000_000) == null);
            try std.testing.expectEqual(backend, owner.active().?.record().backend);
            try std.testing.expectEqualSlices(u8, &request_digest, &owner.active().?.record().request_sha256);
            try std.testing.expectEqualSlices(u8, &policy_digest, &owner.active().?.record().policy_sha256);

            var contender: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
            defer contender.deinit();
            var refused = contender.open(request, other, 1_700_000_000) orelse
                return error.TestUnexpectedResult;
            defer refused.deinit();
            try std.testing.expectEqual(api.ExitStatus.unavailable, refused.exit_status);
            try std.testing.expectEqual(api.DiagnosticId.recovery_required, refused.diagnostics[0].id);
        }
        try std.testing.expect((try readRootAttempt(directory.dir)) == null);

        var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
        defer root_dir.close(std.testing.io);
        const store = root_operation.Store.init(.init(std.testing.io, root_dir));
        const program_digest: [32]u8 = @splat(0x44);
        var stranded = try root_operation.create(std.testing.allocator, .{
            .attempt_id = @splat(0x7c),
            .generation = 2,
            .install_root = root,
            .backend = backend,
            .operation = .{ .repository_bootstrap = .add },
            .state = .mutating,
            .phase = .database,
            .step = 3,
            .mutation_started = true,
            .outcome = .pending,
            .provenance = .pending,
            .request_sha256 = request_digest,
            .policy_sha256 = policy_digest,
            .evidence = .{ .program_sha256 = if (backend == .native) program_digest else null },
            .target_architecture = "amd64",
            .reserved_unix = 1_700_000_000,
            .updated_unix = 1_700_000_000,
        });
        defer stranded.deinit();
        try store.writeAtomic(std.testing.allocator, stranded.record);
        {
            var contender: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
            defer contender.deinit();
            var refused = contender.open(request, other, 1_700_000_000) orelse
                return error.TestUnexpectedResult;
            defer refused.deinit();
            try std.testing.expectEqual(api.ExitStatus.recovery, refused.exit_status);
            try std.testing.expectEqual(api.DiagnosticId.recovery_required, refused.diagnostics[0].id);
        }
        var observed = (try readRootAttempt(directory.dir)).?;
        defer observed.deinit();
        try std.testing.expectEqualSlices(u8, &stranded.record.digest_sha256, &observed.record.digest_sha256);
        var resumed: RootOperationGuard = .{ .io = std.testing.io, .allocator = std.testing.allocator };
        defer resumed.deinit();
        try std.testing.expect(resumed.open(request, backend, 1_700_000_000) == null);
        try std.testing.expectEqualSlices(u8, &stranded.record.digest_sha256, &resumed.active().?.record().digest_sha256);
    }
}

test "repository backend maps alternate-root evidence paths without host inference" {
    var paths = try ResolvedPaths.init(std.testing.allocator, .{
        .root = "/srv/roots/noble",
        .descriptor_url = "https://packages.microsoft.test/config.deb",
        .architecture = "amd64",
    }, .legacy_dpkg);
    defer paths.deinit();
    try std.testing.expectEqualStrings(
        "/srv/roots/noble/var/cache/debz",
        paths.cache_physical,
    );
    try std.testing.expectEqualStrings(
        "/srv/roots/noble/var/lib/debz/repository",
        paths.repository_physical,
    );
    try std.testing.expect(std.mem.startsWith(
        u8,
        paths.operation_state_logical,
        "/var/lib/debz/repository/operations/",
    ));
    try std.testing.expect(std.mem.endsWith(
        u8,
        paths.operation_state_logical,
        "/repo-add-state-v1.json",
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        paths.operation_physical,
        "/srv/roots/noble/var/lib/debz/repository/operations/",
    ));
    var same = try ResolvedPaths.init(std.testing.allocator, .{
        .root = "/srv/roots/noble",
        .descriptor_url = "https://packages.microsoft.test/config.deb",
        .architecture = "amd64",
    }, .legacy_dpkg);
    defer same.deinit();
    try std.testing.expectEqualSlices(u8, &paths.operation_id, &same.operation_id);
    var distinct = try ResolvedPaths.init(std.testing.allocator, .{
        .root = "/srv/roots/noble",
        .descriptor_url = "https://packages.example.test/config.deb",
        .architecture = "amd64",
    }, .legacy_dpkg);
    defer distinct.deinit();
    try std.testing.expect(!std.mem.eql(
        u8,
        &paths.operation_id,
        &distinct.operation_id,
    ));
}

test "repository backend alone permits explicitly requested host root" {
    var request: api.Request = .{
        .root = "/",
        .descriptor_url = "https://packages.microsoft.test/config.deb",
        .architecture = "amd64",
    };
    var policy = repositoryExecutionPolicy(request);
    try std.testing.expect(policy.risk.allow_host_root);
    try std.testing.expectEqual(transaction_executor.ConffilePolicy.keep_existing, policy.conffile);
    try std.testing.expectEqual(
        transaction_executor.ExactLockVerification.locked_packages,
        policy.exact_lock_verification,
    );
    request.root = "/target";
    policy = repositoryExecutionPolicy(request);
    try std.testing.expect(!policy.risk.allow_host_root);
}

test "repository backend applies request-scoped retry backoff" {
    const policy = retryPolicy(.{
        .retry_attempts = 4,
        .retry_backoff_ms = 375,
    });
    try std.testing.expectEqual(@as(u16, 4), policy.max_attempts);
    try std.testing.expectEqual(@as(?u64, 375), policy.linear_backoff_base_ms);
}

test "repository backend extracts static Microsoft-shaped source and keyring material" {
    const fixture = @import("fixtures/openpgp.zig");
    const source_bytes =
        "deb [signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.test/noble prod main\n";
    const payload = try std.mem.concat(
        std.testing.allocator,
        u8,
        &.{ source_bytes, &fixture.keyring },
    );
    defer std.testing.allocator.free(payload);
    var entries = [_]deb_payload.Entry{
        .{
            .path = @constCast("etc/apt/sources.list.d/microsoft-prod.list"),
            .link_target = null,
            .link_literal = null,
            .kind = .regular,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .owner_name = null,
            .group_name = null,
            .mtime = 0,
            .size = source_bytes.len,
            .header_offset = 0,
            .content_offset = 0,
        },
        .{
            .path = @constCast("usr/share/keyrings/microsoft-prod.gpg"),
            .link_target = null,
            .link_literal = null,
            .kind = .regular,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .owner_name = null,
            .group_name = null,
            .mtime = 0,
            .size = fixture.keyring.len,
            .header_offset = source_bytes.len,
            .content_offset = source_bytes.len,
        },
    };
    const empty_entries: []deb_payload.Entry = &.{};
    var validation: deb_payload.Validation = .{
        .allocator = std.testing.allocator,
        .package = @constCast("packages-microsoft-prod"),
        .version = @constCast("1.1-ubuntu24.04"),
        .architecture = @constCast("all"),
        .provenance = .{
            .kind = .local_artifact,
            .repository = @constCast("local"),
            .filename = @constCast("packages-microsoft-prod.deb"),
            .size = payload.len,
            .sha256 = sha256(payload),
        },
        .relationships = .{ .depends = null, .pre_depends = null },
        .control = .{
            .compression = .uncompressed,
            .compressed_bytes = 0,
            .decompressed_bytes = 0,
            .root = null,
            .entries = empty_entries,
            .entry_headers = 0,
            .inventory_bytes = 0,
            .regular_bytes = 0,
        },
        .data = .{
            .compression = .uncompressed,
            .compressed_bytes = payload.len,
            .decompressed_bytes = payload.len,
            .root = null,
            .entries = &entries,
            .entry_headers = entries.len,
            .inventory_bytes = payload.len,
            .regular_bytes = payload.len,
        },
        .scripts = &.{},
        .conffiles = &.{},
        .control_bytes = @constCast(&.{}),
        .data_bytes = payload,
    };
    var material = try inspectDescriptorMaterial(
        std.testing.allocator,
        &validation,
        "amd64",
        .{},
        .{},
    );
    defer material.deinit();
    try std.testing.expectEqual(@as(usize, 1), material.configuration.repositories.len);
    try std.testing.expectEqual(@as(usize, 2), material.evidence.len);
    try std.testing.expectEqualStrings(
        "/etc" ++ "/apt/sources.list.d/microsoft-prod.list",
        material.evidence[0].logical_path,
    );
    try std.testing.expectEqualStrings(
        "/usr/share/keyrings/microsoft-prod.gpg",
        material.evidence[1].logical_path,
    );

    const trusted_sources = [_]struct {
        path: []const u8,
        bytes: []const u8,
    }{
        .{
            .path = "etc/apt/sources.list.d/microsoft-prod.list",
            .bytes = "deb [trusted=yes signed-by=/usr/share/keyrings/microsoft-prod.gpg] " ++
                "https://packages.microsoft.test/noble prod main\n",
        },
        .{
            .path = "etc/apt/sources.list.d/microsoft-prod.sources",
            .bytes = "Types: deb\nURIs: https://packages.microsoft.test/noble\n" ++
                "Suites: prod\nComponents: main\nArchitectures: amd64\n" ++
                "Signed-By: /usr/share/keyrings/microsoft-prod.gpg\nTrusted: yes\n",
        },
    };
    for (trusted_sources) |trusted| {
        const trusted_payload = try std.mem.concat(
            std.testing.allocator,
            u8,
            &.{ trusted.bytes, &fixture.keyring },
        );
        defer std.testing.allocator.free(trusted_payload);
        entries[0].path = @constCast(trusted.path);
        entries[0].size = trusted.bytes.len;
        entries[1].header_offset = trusted.bytes.len;
        entries[1].content_offset = trusted.bytes.len;
        validation.data_bytes = trusted_payload;
        try std.testing.expectError(
            error.MalformedRepositorySource,
            inspectDescriptorMaterial(
                std.testing.allocator,
                &validation,
                "amd64",
                .{},
                .{},
            ),
        );
    }

    const unsigned_source = "deb file:///synthetic-repository stable main\n";
    const unsigned_payload = try std.mem.concat(
        std.testing.allocator,
        u8,
        &.{ unsigned_source, &fixture.keyring },
    );
    defer std.testing.allocator.free(unsigned_payload);
    entries[0].path = @constCast("etc/apt/sources.list.d/microsoft-prod.list");
    entries[0].size = unsigned_source.len;
    entries[1].header_offset = unsigned_source.len;
    entries[1].content_offset = unsigned_source.len;
    validation.data_bytes = unsigned_payload;
    try std.testing.expectError(
        error.UnsignedRepository,
        inspectDescriptorMaterial(
            std.testing.allocator,
            &validation,
            "amd64",
            .{},
            .{},
        ),
    );
    entries[0].path = @constCast("usr/share/doc/microsoft-prod.list");
    try std.testing.expectError(
        error.DynamicRepositoryMaterial,
        inspectDescriptorMaterial(
            std.testing.allocator,
            &validation,
            "amd64",
            .{},
            .{},
        ),
    );
}

test "repository backend uses installed dependencies before requesting refresh" {
    const local_text =
        "Package: packages-microsoft-prod\n" ++
        "Version: 1.1\n" ++
        "Architecture: all\n" ++
        "Depends: ca-certificates\n" ++
        "Filename: descriptor.deb\n" ++
        "Size: 100\n" ++
        "SHA256: 1111111111111111111111111111111111111111111111111111111111111111\n";
    const repository_id: source.RepositoryId = .{ .bytes = @splat('1') };
    const parsed_index = try packages_index.parseBorrowed(
        std.testing.allocator,
        local_text,
        .{
            .repository_id = repository_id,
            .component = "local",
            .architecture = "amd64",
            .source_location = "https://packages.microsoft.test/config.deb",
        },
        .{},
    );
    var index = switch (parsed_index) {
        .diagnostic => return error.InvalidTestIndex,
        .index => |value| value,
    };
    defer index.deinit();
    const evidence: @import("package_origin.zig").LocalArtifactEvidence = .{
        .artifact_id = @splat('1'),
        .sha256 = @splat(0x11),
        .size = 100,
        .package = "packages-microsoft-prod",
        .version = "1.1",
        .architecture = "all",
        .acquisition_url = "https://packages.microsoft.test/config.deb",
        .trust_mode = .verified_https,
    };
    const local_repository = solver.RepositoryInput.fromLocalArtifact(
        &index,
        1000,
        evidence,
    );
    const installed_text =
        "Package: ca-certificates\n" ++
        "Status: install ok installed\n" ++
        "Architecture: amd64\n" ++
        "Version: 20240203\n";
    const parsed_installed = try dpkg_status.parseOwned(
        std.testing.allocator,
        installed_text,
        .{},
    );
    var installed = switch (parsed_installed) {
        .diagnostic => return error.InvalidTestStatus,
        .database => |value| value,
    };
    defer installed.deinit();
    const policies = try makeInstalledPolicies(
        std.testing.allocator,
        installed.database.packages,
    );
    defer std.testing.allocator.free(policies);
    const result = try planDescriptor(
        std.testing.allocator,
        &.{local_repository},
        installed.database.packages,
        policies,
        "amd64",
        "packages-microsoft-prod",
        "1.1",
        false,
        .{},
    );
    var plan = switch (result) {
        .failure => |failure_value| {
            var failure = failure_value;
            defer failure.deinit();
            return error.UnexpectedPlanningFailure;
        },
        .plan => |value| value,
    };
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), plan.actions.len);
    try std.testing.expectEqualStrings("packages-microsoft-prod", plan.actions[0].package);

    var missing = try planDescriptor(
        std.testing.allocator,
        &.{local_repository},
        &.{},
        &.{},
        "amd64",
        "packages-microsoft-prod",
        "1.1",
        false,
        .{},
    );
    switch (missing) {
        .plan => |*unexpected| {
            unexpected.deinit();
            return error.ExpectedDependencyFailure;
        },
        .failure => |*failure| {
            try std.testing.expect(dependencyFailureNeedsRefresh(failure.*));
            failure.deinit();
        },
    }
}

const test_repository_source =
    "deb [signed-by=/usr/share/keyrings/microsoft-prod.gpg] file:///synthetic-repository stable main\n";

const RepositoryTestAcquisition = struct {
    descriptor: []const u8,
    descriptor_available: bool = true,
    descriptor_reads: usize = 0,
    network_descriptor: ?[]const u8 = null,
    network_available: bool = false,
    in_release_requests: usize = 0,
    fail_in_release_request: ?usize = null,
    network_requests: usize = 0,
    now_ms: u64 = 0,
    advance_ms_per_read: u64 = 0,
    switch_backend_to_native: ?*transaction_engine.Kind = null,

    fn dependencies(self: *RepositoryTestAcquisition) repository_acquisition.Dependencies {
        return .{
            .transport = .{ .context = self, .requestFn = requestNetwork },
            .files = .{ .context = self, .readFn = readFile },
            .clock = .{
                .context = self,
                .nowMsFn = nowMilliseconds,
                .sleepMsFn = noSleep,
            },
        };
    }

    fn requestNetwork(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        _: repository_acquisition.HttpRequest,
    ) !repository_acquisition.HttpResponse {
        const self: *RepositoryTestAcquisition = @ptrCast(@alignCast(context.?));
        self.network_requests += 1;
        if (!self.network_available) return error.NetworkForbidden;
        const descriptor = self.network_descriptor orelse
            return error.NetworkForbidden;
        return .{
            .status = 200,
            .body = try allocator.dupe(u8, descriptor),
        };
    }

    fn readFile(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        limit: usize,
        _: repository_acquisition.Deadlines,
    ) !repository_acquisition.FileRead {
        const self: *RepositoryTestAcquisition = @ptrCast(@alignCast(context.?));
        if (self.switch_backend_to_native) |selection| selection.* = .native;
        const fixture = @import("fixtures/openpgp.zig");
        const bytes: []const u8 = if (std.mem.endsWith(u8, path, "descriptor.deb")) blk: {
            self.descriptor_reads += 1;
            if (!self.descriptor_available) return error.FileNotFound;
            break :blk self.descriptor;
        } else if (std.mem.endsWith(u8, path, "/InRelease")) blk: {
            self.in_release_requests += 1;
            if (self.fail_in_release_request == self.in_release_requests)
                break :blk "not a signed release";
            break :blk &fixture.repository_in_release;
        } else if (std.mem.endsWith(u8, path, "/Packages"))
            &fixture.repository_packages
        else
            return error.FileNotFound;
        if (bytes.len > limit) return error.ResponseTooLarge;
        self.now_ms +|= self.advance_ms_per_read;
        return .{ .bytes = try allocator.dupe(u8, bytes), .regular = true };
    }

    fn nowMilliseconds(context: ?*anyopaque) u64 {
        const self: *RepositoryTestAcquisition = @ptrCast(@alignCast(context.?));
        return self.now_ms;
    }

    fn noSleep(_: ?*anyopaque, _: u64) !void {}
};

const RepositoryOperationLock = struct {
    clock_ms: *u64,
    advance_ms: u64 = 0,
    fail: bool = false,
    calls: usize = 0,
    last_wait_ms: ?u64 = null,

    fn interface(self: *RepositoryOperationLock) transaction_executor.LockManager {
        return .{
            .context = self,
            .acquireFn = acquire,
            .heldFn = held,
            .releaseFn = release,
        };
    }

    fn acquire(
        context: *anyopaque,
        _: []const u8,
        wait_ms: u64,
    ) !transaction_executor.LockToken {
        const self: *RepositoryOperationLock = @ptrCast(@alignCast(context));
        self.calls += 1;
        self.last_wait_ms = wait_ms;
        self.clock_ms.* +|= self.advance_ms;
        if (self.fail) return error.LockTimeout;
        return self;
    }

    fn held(_: *anyopaque, _: transaction_executor.LockToken) bool {
        return true;
    }

    fn release(_: *anyopaque, _: transaction_executor.LockToken) void {}
};

const RepositoryTargetLocks = struct {
    clock_ms: *u64,
    fail_call: ?usize = null,
    calls: usize = 0,
    releases: usize = 0,
    held_count: usize = 0,
    waits: [3]?u64 = @splat(null),

    fn interface(self: *RepositoryTargetLocks) transaction_executor.LockManager {
        return .{
            .context = self,
            .acquireFn = acquire,
            .heldFn = held,
            .releaseFn = release,
        };
    }

    fn acquire(
        context: *anyopaque,
        path: []const u8,
        wait_ms: u64,
    ) !transaction_executor.LockToken {
        const self: *RepositoryTargetLocks = @ptrCast(@alignCast(context));
        const expected_suffixes = [_][]const u8{
            "/var/lib/debz/transaction.lock",
            "/var/lib/dpkg/lock-frontend",
            "/var/lib/dpkg/lock",
        };
        if (self.calls >= expected_suffixes.len or
            !std.mem.endsWith(u8, path, expected_suffixes[self.calls]))
            return error.UnexpectedTargetLock;
        self.waits[self.calls] = wait_ms;
        self.calls += 1;
        self.clock_ms.* +|= self.calls;
        if (self.fail_call == self.calls) return error.LockTimeout;
        self.held_count += 1;
        return self;
    }

    fn held(context: *anyopaque, _: transaction_executor.LockToken) bool {
        const self: *RepositoryTargetLocks = @ptrCast(@alignCast(context));
        return self.held_count != 0;
    }

    fn release(context: *anyopaque, _: transaction_executor.LockToken) void {
        const self: *RepositoryTargetLocks = @ptrCast(@alignCast(context));
        std.debug.assert(self.held_count != 0);
        self.held_count -= 1;
        self.releases += 1;
    }
};

const RepositoryLockedStatusReader = struct {
    locks: *RepositoryTargetLocks,
    stable: []const u8,
    intermediate: []const u8,
    calls: usize = 0,
    read_before_all_locks: bool = false,

    fn interface(self: *RepositoryLockedStatusReader) transaction_recovery.StatusReader {
        return .{ .context = self, .readFn = read };
    }

    fn read(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        _: []const u8,
        maximum: usize,
    ) ![]u8 {
        const self: *RepositoryLockedStatusReader = @ptrCast(@alignCast(context));
        self.calls += 1;
        const bytes = if (self.locks.held_count == 3)
            self.stable
        else blk: {
            self.read_before_all_locks = true;
            break :blk self.intermediate;
        };
        if (bytes.len > maximum) return error.StreamTooLong;
        return allocator.dupe(u8, bytes);
    }
};

const RepositoryTestExecutor = struct {
    const LockDigestMode = enum {
        exact,
        missing,
        mismatch,
    };

    io: std.Io,
    directory: std.Io.Dir,
    calls: usize = 0,
    recover_calls: usize = 0,
    saw_lock_before_install: bool = false,
    saw_exact_lock: bool = false,
    recovered_exact_lock: bool = false,
    last_allow_host_root: bool = false,
    interrupt_first: bool = false,
    interrupt_before_install: bool = false,
    interrupted_status: ?[]const u8 = null,
    lock_digest_mode: LockDigestMode = .exact,
    first_plan_sha256: ?[32]u8 = null,
    recovery_plan_sha256: ?[32]u8 = null,
    clock_ms: ?*u64 = null,
    advance_ms_after_install: u64 = 0,
    install_status: ?[]const u8 = null,
    /// Publishes a directory under the operation directory using the name of a
    /// document the backend is about to write, so the very next post-executor
    /// publication fails with the root already mutated.
    collide_after_install: ?[]const u8 = null,
    /// Records the descriptor as only half-configured so installed-descriptor
    /// verification fails after the executor already changed the root, without
    /// disturbing the target's apt configuration.
    half_configure_descriptor: bool = false,
    /// Reports the exact shape of a failure before any spawn: no command
    /// completed and the transaction state never left `not_started`. An
    /// expired deadline, a refused preflight, a lock that could not be taken,
    /// and a journal that could not be decoded all look like this.
    no_start_failure: ?transaction_executor.FailureCode = null,
    /// Refuses the transaction as needing explicit recovery without touching
    /// the root, which is how the backend is driven into its recovery path.
    recovery_transition_first: bool = false,
    /// The same pre-spawn failure shape for the recovery path, where the
    /// transaction state is published only once the journal has decoded.
    no_start_recovery_failure: ?transaction_executor.FailureCode = null,

    fn interface(self: *RepositoryTestExecutor) Executor {
        return .{
            .context = self,
            .executeFn = execute,
            .recoverFn = recover,
        };
    }

    /// The operation directory the backend selected for this request, found
    /// exactly the way `execute` finds the published exact lock.
    fn openOperationDirectory(self: *RepositoryTestExecutor) !std.Io.Dir {
        var operations = try self.directory.openDir(
            self.io,
            "root/var/lib/debz/repository/operations",
            .{ .iterate = true },
        );
        defer operations.close(self.io);
        var iterator = operations.iterate();
        while (try iterator.next(self.io)) |entry| {
            if (entry.kind != .directory) continue;
            var operation = try operations.openDir(self.io, entry.name, .{});
            operation.access(self.io, exact_lock_name, .{}) catch {
                operation.close(self.io);
                continue;
            };
            return operation;
        }
        return error.OperationDirectoryMissing;
    }

    fn execute(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: transaction_executor.Request,
        _: transaction_executor.Dependencies,
    ) !transaction_executor.Report {
        const self: *RepositoryTestExecutor = @ptrCast(@alignCast(context));
        self.calls += 1;
        const plan_sha256 = transaction_executor.planDigest(request.plan.*);
        if (self.first_plan_sha256 == null) self.first_plan_sha256 = plan_sha256;
        var operations = self.directory.openDir(
            self.io,
            "root/var/lib/debz/repository/operations",
            .{ .iterate = true },
        ) catch return error.LockNotPublishedBeforeInstall;
        defer operations.close(self.io);
        var iterator = operations.iterate();
        var found_lock = false;
        while (try iterator.next(self.io)) |entry| {
            if (entry.kind != .directory) continue;
            var operation = try operations.openDir(self.io, entry.name, .{});
            defer operation.close(self.io);
            operation.access(self.io, exact_lock_name, .{}) catch continue;
            found_lock = true;
            break;
        }
        if (!found_lock) return error.LockNotPublishedBeforeInstall;
        self.saw_lock_before_install = true;
        self.last_allow_host_root = request.policy.risk.allow_host_root;
        const exact_lock = request.exact_lock_v2 orelse
            return error.MissingExactLock;
        self.saw_exact_lock = true;
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = .init(allocator);
        // Nothing is installed and nothing is recorded: the report is
        // indistinguishable from an untouched root through its command count.
        if (self.no_start_failure) |code| return .{
            .allocator = allocator,
            .arena = arena,
            .commands = &.{},
            .plan_sha256 = plan_sha256,
            .transaction_state = .not_started,
            .root_identity = @splat(0x22),
            .policy_sha256 = transaction_executor.policyDigest(request.policy),
            .lock_sha256 = exact_lock.digest_sha256,
            .failure = .{ .code = code, .diagnostic = "injected pre-spawn failure" },
        };
        if (self.recovery_transition_first) return .{
            .allocator = allocator,
            .arena = arena,
            .commands = &.{},
            .plan_sha256 = plan_sha256,
            .transaction_state = .interrupted,
            .root_identity = @splat(0x22),
            .policy_sha256 = transaction_executor.policyDigest(request.policy),
            .lock_sha256 = exact_lock.digest_sha256,
            .failure = .{
                .code = .invalid_recovery_transition,
                .diagnostic = "injected recovery requirement",
            },
        };
        const interrupted = self.interrupt_first and self.calls == 1;
        const recovery_required = self.interrupt_first and self.calls > 1;
        if ((!interrupted or !self.interrupt_before_install) and !recovery_required) {
            if (interrupted and self.interrupted_status != null)
                try self.installDescriptorWithStatus(self.interrupted_status.?)
            else
                try self.installDescriptor();
            if (self.half_configure_descriptor) try self.directory.writeFile(self.io, .{
                .sub_path = "root/var/lib/dpkg/status",
                .data = "Package: packages-microsoft-prod\n" ++
                    "Status: install ok half-configured\n" ++
                    "Architecture: all\n" ++
                    "Version: 1.1\n",
            });
            if (self.collide_after_install) |name| {
                var operation = try self.openOperationDirectory();
                defer operation.close(self.io);
                try operation.createDirPath(self.io, name);
            }
            if (self.clock_ms) |clock|
                clock.* +|= self.advance_ms_after_install;
        }
        return .{
            .allocator = allocator,
            .arena = arena,
            .commands = &.{},
            .plan_sha256 = plan_sha256,
            .transaction_state = if (interrupted or recovery_required)
                .interrupted
            else
                .complete,
            .root_identity = @splat(0x22),
            .policy_sha256 = transaction_executor.policyDigest(request.policy),
            .lock_sha256 = switch (self.lock_digest_mode) {
                .exact => exact_lock.digest_sha256,
                .missing => null,
                .mismatch => @splat(0xfe),
            },
            .failure = if (interrupted)
                .{
                    .code = .interrupted,
                    .diagnostic = "injected interruption",
                }
            else if (recovery_required)
                .{
                    .code = .invalid_recovery_transition,
                    .diagnostic = "injected recovery requirement",
                }
            else
                null,
        };
    }

    fn recover(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: transaction_executor.RecoveryRequest,
        _: transaction_executor.Dependencies,
    ) !transaction_executor.RecoveryReport {
        const self: *RepositoryTestExecutor = @ptrCast(@alignCast(context));
        self.recover_calls += 1;
        self.recovery_plan_sha256 = transaction_executor.planDigest(request.plan.*);
        const exact_lock = request.exact_lock_v2 orelse
            return error.MissingExactLock;
        self.recovered_exact_lock = true;
        if (self.no_start_recovery_failure) |code| {
            const failed_arena = try allocator.create(std.heap.ArenaAllocator);
            errdefer allocator.destroy(failed_arena);
            failed_arena.* = .init(allocator);
            // The journal never decoded, so the report carries the state it
            // was initialized with rather than the journal's own.
            return .{
                .allocator = allocator,
                .arena = failed_arena,
                .state = .not_started,
                .commands = &.{},
                .plan_sha256 = transaction_executor.planDigest(request.plan.*),
                .root_identity = @splat(0x22),
                .policy_sha256 = transaction_executor.policyDigest(request.policy),
                .lock_sha256 = exact_lock.digest_sha256,
                .failure = .{ .code = code, .diagnostic = "injected pre-spawn failure" },
            };
        }
        try self.installDescriptor();
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = .init(allocator);
        return .{
            .allocator = allocator,
            .arena = arena,
            .state = .complete,
            .commands = &.{},
            .plan_sha256 = transaction_executor.planDigest(request.plan.*),
            .root_identity = @splat(0x22),
            .policy_sha256 = transaction_executor.policyDigest(request.policy),
            .lock_sha256 = switch (self.lock_digest_mode) {
                .exact => exact_lock.digest_sha256,
                .missing => null,
                .mismatch => @splat(0xfe),
            },
            .failure = null,
        };
    }

    fn installDescriptor(self: *RepositoryTestExecutor) !void {
        return self.installDescriptorWithStatus(
            self.install_status orelse
                "Package: packages-microsoft-prod\n" ++
                    "Status: install ok installed\n" ++
                    "Architecture: all\n" ++
                    "Version: 1.1\n",
        );
    }

    fn installDescriptorWithStatus(
        self: *RepositoryTestExecutor,
        status: []const u8,
    ) !void {
        const fixture = @import("fixtures/openpgp.zig");
        try self.directory.createDirPath(
            self.io,
            "root/etc" ++ "/apt/sources.list.d",
        );
        try self.directory.createDirPath(self.io, "root/usr/share/keyrings");
        try self.directory.writeFile(self.io, .{
            .sub_path = "root/etc" ++ "/apt/sources.list.d/microsoft-prod.list",
            .data = test_repository_source,
        });
        try self.directory.writeFile(self.io, .{
            .sub_path = "root/usr/share/keyrings/microsoft-prod.gpg",
            .data = &fixture.keyring,
        });
        try self.directory.writeFile(self.io, .{
            .sub_path = "root/var/lib/dpkg/status",
            .data = status,
        });
    }
};

const RepositoryStateFailure = struct {
    boundary: state_module.WriteBoundary,
    fail_from_write: usize,
    writes: usize = 0,

    fn hooks(self: *RepositoryStateFailure) state_module.WriteHooks {
        return .{ .context = self, .runFn = run };
    }

    fn run(context: ?*anyopaque, boundary: state_module.WriteBoundary) !void {
        const self: *RepositoryStateFailure = @ptrCast(@alignCast(context.?));
        if (boundary == .before_stage) self.writes += 1;
        if (boundary == self.boundary and self.writes >= self.fail_from_write)
            return error.InjectedStateWriteFailure;
    }
};

fn repositoryTestRoot(
    allocator: std.mem.Allocator,
    directory: std.Io.Dir,
) ![]u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.realPath(std.testing.io, &buffer);
    return std.fmt.allocPrint(allocator, "{s}/root", .{buffer[0..length]});
}

fn stageRepositoryTestRoot(directory: std.Io.Dir) !void {
    try directory.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "",
    });
}

fn expectRepositoryEvidence(
    directory: std.Io.Dir,
    logical_path: ?[]const u8,
) !void {
    const logical = logical_path orelse return error.MissingEvidencePath;
    const relative = try std.fmt.allocPrint(
        std.testing.allocator,
        "root{s}",
        .{logical},
    );
    defer std.testing.allocator.free(relative);
    try directory.access(std.testing.io, relative, .{});
}

test "repository backend snapshots selection before acquisition callbacks" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    acquisition.switch_backend_to_native = &backend.transaction_backend;
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var result = try api.execute(std.testing.allocator, request, backend.interface());
    defer result.deinit();
    try std.testing.expectEqual(transaction_engine.Kind.native, backend.transaction_backend);
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expectEqual(@as(usize, 1), executor.calls);
    try std.testing.expect((try readRootAttempt(directory.dir)) == null);
    var paths = try ResolvedPaths.init(std.testing.allocator, request, .legacy_dpkg);
    defer paths.deinit();
    try std.testing.expectEqualStrings(paths.operation_state_logical, result.paths.operation_state.?);
    var operation_dir = try executor.openOperationDirectory();
    defer operation_dir.close(std.testing.io);
    const store = try exact_lock_v2.Store.init(std.testing.io, operation_dir, exact_lock_name);
    var lock = try store.read(std.testing.allocator, exact_lock_v2.maximum_document_bytes);
    defer lock.deinit();
    try validateLockPolicy(lock.lock, .legacy_dpkg);
    try std.testing.expectError(error.LockPolicyMismatch, validateLockPolicy(lock.lock, .native));

    var next = try api.execute(std.testing.allocator, request, backend.interface());
    defer next.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, next.exit_status);
    try std.testing.expectEqual(api.DiagnosticId.transaction_backend_unavailable, next.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 1), executor.calls);
    try std.testing.expectEqual(@as(usize, 1), acquisition.descriptor_reads);
}

test "repository backend completes and idempotently resumes every production phase" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var result = try api.execute(std.testing.allocator, request, backend.interface());
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expect(result.changed);
    try std.testing.expect(result.installed);
    try std.testing.expect(result.refreshed);
    try std.testing.expectEqual(@as(usize, 1), executor.calls);
    try std.testing.expect(executor.saw_lock_before_install);
    try std.testing.expect(!executor.last_allow_host_root);
    try std.testing.expectEqual(@as(usize, 0), acquisition.network_requests);
    try expectRepositoryEvidence(directory.dir, result.paths.exact_lock);
    try expectRepositoryEvidence(directory.dir, result.paths.provenance);
    try expectRepositoryEvidence(directory.dir, result.paths.target_manifest);
    try expectRepositoryEvidence(directory.dir, result.paths.operation_state);

    result.deinit();
    result = try api.execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expect(!result.changed);
    try std.testing.expect(result.installed);
    try std.testing.expect(result.refreshed);
    try std.testing.expectEqual(@as(usize, 1), executor.calls);

    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc" ++ "/apt/sources.list.d/microsoft-prod.list",
        .data = "deb [signed-by=/usr/share/keyrings/microsoft-prod.gpg] " ++
            "file:///synthetic-repository testing main\n",
    });
    result.deinit();
    result = try api.execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.planning, result.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.managed_file_conflict,
        result.diagnostics[0].id,
    );
    try std.testing.expectEqual(@as(usize, 1), executor.calls);

    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc" ++ "/apt/sources.list.d/microsoft-prod.list",
        .data = test_repository_source,
    });
    result.deinit();
    result = try api.execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expectEqual(@as(usize, 1), executor.calls);
    const changed_descriptor = try std.testing.allocator.dupe(u8, descriptor);
    defer std.testing.allocator.free(changed_descriptor);
    const version_offset = std.mem.indexOf(
        u8,
        changed_descriptor,
        "Version: 1.1\n",
    ) orelse return error.MissingFixtureVersion;
    changed_descriptor[version_offset + "Version: 1.".len] = '2';
    acquisition.descriptor = changed_descriptor;
    var changed_request = request;
    changed_request.expected_sha256 = sha256(changed_descriptor);
    result.deinit();
    result = try api.execute(
        std.testing.allocator,
        changed_request,
        backend.interface(),
    );
    try std.testing.expectEqual(api.ExitStatus.planning, result.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.existing_descriptor_conflict,
        result.diagnostics[0].id,
    );
    try std.testing.expectEqual(@as(usize, 1), executor.calls);

    var original_paths = try ResolvedPaths.init(std.testing.allocator, request, .legacy_dpkg);
    defer original_paths.deinit();
    const provenance_relative = try std.fmt.allocPrint(
        std.testing.allocator,
        "root{s}",
        .{original_paths.provenance_logical},
    );
    defer std.testing.allocator.free(provenance_relative);
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = provenance_relative,
        .data = "{}",
    });
    acquisition.descriptor = descriptor;
    result.deinit();
    result = try api.execute(
        std.testing.allocator,
        request,
        backend.interface(),
    );
    try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.recovery_required,
        result.diagnostics[0].id,
    );
    try std.testing.expectEqual(@as(usize, 1), executor.calls);
}

test "repository backend holds bounded target locks for idempotent verification" {
    const descriptor = @embedFile(
        "fixtures/packages-microsoft-prod-depends_1.1_all.deb",
    );
    const fixture = @import("fixtures/openpgp.zig");
    const exact_status =
        "Package: hello\n" ++
        "Status: install ok installed\n" ++
        "Architecture: amd64\n" ++
        "Version: 1.0-1\n\n" ++
        "Package: packages-microsoft-prod\n" ++
        "Status: install ok installed\n" ++
        "Architecture: all\n" ++
        "Version: 1.1\n";
    const missing_dependency_status =
        "Package: packages-microsoft-prod\n" ++
        "Status: install ok installed\n" ++
        "Architecture: all\n" ++
        "Version: 1.1\n";
    const changed_version_status =
        "Package: hello\n" ++
        "Status: install ok installed\n" ++
        "Architecture: amd64\n" ++
        "Version: 2.0\n\n" ++
        "Package: packages-microsoft-prod\n" ++
        "Status: install ok installed\n" ++
        "Architecture: all\n" ++
        "Version: 1.1\n";
    const changed_architecture_status =
        "Package: hello\n" ++
        "Status: install ok installed\n" ++
        "Architecture: arm64\n" ++
        "Version: 1.0-1\n\n" ++
        "Package: packages-microsoft-prod\n" ++
        "Status: install ok installed\n" ++
        "Architecture: all\n" ++
        "Version: 1.1\n";
    const unhealthy_unrelated_status = exact_status ++
        "\nPackage: unrelated\n" ++
        "Status: install ok unpacked\n" ++
        "Architecture: amd64\n" ++
        "Version: 9\n";
    const healthy_unrelated_status = exact_status ++
        "\nPackage: unrelated\n" ++
        "Status: install ok installed\n" ++
        "Architecture: amd64\n" ++
        "Version: 9\n";
    const JournalMode = enum {
        none,
        unrelated_completed,
        matching_incomplete,
    };
    const Case = struct {
        status: []const u8,
        journal: JournalMode,
        expected_failure: ?transaction_recovery.VerificationFailure = null,
        expected_recovery_calls: usize = 0,
        target_lock_failure: ?usize = null,
    };
    const cases = [_]Case{
        .{ .status = exact_status, .journal = .none },
        .{ .status = exact_status, .journal = .unrelated_completed },
        .{
            .status = missing_dependency_status,
            .journal = .none,
            .expected_failure = .expected_package_missing,
        },
        .{
            .status = missing_dependency_status,
            .journal = .unrelated_completed,
            .expected_failure = .expected_package_missing,
        },
        .{
            .status = changed_version_status,
            .journal = .none,
            .expected_failure = .expected_identity_mismatch,
        },
        .{
            .status = changed_version_status,
            .journal = .unrelated_completed,
            .expected_failure = .expected_identity_mismatch,
        },
        .{
            .status = changed_architecture_status,
            .journal = .none,
            .expected_failure = .expected_package_missing,
        },
        .{
            .status = changed_architecture_status,
            .journal = .unrelated_completed,
            .expected_failure = .expected_package_missing,
        },
        .{
            .status = unhealthy_unrelated_status,
            .journal = .none,
            .expected_failure = .unhealthy_package,
        },
        .{
            .status = unhealthy_unrelated_status,
            .journal = .unrelated_completed,
            .expected_failure = .unhealthy_package,
        },
        .{
            .status = healthy_unrelated_status,
            .journal = .none,
        },
        .{
            .status = healthy_unrelated_status,
            .journal = .unrelated_completed,
        },
        .{
            .status = exact_status,
            .journal = .matching_incomplete,
            .expected_recovery_calls = 1,
        },
        .{
            .status = exact_status,
            .journal = .none,
            .target_lock_failure = 2,
        },
        .{
            .status = exact_status,
            .journal = .unrelated_completed,
            .target_lock_failure = 3,
        },
    };

    for (cases) |case| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        try directory.dir.createDirPath(
            std.testing.io,
            "root/etc" ++ "/apt/sources.list.d",
        );
        try directory.dir.createDirPath(
            std.testing.io,
            "root/usr/share/keyrings",
        );
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "root/etc" ++ "/apt/sources.list.d/microsoft-prod.list",
            .data = test_repository_source,
        });
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "root/usr/share/keyrings/microsoft-prod.gpg",
            .data = &fixture.keyring,
        });
        const root = try repositoryTestRoot(
            std.testing.allocator,
            directory.dir,
        );
        defer std.testing.allocator.free(root);
        var acquisition: RepositoryTestAcquisition = .{
            .descriptor = descriptor,
        };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
            .install_status = case.status,
        };
        var target_locks: RepositoryTargetLocks = .{
            .clock_ms = &acquisition.now_ms,
            .fail_call = case.target_lock_failure,
        };
        var locked_status: RepositoryLockedStatusReader = .{
            .locks = &target_locks,
            .stable = case.status,
            .intermediate = "Package: hello\n" ++
                "Status: install ok half-configured\n" ++
                "Architecture: amd64\n" ++
                "Version: 2.0\n",
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .target_locks = target_locks.interface(),
            .status_reader = locked_status.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = fixture.created + 30,
        };
        const request: api.Request = .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
            .network = .{
                .connect_timeout_ms = 100,
                .read_timeout_ms = 100,
                .overall_timeout_ms = 100,
            },
            .state = .{ .lock_wait_ms = 100 },
        };
        var first = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        try std.testing.expectEqual(api.ExitStatus.download, first.exit_status);
        try std.testing.expectEqual(
            api.DiagnosticId.dependency_acquisition_failed,
            first.diagnostics[0].id,
        );
        first.deinit();

        var paths = try ResolvedPaths.init(std.testing.allocator, request, .legacy_dpkg);
        defer paths.deinit();
        var operation_dir = try std.Io.Dir.cwd().openDir(
            std.testing.io,
            paths.operation_physical,
            .{ .follow_symlinks = false },
        );
        defer operation_dir.close(std.testing.io);
        const plan_store = try repository_plan.Store.init(
            std.testing.io,
            operation_dir,
            exact_plan_name,
        );
        var plan = try plan_store.read(std.testing.allocator);
        defer plan.deinit();
        const lock_store = try exact_lock_v2.Store.init(
            std.testing.io,
            operation_dir,
            exact_lock_name,
        );
        var lock = try lock_store.read(
            std.testing.allocator,
            exact_lock_v2.maximum_document_bytes,
        );
        defer lock.deinit();
        try std.testing.expectEqual(@as(usize, 2), lock.lock.packages.len);
        try executor.installDescriptorWithStatus(case.status);

        if (case.journal != .matching_incomplete) {
            const arena = try std.testing.allocator.create(
                std.heap.ArenaAllocator,
            );
            arena.* = .init(std.testing.allocator);
            var report: transaction_executor.Report = .{
                .allocator = std.testing.allocator,
                .arena = arena,
                .commands = &.{},
                .plan_sha256 = transaction_executor.planDigest(plan),
                .transaction_state = .complete,
                .root_identity = transaction_recovery.rootIdentity(root),
                .policy_sha256 = transaction_executor.policyDigest(
                    repositoryExecutionPolicy(request),
                ),
                .lock_sha256 = lock.lock.digest_sha256,
                .failure = null,
            };
            defer report.deinit();
            _ = try publishProvenance(
                std.testing.allocator,
                std.testing.io,
                operation_dir,
                root,
                &lock.lock,
                report,
                null,
            );
        }

        if (case.journal != .none) {
            const matching = case.journal == .matching_incomplete;
            const journal: transaction_recovery.Journal = .{
                .state = if (matching) .interrupted else .complete,
                .boundary = if (matching) .before_command else .verifying,
                .plan_sha256 = if (matching)
                    transaction_executor.planDigest(plan)
                else
                    @splat(0xa1),
                .root_identity = transaction_recovery.rootIdentity(root),
                .policy_sha256 = transaction_executor.policyDigest(
                    repositoryExecutionPolicy(request),
                ),
                .lock_sha256 = lock.lock.digest_sha256,
                .next_command = 0,
                .commands = &.{},
                .failure = if (matching) "injected interruption" else null,
            };
            var journal_store =
                try transaction_recovery.SystemJournalStore.init(
                    std.testing.io,
                    paths.state_physical,
                    root,
                );
            defer journal_store.deinit();
            if (matching)
                try transaction_recovery.persist(
                    std.testing.allocator,
                    journal_store.interface(),
                    root,
                    journal,
                )
            else
                try transaction_recovery.archive(
                    std.testing.allocator,
                    journal_store.interface(),
                    root,
                    journal,
                );
        }

        var resumed = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        defer resumed.deinit();
        if (case.target_lock_failure) |_| {
            try std.testing.expectEqual(
                api.ExitStatus.recovery,
                resumed.exit_status,
            );
            try std.testing.expectEqual(
                api.DiagnosticId.recovery_required,
                resumed.diagnostics[0].id,
            );
            try std.testing.expectEqualStrings(
                "resume-current-state-lock",
                resumed.diagnostics[0].phase.?,
            );
            try std.testing.expectEqualStrings(
                "LockTimeout",
                resumed.diagnostics[0].message,
            );
        } else if (case.expected_failure) |failure| {
            try std.testing.expectEqual(
                api.ExitStatus.recovery,
                resumed.exit_status,
            );
            try std.testing.expectEqual(
                api.DiagnosticId.recovery_required,
                resumed.diagnostics[0].id,
            );
            try std.testing.expectEqualStrings(
                "resume-current-state",
                resumed.diagnostics[0].phase.?,
            );
            try std.testing.expectEqualStrings(
                @tagName(failure),
                resumed.diagnostics[0].message,
            );
        } else {
            try std.testing.expectEqual(
                api.ExitStatus.success,
                resumed.exit_status,
            );
            try std.testing.expect(!resumed.changed);
        }
        try std.testing.expectEqual(@as(usize, 0), executor.calls);
        try std.testing.expectEqual(
            case.expected_recovery_calls,
            executor.recover_calls,
        );
        if (case.journal == .matching_incomplete) {
            try std.testing.expectEqual(@as(usize, 0), target_locks.calls);
            try std.testing.expectEqual(@as(usize, 0), target_locks.releases);
            try std.testing.expectEqual(@as(usize, 0), locked_status.calls);
        } else if (case.target_lock_failure) |failure_call| {
            try std.testing.expectEqual(failure_call, target_locks.calls);
            try std.testing.expectEqual(
                failure_call - 1,
                target_locks.releases,
            );
            try std.testing.expectEqual(@as(usize, 0), locked_status.calls);
        } else {
            try std.testing.expectEqual(@as(usize, 3), target_locks.calls);
            try std.testing.expectEqual(@as(usize, 3), target_locks.releases);
            try std.testing.expectEqual(@as(usize, 1), locked_status.calls);
            try std.testing.expect(!locked_status.read_before_all_locks);
            try std.testing.expectEqual(@as(u64, 100), target_locks.waits[0].?);
            try std.testing.expectEqual(@as(u64, 99), target_locks.waits[1].?);
            try std.testing.expectEqual(@as(u64, 97), target_locks.waits[2].?);
        }
    }
}

test "repository backend resumes immediately after durable planned checkpoint" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
    };
    var failure: RepositoryStateFailure = .{
        .boundary = .after_rename,
        .fail_from_write = 5,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
        .state_write_hooks = failure.hooks(),
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var interrupted = try api.execute(
        std.testing.allocator,
        request,
        backend.interface(),
    );
    try std.testing.expectEqual(api.ExitStatus.unavailable, interrupted.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.state_persistence_failed,
        interrupted.diagnostics[0].id,
    );
    try std.testing.expectEqual(api.PhaseState.complete, interrupted.planned);
    try std.testing.expect(interrupted.paths.exact_lock == null);
    try std.testing.expectEqual(@as(usize, 0), executor.calls);
    interrupted.deinit();

    backend.state_write_hooks = .{};
    acquisition.descriptor_available = false;
    var resumed = try api.execute(
        std.testing.allocator,
        request,
        backend.interface(),
    );
    defer resumed.deinit();
    try std.testing.expectEqual(api.ExitStatus.success, resumed.exit_status);
    try std.testing.expect(resumed.paths.exact_lock != null);
    try std.testing.expectEqual(@as(usize, 1), executor.calls);
    try std.testing.expectEqual(@as(usize, 1), acquisition.descriptor_reads);
}

test "repository backend resumes validated HTTPS descriptor from CAS without transport" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{
        .descriptor = descriptor,
        .network_descriptor = descriptor,
        .network_available = true,
    };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
    };
    var failure: RepositoryStateFailure = .{
        .boundary = .after_rename,
        .fail_from_write = 5,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
        .state_write_hooks = failure.hooks(),
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "https://vendor.test/descriptor.deb",
        .architecture = "amd64",
    };
    var interrupted = try api.execute(
        std.testing.allocator,
        request,
        backend.interface(),
    );
    try std.testing.expectEqual(api.ExitStatus.unavailable, interrupted.exit_status);
    try std.testing.expectEqual(api.TrustMode.verified_https, interrupted.descriptor.?.trust_mode);
    interrupted.deinit();

    backend.state_write_hooks = .{};
    acquisition.network_available = false;
    var resumed = try api.execute(
        std.testing.allocator,
        request,
        backend.interface(),
    );
    defer resumed.deinit();
    try std.testing.expectEqual(api.ExitStatus.success, resumed.exit_status);
    try std.testing.expectEqual(api.TrustMode.verified_https, resumed.descriptor.?.trust_mode);
    try std.testing.expectEqual(@as(usize, 1), acquisition.network_requests);
    try std.testing.expectEqual(@as(usize, 0), acquisition.descriptor_reads);
}

test "repository backend rejects changed transport and unavailable corrupt descriptor CAS" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const Mode = enum { missing_changed, corrupt_unavailable };
    inline for ([_]Mode{ .missing_changed, .corrupt_unavailable }) |mode| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        var acquisition: RepositoryTestAcquisition = .{
            .descriptor = descriptor,
            .network_descriptor = descriptor,
            .network_available = true,
        };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
        };
        var failure: RepositoryStateFailure = .{
            .boundary = .after_rename,
            .fail_from_write = 5,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .state_write_hooks = failure.hooks(),
        };
        const request: api.Request = .{
            .root = root,
            .descriptor_url = "https://vendor.test/descriptor.deb",
            .architecture = "amd64",
        };
        var interrupted = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        try std.testing.expectEqual(api.ExitStatus.unavailable, interrupted.exit_status);
        interrupted.deinit();

        var digest_hex: [64]u8 = undefined;
        const descriptor_digest = sha256(descriptor);
        formatHex(&digest_hex, &descriptor_digest);
        const object_path = try std.fmt.allocPrint(
            std.testing.allocator,
            "root/var/cache/debz/packages-v1/objects/{s}",
            .{&digest_hex},
        );
        defer std.testing.allocator.free(object_path);
        var changed_storage: ?[]u8 = null;
        defer if (changed_storage) |bytes| std.testing.allocator.free(bytes);
        switch (mode) {
            .missing_changed => {
                try directory.dir.deleteFile(std.testing.io, object_path);
                const changed = try std.testing.allocator.dupe(u8, descriptor);
                changed[changed.len / 2] ^= 1;
                changed_storage = changed;
                acquisition.network_descriptor = changed;
            },
            .corrupt_unavailable => {
                const corrupt = try std.testing.allocator.alloc(u8, descriptor.len);
                defer std.testing.allocator.free(corrupt);
                @memset(corrupt, 0xa5);
                try directory.dir.writeFile(std.testing.io, .{
                    .sub_path = object_path,
                    .data = corrupt,
                });
                acquisition.network_available = false;
            },
        }
        backend.state_write_hooks = .{};
        var resumed = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        defer resumed.deinit();
        try std.testing.expectEqual(api.ExitStatus.download, resumed.exit_status);
        try std.testing.expectEqual(
            api.DiagnosticId.acquisition_failed,
            resumed.diagnostics[0].id,
        );
        try std.testing.expectEqual(@as(usize, 0), executor.calls);
        try std.testing.expectEqual(@as(usize, 2), acquisition.network_requests);
    }
}

test "repository backend binds execution and recovery provenance to the persisted exact lock" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
        .interrupt_first = true,
        .interrupt_before_install = true,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var interrupted = try api.execute(
        std.testing.allocator,
        request,
        backend.interface(),
    );
    try std.testing.expectEqual(api.ExitStatus.transaction, interrupted.exit_status);
    try std.testing.expect(!interrupted.installed);
    try std.testing.expect(interrupted.paths.exact_lock != null);
    try std.testing.expect(interrupted.paths.provenance == null);
    try std.testing.expect(executor.saw_exact_lock);

    var paths = try ResolvedPaths.init(std.testing.allocator, request, .legacy_dpkg);
    defer paths.deinit();
    var operation_dir = try std.Io.Dir.cwd().openDir(
        std.testing.io,
        paths.operation_physical,
        .{ .follow_symlinks = false },
    );
    defer operation_dir.close(std.testing.io);
    const lock_store = try exact_lock_v2.Store.init(
        std.testing.io,
        operation_dir,
        exact_lock_name,
    );
    var first_lock = try lock_store.read(
        std.testing.allocator,
        exact_lock_v2.maximum_document_bytes,
    );
    defer first_lock.deinit();
    const persisted_digest = first_lock.lock.digest_sha256;

    interrupted.deinit();
    try operation_dir.deleteFile(std.testing.io, exact_lock_name);
    var missing_lock = try api.execute(
        std.testing.allocator,
        request,
        backend.interface(),
    );
    try std.testing.expectEqual(api.ExitStatus.recovery, missing_lock.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.recovery_required,
        missing_lock.diagnostics[0].id,
    );
    try std.testing.expectEqual(@as(usize, 1), executor.calls);
    missing_lock.deinit();
    try lock_store.writeAtomic(std.testing.allocator, first_lock.lock);

    var recovered = try api.execute(
        std.testing.allocator,
        request,
        backend.interface(),
    );
    defer recovered.deinit();
    try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
    try std.testing.expect(recovered.installed);
    try std.testing.expect(recovered.paths.provenance != null);
    try std.testing.expectEqual(@as(usize, 2), executor.calls);
    try std.testing.expectEqual(@as(usize, 1), executor.recover_calls);
    try std.testing.expect(executor.recovered_exact_lock);
    var final_lock = try lock_store.read(
        std.testing.allocator,
        exact_lock_v2.maximum_document_bytes,
    );
    defer final_lock.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &persisted_digest,
        &final_lock.lock.digest_sha256,
    );
    try validateRecoveryEvidence(
        std.testing.allocator,
        std.testing.io,
        operation_dir,
        recovered.descriptor.?,
    );
}

test "repository backend classifies shared transaction journals before recovery" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const Case = enum {
        matching_incomplete,
        mismatched_plan_incomplete,
        mismatched_policy_incomplete,
        mismatched_lock_incomplete,
        unrelated_completed,
    };
    inline for ([_]Case{
        .matching_incomplete,
        .mismatched_plan_incomplete,
        .mismatched_policy_incomplete,
        .mismatched_lock_incomplete,
        .unrelated_completed,
    }) |case| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
            .interrupt_first = true,
            .interrupt_before_install = true,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
        };
        const request: api.Request = .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
        };
        var first = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        try std.testing.expectEqual(api.ExitStatus.transaction, first.exit_status);
        first.deinit();
        executor.interrupt_first = false;

        var paths = try ResolvedPaths.init(std.testing.allocator, request, .legacy_dpkg);
        defer paths.deinit();
        var operation_dir = try std.Io.Dir.cwd().openDir(
            std.testing.io,
            paths.operation_physical,
            .{ .follow_symlinks = false },
        );
        defer operation_dir.close(std.testing.io);
        const plan_store = try repository_plan.Store.init(
            std.testing.io,
            operation_dir,
            exact_plan_name,
        );
        var plan = try plan_store.read(std.testing.allocator);
        defer plan.deinit();
        const lock_store = try exact_lock_v2.Store.init(
            std.testing.io,
            operation_dir,
            exact_lock_name,
        );
        var lock = try lock_store.read(
            std.testing.allocator,
            exact_lock_v2.maximum_document_bytes,
        );
        defer lock.deinit();
        const policy = repositoryExecutionPolicy(request);
        const matching = case == .matching_incomplete;
        const completed = case == .unrelated_completed;
        const plan_matches = matching or
            case == .mismatched_policy_incomplete or
            case == .mismatched_lock_incomplete;
        const journal: transaction_recovery.Journal = .{
            .state = if (completed) .complete else .interrupted,
            .boundary = if (completed) .verifying else .before_command,
            .plan_sha256 = if (plan_matches)
                transaction_executor.planDigest(plan)
            else
                @splat(0xa1),
            .root_identity = transaction_recovery.rootIdentity(root),
            .policy_sha256 = if (case == .mismatched_policy_incomplete)
                @splat(0xa2)
            else
                transaction_executor.policyDigest(policy),
            .lock_sha256 = if (case == .mismatched_lock_incomplete)
                @splat(0xa3)
            else
                lock.lock.digest_sha256,
            .next_command = 0,
            .commands = &.{},
            .failure = if (completed) null else "injected interruption",
        };
        var journal_store = try transaction_recovery.SystemJournalStore.init(
            std.testing.io,
            paths.state_physical,
            root,
        );
        defer journal_store.deinit();
        if (completed)
            try transaction_recovery.archive(
                std.testing.allocator,
                journal_store.interface(),
                root,
                journal,
            )
        else
            try transaction_recovery.persist(
                std.testing.allocator,
                journal_store.interface(),
                root,
                journal,
            );

        var resumed = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        defer resumed.deinit();
        switch (case) {
            .matching_incomplete => {
                try std.testing.expectEqual(api.ExitStatus.success, resumed.exit_status);
                try std.testing.expectEqual(@as(usize, 1), executor.calls);
                try std.testing.expectEqual(@as(usize, 1), executor.recover_calls);
            },
            .mismatched_plan_incomplete,
            .mismatched_policy_incomplete,
            .mismatched_lock_incomplete,
            => {
                try std.testing.expectEqual(api.ExitStatus.recovery, resumed.exit_status);
                try std.testing.expectEqual(
                    api.DiagnosticId.recovery_required,
                    resumed.diagnostics[0].id,
                );
                try std.testing.expectEqual(@as(usize, 1), executor.calls);
                try std.testing.expectEqual(@as(usize, 0), executor.recover_calls);
            },
            .unrelated_completed => {
                try std.testing.expectEqual(api.ExitStatus.success, resumed.exit_status);
                try std.testing.expectEqual(@as(usize, 2), executor.calls);
                try std.testing.expectEqual(@as(usize, 0), executor.recover_calls);
            },
        }
    }
}

test "repository backend replays the exact durable plan for interrupted dpkg states" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const interrupted_states = [_][]const u8{
        "Package: packages-microsoft-prod\n" ++
            "Status: install ok unpacked\n" ++
            "Architecture: all\n" ++
            "Version: 1.1\n",
        "Package: packages-microsoft-prod\n" ++
            "Status: install ok half-configured\n" ++
            "Architecture: all\n" ++
            "Version: 1.1\n",
    };
    for (interrupted_states) |status| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
            .interrupt_first = true,
            .interrupted_status = status,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
        };
        const request: api.Request = .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
        };
        var first = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        try std.testing.expectEqual(api.ExitStatus.transaction, first.exit_status);
        first.deinit();
        var resumed = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        defer resumed.deinit();
        try std.testing.expectEqual(api.ExitStatus.success, resumed.exit_status);
        try std.testing.expectEqual(@as(usize, 1), executor.recover_calls);
        try std.testing.expectEqualSlices(
            u8,
            &executor.first_plan_sha256.?,
            &executor.recovery_plan_sha256.?,
        );

        var paths = try ResolvedPaths.init(std.testing.allocator, request, .legacy_dpkg);
        defer paths.deinit();
        var operation = try std.Io.Dir.cwd().openDir(
            std.testing.io,
            paths.operation_physical,
            .{ .follow_symlinks = false },
        );
        defer operation.close(std.testing.io);
        const plan_store = try repository_plan.Store.init(
            std.testing.io,
            operation,
            exact_plan_name,
        );
        var replay = try plan_store.read(std.testing.allocator);
        defer replay.deinit();
        try std.testing.expectEqualSlices(
            u8,
            &executor.first_plan_sha256.?,
            &transaction_executor.planDigest(replay),
        );
    }
}

test "repository backend replays closure when a dependency is partially installed" {
    const descriptor = @embedFile(
        "fixtures/packages-microsoft-prod-depends_1.1_all.deb",
    );
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "Package: hello\n" ++
            "Status: install ok installed\n" ++
            "Architecture: amd64\n" ++
            "Version: 1.0-1\n",
    });
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
        .interrupt_first = true,
        .interrupted_status = "Package: hello\n" ++
            "Status: install ok unpacked\n" ++
            "Architecture: amd64\n" ++
            "Version: 1.0-1\n",
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var first = try api.execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.transaction, first.exit_status);
    first.deinit();
    var resumed = try api.execute(std.testing.allocator, request, backend.interface());
    defer resumed.deinit();
    try std.testing.expectEqual(api.ExitStatus.success, resumed.exit_status);
    try std.testing.expectEqual(@as(usize, 1), executor.recover_calls);
    try std.testing.expectEqualSlices(
        u8,
        &executor.first_plan_sha256.?,
        &executor.recovery_plan_sha256.?,
    );
}

test "repository backend rejects changed requests during exact-plan recovery" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
        .interrupt_first = true,
        .interrupt_before_install = true,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var first = try api.execute(std.testing.allocator, request, backend.interface());
    defer first.deinit();
    try std.testing.expectEqual(api.ExitStatus.transaction, first.exit_status);

    var changed = request;
    changed.resources.maximum_actions -= 1;
    var resumed = try api.execute(std.testing.allocator, changed, backend.interface());
    defer resumed.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, resumed.exit_status);
    try std.testing.expectEqual(api.DiagnosticId.recovery_required, resumed.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 0), executor.recover_calls);
}

test "repository backend rejects a tampered persisted executable plan" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
        .interrupt_first = true,
        .interrupt_before_install = true,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var first = try api.execute(std.testing.allocator, request, backend.interface());
    defer first.deinit();
    try std.testing.expectEqual(api.ExitStatus.transaction, first.exit_status);
    const operation_logical =
        std.fs.path.dirname(first.paths.operation_state.?) orelse
        return error.MissingOperationDirectory;
    const operation_relative = try std.fmt.allocPrint(
        std.testing.allocator,
        "root{s}",
        .{operation_logical},
    );
    defer std.testing.allocator.free(operation_relative);
    var operation = try directory.dir.openDir(
        std.testing.io,
        operation_relative,
        .{ .follow_symlinks = false },
    );
    defer operation.close(std.testing.io);
    try operation.writeFile(std.testing.io, .{
        .sub_path = exact_plan_name,
        .data = "{}",
    });

    var resumed = try api.execute(std.testing.allocator, request, backend.interface());
    defer resumed.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, resumed.exit_status);
    try std.testing.expectEqual(api.DiagnosticId.recovery_required, resumed.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 0), executor.recover_calls);
}

test "repository backend rejects mismatched local artifact evidence on recovery" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
        .interrupt_first = true,
        .interrupt_before_install = true,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var first = try api.execute(std.testing.allocator, request, backend.interface());
    defer first.deinit();
    try std.testing.expectEqual(api.ExitStatus.transaction, first.exit_status);
    const operation_logical =
        std.fs.path.dirname(first.paths.exact_lock.?) orelse
        return error.MissingOperationDirectory;
    const operation_relative = try std.fmt.allocPrint(
        std.testing.allocator,
        "root{s}",
        .{operation_logical},
    );
    defer std.testing.allocator.free(operation_relative);
    var operation = try directory.dir.openDir(
        std.testing.io,
        operation_relative,
        .{ .follow_symlinks = false },
    );
    defer operation.close(std.testing.io);
    const store = try exact_lock_v2.Store.init(std.testing.io, operation, exact_lock_name);
    var original = try store.read(
        std.testing.allocator,
        exact_lock_v2.maximum_document_bytes,
    );
    defer original.deinit();
    var artifacts = try std.testing.allocator.dupe(
        package_origin.LocalArtifactEvidence,
        original.lock.local_artifacts,
    );
    defer std.testing.allocator.free(artifacts);
    const packages = try std.testing.allocator.dupe(
        exact_lock_v2.Package,
        original.lock.packages,
    );
    defer std.testing.allocator.free(packages);
    const tampered_digest: [32]u8 = @splat(0xee);
    artifacts[0].sha256 = tampered_digest;
    artifacts[0].artifact_id = package_origin.artifactIdFromSha256(tampered_digest);
    for (packages) |*package| switch (package.origin) {
        .local_artifact => {
            package.sha256 = tampered_digest;
            package.origin = .{ .local_artifact = artifacts[0] };
        },
        .authenticated_repository => {},
    };
    var tampered = try exact_lock_v2.create(std.testing.allocator, .{
        .target_architecture = original.lock.target_architecture,
        .request_sha256 = original.lock.request_sha256,
        .policy_sha256 = original.lock.policy_sha256,
        .repositories = original.lock.repositories,
        .local_artifacts = artifacts,
        .packages = packages,
        .verified_origins = true,
    });
    defer tampered.deinit();
    try store.writeAtomic(std.testing.allocator, tampered.lock);

    var resumed = try api.execute(std.testing.allocator, request, backend.interface());
    defer resumed.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, resumed.exit_status);
    try std.testing.expectEqual(api.DiagnosticId.recovery_required, resumed.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 0), executor.recover_calls);
}

test "repository backend reconstructs provenance after successful dpkg publication gap" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
        .lock_digest_mode = .missing,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var first = try api.execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.post_install, first.exit_status);
    try std.testing.expect(first.installed);
    try std.testing.expect(first.paths.provenance == null);
    first.deinit();

    executor.lock_digest_mode = .exact;
    var resumed = try api.execute(std.testing.allocator, request, backend.interface());
    defer resumed.deinit();
    try std.testing.expectEqual(api.ExitStatus.success, resumed.exit_status);
    try std.testing.expect(resumed.paths.provenance != null);
    try std.testing.expectEqual(@as(usize, 1), executor.recover_calls);
}

test "repository backend rejects missing and mismatched executor lock digests" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    inline for (.{ RepositoryTestExecutor.LockDigestMode.missing, .mismatch }) |mode| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
            .lock_digest_mode = mode,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
        };
        var result = try api.execute(std.testing.allocator, .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
        }, backend.interface());
        defer result.deinit();
        try std.testing.expectEqual(api.ExitStatus.post_install, result.exit_status);
        try std.testing.expectEqual(
            api.DiagnosticId.provenance_publication_failed,
            result.diagnostics[0].id,
        );
        try std.testing.expect(result.installed);
        try std.testing.expect(result.paths.exact_lock != null);
        try std.testing.expect(result.paths.provenance == null);
        try std.testing.expect(executor.saw_exact_lock);
    }
}

test "repository backend reports and reconciles interrupted state transitions after mutation" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const cases = [_]struct {
        fail_from_write: usize,
        boundary: state_module.WriteBoundary,
        expect_manifest: bool,
        expect_refreshed: bool,
    }{
        .{ .fail_from_write = 7, .boundary = .before_stage, .expect_manifest = false, .expect_refreshed = false },
        .{ .fail_from_write = 7, .boundary = .after_rename, .expect_manifest = false, .expect_refreshed = false },
        .{ .fail_from_write = 8, .boundary = .before_stage, .expect_manifest = true, .expect_refreshed = false },
        .{ .fail_from_write = 9, .boundary = .before_stage, .expect_manifest = true, .expect_refreshed = true },
    };
    for (cases) |case| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
        };
        var failure: RepositoryStateFailure = .{
            .boundary = case.boundary,
            .fail_from_write = case.fail_from_write,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .state_write_hooks = failure.hooks(),
        };
        const request: api.Request = .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
        };
        var failed = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        try std.testing.expectEqual(api.ExitStatus.post_install, failed.exit_status);
        try std.testing.expectEqual(
            api.DiagnosticId.state_persistence_failed,
            failed.diagnostics[0].id,
        );
        try std.testing.expect(failed.installed);
        try std.testing.expect(failed.paths.exact_lock != null);
        try std.testing.expect(failed.paths.provenance != null);
        try std.testing.expectEqual(case.expect_manifest, failed.paths.target_manifest != null);
        try std.testing.expectEqual(case.expect_refreshed, failed.refreshed);

        backend.state_write_hooks = .{};
        failed.deinit();
        var resumed = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        defer resumed.deinit();
        try std.testing.expectEqual(api.ExitStatus.success, resumed.exit_status);
        try std.testing.expect(resumed.installed);
        try std.testing.expect(resumed.refreshed);
        try std.testing.expect(resumed.paths.exact_lock != null);
        try std.testing.expect(resumed.paths.provenance != null);
        try std.testing.expect(resumed.paths.target_manifest != null);
        try std.testing.expectEqual(@as(usize, 1), executor.calls);
    }
}

test "repository operation identity separates both no-refresh transitions" {
    const base: api.Request = .{
        .root = "/target",
        .descriptor_url = "https://example.test/descriptor.deb",
        .architecture = "amd64",
    };
    var no_refresh = base;
    no_refresh.no_refresh = true;
    for ([_]transaction_engine.Kind{ .legacy_dpkg, .native }) |backend| {
        const refreshed_id = requestOperationId(base, backend);
        const no_refresh_id = requestOperationId(no_refresh, backend);
        try std.testing.expect(!std.mem.eql(u8, &refreshed_id, &no_refresh_id));
        try std.testing.expect(!std.mem.eql(
            u8,
            &requestOperationId(no_refresh, backend),
            &requestOperationId(base, backend),
        ));
    }
}

test "opposite no-refresh invocations never reuse or erase durable operation history" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    inline for (.{ false, true }) |first_no_refresh| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
        };
        const first_request: api.Request = .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
            .no_refresh = first_no_refresh,
        };
        var first = try api.execute(
            std.testing.allocator,
            first_request,
            backend.interface(),
        );
        try std.testing.expectEqual(api.ExitStatus.success, first.exit_status);
        try std.testing.expectEqual(!first_no_refresh, first.refreshed);

        var second_request = first_request;
        second_request.no_refresh = !first_no_refresh;
        first.deinit();
        var second = try api.execute(
            std.testing.allocator,
            second_request,
            backend.interface(),
        );
        defer second.deinit();
        try std.testing.expectEqual(api.ExitStatus.planning, second.exit_status);
        try std.testing.expectEqual(
            api.DiagnosticId.existing_descriptor_conflict,
            second.diagnostics[0].id,
        );
        try std.testing.expectEqual(@as(usize, 1), executor.calls);

        var first_paths = try ResolvedPaths.init(
            std.testing.allocator,
            first_request,
            .legacy_dpkg,
        );
        defer first_paths.deinit();
        var first_operation_dir = try std.Io.Dir.cwd().openDir(
            std.testing.io,
            first_paths.operation_physical,
            .{ .follow_symlinks = false },
        );
        defer first_operation_dir.close(std.testing.io);
        const state_store = try state_module.Store.init(
            std.testing.io,
            first_operation_dir,
            operation_state_name,
        );
        var durable = try state_store.read(
            std.testing.allocator,
            state_module.maximum_document_bytes,
        );
        defer durable.deinit();
        try std.testing.expectEqual(first_no_refresh, durable.state.no_refresh);
        try std.testing.expectEqual(!first_no_refresh, durable.state.refreshed);
        try std.testing.expectEqual(state_module.Phase.complete, durable.state.phase);
    }
}

test "repository operation budget enforces exact boundaries and checked overflow" {
    var counter: u64 = 0;
    try OperationBudget.charge(&counter, 10, 10);
    try std.testing.expectEqual(@as(u64, 10), counter);
    try std.testing.expectError(
        error.ResourceBudgetExceeded,
        OperationBudget.charge(&counter, 1, 10),
    );
    counter = std.math.maxInt(u64);
    try std.testing.expectError(
        error.ResourceBudgetExceeded,
        OperationBudget.charge(&counter, 1, std.math.maxInt(u64)),
    );

    var acquisition: RepositoryTestAcquisition = .{ .descriptor = "" };
    var budget = OperationBudget.init(
        acquisition.dependencies().clock,
        .{ .maximum_repositories = 2 },
        100,
        std.testing.allocator,
    );
    acquisition.now_ms = 40;
    const bounded_time = try budget.boundedTime(.{
        .connect_timeout_ms = 90,
        .read_timeout_ms = 80,
        .overall_timeout_ms = 70,
    });
    try std.testing.expectEqual(@as(u64, 60), bounded_time.connect_timeout_ms);
    try std.testing.expectEqual(@as(u64, 60), bounded_time.read_timeout_ms);
    try std.testing.expectEqual(@as(u64, 60), bounded_time.overall_timeout_ms);
    _ = try budget.boundedNetwork(.{}, 2);
    try std.testing.expectError(
        error.ResourceBudgetExceeded,
        budget.boundedNetwork(.{}, 3),
    );
    budget.cache_growth_bytes = budget.policy.maximum_cache_growth_bytes;
    try std.testing.expectError(
        error.ResourceBudgetExceeded,
        budget.reserveCacheGrowth(1, null),
    );

    const local_evidence: package_origin.LocalArtifactEvidence = .{
        .artifact_id = @splat('a'),
        .sha256 = @splat(0x11),
        .size = 4,
        .package = "descriptor",
        .version = "1",
        .architecture = "amd64",
        .acquisition_url = "file:///descriptor.deb",
        .trust_mode = .pinned_sha256,
    };
    const packages = [_]exact_lock_v2.Package{
        .{
            .name = "dependency",
            .version = "1",
            .architecture = "amd64",
            .origin = .{ .authenticated_repository = .{
                .repository_id = @splat('b'),
                .repository_snapshot_sha256 = @splat(0x22),
            } },
            .sha256 = @splat(0x33),
            .declared_size = 7,
            .retention = .dependency,
            .dpkg_selection_hold = false,
        },
        .{
            .name = "descriptor",
            .version = "1",
            .architecture = "amd64",
            .origin = .{ .local_artifact = local_evidence },
            .sha256 = local_evidence.sha256,
            .declared_size = local_evidence.size,
            .retention = .requested,
            .dpkg_selection_hold = false,
        },
    };
    const lock: exact_lock_v2.Lock = .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(0x44),
        .policy_sha256 = @splat(0x55),
        .repositories = &.{},
        .local_artifacts = &.{local_evidence},
        .packages = &packages,
        .digest_sha256 = @splat(0x66),
    };
    var aggregate = OperationBudget.init(
        acquisition.dependencies().clock,
        .{
            .maximum_actions = packages.len,
            .maximum_total_package_bytes = 11,
            .maximum_retained_package_bytes = 11,
        },
        100,
        std.testing.allocator,
    );
    aggregate.descriptor_bytes = local_evidence.size;
    try aggregate.validateLock(lock);
    try std.testing.expectEqual(@as(usize, 7), try aggregate.packageLimit(20));
    aggregate.policy.maximum_total_package_bytes = 10;
    try std.testing.expectError(
        error.ResourceBudgetExceeded,
        aggregate.validateLock(lock),
    );
    aggregate.policy.maximum_total_package_bytes = 11;
    aggregate.policy.maximum_retained_package_bytes = 10;
    try std.testing.expectError(
        error.ResourceBudgetExceeded,
        aggregate.validateLock(lock),
    );
    aggregate.policy.maximum_retained_package_bytes = 11;
    aggregate.policy.maximum_actions = 1;
    try std.testing.expectError(
        error.ResourceBudgetExceeded,
        aggregate.validateLock(lock),
    );
}

test "repository operation lock wait is capped by the absolute operation budget" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const Case = struct {
        lock_wait_ms: u64,
        overall_ms: u64,
        advance_ms: u64,
        fail_lock: bool,
        expected_wait_ms: u64,
        expected_status: api.ExitStatus,
        expected_diagnostic: api.DiagnosticId,
    };
    const cases = [_]Case{
        .{
            .lock_wait_ms = 40,
            .overall_ms = 100,
            .advance_ms = 0,
            .fail_lock = true,
            .expected_wait_ms = 40,
            .expected_status = .recovery,
            .expected_diagnostic = .recovery_required,
        },
        .{
            .lock_wait_ms = 200,
            .overall_ms = 100,
            .advance_ms = 0,
            .fail_lock = true,
            .expected_wait_ms = 100,
            .expected_status = .recovery,
            .expected_diagnostic = .recovery_required,
        },
        .{
            .lock_wait_ms = 200,
            .overall_ms = 100,
            .advance_ms = 100,
            .fail_lock = true,
            .expected_wait_ms = 100,
            .expected_status = .unavailable,
            .expected_diagnostic = .resource_limit_exceeded,
        },
        .{
            .lock_wait_ms = 200,
            .overall_ms = 100,
            .advance_ms = 100,
            .fail_lock = false,
            .expected_wait_ms = 100,
            .expected_status = .unavailable,
            .expected_diagnostic = .resource_limit_exceeded,
        },
    };
    for (cases) |case| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
        };
        var operation_lock: RepositoryOperationLock = .{
            .clock_ms = &acquisition.now_ms,
            .advance_ms = case.advance_ms,
            .fail = case.fail_lock,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .operation_locks = operation_lock.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
        };
        var result = try api.execute(std.testing.allocator, .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
            .state = .{ .lock_wait_ms = case.lock_wait_ms },
            .network = .{
                .connect_timeout_ms = case.overall_ms,
                .read_timeout_ms = case.overall_ms,
                .overall_timeout_ms = case.overall_ms,
            },
        }, backend.interface());
        defer result.deinit();
        try std.testing.expectEqual(case.expected_status, result.exit_status);
        try std.testing.expectEqual(
            case.expected_diagnostic,
            result.diagnostics[0].id,
        );
        try std.testing.expectEqual(@as(usize, 1), operation_lock.calls);
        try std.testing.expectEqual(case.expected_wait_ms, operation_lock.last_wait_ms.?);
        try std.testing.expectEqual(@as(usize, 0), acquisition.descriptor_reads);
        try std.testing.expectEqual(@as(usize, 0), acquisition.network_requests);
        try std.testing.expectEqual(@as(usize, 0), executor.calls);
    }
}

test "repository backend enforces an operation-wide elapsed deadline" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{
        .descriptor = descriptor,
        .advance_ms_per_read = 6,
    };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    var result = try api.execute(std.testing.allocator, .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
        .network = .{
            .connect_timeout_ms = 15,
            .read_timeout_ms = 15,
            .overall_timeout_ms = 15,
        },
    }, backend.interface());
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, result.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.resource_limit_exceeded,
        result.diagnostics[0].id,
    );
    try std.testing.expectEqual(@as(usize, 0), executor.calls);
}

test "repository backend reports elapsed budget exhaustion after mutation truthfully" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
        .clock_ms = &acquisition.now_ms,
        .advance_ms_after_install = 101,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    var result = try api.execute(std.testing.allocator, .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
        .no_refresh = true,
        .network = .{
            .connect_timeout_ms = 100,
            .read_timeout_ms = 100,
            .overall_timeout_ms = 100,
        },
    }, backend.interface());
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.post_install, result.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.resource_limit_exceeded,
        result.diagnostics[0].id,
    );
    try std.testing.expect(result.installed);
    try std.testing.expect(result.paths.exact_lock != null);
    try std.testing.expect(result.paths.provenance != null);
    try std.testing.expectEqual(@as(usize, 1), executor.calls);
}

test "repository backend retains installed evidence when final refresh fails" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{
        .descriptor = descriptor,
        .fail_in_release_request = 2,
    };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var result = try api.execute(std.testing.allocator, request, backend.interface());
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.post_install, result.exit_status);
    try std.testing.expectEqual(api.DiagnosticId.refresh_failed, result.diagnostics[0].id);
    try std.testing.expect(result.installed);
    try std.testing.expect(!result.refreshed);
    try std.testing.expect(result.paths.exact_lock != null);
    try std.testing.expect(result.paths.provenance != null);
    try std.testing.expect(result.paths.target_manifest != null);
    try std.testing.expectEqual(@as(usize, 1), executor.calls);

    acquisition.fail_in_release_request = null;
    result.deinit();
    result = try api.execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expect(!result.changed);
    try std.testing.expect(result.installed);
    try std.testing.expect(result.refreshed);
    try std.testing.expectEqual(@as(usize, 1), executor.calls);
}

test "repository backend completes no-refresh without a final network phase" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    var result = try api.execute(std.testing.allocator, .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
        .no_refresh = true,
    }, backend.interface());
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expectEqual(api.PhaseState.skipped, result.refreshed_phase);
    try std.testing.expect(!result.refreshed);
    try std.testing.expectEqual(@as(usize, 1), acquisition.in_release_requests);
}

test "repository backend authentication failure never reaches mutation" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{
        .descriptor = descriptor,
        .fail_in_release_request = 1,
    };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var result = try api.execute(
        std.testing.allocator,
        request,
        backend.interface(),
    );
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.authentication, result.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.repository_authentication_failed,
        result.diagnostics[0].id,
    );
    try std.testing.expectEqual(@as(usize, 0), executor.calls);
    try std.testing.expect(result.paths.exact_lock == null);
}

test "repository backend refreshes only newly introduced managed repositories" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const fixture = @import("fixtures/openpgp.zig");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    try directory.dir.createDirPath(
        std.testing.io,
        "root/etc" ++ "/apt/sources.list.d",
    );
    try directory.dir.createDirPath(std.testing.io, "root/usr/share/keyrings");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc" ++ "/apt/sources.list.d/microsoft-prod.list",
        .data = test_repository_source,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/usr/share/keyrings/microsoft-prod.gpg",
        .data = &fixture.keyring,
    });
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = fixture.created + 30,
    };
    const request: api.Request = .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    };
    var result = try api.execute(
        std.testing.allocator,
        request,
        backend.interface(),
    );
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expectEqual(api.PhaseState.skipped, result.refreshed_phase);
    try std.testing.expect(!result.refreshed);
    try std.testing.expectEqual(@as(usize, 1), acquisition.in_release_requests);
    result.deinit();
    result = try api.execute(
        std.testing.allocator,
        request,
        backend.interface(),
    );
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expectEqual(api.PhaseState.skipped, result.refreshed_phase);
    try std.testing.expectEqual(@as(usize, 2), acquisition.in_release_requests);
    try std.testing.expectEqual(@as(usize, 1), executor.calls);
}

test "repository backend selects only changed descriptor repositories for final refresh" {
    const fixture = @import("fixtures/openpgp.zig");
    const existing_source =
        "deb [arch=amd64 signed-by=/usr/share/keyrings/vendor.gpg] " ++
        "https://existing.example.test stable main\n";
    const new_source =
        "deb [arch=amd64 signed-by=/usr/share/keyrings/vendor.gpg] " ++
        "https://new.example.test stable main\n";
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    try directory.dir.createDirPath(
        std.testing.io,
        "root/etc" ++ "/apt/sources.list.d",
    );
    try directory.dir.createDirPath(std.testing.io, "root/usr/share/keyrings");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc" ++ "/apt/sources.list.d/existing.list",
        .data = existing_source,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/usr/share/keyrings/vendor.gpg",
        .data = &fixture.keyring,
    });
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var target_files = try target_apt_config.ProductionFileSystem.init(
        std.testing.io,
        root,
    );
    defer target_files.deinit();
    var architecture_process = target_apt_config.SystemProcessRunner{
        .io = std.testing.io,
    };
    var snapshot = try target_apt_config.snapshot(std.testing.allocator, .{
        .root_path = root,
        .architecture_override = "amd64",
        .dependencies = .{
            .filesystem = target_files.interface(),
            .process = architecture_process.interface(),
        },
    });
    defer snapshot.deinit();

    const documents = [_]repository_policy.SourceDocument{
        .{ .bytes = existing_source, .format = .legacy },
        .{ .bytes = new_source, .format = .legacy },
    };
    const normalized = try repository_policy.normalizeBinaryRefresh(
        std.testing.allocator,
        &documents,
        "amd64",
        .{},
    );
    const configuration = switch (normalized) {
        .diagnostic => return error.UnexpectedDiagnostic,
        .configuration => |value| value,
    };
    const files = try std.testing.allocator.alloc(MaterialFile, 3);
    files[0] = .{
        .logical_path = try std.testing.allocator.dupe(
            u8,
            "/etc" ++ "/apt/sources.list.d/existing.list",
        ),
        .bytes = existing_source,
        .sha256 = sha256(existing_source),
        .kind = .source,
    };
    files[1] = .{
        .logical_path = try std.testing.allocator.dupe(
            u8,
            "/etc" ++ "/apt/sources.list.d/new.list",
        ),
        .bytes = new_source,
        .sha256 = sha256(new_source),
        .kind = .source,
    };
    files[2] = .{
        .logical_path = try std.testing.allocator.dupe(
            u8,
            "/usr/share/keyrings/vendor.gpg",
        ),
        .bytes = &fixture.keyring,
        .sha256 = sha256(&fixture.keyring),
        .kind = .keyring,
    };
    const evidence = try std.testing.allocator.alloc(
        state_module.FileEvidence,
        files.len,
    );
    for (files, 0..) |file, index| evidence[index] = .{
        .logical_path = file.logical_path,
        .sha256 = file.sha256,
        .size = file.bytes.len,
    };
    var material: DescriptorMaterial = .{
        .allocator = std.testing.allocator,
        .configuration = configuration,
        .files = files,
        .evidence = evidence,
    };
    defer material.deinit();
    var changed = (try changedDescriptorConfiguration(
        std.testing.allocator,
        &material,
        snapshot,
        "amd64",
        .{},
        .{},
    )) orelse return error.MissingChangedConfiguration;
    defer changed.deinit();
    try std.testing.expectEqual(@as(usize, 1), changed.repositories.len);
    try std.testing.expectEqualStrings(
        "https://new.example.test",
        changed.repositories[0].uri,
    );
}

test "repository backend refreshes imported repositories only for missing dependencies" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod-depends_1.1_all.deb");
    const fixture = @import("fixtures/openpgp.zig");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    try directory.dir.createDirPath(
        std.testing.io,
        "root/etc" ++ "/apt/sources.list.d",
    );
    try directory.dir.createDirPath(std.testing.io, "root/usr/share/keyrings");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc" ++ "/apt/sources.list.d/microsoft-prod.list",
        .data = test_repository_source,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/usr/share/keyrings/microsoft-prod.gpg",
        .data = &fixture.keyring,
    });
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);
    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = fixture.created + 30,
    };
    var result = try api.execute(std.testing.allocator, .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    }, backend.interface());
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.download, result.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.dependency_acquisition_failed,
        result.diagnostics[0].id,
    );
    try std.testing.expectEqual(@as(usize, 2), acquisition.in_release_requests);
    try std.testing.expectEqual(@as(usize, 0), executor.calls);

    const exact_lock_logical =
        result.paths.exact_lock orelse return error.MissingExactLockPath;
    const operation_logical =
        std.fs.path.dirname(exact_lock_logical) orelse
        return error.MissingOperationDirectory;
    const operation_relative = try std.fmt.allocPrint(
        std.testing.allocator,
        "root{s}",
        .{operation_logical},
    );
    defer std.testing.allocator.free(operation_relative);
    var operation_dir = try directory.dir.openDir(
        std.testing.io,
        operation_relative,
        .{},
    );
    defer operation_dir.close(std.testing.io);
    const store = try exact_lock_v2.Store.init(
        std.testing.io,
        operation_dir,
        exact_lock_name,
    );
    var lock = try store.read(
        std.testing.allocator,
        exact_lock_v2.maximum_document_bytes,
    );
    defer lock.deinit();
    try std.testing.expectEqual(@as(usize, 2), lock.lock.packages.len);
    var local_count: usize = 0;
    var repository_count: usize = 0;
    for (lock.lock.packages) |package| switch (package.origin) {
        .local_artifact => local_count += 1,
        .authenticated_repository => repository_count += 1,
    };
    try std.testing.expectEqual(@as(usize, 1), local_count);
    try std.testing.expectEqual(@as(usize, 1), repository_count);

    var repositories = try std.testing.allocator.dupe(
        exact_lock_v2.Repository,
        lock.lock.repositories,
    );
    defer std.testing.allocator.free(repositories);
    const packages = try std.testing.allocator.dupe(
        exact_lock_v2.Package,
        lock.lock.packages,
    );
    defer std.testing.allocator.free(packages);
    const mismatched_snapshot: [32]u8 = @splat(0xdd);
    repositories[0].snapshot_sha256 = mismatched_snapshot;
    for (packages) |*package| switch (package.origin) {
        .authenticated_repository => |origin| {
            package.origin = .{ .authenticated_repository = .{
                .repository_id = origin.repository_id,
                .repository_snapshot_sha256 = mismatched_snapshot,
            } };
        },
        .local_artifact => {},
    };
    var tampered = try exact_lock_v2.create(std.testing.allocator, .{
        .target_architecture = lock.lock.target_architecture,
        .request_sha256 = lock.lock.request_sha256,
        .policy_sha256 = lock.lock.policy_sha256,
        .repositories = repositories,
        .local_artifacts = lock.lock.local_artifacts,
        .packages = packages,
        .verified_origins = true,
    });
    defer tampered.deinit();
    try store.writeAtomic(std.testing.allocator, tampered.lock);

    var resumed = try api.execute(std.testing.allocator, .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    }, backend.interface());
    defer resumed.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, resumed.exit_status);
    try std.testing.expectEqual(api.DiagnosticId.recovery_required, resumed.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 0), executor.calls);
}

test "repository backend rejects unavailable native transaction before root access" {
    var backend: Backend = .{
        .io = std.testing.io,
        .transaction_backend = .native,
    };
    const result = try api.execute(std.testing.allocator, .{
        .root = "/native-repository-backend-unavailable-root",
        .descriptor_url = "https://example.invalid/repository.deb",
        .expected_sha256 = @splat(0x86),
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.unavailable, result.exit_status);
    try std.testing.expectEqual(@as(usize, 1), result.diagnostic_count);
    try std.testing.expectEqual(
        api.DiagnosticId.transaction_backend_unavailable,
        result.diagnostics[0].id,
    );
    try std.testing.expect(!result.changed);
}

/// Reads the durable root attempt straight out of a staged test root, exactly
/// as the next debz invocation would.
fn readRootAttempt(
    directory: std.Io.Dir,
) !?root_operation.OwnedRecord {
    var root_dir = try directory.openDir(std.testing.io, "root", .{ .iterate = true });
    defer root_dir.close(std.testing.io);
    const store = root_operation.Store.init(.init(std.testing.io, root_dir));
    return store.read(std.testing.allocator);
}

/// Whether a package transaction could start on this root right now. Every
/// post-executor failure must keep this false until the bootstrap is resumed,
/// because the shared root attempt is what stops two mutations from
/// overlapping.
fn packageMutationAdmitted(directory: std.Io.Dir, root_path: []const u8) !bool {
    var owned = try root_fs.openAbsoluteRoot(std.testing.io, root_path);
    defer owned.close();
    _ = directory;
    var locks: root_operation.SystemLockBackend = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    var coordinator = try root_operation.Coordinator.open(
        std.testing.io,
        owned.root,
        root_path,
        locks.interface(),
    );
    coordinator.now_unix = 1_700_000_000;
    var attempt = coordinator.acquire(std.testing.allocator, .{
        .intent = .mutation,
        .existing = .reclaim_resolved,
        .backend = .legacy_dpkg,
        .operation = .{ .package_transaction = .install },
        .request_sha256 = @splat(0x31),
        .policy_sha256 = @splat(0x32),
        .target_architecture = "amd64",
    }) catch |err| switch (err) {
        error.RecoveryRequired,
        error.ProvenancePending,
        error.AttemptMismatch,
        error.OperationInProgress,
        error.ResolvedAttemptPresent,
        => return false,
        else => return err,
    };
    // The probe never leaves evidence of its own behind.
    attempt.abandonIfPreMutation(std.testing.allocator) catch {};
    attempt.release();
    return true;
}

// Every stage after the executor can fail on a root the executor already
// changed. The durable root attempt has to survive those failures — clearing
// it would let an unrelated mutation start on a half-bootstrapped root — but
// it must not lock the operation out of its own resumable progress either.
// Before the same-operation binding existed, the second run opened a generic
// mutation intent, was refused by its own evidence, and the root could never
// be finished by debz again.
test "repository backend resumes its own attempt after a failure at every post-executor stage" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const Stage = enum {
        provenance,
        installed_progress,
        verify_installed,
        manifest,
        imported_progress,
        refresh,
    };
    for (std.enums.values(Stage)) |stage| {
        var directory = std.testing.tmpDir(.{ .iterate = true });
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
        };
        var state_failure: RepositoryStateFailure = .{
            .boundary = .after_rename,
            .fail_from_write = std.math.maxInt(usize),
        };
        switch (stage) {
            .provenance => executor.collide_after_install = provenance_name,
            .manifest => executor.collide_after_install = manifest_name,
            .verify_installed => executor.half_configure_descriptor = true,
            // The seventh and eighth durable checkpoints are `installed` and
            // `imported`; both are written after the root was changed.
            .installed_progress => state_failure.fail_from_write = 7,
            .imported_progress => state_failure.fail_from_write = 8,
            .refresh => acquisition.fail_in_release_request = 2,
        }
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .state_write_hooks = state_failure.hooks(),
        };
        const request: api.Request = .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
        };
        var interrupted = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        errdefer std.debug.print("stage: {t}\n", .{stage});
        try std.testing.expect(interrupted.exit_status != .success);
        try std.testing.expectEqual(@as(usize, 1), executor.calls);
        interrupted.deinit();

        // The root attempt kept its mutation evidence rather than being
        // cleared as abandoned, so nothing else may mutate this root.
        var stranded = (try readRootAttempt(directory.dir)).?;
        try std.testing.expect(stranded.record.mutation_started);
        try std.testing.expect(
            stranded.record.state.blocksMutation() or
                stranded.record.provenance == .pending,
        );
        try std.testing.expect(!try packageMutationAdmitted(directory.dir, root));

        // A different descriptor is a different operation: it may neither
        // adopt this evidence nor overwrite it.
        var other = try api.execute(std.testing.allocator, .{
            .root = root,
            .descriptor_url = "file:///other-descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
        }, backend.interface());
        try std.testing.expectEqual(api.ExitStatus.recovery, other.exit_status);
        try std.testing.expectEqual(
            api.DiagnosticId.recovery_required,
            other.diagnostics[0].id,
        );
        other.deinit();
        // A different architecture is a different operation too.
        var other_architecture = try api.execute(std.testing.allocator, .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "arm64",
        }, backend.interface());
        try std.testing.expectEqual(api.ExitStatus.recovery, other_architecture.exit_status);
        other_architecture.deinit();

        var untouched = (try readRootAttempt(directory.dir)).?;
        try std.testing.expectEqualSlices(
            u8,
            &stranded.record.digest_sha256,
            &untouched.record.digest_sha256,
        );
        untouched.deinit();
        stranded.deinit();

        // Clear the injection and rerun exactly the same request.
        backend.state_write_hooks = .{};
        state_failure.fail_from_write = std.math.maxInt(usize);
        executor.collide_after_install = null;
        executor.half_configure_descriptor = false;
        acquisition.fail_in_release_request = null;
        switch (stage) {
            .provenance, .manifest => {
                var operation = try executor.openOperationDirectory();
                defer operation.close(std.testing.io);
                try operation.deleteTree(
                    std.testing.io,
                    if (stage == .provenance) provenance_name else manifest_name,
                );
            },
            else => {},
        }
        var resumed = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        defer resumed.deinit();
        try std.testing.expectEqual(api.ExitStatus.success, resumed.exit_status);
        try std.testing.expect(resumed.installed);
        try std.testing.expect(resumed.paths.provenance != null);
        try std.testing.expect(resumed.paths.target_manifest != null);

        // Provenance was published before the intent was cleared, so the
        // finished bootstrap leaves no active attempt behind and the root is
        // available to the next mutation.
        try std.testing.expect((try readRootAttempt(directory.dir)) == null);
        try std.testing.expect(try packageMutationAdmitted(directory.dir, root));
    }
}

// A crash leaves the record exactly where the last durable boundary put it.
// The rerun has to pick its own attempt back up from each of those boundaries
// without a second mutation ever starting from a generic intent, and without
// the provenance obligation being skipped.
test "repository backend adopts a crashed attempt at every durable boundary" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const Crash = struct {
        state: root_operation.State,
        phase: root_operation.Phase,
        mutation_started: bool,
        outcome: root_operation.Outcome = .pending,
        provenance: root_operation.ProvenanceState = .pending,
    };
    const crashes = [_]Crash{
        // Crashed while reserved, before anything was bound.
        .{ .state = .reserved, .phase = .reserved, .mutation_started = false },
        // Crashed at the hand-over, with no report ever returned.
        .{ .state = .mutation_pending, .phase = .mutation, .mutation_started = false },
        // Crashed after the executor was witnessed as having mutated.
        .{ .state = .mutating, .phase = .mutation, .mutation_started = true },
        .{ .state = .verifying, .phase = .verification, .mutation_started = true },
        .{ .state = .recovery_required, .phase = .mutation, .mutation_started = true },
        .{ .state = .recovering, .phase = .database, .mutation_started = true },
        // Crashed between completing and publishing provenance.
        .{
            .state = .completed,
            .phase = .provenance,
            .mutation_started = true,
            .outcome = .succeeded,
        },
    };
    for (crashes) |crash| {
        var directory = std.testing.tmpDir(.{ .iterate = true });
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        const request: api.Request = .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
        };

        var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
        const store = root_operation.Store.init(.init(std.testing.io, root_dir));
        try store.ensureNamespace();
        var record = try root_operation.create(std.testing.allocator, .{
            .attempt_id = @splat(0x7c),
            .generation = 4,
            .install_root = root,
            .backend = .legacy_dpkg,
            .operation = .{ .repository_bootstrap = .add },
            .state = crash.state,
            .phase = crash.phase,
            .step = 3,
            .mutation_started = crash.mutation_started,
            .outcome = crash.outcome,
            .provenance = crash.provenance,
            .request_sha256 = repositoryRequestDigest(request, .legacy_dpkg),
            .policy_sha256 = repositoryPolicyDigest(request, .legacy_dpkg),
            .target_architecture = "amd64",
            .reserved_unix = 1_700_000_000,
            .updated_unix = 1_700_000_000,
        });
        try store.writeAtomic(std.testing.allocator, record.record);
        record.deinit();
        root_dir.close(std.testing.io);

        errdefer std.debug.print("crash state: {t}\n", .{crash.state});
        // Nothing else may take the root while the crashed evidence stands.
        if (crash.state != .reserved)
            try std.testing.expect(!try packageMutationAdmitted(directory.dir, root));

        var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
        };
        var resumed = try api.execute(
            std.testing.allocator,
            request,
            backend.interface(),
        );
        defer resumed.deinit();
        try std.testing.expectEqual(api.ExitStatus.success, resumed.exit_status);
        // A record that already claimed the bootstrap was completed keeps its
        // outcome; every other boundary is finished by running the bootstrap.
        try std.testing.expect((try readRootAttempt(directory.dir)) == null);
        try std.testing.expect(try packageMutationAdmitted(directory.dir, root));
    }
}

// A rerun adopts the record its own interrupted run left behind, including one
// left at the executor bridge. That run handed control to dpkg and never came
// back, so this run's executor evidence says nothing about it: a deadline that
// expired, a preflight that was refused, a lock that could not be taken, or a
// journal that could not be decoded all report `not_started` with no commands.
// Resolving the inherited bridge from that report discharged another run's
// hand-over as never started and cleared the only evidence blocking the root.
test "repository backend never discharges an inherited bridge with its own no-start report" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const Case = struct {
        code: transaction_executor.FailureCode,
        /// Whether the failure is reported by the executor's recovery path,
        /// which is reached when the transaction refuses to run without one.
        recovery: bool = false,
    };
    const cases = [_]Case{
        .{ .code = .process_timeout },
        .{ .code = .invalid_root },
        .{ .code = .lock_timeout },
        .{ .code = .journal_corrupt },
        // The recovery path reports the same shape, including the journal it
        // never found a state for.
        .{ .code = .journal_missing, .recovery = true },
        .{ .code = .journal_corrupt, .recovery = true },
        .{ .code = .lock_timeout, .recovery = true },
    };
    for (cases) |case| {
        const code = case.code;
        var directory = std.testing.tmpDir(.{ .iterate = true });
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        const request: api.Request = .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
        };
        errdefer std.debug.print(
            "failure code: {t} recovery: {}\n",
            .{ code, case.recovery },
        );

        // The interrupted run of exactly this request stopped at the
        // hand-over, with no witness ever published.
        var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
        const store = root_operation.Store.init(.init(std.testing.io, root_dir));
        try store.ensureNamespace();
        var stranded = try root_operation.create(std.testing.allocator, .{
            .attempt_id = @splat(0x7d),
            .generation = 4,
            .install_root = root,
            .backend = .legacy_dpkg,
            .operation = .{ .repository_bootstrap = .add },
            .state = .mutation_pending,
            .phase = .mutation,
            .step = 3,
            .mutation_started = false,
            .outcome = .pending,
            .provenance = .pending,
            .request_sha256 = repositoryRequestDigest(request, .legacy_dpkg),
            .policy_sha256 = repositoryPolicyDigest(request, .legacy_dpkg),
            .target_architecture = "amd64",
            .reserved_unix = 1_700_000_000,
            .updated_unix = 1_700_000_000,
        });
        defer stranded.deinit();
        try store.writeAtomic(std.testing.allocator, stranded.record);
        root_dir.close(std.testing.io);
        try std.testing.expect(!try packageMutationAdmitted(directory.dir, root));

        var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
            .no_start_failure = if (case.recovery) null else code,
            .recovery_transition_first = case.recovery,
            .no_start_recovery_failure = if (case.recovery) code else null,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
        };
        var result = try api.execute(std.testing.allocator, request, backend.interface());
        defer result.deinit();
        try std.testing.expectEqual(api.ExitStatus.transaction, result.exit_status);
        try std.testing.expectEqual(@as(usize, 1), executor.calls);
        try std.testing.expectEqual(
            @as(usize, if (case.recovery) 1 else 0),
            executor.recover_calls,
        );

        // The inherited hand-over is still unresolved: the record blocks, it
        // carries mutation evidence, and its provenance obligation was not
        // waived by completing it as abandoned.
        var observed = (try readRootAttempt(directory.dir)).?;
        defer observed.deinit();
        try std.testing.expectEqual(
            root_operation.State.recovery_required,
            observed.record.state,
        );
        try std.testing.expect(observed.record.state.blocksMutation());
        try std.testing.expect(observed.record.mutation_started);
        try std.testing.expectEqual(
            root_operation.ProvenanceState.pending,
            observed.record.provenance,
        );
        try std.testing.expectEqual(root_operation.Outcome.pending, observed.record.outcome);
        try std.testing.expect(!observed.record.clearable());
        try std.testing.expect(!try packageMutationAdmitted(directory.dir, root));
    }
}

// The conservative rule only applies to a hand-over this run did not perform.
// A bridge this very run published, whose executor really did report that
// nothing started, still releases the root instead of blocking it.
test "repository backend still clears a bridge it published itself when nothing started" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try stageRepositoryTestRoot(directory.dir);
    const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root);

    var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
    var executor: RepositoryTestExecutor = .{
        .io = std.testing.io,
        .directory = directory.dir,
        .no_start_failure = .lock_timeout,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .executor = executor.interface(),
        .acquisition_dependencies = acquisition.dependencies(),
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    var result = try api.execute(std.testing.allocator, .{
        .root = root,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = sha256(descriptor),
        .architecture = "amd64",
    }, backend.interface());
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.transaction, result.exit_status);
    try std.testing.expectEqual(@as(usize, 1), executor.calls);
    try std.testing.expect((try readRootAttempt(directory.dir)) == null);
    try std.testing.expect(try packageMutationAdmitted(directory.dir, root));
}

// A record that is completed with its provenance discharged is evidence that
// an operation finished. Adopting it — matching request or not — let a rerun
// execute under a record that already said the mutation was over, so a crash
// mid-rerun left durable evidence claiming the opposite. The rerun therefore
// reserves its own attempt instead.
test "repository backend reserves a new attempt instead of adopting a settled record" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    for ([_]bool{ true, false }) |same_request| {
        var directory = std.testing.tmpDir(.{ .iterate = true });
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);
        const request: api.Request = .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
        };
        errdefer std.debug.print("same request: {}\n", .{same_request});

        var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
        const store = root_operation.Store.init(.init(std.testing.io, root_dir));
        try store.ensureNamespace();
        var settled = try root_operation.create(std.testing.allocator, .{
            .attempt_id = @splat(0x7e),
            .generation = 9,
            .install_root = root,
            .backend = .legacy_dpkg,
            .operation = .{ .repository_bootstrap = .add },
            .state = .completed,
            .phase = .provenance,
            .step = 8,
            .mutation_started = true,
            .outcome = .succeeded,
            .provenance = .published,
            .provenance_sha256 = @splat(0xcd),
            .request_sha256 = if (same_request)
                repositoryRequestDigest(request, .legacy_dpkg)
            else
                @splat(0x14),
            .policy_sha256 = repositoryPolicyDigest(request, .legacy_dpkg),
            .target_architecture = "amd64",
            .reserved_unix = 1_700_000_000,
            .updated_unix = 1_700_000_000,
        });
        defer settled.deinit();
        try std.testing.expect(settled.record.clearable());
        try store.writeAtomic(std.testing.allocator, settled.record);
        root_dir.close(std.testing.io);

        var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
            // Crash right after the executor mutated the root, before the
            // rerun could publish its own provenance.
            .collide_after_install = provenance_name,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
        };
        var interrupted = try api.execute(std.testing.allocator, request, backend.interface());
        try std.testing.expect(interrupted.exit_status != .success);
        // The rerun really executed rather than resting on settled evidence.
        try std.testing.expectEqual(@as(usize, 1), executor.calls);
        interrupted.deinit();

        // A fresh attempt: a new identifier, a strictly higher generation, and
        // durable evidence of the rerun's own mutation.
        var reserved = (try readRootAttempt(directory.dir)).?;
        defer reserved.deinit();
        try std.testing.expect(!std.mem.eql(
            u8,
            &settled.record.attempt_id,
            &reserved.record.attempt_id,
        ));
        try std.testing.expect(reserved.record.generation > settled.record.generation);
        try std.testing.expect(reserved.record.mutation_started);
        try std.testing.expect(
            reserved.record.state.blocksMutation() or
                reserved.record.provenance == .pending,
        );
        try std.testing.expect(!reserved.record.clearable());
        // No package transaction may start while the rerun is unresolved.
        try std.testing.expect(!try packageMutationAdmitted(directory.dir, root));

        // Clearing the injection lets the same rerun finish and discharge it.
        executor.collide_after_install = null;
        var operation = try executor.openOperationDirectory();
        try operation.deleteTree(std.testing.io, provenance_name);
        operation.close(std.testing.io);
        var resumed = try api.execute(std.testing.allocator, request, backend.interface());
        defer resumed.deinit();
        try std.testing.expectEqual(api.ExitStatus.success, resumed.exit_status);
        try std.testing.expect((try readRootAttempt(directory.dir)) == null);
        try std.testing.expect(try packageMutationAdmitted(directory.dir, root));
    }
}

// A record that belongs to another operation is never adopted, whichever
// boundary it stopped at, and the bootstrap that finds it leaves it exactly as
// it was published.
test "repository backend refuses to adopt an unrelated unresolved attempt" {
    const descriptor = @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb");
    const cases = [_]struct {
        operation: root_operation.Operation,
        request_digest: [32]u8,
        state: root_operation.State,
        phase: root_operation.Phase,
        mutation_started: bool,
        outcome: root_operation.Outcome = .pending,
        provenance: root_operation.ProvenanceState = .pending,
    }{
        // Another surface entirely.
        .{
            .operation = .{ .package_transaction = .install },
            .request_digest = @splat(0x11),
            .state = .mutating,
            .phase = .database,
            .mutation_started = true,
        },
        // The same surface, a different request.
        .{
            .operation = .{ .repository_bootstrap = .add },
            .request_digest = @splat(0x12),
            .state = .verifying,
            .phase = .verification,
            .mutation_started = true,
        },
        // The same surface, a different request, owing provenance.
        .{
            .operation = .{ .repository_bootstrap = .add },
            .request_digest = @splat(0x13),
            .state = .completed,
            .phase = .provenance,
            .mutation_started = true,
            .outcome = .succeeded,
        },
    };
    for (cases) |case| {
        var directory = std.testing.tmpDir(.{ .iterate = true });
        defer directory.cleanup();
        try stageRepositoryTestRoot(directory.dir);
        const root = try repositoryTestRoot(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root);

        var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
        const store = root_operation.Store.init(.init(std.testing.io, root_dir));
        try store.ensureNamespace();
        var record = try root_operation.create(std.testing.allocator, .{
            .attempt_id = @splat(0x2d),
            .generation = 2,
            .install_root = root,
            .backend = .legacy_dpkg,
            .operation = case.operation,
            .state = case.state,
            .phase = case.phase,
            .step = 6,
            .mutation_started = case.mutation_started,
            .outcome = case.outcome,
            .provenance = case.provenance,
            .request_sha256 = case.request_digest,
            .policy_sha256 = @splat(0x22),
            .target_architecture = "amd64",
            .reserved_unix = 1_700_000_000,
            .updated_unix = 1_700_000_000,
        });
        defer record.deinit();
        try store.writeAtomic(std.testing.allocator, record.record);
        root_dir.close(std.testing.io);

        var acquisition: RepositoryTestAcquisition = .{ .descriptor = descriptor };
        var executor: RepositoryTestExecutor = .{
            .io = std.testing.io,
            .directory = directory.dir,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .executor = executor.interface(),
            .acquisition_dependencies = acquisition.dependencies(),
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
        };
        var result = try api.execute(std.testing.allocator, .{
            .root = root,
            .descriptor_url = "file:///descriptor.deb",
            .expected_sha256 = sha256(descriptor),
            .architecture = "amd64",
        }, backend.interface());
        defer result.deinit();
        try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
        try std.testing.expectEqual(
            api.DiagnosticId.recovery_required,
            result.diagnostics[0].id,
        );
        // The bootstrap never reached the executor and never touched the
        // record it could not adopt.
        try std.testing.expectEqual(@as(usize, 0), executor.calls);
        var observed = (try readRootAttempt(directory.dir)).?;
        defer observed.deinit();
        try std.testing.expectEqualSlices(
            u8,
            &record.record.digest_sha256,
            &observed.record.digest_sha256,
        );
    }
}

test "repository backend refuses bootstrap while a package transaction attempt is unresolved" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const root_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/root",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(root_path);

    var root_dir = try directory.dir.openDir(std.testing.io, "root", .{ .iterate = true });
    defer root_dir.close(std.testing.io);
    const root: root_fs.Root = .init(std.testing.io, root_dir);
    const store = root_operation.Store.init(root);
    try store.ensureNamespace();
    var record = try root_operation.create(std.testing.allocator, .{
        .attempt_id = @splat(0x5b),
        .generation = 1,
        .install_root = root_path,
        .backend = .legacy_dpkg,
        .operation = .{ .package_transaction = .install },
        .state = .mutating,
        .phase = .database,
        .step = 5,
        .mutation_started = true,
        .outcome = .pending,
        .provenance = .pending,
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .target_architecture = "amd64",
        .reserved_unix = 1_700_000_000,
        .updated_unix = 1_700_000_000,
    });
    defer record.deinit();
    try store.writeAtomic(std.testing.allocator, record.record);

    var backend: Backend = .{ .io = std.testing.io, .now_unix = 1_700_000_000 };
    var result = try api.execute(std.testing.allocator, .{
        .root = root_path,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = @splat(0x33),
        .architecture = "amd64",
        .cache = .{ .path = "/var/cache/debz" },
        .state = .{ .path = "/var/lib/debz" },
    }, backend.interface());
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.recovery_required,
        result.diagnostics[0].id,
    );

    // The blocked bootstrap never reached the repository operation lock, so the
    // durable package-transaction evidence is untouched.
    var observed = (try store.read(std.testing.allocator)).?;
    defer observed.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &record.record.digest_sha256,
        &observed.record.digest_sha256,
    );
}

test "repository backend rejects an unavailable native backend before root access" {
    var directory = std.testing.tmpDir(.{ .iterate = true });
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const root_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/root",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(root_path);

    var backend: Backend = .{
        .io = std.testing.io,
        .transaction_backend = .native,
        .native_executor = null,
        .now_unix = 1_700_000_000,
    };
    var result = try api.execute(std.testing.allocator, .{
        .root = root_path,
        .descriptor_url = "file:///descriptor.deb",
        .expected_sha256 = @splat(0x33),
        .architecture = "amd64",
        .cache = .{ .path = "/var/cache/debz" },
        .state = .{ .path = "/var/lib/debz" },
    }, backend.interface());
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.unavailable, result.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.transaction_backend_unavailable,
        result.diagnostics[0].id,
    );

    // The unavailable selection failed before anything touched the root, so the
    // shared operation namespace was never provisioned.
    try std.testing.expectError(
        error.FileNotFound,
        directory.dir.statFile(std.testing.io, "root/var/lib/debz", .{}),
    );
}
