//! Profile-bound orchestration for the apt-shaped system facade.
//!
//! The module deliberately has no command-line parsing. Callers prepare a
//! request, render the returned complete review, obtain confirmation, and then
//! execute the retained exact lock. All host-facing boundaries are injected so
//! tests cannot accidentally inspect or mutate `/`.
const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("debz_build_options");
const api = @import("apt_system_api.zig");
const facade_cli = @import("apt_system_cli.zig");
const operation_state = @import("apt_system_state.zig");
const exact_lock = @import("exact_lock.zig");
const live_root = @import("live_root.zig");
const product_api = @import("product_api.zig");
const production_backend = @import("production_backend.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const root_operation_completion = @import("root_operation_completion.zig");
const solver = @import("solver.zig");
const system_profile = @import("system_profile.zig");
const transaction_provenance = @import("transaction_provenance.zig");
const transaction_result_summary = @import("transaction_result_summary.zig");

pub const operation_directory_name = "operations";
pub const request_document_name = "request-v1.json";
pub const retained_state_name = "state-v1.json";
pub const exact_lock_name = "exact-lock-v1.json";
pub const transaction_result_name = "transaction-result.json";
pub const recovery_completion_name = "root-operation-recovery-completion-v1.json";
pub const completion_document_name = "execution-completion-v1.json";
pub const lower_acknowledgment_name = "lower-acknowledgment-v1.json";
pub const completion_schema_id =
    "https://debz.dev/schema/apt-system-execution-completion-v1";
pub const completion_schema_version: u32 = 1;

pub const ProfileView = struct {
    binding: api.ProfileBinding,
    source_paths: []const []const u8,
    config_paths: []const []const u8,
    keyring_paths: []const []const u8,
    architecture: []const u8,
    foreign_architectures: []const []const u8,
    repository_policy: product_api.RepositoryPolicy,
    cache_path: []const u8,
    state_path: []const u8,
    conffile: product_api.ConffilePolicy,
    proxy: ?[]const u8,
    credential_reference: ?[]const u8,
};

pub const LoadedProfile = struct {
    context: ?*anyopaque,
    view: ProfileView,
    revalidateFn: *const fn (?*anyopaque, std.mem.Allocator) anyerror!void,
    deinitFn: *const fn (?*anyopaque) void,

    pub fn revalidate(
        self: LoadedProfile,
        allocator: std.mem.Allocator,
    ) !void {
        try self.revalidateFn(self.context, allocator);
    }

    pub fn deinit(self: *LoadedProfile) void {
        self.deinitFn(self.context);
        self.* = undefined;
    }
};

pub const ProfileLoader = struct {
    context: *anyopaque,
    loadFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
    ) anyerror!LoadedProfile,

    pub fn load(
        self: ProfileLoader,
        allocator: std.mem.Allocator,
        path: []const u8,
    ) !LoadedProfile {
        return self.loadFn(self.context, allocator, path);
    }
};

/// Concrete strict-profile adapter. Every referenced source, config, keyring,
/// and credential is revalidated against the evidence captured by
/// `system_profile.loadSystem` before each backend invocation.
pub const SystemProfileLoader = struct {
    io: std.Io,
    limits: system_profile.Limits = .{},

    const Lease = struct {
        loaded: system_profile.LoadedProfile,
        file_system: system_profile.SystemFileSystem,
        source_paths: []const []const u8,
        config_paths: []const []const u8,
        allocator: std.mem.Allocator,
    };

    pub fn interface(self: *SystemProfileLoader) ProfileLoader {
        return .{ .context = self, .loadFn = load };
    }

    fn load(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
    ) !LoadedProfile {
        const self: *SystemProfileLoader = @ptrCast(@alignCast(context));
        const lease = try allocator.create(Lease);
        errdefer allocator.destroy(lease);
        var loaded = try system_profile.loadSystem(
            self.io,
            allocator,
            path,
            self.limits,
        );
        errdefer loaded.deinit();
        const sources = try allocator.alloc(
            []const u8,
            loaded.profile.repositories.len,
        );
        errdefer allocator.free(sources);
        var config_count: usize = 0;
        for (loaded.profile.repositories) |repository|
            config_count += @intFromBool(repository.config_path != null);
        const configs = try allocator.alloc([]const u8, config_count);
        errdefer allocator.free(configs);
        var next_config: usize = 0;
        for (loaded.profile.repositories, 0..) |repository, index| {
            sources[index] = repository.source_path;
            if (repository.config_path) |config| {
                configs[next_config] = config;
                next_config += 1;
            }
        }
        lease.* = .{
            .loaded = loaded,
            .file_system = .{ .io = self.io },
            .source_paths = sources,
            .config_paths = configs,
            .allocator = allocator,
        };
        return .{
            .context = lease,
            .view = .{
                .binding = .{
                    .path = lease.loaded.profile_path,
                    .sha256 = lease.loaded.profile_sha256,
                    .reference_evidence_sha256 = lease.loaded.reference_evidence_sha256,
                },
                .source_paths = lease.source_paths,
                .config_paths = lease.config_paths,
                .keyring_paths = lease.loaded.profile.keyring_paths,
                .architecture = lease.loaded.profile.architecture,
                .foreign_architectures = lease.loaded.profile.foreign_architectures,
                .repository_policy = switch (lease.loaded.profile.repository_policy) {
                    .strict_priority => .strict_priority,
                    .best_version => .best_version,
                },
                .cache_path = lease.loaded.profile.cache_path,
                .state_path = lease.loaded.profile.state_path,
                .conffile = switch (lease.loaded.profile.default_conffile) {
                    .keep_existing => .keep_existing,
                    .use_package_version => .use_package_version,
                },
                .proxy = lease.loaded.profile.network.proxy_url,
                .credential_reference = lease.loaded.profile.network.credential_reference,
            },
            .revalidateFn = revalidate,
            .deinitFn = deinit,
        };
    }

    fn revalidate(context: ?*anyopaque, allocator: std.mem.Allocator) !void {
        const lease: *Lease = @ptrCast(@alignCast(context.?));
        for (lease.loaded.trusted_files) |evidence| {
            const bytes = try lease.loaded.readTrustedFile(
                allocator,
                lease.file_system.interface(),
                evidence.path,
                .{},
            );
            defer {
                if (evidence.role == .credential) @memset(bytes, 0);
                allocator.free(bytes);
            }
        }
    }

    fn deinit(context: ?*anyopaque) void {
        const lease: *Lease = @ptrCast(@alignCast(context.?));
        const allocator = lease.allocator;
        allocator.free(lease.source_paths);
        allocator.free(lease.config_paths);
        lease.loaded.deinit();
        allocator.destroy(lease);
    }
};

pub const RootStatus = enum {
    clean,
    completed,
    recovery_required,
};

pub const RootInspection = struct {
    status: RootStatus,
    attempt_id: ?[32]u8 = null,
    record: ?root_operation.OwnedRecord = null,
    deferred_acknowledgment: ?root_operation.DeferredAcknowledgment = null,

    pub fn deinit(self: *RootInspection) void {
        if (self.record) |*record| record.deinit();
        self.* = undefined;
    }
};

pub const BackendResult = struct {
    result: product_api.Result,
    root_status: RootStatus,
    owned_result: ?product_api.OwnedResult = null,
    recovery_completion: ?root_operation_completion.OwnedDocument = null,
    recovery_acknowledgment: ?RecoveryAcknowledgment = null,
    ownership_acknowledgment: ?OwnershipAcknowledgment = null,

    pub fn deinit(self: *BackendResult) void {
        if (self.owned_result) |*owned| owned.deinit();
        if (self.recovery_completion) |*owned| owned.deinit();
        self.* = undefined;
    }
};

pub const WorkflowOperation = enum { install, remove, upgrade_all };
pub const WorkflowMode = enum {
    plan_only,
    download_only,
    reserve,
    execute,
    recover,
};

pub const RecoveryAcknowledgment =
    production_backend.WorkflowRecoveryAcknowledgment;
pub const OwnershipAcknowledgment =
    production_backend.WorkflowOwnershipAcknowledgment;
pub const ReconciliationClaim =
    production_backend.WorkflowReconciliationClaim;

pub const WorkflowRequest = struct {
    operation: WorkflowOperation,
    mode: WorkflowMode,
    selectors: []const solver.PackageSelector,
    options: product_api.CommonOptions,
    defer_recovery_clear: bool = false,
    orchestration_id: ?[32]u8 = null,
    reconciliation_claim: ?ReconciliationClaim = null,
    finalize_ownership: bool = false,
    ownership_acknowledgment: ?OwnershipAcknowledgment = null,
    recovery_acknowledgment: ?RecoveryAcknowledgment = null,
};

pub const Backend = struct {
    context: *anyopaque,
    routeFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        product_api.Request,
    ) anyerror!product_api.Result,
    workflowFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        WorkflowRequest,
    ) anyerror!product_api.Result,

    pub fn route(
        self: Backend,
        allocator: std.mem.Allocator,
        request: product_api.Request,
    ) !product_api.Result {
        return self.routeFn(self.context, allocator, request);
    }

    pub fn workflow(
        self: Backend,
        allocator: std.mem.Allocator,
        request: WorkflowRequest,
    ) !product_api.Result {
        return self.workflowFn(self.context, allocator, request);
    }
};

pub const ProductionBackend = struct {
    backend: *production_backend.Backend,

    pub fn interface(self: *ProductionBackend) Backend {
        return .{
            .context = self,
            .routeFn = route,
            .workflowFn = workflow,
        };
    }

    fn route(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: product_api.Request,
    ) !product_api.Result {
        const self: *ProductionBackend = @ptrCast(@alignCast(context));
        return self.backend.execute(allocator, request);
    }

    fn workflow(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: WorkflowRequest,
    ) !product_api.Result {
        const self: *ProductionBackend = @ptrCast(@alignCast(context));
        return self.backend.executeWorkflow(allocator, .{
            .operation = switch (request.operation) {
                .install => .install,
                .remove => .remove,
                .upgrade_all => .upgrade_all,
            },
            .mode = switch (request.mode) {
                .plan_only => .plan_only,
                .download_only => .download_only,
                .reserve => .reserve,
                .execute => .execute,
                .recover => .recover,
            },
            .selectors = request.selectors,
            .options = request.options,
            .defer_recovery_clear = request.defer_recovery_clear,
            .orchestration_id = request.orchestration_id,
            .reconciliation_claim = request.reconciliation_claim,
            .finalize_ownership = request.finalize_ownership,
            .ownership_acknowledgment = request.ownership_acknowledgment,
            .recovery_acknowledgment = request.recovery_acknowledgment,
        });
    }
};

/// The runner is the only boundary allowed to invoke a backend operation.
/// Production implementations must use `live_root.run` and communicate the
/// backend result back to the parent; direct execution is suitable only for
/// hermetic tests. The orchestrator always supplies
/// `live_root.logical_root_path` and rejects every other root spelling.
pub const LiveRootRunner = struct {
    context: *anyopaque,
    routeFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        Backend,
        product_api.Request,
    ) anyerror!BackendResult,
    workflowFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        Backend,
        WorkflowRequest,
    ) anyerror!BackendResult,
    inspectFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
    ) anyerror!RootInspection,
    readRecoveryCompletionFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
    ) anyerror!?root_operation_completion.OwnedDocument,

    pub fn route(
        self: LiveRootRunner,
        allocator: std.mem.Allocator,
        backend: Backend,
        request: product_api.Request,
    ) !BackendResult {
        if (!std.mem.eql(
            u8,
            request.options.install_root,
            live_root.logical_root_path,
        )) return error.UnsafeInstallRoot;
        return self.routeFn(self.context, allocator, backend, request);
    }

    pub fn workflow(
        self: LiveRootRunner,
        allocator: std.mem.Allocator,
        backend: Backend,
        request: WorkflowRequest,
    ) !BackendResult {
        if (!std.mem.eql(
            u8,
            request.options.install_root,
            live_root.logical_root_path,
        )) return error.UnsafeInstallRoot;
        return self.workflowFn(self.context, allocator, backend, request);
    }

    pub fn inspect(
        self: LiveRootRunner,
        allocator: std.mem.Allocator,
    ) !RootInspection {
        return self.inspectFn(self.context, allocator);
    }

    pub fn readRecoveryCompletion(
        self: LiveRootRunner,
        allocator: std.mem.Allocator,
    ) !?root_operation_completion.OwnedDocument {
        return self.readRecoveryCompletionFn(self.context, allocator);
    }
};

pub const TransportBoundary = enum { before_return };

pub const TransportCrash = struct {
    context: *anyopaque,
    hitFn: *const fn (*anyopaque, TransportBoundary) anyerror!void,

    pub fn hit(self: TransportCrash, boundary: TransportBoundary) !void {
        try self.hitFn(self.context, boundary);
    }
};

pub const PrivateLiveRootRunner = struct {
    io: std.Io,
    termination_grace_ms: u64 = 1_000,
    transport_crash: ?TransportCrash = null,

    const Invocation = union(enum) {
        route: struct {
            backend: Backend,
            request: product_api.Request,
        },
        workflow: struct {
            backend: Backend,
            request: WorkflowRequest,
        },
    };

    const ChildContext = struct {
        runner: *PrivateLiveRootRunner,
        invocation: Invocation,
        output_fd: i32,
    };

    const ReaderContext = struct {
        fd: i32,
        buffer: []u8,
        length: usize = 0,
        failure: ?anyerror = null,
    };

    const CompletionReadContext = struct {
        runner: *PrivateLiveRootRunner,
        output_fd: i32,
    };

    pub fn interface(self: *PrivateLiveRootRunner) LiveRootRunner {
        return .{
            .context = self,
            .routeFn = route,
            .workflowFn = workflow,
            .inspectFn = inspect,
            .readRecoveryCompletionFn = readRecoveryCompletion,
        };
    }

    fn route(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        backend: Backend,
        request: product_api.Request,
    ) !BackendResult {
        const self: *PrivateLiveRootRunner = @ptrCast(@alignCast(context));
        return self.invoke(allocator, .{ .route = .{
            .backend = backend,
            .request = request,
        } });
    }

    fn workflow(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        backend: Backend,
        request: WorkflowRequest,
    ) !BackendResult {
        const self: *PrivateLiveRootRunner = @ptrCast(@alignCast(context));
        return self.invoke(allocator, .{ .workflow = .{
            .backend = backend,
            .request = request,
        } });
    }

    fn inspect(
        context: *anyopaque,
        allocator: std.mem.Allocator,
    ) !RootInspection {
        var signal_guard = try live_root.blockWatchedSignals();
        const inspection = inspectSignalsBlocked(
            context,
            allocator,
            &signal_guard,
        ) catch |err| {
            signal_guard.restore() catch
                return error.SignalSetupFailed;
            return err;
        };
        signal_guard.restore() catch {
            var owned = inspection;
            owned.deinit();
            return error.SignalSetupFailed;
        };
        return inspection;
    }

    fn inspectSignalsBlocked(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        signal_guard: *const live_root.SignalMaskGuard,
    ) !RootInspection {
        const self: *PrivateLiveRootRunner = @ptrCast(@alignCast(context));
        if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
        const linux = std.os.linux;
        var pipe: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) != .SUCCESS)
            return error.PipeFailed;
        var read_open = true;
        var write_open = true;
        defer {
            if (read_open) _ = linux.close(pipe[0]);
            if (write_open) _ = linux.close(pipe[1]);
        }
        const buffer = try allocator.alloc(
            u8,
            root_operation.maximum_document_bytes * 2 + 1,
        );
        defer allocator.free(buffer);
        var reader_context: ReaderContext = .{
            .fd = pipe[0],
            .buffer = buffer,
        };
        const reader = try std.Thread.spawn(
            .{},
            readTransport,
            .{&reader_context},
        );
        var joined = false;
        defer if (!joined) {
            if (write_open) {
                _ = linux.close(pipe[1]);
                write_open = false;
            }
            reader.join();
        };
        var child_context: CompletionReadContext = .{
            .runner = self,
            .output_fd = pipe[1],
        };
        const result = try live_root.runSignalsBlocked(
            .{
                .context = &child_context,
                .child = inspectChild,
                .termination_grace_ms = self.termination_grace_ms,
            },
            signal_guard,
        );
        _ = linux.close(pipe[1]);
        write_open = false;
        reader.join();
        joined = true;
        _ = linux.close(pipe[0]);
        read_open = false;
        if (reader_context.failure) |failure| return failure;
        const child_code = switch (result) {
            .exited => |code| switch (code) {
                0 => return .{ .status = .clean },
                10, 11, 12 => code,
                else => return error.LiveRootChildFailed,
            },
            .signaled => return error.LiveRootChildSignaled,
            .interrupted => return error.LiveRootInterrupted,
            .setup_failed => |failure| return mapSetupFailure(failure),
        };
        const payload = buffer[0..reader_context.length];
        var marker: ?root_operation.DeferredAcknowledgment = null;
        var record_source: ?[]const u8 = null;
        switch (child_code) {
            10 => record_source = payload,
            11 => marker = try root_operation.decodeDeferredAcknowledgment(
                allocator,
                payload,
            ),
            12 => {
                const separator = std.mem.indexOfScalar(u8, payload, '\n') orelse
                    return error.TransportReadFailed;
                marker = try root_operation.decodeDeferredAcknowledgment(
                    allocator,
                    payload[0..separator],
                );
                record_source = payload[separator + 1 ..];
            },
            else => unreachable,
        }
        var inspection: RootInspection = if (record_source) |source_bytes| blk: {
            var record = try root_operation.decode(
                allocator,
                source_bytes,
                root_operation.maximum_document_bytes,
            );
            errdefer record.deinit();
            var value = classifyRootRecord(
                record.record.state,
                record.record.provenance,
                record.record.attempt_id,
            );
            value.record = record;
            break :blk value;
        } else .{
            .status = switch (marker.?.state) {
                .released, .abandoned, .acknowledged => .clean,
                .bound,
                .pending,
                .pre_mutation_reconciliation_claim,
                => .recovery_required,
            },
            .attempt_id = marker.?.attempt_id,
        };
        inspection.deferred_acknowledgment = marker;
        return inspection;
    }

    fn invoke(
        self: *PrivateLiveRootRunner,
        allocator: std.mem.Allocator,
        invocation: Invocation,
    ) !BackendResult {
        var signal_guard = try live_root.blockWatchedSignals();
        const result = self.invokeSignalsBlocked(
            allocator,
            invocation,
            &signal_guard,
        ) catch |err| {
            signal_guard.restore() catch
                return error.SignalSetupFailed;
            return err;
        };
        signal_guard.restore() catch {
            var owned = result;
            owned.deinit();
            return error.SignalSetupFailed;
        };
        return result;
    }

    fn invokeSignalsBlocked(
        self: *PrivateLiveRootRunner,
        allocator: std.mem.Allocator,
        invocation: Invocation,
        signal_guard: *const live_root.SignalMaskGuard,
    ) !BackendResult {
        if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
        const linux = std.os.linux;
        var pipe: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) != .SUCCESS)
            return error.PipeFailed;
        var read_open = true;
        var write_open = true;
        defer {
            if (read_open) _ = linux.close(pipe[0]);
            if (write_open) _ = linux.close(pipe[1]);
        }

        const buffer = try allocator.alloc(
            u8,
            product_api.maximum_result_document_bytes,
        );
        defer allocator.free(buffer);
        var reader_context: ReaderContext = .{
            .fd = pipe[0],
            .buffer = buffer,
        };
        const reader = try std.Thread.spawn(
            .{},
            readTransport,
            .{&reader_context},
        );
        var joined = false;
        defer if (!joined) {
            if (write_open) {
                _ = linux.close(pipe[1]);
                write_open = false;
            }
            reader.join();
        };

        var child_context: ChildContext = .{
            .runner = self,
            .invocation = invocation,
            .output_fd = pipe[1],
        };
        const result = live_root.runSignalsBlocked(.{
            .context = &child_context,
            .child = transportChild,
            .termination_grace_ms = self.termination_grace_ms,
        }, signal_guard) catch |err| {
            _ = linux.close(pipe[1]);
            write_open = false;
            reader.join();
            joined = true;
            return err;
        };
        _ = linux.close(pipe[1]);
        write_open = false;
        reader.join();
        joined = true;
        _ = linux.close(pipe[0]);
        read_open = false;
        if (reader_context.failure) |failure| return failure;
        switch (result) {
            .exited => |code| if (code != 0)
                return error.LiveRootChildFailed,
            .signaled => return error.LiveRootChildSignaled,
            .interrupted => return error.LiveRootInterrupted,
            .setup_failed => |failure| return mapSetupFailure(failure),
        }
        var decoded = try product_api.decodeResult(
            allocator,
            buffer[0..reader_context.length],
        );
        errdefer decoded.deinit();
        const expected_operation: product_api.Operation = switch (invocation) {
            .route => |route_invocation| route_invocation.request.operation,
            .workflow => |workflow_invocation| workflowSurfaceOperation(
                workflow_invocation.request.operation,
                workflow_invocation.request.mode,
            ),
        };
        if (decoded.result.operation != expected_operation)
            return error.BackendOperationMismatch;
        var recovery_completion: ?root_operation_completion.OwnedDocument =
            null;
        errdefer if (recovery_completion) |*owned| owned.deinit();
        if (invocation == .workflow and
            invocation.workflow.request.mode == .recover and
            !invocation.workflow.request.finalize_ownership and
            invocation.workflow.request.reconciliation_claim == null and
            invocation.workflow.request.recovery_acknowledgment == null and
            decoded.result.exit_status == .success)
        {
            recovery_completion = try self.interface()
                .readRecoveryCompletion(allocator) orelse
                return error.MissingRecoveryCompletion;
        }
        var recovery_acknowledgment: ?RecoveryAcknowledgment = null;
        var ownership_acknowledgment: ?OwnershipAcknowledgment = null;
        const root_status: RootStatus = switch (invocation) {
            .route => .clean,
            .workflow => |workflow_invocation| switch (workflow_invocation.request.mode) {
                .reserve, .execute, .recover => if (decoded.result.exit_status == .success) status: {
                    var inspection = try self.interface().inspect(allocator);
                    defer inspection.deinit();
                    if (workflow_invocation.request.mode == .recover and
                        workflow_invocation.request.defer_recovery_clear and
                        !workflow_invocation.request.finalize_ownership and
                        workflow_invocation.request.reconciliation_claim == null and
                        workflow_invocation.request.recovery_acknowledgment == null)
                    {
                        const record = if (inspection.record) |owned|
                            owned.record
                        else
                            return error.MissingRecoveryAcknowledgment;
                        const completion = recovery_completion orelse
                            return error.MissingRecoveryCompletion;
                        if (record.state != .completed or
                            record.provenance != .published or
                            !settledRecoveryProvenanceMatches(
                                record,
                                completion.document,
                            ))
                            return error.InvalidRecoveryAcknowledgment;
                        recovery_acknowledgment = .{
                            .attempt_id = record.attempt_id,
                            .completion_sha256 = completion.document.digest_sha256,
                            .provenance_sha256 = record.provenance_sha256.?,
                            .acknowledgment_id = workflow_invocation.request
                                .orchestration_id orelse
                                return error.MissingRecoveryAcknowledgment,
                        };
                    }
                    if ((workflow_invocation.request.mode == .execute or
                        workflow_invocation.request.reconciliation_claim != null) and
                        workflow_invocation.request.orchestration_id != null and
                        decoded.result.exit_status == .success)
                    {
                        const marker = inspection.deferred_acknowledgment orelse
                            return error.MissingOwnershipAcknowledgment;
                        const acknowledgment_id =
                            workflow_invocation.request.orchestration_id orelse
                            return error.MissingOwnershipAcknowledgment;
                        const expected_marker_state: root_operation.DeferredAcknowledgmentState =
                            if (workflow_invocation.request.reconciliation_claim) |claim|
                                switch (claim) {
                                    .pre_mutation => .pre_mutation_reconciliation_claim,
                                    .post_mutation => .released,
                                }
                            else
                                .released;
                        if (marker.state != expected_marker_state or
                            inspection.record != null or
                            !std.mem.eql(
                                u8,
                                &marker.acknowledgment_id,
                                &acknowledgment_id,
                            ))
                            return error.InvalidOwnershipAcknowledgment;
                        ownership_acknowledgment = .{
                            .attempt_id = marker.attempt_id,
                            .marker_sha256 = marker.digest_sha256,
                            .acknowledgment_id = marker.acknowledgment_id,
                        };
                    }
                    if (workflow_invocation.request.reconciliation_claim !=
                        null and ownership_acknowledgment != null)
                        break :status .completed;
                    break :status switch (inspection.status) {
                        .clean, .completed => .completed,
                        .recovery_required => .recovery_required,
                    };
                } else .recovery_required,
                .plan_only, .download_only => .clean,
            },
        };
        if (self.transport_crash) |crash|
            try crash.hit(.before_return);
        return .{
            .result = decoded.result,
            .root_status = root_status,
            .owned_result = decoded,
            .recovery_completion = recovery_completion,
            .recovery_acknowledgment = recovery_acknowledgment,
            .ownership_acknowledgment = ownership_acknowledgment,
        };
    }

    fn transportChild(
        raw: ?*anyopaque,
        install_root: []const u8,
    ) anyerror!u8 {
        if (!std.mem.eql(u8, install_root, live_root.logical_root_path))
            return error.UnsafeInstallRoot;
        const context: *ChildContext = @ptrCast(@alignCast(raw.?));
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const result = switch (context.invocation) {
            .route => |invocation| try invocation.backend.route(
                allocator,
                invocation.request,
            ),
            .workflow => |invocation| try invocation.backend.workflow(
                allocator,
                invocation.request,
            ),
        };

        const source = try result.canonicalJson(allocator);
        if (source.len > product_api.maximum_result_document_bytes)
            return error.DocumentTooLarge;
        try writeTransport(context.output_fd, source);
        return 0;
    }

    fn inspectChild(
        raw: ?*anyopaque,
        install_root: []const u8,
    ) anyerror!u8 {
        if (!std.mem.eql(u8, install_root, live_root.logical_root_path))
            return error.UnsafeInstallRoot;
        const context: *CompletionReadContext = @ptrCast(@alignCast(raw.?));
        var owned_root = try root_fs.openAbsoluteRoot(
            context.runner.io,
            install_root,
        );
        defer owned_root.close();
        const store = root_operation.Store.init(owned_root.root);
        const marker = try store.readDeferredAcknowledgment(
            std.heap.page_allocator,
        );
        var record = try store.read(std.heap.page_allocator);
        defer if (record) |*owned| owned.deinit();
        if (marker == null and record == null) return 0;
        if (marker) |value| {
            const marker_bytes = try value.canonicalJson(
                std.heap.page_allocator,
            );
            defer std.heap.page_allocator.free(marker_bytes);
            try writeTransport(context.output_fd, marker_bytes);
            if (record != null)
                try writeTransport(context.output_fd, "\n");
        }
        if (record) |owned| {
            const record_bytes = try owned.record.canonicalJson(
                std.heap.page_allocator,
            );
            defer std.heap.page_allocator.free(record_bytes);
            try writeTransport(context.output_fd, record_bytes);
        }
        return if (marker != null)
            if (record != null) 12 else 11
        else
            10;
    }

    fn readRecoveryCompletion(
        context: *anyopaque,
        allocator: std.mem.Allocator,
    ) !?root_operation_completion.OwnedDocument {
        var signal_guard = try live_root.blockWatchedSignals();
        const completion = readRecoveryCompletionSignalsBlocked(
            context,
            allocator,
            &signal_guard,
        ) catch |err| {
            signal_guard.restore() catch
                return error.SignalSetupFailed;
            return err;
        };
        signal_guard.restore() catch {
            if (completion) |owned| {
                var value = owned;
                value.deinit();
            }
            return error.SignalSetupFailed;
        };
        return completion;
    }

    fn readRecoveryCompletionSignalsBlocked(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        signal_guard: *const live_root.SignalMaskGuard,
    ) !?root_operation_completion.OwnedDocument {
        const self: *PrivateLiveRootRunner = @ptrCast(@alignCast(context));
        if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
        const linux = std.os.linux;
        var pipe: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) != .SUCCESS)
            return error.PipeFailed;
        var read_open = true;
        var write_open = true;
        defer {
            if (read_open) _ = linux.close(pipe[0]);
            if (write_open) _ = linux.close(pipe[1]);
        }
        const buffer = try allocator.alloc(
            u8,
            root_operation_completion.maximum_document_bytes,
        );
        defer allocator.free(buffer);
        var reader_context: ReaderContext = .{
            .fd = pipe[0],
            .buffer = buffer,
        };
        const reader = try std.Thread.spawn(
            .{},
            readTransport,
            .{&reader_context},
        );
        var joined = false;
        defer if (!joined) {
            if (write_open) {
                _ = linux.close(pipe[1]);
                write_open = false;
            }
            reader.join();
        };
        var child_context: CompletionReadContext = .{
            .runner = self,
            .output_fd = pipe[1],
        };
        const result = live_root.runSignalsBlocked(.{
            .context = &child_context,
            .child = readRecoveryCompletionChild,
            .termination_grace_ms = self.termination_grace_ms,
        }, signal_guard) catch |err| {
            _ = linux.close(pipe[1]);
            write_open = false;
            reader.join();
            joined = true;
            return err;
        };
        _ = linux.close(pipe[1]);
        write_open = false;
        reader.join();
        joined = true;
        _ = linux.close(pipe[0]);
        read_open = false;
        if (reader_context.failure) |failure| return failure;
        switch (result) {
            .exited => |code| switch (code) {
                0 => {},
                11 => return null,
                else => return error.LiveRootChildFailed,
            },
            .signaled => return error.LiveRootChildSignaled,
            .interrupted => return error.LiveRootInterrupted,
            .setup_failed => |failure| return mapSetupFailure(failure),
        }
        return try root_operation_completion.decode(
            allocator,
            buffer[0..reader_context.length],
            root_operation_completion.maximum_document_bytes,
        );
    }

    fn readRecoveryCompletionChild(
        raw: ?*anyopaque,
        install_root: []const u8,
    ) anyerror!u8 {
        if (!std.mem.eql(u8, install_root, live_root.logical_root_path))
            return error.UnsafeInstallRoot;
        const context: *CompletionReadContext = @ptrCast(@alignCast(raw.?));
        var owned_root = try root_fs.openAbsoluteRoot(
            context.runner.io,
            install_root,
        );
        defer owned_root.close();
        const store: root_operation_completion.Store = .init(owned_root.root);
        const source = try store.readBytes(std.heap.page_allocator) orelse
            return 11;
        defer std.heap.page_allocator.free(source);
        try writeTransport(context.output_fd, source);
        return 0;
    }

    fn readTransport(context: *ReaderContext) void {
        const linux = std.os.linux;
        while (context.length < context.buffer.len) {
            const raw = linux.read(
                context.fd,
                context.buffer[context.length..].ptr,
                context.buffer.len - context.length,
            );
            switch (linux.errno(raw)) {
                .SUCCESS => {
                    if (raw == 0) return;
                    context.length += raw;
                },
                .INTR => continue,
                else => {
                    context.failure = error.TransportReadFailed;
                    return;
                },
            }
        }
        var extra: [1]u8 = undefined;
        while (true) {
            const raw = linux.read(context.fd, &extra, extra.len);
            switch (linux.errno(raw)) {
                .SUCCESS => {
                    if (raw != 0) context.failure = error.DocumentTooLarge;
                    return;
                },
                .INTR => continue,
                else => {
                    context.failure = error.TransportReadFailed;
                    return;
                },
            }
        }
    }

    fn writeTransport(fd: i32, source: []const u8) !void {
        const linux = std.os.linux;
        var written: usize = 0;
        while (written < source.len) {
            const raw = linux.write(
                fd,
                source[written..].ptr,
                source.len - written,
            );
            switch (linux.errno(raw)) {
                .SUCCESS => {
                    if (raw == 0) return error.TransportWriteFailed;
                    written += raw;
                },
                .INTR => continue,
                else => return error.TransportWriteFailed,
            }
        }
    }

    fn mapSetupFailure(
        failure: live_root.SetupFailure,
    ) anyerror {
        return switch (failure.stage) {
            .source_validation, .bind_validation => error.RootReplaced,
            .runtime_validation, .runtime_pin => error.RuntimeReplaced,
            .lock_validation => error.LockReplaced,
            .mountpoint_validation, .recursive_bind => error.MountpointReplaced,
            .mount_namespace,
            .private_propagation,
            .detached_propagation,
            .pid_namespace,
            => error.NamespaceUnavailable,
            .callback => error.LiveRootChildFailed,
            .cleanup => error.LiveRootCleanupFailed,
            else => error.LiveRootSetupFailed,
        };
    }
};

fn classifyRootRecord(
    state: root_operation.State,
    provenance: root_operation.ProvenanceState,
    attempt_id: [32]u8,
) RootInspection {
    return .{
        .status = if (state == .completed)
            switch (provenance) {
                .pending => .completed,
                .published, .not_required => .clean,
            }
        else
            .recovery_required,
        .attempt_id = attempt_id,
    };
}

fn workflowSurfaceOperation(
    operation: WorkflowOperation,
    mode: WorkflowMode,
) product_api.Operation {
    return switch (mode) {
        .plan_only => .plan,
        .download_only => .download,
        .reserve, .execute => switch (operation) {
            .install => .install,
            .remove => .remove,
            .upgrade_all => .upgrade_all,
        },
        .recover => .recover,
    };
}

pub const OperationPaths = struct {
    directory: []u8,
    active_state: []u8,
    retained_state: []u8,
    request: []u8,
    exact_lock: []u8,
    transaction_result: []u8,
    recovery_completion: []u8,
    completion: []u8,
    lower_acknowledgment: []u8,

    pub fn deinit(self: *OperationPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.directory);
        allocator.free(self.active_state);
        allocator.free(self.retained_state);
        allocator.free(self.request);
        allocator.free(self.exact_lock);
        allocator.free(self.transaction_result);
        allocator.free(self.recovery_completion);
        allocator.free(self.completion);
        allocator.free(self.lower_acknowledgment);
        self.* = undefined;
    }
};

pub fn pathsFor(
    allocator: std.mem.Allocator,
    state_path: []const u8,
    attempt_id: [32]u8,
) !OperationPaths {
    const attempt = std.fmt.bytesToHex(attempt_id, .lower);
    const directory = try std.fmt.allocPrint(
        allocator,
        "{s}/apt/{s}/{s}",
        .{ state_path, operation_directory_name, &attempt },
    );
    errdefer allocator.free(directory);
    const active = try std.fmt.allocPrint(
        allocator,
        "{s}/apt/{s}",
        .{ state_path, operation_state.document_name },
    );
    errdefer allocator.free(active);
    return .{
        .directory = directory,
        .active_state = active,
        .retained_state = try join(allocator, directory, retained_state_name),
        .request = try join(allocator, directory, request_document_name),
        .exact_lock = try join(allocator, directory, exact_lock_name),
        .transaction_result = try join(
            allocator,
            directory,
            transaction_result_name,
        ),
        .recovery_completion = try join(
            allocator,
            directory,
            recovery_completion_name,
        ),
        .completion = try join(
            allocator,
            directory,
            completion_document_name,
        ),
        .lower_acknowledgment = try join(
            allocator,
            directory,
            lower_acknowledgment_name,
        ),
    };
}

pub const CompletionInput = struct {
    attempt_id: [32]u8,
    request_sha256: [32]u8,
    profile: api.ProfileBinding,
    exact_lock: api.DocumentBinding,
    transaction_result: api.DocumentBinding,
    recovered: bool,
    completed_unix: i64,
};

pub const ExecutionCompletion = struct {
    attempt_id: [32]u8,
    request_sha256: [32]u8,
    profile: api.ProfileBinding,
    exact_lock: api.DocumentBinding,
    transaction_result: api.DocumentBinding,
    recovered: bool,
    completed_unix: i64,
    digest_sha256: [32]u8,

    pub fn canonicalJson(
        self: ExecutionCompletion,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeCompletionPayload(self, &output.writer);
        output.writer.undo(1);
        try output.writer.writeAll(",\"digest_sha256\":");
        try writeHex(&output.writer, &self.digest_sha256);
        try output.writer.writeByte('}');
        return output.toOwnedSlice();
    }
};

/// Creates ordinary-success or recovered apt/system completion evidence. This
/// schema is intentionally distinct from
/// `root-operation-completion-v1.json`, which is a recovery-only discharge
/// statement owned by the root-operation protocol.
pub fn createExecutionCompletion(input: CompletionInput) !ExecutionCompletion {
    try api.validateProfileBinding(input.profile);
    try api.validateEvidence(.{
        .exact_lock = input.exact_lock,
        .transaction_result = input.transaction_result,
    });
    var result: ExecutionCompletion = .{
        .attempt_id = input.attempt_id,
        .request_sha256 = input.request_sha256,
        .profile = input.profile,
        .exact_lock = input.exact_lock,
        .transaction_result = input.transaction_result,
        .recovered = input.recovered,
        .completed_unix = input.completed_unix,
        .digest_sha256 = undefined,
    };
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(
        &buffer,
    );
    writeCompletionPayload(result, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    result.digest_sha256 = sink.hasher.finalResult();
    return result;
}

fn verifyExistingCompletion(
    allocator: std.mem.Allocator,
    source: []const u8,
    input: CompletionInput,
) !ExecutionCompletion {
    var parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        source,
        .{},
    ) catch return error.InvalidCompletion;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidCompletion;
    const completed_unix = parsed.value.object.get("completed_unix") orelse
        return error.InvalidCompletion;
    const recovered = parsed.value.object.get("recovered") orelse
        return error.InvalidCompletion;
    if (completed_unix != .integer or recovered != .bool or
        recovered.bool != input.recovered)
        return error.CompletionMismatch;
    var retained_input = input;
    retained_input.completed_unix = completed_unix.integer;
    const completion = try createExecutionCompletion(retained_input);
    const canonical = try completion.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source))
        return error.CompletionMismatch;
    return completion;
}

fn completionBinding(
    paths: OperationPaths,
    input: CompletionInput,
    completion: ExecutionCompletion,
) api.CompletionBinding {
    return .{
        .document = .{
            .path = paths.completion,
            .schema = completion_schema_id,
            .version = completion_schema_version,
            .digest_sha256 = completion.digest_sha256,
        },
        .completed_attempt_id = input.attempt_id,
    };
}

pub const StateStore = struct {
    context: *anyopaque,
    readActiveFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
    ) anyerror!?operation_state.OwnedState,
    inspectActiveLockedFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
    ) anyerror!?operation_state.OwnedState,
    reserveFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        []const u8,
        operation_state.State,
    ) anyerror!void,
    compareAndSetFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
        operation_state.Expected,
        operation_state.State,
    ) anyerror!void,
    finishFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        operation_state.Expected,
        operation_state.State,
    ) anyerror!void,
    commitFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        operation_state.Expected,
        operation_state.State,
    ) anyerror!void,
    clearCommittedFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        operation_state.Expected,
    ) anyerror!void,
    readRequestFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
    ) anyerror!api.OwnedRequest,
    readRetainedFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
    ) anyerror!?operation_state.OwnedState,
    retainAcknowledgmentFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        root_operation.DeferredAcknowledgment,
    ) anyerror!void,
    readAcknowledgmentFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
    ) anyerror!?root_operation.DeferredAcknowledgment,
    retainTransactionFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        []const u8,
        [32]u8,
    ) anyerror!api.DocumentBinding,
    retainRecoveryCompletionFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        []const u8,
        [32]u8,
    ) anyerror!api.DocumentBinding,
    readRecoveryCompletionFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        api.DocumentBinding,
    ) anyerror!root_operation_completion.OwnedDocument,
    publishCompletionFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        CompletionInput,
    ) anyerror!api.CompletionBinding,
    verifyCompletionFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        CompletionInput,
        api.CompletionBinding,
    ) anyerror!void,

    pub fn readActive(
        self: StateStore,
        allocator: std.mem.Allocator,
        state_path: []const u8,
    ) !?operation_state.OwnedState {
        return self.readActiveFn(self.context, allocator, state_path);
    }

    pub fn inspectActiveLocked(
        self: StateStore,
        allocator: std.mem.Allocator,
        state_path: []const u8,
    ) !?operation_state.OwnedState {
        return self.inspectActiveLockedFn(
            self.context,
            allocator,
            state_path,
        );
    }

    pub fn readRetained(
        self: StateStore,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
    ) !?operation_state.OwnedState {
        return self.readRetainedFn(self.context, allocator, paths);
    }
};

pub const FinishBoundary = enum { after_retained_publish };

pub const FinishCrash = struct {
    context: *anyopaque,
    hitFn: *const fn (*anyopaque, FinishBoundary) anyerror!void,

    pub fn hit(self: FinishCrash, boundary: FinishBoundary) !void {
        try self.hitFn(self.context, boundary);
    }
};

pub const DirectorySyncBoundary = enum {
    ancestor_parent,
    attempt_parent,
    publication_directory,
    retained_operation_directory,
    retained_attempt_parent,
};

pub const DirectorySync = struct {
    context: *anyopaque,
    syncFn: *const fn (
        *anyopaque,
        std.Io,
        std.Io.Dir,
        DirectorySyncBoundary,
    ) anyerror!void,

    pub fn sync(
        self: DirectorySync,
        io: std.Io,
        dir: std.Io.Dir,
        boundary: DirectorySyncBoundary,
    ) !void {
        try self.syncFn(self.context, io, dir, boundary);
    }
};

pub const RetainedDurabilityBoundary = enum {
    before_file_sync,
    before_active_commit,
};

pub const RetainedDurability = struct {
    context: *anyopaque,
    hitFn: *const fn (
        *anyopaque,
        RetainedDurabilityBoundary,
    ) anyerror!void,

    pub fn hit(
        self: RetainedDurability,
        boundary: RetainedDurabilityBoundary,
    ) !void {
        try self.hitFn(self.context, boundary);
    }
};

const ReservationDurability = struct {
    ancestor_parents: bool = false,
    attempt_parent: bool = false,
    request_document: bool = false,

    fn permitActivePublication(self: ReservationDurability) !void {
        if (!self.ancestor_parents or
            !self.attempt_parent or
            !self.request_document)
            return error.OperationDirectoryNotDurable;
    }
};

pub const SystemStateStore = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    wait_ms: u64 = 30_000,
    finish_crash: ?FinishCrash = null,
    directory_sync: ?DirectorySync = null,
    retained_durability: ?RetainedDurability = null,
    state_write_hooks: operation_state.WriteHooks = .{},

    const operation_lock_name = "operation.lock";

    fn syncDirectoryAt(
        self: *SystemStateStore,
        dir: std.Io.Dir,
        boundary: DirectorySyncBoundary,
    ) !void {
        if (self.directory_sync) |syncer|
            return syncer.sync(self.io, dir, boundary);
        return syncDirectory(self.io, dir);
    }

    pub fn interface(self: *SystemStateStore) StateStore {
        return .{
            .context = self,
            .readActiveFn = readActive,
            .inspectActiveLockedFn = inspectActiveLocked,
            .reserveFn = reserve,
            .compareAndSetFn = compareAndSet,
            .finishFn = finish,
            .commitFn = commit,
            .clearCommittedFn = clearCommitted,
            .readRequestFn = readRequest,
            .readRetainedFn = readRetained,
            .retainAcknowledgmentFn = retainAcknowledgment,
            .readAcknowledgmentFn = readAcknowledgment,
            .retainTransactionFn = retainTransaction,
            .retainRecoveryCompletionFn = retainRecoveryCompletion,
            .readRecoveryCompletionFn = readRecoveryCompletion,
            .publishCompletionFn = publishCompletion,
            .verifyCompletionFn = verifyCompletion,
        };
    }

    fn readActive(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        state_path: []const u8,
    ) !?operation_state.OwnedState {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        const apt_path = try std.fmt.allocPrint(
            allocator,
            "{s}/apt",
            .{state_path},
        );
        defer allocator.free(apt_path);
        var dir = openSecureAbsoluteDirectory(
            self,
            allocator,
            apt_path,
            false,
        ) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer dir.close(self.io);
        var locks: operation_state.SystemLockBackend = .{
            .allocator = self.allocator,
            .io = self.io,
            .dir = dir,
        };
        const store = try operation_state.Store.init(
            self.io,
            dir,
            operation_state.document_name,
            locks.interface(),
        );
        return store.read(
            allocator,
            operation_state.maximum_document_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
    }

    fn inspectActiveLocked(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        state_path: []const u8,
    ) !?operation_state.OwnedState {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        const apt_path = try std.fmt.allocPrint(
            allocator,
            "{s}/apt",
            .{state_path},
        );
        defer allocator.free(apt_path);
        var dir = openSecureAbsoluteDirectory(
            self,
            allocator,
            apt_path,
            false,
        ) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer dir.close(self.io);
        var locks: operation_state.SystemLockBackend = .{
            .allocator = self.allocator,
            .io = self.io,
            .dir = dir,
        };
        const lock = locks.interface();
        const token = try lock.acquire(self.wait_ms);
        defer lock.release(token);
        if (!lock.held(token)) return error.LockLost;
        const store = try operation_state.Store.init(
            self.io,
            dir,
            operation_state.document_name,
            lock,
        );
        return store.read(
            allocator,
            operation_state.maximum_document_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
    }

    fn reserve(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        request_bytes: []const u8,
        initial: operation_state.State,
    ) !void {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        var durability: ReservationDurability = .{};
        const parent_path = std.fs.path.dirname(paths.directory) orelse
            return error.InvalidPath;
        const leaf = std.fs.path.basename(paths.directory);
        var parent = try openSecureAbsoluteDirectory(
            self,
            allocator,
            parent_path,
            true,
        );
        defer parent.close(self.io);
        durability.ancestor_parents = true;
        parent.createDir(
            self.io,
            leaf,
            .fromMode(0o700),
        ) catch |err| switch (err) {
            error.PathAlreadyExists => return error.StateAlreadyExists,
            else => return err,
        };
        try self.syncDirectoryAt(parent, .attempt_parent);
        durability.attempt_parent = true;
        var operation_dir = try openSyncCapableDirectory(
            self.io,
            parent,
            leaf,
            true,
        );
        defer operation_dir.close(self.io);
        try validateSecureDirectoryChain(
            self.io,
            allocator,
            paths.directory,
        );
        try publishAtomic(
            self,
            allocator,
            operation_dir,
            request_document_name,
            request_bytes,
        );
        durability.request_document = true;

        const apt_path = std.fs.path.dirname(paths.active_state) orelse
            return error.InvalidPath;
        var apt_dir = try openSecureAbsoluteDirectory(
            self,
            allocator,
            apt_path,
            true,
        );
        defer apt_dir.close(self.io);
        var locks: operation_state.SystemLockBackend = .{
            .allocator = self.allocator,
            .io = self.io,
            .dir = apt_dir,
        };
        const store = try operation_state.Store.init(
            self.io,
            apt_dir,
            operation_state.document_name,
            locks.interface(),
        );
        try durability.permitActivePublication();
        try store.initialize(
            allocator,
            initial,
            operation_state.maximum_document_bytes,
            self.wait_ms,
        );
    }

    fn compareAndSet(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        state_path: []const u8,
        expected: operation_state.Expected,
        next: operation_state.State,
    ) !void {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        const apt_path = try std.fmt.allocPrint(
            allocator,
            "{s}/apt",
            .{state_path},
        );
        defer allocator.free(apt_path);
        var apt_dir = try openSecureAbsoluteDirectory(
            self,
            allocator,
            apt_path,
            false,
        );
        defer apt_dir.close(self.io);
        var locks: operation_state.SystemLockBackend = .{
            .allocator = self.allocator,
            .io = self.io,
            .dir = apt_dir,
        };
        var store = try operation_state.Store.init(
            self.io,
            apt_dir,
            operation_state.document_name,
            locks.interface(),
        );
        store.write_hooks = self.state_write_hooks;
        try store.compareAndSet(
            allocator,
            expected,
            next,
            operation_state.maximum_document_bytes,
            self.wait_ms,
        );
    }

    fn commit(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        expected: operation_state.Expected,
        final: operation_state.State,
    ) !void {
        _ = try commitRetained(
            context,
            allocator,
            paths,
            expected,
            final,
        );
    }

    fn commitRetained(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        expected: operation_state.Expected,
        final: operation_state.State,
    ) !operation_state.Expected {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        var operation_dir = try openSecureAbsoluteDirectory(
            self,
            allocator,
            paths.directory,
            false,
        );
        defer operation_dir.close(self.io);
        var operation_lock: operation_state.SystemLockBackend = .{
            .allocator = self.allocator,
            .io = self.io,
            .dir = operation_dir,
            .name = operation_lock_name,
        };
        const lock = operation_lock.interface();
        const operation_token = try lock.acquire(self.wait_ms);
        defer lock.release(operation_token);
        if (!lock.held(operation_token)) return error.LockLost;
        const existing = try readOptionalFile(
            allocator,
            self.io,
            operation_dir,
            retained_state_name,
        );
        defer if (existing) |source| allocator.free(source);
        if (existing == null) {
            const final_bytes = try final.canonicalJson(allocator);
            defer allocator.free(final_bytes);
            try self.publishAtomicHeld(
                allocator,
                operation_dir,
                retained_state_name,
                final_bytes,
                lock,
                operation_token,
            );
            if (self.finish_crash) |crash|
                try crash.hit(.after_retained_publish);
        }
        var file = try operation_dir.openFile(
            self.io,
            retained_state_name,
            .{
                .mode = .read_only,
                .allow_directory = false,
                .follow_symlinks = false,
                .resolve_beneath = true,
            },
        );
        defer file.close(self.io);
        if ((try file.stat(self.io)).kind != .file)
            return error.InvalidDocument;
        var reader = file.reader(self.io, &.{});
        const source = try reader.interface.allocRemaining(
            allocator,
            .limited(operation_state.maximum_document_bytes),
        );
        defer allocator.free(source);
        var retained = try operation_state.decode(
            allocator,
            source,
            operation_state.maximum_document_bytes,
        );
        defer retained.deinit();
        if (!finalStateEquivalent(retained.state, final))
            return error.PublicationConflict;
        if (self.retained_durability) |durability|
            try durability.hit(.before_file_sync);
        try file.sync(self.io);
        if (!lock.held(operation_token)) return error.LockLost;
        try self.syncDirectoryAt(
            operation_dir,
            .retained_operation_directory,
        );
        const attempt_parent_path = std.fs.path.dirname(paths.directory) orelse
            return error.InvalidPath;
        var attempt_parent = try openSecureAbsoluteDirectory(
            self,
            allocator,
            attempt_parent_path,
            false,
        );
        defer attempt_parent.close(self.io);
        try self.syncDirectoryAt(
            attempt_parent,
            .retained_attempt_parent,
        );
        if (!lock.held(operation_token)) return error.LockLost;

        if (self.retained_durability) |durability|
            try durability.hit(.before_active_commit);
        try reader.seekTo(0);
        const revalidated_source = try reader.interface.allocRemaining(
            allocator,
            .limited(operation_state.maximum_document_bytes),
        );
        defer allocator.free(revalidated_source);
        var revalidated = try operation_state.decode(
            allocator,
            revalidated_source,
            operation_state.maximum_document_bytes,
        );
        defer revalidated.deinit();
        if (!finalStateEquivalent(revalidated.state, final))
            return error.PublicationConflict;
        const durable_final = revalidated.state;

        // Lock ordering is operation lock, then active-state lock. No caller
        // may acquire an operation lock while holding the active-state lock.
        const state_path = std.fs.path.dirname(
            std.fs.path.dirname(paths.active_state) orelse
                return error.InvalidPath,
        ) orelse return error.InvalidPath;
        const already_final = expected.generation == durable_final.generation and
            std.mem.eql(
                u8,
                &expected.digest_sha256,
                &durable_final.digest_sha256,
            );
        if (!already_final)
            try compareAndSet(
                context,
                allocator,
                state_path,
                expected,
                durable_final,
            );
        try ensureActiveDurable(
            self,
            allocator,
            paths,
            operation_state.Expected.fromState(durable_final),
        );
        if (!lock.held(operation_token)) return error.LockLost;
        return operation_state.Expected.fromState(durable_final);
    }

    fn ensureActiveDurable(
        self: *SystemStateStore,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        expected: operation_state.Expected,
    ) !void {
        const apt_path = std.fs.path.dirname(paths.active_state) orelse
            return error.InvalidPath;
        var apt_dir = try openSecureAbsoluteDirectory(
            self,
            allocator,
            apt_path,
            false,
        );
        defer apt_dir.close(self.io);
        var locks: operation_state.SystemLockBackend = .{
            .allocator = self.allocator,
            .io = self.io,
            .dir = apt_dir,
        };
        var store = try operation_state.Store.init(
            self.io,
            apt_dir,
            operation_state.document_name,
            locks.interface(),
        );
        store.write_hooks = self.state_write_hooks;
        try store.ensureDurable(
            allocator,
            expected,
            operation_state.maximum_document_bytes,
            self.wait_ms,
        );
    }

    fn clearCommitted(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        expected: operation_state.Expected,
    ) !void {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        const apt_path = std.fs.path.dirname(paths.active_state) orelse
            return error.InvalidPath;
        var apt_dir = try openSecureAbsoluteDirectory(
            self,
            allocator,
            apt_path,
            false,
        );
        defer apt_dir.close(self.io);
        var locks: operation_state.SystemLockBackend = .{
            .allocator = self.allocator,
            .io = self.io,
            .dir = apt_dir,
        };
        const token = try locks.interface().acquire(self.wait_ms);
        defer locks.interface().release(token);
        if (!locks.interface().held(token)) return error.LockLost;
        var observed = try operation_state.Store.init(
            self.io,
            apt_dir,
            operation_state.document_name,
            locks.interface(),
        );
        var state = try observed.read(
            allocator,
            operation_state.maximum_document_bytes,
        );
        defer state.deinit();
        if (state.state.generation != expected.generation or
            !std.mem.eql(
                u8,
                &state.state.digest_sha256,
                &expected.digest_sha256,
            )) return error.StaleState;
        try apt_dir.deleteFile(self.io, operation_state.document_name);
        try syncDirectory(self.io, apt_dir);
    }

    fn finish(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        expected: operation_state.Expected,
        final: operation_state.State,
    ) !void {
        const durable_final = try commitRetained(
            context,
            allocator,
            paths,
            expected,
            final,
        );
        try clearCommitted(
            context,
            allocator,
            paths,
            durable_final,
        );
    }

    fn readRequest(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
    ) !api.OwnedRequest {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        const bytes = try readTrustedOperationFile(
            self.io,
            allocator,
            paths.request,
            api.maximum_document_bytes,
        );
        defer allocator.free(bytes);
        return api.decodeRequest(allocator, bytes);
    }

    fn readRetained(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
    ) !?operation_state.OwnedState {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        const bytes = readTrustedOperationFile(
            self.io,
            allocator,
            paths.retained_state,
            operation_state.maximum_document_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer allocator.free(bytes);
        return try operation_state.decode(
            allocator,
            bytes,
            operation_state.maximum_document_bytes,
        );
    }

    fn retainAcknowledgment(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        acknowledgment: root_operation.DeferredAcknowledgment,
    ) !void {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        const source = try acknowledgment.canonicalJson(allocator);
        defer allocator.free(source);
        var operation_dir = try openSecureAbsoluteDirectory(
            self,
            allocator,
            paths.directory,
            false,
        );
        defer operation_dir.close(self.io);
        if (try readOptionalFile(
            allocator,
            self.io,
            operation_dir,
            lower_acknowledgment_name,
        )) |existing| {
            defer allocator.free(existing);
            const decoded = try root_operation.decodeDeferredAcknowledgment(
                allocator,
                existing,
            );
            if (!std.mem.eql(
                u8,
                &decoded.digest_sha256,
                &acknowledgment.digest_sha256,
            )) return error.PublicationConflict;
            return;
        }
        try publishAtomic(
            self,
            allocator,
            operation_dir,
            lower_acknowledgment_name,
            source,
        );
    }

    fn readAcknowledgment(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
    ) !?root_operation.DeferredAcknowledgment {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        const source = readTrustedOperationFile(
            self.io,
            allocator,
            paths.lower_acknowledgment,
            root_operation.maximum_document_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer allocator.free(source);
        return try root_operation.decodeDeferredAcknowledgment(
            allocator,
            source,
        );
    }

    fn retainTransaction(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        source: []const u8,
        digest: [32]u8,
    ) !api.DocumentBinding {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        var validated = try transaction_provenance.validateDocument(
            allocator,
            source,
            transaction_provenance.maximum_document_bytes,
        );
        defer validated.deinit();
        if (!std.mem.eql(u8, &validated.digest_sha256, &digest))
            return error.DigestMismatch;
        var dir = try openSecureAbsoluteDirectory(
            self,
            allocator,
            paths.directory,
            false,
        );
        defer dir.close(self.io);
        try publishAtomic(
            self,
            allocator,
            dir,
            transaction_result_name,
            source,
        );
        return .{
            .path = paths.transaction_result,
            .schema = transaction_provenance.schema_id,
            .version = transaction_provenance.schema_version,
            .digest_sha256 = digest,
        };
    }

    fn retainRecoveryCompletion(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        source: []const u8,
        digest: [32]u8,
    ) !api.DocumentBinding {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        var validated = try root_operation_completion.decode(
            allocator,
            source,
            root_operation_completion.maximum_document_bytes,
        );
        defer validated.deinit();
        if (!std.mem.eql(
            u8,
            &validated.document.digest_sha256,
            &digest,
        )) return error.DigestMismatch;
        var dir = try openSecureAbsoluteDirectory(
            self,
            allocator,
            paths.directory,
            false,
        );
        defer dir.close(self.io);
        try publishAtomic(
            self,
            allocator,
            dir,
            recovery_completion_name,
            source,
        );
        return .{
            .path = paths.recovery_completion,
            .schema = root_operation_completion.schema_id,
            .version = root_operation_completion.schema_version,
            .digest_sha256 = digest,
        };
    }

    fn readRecoveryCompletion(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        binding: api.DocumentBinding,
    ) !root_operation_completion.OwnedDocument {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, binding.path, paths.recovery_completion) or
            !std.mem.eql(
                u8,
                binding.schema,
                root_operation_completion.schema_id,
            ) or
            binding.version != root_operation_completion.schema_version)
            return error.RecoveryCompletionMismatch;
        const bytes = try readTrustedOperationFile(
            self.io,
            allocator,
            paths.recovery_completion,
            root_operation_completion.maximum_document_bytes,
        );
        defer allocator.free(bytes);
        var document = try root_operation_completion.decode(
            allocator,
            bytes,
            root_operation_completion.maximum_document_bytes,
        );
        errdefer document.deinit();
        if (!std.mem.eql(
            u8,
            &document.document.digest_sha256,
            &binding.digest_sha256,
        )) return error.RecoveryCompletionMismatch;
        return document;
    }

    fn publishCompletion(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        input: CompletionInput,
    ) !api.CompletionBinding {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        var dir = try openSecureAbsoluteDirectory(
            self,
            allocator,
            paths.directory,
            false,
        );
        defer dir.close(self.io);
        if (try readOptionalFile(
            allocator,
            self.io,
            dir,
            completion_document_name,
        )) |existing| {
            defer allocator.free(existing);
            const completion = try verifyExistingCompletion(
                allocator,
                existing,
                input,
            );
            return completionBinding(paths, input, completion);
        }

        const completion = try createExecutionCompletion(input);
        const source = try completion.canonicalJson(allocator);
        defer allocator.free(source);
        try publishAtomic(
            self,
            allocator,
            dir,
            completion_document_name,
            source,
        );
        return completionBinding(paths, input, completion);
    }

    fn verifyCompletion(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        input: CompletionInput,
        expected: api.CompletionBinding,
    ) !void {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        var dir = try openSecureAbsoluteDirectory(
            self,
            allocator,
            paths.directory,
            false,
        );
        defer dir.close(self.io);
        const existing = try readOptionalFile(
            allocator,
            self.io,
            dir,
            completion_document_name,
        ) orelse return error.MissingCompletion;
        defer allocator.free(existing);
        const completion = try verifyExistingCompletion(
            allocator,
            existing,
            input,
        );
        const observed = completionBinding(paths, input, completion);
        if (!completionEqual(observed, expected))
            return error.CompletionMismatch;
    }

    fn publishAtomic(
        self: *SystemStateStore,
        allocator: std.mem.Allocator,
        dir: std.Io.Dir,
        name: []const u8,
        source: []const u8,
    ) !void {
        var operation_lock: operation_state.SystemLockBackend = .{
            .allocator = self.allocator,
            .io = self.io,
            .dir = dir,
            .name = operation_lock_name,
        };
        const lock = operation_lock.interface();
        const token = try lock.acquire(self.wait_ms);
        defer lock.release(token);
        try self.publishAtomicHeld(
            allocator,
            dir,
            name,
            source,
            lock,
            token,
        );
    }

    fn publishAtomicHeld(
        self: *SystemStateStore,
        allocator: std.mem.Allocator,
        dir: std.Io.Dir,
        name: []const u8,
        source: []const u8,
        lock: operation_state.LockBackend,
        token: operation_state.LockToken,
    ) !void {
        if (!lock.held(token)) return error.LockLost;
        if (try readOptionalFile(allocator, self.io, dir, name)) |existing| {
            defer allocator.free(existing);
            if (!std.mem.eql(u8, existing, source))
                return error.PublicationConflict;
            return;
        }
        var nonce: [8]u8 = undefined;
        try std.Io.randomSecure(self.io, &nonce);
        var stage_buffer: [64]u8 = undefined;
        const stage = try std.fmt.bufPrint(
            &stage_buffer,
            ".apt-system-{x:0>16}.tmp",
            .{std.mem.readInt(u64, &nonce, .little)},
        );
        var renamed = false;
        defer if (!renamed) dir.deleteFile(self.io, stage) catch {};
        {
            var file = try dir.createFile(self.io, stage, .{
                .exclusive = true,
                .permissions = .fromMode(0o600),
                .resolve_beneath = true,
            });
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, source);
            try file.sync(self.io);
        }
        if (!lock.held(token)) return error.LockLost;
        try dir.rename(stage, dir, name, self.io);
        renamed = true;
        try self.syncDirectoryAt(dir, .publication_directory);
    }
};

pub const VerifiedLock = struct {
    binding: api.DocumentBinding,
    semantic_request_sha256: [32]u8,
};

pub const VerifiedTransaction = struct {
    bytes: []u8,
    binding: api.DocumentBinding,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *VerifiedTransaction) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const VerificationError = error{
    OutOfMemory,
    OperationalVerificationFailure,
    InvariantViolation,
};

pub const ResultVerifier = struct {
    context: *anyopaque,
    verifyLockFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
        []const u8,
        [32]u8,
    ) VerificationError!VerifiedLock,
    verifyTransactionFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
        api.DocumentBinding,
        []const u8,
    ) VerificationError!VerifiedTransaction,
};

pub const SystemResultVerifier = struct {
    io: std.Io,

    pub fn interface(self: *SystemResultVerifier) ResultVerifier {
        return .{
            .context = self,
            .verifyLockFn = verifyLock,
            .verifyTransactionFn = verifyTransaction,
        };
    }

    fn verifyLock(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        architecture: []const u8,
        expected_request_sha256: [32]u8,
    ) VerificationError!VerifiedLock {
        return verifyLockInternal(
            context,
            allocator,
            path,
            architecture,
            expected_request_sha256,
        ) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.OperationalVerificationFailure,
        };
    }

    fn verifyLockInternal(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        architecture: []const u8,
        expected_request_sha256: [32]u8,
    ) !VerifiedLock {
        const self: *SystemResultVerifier = @ptrCast(@alignCast(context));
        const source = try readTrustedOperationFile(
            self.io,
            allocator,
            path,
            exact_lock.maximum_document_bytes,
        );
        defer allocator.free(source);
        var decoded = try exact_lock.decode(
            allocator,
            source,
            exact_lock.maximum_document_bytes,
        );
        defer decoded.deinit();
        if (!std.mem.eql(
            u8,
            decoded.lock.target_architecture,
            architecture,
        )) return error.ArchitectureMismatch;
        if (!std.mem.eql(
            u8,
            &decoded.lock.request_sha256,
            &expected_request_sha256,
        )) return error.RequestDigestMismatch;
        return .{
            .binding = .{
                .path = path,
                .schema = exact_lock.schema_id,
                .version = exact_lock.schema_version,
                .digest_sha256 = decoded.lock.digest_sha256,
            },
            .semantic_request_sha256 = decoded.lock.request_sha256,
        };
    }

    fn verifyTransaction(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        lock_binding: api.DocumentBinding,
        architecture: []const u8,
    ) VerificationError!VerifiedTransaction {
        return verifyTransactionInternal(
            context,
            allocator,
            path,
            lock_binding,
            architecture,
        ) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.OperationalVerificationFailure,
        };
    }

    fn verifyTransactionInternal(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        lock_binding: api.DocumentBinding,
        architecture: []const u8,
    ) !VerifiedTransaction {
        const self: *SystemResultVerifier = @ptrCast(@alignCast(context));
        const lock_source = try readTrustedOperationFile(
            self.io,
            allocator,
            lock_binding.path,
            exact_lock.maximum_document_bytes,
        );
        defer allocator.free(lock_source);
        var lock = try exact_lock.decode(
            allocator,
            lock_source,
            exact_lock.maximum_document_bytes,
        );
        defer lock.deinit();
        if (!std.mem.eql(
            u8,
            &lock.lock.digest_sha256,
            &lock_binding.digest_sha256,
        )) return error.LockEvidenceMismatch;
        const source = try readTrustedOperationFile(
            self.io,
            allocator,
            path,
            transaction_provenance.maximum_document_bytes,
        );
        errdefer allocator.free(source);
        const summary = try transaction_result_summary.verify(
            allocator,
            source,
            lock.lock,
            architecture,
        );
        return .{
            .bytes = source,
            .binding = .{
                .path = path,
                .schema = transaction_provenance.schema_id,
                .version = transaction_provenance.schema_version,
                .digest_sha256 = summary.transaction_digest_sha256,
            },
            .allocator = allocator,
        };
    }
};

pub const IdSource = struct {
    context: *anyopaque,
    nextFn: *const fn (*anyopaque) anyerror![32]u8,
};

pub const Clock = struct {
    context: *anyopaque,
    nowFn: *const fn (*anyopaque) i64,
};

pub const ReviewItem = struct {
    package: []const u8,
    version: ?[]const u8,
    architecture: ?[]const u8,
    detail: ?[]const u8,
};

pub const Preparation = struct {
    request: api.Request,
    request_sha256: [32]u8,
    profile: api.ProfileBinding,
    profile_state_path: []const u8,
    attempt_id: [32]u8,
    active_generation: u64 = 0,
    active_digest_sha256: [32]u8 = @splat(0),
    paths: OperationPaths,
    exact_lock: api.DocumentBinding,
    review: []const ReviewItem,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *Preparation) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn confirmationResult(self: Preparation) !api.Result {
        var result = try api.failure(
            self.request,
            .usage,
            .confirmation_required,
            "confirmation",
            "reviewed exact lock requires explicit confirmation",
        );
        result.profile = self.profile;
        result.evidence = .{
            .exact_lock = self.exact_lock,
            .active_operation_state = self.paths.active_state,
        };
        return api.complete(result);
    }
};

pub const PrepareOutcome = union(enum) {
    ready: Preparation,
    result: api.Result,
};

pub const RecoveryPreparation = struct {
    prepared: Preparation,
    action: []const u8,

    pub fn deinit(self: *RecoveryPreparation) void {
        self.prepared.deinit();
        self.* = undefined;
    }
};

pub const RecoveryPrepareOutcome = union(enum) {
    ready: RecoveryPreparation,
    result: api.Result,
};

pub const OperationalFailure = enum {
    interruption,
    state_io_or_durability,
    transport,
};

pub const ExecutionError = error{
    OutOfMemory,
    ContractViolation,
    InvariantViolation,
};

const InternalExecutionError = error{
    OutOfMemory,
    UnconfirmedExecution,
    UnsupportedApiVersion,
    InvalidProfilePath,
    InvalidPackageCount,
    InvalidPackage,
    DuplicatePackage,
    InvalidOperation,
    UnsafeInstallRoot,
    ArchitectureMismatch,
    BackendOperationMismatch,
    InvalidPath,
    UnsupportedPlatform,
    InvalidInitialState,
    InvalidTransition,
    InvalidGeneration,
    InvalidTimestamp,
    AttemptMismatch,
    MutationEvidenceRollback,
    EvidenceRollback,
    UnexpectedItems,
    InvalidRecoveryContext,
    InvalidSummary,
    TooManyItems,
    InvalidMutationStatus,
    InvalidItem,
    TooManyDiagnostics,
    InvalidExitStatus,
    InvalidProfileBinding,
    InvalidEvidencePath,
    InvalidEvidenceSchema,
    UnexpectedTransactionEvidence,
    InvalidDiagnostic,
    PartialSuccess,
    MissingCompletionEvidence,
    MissingDiagnostic,
    DocumentTooLarge,
    InvalidSelector,
    InvalidProfile,
    InvalidEvidence,
    InvalidCompletionEvidence,
    InvalidOutcome,
    InvalidMutationState,
    MissingExactLock,
    UnexpectedExactLock,
    MissingTransactionResult,
    UnexpectedTransactionResult,
    UnexpectedCompletionEvidence,
    MissingRecoveryLockVerification,
    InvariantViolation,
};

pub const ExecutionInvocation = union(enum) {
    result: api.Result,
    operational_failure: OperationalFailure,
};

pub const CompletionBoundary = enum {
    after_downloaded_state,
    after_ownership_reserved,
    after_mutating_state,
    after_clean_recovery_inspection,
    after_backend_success,
    after_transaction_verified,
    after_transaction_retained,
    after_verifying_state,
    after_acknowledgment_retained,
    before_completion_published,
    after_outer_committed,
    after_pre_mutation_claim_published,
    after_pre_mutation_outer_rechecked,
    before_ownership_acknowledged,
    after_ownership_acknowledged,
    after_recovery_acknowledged,
    after_completion_published,
    after_active_cleared,
};

pub const CompletionCrash = struct {
    context: *anyopaque,
    hitFn: *const fn (*anyopaque, CompletionBoundary) anyerror!void,

    pub fn hit(
        self: CompletionCrash,
        boundary: CompletionBoundary,
    ) !void {
        try self.hitFn(self.context, boundary);
    }
};

pub const Engine = struct {
    profiles: ProfileLoader,
    runner: LiveRootRunner,
    backend: Backend,
    store: StateStore,
    verifier: ResultVerifier,
    ids: IdSource,
    clock: Clock,
    completion_crash: ?CompletionCrash = null,

    pub fn invokeExecute(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        confirmed: bool,
    ) ExecutionError!ExecutionInvocation {
        const result = self.execute(
            allocator,
            prepared,
            confirmed,
        ) catch |err| return executionInvocationFailure(err);
        return .{ .result = result };
    }

    pub fn invokeExecuteRecovery(
        self: *Engine,
        allocator: std.mem.Allocator,
        recovery: RecoveryPreparation,
        confirmed: bool,
    ) ExecutionError!ExecutionInvocation {
        const result = self.executeRecovery(
            allocator,
            recovery,
            confirmed,
        ) catch |err| return executionInvocationFailure(err);
        return .{ .result = result };
    }

    pub fn prepare(
        self: *Engine,
        allocator: std.mem.Allocator,
        request: api.Request,
    ) !PrepareOutcome {
        api.validateRequest(request) catch return .{ .result = try api.failure(
            request,
            .usage,
            .invalid_request,
            "request",
            "invalid apt/system request",
        ) };

        var loaded = self.profiles.load(allocator, request.profile_path) catch
            return .{ .result = try profileFailure(request) };
        defer loaded.deinit();
        if (!profileMatchesPath(loaded.view.binding, request.profile_path))
            return .{ .result = try api.failure(
                request,
                .configuration,
                .profile_invalid,
                "profile",
                "loaded profile path does not bind the requested profile",
            ) };

        if (try self.blockedByActive(allocator, request, loaded.view)) |blocked| return .{ .result = blocked };
        loaded.revalidate(allocator) catch return .{ .result = try api.failure(
            request,
            .configuration,
            .profile_untrusted,
            "profile",
            "trusted profile reference changed before use",
        ) };
        if (request.operation != .list_installed) {
            var lower_status = self.runner.inspect(allocator) catch |err|
                return .{ .result = try liveRootFailure(request, err) };
            defer lower_status.deinit();
            if (lower_status.status != .clean)
                return .{ .result = try api.failure(
                    request,
                    .recovery,
                    .recovery_required,
                    "root-operation",
                    "lower-level root operation requires recovery before repository or package mutation",
                ) };
        }

        return switch (request.operation) {
            .update, .list_installed => .{
                .result = try self.prepareReadOnly(allocator, request, loaded),
            },
            .install, .remove, .upgrade => try self.prepareMutation(
                allocator,
                request,
                loaded,
            ),
            .recover => unreachable,
        };
    }

    fn prepareReadOnly(
        self: *Engine,
        allocator: std.mem.Allocator,
        request: api.Request,
        loaded: LoadedProfile,
    ) InternalExecutionError!api.Result {
        const profile = loaded.view;
        const operation: product_api.Operation = switch (request.operation) {
            .update => .refresh,
            .list_installed => .list_installed,
            else => unreachable,
        };
        loaded.revalidate(allocator) catch return ownedFailure(
            allocator,
            request,
            .configuration,
            .profile_untrusted,
            "profile",
            "trusted profile reference changed immediately before backend routing",
        );
        var run = self.runner.route(allocator, self.backend, .{
            .operation = operation,
            .options = commonOptions(profile, null, null),
        }) catch |err| return liveRootFailure(request, err);
        defer run.deinit();
        return mapProductResult(
            allocator,
            request,
            profile.binding,
            run.result,
            .{},
        );
    }

    fn prepareMutation(
        self: *Engine,
        allocator: std.mem.Allocator,
        request: api.Request,
        loaded: LoadedProfile,
    ) !PrepareOutcome {
        const profile = loaded.view;
        const request_bytes = try request.canonicalJson(allocator);
        defer allocator.free(request_bytes);
        const request_sha256 = try request.digest();
        const attempt_id = try self.ids.nextFn(self.ids.context);
        var generated_paths = try pathsFor(
            allocator,
            profile.state_path,
            attempt_id,
        );
        defer generated_paths.deinit(allocator);

        var current = try operation_state.create(allocator, .{
            .attempt_id = attempt_id,
            .generation = 1,
            .operation = request.operation,
            .phase = .reserved,
            .mutation_started = false,
            .outcome = .pending,
            .request_sha256 = request_sha256,
            .profile = profile.binding,
            .updated_unix = self.clock.nowFn(self.clock.context),
        });
        defer current.deinit();
        self.store.reserveFn(
            self.store.context,
            allocator,
            generated_paths,
            request_bytes,
            current.state,
        ) catch return .{ .result = try api.failure(
            request,
            .configuration,
            .state_persistence_failed,
            "state",
            "cannot reserve durable apt/system operation storage",
        ) };
        self.transition(allocator, profile.state_path, &current, .{
            .phase = .profile_loaded,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .result = try unknownMutationDiagnostic(
                allocator,
                request,
                request.profile_path,
                "reserved apt/system state could not be advanced durably",
            ) },
        };

        const selectors = try selectorsFor(allocator, request);
        defer allocator.free(selectors);
        const workflow_operation = semanticOperation(request.operation);
        loaded.revalidate(allocator) catch return .{
            .result = try self.failBeforeMutation(
                allocator,
                request,
                profile.state_path,
                generated_paths,
                &current,
                .configuration,
                .profile_untrusted,
                "trusted profile reference changed immediately before planning",
            ),
        };
        var planned = self.runner.workflow(allocator, self.backend, .{
            .operation = workflow_operation,
            .mode = .plan_only,
            .selectors = selectors,
            .options = commonOptions(profile, null, generated_paths.exact_lock),
        }) catch |err| {
            return .{ .result = try self.failBeforeMutation(
                allocator,
                request,
                profile.state_path,
                generated_paths,
                &current,
                if (isRootIdentityError(err)) .configuration else .planning,
                if (isRootIdentityError(err))
                    .root_operation_conflict
                else
                    .planning_failed,
                if (isRootIdentityError(err))
                    "private live-root identity changed during planning"
                else
                    "private live-root planning failed",
            ) };
        };
        defer planned.deinit();
        if (planned.result.exit_status != .success) {
            return .{ .result = try self.failBeforeMutation(
                allocator,
                request,
                profile.state_path,
                generated_paths,
                &current,
                mapOutcome(planned.result.exit_status),
                mapDiagnostic(planned.result.exit_status),
                planned.result.summary,
            ) };
        }
        self.transition(allocator, profile.state_path, &current, .{
            .phase = .authenticated,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .result = try unknownMutationDiagnostic(
                allocator,
                request,
                request.profile_path,
                "authenticated apt/system state could not be advanced durably",
            ) },
        };
        const verified = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            generated_paths.exact_lock,
            profile.architecture,
            try workflowSemanticDigest(
                allocator,
                workflow_operation,
                selectors,
            ),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            error.OperationalVerificationFailure => {
                return .{ .result = try self.failBeforeMutation(
                    allocator,
                    request,
                    profile.state_path,
                    generated_paths,
                    &current,
                    .planning,
                    .exact_lock_publication_failed,
                    "planned exact lock is missing, corrupt, or foreign",
                ) };
            },
        };
        if (!std.mem.eql(
            u8,
            verified.binding.path,
            generated_paths.exact_lock,
        )) {
            return .{ .result = try self.failBeforeMutation(
                allocator,
                request,
                profile.state_path,
                generated_paths,
                &current,
                .planning,
                .exact_lock_publication_failed,
                "exact-lock verifier returned a foreign path",
            ) };
        }
        self.transition(allocator, profile.state_path, &current, .{
            .phase = .planned,
            .exact_lock = verified.binding,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .result = try unknownMutationDiagnostic(
                allocator,
                request,
                request.profile_path,
                "planned apt/system state could not be advanced durably",
            ) },
        };

        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = .init(allocator);
        errdefer arena.deinit();
        const owned = arena.allocator();
        const owned_request = try copyRequest(owned, request);
        const paths = try copyPaths(owned, generated_paths);
        const binding = try copyProfileBinding(owned, profile.binding);
        const review = try owned.alloc(ReviewItem, planned.result.items.len);
        for (planned.result.items, 0..) |item, index| {
            review[index] = .{
                .package = try owned.dupe(u8, item.package),
                .version = try dupeOptional(owned, item.version),
                .architecture = try dupeOptional(owned, item.architecture),
                .detail = try dupeOptional(owned, item.detail),
            };
        }
        return .{ .ready = .{
            .request = owned_request,
            .request_sha256 = request_sha256,
            .profile = binding,
            .profile_state_path = try owned.dupe(u8, profile.state_path),
            .attempt_id = attempt_id,
            .active_generation = current.state.generation,
            .active_digest_sha256 = current.state.digest_sha256,
            .paths = paths,
            .exact_lock = try copyDocumentBinding(owned, verified.binding),
            .review = review,
            .arena = arena,
            .backing_allocator = allocator,
        } };
    }

    pub fn execute(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        confirmed: bool,
    ) InternalExecutionError!api.Result {
        if (!confirmed) return prepared.confirmationResult();
        var loaded = self.profiles.load(
            allocator,
            prepared.request.profile_path,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(
                allocator,
                prepared,
            ),
        };
        defer loaded.deinit();
        if (!profileEqual(loaded.view.binding, prepared.profile))
            return self.reconcilePreparedError(allocator, prepared);
        loaded.revalidate(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(allocator, prepared),
        };

        var current = (self.store.readActive(
            allocator,
            loaded.view.state_path,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(allocator, prepared),
        }) orelse return self.reconcilePreparedError(allocator, prepared);
        defer current.deinit();
        if (!stateMatchesPreparation(current.state, prepared))
            return self.reconcilePreparedError(allocator, prepared);
        const before_download = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            prepared.paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(allocator, prepared.request),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            error.OperationalVerificationFailure => return self.reconcilePreparedError(allocator, prepared),
        };
        if (!lockMatchesPreparation(
            before_download.binding,
            prepared,
            current.state,
        )) return self.finishPreMutationFailure(
            allocator,
            prepared,
            &current,
            .planning,
            .planning_failed,
            "reviewed exact lock was replaced before download",
        );
        loaded.revalidate(allocator) catch return self.finishPreMutationFailure(
            allocator,
            prepared,
            &current,
            .configuration,
            .profile_untrusted,
            "trusted profile reference changed immediately before download",
        );

        const selectors = try selectorsFor(allocator, prepared.request);
        defer allocator.free(selectors);
        const workflow_operation = semanticOperation(prepared.request.operation);
        var downloaded = self.runner.workflow(allocator, self.backend, .{
            .operation = workflow_operation,
            .mode = .download_only,
            .selectors = selectors,
            .options = commonOptions(
                loaded.view,
                prepared.paths.exact_lock,
                null,
            ),
        }) catch |err| return self.finishPreMutationFailure(
            allocator,
            prepared,
            &current,
            if (isRootIdentityError(err)) .configuration else .download,
            if (isRootIdentityError(err))
                .root_operation_conflict
            else
                .download_failed,
            if (isRootIdentityError(err))
                "private live-root identity changed before mutation"
            else
                "package acquisition failed before mutation",
        );
        defer downloaded.deinit();
        if (downloaded.result.exit_status != .success)
            return self.finishPreMutationFailure(
                allocator,
                prepared,
                &current,
                mapOutcome(downloaded.result.exit_status),
                mapDiagnostic(downloaded.result.exit_status),
                downloaded.result.summary,
            );
        self.transition(
            allocator,
            loaded.view.state_path,
            &current,
            .{ .phase = .downloaded },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(allocator, prepared),
        };
        self.hitCompletionBoundary(.after_downloaded_state) catch
            return self.reconcilePreparedError(allocator, prepared);
        const before_execute = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            prepared.paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(allocator, prepared.request),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            error.OperationalVerificationFailure => return self.reconcilePreparedError(allocator, prepared),
        };
        if (!lockMatchesPreparation(
            before_execute.binding,
            prepared,
            current.state,
        )) return self.finishPreMutationFailure(
            allocator,
            prepared,
            &current,
            .planning,
            .planning_failed,
            "reviewed exact lock was replaced before execution",
        );
        loaded.revalidate(allocator) catch return self.finishPreMutationFailure(
            allocator,
            prepared,
            &current,
            .configuration,
            .profile_untrusted,
            "trusted profile reference changed after download and before execution",
        );
        var reserved = self.runner.workflow(allocator, self.backend, .{
            .operation = workflow_operation,
            .mode = .reserve,
            .selectors = selectors,
            .options = executeOptions(
                loaded.view,
                prepared.paths.exact_lock,
            ),
            .orchestration_id = prepared.attempt_id,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedErrorWithPolicy(
                allocator,
                prepared,
                .reservation_outcome_ambiguous,
            ),
        };
        defer reserved.deinit();
        if (reserved.result.exit_status != .success or
            reserved.root_status != .recovery_required)
            return self.reconcilePreparedError(allocator, prepared);
        const after_reserve_lock = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            prepared.paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(allocator, prepared.request),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            error.OperationalVerificationFailure => return self.reconcilePreparedError(allocator, prepared),
        };
        if (!lockMatchesPreparation(
            after_reserve_lock.binding,
            prepared,
            current.state,
        )) return self.reconcilePreparedError(allocator, prepared);
        loaded.revalidate(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(allocator, prepared),
        };
        self.hitCompletionBoundary(.after_ownership_reserved) catch
            return self.reconcilePreparedErrorWithPolicy(
                allocator,
                prepared,
                .reservation_outcome_ambiguous,
            );
        self.transition(
            allocator,
            loaded.view.state_path,
            &current,
            .{ .phase = .mutating },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedErrorWithPolicy(
                allocator,
                prepared,
                .reservation_outcome_ambiguous,
            ),
        };
        self.hitCompletionBoundary(.after_mutating_state) catch
            return self.reconcilePreparedError(allocator, prepared);

        var executed = self.runner.workflow(allocator, self.backend, .{
            .operation = workflow_operation,
            .mode = .execute,
            .selectors = selectors,
            .options = executeOptions(
                loaded.view,
                prepared.paths.exact_lock,
            ),
            .orchestration_id = prepared.attempt_id,
        }) catch |err| return self.markRecoveryRequired(
            allocator,
            prepared,
            &current,
            if (isRootIdentityError(err))
                "private live-root identity changed during transaction"
            else
                "transaction execution was interrupted",
        );
        defer executed.deinit();
        if (executed.result.exit_status != .success or
            executed.root_status != .completed)
            return self.markRecoveryRequired(
                allocator,
                prepared,
                &current,
                if (executed.result.summary.len == 0)
                    "transaction did not prove root-operation completion"
                else
                    executed.result.summary,
            );
        self.hitCompletionBoundary(.after_backend_success) catch
            return self.reconcilePreparedError(allocator, prepared);
        return self.verifyAndComplete(
            allocator,
            prepared,
            &loaded,
            &current,
            false,
            null,
            null,
            null,
            null,
            executed.ownership_acknowledgment orelse
                return self.markRecoveryRequired(
                    allocator,
                    prepared,
                    &current,
                    "successful lower transaction did not retain its exact ownership token",
                ),
        );
    }

    /// Converts an unexpected post-prepare execution error into an
    /// evidence-bound recovery result. Integrations must use this instead of
    /// inferring whether mutation began.
    pub fn reconcilePreparedError(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
    ) InternalExecutionError!api.Result {
        return self.reconcilePreparedErrorWithPolicy(
            allocator,
            prepared,
            .clean_proves_pre_mutation,
        );
    }

    const CleanLowerPolicy = enum {
        clean_proves_pre_mutation,
        reservation_outcome_ambiguous,
    };

    fn reconcilePreparedErrorWithPolicy(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        clean_lower_policy: CleanLowerPolicy,
    ) InternalExecutionError!api.Result {
        var active = self.store.inspectActiveLocked(
            allocator,
            prepared.profile_state_path,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            else => return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "active apt/system state could not be verified",
            ),
        };
        defer if (active) |*owned| owned.deinit();
        const state = if (active) |owned| owned.state else return self.reconcileUnknownPreparedFailure(
            allocator,
            prepared,
            "active apt/system state is absent",
        );
        if (!stateMatchesPreparation(state, prepared))
            return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "active apt/system state is foreign or does not match the reviewed request",
            );
        var retained = self.store.readRetainedFn(
            self.store.context,
            allocator,
            prepared.paths,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            else => return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "retained apt/system state could not be verified",
            ),
        };
        defer if (retained) |*owned| owned.deinit();
        if (retained) |owned| {
            if (!retainedFinalMatchesActive(
                owned.state,
                state,
                prepared,
            ))
                return self.reconcileUnknownPreparedFailure(
                    allocator,
                    prepared,
                    "retained apt/system state is foreign to the active operation",
                );
            if (owned.state.mutation_started)
                return self.recoveryFromVerifiedActive(
                    allocator,
                    prepared,
                    owned.state,
                );
        }
        if (!state.mutation_started and
            state.transaction_result == null and
            state.root_operation_completion == null)
            return self.reconcileStablePreMutation(
                allocator,
                prepared,
                state,
                clean_lower_policy,
            );
        return self.recoveryFromVerifiedActive(
            allocator,
            prepared,
            state,
        );
    }

    fn reconcileStablePreMutation(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        snapshot: operation_state.State,
        clean_lower_policy: CleanLowerPolicy,
    ) InternalExecutionError!api.Result {
        var loaded = self.profiles.load(
            allocator,
            snapshot.profile.path,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "the pre-mutation profile binding could not be reopened",
            ),
        };
        defer loaded.deinit();
        if (!profileEqual(loaded.view.binding, snapshot.profile))
            return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "the pre-mutation profile binding changed",
            );
        loaded.revalidate(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "the pre-mutation profile evidence could not be revalidated",
            ),
        };
        const verified_lock = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            prepared.paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(allocator, prepared.request),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            error.OperationalVerificationFailure => return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "the pre-mutation exact lock could not be verified",
            ),
        };
        if (!lockMatchesPreparation(
            verified_lock.binding,
            prepared,
            snapshot,
        )) return self.reconcileUnknownPreparedFailure(
            allocator,
            prepared,
            "the pre-mutation exact lock no longer matches durable state",
        );

        var lower = self.runner.inspect(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "lower root-operation state could not be verified",
            ),
        };
        defer lower.deinit();
        var exclusion: root_operation.DeferredAcknowledgment = undefined;
        if (lower.status == .clean and
            lower.record == null and
            lower.deferred_acknowledgment == null)
        {
            const selectors = try selectorsFor(allocator, prepared.request);
            defer allocator.free(selectors);
            const claim_binding: root_operation.PreMutationReconciliationClaimBinding = .{
                .outer_attempt_id = prepared.attempt_id,
                .outer_generation = snapshot.generation,
                .outer_state_sha256 = snapshot.digest_sha256,
                .profile_sha256 = snapshot.profile.sha256,
                .profile_reference_sha256 = snapshot.profile.reference_evidence_sha256,
                .exact_lock_sha256 = verified_lock.binding.digest_sha256,
                .semantic_request_sha256 = verified_lock.semantic_request_sha256,
            };
            var claimed = self.runner.workflow(
                allocator,
                self.backend,
                .{
                    .operation = semanticOperation(prepared.request.operation),
                    .mode = .recover,
                    .selectors = selectors,
                    .options = executeOptions(
                        loaded.view,
                        prepared.paths.exact_lock,
                    ),
                    .orchestration_id = prepared.attempt_id,
                    .reconciliation_claim = .{ .pre_mutation = .{
                        .outer_generation = claim_binding.outer_generation,
                        .outer_state_sha256 = claim_binding.outer_state_sha256,
                        .profile_sha256 = claim_binding.profile_sha256,
                        .profile_reference_sha256 = claim_binding.profile_reference_sha256,
                        .exact_lock_sha256 = claim_binding.exact_lock_sha256,
                    } },
                },
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return self.reconcileUnknownPreparedFailure(
                    allocator,
                    prepared,
                    "the lower clean-state exclusion claim failed",
                ),
            };
            defer claimed.deinit();
            if (claimed.result.exit_status != .success or
                claimed.root_status != .completed or
                claimed.ownership_acknowledgment == null)
                return self.reconcileUnknownPreparedFailure(
                    allocator,
                    prepared,
                    "the lower clean-state exclusion claim was not durably acknowledged",
                );
            const acknowledgment = claimed.ownership_acknowledgment.?;
            exclusion = .{
                .state = .pre_mutation_reconciliation_claim,
                .attempt_id = acknowledgment.attempt_id,
                .pre_mutation_claim = claim_binding,
                .acknowledgment_id = acknowledgment.acknowledgment_id,
                .digest_sha256 = acknowledgment.marker_sha256,
            };
            self.hitCompletionBoundary(
                .after_pre_mutation_claim_published,
            ) catch return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "pre-mutation reconciliation was interrupted after the lower exclusion claim was published",
            );
        } else if (lower.deferred_acknowledgment) |marker| {
            const exact_claim =
                lower.record == null and
                preMutationReconciliationClaimMatches(
                    marker,
                    prepared,
                    snapshot,
                    verified_lock,
                );
            const exact_abandoned =
                lower.record != null and
                try lowerAbandonedPreMutationMatches(
                    allocator,
                    lower.record.?.record,
                    marker,
                    prepared,
                    loaded.view,
                    verified_lock,
                );
            if (!exact_claim and !exact_abandoned)
                return self.reconcileUnknownPreparedFailure(
                    allocator,
                    prepared,
                    "lower ownership state does not prove an exact pre-mutation reconciliation owner",
                );
            exclusion = marker;
        } else return self.reconcileUnknownPreparedFailure(
            allocator,
            prepared,
            switch (clean_lower_policy) {
                .clean_proves_pre_mutation => "lower state is not eligible for stable pre-mutation reconciliation",
                .reservation_outcome_ambiguous => "the lower reservation outcome is ambiguous",
            },
        );

        var stable = (self.store.inspectActiveLocked(
            allocator,
            prepared.profile_state_path,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "active state could not be rechecked after lower exclusion",
            ),
        }) orelse return self.reconcileUnknownPreparedFailure(
            allocator,
            prepared,
            "active state disappeared after lower exclusion",
        );
        defer stable.deinit();
        if (stable.state.generation != snapshot.generation or
            !std.mem.eql(
                u8,
                &stable.state.digest_sha256,
                &snapshot.digest_sha256,
            ) or
            !stateMatchesPreparation(stable.state, prepared) or
            stable.state.mutation_started or
            stable.state.transaction_result != null or
            stable.state.root_operation_completion != null)
            return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "active state changed while lower pre-mutation exclusion was established",
            );
        self.hitCompletionBoundary(
            .after_pre_mutation_outer_rechecked,
        ) catch return self.reconcileUnknownPreparedFailure(
            allocator,
            prepared,
            "pre-mutation reconciliation was interrupted after the outer state was rechecked",
        );

        const message =
            "execution failed before mutation; stable outer state and an exact lower exclusion prove no package change occurred";
        var committed = if (stable.state.phase == .completed and
            stable.state.outcome == .failed_before_mutation)
            try operation_state.create(allocator, stable.state)
        else committed: {
            var final = try nextState(allocator, stable.state, .{
                .phase = .completed,
                .outcome = .failed_before_mutation,
                .diagnostic = message,
                .updated_unix = self.clock.nowFn(self.clock.context),
            });
            defer final.deinit();
            self.store.commitFn(
                self.store.context,
                allocator,
                prepared.paths,
                operation_state.Expected.fromState(stable.state),
                final.state,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return self.reconcileUnknownPreparedFailure(
                    allocator,
                    prepared,
                    "the stable pre-mutation final state could not be committed",
                ),
            };
            break :committed (self.store.inspectActiveLocked(
                allocator,
                prepared.profile_state_path,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return self.reconcileUnknownPreparedFailure(
                    allocator,
                    prepared,
                    "the committed pre-mutation final state could not be reopened",
                ),
            }) orelse return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "the committed pre-mutation final state is absent",
            );
        };
        defer committed.deinit();
        if (committed.state.outcome != .failed_before_mutation or
            committed.state.mutation_started or
            !stateMatchesPreparation(committed.state, prepared))
            return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "the committed pre-mutation final state is foreign",
            );
        self.acknowledgeCommittedLower(
            allocator,
            prepared,
            &loaded,
            committed.state,
            exclusion,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            else => return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "the lower pre-mutation exclusion could not be finalized",
            ),
        };
        self.store.clearCommittedFn(
            self.store.context,
            allocator,
            prepared.paths,
            operation_state.Expected.fromState(committed.state),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcileUnknownPreparedFailure(
                allocator,
                prepared,
                "the committed pre-mutation state could not be cleared",
            ),
        };
        return ownedFailure(
            allocator,
            prepared.request,
            .configuration,
            .state_persistence_failed,
            "state",
            message,
        );
    }

    fn reconcilePreparedErrorWithCompletion(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        completion: api.CompletionBinding,
        recovered: bool,
    ) InternalExecutionError!api.Result {
        var active = self.store.inspectActiveLocked(
            allocator,
            prepared.profile_state_path,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        defer if (active) |*owned| owned.deinit();
        if (active) |owned| {
            if (stateMatchesPreparation(owned.state, prepared) and
                owned.state.mutation_started and
                owned.state.transaction_result != null)
            {
                var with_completion = owned.state;
                with_completion.root_operation_completion = completion;
                if (recovered) with_completion.outcome = .recovered;
                return self.recoveryFromVerifiedActive(
                    allocator,
                    prepared,
                    with_completion,
                );
            }
        }
        var result = try self.reconcilePreparedError(allocator, prepared);
        errdefer result.deinit();
        const profile = result.profile orelse return result;
        const verified_lock_binding = result.evidence.exact_lock orelse
            return result;
        const transaction = result.evidence.transaction_result orelse
            return result;
        if (!profileEqual(profile, prepared.profile) or
            !documentEqual(verified_lock_binding, prepared.exact_lock))
            return result;
        self.store.verifyCompletionFn(
            self.store.context,
            allocator,
            prepared.paths,
            .{
                .attempt_id = prepared.attempt_id,
                .request_sha256 = prepared.request_sha256,
                .profile = profile,
                .exact_lock = verified_lock_binding,
                .transaction_result = transaction,
                .recovered = recovered,
                .completed_unix = self.clock.nowFn(self.clock.context),
            },
            completion,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return result,
        };
        result.evidence.root_operation_completion = completion;
        result = try api.complete(result);
        return result;
    }

    fn recoveryFromVerifiedActive(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        state: operation_state.State,
    ) !api.Result {
        var loaded = self.profiles.load(
            allocator,
            state.profile.path,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return unknownMutationDiagnostic(
                allocator,
                prepared.request,
                prepared.request.profile_path,
                "the active state proves mutation but its profile could not be reopened",
            ),
        };
        defer loaded.deinit();
        if (!profileEqual(loaded.view.binding, state.profile))
            return unknownMutationDiagnostic(
                allocator,
                prepared.request,
                prepared.request.profile_path,
                "the active state proves mutation but its profile binding is no longer exact",
            );
        loaded.revalidate(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return unknownMutationDiagnostic(
                allocator,
                prepared.request,
                prepared.request.profile_path,
                "the active state proves mutation but its profile could not be revalidated",
            ),
        };
        const state_lock = state.exact_lock orelse
            return unknownMutationDiagnostic(
                allocator,
                prepared.request,
                prepared.request.profile_path,
                "the active state proves mutation but has no exact-lock binding",
            );
        const semantic_request_sha256 = try semanticDigestForRequest(
            allocator,
            prepared.request,
        );
        const verified_lock = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            state_lock.path,
            loaded.view.architecture,
            semantic_request_sha256,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            error.OperationalVerificationFailure => return unknownMutationDiagnostic(
                allocator,
                prepared.request,
                prepared.request.profile_path,
                "the active state proves mutation but its exact lock could not be verified",
            ),
        };
        if (!documentEqual(verified_lock.binding, state_lock) or
            !documentEqual(verified_lock.binding, prepared.exact_lock) or
            !std.mem.eql(
                u8,
                &verified_lock.semantic_request_sha256,
                &semantic_request_sha256,
            ))
            return unknownMutationDiagnostic(
                allocator,
                prepared.request,
                prepared.request.profile_path,
                "the active state proves mutation but its exact lock is foreign",
            );

        if (state.root_operation_completion == null) {
            var lower = self.runner.inspect(allocator) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return unknownMutationDiagnostic(
                    allocator,
                    prepared.request,
                    prepared.request.profile_path,
                    "lower root-operation state could not corroborate the outer mutation claim",
                ),
            };
            defer lower.deinit();
            const marker = lower.deferred_acknowledgment orelse
                return unknownMutationDiagnostic(
                    allocator,
                    prepared.request,
                    prepared.request.profile_path,
                    "outer mutation state has no exact lower ownership marker",
                );
            const record = lower.record orelse
                return unknownMutationDiagnostic(
                    allocator,
                    prepared.request,
                    prepared.request.profile_path,
                    "outer mutation state has no exact lower operation record",
                );
            var lower_completion: ?root_operation_completion.OwnedDocument =
                if (marker.state == .pending or
                marker.state == .acknowledged)
                    self.runner.readRecoveryCompletion(allocator) catch |err|
                        switch (err) {
                            error.OutOfMemory => return error.OutOfMemory,
                            else => return unknownMutationDiagnostic(
                                allocator,
                                prepared.request,
                                prepared.request.profile_path,
                                "lower recovery completion could not be verified",
                            ),
                        }
                else
                    null;
            defer if (lower_completion) |*owned| owned.deinit();
            if (!try lowerMutationMatches(
                allocator,
                record.record,
                marker,
                prepared,
                loaded.view,
                verified_lock,
                if (lower_completion) |owned| owned.document else null,
            )) return unknownMutationDiagnostic(
                allocator,
                prepared.request,
                prepared.request.profile_path,
                "outer and lower mutation evidence are inconsistent",
            );
        }

        var transaction: ?api.DocumentBinding = null;
        if (state.transaction_result) |binding| {
            var verified = self.verifier.verifyTransactionFn(
                self.verifier.context,
                allocator,
                binding.path,
                verified_lock.binding,
                loaded.view.architecture,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvariantViolation => return error.InvariantViolation,
                error.OperationalVerificationFailure => return recoveryDiagnostic(
                    allocator,
                    prepared.request,
                    loaded.view.binding,
                    verified_lock.binding,
                    null,
                    null,
                    true,
                    prepared.profile_state_path,
                ),
            };
            defer verified.deinit();
            if (documentEqual(verified.binding, binding))
                transaction = verified.binding;
        }

        var completion: ?api.CompletionBinding = null;
        if (state.root_operation_completion) |binding| {
            if (transaction) |verified_transaction| {
                self.store.verifyCompletionFn(
                    self.store.context,
                    allocator,
                    prepared.paths,
                    .{
                        .attempt_id = prepared.attempt_id,
                        .request_sha256 = prepared.request_sha256,
                        .profile = loaded.view.binding,
                        .exact_lock = verified_lock.binding,
                        .transaction_result = verified_transaction,
                        .recovered = state.outcome == .recovered,
                        .completed_unix = self.clock.nowFn(self.clock.context),
                    },
                    binding,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return recoveryDiagnostic(
                        allocator,
                        prepared.request,
                        loaded.view.binding,
                        verified_lock.binding,
                        transaction,
                        null,
                        true,
                        prepared.profile_state_path,
                    ),
                };
                completion = binding;
            }
        }
        return recoveryDiagnostic(
            allocator,
            prepared.request,
            loaded.view.binding,
            verified_lock.binding,
            transaction,
            completion,
            true,
            prepared.profile_state_path,
        );
    }

    fn reconcileUnknownPreparedFailure(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        reason: []const u8,
    ) !api.Result {
        _ = self;
        return unknownMutationDiagnostic(
            allocator,
            prepared.request,
            prepared.request.profile_path,
            reason,
        );
    }

    pub fn prepareRecovery(
        self: *Engine,
        allocator: std.mem.Allocator,
        profile_path: []const u8,
    ) !RecoveryPrepareOutcome {
        var loaded = self.profiles.load(allocator, profile_path) catch |err|
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return .{ .result = try unknownMutationDiagnostic(
                    allocator,
                    null,
                    profile_path,
                    "the trusted profile could not be loaded for recovery",
                ) },
            };
        defer loaded.deinit();
        loaded.revalidate(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .result = try unknownMutationDiagnostic(
                allocator,
                null,
                profile_path,
                "the trusted profile changed before recovery state could be verified",
            ) },
        };
        var active = (self.store.inspectActiveLocked(
            allocator,
            loaded.view.state_path,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .result = try unknownMutationDiagnostic(
                allocator,
                null,
                profile_path,
                "active apt/system state could not be verified for recovery",
            ) },
        }) orelse return .{ .result = try unknownMutationDiagnostic(
            allocator,
            null,
            profile_path,
            "active apt/system state is absent",
        ) };
        defer active.deinit();
        if (!profileEqual(active.state.profile, loaded.view.binding))
            return .{ .result = try unknownMutationDiagnostic(
                allocator,
                null,
                profile_path,
                "active apt/system state is foreign to the requested profile",
            ) };
        var paths = try pathsFor(
            allocator,
            loaded.view.state_path,
            active.state.attempt_id,
        );
        defer paths.deinit(allocator);
        var retained = self.store.readRequestFn(
            self.store.context,
            allocator,
            paths,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .result = try unknownMutationDiagnostic(
                allocator,
                null,
                profile_path,
                "the retained semantic request is unreadable",
            ) },
        };
        defer retained.deinit();
        if (!std.mem.eql(
            u8,
            &(try retained.request.digest()),
            &active.state.request_sha256,
        ) or retained.request.operation != active.state.operation or
            !std.mem.eql(
                u8,
                retained.request.profile_path,
                profile_path,
            ))
            return .{ .result = try unknownMutationDiagnostic(
                allocator,
                null,
                profile_path,
                "the retained semantic request does not bind the active operation",
            ) };
        const reconcilable_pre_mutation =
            !active.state.mutation_started and
            (active.state.phase == .planned or
                active.state.phase == .downloaded or
                (active.state.phase == .completed and
                    active.state.outcome == .failed_before_mutation));
        if ((!active.state.mutation_started and
            !reconcilable_pre_mutation) or
            active.state.exact_lock == null)
            return .{ .result = try unknownMutationDiagnostic(
                allocator,
                null,
                profile_path,
                "active apt/system state is not an exact recoverable phase",
            ) };
        const verified = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(allocator, retained.request),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            error.OperationalVerificationFailure => return .{ .result = try unknownMutationDiagnostic(
                allocator,
                null,
                profile_path,
                "the retained exact lock is unreadable or invalid",
            ) },
        };
        if (!std.mem.eql(
            u8,
            verified.binding.path,
            paths.exact_lock,
        ) or !documentEqual(verified.binding, active.state.exact_lock.?))
            return .{ .result = try unknownMutationDiagnostic(
                allocator,
                null,
                profile_path,
                "the retained exact lock differs from active apt/system state",
            ) };

        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = .init(allocator);
        errdefer arena.deinit();
        const owned = arena.allocator();
        const action = try std.fmt.allocPrint(
            owned,
            "debz recover --system-profile {s}",
            .{profile_path},
        );
        const preparation: Preparation = .{
            .request = try copyRequest(owned, retained.request),
            .request_sha256 = active.state.request_sha256,
            .profile = try copyProfileBinding(owned, active.state.profile),
            .profile_state_path = try owned.dupe(u8, loaded.view.state_path),
            .attempt_id = active.state.attempt_id,
            .active_generation = active.state.generation,
            .active_digest_sha256 = active.state.digest_sha256,
            .paths = try copyPaths(owned, paths),
            .exact_lock = try copyDocumentBinding(
                owned,
                active.state.exact_lock.?,
            ),
            .review = &.{},
            .arena = arena,
            .backing_allocator = allocator,
        };
        return .{ .ready = .{
            .prepared = preparation,
            .action = action,
        } };
    }

    pub fn executeRecovery(
        self: *Engine,
        allocator: std.mem.Allocator,
        recovery: RecoveryPreparation,
        confirmed: bool,
    ) InternalExecutionError!api.Result {
        if (!confirmed) return recovery.prepared.confirmationResult();
        var loaded = self.profiles.load(
            allocator,
            recovery.prepared.request.profile_path,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedErrorWithPolicy(
                allocator,
                recovery.prepared,
                .reservation_outcome_ambiguous,
            ),
        };
        defer loaded.deinit();
        if (!profileEqual(loaded.view.binding, recovery.prepared.profile))
            return self.reconcileUnknownPreparedFailure(
                allocator,
                recovery.prepared,
                "the trusted recovery profile binding changed",
            );
        loaded.revalidate(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcileUnknownPreparedFailure(
                allocator,
                recovery.prepared,
                "the trusted recovery profile could not be revalidated",
            ),
        };
        var current = (self.store.readActive(
            allocator,
            loaded.view.state_path,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(
                allocator,
                recovery.prepared,
            ),
        }) orelse return self.reconcilePreparedError(
            allocator,
            recovery.prepared,
        );
        defer current.deinit();
        if (!stateMatchesPreparation(current.state, recovery.prepared) or
            !recoverableOuterPhase(current.state.phase))
            return self.reconcilePreparedError(allocator, recovery.prepared);
        const recovery_lock = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            recovery.prepared.paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(
                allocator,
                recovery.prepared.request,
            ),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            error.OperationalVerificationFailure => return self.reconcilePreparedError(
                allocator,
                recovery.prepared,
            ),
        };
        if (!lockMatchesPreparation(
            recovery_lock.binding,
            recovery.prepared,
            current.state,
        )) return self.reconcilePreparedError(allocator, recovery.prepared);
        loaded.revalidate(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcileUnknownPreparedFailure(
                allocator,
                recovery.prepared,
                "the trusted recovery profile changed before retained state inspection",
            ),
        };
        var retained_final = self.store.readRetained(
            allocator,
            recovery.prepared.paths,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(
                allocator,
                recovery.prepared,
            ),
        };
        defer if (retained_final) |*owned| owned.deinit();
        if (retained_final) |*retained| {
            if (retained.state.outcome == .failed_before_mutation)
                return self.reconcileStablePreMutation(
                    allocator,
                    recovery.prepared,
                    current.state,
                    .clean_proves_pre_mutation,
                );
            return self.reconcileRetainedFinal(
                allocator,
                recovery.prepared,
                &loaded,
                &current,
                retained.state,
                recovery_lock,
            );
        }
        loaded.revalidate(allocator) catch
            return self.reconcileUnknownPreparedFailure(
                allocator,
                recovery.prepared,
                "trusted profile reference changed before recovery inspection",
            );
        var lower_inspection = self.runner.inspect(allocator) catch
            return self.recoveryFailed(
                allocator,
                recovery.prepared,
                &current,
                "lower-level root-operation status could not be inspected",
            );
        defer lower_inspection.deinit();
        loaded.revalidate(allocator) catch
            return self.reconcileUnknownPreparedFailure(
                allocator,
                recovery.prepared,
                "trusted profile reference changed while lower recovery state was inspected",
            );
        const ownership_marker = lower_inspection.deferred_acknowledgment;
        if (ownership_marker) |marker| {
            if (!std.mem.eql(
                u8,
                &marker.acknowledgment_id,
                &recovery.prepared.attempt_id,
            )) return self.recoveryFailed(
                allocator,
                recovery.prepared,
                &current,
                "lower-level root ownership belongs to another outer attempt",
            );
            if (marker.state == .pre_mutation_reconciliation_claim) {
                if (lower_inspection.record != null or
                    !preMutationReconciliationClaimMatches(
                        marker,
                        recovery.prepared,
                        current.state,
                        recovery_lock,
                    ))
                    return unknownMutationDiagnostic(
                        allocator,
                        recovery.prepared.request,
                        recovery.prepared.request.profile_path,
                        "the lower pre-mutation reconciliation claim is foreign or inconsistent",
                    );
                return self.reconcileStablePreMutation(
                    allocator,
                    recovery.prepared,
                    current.state,
                    .clean_proves_pre_mutation,
                );
            }
        }
        const owner_proven_pre_mutation =
            if (ownership_marker) |marker|
                if (lower_inspection.record) |record|
                    try lowerAbandonedPreMutationMatches(
                        allocator,
                        record.record,
                        marker,
                        recovery.prepared,
                        loaded.view,
                        recovery_lock,
                    )
                else
                    false
            else
                false;
        if (ownership_marker) |marker| {
            if ((marker.state == .bound and
                lower_inspection.record == null) or
                (marker.state == .abandoned and
                    !owner_proven_pre_mutation))
                return unknownMutationDiagnostic(
                    allocator,
                    recovery.prepared.request,
                    recovery.prepared.request.profile_path,
                    "lower ownership marker and root-operation record do not jointly prove a safe recovery action",
                );
        }
        const retry_unbound_preflight =
            !current.state.mutation_started and
            current.state.phase == .downloaded and
            ownership_marker == null and
            lower_inspection.status == .clean and
            current.state.transaction_result == null and
            current.state.root_operation_completion == null;
        if (lower_inspection.status == .clean or
            owner_proven_pre_mutation or
            retry_unbound_preflight)
        {
            const finalize_ownership = if (ownership_marker) |marker|
                marker.state == .released or
                    (marker.state == .bound and
                        lower_inspection.record != null and
                        lower_inspection.record.?.record.clearable())
            else
                false;
            const retry_abandoned =
                owner_proven_pre_mutation or retry_unbound_preflight;
            const marker_acknowledgment: ?RecoveryAcknowledgment =
                if (ownership_marker) |marker|
                    if (marker.state == .acknowledged and
                        marker.completion_sha256 != null and
                        marker.provenance_sha256 != null)
                        .{
                            .attempt_id = marker.attempt_id,
                            .completion_sha256 = marker.completion_sha256.?,
                            .provenance_sha256 = marker.provenance_sha256.?,
                            .acknowledgment_id = marker.acknowledgment_id,
                        }
                    else
                        null
                else
                    null;
            if (retry_abandoned) {
                const before_retry = self.verifier.verifyLockFn(
                    self.verifier.context,
                    allocator,
                    recovery.prepared.paths.exact_lock,
                    loaded.view.architecture,
                    try semanticDigestForRequest(
                        allocator,
                        recovery.prepared.request,
                    ),
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.InvariantViolation => return error.InvariantViolation,
                    error.OperationalVerificationFailure => return self.reconcilePreparedError(
                        allocator,
                        recovery.prepared,
                    ),
                };
                if (!lockMatchesPreparation(
                    before_retry.binding,
                    recovery.prepared,
                    current.state,
                )) return self.recoveryFailed(
                    allocator,
                    recovery.prepared,
                    &current,
                    "retained exact lock was replaced before retrying the proven pre-mutation attempt",
                );
                loaded.revalidate(allocator) catch
                    return self.reconcileUnknownPreparedFailure(
                        allocator,
                        recovery.prepared,
                        "trusted profile reference changed before retrying the proven pre-mutation attempt",
                    );
                const selectors = try selectorsFor(
                    allocator,
                    recovery.prepared.request,
                );
                defer allocator.free(selectors);
                if (retry_unbound_preflight) {
                    var reserved = self.runner.workflow(
                        allocator,
                        self.backend,
                        .{
                            .operation = semanticOperation(
                                recovery.prepared.request.operation,
                            ),
                            .mode = .reserve,
                            .selectors = selectors,
                            .options = executeOptions(
                                loaded.view,
                                recovery.prepared.paths.exact_lock,
                            ),
                            .orchestration_id = recovery.prepared.attempt_id,
                        },
                    ) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return self.reconcilePreparedError(
                            allocator,
                            recovery.prepared,
                        ),
                    };
                    defer reserved.deinit();
                    if (reserved.result.exit_status != .success or
                        reserved.root_status != .recovery_required)
                        return self.reconcilePreparedErrorWithPolicy(
                            allocator,
                            recovery.prepared,
                            .reservation_outcome_ambiguous,
                        );
                    const after_reserve = self.verifier.verifyLockFn(
                        self.verifier.context,
                        allocator,
                        recovery.prepared.paths.exact_lock,
                        loaded.view.architecture,
                        try semanticDigestForRequest(
                            allocator,
                            recovery.prepared.request,
                        ),
                    ) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.InvariantViolation => return error.InvariantViolation,
                        error.OperationalVerificationFailure => return self.reconcilePreparedError(
                            allocator,
                            recovery.prepared,
                        ),
                    };
                    if (!lockMatchesPreparation(
                        after_reserve.binding,
                        recovery.prepared,
                        current.state,
                    )) return self.reconcilePreparedError(
                        allocator,
                        recovery.prepared,
                    );
                    loaded.revalidate(allocator) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return self.reconcileUnknownPreparedFailure(
                            allocator,
                            recovery.prepared,
                            "the trusted profile changed after lower reservation",
                        ),
                    };
                }
                if (!current.state.mutation_started)
                    self.transition(
                        allocator,
                        loaded.view.state_path,
                        &current,
                        .{ .phase = .mutating },
                    ) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return self.reconcilePreparedError(
                            allocator,
                            recovery.prepared,
                        ),
                    };
                self.hitCompletionBoundary(.after_mutating_state) catch
                    return self.reconcilePreparedError(
                        allocator,
                        recovery.prepared,
                    );
                var retried = self.runner.workflow(
                    allocator,
                    self.backend,
                    .{
                        .operation = semanticOperation(
                            recovery.prepared.request.operation,
                        ),
                        .mode = .execute,
                        .selectors = selectors,
                        .options = executeOptions(
                            loaded.view,
                            recovery.prepared.paths.exact_lock,
                        ),
                        .orchestration_id = recovery.prepared.attempt_id,
                    },
                ) catch return self.recoveryFailed(
                    allocator,
                    recovery.prepared,
                    &current,
                    "proven pre-mutation attempt retry was interrupted",
                );
                defer retried.deinit();
                if (retried.result.exit_status != .success or
                    retried.root_status != .completed)
                    return self.recoveryFailed(
                        allocator,
                        recovery.prepared,
                        &current,
                        "proven pre-mutation attempt retry did not complete",
                    );
                self.hitCompletionBoundary(.after_backend_success) catch
                    return self.reconcilePreparedError(
                        allocator,
                        recovery.prepared,
                    );
                return self.verifyAndComplete(
                    allocator,
                    recovery.prepared,
                    &loaded,
                    &current,
                    false,
                    null,
                    null,
                    null,
                    null,
                    retried.ownership_acknowledgment orelse
                        return self.recoveryFailed(
                            allocator,
                            recovery.prepared,
                            &current,
                            "retried lower transaction did not retain its exact ownership token",
                        ),
                );
            }
            var reconciliation_acknowledgment: ?OwnershipAcknowledgment = null;
            if (ownership_marker == null) {
                const evidence_sha256 = if (current.state.transaction_result) |binding|
                    binding.digest_sha256
                else evidence: {
                    const shared_source = try std.fmt.allocPrint(
                        allocator,
                        "{s}/{s}",
                        .{ loaded.view.state_path, transaction_result_name },
                    );
                    defer allocator.free(shared_source);
                    var verified = self.verifier.verifyTransactionFn(
                        self.verifier.context,
                        allocator,
                        shared_source,
                        recovery_lock.binding,
                        loaded.view.architecture,
                    ) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.InvariantViolation => return error.InvariantViolation,
                        error.OperationalVerificationFailure => return self.reconcilePreparedError(
                            allocator,
                            recovery.prepared,
                        ),
                    };
                    defer verified.deinit();
                    break :evidence verified.binding.digest_sha256;
                };
                self.hitCompletionBoundary(
                    .after_clean_recovery_inspection,
                ) catch return self.reconcilePreparedError(
                    allocator,
                    recovery.prepared,
                );
                const selectors = try selectorsFor(
                    allocator,
                    recovery.prepared.request,
                );
                defer allocator.free(selectors);
                var claimed = self.runner.workflow(
                    allocator,
                    self.backend,
                    .{
                        .operation = semanticOperation(
                            recovery.prepared.request.operation,
                        ),
                        .mode = .recover,
                        .selectors = selectors,
                        .options = executeOptions(
                            loaded.view,
                            recovery.prepared.paths.exact_lock,
                        ),
                        .orchestration_id = recovery.prepared.attempt_id,
                        .reconciliation_claim = .{ .post_mutation = .{
                            .exact_lock_sha256 = recovery_lock.binding.digest_sha256,
                            .evidence_sha256 = evidence_sha256,
                        } },
                    },
                ) catch return self.recoveryFailed(
                    allocator,
                    recovery.prepared,
                    &current,
                    "clean lower root reconciliation reservation was interrupted",
                );
                defer claimed.deinit();
                if (claimed.result.exit_status != .success or
                    claimed.root_status != .completed)
                    return self.recoveryFailed(
                        allocator,
                        recovery.prepared,
                        &current,
                        "clean lower root could not be reserved for reconciliation",
                    );
                reconciliation_acknowledgment =
                    claimed.ownership_acknowledgment orelse
                    return self.recoveryFailed(
                        allocator,
                        recovery.prepared,
                        &current,
                        "clean lower root reservation returned no durable ownership token",
                    );
            }
            const retained_lower_recovery =
                if (current.state.transaction_result) |binding|
                    std.mem.eql(
                        u8,
                        binding.schema,
                        root_operation_completion.schema_id,
                    ) and std.mem.eql(
                        u8,
                        binding.path,
                        recovery.prepared.paths.recovery_completion,
                    )
                else
                    false;
            const settled_lower_recovery =
                if (lower_inspection.record) |record|
                    !finalize_ownership and
                        record.record.state == .completed and
                        record.record.provenance == .published and
                        (record.record.outcome == .succeeded or
                            record.record.outcome == .recovered)
                else
                    false;
            if (settled_lower_recovery)
                loaded.revalidate(allocator) catch
                    return self.reconcileUnknownPreparedFailure(
                        allocator,
                        recovery.prepared,
                        "trusted profile reference changed before settled recovery evidence reconciliation",
                    );
            var lower_completion = if (retained_lower_recovery)
                self.store.readRecoveryCompletionFn(
                    self.store.context,
                    allocator,
                    recovery.prepared.paths,
                    current.state.transaction_result.?,
                ) catch {
                    return self.recoveryFailed(
                        allocator,
                        recovery.prepared,
                        &current,
                        "retained lower-level recovery completion evidence is invalid",
                    );
                }
            else if (settled_lower_recovery)
                self.runner.readRecoveryCompletion(allocator) catch
                    return self.recoveryFailed(
                        allocator,
                        recovery.prepared,
                        &current,
                        "settled lower-level recovery completion evidence is unavailable",
                    )
            else
                null;
            defer if (lower_completion) |*owned| owned.deinit();
            if (settled_lower_recovery and
                (lower_completion == null or
                    !settledRecoveryProvenanceMatches(
                        lower_inspection.record.?.record,
                        lower_completion.?.document,
                    )))
                return self.recoveryFailed(
                    allocator,
                    recovery.prepared,
                    &current,
                    "settled lower-level recovery completion evidence is stale or foreign",
                );
            loaded.revalidate(allocator) catch
                return self.reconcileUnknownPreparedFailure(
                    allocator,
                    recovery.prepared,
                    "trusted profile reference changed before recovery evidence reconciliation",
                );
            return self.verifyAndComplete(
                allocator,
                recovery.prepared,
                &loaded,
                &current,
                retained_lower_recovery or settled_lower_recovery,
                if (lower_completion) |owned| owned.document else null,
                recovery_lock,
                if (lower_completion) |owned|
                    owned.document.attempt_id
                else
                    null,
                if (settled_lower_recovery)
                    acknowledgmentForSettledRecovery(
                        lower_inspection.record.?.record,
                        lower_completion.?.document,
                        recovery.prepared.attempt_id,
                    )
                else
                    marker_acknowledgment,
                if (finalize_ownership)
                    ownershipAcknowledgment(
                        ownership_marker.?,
                        recovery.prepared.attempt_id,
                    )
                else
                    reconciliation_acknowledgment,
            );
        }
        self.transition(
            allocator,
            loaded.view.state_path,
            &current,
            .{ .phase = .recovering, .diagnostic = "recovery in progress" },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(
                allocator,
                recovery.prepared,
            ),
        };
        const before_recovery = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            recovery.prepared.paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(
                allocator,
                recovery.prepared.request,
            ),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            error.OperationalVerificationFailure => return self.reconcilePreparedError(
                allocator,
                recovery.prepared,
            ),
        };
        if (!lockMatchesPreparation(
            before_recovery.binding,
            recovery.prepared,
            current.state,
        )) return self.recoveryFailed(
            allocator,
            recovery.prepared,
            &current,
            "retained exact lock was replaced immediately before recovery",
        );
        loaded.revalidate(allocator) catch
            return self.reconcileUnknownPreparedFailure(
                allocator,
                recovery.prepared,
                "trusted profile reference changed immediately before recovery execution",
            );
        const selectors = try selectorsFor(
            allocator,
            recovery.prepared.request,
        );
        defer allocator.free(selectors);
        var executed = self.runner.workflow(allocator, self.backend, .{
            .operation = semanticOperation(
                recovery.prepared.request.operation,
            ),
            .mode = .recover,
            .selectors = selectors,
            .options = executeOptions(
                loaded.view,
                recovery.prepared.paths.exact_lock,
            ),
            .defer_recovery_clear = true,
            .orchestration_id = recovery.prepared.attempt_id,
        }) catch return self.recoveryFailed(
            allocator,
            recovery.prepared,
            &current,
            "recovery execution was interrupted",
        );
        defer executed.deinit();
        if (executed.result.exit_status != .success or
            executed.root_status != .completed)
            return self.recoveryFailed(
                allocator,
                recovery.prepared,
                &current,
                if (executed.result.summary.len == 0)
                    "recovery did not prove root-operation completion"
                else
                    executed.result.summary,
            );
        self.hitCompletionBoundary(.after_backend_success) catch
            return self.reconcilePreparedError(
                allocator,
                recovery.prepared,
            );
        loaded.revalidate(allocator) catch
            return self.reconcileUnknownPreparedFailure(
                allocator,
                recovery.prepared,
                "trusted profile reference changed before recovered evidence reconciliation",
            );
        return self.verifyAndComplete(
            allocator,
            recovery.prepared,
            &loaded,
            &current,
            true,
            if (executed.recovery_completion) |owned|
                owned.document
            else
                null,
            before_recovery,
            lower_inspection.attempt_id orelse
                return self.recoveryFailed(
                    allocator,
                    recovery.prepared,
                    &current,
                    "lower-level recovery attempt identity is unavailable",
                ),
            executed.recovery_acknowledgment orelse
                return self.recoveryFailed(
                    allocator,
                    recovery.prepared,
                    &current,
                    "lower-level recovery did not return a durable acknowledgment token",
                ),
            null,
        );
    }

    fn acknowledgeCommittedLower(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        loaded: *LoadedProfile,
        committed: operation_state.State,
        acknowledgment: root_operation.DeferredAcknowledgment,
    ) !void {
        if (!std.mem.eql(
            u8,
            &acknowledgment.acknowledgment_id,
            &prepared.attempt_id,
        )) return error.LowerAcknowledgmentMismatch;
        const before_ack = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            prepared.paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(allocator, prepared.request),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            error.OperationalVerificationFailure => return error.LockEvidenceMismatch,
        };
        if (!lockMatchesPreparation(
            before_ack.binding,
            prepared,
            committed,
        )) return error.LockEvidenceMismatch;
        try loaded.revalidate(allocator);
        const selectors = try selectorsFor(allocator, prepared.request);
        defer allocator.free(selectors);
        switch (acknowledgment.state) {
            .released, .abandoned, .pre_mutation_reconciliation_claim => {
                try self.hitCompletionBoundary(.before_ownership_acknowledged);
                var finalized = try self.runner.workflow(
                    allocator,
                    self.backend,
                    .{
                        .operation = semanticOperation(
                            prepared.request.operation,
                        ),
                        .mode = .recover,
                        .selectors = selectors,
                        .options = executeOptions(
                            loaded.view,
                            prepared.paths.exact_lock,
                        ),
                        .orchestration_id = prepared.attempt_id,
                        .finalize_ownership = true,
                        .ownership_acknowledgment = .{
                            .attempt_id = acknowledgment.attempt_id,
                            .marker_sha256 = acknowledgment.digest_sha256,
                            .acknowledgment_id = acknowledgment.acknowledgment_id,
                        },
                    },
                );
                defer finalized.deinit();
                if (finalized.result.exit_status != .success or
                    finalized.root_status != .completed)
                    return error.LowerAcknowledgmentFailed;
                try self.hitCompletionBoundary(.after_ownership_acknowledged);
            },
            .pending => {
                var finalized = try self.runner.workflow(
                    allocator,
                    self.backend,
                    .{
                        .operation = semanticOperation(
                            prepared.request.operation,
                        ),
                        .mode = .recover,
                        .selectors = selectors,
                        .options = executeOptions(
                            loaded.view,
                            prepared.paths.exact_lock,
                        ),
                        .defer_recovery_clear = true,
                        .orchestration_id = prepared.attempt_id,
                        .recovery_acknowledgment = .{
                            .attempt_id = acknowledgment.attempt_id,
                            .completion_sha256 = acknowledgment.completion_sha256.?,
                            .provenance_sha256 = acknowledgment.provenance_sha256.?,
                            .acknowledgment_id = acknowledgment.acknowledgment_id,
                        },
                    },
                );
                defer finalized.deinit();
                if (finalized.result.exit_status != .success or
                    finalized.root_status != .completed)
                    return error.LowerAcknowledgmentFailed;
                try self.hitCompletionBoundary(.after_recovery_acknowledged);
            },
            else => return error.InvalidLowerAcknowledgment,
        }
    }

    fn verifyAndComplete(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        loaded: *LoadedProfile,
        current: *operation_state.OwnedState,
        recovered: bool,
        recovery_document: ?root_operation_completion.Document,
        recovery_lock: ?VerifiedLock,
        expected_recovery_attempt: ?[32]u8,
        recovery_acknowledgment: ?RecoveryAcknowledgment,
        ownership_acknowledgment: ?OwnershipAcknowledgment,
    ) InternalExecutionError!api.Result {
        const profile = loaded.view;
        var retained: api.DocumentBinding = undefined;
        if (recovered and recovery_document != null) {
            const document = recovery_document.?;
            if (!try recoveryCompletionMatches(
                allocator,
                document,
                prepared,
                profile,
                recovery_lock orelse
                    return error.MissingRecoveryLockVerification,
                expected_recovery_attempt,
            )) return self.markRecoveryRequired(
                allocator,
                prepared,
                current,
                "lower-level recovery completion does not bind the exact lock and semantic request",
            );
            self.hitCompletionBoundary(.after_transaction_verified) catch
                return self.markRecoveryRequired(
                    allocator,
                    prepared,
                    current,
                    "recovery completion verification was interrupted",
                );
            const source = try document.canonicalJson(allocator);
            defer allocator.free(source);
            retained = self.store.retainRecoveryCompletionFn(
                self.store.context,
                allocator,
                prepared.paths,
                source,
                document.digest_sha256,
            ) catch return self.markRecoveryRequired(
                allocator,
                prepared,
                current,
                "verified recovery completion evidence could not be retained",
            );
        } else {
            const existing_retained = if (current.state.transaction_result) |binding|
                std.mem.eql(
                    u8,
                    binding.schema,
                    transaction_provenance.schema_id,
                ) and
                    binding.version == transaction_provenance.schema_version and
                    std.mem.eql(
                        u8,
                        binding.path,
                        prepared.paths.transaction_result,
                    )
            else
                false;
            const shared_source = if (!existing_retained)
                try std.fmt.allocPrint(
                    allocator,
                    "{s}/{s}",
                    .{ profile.state_path, transaction_result_name },
                )
            else
                null;
            defer if (shared_source) |source| allocator.free(source);
            const source_path = if (existing_retained)
                current.state.transaction_result.?.path
            else
                shared_source.?;
            var verified = self.verifier.verifyTransactionFn(
                self.verifier.context,
                allocator,
                source_path,
                prepared.exact_lock,
                profile.architecture,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvariantViolation => return error.InvariantViolation,
                error.OperationalVerificationFailure => return self.markRecoveryRequired(
                    allocator,
                    prepared,
                    current,
                    "transaction result does not verify against the exact lock",
                ),
            };
            defer verified.deinit();
            if (existing_retained and
                (!std.mem.eql(
                    u8,
                    &verified.binding.digest_sha256,
                    &current.state.transaction_result.?.digest_sha256,
                ) or
                    !std.mem.eql(
                        u8,
                        verified.binding.path,
                        current.state.transaction_result.?.path,
                    )))
                return self.markRecoveryRequired(
                    allocator,
                    prepared,
                    current,
                    "retained transaction result binding changed before completion",
                );
            self.hitCompletionBoundary(.after_transaction_verified) catch
                return self.markRecoveryRequired(
                    allocator,
                    prepared,
                    current,
                    "transaction verification was interrupted",
                );
            retained = if (existing_retained)
                current.state.transaction_result.?
            else
                self.store.retainTransactionFn(
                    self.store.context,
                    allocator,
                    prepared.paths,
                    verified.bytes,
                    verified.binding.digest_sha256,
                ) catch return self.markRecoveryRequired(
                    allocator,
                    prepared,
                    current,
                    "verified transaction result could not be retained",
                );
        }
        self.hitCompletionBoundary(.after_transaction_retained) catch
            return self.markRecoveryRequired(
                allocator,
                prepared,
                current,
                "transaction evidence retention was interrupted",
            );
        self.transition(
            allocator,
            profile.state_path,
            current,
            .{
                .phase = if (recovered) .recovering else .verifying,
                .transaction_result = retained,
                .diagnostic = if (recovered)
                    "lower-level recovery completed"
                else
                    "",
            },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(
                allocator,
                prepared,
            ),
        };
        self.hitCompletionBoundary(.after_verifying_state) catch
            return self.reconcilePreparedError(allocator, prepared);
        const durable_acknowledgment = durableLowerAcknowledgment(
            ownership_acknowledgment,
            recovery_acknowledgment,
        ) catch return self.markRecoveryRequired(
            allocator,
            prepared,
            current,
            "lower acknowledgment token is invalid or ambiguous",
        );
        if (durable_acknowledgment) |acknowledgment|
            self.store.retainAcknowledgmentFn(
                self.store.context,
                allocator,
                prepared.paths,
                acknowledgment,
            ) catch return self.markRecoveryRequired(
                allocator,
                prepared,
                current,
                "lower acknowledgment token could not be retained",
            );
        self.hitCompletionBoundary(.after_acknowledgment_retained) catch
            return self.reconcilePreparedError(allocator, prepared);
        self.hitCompletionBoundary(.before_completion_published) catch
            return self.reconcilePreparedError(allocator, prepared);
        const completion = self.store.publishCompletionFn(
            self.store.context,
            allocator,
            prepared.paths,
            .{
                .attempt_id = prepared.attempt_id,
                .request_sha256 = prepared.request_sha256,
                .profile = prepared.profile,
                .exact_lock = prepared.exact_lock,
                .transaction_result = retained,
                .recovered = recovered,
                .completed_unix = self.clock.nowFn(self.clock.context),
            },
        ) catch return self.markRecoveryRequired(
            allocator,
            prepared,
            current,
            "verified completion evidence could not be published",
        );
        self.hitCompletionBoundary(.after_completion_published) catch
            return self.reconcilePreparedErrorWithCompletion(
                allocator,
                prepared,
                completion,
                recovered,
            );
        var final = try nextState(allocator, current.state, .{
            .phase = .completed,
            .outcome = if (recovered) .recovered else .succeeded,
            .transaction_result = retained,
            .root_operation_completion = completion,
            .diagnostic = if (recovered) "recovery completed" else "",
            .updated_unix = self.clock.nowFn(self.clock.context),
        });
        defer final.deinit();
        self.store.commitFn(
            self.store.context,
            allocator,
            prepared.paths,
            operation_state.Expected.fromState(current.state),
            final.state,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedErrorWithCompletion(
                allocator,
                prepared,
                completion,
                recovered,
            ),
        };
        self.hitCompletionBoundary(.after_outer_committed) catch
            return self.reconcilePreparedErrorWithCompletion(
                allocator,
                prepared,
                completion,
                recovered,
            );
        var durable_final = (self.store.readRetainedFn(
            self.store.context,
            allocator,
            prepared.paths,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedErrorWithCompletion(
                allocator,
                prepared,
                completion,
                recovered,
            ),
        }) orelse return self.reconcilePreparedErrorWithCompletion(
            allocator,
            prepared,
            completion,
            recovered,
        );
        defer durable_final.deinit();
        if (!finalStateEquivalent(durable_final.state, final.state))
            return self.reconcilePreparedError(allocator, prepared);
        if (durable_acknowledgment) |acknowledgment|
            self.acknowledgeCommittedLower(
                allocator,
                prepared,
                loaded,
                durable_final.state,
                acknowledgment,
            ) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                if (err == error.InvariantViolation)
                    return error.InvariantViolation;
                return self.reconcilePreparedError(allocator, prepared);
            };
        self.store.clearCommittedFn(
            self.store.context,
            allocator,
            prepared.paths,
            operation_state.Expected.fromState(durable_final.state),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            else => return self.reconcilePreparedError(allocator, prepared),
        };
        self.hitCompletionBoundary(.after_active_cleared) catch
            return completedResult(allocator, prepared, durable_final.state);
        return completedResult(allocator, prepared, durable_final.state);
    }

    fn reconcileRetainedFinal(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        loaded: *LoadedProfile,
        current: *operation_state.OwnedState,
        retained: operation_state.State,
        verified_lock: VerifiedLock,
    ) InternalExecutionError!api.Result {
        if (!retainedFinalMatchesActive(retained, current.state, prepared))
            return self.reconcilePreparedError(allocator, prepared);
        const transaction = retained.transaction_result.?;
        const completion = retained.root_operation_completion.?;
        self.store.verifyCompletionFn(
            self.store.context,
            allocator,
            prepared.paths,
            .{
                .attempt_id = prepared.attempt_id,
                .request_sha256 = prepared.request_sha256,
                .profile = prepared.profile,
                .exact_lock = prepared.exact_lock,
                .transaction_result = transaction,
                .recovered = retained.outcome == .recovered,
                .completed_unix = self.clock.nowFn(self.clock.context),
            },
            completion,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            else => return self.reconcilePreparedError(allocator, prepared),
        };
        const retained_acknowledgment = self.store.readAcknowledgmentFn(
            self.store.context,
            allocator,
            prepared.paths,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            else => return self.reconcilePreparedError(allocator, prepared),
        };
        const acknowledgment = retained_acknowledgment orelse
            return self.reconcilePreparedError(allocator, prepared);
        self.verifyRetainedFinalEvidence(
            allocator,
            prepared,
            loaded,
            retained,
            verified_lock,
            acknowledgment,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            else => return self.reconcilePreparedError(allocator, prepared),
        };
        self.store.commitFn(
            self.store.context,
            allocator,
            prepared.paths,
            operation_state.Expected.fromState(current.state),
            retained,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(allocator, prepared),
        };
        self.acknowledgeCommittedLower(
            allocator,
            prepared,
            loaded,
            retained,
            acknowledgment,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvariantViolation => return error.InvariantViolation,
            else => return self.reconcilePreparedError(allocator, prepared),
        };
        self.store.clearCommittedFn(
            self.store.context,
            allocator,
            prepared.paths,
            operation_state.Expected.fromState(retained),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(allocator, prepared),
        };
        return completedResult(
            allocator,
            prepared,
            retained,
        );
    }

    fn verifyRetainedFinalEvidence(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        loaded: *LoadedProfile,
        retained: operation_state.State,
        verified_lock: VerifiedLock,
        acknowledgment: root_operation.DeferredAcknowledgment,
    ) !void {
        if (!std.mem.eql(
            u8,
            &acknowledgment.acknowledgment_id,
            &prepared.attempt_id,
        )) return error.LowerAcknowledgmentMismatch;
        const retained_lock = retained.exact_lock orelse
            return error.InvalidRetainedEvidence;
        if (!documentEqual(verified_lock.binding, prepared.exact_lock) or
            !documentEqual(verified_lock.binding, retained_lock))
            return error.LockEvidenceMismatch;

        const binding = retained.transaction_result orelse
            return error.InvalidRetainedEvidence;
        switch (retained.outcome) {
            .succeeded => {
                if (acknowledgment.state != .released or
                    !std.mem.eql(
                        u8,
                        binding.path,
                        prepared.paths.transaction_result,
                    ) or
                    !std.mem.eql(
                        u8,
                        binding.schema,
                        transaction_provenance.schema_id,
                    ) or
                    binding.version != transaction_provenance.schema_version)
                    return error.InvalidRetainedEvidence;
                var verified = self.verifier.verifyTransactionFn(
                    self.verifier.context,
                    allocator,
                    prepared.paths.transaction_result,
                    verified_lock.binding,
                    loaded.view.architecture,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.InvariantViolation => return error.InvariantViolation,
                    error.OperationalVerificationFailure => return error.InvalidRetainedEvidence,
                };
                defer verified.deinit();
                if (!documentEqual(verified.binding, binding))
                    return error.InvalidRetainedEvidence;
            },
            .recovered => {
                if (acknowledgment.state != .pending or
                    acknowledgment.completion_sha256 == null or
                    acknowledgment.provenance_sha256 == null or
                    !std.mem.eql(
                        u8,
                        binding.path,
                        prepared.paths.recovery_completion,
                    ) or
                    !std.mem.eql(
                        u8,
                        binding.schema,
                        root_operation_completion.schema_id,
                    ) or
                    binding.version != root_operation_completion.schema_version)
                    return error.InvalidRetainedEvidence;
                var completion = try self.store.readRecoveryCompletionFn(
                    self.store.context,
                    allocator,
                    prepared.paths,
                    binding,
                );
                defer completion.deinit();
                if (!std.mem.eql(
                    u8,
                    &completion.document.digest_sha256,
                    &binding.digest_sha256,
                ) or
                    !std.mem.eql(
                        u8,
                        &completion.document.digest_sha256,
                        &acknowledgment.completion_sha256.?,
                    ) or
                    !try recoveryCompletionMatches(
                        allocator,
                        completion.document,
                        prepared,
                        loaded.view,
                        verified_lock,
                        acknowledgment.attempt_id,
                    ))
                    return error.InvalidRetainedEvidence;
                var published = try reconstructPublishedRecoveryRecord(
                    allocator,
                    completion.document,
                );
                defer published.deinit();
                if (!std.mem.eql(
                    u8,
                    &published.record.provenance_sha256.?,
                    &acknowledgment.provenance_sha256.?,
                )) return error.InvalidRetainedEvidence;
            },
            else => return error.InvalidRetainedEvidence,
        }
    }

    fn blockedByActive(
        self: *Engine,
        allocator: std.mem.Allocator,
        request: api.Request,
        profile: ProfileView,
    ) !?api.Result {
        var active = (self.store.inspectActiveLocked(
            allocator,
            profile.state_path,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return try unknownMutationDiagnostic(
                allocator,
                request,
                request.profile_path,
                "active apt/system state could not be verified",
            ),
        }) orelse return null;
        defer active.deinit();
        if (!profileEqual(active.state.profile, profile.binding))
            return try unknownMutationDiagnostic(
                allocator,
                request,
                request.profile_path,
                "active apt/system state is foreign to the trusted profile",
            );
        var paths = try pathsFor(
            allocator,
            profile.state_path,
            active.state.attempt_id,
        );
        defer paths.deinit(allocator);
        if (!active.state.mutation_started) {
            const exact_lock_binding = active.state.exact_lock orelse
                return try unknownMutationDiagnostic(
                    allocator,
                    request,
                    request.profile_path,
                    "pre-mutation active state has no exact-lock binding",
                );
            var retained_request = self.store.readRequestFn(
                self.store.context,
                allocator,
                paths,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return try unknownMutationDiagnostic(
                    allocator,
                    request,
                    request.profile_path,
                    "the active operation request could not be reopened",
                ),
            };
            defer retained_request.deinit();
            if (!std.mem.eql(
                u8,
                &(try retained_request.request.digest()),
                &active.state.request_sha256,
            ) or retained_request.request.operation != active.state.operation or
                !std.mem.eql(
                    u8,
                    retained_request.request.profile_path,
                    active.state.profile.path,
                ))
                return try unknownMutationDiagnostic(
                    allocator,
                    request,
                    request.profile_path,
                    "the active operation request is foreign to durable state",
                );
            const prepared: Preparation = .{
                .request = retained_request.request,
                .request_sha256 = active.state.request_sha256,
                .profile = active.state.profile,
                .profile_state_path = profile.state_path,
                .attempt_id = active.state.attempt_id,
                .active_generation = active.state.generation,
                .active_digest_sha256 = active.state.digest_sha256,
                .paths = paths,
                .exact_lock = exact_lock_binding,
                .review = &.{},
                .arena = undefined,
                .backing_allocator = allocator,
            };
            var reconciled = try self.reconcileStablePreMutation(
                allocator,
                prepared,
                active.state,
                .clean_proves_pre_mutation,
            );
            if (reconciled.exit_status == .configuration and
                !reconciled.changed and
                reconciled.mutation_status == null)
            {
                reconciled.deinit();
                return null;
            }
            return reconciled;
        }
        return try unknownMutationDiagnostic(
            allocator,
            request,
            request.profile_path,
            "a mutating active operation blocks the requested operation",
        );
    }

    fn transition(
        self: *Engine,
        allocator: std.mem.Allocator,
        state_path: []const u8,
        current: *operation_state.OwnedState,
        change: StateChange,
    ) !void {
        var next = try nextState(allocator, current.state, .{
            .phase = change.phase,
            .exact_lock = change.exact_lock,
            .transaction_result = change.transaction_result,
            .root_operation_completion = change.root_operation_completion,
            .outcome = change.outcome,
            .diagnostic = change.diagnostic,
            .updated_unix = self.clock.nowFn(self.clock.context),
        });
        errdefer next.deinit();
        try self.store.compareAndSetFn(
            self.store.context,
            allocator,
            state_path,
            operation_state.Expected.fromState(current.state),
            next.state,
        );
        current.deinit();
        current.* = next;
    }

    fn failBeforeMutation(
        self: *Engine,
        allocator: std.mem.Allocator,
        request: api.Request,
        state_path: []const u8,
        paths: OperationPaths,
        current: *operation_state.OwnedState,
        outcome: api.Outcome,
        diagnostic: api.DiagnosticId,
        message: []const u8,
    ) !api.Result {
        var final = try nextState(allocator, current.state, .{
            .phase = .completed,
            .outcome = .failed_before_mutation,
            .diagnostic = message,
            .updated_unix = self.clock.nowFn(self.clock.context),
        });
        defer final.deinit();
        self.store.finishFn(
            self.store.context,
            allocator,
            paths,
            operation_state.Expected.fromState(current.state),
            final.state,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return unknownMutationDiagnostic(
                allocator,
                request,
                request.profile_path,
                "pre-mutation failure could not be retained with stable outer and lower state proof",
            ),
        };
        _ = state_path;
        return ownedFailure(
            allocator,
            request,
            outcome,
            diagnostic,
            "prepare",
            message,
        );
    }

    fn finishPreMutationFailure(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        current: *operation_state.OwnedState,
        outcome: api.Outcome,
        diagnostic: api.DiagnosticId,
        message: []const u8,
    ) InternalExecutionError!api.Result {
        var final = try nextState(allocator, current.state, .{
            .phase = .completed,
            .outcome = .failed_before_mutation,
            .diagnostic = message,
            .updated_unix = self.clock.nowFn(self.clock.context),
        });
        defer final.deinit();
        self.store.finishFn(
            self.store.context,
            allocator,
            prepared.paths,
            operation_state.Expected.fromState(current.state),
            final.state,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidInitialState => return error.InvalidInitialState,
            error.InvalidTransition => return error.InvalidTransition,
            error.InvalidGeneration => return error.InvalidGeneration,
            error.InvalidTimestamp => return error.InvalidTimestamp,
            error.AttemptMismatch => return error.AttemptMismatch,
            error.MutationEvidenceRollback => return error.MutationEvidenceRollback,
            error.EvidenceRollback => return error.EvidenceRollback,
            else => return self.reconcilePreparedError(
                allocator,
                prepared,
            ),
        };
        return ownedFailure(
            allocator,
            prepared.request,
            outcome,
            diagnostic,
            "execution",
            message,
        );
    }

    fn markRecoveryRequired(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        current: *operation_state.OwnedState,
        message: []const u8,
    ) InternalExecutionError!api.Result {
        if (current.state.phase != .recovery_required) {
            self.transition(
                allocator,
                prepared.profile_state_path,
                current,
                .{
                    .phase = .recovery_required,
                    .diagnostic = message,
                },
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return self.reconcilePreparedError(
                    allocator,
                    prepared,
                ),
            };
        }
        return self.reconcilePreparedError(allocator, prepared);
    }

    fn recoveryFailed(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        current: *operation_state.OwnedState,
        message: []const u8,
    ) InternalExecutionError!api.Result {
        self.transition(
            allocator,
            prepared.profile_state_path,
            current,
            .{
                .phase = .recovery_required,
                .diagnostic = message,
            },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.reconcilePreparedError(
                allocator,
                prepared,
            ),
        };
        return self.reconcilePreparedError(allocator, prepared);
    }

    fn hitCompletionBoundary(
        self: *Engine,
        boundary: CompletionBoundary,
    ) !void {
        if (self.completion_crash) |crash| try crash.hit(boundary);
    }
};

pub const SystemSources = struct {
    io: std.Io,

    pub fn ids(self: *SystemSources) IdSource {
        return .{ .context = self, .nextFn = next };
    }

    pub fn clock(self: *SystemSources) Clock {
        return .{ .context = self, .nowFn = now };
    }

    fn next(context: *anyopaque) ![32]u8 {
        const self: *SystemSources = @ptrCast(@alignCast(context));
        var value: [32]u8 = undefined;
        try std.Io.randomSecure(self.io, &value);
        return value;
    }

    fn now(context: *anyopaque) i64 {
        const self: *SystemSources = @ptrCast(@alignCast(context));
        const instant = std.Io.Clock.real.now(self.io);
        return @intCast(@divFloor(instant.nanoseconds, std.time.ns_per_s));
    }
};

/// Owns the concrete production adapters and wires an Engine whose only live
/// root access is `PrivateLiveRootRunner`.
pub const ProductionComposition = struct {
    profile_loader: SystemProfileLoader = undefined,
    backend: ProductionBackend = undefined,
    runner: PrivateLiveRootRunner = undefined,
    store: SystemStateStore = undefined,
    verifier: SystemResultVerifier = undefined,
    sources: SystemSources = undefined,
    engine: Engine = undefined,

    pub fn init(
        self: *ProductionComposition,
        allocator: std.mem.Allocator,
        io: std.Io,
        backend: *production_backend.Backend,
    ) void {
        self.profile_loader = .{ .io = io };
        self.backend = .{ .backend = backend };
        self.runner = .{ .io = io };
        self.store = .{ .allocator = allocator, .io = io };
        self.verifier = .{ .io = io };
        self.sources = .{ .io = io };
        self.engine = .{
            .profiles = self.profile_loader.interface(),
            .runner = self.runner.interface(),
            .backend = self.backend.interface(),
            .store = self.store.interface(),
            .verifier = self.verifier.interface(),
            .ids = self.sources.ids(),
            .clock = self.sources.clock(),
        };
    }

    pub fn orchestrator(self: *ProductionComposition) *Engine {
        return &self.engine;
    }
};

const StateChange = struct {
    phase: operation_state.Phase,
    exact_lock: ?api.DocumentBinding = null,
    transaction_result: ?api.DocumentBinding = null,
    root_operation_completion: ?api.CompletionBinding = null,
    outcome: operation_state.Outcome = .pending,
    diagnostic: []const u8 = "",
};

fn nextState(
    allocator: std.mem.Allocator,
    current: operation_state.State,
    change: struct {
        phase: operation_state.Phase,
        exact_lock: ?api.DocumentBinding = null,
        transaction_result: ?api.DocumentBinding = null,
        root_operation_completion: ?api.CompletionBinding = null,
        outcome: operation_state.Outcome = .pending,
        diagnostic: []const u8 = "",
        updated_unix: i64,
    },
) !operation_state.OwnedState {
    return operation_state.create(allocator, .{
        .attempt_id = current.attempt_id,
        .generation = current.generation + 1,
        .operation = current.operation,
        .phase = change.phase,
        .mutation_started = switch (change.phase) {
            .mutating,
            .verifying,
            .recovery_required,
            .recovering,
            => true,
            .completed => current.mutation_started,
            else => false,
        },
        .outcome = change.outcome,
        .request_sha256 = current.request_sha256,
        .profile = current.profile,
        .exact_lock = change.exact_lock orelse current.exact_lock,
        .transaction_result = change.transaction_result orelse current.transaction_result,
        .root_operation_completion = change.root_operation_completion orelse
            current.root_operation_completion,
        .updated_unix = change.updated_unix,
        .diagnostic = change.diagnostic,
    });
}

fn commonOptions(
    profile: ProfileView,
    lock_input: ?[]const u8,
    lock_output: ?[]const u8,
) product_api.CommonOptions {
    return .{
        .install_root = live_root.logical_root_path,
        .source_paths = profile.source_paths,
        .config_paths = profile.config_paths,
        .keyring_paths = profile.keyring_paths,
        .cache_path = profile.cache_path,
        .state_path = profile.state_path,
        .architecture = profile.architecture,
        .foreign_architectures = profile.foreign_architectures,
        .repository_policy = profile.repository_policy,
        .proxy = profile.proxy,
        .credential_reference = profile.credential_reference,
        .lock_input_path = lock_input,
        .lock_output_path = lock_output,
        .assume_yes = true,
        .noninteractive = true,
        .conffile = profile.conffile,
    };
}

fn executeOptions(
    profile: ProfileView,
    lock_input: []const u8,
) product_api.CommonOptions {
    var options = commonOptions(profile, lock_input, null);
    options.offline = true;
    options.cache_only = true;
    return options;
}

fn semanticOperation(operation: api.Operation) WorkflowOperation {
    return switch (operation) {
        .install => .install,
        .remove => .remove,
        .upgrade => .upgrade_all,
        else => unreachable,
    };
}

fn workflowSemanticDigest(
    allocator: std.mem.Allocator,
    operation: WorkflowOperation,
    selectors: []const solver.PackageSelector,
) ![32]u8 {
    return production_backend.workflowSemanticRequestDigest(
        allocator,
        switch (operation) {
            .install => .install,
            .remove => .remove,
            .upgrade_all => .upgrade_all,
        },
        selectors,
    );
}

fn semanticDigestForRequest(
    allocator: std.mem.Allocator,
    request: api.Request,
) ![32]u8 {
    const selectors = try selectorsFor(allocator, request);
    defer allocator.free(selectors);
    return workflowSemanticDigest(
        allocator,
        semanticOperation(request.operation),
        selectors,
    );
}

fn executionInvocationFailure(
    err: InternalExecutionError,
) ExecutionError!ExecutionInvocation {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.UnconfirmedExecution,
        error.UnsupportedApiVersion,
        error.InvalidProfilePath,
        error.InvalidPackageCount,
        error.InvalidPackage,
        error.DuplicatePackage,
        error.InvalidOperation,
        error.UnsafeInstallRoot,
        error.ArchitectureMismatch,
        error.BackendOperationMismatch,
        error.InvalidPath,
        error.UnsupportedPlatform,
        => error.ContractViolation,
        error.InvalidInitialState,
        error.InvalidTransition,
        error.InvalidGeneration,
        error.InvalidTimestamp,
        error.AttemptMismatch,
        error.MutationEvidenceRollback,
        error.EvidenceRollback,
        error.UnexpectedItems,
        error.InvalidRecoveryContext,
        error.InvalidSummary,
        error.TooManyItems,
        error.InvalidMutationStatus,
        error.InvalidItem,
        error.TooManyDiagnostics,
        error.InvalidExitStatus,
        error.InvalidProfileBinding,
        error.InvalidEvidencePath,
        error.InvalidEvidenceSchema,
        error.UnexpectedTransactionEvidence,
        error.InvalidDiagnostic,
        error.PartialSuccess,
        error.MissingCompletionEvidence,
        error.MissingDiagnostic,
        error.DocumentTooLarge,
        error.InvalidSelector,
        error.InvalidProfile,
        error.InvalidEvidence,
        error.InvalidCompletionEvidence,
        error.InvalidOutcome,
        error.InvalidMutationState,
        error.MissingExactLock,
        error.UnexpectedExactLock,
        error.MissingTransactionResult,
        error.UnexpectedTransactionResult,
        error.UnexpectedCompletionEvidence,
        error.MissingRecoveryLockVerification,
        error.InvariantViolation,
        => error.InvariantViolation,
    };
}

fn selectorsFor(
    allocator: std.mem.Allocator,
    request: api.Request,
) ![]solver.PackageSelector {
    const selectors = try allocator.alloc(
        solver.PackageSelector,
        request.packages.len,
    );
    for (request.packages, 0..) |package, index| {
        const equals = std.mem.indexOfScalar(u8, package, '=');
        const identity = if (equals) |at| package[0..at] else package;
        const colon = std.mem.indexOfScalar(u8, identity, ':');
        selectors[index] = .{
            .name = if (colon) |at| identity[0..at] else identity,
            .architecture = if (colon) |at| identity[at + 1 ..] else null,
            .version = if (equals) |at| package[at + 1 ..] else null,
        };
    }
    return selectors;
}

fn mapProductResult(
    allocator: std.mem.Allocator,
    request: api.Request,
    profile: api.ProfileBinding,
    result: product_api.Result,
    evidence: api.Evidence,
) !api.Result {
    if (result.exit_status != .success)
        return ownedFailure(
            allocator,
            request,
            mapOutcome(result.exit_status),
            mapDiagnostic(result.exit_status),
            "backend",
            result.summary,
        );
    if (request.operation != .list_installed and
        request.operation != .update and
        result.items.len != 0)
        return error.UnexpectedItems;
    var items: []api.Item = &.{};
    if (request.operation == .list_installed)
        items = try allocator.alloc(api.Item, result.items.len);
    defer if (items.len != 0) allocator.free(items);
    if (request.operation == .list_installed) {
        for (result.items, 0..) |item, index| {
            items[index] = .{
                .package = item.package,
                .version = item.version,
                .architecture = item.architecture,
                .detail = item.detail,
            };
        }
    }

    var mapped: api.Result = .{
        .operation = request.operation,
        .request_sha256 = try request.digest(),
        .profile = profile,
        .outcome = .success,
        .exit_status = .success,
        .changed = result.changed,
        .summary = result.summary,
        .items = items,
        .evidence = evidence,
    };
    mapped = try api.complete(mapped);
    return api.ownResult(allocator, mapped);
}

fn ownedFailure(
    allocator: std.mem.Allocator,
    request: api.Request,
    outcome: api.Outcome,
    id: api.DiagnosticId,
    phase: []const u8,
    message: []const u8,
) !api.Result {
    return api.ownResult(
        allocator,
        try api.failure(request, outcome, id, phase, message),
    );
}

fn mapOutcome(status: product_api.ExitStatus) api.Outcome {
    return switch (status) {
        .success => .success,
        .usage => .usage,
        .unavailable => .configuration,
        .authentication => .authentication,
        .planning => .planning,
        .download => .download,
        .transaction => .transaction,
        .recovery => .recovery,
        .internal => .internal,
    };
}

fn mapDiagnostic(status: product_api.ExitStatus) api.DiagnosticId {
    return switch (status) {
        .success => .internal_error,
        .usage => .invalid_request,
        .unavailable => .profile_invalid,
        .authentication => .repository_authentication_failed,
        .planning => .planning_failed,
        .download => .download_failed,
        .transaction => .transaction_failed,
        .recovery => .recovery_required,
        .internal => .internal_error,
    };
}

fn profileFailure(request: api.Request) !api.Result {
    return api.failure(
        request,
        .configuration,
        .profile_invalid,
        "profile",
        "explicit trusted system profile could not be loaded",
    );
}

fn liveRootFailure(request: api.Request, err: anyerror) !api.Result {
    return api.failure(
        request,
        if (isRootIdentityError(err)) .configuration else .internal,
        if (isRootIdentityError(err))
            .root_operation_conflict
        else
            .internal_error,
        "live-root",
        if (isRootIdentityError(err))
            "private live-root identity changed"
        else
            "private live-root execution failed",
    );
}

fn isRootIdentityError(err: anyerror) bool {
    return err == error.RootReplaced or
        err == error.RuntimeReplaced or
        err == error.LockReplaced or
        err == error.MountpointReplaced or
        err == error.ActiveHostMount;
}

fn recoveryDiagnostic(
    allocator: std.mem.Allocator,
    request: api.Request,
    profile: api.ProfileBinding,
    lock: ?api.DocumentBinding,
    transaction: ?api.DocumentBinding,
    completion: ?api.CompletionBinding,
    mutation_started: bool,
    state_path: []const u8,
) !api.Result {
    const recovery_message = if (mutation_started)
        try std.fmt.allocPrint(
            allocator,
            "recovery required; run debz recover --system-profile {s}",
            .{profile.path},
        )
    else
        null;
    defer if (recovery_message) |message| allocator.free(message);
    const message = recovery_message orelse
        "an unresolved apt/system operation blocks this request";
    const active_path = try std.fmt.allocPrint(
        allocator,
        "{s}/apt/{s}",
        .{ state_path, operation_state.document_name },
    );
    defer allocator.free(active_path);
    var result = try api.failure(
        request,
        .recovery,
        if (mutation_started) .recovery_required else .root_operation_conflict,
        "recovery",
        message,
    );
    result.profile = profile;
    result.changed = mutation_started;
    result.evidence = .{
        .exact_lock = lock,
        .transaction_result = transaction,
        .root_operation_completion = completion,
        .active_operation_state = active_path,
    };
    result = try api.complete(result);
    return api.ownResult(allocator, result);
}

fn lowerMutationDiagnostic(
    allocator: std.mem.Allocator,
    request: api.Request,
    profile_path: []const u8,
) !api.Result {
    const message = try std.fmt.allocPrint(
        allocator,
        "recovery required; a matching durable lower operation proves mutation occurred; run debz recover --system-profile {s}",
        .{profile_path},
    );
    defer allocator.free(message);
    var result = try api.failure(
        request,
        .recovery,
        .recovery_required,
        "recovery",
        message,
    );
    result.changed = true;
    result = try api.complete(result);
    return api.ownResult(allocator, result);
}

fn unknownMutationDiagnostic(
    allocator: std.mem.Allocator,
    request: ?api.Request,
    profile_path: []const u8,
    reason: []const u8,
) !api.Result {
    const message = try std.fmt.allocPrint(
        allocator,
        "mutation status unknown; fail closed because {s}; inspect and restore durable apt/system state and trusted profile evidence before retrying recovery",
        .{reason},
    );
    defer allocator.free(message);
    const context: api.RecoveryContext = .{
        .profile_path = profile_path,
        .requested_operation = if (request) |value|
            value.operation
        else
            null,
    };
    var result: api.Result = .{
        .operation = .recover,
        .request_sha256 = try api.recoveryRequestDigest(context),
        .outcome = .recovery,
        .exit_status = .recovery,
        .summary = message,
        .recovery_context = context,
        .diagnostics = undefined,
    };
    result.diagnostics[0] = .{
        .id = .recovery_required,
        .outcome = .recovery,
        .phase = "recovery",
        .message = message,
    };
    result.diagnostic_count = 1;
    result.mutation_status = .unknown;
    result = try api.complete(result);
    return api.ownResult(allocator, result);
}

fn failedBeforeMutationDiagnostic(
    allocator: std.mem.Allocator,
    request: api.Request,
    profile: api.ProfileBinding,
    state_path: []const u8,
) !api.Result {
    const active_path = try std.fmt.allocPrint(
        allocator,
        "{s}/apt/{s}",
        .{ state_path, operation_state.document_name },
    );
    defer allocator.free(active_path);
    var result = try api.failure(
        request,
        .internal,
        .internal_error,
        "execution",
        "execution failed before mutation; durable outer state and lower root state prove no package change occurred",
    );
    result.profile = profile;
    result.evidence.active_operation_state = active_path;
    result = try api.complete(result);
    return api.ownResult(allocator, result);
}

fn profileMatchesPath(
    binding: api.ProfileBinding,
    path: []const u8,
) bool {
    return std.mem.eql(u8, binding.path, path);
}

fn profileEqual(
    left: api.ProfileBinding,
    right: api.ProfileBinding,
) bool {
    return std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, &left.sha256, &right.sha256) and
        std.mem.eql(
            u8,
            &left.reference_evidence_sha256,
            &right.reference_evidence_sha256,
        );
}

fn documentEqual(
    left: api.DocumentBinding,
    right: api.DocumentBinding,
) bool {
    return std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.schema, right.schema) and
        left.version == right.version and
        std.mem.eql(u8, &left.digest_sha256, &right.digest_sha256);
}

fn completionEqual(
    left: api.CompletionBinding,
    right: api.CompletionBinding,
) bool {
    return documentEqual(left.document, right.document) and
        std.mem.eql(
            u8,
            &left.completed_attempt_id,
            &right.completed_attempt_id,
        );
}

fn finalStateEquivalent(
    retained: operation_state.State,
    proposed: operation_state.State,
) bool {
    operation_state.validate(retained) catch return false;
    operation_state.validate(proposed) catch return false;
    if (retained.phase != .completed or proposed.phase != .completed or
        retained.operation != proposed.operation or
        retained.mutation_started != proposed.mutation_started or
        retained.outcome != proposed.outcome or
        !std.mem.eql(u8, &retained.attempt_id, &proposed.attempt_id) or
        !std.mem.eql(
            u8,
            &retained.request_sha256,
            &proposed.request_sha256,
        ) or
        !profileEqual(retained.profile, proposed.profile))
        return false;
    return switch (retained.outcome) {
        .pending => false,
        .failed_before_mutation => failedBeforeEvidenceEqual(
            retained,
            proposed,
        ),
        .failed_after_mutation => retained.operation.mutatesRoot() and
            requiredDocumentEqual(retained.exact_lock, proposed.exact_lock) and
            requiredDocumentEqual(
                retained.transaction_result,
                proposed.transaction_result,
            ) and
            retained.root_operation_completion == null and
            proposed.root_operation_completion == null,
        .succeeded => if (retained.operation.mutatesRoot())
            requiredDocumentEqual(retained.exact_lock, proposed.exact_lock) and
                requiredDocumentEqual(
                    retained.transaction_result,
                    proposed.transaction_result,
                ) and
                requiredCompletionEqual(
                    retained.root_operation_completion,
                    proposed.root_operation_completion,
                )
        else
            retained.exact_lock == null and proposed.exact_lock == null and
                retained.transaction_result == null and
                proposed.transaction_result == null and
                retained.root_operation_completion == null and
                proposed.root_operation_completion == null,
        .recovered => retained.operation.mutatesRoot() and
            requiredDocumentEqual(retained.exact_lock, proposed.exact_lock) and
            requiredDocumentEqual(
                retained.transaction_result,
                proposed.transaction_result,
            ) and
            requiredCompletionEqual(
                retained.root_operation_completion,
                proposed.root_operation_completion,
            ),
    };
}

fn failedBeforeEvidenceEqual(
    retained: operation_state.State,
    proposed: operation_state.State,
) bool {
    if (retained.mutation_started or proposed.mutation_started or
        retained.transaction_result != null or
        proposed.transaction_result != null or
        retained.root_operation_completion != null or
        proposed.root_operation_completion != null)
        return false;
    if (!retained.operation.mutatesRoot())
        return retained.exact_lock == null and proposed.exact_lock == null;
    if (retained.exact_lock == null or proposed.exact_lock == null)
        return retained.exact_lock == null and proposed.exact_lock == null;
    return documentEqual(retained.exact_lock.?, proposed.exact_lock.?);
}

fn requiredDocumentEqual(
    left: ?api.DocumentBinding,
    right: ?api.DocumentBinding,
) bool {
    return left != null and right != null and documentEqual(left.?, right.?);
}

fn requiredCompletionEqual(
    left: ?api.CompletionBinding,
    right: ?api.CompletionBinding,
) bool {
    return left != null and right != null and completionEqual(left.?, right.?);
}

fn recoverableOuterPhase(phase: operation_state.Phase) bool {
    return switch (phase) {
        .planned,
        .downloaded,
        .mutating,
        .verifying,
        .recovery_required,
        .recovering,
        .completed,
        => true,
        else => false,
    };
}

fn retainedFinalMatchesActive(
    retained: operation_state.State,
    active: operation_state.State,
    prepared: Preparation,
) bool {
    operation_state.validate(retained) catch return false;
    operation_state.validate(active) catch return false;
    if (retained.phase != .completed or
        !stateMatchesPreparation(retained, prepared))
        return false;
    switch (retained.outcome) {
        .pending => return false,
        .failed_before_mutation => {
            if (retained.mutation_started or
                retained.transaction_result != null or
                retained.root_operation_completion != null or
                retained.exact_lock == null or
                !documentEqual(retained.exact_lock.?, prepared.exact_lock))
                return false;
        },
        .failed_after_mutation => {
            if (!retained.mutation_started or
                retained.transaction_result == null or
                retained.root_operation_completion != null)
                return false;
        },
        .succeeded, .recovered => {
            if (!retained.mutation_started or
                retained.transaction_result == null or
                retained.root_operation_completion == null)
                return false;
        },
    }
    if (active.transaction_result) |transaction|
        if (retained.transaction_result == null or
            !documentEqual(transaction, retained.transaction_result.?))
            return false;
    if (active.root_operation_completion) |completion|
        if (retained.root_operation_completion == null or
            !completionEqual(
                completion,
                retained.root_operation_completion.?,
            ))
            return false;
    if (retained.phase == active.phase and
        retained.generation == active.generation and
        std.mem.eql(
            u8,
            &retained.digest_sha256,
            &active.digest_sha256,
        ))
        return true;
    operation_state.validateTransition(active, retained) catch return false;
    return true;
}

fn completedResult(
    allocator: std.mem.Allocator,
    prepared: Preparation,
    final: operation_state.State,
) !api.Result {
    const recovered = final.outcome == .recovered;
    var result: api.Result = .{
        .operation = prepared.request.operation,
        .request_sha256 = prepared.request_sha256,
        .profile = prepared.profile,
        .outcome = .success,
        .exit_status = .success,
        .changed = true,
        .summary = if (recovered)
            "transaction recovered and verified"
        else
            "transaction completed and verified",
        .evidence = .{
            .exact_lock = final.exact_lock,
            .transaction_result = final.transaction_result,
            .root_operation_completion = final.root_operation_completion,
            .active_operation_state = prepared.paths.retained_state,
        },
    };
    result = try api.complete(result);
    return api.ownResult(allocator, result);
}

fn stateMatchesPreparation(
    state: operation_state.State,
    prepared: Preparation,
) bool {
    const generation_matches =
        prepared.active_generation == 0 or
        state.generation > prepared.active_generation or
        (state.generation == prepared.active_generation and
            std.mem.eql(
                u8,
                &state.digest_sha256,
                &prepared.active_digest_sha256,
            ));
    return generation_matches and
        std.mem.eql(u8, &state.attempt_id, &prepared.attempt_id) and
        state.operation == prepared.request.operation and
        std.mem.eql(u8, &state.request_sha256, &prepared.request_sha256) and
        profileEqual(state.profile, prepared.profile) and
        state.exact_lock != null and
        documentEqual(state.exact_lock.?, prepared.exact_lock);
}

fn lockMatchesPreparation(
    observed: api.DocumentBinding,
    prepared: Preparation,
    state: operation_state.State,
) bool {
    return std.mem.eql(u8, observed.path, prepared.paths.exact_lock) and
        documentEqual(observed, prepared.exact_lock) and
        state.exact_lock != null and
        documentEqual(observed, state.exact_lock.?);
}

fn recoveryCompletionMatches(
    allocator: std.mem.Allocator,
    document: root_operation_completion.Document,
    prepared: Preparation,
    profile: ProfileView,
    verified_lock: VerifiedLock,
    expected_attempt_id: ?[32]u8,
) !bool {
    if (expected_attempt_id) |attempt_id|
        if (!std.mem.eql(u8, &document.attempt_id, &attempt_id))
            return false;
    const lock = document.exact_lock orelse return false;
    const expected_operation: product_api.Operation = switch (prepared.request.operation) {
        .install => .install,
        .remove => .remove,
        .upgrade => .upgrade_all,
        else => return false,
    };
    const workflow_operation: production_backend.WorkflowSemanticOperation = switch (prepared.request.operation) {
        .install => .install,
        .remove => .remove,
        .upgrade => .upgrade_all,
        else => return false,
    };
    const selectors = try selectorsFor(allocator, prepared.request);
    defer allocator.free(selectors);
    const semantic_request_sha256 = try production_backend.workflowSemanticRequestDigest(
        allocator,
        workflow_operation,
        selectors,
    );
    const options = executeOptions(profile, prepared.paths.exact_lock);
    const original_request_sha256 = try production_backend.workflowProductRequestDigest(
        allocator,
        workflow_operation,
        .execute,
        selectors,
        options,
    );
    const recovery_request_sha256 = try production_backend.workflowProductRequestDigest(
        allocator,
        workflow_operation,
        .recover,
        selectors,
        options,
    );
    const operation_matches = switch (document.operation) {
        .package_transaction => |operation| operation == expected_operation,
        .repository_bootstrap => false,
    };
    return operation_matches and
        document.mutation_started and
        (document.outcome == .succeeded or document.outcome == .recovered) and
        std.mem.eql(
            u8,
            &verified_lock.semantic_request_sha256,
            &semantic_request_sha256,
        ) and
        std.mem.eql(
            u8,
            &document.request_sha256,
            &original_request_sha256,
        ) and
        std.mem.eql(
            u8,
            &document.discharge.request_sha256,
            &recovery_request_sha256,
        ) and
        std.mem.eql(u8, document.install_root, live_root.logical_root_path) and
        std.mem.eql(u8, document.target_architecture, profile.architecture) and
        std.mem.eql(u8, lock.schema, prepared.exact_lock.schema) and
        lock.version == prepared.exact_lock.version and
        std.mem.eql(
            u8,
            &lock.digest_sha256,
            &prepared.exact_lock.digest_sha256,
        ) and
        document.discharge.surface == .package_transaction and
        std.mem.eql(u8, document.discharge.operation, "recover");
}

fn preMutationReconciliationClaimMatches(
    marker: root_operation.DeferredAcknowledgment,
    prepared: Preparation,
    snapshot: operation_state.State,
    verified_lock: VerifiedLock,
) bool {
    const claim = marker.pre_mutation_claim orelse return false;
    const marker_match = root_operation.matchesPreMutationReconciliationClaim(
        marker,
        claim,
    );
    const attempt_match = std.mem.eql(
        u8,
        &claim.outer_attempt_id,
        &prepared.attempt_id,
    );
    const profile_match = std.mem.eql(
        u8,
        &claim.profile_sha256,
        &snapshot.profile.sha256,
    );
    const reference_match = std.mem.eql(
        u8,
        &claim.profile_reference_sha256,
        &snapshot.profile.reference_evidence_sha256,
    );
    const lock_match = std.mem.eql(
        u8,
        &claim.exact_lock_sha256,
        &verified_lock.binding.digest_sha256,
    );
    const semantic_match = std.mem.eql(
        u8,
        &claim.semantic_request_sha256,
        &verified_lock.semantic_request_sha256,
    );
    if (!marker_match or !attempt_match or !profile_match or
        !reference_match or !lock_match or !semantic_match)
        return false;
    if (snapshot.generation == claim.outer_generation and
        std.mem.eql(
            u8,
            &snapshot.digest_sha256,
            &claim.outer_state_sha256,
        ))
        return true;
    const committed_generation = std.math.add(
        u64,
        claim.outer_generation,
        1,
    ) catch return false;
    return snapshot.generation == committed_generation and
        snapshot.phase == .completed and
        snapshot.outcome == .failed_before_mutation and
        !snapshot.mutation_started and
        snapshot.transaction_result == null and
        snapshot.root_operation_completion == null;
}

fn lowerAbandonedPreMutationMatches(
    allocator: std.mem.Allocator,
    record: root_operation.Record,
    marker: root_operation.DeferredAcknowledgment,
    prepared: Preparation,
    profile: ProfileView,
    verified_lock: VerifiedLock,
) !bool {
    if (root_operation.deferredRecordCompatibility(
        record,
        marker,
        false,
    ) != .abandoned_pre_mutation or
        !std.mem.eql(
            u8,
            &marker.acknowledgment_id,
            &prepared.attempt_id,
        ) or
        !std.mem.eql(u8, &marker.attempt_id, &record.attempt_id) or
        record.state != .completed or
        record.mutation_started or
        record.outcome != .abandoned_before_mutation or
        record.provenance != .not_required or
        !std.mem.eql(u8, record.install_root, live_root.logical_root_path) or
        !std.mem.eql(u8, record.target_architecture, profile.architecture))
        return false;
    const expected_operation: product_api.Operation = switch (prepared.request.operation) {
        .install => .install,
        .remove => .remove,
        .upgrade => .upgrade_all,
        else => return false,
    };
    const workflow_operation: production_backend.WorkflowSemanticOperation = switch (prepared.request.operation) {
        .install => .install,
        .remove => .remove,
        .upgrade => .upgrade_all,
        else => return false,
    };
    const operation_matches = switch (record.operation) {
        .package_transaction => |operation| operation == expected_operation,
        .repository_bootstrap => false,
    };
    if (!operation_matches) return false;
    const lock = record.exact_lock orelse return false;
    if (!std.mem.eql(u8, lock.schema, verified_lock.binding.schema) or
        lock.version != verified_lock.binding.version or
        !std.mem.eql(
            u8,
            &lock.digest_sha256,
            &verified_lock.binding.digest_sha256,
        ))
        return false;
    const selectors = try selectorsFor(allocator, prepared.request);
    defer allocator.free(selectors);
    const expected_request = try production_backend.workflowProductRequestDigest(
        allocator,
        workflow_operation,
        .execute,
        selectors,
        executeOptions(profile, prepared.paths.exact_lock),
    );
    return std.mem.eql(
        u8,
        &record.request_sha256,
        &expected_request,
    );
}

fn lowerMutationMatches(
    allocator: std.mem.Allocator,
    record: root_operation.Record,
    marker: root_operation.DeferredAcknowledgment,
    prepared: Preparation,
    profile: ProfileView,
    verified_lock: VerifiedLock,
    completion: ?root_operation_completion.Document,
) !bool {
    const compatibility = root_operation.deferredRecordCompatibility(
        record,
        marker,
        false,
    );
    const protocol_proves_mutation = switch (compatibility) {
        .bound_mutating => true,
        .released_completed => std.mem.eql(
            u8,
            &record.provenance_sha256.?,
            &root_operation.provenanceDigest(record, .{
                .outcome = record.outcome,
                .journal_archived = true,
            }),
        ),
        .pending_published, .acknowledged_published => proof: {
            const document = completion orelse break :proof false;
            if (marker.completion_sha256 == null or
                !std.mem.eql(
                    u8,
                    &marker.completion_sha256.?,
                    &document.digest_sha256,
                ) or
                !settledRecoveryProvenanceMatches(record, document) or
                !try recoveryCompletionMatches(
                    allocator,
                    document,
                    prepared,
                    profile,
                    verified_lock,
                    marker.attempt_id,
                ))
                break :proof false;
            break :proof true;
        },
        else => false,
    };
    if (!protocol_proves_mutation or
        !std.mem.eql(
            u8,
            &marker.acknowledgment_id,
            &prepared.attempt_id,
        ) or
        !std.mem.eql(u8, &marker.attempt_id, &record.attempt_id) or
        !record.mutation_started or
        !std.mem.eql(u8, record.install_root, live_root.logical_root_path) or
        !std.mem.eql(u8, record.target_architecture, profile.architecture))
        return false;
    const expected_operation: product_api.Operation = switch (prepared.request.operation) {
        .install => .install,
        .remove => .remove,
        .upgrade => .upgrade_all,
        else => return false,
    };
    const workflow_operation: production_backend.WorkflowSemanticOperation = switch (prepared.request.operation) {
        .install => .install,
        .remove => .remove,
        .upgrade => .upgrade_all,
        else => return false,
    };
    switch (record.operation) {
        .package_transaction => |operation| {
            if (operation != expected_operation) return false;
        },
        .repository_bootstrap => return false,
    }
    const lock = record.exact_lock orelse return false;
    if (!std.mem.eql(u8, lock.schema, verified_lock.binding.schema) or
        lock.version != verified_lock.binding.version or
        !std.mem.eql(
            u8,
            &lock.digest_sha256,
            &verified_lock.binding.digest_sha256,
        ))
        return false;
    const selectors = try selectorsFor(allocator, prepared.request);
    defer allocator.free(selectors);
    const execute_digest = try production_backend.workflowProductRequestDigest(
        allocator,
        workflow_operation,
        .execute,
        selectors,
        executeOptions(profile, prepared.paths.exact_lock),
    );
    if (std.mem.eql(u8, &record.request_sha256, &execute_digest)) return true;
    const recovery_digest = try production_backend.workflowProductRequestDigest(
        allocator,
        workflow_operation,
        .recover,
        selectors,
        executeOptions(profile, prepared.paths.exact_lock),
    );
    return std.mem.eql(u8, &record.request_sha256, &recovery_digest);
}

fn settledRecoveryProvenanceMatches(
    record: root_operation.Record,
    document: root_operation_completion.Document,
) bool {
    const provenance_sha256 = record.provenance_sha256 orelse return false;
    if (!std.mem.eql(u8, &record.attempt_id, &document.attempt_id))
        return false;
    const expected = root_operation.provenanceDigest(record, .{
        .outcome = record.outcome,
        .document_sha256 = document.digest_sha256,
        .journal_archived = document.journal.status == .archived,
    });
    return std.mem.eql(u8, &provenance_sha256, &expected);
}

fn acknowledgmentForSettledRecovery(
    record: root_operation.Record,
    document: root_operation_completion.Document,
    acknowledgment_id: [32]u8,
) RecoveryAcknowledgment {
    return .{
        .attempt_id = record.attempt_id,
        .completion_sha256 = document.digest_sha256,
        .provenance_sha256 = record.provenance_sha256.?,
        .acknowledgment_id = acknowledgment_id,
    };
}

fn ownershipAcknowledgment(
    marker: root_operation.DeferredAcknowledgment,
    acknowledgment_id: [32]u8,
) OwnershipAcknowledgment {
    return .{
        .attempt_id = marker.attempt_id,
        .marker_sha256 = marker.digest_sha256,
        .acknowledgment_id = acknowledgment_id,
    };
}

fn durableLowerAcknowledgment(
    ownership: ?OwnershipAcknowledgment,
    recovery: ?RecoveryAcknowledgment,
) !?root_operation.DeferredAcknowledgment {
    if (ownership != null and recovery != null)
        return error.AmbiguousLowerAcknowledgment;
    if (ownership) |acknowledgment| {
        const marker = try root_operation.createDeferredAcknowledgment(.{
            .state = .released,
            .attempt_id = acknowledgment.attempt_id,
            .acknowledgment_id = acknowledgment.acknowledgment_id,
        });
        if (!std.mem.eql(
            u8,
            &marker.digest_sha256,
            &acknowledgment.marker_sha256,
        )) return error.LowerAcknowledgmentMismatch;
        return marker;
    }
    if (recovery) |acknowledgment|
        return try root_operation.createDeferredAcknowledgment(.{
            .state = .pending,
            .attempt_id = acknowledgment.attempt_id,
            .completion_sha256 = acknowledgment.completion_sha256,
            .provenance_sha256 = acknowledgment.provenance_sha256,
            .acknowledgment_id = acknowledgment.acknowledgment_id,
        });
    return null;
}

fn lowerAcknowledgmentMatches(
    durable: root_operation.DeferredAcknowledgment,
    observed: root_operation.DeferredAcknowledgment,
) bool {
    if (!std.mem.eql(u8, &durable.attempt_id, &observed.attempt_id) or
        !std.mem.eql(
            u8,
            &durable.acknowledgment_id,
            &observed.acknowledgment_id,
        ))
        return false;
    return switch (durable.state) {
        .released => observed.state == .released and std.mem.eql(
            u8,
            &durable.digest_sha256,
            &observed.digest_sha256,
        ),
        .pending => (observed.state == .pending or
            observed.state == .acknowledged) and
            optionalDigestEqual(
                durable.completion_sha256,
                observed.completion_sha256,
            ) and
            optionalDigestEqual(
                durable.provenance_sha256,
                observed.provenance_sha256,
            ),
        else => false,
    };
}

fn optionalDigestEqual(left: ?[32]u8, right: ?[32]u8) bool {
    if (left == null or right == null) return left == null and right == null;
    return std.mem.eql(u8, &left.?, &right.?);
}

fn copyRequest(
    allocator: std.mem.Allocator,
    request: api.Request,
) !api.Request {
    const packages = try allocator.alloc([]const u8, request.packages.len);
    for (request.packages, 0..) |package, index|
        packages[index] = try allocator.dupe(u8, package);
    return .{
        .api_version = request.api_version,
        .operation = request.operation,
        .profile_path = try allocator.dupe(u8, request.profile_path),
        .packages = packages,
        .assume_yes = request.assume_yes,
    };
}

fn copyProfileBinding(
    allocator: std.mem.Allocator,
    binding: api.ProfileBinding,
) !api.ProfileBinding {
    return .{
        .path = try allocator.dupe(u8, binding.path),
        .sha256 = binding.sha256,
        .reference_evidence_sha256 = binding.reference_evidence_sha256,
    };
}

fn copyDocumentBinding(
    allocator: std.mem.Allocator,
    binding: api.DocumentBinding,
) !api.DocumentBinding {
    return .{
        .path = try allocator.dupe(u8, binding.path),
        .schema = try allocator.dupe(u8, binding.schema),
        .version = binding.version,
        .digest_sha256 = binding.digest_sha256,
    };
}

fn copyPaths(
    allocator: std.mem.Allocator,
    paths: OperationPaths,
) !OperationPaths {
    return .{
        .directory = try allocator.dupe(u8, paths.directory),
        .active_state = try allocator.dupe(u8, paths.active_state),
        .retained_state = try allocator.dupe(u8, paths.retained_state),
        .request = try allocator.dupe(u8, paths.request),
        .exact_lock = try allocator.dupe(u8, paths.exact_lock),
        .transaction_result = try allocator.dupe(
            u8,
            paths.transaction_result,
        ),
        .recovery_completion = try allocator.dupe(
            u8,
            paths.recovery_completion,
        ),
        .completion = try allocator.dupe(u8, paths.completion),
        .lower_acknowledgment = try allocator.dupe(
            u8,
            paths.lower_acknowledgment,
        ),
    };
}

fn dupeOptional(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
) !?[]const u8 {
    return if (value) |bytes| try allocator.dupe(u8, bytes) else null;
}

fn join(
    allocator: std.mem.Allocator,
    parent: []const u8,
    leaf: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ parent, leaf });
}

fn writeCompletionPayload(
    completion: ExecutionCompletion,
    writer: *std.Io.Writer,
) !void {
    try writer.writeAll("{\"schema\":");
    try writeString(writer, completion_schema_id);
    try writer.print(",\"version\":{},\"attempt_id\":", .{
        completion_schema_version,
    });
    try writeHex(writer, &completion.attempt_id);
    try writer.writeAll(",\"request_sha256\":");
    try writeHex(writer, &completion.request_sha256);
    try writer.writeAll(",\"profile\":");
    try writeProfile(writer, completion.profile);
    try writer.writeAll(",\"exact_lock\":");
    try writeDocument(writer, completion.exact_lock);
    try writer.writeAll(",\"transaction_result\":");
    try writeDocument(writer, completion.transaction_result);
    try writer.print(
        ",\"root_operation_status\":\"completed\",\"recovered\":{},\"completed_unix\":{}}}",
        .{ completion.recovered, completion.completed_unix },
    );
}

fn writeProfile(writer: *std.Io.Writer, profile: api.ProfileBinding) !void {
    try writer.writeAll("{\"path\":");
    try writeString(writer, profile.path);
    try writer.writeAll(",\"sha256\":");
    try writeHex(writer, &profile.sha256);
    try writer.writeAll(",\"reference_evidence_sha256\":");
    try writeHex(writer, &profile.reference_evidence_sha256);
    try writer.writeByte('}');
}

fn writeDocument(
    writer: *std.Io.Writer,
    document: api.DocumentBinding,
) !void {
    try writer.writeAll("{\"path\":");
    try writeString(writer, document.path);
    try writer.writeAll(",\"schema\":");
    try writeString(writer, document.schema);
    try writer.print(",\"version\":{},\"digest_sha256\":", .{
        document.version,
    });
    try writeHex(writer, &document.digest_sha256);
    try writer.writeByte('}');
}

fn writeString(writer: *std.Io.Writer, value: []const u8) !void {
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

fn writeHex(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
    try writer.writeByte('"');
}

fn readTrustedOperationFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    var file_system: system_profile.SystemFileSystem = .{ .io = io };
    const result = try file_system.interface().read(
        allocator,
        path,
        maximum_bytes,
    );
    return result.bytes;
}

fn openSecureAbsoluteDirectory(
    store: *SystemStateStore,
    allocator: std.mem.Allocator,
    path: []const u8,
    create: bool,
) !std.Io.Dir {
    const io = store.io;
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/')
        return error.InvalidPath;
    var current = try openSyncCapableDirectory(
        io,
        .cwd(),
        "/",
        false,
    );
    errdefer current.close(io);
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return error.InvalidPath;
        const next = openSyncCapableDirectory(
            io,
            current,
            component,
            true,
        ) catch |err| switch (err) {
            error.FileNotFound => create_block: {
                if (!create) return err;
                current.createDir(
                    io,
                    component,
                    .fromMode(0o700),
                ) catch |create_err| switch (create_err) {
                    error.PathAlreadyExists => {},
                    else => return create_err,
                };
                try store.syncDirectoryAt(
                    current,
                    .ancestor_parent,
                );
                break :create_block try openSyncCapableDirectory(
                    io,
                    current,
                    component,
                    true,
                );
            },
            else => return err,
        };
        current.close(io);
        current = next;
    }
    try validateSecureDirectoryChain(io, allocator, path);
    return current;
}

fn openSyncCapableDirectory(
    io: std.Io,
    parent: std.Io.Dir,
    path: []const u8,
    resolve_beneath: bool,
) !std.Io.Dir {
    // Dir.openDir uses an O_PATH handle on Linux, which cannot be fsynced.
    var file = try parent.openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = true,
        .follow_symlinks = false,
        .resolve_beneath = resolve_beneath,
    });
    errdefer file.close(io);
    if ((try file.stat(io)).kind != .directory) return error.NotDir;
    return .{ .handle = file.handle };
}

fn validateSecureDirectoryChain(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) !void {
    var file_system: system_profile.SystemFileSystem = .{ .io = io };
    try validateDirectoryMetadata(
        try file_system.interface().inspectDirectory("/"),
    );
    var prefix = std.ArrayListUnmanaged(u8).empty;
    defer prefix.deinit(allocator);
    try prefix.append(allocator, '/');
    var components = std.mem.splitScalar(u8, path[1..], '/');
    var first = true;
    while (components.next()) |component| {
        if (!first) try prefix.append(allocator, '/');
        first = false;
        try prefix.appendSlice(allocator, component);
        try validateDirectoryMetadata(
            try file_system.interface().inspectDirectory(prefix.items),
        );
    }
}

fn validateDirectoryMetadata(metadata: system_profile.Metadata) !void {
    if (metadata.kind != .directory) return error.InvalidDirectory;
    if (!metadata.modeled) return error.OwnershipUnavailable;
    if (metadata.uid != 0) return error.NotRootOwned;
    if (metadata.mode & 0o022 != 0) return error.InsecurePermissions;
}

fn readOptionalFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
) !?[]u8 {
    var file = dir.openFile(io, name, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return try reader.interface.allocRemaining(
        allocator,
        .limited(transaction_provenance.maximum_document_bytes),
    );
}

fn syncDirectory(io: std.Io, dir: std.Io.Dir) !void {
    _ = io;
    if (@import("builtin").os.tag != .linux) return;
    switch (std.os.linux.errno(std.os.linux.fsync(dir.handle))) {
        .SUCCESS => {},
        .BADF => return error.InvalidDirectoryHandle,
        .INVAL, .ROFS => return error.OperationUnsupported,
        .IO => return error.InputOutput,
        .NOSPC => return error.NoSpaceLeft,
        .DQUOT => return error.DiskQuota,
        else => return error.Unexpected,
    }
}

const TestStatePair = struct {
    current: operation_state.OwnedState,
    final: operation_state.OwnedState,

    fn deinit(self: *TestStatePair) void {
        self.final.deinit();
        self.current.deinit();
        self.* = undefined;
    }
};

const TestDirectorySync = struct {
    events: [32]DirectorySyncBoundary = undefined,
    count: usize = 0,
    fail_on: ?DirectorySyncBoundary = null,

    fn interface(self: *TestDirectorySync) DirectorySync {
        return .{ .context = self, .syncFn = sync };
    }

    fn sync(
        context: *anyopaque,
        io: std.Io,
        dir: std.Io.Dir,
        boundary: DirectorySyncBoundary,
    ) !void {
        const self: *TestDirectorySync = @ptrCast(@alignCast(context));
        self.events[self.count] = boundary;
        self.count += 1;
        if (self.fail_on == boundary) return error.InjectedDirectorySyncFailure;
        try syncDirectory(io, dir);
    }
};

fn testStatePair(
    allocator: std.mem.Allocator,
    paths: OperationPaths,
    attempt_id: [32]u8,
) !TestStatePair {
    const exact: api.DocumentBinding = .{
        .path = paths.exact_lock,
        .schema = exact_lock.schema_id,
        .version = exact_lock.schema_version,
        .digest_sha256 = @splat(0x51),
    };
    const transaction: api.DocumentBinding = .{
        .path = paths.transaction_result,
        .schema = transaction_provenance.schema_id,
        .version = transaction_provenance.schema_version,
        .digest_sha256 = @splat(0x52),
    };
    var current = try operation_state.create(allocator, .{
        .attempt_id = attempt_id,
        .generation = 7,
        .operation = .install,
        .phase = .verifying,
        .mutation_started = true,
        .outcome = .pending,
        .request_sha256 = @splat(0x53),
        .profile = .{
            .path = "/profile.json",
            .sha256 = @splat(0x54),
            .reference_evidence_sha256 = @splat(0x55),
        },
        .exact_lock = exact,
        .transaction_result = transaction,
        .updated_unix = 100,
    });
    errdefer current.deinit();
    const completion: api.CompletionBinding = .{
        .document = .{
            .path = paths.completion,
            .schema = completion_schema_id,
            .version = completion_schema_version,
            .digest_sha256 = @splat(0x56),
        },
        .completed_attempt_id = attempt_id,
    };
    const final = try nextState(allocator, current.state, .{
        .phase = .completed,
        .outcome = .succeeded,
        .root_operation_completion = completion,
        .updated_unix = 200,
    });
    return .{ .current = current, .final = final };
}

fn testInitialState(
    allocator: std.mem.Allocator,
    attempt_id: [32]u8,
) !operation_state.OwnedState {
    return operation_state.create(allocator, .{
        .attempt_id = attempt_id,
        .generation = 1,
        .operation = .install,
        .phase = .reserved,
        .mutation_started = false,
        .outcome = .pending,
        .request_sha256 = @splat(0x53),
        .profile = .{
            .path = "/profile.json",
            .sha256 = @splat(0x54),
            .reference_evidence_sha256 = @splat(0x55),
        },
        .updated_unix = 100,
    });
}

fn reserveVerifyingTestState(
    allocator: std.mem.Allocator,
    store: StateStore,
    state_path: []const u8,
    paths: OperationPaths,
    attempt_id: [32]u8,
) !TestStatePair {
    var initial = try testInitialState(allocator, attempt_id);
    defer initial.deinit();
    var profile_loaded = try nextState(allocator, initial.state, .{
        .phase = .profile_loaded,
        .updated_unix = 110,
    });
    defer profile_loaded.deinit();
    var authenticated = try nextState(allocator, profile_loaded.state, .{
        .phase = .authenticated,
        .updated_unix = 120,
    });
    defer authenticated.deinit();
    var downloaded = try nextState(allocator, authenticated.state, .{
        .phase = .downloaded,
        .exact_lock = .{
            .path = paths.exact_lock,
            .schema = exact_lock.schema_id,
            .version = exact_lock.schema_version,
            .digest_sha256 = @splat(0x51),
        },
        .updated_unix = 130,
    });
    defer downloaded.deinit();
    var mutating = try nextState(allocator, downloaded.state, .{
        .phase = .mutating,
        .updated_unix = 140,
    });
    defer mutating.deinit();
    var verifying = try nextState(allocator, mutating.state, .{
        .phase = .verifying,
        .transaction_result = .{
            .path = paths.transaction_result,
            .schema = transaction_provenance.schema_id,
            .version = transaction_provenance.schema_version,
            .digest_sha256 = @splat(0x52),
        },
        .updated_unix = 150,
    });
    errdefer verifying.deinit();
    var final = try nextState(allocator, verifying.state, .{
        .phase = .completed,
        .outcome = .succeeded,
        .root_operation_completion = .{
            .document = .{
                .path = paths.completion,
                .schema = completion_schema_id,
                .version = completion_schema_version,
                .digest_sha256 = @splat(0x56),
            },
            .completed_attempt_id = attempt_id,
        },
        .updated_unix = 200,
    });
    errdefer final.deinit();
    try store.reserveFn(
        store.context,
        allocator,
        paths,
        "{}",
        initial.state,
    );
    inline for (.{
        .{ initial.state, profile_loaded.state },
        .{ profile_loaded.state, authenticated.state },
        .{ authenticated.state, downloaded.state },
        .{ downloaded.state, mutating.state },
        .{ mutating.state, verifying.state },
    }) |transition| try store.compareAndSetFn(
        store.context,
        allocator,
        state_path,
        operation_state.Expected.fromState(transition[0]),
        transition[1],
    );
    return .{ .current = verifying, .final = final };
}

fn reserveDownloadedTestState(
    allocator: std.mem.Allocator,
    store: StateStore,
    state_path: []const u8,
    paths: OperationPaths,
    attempt_id: [32]u8,
) !operation_state.OwnedState {
    var initial = try testInitialState(allocator, attempt_id);
    defer initial.deinit();
    var profile_loaded = try nextState(allocator, initial.state, .{
        .phase = .profile_loaded,
        .updated_unix = 110,
    });
    defer profile_loaded.deinit();
    var authenticated = try nextState(allocator, profile_loaded.state, .{
        .phase = .authenticated,
        .updated_unix = 120,
    });
    defer authenticated.deinit();
    var downloaded = try nextState(allocator, authenticated.state, .{
        .phase = .downloaded,
        .exact_lock = .{
            .path = paths.exact_lock,
            .schema = exact_lock.schema_id,
            .version = exact_lock.schema_version,
            .digest_sha256 = @splat(0x51),
        },
        .updated_unix = 130,
    });
    errdefer downloaded.deinit();
    try store.reserveFn(
        store.context,
        allocator,
        paths,
        "{}",
        initial.state,
    );
    inline for (.{
        .{ initial.state, profile_loaded.state },
        .{ profile_loaded.state, authenticated.state },
        .{ authenticated.state, downloaded.state },
    }) |transition| try store.compareAndSetFn(
        store.context,
        allocator,
        state_path,
        operation_state.Expected.fromState(transition[0]),
        transition[1],
    );
    return downloaded;
}

fn requirePrivilegedProductionTest() !void {
    if (builtin.os.tag == .linux and std.os.linux.geteuid() == 0) return;
    if (build_options.require_privileged_orchestration_tests)
        return error.RequiredPrivilegedOrchestrationCoverageUnavailable;
    return error.SkipZigTest;
}

fn privilegedCoverageUnavailable() anyerror {
    return if (build_options.require_privileged_orchestration_tests)
        error.RequiredPrivilegedOrchestrationCoverageUnavailable
    else
        error.SkipZigTest;
}

test "apt_system_orchestrator.test.required_privileged.manifest covers every privileged test" {
    const source = @embedFile("apt_system_orchestrator.zig");
    const test_prefix = "\ntest \"";
    const required_tag =
        "apt_system_orchestrator.test.required_privileged.";
    const privilege_call =
        "requirePrivilegedProduction" ++ "Test();";
    const unavailable_call =
        "privilegedCoverage" ++ "Unavailable()";
    var cursor: usize = 0;
    var tagged_count: usize = 0;
    var privilege_dependent_count: usize = 0;
    while (std.mem.indexOfPos(u8, source, cursor, test_prefix)) |start| {
        const body_start = start + test_prefix.len;
        const name_end = std.mem.indexOfScalarPos(
            u8,
            source,
            body_start,
            '"',
        ) orelse return error.InvalidTestManifest;
        const next = std.mem.indexOfPos(
            u8,
            source,
            name_end,
            test_prefix,
        ) orelse source.len;
        const name = source[body_start..name_end];
        const body = source[name_end..next];
        const tagged = std.mem.startsWith(u8, name, required_tag);
        if (tagged) tagged_count += 1;
        if (std.mem.indexOf(
            u8,
            body,
            privilege_call,
        ) != null or std.mem.indexOf(
            u8,
            body,
            unavailable_call,
        ) != null) {
            privilege_dependent_count += 1;
            try std.testing.expect(tagged);
        }
        cursor = next;
    }
    try std.testing.expectEqual(@as(usize, 24), tagged_count);
    try std.testing.expectEqual(
        @as(usize, 20),
        privilege_dependent_count,
    );
}

test "apt_system_orchestrator.test.selector parsing preserves one batch" {
    const request: api.Request = .{
        .operation = .install,
        .profile_path = "/profile.json",
        .packages = &.{ "beta:amd64=2", "alpha" },
    };
    const selectors = try selectorsFor(std.testing.allocator, request);
    defer std.testing.allocator.free(selectors);
    try std.testing.expectEqual(@as(usize, 2), selectors.len);
    try std.testing.expectEqualStrings("beta", selectors[0].name);
    try std.testing.expectEqualStrings("amd64", selectors[0].architecture.?);
    try std.testing.expectEqualStrings("2", selectors[0].version.?);
    try std.testing.expectEqualStrings("alpha", selectors[1].name);
}

test "apt_system_orchestrator.test.operation paths are retained under one filesystem" {
    const attempt: [32]u8 = @splat(0xab);
    var paths = try pathsFor(std.testing.allocator, "/var/lib/debz", attempt);
    defer paths.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.startsWith(
        u8,
        paths.exact_lock,
        "/var/lib/debz/apt/operations/",
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        paths.transaction_result,
        paths.directory,
    ));
    try std.testing.expectEqualStrings(
        "/var/lib/debz/apt/active-operation-v1.json",
        paths.active_state,
    );
}

test "apt_system_orchestrator.test.execution boundary propagates only contract classes" {
    try std.testing.expectError(
        error.OutOfMemory,
        executionInvocationFailure(error.OutOfMemory),
    );
    try std.testing.expectError(
        error.InvariantViolation,
        executionInvocationFailure(error.InvalidTransition),
    );
}

test "apt_system_orchestrator.test.required_privileged.production options preserve host-root denial" {
    const profile: ProfileView = .{
        .binding = .{
            .path = "/profile.json",
            .sha256 = @splat(1),
            .reference_evidence_sha256 = @splat(2),
        },
        .source_paths = &.{"/source"},
        .config_paths = &.{},
        .keyring_paths = &.{"/keyring"},
        .architecture = "amd64",
        .foreign_architectures = &.{},
        .repository_policy = .strict_priority,
        .cache_path = "/var/cache/debz",
        .state_path = "/var/lib/debz",
        .conffile = .keep_existing,
        .proxy = null,
        .credential_reference = null,
    };
    const options = commonOptions(profile, "/lock", null);
    try std.testing.expectEqualStrings(
        live_root.logical_root_path,
        options.install_root,
    );
    try std.testing.expect(!live_root.host_root_allowed);
    try std.testing.expectEqual(product_api.ConffilePolicy.keep_existing, options.conffile);
}

test "apt_system_orchestrator.test.system result verifier exposes lock and provenance boundaries" {
    var verifier: SystemResultVerifier = .{ .io = std.testing.io };
    const interface = verifier.interface();
    try std.testing.expect(interface.context == @as(*anyopaque, @ptrCast(&verifier)));
}

test "apt_system_orchestrator.test.system state store exposes durable operation boundary" {
    var store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    const interface = store.interface();
    try std.testing.expect(interface.context == @as(*anyopaque, @ptrCast(&store)));
}

test "apt_system_orchestrator.test.active publication requires the complete directory durability sequence" {
    var durability: ReservationDurability = .{};
    try std.testing.expectError(
        error.OperationDirectoryNotDurable,
        durability.permitActivePublication(),
    );
    durability.ancestor_parents = true;
    try std.testing.expectError(
        error.OperationDirectoryNotDurable,
        durability.permitActivePublication(),
    );
    durability.attempt_parent = true;
    try std.testing.expectError(
        error.OperationDirectoryNotDurable,
        durability.permitActivePublication(),
    );
    durability.request_document = true;
    try durability.permitActivePublication();
}

test "apt_system_orchestrator.test.required_privileged.durability operation directory parent is durable before active publication" {
    try requirePrivilegedProductionTest();
    {
        const root_path = try std.fmt.allocPrint(
            std.testing.allocator,
            "/root/debz-apt-system-durability-{d}-success",
            .{std.os.linux.getpid()},
        );
        defer std.testing.allocator.free(root_path);
        defer std.Io.Dir.cwd().deleteTree(
            std.testing.io,
            root_path,
        ) catch {};
        const state_path = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}/state",
            .{root_path},
        );
        defer std.testing.allocator.free(state_path);
        const attempt_id: [32]u8 = @splat(0x31);
        var paths = try pathsFor(
            std.testing.allocator,
            state_path,
            attempt_id,
        );
        defer paths.deinit(std.testing.allocator);
        var initial = try testInitialState(
            std.testing.allocator,
            attempt_id,
        );
        defer initial.deinit();
        var syncs: TestDirectorySync = .{};
        var store: SystemStateStore = .{
            .allocator = std.testing.allocator,
            .io = std.testing.io,
            .directory_sync = syncs.interface(),
        };
        const interface = store.interface();
        try interface.reserveFn(
            interface.context,
            std.testing.allocator,
            paths,
            "{}",
            initial.state,
        );
        const events = syncs.events[0..syncs.count];
        const attempt_index = std.mem.indexOfScalar(
            DirectorySyncBoundary,
            events,
            .attempt_parent,
        ) orelse return error.MissingAttemptParentSync;
        const publication_index = std.mem.indexOfScalar(
            DirectorySyncBoundary,
            events,
            .publication_directory,
        ) orelse return error.MissingPublicationSync;
        try std.testing.expect(attempt_index < publication_index);
        try std.testing.expect(std.mem.indexOfScalar(
            DirectorySyncBoundary,
            events[0..attempt_index],
            .ancestor_parent,
        ) != null);
    }
    {
        const root_path = try std.fmt.allocPrint(
            std.testing.allocator,
            "/root/debz-apt-system-durability-{d}-failure",
            .{std.os.linux.getpid()},
        );
        defer std.testing.allocator.free(root_path);
        defer std.Io.Dir.cwd().deleteTree(
            std.testing.io,
            root_path,
        ) catch {};
        const state_path = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}/state",
            .{root_path},
        );
        defer std.testing.allocator.free(state_path);
        const attempt_id: [32]u8 = @splat(0x32);
        var paths = try pathsFor(
            std.testing.allocator,
            state_path,
            attempt_id,
        );
        defer paths.deinit(std.testing.allocator);
        var initial = try testInitialState(
            std.testing.allocator,
            attempt_id,
        );
        defer initial.deinit();
        var syncs: TestDirectorySync = .{
            .fail_on = .attempt_parent,
        };
        var store: SystemStateStore = .{
            .allocator = std.testing.allocator,
            .io = std.testing.io,
            .directory_sync = syncs.interface(),
        };
        const interface = store.interface();
        try std.testing.expectError(
            error.InjectedDirectorySyncFailure,
            interface.reserveFn(
                interface.context,
                std.testing.allocator,
                paths,
                "{}",
                initial.state,
            ),
        );
        var active = try interface.readActive(
            std.testing.allocator,
            state_path,
        );
        defer if (active) |*state| state.deinit();
        try std.testing.expect(active == null);
        try std.testing.expectError(
            error.FileNotFound,
            readTrustedOperationFile(
                std.testing.io,
                std.testing.allocator,
                paths.request,
                api.maximum_document_bytes,
            ),
        );
    }
}

test "apt_system_orchestrator.test.required_privileged.durability failBeforeMutation retains and repeats without active wedge" {
    try requirePrivilegedProductionTest();
    const root_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "/root/debz-fail-before-mutation-{d}",
        .{std.os.linux.getpid()},
    );
    defer std.testing.allocator.free(root_path);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, root_path) catch {};
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{root_path},
    );
    defer std.testing.allocator.free(state_path);
    var profile: FakeProfileLoader = .{ .state_path = state_path };
    var backend: FakeBackend = .{ .download_status = .download };
    var runner: FakeRunner = .{ .allocator = std.testing.allocator };
    defer runner.deinit();
    var store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    var verifier: FakeVerifier = .{};
    var sources: FakeSources = .{};
    var engine: Engine = .{
        .profiles = profile.interface(),
        .runner = runner.interface(),
        .backend = backend.interface(),
        .store = store.interface(),
        .verifier = verifier.interface(),
        .ids = sources.ids(),
        .clock = sources.clock(),
    };
    sources.next_id = @splat(0x33);
    {
        var prepared = try expectReady(try engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        var result = try engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(api.Outcome.download, result.outcome);
        try std.testing.expect((try store.interface().readActive(
            std.testing.allocator,
            state_path,
        )) == null);
        var retained = (try store.interface().readRetainedFn(
            store.interface().context,
            std.testing.allocator,
            prepared.paths,
        )) orelse return error.MissingRetainedState;
        defer retained.deinit();
        try std.testing.expectEqual(
            operation_state.Outcome.failed_before_mutation,
            retained.state.outcome,
        );
        try std.testing.expect(retained.state.exact_lock != null);
        try std.testing.expect(retained.state.transaction_result == null);
        try std.testing.expect(retained.state.root_operation_completion == null);
        try std.testing.expectEqualStrings(
            result.summary,
            retained.state.diagnostic,
        );
    }
    sources.next_id = @splat(0x34);
    var crash: TestFinishCrash = .{};
    store.finish_crash = crash.interface();
    var interrupted = try expectReady(try engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer interrupted.deinit();
    var interrupted_result = try engine.execute(
        std.testing.allocator,
        interrupted,
        true,
    );
    defer interrupted_result.deinit();
    try std.testing.expectEqual(
        api.DiagnosticId.state_persistence_failed,
        interrupted_result.diagnostics[0].id,
    );
    var interrupted_active = try store.interface().readActive(
        std.testing.allocator,
        state_path,
    );
    defer if (interrupted_active) |*owned| owned.deinit();
    try std.testing.expect(interrupted_active == null);
    var interrupted_retained = (try store.interface().readRetainedFn(
        store.interface().context,
        std.testing.allocator,
        interrupted.paths,
    )) orelse return error.MissingRetainedState;
    defer interrupted_retained.deinit();
    const retained_digest = interrupted_retained.state.digest_sha256;
    const retained_generation = interrupted_retained.state.generation;
    const retained_timestamp = interrupted_retained.state.updated_unix;
    store.finish_crash = null;
    sources.next_id = @splat(0x35);
    var repeated = try expectReady(try engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer repeated.deinit();
    var reconciled_retained = (try store.interface().readRetainedFn(
        store.interface().context,
        std.testing.allocator,
        interrupted.paths,
    )) orelse return error.MissingRetainedState;
    defer reconciled_retained.deinit();
    try std.testing.expectEqual(
        retained_digest,
        reconciled_retained.state.digest_sha256,
    );
    try std.testing.expectEqual(
        retained_generation,
        reconciled_retained.state.generation,
    );
    try std.testing.expectEqual(
        retained_timestamp,
        reconciled_retained.state.updated_unix,
    );
    var repeated_result = try engine.execute(
        std.testing.allocator,
        repeated,
        true,
    );
    defer repeated_result.deinit();
    try std.testing.expectEqual(
        api.Outcome.download,
        repeated_result.outcome,
    );
    try std.testing.expect((try store.interface().readActive(
        std.testing.allocator,
        state_path,
    )) == null);
    try std.testing.expectEqual(@as(usize, 3), backend.download_calls);
}

test "apt_system_orchestrator.test.required_privileged.durability retained failure restart adopts exact state and rejects foreign evidence" {
    try requirePrivilegedProductionTest();
    const root_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "/root/debz-retained-failure-{d}",
        .{std.os.linux.getpid()},
    );
    defer std.testing.allocator.free(root_path);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, root_path) catch {};
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/restart/state",
        .{root_path},
    );
    defer std.testing.allocator.free(state_path);
    const attempt_id: [32]u8 = @splat(0x71);
    var paths = try pathsFor(
        std.testing.allocator,
        state_path,
        attempt_id,
    );
    defer paths.deinit(std.testing.allocator);
    var crash: TestFinishCrash = .{};
    var crashing_store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .finish_crash = crash.interface(),
    };
    const crashing = crashing_store.interface();
    var downloaded = try reserveDownloadedTestState(
        std.testing.allocator,
        crashing,
        state_path,
        paths,
        attempt_id,
    );
    defer downloaded.deinit();
    var original = try nextState(
        std.testing.allocator,
        downloaded.state,
        .{
            .phase = .completed,
            .outcome = .failed_before_mutation,
            .diagnostic = "original retained failure",
            .updated_unix = 200,
        },
    );
    defer original.deinit();
    try std.testing.expectError(
        error.InjectedFinishCrash,
        crashing.finishFn(
            crashing.context,
            std.testing.allocator,
            paths,
            operation_state.Expected.fromState(downloaded.state),
            original.state,
        ),
    );
    var reopened_store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    const reopened = reopened_store.interface();
    var active = (try reopened.readActive(
        std.testing.allocator,
        state_path,
    )) orelse return error.MissingActiveState;
    defer active.deinit();
    var regenerated = try nextState(
        std.testing.allocator,
        active.state,
        .{
            .phase = .completed,
            .outcome = .failed_before_mutation,
            .diagnostic = "regenerated after restart",
            .updated_unix = 999,
        },
    );
    defer regenerated.deinit();
    try reopened.finishFn(
        reopened.context,
        std.testing.allocator,
        paths,
        operation_state.Expected.fromState(active.state),
        regenerated.state,
    );
    try std.testing.expect((try reopened.readActive(
        std.testing.allocator,
        state_path,
    )) == null);
    var retained = (try reopened.readRetainedFn(
        reopened.context,
        std.testing.allocator,
        paths,
    )) orelse return error.MissingRetainedState;
    defer retained.deinit();
    try std.testing.expectEqual(
        original.state.digest_sha256,
        retained.state.digest_sha256,
    );
    try std.testing.expectEqual(
        original.state.generation,
        retained.state.generation,
    );
    try std.testing.expectEqual(
        original.state.updated_unix,
        retained.state.updated_unix,
    );
    try std.testing.expectEqualStrings(
        original.state.diagnostic,
        retained.state.diagnostic,
    );

    const foreign_state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/foreign/state",
        .{root_path},
    );
    defer std.testing.allocator.free(foreign_state_path);
    const owner_attempt: [32]u8 = @splat(0x72);
    var foreign_paths = try pathsFor(
        std.testing.allocator,
        foreign_state_path,
        owner_attempt,
    );
    defer foreign_paths.deinit(std.testing.allocator);
    var owner = try reserveDownloadedTestState(
        std.testing.allocator,
        reopened,
        foreign_state_path,
        foreign_paths,
        owner_attempt,
    );
    defer owner.deinit();
    var owner_final = try nextState(
        std.testing.allocator,
        owner.state,
        .{
            .phase = .completed,
            .outcome = .failed_before_mutation,
            .diagnostic = "owner failure",
            .updated_unix = 200,
        },
    );
    defer owner_final.deinit();
    var foreign_final = try operation_state.create(
        std.testing.allocator,
        .{
            .attempt_id = @splat(0x73),
            .generation = owner_final.state.generation,
            .operation = owner_final.state.operation,
            .phase = .completed,
            .mutation_started = false,
            .outcome = .failed_before_mutation,
            .request_sha256 = owner_final.state.request_sha256,
            .profile = owner_final.state.profile,
            .exact_lock = owner_final.state.exact_lock,
            .updated_unix = owner_final.state.updated_unix,
            .diagnostic = "foreign failure",
        },
    );
    defer foreign_final.deinit();
    const foreign_source = try foreign_final.state.canonicalJson(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(foreign_source);
    try writeAbsoluteTestFile(
        foreign_paths.retained_state,
        foreign_source,
    );
    try std.testing.expectError(
        error.PublicationConflict,
        reopened.finishFn(
            reopened.context,
            std.testing.allocator,
            foreign_paths,
            operation_state.Expected.fromState(owner.state),
            owner_final.state,
        ),
    );
    var foreign_active = (try reopened.readActive(
        std.testing.allocator,
        foreign_state_path,
    )) orelse return error.MissingActiveState;
    defer foreign_active.deinit();
    try std.testing.expectEqual(
        owner.state.digest_sha256,
        foreign_active.state.digest_sha256,
    );

    const evidence_state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/evidence/state",
        .{root_path},
    );
    defer std.testing.allocator.free(evidence_state_path);
    const evidence_attempt: [32]u8 = @splat(0x74);
    var evidence_paths = try pathsFor(
        std.testing.allocator,
        evidence_state_path,
        evidence_attempt,
    );
    defer evidence_paths.deinit(std.testing.allocator);
    var evidence_owner = try reserveDownloadedTestState(
        std.testing.allocator,
        reopened,
        evidence_state_path,
        evidence_paths,
        evidence_attempt,
    );
    defer evidence_owner.deinit();
    var evidence_final = try nextState(
        std.testing.allocator,
        evidence_owner.state,
        .{
            .phase = .completed,
            .outcome = .failed_before_mutation,
            .diagnostic = "failure with forbidden evidence",
            .updated_unix = 200,
        },
    );
    defer evidence_final.deinit();
    var invalid_evidence = evidence_final.state;
    invalid_evidence.transaction_result = .{
        .path = evidence_paths.transaction_result,
        .schema = transaction_provenance.schema_id,
        .version = transaction_provenance.schema_version,
        .digest_sha256 = @splat(0x75),
    };
    try std.testing.expectError(
        error.UnexpectedTransactionEvidence,
        reopened.finishFn(
            reopened.context,
            std.testing.allocator,
            evidence_paths,
            operation_state.Expected.fromState(evidence_owner.state),
            invalid_evidence,
        ),
    );
    var evidence_active = (try reopened.readActive(
        std.testing.allocator,
        evidence_state_path,
    )) orelse return error.MissingActiveState;
    defer evidence_active.deinit();
    try std.testing.expectEqual(
        evidence_owner.state.digest_sha256,
        evidence_active.state.digest_sha256,
    );
    try std.testing.expect((try reopened.readRetainedFn(
        reopened.context,
        std.testing.allocator,
        evidence_paths,
    )) == null);
}

test "apt_system_orchestrator.test.required_privileged.durability system finish reuses retained final after pre-CAS crash" {
    try requirePrivilegedProductionTest();
    const root_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "/root/debz-system-finish-reuse-{d}",
        .{std.os.linux.getpid()},
    );
    defer std.testing.allocator.free(root_path);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, root_path) catch {};
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{root_path},
    );
    defer std.testing.allocator.free(state_path);
    const attempt_id: [32]u8 = @splat(0x41);
    var paths = try pathsFor(
        std.testing.allocator,
        state_path,
        attempt_id,
    );
    defer paths.deinit(std.testing.allocator);
    var crash: TestFinishCrash = .{};
    var store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .finish_crash = crash.interface(),
    };
    const interface = store.interface();
    var states = try reserveVerifyingTestState(
        std.testing.allocator,
        interface,
        state_path,
        paths,
        attempt_id,
    );
    defer states.deinit();
    try std.testing.expectError(
        error.InjectedFinishCrash,
        interface.finishFn(
            interface.context,
            std.testing.allocator,
            paths,
            operation_state.Expected.fromState(states.current.state),
            states.final.state,
        ),
    );
    const retained_before = try readTrustedOperationFile(
        std.testing.io,
        std.testing.allocator,
        paths.retained_state,
        operation_state.maximum_document_bytes,
    );
    defer std.testing.allocator.free(retained_before);
    var active = (try interface.readActive(
        std.testing.allocator,
        state_path,
    )).?;
    defer active.deinit();
    try std.testing.expectEqual(
        states.current.state.digest_sha256,
        active.state.digest_sha256,
    );

    store.finish_crash = null;
    try interface.finishFn(
        interface.context,
        std.testing.allocator,
        paths,
        operation_state.Expected.fromState(active.state),
        states.final.state,
    );
    try std.testing.expect((try interface.readActive(
        std.testing.allocator,
        state_path,
    )) == null);
    const retained_after = try readTrustedOperationFile(
        std.testing.io,
        std.testing.allocator,
        paths.retained_state,
        operation_state.maximum_document_bytes,
    );
    defer std.testing.allocator.free(retained_after);
    try std.testing.expectEqualSlices(
        u8,
        retained_before,
        retained_after,
    );
}

test "apt_system_orchestrator.test.required_privileged.durability system finish rejects foreign retained final" {
    try requirePrivilegedProductionTest();
    const root_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "/root/debz-system-finish-foreign-{d}",
        .{std.os.linux.getpid()},
    );
    defer std.testing.allocator.free(root_path);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, root_path) catch {};
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{root_path},
    );
    defer std.testing.allocator.free(state_path);
    const attempt_id: [32]u8 = @splat(0x61);
    var paths = try pathsFor(
        std.testing.allocator,
        state_path,
        attempt_id,
    );
    defer paths.deinit(std.testing.allocator);
    var crash: TestFinishCrash = .{};
    var store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .finish_crash = crash.interface(),
    };
    const interface = store.interface();
    var states = try reserveVerifyingTestState(
        std.testing.allocator,
        interface,
        state_path,
        paths,
        attempt_id,
    );
    defer states.deinit();
    try std.testing.expectError(
        error.InjectedFinishCrash,
        interface.finishFn(
            interface.context,
            std.testing.allocator,
            paths,
            operation_state.Expected.fromState(states.current.state),
            states.final.state,
        ),
    );
    var foreign_paths = try pathsFor(
        std.testing.allocator,
        state_path,
        @as([32]u8, @splat(0x62)),
    );
    defer foreign_paths.deinit(std.testing.allocator);
    var foreign = try testStatePair(
        std.testing.allocator,
        foreign_paths,
        @splat(0x62),
    );
    defer foreign.deinit();
    const foreign_bytes = try foreign.final.state.canonicalJson(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(foreign_bytes);
    try writeAbsoluteTestFile(paths.retained_state, foreign_bytes);
    store.finish_crash = null;
    try std.testing.expectError(
        error.PublicationConflict,
        interface.finishFn(
            interface.context,
            std.testing.allocator,
            paths,
            operation_state.Expected.fromState(states.current.state),
            states.final.state,
        ),
    );
    var active = (try interface.readActive(
        std.testing.allocator,
        state_path,
    )).?;
    defer active.deinit();
    try std.testing.expectEqual(
        states.current.state.digest_sha256,
        active.state.digest_sha256,
    );
}

test "apt_system_orchestrator.test.required_privileged.production retained commit lock excludes evidence republish through active CAS" {
    try requirePrivilegedProductionTest();
    try runRetainedCommitOverlapWatchdog(10_000);
}

test "apt_system_orchestrator.test.ordinary completion uses a distinct lock-bound schema" {
    const input: CompletionInput = .{
        .attempt_id = @splat(0x01),
        .request_sha256 = @splat(0x02),
        .profile = .{
            .path = "/profile.json",
            .sha256 = @splat(0x03),
            .reference_evidence_sha256 = @splat(0x04),
        },
        .exact_lock = .{
            .path = "/state/apt/operations/id/exact-lock-v1.json",
            .schema = exact_lock.schema_id,
            .version = exact_lock.schema_version,
            .digest_sha256 = @splat(0x05),
        },
        .transaction_result = .{
            .path = "/state/apt/operations/id/transaction-result.json",
            .schema = transaction_provenance.schema_id,
            .version = transaction_provenance.schema_version,
            .digest_sha256 = @splat(0x06),
        },
        .recovered = false,
        .completed_unix = 100,
    };
    const completion = try createExecutionCompletion(input);
    const source = try completion.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(source);
    try std.testing.expect(std.mem.indexOf(
        u8,
        source,
        completion_schema_id,
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        source,
        "root-operation-completion-v1",
    ) == null);
    var retry = input;
    retry.completed_unix = 200;
    const existing = try verifyExistingCompletion(
        std.testing.allocator,
        source,
        retry,
    );
    try std.testing.expectEqual(completion.digest_sha256, existing.digest_sha256);
    retry.recovered = true;
    try std.testing.expectError(
        error.CompletionMismatch,
        verifyExistingCompletion(std.testing.allocator, source, retry),
    );
}

test "apt_system_orchestrator.test.request decoder rejects noncanonical recovery input" {
    const request: api.Request = .{
        .operation = .remove,
        .profile_path = "/profile.json",
        .packages = &.{ "a", "b" },
    };
    const bytes = try request.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var decoded = try api.decodeRequest(std.testing.allocator, bytes);
    defer decoded.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &(try request.digest()),
        &(try decoded.request.digest()),
    );
    const padded = try std.fmt.allocPrint(std.testing.allocator, " {s}", .{bytes});
    defer std.testing.allocator.free(padded);
    try std.testing.expectError(
        error.NonCanonicalDocument,
        api.decodeRequest(std.testing.allocator, padded),
    );
}

const FakeProfileLoader = struct {
    load_count: usize = 0,
    revalidate_count: usize = 0,
    fail_revalidate: bool = false,
    fail_revalidate_on: ?usize = null,
    drift_after_first: bool = false,
    state_path: []const u8 = "/state",
    cache_path: []const u8 = "/cache",
    source_paths: [1][]const u8 = .{"/etc/debz/source"},
    keyring_paths: [1][]const u8 = .{"/etc/debz/keyring"},
    profile_digest: u8 = 0x11,
    reference_digest: u8 = 0x22,

    fn interface(self: *FakeProfileLoader) ProfileLoader {
        return .{ .context = self, .loadFn = load };
    }

    fn load(
        context: *anyopaque,
        _: std.mem.Allocator,
        path: []const u8,
    ) !LoadedProfile {
        const self: *FakeProfileLoader = @ptrCast(@alignCast(context));
        self.load_count += 1;
        if (!std.mem.eql(u8, path, "/profile.json"))
            return error.FileNotFound;
        return .{
            .context = self,
            .view = .{
                .binding = .{
                    .path = "/profile.json",
                    .sha256 = @splat(
                        if (self.drift_after_first and self.load_count > 1)
                            0x44
                        else
                            self.profile_digest,
                    ),
                    .reference_evidence_sha256 = @splat(self.reference_digest),
                },
                .source_paths = &self.source_paths,
                .config_paths = &.{},
                .keyring_paths = &self.keyring_paths,
                .architecture = "amd64",
                .foreign_architectures = &.{},
                .repository_policy = .strict_priority,
                .cache_path = self.cache_path,
                .state_path = self.state_path,
                .conffile = .keep_existing,
                .proxy = null,
                .credential_reference = null,
            },
            .revalidateFn = revalidate,
            .deinitFn = deinit,
        };
    }

    fn revalidate(context: ?*anyopaque, _: std.mem.Allocator) !void {
        const self: *FakeProfileLoader = @ptrCast(@alignCast(context.?));
        self.revalidate_count += 1;
        if (self.fail_revalidate or
            self.fail_revalidate_on == self.revalidate_count)
            return error.TrustedFileContentChanged;
    }

    fn deinit(_: ?*anyopaque) void {}
};

const FakeBackend = struct {
    route_calls: usize = 0,
    workflow_calls: usize = 0,
    plan_calls: usize = 0,
    download_calls: usize = 0,
    reserve_calls: usize = 0,
    execute_calls: usize = 0,
    recover_calls: usize = 0,
    recovery_ack_calls: usize = 0,
    last_route: ?product_api.Operation = null,
    last_selector_count: usize = 0,
    last_operation: ?WorkflowOperation = null,
    plan_status: product_api.ExitStatus = .success,
    download_status: product_api.ExitStatus = .success,
    execute_status: product_api.ExitStatus = .success,
    recover_status: product_api.ExitStatus = .success,
    planned_items: [3]product_api.Item = .{
        .{ .package = "alpha", .version = "1", .architecture = "amd64" },
        .{ .package = "beta", .version = "1", .architecture = "amd64" },
        .{ .package = "dependency", .version = "1", .architecture = "amd64" },
    },
    planned_item_count: usize = 3,
    installed_items: [2]product_api.Item = .{
        .{ .package = "installed-a", .version = "1", .architecture = "amd64" },
        .{ .package = "installed-b", .version = "2", .architecture = "all" },
    },

    fn interface(self: *FakeBackend) Backend {
        return .{
            .context = self,
            .routeFn = route,
            .workflowFn = workflow,
        };
    }

    fn route(
        context: *anyopaque,
        _: std.mem.Allocator,
        request: product_api.Request,
    ) !product_api.Result {
        const self: *FakeBackend = @ptrCast(@alignCast(context));
        self.route_calls += 1;
        self.last_route = request.operation;
        return .{
            .operation = request.operation,
            .exit_status = .success,
            .changed = request.operation == .refresh,
            .summary = if (request.operation == .refresh)
                "metadata refreshed"
            else
                "installed packages listed",
            .items = if (request.operation == .list_installed or
                request.operation == .refresh)
                &self.installed_items
            else
                &.{},
        };
    }

    fn workflow(
        context: *anyopaque,
        _: std.mem.Allocator,
        request: WorkflowRequest,
    ) !product_api.Result {
        const self: *FakeBackend = @ptrCast(@alignCast(context));
        self.workflow_calls += 1;
        self.last_selector_count = request.selectors.len;
        self.last_operation = request.operation;
        if (request.recovery_acknowledgment != null) {
            self.recovery_ack_calls += 1;
            return .{
                .operation = .recover,
                .exit_status = .success,
                .changed = false,
                .summary = "lower recovery acknowledgment finalized",
            };
        }
        if (request.finalize_ownership) {
            return .{
                .operation = .recover,
                .exit_status = .success,
                .changed = false,
                .summary = "lower orchestration ownership finalized",
            };
        }
        if (request.reconciliation_claim != null) {
            return .{
                .operation = .recover,
                .exit_status = .success,
                .changed = false,
                .summary = "lower reconciliation claim published",
            };
        }
        const status = switch (request.mode) {
            .plan_only => status: {
                self.plan_calls += 1;
                break :status self.plan_status;
            },
            .download_only => status: {
                self.download_calls += 1;
                break :status self.download_status;
            },
            .reserve => status: {
                self.reserve_calls += 1;
                break :status .success;
            },
            .execute => status: {
                self.execute_calls += 1;
                break :status self.execute_status;
            },
            .recover => status: {
                self.recover_calls += 1;
                break :status self.recover_status;
            },
        };
        return .{
            .operation = switch (request.mode) {
                .plan_only => .plan,
                .download_only => .download,
                .reserve, .execute => switch (request.operation) {
                    .install => .install,
                    .remove => .remove,
                    .upgrade_all => .upgrade_all,
                },
                .recover => .recover,
            },
            .exit_status = status,
            .changed = request.mode == .execute or request.mode == .recover,
            .summary = if (status == .success) "ok" else "injected failure",
            .items = if (request.mode == .plan_only)
                self.planned_items[0..self.planned_item_count]
            else
                &.{},
            .diagnostics = .{.{
                .id = .internal_error,
                .message = "injected failure",
            }},
            .diagnostic_count = if (status == .success) 0 else 1,
        };
    }
};

const SignalTestBackend = struct {
    ready_fd: ?i32 = null,

    fn interface(self: *SignalTestBackend) Backend {
        return .{
            .context = self,
            .routeFn = route,
            .workflowFn = workflow,
        };
    }

    fn route(
        context: *anyopaque,
        _: std.mem.Allocator,
        _: product_api.Request,
    ) !product_api.Result {
        const self: *SignalTestBackend = @ptrCast(@alignCast(context));
        if (self.ready_fd) |fd| {
            var byte: [1]u8 = .{1};
            if (std.os.linux.errno(std.os.linux.write(
                fd,
                &byte,
                byte.len,
            )) != .SUCCESS) return error.ReadySignalFailed;
        }
        waitForSignal();
    }

    fn workflow(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: WorkflowRequest,
    ) !product_api.Result {
        waitForSignal();
    }

    fn waitForSignal() noreturn {
        while (true) {
            var request: std.os.linux.timespec = .{
                .sec = 1,
                .nsec = 0,
            };
            var remaining: std.os.linux.timespec = undefined;
            _ = std.os.linux.nanosleep(&request, &remaining);
        }
    }
};

fn reapSignalTestProcess(pid: i32) !u32 {
    while (true) {
        var status: u32 = 0;
        const waited = std.os.linux.waitpid(pid, &status, 0);
        switch (std.os.linux.errno(waited)) {
            .SUCCESS => return status,
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
}

fn reapTestProcessWithDeadline(pid: i32, timeout_ms: u64) !u32 {
    const started = std.Io.Clock.awake.now(std.testing.io);
    while (true) {
        var status: u32 = 0;
        const waited = std.os.linux.waitpid(
            pid,
            &status,
            std.os.linux.W.NOHANG,
        );
        switch (std.os.linux.errno(waited)) {
            .SUCCESS => if (waited != 0) return status,
            .INTR => continue,
            else => return error.WaitFailed,
        }
        if (started.durationTo(
            std.Io.Clock.awake.now(std.testing.io),
        ).toMilliseconds() >= timeout_ms) return error.ProcessTimedOut;
        var request: std.os.linux.timespec = .{
            .sec = 0,
            .nsec = 1_000_000,
        };
        var remaining: std.os.linux.timespec = undefined;
        _ = std.os.linux.nanosleep(&request, &remaining);
    }
}

fn waitForSignalTestByte(fd: i32, timeout_ms: u64) !bool {
    var elapsed: u64 = 0;
    while (elapsed < timeout_ms) : (elapsed += 5) {
        var byte: [1]u8 = undefined;
        const result = std.os.linux.read(fd, &byte, byte.len);
        switch (std.os.linux.errno(result)) {
            .SUCCESS => return result == 1,
            .INTR => continue,
            .AGAIN => {},
            else => return error.ReadySignalFailed,
        }
        var delay: std.os.linux.timespec = .{
            .sec = 0,
            .nsec = 5_000_000,
        };
        var remaining: std.os.linux.timespec = undefined;
        _ = std.os.linux.nanosleep(&delay, &remaining);
    }
    return false;
}

const FakeRunner = struct {
    allocator: std.mem.Allocator,
    calls: usize = 0,
    inspect_calls: usize = 0,
    saw_stable_root: bool = true,
    execute_root_status: RootStatus = .completed,
    recover_root_status: RootStatus = .completed,
    inspect_status: RootStatus = .clean,
    fail_mode: ?WorkflowMode = null,
    transport_roundtrip: bool = false,
    inspect_record_source: ?[]u8 = null,
    inspect_deferred_acknowledgment: ?root_operation.DeferredAcknowledgment = null,
    recovery_completion_source: ?[]u8 = null,
    recovery_completion_reads: usize = 0,
    recovery_ack_calls: usize = 0,
    ownership_finalize_calls: usize = 0,
    publish_released_on_execute: bool = false,
    publish_bound_on_execute: bool = false,
    publish_abandoned_on_execute: bool = false,
    fail_after_recovery_transport: bool = false,
    recovery_completion_mismatch: RecoveryCompletionMismatch = .none,

    const RecoveryCompletionMismatch = enum {
        none,
        original_request,
        discharge_request,
        attempt,
        successful_outcome,
    };

    fn deinit(self: *FakeRunner) void {
        if (self.inspect_record_source) |source|
            self.allocator.free(source);
        if (self.recovery_completion_source) |source|
            self.allocator.free(source);
        self.* = undefined;
    }

    fn interface(self: *FakeRunner) LiveRootRunner {
        return .{
            .context = self,
            .routeFn = route,
            .workflowFn = workflow,
            .inspectFn = inspect,
            .readRecoveryCompletionFn = readRecoveryCompletion,
        };
    }

    fn route(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        backend: Backend,
        request: product_api.Request,
    ) !BackendResult {
        const self: *FakeRunner = @ptrCast(@alignCast(context));
        self.calls += 1;
        self.saw_stable_root = self.saw_stable_root and std.mem.eql(
            u8,
            request.options.install_root,
            live_root.logical_root_path,
        );
        const result = try backend.route(allocator, request);
        if (!self.transport_roundtrip) return .{
            .result = result,
            .root_status = .clean,
        };
        const source = try result.canonicalJson(allocator);
        defer allocator.free(source);
        var decoded = try product_api.decodeResult(allocator, source);
        errdefer decoded.deinit();
        return .{
            .result = decoded.result,
            .root_status = .clean,
            .owned_result = decoded,
        };
    }

    fn workflow(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        backend: Backend,
        request: WorkflowRequest,
    ) !BackendResult {
        const self: *FakeRunner = @ptrCast(@alignCast(context));
        self.calls += 1;
        self.saw_stable_root = self.saw_stable_root and std.mem.eql(
            u8,
            request.options.install_root,
            live_root.logical_root_path,
        );
        if (request.mode == .execute and self.publish_bound_on_execute) {
            self.publish_bound_on_execute = false;
            self.inspect_deferred_acknowledgment =
                try root_operation.createDeferredAcknowledgment(.{
                    .state = .bound,
                    .attempt_id = @splat(0x80),
                    .acknowledgment_id = request.orchestration_id orelse
                        return error.MissingRecoveryAcknowledgment,
                });
            self.inspect_status = .recovery_required;
            return error.RootReplaced;
        }
        if (self.fail_mode == request.mode) {
            if (request.mode == .execute and
                self.inspect_deferred_acknowledgment != null)
                try self.publishFakeMutatingRecord(allocator, request);
            if (request.mode == .execute or request.mode == .recover)
                self.inspect_status = .recovery_required;
            return error.RootReplaced;
        }
        const backend_result = try backend.workflow(allocator, request);
        var result: BackendResult = .{
            .result = backend_result,
            .root_status = switch (request.mode) {
                .reserve => .recovery_required,
                .execute => self.execute_root_status,
                .recover => self.recover_root_status,
                else => .clean,
            },
        };
        if (request.mode == .reserve and
            result.result.exit_status == .success)
        {
            self.inspect_deferred_acknowledgment =
                try root_operation.createDeferredAcknowledgment(.{
                    .state = .bound,
                    .attempt_id = @splat(0x7f),
                    .acknowledgment_id = request.orchestration_id orelse
                        return error.MissingRecoveryAcknowledgment,
                });
            self.inspect_status = .recovery_required;
        }
        if (request.reconciliation_claim != null and
            result.result.exit_status == .success)
        {
            if (self.inspect_deferred_acknowledgment != null or
                self.inspect_record_source != null)
                return error.ReconciliationRootNotClean;
            const claim_binding: ?root_operation
                .PreMutationReconciliationClaimBinding =
                switch (request.reconciliation_claim.?) {
                    .pre_mutation => |claim| .{
                        .outer_attempt_id = request.orchestration_id orelse
                            return error.MissingOwnershipAcknowledgment,
                        .outer_generation = claim.outer_generation,
                        .outer_state_sha256 = claim.outer_state_sha256,
                        .profile_sha256 = claim.profile_sha256,
                        .profile_reference_sha256 = claim.profile_reference_sha256,
                        .exact_lock_sha256 = claim.exact_lock_sha256,
                        .semantic_request_sha256 = try workflowSemanticDigest(
                            allocator,
                            request.operation,
                            request.selectors,
                        ),
                    },
                    .post_mutation => null,
                };
            const claim_attempt_id = if (claim_binding) |binding|
                root_operation.preMutationReconciliationClaimId(binding)
            else
                @as([32]u8, @splat(0x7e));
            self.inspect_deferred_acknowledgment =
                try root_operation.createDeferredAcknowledgment(.{
                    .state = switch (request.reconciliation_claim.?) {
                        .pre_mutation => .pre_mutation_reconciliation_claim,
                        .post_mutation => .released,
                    },
                    .attempt_id = claim_attempt_id,
                    .pre_mutation_claim = claim_binding,
                    .acknowledgment_id = request.orchestration_id orelse
                        return error.MissingOwnershipAcknowledgment,
                });
            self.inspect_status = .clean;
            result.ownership_acknowledgment = ownershipAcknowledgment(
                self.inspect_deferred_acknowledgment.?,
                request.orchestration_id.?,
            );
        }
        if (request.finalize_ownership and
            result.result.exit_status == .success)
        {
            const acknowledgment = request.ownership_acknowledgment orelse
                return error.MissingOwnershipAcknowledgment;
            const marker = self.inspect_deferred_acknowledgment orelse {
                if (self.inspect_record_source != null)
                    return error.MissingOwnershipAcknowledgment;
                self.ownership_finalize_calls += 1;
                self.inspect_status = .clean;
                return result;
            };
            if (!std.mem.eql(
                u8,
                &marker.digest_sha256,
                &acknowledgment.marker_sha256,
            ) or
                !std.mem.eql(
                    u8,
                    &marker.attempt_id,
                    &acknowledgment.attempt_id,
                ) or
                !std.mem.eql(
                    u8,
                    &marker.acknowledgment_id,
                    &acknowledgment.acknowledgment_id,
                ))
                return error.InvalidOwnershipAcknowledgment;
            self.ownership_finalize_calls += 1;
            if (self.inspect_record_source) |source|
                self.allocator.free(source);
            self.inspect_record_source = null;
            self.inspect_deferred_acknowledgment = null;
            self.inspect_status = .clean;
        }
        if (request.mode == .execute and
            self.publish_released_on_execute and
            result.result.exit_status == .success)
        {
            self.inspect_deferred_acknowledgment =
                try root_operation.createDeferredAcknowledgment(.{
                    .state = .released,
                    .attempt_id = @splat(0x81),
                    .acknowledgment_id = request.orchestration_id orelse
                        return error.MissingRecoveryAcknowledgment,
                });
            self.inspect_status = .clean;
        }
        if (request.mode == .execute and
            self.publish_abandoned_on_execute)
        {
            self.inspect_deferred_acknowledgment =
                try root_operation.createDeferredAcknowledgment(.{
                    .state = .abandoned,
                    .attempt_id = @splat(0x82),
                    .acknowledgment_id = request.orchestration_id orelse
                        return error.MissingRecoveryAcknowledgment,
                });
            try self.publishFakeAbandonedRecord(allocator, request);
            self.publish_abandoned_on_execute = false;
            self.inspect_status = .clean;
        } else if (request.mode == .execute and
            result.result.exit_status == .success and
            self.inspect_deferred_acknowledgment != null and
            (self.inspect_deferred_acknowledgment.?.state == .abandoned or
                self.inspect_deferred_acknowledgment.?.state == .bound))
        {
            const marker = self.inspect_deferred_acknowledgment.?;
            self.inspect_deferred_acknowledgment =
                try root_operation.createDeferredAcknowledgment(.{
                    .state = .released,
                    .attempt_id = marker.attempt_id,
                    .acknowledgment_id = marker.acknowledgment_id,
                });
            if (self.inspect_record_source) |source|
                self.allocator.free(source);
            self.inspect_record_source = null;
            self.inspect_status = .clean;
        }
        if (request.mode == .execute and
            result.result.exit_status == .success)
        {
            const marker = self.inspect_deferred_acknowledgment orelse
                return error.MissingOwnershipAcknowledgment;
            if (marker.state != .released)
                return error.InvalidOwnershipAcknowledgment;
            result.ownership_acknowledgment = ownershipAcknowledgment(
                marker,
                request.orchestration_id orelse
                    return error.MissingOwnershipAcknowledgment,
            );
        }
        if (request.mode == .execute and
            result.result.exit_status != .success and
            self.inspect_deferred_acknowledgment != null and
            self.inspect_deferred_acknowledgment.?.state == .bound and
            !self.publish_abandoned_on_execute)
            try self.publishFakeMutatingRecord(allocator, request);
        if (self.transport_roundtrip) {
            const source = try backend_result.canonicalJson(allocator);
            defer allocator.free(source);
            var decoded = try product_api.decodeResult(allocator, source);
            errdefer decoded.deinit();
            result.result = decoded.result;
            result.owned_result = decoded;
        }
        if (request.mode == .recover and
            !request.finalize_ownership and
            request.reconciliation_claim == null and
            result.result.exit_status == .success)
        {
            if (request.recovery_acknowledgment) |_| {
                if (self.inspect_deferred_acknowledgment == null and
                    self.inspect_record_source != null)
                    return error.MissingRecoveryAcknowledgment;
                self.recovery_ack_calls += 1;
                if (self.inspect_record_source) |source|
                    self.allocator.free(source);
                self.inspect_record_source = null;
                self.inspect_deferred_acknowledgment = null;
            } else {
                var completion = try fakeRecoveryCompletion(
                    allocator,
                    request,
                    self.recovery_completion_mismatch,
                    if (self.inspect_deferred_acknowledgment) |marker|
                        marker.attempt_id
                    else
                        null,
                );
                errdefer completion.deinit();
                const source =
                    try completion.document.canonicalJson(self.allocator);
                if (self.recovery_completion_source) |previous|
                    self.allocator.free(previous);
                self.recovery_completion_source = source;
                var record = try reconstructPublishedRecoveryRecord(
                    allocator,
                    completion.document,
                );
                defer record.deinit();
                const record_source =
                    try record.record.canonicalJson(self.allocator);
                if (self.inspect_record_source) |previous|
                    self.allocator.free(previous);
                self.inspect_record_source = record_source;
                self.inspect_deferred_acknowledgment =
                    try root_operation.createDeferredAcknowledgment(.{
                        .state = .pending,
                        .attempt_id = completion.document.attempt_id,
                        .completion_sha256 = completion.document.digest_sha256,
                        .provenance_sha256 = record.record.provenance_sha256.?,
                        .acknowledgment_id = request.orchestration_id orelse
                            return error.MissingRecoveryAcknowledgment,
                    });
                result.recovery_acknowledgment = .{
                    .attempt_id = completion.document.attempt_id,
                    .completion_sha256 = completion.document.digest_sha256,
                    .provenance_sha256 = record.record.provenance_sha256.?,
                    .acknowledgment_id = request.orchestration_id orelse
                        return error.MissingRecoveryAcknowledgment,
                };
                if (self.fail_after_recovery_transport) {
                    self.fail_after_recovery_transport = false;
                    return error.TransportReadFailed;
                }
                result.recovery_completion = completion;
            }
        }
        if (request.mode == .execute or request.mode == .recover)
            self.inspect_status = .clean;
        return result;
    }

    fn publishFakeMutatingRecord(
        self: *FakeRunner,
        allocator: std.mem.Allocator,
        request: WorkflowRequest,
    ) !void {
        const marker = self.inspect_deferred_acknowledgment orelse return;
        const request_sha256 =
            try production_backend.workflowProductRequestDigest(
                allocator,
                switch (request.operation) {
                    .install => .install,
                    .remove => .remove,
                    .upgrade_all => .upgrade_all,
                },
                .execute,
                request.selectors,
                request.options,
            );
        var record = try root_operation.create(allocator, .{
            .attempt_id = marker.attempt_id,
            .generation = 1,
            .install_root = live_root.logical_root_path,
            .backend = .legacy_dpkg,
            .operation = .{ .package_transaction = switch (request.operation) {
                .install => .install,
                .remove => .remove,
                .upgrade_all => .upgrade_all,
            } },
            .state = .mutating,
            .phase = .mutation,
            .step = 2,
            .mutation_started = true,
            .outcome = .pending,
            .provenance = .pending,
            .evidence = .{
                .exact_lock = .{
                    .schema = exact_lock.schema_id,
                    .version = exact_lock.schema_version,
                    .digest_sha256 = @splat(0x55),
                },
            },
            .request_sha256 = request_sha256,
            .policy_sha256 = @splat(0x32),
            .target_architecture = request.options.architecture,
            .reserved_unix = 90,
            .updated_unix = 100,
        });
        defer record.deinit();
        const source = try record.record.canonicalJson(self.allocator);
        if (self.inspect_record_source) |previous|
            self.allocator.free(previous);
        self.inspect_record_source = source;
        self.inspect_status = .recovery_required;
    }

    fn publishFakeAbandonedRecord(
        self: *FakeRunner,
        allocator: std.mem.Allocator,
        request: WorkflowRequest,
    ) !void {
        const marker = self.inspect_deferred_acknowledgment orelse return;
        const request_sha256 =
            try production_backend.workflowProductRequestDigest(
                allocator,
                switch (request.operation) {
                    .install => .install,
                    .remove => .remove,
                    .upgrade_all => .upgrade_all,
                },
                .execute,
                request.selectors,
                request.options,
            );
        var record = try root_operation.create(allocator, .{
            .attempt_id = marker.attempt_id,
            .generation = 2,
            .install_root = live_root.logical_root_path,
            .backend = .legacy_dpkg,
            .operation = .{ .package_transaction = switch (request.operation) {
                .install => .install,
                .remove => .remove,
                .upgrade_all => .upgrade_all,
            } },
            .state = .completed,
            .phase = .provenance,
            .step = 2,
            .mutation_started = false,
            .outcome = .abandoned_before_mutation,
            .provenance = .not_required,
            .evidence = .{
                .exact_lock = .{
                    .schema = exact_lock.schema_id,
                    .version = exact_lock.schema_version,
                    .digest_sha256 = @splat(0x55),
                },
            },
            .request_sha256 = request_sha256,
            .policy_sha256 = @splat(0x32),
            .target_architecture = request.options.architecture,
            .reserved_unix = 90,
            .updated_unix = 100,
        });
        defer record.deinit();
        const source = try record.record.canonicalJson(self.allocator);
        if (self.inspect_record_source) |previous|
            self.allocator.free(previous);
        self.inspect_record_source = source;
    }

    fn inspect(
        context: *anyopaque,
        allocator: std.mem.Allocator,
    ) !RootInspection {
        const self: *FakeRunner = @ptrCast(@alignCast(context));
        self.inspect_calls += 1;
        if (self.inspect_record_source) |source| {
            var record = try root_operation.decode(
                allocator,
                source,
                root_operation.maximum_document_bytes,
            );
            errdefer record.deinit();
            var inspection = classifyRootRecord(
                record.record.state,
                record.record.provenance,
                record.record.attempt_id,
            );
            inspection.record = record;
            inspection.deferred_acknowledgment =
                self.inspect_deferred_acknowledgment;
            return inspection;
        }
        return .{
            .status = if (self.inspect_deferred_acknowledgment) |marker|
                switch (marker.state) {
                    .released, .abandoned, .acknowledged => .clean,
                    .bound,
                    .pending,
                    .pre_mutation_reconciliation_claim,
                    => .recovery_required,
                }
            else
                self.inspect_status,
            .attempt_id = if (self.inspect_status == .clean)
                null
            else
                @splat(0x91),
            .deferred_acknowledgment = self.inspect_deferred_acknowledgment,
        };
    }

    fn readRecoveryCompletion(
        context: *anyopaque,
        allocator: std.mem.Allocator,
    ) !?root_operation_completion.OwnedDocument {
        const self: *FakeRunner = @ptrCast(@alignCast(context));
        self.recovery_completion_reads += 1;
        const source = self.recovery_completion_source orelse return null;
        return try root_operation_completion.decode(
            allocator,
            source,
            root_operation_completion.maximum_document_bytes,
        );
    }
};

fn fakeRecoveryCompletion(
    allocator: std.mem.Allocator,
    request: WorkflowRequest,
    mismatch: FakeRunner.RecoveryCompletionMismatch,
    retained_attempt_id: ?[32]u8,
) !root_operation_completion.OwnedDocument {
    const production_operation: production_backend.WorkflowSemanticOperation = switch (request.operation) {
        .install => .install,
        .remove => .remove,
        .upgrade_all => .upgrade_all,
    };
    const semantic_operation: product_api.Operation = switch (request.operation) {
        .install => .install,
        .remove => .remove,
        .upgrade_all => .upgrade_all,
    };
    var original_request_digest = try production_backend.workflowProductRequestDigest(
        allocator,
        production_operation,
        .execute,
        request.selectors,
        request.options,
    );
    var recovery_request_digest = try production_backend.workflowProductRequestDigest(
        allocator,
        production_operation,
        .recover,
        request.selectors,
        request.options,
    );
    if (mismatch == .original_request) original_request_digest[0] ^= 0xff;
    if (mismatch == .discharge_request) recovery_request_digest[0] ^= 0xff;
    var record = try root_operation.create(allocator, .{
        .attempt_id = if (mismatch == .attempt)
            @splat(0x92)
        else
            retained_attempt_id orelse @splat(0x91),
        .generation = 4,
        .install_root = live_root.logical_root_path,
        .backend = .legacy_dpkg,
        .operation = .{ .package_transaction = semantic_operation },
        .state = .completed,
        .phase = .provenance,
        .step = 4,
        .mutation_started = true,
        .outcome = if (mismatch == .successful_outcome)
            .succeeded
        else
            .recovered,
        .provenance = .pending,
        .evidence = .{ .exact_lock = .{
            .schema = exact_lock.schema_id,
            .version = exact_lock.schema_version,
            .digest_sha256 = @splat(0x55),
        } },
        .request_sha256 = original_request_digest,
        .policy_sha256 = @splat(0x92),
        .target_architecture = request.options.architecture,
        .reserved_unix = 90,
        .updated_unix = 100,
    });
    defer record.deinit();
    return root_operation_completion.create(allocator, .{
        .record = record.record,
        .transaction_provenance = .{
            .status = .unavailable,
            .detail = "transaction provenance publication was interrupted",
        },
        .journal = .{
            .status = .absent,
            .detail = "no transaction journal remains",
        },
        .discharge = .{
            .surface = .package_transaction,
            .operation = "recover",
            .request_sha256 = recovery_request_digest,
        },
    });
}

fn reconstructPublishedRecoveryRecord(
    allocator: std.mem.Allocator,
    document: root_operation_completion.Document,
) !root_operation.OwnedRecord {
    var pending = try root_operation.create(allocator, .{
        .attempt_id = document.attempt_id,
        .generation = document.record_generation,
        .install_root = document.install_root,
        .backend = document.backend,
        .operation = document.operation,
        .state = .completed,
        .phase = .provenance,
        .step = document.step,
        .mutation_started = true,
        .outcome = document.outcome,
        .provenance = .pending,
        .evidence = .{
            .authorization_sha256 = document.authorization_sha256,
            .program_sha256 = document.program_sha256,
            .plan_sha256 = document.plan_sha256,
            .exact_lock = document.exact_lock,
            .database_generation_sha256 = document.database_generation_sha256,
            .artifact_evidence_sha256 = document.artifact_evidence_sha256,
        },
        .request_sha256 = document.request_sha256,
        .policy_sha256 = document.policy_sha256,
        .target_architecture = document.target_architecture,
        .foreign_architectures = document.foreign_architectures,
        .reserved_unix = document.reserved_unix,
        .updated_unix = document.updated_unix,
    });
    defer pending.deinit();
    const provenance_sha256 = root_operation.provenanceDigest(
        pending.record,
        .{
            .outcome = document.outcome,
            .document_sha256 = document.digest_sha256,
            .journal_archived = document.journal.status == .archived,
        },
    );
    return root_operation.create(allocator, .{
        .attempt_id = document.attempt_id,
        .generation = document.record_generation + 1,
        .install_root = document.install_root,
        .backend = document.backend,
        .operation = document.operation,
        .state = .completed,
        .phase = .provenance,
        .step = document.step + 1,
        .mutation_started = true,
        .outcome = document.outcome,
        .provenance = .published,
        .provenance_sha256 = provenance_sha256,
        .evidence = pending.record.evidence(),
        .request_sha256 = document.request_sha256,
        .policy_sha256 = document.policy_sha256,
        .target_architecture = document.target_architecture,
        .foreign_architectures = document.foreign_architectures,
        .reserved_unix = document.reserved_unix,
        .updated_unix = document.updated_unix + 1,
    });
}

const OuterGenerationRaceRunner = struct {
    inner: *FakeRunner,
    store: StateStore,
    state_path: []const u8,
    advanced: bool = false,

    fn interface(self: *OuterGenerationRaceRunner) LiveRootRunner {
        return .{
            .context = self,
            .routeFn = route,
            .workflowFn = workflow,
            .inspectFn = inspect,
            .readRecoveryCompletionFn = readRecoveryCompletion,
        };
    }

    fn route(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        backend: Backend,
        request: product_api.Request,
    ) !BackendResult {
        const self: *OuterGenerationRaceRunner = @ptrCast(@alignCast(context));
        return FakeRunner.route(self.inner, allocator, backend, request);
    }

    fn workflow(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        backend: Backend,
        request: WorkflowRequest,
    ) !BackendResult {
        const self: *OuterGenerationRaceRunner = @ptrCast(@alignCast(context));
        var result = try FakeRunner.workflow(
            self.inner,
            allocator,
            backend,
            request,
        );
        errdefer result.deinit();
        if (request.reconciliation_claim != null and !self.advanced) {
            var current = (try self.store.readActive(
                allocator,
                self.state_path,
            )) orelse return error.MissingActiveState;
            defer current.deinit();
            var mutating = try nextState(allocator, current.state, .{
                .phase = .mutating,
                .updated_unix = current.state.updated_unix + 1,
            });
            defer mutating.deinit();
            try self.store.compareAndSetFn(
                self.store.context,
                allocator,
                self.state_path,
                operation_state.Expected.fromState(current.state),
                mutating.state,
            );
            self.advanced = true;
        }
        return result;
    }

    fn inspect(
        context: *anyopaque,
        allocator: std.mem.Allocator,
    ) !RootInspection {
        const self: *OuterGenerationRaceRunner = @ptrCast(@alignCast(context));
        return FakeRunner.inspect(self.inner, allocator);
    }

    fn readRecoveryCompletion(
        context: *anyopaque,
        allocator: std.mem.Allocator,
    ) !?root_operation_completion.OwnedDocument {
        const self: *OuterGenerationRaceRunner = @ptrCast(@alignCast(context));
        return FakeRunner.readRecoveryCompletion(
            self.inner,
            allocator,
        );
    }
};

const FakeStateStore = struct {
    allocator: std.mem.Allocator,
    active_bytes: ?[]u8 = null,
    retained_bytes: ?[]u8 = null,
    request_bytes: ?[]u8 = null,
    recovery_completion_bytes: ?[]u8 = null,
    lower_acknowledgment: ?root_operation.DeferredAcknowledgment = null,
    reserve_calls: usize = 0,
    transition_calls: usize = 0,
    finish_calls: usize = 0,
    retained_transaction: bool = false,
    completion_published: bool = false,
    fail_finish: bool = false,
    fail_after_retain_once: bool = false,
    fail_after_active_cas_once: bool = false,
    fail_recovery_retain_once: bool = false,
    fail_inspect_active: bool = false,
    hide_inspected_active: bool = false,
    foreign_inspected_active: bool = false,
    inspect_active_calls: usize = 0,
    advance_on_inspect_call: ?usize = null,
    stale_finish_once: bool = false,
    compare_failure_once: ?anyerror = null,

    fn deinit(self: *FakeStateStore) void {
        if (self.active_bytes) |bytes| self.allocator.free(bytes);
        if (self.retained_bytes) |bytes| self.allocator.free(bytes);
        if (self.request_bytes) |bytes| self.allocator.free(bytes);
        if (self.recovery_completion_bytes) |bytes|
            self.allocator.free(bytes);
        self.* = undefined;
    }

    fn interface(self: *FakeStateStore) StateStore {
        return .{
            .context = self,
            .readActiveFn = readActive,
            .inspectActiveLockedFn = inspectActive,
            .reserveFn = reserve,
            .compareAndSetFn = compareAndSet,
            .finishFn = finish,
            .commitFn = commit,
            .clearCommittedFn = clearCommitted,
            .readRequestFn = readRequest,
            .readRetainedFn = readRetained,
            .retainAcknowledgmentFn = retainAcknowledgment,
            .readAcknowledgmentFn = readAcknowledgment,
            .retainTransactionFn = retainTransaction,
            .retainRecoveryCompletionFn = retainRecoveryCompletion,
            .readRecoveryCompletionFn = readRecoveryCompletion,
            .publishCompletionFn = publishCompletion,
            .verifyCompletionFn = verifyCompletion,
        };
    }

    fn readActive(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        _: []const u8,
    ) !?operation_state.OwnedState {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        const bytes = self.active_bytes orelse return null;
        return try operation_state.decode(
            allocator,
            bytes,
            operation_state.maximum_document_bytes,
        );
    }

    fn inspectActive(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        state_path: []const u8,
    ) !?operation_state.OwnedState {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        self.inspect_active_calls += 1;
        if (self.advance_on_inspect_call) |target| {
            if (target == self.inspect_active_calls) {
                var current = (try readActive(
                    context,
                    allocator,
                    state_path,
                )).?;
                defer current.deinit();
                var advanced = current.state;
                advanced.generation += 1;
                advanced.phase = .mutating;
                advanced.mutation_started = true;
                var owned = try operation_state.create(allocator, advanced);
                defer owned.deinit();
                const bytes = try owned.state.canonicalJson(self.allocator);
                self.allocator.free(self.active_bytes.?);
                self.active_bytes = bytes;
            }
        }
        if (self.fail_inspect_active) return error.InjectedActiveReadFailure;
        if (self.hide_inspected_active) return null;
        var active = (try readActive(context, allocator, state_path)) orelse
            return null;
        if (!self.foreign_inspected_active) return active;
        defer active.deinit();
        var foreign = active.state;
        foreign.attempt_id[0] ^= 0xff;
        return try operation_state.create(allocator, foreign);
    }

    fn reserve(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        _: OperationPaths,
        request_bytes: []const u8,
        state: operation_state.State,
    ) !void {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        if (self.active_bytes != null) return error.StateAlreadyExists;
        self.reserve_calls += 1;
        if (self.request_bytes) |bytes| self.allocator.free(bytes);
        self.request_bytes = try self.allocator.dupe(u8, request_bytes);
        self.active_bytes = try state.canonicalJson(allocator);
    }

    fn compareAndSet(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        _: []const u8,
        expected: operation_state.Expected,
        next: operation_state.State,
    ) !void {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        if (self.compare_failure_once) |failure| {
            self.compare_failure_once = null;
            return failure;
        }
        var current = (try readActive(context, allocator, "")).?;
        defer current.deinit();
        if (current.state.generation != expected.generation or
            !std.mem.eql(
                u8,
                &current.state.attempt_id,
                &expected.attempt_id,
            ) or
            !std.mem.eql(
                u8,
                &current.state.digest_sha256,
                &expected.digest_sha256,
            ))
            return error.StaleState;
        try operation_state.validateTransition(current.state, next);
        const bytes = try next.canonicalJson(self.allocator);
        self.allocator.free(self.active_bytes.?);
        self.active_bytes = bytes;
        self.transition_calls += 1;
    }

    fn commit(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        _: OperationPaths,
        expected: operation_state.Expected,
        final: operation_state.State,
    ) !void {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        if (self.stale_finish_once) {
            self.stale_finish_once = false;
            var current = (try readActive(context, allocator, "")).?;
            defer current.deinit();
            var advanced = current.state;
            advanced.generation += 1;
            advanced.phase = .mutating;
            advanced.mutation_started = true;
            var owned = try operation_state.create(allocator, advanced);
            defer owned.deinit();
            const bytes = try owned.state.canonicalJson(self.allocator);
            self.allocator.free(self.active_bytes.?);
            self.active_bytes = bytes;
            return error.StaleState;
        }
        if (self.fail_finish) return error.InjectedFinishFailure;
        if (self.fail_after_retain_once) {
            self.fail_after_retain_once = false;
            if (self.retained_bytes) |bytes| self.allocator.free(bytes);
            self.retained_bytes = try final.canonicalJson(self.allocator);
            return error.InjectedFinishCrash;
        }
        if (self.retained_bytes == null)
            self.retained_bytes = try final.canonicalJson(self.allocator);
        if (expected.generation != final.generation or
            !std.mem.eql(
                u8,
                &expected.digest_sha256,
                &final.digest_sha256,
            ))
            try compareAndSet(context, allocator, "", expected, final);
        if (self.fail_after_active_cas_once) {
            self.fail_after_active_cas_once = false;
            return error.InjectedFinishCrash;
        }
    }

    fn clearCommitted(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        _: OperationPaths,
        expected: operation_state.Expected,
    ) !void {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        var current = (try readActive(context, allocator, "")).?;
        defer current.deinit();
        if (current.state.generation != expected.generation or
            !std.mem.eql(
                u8,
                &current.state.digest_sha256,
                &expected.digest_sha256,
            )) return error.StaleState;
        self.allocator.free(self.active_bytes.?);
        self.active_bytes = null;
        self.finish_calls += 1;
    }

    fn finish(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        expected: operation_state.Expected,
        final: operation_state.State,
    ) !void {
        try commit(context, allocator, paths, expected, final);
        try clearCommitted(
            context,
            allocator,
            paths,
            operation_state.Expected.fromState(final),
        );
    }

    fn readRequest(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        _: OperationPaths,
    ) !api.OwnedRequest {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        return api.decodeRequest(allocator, self.request_bytes orelse
            return error.FileNotFound);
    }

    fn readRetained(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        _: OperationPaths,
    ) !?operation_state.OwnedState {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        const bytes = self.retained_bytes orelse return null;
        return try operation_state.decode(
            allocator,
            bytes,
            operation_state.maximum_document_bytes,
        );
    }

    fn retainAcknowledgment(
        context: *anyopaque,
        _: std.mem.Allocator,
        _: OperationPaths,
        acknowledgment: root_operation.DeferredAcknowledgment,
    ) !void {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        if (self.lower_acknowledgment) |existing| {
            if (!std.mem.eql(
                u8,
                &existing.digest_sha256,
                &acknowledgment.digest_sha256,
            )) return error.PublicationConflict;
            return;
        }
        self.lower_acknowledgment = acknowledgment;
    }

    fn readAcknowledgment(
        context: *anyopaque,
        _: std.mem.Allocator,
        _: OperationPaths,
    ) !?root_operation.DeferredAcknowledgment {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        return self.lower_acknowledgment;
    }

    fn retainTransaction(
        context: *anyopaque,
        _: std.mem.Allocator,
        paths: OperationPaths,
        _: []const u8,
        digest: [32]u8,
    ) !api.DocumentBinding {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        self.retained_transaction = true;
        return .{
            .path = paths.transaction_result,
            .schema = transaction_provenance.schema_id,
            .version = transaction_provenance.schema_version,
            .digest_sha256 = digest,
        };
    }

    fn readRecoveryCompletion(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        binding: api.DocumentBinding,
    ) !root_operation_completion.OwnedDocument {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, binding.path, paths.recovery_completion))
            return error.RecoveryCompletionMismatch;
        const source = self.recovery_completion_bytes orelse
            return error.FileNotFound;
        var document = try root_operation_completion.decode(
            allocator,
            source,
            root_operation_completion.maximum_document_bytes,
        );
        errdefer document.deinit();
        if (!std.mem.eql(
            u8,
            &document.document.digest_sha256,
            &binding.digest_sha256,
        )) return error.RecoveryCompletionMismatch;
        return document;
    }

    fn retainRecoveryCompletion(
        context: *anyopaque,
        _: std.mem.Allocator,
        paths: OperationPaths,
        source: []const u8,
        digest: [32]u8,
    ) !api.DocumentBinding {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        if (self.fail_recovery_retain_once) {
            self.fail_recovery_retain_once = false;
            return error.InjectedRecoveryRetainFailure;
        }
        self.retained_transaction = true;
        if (self.recovery_completion_bytes) |previous|
            self.allocator.free(previous);
        self.recovery_completion_bytes = try self.allocator.dupe(
            u8,
            source,
        );
        return .{
            .path = paths.recovery_completion,
            .schema = root_operation_completion.schema_id,
            .version = root_operation_completion.schema_version,
            .digest_sha256 = digest,
        };
    }

    fn publishCompletion(
        context: *anyopaque,
        _: std.mem.Allocator,
        paths: OperationPaths,
        input: CompletionInput,
    ) !api.CompletionBinding {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        self.completion_published = true;
        return .{
            .document = .{
                .path = paths.completion,
                .schema = completion_schema_id,
                .version = completion_schema_version,
                .digest_sha256 = @splat(0x77),
            },
            .completed_attempt_id = input.attempt_id,
        };
    }

    fn verifyCompletion(
        context: *anyopaque,
        _: std.mem.Allocator,
        _: OperationPaths,
        input: CompletionInput,
        expected: api.CompletionBinding,
    ) !void {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        if (!self.completion_published or
            !std.mem.eql(
                u8,
                &expected.completed_attempt_id,
                &input.attempt_id,
            ))
            return error.CompletionMismatch;
    }
};

const FakeVerifier = struct {
    lock_valid: bool = true,
    transaction_valid: bool = true,
    lock_failure: ?VerificationError = null,
    transaction_failure: ?VerificationError = null,
    lock_failure_on_check: ?struct {
        check: usize,
        failure: VerificationError,
    } = null,
    transaction_failure_on_check: ?struct {
        check: usize,
        failure: VerificationError,
    } = null,
    lock_digest: [32]u8 = @splat(0x55),
    transaction_digest: [32]u8 = @splat(0x66),
    transaction_source: ?[]const u8 = null,
    lock_checks: usize = 0,
    different_lock_check: ?usize = null,
    different_semantic_check: ?usize = null,
    transaction_checks: usize = 0,

    fn interface(self: *FakeVerifier) ResultVerifier {
        return .{
            .context = self,
            .verifyLockFn = verifyLock,
            .verifyTransactionFn = verifyTransaction,
        };
    }

    fn verifyLock(
        context: *anyopaque,
        _: std.mem.Allocator,
        path: []const u8,
        _: []const u8,
        expected_request_sha256: [32]u8,
    ) VerificationError!VerifiedLock {
        const self: *FakeVerifier = @ptrCast(@alignCast(context));
        self.lock_checks += 1;
        if (self.lock_failure_on_check) |injected|
            if (injected.check == self.lock_checks)
                return injected.failure;
        if (self.lock_failure) |failure| return failure;
        if (!self.lock_valid) return error.OperationalVerificationFailure;
        const digest = if (self.different_lock_check == self.lock_checks)
            [_]u8{0x77} ** 32
        else
            self.lock_digest;
        var semantic_request_sha256 = expected_request_sha256;
        if (self.different_semantic_check == self.lock_checks)
            semantic_request_sha256[0] ^= 0xff;
        return .{
            .binding = .{
                .path = path,
                .schema = exact_lock.schema_id,
                .version = exact_lock.schema_version,
                .digest_sha256 = digest,
            },
            .semantic_request_sha256 = semantic_request_sha256,
        };
    }

    fn verifyTransaction(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        _: api.DocumentBinding,
        _: []const u8,
    ) VerificationError!VerifiedTransaction {
        const self: *FakeVerifier = @ptrCast(@alignCast(context));
        self.transaction_checks += 1;
        if (self.transaction_failure_on_check) |injected|
            if (injected.check == self.transaction_checks)
                return injected.failure;
        if (self.transaction_failure) |failure| return failure;
        if (!self.transaction_valid)
            return error.OperationalVerificationFailure;
        return .{
            .bytes = try allocator.dupe(
                u8,
                self.transaction_source orelse "{\"verified\":true}",
            ),
            .binding = .{
                .path = path,
                .schema = transaction_provenance.schema_id,
                .version = transaction_provenance.schema_version,
                .digest_sha256 = self.transaction_digest,
            },
            .allocator = allocator,
        };
    }
};

const OneShotOperationalLockVerifier = struct {
    inner: ResultVerifier,
    failed: bool = false,

    fn interface(self: *OneShotOperationalLockVerifier) ResultVerifier {
        return .{
            .context = self,
            .verifyLockFn = verifyLock,
            .verifyTransactionFn = verifyTransaction,
        };
    }

    fn verifyLock(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        architecture: []const u8,
        expected_request_sha256: [32]u8,
    ) VerificationError!VerifiedLock {
        const self: *OneShotOperationalLockVerifier =
            @ptrCast(@alignCast(context));
        if (!self.failed) {
            self.failed = true;
            return error.OperationalVerificationFailure;
        }
        return self.inner.verifyLockFn(
            self.inner.context,
            allocator,
            path,
            architecture,
            expected_request_sha256,
        );
    }

    fn verifyTransaction(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        lock: api.DocumentBinding,
        architecture: []const u8,
    ) VerificationError!VerifiedTransaction {
        const self: *OneShotOperationalLockVerifier =
            @ptrCast(@alignCast(context));
        return self.inner.verifyTransactionFn(
            self.inner.context,
            allocator,
            path,
            lock,
            architecture,
        );
    }
};

const FakeSources = struct {
    next_id: [32]u8 = @splat(0x33),
    now_value: i64 = 100,

    fn ids(self: *FakeSources) IdSource {
        return .{ .context = self, .nextFn = next };
    }

    fn clock(self: *FakeSources) Clock {
        return .{ .context = self, .nowFn = now };
    }

    fn next(context: *anyopaque) ![32]u8 {
        const self: *FakeSources = @ptrCast(@alignCast(context));
        return self.next_id;
    }

    fn now(context: *anyopaque) i64 {
        const self: *FakeSources = @ptrCast(@alignCast(context));
        return self.now_value;
    }
};

const FakeCompletionCrash = struct {
    boundary: CompletionBoundary,
    triggered: bool = false,

    fn interface(self: *FakeCompletionCrash) CompletionCrash {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(context: *anyopaque, boundary: CompletionBoundary) !void {
        const self: *FakeCompletionCrash = @ptrCast(@alignCast(context));
        if (!self.triggered and boundary == self.boundary) {
            self.triggered = true;
            return error.InjectedCompletionCrash;
        }
    }
};

const TestFinishCrash = struct {
    triggered: bool = false,

    fn interface(self: *TestFinishCrash) FinishCrash {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(context: *anyopaque, _: FinishBoundary) !void {
        const self: *TestFinishCrash = @ptrCast(@alignCast(context));
        if (!self.triggered) {
            self.triggered = true;
            return error.InjectedFinishCrash;
        }
    }
};

const RetainedCommitBarrier = struct {
    mutex: std.Io.Mutex = .init,
    condition: std.Io.Condition = .init,
    reached: bool = false,
    released: bool = false,
    aborted: bool = false,

    fn interface(self: *RetainedCommitBarrier) RetainedDurability {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(
        context: *anyopaque,
        boundary: RetainedDurabilityBoundary,
    ) !void {
        if (boundary != .before_active_commit) return;
        const self: *RetainedCommitBarrier = @ptrCast(@alignCast(context));
        self.mutex.lockUncancelable(std.testing.io);
        defer self.mutex.unlock(std.testing.io);
        self.reached = true;
        self.condition.broadcast(std.testing.io);
        while (!self.released)
            self.condition.waitUncancelable(std.testing.io, &self.mutex);
    }

    fn waitReached(self: *RetainedCommitBarrier) bool {
        self.mutex.lockUncancelable(std.testing.io);
        defer self.mutex.unlock(std.testing.io);
        while (!self.reached and !self.aborted)
            self.condition.waitUncancelable(std.testing.io, &self.mutex);
        return self.reached;
    }

    fn release(self: *RetainedCommitBarrier) void {
        self.mutex.lockUncancelable(std.testing.io);
        defer self.mutex.unlock(std.testing.io);
        self.released = true;
        self.condition.broadcast(std.testing.io);
    }

    fn abort(self: *RetainedCommitBarrier) void {
        self.mutex.lockUncancelable(std.testing.io);
        defer self.mutex.unlock(std.testing.io);
        self.aborted = true;
        self.condition.broadcast(std.testing.io);
    }
};

fn runRetainedCommitOverlapScenario() !void {
    const root_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "/root/debz-retained-commit-overlap-{d}",
        .{std.os.linux.getpid()},
    );
    defer std.testing.allocator.free(root_path);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, root_path) catch {};
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{root_path},
    );
    defer std.testing.allocator.free(state_path);
    const attempt_id: [32]u8 = @splat(0x4b);
    var paths = try pathsFor(
        std.testing.allocator,
        state_path,
        attempt_id,
    );
    defer paths.deinit(std.testing.allocator);
    var initial = try testInitialState(
        std.testing.allocator,
        attempt_id,
    );
    defer initial.deinit();
    var profile_loaded = try nextState(
        std.testing.allocator,
        initial.state,
        .{
            .phase = .profile_loaded,
            .updated_unix = 105,
        },
    );
    defer profile_loaded.deinit();
    var authenticated = try nextState(
        std.testing.allocator,
        profile_loaded.state,
        .{
            .phase = .authenticated,
            .updated_unix = 108,
        },
    );
    defer authenticated.deinit();
    var downloaded = try nextState(
        std.testing.allocator,
        authenticated.state,
        .{
            .phase = .downloaded,
            .exact_lock = .{
                .path = paths.exact_lock,
                .schema = exact_lock.schema_id,
                .version = exact_lock.schema_version,
                .digest_sha256 = @splat(0x51),
            },
            .updated_unix = 110,
        },
    );
    defer downloaded.deinit();
    var mutating = try nextState(
        std.testing.allocator,
        downloaded.state,
        .{
            .phase = .mutating,
            .updated_unix = 120,
        },
    );
    defer mutating.deinit();
    var verifying = try nextState(
        std.testing.allocator,
        mutating.state,
        .{
            .phase = .verifying,
            .transaction_result = .{
                .path = paths.transaction_result,
                .schema = transaction_provenance.schema_id,
                .version = transaction_provenance.schema_version,
                .digest_sha256 = @splat(0x52),
            },
            .updated_unix = 130,
        },
    );
    defer verifying.deinit();
    var final = try nextState(
        std.testing.allocator,
        verifying.state,
        .{
            .phase = .completed,
            .outcome = .succeeded,
            .root_operation_completion = .{
                .document = .{
                    .path = paths.completion,
                    .schema = completion_schema_id,
                    .version = completion_schema_version,
                    .digest_sha256 = @splat(0x56),
                },
                .completed_attempt_id = attempt_id,
            },
            .updated_unix = 200,
        },
    );
    defer final.deinit();
    var barrier: RetainedCommitBarrier = .{};
    var owner_store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .retained_durability = barrier.interface(),
    };
    const owner = owner_store.interface();
    try owner.reserveFn(
        owner.context,
        std.testing.allocator,
        paths,
        "{}",
        initial.state,
    );
    try owner.compareAndSetFn(
        owner.context,
        std.testing.allocator,
        state_path,
        operation_state.Expected.fromState(initial.state),
        profile_loaded.state,
    );
    try owner.compareAndSetFn(
        owner.context,
        std.testing.allocator,
        state_path,
        operation_state.Expected.fromState(profile_loaded.state),
        authenticated.state,
    );
    try owner.compareAndSetFn(
        owner.context,
        std.testing.allocator,
        state_path,
        operation_state.Expected.fromState(authenticated.state),
        downloaded.state,
    );
    try owner.compareAndSetFn(
        owner.context,
        std.testing.allocator,
        state_path,
        operation_state.Expected.fromState(downloaded.state),
        mutating.state,
    );
    try owner.compareAndSetFn(
        owner.context,
        std.testing.allocator,
        state_path,
        operation_state.Expected.fromState(mutating.state),
        verifying.state,
    );
    const OwnerContext = struct {
        store: StateStore,
        paths: OperationPaths,
        expected: operation_state.Expected,
        final: operation_state.State,
        barrier: *RetainedCommitBarrier,
        failure: ?anyerror = null,

        fn run(context: *@This()) void {
            context.store.commitFn(
                context.store.context,
                std.heap.page_allocator,
                context.paths,
                context.expected,
                context.final,
            ) catch |err| {
                context.failure = err;
                context.barrier.abort();
            };
        }
    };
    var owner_context: OwnerContext = .{
        .store = owner,
        .paths = paths,
        .expected = operation_state.Expected.fromState(verifying.state),
        .final = final.state,
        .barrier = &barrier,
    };
    const owner_thread = try std.Thread.spawn(
        .{},
        OwnerContext.run,
        .{&owner_context},
    );
    if (!barrier.waitReached()) {
        owner_thread.join();
        return owner_context.failure orelse error.OwnerCommitAborted;
    }
    var contender_store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .wait_ms = 0,
    };
    const contender = contender_store.interface();
    try std.testing.expectError(
        error.LockTimeout,
        contender.commitFn(
            contender.context,
            std.testing.allocator,
            paths,
            operation_state.Expected.fromState(verifying.state),
            final.state,
        ),
    );
    barrier.release();
    owner_thread.join();
    if (owner_context.failure) |failure| return failure;
    var active = (try owner.readActive(
        std.testing.allocator,
        state_path,
    )) orelse return error.MissingActiveState;
    defer active.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &final.state.digest_sha256,
        &active.state.digest_sha256,
    );
    var retained = (try owner.readRetained(
        std.testing.allocator,
        paths,
    )) orelse return error.MissingRetainedState;
    defer retained.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &final.state.digest_sha256,
        &retained.state.digest_sha256,
    );
}

fn runRetainedCommitOverlapWatchdog(timeout_ms: u64) !void {
    const linux = std.os.linux;
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(forked);
    if (pid == 0) {
        runRetainedCommitOverlapScenario() catch |err| {
            std.debug.print("retained commit overlap failed: {s}\n", .{
                @errorName(err),
            });
            linux.exit_group(111);
        };
        linux.exit_group(0);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        var status: u32 = 0;
        while (linux.errno(linux.waitpid(pid, &status, 0)) == .INTR) {}
    };
    const started = std.Io.Clock.awake.now(std.testing.io);
    while (true) {
        var status: u32 = 0;
        const waited = linux.waitpid(pid, &status, linux.W.NOHANG);
        switch (linux.errno(waited)) {
            .SUCCESS => if (waited != 0) {
                reaped = true;
                if (!linux.W.IFEXITED(status) or
                    linux.W.EXITSTATUS(status) != 0)
                    return error.RetainedCommitOverlapFailed;
                return;
            },
            .INTR => continue,
            else => return error.WaitFailed,
        }
        if (started.durationTo(
            std.Io.Clock.awake.now(std.testing.io),
        ).toMilliseconds() >= timeout_ms) {
            _ = linux.kill(pid, .KILL);
            while (true) {
                const final_wait = linux.waitpid(pid, &status, 0);
                switch (linux.errno(final_wait)) {
                    .SUCCESS => break,
                    .INTR => continue,
                    else => return error.WaitFailed,
                }
            }
            reaped = true;
            return error.RetainedCommitOverlapTimedOut;
        }
        var request: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
        var remaining: linux.timespec = undefined;
        _ = linux.nanosleep(&request, &remaining);
    }
}

const ProductionRunnerProcess = struct {
    io: std.Io,
    dpkg: std.Io.Dir,

    fn interface(
        self: *ProductionRunnerProcess,
    ) @import("transaction_executor.zig").ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(
        context: *anyopaque,
        invocation: @import("transaction_executor.zig").Invocation,
    ) !@import("transaction_executor.zig").ProcessResult {
        const self: *ProductionRunnerProcess = @ptrCast(@alignCast(context));
        if (invocation.phase == .remove) {
            if (self.dpkg.access(self.io, "mutation-observed", .{})) {
                return .{ .termination = .{ .exited = 99 } };
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            }
            try self.dpkg.writeFile(self.io, .{
                .sub_path = "mutation-observed",
                .data = "once",
            });
            try self.dpkg.writeFile(self.io, .{
                .sub_path = "status",
                .data = "",
            });
        }
        return .{ .termination = .{ .exited = 0 } };
    }
};

const ProductionRunnerFixture = struct {
    allocator: std.mem.Allocator,
    root_path: []u8,
    source_path: []u8,
    keyring_path: []u8,
    cache_path: []u8,
    state_path: []u8,
    source_paths: [1][]const u8,
    keyring_paths: [1][]const u8,
    dpkg: std.Io.Dir,
    mounted: bool = true,

    fn init(allocator: std.mem.Allocator) !ProductionRunnerFixture {
        const fixture = @import("fixtures/openpgp.zig");
        cleanupProductionRootArtifacts();
        const root_path = try std.fmt.allocPrint(
            allocator,
            "/run/debz-orchestrator-production-{d}",
            .{std.os.linux.getpid()},
        );
        errdefer allocator.free(root_path);
        std.Io.Dir.cwd().deleteTree(std.testing.io, root_path) catch {};
        const repository_packages_directory = try std.fmt.allocPrint(
            allocator,
            "{s}/repo/dists/stable/main/binary-amd64",
            .{root_path},
        );
        defer allocator.free(repository_packages_directory);
        try std.Io.Dir.cwd().createDirPath(
            std.testing.io,
            repository_packages_directory,
        );
        const dpkg_path = try std.fmt.allocPrint(
            allocator,
            "{s}/dpkg",
            .{root_path},
        );
        defer allocator.free(dpkg_path);
        try std.Io.Dir.cwd().createDirPath(std.testing.io, dpkg_path);
        const state_path = try std.fmt.allocPrint(
            allocator,
            "/root/debz-orchestrator-production-state-{d}",
            .{std.os.linux.getpid()},
        );
        errdefer allocator.free(state_path);
        std.Io.Dir.cwd().deleteTree(std.testing.io, state_path) catch {};
        const cache_path = try std.fmt.allocPrint(
            allocator,
            "{s}/cache",
            .{root_path},
        );
        errdefer allocator.free(cache_path);
        const source_path = try std.fmt.allocPrint(
            allocator,
            "{s}/sources.list",
            .{root_path},
        );
        errdefer allocator.free(source_path);
        const keyring_path = try std.fmt.allocPrint(
            allocator,
            "{s}/keyring.gpg",
            .{root_path},
        );
        errdefer allocator.free(keyring_path);
        const repository_path = try std.fmt.allocPrint(
            allocator,
            "{s}/repo",
            .{root_path},
        );
        defer allocator.free(repository_path);
        const source = try std.fmt.allocPrint(
            allocator,
            "deb [arch=amd64 signed-by={s}] file://{s} stable main\n",
            .{ keyring_path, repository_path },
        );
        defer allocator.free(source);
        try writeAbsoluteTestFile(source_path, source);
        try writeAbsoluteTestFile(keyring_path, &fixture.keyring);
        const in_release_path = try std.fmt.allocPrint(
            allocator,
            "{s}/repo/dists/stable/InRelease",
            .{root_path},
        );
        defer allocator.free(in_release_path);
        try writeAbsoluteTestFile(
            in_release_path,
            &fixture.repository_in_release,
        );
        const packages_path = try std.fmt.allocPrint(
            allocator,
            "{s}/repo/dists/stable/main/binary-amd64/Packages",
            .{root_path},
        );
        defer allocator.free(packages_path);
        try writeAbsoluteTestFile(packages_path, &fixture.repository_packages);
        const status_path = try std.fmt.allocPrint(
            allocator,
            "{s}/status",
            .{dpkg_path},
        );
        defer allocator.free(status_path);
        try writeAbsoluteTestFile(status_path,
            \\Package: removable
            \\Status: install ok installed
            \\Priority: optional
            \\Architecture: amd64
            \\Version: 1
            \\
        );
        const source_z = try allocator.dupeZ(u8, dpkg_path);
        defer allocator.free(source_z);
        switch (std.os.linux.errno(std.os.linux.mount(
            source_z,
            "/var/lib/dpkg",
            null,
            std.os.linux.MS.BIND,
            0,
        ))) {
            .SUCCESS => {},
            else => return error.NamespaceUnavailable,
        }
        errdefer _ = std.os.linux.umount2("/var/lib/dpkg", std.os.linux.MNT.DETACH);
        var dpkg = try std.Io.Dir.cwd().openDir(
            std.testing.io,
            dpkg_path,
            .{},
        );
        errdefer dpkg.close(std.testing.io);
        return .{
            .allocator = allocator,
            .root_path = root_path,
            .source_path = source_path,
            .keyring_path = keyring_path,
            .cache_path = cache_path,
            .state_path = state_path,
            .source_paths = .{source_path},
            .keyring_paths = .{keyring_path},
            .dpkg = dpkg,
        };
    }

    fn deinit(self: *ProductionRunnerFixture) void {
        if (self.mounted) {
            _ = std.os.linux.umount2(
                "/var/lib/dpkg",
                std.os.linux.MNT.DETACH,
            );
            self.mounted = false;
        }
        self.dpkg.close(std.testing.io);
        std.Io.Dir.cwd().deleteTree(std.testing.io, self.root_path) catch {};
        std.Io.Dir.cwd().deleteTree(std.testing.io, self.state_path) catch {};
        self.allocator.free(self.root_path);
        self.allocator.free(self.source_path);
        self.allocator.free(self.keyring_path);
        self.allocator.free(self.cache_path);
        self.allocator.free(self.state_path);
        cleanupProductionRootArtifacts();
        self.* = undefined;
    }
};

fn cleanupProductionRootArtifacts() void {
    inline for (.{
        "/" ++ root_operation.record_path,
        "/" ++ root_operation.deferred_ack_path,
        "/" ++ root_operation_completion.document_path,
    }) |path|
        std.Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};
}

const ProcessDeathCompletionCrash = struct {
    boundary: CompletionBoundary,

    fn interface(self: *ProcessDeathCompletionCrash) CompletionCrash {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(context: *anyopaque, boundary: CompletionBoundary) !void {
        const self: *ProcessDeathCompletionCrash =
            @ptrCast(@alignCast(context));
        if (boundary == self.boundary)
            std.os.linux.exit_group(91);
    }
};

const ProcessDeathFinishCrash = struct {
    fn interface(self: *ProcessDeathFinishCrash) FinishCrash {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(_: *anyopaque, _: FinishBoundary) !void {
        std.os.linux.exit_group(91);
    }
};

const ProcessDeathStateWriteCrash = struct {
    fn interface(
        self: *ProcessDeathStateWriteCrash,
    ) operation_state.WriteHooks {
        return .{ .context = self, .runFn = hit };
    }

    fn hit(
        _: ?*anyopaque,
        boundary: operation_state.WriteBoundary,
    ) !void {
        if (boundary == .after_rename)
            std.os.linux.exit_group(91);
    }
};

const CleanInspectionProcessBarrier = struct {
    ready_fd: i32,
    release_fd: i32,

    fn interface(self: *CleanInspectionProcessBarrier) CompletionCrash {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(context: *anyopaque, boundary: CompletionBoundary) !void {
        if (boundary != .after_clean_recovery_inspection) return;
        const self: *CleanInspectionProcessBarrier =
            @ptrCast(@alignCast(context));
        try PrivateLiveRootRunner.writeTransport(self.ready_fd, "R");
        var byte: [1]u8 = undefined;
        while (true) {
            const read = std.os.linux.read(self.release_fd, &byte, 1);
            switch (std.os.linux.errno(read)) {
                .SUCCESS => {
                    if (read != 1) return error.BarrierClosed;
                    return;
                },
                .INTR => continue,
                else => return error.BarrierReadFailed,
            }
        }
    }
};

const CommitDurabilityFault = struct {
    armed: bool = false,
    fail_after_rename: bool = false,
    fail_resync: bool = false,
    fail_retained_publication_dir: bool = false,
    fail_retained_file_sync: bool = false,
    fail_retained_operation_dir_sync: bool = false,

    fn completionInterface(self: *CommitDurabilityFault) CompletionCrash {
        return .{ .context = self, .hitFn = hitCompletion };
    }

    fn stateHooks(self: *CommitDurabilityFault) operation_state.WriteHooks {
        return .{ .context = self, .runFn = hitState };
    }

    fn directoryInterface(self: *CommitDurabilityFault) DirectorySync {
        return .{ .context = self, .syncFn = syncDirectoryFault };
    }

    fn retainedInterface(self: *CommitDurabilityFault) RetainedDurability {
        return .{ .context = self, .hitFn = hitRetained };
    }

    fn hitCompletion(
        context: *anyopaque,
        boundary: CompletionBoundary,
    ) !void {
        const self: *CommitDurabilityFault = @ptrCast(@alignCast(context));
        if (boundary == .after_completion_published)
            self.armed = true;
    }

    fn hitState(
        context: ?*anyopaque,
        boundary: operation_state.WriteBoundary,
    ) !void {
        const self: *CommitDurabilityFault =
            @ptrCast(@alignCast(context.?));
        if (boundary == .after_rename and self.armed and
            self.fail_after_rename)
        {
            self.fail_after_rename = false;
            return error.InjectedPostRenameFailure;
        }
        if (boundary == .before_durability_resync and self.fail_resync)
            return error.InjectedDurabilityResyncFailure;
    }

    fn syncDirectoryFault(
        context: *anyopaque,
        io: std.Io,
        dir: std.Io.Dir,
        boundary: DirectorySyncBoundary,
    ) !void {
        const self: *CommitDurabilityFault = @ptrCast(@alignCast(context));
        if (boundary == .publication_directory and self.armed and
            self.fail_retained_publication_dir)
        {
            self.fail_retained_publication_dir = false;
            return error.InjectedRetainedPublicationSyncFailure;
        }
        if (boundary == .retained_operation_directory and
            self.fail_retained_operation_dir_sync)
            return error.InjectedRetainedDirectorySyncFailure;
        try syncDirectory(io, dir);
    }

    fn hitRetained(
        context: *anyopaque,
        boundary: RetainedDurabilityBoundary,
    ) !void {
        const self: *CommitDurabilityFault = @ptrCast(@alignCast(context));
        if (boundary == .before_file_sync and self.fail_retained_file_sync)
            return error.InjectedRetainedFileSyncFailure;
    }
};

const ProcessDeathTransportCrash = struct {
    calls_to_skip: usize = 0,

    fn interface(self: *ProcessDeathTransportCrash) TransportCrash {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(context: *anyopaque, _: TransportBoundary) !void {
        const self: *ProcessDeathTransportCrash =
            @ptrCast(@alignCast(context));
        if (self.calls_to_skip != 0) {
            self.calls_to_skip -= 1;
            return;
        }
        std.os.linux.exit_group(92);
    }
};

const AbandonAfterReservationTransport = struct {
    io: std.Io,
    disrupted_path: []const u8,
    held_path: []const u8,
    calls_to_skip: usize = 1,
    moved: bool = false,

    fn interface(self: *AbandonAfterReservationTransport) TransportCrash {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(context: *anyopaque, _: TransportBoundary) !void {
        const self: *AbandonAfterReservationTransport =
            @ptrCast(@alignCast(context));
        if (self.calls_to_skip != 0) {
            self.calls_to_skip -= 1;
            return;
        }
        if (self.moved) return;
        try std.Io.Dir.cwd().rename(
            self.disrupted_path,
            std.Io.Dir.cwd(),
            self.held_path,
            self.io,
        );
        self.moved = true;
    }
};

const ProductionChildCrash = struct {
    boundary: production_backend.CompletionPoint,

    fn interface(
        self: *ProductionChildCrash,
    ) production_backend.CompletionCrash {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(
        context: *anyopaque,
        boundary: production_backend.CompletionPoint,
    ) !void {
        const self: *ProductionChildCrash = @ptrCast(@alignCast(context));
        if (boundary == self.boundary)
            return error.InjectedProductionChildCrash;
    }
};

fn expectForeignProductionReservationBlocked(
    fixture: *ProductionRunnerFixture,
    prepared: Preparation,
    runner: LiveRootRunner,
    backend: Backend,
    foreign_id: [32]u8,
) !void {
    const foreign_state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}-foreign",
        .{fixture.state_path},
    );
    defer std.testing.allocator.free(foreign_state_path);
    var foreign_profile: FakeProfileLoader = .{
        .state_path = foreign_state_path,
        .cache_path = fixture.cache_path,
        .source_paths = fixture.source_paths,
        .keyring_paths = fixture.keyring_paths,
    };
    var loaded = try foreign_profile.interface().load(
        std.testing.allocator,
        "/profile.json",
    );
    defer loaded.deinit();
    var result = try runner.workflow(
        std.testing.allocator,
        backend,
        .{
            .operation = .remove,
            .mode = .reserve,
            .selectors = &.{.{ .name = "removable" }},
            .options = executeOptions(
                loaded.view,
                prepared.paths.exact_lock,
            ),
            .orchestration_id = foreign_id,
        },
    );
    defer result.deinit();
    try std.testing.expectEqual(
        product_api.ExitStatus.recovery,
        result.result.exit_status,
    );
}

const MarkerLossRecordKind = enum {
    reserved,
    preflight,
    mutation_pending,
    mutating,
    verifying,
    completed_pending,
    completed_published,
    recovery_required,
    recovering,
    unknown,
};

fn markerLossRecord(
    allocator: std.mem.Allocator,
    kind: MarkerLossRecordKind,
) ![]u8 {
    if (kind == .unknown)
        return allocator.dupe(u8, "{\"legacy\":\"unknown\"}\n");
    const state: root_operation.State = switch (kind) {
        .reserved => .reserved,
        .preflight => .preflight,
        .mutation_pending => .mutation_pending,
        .mutating => .mutating,
        .verifying => .verifying,
        .completed_pending, .completed_published => .completed,
        .recovery_required => .recovery_required,
        .recovering => .recovering,
        .unknown => unreachable,
    };
    const completed = state == .completed;
    const mutation_started = switch (state) {
        .reserved, .preflight, .mutation_pending => false,
        else => true,
    };
    const provenance: root_operation.ProvenanceState =
        if (kind == .completed_published) .published else .pending;
    var record = try root_operation.create(allocator, .{
        .attempt_id = @splat(0xe1),
        .generation = 1,
        .install_root = live_root.logical_root_path,
        .backend = .legacy_dpkg,
        .operation = .{ .package_transaction = .remove },
        .state = state,
        .phase = switch (kind) {
            .reserved => .reserved,
            .preflight, .mutation_pending => .preflight,
            .mutating, .recovery_required, .recovering => .mutation,
            .verifying => .verification,
            .completed_pending, .completed_published => .provenance,
            .unknown => unreachable,
        },
        .step = 1,
        .mutation_started = mutation_started,
        .outcome = if (completed) .succeeded else .pending,
        .provenance = provenance,
        .provenance_sha256 = if (provenance == .published)
            @splat(0xe2)
        else
            null,
        .request_sha256 = @splat(0xe3),
        .policy_sha256 = @splat(0xe4),
        .target_architecture = "amd64",
        .reserved_unix = 1,
        .updated_unix = 2,
    });
    defer record.deinit();
    return record.record.canonicalJson(allocator);
}

fn writeAbsoluteTestFile(path: []const u8, bytes: []const u8) !void {
    const file = try std.Io.Dir.cwd().createFile(std.testing.io, path, .{
        .truncate = true,
    });
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, bytes);
}

const Harness = struct {
    profile: FakeProfileLoader = .{},
    backend: FakeBackend = .{},
    runner: FakeRunner = undefined,
    store: FakeStateStore,
    verifier: FakeVerifier = .{},
    sources: FakeSources = .{},
    engine: Engine = undefined,

    fn init(allocator: std.mem.Allocator) Harness {
        return .{
            .runner = .{ .allocator = allocator },
            .store = .{ .allocator = allocator },
        };
    }

    fn rebind(self: *Harness) void {
        self.engine = .{
            .profiles = self.profile.interface(),
            .runner = self.runner.interface(),
            .backend = self.backend.interface(),
            .store = self.store.interface(),
            .verifier = self.verifier.interface(),
            .ids = self.sources.ids(),
            .clock = self.sources.clock(),
        };
    }

    fn deinit(self: *Harness) void {
        self.runner.deinit();
        self.store.deinit();
        self.* = undefined;
    }
};

fn mutationRequest(
    operation: api.Operation,
    packages: []const []const u8,
) api.Request {
    return .{
        .operation = operation,
        .profile_path = "/profile.json",
        .packages = packages,
    };
}

fn expectReady(outcome: PrepareOutcome) !Preparation {
    return switch (outcome) {
        .ready => |prepared| prepared,
        .result => |value| {
            var result = value;
            defer result.deinit();
            std.debug.print("unexpected result: {s}\n", .{result.summary});
            return error.ExpectedPreparation;
        },
    };
}

test "apt_system_orchestrator.test.required_privileged.recovery preflight lock-acquisition death permits only a fresh request after stable proof" {
    try requirePrivilegedProductionTest();
    const root_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "/root/debz-apt-preflight-restart-{d}",
        .{std.os.linux.getpid()},
    );
    defer std.testing.allocator.free(root_path);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, root_path) catch {};
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{root_path},
    );
    defer std.testing.allocator.free(state_path);

    var profile: FakeProfileLoader = .{ .state_path = state_path };
    var backend: FakeBackend = .{};
    var runner: FakeRunner = .{
        .allocator = std.testing.allocator,
        .fail_mode = .reserve,
    };
    var store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    var verifier: FakeVerifier = .{};
    var sources: FakeSources = .{};
    var engine: Engine = .{
        .profiles = profile.interface(),
        .runner = runner.interface(),
        .backend = backend.interface(),
        .store = store.interface(),
        .verifier = verifier.interface(),
        .ids = sources.ids(),
        .clock = sources.clock(),
    };
    var prepared = try expectReady(try engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    var interrupted = try engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer interrupted.deinit();
    try std.testing.expectEqual(api.Outcome.configuration, interrupted.outcome);
    try std.testing.expect(!interrupted.changed);
    try std.testing.expectEqual(@as(usize, 0), backend.execute_calls);
    var active = try store.interface().readActive(
        std.testing.allocator,
        state_path,
    );
    defer if (active) |*owned| owned.deinit();
    try std.testing.expect(active == null);

    runner.fail_mode = null;
    sources.next_id = @splat(0x72);
    var transaction = try transaction_provenance.create(
        std.testing.allocator,
        .{
            .target_architecture = "amd64",
            .request_sha256 = @splat(0x41),
            .solver_policy_sha256 = @splat(0x42),
            .executor_policy_sha256 = @splat(0x43),
            .plan_sha256 = @splat(0x44),
            .lock_sha256 = verifier.lock_digest,
            .repositories = &.{},
            .packages = &.{},
            .commands = &.{},
            .journal_steps = &.{},
            .final_verification = .{
                .status = .exact_match,
                .installed_state_sha256 = @splat(0x45),
                .package_origins_sha256 = @splat(0x46),
                .detail = "verified",
            },
            .outcome = .succeeded,
        },
    );
    defer transaction.deinit();
    const transaction_source = try transaction.result.canonicalJson(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(transaction_source);
    verifier.transaction_digest = transaction.result.digest_sha256;
    verifier.transaction_source = transaction_source;
    var fresh = try expectReady(try engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer fresh.deinit();
    var completed = try engine.execute(
        std.testing.allocator,
        fresh,
        true,
    );
    defer completed.deinit();
    try std.testing.expectEqual(api.Outcome.success, completed.outcome);
    try std.testing.expectEqual(@as(usize, 1), backend.reserve_calls);
    try std.testing.expectEqual(@as(usize, 1), backend.execute_calls);
    try std.testing.expectEqual(@as(usize, 0), backend.recover_calls);
    active = try store.interface().readActive(
        std.testing.allocator,
        state_path,
    );
    defer if (active) |*owned| owned.deinit();
    try std.testing.expect(active == null);
}

test "apt_system_orchestrator.test.required_privileged.production outer generation race cannot report pre-mutation" {
    try requirePrivilegedProductionTest();
    const root_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "/root/debz-apt-generation-race-{d}",
        .{std.os.linux.getpid()},
    );
    defer std.testing.allocator.free(root_path);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, root_path) catch {};
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{root_path},
    );
    defer std.testing.allocator.free(state_path);

    var profile: FakeProfileLoader = .{ .state_path = state_path };
    var backend: FakeBackend = .{};
    var inner_runner: FakeRunner = .{ .allocator = std.testing.allocator };
    defer inner_runner.deinit();
    var system_store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    const store = system_store.interface();
    var race_runner: OuterGenerationRaceRunner = .{
        .inner = &inner_runner,
        .store = store,
        .state_path = state_path,
    };
    var verifier: FakeVerifier = .{};
    var sources: FakeSources = .{};
    var crash: FakeCompletionCrash = .{ .boundary = .after_downloaded_state };
    var engine: Engine = .{
        .profiles = profile.interface(),
        .runner = race_runner.interface(),
        .backend = backend.interface(),
        .store = store,
        .verifier = verifier.interface(),
        .ids = sources.ids(),
        .clock = sources.clock(),
        .completion_crash = crash.interface(),
    };
    var prepared = try expectReady(try engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    var result = try engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer result.deinit();
    try std.testing.expect(crash.triggered);
    try std.testing.expect(race_runner.advanced);
    try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
    try std.testing.expectEqual(
        api.MutationStatus.unknown,
        result.mutation_status.?,
    );
    try std.testing.expect(!result.changed);
    try std.testing.expect(result.profile == null);
    try std.testing.expectEqual(@as(usize, 0), backend.execute_calls);
    var active = (try store.readActive(
        std.testing.allocator,
        state_path,
    )) orelse return error.MissingActiveState;
    defer active.deinit();
    try std.testing.expect(active.state.mutation_started);
}

test "apt_system_orchestrator.test.update and list route through stable live root" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    harness.runner.transport_roundtrip = true;
    const update = try harness.engine.prepare(std.testing.allocator, .{
        .operation = .update,
        .profile_path = "/profile.json",
    });
    switch (update) {
        .result => |value| {
            var result = value;
            defer result.deinit();
            try std.testing.expectEqual(api.Outcome.success, result.outcome);
            try std.testing.expectEqual(@as(usize, 0), result.items.len);
        },
        .ready => return error.UnexpectedPreparation,
    }
    const list = try harness.engine.prepare(std.testing.allocator, .{
        .operation = .list_installed,
        .profile_path = "/profile.json",
    });
    switch (list) {
        .result => |value| {
            var result = value;
            defer result.deinit();
            try std.testing.expectEqual(api.Outcome.success, result.outcome);
            try std.testing.expectEqual(@as(usize, 2), result.items.len);
            try std.testing.expectEqualStrings("installed-a", result.items[0].package);
            try std.testing.expectEqualStrings("1", result.items[0].version.?);
            try std.testing.expectEqualStrings("amd64", result.items[0].architecture.?);
            try std.testing.expectEqualStrings("installed-b", result.items[1].package);
            try std.testing.expectEqualStrings("2", result.items[1].version.?);
            try std.testing.expectEqualStrings("all", result.items[1].architecture.?);
            const json = try result.canonicalJson(std.testing.allocator);
            defer std.testing.allocator.free(json);
            try std.testing.expect(std.mem.indexOf(
                u8,
                json,
                "\"package\":\"installed-a\",\"version\":\"1\",\"architecture\":\"amd64\"",
            ) != null);
        },
        .ready => return error.UnexpectedPreparation,
    }
    try std.testing.expectEqual(@as(usize, 2), harness.backend.route_calls);
    try std.testing.expect(harness.runner.saw_stable_root);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.workflow_calls);
}

test "apt_system_orchestrator.test.execution state errors reconcile at durable boundary" {
    for ([_]anyerror{
        error.LockTimeout,
        error.LockFailed,
        error.LockUnavailable,
        error.UnsupportedSchema,
        error.NonCanonicalDocument,
    }) |failure| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.store.compare_failure_once = failure;
        const invocation = try harness.engine.invokeExecute(
            std.testing.allocator,
            prepared,
            true,
        );
        var result = switch (invocation) {
            .result => |value| value,
            .operational_failure => return error.Unexpected,
        };
        defer result.deinit();
        try std.testing.expectEqual(api.Outcome.configuration, result.outcome);
        try std.testing.expectEqual(
            api.ExitStatus.configuration,
            result.exit_status,
        );
        try std.testing.expect(!result.changed);
        try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
        try std.testing.expect(harness.store.active_bytes == null);
    }
}

test "apt_system_orchestrator.test.completed lower root requires recovery only while provenance is pending" {
    const attempt: [32]u8 = @splat(0x57);
    const pending = classifyRootRecord(.completed, .pending, attempt);
    try std.testing.expectEqual(RootStatus.completed, pending.status);
    try std.testing.expectEqualSlices(u8, &attempt, &pending.attempt_id.?);

    const published = classifyRootRecord(.completed, .published, attempt);
    try std.testing.expectEqual(RootStatus.clean, published.status);
    const not_required = classifyRootRecord(
        .completed,
        .not_required,
        attempt,
    );
    try std.testing.expectEqual(RootStatus.clean, not_required.status);
    const active = classifyRootRecord(.mutating, .pending, attempt);
    try std.testing.expectEqual(RootStatus.recovery_required, active.status);
}

test "apt_system_orchestrator.test.required_privileged.production private runner transfers canonical result through live-root namespace" {
    try requirePrivilegedProductionTest();
    var original_mask: std.os.linux.sigset_t = undefined;
    try std.testing.expectEqual(
        std.os.linux.E.SUCCESS,
        std.os.linux.errno(std.os.linux.sigprocmask(
            std.os.linux.SIG.SETMASK,
            null,
            &original_mask,
        )),
    );
    var runner: PrivateLiveRootRunner = .{ .io = std.testing.io };
    var backend: FakeBackend = .{};
    var result = runner.interface().route(
        std.testing.allocator,
        backend.interface(),
        .{
            .operation = .list_installed,
            .options = .{
                .install_root = live_root.logical_root_path,
                .cache_path = "/var/cache/apt",
                .state_path = "/var/lib/apt",
                .architecture = "amd64",
            },
        },
    ) catch |err| switch (err) {
        error.NotPrivileged,
        error.NamespaceUnavailable,
        error.UnsafeRuntimeDirectory,
        => return privilegedCoverageUnavailable(),
        else => return err,
    };
    defer result.deinit();
    try std.testing.expectEqual(product_api.ExitStatus.success, result.result.exit_status);
    try std.testing.expectEqual(RootStatus.clean, result.root_status);
    try std.testing.expectEqual(@as(usize, 2), result.result.items.len);
    try std.testing.expectEqualStrings("installed-a", result.result.items[0].package);
    try std.testing.expectEqualStrings("1", result.result.items[0].version.?);
    try std.testing.expectEqualStrings("amd64", result.result.items[0].architecture.?);
    var inspection = try runner.interface().inspect(std.testing.allocator);
    defer inspection.deinit();
    try std.testing.expectEqual(RootStatus.clean, inspection.status);
    try std.testing.expect(inspection.attempt_id == null);
    var restored_mask: std.os.linux.sigset_t = undefined;
    _ = std.os.linux.sigprocmask(
        std.os.linux.SIG.SETMASK,
        null,
        &restored_mask,
    );
    try std.testing.expectEqualSlices(
        u8,
        std.mem.asBytes(&original_mask),
        std.mem.asBytes(&restored_mask),
    );
}

test "apt_system_orchestrator.test.required_privileged.production private runner validates every workflow mode transport operation" {
    try requirePrivilegedProductionTest();
    inline for (std.meta.tags(WorkflowMode)) |mode| {
        var runner: PrivateLiveRootRunner = .{ .io = std.testing.io };
        var backend: FakeBackend = .{};
        if (mode == .recover) backend.recover_status = .recovery;
        var result = runner.interface().workflow(
            std.testing.allocator,
            backend.interface(),
            .{
                .operation = .install,
                .mode = mode,
                .selectors = &.{.{ .name = "alpha" }},
                .options = .{
                    .install_root = live_root.logical_root_path,
                    .cache_path = "/var/cache/apt",
                    .state_path = "/var/lib/apt",
                    .architecture = "amd64",
                },
            },
        ) catch |err| switch (err) {
            error.NotPrivileged,
            error.NamespaceUnavailable,
            error.UnsafeRuntimeDirectory,
            => return privilegedCoverageUnavailable(),
            else => return err,
        };
        defer result.deinit();
        try std.testing.expectEqual(
            workflowSurfaceOperation(.install, mode),
            result.result.operation,
        );
        try std.testing.expectEqualStrings(
            if (mode == .recover) "injected failure" else "ok",
            result.result.summary,
        );
    }
    var runner: PrivateLiveRootRunner = .{ .io = std.testing.io };
    var backend: FakeBackend = .{};
    var finalized = runner.interface().workflow(
        std.testing.allocator,
        backend.interface(),
        .{
            .operation = .install,
            .mode = .recover,
            .selectors = &.{.{ .name = "alpha" }},
            .options = .{
                .install_root = live_root.logical_root_path,
                .cache_path = "/var/cache/apt",
                .state_path = "/var/lib/apt",
                .architecture = "amd64",
            },
            .orchestration_id = @splat(0x71),
            .finalize_ownership = true,
        },
    ) catch |err| switch (err) {
        error.NotPrivileged,
        error.NamespaceUnavailable,
        error.UnsafeRuntimeDirectory,
        => return privilegedCoverageUnavailable(),
        else => return err,
    };
    defer finalized.deinit();
    try std.testing.expectEqual(
        product_api.ExitStatus.success,
        finalized.result.exit_status,
    );
    try std.testing.expectEqual(RootStatus.completed, finalized.root_status);
}

test "apt_system_orchestrator.test.required_privileged.production private transport signal is supervised and releases live-root lock" {
    try requirePrivilegedProductionTest();
    var preflight_runner: PrivateLiveRootRunner = .{
        .io = std.testing.io,
        .termination_grace_ms = 50,
    };
    var preflight_backend: FakeBackend = .{};
    var preflight = preflight_runner.interface().route(
        std.testing.allocator,
        preflight_backend.interface(),
        .{
            .operation = .list_installed,
            .options = .{
                .install_root = live_root.logical_root_path,
                .cache_path = "/var/cache/apt",
                .state_path = "/var/lib/apt",
                .architecture = "amd64",
            },
        },
    ) catch |err| switch (err) {
        error.NotPrivileged,
        error.NamespaceUnavailable,
        error.UnsafeRuntimeDirectory,
        => return privilegedCoverageUnavailable(),
        else => return err,
    };
    preflight.deinit();

    var ready: [2]i32 = undefined;
    try std.testing.expectEqual(
        std.os.linux.E.SUCCESS,
        std.os.linux.errno(std.os.linux.pipe2(
            &ready,
            .{ .CLOEXEC = true, .NONBLOCK = true },
        )),
    );
    defer {
        _ = std.os.linux.close(ready[0]);
        _ = std.os.linux.close(ready[1]);
    }
    const runner_pid = try live_root.testing.forkProcess();
    if (runner_pid == 0) {
        _ = std.os.linux.close(ready[0]);
        var runner: PrivateLiveRootRunner = .{
            .io = std.testing.io,
            .termination_grace_ms = 50,
        };
        var backend: SignalTestBackend = .{ .ready_fd = ready[1] };
        var result = runner.interface().route(
            std.heap.page_allocator,
            backend.interface(),
            .{
                .operation = .list_installed,
                .options = .{
                    .install_root = live_root.logical_root_path,
                    .cache_path = "/var/cache/apt",
                    .state_path = "/var/lib/apt",
                    .architecture = "amd64",
                },
            },
        ) catch |err| switch (err) {
            error.LiveRootInterrupted => std.os.linux.exit_group(0),
            else => std.os.linux.exit_group(121),
        };
        result.deinit();
        std.os.linux.exit_group(122);
    }
    _ = std.os.linux.close(ready[1]);
    ready[1] = -1;
    var runner_live = true;
    defer if (runner_live) {
        _ = std.os.linux.kill(runner_pid, .KILL);
        _ = reapSignalTestProcess(runner_pid) catch null;
    };
    try std.testing.expect(try waitForSignalTestByte(ready[0], 5_000));
    try std.testing.expectEqual(
        std.os.linux.E.SUCCESS,
        std.os.linux.errno(std.os.linux.kill(runner_pid, .TERM)),
    );
    const status = try reapSignalTestProcess(runner_pid);
    runner_live = false;
    try std.testing.expect(std.os.linux.W.IFEXITED(status));
    try std.testing.expectEqual(
        @as(u8, 0),
        std.os.linux.W.EXITSTATUS(status),
    );

    var final_backend: FakeBackend = .{};
    var final_result = try preflight_runner.interface().route(
        std.testing.allocator,
        final_backend.interface(),
        .{
            .operation = .list_installed,
            .options = .{
                .install_root = live_root.logical_root_path,
                .cache_path = "/var/cache/apt",
                .state_path = "/var/lib/apt",
                .architecture = "amd64",
            },
        },
    );
    defer final_result.deinit();
    try std.testing.expectEqual(
        product_api.ExitStatus.success,
        final_result.result.exit_status,
    );
}

test "apt_system_orchestrator.test.private transport failures join helpers and restore caller signal mask" {
    if (builtin.os.tag != .linux or std.os.linux.geteuid() == 0)
        return error.SkipZigTest;
    var original: std.os.linux.sigset_t = undefined;
    try std.testing.expectEqual(
        std.os.linux.E.SUCCESS,
        std.os.linux.errno(std.os.linux.sigprocmask(
            std.os.linux.SIG.SETMASK,
            null,
            &original,
        )),
    );
    var runner: PrivateLiveRootRunner = .{ .io = std.testing.io };
    var backend: FakeBackend = .{};
    try std.testing.expectError(
        error.NotPrivileged,
        runner.interface().route(
            std.testing.allocator,
            backend.interface(),
            .{
                .operation = .list_installed,
                .options = .{
                    .install_root = live_root.logical_root_path,
                    .cache_path = "/var/cache/apt",
                    .state_path = "/var/lib/apt",
                    .architecture = "amd64",
                },
            },
        ),
    );
    var after_route: std.os.linux.sigset_t = undefined;
    _ = std.os.linux.sigprocmask(
        std.os.linux.SIG.SETMASK,
        null,
        &after_route,
    );
    try std.testing.expectEqualSlices(
        u8,
        std.mem.asBytes(&original),
        std.mem.asBytes(&after_route),
    );
    try std.testing.expectError(
        error.NotPrivileged,
        runner.interface().inspect(std.testing.allocator),
    );
    var after_inspect: std.os.linux.sigset_t = undefined;
    _ = std.os.linux.sigprocmask(
        std.os.linux.SIG.SETMASK,
        null,
        &after_inspect,
    );
    try std.testing.expectEqualSlices(
        u8,
        std.mem.asBytes(&original),
        std.mem.asBytes(&after_inspect),
    );
    try std.testing.expectError(
        error.NotPrivileged,
        runner.interface().readRecoveryCompletion(
            std.testing.allocator,
        ),
    );
    var after_completion: std.os.linux.sigset_t = undefined;
    _ = std.os.linux.sigprocmask(
        std.os.linux.SIG.SETMASK,
        null,
        &after_completion,
    );
    try std.testing.expectEqualSlices(
        u8,
        std.mem.asBytes(&original),
        std.mem.asBytes(&after_completion),
    );
}

test "apt_system_orchestrator.test.required_privileged.production pre-mutation reconciliation claim crash matrix converges without mutation" {
    try requirePrivilegedProductionTest();
    const CrashCase = enum {
        after_claim_publish,
        after_outer_recheck,
        after_retained_publish,
        after_active_cas,
        before_claim_ack,
        after_claim_ack,
    };
    inline for (std.enums.values(CrashCase)) |crash_case| {
        var fixture = ProductionRunnerFixture.init(
            std.testing.allocator,
        ) catch |err| switch (err) {
            error.NamespaceUnavailable => return privilegedCoverageUnavailable(),
            else => return err,
        };
        defer fixture.deinit();
        var process: ProductionRunnerProcess = .{
            .io = std.testing.io,
            .dpkg = fixture.dpkg,
        };
        var production: production_backend.Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
        };
        var backend: ProductionBackend = .{ .backend = &production };
        var runner: PrivateLiveRootRunner = .{ .io = std.testing.io };
        var profile: FakeProfileLoader = .{
            .state_path = fixture.state_path,
            .cache_path = fixture.cache_path,
            .source_paths = fixture.source_paths,
            .keyring_paths = fixture.keyring_paths,
        };
        var system_verifier: SystemResultVerifier = .{
            .io = std.testing.io,
        };
        var sources: FakeSources = .{};
        var parent_store: SystemStateStore = .{
            .allocator = std.testing.allocator,
            .io = std.testing.io,
        };
        var parent_engine: Engine = .{
            .profiles = profile.interface(),
            .runner = runner.interface(),
            .backend = backend.interface(),
            .store = parent_store.interface(),
            .verifier = system_verifier.interface(),
            .ids = sources.ids(),
            .clock = sources.clock(),
        };
        var prepared = try expectReady(try parent_engine.prepare(
            std.testing.allocator,
            mutationRequest(.remove, &.{"removable"}),
        ));
        defer prepared.deinit();

        const child = try live_root.testing.forkProcess();
        if (child == 0) {
            var one_shot: OneShotOperationalLockVerifier = .{
                .inner = system_verifier.interface(),
            };
            var completion_crash: ProcessDeathCompletionCrash = .{
                .boundary = switch (crash_case) {
                    .after_claim_publish => .after_pre_mutation_claim_published,
                    .after_outer_recheck => .after_pre_mutation_outer_rechecked,
                    .before_claim_ack => .before_ownership_acknowledged,
                    .after_claim_ack => .after_ownership_acknowledged,
                    .after_retained_publish,
                    .after_active_cas,
                    => .after_backend_success,
                },
            };
            var finish_crash: ProcessDeathFinishCrash = .{};
            var state_crash: ProcessDeathStateWriteCrash = .{};
            var child_store: SystemStateStore = .{
                .allocator = std.heap.page_allocator,
                .io = std.testing.io,
                .finish_crash = if (crash_case == .after_retained_publish)
                    finish_crash.interface()
                else
                    null,
                .state_write_hooks = if (crash_case == .after_active_cas)
                    state_crash.interface()
                else
                    .{},
            };
            var child_engine: Engine = .{
                .profiles = profile.interface(),
                .runner = runner.interface(),
                .backend = backend.interface(),
                .store = child_store.interface(),
                .verifier = one_shot.interface(),
                .ids = sources.ids(),
                .clock = sources.clock(),
                .completion_crash = switch (crash_case) {
                    .after_claim_publish,
                    .after_outer_recheck,
                    .before_claim_ack,
                    .after_claim_ack,
                    => completion_crash.interface(),
                    .after_retained_publish, .after_active_cas => null,
                },
            };
            _ = child_engine.execute(
                std.heap.page_allocator,
                prepared,
                true,
            ) catch {};
            std.os.linux.exit_group(96);
        }
        const child_status = try reapSignalTestProcess(child);
        try std.testing.expect(std.os.linux.W.IFEXITED(child_status));
        try std.testing.expectEqual(
            @as(u8, 91),
            std.os.linux.W.EXITSTATUS(child_status),
        );
        var mutation_observed = true;
        fixture.dpkg.access(
            std.testing.io,
            "mutation-observed",
            .{},
        ) catch {
            mutation_observed = false;
        };
        try std.testing.expect(!mutation_observed);

        var inspection = try runner.interface().inspect(
            std.testing.allocator,
        );
        defer inspection.deinit();
        if (crash_case == .after_claim_ack) {
            try std.testing.expect(
                inspection.deferred_acknowledgment == null,
            );
        } else {
            const marker = inspection.deferred_acknowledgment orelse
                return error.MissingOwnershipAcknowledgment;
            try std.testing.expectEqual(
                root_operation.DeferredAcknowledgmentState
                    .pre_mutation_reconciliation_claim,
                marker.state,
            );
        }

        var recovery = switch (try parent_engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer recovery.deinit();
        var result = try parent_engine.executeRecovery(
            std.testing.allocator,
            recovery,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(
            api.ExitStatus.configuration,
            result.exit_status,
        );
        try std.testing.expect(!result.changed);
        var final_active = try parent_store.interface().readActive(
            std.testing.allocator,
            fixture.state_path,
        );
        defer if (final_active) |*active| active.deinit();
        try std.testing.expect(final_active == null);
        var final_inspection = try runner.interface().inspect(
            std.testing.allocator,
        );
        defer final_inspection.deinit();
        try std.testing.expect(
            final_inspection.deferred_acknowledgment == null,
        );
        mutation_observed = true;
        fixture.dpkg.access(
            std.testing.io,
            "mutation-observed",
            .{},
        ) catch {
            mutation_observed = false;
        };
        try std.testing.expect(!mutation_observed);
    }
}

test "apt_system_orchestrator.test.required_privileged.production runner retains successful ownership through outer crash matrix" {
    try requirePrivilegedProductionTest();
    const CrashCase = union(enum) {
        lower: production_backend.CompletionPoint,
        transport,
        outer: CompletionBoundary,
    };
    inline for ([_]CrashCase{
        .{ .lower = .after_completed_record },
        .{ .lower = .after_transaction_provenance },
        .{ .lower = .after_ownership_record_clear },
        .transport,
        .{ .outer = .after_backend_success },
        .{ .outer = .after_transaction_verified },
        .{ .outer = .after_transaction_retained },
        .{ .outer = .after_acknowledgment_retained },
        .{ .outer = .before_completion_published },
        .{ .outer = .after_completion_published },
        .{ .outer = .after_outer_committed },
        .{ .outer = .before_ownership_acknowledged },
        .{ .outer = .after_ownership_acknowledged },
    }) |crash_case| {
        var fixture = ProductionRunnerFixture.init(
            std.testing.allocator,
        ) catch |err| switch (err) {
            error.NamespaceUnavailable => return privilegedCoverageUnavailable(),
            else => return err,
        };
        defer fixture.deinit();
        var process: ProductionRunnerProcess = .{
            .io = std.testing.io,
            .dpkg = fixture.dpkg,
        };
        var production: production_backend.Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
        };
        var backend: ProductionBackend = .{ .backend = &production };
        var runner: PrivateLiveRootRunner = .{ .io = std.testing.io };
        var profile: FakeProfileLoader = .{
            .state_path = fixture.state_path,
            .cache_path = fixture.cache_path,
            .source_paths = fixture.source_paths,
            .keyring_paths = fixture.keyring_paths,
        };
        var store: SystemStateStore = .{
            .allocator = std.testing.allocator,
            .io = std.testing.io,
        };
        var verifier: SystemResultVerifier = .{ .io = std.testing.io };
        var sources: FakeSources = .{};
        var engine: Engine = .{
            .profiles = profile.interface(),
            .runner = runner.interface(),
            .backend = backend.interface(),
            .store = store.interface(),
            .verifier = verifier.interface(),
            .ids = sources.ids(),
            .clock = sources.clock(),
        };
        var prepared = try expectReady(try engine.prepare(
            std.testing.allocator,
            mutationRequest(.remove, &.{"removable"}),
        ));
        defer prepared.deinit();

        const child = try live_root.testing.forkProcess();
        if (child == 0) {
            switch (crash_case) {
                .lower => |boundary| {
                    var crash: ProductionChildCrash = .{
                        .boundary = boundary,
                    };
                    production.completion_crash = crash.interface();
                    var result = engine.execute(
                        std.heap.page_allocator,
                        prepared,
                        true,
                    ) catch std.os.linux.exit_group(93);
                    result.deinit();
                    std.os.linux.exit_group(91);
                },
                .transport => {
                    var crash: ProcessDeathTransportCrash = .{
                        .calls_to_skip = 2,
                    };
                    runner.transport_crash = crash.interface();
                    _ = engine.execute(
                        std.heap.page_allocator,
                        prepared,
                        true,
                    ) catch {};
                    std.os.linux.exit_group(94);
                },
                .outer => |boundary| {
                    var crash: ProcessDeathCompletionCrash = .{
                        .boundary = boundary,
                    };
                    engine.completion_crash = crash.interface();
                    _ = engine.execute(
                        std.heap.page_allocator,
                        prepared,
                        true,
                    ) catch {};
                    std.os.linux.exit_group(95);
                },
            }
        }
        const child_status = try reapSignalTestProcess(child);
        try std.testing.expect(std.os.linux.W.IFEXITED(child_status));
        try fixture.dpkg.access(
            std.testing.io,
            "mutation-observed",
            .{},
        );

        var active = (try store.interface().readActive(
            std.testing.allocator,
            fixture.state_path,
        )).?;
        defer active.deinit();
        try std.testing.expect(active.state.mutation_started);

        var inspection = try runner.interface().inspect(
            std.testing.allocator,
        );
        defer inspection.deinit();
        const before_ack = switch (crash_case) {
            .outer => |boundary| boundary != .after_ownership_acknowledged,
            else => true,
        };
        const foreign_state_path = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}-foreign",
            .{fixture.state_path},
        );
        defer std.testing.allocator.free(foreign_state_path);
        var foreign_profile: FakeProfileLoader = .{
            .state_path = foreign_state_path,
            .cache_path = fixture.cache_path,
            .source_paths = fixture.source_paths,
            .keyring_paths = fixture.keyring_paths,
        };
        var loaded_foreign = try foreign_profile.interface().load(
            std.testing.allocator,
            "/profile.json",
        );
        defer loaded_foreign.deinit();
        if (before_ack) {
            const marker = inspection.deferred_acknowledgment orelse
                return error.MissingOwnershipAcknowledgment;
            var foreign = try runner.interface().workflow(
                std.testing.allocator,
                backend.interface(),
                .{
                    .operation = .remove,
                    .mode = .reserve,
                    .selectors = &.{.{ .name = "removable" }},
                    .options = executeOptions(
                        loaded_foreign.view,
                        prepared.paths.exact_lock,
                    ),
                    .orchestration_id = @splat(0xa7),
                },
            );
            defer foreign.deinit();
            try std.testing.expectEqual(
                product_api.ExitStatus.recovery,
                foreign.result.exit_status,
            );
            var after_foreign = try runner.interface().inspect(
                std.testing.allocator,
            );
            defer after_foreign.deinit();
            try std.testing.expectEqualSlices(
                u8,
                &marker.acknowledgment_id,
                &after_foreign.deferred_acknowledgment.?.acknowledgment_id,
            );
        } else {
            try std.testing.expect(
                inspection.deferred_acknowledgment == null,
            );
            var foreign = try runner.interface().workflow(
                std.testing.allocator,
                backend.interface(),
                .{
                    .operation = .remove,
                    .mode = .reserve,
                    .selectors = &.{.{ .name = "removable" }},
                    .options = executeOptions(
                        loaded_foreign.view,
                        prepared.paths.exact_lock,
                    ),
                    .orchestration_id = @splat(0xa7),
                },
            );
            defer foreign.deinit();
            try std.testing.expectEqual(
                product_api.ExitStatus.success,
                foreign.result.exit_status,
            );
            var foreign_marker = try runner.interface().inspect(
                std.testing.allocator,
            );
            defer foreign_marker.deinit();
            _ = foreign_marker.deferred_acknowledgment orelse
                return error.MissingOwnershipAcknowledgment;
            const held_source = try std.fmt.allocPrint(
                std.testing.allocator,
                "{s}.foreign-held",
                .{fixture.source_path},
            );
            defer std.testing.allocator.free(held_source);
            try std.Io.Dir.cwd().rename(
                fixture.source_path,
                std.Io.Dir.cwd(),
                held_source,
                std.testing.io,
            );
            var foreign_executed = try runner.interface().workflow(
                std.testing.allocator,
                backend.interface(),
                .{
                    .operation = .remove,
                    .mode = .execute,
                    .selectors = &.{.{ .name = "removable" }},
                    .options = executeOptions(
                        loaded_foreign.view,
                        prepared.paths.exact_lock,
                    ),
                    .orchestration_id = @splat(0xa7),
                },
            );
            defer foreign_executed.deinit();
            try std.Io.Dir.cwd().rename(
                held_source,
                std.Io.Dir.cwd(),
                fixture.source_path,
                std.testing.io,
            );
            try std.testing.expect(
                foreign_executed.result.exit_status != .success,
            );
            var abandoned = try runner.interface().inspect(
                std.testing.allocator,
            );
            defer abandoned.deinit();
            const abandoned_marker =
                abandoned.deferred_acknowledgment orelse
                return error.MissingOwnershipAcknowledgment;
            try std.testing.expectEqual(
                root_operation.DeferredAcknowledgmentState.abandoned,
                abandoned_marker.state,
            );
            var finalized = try runner.interface().workflow(
                std.testing.allocator,
                backend.interface(),
                .{
                    .operation = .remove,
                    .mode = .recover,
                    .selectors = &.{.{ .name = "removable" }},
                    .options = executeOptions(
                        loaded_foreign.view,
                        prepared.paths.exact_lock,
                    ),
                    .orchestration_id = @splat(0xa7),
                    .finalize_ownership = true,
                    .ownership_acknowledgment = .{
                        .attempt_id = abandoned_marker.attempt_id,
                        .marker_sha256 = abandoned_marker.digest_sha256,
                        .acknowledgment_id = @splat(0xa7),
                    },
                },
            );
            defer finalized.deinit();
            try std.testing.expectEqual(
                product_api.ExitStatus.success,
                finalized.result.exit_status,
            );
        }

        var blocked = try engine.prepare(
            std.testing.allocator,
            mutationRequest(.remove, &.{"removable"}),
        );
        switch (blocked) {
            .result => |*result| {
                defer result.deinit();
                try std.testing.expectEqual(api.Outcome.recovery, result.outcome);
            },
            .ready => |*unexpected| {
                unexpected.deinit();
                return error.ExpectedRecoveryDiagnostic;
            },
        }
        var recovery = switch (try engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer recovery.deinit();
        var completed = try engine.executeRecovery(
            std.testing.allocator,
            recovery,
            true,
        );
        defer completed.deinit();
        try std.testing.expectEqual(api.Outcome.success, completed.outcome);
        try std.testing.expect((try store.interface().readActive(
            std.testing.allocator,
            fixture.state_path,
        )) == null);
        var clean = try runner.interface().inspect(std.testing.allocator);
        defer clean.deinit();
        try std.testing.expectEqual(RootStatus.clean, clean.status);
        try std.testing.expect(clean.deferred_acknowledgment == null);
    }
}

test "apt_system_orchestrator.test.required_privileged.production restart resyncs visible final state before lower acknowledgment" {
    try requirePrivilegedProductionTest();
    const Barrier = enum { active_state, retained_final };
    inline for (.{ false, true }) |recovering| {
        inline for (std.enums.values(Barrier)) |barrier| {
            var fixture = ProductionRunnerFixture.init(
                std.testing.allocator,
            ) catch |err| switch (err) {
                error.NamespaceUnavailable => return privilegedCoverageUnavailable(),
                else => return err,
            };
            defer fixture.deinit();
            var process: ProductionRunnerProcess = .{
                .io = std.testing.io,
                .dpkg = fixture.dpkg,
            };
            var production: production_backend.Backend = .{
                .io = std.testing.io,
                .now_unix = @import("fixtures/openpgp.zig").created + 30,
                .process_runner = process.interface(),
            };
            var backend: ProductionBackend = .{ .backend = &production };
            var private_runner: PrivateLiveRootRunner = .{ .io = std.testing.io };
            const runner = private_runner.interface();
            var profile: FakeProfileLoader = .{
                .state_path = fixture.state_path,
                .cache_path = fixture.cache_path,
                .source_paths = fixture.source_paths,
                .keyring_paths = fixture.keyring_paths,
            };
            var verifier: SystemResultVerifier = .{ .io = std.testing.io };
            var sources: FakeSources = .{};
            var parent_store: SystemStateStore = .{
                .allocator = std.testing.allocator,
                .io = std.testing.io,
            };
            var parent_engine: Engine = .{
                .profiles = profile.interface(),
                .runner = runner,
                .backend = backend.interface(),
                .store = parent_store.interface(),
                .verifier = verifier.interface(),
                .ids = sources.ids(),
                .clock = sources.clock(),
            };
            var prepared = try expectReady(try parent_engine.prepare(
                std.testing.allocator,
                mutationRequest(.remove, &.{"removable"}),
            ));
            defer prepared.deinit();

            if (recovering) {
                const mutation_child = try live_root.testing.forkProcess();
                if (mutation_child == 0) {
                    var crash: ProductionChildCrash = .{
                        .boundary = .after_completed_record,
                    };
                    production.completion_crash = crash.interface();
                    _ = parent_engine.execute(
                        std.heap.page_allocator,
                        prepared,
                        true,
                    ) catch {};
                    std.os.linux.exit_group(103);
                }
                _ = try reapSignalTestProcess(mutation_child);
            }

            var recovery: ?RecoveryPreparation = if (recovering)
                switch (try parent_engine.prepareRecovery(
                    std.testing.allocator,
                    "/profile.json",
                )) {
                    .ready => |value| value,
                    .result => return error.ExpectedRecoveryPreparation,
                }
            else
                null;
            defer if (recovery) |*value| value.deinit();
            const commit_child = try live_root.testing.forkProcess();
            if (commit_child == 0) {
                var fault: CommitDurabilityFault = .{
                    .fail_after_rename = barrier == .active_state,
                    .fail_retained_publication_dir = barrier == .retained_final,
                };
                var child_store: SystemStateStore = .{
                    .allocator = std.heap.page_allocator,
                    .io = std.testing.io,
                    .directory_sync = fault.directoryInterface(),
                    .retained_durability = fault.retainedInterface(),
                    .state_write_hooks = fault.stateHooks(),
                };
                var child_engine: Engine = .{
                    .profiles = profile.interface(),
                    .runner = runner,
                    .backend = backend.interface(),
                    .store = child_store.interface(),
                    .verifier = verifier.interface(),
                    .ids = sources.ids(),
                    .clock = sources.clock(),
                    .completion_crash = fault.completionInterface(),
                };
                if (recovering) {
                    _ = child_engine.executeRecovery(
                        std.heap.page_allocator,
                        recovery.?,
                        true,
                    ) catch {};
                } else {
                    _ = child_engine.execute(
                        std.heap.page_allocator,
                        prepared,
                        true,
                    ) catch {};
                }
                std.os.linux.exit_group(104);
            }
            _ = try reapSignalTestProcess(commit_child);
            try fixture.dpkg.access(std.testing.io, "mutation-observed", .{});
            var protected = try runner.inspect(std.testing.allocator);
            defer protected.deinit();
            _ = protected.deferred_acknowledgment orelse
                return error.MissingOwnershipAcknowledgment;

            var restart_fault: CommitDurabilityFault = .{
                .fail_resync = barrier == .active_state,
                .fail_retained_file_sync = barrier == .retained_final,
            };
            var restart_store: SystemStateStore = .{
                .allocator = std.testing.allocator,
                .io = std.testing.io,
                .directory_sync = restart_fault.directoryInterface(),
                .retained_durability = restart_fault.retainedInterface(),
                .state_write_hooks = restart_fault.stateHooks(),
            };
            var restart_engine: Engine = .{
                .profiles = profile.interface(),
                .runner = runner,
                .backend = backend.interface(),
                .store = restart_store.interface(),
                .verifier = verifier.interface(),
                .ids = sources.ids(),
                .clock = sources.clock(),
            };
            var first_retry = switch (try restart_engine.prepareRecovery(
                std.testing.allocator,
                "/profile.json",
            )) {
                .ready => |value| value,
                .result => return error.ExpectedRecoveryPreparation,
            };
            defer first_retry.deinit();
            var unsynced = try restart_engine.executeRecovery(
                std.testing.allocator,
                first_retry,
                true,
            );
            defer unsynced.deinit();
            try std.testing.expect(unsynced.outcome != .success);
            try expectForeignProductionReservationBlocked(
                &fixture,
                prepared,
                runner,
                backend.interface(),
                @splat(0xc7),
            );
            var still_protected = try runner.inspect(std.testing.allocator);
            defer still_protected.deinit();
            _ = still_protected.deferred_acknowledgment orelse
                return error.MissingOwnershipAcknowledgment;

            restart_fault.fail_resync = false;
            restart_fault.fail_retained_file_sync = false;
            if (barrier == .retained_final) {
                restart_fault.fail_retained_operation_dir_sync = true;
                var directory_retry = switch (try restart_engine.prepareRecovery(
                    std.testing.allocator,
                    "/profile.json",
                )) {
                    .ready => |value| value,
                    .result => return error.ExpectedRecoveryPreparation,
                };
                defer directory_retry.deinit();
                var directory_unsynced = try restart_engine.executeRecovery(
                    std.testing.allocator,
                    directory_retry,
                    true,
                );
                defer directory_unsynced.deinit();
                try std.testing.expect(directory_unsynced.outcome != .success);
                try expectForeignProductionReservationBlocked(
                    &fixture,
                    prepared,
                    runner,
                    backend.interface(),
                    @splat(0xc8),
                );
                var directory_protected = try runner.inspect(
                    std.testing.allocator,
                );
                defer directory_protected.deinit();
                _ = directory_protected.deferred_acknowledgment orelse
                    return error.MissingOwnershipAcknowledgment;
                restart_fault.fail_retained_operation_dir_sync = false;
            }
            var final_retry = switch (try restart_engine.prepareRecovery(
                std.testing.allocator,
                "/profile.json",
            )) {
                .ready => |value| value,
                .result => return error.ExpectedRecoveryPreparation,
            };
            defer final_retry.deinit();
            var completed = try restart_engine.executeRecovery(
                std.testing.allocator,
                final_retry,
                true,
            );
            defer completed.deinit();
            try std.testing.expectEqual(api.Outcome.success, completed.outcome);
            try std.testing.expect((try restart_store.interface().readActive(
                std.testing.allocator,
                fixture.state_path,
            )) == null);
            var clean = try runner.inspect(std.testing.allocator);
            defer clean.deinit();
            try std.testing.expect(clean.deferred_acknowledgment == null);
        }
    }
}

test "apt_system_orchestrator.test.required_privileged.production retained evidence corruption cannot acknowledge lower ownership" {
    try requirePrivilegedProductionTest();
    const Fault = enum {
        missing_evidence,
        corrupt_evidence,
        foreign_lower_attempt,
        foreign_outer_attempt,
    };
    inline for (.{ false, true }) |recovering| {
        inline for (std.enums.values(Fault)) |fault| {
            var fixture = ProductionRunnerFixture.init(
                std.testing.allocator,
            ) catch |err| switch (err) {
                error.NamespaceUnavailable => return privilegedCoverageUnavailable(),
                else => return err,
            };
            defer fixture.deinit();
            var process: ProductionRunnerProcess = .{
                .io = std.testing.io,
                .dpkg = fixture.dpkg,
            };
            var production: production_backend.Backend = .{
                .io = std.testing.io,
                .now_unix = @import("fixtures/openpgp.zig").created + 30,
                .process_runner = process.interface(),
            };
            var backend: ProductionBackend = .{ .backend = &production };
            var private_runner: PrivateLiveRootRunner = .{
                .io = std.testing.io,
            };
            const runner = private_runner.interface();
            var profile: FakeProfileLoader = .{
                .state_path = fixture.state_path,
                .cache_path = fixture.cache_path,
                .source_paths = fixture.source_paths,
                .keyring_paths = fixture.keyring_paths,
            };
            var store: SystemStateStore = .{
                .allocator = std.testing.allocator,
                .io = std.testing.io,
            };
            var verifier: SystemResultVerifier = .{ .io = std.testing.io };
            var sources: FakeSources = .{};
            var engine: Engine = .{
                .profiles = profile.interface(),
                .runner = runner,
                .backend = backend.interface(),
                .store = store.interface(),
                .verifier = verifier.interface(),
                .ids = sources.ids(),
                .clock = sources.clock(),
            };
            var prepared = try expectReady(try engine.prepare(
                std.testing.allocator,
                mutationRequest(.remove, &.{"removable"}),
            ));
            defer prepared.deinit();

            if (recovering) {
                const mutation_child = try live_root.testing.forkProcess();
                if (mutation_child == 0) {
                    var crash: ProductionChildCrash = .{
                        .boundary = .after_completed_record,
                    };
                    production.completion_crash = crash.interface();
                    _ = engine.execute(
                        std.heap.page_allocator,
                        prepared,
                        true,
                    ) catch {};
                    std.os.linux.exit_group(105);
                }
                _ = try reapSignalTestProcess(mutation_child);
            }
            var initial_recovery: ?RecoveryPreparation = if (recovering)
                switch (try engine.prepareRecovery(
                    std.testing.allocator,
                    "/profile.json",
                )) {
                    .ready => |value| value,
                    .result => return error.ExpectedRecoveryPreparation,
                }
            else
                null;
            defer if (initial_recovery) |*value| value.deinit();
            const commit_child = try live_root.testing.forkProcess();
            if (commit_child == 0) {
                var crash: ProcessDeathCompletionCrash = .{
                    .boundary = .after_outer_committed,
                };
                engine.completion_crash = crash.interface();
                if (recovering) {
                    _ = engine.executeRecovery(
                        std.heap.page_allocator,
                        initial_recovery.?,
                        true,
                    ) catch {};
                } else {
                    _ = engine.execute(
                        std.heap.page_allocator,
                        prepared,
                        true,
                    ) catch {};
                }
                std.os.linux.exit_group(106);
            }
            _ = try reapSignalTestProcess(commit_child);
            try fixture.dpkg.access(std.testing.io, "mutation-observed", .{});

            const evidence_path = if (recovering)
                prepared.paths.recovery_completion
            else
                prepared.paths.transaction_result;
            const evidence_limit = if (recovering)
                root_operation_completion.maximum_document_bytes
            else
                transaction_provenance.maximum_document_bytes;
            const exact_evidence = try readTrustedOperationFile(
                std.testing.io,
                std.testing.allocator,
                evidence_path,
                evidence_limit,
            );
            defer std.testing.allocator.free(exact_evidence);
            const exact_acknowledgment = try readTrustedOperationFile(
                std.testing.io,
                std.testing.allocator,
                prepared.paths.lower_acknowledgment,
                root_operation.maximum_document_bytes,
            );
            defer std.testing.allocator.free(exact_acknowledgment);

            switch (fault) {
                .missing_evidence => try std.Io.Dir.cwd().deleteFile(
                    std.testing.io,
                    evidence_path,
                ),
                .corrupt_evidence => try writeAbsoluteTestFile(
                    evidence_path,
                    "{\"corrupt\":true}\n",
                ),
                .foreign_lower_attempt, .foreign_outer_attempt => {
                    const exact = try root_operation
                        .decodeDeferredAcknowledgment(
                        std.testing.allocator,
                        exact_acknowledgment,
                    );
                    var attempt_id = exact.attempt_id;
                    var acknowledgment_id = exact.acknowledgment_id;
                    if (fault == .foreign_lower_attempt)
                        attempt_id[0] ^= 0xff
                    else
                        acknowledgment_id[0] ^= 0xff;
                    const foreign = try root_operation
                        .createDeferredAcknowledgment(.{
                        .state = exact.state,
                        .attempt_id = attempt_id,
                        .completion_sha256 = exact.completion_sha256,
                        .provenance_sha256 = exact.provenance_sha256,
                        .acknowledgment_id = acknowledgment_id,
                    });
                    const source = try foreign.canonicalJson(
                        std.testing.allocator,
                    );
                    defer std.testing.allocator.free(source);
                    try writeAbsoluteTestFile(
                        prepared.paths.lower_acknowledgment,
                        source,
                    );
                },
            }

            var retry = switch (try engine.prepareRecovery(
                std.testing.allocator,
                "/profile.json",
            )) {
                .ready => |value| value,
                .result => return error.ExpectedRecoveryPreparation,
            };
            defer retry.deinit();
            var rejected = try engine.executeRecovery(
                std.testing.allocator,
                retry,
                true,
            );
            defer rejected.deinit();
            try std.testing.expect(rejected.outcome != .success);
            var protected = try runner.inspect(std.testing.allocator);
            defer protected.deinit();
            _ = protected.deferred_acknowledgment orelse
                return error.MissingOwnershipAcknowledgment;
            try expectForeignProductionReservationBlocked(
                &fixture,
                prepared,
                runner,
                backend.interface(),
                @splat(0xd7),
            );

            try writeAbsoluteTestFile(evidence_path, exact_evidence);
            try writeAbsoluteTestFile(
                prepared.paths.lower_acknowledgment,
                exact_acknowledgment,
            );
            var restored = switch (try engine.prepareRecovery(
                std.testing.allocator,
                "/profile.json",
            )) {
                .ready => |value| value,
                .result => return error.ExpectedRecoveryPreparation,
            };
            defer restored.deinit();
            var completed = try engine.executeRecovery(
                std.testing.allocator,
                restored,
                true,
            );
            defer completed.deinit();
            try std.testing.expectEqual(api.Outcome.success, completed.outcome);
            var clean = try runner.inspect(std.testing.allocator);
            defer clean.deinit();
            try std.testing.expect(clean.deferred_acknowledgment == null);
        }
    }
}

test "apt_system_orchestrator.test.required_privileged.production clean reconciliation race never clears outer state after foreign reservation" {
    try requirePrivilegedProductionTest();
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture = ProductionRunnerFixture.init(
        std.testing.allocator,
    ) catch |err| switch (err) {
        error.NamespaceUnavailable => return privilegedCoverageUnavailable(),
        else => return err,
    };
    defer fixture.deinit();
    var process: ProductionRunnerProcess = .{
        .io = std.testing.io,
        .dpkg = fixture.dpkg,
    };
    var production: production_backend.Backend = .{
        .io = std.testing.io,
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
        .process_runner = process.interface(),
    };
    var backend: ProductionBackend = .{ .backend = &production };
    var runner: PrivateLiveRootRunner = .{ .io = std.testing.io };
    var profile: FakeProfileLoader = .{
        .state_path = fixture.state_path,
        .cache_path = fixture.cache_path,
        .source_paths = fixture.source_paths,
        .keyring_paths = fixture.keyring_paths,
    };
    var store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    var verifier: SystemResultVerifier = .{ .io = std.testing.io };
    var sources: FakeSources = .{};
    var engine: Engine = .{
        .profiles = profile.interface(),
        .runner = runner.interface(),
        .backend = backend.interface(),
        .store = store.interface(),
        .verifier = verifier.interface(),
        .ids = sources.ids(),
        .clock = sources.clock(),
    };
    var loaded = try profile.interface().load(
        std.testing.allocator,
        "/profile.json",
    );
    defer loaded.deinit();
    var prepared = try expectReady(try engine.prepare(
        std.testing.allocator,
        mutationRequest(.remove, &.{"removable"}),
    ));
    defer prepared.deinit();
    const crash_pid = try live_root.testing.forkProcess();
    if (crash_pid == 0) {
        var crash: ProcessDeathCompletionCrash = .{
            .boundary = .after_backend_success,
        };
        engine.completion_crash = crash.interface();
        _ = engine.execute(
            std.heap.page_allocator,
            prepared,
            true,
        ) catch std.os.linux.exit_group(111);
        std.os.linux.exit_group(112);
    }
    const crash_status = try reapSignalTestProcess(crash_pid);
    try std.testing.expect(std.os.linux.W.IFEXITED(crash_status));
    try std.testing.expectEqual(
        @as(u8, 91),
        std.os.linux.W.EXITSTATUS(crash_status),
    );
    try std.Io.Dir.cwd().deleteFile(
        std.testing.io,
        "/" ++ root_operation.deferred_ack_path,
    );
    var root_status = try runner.interface().inspect(std.testing.allocator);
    defer root_status.deinit();
    try std.testing.expectEqual(.clean, root_status.status);
    var recovery = switch (try engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer recovery.deinit();
    var ready_fds: [2]i32 = undefined;
    if (std.os.linux.errno(std.os.linux.pipe2(
        &ready_fds,
        .{ .CLOEXEC = true, .NONBLOCK = true },
    )) != .SUCCESS) return error.PipeFailed;
    defer {
        if (ready_fds[0] >= 0) _ = std.os.linux.close(ready_fds[0]);
        if (ready_fds[1] >= 0) _ = std.os.linux.close(ready_fds[1]);
    }
    var release_fds: [2]i32 = undefined;
    if (std.os.linux.errno(std.os.linux.pipe2(
        &release_fds,
        .{ .CLOEXEC = true },
    )) != .SUCCESS) return error.PipeFailed;
    defer {
        if (release_fds[0] >= 0) _ = std.os.linux.close(release_fds[0]);
        if (release_fds[1] >= 0) _ = std.os.linux.close(release_fds[1]);
    }
    const recovery_pid_raw = std.os.linux.fork();
    if (std.os.linux.errno(recovery_pid_raw) != .SUCCESS)
        return error.ForkFailed;
    const recovery_pid: i32 = @intCast(recovery_pid_raw);
    var recovery_reaped = false;
    defer if (!recovery_reaped) {
        _ = std.os.linux.kill(recovery_pid, .KILL);
        _ = reapSignalTestProcess(recovery_pid) catch {};
    };
    if (recovery_pid == 0) {
        _ = std.os.linux.close(ready_fds[0]);
        _ = std.os.linux.close(release_fds[1]);
        var barrier: CleanInspectionProcessBarrier = .{
            .ready_fd = ready_fds[1],
            .release_fd = release_fds[0],
        };
        engine.completion_crash = barrier.interface();
        var child_result = engine.executeRecovery(
            std.heap.page_allocator,
            recovery,
            true,
        ) catch std.os.linux.exit_group(113);
        const outcome = child_result.outcome;
        child_result.deinit();
        std.os.linux.exit_group(if (outcome == .recovery) 0 else 114);
    }
    _ = std.os.linux.close(ready_fds[1]);
    ready_fds[1] = -1;
    _ = std.os.linux.close(release_fds[0]);
    release_fds[0] = -1;
    try std.testing.expect(try waitForSignalTestByte(
        ready_fds[0],
        5_000,
    ));
    const foreign_id: [32]u8 = @splat(0xb7);
    var foreign_reservation = try runner.interface().workflow(
        std.testing.allocator,
        backend.interface(),
        .{
            .operation = .remove,
            .mode = .reserve,
            .selectors = &.{.{ .name = "removable" }},
            .options = executeOptions(
                loaded.view,
                prepared.paths.exact_lock,
            ),
            .orchestration_id = foreign_id,
        },
    );
    defer foreign_reservation.deinit();
    try std.testing.expectEqual(
        product_api.ExitStatus.success,
        foreign_reservation.result.exit_status,
    );
    try PrivateLiveRootRunner.writeTransport(release_fds[1], "G");
    const recovery_status = try reapTestProcessWithDeadline(
        recovery_pid,
        10_000,
    );
    recovery_reaped = true;
    try std.testing.expect(std.os.linux.W.IFEXITED(recovery_status));
    try std.testing.expectEqual(
        @as(u8, 0),
        std.os.linux.W.EXITSTATUS(recovery_status),
    );
    var active = (try store.interface().readActive(
        std.testing.allocator,
        fixture.state_path,
    )) orelse return error.MissingActiveState;
    defer active.deinit();
    try std.testing.expect(active.state.mutation_started);
    var contested_status = try runner.interface().inspect(
        std.testing.allocator,
    );
    defer contested_status.deinit();
    const acknowledgment = contested_status.deferred_acknowledgment orelse
        return error.MissingDeferredAcknowledgment;
    try std.testing.expectEqualSlices(
        u8,
        &foreign_id,
        &acknowledgment.acknowledgment_id,
    );
}

test "apt_system_orchestrator.test.required_privileged.production missing marker never clears a retained lower record" {
    try requirePrivilegedProductionTest();
    inline for (.{ false, true }) |recovering| {
        inline for (std.enums.values(MarkerLossRecordKind)) |record_kind| {
            var fixture = ProductionRunnerFixture.init(
                std.testing.allocator,
            ) catch |err| switch (err) {
                error.NamespaceUnavailable => return privilegedCoverageUnavailable(),
                else => return err,
            };
            defer fixture.deinit();
            var process: ProductionRunnerProcess = .{
                .io = std.testing.io,
                .dpkg = fixture.dpkg,
            };
            var production: production_backend.Backend = .{
                .io = std.testing.io,
                .now_unix = @import("fixtures/openpgp.zig").created + 30,
                .process_runner = process.interface(),
            };
            var backend: ProductionBackend = .{ .backend = &production };
            var private_runner: PrivateLiveRootRunner = .{
                .io = std.testing.io,
            };
            const runner = private_runner.interface();
            var profile: FakeProfileLoader = .{
                .state_path = fixture.state_path,
                .cache_path = fixture.cache_path,
                .source_paths = fixture.source_paths,
                .keyring_paths = fixture.keyring_paths,
            };
            var store: SystemStateStore = .{
                .allocator = std.testing.allocator,
                .io = std.testing.io,
            };
            var verifier: SystemResultVerifier = .{ .io = std.testing.io };
            var sources: FakeSources = .{};
            var engine: Engine = .{
                .profiles = profile.interface(),
                .runner = runner,
                .backend = backend.interface(),
                .store = store.interface(),
                .verifier = verifier.interface(),
                .ids = sources.ids(),
                .clock = sources.clock(),
            };
            var prepared = try expectReady(try engine.prepare(
                std.testing.allocator,
                mutationRequest(.remove, &.{"removable"}),
            ));
            defer prepared.deinit();

            if (recovering) {
                const mutation_child = try live_root.testing.forkProcess();
                if (mutation_child == 0) {
                    var crash: ProductionChildCrash = .{
                        .boundary = .after_completed_record,
                    };
                    production.completion_crash = crash.interface();
                    _ = engine.execute(
                        std.heap.page_allocator,
                        prepared,
                        true,
                    ) catch {};
                    std.os.linux.exit_group(107);
                }
                _ = try reapSignalTestProcess(mutation_child);
            }
            var recovery: ?RecoveryPreparation = if (recovering)
                switch (try engine.prepareRecovery(
                    std.testing.allocator,
                    "/profile.json",
                )) {
                    .ready => |value| value,
                    .result => return error.ExpectedRecoveryPreparation,
                }
            else
                null;
            defer if (recovery) |*value| value.deinit();
            const commit_child = try live_root.testing.forkProcess();
            if (commit_child == 0) {
                var crash: ProcessDeathCompletionCrash = .{
                    .boundary = .after_outer_committed,
                };
                engine.completion_crash = crash.interface();
                if (recovering) {
                    _ = engine.executeRecovery(
                        std.heap.page_allocator,
                        recovery.?,
                        true,
                    ) catch {};
                } else {
                    _ = engine.execute(
                        std.heap.page_allocator,
                        prepared,
                        true,
                    ) catch {};
                }
                std.os.linux.exit_group(108);
            }
            _ = try reapSignalTestProcess(commit_child);
            try fixture.dpkg.access(std.testing.io, "mutation-observed", .{});

            try std.Io.Dir.cwd().deleteFile(
                std.testing.io,
                "/" ++ root_operation.deferred_ack_path,
            );
            const record_source = try markerLossRecord(
                std.testing.allocator,
                record_kind,
            );
            defer std.testing.allocator.free(record_source);
            try writeAbsoluteTestFile(
                "/" ++ root_operation.record_path,
                record_source,
            );

            var retry = switch (try engine.prepareRecovery(
                std.testing.allocator,
                "/profile.json",
            )) {
                .ready => |value| value,
                .result => return error.ExpectedRecoveryPreparation,
            };
            defer retry.deinit();
            var blocked = try engine.executeRecovery(
                std.testing.allocator,
                retry,
                true,
            );
            defer blocked.deinit();
            try std.testing.expect(blocked.outcome != .success);
            var active = (try store.interface().readActive(
                std.testing.allocator,
                fixture.state_path,
            )) orelse return error.MissingActiveState;
            defer active.deinit();
            try std.testing.expectEqual(
                operation_state.Phase.completed,
                active.state.phase,
            );
            const record_after = try readTrustedOperationFile(
                std.testing.io,
                std.testing.allocator,
                "/" ++ root_operation.record_path,
                root_operation.maximum_document_bytes,
            );
            defer std.testing.allocator.free(record_after);
            try std.testing.expectEqualSlices(
                u8,
                record_source,
                record_after,
            );
            try expectForeignProductionReservationBlocked(
                &fixture,
                prepared,
                runner,
                backend.interface(),
                @splat(0xe5),
            );

            try std.Io.Dir.cwd().deleteFile(
                std.testing.io,
                "/" ++ root_operation.record_path,
            );
            var clean_retry = switch (try engine.prepareRecovery(
                std.testing.allocator,
                "/profile.json",
            )) {
                .ready => |value| value,
                .result => return error.ExpectedRecoveryPreparation,
            };
            defer clean_retry.deinit();
            var completed = try engine.executeRecovery(
                std.testing.allocator,
                clean_retry,
                true,
            );
            defer completed.deinit();
            try std.testing.expectEqual(api.Outcome.success, completed.outcome);
            try std.testing.expect((try store.interface().readActive(
                std.testing.allocator,
                fixture.state_path,
            )) == null);
        }
    }
}

test "apt_system_orchestrator.test.required_privileged.production recovery commits unavailable provenance before acknowledgment" {
    try requirePrivilegedProductionTest();
    inline for ([_]CompletionBoundary{
        .before_completion_published,
        .after_completion_published,
        .after_outer_committed,
        .after_recovery_acknowledged,
    }) |boundary| {
        var fixture = ProductionRunnerFixture.init(
            std.testing.allocator,
        ) catch |err| switch (err) {
            error.NamespaceUnavailable => return privilegedCoverageUnavailable(),
            else => return err,
        };
        defer fixture.deinit();
        var process: ProductionRunnerProcess = .{
            .io = std.testing.io,
            .dpkg = fixture.dpkg,
        };
        var production: production_backend.Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
        };
        var backend: ProductionBackend = .{ .backend = &production };
        var runner: PrivateLiveRootRunner = .{ .io = std.testing.io };
        var profile: FakeProfileLoader = .{
            .state_path = fixture.state_path,
            .cache_path = fixture.cache_path,
            .source_paths = fixture.source_paths,
            .keyring_paths = fixture.keyring_paths,
        };
        var store: SystemStateStore = .{
            .allocator = std.testing.allocator,
            .io = std.testing.io,
        };
        var verifier: SystemResultVerifier = .{ .io = std.testing.io };
        var sources: FakeSources = .{};
        var engine: Engine = .{
            .profiles = profile.interface(),
            .runner = runner.interface(),
            .backend = backend.interface(),
            .store = store.interface(),
            .verifier = verifier.interface(),
            .ids = sources.ids(),
            .clock = sources.clock(),
        };
        var prepared = try expectReady(try engine.prepare(
            std.testing.allocator,
            mutationRequest(.remove, &.{"removable"}),
        ));
        defer prepared.deinit();

        const execute_child = try live_root.testing.forkProcess();
        if (execute_child == 0) {
            var crash: ProductionChildCrash = .{
                .boundary = .after_completed_record,
            };
            production.completion_crash = crash.interface();
            _ = engine.execute(
                std.heap.page_allocator,
                prepared,
                true,
            ) catch {};
            std.os.linux.exit_group(101);
        }
        _ = try reapSignalTestProcess(execute_child);
        try fixture.dpkg.access(
            std.testing.io,
            "mutation-observed",
            .{},
        );
        const shared_transaction = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}/{s}",
            .{ fixture.state_path, transaction_result_name },
        );
        defer std.testing.allocator.free(shared_transaction);
        try std.testing.expectError(
            error.FileNotFound,
            std.Io.Dir.cwd().access(
                std.testing.io,
                shared_transaction,
                .{},
            ),
        );

        var recovery = switch (try engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer recovery.deinit();
        const recovery_child = try live_root.testing.forkProcess();
        if (recovery_child == 0) {
            var crash: ProcessDeathCompletionCrash = .{
                .boundary = boundary,
            };
            engine.completion_crash = crash.interface();
            _ = engine.executeRecovery(
                std.heap.page_allocator,
                recovery,
                true,
            ) catch {};
            std.os.linux.exit_group(102);
        }
        _ = try reapSignalTestProcess(recovery_child);

        var active = (try store.interface().readActive(
            std.testing.allocator,
            fixture.state_path,
        )).?;
        defer active.deinit();
        try std.testing.expect(active.state.mutation_started);
        var inspection = try runner.interface().inspect(
            std.testing.allocator,
        );
        defer inspection.deinit();
        const before_ack = boundary != .after_recovery_acknowledged;
        if (before_ack) {
            const marker = inspection.deferred_acknowledgment orelse
                return error.MissingRecoveryAcknowledgment;
            try std.testing.expect(
                marker.state == .pending or marker.state == .acknowledged,
            );
            const foreign_state_path = try std.fmt.allocPrint(
                std.testing.allocator,
                "{s}-foreign",
                .{fixture.state_path},
            );
            defer std.testing.allocator.free(foreign_state_path);
            var foreign_profile: FakeProfileLoader = .{
                .state_path = foreign_state_path,
                .cache_path = fixture.cache_path,
                .source_paths = fixture.source_paths,
                .keyring_paths = fixture.keyring_paths,
            };
            var loaded_foreign = try foreign_profile.interface().load(
                std.testing.allocator,
                "/profile.json",
            );
            defer loaded_foreign.deinit();
            var foreign = try runner.interface().workflow(
                std.testing.allocator,
                backend.interface(),
                .{
                    .operation = .remove,
                    .mode = .reserve,
                    .selectors = &.{.{ .name = "removable" }},
                    .options = executeOptions(
                        loaded_foreign.view,
                        prepared.paths.exact_lock,
                    ),
                    .orchestration_id = @splat(0xb7),
                },
            );
            defer foreign.deinit();
            try std.testing.expectEqual(
                product_api.ExitStatus.recovery,
                foreign.result.exit_status,
            );
        } else {
            try std.testing.expect(
                inspection.deferred_acknowledgment == null,
            );
            try std.testing.expectEqual(
                operation_state.Phase.completed,
                active.state.phase,
            );
        }

        var retry = switch (try engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer retry.deinit();
        var completed = try engine.executeRecovery(
            std.testing.allocator,
            retry,
            true,
        );
        defer completed.deinit();
        try std.testing.expectEqual(api.Outcome.success, completed.outcome);
        try std.testing.expect((try store.interface().readActive(
            std.testing.allocator,
            fixture.state_path,
        )) == null);
        var clean = try runner.interface().inspect(std.testing.allocator);
        defer clean.deinit();
        try std.testing.expectEqual(RootStatus.clean, clean.status);
        try std.testing.expect(clean.deferred_acknowledgment == null);
    }
}

test "apt_system_orchestrator.test.required_privileged.production runner retries every durable pre-mutation classification" {
    try requirePrivilegedProductionTest();
    const RetryCase = enum {
        downloaded_unbound,
        reserved_bound,
        mutating_bound,
        abandoned,
    };
    inline for ([_]RetryCase{
        .downloaded_unbound,
        .reserved_bound,
        .mutating_bound,
        .abandoned,
    }) |retry_case| {
        var fixture = ProductionRunnerFixture.init(
            std.testing.allocator,
        ) catch |err| switch (err) {
            error.NamespaceUnavailable => return privilegedCoverageUnavailable(),
            else => return err,
        };
        defer fixture.deinit();
        var process: ProductionRunnerProcess = .{
            .io = std.testing.io,
            .dpkg = fixture.dpkg,
        };
        var production: production_backend.Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
        };
        var backend: ProductionBackend = .{ .backend = &production };
        var runner: PrivateLiveRootRunner = .{ .io = std.testing.io };
        var profile: FakeProfileLoader = .{
            .state_path = fixture.state_path,
            .cache_path = fixture.cache_path,
            .source_paths = fixture.source_paths,
            .keyring_paths = fixture.keyring_paths,
        };
        var store: SystemStateStore = .{
            .allocator = std.testing.allocator,
            .io = std.testing.io,
        };
        var verifier: SystemResultVerifier = .{ .io = std.testing.io };
        var sources: FakeSources = .{};
        var engine: Engine = .{
            .profiles = profile.interface(),
            .runner = runner.interface(),
            .backend = backend.interface(),
            .store = store.interface(),
            .verifier = verifier.interface(),
            .ids = sources.ids(),
            .clock = sources.clock(),
        };
        var prepared = try expectReady(try engine.prepare(
            std.testing.allocator,
            mutationRequest(.remove, &.{"removable"}),
        ));
        defer prepared.deinit();
        const held_path = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}.held",
            .{fixture.source_path},
        );
        defer std.testing.allocator.free(held_path);

        const child = try live_root.testing.forkProcess();
        if (child == 0) {
            switch (retry_case) {
                .downloaded_unbound, .reserved_bound, .mutating_bound => {
                    var crash: ProcessDeathCompletionCrash = .{
                        .boundary = switch (retry_case) {
                            .downloaded_unbound => .after_downloaded_state,
                            .reserved_bound => .after_ownership_reserved,
                            .mutating_bound => .after_mutating_state,
                            .abandoned => unreachable,
                        },
                    };
                    engine.completion_crash = crash.interface();
                    _ = engine.execute(
                        std.heap.page_allocator,
                        prepared,
                        true,
                    ) catch {};
                    std.os.linux.exit_group(96);
                },
                .abandoned => {
                    var abandon: AbandonAfterReservationTransport = .{
                        .io = std.testing.io,
                        .disrupted_path = fixture.source_path,
                        .held_path = held_path,
                    };
                    runner.transport_crash = abandon.interface();
                    var result = engine.execute(
                        std.heap.page_allocator,
                        prepared,
                        true,
                    ) catch std.os.linux.exit_group(97);
                    result.deinit();
                    std.os.linux.exit_group(98);
                },
            }
        }
        const child_status = try reapSignalTestProcess(child);
        try std.testing.expect(std.os.linux.W.IFEXITED(child_status));
        if (retry_case == .abandoned) {
            try std.Io.Dir.cwd().rename(
                held_path,
                std.Io.Dir.cwd(),
                fixture.source_path,
                std.testing.io,
            );
        }
        try std.testing.expectError(
            error.FileNotFound,
            fixture.dpkg.access(
                std.testing.io,
                "mutation-observed",
                .{},
            ),
        );

        var active = (try store.interface().readActive(
            std.testing.allocator,
            fixture.state_path,
        )).?;
        defer active.deinit();
        try std.testing.expectEqual(
            retry_case != .downloaded_unbound and
                retry_case != .reserved_bound,
            active.state.mutation_started,
        );
        const original_attempt = active.state.attempt_id;
        if (retry_case != .downloaded_unbound) {
            inline for ([_][]const []const u8{
                &.{"removable"},
                &.{"foreign"},
            }) |selectors| {
                var blocked = try engine.prepare(
                    std.testing.allocator,
                    mutationRequest(.remove, selectors),
                );
                switch (blocked) {
                    .result => |*result| {
                        defer result.deinit();
                        try std.testing.expectEqual(
                            api.Outcome.recovery,
                            result.outcome,
                        );
                    },
                    .ready => |*unexpected| {
                        unexpected.deinit();
                        return error.ExpectedRecoveryDiagnostic;
                    },
                }
                var still_active = (try store.interface().readActive(
                    std.testing.allocator,
                    fixture.state_path,
                )).?;
                defer still_active.deinit();
                try std.testing.expectEqualSlices(
                    u8,
                    &original_attempt,
                    &still_active.state.attempt_id,
                );
            }
        }

        var recovery = switch (try engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer recovery.deinit();
        var completed = try engine.executeRecovery(
            std.testing.allocator,
            recovery,
            true,
        );
        defer completed.deinit();
        if (retry_case != .downloaded_unbound) {
            try std.testing.expectEqual(
                api.Outcome.recovery,
                completed.outcome,
            );
            try std.testing.expectEqual(
                api.MutationStatus.unknown,
                completed.mutation_status.?,
            );
            try std.testing.expect(!completed.changed);
            try std.testing.expectError(
                error.FileNotFound,
                fixture.dpkg.access(
                    std.testing.io,
                    "mutation-observed",
                    .{},
                ),
            );
            var retained_active = try store.interface().readActive(
                std.testing.allocator,
                fixture.state_path,
            );
            defer if (retained_active) |*owned| owned.deinit();
            try std.testing.expect(retained_active != null);
        } else {
            try std.testing.expectEqual(api.Outcome.success, completed.outcome);
            try fixture.dpkg.access(
                std.testing.io,
                "mutation-observed",
                .{},
            );
            try std.testing.expect((try store.interface().readActive(
                std.testing.allocator,
                fixture.state_path,
            )) == null);
            var clean = try runner.interface().inspect(std.testing.allocator);
            defer clean.deinit();
            try std.testing.expectEqual(RootStatus.clean, clean.status);
            try std.testing.expect(clean.deferred_acknowledgment == null);
        }
    }
}

test "apt_system_orchestrator.test.backend failure text survives transport destruction" {
    {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        harness.runner.transport_roundtrip = true;
        harness.backend.plan_status = .planning;
        const outcome = try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        );
        switch (outcome) {
            .result => |value| {
                var result = value;
                defer result.deinit();
                try std.testing.expectEqualStrings("injected failure", result.summary);
                try std.testing.expectEqualStrings(
                    "injected failure",
                    result.diagnostics[0].message,
                );
                const source = try result.canonicalJson(std.testing.allocator);
                defer std.testing.allocator.free(source);
                try std.testing.expect(std.mem.indexOf(
                    u8,
                    source,
                    "\"summary\":\"injected failure\"",
                ) != null);
            },
            .ready => return error.UnexpectedPreparation,
        }
    }
    {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        harness.runner.transport_roundtrip = true;
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.backend.download_status = .download;
        var result = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqualStrings("injected failure", result.summary);
        try std.testing.expectEqualStrings(
            "injected failure",
            result.diagnostics[0].message,
        );
        const source = try result.canonicalJson(std.testing.allocator);
        defer std.testing.allocator.free(source);
        try std.testing.expect(std.mem.indexOf(
            u8,
            source,
            "\"summary\":\"injected failure\"",
        ) != null);
    }
}

test "apt_system_orchestrator.test.lower root recovery blocks repository and package work" {
    inline for (.{ api.Operation.update, api.Operation.install }) |operation| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        harness.runner.inspect_status = .recovery_required;
        const outcome = try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(
                operation,
                if (operation == .install) &.{"alpha"} else &.{},
            ),
        );
        switch (outcome) {
            .result => |value| {
                var result = value;
                defer result.deinit();
                try std.testing.expectEqual(api.Outcome.recovery, result.outcome);
                try std.testing.expectEqual(
                    api.DiagnosticId.recovery_required,
                    result.diagnostics[0].id,
                );
            },
            .ready => return error.UnexpectedPreparation,
        }
        try std.testing.expectEqual(@as(usize, 0), harness.backend.route_calls);
        try std.testing.expectEqual(@as(usize, 0), harness.backend.workflow_calls);
        try std.testing.expectEqual(@as(usize, 0), harness.store.reserve_calls);
    }
}

test "apt_system_orchestrator.test.required_privileged.production composition instantiates the delivered engine" {
    var backend: production_backend.Backend = undefined;
    var composition: ProductionComposition = undefined;
    composition.init(
        std.testing.allocator,
        std.testing.io,
        &backend,
    );
    try std.testing.expect(composition.orchestrator() == &composition.engine);
    try std.testing.expect(
        composition.engine.runner.context == @as(*anyopaque, @ptrCast(&composition.runner)),
    );
    try std.testing.expect(
        composition.engine.backend.context == @as(*anyopaque, @ptrCast(&composition.backend)),
    );
}

test "apt_system_orchestrator.test.required_privileged.production CLI reconciliation reads exact active state under lock" {
    try requirePrivilegedProductionTest();
    const root_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "/root/debz-apt-cli-reconciliation-{d}",
        .{std.os.linux.getpid()},
    );
    defer std.testing.allocator.free(root_path);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, root_path) catch {};
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{root_path},
    );
    defer std.testing.allocator.free(state_path);
    const attempt_id: [32]u8 = @splat(0x61);
    var paths = try pathsFor(
        std.testing.allocator,
        state_path,
        attempt_id,
    );
    defer paths.deinit(std.testing.allocator);
    var store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    const state_store = store.interface();
    var states = try reserveVerifyingTestState(
        std.testing.allocator,
        state_store,
        state_path,
        paths,
        attempt_id,
    );
    defer states.deinit();
    const prepared: Preparation = .{
        .request = .{
            .operation = .install,
            .profile_path = "/profile.json",
            .packages = &.{"alpha"},
        },
        .request_sha256 = @splat(0x53),
        .profile = states.current.state.profile,
        .profile_state_path = state_path,
        .attempt_id = attempt_id,
        .active_generation = states.current.state.generation,
        .active_digest_sha256 = states.current.state.digest_sha256,
        .paths = paths,
        .exact_lock = states.current.state.exact_lock.?,
        .review = &.{},
        .arena = undefined,
        .backing_allocator = std.testing.allocator,
    };
    var engine: Engine = undefined;
    engine.store = state_store;
    var runner: FakeRunner = .{ .allocator = std.testing.allocator };
    defer runner.deinit();
    engine.runner = runner.interface();
    var profiles: FakeProfileLoader = .{
        .state_path = state_path,
        .profile_digest = 0x54,
        .reference_digest = 0x55,
    };
    engine.profiles = profiles.interface();
    var verifier: FakeVerifier = .{
        .lock_digest = @splat(0x51),
        .transaction_digest = @splat(0x52),
    };
    engine.verifier = verifier.interface();
    var result = try engine.reconcilePreparedError(
        std.testing.allocator,
        prepared,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
    try std.testing.expect(!result.changed);
    try std.testing.expectEqual(
        api.MutationStatus.unknown,
        result.mutation_status.?,
    );
    try std.testing.expectEqual(
        api.DiagnosticId.recovery_required,
        result.diagnostics[0].id,
    );
    try std.testing.expect(result.profile == null);
    try std.testing.expect(result.evidence.exact_lock == null);
    try std.testing.expect(result.evidence.transaction_result == null);
    try std.testing.expect(result.evidence.active_operation_state == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        result.summary,
        "debz recover --system-profile /profile.json",
    ) == null);

    const original_active = try states.current.state.canonicalJson(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(original_active);
    inline for (.{
        "missing",
        "stale-generation",
        "foreign-outer",
        "foreign-profile",
        "profile-drift",
        "lock-replacement",
    }) |fixture| {
        if (std.mem.eql(u8, fixture, "missing")) {
            try std.Io.Dir.cwd().deleteFile(
                std.testing.io,
                paths.active_state,
            );
        } else if (std.mem.eql(u8, fixture, "profile-drift")) {
            profiles.profile_digest ^= 0xff;
        } else if (std.mem.eql(u8, fixture, "lock-replacement")) {
            verifier.lock_valid = false;
        } else {
            var altered = states.current.state;
            if (std.mem.eql(u8, fixture, "stale-generation"))
                altered.generation -= 1
            else if (std.mem.eql(u8, fixture, "foreign-outer"))
                altered.attempt_id[0] ^= 0xff
            else
                altered.profile.sha256[0] ^= 0xff;
            var owned_altered = try operation_state.create(
                std.testing.allocator,
                altered,
            );
            defer owned_altered.deinit();
            const altered_bytes = try owned_altered.state.canonicalJson(
                std.testing.allocator,
            );
            defer std.testing.allocator.free(altered_bytes);
            try writeAbsoluteTestFile(paths.active_state, altered_bytes);
        }
        var fault_result = try engine.reconcilePreparedError(
            std.testing.allocator,
            prepared,
        );
        defer fault_result.deinit();
        try std.testing.expectEqual(
            api.MutationStatus.unknown,
            fault_result.mutation_status.?,
        );
        try std.testing.expect(!fault_result.changed);
        try std.testing.expect(fault_result.profile == null);
        try std.testing.expect(
            fault_result.evidence.active_operation_state == null,
        );
        profiles.profile_digest = 0x54;
        verifier.lock_valid = true;
        try writeAbsoluteTestFile(paths.active_state, original_active);
    }

    const retained_request = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        paths.request,
        std.testing.allocator,
        .limited(api.maximum_document_bytes),
    );
    defer std.testing.allocator.free(retained_request);
    try std.Io.Dir.cwd().deleteFile(std.testing.io, paths.request);
    var unreadable_request = switch (try engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .result => |value| value,
        .ready => return error.ExpectedRecoveryDiagnostic,
    };
    defer unreadable_request.deinit();
    try std.testing.expectEqual(
        api.MutationStatus.unknown,
        unreadable_request.mutation_status.?,
    );
    try std.testing.expect(unreadable_request.profile == null);
    try writeAbsoluteTestFile(paths.request, retained_request);

    try writeAbsoluteTestFile(
        paths.active_state,
        "{\"corrupt\":true}\n",
    );
    var unknown = try engine.reconcilePreparedError(
        std.testing.allocator,
        prepared,
    );
    defer unknown.deinit();
    try std.testing.expectEqual(api.MutationStatus.unknown, unknown.mutation_status.?);
    try std.testing.expect(!unknown.changed);
    try std.testing.expect(unknown.profile == null);
    try std.testing.expect(unknown.evidence.active_operation_state == null);
    for ([_]facade_cli.OutputFormat{ .human, .json }) |output| {
        var stdout: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stdout.deinit();
        var stderr: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stderr.deinit();
        try facade_cli.writeResult(
            std.testing.allocator,
            unknown,
            output,
            &stdout.writer,
            &stderr.writer,
        );
        const rendered = if (output == .json)
            stdout.written()
        else
            stderr.written();
        try std.testing.expect(std.mem.indexOf(
            u8,
            rendered,
            if (output == .json)
                "\"mutation_status\":\"unknown\""
            else
                "Changed: unknown (recovery required)",
        ) != null);
        if (output == .json)
            try std.testing.expectEqual(
                @as(usize, 1),
                std.mem.count(u8, rendered, "\n"),
            );
    }

    var recovery_result = switch (try engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .result => |value| value,
        .ready => return error.ExpectedRecoveryDiagnostic,
    };
    defer recovery_result.deinit();
    try std.testing.expectEqual(
        api.MutationStatus.unknown,
        recovery_result.mutation_status.?,
    );
    try std.testing.expect(recovery_result.profile == null);
    try std.testing.expect(
        recovery_result.evidence.active_operation_state == null,
    );
}

test "apt_system_orchestrator.test.reconciliation distinguishes durable pre-mutation lower mutation and unknown state" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();

    var pre_mutation = try harness.engine.reconcilePreparedError(
        std.testing.allocator,
        prepared,
    );
    defer pre_mutation.deinit();
    try std.testing.expectEqual(
        api.ExitStatus.configuration,
        pre_mutation.exit_status,
    );
    try std.testing.expect(!pre_mutation.changed);
    try std.testing.expect(pre_mutation.mutation_status == null);
    try std.testing.expect(
        pre_mutation.evidence.active_operation_state == null,
    );
    try std.testing.expect(harness.store.active_bytes == null);
    try std.testing.expectEqual(
        @as(usize, 1),
        harness.runner.ownership_finalize_calls,
    );
    try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);

    inline for (.{
        "read-error",
        "absent",
        "foreign",
    }) |mode| {
        harness.store.fail_inspect_active = std.mem.eql(u8, mode, "read-error");
        harness.store.hide_inspected_active = std.mem.eql(u8, mode, "absent");
        harness.store.foreign_inspected_active = std.mem.eql(u8, mode, "foreign");
        var unknown = try harness.engine.reconcilePreparedError(
            std.testing.allocator,
            prepared,
        );
        defer unknown.deinit();
        try std.testing.expectEqual(api.ExitStatus.recovery, unknown.exit_status);
        try std.testing.expectEqual(
            api.MutationStatus.unknown,
            unknown.mutation_status.?,
        );
        try std.testing.expect(!unknown.changed);
        try std.testing.expect(unknown.profile == null);
        try std.testing.expect(unknown.evidence.exact_lock == null);
        try std.testing.expect(unknown.evidence.transaction_result == null);
        try std.testing.expect(
            unknown.evidence.root_operation_completion == null,
        );
        try std.testing.expect(
            unknown.evidence.active_operation_state == null,
        );
    }
    harness.store.fail_inspect_active = false;
    harness.store.hide_inspected_active = false;
    harness.store.foreign_inspected_active = false;
    harness.runner.inspect_deferred_acknowledgment =
        try root_operation.createDeferredAcknowledgment(.{
            .state = .released,
            .attempt_id = @splat(0x77),
            .acknowledgment_id = prepared.attempt_id,
        });
    var lower_mutated = try harness.engine.reconcilePreparedError(
        std.testing.allocator,
        prepared,
    );
    defer lower_mutated.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, lower_mutated.exit_status);
    try std.testing.expect(!lower_mutated.changed);
    try std.testing.expectEqual(
        api.MutationStatus.unknown,
        lower_mutated.mutation_status.?,
    );
    try std.testing.expect(lower_mutated.profile == null);
    try std.testing.expect(lower_mutated.evidence.exact_lock == null);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
}

test "apt_system_orchestrator.test.pre-mutation reconciliation rejects generation race and retains lower exclusion" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    harness.store.advance_on_inspect_call =
        harness.store.inspect_active_calls + 2;
    var result = try harness.engine.reconcilePreparedError(
        std.testing.allocator,
        prepared,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
    try std.testing.expectEqual(
        api.MutationStatus.unknown,
        result.mutation_status.?,
    );
    try std.testing.expectEqual(api.Operation.recover, result.operation);
    try std.testing.expectEqual(
        api.Operation.install,
        result.recovery_context.?.requested_operation.?,
    );
    try std.testing.expect(result.recovery_context.?.action == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        result.summary,
        "debz recover --system-profile",
    ) == null);
    try std.testing.expect(!result.changed);
    try std.testing.expect(result.profile == null);
    try std.testing.expect(result.evidence.active_operation_state == null);
    try std.testing.expect(
        harness.runner.inspect_deferred_acknowledgment != null,
    );
    var active = try operation_state.decode(
        std.testing.allocator,
        harness.store.active_bytes.?,
        operation_state.maximum_document_bytes,
    );
    defer active.deinit();
    try std.testing.expect(active.state.mutation_started);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
}

test "apt_system_orchestrator.test.finish pre-mutation fsync and CAS races never fabricate unchanged" {
    inline for (.{ "fsync", "stale-cas" }) |fault| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        harness.backend.download_status = .download;
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        if (std.mem.eql(u8, fault, "fsync"))
            harness.store.fail_finish = true
        else
            harness.store.stale_finish_once = true;
        var result = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
        try std.testing.expect(harness.store.active_bytes != null);
        try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
        try std.testing.expectEqual(
            api.MutationStatus.unknown,
            result.mutation_status.?,
        );
        try std.testing.expectEqual(api.Operation.recover, result.operation);
        try std.testing.expectEqual(
            api.Operation.install,
            result.recovery_context.?.requested_operation.?,
        );
        try std.testing.expect(result.recovery_context.?.action == null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            result.summary,
            "debz recover --system-profile",
        ) == null);
        try std.testing.expect(!result.changed);
        try std.testing.expect(result.profile == null);
    }
}

test "apt_system_orchestrator.test.pre-mutation reconciliation claims survive every outer crash boundary" {
    const CrashCase = enum {
        after_claim_publish,
        after_outer_recheck,
        after_retained_publish,
        after_active_cas,
        before_claim_ack,
        after_claim_ack,
    };
    inline for (std.enums.values(CrashCase)) |crash_case| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.verifier.lock_failure_on_check = .{
            .check = harness.verifier.lock_checks + 1,
            .failure = error.OperationalVerificationFailure,
        };
        var crash: FakeCompletionCrash = .{
            .boundary = switch (crash_case) {
                .after_claim_publish => .after_pre_mutation_claim_published,
                .after_outer_recheck => .after_pre_mutation_outer_rechecked,
                .before_claim_ack => .before_ownership_acknowledged,
                .after_claim_ack => .after_ownership_acknowledged,
                .after_retained_publish,
                .after_active_cas,
                => .after_backend_success,
            },
        };
        switch (crash_case) {
            .after_claim_publish,
            .after_outer_recheck,
            .before_claim_ack,
            .after_claim_ack,
            => harness.engine.completion_crash = crash.interface(),
            .after_retained_publish => harness.store.fail_after_retain_once = true,
            .after_active_cas => harness.store.fail_after_active_cas_once = true,
        }
        var interrupted = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer interrupted.deinit();
        try std.testing.expectEqual(
            api.ExitStatus.recovery,
            interrupted.exit_status,
        );
        try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
        harness.engine.completion_crash = null;

        if (crash_case == .after_active_cas) {
            const marker = harness.runner.inspect_deferred_acknowledgment orelse
                return error.MissingOwnershipAcknowledgment;
            try std.testing.expectEqual(
                root_operation.DeferredAcknowledgmentState
                    .pre_mutation_reconciliation_claim,
                marker.state,
            );
            const foreign = try harness.engine.prepareRecovery(
                std.testing.allocator,
                "/foreign-profile.json",
            );
            switch (foreign) {
                .ready => |value| {
                    var unexpected = value;
                    unexpected.deinit();
                    return error.UnexpectedForeignRecovery;
                },
                .result => |value| {
                    var result = value;
                    defer result.deinit();
                    try std.testing.expectEqual(
                        api.MutationStatus.unknown,
                        result.mutation_status.?,
                    );
                },
            }
            try std.testing.expect(
                harness.runner.inspect_deferred_acknowledgment != null,
            );
        }

        var recovery = switch (try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => |result| {
                var owned = result;
                defer owned.deinit();
                return error.ExpectedRecoveryPreparation;
            },
        };
        defer recovery.deinit();
        var converged = try harness.engine.executeRecovery(
            std.testing.allocator,
            recovery,
            true,
        );
        defer converged.deinit();
        try std.testing.expectEqual(
            api.ExitStatus.configuration,
            converged.exit_status,
        );
        try std.testing.expect(!converged.changed);
        try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
        try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
        try std.testing.expect(harness.store.active_bytes == null);
        try std.testing.expect(
            harness.runner.inspect_deferred_acknowledgment == null,
        );
    }
}

test "apt_system_orchestrator.test.verifier OOM and invariant failures bypass reconciliation" {
    inline for ([_]VerificationError{
        error.OutOfMemory,
        error.InvariantViolation,
    }) |failure| {
        var lock_harness = Harness.init(std.testing.allocator);
        defer lock_harness.deinit();
        lock_harness.rebind();
        var lock_prepared = try expectReady(try lock_harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer lock_prepared.deinit();
        const lock_inspections = lock_harness.runner.inspect_calls;
        const lock_finish_calls = lock_harness.store.finish_calls;
        lock_harness.verifier.lock_failure_on_check = .{
            .check = lock_harness.verifier.lock_checks + 1,
            .failure = failure,
        };
        if (failure == error.OutOfMemory)
            try std.testing.expectError(
                error.OutOfMemory,
                lock_harness.engine.execute(
                    std.testing.allocator,
                    lock_prepared,
                    true,
                ),
            )
        else
            try std.testing.expectError(
                error.InvariantViolation,
                lock_harness.engine.execute(
                    std.testing.allocator,
                    lock_prepared,
                    true,
                ),
            );
        try std.testing.expectEqual(
            lock_inspections,
            lock_harness.runner.inspect_calls,
        );
        try std.testing.expectEqual(
            lock_finish_calls,
            lock_harness.store.finish_calls,
        );
        try std.testing.expect(lock_harness.store.active_bytes != null);
        try std.testing.expectEqual(
            @as(usize, 0),
            lock_harness.backend.execute_calls,
        );

        var transaction_harness = Harness.init(std.testing.allocator);
        defer transaction_harness.deinit();
        transaction_harness.rebind();
        var transaction_prepared = try expectReady(
            try transaction_harness.engine.prepare(
                std.testing.allocator,
                mutationRequest(.install, &.{"alpha"}),
            ),
        );
        defer transaction_prepared.deinit();
        transaction_harness.verifier.transaction_failure_on_check = .{
            .check = transaction_harness.verifier.transaction_checks + 1,
            .failure = failure,
        };
        const transaction_inspections =
            transaction_harness.runner.inspect_calls;
        if (failure == error.OutOfMemory)
            try std.testing.expectError(
                error.OutOfMemory,
                transaction_harness.engine.execute(
                    std.testing.allocator,
                    transaction_prepared,
                    true,
                ),
            )
        else
            try std.testing.expectError(
                error.InvariantViolation,
                transaction_harness.engine.execute(
                    std.testing.allocator,
                    transaction_prepared,
                    true,
                ),
            );
        try std.testing.expectEqual(
            transaction_inspections,
            transaction_harness.runner.inspect_calls,
        );
        try std.testing.expectEqual(
            @as(usize, 1),
            transaction_harness.backend.execute_calls,
        );
        try std.testing.expectEqual(
            @as(usize, 0),
            transaction_harness.runner.ownership_finalize_calls,
        );
        var active = try operation_state.decode(
            std.testing.allocator,
            transaction_harness.store.active_bytes.?,
            operation_state.maximum_document_bytes,
        );
        defer active.deinit();
        try std.testing.expect(active.state.mutation_started);

        var acknowledgment_harness = Harness.init(std.testing.allocator);
        defer acknowledgment_harness.deinit();
        acknowledgment_harness.rebind();
        var acknowledgment_prepared = try expectReady(
            try acknowledgment_harness.engine.prepare(
                std.testing.allocator,
                mutationRequest(.install, &.{"alpha"}),
            ),
        );
        defer acknowledgment_prepared.deinit();
        acknowledgment_harness.verifier.lock_failure_on_check = .{
            .check = acknowledgment_harness.verifier.lock_checks + 4,
            .failure = failure,
        };
        if (failure == error.OutOfMemory)
            try std.testing.expectError(
                error.OutOfMemory,
                acknowledgment_harness.engine.execute(
                    std.testing.allocator,
                    acknowledgment_prepared,
                    true,
                ),
            )
        else
            try std.testing.expectError(
                error.InvariantViolation,
                acknowledgment_harness.engine.execute(
                    std.testing.allocator,
                    acknowledgment_prepared,
                    true,
                ),
            );
        try std.testing.expectEqual(
            @as(usize, 0),
            acknowledgment_harness.runner.ownership_finalize_calls,
        );
        try std.testing.expect(
            acknowledgment_harness.store.active_bytes != null,
        );
    }
}

test "apt_system_orchestrator.test.operational verifier failures enter durable reconciliation" {
    {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.verifier.lock_failure_on_check = .{
            .check = harness.verifier.lock_checks + 1,
            .failure = error.OperationalVerificationFailure,
        };
        var result = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(
            api.ExitStatus.configuration,
            result.exit_status,
        );
        try std.testing.expect(!result.changed);
        try std.testing.expect(harness.store.active_bytes == null);
        try std.testing.expect(
            harness.runner.inspect_deferred_acknowledgment == null,
        );
    }
    {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.verifier.transaction_failure_on_check = .{
            .check = harness.verifier.transaction_checks + 1,
            .failure = error.OperationalVerificationFailure,
        };
        const inspections = harness.runner.inspect_calls;
        var result = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
        try std.testing.expectEqual(
            api.MutationStatus.unknown,
            result.mutation_status.?,
        );
        try std.testing.expect(harness.runner.inspect_calls > inspections);
        try std.testing.expect(harness.store.active_bytes != null);
        try std.testing.expectEqual(@as(usize, 1), harness.backend.execute_calls);
    }
}

test "apt_system_orchestrator.test.lower marker and record matrix never infers mutation from acknowledgment alone" {
    for (std.enums.values(root_operation.DeferredAcknowledgmentState)) |state| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        const claim_binding: ?root_operation.PreMutationReconciliationClaimBinding =
            if (state == .pre_mutation_reconciliation_claim) .{
                .outer_attempt_id = prepared.attempt_id,
                .outer_generation = 99,
                .outer_state_sha256 = @splat(0x84),
                .profile_sha256 = @splat(0x85),
                .profile_reference_sha256 = @splat(0x86),
                .exact_lock_sha256 = @splat(0x87),
                .semantic_request_sha256 = @splat(0x88),
            } else null;
        harness.runner.inspect_deferred_acknowledgment =
            try root_operation.createDeferredAcknowledgment(.{
                .state = state,
                .attempt_id = if (claim_binding) |claim|
                    root_operation.preMutationReconciliationClaimId(claim)
                else
                    @splat(0x81),
                .completion_sha256 = if (state == .pending or
                    state == .acknowledged)
                    @splat(0x82)
                else
                    null,
                .provenance_sha256 = if (state == .pending or
                    state == .acknowledged)
                    @splat(0x83)
                else
                    null,
                .pre_mutation_claim = claim_binding,
                .acknowledgment_id = prepared.attempt_id,
            });
        var result = try harness.engine.reconcilePreparedError(
            std.testing.allocator,
            prepared,
        );
        defer result.deinit();
        try std.testing.expectEqual(
            api.MutationStatus.unknown,
            result.mutation_status.?,
        );
        try std.testing.expect(!result.changed);
        try std.testing.expect(result.profile == null);
        try std.testing.expect(result.evidence.exact_lock == null);
    }
}

test "apt_system_orchestrator.test.only exact abandoned lower record permits pre-mutation finalization" {
    inline for (.{
        "exact-abandoned",
        "foreign-ack",
        "bound-abandoned",
        "record-only",
        "released-mutating",
    }) |fixture| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        const profile: ProfileView = .{
            .binding = prepared.profile,
            .source_paths = &harness.profile.source_paths,
            .config_paths = &.{},
            .keyring_paths = &harness.profile.keyring_paths,
            .architecture = "amd64",
            .foreign_architectures = &.{},
            .repository_policy = .strict_priority,
            .cache_path = harness.profile.cache_path,
            .state_path = harness.profile.state_path,
            .conffile = .keep_existing,
            .proxy = null,
            .credential_reference = null,
        };
        const selectors = [_]solver.PackageSelector{.{
            .name = "alpha",
        }};
        const workflow_request: WorkflowRequest = .{
            .operation = .install,
            .mode = .execute,
            .selectors = &selectors,
            .options = executeOptions(
                profile,
                prepared.paths.exact_lock,
            ),
            .orchestration_id = prepared.attempt_id,
        };
        const marker_state: root_operation.DeferredAcknowledgmentState =
            if (std.mem.eql(u8, fixture, "bound-abandoned"))
                .bound
            else
                .abandoned;
        harness.runner.inspect_deferred_acknowledgment =
            try root_operation.createDeferredAcknowledgment(.{
                .state = marker_state,
                .attempt_id = @splat(0x82),
                .acknowledgment_id = if (std.mem.eql(
                    u8,
                    fixture,
                    "foreign-ack",
                ))
                    @splat(0x84)
                else
                    prepared.attempt_id,
            });
        if (std.mem.eql(u8, fixture, "released-mutating")) {
            harness.runner.inspect_deferred_acknowledgment =
                try root_operation.createDeferredAcknowledgment(.{
                    .state = .released,
                    .attempt_id = @splat(0x82),
                    .acknowledgment_id = prepared.attempt_id,
                });
            try harness.runner.publishFakeMutatingRecord(
                std.testing.allocator,
                workflow_request,
            );
        } else {
            try harness.runner.publishFakeAbandonedRecord(
                std.testing.allocator,
                workflow_request,
            );
            if (std.mem.eql(u8, fixture, "record-only"))
                harness.runner.inspect_deferred_acknowledgment = null;
        }
        var result = try harness.engine.reconcilePreparedError(
            std.testing.allocator,
            prepared,
        );
        defer result.deinit();
        if (std.mem.eql(u8, fixture, "exact-abandoned")) {
            try std.testing.expectEqual(
                api.ExitStatus.configuration,
                result.exit_status,
            );
            try std.testing.expect(!result.changed);
            try std.testing.expect(result.mutation_status == null);
            try std.testing.expect(harness.store.active_bytes == null);
            try std.testing.expect(
                harness.runner.inspect_deferred_acknowledgment == null,
            );
        } else {
            try std.testing.expectEqual(
                api.MutationStatus.unknown,
                result.mutation_status.?,
            );
            try std.testing.expect(!result.changed);
            try std.testing.expect(result.profile == null);
            try std.testing.expect(harness.store.active_bytes != null);
        }
    }
}

const ActiveStateFault = enum {
    stale_generation,
    foreign_attempt,
    foreign_profile,
};

fn injectActiveStateFault(
    store: *FakeStateStore,
    fault: ActiveStateFault,
) !void {
    var active = try operation_state.decode(
        std.testing.allocator,
        store.active_bytes orelse return error.MissingActiveState,
        operation_state.maximum_document_bytes,
    );
    defer active.deinit();
    var changed = active.state;
    switch (fault) {
        .stale_generation => changed.generation -= 1,
        .foreign_attempt => changed.attempt_id[0] ^= 0xff,
        .foreign_profile => changed.profile.sha256[0] ^= 0xff,
    }
    var replacement = try operation_state.create(
        std.testing.allocator,
        changed,
    );
    defer replacement.deinit();
    const bytes = try replacement.state.canonicalJson(store.allocator);
    store.allocator.free(store.active_bytes.?);
    store.active_bytes = bytes;
}

test "apt_system_orchestrator.test.recovery execution state faults are evidence-free unknown and do not replay mutation" {
    inline for (.{
        "missing",
        "corrupt",
        "stale-generation",
        "foreign-outer",
        "foreign-profile",
        "profile-drift",
        "lock-replacement",
    }) |fixture| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.runner.fail_mode = .execute;
        var interrupted = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer interrupted.deinit();
        harness.runner.fail_mode = null;
        var recovery = switch (try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer recovery.deinit();
        const recover_calls = harness.backend.recover_calls;

        if (std.mem.eql(u8, fixture, "missing")) {
            harness.store.allocator.free(harness.store.active_bytes.?);
            harness.store.active_bytes = null;
        } else if (std.mem.eql(u8, fixture, "corrupt")) {
            harness.store.allocator.free(harness.store.active_bytes.?);
            harness.store.active_bytes = try harness.store.allocator.dupe(
                u8,
                "{\"corrupt\":true}",
            );
        } else if (std.mem.eql(u8, fixture, "stale-generation")) {
            try injectActiveStateFault(
                &harness.store,
                .stale_generation,
            );
        } else if (std.mem.eql(u8, fixture, "foreign-outer")) {
            try injectActiveStateFault(&harness.store, .foreign_attempt);
        } else if (std.mem.eql(u8, fixture, "foreign-profile")) {
            try injectActiveStateFault(&harness.store, .foreign_profile);
        } else if (std.mem.eql(u8, fixture, "profile-drift")) {
            harness.profile.profile_digest ^= 0xff;
        } else {
            harness.verifier.lock_valid = false;
        }

        var result = try harness.engine.executeRecovery(
            std.testing.allocator,
            recovery,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
        try std.testing.expectEqual(
            api.MutationStatus.unknown,
            result.mutation_status.?,
        );
        try std.testing.expect(!result.changed);
        try std.testing.expect(result.profile == null);
        try std.testing.expect(result.evidence.exact_lock == null);
        try std.testing.expect(result.evidence.transaction_result == null);
        try std.testing.expect(
            result.evidence.root_operation_completion == null,
        );
        try std.testing.expect(
            result.evidence.active_operation_state == null,
        );
        try std.testing.expectEqual(recover_calls, harness.backend.recover_calls);
        for ([_]facade_cli.OutputFormat{ .human, .json }) |output| {
            var stdout: std.Io.Writer.Allocating =
                .init(std.testing.allocator);
            defer stdout.deinit();
            var stderr: std.Io.Writer.Allocating =
                .init(std.testing.allocator);
            defer stderr.deinit();
            try facade_cli.writeResult(
                std.testing.allocator,
                result,
                output,
                &stdout.writer,
                &stderr.writer,
            );
            const rendered = if (output == .json)
                stdout.written()
            else
                stderr.written();
            try std.testing.expect(std.mem.indexOf(
                u8,
                rendered,
                if (output == .json)
                    "\"mutation_status\":\"unknown\""
                else
                    "Changed: unknown (recovery required)",
            ) != null);
            if (output == .json)
                try std.testing.expectEqual(
                    @as(usize, 1),
                    std.mem.count(u8, rendered, "\n"),
                );
        }
    }
}

test "apt_system_orchestrator.test.recovery preparation request faults are evidence-free unknown" {
    inline for (.{ "unreadable", "mismatch" }) |fixture| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.runner.fail_mode = .execute;
        var interrupted = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer interrupted.deinit();
        harness.runner.fail_mode = null;
        harness.store.allocator.free(harness.store.request_bytes.?);
        harness.store.request_bytes = null;
        if (std.mem.eql(u8, fixture, "mismatch")) {
            const foreign_request: api.Request = .{
                .operation = .remove,
                .profile_path = "/profile.json",
                .packages = &.{"alpha"},
            };
            harness.store.request_bytes =
                try foreign_request.canonicalJson(harness.store.allocator);
        }
        const outcome = try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        );
        var result = switch (outcome) {
            .result => |value| value,
            .ready => |value| {
                var owned = value;
                owned.deinit();
                return error.ExpectedRecoveryDiagnostic;
            },
        };
        defer result.deinit();
        try std.testing.expectEqual(
            api.MutationStatus.unknown,
            result.mutation_status.?,
        );
        try std.testing.expect(!result.changed);
        try std.testing.expect(result.profile == null);
        try std.testing.expectEqual(api.Operation.recover, result.operation);
        try std.testing.expect(
            result.recovery_context.?.requested_operation == null,
        );
        try std.testing.expect(result.recovery_context.?.action == null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            result.summary,
            "debz recover --system-profile",
        ) == null);
        try std.testing.expect(
            result.evidence.active_operation_state == null,
        );
        try std.testing.expect(harness.store.active_bytes != null);
        try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
    }
}

test "apt_system_orchestrator.test.recovery preparation inspection faults return unknown without clearing state" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    const active_before = try std.testing.allocator.dupe(
        u8,
        harness.store.active_bytes.?,
    );
    defer std.testing.allocator.free(active_before);
    harness.store.fail_inspect_active = true;
    var result = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .result => |value| value,
        .ready => return error.ExpectedRecoveryDiagnostic,
    };
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
    try std.testing.expectEqual(api.MutationStatus.unknown, result.mutation_status.?);
    try std.testing.expectEqual(api.Operation.recover, result.operation);
    try std.testing.expect(
        result.recovery_context.?.requested_operation == null,
    );
    try std.testing.expect(result.recovery_context.?.action == null);
    try std.testing.expect(!result.changed);
    try std.testing.expect(result.profile == null);
    try std.testing.expect(result.evidence.active_operation_state == null);
    try std.testing.expectEqualSlices(
        u8,
        active_before,
        harness.store.active_bytes.?,
    );
    try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
}

test "apt_system_orchestrator.test.multi-package prepare makes one plan and one lock without mutation" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{ "beta", "alpha" }),
    ));
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 1), harness.backend.plan_calls);
    try std.testing.expectEqual(@as(usize, 2), harness.backend.last_selector_count);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.download_calls);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
    try std.testing.expectEqual(@as(usize, 3), prepared.review.len);
    try std.testing.expectEqual(@as(usize, 1), harness.store.reserve_calls);
    try std.testing.expect(harness.store.active_bytes != null);

    var confirmation = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        false,
    );
    defer confirmation.deinit();
    try std.testing.expectEqual(api.DiagnosticId.confirmation_required, confirmation.diagnostics[0].id);
    const confirmation_json = try confirmation.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(confirmation_json);
    try std.testing.expect(std.mem.indexOf(
        u8,
        confirmation_json,
        "\"id\":\"confirmation_required\"",
    ) != null);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
}

test "apt_system_orchestrator.test.remove-to-empty review retains every planned removal" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    harness.backend.planned_items[0] = .{ .package = "first", .detail = "remove" };
    harness.backend.planned_items[1] = .{ .package = "second", .detail = "remove" };
    harness.backend.planned_item_count = 2;
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.remove, &.{ "first", "second" }),
    ));
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 2), prepared.review.len);
    try std.testing.expectEqualStrings("remove", prepared.review[0].detail.?);
    try std.testing.expectEqual(WorkflowOperation.remove, harness.backend.last_operation.?);
}

test "apt_system_orchestrator.test.confirmed execution uses exact lock and verifies completion" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{ "alpha", "beta" }),
    ));
    defer prepared.deinit();
    var result = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.Outcome.success, result.outcome);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.download_calls);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.execute_calls);
    try std.testing.expectEqual(@as(usize, 1), harness.verifier.transaction_checks);
    try std.testing.expect(harness.store.retained_transaction);
    try std.testing.expect(harness.store.completion_published);
    try std.testing.expect(harness.store.active_bytes == null);
    try std.testing.expect(harness.store.retained_bytes != null);
    try std.testing.expectEqualStrings(
        completion_schema_id,
        result.evidence.root_operation_completion.?.document.schema,
    );
}

test "apt_system_orchestrator.test.profile drift and exact-lock drift fail before mutation" {
    var profile_harness = Harness.init(std.testing.allocator);
    defer profile_harness.deinit();
    profile_harness.rebind();
    var profile_prepared = try expectReady(try profile_harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer profile_prepared.deinit();
    profile_harness.profile.drift_after_first = true;
    var profile_result = try profile_harness.engine.execute(
        std.testing.allocator,
        profile_prepared,
        true,
    );
    defer profile_result.deinit();
    try std.testing.expectEqual(
        api.DiagnosticId.recovery_required,
        profile_result.diagnostics[0].id,
    );
    try std.testing.expectEqual(
        api.MutationStatus.unknown,
        profile_result.mutation_status.?,
    );
    try std.testing.expectEqual(@as(usize, 0), profile_harness.backend.execute_calls);
    try std.testing.expect(profile_harness.store.active_bytes != null);

    var lock_harness = Harness.init(std.testing.allocator);
    defer lock_harness.deinit();
    lock_harness.rebind();
    var lock_prepared = try expectReady(try lock_harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer lock_prepared.deinit();
    lock_harness.verifier.lock_valid = false;
    var lock_result = try lock_harness.engine.execute(
        std.testing.allocator,
        lock_prepared,
        true,
    );
    defer lock_result.deinit();
    try std.testing.expectEqual(api.Outcome.recovery, lock_result.outcome);
    try std.testing.expectEqual(
        api.MutationStatus.unknown,
        lock_result.mutation_status.?,
    );
    try std.testing.expectEqual(@as(usize, 0), lock_harness.backend.execute_calls);
    try std.testing.expect(lock_harness.store.active_bytes != null);
}

test "apt_system_orchestrator.test.valid lock replacement is rejected before download and execute" {
    inline for (.{ @as(usize, 2), @as(usize, 3) }) |replacement_check| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.verifier.different_lock_check = replacement_check;
        var result = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(api.Outcome.planning, result.outcome);
        try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
        try std.testing.expect(harness.store.active_bytes == null);
        try std.testing.expectEqual(
            @as(usize, if (replacement_check == 2) 0 else 1),
            harness.backend.download_calls,
        );
    }
}

test "apt_system_orchestrator.test.profile references are revalidated at every backend boundary" {
    {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        harness.profile.fail_revalidate_on = 2;
        const outcome = try harness.engine.prepare(std.testing.allocator, .{
            .operation = .list_installed,
            .profile_path = "/profile.json",
        });
        switch (outcome) {
            .result => |value| {
                var result = value;
                defer result.deinit();
                try std.testing.expectEqual(
                    api.DiagnosticId.profile_untrusted,
                    result.diagnostics[0].id,
                );
            },
            .ready => return error.UnexpectedPreparation,
        }
        try std.testing.expectEqual(@as(usize, 0), harness.backend.route_calls);
    }
    {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        harness.profile.fail_revalidate_on = 2;
        const outcome = try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        );
        switch (outcome) {
            .result => |value| {
                var result = value;
                defer result.deinit();
                try std.testing.expectEqual(
                    api.DiagnosticId.profile_untrusted,
                    result.diagnostics[0].id,
                );
            },
            .ready => return error.UnexpectedPreparation,
        }
        try std.testing.expectEqual(@as(usize, 0), harness.backend.plan_calls);
    }
    inline for (.{ @as(usize, 4), @as(usize, 5) }) |failure_call| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.profile.fail_revalidate_on = failure_call;
        var result = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(
            api.DiagnosticId.profile_untrusted,
            result.diagnostics[0].id,
        );
        try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
        try std.testing.expectEqual(
            @as(usize, if (failure_call == 4) 0 else 1),
            harness.backend.download_calls,
        );
    }
}

test "apt_system_orchestrator.test.cache corruption cleans up as pre-mutation failure" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    harness.backend.download_status = .download;
    var result = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.Outcome.download, result.outcome);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
    try std.testing.expect(harness.store.active_bytes == null);
    try std.testing.expect(harness.store.retained_bytes != null);
}

test "apt_system_orchestrator.test.transaction interruption retains recoverable active state" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.upgrade, &.{}),
    ));
    defer prepared.deinit();
    harness.runner.fail_mode = .execute;
    var result = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.Outcome.recovery, result.outcome);
    try std.testing.expectEqual(api.DiagnosticId.recovery_required, result.diagnostics[0].id);
    try std.testing.expect(std.mem.indexOf(
        u8,
        result.summary,
        "debz recover --system-profile /profile.json",
    ) != null);
    var active = (try harness.store.interface().readActive(
        std.testing.allocator,
        "/state",
    )).?;
    defer active.deinit();
    try std.testing.expectEqual(operation_state.Phase.recovery_required, active.state.phase);
    try std.testing.expect(active.state.mutation_started);
    const plans_before = harness.backend.plan_calls;
    harness.profile.drift_after_first = true;
    const foreign = try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.remove, &.{"other"}),
    );
    switch (foreign) {
        .result => |blocked| {
            var owned = blocked;
            defer owned.deinit();
            try std.testing.expectEqual(api.DiagnosticId.recovery_required, owned.diagnostics[0].id);
        },
        .ready => return error.UnexpectedPreparation,
    }
    try std.testing.expectEqual(plans_before, harness.backend.plan_calls);
}

test "apt_system_orchestrator.test.stale pre-mutation state is retained and safely superseded" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var first = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer first.deinit();
    const second = try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.remove, &.{"beta"}),
    );
    switch (second) {
        .ready => |value| {
            var replacement = value;
            defer replacement.deinit();
            try std.testing.expectEqual(api.Operation.remove, replacement.request.operation);
        },
        .result => return error.ExpectedPreparation,
    }
    try std.testing.expectEqual(@as(usize, 2), harness.backend.plan_calls);
    try std.testing.expect(harness.store.retained_bytes != null);
}

test "apt_system_orchestrator.test.root replacement is reported before mutation" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    harness.runner.fail_mode = .plan_only;
    const outcome = try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    );
    switch (outcome) {
        .result => |value| {
            var result = value;
            defer result.deinit();
            try std.testing.expectEqual(api.Outcome.configuration, result.outcome);
            try std.testing.expectEqual(
                api.DiagnosticId.root_operation_conflict,
                result.diagnostics[0].id,
            );
            try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
        },
        .ready => return error.UnexpectedPreparation,
    }
    try std.testing.expect(harness.store.active_bytes == null);
}

test "apt_system_orchestrator.test.invalid transaction evidence enters recovery without completion publication" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    harness.verifier.transaction_valid = false;
    var result = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.Outcome.recovery, result.outcome);
    try std.testing.expect(!harness.store.completion_published);
    try std.testing.expect(harness.store.active_bytes != null);
}

test "apt_system_orchestrator.test.recovery reconstructs retained request and exact lock" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.remove, &.{ "first", "second" }),
    ));
    defer prepared.deinit();
    harness.runner.fail_mode = .execute;
    var interrupted = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer interrupted.deinit();
    harness.runner.fail_mode = null;

    var recovery = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer recovery.deinit();
    try std.testing.expectEqualStrings(
        "debz recover --system-profile /profile.json",
        recovery.action,
    );
    try std.testing.expectEqual(@as(usize, 2), recovery.prepared.request.packages.len);
    var result = try harness.engine.executeRecovery(
        std.testing.allocator,
        recovery,
        true,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.Outcome.success, result.outcome);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
    try std.testing.expect(harness.store.active_bytes == null);
    const repeated = try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    );
    switch (repeated) {
        .result => |value| {
            var diagnostic = value;
            defer diagnostic.deinit();
            try std.testing.expectEqual(api.Outcome.recovery, diagnostic.outcome);
        },
        .ready => return error.UnexpectedRecoveryPreparation,
    }
    try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
}

test "apt_system_orchestrator.test.completed lower record is discharged before outer reconciliation" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    harness.runner.fail_mode = .execute;
    var interrupted = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer interrupted.deinit();
    harness.runner.fail_mode = null;
    harness.runner.inspect_status = .completed;
    var recovery = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer recovery.deinit();
    var result = try harness.engine.executeRecovery(
        std.testing.allocator,
        recovery,
        true,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.Outcome.success, result.outcome);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
    try std.testing.expect(harness.store.active_bytes == null);

    var next = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.remove, &.{"beta"}),
    ));
    defer next.deinit();
    try std.testing.expectEqual(@as(usize, 2), harness.backend.plan_calls);
}

test "apt_system_orchestrator.test.required_privileged.production recovery bindings fail closed independently" {
    inline for (.{ "original", "discharge", "semantic", "attempt" }) |domain| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.runner.fail_mode = .execute;
        var interrupted = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer interrupted.deinit();
        harness.runner.fail_mode = null;
        var recovery = switch (try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer recovery.deinit();
        if (std.mem.eql(u8, domain, "original"))
            harness.runner.recovery_completion_mismatch = .original_request
        else if (std.mem.eql(u8, domain, "discharge"))
            harness.runner.recovery_completion_mismatch = .discharge_request
        else if (std.mem.eql(u8, domain, "attempt"))
            harness.runner.recovery_completion_mismatch = .attempt
        else
            harness.verifier.different_semantic_check =
                harness.verifier.lock_checks + 2;
        var result = try harness.engine.executeRecovery(
            std.testing.allocator,
            recovery,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(api.Outcome.recovery, result.outcome);
        try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
        try std.testing.expect(harness.store.active_bytes != null);
        try std.testing.expect(!harness.store.completion_published);
    }
}

test "apt_system_orchestrator.test.settled published recovery reconciles without lower workflow replay" {
    inline for (.{ FakeRunner.RecoveryCompletionMismatch.none, .successful_outcome }) |fixture|
        try expectSettledPublishedRecovery(fixture);
}

fn expectSettledPublishedRecovery(
    fixture: FakeRunner.RecoveryCompletionMismatch,
) !void {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    harness.runner.fail_mode = .execute;
    var interrupted = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer interrupted.deinit();
    harness.runner.fail_mode = null;
    var recovery = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer recovery.deinit();

    var loaded = try harness.profile.interface().load(
        std.testing.allocator,
        "/profile.json",
    );
    defer loaded.deinit();
    const selectors = try selectorsFor(
        std.testing.allocator,
        prepared.request,
    );
    defer std.testing.allocator.free(selectors);
    const workflow_request: WorkflowRequest = .{
        .operation = .install,
        .mode = .recover,
        .selectors = selectors,
        .options = executeOptions(
            loaded.view,
            prepared.paths.exact_lock,
        ),
    };
    var completion = try fakeRecoveryCompletion(
        std.testing.allocator,
        workflow_request,
        fixture,
        null,
    );
    defer completion.deinit();
    var pending_record = try root_operation.create(
        std.testing.allocator,
        .{
            .attempt_id = completion.document.attempt_id,
            .generation = 4,
            .install_root = live_root.logical_root_path,
            .backend = .legacy_dpkg,
            .operation = .{ .package_transaction = .install },
            .state = .completed,
            .phase = .provenance,
            .step = 4,
            .mutation_started = true,
            .outcome = completion.document.outcome,
            .provenance = .pending,
            .evidence = .{ .exact_lock = .{
                .schema = exact_lock.schema_id,
                .version = exact_lock.schema_version,
                .digest_sha256 = @splat(0x55),
            } },
            .request_sha256 = completion.document.request_sha256,
            .policy_sha256 = @splat(0x92),
            .target_architecture = "amd64",
            .reserved_unix = 90,
            .updated_unix = 100,
        },
    );
    defer pending_record.deinit();
    const provenance_sha256 = root_operation.provenanceDigest(
        pending_record.record,
        .{
            .outcome = completion.document.outcome,
            .document_sha256 = completion.document.digest_sha256,
            .journal_archived = false,
        },
    );
    var published_record = try root_operation.create(
        std.testing.allocator,
        .{
            .attempt_id = completion.document.attempt_id,
            .generation = 5,
            .install_root = live_root.logical_root_path,
            .backend = .legacy_dpkg,
            .operation = .{ .package_transaction = .install },
            .state = .completed,
            .phase = .provenance,
            .step = 5,
            .mutation_started = true,
            .outcome = completion.document.outcome,
            .provenance = .published,
            .provenance_sha256 = provenance_sha256,
            .evidence = .{ .exact_lock = .{
                .schema = exact_lock.schema_id,
                .version = exact_lock.schema_version,
                .digest_sha256 = @splat(0x55),
            } },
            .request_sha256 = completion.document.request_sha256,
            .policy_sha256 = @splat(0x92),
            .target_architecture = "amd64",
            .reserved_unix = 90,
            .updated_unix = 101,
        },
    );
    defer published_record.deinit();
    if (harness.runner.inspect_record_source) |previous|
        harness.runner.allocator.free(previous);
    harness.runner.inspect_record_source =
        try published_record.record.canonicalJson(
            harness.runner.allocator,
        );
    harness.runner.inspect_deferred_acknowledgment =
        try root_operation.createDeferredAcknowledgment(.{
            .state = .pending,
            .attempt_id = completion.document.attempt_id,
            .completion_sha256 = completion.document.digest_sha256,
            .provenance_sha256 = provenance_sha256,
            .acknowledgment_id = prepared.attempt_id,
        });
    harness.runner.recovery_completion_source =
        try completion.document.canonicalJson(
            harness.runner.allocator,
        );

    var result = try harness.engine.executeRecovery(
        std.testing.allocator,
        recovery,
        true,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.Outcome.success, result.outcome);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
    try std.testing.expectEqual(
        @as(usize, 1),
        harness.backend.recovery_ack_calls,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        harness.runner.recovery_completion_reads,
    );
    try std.testing.expect(harness.store.active_bytes == null);
    var next = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.remove, &.{"beta"}),
    ));
    defer next.deinit();
    try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
}

test "apt_system_orchestrator.test.valid lock replacement is rejected before recovery mutation" {
    inline for (.{ @as(usize, 1), @as(usize, 2) }) |check_offset| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.remove, &.{"first"}),
        ));
        defer prepared.deinit();
        harness.runner.fail_mode = .execute;
        var interrupted = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer interrupted.deinit();
        harness.runner.fail_mode = null;
        var recovery = switch (try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer recovery.deinit();
        harness.verifier.different_lock_check =
            harness.verifier.lock_checks + check_offset;
        var result = try harness.engine.executeRecovery(
            std.testing.allocator,
            recovery,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(api.Outcome.recovery, result.outcome);
        try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
    }
}

test "apt_system_orchestrator.test.profile replacement blocks recovery and reconciliation calls" {
    {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.runner.fail_mode = .execute;
        var interrupted = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer interrupted.deinit();
        harness.runner.fail_mode = null;
        var recovery = switch (try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer recovery.deinit();
        harness.profile.fail_revalidate_on =
            harness.profile.revalidate_count + 3;
        var result = try harness.engine.executeRecovery(
            std.testing.allocator,
            recovery,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(
            api.DiagnosticId.recovery_required,
            result.diagnostics[0].id,
        );
        try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
    }
    {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.runner.fail_mode = .execute;
        var interrupted = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer interrupted.deinit();
        harness.runner.fail_mode = null;
        var first_recovery = switch (try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer first_recovery.deinit();
        var crash: FakeCompletionCrash = .{ .boundary = .after_backend_success };
        harness.engine.completion_crash = crash.interface();
        var crashed = try harness.engine.executeRecovery(
            std.testing.allocator,
            first_recovery,
            true,
        );
        defer crashed.deinit();
        try std.testing.expectEqual(api.Outcome.recovery, crashed.outcome);
        const completion_reads_before_profile_replacement =
            harness.runner.recovery_completion_reads;
        harness.engine.completion_crash = null;
        var reconciliation = switch (try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer reconciliation.deinit();
        harness.profile.fail_revalidate_on =
            harness.profile.revalidate_count + 3;
        var result = try harness.engine.executeRecovery(
            std.testing.allocator,
            reconciliation,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(api.Outcome.recovery, result.outcome);
        try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
        try std.testing.expectEqual(
            completion_reads_before_profile_replacement,
            harness.runner.recovery_completion_reads,
        );
    }
}

test "apt_system_orchestrator.test.post-backend crashes reconcile without a second mutation" {
    inline for (.{
        CompletionBoundary.after_backend_success,
        .after_transaction_verified,
        .after_transaction_retained,
        .after_verifying_state,
        .after_completion_published,
    }) |boundary| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        harness.runner.inspect_status = .clean;
        var crash: FakeCompletionCrash = .{ .boundary = boundary };
        harness.engine.completion_crash = crash.interface();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        var diagnostic = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer diagnostic.deinit();
        try std.testing.expect(crash.triggered);
        try std.testing.expectEqual(@as(usize, 1), harness.backend.execute_calls);
        try std.testing.expectEqual(api.Outcome.recovery, diagnostic.outcome);
        try std.testing.expectEqual(
            api.DiagnosticId.recovery_required,
            diagnostic.diagnostics[0].id,
        );
        if (boundary == .after_completion_published) {
            try std.testing.expect(diagnostic.changed);
            try std.testing.expect(diagnostic.profile != null);
            try std.testing.expect(diagnostic.evidence.exact_lock != null);
            try std.testing.expect(
                diagnostic.evidence.active_operation_state != null,
            );
        } else {
            try std.testing.expect(!diagnostic.changed);
            try std.testing.expectEqual(
                api.MutationStatus.unknown,
                diagnostic.mutation_status.?,
            );
            try std.testing.expect(diagnostic.profile == null);
            try std.testing.expect(diagnostic.evidence.exact_lock == null);
        }
        harness.engine.completion_crash = null;

        var recovery = switch (try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer recovery.deinit();
        var result = try harness.engine.executeRecovery(
            std.testing.allocator,
            recovery,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(api.Outcome.success, result.outcome);
        try std.testing.expectEqual(@as(usize, 1), harness.backend.execute_calls);
        try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
        try std.testing.expect(harness.runner.inspect_calls >= 2);
        try std.testing.expect(harness.store.active_bytes == null);
    }
}

test "apt_system_orchestrator.test.owner-bound cleanup survives every outer retention crash" {
    inline for (.{
        CompletionBoundary.after_backend_success,
        .after_transaction_verified,
        .after_transaction_retained,
        .after_verifying_state,
    }) |boundary| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        harness.runner.publish_released_on_execute = true;
        var crash: FakeCompletionCrash = .{ .boundary = boundary };
        harness.engine.completion_crash = crash.interface();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        var diagnostic = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer diagnostic.deinit();
        try std.testing.expect(crash.triggered);
        try std.testing.expectEqual(api.Outcome.recovery, diagnostic.outcome);
        try std.testing.expectEqual(@as(usize, 1), harness.backend.execute_calls);
        try std.testing.expect(
            harness.runner.inspect_deferred_acknowledgment != null,
        );
        harness.engine.completion_crash = null;

        var recovery = switch (try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer recovery.deinit();
        var result = try harness.engine.executeRecovery(
            std.testing.allocator,
            recovery,
            true,
        );
        defer result.deinit();
        try std.testing.expectEqual(api.Outcome.success, result.outcome);
        try std.testing.expectEqual(@as(usize, 1), harness.backend.execute_calls);
        try std.testing.expectEqual(
            @as(usize, 1),
            harness.runner.ownership_finalize_calls,
        );
        try std.testing.expect(
            harness.runner.inspect_deferred_acknowledgment == null,
        );
        try std.testing.expect(harness.store.active_bytes == null);
    }
}

test "apt_system_orchestrator.test.owner-bound pre-mutation abandon retries exactly once" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    harness.backend.execute_status = .transaction;
    harness.runner.publish_abandoned_on_execute = true;
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    var interrupted = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer interrupted.deinit();
    try std.testing.expectEqual(api.Outcome.recovery, interrupted.outcome);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.execute_calls);
    try std.testing.expectEqual(
        root_operation.DeferredAcknowledgmentState.abandoned,
        harness.runner.inspect_deferred_acknowledgment.?.state,
    );

    harness.backend.execute_status = .success;
    var recovery = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer recovery.deinit();
    var result = try harness.engine.executeRecovery(
        std.testing.allocator,
        recovery,
        true,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.Outcome.success, result.outcome);
    try std.testing.expectEqual(@as(usize, 2), harness.backend.execute_calls);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
    try std.testing.expect(
        harness.runner.inspect_deferred_acknowledgment == null,
    );
    try std.testing.expect(harness.store.active_bytes == null);
}

test "apt_system_orchestrator.test.bound marker without record remains unknown" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    harness.runner.publish_bound_on_execute = true;
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    var interrupted = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer interrupted.deinit();
    try std.testing.expectEqual(api.Outcome.recovery, interrupted.outcome);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
    try std.testing.expectEqual(
        root_operation.DeferredAcknowledgmentState.bound,
        harness.runner.inspect_deferred_acknowledgment.?.state,
    );

    const exact_marker = harness.runner.inspect_deferred_acknowledgment.?;
    const foreign_id: [32]u8 = @splat(0xf1);
    harness.runner.inspect_deferred_acknowledgment =
        try root_operation.createDeferredAcknowledgment(.{
            .state = .bound,
            .attempt_id = exact_marker.attempt_id,
            .acknowledgment_id = foreign_id,
        });
    var foreign_recovery = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer foreign_recovery.deinit();
    var rejected = try harness.engine.executeRecovery(
        std.testing.allocator,
        foreign_recovery,
        true,
    );
    defer rejected.deinit();
    try std.testing.expectEqual(api.Outcome.recovery, rejected.outcome);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
    try std.testing.expectEqualSlices(
        u8,
        &foreign_id,
        &harness.runner.inspect_deferred_acknowledgment.?.acknowledgment_id,
    );
    harness.runner.inspect_deferred_acknowledgment = exact_marker;

    var recovery = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer recovery.deinit();
    var result = try harness.engine.executeRecovery(
        std.testing.allocator,
        recovery,
        true,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.Outcome.recovery, result.outcome);
    try std.testing.expectEqual(api.MutationStatus.unknown, result.mutation_status.?);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.execute_calls);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
    try std.testing.expect(
        harness.runner.inspect_deferred_acknowledgment != null,
    );
    try std.testing.expect(harness.store.active_bytes != null);
}

test "apt_system_orchestrator.test.post-recovery crashes use exact retained binding and ignore stale global completion" {
    inline for ([_]CompletionBoundary{
        .after_backend_success,
        .after_transaction_verified,
        .after_transaction_retained,
        .after_verifying_state,
        .after_recovery_acknowledged,
        .after_completion_published,
    }) |boundary| {
        var harness = Harness.init(std.testing.allocator);
        defer harness.deinit();
        harness.rebind();
        var prepared = try expectReady(try harness.engine.prepare(
            std.testing.allocator,
            mutationRequest(.install, &.{"alpha"}),
        ));
        defer prepared.deinit();
        harness.runner.fail_mode = .execute;
        var interrupted = try harness.engine.execute(
            std.testing.allocator,
            prepared,
            true,
        );
        defer interrupted.deinit();
        harness.runner.fail_mode = null;
        var first_recovery = switch (try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer first_recovery.deinit();
        var crash: FakeCompletionCrash = .{ .boundary = boundary };
        harness.engine.completion_crash = crash.interface();
        var crashed = try harness.engine.executeRecovery(
            std.testing.allocator,
            first_recovery,
            true,
        );
        defer crashed.deinit();
        try std.testing.expectEqual(api.Outcome.recovery, crashed.outcome);
        try std.testing.expect(crash.triggered);
        try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
        if (boundary == .after_recovery_acknowledged) {
            try std.testing.expectEqual(
                @as(usize, 1),
                harness.backend.recovery_ack_calls,
            );
        }
        harness.engine.completion_crash = null;
        harness.runner.inspect_status = .clean;
        const genuine_completion = if (harness.runner.recovery_completion_source) |source|
            try harness.runner.allocator.dupe(u8, source)
        else
            return error.MissingRecoveryCompletion;
        defer harness.runner.allocator.free(genuine_completion);
        if (harness.runner.recovery_completion_source) |source|
            harness.runner.allocator.free(source);
        var stale_profile = try harness.profile.interface().load(
            std.testing.allocator,
            "/profile.json",
        );
        defer stale_profile.deinit();
        const stale_selectors = try selectorsFor(
            std.testing.allocator,
            prepared.request,
        );
        defer std.testing.allocator.free(stale_selectors);
        var stale_completion = try fakeRecoveryCompletion(
            std.testing.allocator,
            .{
                .operation = .install,
                .mode = .recover,
                .selectors = stale_selectors,
                .options = executeOptions(
                    stale_profile.view,
                    prepared.paths.exact_lock,
                ),
            },
            .attempt,
            null,
        );
        defer stale_completion.deinit();
        harness.runner.recovery_completion_source =
            try stale_completion.document.canonicalJson(
                harness.runner.allocator,
            );

        var reconciliation = switch (try harness.engine.prepareRecovery(
            std.testing.allocator,
            "/profile.json",
        )) {
            .ready => |value| value,
            .result => return error.ExpectedRecoveryPreparation,
        };
        defer reconciliation.deinit();
        var result = try harness.engine.executeRecovery(
            std.testing.allocator,
            reconciliation,
            true,
        );
        defer result.deinit();
        const outer_binding_committed =
            boundary == .after_verifying_state or
            boundary == .after_recovery_acknowledged or
            boundary == .after_completion_published;
        try std.testing.expectEqual(
            if (outer_binding_committed)
                api.Outcome.success
            else
                api.Outcome.recovery,
            result.outcome,
        );
        try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
        if (!outer_binding_committed) {
            try std.testing.expectEqual(
                @as(usize, 0),
                harness.backend.recovery_ack_calls,
            );
            harness.runner.allocator.free(
                harness.runner.recovery_completion_source.?,
            );
            harness.runner.recovery_completion_source =
                try harness.runner.allocator.dupe(u8, genuine_completion);
            var final_recovery = switch (try harness.engine.prepareRecovery(
                std.testing.allocator,
                "/profile.json",
            )) {
                .ready => |value| value,
                .result => return error.ExpectedRecoveryPreparation,
            };
            defer final_recovery.deinit();
            var final = try harness.engine.executeRecovery(
                std.testing.allocator,
                final_recovery,
                true,
            );
            defer final.deinit();
            try std.testing.expectEqual(api.Outcome.success, final.outcome);
        }
        try std.testing.expectEqual(
            if (boundary == .after_recovery_acknowledged)
                @as(usize, 2)
            else
                @as(usize, 1),
            harness.backend.recovery_ack_calls,
        );
        try std.testing.expectEqual(
            if (boundary == .after_recovery_acknowledged)
                @as(usize, 2)
            else
                @as(usize, 1),
            harness.runner.recovery_ack_calls,
        );
        try std.testing.expect(harness.store.active_bytes == null);
    }
}

test "apt_system_orchestrator.test.recovery transport failure preserves lower token for retry without second mutation" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    harness.runner.fail_mode = .execute;
    var interrupted = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer interrupted.deinit();
    harness.runner.fail_mode = null;

    var first_recovery = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer first_recovery.deinit();
    harness.runner.fail_after_recovery_transport = true;
    var failed = try harness.engine.executeRecovery(
        std.testing.allocator,
        first_recovery,
        true,
    );
    defer failed.deinit();
    try std.testing.expectEqual(api.Outcome.recovery, failed.outcome);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.recovery_ack_calls);

    var retry = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer retry.deinit();
    var completed = try harness.engine.executeRecovery(
        std.testing.allocator,
        retry,
        true,
    );
    defer completed.deinit();
    try std.testing.expectEqual(api.Outcome.success, completed.outcome);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.recovery_ack_calls);
    try std.testing.expectEqual(@as(usize, 1), harness.runner.recovery_ack_calls);
    try std.testing.expect(harness.store.active_bytes == null);
}

test "apt_system_orchestrator.test.recovery retention failure preserves lower token for retry without second mutation" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    harness.runner.fail_mode = .execute;
    var interrupted = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer interrupted.deinit();
    harness.runner.fail_mode = null;

    var first_recovery = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer first_recovery.deinit();
    harness.store.fail_recovery_retain_once = true;
    var failed = try harness.engine.executeRecovery(
        std.testing.allocator,
        first_recovery,
        true,
    );
    defer failed.deinit();
    try std.testing.expectEqual(api.Outcome.recovery, failed.outcome);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.recovery_ack_calls);

    var retry = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer retry.deinit();
    var completed = try harness.engine.executeRecovery(
        std.testing.allocator,
        retry,
        true,
    );
    defer completed.deinit();
    try std.testing.expectEqual(api.Outcome.success, completed.outcome);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.recovery_ack_calls);
    try std.testing.expectEqual(@as(usize, 1), harness.runner.recovery_ack_calls);
    try std.testing.expect(harness.store.active_bytes == null);
}

test "apt_system_orchestrator.test.finish failure leaves completion evidence active for deterministic reconciliation" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    harness.store.fail_finish = true;
    var result = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.recovery_required,
        result.diagnostics[0].id,
    );
    try std.testing.expect(result.changed);
    try std.testing.expect(result.profile != null);
    try std.testing.expect(result.evidence.exact_lock != null);
    try std.testing.expect(result.evidence.transaction_result != null);
    try std.testing.expect(result.evidence.root_operation_completion != null);
    try std.testing.expect(result.evidence.active_operation_state != null);
    try std.testing.expect(harness.store.active_bytes != null);
    try std.testing.expect(harness.store.completion_published);
}

test "apt_system_orchestrator.test.retained final state reconciles without regeneration" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
    var prepared = try expectReady(try harness.engine.prepare(
        std.testing.allocator,
        mutationRequest(.install, &.{"alpha"}),
    ));
    defer prepared.deinit();
    harness.store.fail_after_retain_once = true;
    var failed = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    defer failed.deinit();
    try std.testing.expectEqual(api.ExitStatus.recovery, failed.exit_status);
    try std.testing.expectEqual(
        api.DiagnosticId.recovery_required,
        failed.diagnostics[0].id,
    );
    try std.testing.expect(failed.changed);
    try std.testing.expect(failed.evidence.root_operation_completion != null);
    try std.testing.expect(
        harness.runner.inspect_deferred_acknowledgment != null,
    );
    const retained_before = try std.testing.allocator.dupe(
        u8,
        harness.store.retained_bytes.?,
    );
    defer std.testing.allocator.free(retained_before);
    harness.sources.now_value = 999;
    var recovery = switch (try harness.engine.prepareRecovery(
        std.testing.allocator,
        "/profile.json",
    )) {
        .ready => |value| value,
        .result => return error.ExpectedRecoveryPreparation,
    };
    defer recovery.deinit();
    const inspections_before = harness.runner.inspect_calls;
    var result = try harness.engine.executeRecovery(
        std.testing.allocator,
        recovery,
        true,
    );
    defer result.deinit();
    try std.testing.expectEqual(api.Outcome.success, result.outcome);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
    try std.testing.expectEqual(
        inspections_before,
        harness.runner.inspect_calls,
    );
    try std.testing.expectEqualSlices(
        u8,
        retained_before,
        harness.store.retained_bytes.?,
    );
    try std.testing.expect(harness.store.active_bytes == null);
    try std.testing.expect(
        harness.runner.inspect_deferred_acknowledgment == null,
    );
}

comptime {
    _ = exact_lock.schema_id;
    _ = transaction_provenance.schema_id;
}
