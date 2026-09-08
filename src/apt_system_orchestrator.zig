//! Profile-bound orchestration for the apt-shaped system facade.
//!
//! The module deliberately has no command-line parsing. Callers prepare a
//! request, render the returned complete review, obtain confirmation, and then
//! execute the retained exact lock. All host-facing boundaries are injected so
//! tests cannot accidentally inspect or mutate `/`.
const std = @import("std");
const builtin = @import("builtin");
const api = @import("apt_system_api.zig");
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

    pub fn deinit(self: *BackendResult) void {
        if (self.owned_result) |*owned| owned.deinit();
        if (self.recovery_completion) |*owned| owned.deinit();
        self.* = undefined;
    }
};

pub const WorkflowOperation = enum { install, remove, upgrade_all };
pub const WorkflowMode = enum { plan_only, download_only, execute, recover };

pub const RecoveryAcknowledgment =
    production_backend.WorkflowRecoveryAcknowledgment;

pub const WorkflowRequest = struct {
    operation: WorkflowOperation,
    mode: WorkflowMode,
    selectors: []const solver.PackageSelector,
    options: product_api.CommonOptions,
    defer_recovery_clear: bool = false,
    orchestration_id: ?[32]u8 = null,
    finalize_ownership: bool = false,
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
                .execute => .execute,
                .recover => .recover,
            },
            .selectors = request.selectors,
            .options = request.options,
            .defer_recovery_clear = request.defer_recovery_clear,
            .orchestration_id = request.orchestration_id,
            .finalize_ownership = request.finalize_ownership,
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

pub const PrivateLiveRootRunner = struct {
    io: std.Io,
    termination_grace_ms: u64 = 1_000,

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
                .bound, .pending => .recovery_required,
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
            invocation.workflow.request.recovery_acknowledgment == null and
            decoded.result.exit_status == .success)
        {
            recovery_completion = try self.interface()
                .readRecoveryCompletion(allocator) orelse
                return error.MissingRecoveryCompletion;
        }
        var recovery_acknowledgment: ?RecoveryAcknowledgment = null;
        const root_status: RootStatus = switch (invocation) {
            .route => .clean,
            .workflow => |workflow_invocation| switch (workflow_invocation.request.mode) {
                .execute, .recover => if (decoded.result.exit_status == .success) status: {
                    var inspection = try self.interface().inspect(allocator);
                    defer inspection.deinit();
                    if (workflow_invocation.request.mode == .recover and
                        workflow_invocation.request.defer_recovery_clear and
                        !workflow_invocation.request.finalize_ownership and
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
                    break :status switch (inspection.status) {
                        .clean, .completed => .completed,
                        .recovery_required => .recovery_required,
                    };
                } else .recovery_required,
                .plan_only, .download_only => .clean,
            },
        };
        return .{
            .result = decoded.result,
            .root_status = root_status,
            .owned_result = decoded,
            .recovery_completion = recovery_completion,
            .recovery_acknowledgment = recovery_acknowledgment,
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
        .execute => switch (operation) {
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

    pub fn deinit(self: *OperationPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.directory);
        allocator.free(self.active_state);
        allocator.free(self.retained_state);
        allocator.free(self.request);
        allocator.free(self.exact_lock);
        allocator.free(self.transaction_result);
        allocator.free(self.recovery_completion);
        allocator.free(self.completion);
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
            .reserveFn = reserve,
            .compareAndSetFn = compareAndSet,
            .finishFn = finish,
            .readRequestFn = readRequest,
            .readRetainedFn = readRetained,
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
        const store = try operation_state.Store.init(
            self.io,
            apt_dir,
            operation_state.document_name,
            locks.interface(),
        );
        try store.compareAndSet(
            allocator,
            expected,
            next,
            operation_state.maximum_document_bytes,
            self.wait_ms,
        );
    }

    fn finish(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        expected: operation_state.Expected,
        final: operation_state.State,
    ) !void {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        var operation_dir = try openSecureAbsoluteDirectory(
            self,
            allocator,
            paths.directory,
            false,
        );
        defer operation_dir.close(self.io);
        var retained: ?operation_state.OwnedState = null;
        defer if (retained) |*owned| owned.deinit();
        if (try readOptionalFile(
            allocator,
            self.io,
            operation_dir,
            retained_state_name,
        )) |source| {
            defer allocator.free(source);
            retained = try operation_state.decode(
                allocator,
                source,
                operation_state.maximum_document_bytes,
            );
            if (!finalStateEquivalent(retained.?.state, final))
                return error.PublicationConflict;
        } else {
            const final_bytes = try final.canonicalJson(allocator);
            defer allocator.free(final_bytes);
            try publishAtomic(
                self,
                allocator,
                operation_dir,
                retained_state_name,
                final_bytes,
            );
            retained = try operation_state.decode(
                allocator,
                final_bytes,
                operation_state.maximum_document_bytes,
            );
            if (self.finish_crash) |crash|
                try crash.hit(.after_retained_publish);
        }
        const durable_final = retained.?.state;

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
        if (state.state.generation != durable_final.generation or
            !std.mem.eql(
                u8,
                &state.state.digest_sha256,
                &durable_final.digest_sha256,
            )) return error.StaleState;
        try apt_dir.deleteFile(self.io, operation_state.document_name);
        try syncDirectory(self.io, apt_dir);
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

pub const ResultVerifier = struct {
    context: *anyopaque,
    verifyLockFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
        []const u8,
        [32]u8,
    ) anyerror!VerifiedLock,
    verifyTransactionFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
        api.DocumentBinding,
        []const u8,
    ) anyerror!VerifiedTransaction,
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

pub const CompletionBoundary = enum {
    after_backend_success,
    after_transaction_verified,
    after_transaction_retained,
    after_verifying_state,
    after_recovery_acknowledged,
    after_completion_published,
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
        };
    }

    fn prepareReadOnly(
        self: *Engine,
        allocator: std.mem.Allocator,
        request: api.Request,
        loaded: LoadedProfile,
    ) !api.Result {
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
        try self.transition(allocator, profile.state_path, &current, .{
            .phase = .profile_loaded,
        });

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
        try self.transition(allocator, profile.state_path, &current, .{
            .phase = .authenticated,
        });
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
        ) catch {
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
        try self.transition(allocator, profile.state_path, &current, .{
            .phase = .planned,
            .exact_lock = verified.binding,
        });

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
    ) !api.Result {
        if (!confirmed) return prepared.confirmationResult();
        var loaded = self.profiles.load(
            allocator,
            prepared.request.profile_path,
        ) catch return self.abortPreparation(
            allocator,
            prepared,
            .configuration,
            .profile_invalid,
            "explicit trusted system profile could not be reloaded",
        );
        defer loaded.deinit();
        if (!profileEqual(loaded.view.binding, prepared.profile))
            return self.abortPreparation(
                allocator,
                prepared,
                .configuration,
                .profile_untrusted,
                "system profile changed after review",
            );
        loaded.revalidate(allocator) catch return self.abortPreparation(
            allocator,
            prepared,
            .configuration,
            .profile_untrusted,
            "trusted profile reference changed after review",
        );

        var current = (try self.store.readActive(
            allocator,
            loaded.view.state_path,
        )) orelse return api.failure(
            prepared.request,
            .recovery,
            .recovery_required,
            "state",
            "reviewed active operation is missing",
        );
        defer current.deinit();
        if (!stateMatchesPreparation(current.state, prepared))
            return api.failure(
                prepared.request,
                .recovery,
                .recovery_required,
                "state",
                "active operation is stale or belongs to another request",
            );
        const before_download = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            prepared.paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(allocator, prepared.request),
        ) catch return self.finishPreMutationFailure(
            allocator,
            prepared,
            &current,
            .planning,
            .planning_failed,
            "reviewed exact lock is no longer valid",
        );
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
        try self.transition(
            allocator,
            loaded.view.state_path,
            &current,
            .{ .phase = .downloaded },
        );
        const before_execute = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            prepared.paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(allocator, prepared.request),
        ) catch return self.finishPreMutationFailure(
            allocator,
            prepared,
            &current,
            .planning,
            .planning_failed,
            "reviewed exact lock is invalid before execution",
        );
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
        try self.transition(
            allocator,
            loaded.view.state_path,
            &current,
            .{ .phase = .mutating },
        );

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
        try self.hitCompletionBoundary(.after_backend_success);
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
            false,
        );
    }

    pub fn prepareRecovery(
        self: *Engine,
        allocator: std.mem.Allocator,
        profile_path: []const u8,
    ) !RecoveryPrepareOutcome {
        const probe: api.Request = .{
            .operation = .upgrade,
            .profile_path = profile_path,
        };
        var loaded = self.profiles.load(allocator, profile_path) catch
            return .{ .result = try profileFailure(probe) };
        defer loaded.deinit();
        loaded.revalidate(allocator) catch return .{ .result = try api.failure(
            probe,
            .configuration,
            .profile_untrusted,
            "profile",
            "trusted profile reference changed before recovery",
        ) };
        var active = (try self.store.readActive(
            allocator,
            loaded.view.state_path,
        )) orelse return .{ .result = try api.failure(
            probe,
            .recovery,
            .recovery_failed,
            "recovery",
            "no active apt/system operation requires recovery",
        ) };
        defer active.deinit();
        if (!profileEqual(active.state.profile, loaded.view.binding))
            return .{ .result = try api.failure(
                probe,
                .recovery,
                .recovery_required,
                "recovery",
                "active operation belongs to a different profile",
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
        ) catch return .{ .result = try api.failure(
            probe,
            .recovery,
            .recovery_required,
            "recovery",
            "retained semantic request is unavailable",
        ) };
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
            return .{ .result = try api.failure(
                retained.request,
                .recovery,
                .recovery_required,
                "recovery",
                "retained request does not bind the active operation",
            ) };
        if (!active.state.mutation_started or active.state.exact_lock == null)
            return .{ .result = try api.failure(
                retained.request,
                .recovery,
                .recovery_required,
                "recovery",
                "active state is not a recoverable post-mutation operation",
            ) };
        const verified = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(allocator, retained.request),
        ) catch return .{ .result = try api.failure(
            retained.request,
            .recovery,
            .recovery_required,
            "recovery",
            "retained exact lock is invalid",
        ) };
        if (!std.mem.eql(
            u8,
            verified.binding.path,
            paths.exact_lock,
        ) or !documentEqual(verified.binding, active.state.exact_lock.?))
            return .{ .result = try api.failure(
                retained.request,
                .recovery,
                .recovery_required,
                "recovery",
                "retained exact lock differs from active state",
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
    ) !api.Result {
        if (!confirmed) return recovery.prepared.confirmationResult();
        var loaded = self.profiles.load(
            allocator,
            recovery.prepared.request.profile_path,
        ) catch return profileFailure(recovery.prepared.request);
        defer loaded.deinit();
        if (!profileEqual(loaded.view.binding, recovery.prepared.profile))
            return api.failure(
                recovery.prepared.request,
                .recovery,
                .recovery_required,
                "recovery",
                "profile changed after recovery preparation",
            );
        loaded.revalidate(allocator) catch return api.failure(
            recovery.prepared.request,
            .recovery,
            .recovery_required,
            "recovery",
            "trusted profile reference changed after recovery preparation",
        );
        var current = (try self.store.readActive(
            allocator,
            loaded.view.state_path,
        )) orelse return api.failure(
            recovery.prepared.request,
            .recovery,
            .recovery_required,
            "recovery",
            "active recovery state disappeared",
        );
        defer current.deinit();
        if (!stateMatchesPreparation(current.state, recovery.prepared) or
            !recoverableOuterPhase(current.state.phase))
            return api.failure(
                recovery.prepared.request,
                .recovery,
                .recovery_required,
                "recovery",
                "active recovery state is stale or foreign",
            );
        const recovery_lock = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            recovery.prepared.paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(
                allocator,
                recovery.prepared.request,
            ),
        ) catch return api.failure(
            recovery.prepared.request,
            .recovery,
            .recovery_required,
            "recovery",
            "retained exact lock is no longer valid",
        );
        if (!lockMatchesPreparation(
            recovery_lock.binding,
            recovery.prepared,
            current.state,
        )) return api.failure(
            recovery.prepared.request,
            .recovery,
            .recovery_required,
            "recovery",
            "retained exact lock was replaced before recovery",
        );
        loaded.revalidate(allocator) catch return recoveryDiagnostic(
            allocator,
            recovery.prepared.request,
            current.state.profile,
            current.state.exact_lock,
            current.state.transaction_result,
            current.state.root_operation_completion,
            true,
            recovery.prepared.profile_state_path,
        );
        var retained_final = self.store.readRetained(
            allocator,
            recovery.prepared.paths,
        ) catch return recoveryDiagnostic(
            allocator,
            recovery.prepared.request,
            current.state.profile,
            current.state.exact_lock,
            current.state.transaction_result,
            current.state.root_operation_completion,
            true,
            recovery.prepared.profile_state_path,
        );
        defer if (retained_final) |*owned| owned.deinit();
        if (retained_final) |*retained|
            return self.reconcileRetainedFinal(
                allocator,
                recovery.prepared,
                &current,
                retained.state,
            );
        loaded.revalidate(allocator) catch return self.recoveryFailed(
            allocator,
            recovery.prepared,
            &current,
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
        }
        const owner_proven_pre_mutation =
            if (ownership_marker) |marker|
                marker.state == .bound and
                    (lower_inspection.record == null or
                        lower_inspection.record.?.record.state.provenPreMutation())
            else
                false;
        if (lower_inspection.status == .clean or owner_proven_pre_mutation) {
            const finalize_ownership = if (ownership_marker) |marker|
                marker.state == .released or
                    (marker.state == .bound and
                        lower_inspection.record != null and
                        lower_inspection.record.?.record.clearable())
            else
                false;
            const retry_abandoned = if (ownership_marker) |marker|
                marker.state == .abandoned or
                    (marker.state == .bound and
                        (lower_inspection.record == null or
                            lower_inspection.record.?.record.state
                                .provenPreMutation() or
                            lower_inspection.record.?.record.outcome ==
                                .abandoned_before_mutation))
            else
                false;
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
                ) catch return self.recoveryFailed(
                    allocator,
                    recovery.prepared,
                    &current,
                    "retained exact lock is invalid before retrying the proven pre-mutation attempt",
                );
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
                    return self.recoveryFailed(
                        allocator,
                        recovery.prepared,
                        &current,
                        "trusted profile reference changed before retrying the proven pre-mutation attempt",
                    );
                const selectors = try selectorsFor(
                    allocator,
                    recovery.prepared.request,
                );
                defer allocator.free(selectors);
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
                try self.hitCompletionBoundary(.after_backend_success);
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
                    false,
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
                    return self.recoveryFailed(
                        allocator,
                        recovery.prepared,
                        &current,
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
            loaded.revalidate(allocator) catch return self.recoveryFailed(
                allocator,
                recovery.prepared,
                &current,
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
                finalize_ownership,
            );
        }
        try self.transition(
            allocator,
            loaded.view.state_path,
            &current,
            .{ .phase = .recovering, .diagnostic = "recovery in progress" },
        );
        const before_recovery = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            recovery.prepared.paths.exact_lock,
            loaded.view.architecture,
            try semanticDigestForRequest(
                allocator,
                recovery.prepared.request,
            ),
        ) catch return self.recoveryFailed(
            allocator,
            recovery.prepared,
            &current,
            "retained exact lock is invalid immediately before recovery",
        );
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
        loaded.revalidate(allocator) catch return self.recoveryFailed(
            allocator,
            recovery.prepared,
            &current,
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
        try self.hitCompletionBoundary(.after_backend_success);
        loaded.revalidate(allocator) catch return self.recoveryFailed(
            allocator,
            recovery.prepared,
            &current,
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
            false,
        );
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
        finalize_ownership: bool,
    ) !api.Result {
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
            try self.hitCompletionBoundary(.after_transaction_verified);
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
            const source_path = try std.fmt.allocPrint(
                allocator,
                "{s}/{s}",
                .{ profile.state_path, transaction_result_name },
            );
            defer allocator.free(source_path);
            var verified = self.verifier.verifyTransactionFn(
                self.verifier.context,
                allocator,
                source_path,
                prepared.exact_lock,
                profile.architecture,
            ) catch return self.markRecoveryRequired(
                allocator,
                prepared,
                current,
                "transaction result does not verify against the exact lock",
            );
            defer verified.deinit();
            try self.hitCompletionBoundary(.after_transaction_verified);
            retained = self.store.retainTransactionFn(
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
        try self.hitCompletionBoundary(.after_transaction_retained);
        try self.transition(
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
        );
        try self.hitCompletionBoundary(.after_verifying_state);
        if (finalize_ownership) {
            const before_finalize = self.verifier.verifyLockFn(
                self.verifier.context,
                allocator,
                prepared.paths.exact_lock,
                profile.architecture,
                try semanticDigestForRequest(allocator, prepared.request),
            ) catch return self.markRecoveryRequired(
                allocator,
                prepared,
                current,
                "retained exact lock is invalid before lower ownership finalization",
            );
            if (!lockMatchesPreparation(
                before_finalize.binding,
                prepared,
                current.state,
            )) return self.markRecoveryRequired(
                allocator,
                prepared,
                current,
                "retained exact lock was replaced before lower ownership finalization",
            );
            loaded.revalidate(allocator) catch
                return self.markRecoveryRequired(
                    allocator,
                    prepared,
                    current,
                    "trusted profile reference changed before lower ownership finalization",
                );
            const selectors = try selectorsFor(allocator, prepared.request);
            defer allocator.free(selectors);
            var finalized = self.runner.workflow(
                allocator,
                self.backend,
                .{
                    .operation = semanticOperation(prepared.request.operation),
                    .mode = .recover,
                    .selectors = selectors,
                    .options = executeOptions(
                        profile,
                        prepared.paths.exact_lock,
                    ),
                    .orchestration_id = prepared.attempt_id,
                    .finalize_ownership = true,
                },
            ) catch return self.markRecoveryRequired(
                allocator,
                prepared,
                current,
                "lower ownership finalization was interrupted",
            );
            defer finalized.deinit();
            if (finalized.result.exit_status != .success or
                finalized.root_status != .completed)
                return self.markRecoveryRequired(
                    allocator,
                    prepared,
                    current,
                    "lower ownership finalization did not clear the exact owner-bound state",
                );
        }
        if (recovered) {
            if (recovery_acknowledgment) |acknowledgment| {
                const before_ack = self.verifier.verifyLockFn(
                    self.verifier.context,
                    allocator,
                    prepared.paths.exact_lock,
                    profile.architecture,
                    try semanticDigestForRequest(allocator, prepared.request),
                ) catch return self.markRecoveryRequired(
                    allocator,
                    prepared,
                    current,
                    "retained exact lock is invalid before lower recovery acknowledgment",
                );
                if (!lockMatchesPreparation(
                    before_ack.binding,
                    prepared,
                    current.state,
                )) return self.markRecoveryRequired(
                    allocator,
                    prepared,
                    current,
                    "retained exact lock was replaced before lower recovery acknowledgment",
                );
                loaded.revalidate(allocator) catch
                    return self.markRecoveryRequired(
                        allocator,
                        prepared,
                        current,
                        "trusted profile reference changed before lower recovery acknowledgment",
                    );
                const selectors = try selectorsFor(
                    allocator,
                    prepared.request,
                );
                defer allocator.free(selectors);
                var acknowledged = self.runner.workflow(
                    allocator,
                    self.backend,
                    .{
                        .operation = semanticOperation(
                            prepared.request.operation,
                        ),
                        .mode = .recover,
                        .selectors = selectors,
                        .options = executeOptions(
                            profile,
                            prepared.paths.exact_lock,
                        ),
                        .defer_recovery_clear = true,
                        .orchestration_id = prepared.attempt_id,
                        .recovery_acknowledgment = acknowledgment,
                    },
                ) catch return self.markRecoveryRequired(
                    allocator,
                    prepared,
                    current,
                    "lower recovery acknowledgment was interrupted",
                );
                defer acknowledged.deinit();
                if (acknowledged.result.exit_status != .success or
                    acknowledged.root_status != .completed)
                    return self.markRecoveryRequired(
                        allocator,
                        prepared,
                        current,
                        "lower recovery acknowledgment did not clear the exact settled attempt",
                    );
            }
            try self.hitCompletionBoundary(.after_recovery_acknowledged);
        }
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
        try self.hitCompletionBoundary(.after_completion_published);
        var final = try nextState(allocator, current.state, .{
            .phase = .completed,
            .outcome = if (recovered) .recovered else .succeeded,
            .transaction_result = retained,
            .root_operation_completion = completion,
            .diagnostic = if (recovered) "recovery completed" else "",
            .updated_unix = self.clock.nowFn(self.clock.context),
        });
        defer final.deinit();
        self.store.finishFn(
            self.store.context,
            allocator,
            prepared.paths,
            operation_state.Expected.fromState(current.state),
            final.state,
        ) catch return api.failure(
            prepared.request,
            .configuration,
            .state_persistence_failed,
            "state",
            "completion is verified but durable active-state publication failed",
        );
        return completedResult(allocator, prepared, final.state);
    }

    fn reconcileRetainedFinal(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        current: *operation_state.OwnedState,
        retained: operation_state.State,
    ) !api.Result {
        if (!retainedFinalMatchesActive(retained, current.state, prepared))
            return recoveryDiagnostic(
                allocator,
                prepared.request,
                current.state.profile,
                current.state.exact_lock,
                current.state.transaction_result,
                current.state.root_operation_completion,
                true,
                prepared.profile_state_path,
            );
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
        ) catch return recoveryDiagnostic(
            allocator,
            prepared.request,
            current.state.profile,
            current.state.exact_lock,
            current.state.transaction_result,
            current.state.root_operation_completion,
            true,
            prepared.profile_state_path,
        );
        self.store.finishFn(
            self.store.context,
            allocator,
            prepared.paths,
            operation_state.Expected.fromState(current.state),
            retained,
        ) catch return api.failure(
            prepared.request,
            .configuration,
            .state_persistence_failed,
            "state",
            "retained final state could not reconcile the active operation",
        );
        return completedResult(
            allocator,
            prepared,
            retained,
        );
    }

    fn blockedByActive(
        self: *Engine,
        allocator: std.mem.Allocator,
        request: api.Request,
        profile: ProfileView,
    ) !?api.Result {
        var active = (try self.store.readActive(allocator, profile.state_path)) orelse
            return null;
        defer active.deinit();
        var paths = try pathsFor(
            allocator,
            profile.state_path,
            active.state.attempt_id,
        );
        defer paths.deinit(allocator);
        if (active.state.phase == .completed and
            active.state.outcome != .failed_after_mutation)
        {
            self.store.finishFn(
                self.store.context,
                allocator,
                paths,
                operation_state.Expected.fromState(active.state),
                active.state,
            ) catch return try api.failure(
                request,
                .configuration,
                .state_persistence_failed,
                "state",
                "completed active operation could not be reconciled",
            );
            return null;
        }
        if (!active.state.mutation_started) {
            var abandoned = try nextState(allocator, active.state, .{
                .phase = .completed,
                .outcome = .failed_before_mutation,
                .diagnostic = "superseded before package mutation",
                .updated_unix = self.clock.nowFn(self.clock.context),
            });
            defer abandoned.deinit();
            self.store.finishFn(
                self.store.context,
                allocator,
                paths,
                operation_state.Expected.fromState(active.state),
                abandoned.state,
            ) catch return try api.failure(
                request,
                .configuration,
                .state_persistence_failed,
                "state",
                "pre-mutation active operation could not be abandoned safely",
            );
            return null;
        }
        return try recoveryDiagnostic(
            allocator,
            request,
            active.state.profile,
            active.state.exact_lock,
            active.state.transaction_result,
            active.state.root_operation_completion,
            active.state.mutation_started,
            profile.state_path,
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
        ) catch return api.failure(
            request,
            .configuration,
            .state_persistence_failed,
            "state",
            "pre-mutation failure could not be retained safely",
        );
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
    ) !api.Result {
        return self.failBeforeMutation(
            allocator,
            prepared.request,
            prepared.profile_state_path,
            prepared.paths,
            current,
            outcome,
            diagnostic,
            message,
        );
    }

    fn abortPreparation(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        outcome: api.Outcome,
        diagnostic: api.DiagnosticId,
        message: []const u8,
    ) !api.Result {
        var current = (try self.store.readActive(
            allocator,
            prepared.profile_state_path,
        )) orelse return api.failure(
            prepared.request,
            .recovery,
            .recovery_required,
            "state",
            "reviewed active operation is missing",
        );
        defer current.deinit();
        if (!stateMatchesPreparation(current.state, prepared) or
            current.state.mutation_started)
            return recoveryDiagnostic(
                allocator,
                prepared.request,
                current.state.profile,
                current.state.exact_lock,
                current.state.transaction_result,
                current.state.root_operation_completion,
                current.state.mutation_started,
                prepared.profile_state_path,
            );
        return self.finishPreMutationFailure(
            allocator,
            prepared,
            &current,
            outcome,
            diagnostic,
            message,
        );
    }

    fn markRecoveryRequired(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        current: *operation_state.OwnedState,
        message: []const u8,
    ) !api.Result {
        if (current.state.phase != .recovery_required) {
            try self.transition(
                allocator,
                prepared.profile_state_path,
                current,
                .{
                    .phase = .recovery_required,
                    .diagnostic = message,
                },
            );
        }
        return recoveryDiagnostic(
            allocator,
            prepared.request,
            prepared.profile,
            current.state.exact_lock,
            current.state.transaction_result,
            current.state.root_operation_completion,
            true,
            prepared.profile_state_path,
        );
    }

    fn recoveryFailed(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        current: *operation_state.OwnedState,
        message: []const u8,
    ) !api.Result {
        try self.transition(
            allocator,
            prepared.profile_state_path,
            current,
            .{
                .phase = .recovery_required,
                .diagnostic = message,
            },
        );
        return recoveryDiagnostic(
            allocator,
            prepared.request,
            prepared.profile,
            current.state.exact_lock,
            current.state.transaction_result,
            current.state.root_operation_completion,
            true,
            prepared.profile_state_path,
        );
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
    result.evidence = .{
        .exact_lock = lock,
        .transaction_result = transaction,
        .root_operation_completion = completion,
        .active_operation_state = active_path,
    };
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
    return retained.phase == .completed and
        proposed.phase == .completed and
        retained.generation == proposed.generation and
        retained.operation == proposed.operation and
        retained.mutation_started == proposed.mutation_started and
        retained.outcome == proposed.outcome and
        std.mem.eql(u8, &retained.attempt_id, &proposed.attempt_id) and
        std.mem.eql(
            u8,
            &retained.request_sha256,
            &proposed.request_sha256,
        ) and
        profileEqual(retained.profile, proposed.profile) and
        retained.exact_lock != null and
        proposed.exact_lock != null and
        documentEqual(retained.exact_lock.?, proposed.exact_lock.?) and
        retained.transaction_result != null and
        proposed.transaction_result != null and
        documentEqual(
            retained.transaction_result.?,
            proposed.transaction_result.?,
        ) and
        retained.root_operation_completion != null and
        proposed.root_operation_completion != null and
        completionEqual(
            retained.root_operation_completion.?,
            proposed.root_operation_completion.?,
        );
}

fn recoverableOuterPhase(phase: operation_state.Phase) bool {
    return switch (phase) {
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
    if (retained.phase != .completed or
        (retained.outcome != .succeeded and retained.outcome != .recovered) or
        !stateMatchesPreparation(retained, prepared) or
        retained.transaction_result == null or
        retained.root_operation_completion == null)
        return false;
    if (active.transaction_result) |transaction|
        if (!documentEqual(transaction, retained.transaction_result.?))
            return false;
    if (active.root_operation_completion) |completion|
        if (!completionEqual(
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
    return std.mem.eql(u8, &state.attempt_id, &prepared.attempt_id) and
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

test "apt_system_orchestrator.test.production options preserve host-root denial" {
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

test "apt_system_orchestrator.test.operation directory parent is durable before active publication" {
    if (builtin.os.tag != .linux or std.os.linux.geteuid() != 0)
        return error.SkipZigTest;
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

test "apt_system_orchestrator.test.system finish reuses retained final after pre-CAS crash" {
    if (builtin.os.tag != .linux or std.os.linux.geteuid() != 0)
        return error.SkipZigTest;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try directory.dir.realPath(
        std.testing.io,
        &root_buffer,
    );
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{root_buffer[0..root_length]},
    );
    defer std.testing.allocator.free(state_path);
    const attempt_id: [32]u8 = @splat(0x41);
    var paths = try pathsFor(
        std.testing.allocator,
        state_path,
        attempt_id,
    );
    defer paths.deinit(std.testing.allocator);
    var states = try testStatePair(
        std.testing.allocator,
        paths,
        attempt_id,
    );
    defer states.deinit();
    var crash: TestFinishCrash = .{};
    var store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .finish_crash = crash.interface(),
    };
    const interface = store.interface();
    interface.reserveFn(
        interface.context,
        std.testing.allocator,
        paths,
        "{}",
        states.current.state,
    ) catch |err| switch (err) {
        error.NotRootOwned => return error.SkipZigTest,
        else => return err,
    };
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

    var regenerated = try nextState(
        std.testing.allocator,
        active.state,
        .{
            .phase = .completed,
            .outcome = .succeeded,
            .root_operation_completion = states.final.state.root_operation_completion,
            .updated_unix = 999,
        },
    );
    defer regenerated.deinit();
    store.finish_crash = null;
    try interface.finishFn(
        interface.context,
        std.testing.allocator,
        paths,
        operation_state.Expected.fromState(active.state),
        regenerated.state,
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

test "apt_system_orchestrator.test.system finish rejects foreign retained final" {
    if (builtin.os.tag != .linux or std.os.linux.geteuid() != 0)
        return error.SkipZigTest;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try directory.dir.realPath(
        std.testing.io,
        &root_buffer,
    );
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{root_buffer[0..root_length]},
    );
    defer std.testing.allocator.free(state_path);
    const attempt_id: [32]u8 = @splat(0x61);
    var paths = try pathsFor(
        std.testing.allocator,
        state_path,
        attempt_id,
    );
    defer paths.deinit(std.testing.allocator);
    var states = try testStatePair(
        std.testing.allocator,
        paths,
        attempt_id,
    );
    defer states.deinit();
    var crash: TestFinishCrash = .{};
    var store: SystemStateStore = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .finish_crash = crash.interface(),
    };
    const interface = store.interface();
    interface.reserveFn(
        interface.context,
        std.testing.allocator,
        paths,
        "{}",
        states.current.state,
    ) catch |err| switch (err) {
        error.NotRootOwned => return error.SkipZigTest,
        else => return err,
    };
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
    const attempt_hex = std.fmt.bytesToHex(attempt_id, .lower);
    const retained_relative = try std.fmt.allocPrint(
        std.testing.allocator,
        "state/apt/operations/{s}/{s}",
        .{ &attempt_hex, retained_state_name },
    );
    defer std.testing.allocator.free(retained_relative);
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = retained_relative,
        .data = foreign_bytes,
    });
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
    source_paths: [1][]const u8 = .{"/etc/debz/source"},
    keyring_paths: [1][]const u8 = .{"/etc/debz/keyring"},

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
                            0x11,
                    ),
                    .reference_evidence_sha256 = @splat(0x22),
                },
                .source_paths = &self.source_paths,
                .config_paths = &.{},
                .keyring_paths = &self.keyring_paths,
                .architecture = "amd64",
                .foreign_architectures = &.{},
                .repository_policy = .strict_priority,
                .cache_path = "/cache",
                .state_path = "/state",
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
        const status = switch (request.mode) {
            .plan_only => status: {
                self.plan_calls += 1;
                break :status self.plan_status;
            },
            .download_only => status: {
                self.download_calls += 1;
                break :status self.download_status;
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
                .execute => switch (request.operation) {
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
            if (request.mode == .execute or request.mode == .recover)
                self.inspect_status = .recovery_required;
            return error.RootReplaced;
        }
        const backend_result = try backend.workflow(allocator, request);
        var result: BackendResult = .{
            .result = backend_result,
            .root_status = switch (request.mode) {
                .execute => self.execute_root_status,
                .recover => self.recover_root_status,
                else => .clean,
            },
        };
        if (request.finalize_ownership and
            result.result.exit_status == .success)
        {
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
            self.publish_abandoned_on_execute = false;
            self.inspect_status = .clean;
        } else if (request.mode == .execute and
            result.result.exit_status == .success and
            self.inspect_deferred_acknowledgment != null and
            (self.inspect_deferred_acknowledgment.?.state == .abandoned or
                self.inspect_deferred_acknowledgment.?.state == .bound))
        {
            self.inspect_deferred_acknowledgment = null;
            self.inspect_status = .clean;
        }
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
            result.result.exit_status == .success)
        {
            if (request.recovery_acknowledgment) |_| {
                self.recovery_ack_calls += 1;
                if (self.inspect_record_source) |source|
                    self.allocator.free(source);
                self.inspect_record_source = null;
            } else {
                var completion = try fakeRecoveryCompletion(
                    allocator,
                    request,
                    self.recovery_completion_mismatch,
                );
                errdefer completion.deinit();
                const source =
                    try completion.document.canonicalJson(self.allocator);
                if (self.recovery_completion_source) |previous|
                    self.allocator.free(previous);
                self.recovery_completion_source = source;
                var record = try fakePublishedRecoveryRecord(
                    allocator,
                    completion.document,
                );
                defer record.deinit();
                const record_source =
                    try record.record.canonicalJson(self.allocator);
                if (self.inspect_record_source) |previous|
                    self.allocator.free(previous);
                self.inspect_record_source = record_source;
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
                    .bound, .pending => .recovery_required,
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
            @splat(0x91),
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

fn fakePublishedRecoveryRecord(
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

const FakeStateStore = struct {
    allocator: std.mem.Allocator,
    active_bytes: ?[]u8 = null,
    retained_bytes: ?[]u8 = null,
    request_bytes: ?[]u8 = null,
    recovery_completion_bytes: ?[]u8 = null,
    reserve_calls: usize = 0,
    transition_calls: usize = 0,
    finish_calls: usize = 0,
    retained_transaction: bool = false,
    completion_published: bool = false,
    fail_finish: bool = false,
    fail_after_retain_once: bool = false,
    fail_recovery_retain_once: bool = false,

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
            .reserveFn = reserve,
            .compareAndSetFn = compareAndSet,
            .finishFn = finish,
            .readRequestFn = readRequest,
            .readRetainedFn = readRetained,
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

    fn finish(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        _: OperationPaths,
        expected: operation_state.Expected,
        final: operation_state.State,
    ) !void {
        const self: *FakeStateStore = @ptrCast(@alignCast(context));
        if (self.fail_finish) return error.InjectedFinishFailure;
        if (self.fail_after_retain_once) {
            self.fail_after_retain_once = false;
            if (self.retained_bytes) |bytes| self.allocator.free(bytes);
            self.retained_bytes = try final.canonicalJson(self.allocator);
            return error.InjectedFinishCrash;
        }
        if (expected.generation != final.generation or
            !std.mem.eql(
                u8,
                &expected.digest_sha256,
                &final.digest_sha256,
            ))
            try compareAndSet(context, allocator, "", expected, final);
        if (self.retained_bytes) |bytes| self.allocator.free(bytes);
        self.retained_bytes = self.active_bytes;
        self.active_bytes = null;
        self.finish_calls += 1;
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
    lock_digest: [32]u8 = @splat(0x55),
    transaction_digest: [32]u8 = @splat(0x66),
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
    ) !VerifiedLock {
        const self: *FakeVerifier = @ptrCast(@alignCast(context));
        self.lock_checks += 1;
        if (!self.lock_valid) return error.DigestMismatch;
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
    ) !VerifiedTransaction {
        const self: *FakeVerifier = @ptrCast(@alignCast(context));
        self.transaction_checks += 1;
        if (!self.transaction_valid) return error.LockEvidenceMismatch;
        return .{
            .bytes = try allocator.dupe(u8, "{\"verified\":true}"),
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

test "apt_system_orchestrator.test.private runner transfers canonical result through live-root namespace" {
    if (builtin.os.tag != .linux or std.os.linux.geteuid() != 0)
        return error.SkipZigTest;
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
        => return error.SkipZigTest,
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

test "apt_system_orchestrator.test.private runner validates every workflow mode transport operation" {
    if (builtin.os.tag != .linux or std.os.linux.geteuid() != 0)
        return error.SkipZigTest;
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
            => return error.SkipZigTest,
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
        => return error.SkipZigTest,
        else => return err,
    };
    defer finalized.deinit();
    try std.testing.expectEqual(
        product_api.ExitStatus.success,
        finalized.result.exit_status,
    );
    try std.testing.expectEqual(RootStatus.completed, finalized.root_status);
}

test "apt_system_orchestrator.test.private transport signal is supervised and releases live-root lock" {
    if (builtin.os.tag != .linux or std.os.linux.geteuid() != 0)
        return error.SkipZigTest;
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
        => return error.SkipZigTest,
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

test "apt_system_orchestrator.test.production composition instantiates the delivered engine" {
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
    try std.testing.expectEqual(api.DiagnosticId.profile_untrusted, profile_result.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 0), profile_harness.backend.execute_calls);
    try std.testing.expect(profile_harness.store.active_bytes == null);

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
    try std.testing.expectEqual(api.Outcome.planning, lock_result.outcome);
    try std.testing.expectEqual(@as(usize, 0), lock_harness.backend.execute_calls);
    try std.testing.expect(lock_harness.store.active_bytes == null);
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

test "apt_system_orchestrator.test.production recovery bindings fail closed independently" {
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
    harness.runner.inspect_record_source =
        try published_record.record.canonicalJson(
            harness.runner.allocator,
        );
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
        try std.testing.expectError(
            error.InjectedCompletionCrash,
            harness.engine.executeRecovery(
                std.testing.allocator,
                first_recovery,
                true,
            ),
        );
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
            @as(usize, 0),
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
        try std.testing.expectError(
            error.InjectedCompletionCrash,
            harness.engine.execute(std.testing.allocator, prepared, true),
        );
        try std.testing.expect(crash.triggered);
        try std.testing.expectEqual(@as(usize, 1), harness.backend.execute_calls);
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
        try std.testing.expectEqual(@as(usize, 2), harness.runner.inspect_calls);
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
        try std.testing.expectError(
            error.InjectedCompletionCrash,
            harness.engine.execute(std.testing.allocator, prepared, true),
        );
        try std.testing.expect(crash.triggered);
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

test "apt_system_orchestrator.test.owner-bound publication crash retries execution without recovery intent" {
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
    try std.testing.expectEqual(api.Outcome.success, result.outcome);
    try std.testing.expectEqual(@as(usize, 1), harness.backend.execute_calls);
    try std.testing.expectEqual(@as(usize, 0), harness.backend.recover_calls);
    try std.testing.expect(
        harness.runner.inspect_deferred_acknowledgment == null,
    );
    try std.testing.expect(harness.store.active_bytes == null);
}

test "apt_system_orchestrator.test.post-recovery crashes use exact retained binding and ignore stale global completion" {
    inline for (std.meta.tags(CompletionBoundary)) |boundary| {
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
        try std.testing.expectError(
            error.InjectedCompletionCrash,
            harness.engine.executeRecovery(
                std.testing.allocator,
                first_recovery,
                true,
            ),
        );
        try std.testing.expect(crash.triggered);
        try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
        if (boundary == .after_recovery_acknowledged or
            boundary == .after_completion_published)
        {
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
            @as(usize, 1),
            harness.backend.recovery_ack_calls,
        );
        try std.testing.expectEqual(
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
    const result = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
    try std.testing.expectEqual(api.DiagnosticId.state_persistence_failed, result.diagnostics[0].id);
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
    try std.testing.expectEqual(
        api.DiagnosticId.state_persistence_failed,
        failed.diagnostics[0].id,
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
}

comptime {
    _ = exact_lock.schema_id;
    _ = transaction_provenance.schema_id;
}
