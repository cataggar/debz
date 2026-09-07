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
const solver = @import("solver.zig");
const system_profile = @import("system_profile.zig");
const transaction_provenance = @import("transaction_provenance.zig");
const transaction_result_summary = @import("transaction_result_summary.zig");

pub const operation_directory_name = "operations";
pub const request_document_name = "request-v1.json";
pub const retained_state_name = "state-v1.json";
pub const exact_lock_name = "exact-lock-v1.json";
pub const transaction_result_name = "transaction-result.json";
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

pub const BackendResult = struct {
    result: product_api.Result,
    root_status: RootStatus,
    owned_result: ?product_api.OwnedResult = null,

    pub fn deinit(self: *BackendResult) void {
        if (self.owned_result) |*owned| owned.deinit();
        self.* = undefined;
    }
};

pub const WorkflowOperation = enum { install, remove, upgrade_all };
pub const WorkflowMode = enum { plan_only, download_only, execute, recover };

pub const WorkflowRequest = struct {
    operation: WorkflowOperation,
    mode: WorkflowMode,
    selectors: []const solver.PackageSelector,
    options: product_api.CommonOptions,
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
    inspectFn: *const fn (*anyopaque) anyerror!RootStatus,

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

    pub fn inspect(self: LiveRootRunner) !RootStatus {
        return self.inspectFn(self.context);
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

    pub fn interface(self: *PrivateLiveRootRunner) LiveRootRunner {
        return .{
            .context = self,
            .routeFn = route,
            .workflowFn = workflow,
            .inspectFn = inspect,
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

    fn inspect(context: *anyopaque) !RootStatus {
        const self: *PrivateLiveRootRunner = @ptrCast(@alignCast(context));
        const result = try live_root.run(.{
            .context = self,
            .child = inspectChild,
            .termination_grace_ms = self.termination_grace_ms,
        });
        return switch (result) {
            .exited => |code| switch (code) {
                0 => .clean,
                10 => .recovery_required,
                else => error.LiveRootChildFailed,
            },
            .signaled => error.LiveRootChildSignaled,
            .interrupted => error.LiveRootInterrupted,
            .setup_failed => |failure| mapSetupFailure(failure),
        };
    }

    fn invoke(
        self: *PrivateLiveRootRunner,
        allocator: std.mem.Allocator,
        invocation: Invocation,
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
        const result = live_root.run(.{
            .context = &child_context,
            .child = transportChild,
            .termination_grace_ms = self.termination_grace_ms,
        }) catch |err| {
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
            .workflow => |workflow_invocation| switch (workflow_invocation.request.operation) {
                .install => .install,
                .remove => .remove,
                .upgrade_all => .upgrade_all,
            },
        };
        if (decoded.result.operation != expected_operation)
            return error.BackendOperationMismatch;
        const root_status: RootStatus = switch (invocation) {
            .route => .clean,
            .workflow => |workflow_invocation| switch (workflow_invocation.request.mode) {
                .execute, .recover => if (decoded.result.exit_status == .success)
                    switch (try self.interface().inspect()) {
                        .clean, .completed => .completed,
                        .recovery_required => .recovery_required,
                    }
                else
                    .recovery_required,
                .plan_only, .download_only => .clean,
            },
        };
        return .{
            .result = decoded.result,
            .root_status = root_status,
            .owned_result = decoded,
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
        const self: *PrivateLiveRootRunner = @ptrCast(@alignCast(raw.?));
        var owned_root = try root_fs.openAbsoluteRoot(self.io, install_root);
        defer owned_root.close();
        var record = (try root_operation.Store.init(
            owned_root.root,
        ).read(std.heap.page_allocator)) orelse return 0;
        defer record.deinit();
        return 10;
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

pub const OperationPaths = struct {
    directory: []u8,
    active_state: []u8,
    retained_state: []u8,
    request: []u8,
    exact_lock: []u8,
    transaction_result: []u8,
    completion: []u8,

    pub fn deinit(self: *OperationPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.directory);
        allocator.free(self.active_state);
        allocator.free(self.retained_state);
        allocator.free(self.request);
        allocator.free(self.exact_lock);
        allocator.free(self.transaction_result);
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
    retainTransactionFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        []const u8,
        [32]u8,
    ) anyerror!api.DocumentBinding,
    publishCompletionFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        OperationPaths,
        CompletionInput,
    ) anyerror!api.CompletionBinding,

    pub fn readActive(
        self: StateStore,
        allocator: std.mem.Allocator,
        state_path: []const u8,
    ) !?operation_state.OwnedState {
        return self.readActiveFn(self.context, allocator, state_path);
    }
};

pub const SystemStateStore = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    wait_ms: u64 = 30_000,

    const operation_lock_name = "operation.lock";

    pub fn interface(self: *SystemStateStore) StateStore {
        return .{
            .context = self,
            .readActiveFn = readActive,
            .reserveFn = reserve,
            .compareAndSetFn = compareAndSet,
            .finishFn = finish,
            .readRequestFn = readRequest,
            .retainTransactionFn = retainTransaction,
            .publishCompletionFn = publishCompletion,
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
            self.io,
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
        const parent_path = std.fs.path.dirname(paths.directory) orelse
            return error.InvalidPath;
        const leaf = std.fs.path.basename(paths.directory);
        var parent = try openSecureAbsoluteDirectory(
            self.io,
            allocator,
            parent_path,
            true,
        );
        defer parent.close(self.io);
        parent.createDir(
            self.io,
            leaf,
            .fromMode(0o700),
        ) catch |err| switch (err) {
            error.PathAlreadyExists => return error.StateAlreadyExists,
            else => return err,
        };
        var operation_dir = try parent.openDir(self.io, leaf, .{
            .follow_symlinks = false,
        });
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

        const apt_path = std.fs.path.dirname(paths.active_state) orelse
            return error.InvalidPath;
        var apt_dir = try openSecureAbsoluteDirectory(
            self.io,
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
            self.io,
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
            self.io,
            allocator,
            paths.directory,
            false,
        );
        defer operation_dir.close(self.io);
        const final_bytes = try final.canonicalJson(allocator);
        defer allocator.free(final_bytes);
        try publishAtomic(
            self,
            allocator,
            operation_dir,
            retained_state_name,
            final_bytes,
        );

        const state_path = std.fs.path.dirname(
            std.fs.path.dirname(paths.active_state) orelse
                return error.InvalidPath,
        ) orelse return error.InvalidPath;
        const already_final = expected.generation == final.generation and
            std.mem.eql(
                u8,
                &expected.digest_sha256,
                &final.digest_sha256,
            );
        if (!already_final)
            try compareAndSet(context, allocator, state_path, expected, final);
        const apt_path = std.fs.path.dirname(paths.active_state) orelse
            return error.InvalidPath;
        var apt_dir = try openSecureAbsoluteDirectory(
            self.io,
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
        if (state.state.generation != final.generation or
            !std.mem.eql(
                u8,
                &state.state.digest_sha256,
                &final.digest_sha256,
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
            self.io,
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

    fn publishCompletion(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        paths: OperationPaths,
        input: CompletionInput,
    ) !api.CompletionBinding {
        const self: *SystemStateStore = @ptrCast(@alignCast(context));
        var dir = try openSecureAbsoluteDirectory(
            self.io,
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
        try syncDirectory(self.io, dir);
    }
};

pub const VerifiedLock = struct {
    binding: api.DocumentBinding,
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
        return .{ .binding = .{
            .path = path,
            .schema = exact_lock.schema_id,
            .version = exact_lock.schema_version,
            .digest_sha256 = decoded.lock.digest_sha256,
        } };
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
            const lower_status = self.runner.inspect() catch |err|
                return .{ .result = try liveRootFailure(request, err) };
            if (lower_status != .clean)
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
                .result = try self.prepareReadOnly(allocator, request, loaded.view),
            },
            .install, .remove, .upgrade => try self.prepareMutation(
                allocator,
                request,
                loaded.view,
            ),
        };
    }

    fn prepareReadOnly(
        self: *Engine,
        allocator: std.mem.Allocator,
        request: api.Request,
        profile: ProfileView,
    ) !api.Result {
        const operation: product_api.Operation = switch (request.operation) {
            .update => .refresh,
            .list_installed => .list_installed,
            else => unreachable,
        };
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
        profile: ProfileView,
    ) !PrepareOutcome {
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
            loaded.view,
            &current,
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
        if (active.state.phase != .recovery_required and
            active.state.phase != .recovering)
        {
            try self.transition(
                allocator,
                loaded.view.state_path,
                &active,
                .{
                    .phase = .recovery_required,
                    .diagnostic = "interrupted mutation requires recovery",
                },
            );
        }
        const verified = self.verifier.verifyLockFn(
            self.verifier.context,
            allocator,
            paths.exact_lock,
            loaded.view.architecture,
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
            (current.state.phase != .recovery_required and
                current.state.phase != .recovering))
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
        const lower_status = self.runner.inspect() catch
            return self.recoveryFailed(
                allocator,
                recovery.prepared,
                &current,
                "lower-level root-operation status could not be inspected",
            );
        if (lower_status == .clean or lower_status == .completed) {
            const lower_recovery_completed =
                current.state.phase == .recovering;
            try self.transition(
                allocator,
                loaded.view.state_path,
                &current,
                .{
                    .phase = .recovering,
                    .diagnostic = "reconciling completed transaction",
                },
            );
            return self.verifyAndComplete(
                allocator,
                recovery.prepared,
                loaded.view,
                &current,
                lower_recovery_completed,
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
        return self.verifyAndComplete(
            allocator,
            recovery.prepared,
            loaded.view,
            &current,
            true,
        );
    }

    fn verifyAndComplete(
        self: *Engine,
        allocator: std.mem.Allocator,
        prepared: Preparation,
        profile: ProfileView,
        current: *operation_state.OwnedState,
        recovered: bool,
    ) !api.Result {
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
        const retained = self.store.retainTransactionFn(
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
                .exact_lock = prepared.exact_lock,
                .transaction_result = retained,
                .root_operation_completion = completion,
                .active_operation_state = prepared.paths.retained_state,
            },
        };
        result = try api.complete(result);
        return api.ownResult(allocator, result);
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
        return api.failure(request, outcome, diagnostic, "prepare", message);
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
        return api.failure(
            request,
            mapOutcome(result.exit_status),
            mapDiagnostic(result.exit_status),
            "backend",
            result.summary,
        );
    if (request.operation != .list_installed and result.items.len != 0)
        return error.UnexpectedItems;
    var items: []api.Item = &.{};
    if (request.operation == .list_installed)
        items = try allocator.alloc(api.Item, result.items.len);
    defer if (items.len != 0) allocator.free(items);
    for (result.items, 0..) |item, index| {
        items[index] = .{
            .package = item.package,
            .version = item.version,
            .architecture = item.architecture,
            .detail = item.detail,
        };
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
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    create: bool,
) !std.Io.Dir {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/')
        return error.InvalidPath;
    var current = try std.Io.Dir.openDirAbsolute(io, "/", .{
        .follow_symlinks = false,
    });
    errdefer current.close(io);
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return error.InvalidPath;
        const next = current.openDir(io, component, .{
            .follow_symlinks = false,
        }) catch |err| switch (err) {
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
                break :create_block try current.openDir(io, component, .{
                    .follow_symlinks = false,
                });
            },
            else => return err,
        };
        current.close(io);
        current = next;
    }
    try validateSecureDirectoryChain(io, allocator, path);
    return current;
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
        if (self.fail_revalidate) return error.TrustedFileContentChanged;
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
            .items = if (request.operation == .list_installed)
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

const FakeRunner = struct {
    calls: usize = 0,
    inspect_calls: usize = 0,
    saw_stable_root: bool = true,
    execute_root_status: RootStatus = .completed,
    recover_root_status: RootStatus = .completed,
    inspect_status: RootStatus = .clean,
    fail_mode: ?WorkflowMode = null,

    fn interface(self: *FakeRunner) LiveRootRunner {
        return .{
            .context = self,
            .routeFn = route,
            .workflowFn = workflow,
            .inspectFn = inspect,
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
        return .{
            .result = try backend.route(allocator, request),
            .root_status = .clean,
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
        if (self.fail_mode == request.mode) {
            if (request.mode == .execute or request.mode == .recover)
                self.inspect_status = .recovery_required;
            return error.RootReplaced;
        }
        const result: BackendResult = .{
            .result = try backend.workflow(allocator, request),
            .root_status = switch (request.mode) {
                .execute => self.execute_root_status,
                .recover => self.recover_root_status,
                else => .clean,
            },
        };
        if (request.mode == .execute or request.mode == .recover)
            self.inspect_status = .clean;
        return result;
    }

    fn inspect(context: *anyopaque) !RootStatus {
        const self: *FakeRunner = @ptrCast(@alignCast(context));
        self.inspect_calls += 1;
        return self.inspect_status;
    }
};

const FakeStateStore = struct {
    allocator: std.mem.Allocator,
    active_bytes: ?[]u8 = null,
    retained_bytes: ?[]u8 = null,
    request_bytes: ?[]u8 = null,
    reserve_calls: usize = 0,
    transition_calls: usize = 0,
    finish_calls: usize = 0,
    retained_transaction: bool = false,
    completion_published: bool = false,
    fail_finish: bool = false,

    fn deinit(self: *FakeStateStore) void {
        if (self.active_bytes) |bytes| self.allocator.free(bytes);
        if (self.retained_bytes) |bytes| self.allocator.free(bytes);
        if (self.request_bytes) |bytes| self.allocator.free(bytes);
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
            .retainTransactionFn = retainTransaction,
            .publishCompletionFn = publishCompletion,
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
};

const FakeVerifier = struct {
    lock_valid: bool = true,
    transaction_valid: bool = true,
    lock_digest: [32]u8 = @splat(0x55),
    transaction_digest: [32]u8 = @splat(0x66),
    lock_checks: usize = 0,
    different_lock_check: ?usize = null,
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
    ) !VerifiedLock {
        const self: *FakeVerifier = @ptrCast(@alignCast(context));
        self.lock_checks += 1;
        if (!self.lock_valid) return error.DigestMismatch;
        const digest = if (self.different_lock_check == self.lock_checks)
            [_]u8{0x77} ** 32
        else
            self.lock_digest;
        return .{ .binding = .{
            .path = path,
            .schema = exact_lock.schema_id,
            .version = exact_lock.schema_version,
            .digest_sha256 = digest,
        } };
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

const Harness = struct {
    profile: FakeProfileLoader = .{},
    backend: FakeBackend = .{},
    runner: FakeRunner = .{},
    store: FakeStateStore,
    verifier: FakeVerifier = .{},
    sources: FakeSources = .{},
    engine: Engine = undefined,

    fn init(allocator: std.mem.Allocator) Harness {
        return .{
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
        .result => |result| {
            std.debug.print("unexpected result: {s}\n", .{result.summary});
            return error.ExpectedPreparation;
        },
    };
}

test "apt_system_orchestrator.test.update and list route through stable live root" {
    var harness = Harness.init(std.testing.allocator);
    defer harness.deinit();
    harness.rebind();
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

test "apt_system_orchestrator.test.private runner transfers canonical result through live-root namespace" {
    if (builtin.os.tag != .linux or std.os.linux.geteuid() != 0)
        return error.SkipZigTest;
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
        error.NotPrivileged, error.NamespaceUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer result.deinit();
    try std.testing.expectEqual(product_api.ExitStatus.success, result.result.exit_status);
    try std.testing.expectEqual(RootStatus.clean, result.root_status);
    try std.testing.expectEqual(@as(usize, 2), result.result.items.len);
    try std.testing.expectEqualStrings("installed-a", result.result.items[0].package);
    try std.testing.expectEqualStrings("1", result.result.items[0].version.?);
    try std.testing.expectEqualStrings("amd64", result.result.items[0].architecture.?);
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
    const profile_result = try profile_harness.engine.execute(
        std.testing.allocator,
        profile_prepared,
        true,
    );
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
    const lock_result = try lock_harness.engine.execute(
        std.testing.allocator,
        lock_prepared,
        true,
    );
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
    const result = try harness.engine.execute(
        std.testing.allocator,
        prepared,
        true,
    );
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
        .result => |result| {
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

test "apt_system_orchestrator.test.post-backend crashes reconcile without a second mutation" {
    inline for (std.meta.tags(CompletionBoundary)) |boundary| {
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

test "apt_system_orchestrator.test.post-recovery crashes reconcile without a second recovery" {
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
        harness.engine.completion_crash = null;
        harness.runner.inspect_status = .clean;

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
        try std.testing.expectEqual(api.Outcome.success, result.outcome);
        try std.testing.expectEqual(@as(usize, 1), harness.backend.recover_calls);
        try std.testing.expect(harness.store.active_bytes == null);
    }
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

comptime {
    _ = exact_lock.schema_id;
    _ = transaction_provenance.schema_id;
}
