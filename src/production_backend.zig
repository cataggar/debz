const std = @import("std");
const api = @import("product_api.zig");
const deb_payload = @import("deb_payload.zig");
const dpkg_status = @import("dpkg_status.zig");
const metadata_cache = @import("metadata_cache.zig");
const package_acquisition = @import("package_acquisition.zig");
const package_cache_archive = @import("package_cache_archive.zig");
const package_cache_workflow = @import("package_cache_workflow.zig");
const repository_acquisition = @import("repository_acquisition.zig");
const repository_policy = @import("repository_policy.zig");
const repository_refresh = @import("repository_refresh.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const root_operation_completion = @import("root_operation_completion.zig");
const solver = @import("solver.zig");
const source = @import("source.zig");
const transaction_engine = @import("transaction_engine.zig");
const transaction_executor = @import("transaction_executor.zig");
const live_root = @import("live_root.zig");
const transaction_recovery = @import("transaction_recovery.zig");
const transaction_provenance = @import("transaction_provenance.zig");
const exact_lock = @import("exact_lock.zig");
const openpgp = @import("openpgp_verifier.zig");

pub const Executor = transaction_engine.Executor;

/// Internal package workflow contract. Product API v1 remains a singleton
/// facade for install and remove; orchestrators use this seam when one
/// reviewed exact lock must bind a batch.
pub const WorkflowSemanticOperation = enum { install, remove, upgrade_all };
pub const WorkflowMode = enum {
    plan_only,
    download_only,
    reserve,
    execute,
    recover,
};

pub const WorkflowRecoveryAcknowledgment = struct {
    attempt_id: [32]u8,
    completion_sha256: [32]u8,
    provenance_sha256: [32]u8,
    acknowledgment_id: [32]u8,
};

pub const WorkflowOwnershipAcknowledgment = struct {
    attempt_id: [32]u8,
    marker_sha256: [32]u8,
    marker_exact_identity_sha256: [32]u8,
    acknowledgment_id: [32]u8,
    marker: root_operation.DeferredAcknowledgment,
};

pub const WorkflowReconciliationClaim = union(enum) {
    pre_mutation: struct {
        outer_generation: u64,
        outer_state_sha256: [32]u8,
        profile_sha256: [32]u8,
        profile_reference_sha256: [32]u8,
        exact_lock_sha256: [32]u8,
    },
    post_mutation: struct {
        exact_lock_sha256: [32]u8,
        evidence_sha256: [32]u8,
    },
};

pub const WorkflowRequest = struct {
    operation: WorkflowSemanticOperation,
    mode: WorkflowMode,
    selectors: []const solver.PackageSelector = &.{},
    options: api.CommonOptions,
    /// Internal cross-layer protocol. Ordinary product recovery keeps its
    /// historical clear-on-success behavior.
    defer_recovery_clear: bool = false,
    /// Internal outer-attempt identity, bound into the lower root record
    /// namespace before an orchestrated mutation can begin.
    orchestration_id: ?[32]u8 = null,
    recovery_review_claim: ?root_operation.RecoveryReviewClaim = null,
    /// Exact lower owner authenticated by durable outer-operation evidence
    /// for a restarted v2 workflow.
    expected_ownership_marker: ?root_operation.DeferredAcknowledgment = null,
    reconciliation_claim: ?WorkflowReconciliationClaim = null,
    finalize_ownership: bool = false,
    ownership_acknowledgment: ?WorkflowOwnershipAcknowledgment = null,
    recovery_acknowledgment: ?WorkflowRecoveryAcknowledgment = null,
};

const WorkflowDirective = struct {
    operation: WorkflowSemanticOperation,
    mode: WorkflowMode,
    defer_recovery_clear: bool = false,
    orchestration_id: ?[32]u8 = null,
    recovery_review_claim: ?root_operation.RecoveryReviewClaim = null,
    expected_ownership_marker: ?root_operation.DeferredAcknowledgment = null,
};

const TransactionSemanticOperation = enum {
    install,
    remove,
    upgrade,
    upgrade_all,
    reinstall,
};

/// Durable boundary inside the completion sequence of one product mutation.
///
/// The window between the terminal `completed` record and the cleared active
/// intent is the only part of a product transaction that a crash can leave
/// blocking a healthy root, so every step in it is a named seam. Production
/// callers leave `Backend.completion_crash` null and each step simply runs.
pub const CompletionPoint = enum {
    after_root_lock_acquired,
    after_binding_published,
    before_retry_terminal_publish,
    after_retry_terminal_publish,
    before_retry_record_clear,
    after_retry_record_clear,
    before_binding_published,
    /// The completed record is durable; nothing else has run.
    after_completed_record,
    /// The recovery intent has been removed from the state directory.
    after_recovery_intent_deleted,
    /// The detailed transaction provenance document has been published.
    after_transaction_provenance,
    /// A recovery published the root-operation completion statement but has
    /// not yet bound it to the record.
    after_owed_provenance_document,
    /// The record carries its provenance digest but the active intent has not
    /// been cleared yet.
    after_provenance_published,
    /// A deferred recovery has prepared its success result while the exact
    /// completed/published lower record still remains durable.
    before_deferred_recovery_return,
    before_ownership_terminal_publish,
    after_ownership_terminal_publish,
    before_ownership_record_clear,
    after_ownership_record_clear,
    before_ownership_marker_clear,
    after_ownership_marker_clear,
    before_reconciliation_marker_publish,
    after_reconciliation_marker_publish,
    before_deferred_acknowledged,
    after_deferred_acknowledged,
    before_deferred_record_cleared,
    after_deferred_record_cleared,
    before_deferred_marker_cleared,
    after_deferred_marker_cleared,
};

/// Test seam that reproduces a process death at a completion boundary. A
/// non-null error return leaves every durable artifact exactly as the crashed
/// process would have left it: nothing is completed, cleared, or rolled back
/// on the way out.
pub const CompletionCrash = struct {
    context: *anyopaque,
    hitFn: *const fn (*anyopaque, CompletionPoint) anyerror!void,

    pub fn hit(self: CompletionCrash, point: CompletionPoint) !void {
        return self.hitFn(self.context, point);
    }
};

pub const RootBindingPoint = enum {
    after_root_lock_acquired,
    before_retry_terminal_publish,
    after_retry_terminal_publish,
    before_retry_record_clear,
    after_retry_record_clear,
    before_binding_published,
    after_binding_published,
};

pub const RootBindingSync = struct {
    context: *anyopaque,
    hitFn: *const fn (*anyopaque, RootBindingPoint) anyerror!void,

    pub fn hit(self: RootBindingSync, point: RootBindingPoint) !void {
        return self.hitFn(self.context, point);
    }
};

const RepositoryOptions = struct {
    source_paths: []const []const u8,
    config_paths: []const []const u8,
    keyring_paths: []const []const u8,
    default_release: ?[]const u8,
    proxy: ?[]const u8,
    credential_reference: ?[]const u8,
    deadline_ms: ?u64,
    offline: bool,
};

pub const Backend = struct {
    io: std.Io,
    transaction_backend: transaction_engine.Kind = .legacy_dpkg,
    executor: Executor = .legacy_dpkg,
    native_executor: ?Executor = null,
    process_runner: ?transaction_executor.ProcessRunner = null,
    now_unix: ?i64 = null,
    /// Test seam. Production callers leave it null and every completion
    /// boundary runs to its durable end.
    completion_crash: ?CompletionCrash = null,
    /// Test-only synchronization around the root lock and initial binding.
    root_binding_sync: ?RootBindingSync = null,

    pub fn interface(self: *Backend) api.Backend {
        return .{ .context = self, .executeFn = executeOpaque };
    }

    pub fn executeOpaque(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: api.Request,
    ) !api.Result {
        const self: *Backend = @ptrCast(@alignCast(context));
        return self.execute(allocator, request);
    }

    pub fn execute(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !api.Result {
        return self.route(allocator, request) catch |err|
            mapRuntimeError(request.operation, err);
    }

    /// Executes the internal semantic-operation/mode contract. Planning and
    /// downloading cannot reserve or mutate the root. Execution and recovery
    /// require an explicit exact lock, confirmation, and conffile policy.
    pub fn executeWorkflow(
        self: *Backend,
        allocator: std.mem.Allocator,
        workflow: WorkflowRequest,
    ) !api.Result {
        const operation = workflowSurfaceOperation(workflow.operation, workflow.mode);
        const count_valid = switch (workflow.operation) {
            .install, .remove => workflow.selectors.len != 0,
            .upgrade_all => workflow.selectors.len == 0,
        };
        if (!count_valid)
            return api.failure(operation, .usage, .invalid_request, "invalid workflow selector count");
        if (workflow.mode == .plan_only and workflow.options.lock_output_path == null)
            return api.failure(operation, .usage, .configuration_required, "plan-only workflow requires an exact-lock output path");
        if (workflow.mode == .reserve or
            workflow.mode == .execute or
            workflow.mode == .recover)
        {
            if (workflow.options.lock_input_path == null)
                return api.failure(operation, .usage, .configuration_required, "execution and recovery require an exact-lock input");
            if (!workflow.options.assume_yes)
                return api.failure(operation, .usage, .confirmation_required, "execution and recovery require explicit confirmation");
            if (workflow.options.conffile == .unspecified)
                return api.failure(operation, .usage, .conffile_policy_required, "execution and recovery require an explicit conffile policy");
        }
        if (workflow.mode == .reserve or
            workflow.mode == .execute or
            workflow.mode == .recover)
        {
            _ = self.selectedExecutor() catch return api.failure(
                operation,
                .unavailable,
                .transaction_backend_unavailable,
                "selected transaction backend is unavailable",
            );
        }

        const canonical_selectors = try allocator.dupe(solver.PackageSelector, workflow.selectors);
        defer allocator.free(canonical_selectors);
        std.mem.sort(
            solver.PackageSelector,
            canonical_selectors,
            {},
            lessWorkflowSelector,
        );
        const packages = try allocator.alloc([]const u8, canonical_selectors.len);
        defer allocator.free(packages);
        var formatted_count: usize = 0;
        errdefer for (packages[0..formatted_count]) |package| allocator.free(package);
        for (canonical_selectors, 0..) |selector, index| {
            packages[index] = try formatSelector(allocator, selector);
            formatted_count += 1;
        }
        defer {
            for (packages) |package| allocator.free(package);
        }

        const request: api.Request = .{
            .operation = operation,
            .packages = packages,
            .options = workflow.options,
        };
        if (workflow.reconciliation_claim) |claim| {
            if (workflow.mode != .recover or
                workflow.orchestration_id == null or
                workflow.defer_recovery_clear or
                workflow.finalize_ownership or
                workflow.ownership_acknowledgment != null or
                workflow.recovery_acknowledgment != null)
                return api.failure(
                    operation,
                    .internal,
                    .internal_error,
                    "invalid clean-reconciliation claim request",
                );
            return self.claimWorkflowReconciliation(
                allocator,
                request,
                workflow.operation,
                workflow.selectors,
                workflow.orchestration_id.?,
                claim,
                workflow.recovery_review_claim,
            );
        }
        if (workflow.recovery_acknowledgment) |acknowledgment| {
            if (workflow.mode != .recover or !workflow.defer_recovery_clear or
                workflow.orchestration_id == null or
                !std.mem.eql(
                    u8,
                    &workflow.orchestration_id.?,
                    &acknowledgment.acknowledgment_id,
                ))
                return api.failure(
                    operation,
                    .usage,
                    .invalid_request,
                    "invalid internal recovery acknowledgment",
                );
            return self.acknowledgeWorkflowRecovery(
                allocator,
                request,
                workflow.operation,
                acknowledgment,
                workflow.recovery_review_claim,
            ) catch |err| mapRuntimeError(operation, err);
        }
        if (workflow.finalize_ownership) {
            if (workflow.mode != .recover or
                workflow.orchestration_id == null or
                workflow.defer_recovery_clear or
                workflow.recovery_acknowledgment != null or
                workflow.ownership_acknowledgment == null or
                !std.mem.eql(
                    u8,
                    &workflow.orchestration_id.?,
                    &workflow.ownership_acknowledgment.?.acknowledgment_id,
                ))
                return api.failure(
                    operation,
                    .internal,
                    .internal_error,
                    "invalid orchestration ownership finalization request",
                );
            return self.finalizeWorkflowOwnership(
                allocator,
                request,
                workflow.operation,
                workflow.ownership_acknowledgment.?,
                workflow.recovery_review_claim,
            );
        }
        if (workflow.ownership_acknowledgment != null)
            return api.failure(
                operation,
                .usage,
                .invalid_request,
                "unexpected orchestration ownership acknowledgment",
            );
        return self.withRepositories(allocator, request, .{
            .operation = workflow.operation,
            .mode = workflow.mode,
            .defer_recovery_clear = workflow.defer_recovery_clear,
            .orchestration_id = workflow.orchestration_id,
            .recovery_review_claim = workflow.recovery_review_claim,
            .expected_ownership_marker = workflow.expected_ownership_marker,
        }) catch |err| mapRuntimeError(operation, err);
    }

    pub fn packageCacheFingerprint(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: package_cache_workflow.Request,
        debz_version: []const u8,
    ) !package_cache_workflow.Fingerprint {
        try package_cache_workflow.validateRequest(request, false);
        var lock = readLock(allocator, self.io, request.lock_input_path) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UnsupportedSchema => return error.UnsupportedLockSchema,
            else => return error.InvalidExactLock,
        };
        defer lock.deinit();
        return package_cache_workflow.createFingerprint(
            allocator,
            lock.lock,
            request.architecture,
            debz_version,
            request.cache_root,
            request.policy(),
        );
    }

    pub fn packageCachePrepare(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: package_cache_workflow.Request,
        debz_version: []const u8,
    ) !package_cache_workflow.PrepareResult {
        try package_cache_workflow.validateRequest(request, true);
        var lock = readLock(allocator, self.io, request.lock_input_path) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UnsupportedSchema => return error.UnsupportedLockSchema,
            else => return error.InvalidExactLock,
        };
        defer lock.deinit();
        var validated_fingerprint = try package_cache_workflow.createFingerprint(
            allocator,
            lock.lock,
            request.architecture,
            debz_version,
            request.cache_root,
            request.policy(),
        );
        defer validated_fingerprint.deinit();

        const repository_options: RepositoryOptions = .{
            .source_paths = request.source_paths,
            .config_paths = request.config_paths,
            .keyring_paths = request.keyring_paths,
            .default_release = request.default_release,
            .proxy = request.proxy,
            .credential_reference = request.credential_reference,
            .deadline_ms = request.deadline_ms,
            .offline = request.offline,
        };

        var loaded = try self.loadRepositoryDocuments(allocator, repository_options);
        defer loaded.deinit();
        const normalized = try repository_policy.normalize(
            allocator,
            loaded.documents,
            request.architecture,
            .{},
        );
        var configuration = switch (normalized) {
            .diagnostic => return error.InvalidRepositoryConfig,
            .configuration => |value| value,
        };
        defer configuration.deinit();
        for (configuration.repositories) |repository| {
            if (repository.signed_by.len == 0) return error.NoKeyrings;
            for (repository.signed_by) |path| if (!containsString(request.keyring_paths, path))
                return error.NoKeyrings;
        }
        for (request.keyring_paths) |path| try validateRegularFile(self.io, path);
        if (request.credential_reference) |path| try validateRegularFile(self.io, path);

        var cache_root = try openOrCreateAbsoluteDirectory(self.io, request.cache_root);
        defer cache_root.close(self.io);
        var package_cache = try package_acquisition.Cache.initFromDir(self.io, cache_root, .{
            .maximum_object_bytes = request.limits.maximum_package_bytes,
        });
        defer package_cache.deinit();
        var package_writer = try package_cache.acquireWriter(request.lock_wait_ms);
        defer package_writer.release();
        const initial_cleanup = try package_cache_workflow.cleanupStagingForPrepare(
            allocator,
            &package_cache,
            request.policy(),
            &package_writer,
        );
        if (request.archive_input_path) |path| {
            var archive = try openRegularFileAbsoluteNoFollow(self.io, path);
            defer archive.close(self.io);
            _ = try package_cache_archive.importFile(
                allocator,
                self.io,
                archive,
                &package_cache,
                lock.lock,
                .{
                    .maximum_objects = request.limits.maximum_lock_packages,
                    .maximum_object_bytes = request.limits.maximum_package_bytes,
                    .maximum_total_object_bytes = request.limits.maximum_total_package_bytes,
                },
                .{
                    .repair_corrupt = request.corrupt_cache == .repair_online,
                    .require_exact_closure = request.restored_cache == .exact,
                },
                &package_writer,
            );
        }
        _ = try package_cache_workflow.preflight(
            allocator,
            lock.lock,
            &package_cache,
            request.policy(),
            &package_writer,
        );
        var metadata = try metadata_cache.Cache.initFromDir(self.io, cache_root, .{});
        defer metadata.deinit();
        var acquisition = repository_acquisition.Production{ .io = self.io };
        const credential_bytes: ?[]u8 = if (request.credential_reference) |path|
            try readCredential(allocator, self.io, path)
        else
            null;
        defer if (credential_bytes) |value| allocator.free(value);
        var credential_context = if (credential_bytes != null)
            try CredentialContext.init(allocator, configuration.repositories, credential_bytes.?)
        else
            CredentialContext.empty();
        defer credential_context.deinit(allocator);
        const credentials: repository_acquisition.CredentialsProvider = if (credential_bytes != null)
            .{ .context = &credential_context, .getFn = CredentialContext.get }
        else
            .none;
        var now = self.now_unix orelse realNow(self.io);
        const runtimes = try makeRuntimes(
            allocator,
            repository_options,
            &configuration,
            now,
            credentials,
        );
        defer freeRuntimes(allocator, runtimes);
        var refresh_outcome = try repository_policy.refreshAll(allocator, .{
            .configuration = &configuration,
            .runtimes = runtimes,
            .mode = if (request.offline) .cache_only else .online,
            .dependencies = .{
                .acquisition = acquisition.dependencies(),
                .cache = &metadata,
                .clock = .{ .context = &now, .nowUnixFn = fixedNow },
                .io = self.io,
            },
        });
        defer refresh_outcome.deinit(allocator);
        const refreshed = switch (refresh_outcome) {
            .failed => return if (request.offline)
                error.OfflineRepositoryEvidenceMissing
            else
                error.RepositoryAuthenticationFailed,
            .published => |*value| value,
        };

        const views = try allocator.alloc(
            package_cache_workflow.RepositoryView,
            refreshed.universe.repositories.len,
        );
        defer allocator.free(views);
        for (refreshed.universe.repositories, 0..) |repository, index| {
            const normalized_repository = findNormalized(
                configuration.repositories,
                repository.repository_id,
            ) orelse return error.MissingRepository;
            const state = findPublishedState(
                refreshed.states,
                repository.repository_id,
            ) orelse return error.MissingRepository;
            views[index] = .{
                .input = repository,
                .base_uri = try repository_acquisition.Uri.parse(normalized_repository.uri),
                .release_sha256 = state.release_digest.bytes,
                .index_sha256 = state.index_digest.bytes,
                .signer_fingerprint = state.signer_fingerprint,
            };
        }

        var result = try package_cache_workflow.prepareWithWriterLockAfterCleanup(allocator, .{
            .lock = &lock.lock,
            .cache = &package_cache,
            .repositories = views,
            .architecture = request.architecture,
            .debz_version = debz_version,
            .cache_root = request.cache_root,
            .policy = request.policy(),
            .proxy = try proxyPolicy(request.proxy),
            .credentials = credentials,
            .acquisition = acquisition.dependencies(),
        }, &package_writer, initial_cleanup);
        errdefer result.deinit();
        if (request.archive_output_path) |path| {
            const parent = std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath;
            const leaf = std.fs.path.basename(path);
            var output_dir = try openAbsoluteDirectory(self.io, parent);
            defer output_dir.close(self.io);
            var output = try output_dir.createFile(self.io, leaf, .{
                .exclusive = true,
                .permissions = if (@import("builtin").os.tag == .windows)
                    .default_file
                else
                    .fromMode(0o600),
                .resolve_beneath = true,
            });
            errdefer output_dir.deleteFile(self.io, leaf) catch {};
            defer output.close(self.io);
            _ = try package_cache_archive.exportFile(
                allocator,
                self.io,
                output,
                &package_cache,
                lock.lock,
                .{
                    .maximum_objects = request.limits.maximum_lock_packages,
                    .maximum_object_bytes = request.limits.maximum_package_bytes,
                    .maximum_total_object_bytes = request.limits.maximum_total_package_bytes,
                },
                &package_writer,
            );
        }
        return result;
    }

    fn route(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !api.Result {
        if (usesPackageTransaction(request.operation)) {
            _ = self.selectedExecutor() catch return api.failure(
                request.operation,
                .unavailable,
                .transaction_backend_unavailable,
                "selected transaction backend is unavailable",
            );
        }
        if ((request.options.lock_input_path != null or request.options.lock_output_path != null) and
            switch (request.operation) {
                .install, .remove, .upgrade, .upgrade_all, .reinstall, .download, .plan, .recover => false,
                else => true,
            })
            return api.failure(request.operation, .usage, .invalid_request, "exact-lock options are not valid for this command");
        return switch (request.operation) {
            .list_installed => self.listInstalled(allocator, request),
            .why => self.why(allocator, request),
            .clean => self.clean(allocator, request),
            else => self.withRepositories(allocator, request, null),
        };
    }

    fn selectedExecutor(self: *const Backend) transaction_engine.SelectionError!Executor {
        return transaction_engine.select(
            self.transaction_backend,
            self.executor,
            self.native_executor,
        );
    }

    fn listInstalled(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !api.Result {
        var installed = try self.loadInstalled(allocator, request);
        defer installed.deinit();
        var items: std.ArrayList(api.Item) = .empty;
        for (installed.database.packages) |package| {
            if (!package.status.isFullyInstalled()) continue;
            try items.append(allocator, .{
                .package = try allocator.dupe(u8, package.name.value),
                .version = try allocator.dupe(u8, package.version.spelling.value),
                .architecture = try allocator.dupe(u8, package.architecture.value),
                .detail = if (package.status.want == .hold) "held" else "installed",
            });
        }
        sortItems(items.items);
        return success(request.operation, false, "installed package state loaded", try items.toOwnedSlice(allocator));
    }

    fn why(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !api.Result {
        var installed = try self.loadInstalled(allocator, request);
        defer installed.deinit();
        var items: std.ArrayList(api.Item) = .empty;
        for (request.packages) |name| {
            var found = false;
            for (installed.database.packages) |package| {
                if (std.mem.eql(u8, package.name.value, selectorName(name)) and package.status.isFullyInstalled()) {
                    found = true;
                    try items.append(allocator, .{
                        .package = try allocator.dupe(u8, package.name.value),
                        .version = try allocator.dupe(u8, package.version.spelling.value),
                        .architecture = try allocator.dupe(u8, package.architecture.value),
                        .detail = if (package.status.want == .hold) "explicit dpkg hold" else "present in explicit installed state",
                    });
                }
            }
            if (!found) try items.append(allocator, .{
                .package = try allocator.dupe(u8, name),
                .detail = "not installed",
            });
        }
        sortItems(items.items);
        return success(request.operation, false, "installed-state reasons evaluated", try items.toOwnedSlice(allocator));
    }

    fn clean(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !api.Result {
        var cache_root = try openOrCreateAbsoluteDirectory(self.io, request.options.cache_path);
        defer cache_root.close(self.io);
        var cache = try package_acquisition.Cache.initFromDir(self.io, cache_root, .{
            .maximum_object_bytes = 1024 * 1024 * 1024,
        });
        defer cache.deinit();
        const staging = try cache.cleanupStaging(allocator, 100_000, .fail_fast);
        const gc = try cache.garbageCollect(allocator, .{
            .maximum_directory_entries = 100_000,
            .maximum_objects_scanned = 100_000,
            .maximum_objects_deleted = 100_000,
            .maximum_bytes_deleted = std.math.maxInt(u64),
        });
        var metadata = try metadata_cache.Cache.initFromDir(self.io, cache_root, .{});
        defer metadata.deinit();
        const metadata_gc = try metadata.garbageCollect(allocator, .{
            .max_objects_scanned = 100_000,
            .max_objects_deleted = 100_000,
        });
        const detail = try std.fmt.allocPrint(
            allocator,
            "staging_deleted={d}, packages_deleted={d}, bytes_deleted={d}, metadata_deleted={d}",
            .{ staging.deleted, gc.deleted, gc.bytes_deleted, metadata_gc.deleted },
        );
        const items = try allocator.alloc(api.Item, 1);
        items[0] = .{ .package = "cache", .detail = detail };
        return success(
            request.operation,
            staging.deleted != 0 or gc.deleted != 0 or metadata_gc.deleted != 0,
            "cache cleaned",
            items,
        );
    }

    fn withRepositories(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: api.Request,
        workflow: ?WorkflowDirective,
    ) !api.Result {
        if (request.options.source_paths.len == 0 and request.options.config_paths.len == 0)
            return api.failure(request.operation, .usage, .configuration_required, "repository command requires --source or --config");
        if (request.options.keyring_paths.len == 0)
            return api.failure(request.operation, .usage, .configuration_required, "authenticated repository command requires --keyring");

        // Rank 0 of the total lock order. Every root mutation this backend can
        // reach — acquisition staging, the transaction journal, and the
        // executor's own target locks — happens inside this attempt, so a
        // repository bootstrap or a second package transaction cannot overlap
        // it. The selected transaction backend was already proven available in
        // `route`, so an unavailable native selection still fails before any
        // root access.
        var guard: RootOperationGuard = .{ .backend = self, .allocator = allocator };
        defer guard.deinit();
        guard.preserve_settled = if (workflow) |directive|
            directive.mode == .recover and directive.defer_recovery_clear
        else
            false;
        guard.orchestration_id = if (workflow) |directive|
            directive.orchestration_id
        else
            null;
        guard.recovery_review_claim = if (workflow) |directive|
            directive.recovery_review_claim
        else
            null;
        guard.expected_ownership_marker = if (workflow) |directive|
            directive.expected_ownership_marker
        else
            null;
        if (guard.preserve_settled and
            guard.orchestration_id == null)
            return api.failure(
                request.operation,
                .internal,
                .internal_error,
                "deferred recovery requires an acknowledgment identity",
            );
        if (workflowRootOperation(request.operation, workflow)) |operation| {
            if (guard.open(allocator, request, operation)) |failure| return failure;
        }
        if (workflowMode(request.operation, workflow) == .reserve) {
            guard.preserve_pre_mutation = true;
            return success(
                request.operation,
                false,
                "root operation ownership reserved",
                &.{},
            );
        }

        // A completed attempt that still owes provenance is resolved before any
        // repository, network, journal, or executor work. Its transaction is
        // over — the mutation was durably witnessed and the record says so —
        // so the only thing left to do is publish the provenance the crash
        // interrupted. Running the command-oriented executor first would ask
        // the legacy journal about a transaction it already archived and
        // answer with a failure that can never discharge the obligation.
        if (workflowMode(request.operation, workflow) == .recover) {
            if (try self.dischargeOwedProvenance(
                allocator,
                &guard,
                request,
                if (workflow) |directive|
                    directive.defer_recovery_clear
                else
                    false,
                if (workflow) |directive|
                    directive.orchestration_id
                else
                    null,
            )) |result|
                return result;
        }

        const repository_options: RepositoryOptions = .{
            .source_paths = request.options.source_paths,
            .config_paths = request.options.config_paths,
            .keyring_paths = request.options.keyring_paths,
            .default_release = request.options.default_release,
            .proxy = request.options.proxy,
            .credential_reference = request.options.credential_reference,
            .deadline_ms = request.options.deadline_ms,
            .offline = request.options.offline,
        };
        var loaded = try self.loadRepositoryDocuments(allocator, repository_options);
        defer loaded.deinit();
        const normalized = try repository_policy.normalize(
            allocator,
            loaded.documents,
            request.options.architecture,
            .{},
        );
        var configuration = switch (normalized) {
            .diagnostic => |diagnostic| return api.failure(
                request.operation,
                .usage,
                .configuration_required,
                diagnostic.message(),
            ),
            .configuration => |value| value,
        };
        defer configuration.deinit();
        for (configuration.repositories) |repository| {
            if (repository.signed_by.len == 0)
                return api.failure(request.operation, .usage, .configuration_required, "every repository source must declare Signed-By");
            for (repository.signed_by) |path| if (!containsString(request.options.keyring_paths, path))
                return api.failure(request.operation, .usage, .configuration_required, "Signed-By path was not declared with --keyring");
        }

        var cache_root = try openOrCreateAbsoluteDirectory(self.io, request.options.cache_path);
        defer cache_root.close(self.io);
        var metadata = try metadata_cache.Cache.initFromDir(self.io, cache_root, .{});
        defer metadata.deinit();
        var acquisition = repository_acquisition.Production{ .io = self.io };
        const credential_bytes: ?[]u8 = if (request.options.credential_reference) |path|
            try readCredential(allocator, self.io, path)
        else
            null;
        defer if (credential_bytes) |value| allocator.free(value);
        var credential_context = if (credential_bytes != null)
            try CredentialContext.init(allocator, configuration.repositories, credential_bytes.?)
        else
            CredentialContext.empty();
        defer credential_context.deinit(allocator);
        const credentials: repository_acquisition.CredentialsProvider = if (credential_bytes != null)
            .{ .context = &credential_context, .getFn = CredentialContext.get }
        else
            .none;
        var now = self.now_unix orelse realNow(self.io);
        const runtimes = try makeRuntimes(allocator, repository_options, &configuration, now, credentials);
        defer freeRuntimes(allocator, runtimes);
        var refresh_outcome = try repository_policy.refreshAll(allocator, .{
            .configuration = &configuration,
            .runtimes = runtimes,
            .mode = if (workflowMode(request.operation, workflow) == .recover or request.options.offline or request.options.cache_only)
                .cache_only
            else
                .online,
            .dependencies = .{
                .acquisition = acquisition.dependencies(),
                .cache = &metadata,
                .clock = .{ .context = &now, .nowUnixFn = fixedNow },
                .io = self.io,
            },
        });
        defer refresh_outcome.deinit(allocator);
        const refreshed = switch (refresh_outcome) {
            .failed => |diagnostics| {
                const message = if (diagnostics.len == 0) "repository refresh failed" else diagnostics[0].error_name;
                return api.failure(
                    request.operation,
                    if (request.options.offline) .download else .authentication,
                    if (request.options.offline) .offline_cache_miss else .repository_authentication_failed,
                    message,
                );
            },
            .published => |*value| value,
        };

        if (request.operation == .refresh) {
            var items = try allocator.alloc(api.Item, refreshed.states.len);
            for (refreshed.states, 0..) |state, index| items[index] = .{
                .package = try allocator.dupe(u8, state.repository_id.slice()),
                .version = try allocator.dupe(u8, state.release_suite),
                .architecture = null,
                .detail = if (state.stale) "authenticated stale cache" else "authenticated",
            };
            return success(.refresh, true, "authenticated repository metadata refreshed", items);
        }
        if (request.operation == .list_available or request.operation == .info or request.operation == .provides)
            return queryAvailable(allocator, request, refreshed);

        var installed = try self.loadInstalled(allocator, request);
        defer installed.deinit();
        const planning_records = if (workflowMode(request.operation, workflow) == .recover)
            try healthyInstalledRecords(allocator, installed.database.packages)
        else
            installed.database.packages;
        defer if (workflowMode(request.operation, workflow) == .recover) allocator.free(planning_records);
        const policies = try installedPolicies(allocator, planning_records);
        defer allocator.free(policies);
        var recovery_intent: ?std.json.Parsed(RecoveryIntent) = if (workflowMode(request.operation, workflow) == .recover)
            try readRecoveryIntent(allocator, self.io, request.options.state_path)
        else
            null;
        defer if (recovery_intent) |*value| value.deinit();
        var effective_request = request;
        if (recovery_intent) |*intent| {
            if (workflow) |directive| {
                if (intent.value.operation != workflowSemanticSurface(directive.operation) or
                    !stringSlicesEqual(intent.value.packages, request.packages))
                    return api.failure(request.operation, .recovery, .recovery_failed, "recovery intent does not match the requested semantic operation and selectors");
            }
            effective_request.operation = intent.value.operation;
            effective_request.packages = intent.value.packages;
            effective_request.options.recommends = intent.value.recommends;
            effective_request.options.allow_downgrade = intent.value.allow_downgrade;
            effective_request.options.repository_policy = intent.value.repository_policy;
            effective_request.options.conffile = intent.value.conffile;
            effective_request.options.force = intent.value.force;
            effective_request.options.lock_wait_ms = intent.value.lock_wait_ms;
        }
        const mode = workflowMode(request.operation, workflow);
        if (request.options.lock_output_path != null and request.options.lock_input_path == null and
            mode != .plan_only and mode != .download_only)
            return api.failure(request.operation, .usage, .configuration_required, "--lock-output without --lock-input is restricted to non-mutating plan or download lock resolution");
        var lock: ?exact_lock.OwnedLock = if (request.options.lock_input_path) |path|
            readLock(allocator, self.io, path) catch
                return api.failure(request.operation, .planning, .planning_failed, "exact lock is invalid")
        else
            null;
        defer if (lock) |*value| value.deinit();
        const selectors = try allocator.alloc(solver.PackageSelector, effective_request.packages.len);
        defer allocator.free(selectors);
        for (effective_request.packages, 0..) |value, index| selectors[index] = parseSelector(value);
        const semantic_request_digest = try semanticRequestDigest(
            allocator,
            effective_request.operation,
            workflow,
            selectors,
        );
        const solver_policy_digest = package_cache_workflow.solverPolicyDigest(
            effective_request.options.recommends,
            effective_request.options.allow_downgrade,
            switch (effective_request.options.repository_policy) {
                .strict_priority => .strict_priority,
                .best_version => .best_version,
            },
        );
        if (lock) |*value| {
            if (!std.mem.eql(u8, &semantic_request_digest, &value.lock.request_sha256))
                return api.failure(request.operation, .planning, .lock_verification_failed, "exact lock semantic request does not match the requested operation and selectors");
            if (!std.mem.eql(u8, &solver_policy_digest, &value.lock.policy_sha256))
                return api.failure(request.operation, .planning, .lock_verification_failed, "exact lock solver policy does not match the effective request policy");
        }
        var planning = try solver.planTransaction(allocator, .{
            .repositories = refreshed.universe.repositories,
            .installed = .{
                .records = planning_records,
                .native_architecture = request.options.architecture,
                .policies = policies,
                .hold_authority = .explicit_policy,
            },
            .target_architecture = request.options.architecture,
            .mode = if (mode == .download_only) .download_only else .plan_only,
            .request = try planRequestFromWorkflow(effective_request.operation, workflow, selectors),
            .policy = .{
                .recommends = effective_request.options.recommends,
                .allow_downgrade = effective_request.options.allow_downgrade,
                .strict_repository_priority = effective_request.options.repository_policy == .strict_priority,
            },
            .exact_lock = if (lock) |*value| &value.lock else null,
        });
        defer switch (planning) {
            .plan => |*value| value.deinit(),
            .failure => |*value| value.deinit(),
        };
        const plan = switch (planning) {
            .failure => |failure| {
                const message = if (failure.problems.len == 0)
                    "planning failed"
                else
                    try allocator.dupe(u8, failure.problems[0].detail);
                return api.failure(request.operation, .planning, .planning_failed, message);
            },
            .plan => |*value| value,
        };
        var generated_lock: ?exact_lock.OwnedLock = null;
        defer if (generated_lock) |*value| value.deinit();
        if (request.options.lock_output_path) |path| {
            if (lock) |*value| {
                try writeLock(allocator, self.io, path, value.lock);
            } else {
                generated_lock = lockFromPlan(
                    allocator,
                    effective_request,
                    refreshed,
                    planning_records,
                    plan.*,
                    semantic_request_digest,
                    solver_policy_digest,
                ) catch |err|
                    switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return api.failure(
                            request.operation,
                            .planning,
                            .planning_failed,
                            try std.fmt.allocPrint(allocator, "authenticated plan could not produce a complete exact lock: {s}", .{@errorName(err)}),
                        ),
                    };
                try writeLock(allocator, self.io, path, generated_lock.?.lock);
            }
        }
        if (mode == .plan_only) return planResult(allocator, request.operation, plan.*);

        // The reviewed plan and the exact lock it was resolved against are the
        // preflight evidence for this attempt. Binding them before acquisition
        // means a resumed attempt can prove which plan it was reserved for.
        if (try guard.preflight(allocator, request.operation, .{
            .plan_sha256 = transaction_executor.planDigest(plan.*),
            .exact_lock = if (lock) |*value| .{
                .schema = exact_lock.schema_id,
                .version = exact_lock.schema_version,
                .digest_sha256 = value.lock.digest_sha256,
            } else null,
        })) |failure| return failure;

        var package_cache = try package_acquisition.Cache.initFromDir(self.io, cache_root, .{
            .maximum_object_bytes = 1024 * 1024 * 1024,
        });
        defer package_cache.deinit();
        var artifacts: std.ArrayList(transaction_executor.Artifact) = .empty;
        defer {
            for (artifacts.items) |artifact| allocator.free(artifact.path);
            artifacts.deinit(allocator);
        }
        var verified: std.ArrayList(package_acquisition.VerifiedPackage) = .empty;
        defer {
            for (verified.items) |*package| package.deinit();
            verified.deinit(allocator);
        }
        for (plan.actions) |action| {
            const origin = try authenticatedPackageOrigin(action.selected_origin_v2 orelse continue);
            const repository_input = findRepositoryInput(refreshed.universe.repositories, origin.repository_id) orelse
                return error.MissingRepository;
            const normalized_repository = findNormalized(configuration.repositories, origin.repository_id) orelse
                return error.MissingRepository;
            const selected = try package_acquisition.SelectedPackage.fromSolverSelection(
                repository_input,
                origin,
                try repository_acquisition.Uri.parse(normalized_repository.uri),
            );
            var package = package_acquisition.acquirePackage(
                allocator,
                &package_cache,
                .{
                    .selected = selected,
                    .policy = .{
                        .mode = if (request.options.offline or request.options.cache_only) .cache_only else .online,
                        .workflow = if (mode == .download_only) .download_only else .transaction,
                        .maximum_package_bytes = 1024 * 1024 * 1024,
                        .deadlines = deadlines(request.options.deadline_ms),
                        .redirect_limit = 8,
                        .retry = productionRetryPolicy(),
                        .proxy = try proxyPolicy(request.options.proxy),
                        .credentials = credentials,
                    },
                    .exact_lock_package = if (lock) |*value|
                        value.lock.findPackage(action.package, action.version, action.architecture)
                    else
                        null,
                },
                acquisition.dependencies(),
            ) catch |err| return api.failure(
                request.operation,
                .download,
                .download_failed,
                try std.fmt.allocPrint(
                    allocator,
                    "package acquisition failed for {s}={s}:{s}: {s}",
                    .{ action.package, action.version, action.architecture, @errorName(err) },
                ),
            );
            var validation_result = deb_payload.validate(allocator, package.bytes, .{
                .repository = origin.repository_id.slice(),
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
            switch (validation_result) {
                .diagnostic => |diagnostic| {
                    const message = try std.fmt.allocPrint(
                        allocator,
                        "payload validation failed for {s}={s}:{s}: stage={s} code={s} decompression={s}: {s}",
                        .{
                            action.package,
                            action.version,
                            action.architecture,
                            @tagName(diagnostic.stage),
                            @tagName(diagnostic.code),
                            if (diagnostic.decompression_error) |err| @errorName(err) else "none",
                            diagnostic.message(),
                        },
                    );
                    package.deinit();
                    return api.failure(
                        request.operation,
                        .download,
                        .download_failed,
                        message,
                    );
                },
                .validation => |*validation| validation.deinit(),
            }
            const path = try std.fmt.allocPrint(
                allocator,
                "{s}/packages-v1/objects/{s}",
                .{ request.options.cache_path, &package.provenance.cache_key },
            );
            try artifacts.append(allocator, .{
                .package = action.package,
                .version = action.version,
                .architecture = action.architecture,
                .path = path,
            });
            try verified.append(allocator, package);
        }
        if (mode == .download_only)
            return planResultChanged(allocator, request.operation, plan.*, false, "packages downloaded and verified");

        const executor_policy = try executionPolicy(allocator, effective_request);
        var system_process = transaction_executor.SystemProcessRunner{ .allocator = allocator, .io = self.io };
        defer system_process.deinit();
        var system_files = transaction_executor.SystemFileSystem{ .allocator = allocator, .io = self.io };
        var system_locks = transaction_executor.SystemLockManager{ .allocator = allocator, .io = self.io };
        var journal = try transaction_recovery.SystemJournalStore.init(
            self.io,
            request.options.state_path,
            request.options.install_root,
        );
        defer journal.deinit();
        var status_reader = transaction_recovery.SystemStatusFileReader{
            .io = self.io,
            .expected_root = request.options.install_root,
        };
        const dependencies: transaction_executor.Dependencies = .{
            .filesystem = system_files.interface(),
            .locks = system_locks.interface(),
            .process = self.process_runner orelse system_process.interface(),
            .journal = journal.interface(),
            .status = status_reader.interface(),
        };
        if (mode == .recover) {
            const executor = self.selectedExecutor() catch unreachable;
            // The journal is command-oriented, so the bridge stays pending
            // until the executor reports which commands it replayed.
            if (try guard.enterExecutor(allocator, request.operation)) |failure| return failure;
            var report = try executor.recover(allocator, .{
                .plan = plan,
                .install_root = request.options.install_root,
                .policy = executor_policy,
                .exact_lock = if (lock) |*value| &value.lock else null,
            }, dependencies);
            defer report.deinit();
            if (!report.succeeded()) {
                if (try guard.observe(
                    allocator,
                    request.operation,
                    root_operation.recoveryReportWitness(report),
                    .failed,
                )) |failure| return failure;
                return api.failure(request.operation, .recovery, .recovery_failed, if (report.failure) |failure|
                    try describeExecutorFailure(allocator, "recovery", failure)
                else
                    "recovery failed");
            }
            if (try guard.observe(
                allocator,
                request.operation,
                root_operation.recoveryReportWitness(report),
                .recovered,
            )) |failure| return failure;
            if (try self.dischargeOwedProvenance(
                allocator,
                &guard,
                request,
                if (workflow) |directive|
                    directive.defer_recovery_clear
                else
                    false,
                if (workflow) |directive|
                    directive.orchestration_id
                else
                    null,
            )) |result| return result;
            return blockedRecovery(
                request.operation,
                "recovered transaction did not publish required root-operation completion provenance",
            );
        }
        try writeRecoveryIntent(allocator, self.io, request.options.state_path, effective_request);
        const executor = self.selectedExecutor() catch unreachable;
        // Handing control to the command-oriented executor is the point after
        // which this backend can no longer prove that nothing was mutated. The
        // record is durably marked pending here and resolved from the
        // executor's own command evidence below.
        if (try guard.enterExecutor(allocator, request.operation)) |failure| return failure;
        var report = try executor.execute(allocator, .{
            .plan = plan,
            .install_root = request.options.install_root,
            .artifacts = artifacts.items,
            .policy = executor_policy,
            .exact_lock = if (lock) |*value| &value.lock else null,
        }, dependencies);
        defer report.deinit();
        if (!report.succeeded()) {
            if (try guard.observe(
                allocator,
                request.operation,
                root_operation.reportWitness(report),
                .failed,
            )) |failure| return failure;
            return api.failure(request.operation, .transaction, .transaction_failed, if (report.failure) |failure|
                try describeExecutorFailure(allocator, "transaction", failure)
            else
                "transaction failed");
        }
        if (try guard.observe(
            allocator,
            request.operation,
            root_operation.reportWitness(report),
            .succeeded,
        )) |failure| return failure;
        try guard.crash(.after_completed_record);
        try deleteRecoveryIntent(self.io, request.options.state_path);
        try guard.crash(.after_recovery_intent_deleted);
        if (lock) |*value| {
            var verify: transaction_provenance.VerifyDiagnostic = .{};
            writeExecutionProvenance(
                allocator,
                self.io,
                request,
                refreshed,
                value.lock,
                report,
                dependencies.status,
                &verify,
            ) catch |err| switch (err) {
                error.RepositoryEvidenceMismatch,
                error.MissingPackageEvidence,
                error.PackageDigestMismatch,
                => return api.failure(
                    request.operation,
                    .internal,
                    .lock_verification_failed,
                    try std.fmt.allocPrint(
                        allocator,
                        "exact-lock evidence rejected during {s}: {s}",
                        .{ @tagName(request.operation), verify.message() },
                    ),
                ),
                else => return err,
            };
        }
        try guard.crash(.after_transaction_provenance);
        if (try guard.finish(allocator, request.operation)) |failure| return failure;
        return planResultChanged(allocator, request.operation, plan.*, true, "transaction completed");
    }

    /// Discharges the provenance a completed product attempt still owes.
    ///
    /// A transaction that crashed between publishing its terminal `completed`
    /// boundary and publishing its provenance leaves a record that refuses
    /// every later mutation of the root. That transaction is over: its
    /// mutation was durably witnessed under the root mutation lock, its
    /// journal was archived by the executor that finished it, and re-running
    /// `dpkg` would be a second mutation rather than a recovery. The legacy
    /// journal can no longer answer for it either — a rerun asks about a plan
    /// the archived journal was not written for — so the obligation would
    /// never be discharged and the root would stay blocked forever.
    ///
    /// So the obligation is discharged directly and honestly: whatever
    /// detailed transaction provenance survived is verified against the
    /// record, a versioned root-operation completion statement that says
    /// exactly what was witnessed and what the crash interrupted is published
    /// inside the root, the record is transitioned to `published` bound to
    /// that statement. Ordinary product recovery then clears the active
    /// intent. The internal apt/system workflow may defer that clear until its
    /// outer state durably retains and acknowledges the exact completion
    /// token. Nothing about the interrupted transaction's commands, scripts,
    /// or packages is invented, and any mismatch, corruption, or I/O failure
    /// leaves the record exactly as it was with an actionable diagnostic.
    ///
    /// `null` means nothing is owed, so the ordinary recovery path continues.
    fn dischargeOwedProvenance(
        self: *Backend,
        allocator: std.mem.Allocator,
        guard: *RootOperationGuard,
        request: api.Request,
        defer_clear: bool,
        acknowledgment_id: ?[32]u8,
    ) !?api.Result {
        var attempt = guard.active() orelse return null;
        const record = attempt.record();
        if (defer_clear and record.state == .completed and
            record.provenance == .published)
        {
            var completion = (root_operation_completion.Store.init(
                guard.owned_root.?.root,
            ).read(allocator) catch return blockedRecovery(
                request.operation,
                "settled lower recovery completion evidence is unreadable",
            )) orelse return blockedRecovery(
                request.operation,
                "settled lower recovery completion evidence is missing",
            );
            defer completion.deinit();
            if (!recoveryCompletionMatchesRecord(
                completion.document,
                record,
                request,
            )) return blockedRecovery(
                request.operation,
                "settled lower recovery completion evidence is stale or foreign",
            );
            const marker = root_operation.Store.init(
                guard.owned_root.?.root,
            ).readDeferredAcknowledgment(allocator) catch
                return blockedRecovery(
                    request.operation,
                    "deferred lower recovery marker is unreadable",
                );
            if (marker == null or acknowledgment_id == null or
                !deferredMarkerMatches(
                    marker.?,
                    record,
                    completion.document,
                    acknowledgment_id.?,
                ))
                return blockedRecovery(
                    request.operation,
                    "deferred lower recovery marker is missing, stale, or foreign",
                );
            guard.preserve_settled = true;
            const items = try allocator.alloc(api.Item, 1);
            items[0] = .{
                .package = "root-operation",
                .detail = try std.fmt.allocPrint(
                    allocator,
                    "outcome={s} transaction_provenance={s} statement_sha256={s}",
                    .{
                        @tagName(completion.document.outcome),
                        @tagName(
                            completion.document.transaction_provenance.status,
                        ),
                        &std.fmt.bytesToHex(
                            completion.document.digest_sha256,
                            .lower,
                        ),
                    },
                ),
            };
            try guard.crash(.before_deferred_recovery_return);
            return success(
                request.operation,
                false,
                "settled lower recovery completion awaits outer acknowledgment",
                items,
            );
        }
        if (record.state != .completed or record.provenance != .pending) return null;

        // Only the surface and backend that published the record may finish
        // it. A package transaction can never speak for a repository
        // bootstrap's evidence, and a record written for another transaction
        // backend is not this backend's to discharge.
        switch (record.operation) {
            .package_transaction => {},
            .repository_bootstrap => return blockedRecovery(
                request.operation,
                "an interrupted repository bootstrap owes provenance for this root; rerun the same 'debz repo add' request to finish it",
            ),
        }
        if (record.backend != self.transaction_backend) return blockedRecovery(
            request.operation,
            "the interrupted root attempt was executed by a different transaction backend",
        );
        const orchestration_binding =
            if (defer_clear)
                root_operation.Store.init(
                    guard.owned_root.?.root,
                ).readDeferredAcknowledgment(allocator) catch |err|
                    switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.ContractViolation => return error.ContractViolation,
                        error.InvariantViolation => return error.InvariantViolation,
                        else => return blockedRecovery(
                            request.operation,
                            "lower orchestration binding is unreadable",
                        ),
                    }
            else
                null;
        if (defer_clear and
            (orchestration_binding == null or acknowledgment_id == null or
                (orchestration_binding.?.state != .bound and
                    orchestration_binding.?.state != .pending) or
                !std.mem.eql(
                    u8,
                    &orchestration_binding.?.attempt_id,
                    &record.attempt_id,
                ) or
                !std.mem.eql(
                    u8,
                    &orchestration_binding.?.acknowledgment_id,
                    &acknowledgment_id.?,
                )))
            return blockedRecovery(
                request.operation,
                "lower orchestration binding is missing, stale, or foreign",
            );

        const evidence = try self.collectOwedEvidence(allocator, request, record);
        if (evidence.blocked) |message| return blockedRecovery(request.operation, message);

        var statement = root_operation_completion.create(allocator, .{
            .record = record,
            .transaction_provenance = evidence.transaction,
            .journal = evidence.journal,
            .discharge = .{
                .surface = .package_transaction,
                .operation = @tagName(request.operation),
                .request_sha256 = productRequestDigest(request),
            },
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return blockedRecovery(request.operation, try std.fmt.allocPrint(
                allocator,
                "the interrupted root attempt cannot be described honestly: {s}",
                .{@errorName(err)},
            )),
        };
        defer statement.deinit();

        const store: root_operation_completion.Store = .init(guard.owned_root.?.root);
        store.publish(allocator, statement.document) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ContractViolation => return error.ContractViolation,
            error.InvariantViolation => return error.InvariantViolation,
            else => return blockedRecovery(
                request.operation,
                try std.fmt.allocPrint(
                    allocator,
                    "root-operation completion provenance could not be published at {s}/{s}: {s}",
                    .{
                        request.options.install_root,
                        root_operation_completion.document_path,
                        @errorName(err),
                    },
                ),
            ),
        };
        try guard.crash(.after_owed_provenance_document);

        // Provenance before clearing, exactly as an uninterrupted completion
        // does it: the digest binds the attempt to the statement just
        // published, so the cleared intent always leaves a verifiable link.
        const provenance_sha256 = root_operation.provenanceDigest(record, .{
            .outcome = record.outcome,
            .document_sha256 = statement.document.digest_sha256,
            .journal_archived = evidence.journal.status == .archived,
        });
        if (defer_clear) {
            const marker_base =
                try root_operation.createDeferredAcknowledgment(.{
                    .state = .pending,
                    .attempt_id = record.attempt_id,
                    .completion_sha256 = statement.document.digest_sha256,
                    .provenance_sha256 = provenance_sha256,
                    .acknowledgment_id = orchestration_binding.?.acknowledgment_id,
                });
            const marker = if (orchestration_binding.?
                .recovery_review_claim_sha256 != null)
                try root_operation.carryDeferredAcknowledgmentReviewOwner(
                    marker_base,
                    orchestration_binding.?,
                )
            else
                marker_base;
            root_operation.Store.init(
                guard.owned_root.?.root,
            ).publishDeferredAcknowledgment(
                allocator,
                marker,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.ContractViolation => return error.ContractViolation,
                error.InvariantViolation => return error.InvariantViolation,
                else => return blockedRecovery(
                    request.operation,
                    "deferred lower recovery marker could not be published",
                ),
            };
        }
        attempt.publishProvenance(
            allocator,
            provenance_sha256,
        ) catch |err| return mapRootOperationError(request.operation, err);
        try guard.crash(.after_provenance_published);
        if (defer_clear) {
            guard.preserve_settled = true;
        } else {
            attempt.clear() catch |err| return mapRootOperationError(request.operation, err);
        }

        // Removing the recovery intent is the last step the crashed run never
        // reached, and the transaction it described is now definitively over.
        // A state directory that refuses the removal must not re-block a root
        // whose obligation is already discharged, so the result reports what
        // happened instead of failing a completed recovery.
        const intent_removed = if (deleteRecoveryIntent(self.io, request.options.state_path))
            true
        else |_|
            false;

        const items = try allocator.alloc(api.Item, 1);
        items[0] = .{
            .package = "root-operation",
            .detail = try std.fmt.allocPrint(
                allocator,
                "outcome={s} transaction_provenance={s} journal={s} recovery_intent={s} statement_sha256={s}",
                .{
                    @tagName(statement.document.outcome),
                    @tagName(statement.document.transaction_provenance.status),
                    @tagName(statement.document.journal.status),
                    if (intent_removed) "removed" else "retained",
                    &std.fmt.bytesToHex(statement.document.digest_sha256, .lower),
                },
            ),
        };
        const result = success(
            request.operation,
            true,
            switch (evidence.transaction.status) {
                .already_present, .recovered => "interrupted transaction completion recovered; published transaction provenance verified",
                .unavailable => "interrupted transaction completion recovered; detailed transaction provenance was interrupted",
            },
            items,
        );
        if (defer_clear) try guard.crash(.before_deferred_recovery_return);
        return result;
    }

    /// Clears a deferred completed/published lower record only after the
    /// orchestrator has durably retained the exact completion token.
    fn acknowledgeWorkflowRecovery(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: api.Request,
        semantic_operation: WorkflowSemanticOperation,
        acknowledgment: WorkflowRecoveryAcknowledgment,
        recovery_review_claim: ?root_operation.RecoveryReviewClaim,
    ) !api.Result {
        var owned_root = root_fs.openAbsoluteRoot(
            self.io,
            request.options.install_root,
        ) catch return blockedRecovery(
            request.operation,
            "the live root is unavailable while acknowledging recovery",
        );
        defer owned_root.close();
        var locks: root_operation.SystemLockBackend = .{
            .allocator = allocator,
            .io = self.io,
        };
        const lock_backend = locks.interface();
        const coordinator = root_operation.Coordinator.open(
            self.io,
            owned_root.root,
            request.options.install_root,
            lock_backend,
        ) catch |err| return mapRootOperationError(request.operation, err);
        const token = lock_backend.acquire(.{
            .rank = .root_operation,
            .root = owned_root.root,
            .identity = coordinator.identity,
            .path = root_operation.lock_path,
            .wait_ms = request.options.lock_wait_ms,
            .cancellation = transaction_executor.Cancellation.never(),
        }) catch |err| return mapRootOperationError(request.operation, err);
        defer lock_backend.release(token);
        const store = coordinator.store();
        var marker = store.readDeferredAcknowledgment(allocator) catch |err|
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.ContractViolation => return error.ContractViolation,
                error.InvariantViolation => return error.InvariantViolation,
                else => return blockedRecovery(
                    request.operation,
                    "deferred lower recovery marker is unreadable",
                ),
            };
        var record = store.read(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ContractViolation => return error.ContractViolation,
            error.InvariantViolation => return error.InvariantViolation,
            else => return blockedRecovery(
                request.operation,
                "deferred lower recovery record is unreadable",
            ),
        };
        defer if (record) |*owned| owned.deinit();
        if (marker == null) {
            if (record != null) return blockedRecovery(
                request.operation,
                "deferred lower recovery marker is missing for an active record",
            );
            if (recovery_review_claim) |claim| {
                const review = store.readRecoveryReviewClaim(
                    allocator,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.ContractViolation => return error.ContractViolation,
                    error.InvariantViolation => return error.InvariantViolation,
                    else => return blockedRecovery(
                        request.operation,
                        "confirmed recovery review ownership is unreadable",
                    ),
                };
                if (review != null) {
                    const reconstructed =
                        root_operation.createDeferredAcknowledgment(.{
                            .state = .acknowledged,
                            .attempt_id = acknowledgment.attempt_id,
                            .completion_sha256 = acknowledgment.completion_sha256,
                            .provenance_sha256 = acknowledgment.provenance_sha256,
                            .acknowledgment_id = acknowledgment.acknowledgment_id,
                        }) catch return blockedRecovery(
                            request.operation,
                            "confirmed recovery review cannot reconstruct exact lower ownership",
                        );
                    store.exchangeRecoveryReviewClaimForOwnership(
                        allocator,
                        .{
                            .expected_claim = claim,
                            .expected_marker = null,
                            .expected_record_sha256 = null,
                            .replacement_marker = reconstructed,
                        },
                    ) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.ContractViolation => return error.ContractViolation,
                        error.InvariantViolation => return error.InvariantViolation,
                        else => return blockedRecovery(
                            request.operation,
                            "confirmed recovery review could not restore exact lower ownership",
                        ),
                    };
                    marker =
                        try root_operation.bindDeferredAcknowledgmentToRecoveryReview(
                            reconstructed,
                            claim,
                        );
                }
            }
            if (marker == null) return success(
                request.operation,
                false,
                "lower recovery acknowledgment was already finalized",
                &.{},
            );
        }
        var observed_marker = marker.?;
        if (observed_marker.state == .bound or
            observed_marker.completion_sha256 == null or
            observed_marker.provenance_sha256 == null or
            !std.mem.eql(
                u8,
                &observed_marker.attempt_id,
                &acknowledgment.attempt_id,
            ) or
            !std.mem.eql(
                u8,
                &observed_marker.completion_sha256.?,
                &acknowledgment.completion_sha256,
            ) or
            !std.mem.eql(
                u8,
                &observed_marker.provenance_sha256.?,
                &acknowledgment.provenance_sha256,
            ) or
            !std.mem.eql(
                u8,
                &observed_marker.acknowledgment_id,
                &acknowledgment.acknowledgment_id,
            ))
            return blockedRecovery(
                request.operation,
                "deferred lower recovery acknowledgment marker is stale or foreign",
            );
        const expected_operation: api.Operation =
            workflowSemanticSurface(semantic_operation);

        var completion = (root_operation_completion.Store.init(
            owned_root.root,
        ).read(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ContractViolation => return error.ContractViolation,
            error.InvariantViolation => return error.InvariantViolation,
            else => return blockedRecovery(
                request.operation,
                "deferred lower recovery completion evidence is unreadable",
            ),
        }) orelse return blockedRecovery(
            request.operation,
            "deferred lower recovery completion evidence is missing",
        );
        defer completion.deinit();
        const document = completion.document;
        if (!std.mem.eql(
            u8,
            &document.digest_sha256,
            &acknowledgment.completion_sha256,
        ) or !std.mem.eql(
            u8,
            &document.attempt_id,
            &acknowledgment.attempt_id,
        ))
            return blockedRecovery(
                request.operation,
                "deferred lower recovery acknowledgment token is stale or foreign",
            );
        if (observed_marker.state == .pending) {
            const active = if (record) |owned|
                owned.record
            else
                return blockedRecovery(
                    request.operation,
                    "pending deferred acknowledgment has no lower record",
                );
            if (active.operation != .package_transaction or
                active.operation.package_transaction != expected_operation or
                active.backend != self.transaction_backend or
                !recoveryCompletionMatchesRecord(document, active, request))
                return blockedRecovery(
                    request.operation,
                    "deferred lower recovery acknowledgment names a foreign operation",
                );
        }
        if (recovery_review_claim) |expected_review| {
            store.exchangeRecoveryReviewClaimForOwnership(
                allocator,
                .{
                    .expected_claim = expected_review,
                    .expected_marker = observed_marker,
                    .expected_record_sha256 = if (record) |owned|
                        owned.record.digest_sha256
                    else
                        null,
                    .replacement_marker = observed_marker,
                },
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.ContractViolation => return error.ContractViolation,
                error.InvariantViolation => return error.InvariantViolation,
                else => return blockedRecovery(
                    request.operation,
                    "confirmed recovery review could not be exchanged for the verified lower recovery owner",
                ),
            };
            observed_marker =
                try root_operation.bindDeferredAcknowledgmentToRecoveryReview(
                    observed_marker,
                    expected_review,
                );
        }
        var acknowledged_marker = observed_marker;
        if (observed_marker.state == .pending) {
            if (self.completion_crash) |crash|
                try crash.hit(.before_deferred_acknowledged);
            acknowledged_marker =
                store.acknowledgeDeferredAcknowledgment(
                    allocator,
                    observed_marker,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.ContractViolation => return error.ContractViolation,
                    error.InvariantViolation => return error.InvariantViolation,
                    else => return blockedRecovery(
                        request.operation,
                        "deferred lower recovery acknowledgment could not be committed",
                    ),
                };
            if (self.completion_crash) |crash|
                try crash.hit(.after_deferred_acknowledged);
        }
        store.cleanupOwned(allocator, .{
            .authorization = root_operation.authorizationFromTrustedMarker(
                acknowledged_marker,
            ),
            .terminal_state = .acknowledged,
            .observer = self.deferredCleanupObserver(),
        }) catch |err| {
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.ContractViolation => error.ContractViolation,
                error.InvariantViolation => error.InvariantViolation,
                error.InjectedCompletionCrash => error.InjectedCompletionCrash,
                else => blockedRecovery(
                    request.operation,
                    "deferred lower recovery ownership could not be cleared",
                ),
            };
        };
        if (record) |*owned| {
            owned.deinit();
            record = null;
        }
        _ = deleteRecoveryIntent(self.io, request.options.state_path) catch {};
        return success(
            request.operation,
            false,
            "lower recovery acknowledgment finalized",
            &.{},
        );
    }

    fn deferredCleanupObserver(
        self: *Backend,
    ) root_operation.OwnershipCleanupObserver {
        return .{ .context = self, .hitFn = observeDeferredCleanup };
    }

    fn observeDeferredCleanup(
        context: *anyopaque,
        point: root_operation.OwnershipCleanupPoint,
    ) !void {
        const self: *Backend = @ptrCast(@alignCast(context));
        const crash = self.completion_crash orelse return;
        try crash.hit(switch (point) {
            .before_terminal_publish => .before_deferred_acknowledged,
            .after_terminal_publish => .after_deferred_acknowledged,
            .before_record_clear => .before_deferred_record_cleared,
            .after_record_clear => .after_deferred_record_cleared,
            .before_binding_clear => .before_deferred_marker_cleared,
            .after_binding_clear => .after_deferred_marker_cleared,
        });
    }

    fn finalizeWorkflowOwnership(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: api.Request,
        workflow_operation: WorkflowSemanticOperation,
        acknowledgment: WorkflowOwnershipAcknowledgment,
        recovery_review_claim: ?root_operation.RecoveryReviewClaim,
    ) !api.Result {
        var owned_root = root_fs.openAbsoluteRoot(
            self.io,
            request.options.install_root,
        ) catch return blockedRecovery(
            request.operation,
            "the live root is unavailable while finalizing ownership",
        );
        defer owned_root.close();
        var locks: root_operation.SystemLockBackend = .{
            .allocator = allocator,
            .io = self.io,
        };
        const lock_backend = locks.interface();
        const coordinator = root_operation.Coordinator.open(
            self.io,
            owned_root.root,
            request.options.install_root,
            lock_backend,
        ) catch |err| return mapRootOperationError(request.operation, err);
        const token = lock_backend.acquire(.{
            .rank = .root_operation,
            .root = owned_root.root,
            .identity = coordinator.identity,
            .path = root_operation.lock_path,
            .wait_ms = request.options.lock_wait_ms,
            .cancellation = transaction_executor.Cancellation.never(),
        }) catch |err| return mapRootOperationError(request.operation, err);
        defer lock_backend.release(token);
        const store = coordinator.store();
        var marker = store.readDeferredAcknowledgment(allocator) catch
            return blockedRecovery(
                request.operation,
                "lower ownership marker is unreadable",
            );
        var record = store.read(allocator) catch return blockedRecovery(
            request.operation,
            "lower ownership record is unreadable",
        );
        defer if (record) |*owned| owned.deinit();
        if (marker == null) {
            if (record != null) return blockedRecovery(
                request.operation,
                "lower ownership marker is missing for an active record",
            );
            if (recovery_review_claim) |claim| {
                const review = store.readRecoveryReviewClaim(
                    allocator,
                ) catch return blockedRecovery(
                    request.operation,
                    "confirmed recovery review ownership is unreadable",
                );
                if (review != null) {
                    const owner = acknowledgment.marker;
                    if (!std.mem.eql(
                        u8,
                        &owner.digest_sha256,
                        &acknowledgment.marker_sha256,
                    ) or !std.mem.eql(
                        u8,
                        &root_operation.deferredAcknowledgmentExactIdentity(
                            owner,
                        ),
                        &acknowledgment.marker_exact_identity_sha256,
                    ) or !std.mem.eql(
                        u8,
                        &owner.attempt_id,
                        &acknowledgment.attempt_id,
                    ) or !std.mem.eql(
                        u8,
                        &owner.acknowledgment_id,
                        &acknowledgment.acknowledgment_id,
                    ))
                        return blockedRecovery(
                            request.operation,
                            "confirmed recovery review cannot reconstruct exact lower ownership",
                        );
                    store.exchangeRecoveryReviewClaimForOwnership(
                        allocator,
                        .{
                            .expected_claim = claim,
                            .expected_marker = null,
                            .expected_record_sha256 = null,
                            .replacement_marker = owner,
                        },
                    ) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return blockedRecovery(
                            request.operation,
                            "confirmed recovery review could not restore exact lower ownership",
                        ),
                    };
                    marker = owner;
                }
            }
            if (marker == null) return success(
                request.operation,
                false,
                "lower orchestration ownership was already finalized",
                &.{},
            );
        }
        var observed = marker.?;
        if (!std.mem.eql(
            u8,
            &acknowledgment.marker.digest_sha256,
            &acknowledgment.marker_sha256,
        ) or !std.mem.eql(
            u8,
            &root_operation.deferredAcknowledgmentExactIdentity(
                acknowledgment.marker,
            ),
            &acknowledgment.marker_exact_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &acknowledgment.marker.attempt_id,
            &acknowledgment.attempt_id,
        ) or !std.mem.eql(
            u8,
            &acknowledgment.marker.acknowledgment_id,
            &acknowledgment.acknowledgment_id,
        ))
            return blockedRecovery(
                request.operation,
                "lower ownership acknowledgment is internally inconsistent",
            );
        const expected_observed = if (recovery_review_claim) |review|
            if (observed.recovery_review_claim_sha256 != null)
                root_operation.bindDeferredAcknowledgmentToRecoveryReview(
                    acknowledgment.marker,
                    review,
                ) catch return blockedRecovery(
                    request.operation,
                    "lower ownership acknowledgment cannot be bound to the confirmed recovery review",
                )
            else
                acknowledgment.marker
        else
            acknowledgment.marker;
        if (observed.state == .pre_mutation_reconciliation_claim) {
            const claim = observed.pre_mutation_claim orelse
                return blockedRecovery(
                    request.operation,
                    "lower reconciliation claim binding is absent",
                );
            const selectors = try allocator.alloc(
                solver.PackageSelector,
                request.packages.len,
            );
            defer allocator.free(selectors);
            for (request.packages, 0..) |package, index|
                selectors[index] = parseSelector(package);
            const semantic_sha256 = try workflowSemanticRequestDigest(
                allocator,
                workflow_operation,
                selectors,
            );
            if (record != null or
                !std.mem.eql(
                    u8,
                    &claim.outer_attempt_id,
                    &acknowledgment.acknowledgment_id,
                ) or
                !std.mem.eql(
                    u8,
                    &claim.semantic_request_sha256,
                    &semantic_sha256,
                ) or
                !std.mem.eql(
                    u8,
                    &observed.digest_sha256,
                    &expected_observed.digest_sha256,
                ) or
                !std.mem.eql(
                    u8,
                    &root_operation.deferredAcknowledgmentExactIdentity(
                        observed,
                    ),
                    &root_operation.deferredAcknowledgmentExactIdentity(
                        expected_observed,
                    ),
                ) or
                !root_operation.deferredAcknowledgmentExactEqual(
                    observed,
                    expected_observed,
                ) or
                !std.mem.eql(
                    u8,
                    &observed.attempt_id,
                    &acknowledgment.attempt_id,
                ) or
                !std.mem.eql(
                    u8,
                    &observed.acknowledgment_id,
                    &acknowledgment.acknowledgment_id,
                ))
                return blockedRecovery(
                    request.operation,
                    "lower reconciliation claim belongs to another orchestrator",
                );
            if (recovery_review_claim) |expected_review| {
                store.exchangeRecoveryReviewClaimForOwnership(
                    allocator,
                    .{
                        .expected_claim = expected_review,
                        .expected_marker = observed,
                        .expected_record_sha256 = null,
                        .replacement_marker = observed,
                    },
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return blockedRecovery(
                        request.operation,
                        "confirmed recovery review could not be exchanged for the verified reconciliation owner",
                    ),
                };
                observed =
                    try root_operation.bindDeferredAcknowledgmentToRecoveryReview(
                        observed,
                        expected_review,
                    );
            }
            if (self.completion_crash) |crash|
                crash.hit(.before_ownership_marker_clear) catch
                    return blockedRecovery(
                        request.operation,
                        "lower reconciliation claim acknowledgment was interrupted",
                    );
            store.clearDeferredAcknowledgment(
                allocator,
                observed,
            ) catch return blockedRecovery(
                request.operation,
                "lower reconciliation claim could not be acknowledged",
            );
            if (self.completion_crash) |crash|
                crash.hit(.after_ownership_marker_clear) catch
                    return blockedRecovery(
                        request.operation,
                        "lower reconciliation claim acknowledgment was interrupted",
                    );
            return success(
                request.operation,
                false,
                "lower reconciliation claim finalized",
                &.{},
            );
        }
        if (!std.mem.eql(
            u8,
            &observed.digest_sha256,
            &expected_observed.digest_sha256,
        ) or
            !std.mem.eql(
                u8,
                &root_operation.deferredAcknowledgmentExactIdentity(
                    observed,
                ),
                &root_operation.deferredAcknowledgmentExactIdentity(
                    expected_observed,
                ),
            ) or !root_operation.deferredAcknowledgmentExactEqual(
            observed,
            expected_observed,
        ) or
            !std.mem.eql(
                u8,
                &observed.attempt_id,
                &acknowledgment.attempt_id,
            ) or
            !std.mem.eql(
                u8,
                &observed.acknowledgment_id,
                &acknowledgment.acknowledgment_id,
            ))
            return blockedRecovery(
                request.operation,
                "lower ownership marker belongs to another orchestrator",
            );
        const compatibility = root_operation.deferredRecordCompatibility(
            if (record) |owned| owned.record else null,
            observed,
            false,
        );
        const finalizable = switch (compatibility) {
            .released_without_record,
            .abandoned_without_record,
            .released_completed,
            .abandoned_pre_mutation,
            .bound_completed_success,
            .bound_completed_abandoned,
            => true,
            else => false,
        };
        if (!finalizable) return blockedRecovery(
            request.operation,
            "lower ownership record is unfinished, incompatible, or foreign",
        );
        if (recovery_review_claim) |expected_review| {
            store.exchangeRecoveryReviewClaimForOwnership(
                allocator,
                .{
                    .expected_claim = expected_review,
                    .expected_marker = observed,
                    .expected_record_sha256 = if (record) |owned|
                        owned.record.digest_sha256
                    else
                        null,
                    .replacement_marker = observed,
                },
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return blockedRecovery(
                    request.operation,
                    "confirmed recovery review could not be exchanged for the verified lower owner",
                ),
            };
            observed =
                try root_operation.bindDeferredAcknowledgmentToRecoveryReview(
                    observed,
                    expected_review,
                );
        }
        store.cleanupOwned(allocator, .{
            .authorization = root_operation.authorizationFromTrustedMarker(observed),
            .terminal_state = if (compatibility == .abandoned_without_record or
                compatibility == .abandoned_pre_mutation or
                compatibility == .bound_completed_abandoned)
                .abandoned
            else
                .released,
            .observer = self.ownershipCleanupObserver(),
        }) catch return blockedRecovery(
            request.operation,
            "lower ownership could not be finalized",
        );
        if (record) |*owned| {
            owned.deinit();
            record = null;
        }
        return success(
            request.operation,
            false,
            "lower orchestration ownership finalized",
            &.{},
        );
    }

    fn claimWorkflowReconciliation(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: api.Request,
        semantic_operation: WorkflowSemanticOperation,
        selectors: []const solver.PackageSelector,
        orchestration_id: [32]u8,
        claim: WorkflowReconciliationClaim,
        recovery_review_claim: ?root_operation.RecoveryReviewClaim,
    ) !api.Result {
        var owned_root = root_fs.openAbsoluteRoot(
            self.io,
            request.options.install_root,
        ) catch return blockedRecovery(
            request.operation,
            "the live root is unavailable while claiming reconciliation",
        );
        defer owned_root.close();
        var locks: root_operation.SystemLockBackend = .{
            .allocator = allocator,
            .io = self.io,
        };
        const lock_backend = locks.interface();
        const coordinator = root_operation.Coordinator.open(
            self.io,
            owned_root.root,
            request.options.install_root,
            lock_backend,
        ) catch |err| return mapRootOperationError(request.operation, err);
        const token = lock_backend.acquire(.{
            .rank = .root_operation,
            .root = owned_root.root,
            .identity = coordinator.identity,
            .path = root_operation.lock_path,
            .wait_ms = request.options.lock_wait_ms,
            .cancellation = transaction_executor.Cancellation.never(),
        }) catch |err| return mapRootOperationError(request.operation, err);
        defer lock_backend.release(token);
        const store = coordinator.store();
        const marker = store.readDeferredAcknowledgment(allocator) catch
            return blockedRecovery(
                request.operation,
                "lower reconciliation marker is unreadable",
            );
        var record = store.read(allocator) catch return blockedRecovery(
            request.operation,
            "lower reconciliation record is unreadable",
        );
        defer if (record) |*owned| owned.deinit();
        if (marker != null or record != null)
            return blockedRecovery(
                request.operation,
                "lower root is not clean for reconciliation",
            );
        const execute_request_sha256 = try workflowProductRequestDigest(
            allocator,
            semantic_operation,
            .execute,
            selectors,
            request.options,
        );
        const semantic_request_sha256 = try workflowSemanticRequestDigest(
            allocator,
            semantic_operation,
            selectors,
        );
        const attempt_id = switch (claim) {
            .pre_mutation => |binding| root_operation.preMutationReconciliationClaimId(.{
                .outer_attempt_id = orchestration_id,
                .outer_generation = binding.outer_generation,
                .outer_state_sha256 = binding.outer_state_sha256,
                .profile_sha256 = binding.profile_sha256,
                .profile_reference_sha256 = binding.profile_reference_sha256,
                .exact_lock_sha256 = binding.exact_lock_sha256,
                .semantic_request_sha256 = semantic_request_sha256,
            }),
            .post_mutation => |binding| reconciliationAttemptId(
                orchestration_id,
                execute_request_sha256,
                binding.exact_lock_sha256,
                binding.evidence_sha256,
            ),
        };
        const reconciliation = try root_operation.createDeferredAcknowledgment(
            .{
                .state = switch (claim) {
                    .pre_mutation => .pre_mutation_reconciliation_claim,
                    .post_mutation => .released,
                },
                .attempt_id = attempt_id,
                .pre_mutation_claim = switch (claim) {
                    .pre_mutation => |binding| .{
                        .outer_attempt_id = orchestration_id,
                        .outer_generation = binding.outer_generation,
                        .outer_state_sha256 = binding.outer_state_sha256,
                        .profile_sha256 = binding.profile_sha256,
                        .profile_reference_sha256 = binding.profile_reference_sha256,
                        .exact_lock_sha256 = binding.exact_lock_sha256,
                        .semantic_request_sha256 = semantic_request_sha256,
                    },
                    .post_mutation => null,
                },
                .acknowledgment_id = orchestration_id,
            },
        );
        if (self.completion_crash) |crash|
            try crash.hit(.before_reconciliation_marker_publish);
        if (recovery_review_claim) |expected_review|
            store.exchangeRecoveryReviewClaimForOwnership(
                allocator,
                .{
                    .expected_claim = expected_review,
                    .expected_marker = null,
                    .expected_record_sha256 = null,
                    .replacement_marker = reconciliation,
                },
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return blockedRecovery(
                    request.operation,
                    "the confirmed recovery review could not be atomically exchanged for reconciliation ownership",
                ),
            }
        else
            store.publishDeferredAcknowledgment(
                allocator,
                reconciliation,
            ) catch return blockedRecovery(
                request.operation,
                "lower reconciliation ownership could not be published",
            );
        if (self.completion_crash) |crash|
            try crash.hit(.after_reconciliation_marker_publish);
        return success(
            request.operation,
            false,
            "clean lower root reserved for outer reconciliation",
            &.{},
        );
    }

    fn reconciliationAttemptId(
        orchestration_id: [32]u8,
        semantic_sha256: [32]u8,
        exact_lock_sha256: [32]u8,
        evidence_sha256: [32]u8,
    ) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("debz-root-reconciliation-v1\x00");
        hash.update(&orchestration_id);
        hash.update(&semantic_sha256);
        hash.update(&exact_lock_sha256);
        hash.update(&evidence_sha256);
        return hash.finalResult();
    }

    fn ownershipCleanupObserver(
        self: *Backend,
    ) root_operation.OwnershipCleanupObserver {
        return .{ .context = self, .hitFn = observeOwnershipCleanup };
    }

    fn observeOwnershipCleanup(
        context: *anyopaque,
        point: root_operation.OwnershipCleanupPoint,
    ) !void {
        const self: *Backend = @ptrCast(@alignCast(context));
        const crash = self.completion_crash orelse return;
        try crash.hit(switch (point) {
            .before_terminal_publish => .before_ownership_terminal_publish,
            .after_terminal_publish => .after_ownership_terminal_publish,
            .before_record_clear => .before_ownership_record_clear,
            .after_record_clear => .after_ownership_record_clear,
            .before_binding_clear => .before_ownership_marker_clear,
            .after_binding_clear => .after_ownership_marker_clear,
        });
    }

    /// Reads back what survived of a completed attempt's evidence.
    ///
    /// Absence is a fact and is reported as such; anything that exists but
    /// cannot be read, decoded, or bound to this attempt blocks the discharge
    /// instead of being explained away, because clearing the record while an
    /// unexplained document sits exactly where this attempt would have
    /// published one would make the cleared record a lie.
    fn collectOwedEvidence(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: api.Request,
        record: root_operation.Record,
    ) !OwedEvidence {
        var dir = openAbsoluteDirectory(self.io, request.options.state_path) catch |err| switch (err) {
            error.FileNotFound => return .{
                .transaction = .{
                    .status = .unavailable,
                    .detail = "the explicit state path consulted by recovery does not exist",
                },
                .journal = .{
                    .status = .absent,
                    .detail = "the explicit state path consulted by recovery does not exist",
                },
            },
            else => return blockedEvidence(try std.fmt.allocPrint(
                allocator,
                "the explicit state path {s} could not be opened to verify the interrupted transaction: {s}",
                .{ request.options.state_path, @errorName(err) },
            )),
        };
        defer dir.close(self.io);

        var transaction: root_operation_completion.TransactionProvenance = .{
            .status = .unavailable,
            .detail = "no detailed transaction provenance exists under the explicit state path consulted by recovery",
        };
        const provenance_store = transaction_provenance.Store.init(
            self.io,
            dir,
            transaction_result_name,
        ) catch |err| return blockedEvidence(try std.fmt.allocPrint(
            allocator,
            "the transaction provenance path is unusable: {s}",
            .{@errorName(err)},
        ));
        if (provenance_store.read(allocator, transaction_provenance.maximum_document_bytes)) |read| {
            var validated = read;
            defer validated.deinit();
            const binding = transaction_provenance.readBinding(
                allocator,
                validated.bytes,
                transaction_provenance.maximum_document_bytes,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return blockedEvidence(try std.fmt.allocPrint(
                    allocator,
                    "{s}/{s} is not a readable transaction provenance document ({s}); inspect it before recovering this root",
                    .{ request.options.state_path, transaction_result_name, @errorName(err) },
                )),
            };
            if (transactionProvenanceMismatch(record, binding)) |reason|
                return blockedEvidence(try std.fmt.allocPrint(
                    allocator,
                    "{s}/{s} does not describe the interrupted transaction ({s}); inspect it before recovering this root",
                    .{ request.options.state_path, transaction_result_name, reason },
                ));
            transaction = .{
                .status = .already_present,
                .schema = transaction_provenance.schema_id,
                .document_sha256 = binding.digest_sha256,
                .detail = "published transaction provenance verified against the completed attempt",
            };
        } else |err| switch (err) {
            error.FileNotFound => {},
            error.OutOfMemory => return error.OutOfMemory,
            else => return blockedEvidence(try std.fmt.allocPrint(
                allocator,
                "{s}/{s} could not be read as a regular file ({s}); inspect it before recovering this root",
                .{ request.options.state_path, transaction_result_name, @errorName(err) },
            )),
        }

        return .{
            .transaction = transaction,
            .journal = try self.collectJournalEvidence(allocator, dir),
        };
    }

    /// The transaction journal as it stands now. It is evidence about the
    /// interrupted transaction, never authority over it, so a journal that
    /// cannot be read is reported rather than treated as proof of anything.
    fn collectJournalEvidence(
        self: *Backend,
        allocator: std.mem.Allocator,
        dir: std.Io.Dir,
    ) !root_operation_completion.Journal {
        const candidates = [_]struct {
            name: []const u8,
            status: root_operation_completion.JournalStatus,
            detail: []const u8,
        }{
            .{
                .name = "transaction.complete",
                .status = .archived,
                .detail = "transaction.complete was archived by the executor that finished the transaction",
            },
            .{
                .name = "transaction.journal",
                .status = .active,
                .detail = "transaction.journal was still active when the completion was interrupted",
            },
        };
        for (candidates) |candidate| {
            const digest = self.readStateDigest(allocator, dir, candidate.name) catch |err| switch (err) {
                error.FileNotFound => continue,
                error.OutOfMemory => return error.OutOfMemory,
                else => return .{
                    .status = .unreadable,
                    .detail = try std.fmt.allocPrint(
                        allocator,
                        "{s} could not be read: {s}",
                        .{ candidate.name, @errorName(err) },
                    ),
                },
            };
            return .{
                .status = candidate.status,
                .document_sha256 = digest,
                .detail = candidate.detail,
            };
        }
        return .{
            .status = .absent,
            .detail = "no transaction journal remains under the explicit state path consulted by recovery",
        };
    }

    /// Digest of one bounded state-directory file, read without following a
    /// symbolic link and without accepting a directory.
    fn readStateDigest(
        self: *Backend,
        allocator: std.mem.Allocator,
        dir: std.Io.Dir,
        name: []const u8,
    ) ![32]u8 {
        var file = try dir.openFile(self.io, name, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        const bytes = try reader.interface.allocRemaining(
            allocator,
            .limited(transaction_recovery.maximum_journal_bytes),
        );
        defer allocator.free(bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        return digest;
    }

    fn loadInstalled(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !dpkg_status.OwnedDatabase {
        const allocated_path = if (request.options.status_path == null)
            try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/status", .{request.options.install_root})
        else
            null;
        defer if (allocated_path) |path| allocator.free(path);
        const path = request.options.status_path orelse allocated_path.?;
        const parsed = blk: {
            break :blk dpkg_status.parseFile(allocator, self.io, path, .{}) catch |err| {
                if (err != error.FileNotFound) return err;
                // A root with no dpkg database has nothing installed. That is
                // precisely what a root looks like before its first
                // transaction, and debootstrap writes the same statement as an
                // empty status file, so the two roots describe one installed
                // set and must resolve alike. Refusing the absent one made
                // bootstrapping a fresh root impossible to plan: the caller had
                // to materialize an empty file to say what its absence already
                // said.
                //
                // The root itself must still exist. A missing database inside a
                // real root is a fresh root; a missing root is a misconfigured
                // one, and only the first is a fact about packages.
                if (!self.installRootExists(request.options.install_root)) return err;
                break :blk try dpkg_status.parseOwned(allocator, "", .{});
            };
        };
        return switch (parsed) {
            .diagnostic => |diagnostic| {
                _ = diagnostic;
                return error.InvalidInstalledState;
            },
            .database => |database| database,
        };
    }

    /// Whether the install root exists as a directory, which separates a root
    /// that has not been bootstrapped yet from one that was never there.
    fn installRootExists(self: *Backend, install_root: []const u8) bool {
        if (install_root.len == 0) return false;
        var dir = std.Io.Dir.cwd().openDir(self.io, install_root, .{}) catch return false;
        dir.close(self.io);
        return true;
    }

    fn loadRepositoryDocuments(
        self: *Backend,
        allocator: std.mem.Allocator,
        options: RepositoryOptions,
    ) !LoadedDocuments {
        var documents: std.ArrayList(repository_policy.SourceDocument) = .empty;
        var bytes: std.ArrayList([]u8) = .empty;
        for (options.source_paths) |path| {
            const contents = try readFile(allocator, self.io, path, 8 * 1024 * 1024);
            try bytes.append(allocator, contents);
            try documents.append(allocator, .{
                .bytes = contents,
                .format = sourceFormat(path),
                .policy = basePolicy(options),
            });
        }
        for (options.config_paths) |path| {
            const config_bytes = try readFile(allocator, self.io, path, 1024 * 1024);
            defer allocator.free(config_bytes);
            const Wire = struct {
                source_path: []const u8,
                priority: i32 = 500,
                default_release: ?[]const u8 = null,
                immutable: bool = false,
            };
            var parsed = try std.json.parseFromSlice(Wire, allocator, config_bytes, .{
                .allocate = .alloc_always,
                .ignore_unknown_fields = false,
            });
            defer parsed.deinit();
            if (parsed.value.source_path.len == 0 or parsed.value.source_path[0] != '/')
                return error.InvalidRepositoryConfig;
            const contents = try readFile(allocator, self.io, parsed.value.source_path, 8 * 1024 * 1024);
            try bytes.append(allocator, contents);
            var policy = basePolicy(options);
            policy.priority = parsed.value.priority;
            policy.default_release = if (parsed.value.default_release) |value|
                try allocator.dupe(u8, value)
            else
                options.default_release;
            policy.immutability.kind = if (parsed.value.immutable) .immutable_url else .moving;
            try documents.append(allocator, .{
                .bytes = contents,
                .format = sourceFormat(parsed.value.source_path),
                .policy = policy,
            });
        }
        return .{
            .allocator = allocator,
            .documents = try documents.toOwnedSlice(allocator),
            .bytes = try bytes.toOwnedSlice(allocator),
        };
    }
};

const LoadedDocuments = struct {
    allocator: std.mem.Allocator,
    documents: []repository_policy.SourceDocument,
    bytes: [][]u8,

    fn deinit(self: *LoadedDocuments) void {
        for (self.bytes) |value| self.allocator.free(value);
        self.allocator.free(self.bytes);
        self.allocator.free(self.documents);
        self.* = undefined;
    }
};

/// Mutation surfaces that share the root operation namespace. Query, plan,
/// download, refresh, and cache operations never reserve the root, so they
/// stay usable while another attempt holds it.
fn rootOperationSurface(operation: api.Operation) ?root_operation.Operation {
    return switch (operation) {
        .install, .remove, .upgrade, .upgrade_all, .reinstall, .recover => .{
            .package_transaction = operation,
        },
        .refresh,
        .download,
        .plan,
        .list_installed,
        .list_available,
        .info,
        .provides,
        .why,
        .clean,
        => null,
    };
}

fn workflowSemanticSurface(operation: WorkflowSemanticOperation) api.Operation {
    return switch (operation) {
        .install => .install,
        .remove => .remove,
        .upgrade_all => .upgrade_all,
    };
}

fn workflowSurfaceOperation(
    operation: WorkflowSemanticOperation,
    mode: WorkflowMode,
) api.Operation {
    return switch (mode) {
        .plan_only => .plan,
        .download_only => .download,
        .reserve, .execute => workflowSemanticSurface(operation),
        .recover => .recover,
    };
}

fn workflowMode(operation: api.Operation, workflow: ?WorkflowDirective) WorkflowMode {
    if (workflow) |directive| return directive.mode;
    return switch (operation) {
        .plan => .plan_only,
        .download => .download_only,
        .recover => .recover,
        else => .execute,
    };
}

fn workflowRootOperation(
    operation: api.Operation,
    workflow: ?WorkflowDirective,
) ?root_operation.Operation {
    if (workflow) |directive| return switch (directive.mode) {
        .plan_only, .download_only => null,
        .reserve, .execute, .recover => .{
            .package_transaction = workflowSemanticSurface(directive.operation),
        },
    };
    return rootOperationSurface(operation);
}

/// Bounded digest of the reviewed request. It binds exactly what the caller
/// asked for, so a resumed attempt can prove it belongs to this request.
fn productRequestDigest(request: api.Request) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-product-request-v1\x00");
    hash.update(@tagName(request.operation));
    hash.update("\x00");
    hash.update(request.options.install_root);
    hash.update("\x00");
    hash.update(request.options.architecture);
    hash.update("\x00");
    hash.update(if (request.options.recommends) "\x01" else "\x00");
    hash.update(@tagName(request.options.repository_policy));
    hash.update(@tagName(request.options.conffile));
    hash.update(if (request.options.allow_downgrade) "\x01" else "\x00");
    for (request.packages) |package| {
        hash.update(package);
        hash.update("\x00");
    }
    return hash.finalResult();
}

fn recoveryCompletionMatchesRecord(
    document: root_operation_completion.Document,
    record: root_operation.Record,
    recovery_request: api.Request,
) bool {
    const original_operation: api.Operation = switch (record.operation) {
        .package_transaction => |operation| operation,
        .repository_bootstrap => return false,
    };
    var original_request = recovery_request;
    original_request.operation = original_operation;
    const lock_matches = if (record.exact_lock) |record_lock|
        if (document.exact_lock) |document_lock|
            std.mem.eql(u8, record_lock.schema, document_lock.schema) and
                record_lock.version == document_lock.version and
                std.mem.eql(
                    u8,
                    &record_lock.digest_sha256,
                    &document_lock.digest_sha256,
                )
        else
            false
    else
        false;
    const provenance_sha256 = record.provenance_sha256 orelse return false;
    const expected_provenance = root_operation.provenanceDigest(record, .{
        .outcome = record.outcome,
        .document_sha256 = document.digest_sha256,
        .journal_archived = document.journal.status == .archived,
    });
    return std.mem.eql(u8, &document.attempt_id, &record.attempt_id) and
        std.mem.eql(
            u8,
            &document.request_sha256,
            &productRequestDigest(original_request),
        ) and
        std.mem.eql(
            u8,
            &document.discharge.request_sha256,
            &productRequestDigest(recovery_request),
        ) and
        document.discharge.surface == .package_transaction and
        std.mem.eql(u8, document.discharge.operation, "recover") and
        lock_matches and
        std.mem.eql(u8, &expected_provenance, &provenance_sha256);
}

fn deferredMarkerMatches(
    marker: root_operation.DeferredAcknowledgment,
    record: root_operation.Record,
    document: root_operation_completion.Document,
    acknowledgment_id: [32]u8,
) bool {
    const provenance_sha256 = record.provenance_sha256 orelse return false;
    return marker.state == .pending and
        marker.completion_sha256 != null and
        marker.provenance_sha256 != null and
        std.mem.eql(u8, &marker.attempt_id, &record.attempt_id) and
        std.mem.eql(
            u8,
            &marker.completion_sha256.?,
            &document.digest_sha256,
        ) and
        std.mem.eql(
            u8,
            &marker.provenance_sha256.?,
            &provenance_sha256,
        ) and
        std.mem.eql(
            u8,
            &marker.acknowledgment_id,
            &acknowledgment_id,
        );
}

fn recordMatchesAcknowledgment(
    record: root_operation.Record,
    marker: root_operation.DeferredAcknowledgment,
) bool {
    return record.state == .completed and
        record.provenance == .published and
        record.provenance_sha256 != null and
        marker.provenance_sha256 != null and
        std.mem.eql(u8, &record.attempt_id, &marker.attempt_id) and
        std.mem.eql(
            u8,
            &record.provenance_sha256.?,
            &marker.provenance_sha256.?,
        );
}

/// Owns rank 0 of the lock order for one product mutation. It is deliberately
/// a thin bridge: it reserves the root, publishes each durable boundary the
/// current command-oriented executor can justify, and resolves the pending
/// bridge from the executor's own command evidence rather than assuming that
/// handing over control mutated anything.
const RootOperationGuard = struct {
    backend: *Backend,
    allocator: std.mem.Allocator,
    owned_root: ?root_fs.OwnedRoot = null,
    locks: root_operation.SystemLockBackend = undefined,
    coordinator: root_operation.Coordinator = undefined,
    attempt: ?root_operation.Attempt = null,
    /// Set when a simulated process death unwound through this guard. The
    /// durable record then stays exactly as it was published, because a dead
    /// process cannot complete, clear, or abandon anything.
    crashed: bool = false,
    /// The apt-system orchestrator has requested a durable lower
    /// acknowledgment hand-off. The settled record remains until that outer
    /// coordinator retains and explicitly acknowledges its exact token.
    preserve_settled: bool = false,
    /// Reservation-only workflow calls intentionally leave their exact
    /// pre-mutation binding for the subsequent execute call to adopt.
    preserve_pre_mutation: bool = false,
    orchestration_id: ?[32]u8 = null,
    recovery_review_claim: ?root_operation.RecoveryReviewClaim = null,
    expected_ownership_marker: ?root_operation.DeferredAcknowledgment = null,
    ownership_marker: ?root_operation.DeferredAcknowledgment = null,

    const Completion = enum { succeeded, failed, recovered };

    /// Pointer to the live attempt, never a copy: every boundary must be
    /// published on the record this guard owns.
    fn active(self: *RootOperationGuard) ?*root_operation.Attempt {
        if (self.attempt) |*value| return value;
        return null;
    }

    /// Reproduces a process death at one completion boundary. Only the test
    /// seam can reach it; without an injector every boundary simply runs.
    fn crash(self: *RootOperationGuard, point: CompletionPoint) !void {
        const injector = self.backend.completion_crash orelse return;
        injector.hit(point) catch |err| {
            self.crashed = true;
            return err;
        };
    }

    fn acquisitionObserver(
        self: *RootOperationGuard,
    ) root_operation.AcquisitionObserver {
        return .{ .context = self, .hitFn = observeAcquisition };
    }

    fn observeAcquisition(
        context: *anyopaque,
        point: root_operation.AcquisitionPoint,
    ) !void {
        const self: *RootOperationGuard = @ptrCast(@alignCast(context));
        const binding_point: RootBindingPoint = switch (point) {
            .after_lock_acquired => .after_root_lock_acquired,
            .before_retry_terminal_publish => .before_retry_terminal_publish,
            .after_retry_terminal_publish => .after_retry_terminal_publish,
            .before_retry_record_clear => .before_retry_record_clear,
            .after_retry_record_clear => .after_retry_record_clear,
            .before_binding_published => .before_binding_published,
            .after_binding_published => .after_binding_published,
        };
        if (self.backend.root_binding_sync) |sync|
            try sync.hit(binding_point);
        try self.crash(switch (point) {
            .after_lock_acquired => .after_root_lock_acquired,
            .before_retry_terminal_publish => .before_retry_terminal_publish,
            .after_retry_terminal_publish => .after_retry_terminal_publish,
            .before_retry_record_clear => .before_retry_record_clear,
            .after_retry_record_clear => .after_retry_record_clear,
            .before_binding_published => .before_binding_published,
            .after_binding_published => .after_binding_published,
        });
    }

    fn open(
        self: *RootOperationGuard,
        allocator: std.mem.Allocator,
        request: api.Request,
        operation: root_operation.Operation,
    ) ?api.Result {
        self.owned_root = root_fs.openAbsoluteRoot(
            self.backend.io,
            request.options.install_root,
        ) catch return api.failure(
            request.operation,
            .usage,
            .invalid_request,
            "install root is unsafe or unavailable",
        );
        self.locks = .{ .allocator = allocator, .io = self.backend.io };
        self.coordinator = root_operation.Coordinator.open(
            self.backend.io,
            self.owned_root.?.root,
            request.options.install_root,
            self.locks.interface(),
        ) catch |err| return mapRootOperationError(request.operation, err);
        self.coordinator.now_unix = self.backend.now_unix;
        self.attempt = self.coordinator.acquire(allocator, .{
            .intent = if (request.operation == .recover) .recovery else .mutation,
            // A record that never left the pre-mutation states is durable
            // proof that nothing was touched, so a crashed attempt does not
            // strand the root. Anything from the executor bridge onwards is
            // recovery evidence and still refuses a second mutation.
            .existing = .reclaim_resolved,
            .backend = self.backend.transaction_backend,
            .operation = operation,
            .request_sha256 = productRequestDigest(request),
            .policy_sha256 = package_cache_workflow.solverPolicyDigest(
                request.options.recommends,
                request.options.allow_downgrade,
                switch (request.options.repository_policy) {
                    .strict_priority => .strict_priority,
                    .best_version => .best_version,
                },
            ),
            .target_architecture = request.options.architecture,
            .wait_ms = request.options.lock_wait_ms,
            .adopt_settled_for_acknowledgment = self.preserve_settled,
            .orchestration_id = self.orchestration_id,
            .recovery_review_claim = self.recovery_review_claim,
            .expected_deferred_acknowledgment = self.expected_ownership_marker,
            .acquisition_observer = self.acquisitionObserver(),
        }) catch |err| return mapRootOperationError(request.operation, err);
        if (self.orchestration_id) |orchestration_id| {
            const store = self.coordinator.store();
            const existing = store.readDeferredAcknowledgment(
                allocator,
            ) catch return api.failure(
                request.operation,
                .internal,
                .internal_error,
                "lower orchestration binding is unreadable",
            );
            if (existing) |binding| {
                if (!std.mem.eql(
                    u8,
                    &binding.attempt_id,
                    &self.attempt.?.record().attempt_id,
                ) or !std.mem.eql(
                    u8,
                    &binding.acknowledgment_id,
                    &orchestration_id,
                )) return blockedRecovery(
                    request.operation,
                    "lower operation belongs to a different outer orchestrator attempt",
                );
                self.ownership_marker = if (binding.document_version ==
                    root_operation.deferred_ack_v2_schema_version)
                authenticated: {
                    if (self.expected_ownership_marker) |expected| {
                        if (!root_operation.deferredAcknowledgmentExactEqual(
                            binding,
                            expected,
                        )) return blockedRecovery(
                            request.operation,
                            "lower operation does not match the authenticated exact ownership token",
                        );
                        break :authenticated expected;
                    }
                    const claim = self.recovery_review_claim orelse
                        return blockedRecovery(
                            request.operation,
                            "exact lower ownership evidence is unavailable",
                        );
                    const base = claim.prior_marker orelse
                        root_operation.createDeferredAcknowledgment(.{
                            .state = .bound,
                            .attempt_id = self.attempt.?.record().attempt_id,
                            .acknowledgment_id = orchestration_id,
                        }) catch return blockedRecovery(
                        request.operation,
                        "exact lower ownership evidence is invalid",
                    );
                    const expected =
                        root_operation.bindDeferredAcknowledgmentToRecoveryReview(
                            base,
                            claim,
                        ) catch return blockedRecovery(
                            request.operation,
                            "exact lower ownership evidence is invalid",
                        );
                    if (!root_operation.deferredAcknowledgmentExactEqual(
                        binding,
                        expected,
                    )) return blockedRecovery(
                        request.operation,
                        "lower operation does not match the reviewed exact ownership token",
                    );
                    break :authenticated expected;
                } else binding;
            } else return blockedRecovery(
                request.operation,
                "lower operation has no originating outer orchestration binding",
            );
        }
        return null;
    }

    fn preflight(
        self: *RootOperationGuard,
        allocator: std.mem.Allocator,
        operation: api.Operation,
        evidence: root_operation.Evidence,
    ) !?api.Result {
        var attempt = self.active() orelse return null;
        if (attempt.record().state != .reserved and attempt.record().state != .preflight)
            return null;
        attempt.advance(allocator, .{
            .state = .preflight,
            .phase = .preflight,
            .evidence = evidence,
        }) catch |err| return mapRootOperationError(operation, err);
        return null;
    }

    fn enterExecutor(
        self: *RootOperationGuard,
        allocator: std.mem.Allocator,
        operation: api.Operation,
    ) !?api.Result {
        var attempt = self.active() orelse return null;
        switch (attempt.record().state) {
            // Nothing was mutated yet, so publish the bridge.
            .reserved, .preflight => attempt.advance(allocator, .{
                .state = .mutation_pending,
                .phase = .mutation,
            }) catch |err| return mapRootOperationError(operation, err),
            // The bridge an earlier run published stays exactly as it is. It
            // is inherited rather than republished, so this run's own executor
            // evidence can never discharge it as never having started.
            .mutation_pending => {},
            // An adopted attempt already carries mutation evidence. Recovery
            // resumes it through the durable recovery boundary instead of
            // pretending it is a fresh hand-over.
            .mutating, .verifying, .recovery_required, .recovering => attempt.beginRecovery(
                allocator,
                .mutation,
            ) catch |err| return mapRootOperationError(operation, err),
            // The attempt already finished; only its provenance is owed.
            .completed => {},
        }
        // The executor takes the target locks next. Declaring the rank keeps
        // the total lock order enforced for locks this guard does not own.
        attempt.enterRank(.target_database) catch |err|
            return mapRootOperationError(operation, err);
        return null;
    }

    /// Resolves the bridge from the executor's own transaction evidence. The
    /// witness is derived by `root_operation`, never from a command count:
    /// the executor records a command only after it completed, so a first
    /// command that timed out, hit the deadline, or failed to spawn reports
    /// zero commands while `dpkg` may already have mutated the root.
    ///
    /// This run's evidence only ever speaks for this run's hand-over, so the
    /// attempt itself decides which witness may be applied: a bridge inherited
    /// from an earlier run is resolved as observed mutation no matter what
    /// this executor reports, and the applied witness — never the reported one
    /// — decides whether the attempt is durably abandoned.
    fn observe(
        self: *RootOperationGuard,
        allocator: std.mem.Allocator,
        operation: api.Operation,
        observed: root_operation.Witness,
        completion: Completion,
    ) !?api.Result {
        var attempt = self.active() orelse return null;
        // Already finished; `finish` still owes its provenance.
        if (attempt.record().state == .completed) return null;
        if (attempt.record().state == .mutation_pending) {
            const applied = attempt.witness(allocator, observed) catch |err|
                return mapRootOperationError(operation, err);
            // Nothing ran under a bridge this invocation published, so the
            // attempt is durably abandoned before any mutation and needs no
            // further boundary.
            if (applied == .proved_not_started) return null;
        }
        if (!attempt.record().mutation_started) return null;
        switch (completion) {
            .succeeded => {
                attempt.advance(allocator, .{
                    .state = .verifying,
                    .phase = .verification,
                }) catch |err| return mapRootOperationError(operation, err);
                attempt.complete(allocator, .succeeded) catch |err|
                    return mapRootOperationError(operation, err);
            },
            .recovered => if (attempt.record().state != .completed) {
                attempt.beginRecovery(allocator, .database) catch |err|
                    return mapRootOperationError(operation, err);
                attempt.complete(allocator, .recovered) catch |err|
                    return mapRootOperationError(operation, err);
            },
            // A failure after mutation stays durably unrecovered: the next
            // mutation is refused until an explicit recovery resolves it.
            .failed => attempt.requireRecovery(allocator, .mutation) catch |err|
                return mapRootOperationError(operation, err),
        }
        return null;
    }

    /// Publishes provenance and only then clears the active intent.
    fn finish(
        self: *RootOperationGuard,
        allocator: std.mem.Allocator,
        operation: api.Operation,
    ) !?api.Result {
        var attempt = self.active() orelse return null;
        const record = attempt.record();
        if (record.state != .completed) return null;
        if (record.provenance == .pending) attempt.publishProvenance(
            allocator,
            root_operation.provenanceDigest(record, .{
                .outcome = record.outcome,
                .journal_archived = true,
            }),
        ) catch |err| return mapRootOperationError(operation, err);
        try self.crash(.after_provenance_published);
        if (self.orchestration_id == null) {
            attempt.clear() catch |err|
                return mapRootOperationError(operation, err);
        } else {
            _ = self.coordinator.store().retainOwnedTerminal(
                allocator,
                .{
                    .authorization = root_operation.authorizationFromTrustedMarker(
                        self.ownership_marker orelse
                            return blockedRecovery(
                                operation,
                                "exact lower ownership evidence is unavailable",
                            ),
                    ),
                    .terminal_state = .released,
                    .observer = self.cleanupObserver(),
                },
            ) catch {
                return blockedRecovery(
                    operation,
                    "completed lower operation ownership could not be retained",
                );
            };
            self.preserve_settled = true;
        }
        return null;
    }

    fn finalizeOrchestrationOwnership(
        self: *RootOperationGuard,
        terminal_state: root_operation.DeferredAcknowledgmentState,
    ) !void {
        _ = self.orchestration_id orelse return;
        _ = self.active() orelse return;
        try self.coordinator.store().cleanupOwned(self.allocator, .{
            .authorization = root_operation.authorizationFromTrustedMarker(
                self.ownership_marker orelse
                    return error.AuthorizationEvidenceMissing,
            ),
            .terminal_state = terminal_state,
            .observer = self.cleanupObserver(),
        });
    }

    fn cleanupObserver(
        self: *RootOperationGuard,
    ) root_operation.OwnershipCleanupObserver {
        return .{ .context = self, .hitFn = observeCleanup };
    }

    fn observeCleanup(
        context: *anyopaque,
        point: root_operation.OwnershipCleanupPoint,
    ) !void {
        const self: *RootOperationGuard = @ptrCast(@alignCast(context));
        try self.crash(switch (point) {
            .before_terminal_publish => .before_ownership_terminal_publish,
            .after_terminal_publish => .after_ownership_terminal_publish,
            .before_record_clear => .before_ownership_record_clear,
            .after_record_clear => .after_ownership_record_clear,
            .before_binding_clear => .before_ownership_marker_clear,
            .after_binding_clear => .after_ownership_marker_clear,
        });
    }

    fn deinit(self: *RootOperationGuard) void {
        if (self.attempt) |*value| {
            // An attempt durably proven never to have mutated the root is
            // released rather than left behind, and a finished attempt whose
            // provenance obligation is discharged is cleared. Anything at or
            // past the executor bridge stays exactly as published, so the next
            // mutation is refused until it is explicitly recovered. A failure
            // here simply leaves the record, which the next attempt reports.
            // A simulated crash unwinds without any of this: the record must
            // survive exactly as the dead process left it.
            if (value.locked() and !self.crashed and
                !self.preserve_pre_mutation)
            {
                if (value.record().state.provenPreMutation()) {
                    if (self.orchestration_id == null) {
                        value.abandonIfPreMutation(self.allocator) catch {};
                    } else {
                        value.complete(
                            self.allocator,
                            .abandoned_before_mutation,
                        ) catch {};
                        if (value.record().clearable())
                            _ = self.coordinator.store().retainOwnedTerminal(
                                self.allocator,
                                .{
                                    .authorization = root_operation.authorizationFromTrustedMarker(
                                        self.ownership_marker orelse
                                            return,
                                    ),
                                    .terminal_state = .abandoned,
                                    .observer = self.cleanupObserver(),
                                },
                            ) catch {};
                    }
                } else if (value.record().clearable() and !self.preserve_settled) {
                    if (self.orchestration_id == null) {
                        value.clear() catch {};
                    } else {
                        self.finalizeOrchestrationOwnership(.released) catch {};
                    }
                }
            }
            value.release();
        }
        self.attempt = null;
        if (self.owned_root) |*value| value.close();
        self.owned_root = null;
    }
};

/// Name of the detailed transaction provenance document a locked product
/// transaction publishes under the explicit state path.
const transaction_result_name = "transaction-result.json";

/// What survived of a completed attempt's evidence, or the reason its
/// provenance obligation may not be discharged at all.
const OwedEvidence = struct {
    transaction: root_operation_completion.TransactionProvenance,
    journal: root_operation_completion.Journal,
    /// When set, nothing is published and the record stays exactly as the
    /// interrupted attempt left it.
    blocked: ?[]const u8 = null,
};

fn blockedEvidence(message: []const u8) OwedEvidence {
    return .{
        .transaction = .{ .status = .unavailable, .detail = "evidence was not evaluated" },
        .journal = .{ .status = .absent, .detail = "evidence was not evaluated" },
        .blocked = message,
    };
}

/// A root whose owed provenance cannot be discharged stays blocked. The
/// diagnostic names the exact document to inspect, and the record is left
/// exactly as published so no evidence is destroyed by the report.
fn blockedRecovery(operation: api.Operation, message: []const u8) api.Result {
    return api.failure(
        operation,
        .recovery,
        .root_operation_recovery_required,
        message,
    );
}

/// Why a published transaction provenance document does not describe the
/// interrupted attempt, or `null` when it does. The plan and exact-lock
/// digests are the attempt's own preflight evidence, so a document that
/// carries different ones was published for a different transaction.
fn transactionProvenanceMismatch(
    record: root_operation.Record,
    binding: transaction_provenance.DocumentBinding,
) ?[]const u8 {
    const plan = record.plan_sha256 orelse
        return "the interrupted attempt bound no reviewed plan to compare it against";
    if (!std.mem.eql(u8, &plan, &binding.plan_sha256))
        return "its plan digest belongs to a different transaction";
    const lock = record.exact_lock orelse
        return "the interrupted attempt bound no exact lock to compare it against";
    if (!std.mem.eql(u8, &lock.digest_sha256, &binding.lock_sha256))
        return "its exact-lock digest belongs to a different transaction";
    if (!std.mem.eql(u8, record.target_architecture, binding.architecture()))
        return "its target architecture differs from the interrupted attempt";
    if (record.outcome == .succeeded and binding.outcome != .succeeded)
        return "it does not describe a successful transaction";
    return null;
}

fn mapRootOperationError(operation: api.Operation, err: anyerror) api.Result {
    return switch (err) {
        error.LockTimeout, error.LockUnavailable => api.failure(
            operation,
            .unavailable,
            .root_operation_conflict,
            "another debz operation holds the root mutation lock",
        ),
        error.LockCanceled => api.failure(
            operation,
            .unavailable,
            .root_operation_conflict,
            "root mutation lock acquisition was cancelled",
        ),
        error.OperationInProgress, error.ResolvedAttemptPresent, error.AttemptMismatch => api.failure(
            operation,
            .recovery,
            .root_operation_conflict,
            "an interrupted debz operation left an unresolved root attempt",
        ),
        error.RecoveryRequired => api.failure(
            operation,
            .recovery,
            .root_operation_recovery_required,
            "a previous debz operation mutated this root and requires recovery",
        ),
        error.AuthorizationEvidenceMissing,
        error.DeferredAcknowledgmentMismatch,
        => api.failure(
            operation,
            .recovery,
            .root_operation_recovery_required,
            "the exact durable v2 root ownership token is unavailable or does not match",
        ),
        // The transaction itself finished; only the provenance it owes is
        // missing. Naming the command that discharges it keeps the root from
        // looking like it needs a hand-repaired record.
        error.ProvenancePending => api.failure(
            operation,
            .recovery,
            .root_operation_recovery_required,
            "a previous debz operation completed on this root before publishing its provenance and requires recovery; run 'debz recover' to publish it",
        ),
        error.RootIdentityMismatch => api.failure(
            operation,
            .recovery,
            .root_operation_recovery_required,
            "the active root attempt belongs to a different root",
        ),
        error.RecordCorrupt, error.UnsupportedSchema => api.failure(
            operation,
            .recovery,
            .root_operation_recovery_required,
            "the active root attempt record is unreadable",
        ),
        error.InvalidRoot, error.RootTooLong, error.NamespaceUnavailable => api.failure(
            operation,
            .usage,
            .invalid_request,
            "install root cannot host the debz operation namespace",
        ),
        else => api.failure(
            operation,
            .internal,
            .internal_error,
            "root operation coordination failed",
        ),
    };
}

const CredentialContext = struct {
    authorization: []const u8,
    scheme: []const u8,
    host: []const u8,
    port: u16,

    fn empty() CredentialContext {
        return .{ .authorization = "", .scheme = "", .host = "", .port = 0 };
    }

    fn init(
        allocator: std.mem.Allocator,
        repositories: []const repository_policy.NormalizedRepository,
        authorization: []const u8,
    ) !CredentialContext {
        if (repositories.len == 0) return error.InvalidCredentialScope;
        const first = try repository_acquisition.Uri.parse(repositories[0].uri);
        var result = try fromUri(allocator, first, authorization);
        errdefer result.deinit(allocator);
        for (repositories[1..]) |repository| {
            const uri = try repository_acquisition.Uri.parse(repository.uri);
            if (!result.matches(uri)) return error.InvalidCredentialScope;
        }
        return result;
    }

    fn fromUri(
        allocator: std.mem.Allocator,
        uri: repository_acquisition.Uri,
        authorization: []const u8,
    ) !CredentialContext {
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "http") and
            !std.ascii.eqlIgnoreCase(uri.scheme, "https"))
            return error.InvalidCredentialScope;
        const host_component = uri.host orelse return error.InvalidCredentialScope;
        var host_buffer: [4096]u8 = undefined;
        const host = host_component.toRaw(&host_buffer) catch return error.InvalidCredentialScope;
        const scheme = try allocator.dupe(u8, uri.scheme);
        errdefer allocator.free(scheme);
        const owned_host = try allocator.dupe(u8, host);
        return .{
            .authorization = authorization,
            .scheme = scheme,
            .host = owned_host,
            .port = effectivePort(uri),
        };
    }

    fn deinit(self: *CredentialContext, allocator: std.mem.Allocator) void {
        if (self.scheme.len != 0) allocator.free(self.scheme);
        if (self.host.len != 0) allocator.free(self.host);
        self.* = undefined;
    }

    fn matches(self: CredentialContext, uri: repository_acquisition.Uri) bool {
        const host_component = uri.host orelse return false;
        var host_buffer: [4096]u8 = undefined;
        const host = host_component.toRaw(&host_buffer) catch return false;
        return std.ascii.eqlIgnoreCase(self.scheme, uri.scheme) and
            std.ascii.eqlIgnoreCase(self.host, host) and
            self.port == effectivePort(uri);
    }

    fn get(context: ?*anyopaque, uri: repository_acquisition.Uri) !?repository_acquisition.Credential {
        const self: *CredentialContext = @ptrCast(@alignCast(context.?));
        if (!self.matches(uri)) return null;
        return .{ .authorization = self.authorization };
    }
};

fn effectivePort(uri: repository_acquisition.Uri) u16 {
    return uri.port orelse if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
}

const RecoveryIntent = struct {
    operation: api.Operation,
    packages: []const []const u8,
    recommends: bool,
    allow_downgrade: bool,
    repository_policy: api.RepositoryPolicy,
    conffile: api.ConffilePolicy,
    force: []const api.ForcePolicy,
    lock_wait_ms: u64,
};

fn readRecoveryIntent(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_path: []const u8,
) !std.json.Parsed(RecoveryIntent) {
    const path = try std.fmt.allocPrint(allocator, "{s}/recovery-request.json", .{state_path});
    defer allocator.free(path);
    const bytes = try readFile(allocator, io, path, 1024 * 1024);
    defer allocator.free(bytes);
    return std.json.parseFromSlice(RecoveryIntent, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
}

fn writeRecoveryIntent(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_path: []const u8,
    request: api.Request,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const writer = &output.writer;
    try writer.print(
        "{{\"operation\":\"{s}\",\"packages\":[",
        .{@tagName(request.operation)},
    );
    for (request.packages, 0..) |package, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("\"{s}\"", .{package});
    }
    try writer.print(
        "],\"recommends\":{s},\"allow_downgrade\":{s},\"repository_policy\":\"{s}\",\"conffile\":\"{s}\",\"force\":[",
        .{
            if (request.options.recommends) "true" else "false",
            if (request.options.allow_downgrade) "true" else "false",
            @tagName(request.options.repository_policy),
            @tagName(request.options.conffile),
        },
    );
    for (request.options.force, 0..) |force, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("\"{s}\"", .{@tagName(force)});
    }
    try writer.print("],\"lock_wait_ms\":{d}}}\n", .{request.options.lock_wait_ms});
    const bytes = try output.toOwnedSlice();
    defer allocator.free(bytes);
    var dir = try openAbsoluteDirectory(io, state_path);
    defer dir.close(io);
    const stage = ".recovery-request.json.new";
    dir.deleteFile(io, stage) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    {
        var file = try dir.createFile(io, stage, .{
            .exclusive = true,
            .permissions = if (@import("builtin").os.tag == .windows) .default_file else .fromMode(0o600),
            .resolve_beneath = true,
        });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        try file.sync(io);
    }

    try dir.rename(stage, dir, "recovery-request.json", io);
    try syncDirectory(dir);
}

fn deleteRecoveryIntent(io: std.Io, state_path: []const u8) !void {
    var dir = try openAbsoluteDirectory(io, state_path);
    defer dir.close(io);
    dir.deleteFile(io, "recovery-request.json") catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    try syncDirectory(dir);
}

fn syncDirectory(dir: std.Io.Dir) !void {
    switch (@import("builtin").os.tag) {
        .linux => if (std.posix.errno(std.os.linux.fsync(dir.handle)) != .SUCCESS)
            return error.Unexpected,
        else => {},
    }
}

fn readCredential(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const bytes = try readFile(allocator, io, path, 16 * 1024);
    const value = std.mem.trim(u8, bytes, " \t\r\n");
    if (value.len == 0 or std.mem.indexOfAny(u8, value, "\r\n") != null) {
        allocator.free(bytes);
        return error.InvalidCredentialFile;
    }
    if (value.ptr != bytes.ptr or value.len != bytes.len) {
        const owned = try allocator.dupe(u8, value);
        allocator.free(bytes);
        return owned;
    }
    return bytes[0..value.len];
}

fn basePolicy(options: RepositoryOptions) repository_policy.Policy {
    return .{
        .default_release = options.default_release,
        .proxy = if (options.proxy != null)
            .{ .declared = .{ .id = "cli-proxy" } }
        else
            .direct,
        .credentials = if (options.credential_reference) |value|
            .{ .id = value }
        else
            null,
        .deadlines = deadlines(options.deadline_ms),
    };
}

fn makeRuntimes(
    allocator: std.mem.Allocator,
    options: RepositoryOptions,
    configuration: *const repository_policy.Configuration,
    now_unix: i64,
    credentials: repository_acquisition.CredentialsProvider,
) ![]repository_policy.Runtime {
    var runtimes = try allocator.alloc(repository_policy.Runtime, configuration.repositories.len);
    var initialized: usize = 0;
    errdefer {
        freeRuntimeKeyrings(allocator, runtimes[0..initialized]);
        allocator.free(runtimes);
    }
    for (configuration.repositories, 0..) |repository, index| {
        const proxy = try proxyPolicy(options.proxy);
        var keyrings = try allocator.alloc(openpgp.Keyring, repository.signed_by.len);
        for (repository.signed_by, 0..) |path, key_index| keyrings[key_index] = .{ .path = path };
        const auth: repository_refresh.AuthenticationInput = .{ .in_release = .{
            .keyrings = .{ .many = keyrings },
            .accepted_primary_fingerprints = &.{},
            .verification_time = now_unix,
        } };
        runtimes[index] = .{
            .repository_id = repository.id,
            .declared_proxy = if (options.proxy != null) .{ .id = "cli-proxy" } else null,
            .declared_credentials = if (options.credential_reference) |value| .{ .id = value } else null,
            .declared_keyrings = repository.signed_by,
            .authentication = auth,
            .acquisition = .{
                .proxy = proxy,
                .deadlines = deadlines(options.deadline_ms),
                .redirect_limit = 8,
                .retry = productionRetryPolicy(),
                .credentials = credentials,
                .maximum_release_bytes = 16 * 1024 * 1024,
            },
            .refresh = .{
                .mode = if (options.offline) .cache_only else .online,
                .compression_order = &.{ .xz, .gzip, .zstd, .uncompressed },
                .by_hash_fallback = .not_found_only,
                .maximum_future_seconds = 300,
                .expiry_policy = if (repository.immutability.kind == .moving)
                    .require_valid_until
                else
                    .allow_missing_valid_until,
                .maximum_compressed_bytes = 64 * 1024 * 1024,
                .maximum_decompressed_bytes = 256 * 1024 * 1024,
                .maximum_decoder_memory = 256 * 1024 * 1024,
            },
        };
        initialized += 1;
    }
    return runtimes;
}

fn freeRuntimes(allocator: std.mem.Allocator, runtimes: []repository_policy.Runtime) void {
    freeRuntimeKeyrings(allocator, runtimes);
    allocator.free(runtimes);
}

fn freeRuntimeKeyrings(allocator: std.mem.Allocator, runtimes: []repository_policy.Runtime) void {
    for (runtimes) |runtime| switch (runtime.authentication) {
        .in_release => |authentication| switch (authentication.keyrings) {
            .many => |keyrings| allocator.free(keyrings),
            else => {},
        },
        else => {},
    };
}

fn queryAvailable(
    allocator: std.mem.Allocator,
    request: api.Request,
    refreshed: *repository_policy.RefreshResult,
) !api.Result {
    var items: std.ArrayList(api.Item) = .empty;
    for (refreshed.snapshots) |snapshot| {
        for (snapshot.snapshot.packages.records) |record| {
            const name = record.control.package.text;
            if (request.operation == .info and !containsSelector(request.packages, name)) continue;
            if (request.operation == .provides and !recordProvides(record, request.packages)) continue;
            try items.append(allocator, .{
                .package = try allocator.dupe(u8, name),
                .version = try allocator.dupe(u8, record.control.version.value.original),
                .architecture = try allocator.dupe(u8, record.control.architecture.text),
                .detail = try allocator.dupe(u8, record.location.source),
            });
        }
    }
    sortItems(items.items);
    return success(request.operation, false, "authenticated repository view queried", try items.toOwnedSlice(allocator));
}

fn recordProvides(record: anytype, requested: []const []const u8) bool {
    for (requested) |name| {
        if (std.mem.eql(u8, record.control.package.text, selectorName(name))) return true;
        if (record.control.provides) |relation| {
            for (relation.value.groups) |group|
                for (group.alternatives) |alternative|
                    if (std.mem.eql(u8, alternative.package.name.text, selectorName(name))) return true;
        }
    }
    return false;
}

/// Builds a credential-free, structured diagnostic for a failed executor
/// report. The bare `failure.diagnostic` (for example "FileNotFound") is not
/// actionable in production, so this names the failing stage, machine failure
/// code, dpkg phase, package, and lock path alongside the raw diagnostic. None
/// of these fields carry credentials (lock paths and package names are public),
/// and the embedding host additionally redacts the whole message before it is
/// surfaced, so backend errors point at the missing stage/artifact without ever
/// exposing secrets.
fn describeExecutorFailure(
    allocator: std.mem.Allocator,
    stage: []const u8,
    failure: transaction_executor.Failure,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s} failed: code={s} phase={s} package={s} lock_path={s} completed_commands={d}: {s}",
        .{
            stage,
            @tagName(failure.code),
            if (failure.phase) |phase| @tagName(phase) else "none",
            failure.package orelse "none",
            failure.lock_path orelse "none",
            failure.completed_commands,
            if (failure.diagnostic.len == 0) "no diagnostic detail" else failure.diagnostic,
        },
    );
}

fn installedPolicies(
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

fn healthyInstalledRecords(
    allocator: std.mem.Allocator,
    packages: []const dpkg_status.Package,
) ![]dpkg_status.Package {
    var records: std.ArrayList(dpkg_status.Package) = .empty;
    for (packages) |package| {
        if (package.status.isFullyInstalled()) try records.append(allocator, package);
    }
    return records.toOwnedSlice(allocator);
}

fn planRequestFromWorkflow(
    operation: api.Operation,
    workflow: ?WorkflowDirective,
    selectors: []solver.PackageSelector,
) !solver.PlanRequest {
    if (workflow) |directive| return switch (directive.operation) {
        .install => .{ .install = selectors },
        .remove => .{ .remove = selectors },
        .upgrade_all => .upgrade_all,
    };
    return switch (operation) {
        .install, .plan, .download => if (selectors.len == 0) .upgrade_all else .{ .install = selectors[0..1] },
        .remove => .{ .remove = selectors[0..1] },
        .upgrade => .{ .upgrade = selectors },
        .upgrade_all => .upgrade_all,
        .reinstall => .{ .reinstall = selectors[0] },
        .recover => .upgrade_all,
        else => error.InvalidOperation,
    };
}

fn semanticRequestDigest(
    allocator: std.mem.Allocator,
    operation: api.Operation,
    workflow: ?WorkflowDirective,
    selectors: []const solver.PackageSelector,
) ![32]u8 {
    const semantic = if (workflow) |directive|
        switch (directive.operation) {
            .install => TransactionSemanticOperation.install,
            .remove => TransactionSemanticOperation.remove,
            .upgrade_all => TransactionSemanticOperation.upgrade_all,
        }
    else switch (operation) {
        .install, .plan, .download => if (selectors.len == 0)
            TransactionSemanticOperation.upgrade_all
        else
            TransactionSemanticOperation.install,
        .remove => TransactionSemanticOperation.remove,
        .upgrade => TransactionSemanticOperation.upgrade,
        .upgrade_all => TransactionSemanticOperation.upgrade_all,
        .reinstall => TransactionSemanticOperation.reinstall,
        else => return error.InvalidOperation,
    };
    const canonical = try allocator.dupe(solver.PackageSelector, selectors);
    defer allocator.free(canonical);
    std.mem.sort(solver.PackageSelector, canonical, {}, lessWorkflowSelector);

    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-semantic-transaction-request-v1\x00");
    hash.update(@tagName(semantic));
    hash.update("\x00");
    for (canonical) |selector| {
        hashLengthPrefixed(&hash, selector.name);
        hashOptionalText(&hash, selector.architecture);
        hashOptionalText(&hash, selector.version);
    }
    return hash.finalResult();
}

pub fn workflowSemanticRequestDigest(
    allocator: std.mem.Allocator,
    operation: WorkflowSemanticOperation,
    selectors: []const solver.PackageSelector,
) ![32]u8 {
    return semanticRequestDigest(
        allocator,
        .recover,
        .{
            .operation = operation,
            .mode = .recover,
            .defer_recovery_clear = false,
        },
        selectors,
    );
}

pub fn workflowProductRequestDigest(
    allocator: std.mem.Allocator,
    operation: WorkflowSemanticOperation,
    mode: WorkflowMode,
    selectors: []const solver.PackageSelector,
    options: api.CommonOptions,
) ![32]u8 {
    const canonical = try allocator.dupe(solver.PackageSelector, selectors);
    defer allocator.free(canonical);
    std.mem.sort(solver.PackageSelector, canonical, {}, lessWorkflowSelector);
    const packages = try allocator.alloc([]const u8, canonical.len);
    defer allocator.free(packages);
    var formatted: usize = 0;
    errdefer for (packages[0..formatted]) |package| allocator.free(package);
    for (canonical, 0..) |selector, index| {
        packages[index] = try formatSelector(allocator, selector);
        formatted += 1;
    }
    defer for (packages) |package| allocator.free(package);
    return productRequestDigest(.{
        .operation = workflowSurfaceOperation(operation, mode),
        .packages = packages,
        .options = options,
    });
}

fn hashLengthPrefixed(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    var length_buffer: [32]u8 = undefined;
    const length = std.fmt.bufPrint(&length_buffer, "{d}:", .{value.len}) catch unreachable;
    hash.update(length);
    hash.update(value);
}

fn hashOptionalText(hash: *std.crypto.hash.sha2.Sha256, value: ?[]const u8) void {
    if (value) |text| {
        hash.update("\x01");
        hashLengthPrefixed(hash, text);
    } else {
        hash.update("\x00");
    }
}

fn formatSelector(allocator: std.mem.Allocator, selector: solver.PackageSelector) ![]u8 {
    if (selector.name.len == 0 or
        (selector.version != null and selector.version.?.len == 0) or
        (selector.architecture != null and selector.architecture.?.len == 0))
        return error.InvalidSelector;
    if (selector.architecture) |architecture| {
        if (selector.version) |version|
            return std.fmt.allocPrint(allocator, "{s}:{s}={s}", .{ selector.name, architecture, version });
        return std.fmt.allocPrint(allocator, "{s}:{s}", .{ selector.name, architecture });
    }
    if (selector.version) |version|
        return std.fmt.allocPrint(allocator, "{s}={s}", .{ selector.name, version });
    return allocator.dupe(u8, selector.name);
}

fn lessWorkflowSelector(
    _: void,
    left: solver.PackageSelector,
    right: solver.PackageSelector,
) bool {
    const name_order = std.mem.order(u8, left.name, right.name);
    if (name_order != .eq) return name_order == .lt;
    const architecture_order = workflowOptionalTextOrder(left.architecture, right.architecture);
    if (architecture_order != .eq) return architecture_order == .lt;
    return workflowOptionalTextOrder(left.version, right.version) == .lt;
}

fn workflowOptionalTextOrder(left: ?[]const u8, right: ?[]const u8) std.math.Order {
    if (left == null and right != null) return .lt;
    if (left != null and right == null) return .gt;
    if (left == null) return .eq;
    return std.mem.order(u8, left.?, right.?);
}

fn stringSlicesEqual(left: []const []const u8, right: []const []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_value, right_value|
        if (!std.mem.eql(u8, left_value, right_value)) return false;
    return true;
}

fn parseSelector(value: []const u8) solver.PackageSelector {
    var name_arch = value;
    var version: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, value, '=')) |equals| {
        name_arch = value[0..equals];
        version = value[equals + 1 ..];
    }
    var name = name_arch;
    var architecture: ?[]const u8 = null;
    if (std.mem.lastIndexOfScalar(u8, name_arch, ':')) |colon| {
        name = name_arch[0..colon];
        architecture = name_arch[colon + 1 ..];
    }
    return .{ .name = name, .version = version, .architecture = architecture };
}

fn selectorName(value: []const u8) []const u8 {
    return parseSelector(value).name;
}

fn executionPolicy(allocator: std.mem.Allocator, request: api.Request) !transaction_executor.Policy {
    const forces = try allocator.alloc(transaction_executor.ForceRisk, request.options.force.len);
    for (request.options.force, 0..) |force, index| forces[index] = switch (force) {
        .depends => .depends,
        .depends_version => .depends_version,
        .break_replaces => .break_replaces,
        .overwrite => .overwrite,
        .overwrite_dir => .overwrite_dir,
        .remove_reinstreq => .remove_reinstreq,
    };
    return .{
        .conffile = switch (request.options.conffile) {
            .keep_existing => .keep_existing,
            .use_package_version => .use_package_version,
            .unspecified => .keep_existing,
        },
        .locks = .{ .wait_ms = request.options.lock_wait_ms },
        .risk = .{
            .allow_host_root = false,
            .force = forces,
        },
    };
}

fn proxyPolicy(value: ?[]const u8) !repository_acquisition.ProxyPolicy {
    const text = value orelse return .direct;
    const uri = try repository_acquisition.Uri.parse(text);
    if (uri.user != null or uri.password != null) return error.CredentialBearingProxy;
    const endpoint: repository_acquisition.ProxyEndpoint = .{ .uri = uri };
    return .{ .http = endpoint, .https = endpoint };
}

fn deadlines(overall: ?u64) repository_acquisition.Deadlines {
    const bounded = overall orelse {
        const unbounded: u64 = @intCast(std.math.maxInt(i64));
        return .{
            .connect_ms = unbounded,
            .read_ms = unbounded,
            .overall_ms = unbounded,
        };
    };
    return .{
        .connect_ms = @min(bounded, 10_000),
        .read_ms = @min(bounded, 30_000),
        .overall_ms = bounded,
    };
}

test "product API operations exhaustively deny host-root execution" {
    try std.testing.expect(!live_root.host_root_allowed);
    try std.testing.expect(!std.mem.eql(u8, live_root.logical_root_path, "/"));
    inline for (std.meta.fields(api.Operation)) |field| {
        const operation: api.Operation = @enumFromInt(field.value);
        var request: api.Request = .{
            .operation = operation,
            .options = .{
                .install_root = "/",
                .cache_path = "/cache",
                .state_path = "/state",
                .architecture = "amd64",
            },
        };
        const policy = try executionPolicy(std.testing.allocator, request);
        defer std.testing.allocator.free(policy.risk.force);
        try std.testing.expect(!policy.risk.allow_host_root);
        request.options.install_root = live_root.logical_root_path;
        const alternate = try executionPolicy(std.testing.allocator, request);
        defer std.testing.allocator.free(alternate.risk.force);
        try std.testing.expect(!alternate.risk.allow_host_root);
    }
}

test "production acquisition is unbounded unless a deadline is explicit" {
    const unbounded: u64 = @intCast(std.math.maxInt(i64));
    try std.testing.expectEqual(
        repository_acquisition.Deadlines{
            .connect_ms = unbounded,
            .read_ms = unbounded,
            .overall_ms = unbounded,
        },
        deadlines(null),
    );
    try std.testing.expectEqual(
        repository_acquisition.Deadlines{
            .connect_ms = 10_000,
            .read_ms = 30_000,
            .overall_ms = 60_000,
        },
        deadlines(60_000),
    );
}

fn productionRetryPolicy() repository_acquisition.RetryPolicy {
    return .{ .max_attempts = 6, .backoff_ms = productionRetryBackoff };
}

fn productionRetryBackoff(attempt: u16) u64 {
    return @as(u64, attempt) * 2_000;
}

fn sourceFormat(path: []const u8) source.Format {
    return if (std.mem.endsWith(u8, path, ".sources")) .deb822 else .legacy;
}

fn readFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    maximum: usize,
) ![]u8 {
    const parent = std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath;
    const leaf = std.fs.path.basename(path);
    var dir = try openAbsoluteDirectory(io, parent);
    defer dir.close(io);
    var file = try dir.openFile(io, leaf, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(maximum));
}

fn validateRegularFile(io: std.Io, path: []const u8) !void {
    var file = try openRegularFileAbsoluteNoFollow(io, path);
    defer file.close(io);
}

fn openRegularFileAbsoluteNoFollow(io: std.Io, path: []const u8) !std.Io.File {
    const parent = std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath;
    const leaf = std.fs.path.basename(path);
    var dir = try openAbsoluteDirectory(io, parent);
    defer dir.close(io);
    const file = package_acquisition.openRegularFileNoFollow(dir, io, leaf) catch |err|
        return switch (err) {
            error.IsDir,
            error.SymLinkLoop,
            error.NotDir,
            error.NotRegularFile,
            error.AccessDenied,
            error.PermissionDenied,
            error.PipeBusy,
            error.NoDevice,
            error.DeviceBusy,
            error.WouldBlock,
            => error.NotRegularFile,
            else => |other| other,
        };
    errdefer file.close(io);
    const stat = file.stat(io) catch return error.NotRegularFile;
    if (stat.kind != .file) return error.NotRegularFile;
    return file;
}

fn readLock(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !exact_lock.OwnedLock {
    const bytes = try readFile(allocator, io, path, exact_lock.maximum_document_bytes);
    defer allocator.free(bytes);
    return exact_lock.decode(allocator, bytes, exact_lock.maximum_document_bytes);
}

fn writeLock(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    lock: exact_lock.Lock,
) !void {
    const parent = std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath;
    const leaf = std.fs.path.basename(path);
    var dir = try openAbsoluteDirectory(io, parent);
    defer dir.close(io);
    const store = try exact_lock.Store.init(io, dir, leaf);
    try store.writeAtomic(allocator, lock);
}

fn lockFromPlan(
    allocator: std.mem.Allocator,
    request: api.Request,
    refreshed: *repository_policy.RefreshResult,
    installed: []const dpkg_status.Package,
    plan: solver.Plan,
    semantic_request_digest: [32]u8,
    solver_policy_digest: [32]u8,
) !exact_lock.OwnedLock {
    var packages: std.ArrayList(exact_lock.Package) = .empty;
    defer packages.deinit(allocator);
    var repository_ids: std.ArrayList([64]u8) = .empty;
    defer repository_ids.deinit(allocator);

    for (plan.actions) |action| {
        const origin = try authenticatedPackageOrigin(action.selected_origin_v2 orelse continue);
        const repository = findRepositoryInput(refreshed.universe.repositories, origin.repository_id) orelse
            return error.MissingRepository;
        const record = repository.packages.records[origin.record_index];
        var repository_id: [64]u8 = undefined;
        @memcpy(&repository_id, origin.repository_id.slice());
        var seen = false;
        for (repository_ids.items) |existing| {
            if (std.mem.eql(u8, &existing, &repository_id)) {
                seen = true;
                break;
            }
        }
        if (!seen) try repository_ids.append(allocator, repository_id);
        try packages.append(allocator, .{
            .name = action.package,
            .version = action.version,
            .architecture = action.architecture,
            .repository_id = repository_id,
            .repository_snapshot_sha256 = repository.authenticated_snapshot_sha256 orelse
                return error.MissingRepository,
            .sha256 = record.transport.sha256.bytes,
            .declared_size = record.transport.size.value,
            .retention = if (action.requested) .requested else .dependency,
            .dpkg_selection_hold = false,
        });
    }
    for (installed) |package| {
        if (!package.status.isFullyInstalled() or
            planChangesIdentity(plan.actions, package.name.value, package.architecture.value))
            continue;
        const origin = findRetainedOrigin(
            refreshed.universe.repositories,
            package.name.value,
            package.version.spelling.value,
            package.architecture.value,
        ) orelse return error.RetainedPackageUnavailable;
        const repository = findRepositoryInput(refreshed.universe.repositories, origin.repository_id) orelse
            return error.MissingRepository;
        const record = repository.packages.records[origin.record_index];
        var repository_id: [64]u8 = undefined;
        @memcpy(&repository_id, origin.repository_id.slice());
        var seen = false;
        for (repository_ids.items) |existing| {
            if (std.mem.eql(u8, &existing, &repository_id)) {
                seen = true;
                break;
            }
        }
        if (!seen) try repository_ids.append(allocator, repository_id);
        try packages.append(allocator, .{
            .name = package.name.value,
            .version = package.version.spelling.value,
            .architecture = package.architecture.value,
            .repository_id = repository_id,
            .repository_snapshot_sha256 = repository.authenticated_snapshot_sha256 orelse
                return error.MissingRepository,
            .sha256 = record.transport.sha256.bytes,
            .declared_size = record.transport.size.value,
            .retention = .retained,
            .dpkg_selection_hold = package.status.want == .hold,
        });
    }
    if (packages.items.len == 0) {
        for (refreshed.universe.repositories) |repository| {
            var repository_id: [64]u8 = undefined;
            @memcpy(&repository_id, repository.repository_id.slice());
            try repository_ids.append(allocator, repository_id);
        }
    }

    var repositories: std.ArrayList(exact_lock.Repository) = .empty;
    defer repositories.deinit(allocator);
    var signer_storage: std.ArrayList([][20]u8) = .empty;
    defer {
        for (signer_storage.items) |signers| allocator.free(signers);
        signer_storage.deinit(allocator);
    }

    for (repository_ids.items) |repository_id| {
        const snapshot = findSnapshot(refreshed.snapshots, repository_id) orelse
            return error.MissingRepository;
        const evidence = snapshot.snapshot.provenance.authentication_evidence;
        var signers = try allocator.alloc([20]u8, evidence.signatures.len);
        var signer_count: usize = 0;
        for (evidence.signatures) |signature| if (signature.primary_fingerprint) |fingerprint| {
            signers[signer_count] = fingerprint;
            signer_count += 1;
        };
        if (signer_count == 0) {
            allocator.free(signers);
            return error.MissingRepository;
        }
        try signer_storage.append(allocator, signers);
        try repositories.append(allocator, .{
            .id = repository_id,
            .snapshot_sha256 = repository_refresh.snapshotDigest(snapshot),
            .release_sha256 = snapshot.snapshot.provenance.release_digest.bytes,
            .index_sha256 = snapshot.snapshot.provenance.index_digest.bytes,
            .signer_fingerprints = signers[0..signer_count],
        });
    }

    return exact_lock.create(allocator, .{
        .target_architecture = request.options.architecture,
        .request_sha256 = semantic_request_digest,
        .policy_sha256 = solver_policy_digest,
        .repositories = repositories.items,
        .packages = packages.items,
        .authenticated_metadata = true,
    });
}

fn planChangesIdentity(
    actions: []const solver.PlanAction,
    name: []const u8,
    architecture: []const u8,
) bool {
    for (actions) |action| {
        if (std.mem.eql(u8, action.package, name) and
            std.mem.eql(u8, action.architecture, architecture))
            return true;
    }
    return false;
}

fn findRetainedOrigin(
    repositories: []const solver.RepositoryInput,
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
) ?solver.AuthenticatedRepositoryPackageOrigin {
    var best: ?solver.AuthenticatedRepositoryPackageOrigin = null;
    for (repositories) |repository| {
        for (repository.packages.records, 0..) |record, index| {
            if (!std.mem.eql(u8, record.control.package.text, name) or
                !std.mem.eql(u8, record.control.version.value.original, version) or
                !std.mem.eql(u8, record.control.architecture.text, architecture))
                continue;
            const candidate: solver.AuthenticatedRepositoryPackageOrigin = .{
                .repository_id = repository.repository_id,
                .repository_priority = repository.priority,
                .record_index = index,
                .package = record.control.package.text,
                .version = record.control.version.value.original,
                .architecture = record.control.architecture.text,
                .source_location = record.location.source,
            };
            if (best == null or betterRetainedOrigin(candidate, best.?)) best = candidate;
        }
    }
    return best;
}

fn betterRetainedOrigin(
    candidate: solver.AuthenticatedRepositoryPackageOrigin,
    current: solver.AuthenticatedRepositoryPackageOrigin,
) bool {
    if (candidate.repository_priority != current.repository_priority)
        return candidate.repository_priority > current.repository_priority;
    return std.mem.order(
        u8,
        candidate.repository_id.slice(),
        current.repository_id.slice(),
    ) == .lt;
}

fn findSnapshot(
    snapshots: []const repository_refresh.AuthenticatedResult,
    repository_id: [64]u8,
) ?*const repository_refresh.AuthenticatedResult {
    for (snapshots) |*snapshot| {
        if (std.mem.eql(u8, snapshot.snapshot.provenance.repository_id.slice(), &repository_id))
            return snapshot;
    }
    return null;
}

fn writeExecutionProvenance(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: api.Request,
    refreshed: *repository_policy.RefreshResult,
    lock: exact_lock.Lock,
    report: transaction_executor.Report,
    status: transaction_recovery.StatusReader,
    verify: *transaction_provenance.VerifyDiagnostic,
) !void {
    // The lock records only repositories that actually supplied a package, so the
    // evidence has to be drawn from the lock rather than from every refreshed
    // snapshot; provenance keeps a one-to-one binding with the lock.
    const repositories = try allocator.alloc(transaction_provenance.RepositoryEvidence, lock.repositories.len);
    for (lock.repositories, 0..) |locked, index| {
        const snapshot = findSnapshot(refreshed.snapshots, locked.id) orelse
            return error.MissingRepository;
        const evidence = snapshot.snapshot.provenance.authentication_evidence;
        const signers = try allocator.alloc([20]u8, evidence.signatures.len);
        var signer_count: usize = 0;
        for (evidence.signatures) |signature| if (signature.primary_fingerprint) |fingerprint| {
            signers[signer_count] = fingerprint;
            signer_count += 1;
        };
        repositories[index] = .{
            .source_config_id = locked.id,
            .snapshot_sha256 = repository_refresh.snapshotDigest(snapshot),
            .release_sha256 = snapshot.snapshot.provenance.release_digest.bytes,
            .signature_sha256 = if (evidence.signature_digest) |digest| digest.bytes else null,
            .metadata_sha256 = snapshot.snapshot.provenance.index_digest.bytes,
            .signer_fingerprints = signers[0..signer_count],
            .signature_verified = true,
        };
    }
    const packages = try allocator.alloc(transaction_provenance.PackageEvidence, lock.packages.len);
    for (lock.packages, 0..) |package, index| packages[index] = .{
        .name = package.name,
        .version = package.version,
        .architecture = package.architecture,
        .repository_id = package.repository_id,
        .repository_snapshot_sha256 = package.repository_snapshot_sha256,
        .package_sha256 = package.sha256,
        .cas_sha256 = package.sha256,
        .declared_size = package.declared_size,
    };
    try transaction_provenance.verifyLockEvidence(lock, repositories, packages, verify);
    const status_bytes = try status.read(allocator, request.options.install_root, 64 * 1024 * 1024);
    defer allocator.free(status_bytes);
    var status_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(status_bytes, &status_digest, .{});
    var provenance = try transaction_provenance.createFromExecution(allocator, .{
        .exact_lock = &lock,
        .target_architecture = request.options.architecture,
        .request_sha256 = lock.request_sha256,
        .solver_policy_sha256 = lock.policy_sha256,
        .repositories = repositories,
        .packages = packages,
        .journal_steps = &.{},
        .final_verification = .{
            .status = .exact_match,
            .installed_state_sha256 = status_digest,
            .package_origins_sha256 = lock.digest_sha256,
            .detail = "executor and exact-lock verification completed",
        },
    }, report);
    defer provenance.deinit();
    var dir = try openAbsoluteDirectory(io, request.options.state_path);
    defer dir.close(io);
    const store = try transaction_provenance.Store.init(io, dir, transaction_result_name);
    try store.writeAtomic(allocator, provenance.result);
}

fn planResult(allocator: std.mem.Allocator, operation: api.Operation, plan: solver.Plan) !api.Result {
    return planResultChanged(allocator, operation, plan, false, "transaction plan produced");
}

fn planResultChanged(
    allocator: std.mem.Allocator,
    operation: api.Operation,
    plan: solver.Plan,
    changed: bool,
    summary: []const u8,
) !api.Result {
    var items = try allocator.alloc(api.Item, plan.actions.len);
    for (plan.actions, 0..) |action, index| items[index] = .{
        .package = try allocator.dupe(u8, action.package),
        .version = try allocator.dupe(u8, action.version),
        .architecture = try allocator.dupe(u8, action.architecture),
        .detail = @tagName(action.kind),
    };
    return success(operation, changed, summary, items);
}

fn success(operation: api.Operation, changed: bool, summary: []const u8, items: []const api.Item) api.Result {
    return .{
        .operation = operation,
        .exit_status = .success,
        .changed = changed,
        .summary = summary,
        .items = items,
    };
}

fn sortItems(items: []api.Item) void {
    std.mem.sort(api.Item, items, {}, struct {
        fn lessThan(_: void, left: api.Item, right: api.Item) bool {
            const package_order = std.mem.order(u8, left.package, right.package);
            if (package_order != .eq) return package_order == .lt;
            const architecture_order = optionalOrder(left.architecture, right.architecture);
            if (architecture_order != .eq) return architecture_order == .lt;
            const version_order = optionalOrder(left.version, right.version);
            if (version_order != .eq) return version_order == .lt;
            return optionalOrder(left.detail, right.detail) == .lt;
        }

        fn optionalOrder(left: ?[]const u8, right: ?[]const u8) std.math.Order {
            if (left == null) return if (right == null) .eq else .lt;
            if (right == null) return .gt;
            return std.mem.order(u8, left.?, right.?);
        }
    }.lessThan);
}

fn openAbsoluteDirectory(io: std.Io, path: []const u8) !std.Io.Dir {
    if (!std.fs.path.isAbsolute(path)) return error.InvalidAbsolutePath;
    var current = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false });
    errdefer current.close(io);
    if (std.mem.eql(u8, path, "/")) return current;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.InvalidAbsolutePath;
        const next = try current.openDir(io, component, .{ .follow_symlinks = false });
        current.close(io);
        current = next;
    }
    return current;
}

fn openOrCreateAbsoluteDirectory(io: std.Io, path: []const u8) !std.Io.Dir {
    if (!std.fs.path.isAbsolute(path)) return error.InvalidAbsolutePath;
    var current = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false });
    errdefer current.close(io);
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.InvalidAbsolutePath;
        current.createDir(io, component, .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const next = try current.openDir(io, component, .{ .follow_symlinks = false });
        current.close(io);
        current = next;
    }
    return current;
}

fn mapRuntimeError(operation: api.Operation, err: anyerror) api.Result {
    return switch (err) {
        error.FileNotFound,
        error.InvalidRepositoryConfig,
        error.InvalidInstalledState,
        error.CredentialBearingProxy,
        error.InvalidCredentialFile,
        error.InvalidAbsolutePath,
        error.InvalidCredentialScope,
        => api.failure(operation, .usage, .configuration_required, @errorName(err)),
        error.CacheMiss, error.CorruptObject => api.failure(operation, .download, .offline_cache_miss, @errorName(err)),
        error.NoValidAcceptedSignature,
        error.WrongSigningKey,
        error.InvalidSignature,
        error.MalformedKeyring,
        error.NoKeyrings,
        => api.failure(operation, .authentication, .repository_authentication_failed, @errorName(err)),
        error.PackageTooLarge, error.SizeMismatch, error.DigestMismatch => api.failure(operation, .download, .download_failed, @errorName(err)),
        error.InvalidPackagePayload => api.failure(operation, .download, .download_failed, @errorName(err)),
        else => api.failure(operation, .internal, .internal_error, @errorName(err)),
    };
}

test "production backend rejects unavailable native transaction before repository work" {
    var backend: Backend = .{
        .io = std.testing.io,
        .transaction_backend = .native,
    };
    const result = try api.execute(std.testing.allocator, .{
        .operation = .install,
        .packages = &.{"demo"},
        .options = .{
            .install_root = "/native-backend-unavailable-root",
            .cache_path = "/native-backend-unavailable-cache",
            .state_path = "/native-backend-unavailable-state",
            .architecture = "amd64",
            .assume_yes = true,
            .noninteractive = true,
            .conffile = .keep_existing,
        },
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.unavailable, result.exit_status);
    try std.testing.expectEqual(@as(usize, 1), result.diagnostic_count);
    try std.testing.expectEqual(
        api.ErrorId.transaction_backend_unavailable,
        result.diagnostics[0].id,
    );
    try std.testing.expect(!result.changed);
}

fn containsString(values: []const []const u8, target: []const u8) bool {
    for (values) |value| if (std.mem.eql(u8, value, target)) return true;
    return false;
}

fn usesPackageTransaction(operation: api.Operation) bool {
    return switch (operation) {
        .install, .remove, .upgrade, .upgrade_all, .reinstall, .recover => true,
        .refresh,
        .download,
        .plan,
        .list_installed,
        .list_available,
        .info,
        .provides,
        .why,
        .clean,
        => false,
    };
}

fn containsSelector(values: []const []const u8, target: []const u8) bool {
    for (values) |value| if (std.mem.eql(u8, selectorName(value), target)) return true;
    return false;
}

fn findRepositoryInput(
    repositories: []const solver.RepositoryInput,
    id: source.RepositoryId,
) ?solver.RepositoryInput {
    for (repositories) |repository|
        if (std.mem.eql(u8, repository.repository_id.slice(), id.slice())) return repository;
    return null;
}

fn authenticatedPackageOrigin(
    origin: solver.TaggedPackageOrigin,
) !solver.AuthenticatedRepositoryPackageOrigin {
    return switch (origin) {
        .authenticated_repository => |repository| repository,
        .local_artifact => error.UnsupportedLocalArtifactOrigin,
    };
}

fn findNormalized(
    repositories: []const repository_policy.NormalizedRepository,
    id: source.RepositoryId,
) ?repository_policy.NormalizedRepository {
    for (repositories) |repository|
        if (std.mem.eql(u8, repository.id.slice(), id.slice())) return repository;
    return null;
}

fn findPublishedState(
    states: []const repository_policy.PublishedRepositoryState,
    id: source.RepositoryId,
) ?repository_policy.PublishedRepositoryState {
    for (states) |state|
        if (std.mem.eql(u8, state.repository_id.slice(), id.slice())) return state;
    return null;
}

fn fixedNow(context: ?*anyopaque) i64 {
    return @as(*const i64, @ptrCast(@alignCast(context.?))).*;
}

fn realNow(io: std.Io) i64 {
    const instant = std.Io.Clock.real.now(io);
    return @intCast(@divFloor(instant.nanoseconds, std.time.ns_per_s));
}

const TestProcess = struct {
    io: std.Io,
    dir: std.Io.Dir,
    calls: usize = 0,

    fn interface(self: *TestProcess) transaction_executor.ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(context: *anyopaque, invocation: transaction_executor.Invocation) !transaction_executor.ProcessResult {
        const self: *TestProcess = @ptrCast(@alignCast(context));
        self.calls += 1;
        if (invocation.phase == .remove) try self.dir.writeFile(self.io, .{
            .sub_path = "root/var/lib/dpkg/status",
            .data = "",
        });
        return .{ .termination = .{ .exited = 0 } };
    }
};

const FailOnceProcess = struct {
    io: std.Io,
    dir: std.Io.Dir,
    calls: usize = 0,

    fn interface(self: *FailOnceProcess) transaction_executor.ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(
        context: *anyopaque,
        invocation: transaction_executor.Invocation,
    ) !transaction_executor.ProcessResult {
        const self: *FailOnceProcess = @ptrCast(@alignCast(context));
        self.calls += 1;
        if (self.calls == 1)
            return .{ .termination = .{ .exited = 1 } };
        _ = invocation;
        try self.dir.writeFile(self.io, .{
            .sub_path = "root/var/lib/dpkg/status",
            .data = "",
        });
        return .{ .termination = .{ .exited = 0 } };
    }
};

const TestCompletionCrash = struct {
    point: CompletionPoint,
    triggered: bool = false,

    fn interface(self: *TestCompletionCrash) CompletionCrash {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(context: *anyopaque, point: CompletionPoint) !void {
        const self: *TestCompletionCrash = @ptrCast(@alignCast(context));
        if (!self.triggered and point == self.point) {
            self.triggered = true;
            return error.InjectedCompletionCrash;
        }
    }
};

const TestRootBindingBarrier = struct {
    point: RootBindingPoint,
    reached: std.atomic.Value(bool) = .init(false),
    released: std.atomic.Value(bool) = .init(false),

    fn interface(self: *TestRootBindingBarrier) RootBindingSync {
        return .{ .context = self, .hitFn = hit };
    }

    fn hit(context: *anyopaque, point: RootBindingPoint) !void {
        const self: *TestRootBindingBarrier = @ptrCast(@alignCast(context));
        if (point != self.point) return;
        self.reached.store(true, .release);
        while (!self.released.load(.acquire))
            std.atomic.spinLoopHint();
    }

    fn wait(self: *TestRootBindingBarrier, wait_ms: u64) !void {
        const started = std.Io.Clock.awake.now(std.testing.io);
        while (!self.reached.load(.acquire)) {
            const elapsed = started.durationTo(
                std.Io.Clock.awake.now(std.testing.io),
            ).toMilliseconds();
            if (elapsed >= wait_ms) return error.TestTimedOut;
            std.atomic.spinLoopHint();
        }
    }

    fn release(self: *TestRootBindingBarrier) void {
        self.released.store(true, .release);
    }
};

const ProductionWorkflowFixture = struct {
    allocator: std.mem.Allocator,
    source_path: []u8,
    keyring_path: []u8,
    source_paths: [1][]const u8,
    keyring_paths: [1][]const u8,
    install_root: []u8,
    cache_path: []u8,
    state_path: []u8,
    lock_path: []u8,
    second_lock_path: []u8,

    fn init(
        allocator: std.mem.Allocator,
        directory: *std.testing.TmpDir,
        status: []const u8,
    ) !ProductionWorkflowFixture {
        const fixture = @import("fixtures/openpgp.zig");
        return initWithRepository(
            allocator,
            directory,
            status,
            &fixture.repository_in_release,
            &fixture.repository_packages,
            &fixture.keyring,
        );
    }

    fn initWithRepository(
        allocator: std.mem.Allocator,
        directory: *std.testing.TmpDir,
        status: []const u8,
        in_release: []const u8,
        packages: []const u8,
        keyring: []const u8,
    ) !ProductionWorkflowFixture {
        try directory.dir.createDirPath(std.testing.io, "repo/dists/stable/main/binary-amd64");
        try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");
        try directory.dir.createDirPath(std.testing.io, "root/var/lib/debz");
        try directory.dir.createDirPath(std.testing.io, "state");
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "repo/dists/stable/InRelease",
            .data = in_release,
        });
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "repo/dists/stable/main/binary-amd64/Packages",
            .data = packages,
        });
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "keyring.gpg",
            .data = keyring,
        });
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "root/var/lib/dpkg/status",
            .data = status,
        });

        var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
        const root = real_buffer[0..real_length];
        const source_path = try std.fmt.allocPrint(allocator, "{s}/sources.list", .{root});
        errdefer allocator.free(source_path);
        const keyring_path = try std.fmt.allocPrint(allocator, "{s}/keyring.gpg", .{root});
        errdefer allocator.free(keyring_path);
        const repository_path = try std.fmt.allocPrint(allocator, "{s}/repo", .{root});
        defer allocator.free(repository_path);
        const source_bytes = try std.fmt.allocPrint(
            allocator,
            "deb [arch=amd64 signed-by={s}] file://{s} stable main\n",
            .{ keyring_path, repository_path },
        );
        defer allocator.free(source_bytes);
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "sources.list",
            .data = source_bytes,
        });
        const install_root = try std.fmt.allocPrint(allocator, "{s}/root", .{root});
        errdefer allocator.free(install_root);
        const cache_path = try std.fmt.allocPrint(allocator, "{s}/cache", .{root});
        errdefer allocator.free(cache_path);
        const state_path = try std.fmt.allocPrint(allocator, "{s}/state", .{root});
        errdefer allocator.free(state_path);
        const lock_path = try std.fmt.allocPrint(allocator, "{s}/batch-lock.json", .{root});
        errdefer allocator.free(lock_path);
        const second_lock_path = try std.fmt.allocPrint(allocator, "{s}/single-lock.json", .{root});
        errdefer allocator.free(second_lock_path);
        return .{
            .allocator = allocator,
            .source_path = source_path,
            .keyring_path = keyring_path,
            .source_paths = .{source_path},
            .keyring_paths = .{keyring_path},
            .install_root = install_root,
            .cache_path = cache_path,
            .state_path = state_path,
            .lock_path = lock_path,
            .second_lock_path = second_lock_path,
        };
    }

    fn deinit(self: *ProductionWorkflowFixture) void {
        self.allocator.free(self.source_path);
        self.allocator.free(self.keyring_path);
        self.allocator.free(self.install_root);
        self.allocator.free(self.cache_path);
        self.allocator.free(self.state_path);
        self.allocator.free(self.lock_path);
        self.allocator.free(self.second_lock_path);
        self.* = undefined;
    }

    fn options(self: *const ProductionWorkflowFixture) api.CommonOptions {
        return .{
            .install_root = self.install_root,
            .source_paths = &self.source_paths,
            .keyring_paths = &self.keyring_paths,
            .cache_path = self.cache_path,
            .state_path = self.state_path,
            .architecture = "amd64",
        };
    }
};

const DeferredAckContender = struct {
    backend: *Backend,
    request: WorkflowRequest,
    status: ?api.ExitStatus = null,
    started: std.atomic.Value(bool) = .init(false),
    finished: std.atomic.Value(bool) = .init(false),
    stall: bool = false,

    fn run(self: *DeferredAckContender) void {
        self.started.store(true, .release);
        defer self.finished.store(true, .release);
        if (self.stall) {
            while (true) {
                var request: std.os.linux.timespec = .{
                    .sec = 1,
                    .nsec = 0,
                };
                var remaining: std.os.linux.timespec = undefined;
                _ = std.os.linux.nanosleep(&request, &remaining);
            }
        }
        const result = self.backend.executeWorkflow(
            std.heap.page_allocator,
            self.request,
        ) catch {
            self.status = .internal;
            return;
        };

        self.status = result.exit_status;
    }
};

const OverlapStallRole = enum { none, owner, distinct, identical };

fn waitForContender(
    flag: *const std.atomic.Value(bool),
    wait_ms: u64,
) !void {
    const started = std.Io.Clock.awake.now(std.testing.io);
    while (!flag.load(.acquire)) {
        const elapsed = started.durationTo(
            std.Io.Clock.awake.now(std.testing.io),
        ).toMilliseconds();
        if (elapsed >= wait_ms) return error.TestTimedOut;
        std.atomic.spinLoopHint();
    }
}

fn backendRootRecord(
    allocator: std.mem.Allocator,
    directory: *std.testing.TmpDir,
) !?root_operation.OwnedRecord {
    const bytes = directory.dir.readFileAlloc(
        std.testing.io,
        "root/" ++ root_operation.record_path,
        allocator,
        .limited(root_operation.maximum_document_bytes),
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);
    return try root_operation.decode(
        allocator,
        bytes,
        root_operation.maximum_document_bytes,
    );
}

fn backendRootCompletion(
    allocator: std.mem.Allocator,
    directory: *std.testing.TmpDir,
) !?root_operation_completion.OwnedDocument {
    const bytes = directory.dir.readFileAlloc(
        std.testing.io,
        "root/" ++ root_operation_completion.document_path,
        allocator,
        .limited(root_operation_completion.maximum_document_bytes),
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);
    return try root_operation_completion.decode(
        allocator,
        bytes,
        root_operation_completion.maximum_document_bytes,
    );
}

fn backendDeferredMarker(
    allocator: std.mem.Allocator,
    directory: *std.testing.TmpDir,
) !?root_operation.DeferredAcknowledgment {
    const bytes = directory.dir.readFileAlloc(
        std.testing.io,
        "root/" ++ root_operation.deferred_ack_path,
        allocator,
        .limited(root_operation.maximum_document_bytes),
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);
    return try root_operation.decodeDeferredAcknowledgment(allocator, bytes);
}

test "production workflow reconciliation claims are distinct durable exclusive and crash convergent" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const ClaimCase = struct {
        point: CompletionPoint,
        pre_mutation: bool,
    };
    inline for ([_]ClaimCase{
        .{
            .point = .before_reconciliation_marker_publish,
            .pre_mutation = false,
        },
        .{
            .point = .after_reconciliation_marker_publish,
            .pre_mutation = false,
        },
        .{
            .point = .before_reconciliation_marker_publish,
            .pre_mutation = true,
        },
        .{
            .point = .after_reconciliation_marker_publish,
            .pre_mutation = true,
        },
    }) |claim_case| {
        const point = claim_case.point;
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        var fixture = try ProductionWorkflowFixture.init(
            allocator,
            &directory,
            "Package: removable\nVersion: 1\nArchitecture: amd64\n" ++
                "Status: install ok installed\n\n",
        );
        defer fixture.deinit();
        var process = TestProcess{
            .io = std.testing.io,
            .dir = directory.dir,
        };
        var crash: TestCompletionCrash = .{ .point = point };
        var backend: Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
            .completion_crash = crash.interface(),
        };
        const outer_id: [32]u8 = @splat(0xa1);
        const selectors = [_]solver.PackageSelector{
            .{ .name = "removable" },
        };
        var claim_options = fixture.options();
        claim_options.lock_input_path = fixture.lock_path;
        claim_options.assume_yes = true;
        claim_options.conffile = .keep_existing;
        const pre_mutation_binding: root_operation.PreMutationReconciliationClaimBinding = .{
            .outer_attempt_id = outer_id,
            .outer_generation = 9,
            .outer_state_sha256 = @splat(0xa2),
            .profile_sha256 = @splat(0xa3),
            .profile_reference_sha256 = @splat(0xa4),
            .exact_lock_sha256 = @splat(0xb2),
            .semantic_request_sha256 = try workflowSemanticRequestDigest(
                allocator,
                .remove,
                &selectors,
            ),
        };
        const request: WorkflowRequest = .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = claim_options,
            .orchestration_id = outer_id,
            .reconciliation_claim = if (claim_case.pre_mutation)
                .{ .pre_mutation = .{
                    .outer_generation = pre_mutation_binding.outer_generation,
                    .outer_state_sha256 = pre_mutation_binding.outer_state_sha256,
                    .profile_sha256 = pre_mutation_binding.profile_sha256,
                    .profile_reference_sha256 = pre_mutation_binding.profile_reference_sha256,
                    .exact_lock_sha256 = pre_mutation_binding.exact_lock_sha256,
                } }
            else
                .{ .post_mutation = .{
                    .exact_lock_sha256 = @splat(0xb2),
                    .evidence_sha256 = @splat(0xc3),
                } },
        };
        try std.testing.expectError(
            error.InjectedCompletionCrash,
            backend.executeWorkflow(allocator, request),
        );
        var reopened_backend: Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
        };
        const marker = try backendDeferredMarker(
            allocator,
            &directory,
        );
        if (point == .before_reconciliation_marker_publish) {
            try std.testing.expect(marker == null);
            const claimed = try reopened_backend.executeWorkflow(
                allocator,
                request,
            );
            try std.testing.expectEqual(api.ExitStatus.success, claimed.exit_status);
        } else {
            const retained = marker orelse
                return error.MissingDeferredAcknowledgment;
            try std.testing.expectEqual(
                if (claim_case.pre_mutation)
                    root_operation.DeferredAcknowledgmentState
                        .pre_mutation_reconciliation_claim
                else
                    .released,
                retained.state,
            );
            if (claim_case.pre_mutation)
                try std.testing.expect(
                    root_operation.matchesPreMutationReconciliationClaim(
                        retained,
                        pre_mutation_binding,
                    ),
                );
            try std.testing.expectEqualSlices(
                u8,
                &outer_id,
                &retained.acknowledgment_id,
            );
        }
        const retained = (try backendDeferredMarker(
            allocator,
            &directory,
        )) orelse return error.MissingDeferredAcknowledgment;
        try std.testing.expect((try backendRootRecord(
            allocator,
            &directory,
        )) == null);
        const foreign = try reopened_backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .reserve,
            .selectors = &selectors,
            .options = claim_options,
            .orchestration_id = @splat(0xd4),
        });
        try std.testing.expectEqual(api.ExitStatus.recovery, foreign.exit_status);
        const acknowledged = try reopened_backend.executeWorkflow(
            allocator,
            .{
                .operation = .remove,
                .mode = .recover,
                .selectors = &selectors,
                .options = claim_options,
                .orchestration_id = outer_id,
                .finalize_ownership = true,
                .ownership_acknowledgment = .{
                    .attempt_id = retained.attempt_id,
                    .marker_sha256 = retained.digest_sha256,
                    .marker_exact_identity_sha256 = root_operation.deferredAcknowledgmentExactIdentity(
                        retained,
                    ),
                    .acknowledgment_id = retained.acknowledgment_id,
                    .marker = retained,
                },
            },
        );
        try std.testing.expectEqual(
            api.ExitStatus.success,
            acknowledged.exit_status,
        );
        try std.testing.expect((try backendDeferredMarker(
            allocator,
            &directory,
        )) == null);
        try std.testing.expect((try backendRootRecord(
            allocator,
            &directory,
        )) == null);
        const next = try reopened_backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .reserve,
            .selectors = &selectors,
            .options = claim_options,
            .orchestration_id = @splat(0xe5),
        });
        try std.testing.expectEqual(api.ExitStatus.success, next.exit_status);
    }
}

test "production workflow plans a successful batch install into one exact lock" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const in_release = @embedFile("fixtures/batch_workflow/InRelease");
    const packages = @embedFile("fixtures/batch_workflow/Packages");
    const keyring = @embedFile("fixtures/batch_workflow/keyring.gpg");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var fixture = try ProductionWorkflowFixture.initWithRepository(
        allocator,
        &directory,
        "",
        in_release,
        packages,
        keyring,
    );
    defer fixture.deinit();
    var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
    var backend: Backend = .{
        .io = std.testing.io,
        .now_unix = 1_788_796_860,
        .process_runner = process.interface(),
    };
    const selectors = [_]solver.PackageSelector{ .{ .name = "beta" }, .{ .name = "alpha" } };
    var options = fixture.options();
    options.lock_output_path = fixture.lock_path;
    const planned = try backend.executeWorkflow(allocator, .{
        .operation = .install,
        .mode = .plan_only,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);
    try std.testing.expectEqual(@as(usize, 3), planned.items.len);
    try std.testing.expectEqual(@as(usize, 0), process.calls);

    const lock_bytes = try readFile(
        allocator,
        std.testing.io,
        fixture.lock_path,
        exact_lock.maximum_document_bytes,
    );
    defer allocator.free(lock_bytes);
    var lock = try exact_lock.decode(
        allocator,
        lock_bytes,
        exact_lock.maximum_document_bytes,
    );
    defer lock.deinit();
    try std.testing.expectEqual(@as(usize, 3), lock.lock.packages.len);
    var requested: usize = 0;
    var dependencies: usize = 0;
    for (lock.lock.packages) |package| switch (package.retention) {
        .requested => requested += 1,
        .dependency => dependencies += 1,
        .retained => {},
    };
    try std.testing.expectEqual(@as(usize, 2), requested);
    try std.testing.expectEqual(@as(usize, 1), dependencies);

    var replay_options = fixture.options();
    replay_options.lock_input_path = fixture.lock_path;
    replay_options.lock_output_path = fixture.second_lock_path;
    const replayed = try backend.executeWorkflow(allocator, .{
        .operation = .install,
        .mode = .plan_only,
        .selectors = &selectors,
        .options = replay_options,
    });
    try std.testing.expectEqual(api.ExitStatus.success, replayed.exit_status);
    const replay_bytes = try readFile(
        allocator,
        std.testing.io,
        fixture.second_lock_path,
        exact_lock.maximum_document_bytes,
    );
    defer allocator.free(replay_bytes);
    try std.testing.expectEqualStrings(lock_bytes, replay_bytes);
}

test "production workflow plan-only batches do not mutate and removal locks replay" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const signed_fixture = @import("fixtures/openpgp.zig");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var fixture = try ProductionWorkflowFixture.init(
        allocator,
        &directory,
        "Package: first\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n\n" ++
            "Package: second\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n",
    );
    defer fixture.deinit();

    var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
    var backend: Backend = .{
        .io = std.testing.io,
        .now_unix = signed_fixture.created + 30,
        .process_runner = process.interface(),
    };
    const removals = [_]solver.PackageSelector{ .{ .name = "first" }, .{ .name = "second" } };
    var plan_options = fixture.options();
    plan_options.lock_output_path = fixture.lock_path;
    const planned = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .plan_only,
        .selectors = &removals,
        .options = plan_options,
    });
    try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);
    try std.testing.expectEqual(@as(usize, 2), planned.items.len);
    try std.testing.expectEqual(@as(usize, 0), process.calls);
    const unchanged = try directory.dir.readFileAlloc(
        std.testing.io,
        "root/var/lib/dpkg/status",
        allocator,
        .limited(4096),
    );
    defer allocator.free(unchanged);
    try std.testing.expect(std.mem.indexOf(u8, unchanged, "Package: first") != null);
    try std.testing.expect(std.mem.indexOf(u8, unchanged, "Package: second") != null);

    const lock_bytes = try readFile(
        allocator,
        std.testing.io,
        fixture.lock_path,
        exact_lock.maximum_document_bytes,
    );
    defer allocator.free(lock_bytes);
    var lock = try exact_lock.decode(
        allocator,
        lock_bytes,
        exact_lock.maximum_document_bytes,
    );
    defer lock.deinit();
    try std.testing.expectEqual(@as(usize, 0), lock.lock.packages.len);
    try std.testing.expectEqual(@as(usize, 1), lock.lock.repositories.len);

    var execute_options = fixture.options();
    execute_options.lock_input_path = fixture.lock_path;
    execute_options.assume_yes = true;
    execute_options.noninteractive = true;
    execute_options.conffile = .keep_existing;
    var wrong_policy = execute_options;
    wrong_policy.recommends = true;
    const policy_mismatch = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .execute,
        .selectors = &removals,
        .options = wrong_policy,
    });
    try std.testing.expectEqual(api.ExitStatus.planning, policy_mismatch.exit_status);
    try std.testing.expectEqual(
        api.ErrorId.lock_verification_failed,
        policy_mismatch.diagnostics[0].id,
    );
    try std.testing.expectEqual(@as(usize, 0), process.calls);

    const incomplete = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .execute,
        .selectors = removals[0..1],
        .options = execute_options,
    });
    try std.testing.expectEqual(api.ExitStatus.planning, incomplete.exit_status);
    try std.testing.expectEqual(
        api.ErrorId.lock_verification_failed,
        incomplete.diagnostics[0].id,
    );
    try std.testing.expectEqual(@as(usize, 0), process.calls);

    const executed = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .execute,
        .selectors = &removals,
        .options = execute_options,
    });
    try std.testing.expectEqual(api.ExitStatus.success, executed.exit_status);
    try std.testing.expect(executed.changed);
    try std.testing.expect(process.calls != 0);
    const final_status = try directory.dir.readFileAlloc(
        std.testing.io,
        "root/var/lib/dpkg/status",
        allocator,
        .limited(4096),
    );
    defer allocator.free(final_status);
    try std.testing.expectEqual(@as(usize, 0), final_status.len);
}

test "production workflow recovery reconciles completion without a second mutation" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var fixture = try ProductionWorkflowFixture.init(allocator, &directory,
        \\Package: removable
        \\Status: install ok installed
        \\Priority: optional
        \\Architecture: amd64
        \\Version: 1
        \\
    );
    defer fixture.deinit();
    var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
    var crash: TestCompletionCrash = .{ .point = .after_completed_record };
    var backend: Backend = .{
        .io = std.testing.io,
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
        .process_runner = process.interface(),
        .completion_crash = crash.interface(),
    };
    const selectors = [_]solver.PackageSelector{.{ .name = "removable" }};
    var options = fixture.options();
    options.lock_output_path = fixture.lock_path;
    const planned = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .plan_only,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);

    options.lock_output_path = null;
    options.lock_input_path = fixture.lock_path;
    options.assume_yes = true;
    options.noninteractive = true;
    options.conffile = .keep_existing;
    const interrupted = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .execute,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);
    try std.testing.expect(crash.triggered);
    try std.testing.expectEqual(@as(usize, 2), process.calls);

    backend.completion_crash = null;
    const recovered = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .recover,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
    try std.testing.expectEqual(@as(usize, 2), process.calls);
    const completion_source = try directory.dir.readFileAlloc(
        std.testing.io,
        "root/" ++ root_operation_completion.document_path,
        allocator,
        .limited(root_operation_completion.maximum_document_bytes),
    );
    defer allocator.free(completion_source);
    var completion = try root_operation_completion.decode(
        allocator,
        completion_source,
        root_operation_completion.maximum_document_bytes,
    );
    defer completion.deinit();
    try std.testing.expectEqual(
        root_operation_completion.TransactionProvenanceStatus.unavailable,
        completion.document.transaction_provenance.status,
    );
    try std.testing.expectEqualStrings(
        "recover",
        completion.document.discharge.operation,
    );
    try std.testing.expectError(
        error.FileNotFound,
        directory.dir.openFile(
            std.testing.io,
            "root/" ++ root_operation.record_path,
            .{},
        ),
    );
    const future = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .execute,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expect(future.exit_status != .recovery);
}

test "production recovery crash after provenance publication leaves a settled clearable record" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var fixture = try ProductionWorkflowFixture.init(allocator, &directory,
        \\Package: removable
        \\Status: install ok installed
        \\Priority: optional
        \\Architecture: amd64
        \\Version: 1
        \\
    );
    defer fixture.deinit();
    var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
    var initial_crash: TestCompletionCrash = .{
        .point = .after_completed_record,
    };
    var backend: Backend = .{
        .io = std.testing.io,
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
        .process_runner = process.interface(),
        .completion_crash = initial_crash.interface(),
    };
    const selectors = [_]solver.PackageSelector{.{ .name = "removable" }};
    var options = fixture.options();
    options.lock_output_path = fixture.lock_path;
    const planned = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .plan_only,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);

    options.lock_output_path = null;
    options.lock_input_path = fixture.lock_path;
    options.assume_yes = true;
    options.noninteractive = true;
    options.conffile = .keep_existing;
    const interrupted = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .execute,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);
    try std.testing.expect(initial_crash.triggered);
    const mutation_calls = process.calls;

    var published_crash: TestCompletionCrash = .{
        .point = .after_provenance_published,
    };
    backend.completion_crash = published_crash.interface();
    const discharge = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .recover,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.internal, discharge.exit_status);
    try std.testing.expect(published_crash.triggered);
    try std.testing.expectEqual(mutation_calls, process.calls);

    const record_source = try directory.dir.readFileAlloc(
        std.testing.io,
        "root/" ++ root_operation.record_path,
        allocator,
        .limited(root_operation.maximum_document_bytes),
    );
    defer allocator.free(record_source);
    var record = try root_operation.decode(
        allocator,
        record_source,
        root_operation.maximum_document_bytes,
    );
    defer record.deinit();
    try std.testing.expectEqual(root_operation.State.completed, record.record.state);
    try std.testing.expectEqual(root_operation.Outcome.succeeded, record.record.outcome);
    try std.testing.expectEqual(
        root_operation.ProvenanceState.published,
        record.record.provenance,
    );

    backend.completion_crash = null;
    const future = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .execute,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expect(future.exit_status != .recovery);
}

test "production workflow deferred recovery completion survives every handoff crash and acknowledges once" {
    inline for (.{
        .{
            .recovery = CompletionPoint.after_owed_provenance_document,
            .acknowledgment = CompletionPoint.before_deferred_acknowledged,
        },
        .{
            .recovery = CompletionPoint.after_provenance_published,
            .acknowledgment = CompletionPoint.after_deferred_acknowledged,
        },
        .{
            .recovery = CompletionPoint.before_deferred_recovery_return,
            .acknowledgment = CompletionPoint.before_deferred_record_cleared,
        },
        .{
            .recovery = CompletionPoint.after_owed_provenance_document,
            .acknowledgment = CompletionPoint.after_deferred_record_cleared,
        },
        .{
            .recovery = CompletionPoint.after_provenance_published,
            .acknowledgment = CompletionPoint.before_deferred_marker_cleared,
        },
        .{
            .recovery = CompletionPoint.before_deferred_recovery_return,
            .acknowledgment = CompletionPoint.after_deferred_marker_cleared,
        },
    }) |crash_case| {
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        var fixture = try ProductionWorkflowFixture.init(allocator, &directory,
            \\Package: removable
            \\Status: install ok installed
            \\Priority: optional
            \\Architecture: amd64
            \\Version: 1
            \\
        );
        defer fixture.deinit();
        var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
        var initial_crash: TestCompletionCrash = .{
            .point = .after_completed_record,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
            .completion_crash = initial_crash.interface(),
        };
        const selectors = [_]solver.PackageSelector{.{ .name = "removable" }};
        var options = fixture.options();
        options.lock_output_path = fixture.lock_path;
        const planned = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .plan_only,
            .selectors = &selectors,
            .options = options,
        });
        try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);
        options.lock_output_path = null;
        options.lock_input_path = fixture.lock_path;
        options.assume_yes = true;
        options.noninteractive = true;
        options.conffile = .keep_existing;
        const acknowledgment_id: [32]u8 = @splat(0x6a);
        const interrupted = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .execute,
            .selectors = &selectors,
            .options = options,
            .orchestration_id = acknowledgment_id,
        });
        try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);
        const mutation_calls = process.calls;
        const competing_orchestration_id: [32]u8 = @splat(0x7b);
        var competing_options = options;
        competing_options.state_path = try std.fmt.allocPrint(
            allocator,
            "{s}-competing",
            .{fixture.state_path},
        );
        const competing_execute = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .execute,
            .selectors = &selectors,
            .options = competing_options,
            .orchestration_id = competing_orchestration_id,
        });
        try std.testing.expectEqual(
            api.ExitStatus.recovery,
            competing_execute.exit_status,
        );
        const competing_recovery = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = competing_options,
            .defer_recovery_clear = true,
            .orchestration_id = competing_orchestration_id,
        });
        try std.testing.expectEqual(
            api.ExitStatus.recovery,
            competing_recovery.exit_status,
        );
        try std.testing.expectEqual(mutation_calls, process.calls);
        const bound_source = try directory.dir.readFileAlloc(
            std.testing.io,
            "root/" ++ root_operation.deferred_ack_path,
            allocator,
            .limited(root_operation.maximum_document_bytes),
        );
        const bound = try root_operation.decodeDeferredAcknowledgment(
            allocator,
            bound_source,
        );
        try std.testing.expectEqual(
            root_operation.DeferredAcknowledgmentState.bound,
            bound.state,
        );
        try std.testing.expectEqualSlices(
            u8,
            &acknowledgment_id,
            &bound.acknowledgment_id,
        );

        var recovery_crash: TestCompletionCrash = .{
            .point = crash_case.recovery,
        };
        backend.completion_crash = recovery_crash.interface();
        const first_recovery = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = options,
            .defer_recovery_clear = true,
            .orchestration_id = acknowledgment_id,
        });
        try std.testing.expectEqual(
            api.ExitStatus.internal,
            first_recovery.exit_status,
        );
        try std.testing.expect(recovery_crash.triggered);
        try std.testing.expectEqual(mutation_calls, process.calls);

        backend.completion_crash = null;
        const recovered = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = options,
            .defer_recovery_clear = true,
            .orchestration_id = acknowledgment_id,
        });
        try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
        try std.testing.expectEqual(mutation_calls, process.calls);
        const record_source = try directory.dir.readFileAlloc(
            std.testing.io,
            "root/" ++ root_operation.record_path,
            allocator,
            .limited(root_operation.maximum_document_bytes),
        );
        var record = try root_operation.decode(
            allocator,
            record_source,
            root_operation.maximum_document_bytes,
        );
        defer record.deinit();
        const completion_source = try directory.dir.readFileAlloc(
            std.testing.io,
            "root/" ++ root_operation_completion.document_path,
            allocator,
            .limited(root_operation_completion.maximum_document_bytes),
        );
        var completion = try root_operation_completion.decode(
            allocator,
            completion_source,
            root_operation_completion.maximum_document_bytes,
        );
        defer completion.deinit();
        try std.testing.expectEqual(
            root_operation.ProvenanceState.published,
            record.record.provenance,
        );
        try std.testing.expectEqual(
            root_operation_completion.TransactionProvenanceStatus.unavailable,
            completion.document.transaction_provenance.status,
        );
        try directory.dir.access(
            std.testing.io,
            "root/" ++ root_operation.deferred_ack_path,
            .{},
        );
        var contender: DeferredAckContender = .{
            .backend = &backend,
            .request = .{
                .operation = .remove,
                .mode = .execute,
                .selectors = &selectors,
                .options = competing_options,
                .orchestration_id = competing_orchestration_id,
            },
        };
        const contender_thread = try std.Thread.spawn(
            .{},
            DeferredAckContender.run,
            .{&contender},
        );
        contender_thread.join();
        try std.testing.expectEqual(
            api.ExitStatus.recovery,
            contender.status.?,
        );
        try std.testing.expectEqual(mutation_calls, process.calls);

        var wrong_completion = completion.document.digest_sha256;
        wrong_completion[0] ^= 0xff;
        const rejected = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = options,
            .defer_recovery_clear = true,
            .orchestration_id = acknowledgment_id,
            .recovery_acknowledgment = .{
                .attempt_id = record.record.attempt_id,
                .completion_sha256 = wrong_completion,
                .provenance_sha256 = record.record.provenance_sha256.?,
                .acknowledgment_id = acknowledgment_id,
            },
        });
        try std.testing.expectEqual(api.ExitStatus.recovery, rejected.exit_status);
        try directory.dir.access(
            std.testing.io,
            "root/" ++ root_operation.record_path,
            .{},
        );
        const foreign_ack = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = options,
            .defer_recovery_clear = true,
            .orchestration_id = competing_orchestration_id,
            .recovery_acknowledgment = .{
                .attempt_id = record.record.attempt_id,
                .completion_sha256 = completion.document.digest_sha256,
                .provenance_sha256 = record.record.provenance_sha256.?,
                .acknowledgment_id = competing_orchestration_id,
            },
        });
        try std.testing.expectEqual(
            api.ExitStatus.recovery,
            foreign_ack.exit_status,
        );
        try directory.dir.access(
            std.testing.io,
            "root/" ++ root_operation.deferred_ack_path,
            .{},
        );
        {
            var acknowledgment_crash: TestCompletionCrash = .{
                .point = crash_case.acknowledgment,
            };
            backend.completion_crash = acknowledgment_crash.interface();
            const interrupted_ack = try backend.executeWorkflow(allocator, .{
                .operation = .remove,
                .mode = .recover,
                .selectors = &selectors,
                .options = options,
                .defer_recovery_clear = true,
                .orchestration_id = acknowledgment_id,
                .recovery_acknowledgment = .{
                    .attempt_id = record.record.attempt_id,
                    .completion_sha256 = completion.document.digest_sha256,
                    .provenance_sha256 = record.record.provenance_sha256.?,
                    .acknowledgment_id = acknowledgment_id,
                },
            });
            try std.testing.expectEqual(
                api.ExitStatus.internal,
                interrupted_ack.exit_status,
            );
            try std.testing.expect(acknowledgment_crash.triggered);
            backend.completion_crash = null;
            try std.testing.expectEqual(mutation_calls, process.calls);
            if (try backendDeferredMarker(allocator, &directory)) |_| {
                const foreign_retry = try backend.executeWorkflow(
                    allocator,
                    .{
                        .operation = .remove,
                        .mode = .recover,
                        .selectors = &selectors,
                        .options = options,
                        .defer_recovery_clear = true,
                        .orchestration_id = competing_orchestration_id,
                        .recovery_acknowledgment = .{
                            .attempt_id = record.record.attempt_id,
                            .completion_sha256 = completion.document.digest_sha256,
                            .provenance_sha256 = record.record.provenance_sha256.?,
                            .acknowledgment_id = competing_orchestration_id,
                        },
                    },
                );
                try std.testing.expectEqual(
                    api.ExitStatus.recovery,
                    foreign_retry.exit_status,
                );
            }
        }
        const acknowledged = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = options,
            .defer_recovery_clear = true,
            .orchestration_id = acknowledgment_id,
            .recovery_acknowledgment = .{
                .attempt_id = record.record.attempt_id,
                .completion_sha256 = completion.document.digest_sha256,
                .provenance_sha256 = record.record.provenance_sha256.?,
                .acknowledgment_id = acknowledgment_id,
            },
        });
        try std.testing.expectEqual(
            api.ExitStatus.success,
            acknowledged.exit_status,
        );
        try std.testing.expectEqual(mutation_calls, process.calls);
        try std.testing.expectError(
            error.FileNotFound,
            directory.dir.access(
                std.testing.io,
                "root/" ++ root_operation.record_path,
                .{},
            ),
        );
        try std.testing.expectError(
            error.FileNotFound,
            directory.dir.access(
                std.testing.io,
                "root/" ++ root_operation.deferred_ack_path,
                .{},
            ),
        );
        const repeated = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = options,
            .defer_recovery_clear = true,
            .orchestration_id = acknowledgment_id,
            .recovery_acknowledgment = .{
                .attempt_id = record.record.attempt_id,
                .completion_sha256 = completion.document.digest_sha256,
                .provenance_sha256 = record.record.provenance_sha256.?,
                .acknowledgment_id = acknowledgment_id,
            },
        });
        try std.testing.expectEqual(api.ExitStatus.success, repeated.exit_status);
        try std.testing.expectEqual(mutation_calls, process.calls);
        const future = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .execute,
            .selectors = &selectors,
            .options = competing_options,
            .orchestration_id = competing_orchestration_id,
        });
        try std.testing.expect(future.exit_status != .recovery);
    }
}

test "production workflow deferred recovery cannot claim an unbound lower attempt" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var fixture = try ProductionWorkflowFixture.init(allocator, &directory,
        \\Package: removable
        \\Status: install ok installed
        \\Priority: optional
        \\Architecture: amd64
        \\Version: 1
        \\
    );
    defer fixture.deinit();
    var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
    var crash: TestCompletionCrash = .{ .point = .after_completed_record };
    var backend: Backend = .{
        .io = std.testing.io,
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
        .process_runner = process.interface(),
        .completion_crash = crash.interface(),
    };
    const selectors = [_]solver.PackageSelector{.{ .name = "removable" }};
    var options = fixture.options();
    options.lock_output_path = fixture.lock_path;
    const planned = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .plan_only,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);
    options.lock_output_path = null;
    options.lock_input_path = fixture.lock_path;
    options.assume_yes = true;
    options.noninteractive = true;
    options.conffile = .keep_existing;
    const interrupted = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .execute,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);
    const mutation_calls = process.calls;

    backend.completion_crash = null;
    const rejected = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .recover,
        .selectors = &selectors,
        .options = options,
        .defer_recovery_clear = true,
        .orchestration_id = @splat(0x5c),
    });
    try std.testing.expectEqual(api.ExitStatus.recovery, rejected.exit_status);
    try std.testing.expectEqual(mutation_calls, process.calls);
    try std.testing.expectError(
        error.FileNotFound,
        directory.dir.access(
            std.testing.io,
            "root/" ++ root_operation.deferred_ack_path,
            .{},
        ),
    );
}

fn runRootBindingOverlapScenario(stall_role: OverlapStallRole) !void {
    inline for ([_]RootBindingPoint{
        .after_root_lock_acquired,
        .after_binding_published,
    }) |binding_point| {
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        var fixture = try ProductionWorkflowFixture.init(allocator, &directory,
            \\Package: removable
            \\Status: install ok installed
            \\Priority: optional
            \\Architecture: amd64
            \\Version: 1
            \\
        );
        defer fixture.deinit();
        var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
        var completion_crash: TestCompletionCrash = .{
            .point = .after_completed_record,
        };
        var barrier: TestRootBindingBarrier = .{ .point = binding_point };
        var backend: Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
            .completion_crash = completion_crash.interface(),
            .root_binding_sync = barrier.interface(),
        };
        const selectors = [_]solver.PackageSelector{.{ .name = "removable" }};
        var options = fixture.options();
        options.lock_output_path = fixture.lock_path;
        const planned = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .plan_only,
            .selectors = &selectors,
            .options = options,
        });
        try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);
        options.lock_output_path = null;
        options.lock_input_path = fixture.lock_path;
        options.assume_yes = true;
        options.noninteractive = true;
        options.conffile = .keep_existing;
        options.lock_wait_ms = 25;
        const owner_id: [32]u8 = @splat(0xa1);
        var owner: DeferredAckContender = .{
            .backend = &backend,
            .stall = stall_role == .owner,
            .request = .{
                .operation = .remove,
                .mode = .execute,
                .selectors = &selectors,
                .options = options,
                .orchestration_id = owner_id,
            },
        };
        const owner_thread = try std.Thread.spawn(
            .{},
            DeferredAckContender.run,
            .{&owner},
        );
        var owner_joined = false;
        defer {
            barrier.release();
            if (!owner_joined) {
                waitForContender(&owner.finished, 5_000) catch
                    @panic("owner thread exceeded deterministic watchdog");
                owner_thread.join();
            }
        }
        try barrier.wait(5_000);

        var distinct_options = options;
        distinct_options.state_path = try std.fmt.allocPrint(
            allocator,
            "{s}-distinct",
            .{fixture.state_path},
        );
        var identical_options = options;
        identical_options.state_path = try std.fmt.allocPrint(
            allocator,
            "{s}-identical",
            .{fixture.state_path},
        );
        var distinct: DeferredAckContender = .{
            .backend = &backend,
            .stall = stall_role == .distinct,
            .request = .{
                .operation = .install,
                .mode = .execute,
                .selectors = &selectors,
                .options = distinct_options,
                .orchestration_id = @splat(0xb2),
            },
        };
        var identical: DeferredAckContender = .{
            .backend = &backend,
            .stall = stall_role == .identical,
            .request = .{
                .operation = .remove,
                .mode = .execute,
                .selectors = &selectors,
                .options = identical_options,
                .orchestration_id = @splat(0xc3),
            },
        };
        const distinct_thread = try std.Thread.spawn(
            .{},
            DeferredAckContender.run,
            .{&distinct},
        );
        const identical_thread = try std.Thread.spawn(
            .{},
            DeferredAckContender.run,
            .{&identical},
        );
        try waitForContender(&distinct.started, 5_000);
        try waitForContender(&identical.started, 5_000);
        try waitForContender(&distinct.finished, 5_000);
        try waitForContender(&identical.finished, 5_000);
        try std.testing.expect(distinct.status.? != .success);
        try std.testing.expect(identical.status.? != .success);
        try std.testing.expectEqual(@as(usize, 0), process.calls);
        if (binding_point == .after_binding_published) {
            const held_marker = (try backendDeferredMarker(
                allocator,
                &directory,
            )).?;
            try std.testing.expectEqualSlices(
                u8,
                &owner_id,
                &held_marker.acknowledgment_id,
            );
        }
        barrier.release();
        distinct_thread.join();
        identical_thread.join();
        try waitForContender(&owner.finished, 5_000);
        owner_thread.join();
        owner_joined = true;
        try std.testing.expectEqual(api.ExitStatus.internal, owner.status.?);
        const mutation_calls = process.calls;
        try std.testing.expect(mutation_calls != 0);
        backend.root_binding_sync = null;
        backend.completion_crash = null;

        const marker_source = try directory.dir.readFileAlloc(
            std.testing.io,
            "root/" ++ root_operation.deferred_ack_path,
            allocator,
            .limited(root_operation.maximum_document_bytes),
        );
        const marker = try root_operation.decodeDeferredAcknowledgment(
            allocator,
            marker_source,
        );
        try std.testing.expectEqual(
            root_operation.DeferredAcknowledgmentState.bound,
            marker.state,
        );
        try std.testing.expectEqualSlices(
            u8,
            &owner_id,
            &marker.acknowledgment_id,
        );

        const recovered = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = options,
            .defer_recovery_clear = true,
            .orchestration_id = owner_id,
        });
        try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
        try std.testing.expectEqual(mutation_calls, process.calls);
        var record = (try backendRootRecord(
            allocator,
            &directory,
        )).?;
        defer record.deinit();
        var completion = (try backendRootCompletion(
            allocator,
            &directory,
        )).?;
        defer completion.deinit();
        const acknowledged = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = options,
            .defer_recovery_clear = true,
            .orchestration_id = owner_id,
            .recovery_acknowledgment = .{
                .attempt_id = record.record.attempt_id,
                .completion_sha256 = completion.document.digest_sha256,
                .provenance_sha256 = record.record.provenance_sha256.?,
                .acknowledgment_id = owner_id,
            },
        });
        try std.testing.expectEqual(api.ExitStatus.success, acknowledged.exit_status);
        try std.testing.expectEqual(mutation_calls, process.calls);
        const later = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .execute,
            .selectors = &selectors,
            .options = identical_options,
            .orchestration_id = @splat(0xc3),
        });
        try std.testing.expect(later.exit_status != .recovery);
    }
}

fn runOverlapWatchdog(
    stall_role: OverlapStallRole,
    timeout_ms: u64,
    expect_timeout: bool,
) !void {
    const linux = std.os.linux;
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(forked);
    if (pid == 0) {
        runRootBindingOverlapScenario(stall_role) catch
            linux.exit_group(101);
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
            .SUCCESS => {
                if (waited != 0) {
                    reaped = true;
                    if (expect_timeout)
                        return error.StalledChildExitedBeforeWatchdog;
                    if (!linux.W.IFEXITED(status) or
                        linux.W.EXITSTATUS(status) != 0)
                        return error.OverlapChildFailed;
                    return;
                }
            },
            .INTR => continue,
            else => return error.WaitFailed,
        }
        const elapsed = started.durationTo(
            std.Io.Clock.awake.now(std.testing.io),
        ).toMilliseconds();
        if (elapsed >= timeout_ms) {
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
            if (!expect_timeout) return error.OverlapChildTimedOut;
            return;
        }
        var request: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
        var remaining: linux.timespec = undefined;
        _ = linux.nanosleep(&request, &remaining);
    }
}

test "production workflow root binding excludes overlapping foreign owners" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    try runOverlapWatchdog(.none, 15_000, false);
    inline for (.{ OverlapStallRole.owner, .distinct, .identical }) |role|
        try runOverlapWatchdog(role, 250, true);
}

test "production workflow ownership cleanup converges across every durable boundary" {
    inline for ([_]CompletionPoint{
        .before_ownership_terminal_publish,
        .after_ownership_terminal_publish,
        .before_ownership_record_clear,
        .after_ownership_record_clear,
    }) |crash_point| {
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        var fixture = try ProductionWorkflowFixture.init(allocator, &directory,
            \\Package: removable
            \\Status: install ok installed
            \\Priority: optional
            \\Architecture: amd64
            \\Version: 1
            \\
        );
        defer fixture.deinit();
        var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
        var crash: TestCompletionCrash = .{ .point = crash_point };
        var backend: Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
            .completion_crash = crash.interface(),
        };
        const selectors = [_]solver.PackageSelector{.{ .name = "removable" }};
        var options = fixture.options();
        options.lock_output_path = fixture.lock_path;
        const planned = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .plan_only,
            .selectors = &selectors,
            .options = options,
        });
        try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);
        options.lock_output_path = null;
        options.lock_input_path = fixture.lock_path;
        options.assume_yes = true;
        options.noninteractive = true;
        options.conffile = .keep_existing;
        const owner_id: [32]u8 = @splat(0xd4);
        const interrupted = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .execute,
            .selectors = &selectors,
            .options = options,
            .orchestration_id = owner_id,
        });
        try std.testing.expectEqual(api.ExitStatus.recovery, interrupted.exit_status);
        try std.testing.expect(crash.triggered);
        const mutation_calls = process.calls;
        try std.testing.expect(mutation_calls != 0);

        const marker_before = try backendDeferredMarker(allocator, &directory);
        if (marker_before) |marker| {
            try std.testing.expect(
                marker.state == .bound or marker.state == .released,
            );
            try std.testing.expectEqualSlices(
                u8,
                &owner_id,
                &marker.acknowledgment_id,
            );
            var foreign_options = options;
            foreign_options.state_path = try std.fmt.allocPrint(
                allocator,
                "{s}-foreign-cleanup",
                .{fixture.state_path},
            );
            const foreign = try backend.executeWorkflow(allocator, .{
                .operation = .remove,
                .mode = .execute,
                .selectors = &selectors,
                .options = foreign_options,
                .orchestration_id = @splat(0xe5),
            });
            try std.testing.expectEqual(api.ExitStatus.recovery, foreign.exit_status);
            try std.testing.expectEqual(mutation_calls, process.calls);
            const foreign_finalize = try backend.executeWorkflow(allocator, .{
                .operation = .remove,
                .mode = .recover,
                .selectors = &selectors,
                .options = foreign_options,
                .orchestration_id = @splat(0xe5),
                .finalize_ownership = true,
                .ownership_acknowledgment = .{
                    .attempt_id = marker.attempt_id,
                    .marker_sha256 = marker.digest_sha256,
                    .marker_exact_identity_sha256 = root_operation.deferredAcknowledgmentExactIdentity(
                        marker,
                    ),
                    .acknowledgment_id = @splat(0xe5),
                    .marker = marker,
                },
            });
            try std.testing.expectEqual(
                api.ExitStatus.recovery,
                foreign_finalize.exit_status,
            );
            try std.testing.expectEqual(mutation_calls, process.calls);

            backend.completion_crash = null;
            const finalized = try backend.executeWorkflow(allocator, .{
                .operation = .remove,
                .mode = .recover,
                .selectors = &selectors,
                .options = options,
                .orchestration_id = owner_id,
                .finalize_ownership = true,
                .ownership_acknowledgment = .{
                    .attempt_id = marker.attempt_id,
                    .marker_sha256 = marker.digest_sha256,
                    .marker_exact_identity_sha256 = root_operation.deferredAcknowledgmentExactIdentity(
                        marker,
                    ),
                    .acknowledgment_id = owner_id,
                    .marker = marker,
                },
            });
            try std.testing.expectEqual(api.ExitStatus.success, finalized.exit_status);
            try std.testing.expectEqual(mutation_calls, process.calls);
            try std.testing.expect((try backendRootRecord(
                allocator,
                &directory,
            )) == null);
            try std.testing.expect((try backendDeferredMarker(
                allocator,
                &directory,
            )) == null);
        } else {
            try std.testing.expect((try backendRootRecord(
                allocator,
                &directory,
            )) == null);
        }
        var later_options = options;
        later_options.state_path = try std.fmt.allocPrint(
            allocator,
            "{s}-later-cleanup",
            .{fixture.state_path},
        );
        const later = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .execute,
            .selectors = &selectors,
            .options = later_options,
            .orchestration_id = @splat(0xf6),
        });
        try std.testing.expect(later.exit_status != .recovery);
    }
}

test "production workflow pre-mutation ownership abandon converges across every durable boundary" {
    inline for ([_]CompletionPoint{
        .after_root_lock_acquired,
        .after_binding_published,
        .before_ownership_terminal_publish,
        .after_ownership_terminal_publish,
        .before_ownership_record_clear,
        .after_ownership_record_clear,
    }) |crash_point| {
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        var fixture = try ProductionWorkflowFixture.init(allocator, &directory,
            \\Package: removable
            \\Status: install ok installed
            \\Priority: optional
            \\Architecture: amd64
            \\Version: 1
            \\
        );
        defer fixture.deinit();
        var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
        var crash: TestCompletionCrash = .{ .point = crash_point };
        var backend: Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
            .completion_crash = crash.interface(),
        };
        const selectors = [_]solver.PackageSelector{.{ .name = "removable" }};
        var options = fixture.options();
        options.lock_output_path = fixture.lock_path;
        const planned = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .plan_only,
            .selectors = &selectors,
            .options = options,
        });
        try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);
        const valid_source = try directory.dir.readFileAlloc(
            std.testing.io,
            "sources.list",
            allocator,
            .limited(4096),
        );
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "sources.list",
            .data = "not-an-apt-source\n",
        });
        options.lock_output_path = null;
        options.lock_input_path = fixture.lock_path;
        options.assume_yes = true;
        options.noninteractive = true;
        options.conffile = .keep_existing;
        const owner_id: [32]u8 = @splat(0x17);
        if (backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .execute,
            .selectors = &selectors,
            .options = options,
            .orchestration_id = owner_id,
        })) |failed| {
            try std.testing.expect(failed.exit_status != .success);
        } else |_| {}
        try std.testing.expect(crash.triggered);
        try std.testing.expectEqual(@as(usize, 0), process.calls);
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "sources.list",
            .data = valid_source,
        });

        if (try backendDeferredMarker(allocator, &directory)) |marker| {
            try std.testing.expect(
                marker.state == .bound or marker.state == .abandoned,
            );
            try std.testing.expectEqualSlices(
                u8,
                &owner_id,
                &marker.acknowledgment_id,
            );
            var foreign_options = options;
            foreign_options.state_path = try std.fmt.allocPrint(
                allocator,
                "{s}-foreign-abandon",
                .{fixture.state_path},
            );
            const foreign = try backend.executeWorkflow(allocator, .{
                .operation = .remove,
                .mode = .execute,
                .selectors = &selectors,
                .options = foreign_options,
                .orchestration_id = @splat(0x28),
            });
            try std.testing.expectEqual(api.ExitStatus.recovery, foreign.exit_status);
            try std.testing.expectEqual(@as(usize, 0), process.calls);

            backend.completion_crash = null;
            const finalized = try backend.executeWorkflow(allocator, .{
                .operation = .remove,
                .mode = .execute,
                .selectors = &selectors,
                .options = options,
                .orchestration_id = owner_id,
            });
            if (finalized.exit_status != .success) {
                try std.testing.expectEqual(@as(usize, 0), process.calls);
                const executed = try backend.executeWorkflow(allocator, .{
                    .operation = .remove,
                    .mode = .execute,
                    .selectors = &selectors,
                    .options = options,
                    .orchestration_id = owner_id,
                });
                try std.testing.expectEqual(api.ExitStatus.success, executed.exit_status);
            }
        } else {
            backend.completion_crash = null;
            const executed = try backend.executeWorkflow(allocator, .{
                .operation = .remove,
                .mode = .execute,
                .selectors = &selectors,
                .options = options,
                .orchestration_id = owner_id,
            });
            try std.testing.expectEqual(api.ExitStatus.success, executed.exit_status);
        }
        try std.testing.expect(process.calls != 0);
        try std.testing.expect((try backendRootRecord(
            allocator,
            &directory,
        )) == null);
        const released = (try backendDeferredMarker(
            allocator,
            &directory,
        )).?;
        try std.testing.expectEqual(
            root_operation.DeferredAcknowledgmentState.released,
            released.state,
        );
        const acknowledged = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = options,
            .orchestration_id = owner_id,
            .finalize_ownership = true,
            .ownership_acknowledgment = .{
                .attempt_id = released.attempt_id,
                .marker_sha256 = released.digest_sha256,
                .marker_exact_identity_sha256 = root_operation.deferredAcknowledgmentExactIdentity(
                    released,
                ),
                .acknowledgment_id = owner_id,
                .marker = released,
            },
        });
        try std.testing.expectEqual(api.ExitStatus.success, acknowledged.exit_status);
        try std.testing.expect((try backendDeferredMarker(
            allocator,
            &directory,
        )) == null);
    }
}

test "production ownership finalization rejects a valid colliding v2 owner" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var fixture = try ProductionWorkflowFixture.init(allocator, &directory,
        \\Package: removable
        \\Status: install ok installed
        \\Priority: optional
        \\Architecture: amd64
        \\Version: 1
        \\
    );
    defer fixture.deinit();
    const owner_id: [32]u8 = @splat(0x31);
    const claim_a = try root_operation.createRecoveryReviewClaim(.{
        .outer_attempt_id = owner_id,
        .outer_generation = 1,
        .outer_state_sha256 = @splat(0x32),
        .profile_sha256 = @splat(0x33),
        .profile_reference_sha256 = @splat(0x34),
        .exact_lock_sha256 = @splat(0x35),
        .semantic_request_sha256 = @splat(0x36),
        .mutation_status = .unchanged,
        .nonce = @splat(0x37),
    });
    const claim_b = try root_operation.createRecoveryReviewClaim(.{
        .outer_attempt_id = claim_a.outer_attempt_id,
        .outer_generation = claim_a.outer_generation,
        .outer_state_sha256 = claim_a.outer_state_sha256,
        .profile_sha256 = claim_a.profile_sha256,
        .profile_reference_sha256 = claim_a.profile_reference_sha256,
        .exact_lock_sha256 = claim_a.exact_lock_sha256,
        .semantic_request_sha256 = claim_a.semantic_request_sha256,
        .mutation_status = claim_a.mutation_status,
        .nonce = @splat(0x38),
    });
    const base = try root_operation.createDeferredAcknowledgment(.{
        .state = .released,
        .attempt_id = @splat(0x39),
        .acknowledgment_id = owner_id,
    });
    const marker_a =
        try root_operation.bindDeferredAcknowledgmentToRecoveryReview(
            base,
            claim_a,
        );
    const marker_b =
        try root_operation.bindDeferredAcknowledgmentToRecoveryReview(
            base,
            claim_b,
        );
    try std.testing.expectEqualSlices(
        u8,
        &marker_a.digest_sha256,
        &marker_b.digest_sha256,
    );
    try std.testing.expect(!root_operation.deferredAcknowledgmentExactEqual(
        marker_a,
        marker_b,
    ));

    var owned_root = try root_fs.openAbsoluteRoot(
        std.testing.io,
        fixture.install_root,
    );
    defer owned_root.close();
    const store = root_operation.Store.init(owned_root.root);
    try store.ensureNamespace();
    try store.publishDeferredAcknowledgment(allocator, marker_b);

    var backend: Backend = .{
        .io = std.testing.io,
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
    };
    const selectors = [_]solver.PackageSelector{.{ .name = "removable" }};
    const options = fixture.options();
    const foreign = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .recover,
        .selectors = &selectors,
        .options = options,
        .orchestration_id = owner_id,
        .finalize_ownership = true,
        .ownership_acknowledgment = .{
            .attempt_id = marker_a.attempt_id,
            .marker_sha256 = marker_a.digest_sha256,
            .marker_exact_identity_sha256 = root_operation.deferredAcknowledgmentExactIdentity(marker_a),
            .acknowledgment_id = owner_id,
            .marker = marker_a,
        },
    });
    try std.testing.expectEqual(api.ExitStatus.recovery, foreign.exit_status);
    try std.testing.expect(root_operation.deferredAcknowledgmentExactEqual(
        marker_b,
        (try store.readDeferredAcknowledgment(allocator)).?,
    ));

    const exact = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .recover,
        .selectors = &selectors,
        .options = options,
        .orchestration_id = owner_id,
        .finalize_ownership = true,
        .ownership_acknowledgment = .{
            .attempt_id = marker_b.attempt_id,
            .marker_sha256 = marker_b.digest_sha256,
            .marker_exact_identity_sha256 = root_operation.deferredAcknowledgmentExactIdentity(marker_b),
            .acknowledgment_id = owner_id,
            .marker = marker_b,
        },
    });
    try std.testing.expectEqual(api.ExitStatus.success, exact.exit_status);
    try std.testing.expect(
        (try store.readDeferredAcknowledgment(allocator)) == null,
    );
}

test "production restart requires the authenticated exact v2 owner" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var fixture = try ProductionWorkflowFixture.init(allocator, &directory,
        \\Package: removable
        \\Status: install ok installed
        \\Priority: optional
        \\Architecture: amd64
        \\Version: 1
        \\
    );
    defer fixture.deinit();
    var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
    var backend: Backend = .{
        .io = std.testing.io,
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
        .process_runner = process.interface(),
    };
    const selectors = [_]solver.PackageSelector{.{ .name = "removable" }};
    var options = fixture.options();
    options.lock_output_path = fixture.lock_path;
    const planned = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .plan_only,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);
    options.lock_output_path = null;
    options.lock_input_path = fixture.lock_path;
    options.assume_yes = true;
    options.noninteractive = true;
    options.conffile = .keep_existing;

    const owner_id: [32]u8 = @splat(0x71);
    const claim_a = try root_operation.createRecoveryReviewClaim(.{
        .outer_attempt_id = owner_id,
        .outer_generation = 1,
        .outer_state_sha256 = @splat(0x72),
        .profile_sha256 = @splat(0x73),
        .profile_reference_sha256 = @splat(0x74),
        .exact_lock_sha256 = @splat(0x75),
        .semantic_request_sha256 = @splat(0x76),
        .mutation_status = .unchanged,
        .nonce = @splat(0x77),
    });
    var owned_root = try root_fs.openAbsoluteRoot(
        std.testing.io,
        fixture.install_root,
    );
    defer owned_root.close();
    const store = root_operation.Store.init(owned_root.root);
    try store.ensureNamespace();
    try store.publishRecoveryReviewClaim(allocator, claim_a);
    const reserved = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .reserve,
        .selectors = &selectors,
        .options = options,
        .orchestration_id = owner_id,
        .recovery_review_claim = claim_a,
    });
    try std.testing.expectEqual(api.ExitStatus.success, reserved.exit_status);
    const marker_a = (try store.readDeferredAcknowledgment(allocator)).?;
    try std.testing.expectEqual(
        root_operation.DeferredAcknowledgmentState.bound,
        marker_a.state,
    );

    const claim_b = try root_operation.createRecoveryReviewClaim(.{
        .outer_attempt_id = claim_a.outer_attempt_id,
        .outer_generation = claim_a.outer_generation,
        .outer_state_sha256 = claim_a.outer_state_sha256,
        .profile_sha256 = claim_a.profile_sha256,
        .profile_reference_sha256 = claim_a.profile_reference_sha256,
        .exact_lock_sha256 = claim_a.exact_lock_sha256,
        .semantic_request_sha256 = claim_a.semantic_request_sha256,
        .mutation_status = claim_a.mutation_status,
        .nonce = @splat(0x78),
    });
    const base = try root_operation.createDeferredAcknowledgment(.{
        .state = .bound,
        .attempt_id = marker_a.attempt_id,
        .acknowledgment_id = owner_id,
    });
    const marker_b =
        try root_operation.bindDeferredAcknowledgmentToRecoveryReview(
            base,
            claim_b,
        );
    try std.testing.expectEqualSlices(
        u8,
        &marker_a.digest_sha256,
        &marker_b.digest_sha256,
    );
    try std.testing.expect(!root_operation.deferredAcknowledgmentExactEqual(
        marker_a,
        marker_b,
    ));
    const marker_b_source = try marker_b.canonicalJson(allocator);
    try owned_root.root.publishFile(
        try root_fs.Path.init(root_operation.deferred_ack_path),
        marker_b_source,
        .{ .permissions = 0o600, .overwrite = .replace, .durable = true },
    );
    var reopened_backend: Backend = .{
        .io = std.testing.io,
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
        .process_runner = process.interface(),
    };

    const foreign = try reopened_backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .execute,
        .selectors = &selectors,
        .options = options,
        .orchestration_id = owner_id,
        .expected_ownership_marker = marker_a,
    });
    try std.testing.expectEqual(api.ExitStatus.recovery, foreign.exit_status);
    try std.testing.expectEqual(@as(usize, 0), process.calls);
    try std.testing.expect(root_operation.deferredAcknowledgmentExactEqual(
        marker_b,
        (try store.readDeferredAcknowledgment(allocator)).?,
    ));
    var retained_record = (try backendRootRecord(
        allocator,
        &directory,
    )) orelse return error.MissingRootOperationRecord;
    retained_record.deinit();

    const exact = try reopened_backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .execute,
        .selectors = &selectors,
        .options = options,
        .orchestration_id = owner_id,
        .expected_ownership_marker = marker_b,
    });
    try std.testing.expectEqual(api.ExitStatus.success, exact.exit_status);
    try std.testing.expect(process.calls != 0);
    try std.testing.expect((try backendRootRecord(
        allocator,
        &directory,
    )) == null);
    try std.testing.expectEqual(
        root_operation.DeferredAcknowledgmentState.released,
        (try store.readDeferredAcknowledgment(allocator)).?.state,
    );
}

test "production workflow retry rotation preserves continuous owner proof across process death" {
    inline for ([_]CompletionPoint{
        .before_retry_terminal_publish,
        .after_retry_terminal_publish,
        .before_retry_record_clear,
        .after_retry_record_clear,
        .before_binding_published,
        .after_binding_published,
    }) |rotation_point| {
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        var fixture = try ProductionWorkflowFixture.init(allocator, &directory,
            \\Package: removable
            \\Status: install ok installed
            \\Priority: optional
            \\Architecture: amd64
            \\Version: 1
            \\
        );
        defer fixture.deinit();
        var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
        var initial_crash: TestCompletionCrash = .{
            .point = .before_ownership_terminal_publish,
        };
        var backend: Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
            .completion_crash = if (rotation_point == .before_binding_published or
                rotation_point == .after_binding_published)
                null
            else
                initial_crash.interface(),
        };
        const selectors = [_]solver.PackageSelector{.{ .name = "removable" }};
        var options = fixture.options();
        options.lock_output_path = fixture.lock_path;
        const planned = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .plan_only,
            .selectors = &selectors,
            .options = options,
        });
        try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);
        const valid_source = try directory.dir.readFileAlloc(
            std.testing.io,
            "sources.list",
            allocator,
            .limited(4096),
        );
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "sources.list",
            .data = "not-an-apt-source\n",
        });
        options.lock_output_path = null;
        options.lock_input_path = fixture.lock_path;
        options.assume_yes = true;
        options.noninteractive = true;
        options.conffile = .keep_existing;
        const owner_id: [32]u8 = @splat(0x37);
        const failed = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .execute,
            .selectors = &selectors,
            .options = options,
            .orchestration_id = owner_id,
        });
        try std.testing.expect(failed.exit_status != .success);
        try std.testing.expectEqual(@as(usize, 0), process.calls);
        if (backend.completion_crash != null) {
            try std.testing.expect(initial_crash.triggered);
        } else {
            const abandoned = (try backendDeferredMarker(
                allocator,
                &directory,
            )).?;
            try std.testing.expectEqual(
                root_operation.DeferredAcknowledgmentState.abandoned,
                abandoned.state,
            );
            try std.testing.expect((try backendRootRecord(
                allocator,
                &directory,
            )) == null);
        }
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "sources.list",
            .data = valid_source,
        });

        var rotation_crash: TestCompletionCrash = .{
            .point = rotation_point,
        };
        backend.completion_crash = rotation_crash.interface();
        const interrupted = try backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .execute,
            .selectors = &selectors,
            .options = options,
            .orchestration_id = owner_id,
        });
        try std.testing.expectEqual(api.ExitStatus.internal, interrupted.exit_status);
        try std.testing.expect(rotation_crash.triggered);
        try std.testing.expectEqual(@as(usize, 0), process.calls);

        var reopened_backend: Backend = .{
            .io = std.testing.io,
            .now_unix = @import("fixtures/openpgp.zig").created + 30,
            .process_runner = process.interface(),
        };
        var foreign_options = options;
        foreign_options.state_path = try std.fmt.allocPrint(
            allocator,
            "{s}-foreign-rotation",
            .{fixture.state_path},
        );
        const foreign = try reopened_backend.executeWorkflow(allocator, .{
            .operation = .install,
            .mode = .execute,
            .selectors = &selectors,
            .options = foreign_options,
            .orchestration_id = @splat(0x48),
        });
        try std.testing.expectEqual(api.ExitStatus.recovery, foreign.exit_status);
        try std.testing.expectEqual(@as(usize, 0), process.calls);

        const completed = try reopened_backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .execute,
            .selectors = &selectors,
            .options = options,
            .orchestration_id = owner_id,
        });
        try std.testing.expectEqual(api.ExitStatus.success, completed.exit_status);
        try std.testing.expect(process.calls != 0);
        try std.testing.expect((try backendRootRecord(
            allocator,
            &directory,
        )) == null);
        const released = (try backendDeferredMarker(
            allocator,
            &directory,
        )).?;
        try std.testing.expectEqual(
            root_operation.DeferredAcknowledgmentState.released,
            released.state,
        );
        const acknowledged = try reopened_backend.executeWorkflow(allocator, .{
            .operation = .remove,
            .mode = .recover,
            .selectors = &selectors,
            .options = options,
            .orchestration_id = owner_id,
            .finalize_ownership = true,
            .ownership_acknowledgment = .{
                .attempt_id = released.attempt_id,
                .marker_sha256 = released.digest_sha256,
                .marker_exact_identity_sha256 = root_operation.deferredAcknowledgmentExactIdentity(
                    released,
                ),
                .acknowledgment_id = owner_id,
                .marker = released,
            },
        });
        try std.testing.expectEqual(api.ExitStatus.success, acknowledged.exit_status);
        try std.testing.expect((try backendDeferredMarker(
            allocator,
            &directory,
        )) == null);
    }
}

test "production workflow successful recovery publishes honest completion evidence" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var fixture = try ProductionWorkflowFixture.init(allocator, &directory,
        \\Package: removable
        \\Status: install ok installed
        \\Priority: optional
        \\Architecture: amd64
        \\Version: 1
        \\
    );
    defer fixture.deinit();
    var process = FailOnceProcess{ .io = std.testing.io, .dir = directory.dir };
    var backend: Backend = .{
        .io = std.testing.io,
        .now_unix = @import("fixtures/openpgp.zig").created + 30,
        .process_runner = process.interface(),
    };
    const selectors = [_]solver.PackageSelector{.{ .name = "removable" }};
    var options = fixture.options();
    options.lock_output_path = fixture.lock_path;
    const planned = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .plan_only,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.success, planned.exit_status);

    options.lock_output_path = null;
    options.lock_input_path = fixture.lock_path;
    options.assume_yes = true;
    options.noninteractive = true;
    options.conffile = .keep_existing;
    const failed = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .execute,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.transaction, failed.exit_status);
    try std.testing.expectEqual(@as(usize, 1), process.calls);

    const recovered = try backend.executeWorkflow(allocator, .{
        .operation = .remove,
        .mode = .recover,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.success, recovered.exit_status);
    try std.testing.expect(process.calls > 1);
    const completion_source = try directory.dir.readFileAlloc(
        std.testing.io,
        "root/" ++ root_operation_completion.document_path,
        allocator,
        .limited(root_operation_completion.maximum_document_bytes),
    );
    var completion = try root_operation_completion.decode(
        allocator,
        completion_source,
        root_operation_completion.maximum_document_bytes,
    );
    defer completion.deinit();
    try std.testing.expect(
        completion.document.transaction_provenance.status ==
            .unavailable or
            completion.document.transaction_provenance.status == .recovered,
    );
    try std.testing.expectEqual(root_operation.Outcome.recovered, completion.document.outcome);
    try std.testing.expectEqualStrings("recover", completion.document.discharge.operation);
    try std.testing.expectEqualSlices(
        u8,
        &(try workflowProductRequestDigest(
            allocator,
            .remove,
            .execute,
            &selectors,
            options,
        )),
        &completion.document.request_sha256,
    );
    try std.testing.expectEqualSlices(
        u8,
        &(try workflowProductRequestDigest(
            allocator,
            .remove,
            .recover,
            &selectors,
            options,
        )),
        &completion.document.discharge.request_sha256,
    );
    const lock_source = try readFile(
        allocator,
        std.testing.io,
        fixture.lock_path,
        exact_lock.maximum_document_bytes,
    );
    var lock = try exact_lock.decode(
        allocator,
        lock_source,
        exact_lock.maximum_document_bytes,
    );
    defer lock.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &(try workflowSemanticRequestDigest(
            allocator,
            .remove,
            &selectors,
        )),
        &lock.lock.request_sha256,
    );
}

test "production workflow accepts batch install planning and requires lock-bound execution" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const signed_fixture = @import("fixtures/openpgp.zig");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var fixture = try ProductionWorkflowFixture.init(allocator, &directory, "");
    defer fixture.deinit();
    var process = TestProcess{ .io = std.testing.io, .dir = directory.dir };
    var backend: Backend = .{
        .io = std.testing.io,
        .now_unix = signed_fixture.created + 30,
        .process_runner = process.interface(),
    };
    const selectors = [_]solver.PackageSelector{ .{ .name = "hello" }, .{ .name = "missing" } };
    var options = fixture.options();
    options.lock_output_path = fixture.lock_path;
    const planned = try backend.executeWorkflow(allocator, .{
        .operation = .install,
        .mode = .plan_only,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.planning, planned.exit_status);
    try std.testing.expectEqual(@as(usize, 0), process.calls);

    options.lock_output_path = null;
    options.assume_yes = true;
    options.noninteractive = true;
    options.conffile = .keep_existing;
    const no_lock = try backend.executeWorkflow(allocator, .{
        .operation = .install,
        .mode = .execute,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ExitStatus.usage, no_lock.exit_status);
    try std.testing.expectEqual(api.ErrorId.configuration_required, no_lock.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 0), process.calls);

    options.lock_input_path = "/explicit/exact-lock.json";
    options.assume_yes = false;
    const no_confirmation = try backend.executeWorkflow(allocator, .{
        .operation = .install,
        .mode = .execute,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ErrorId.confirmation_required, no_confirmation.diagnostics[0].id);
    options.assume_yes = true;
    options.conffile = .unspecified;
    const no_conffile = try backend.executeWorkflow(allocator, .{
        .operation = .install,
        .mode = .execute,
        .selectors = &selectors,
        .options = options,
    });
    try std.testing.expectEqual(api.ErrorId.conffile_policy_required, no_conffile.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 0), process.calls);
}

test "production workflow digest binds every selector and product v1 stays singleton" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const options: api.CommonOptions = .{
        .install_root = "/root",
        .cache_path = "/cache",
        .state_path = "/state",
        .architecture = "amd64",
        .assume_yes = true,
    };
    const selector = [_]solver.PackageSelector{.{ .name = "first" }};
    const selectors = [_]solver.PackageSelector{
        .{ .name = "first" },
        .{ .name = "second", .architecture = "amd64", .version = "1" },
    };
    const reversed = [_]solver.PackageSelector{ selectors[1], selectors[0] };
    const first_semantic = try semanticRequestDigest(
        allocator,
        .plan,
        .{ .operation = .install, .mode = .plan_only },
        &selector,
    );
    const planned_semantic = try semanticRequestDigest(
        allocator,
        .plan,
        .{ .operation = .install, .mode = .plan_only },
        &selectors,
    );
    const downloaded_semantic = try semanticRequestDigest(
        allocator,
        .download,
        .{ .operation = .install, .mode = .download_only },
        &reversed,
    );
    const executed_semantic = try semanticRequestDigest(
        allocator,
        .install,
        .{ .operation = .install, .mode = .execute },
        &reversed,
    );
    const recovered_semantic = try semanticRequestDigest(
        allocator,
        .recover,
        .{ .operation = .install, .mode = .recover },
        &selectors,
    );
    const removed_semantic = try semanticRequestDigest(
        allocator,
        .remove,
        .{ .operation = .remove, .mode = .execute },
        &selectors,
    );
    try std.testing.expect(!std.mem.eql(u8, &first_semantic, &planned_semantic));
    try std.testing.expectEqualSlices(u8, &planned_semantic, &downloaded_semantic);
    try std.testing.expectEqualSlices(u8, &planned_semantic, &executed_semantic);
    try std.testing.expectEqualSlices(u8, &planned_semantic, &recovered_semantic);
    try std.testing.expect(!std.mem.eql(u8, &planned_semantic, &removed_semantic));

    const execute_first = productRequestDigest(.{
        .operation = .install,
        .packages = &.{"first"},
        .options = options,
    });
    const execute_batch = productRequestDigest(.{
        .operation = .install,
        .packages = &.{ "first", "second:amd64=1" },
        .options = options,
    });
    const recovery_first = productRequestDigest(.{
        .operation = .recover,
        .packages = &.{"first"},
        .options = options,
    });
    const recovery_batch = productRequestDigest(.{
        .operation = .recover,
        .packages = &.{ "first", "second:amd64=1" },
        .options = options,
    });
    try std.testing.expect(!std.mem.eql(u8, &execute_first, &execute_batch));
    try std.testing.expect(!std.mem.eql(u8, &recovery_first, &recovery_batch));
    try std.testing.expectEqualSlices(
        u8,
        &execute_batch,
        &(try workflowProductRequestDigest(
            allocator,
            .install,
            .execute,
            &selectors,
            options,
        )),
    );
    try std.testing.expectEqualSlices(
        u8,
        &recovery_batch,
        &(try workflowProductRequestDigest(
            allocator,
            .install,
            .recover,
            &selectors,
            options,
        )),
    );

    var backend: Backend = .{ .io = std.testing.io };
    const rejected = try api.execute(allocator, .{
        .operation = .install,
        .packages = &.{ "first", "second" },
        .options = options,
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.usage, rejected.exit_status);
    try std.testing.expectEqual(api.ErrorId.invalid_request, rejected.diagnostics[0].id);
}

test "production backend reports command-specific missing repository input" {
    var backend: Backend = .{ .io = std.testing.io };
    const result = try backend.execute(std.testing.allocator, .{
        .operation = .list_available,
        .options = .{
            .install_root = "/fixture/root",
            .cache_path = "/fixture/cache",
            .state_path = "/fixture/state",
            .architecture = "amd64",
        },
    });
    try std.testing.expectEqual(api.ExitStatus.usage, result.exit_status);
    try std.testing.expectEqual(api.ErrorId.configuration_required, result.diagnostics[0].id);
}

test "production credentials are restricted to one repository origin" {
    var context = try CredentialContext.fromUri(
        std.testing.allocator,
        try repository_acquisition.Uri.parse("https://repo.example:443/debian"),
        "Bearer secret",
    );
    defer context.deinit(std.testing.allocator);
    try std.testing.expect((try CredentialContext.get(
        &context,
        try repository_acquisition.Uri.parse("https://REPO.example/other"),
    )) != null);
    try std.testing.expect((try CredentialContext.get(
        &context,
        try repository_acquisition.Uri.parse("https://attacker.example/debian"),
    )) == null);
    try std.testing.expect((try CredentialContext.get(
        &context,
        try repository_acquisition.Uri.parse("https://repo.example:444/debian"),
    )) == null);
}

test "production explicit file reads reject symlinked parents" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "real");
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "real/input", .data = "secret" });
    try directory.dir.symLink(std.testing.io, "real", "linked", .{ .is_directory = true });
    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/linked/input",
        .{real_buffer[0..real_length]},
    );
    defer std.testing.allocator.free(path);
    try std.testing.expectError(
        error.NotDir,
        readFile(std.testing.allocator, std.testing.io, path, 1024),
    );
}

test "production backend authenticates an explicit file repository" {
    const fixture = @import("fixtures/openpgp.zig");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "repo/dists/stable/main/binary-amd64");
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.createDirPath(std.testing.io, "state");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "repo/dists/stable/InRelease",
        .data = &fixture.repository_in_release,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "repo/dists/stable/main/binary-amd64/Packages",
        .data = &fixture.repository_packages,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "keyring.gpg",
        .data = &fixture.keyring,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "",
    });

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const root = real_buffer[0..real_length];
    const source_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sources.list", .{root});
    defer std.testing.allocator.free(source_path);
    const keyring_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/keyring.gpg", .{root});
    defer std.testing.allocator.free(keyring_path);
    const repository_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/repo", .{root});
    defer std.testing.allocator.free(repository_path);
    const source_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "deb [arch=amd64 signed-by={s}] file://{s} stable main\n",
        .{ keyring_path, repository_path },
    );
    defer std.testing.allocator.free(source_bytes);
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "sources.list",
        .data = source_bytes,
    });
    const install_root = try std.fmt.allocPrint(std.testing.allocator, "{s}/root", .{root});
    defer std.testing.allocator.free(install_root);
    const cache_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/cache", .{root});
    defer std.testing.allocator.free(cache_path);
    const state_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state", .{root});
    defer std.testing.allocator.free(state_path);

    var backend: Backend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
    };
    const result = try api.execute(std.testing.allocator, .{
        .operation = .list_available,
        .options = .{
            .install_root = install_root,
            .source_paths = &.{source_path},
            .keyring_paths = &.{keyring_path},
            .cache_path = cache_path,
            .state_path = state_path,
            .architecture = "amd64",
        },
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expect(result.items.len != 0);
}

test "production exact lock imports and validates the installed baseline" {
    const fixture = @import("fixtures/openpgp.zig");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "repo/dists/stable/main/binary-amd64");
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.createDirPath(std.testing.io, "state");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "repo/dists/stable/InRelease",
        .data = &fixture.repository_in_release,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "repo/dists/stable/main/binary-amd64/Packages",
        .data = &fixture.repository_packages,
    });
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "keyring.gpg", .data = &fixture.keyring });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data =
        \\Package: hello
        \\Status: install ok installed
        \\Priority: optional
        \\Architecture: amd64
        \\Version: 1.0-1
        \\
        ,
    });

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const root = real_buffer[0..real_length];
    const source_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sources.list", .{root});
    defer std.testing.allocator.free(source_path);
    const keyring_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/keyring.gpg", .{root});
    defer std.testing.allocator.free(keyring_path);
    const repository_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/repo", .{root});
    defer std.testing.allocator.free(repository_path);
    const source_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "deb [arch=amd64 signed-by={s}] file://{s} stable main\n",
        .{ keyring_path, repository_path },
    );
    defer std.testing.allocator.free(source_bytes);
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "sources.list", .data = source_bytes });
    const install_root = try std.fmt.allocPrint(std.testing.allocator, "{s}/root", .{root});
    defer std.testing.allocator.free(install_root);
    const cache_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/cache", .{root});
    defer std.testing.allocator.free(cache_path);
    const state_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state", .{root});
    defer std.testing.allocator.free(state_path);
    const lock_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/exact-lock.json", .{root});
    defer std.testing.allocator.free(lock_path);

    var backend: Backend = .{ .io = std.testing.io, .now_unix = fixture.created + 30 };
    const resolved = try api.execute(std.testing.allocator, .{
        .operation = .plan,
        .packages = &.{"hello"},
        .options = .{
            .install_root = install_root,
            .source_paths = &.{source_path},
            .keyring_paths = &.{keyring_path},
            .cache_path = cache_path,
            .state_path = state_path,
            .architecture = "amd64",
            .lock_output_path = lock_path,
        },
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, resolved.exit_status);
    const lock_bytes = try readFile(
        std.testing.allocator,
        std.testing.io,
        lock_path,
        exact_lock.maximum_document_bytes,
    );
    defer std.testing.allocator.free(lock_bytes);
    var lock = try exact_lock.decode(
        std.testing.allocator,
        lock_bytes,
        exact_lock.maximum_document_bytes,
    );
    defer lock.deinit();
    try std.testing.expectEqual(@as(usize, 1), lock.lock.packages.len);
    try std.testing.expectEqual(exact_lock.Retention.retained, lock.lock.packages[0].retention);
    try std.testing.expectEqualStrings("hello", lock.lock.packages[0].name);
    try std.testing.expectEqualStrings("1.0-1", lock.lock.packages[0].version);
    try std.testing.expectEqualStrings("amd64", lock.lock.packages[0].architecture);

    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data =
        \\Package: hello
        \\Status: install ok installed
        \\Priority: optional
        \\Architecture: amd64
        \\Version: 1.0-2
        \\
        ,
    });
    const drift = try api.execute(std.testing.allocator, .{
        .operation = .plan,
        .packages = &.{"hello"},
        .options = .{
            .install_root = install_root,
            .source_paths = &.{source_path},
            .keyring_paths = &.{keyring_path},
            .cache_path = cache_path,
            .state_path = state_path,
            .architecture = "amd64",
            .lock_output_path = lock_path,
        },
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.planning, drift.exit_status);

    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data =
        \\Package: baseline-only
        \\Status: install ok installed
        \\Priority: optional
        \\Architecture: amd64
        \\Version: 1
        \\
        ,
    });
    const missing = try api.execute(std.testing.allocator, .{
        .operation = .plan,
        .packages = &.{"hello"},
        .options = .{
            .install_root = install_root,
            .source_paths = &.{source_path},
            .keyring_paths = &.{keyring_path},
            .cache_path = cache_path,
            .state_path = state_path,
            .architecture = "amd64",
            .lock_output_path = lock_path,
        },
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.planning, missing.exit_status);
}

test "production backend mutation uses injected process runner" {
    const fixture = @import("fixtures/openpgp.zig");
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "repo/dists/stable/main/binary-amd64");
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/debz");
    try directory.dir.createDirPath(std.testing.io, "state");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "repo/dists/stable/InRelease",
        .data = &fixture.repository_in_release,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "repo/dists/stable/main/binary-amd64/Packages",
        .data = &fixture.repository_packages,
    });
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "keyring.gpg", .data = &fixture.keyring });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data =
        \\Package: removable
        \\Status: install ok installed
        \\Priority: optional
        \\Architecture: amd64
        \\Version: 1
        \\
        ,
    });

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try directory.dir.realPath(std.testing.io, &real_buffer);
    const root = real_buffer[0..real_length];
    const source_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sources.list", .{root});
    defer std.testing.allocator.free(source_path);
    const keyring_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/keyring.gpg", .{root});
    defer std.testing.allocator.free(keyring_path);
    const repository_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/repo", .{root});
    defer std.testing.allocator.free(repository_path);
    const source_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "deb [arch=amd64 signed-by={s}] file://{s} stable main\n",
        .{ keyring_path, repository_path },
    );
    defer std.testing.allocator.free(source_bytes);
    try directory.dir.writeFile(std.testing.io, .{ .sub_path = "sources.list", .data = source_bytes });
    const install_root = try std.fmt.allocPrint(std.testing.allocator, "{s}/root", .{root});
    defer std.testing.allocator.free(install_root);
    const cache_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/cache", .{root});
    defer std.testing.allocator.free(cache_path);
    const state_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state", .{root});
    defer std.testing.allocator.free(state_path);

    var fake = TestProcess{ .io = std.testing.io, .dir = directory.dir };
    var backend: Backend = .{
        .io = std.testing.io,
        .now_unix = fixture.created + 30,
        .process_runner = fake.interface(),
    };
    const result = try api.execute(std.testing.allocator, .{
        .operation = .remove,
        .packages = &.{"removable"},
        .options = .{
            .install_root = install_root,
            .source_paths = &.{source_path},
            .keyring_paths = &.{keyring_path},
            .cache_path = cache_path,
            .state_path = state_path,
            .architecture = "amd64",
            .assume_yes = true,
        },
    }, backend.interface());
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expect(result.changed);
    try std.testing.expectError(
        error.FileNotFound,
        directory.dir.openFile(std.testing.io, "state/recovery-request.json", .{}),
    );
}
