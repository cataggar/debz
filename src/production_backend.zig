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
const solver = @import("solver.zig");
const source = @import("source.zig");
const transaction_engine = @import("transaction_engine.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_recovery = @import("transaction_recovery.zig");
const transaction_provenance = @import("transaction_provenance.zig");
const exact_lock = @import("exact_lock.zig");
const openpgp = @import("openpgp_verifier.zig");

pub const Executor = transaction_engine.Executor;

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
            else => self.withRepositories(allocator, request),
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

    fn withRepositories(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !api.Result {
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
        if (rootOperationSurface(request.operation)) |operation| {
            if (guard.open(allocator, request, operation)) |failure| return failure;
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
            .mode = if (request.operation == .recover or request.options.offline or request.options.cache_only)
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
        const planning_records = if (request.operation == .recover)
            try healthyInstalledRecords(allocator, installed.database.packages)
        else
            installed.database.packages;
        defer if (request.operation == .recover) allocator.free(planning_records);
        const policies = try installedPolicies(allocator, planning_records);
        defer allocator.free(policies);
        var recovery_intent: ?std.json.Parsed(RecoveryIntent) = if (request.operation == .recover)
            try readRecoveryIntent(allocator, self.io, request.options.state_path)
        else
            null;
        defer if (recovery_intent) |*value| value.deinit();
        var effective_request = request;
        if (recovery_intent) |*intent| {
            effective_request.operation = intent.value.operation;
            effective_request.packages = intent.value.packages;
            effective_request.options.recommends = intent.value.recommends;
            effective_request.options.allow_downgrade = intent.value.allow_downgrade;
            effective_request.options.repository_policy = intent.value.repository_policy;
            effective_request.options.conffile = intent.value.conffile;
            effective_request.options.force = intent.value.force;
            effective_request.options.lock_wait_ms = intent.value.lock_wait_ms;
        }
        if (request.options.lock_output_path != null and request.options.lock_input_path == null and
            request.operation != .plan and request.operation != .download)
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
        var planning = try solver.planTransaction(allocator, .{
            .repositories = refreshed.universe.repositories,
            .installed = .{
                .records = planning_records,
                .native_architecture = request.options.architecture,
                .policies = policies,
                .hold_authority = .explicit_policy,
            },
            .target_architecture = request.options.architecture,
            .mode = if (effective_request.operation == .download) .download_only else .plan_only,
            .request = try planRequestFromSelectors(effective_request.operation, selectors),
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
        if (request.operation == .plan) return planResult(allocator, request.operation, plan.*);

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
                        .workflow = if (request.operation == .download) .download_only else .transaction,
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
        if (request.operation == .download)
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
        if (request.operation == .recover) {
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
                    report.commands.len != 0 or report.state != .not_started,
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
                report.commands.len != 0,
                .recovered,
            )) |failure| return failure;
            try deleteRecoveryIntent(self.io, request.options.state_path);
            if (try guard.finish(allocator, request.operation)) |failure| return failure;
            return success(request.operation, true, "transaction recovery completed", &.{});
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
                report.commands.len != 0,
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
            report.commands.len != 0,
            .succeeded,
        )) |failure| return failure;
        try deleteRecoveryIntent(self.io, request.options.state_path);
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
        if (try guard.finish(allocator, request.operation)) |failure| return failure;
        return planResultChanged(allocator, request.operation, plan.*, true, "transaction completed");
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

    const Completion = enum { succeeded, failed, recovered };

    /// Pointer to the live attempt, never a copy: every boundary must be
    /// published on the record this guard owns.
    fn active(self: *RootOperationGuard) ?*root_operation.Attempt {
        if (self.attempt) |*value| return value;
        return null;
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
        }) catch |err| return mapRootOperationError(request.operation, err);
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

    /// Resolves the bridge from the executor's command evidence. No command
    /// means no dpkg invocation, which is the only way this backend can prove
    /// that nothing was mutated.
    fn observe(
        self: *RootOperationGuard,
        allocator: std.mem.Allocator,
        operation: api.Operation,
        mutation_observed: bool,
        completion: Completion,
    ) !?api.Result {
        var attempt = self.active() orelse return null;
        // Already finished; `finish` still owes its provenance.
        if (attempt.record().state == .completed) return null;
        if (attempt.record().state == .mutation_pending) {
            attempt.witness(
                allocator,
                if (mutation_observed) .mutation_observed else .proved_not_started,
            ) catch |err| return mapRootOperationError(operation, err);
            // No command ran, so the attempt is durably abandoned before any
            // mutation and needs no further boundary.
            if (!mutation_observed) return null;
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
        attempt.clear() catch |err| return mapRootOperationError(operation, err);
        return null;
    }

    fn deinit(self: *RootOperationGuard) void {
        if (self.attempt) |*value| {
            // An attempt durably proven never to have mutated the root is
            // released rather than left behind, and a finished attempt whose
            // provenance obligation is discharged is cleared. Anything at or
            // past the executor bridge stays exactly as published, so the next
            // mutation is refused until it is explicitly recovered. A failure
            // here simply leaves the record, which the next attempt reports.
            if (value.locked()) {
                if (value.record().state.provenPreMutation())
                    value.abandonIfPreMutation(self.allocator) catch {}
                else if (value.record().clearable()) value.clear() catch {};
            }
            value.release();
        }
        self.attempt = null;
        if (self.owned_root) |*value| value.close();
        self.owned_root = null;
    }
};

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
        error.OperationInProgress, error.ResolvedAttemptPresent => api.failure(
            operation,
            .recovery,
            .root_operation_conflict,
            "an interrupted debz operation left an unresolved root attempt",
        ),
        error.RecoveryRequired, error.ProvenancePending => api.failure(
            operation,
            .recovery,
            .root_operation_recovery_required,
            "a previous debz operation mutated this root and requires recovery",
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

fn planRequestFromSelectors(operation: api.Operation, selectors: []solver.PackageSelector) !solver.PlanRequest {
    return switch (operation) {
        .install, .plan, .download => if (selectors.len == 0) .upgrade_all else .{ .install = selectors[0] },
        .remove => .{ .remove = selectors[0] },
        .upgrade => .{ .upgrade = selectors },
        .upgrade_all => .upgrade_all,
        .reinstall => .{ .reinstall = selectors[0] },
        .recover => .upgrade_all,
        else => error.InvalidOperation,
    };
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
        request.options.install_root = "/alternate";
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

    const plan_json = try plan.canonicalJson(allocator);
    defer allocator.free(plan_json);
    var request_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(plan_json, &request_digest, .{});
    return exact_lock.create(allocator, .{
        .target_architecture = request.options.architecture,
        .request_sha256 = request_digest,
        .policy_sha256 = package_cache_workflow.solverPolicyDigest(
            request.options.recommends,
            request.options.allow_downgrade,
            switch (request.options.repository_policy) {
                .strict_priority => .strict_priority,
                .best_version => .best_version,
            },
        ),
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
    const store = try transaction_provenance.Store.init(io, dir, "transaction-result.json");
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

    fn interface(self: *TestProcess) transaction_executor.ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(context: *anyopaque, invocation: transaction_executor.Invocation) !transaction_executor.ProcessResult {
        const self: *TestProcess = @ptrCast(@alignCast(context));
        if (invocation.phase == .remove) try self.dir.writeFile(self.io, .{
            .sub_path = "root/var/lib/dpkg/status",
            .data = "",
        });
        return .{ .termination = .{ .exited = 0 } };
    }
};

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
    try std.testing.expect((try context.get(
        &context,
        try repository_acquisition.Uri.parse("https://REPO.example/other"),
    )) != null);
    try std.testing.expect((try context.get(
        &context,
        try repository_acquisition.Uri.parse("https://attacker.example/debian"),
    )) == null);
    try std.testing.expect((try context.get(
        &context,
        try repository_acquisition.Uri.parse("https://repo.example:444/debian"),
    )) == null);
}

test "production explicit file reads reject symlinked parents" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.makePath(std.testing.io, "real");
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
    try directory.dir.makePath(std.testing.io, "repo/dists/stable/main/binary-amd64");
    try directory.dir.makePath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.makePath(std.testing.io, "state");
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
    try directory.dir.makePath(std.testing.io, "repo/dists/stable/main/binary-amd64");
    try directory.dir.makePath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.makePath(std.testing.io, "state");
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
    try directory.dir.makePath(std.testing.io, "repo/dists/stable/main/binary-amd64");
    try directory.dir.makePath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.makePath(std.testing.io, "root/var/lib/debz");
    try directory.dir.makePath(std.testing.io, "state");
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
