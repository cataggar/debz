const std = @import("std");
const api = @import("product_api.zig");
const debian_version = @import("debian_version.zig");
const deb_payload = @import("deb_payload.zig");
const dpkg_status = @import("dpkg_status.zig");
const metadata_cache = @import("metadata_cache.zig");
const package_acquisition = @import("package_acquisition.zig");
const repository_acquisition = @import("repository_acquisition.zig");
const repository_policy = @import("repository_policy.zig");
const repository_refresh = @import("repository_refresh.zig");
const solver = @import("solver.zig");
const source = @import("source.zig");
const target_apt_config = @import("target_apt_config.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_recovery = @import("transaction_recovery.zig");
const transaction_provenance = @import("transaction_provenance.zig");
const transaction_provenance_v2 = @import("transaction_provenance_v2.zig");
const transaction_provenance_v3 = @import("transaction_provenance_v3.zig");
const exact_lock = @import("exact_lock.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const openpgp = @import("openpgp_verifier.zig");

pub const Executor = struct {
    context: *anyopaque,
    executeFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        transaction_executor.Request,
        transaction_executor.Dependencies,
    ) anyerror!transaction_executor.Report,
    recoverFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        transaction_executor.RecoveryRequest,
        transaction_executor.Dependencies,
    ) anyerror!transaction_executor.RecoveryReport,

    pub const system: Executor = .{
        .context = @ptrCast(@constCast(&system_executor_context)),
        .executeFn = systemExecute,
        .recoverFn = systemRecover,
    };
};

var system_executor_context: u8 = 0;

fn systemExecute(
    _: *anyopaque,
    allocator: std.mem.Allocator,
    request: transaction_executor.Request,
    dependencies: transaction_executor.Dependencies,
) !transaction_executor.Report {
    return transaction_executor.execute(allocator, request, dependencies);
}

fn systemRecover(
    _: *anyopaque,
    allocator: std.mem.Allocator,
    request: transaction_executor.RecoveryRequest,
    dependencies: transaction_executor.Dependencies,
) !transaction_executor.RecoveryReport {
    return transaction_executor.recover(allocator, request, dependencies);
}

pub const Backend = struct {
    io: std.Io,
    executor: Executor = .system,
    process_runner: ?transaction_executor.ProcessRunner = null,
    now_unix: ?i64 = null,
    system_profile: bool = false,
    system_snapshot: ?*const target_apt_config.Snapshot = null,

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

    fn route(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !api.Result {
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
        if (self.system_profile and request.operation.mutates() and
            request.operation != .recover)
        {
            var pending = try readRecoveryIntentIfPresent(
                allocator,
                self.io,
                request.options.state_path,
            );
            defer if (pending) |*intent| intent.deinit();
            if (pending) |*intent| {
                const exact_lock_path = if (intent.value.exact_lock_path) |path|
                    try allocator.dupe(u8, path)
                else
                    null;
                const recovery_path = if (intent.value.evidence_directory) |path|
                    try std.fmt.allocPrint(
                        allocator,
                        "{s}/recovery-request.json",
                        .{path},
                    )
                else
                    null;
                return api.failureWithPaths(
                    request.operation,
                    .recovery,
                    .recovery_required,
                    "an interrupted transaction is retained; run 'debz recover' before planning another mutation",
                    .{
                        .exact_lock = exact_lock_path,
                        .recovery = recovery_path,
                    },
                );
            }
        }
        var loaded_storage: LoadedDocuments = undefined;
        var loaded_initialized = false;
        defer if (loaded_initialized) loaded_storage.deinit();
        var configuration_storage: repository_policy.Configuration = undefined;
        var configuration_initialized = false;
        defer if (configuration_initialized) configuration_storage.deinit();
        const configuration: *const repository_policy.Configuration = if (self.system_snapshot) |snapshot|
            &snapshot.configuration
        else blk: {
            if (request.options.source_paths.len == 0 and request.options.config_paths.len == 0)
                return api.failure(request.operation, .usage, .configuration_required, "repository command requires --source or --config");
            if (request.options.keyring_paths.len == 0)
                return api.failure(request.operation, .usage, .configuration_required, "authenticated repository command requires --keyring");

            loaded_storage = try self.loadRepositoryDocuments(allocator, request);
            loaded_initialized = true;
            const normalized = try repository_policy.normalize(
                allocator,
                loaded_storage.documents,
                request.options.architecture,
                .{},
            );
            configuration_storage = switch (normalized) {
                .diagnostic => |diagnostic| return api.failure(
                    request.operation,
                    .usage,
                    .configuration_required,
                    diagnostic.message(),
                ),
                .configuration => |value| value,
            };
            configuration_initialized = true;
            for (configuration_storage.repositories) |repository| {
                if (repository.signed_by.len == 0)
                    return api.failure(request.operation, .usage, .configuration_required, "every repository source must declare Signed-By");
                for (repository.signed_by) |path| if (!containsString(request.options.keyring_paths, path))
                    return api.failure(request.operation, .usage, .configuration_required, "Signed-By path was not declared with --keyring");
            }
            break :blk &configuration_storage;
        };

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
        const runtimes = try makeRuntimes(
            allocator,
            request,
            configuration,
            self.system_snapshot,
            now,
            credentials,
        );
        defer freeRuntimes(allocator, runtimes);
        var refresh_outcome = try repository_policy.refreshAll(allocator, .{
            .configuration = configuration,
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
            if (effective_request.options.lock_input_path == null)
                effective_request.options.lock_input_path = intent.value.exact_lock_path;
        }
        if (request.options.lock_output_path != null and effective_request.options.lock_input_path == null and
            request.operation != .plan and request.operation != .download)
            return api.failure(request.operation, .usage, .configuration_required, "--lock-output without --lock-input is restricted to non-mutating plan or download lock resolution");
        var lock: ?exact_lock.OwnedLock = null;
        defer if (lock) |*value| value.deinit();
        var lock_v2: ?exact_lock_v2.OwnedLock = null;
        defer if (lock_v2) |*value| value.deinit();
        if (effective_request.options.lock_input_path) |path| {
            lock = readLock(allocator, self.io, path) catch null;
            if (lock == null and self.system_profile)
                lock_v2 = readLockV2(allocator, self.io, path) catch null;
            if (lock == null and lock_v2 == null)
                return api.failure(
                    request.operation,
                    .planning,
                    .planning_failed,
                    "exact lock is invalid",
                );
        }
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
        if (try dependencyVersionConflict(
            allocator,
            plan.*,
            planning_records,
            refreshed.universe.repositories,
        )) |message|
            return api.failure(
                request.operation,
                .planning,
                .planning_failed,
                message,
            );
        if (!effective_request.options.allow_downgrade) {
            for (plan.actions) |action| {
                if (action.kind == .downgrade)
                    return api.failure(
                        request.operation,
                        .planning,
                        .planning_failed,
                        try std.fmt.allocPrint(
                            allocator,
                            "dependency solution requires forbidden downgrade of {s} to {s}",
                            .{ action.package, action.version },
                        ),
                    );
            }
        }
        var generated_lock: ?exact_lock.OwnedLock = null;
        defer if (generated_lock) |*value| value.deinit();
        var generated_lock_v2: ?exact_lock_v2.OwnedLock = null;
        defer if (generated_lock_v2) |*value| value.deinit();
        if (self.system_profile and request.operation.mutates() and
            request.operation != .recover and
            effective_request.options.lock_input_path == null and
            plan.actions.len == 0)
            return planResultChanged(
                allocator,
                request.operation,
                plan.*,
                false,
                "requested state already satisfied",
            );
        const generate_lock = lock == null and lock_v2 == null and
            request.options.lock_output_path != null;
        if (generate_lock) {
            generated_lock = lockFromPlan(
                allocator,
                effective_request,
                refreshed,
                planning_records,
                plan.*,
                request.options.lock_output_path != null,
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
        }
        const generate_system_lock = lock == null and lock_v2 == null and
            self.system_profile and request.operation.mutates() and
            request.operation != .recover;
        if (generate_system_lock) {
            generated_lock_v2 = lockV2FromPlan(
                allocator,
                effective_request,
                refreshed,
                plan.*,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return api.failure(
                    request.operation,
                    .planning,
                    .planning_failed,
                    try std.fmt.allocPrint(
                        allocator,
                        "authenticated plan could not produce a complete exact lock: {s}",
                        .{@errorName(err)},
                    ),
                ),
            };
        }
        const effective_lock: ?*const exact_lock.Lock = if (lock) |*value|
            &value.lock
        else if (generated_lock) |*value|
            &value.lock
        else
            null;
        const effective_lock_v2: ?*const exact_lock_v2.Lock = if (lock_v2) |*value|
            &value.lock
        else if (generated_lock_v2) |*value|
            &value.lock
        else
            null;
        if (request.options.lock_output_path) |path| {
            try writeLock(allocator, self.io, path, effective_lock.?.*);
        }
        var transaction_evidence: ?TransactionEvidence = null;
        if (self.system_profile and request.operation.mutates() and
            request.operation != .recover)
        {
            transaction_evidence = (if (effective_lock_v2) |value|
                prepareTransactionEvidenceV2(
                    allocator,
                    self.io,
                    request.options.state_path,
                    value.*,
                    effective_request.options.lock_input_path,
                )
            else
                prepareTransactionEvidence(
                    allocator,
                    self.io,
                    request.options.state_path,
                    effective_lock.?.*,
                    effective_request.options.lock_input_path,
                )) catch |err| return api.failure(
                request.operation,
                .planning,
                .planning_failed,
                try std.fmt.allocPrint(
                    allocator,
                    "exact lock could not be retained before mutation: {s}",
                    .{@errorName(err)},
                ),
            );
        } else if (request.operation == .recover and recovery_intent != null and
            (effective_lock != null or effective_lock_v2 != null))
        {
            transaction_evidence = .{
                .exact_lock_path = try allocator.dupe(
                    u8,
                    effective_request.options.lock_input_path.?,
                ),
                .directory_path = try allocator.dupe(
                    u8,
                    recovery_intent.?.value.evidence_directory orelse
                        request.options.state_path,
                ),
                .provenance_path = if (recovery_intent.?.value.evidence_directory) |path|
                    try std.fmt.allocPrint(
                        allocator,
                        "{s}/{s}",
                        .{
                            path,
                            if (effective_lock_v2 != null)
                                "transaction-result-v3.json"
                            else
                                "transaction-result.json",
                        },
                    )
                else
                    try std.fmt.allocPrint(
                        allocator,
                        "{s}/transaction-result.json",
                        .{request.options.state_path},
                    ),
                .recovery_path = if (recovery_intent.?.value.evidence_directory) |path|
                    try std.fmt.allocPrint(allocator, "{s}/recovery-request.json", .{path})
                else
                    try std.fmt.allocPrint(
                        allocator,
                        "{s}/recovery-request.json",
                        .{request.options.state_path},
                    ),
            };
        }
        if (request.operation == .plan) {
            var result = try planResult(allocator, request.operation, plan.*);
            result.paths.exact_lock = request.options.lock_output_path orelse
                effective_request.options.lock_input_path;
            return result;
        }

        var package_cache = package_acquisition.Cache.initFromDir(self.io, cache_root, .{
            .maximum_object_bytes = 1024 * 1024 * 1024,
        }) catch |err| return api.failureWithPaths(
            request.operation,
            .download,
            .download_failed,
            try std.fmt.allocPrint(
                allocator,
                "package cache initialization failed: {s}",
                .{@errorName(err)},
            ),
            exactEvidence(transaction_evidence),
        );
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
                    .exact_lock_package = if (effective_lock) |value|
                        value.findPackage(action.package, action.version, action.architecture)
                    else
                        null,
                    .exact_lock_package_v2 = if (effective_lock_v2) |value|
                        value.findPackage(action.package, action.version, action.architecture)
                    else
                        null,
                },
                acquisition.dependencies(),
            ) catch |err| return api.failureWithPaths(
                request.operation,
                .download,
                .download_failed,
                try std.fmt.allocPrint(
                    allocator,
                    "package acquisition failed for {s}={s}:{s}: {s}",
                    .{ action.package, action.version, action.architecture, @errorName(err) },
                ),
                exactEvidence(transaction_evidence),
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
                    return api.failureWithPaths(
                        request.operation,
                        .download,
                        .download_failed,
                        message,
                        exactEvidence(transaction_evidence),
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
        if (request.operation == .download) {
            var result = try planResultChanged(
                allocator,
                request.operation,
                plan.*,
                false,
                "packages downloaded and verified",
            );
            result.paths.exact_lock = request.options.lock_output_path orelse
                effective_request.options.lock_input_path;
            return result;
        }

        var executor_policy = try executionPolicy(
            allocator,
            effective_request,
            self.system_profile,
        );
        if (effective_lock_v2 != null)
            executor_policy.exact_lock_verification = .locked_packages;
        var system_process = transaction_executor.SystemProcessRunner{ .allocator = allocator, .io = self.io };
        defer system_process.deinit();
        var system_files = transaction_executor.SystemFileSystem{ .allocator = allocator, .io = self.io };
        var system_locks = transaction_executor.SystemLockManager{ .allocator = allocator, .io = self.io };
        const journal_path = if (transaction_evidence) |paths|
            paths.directory_path
        else
            request.options.state_path;
        var journal = transaction_recovery.SystemJournalStore.init(
            self.io,
            journal_path,
            request.options.install_root,
        ) catch |err| return api.failureWithPaths(
            request.operation,
            .recovery,
            .recovery_failed,
            try std.fmt.allocPrint(
                allocator,
                "transaction journal initialization failed: {s}",
                .{@errorName(err)},
            ),
            exactEvidence(transaction_evidence),
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
            var report = self.executor.recoverFn(self.executor.context, allocator, .{
                .plan = plan,
                .install_root = request.options.install_root,
                .policy = executor_policy,
                .exact_lock = effective_lock,
                .exact_lock_v2 = effective_lock_v2,
            }, dependencies) catch |err| return api.failureWithPaths(
                request.operation,
                .recovery,
                .recovery_failed,
                try std.fmt.allocPrint(
                    allocator,
                    "recovery executor failed before producing a report: {s}",
                    .{@errorName(err)},
                ),
                resultEvidence(transaction_evidence),
            );
            defer report.deinit();
            if (effective_lock_v2) |value| {
                var verify: transaction_provenance_v2.VerifyDiagnostic = .{};
                writeRecoveryProvenanceV2(
                    allocator,
                    self.io,
                    request,
                    refreshed,
                    value.*,
                    report,
                    dependencies.status,
                    &verify,
                    if (transaction_evidence) |paths|
                        paths.provenance_path
                    else
                        null,
                ) catch |err| switch (err) {
                    error.RepositoryEvidenceMismatch,
                    error.MissingPackageEvidence,
                    error.PackageDigestMismatch,
                    => return api.failureWithPaths(
                        request.operation,
                        .internal,
                        .lock_verification_failed,
                        try std.fmt.allocPrint(
                            allocator,
                            "exact-lock evidence rejected during recovery: {s}",
                            .{verify.message()},
                        ),
                        resultEvidence(transaction_evidence),
                    ),
                    else => return api.failureWithPaths(
                        request.operation,
                        .internal,
                        .internal_error,
                        try std.fmt.allocPrint(
                            allocator,
                            "recovery provenance publication failed: {s}",
                            .{@errorName(err)},
                        ),
                        resultEvidence(transaction_evidence),
                    ),
                };
            }
            if (!report.succeeded())
                return api.failureWithPaths(request.operation, .recovery, .recovery_failed, if (report.failure) |failure|
                    try describeExecutorFailure(allocator, "recovery", failure)
                else
                    "recovery failed", resultEvidence(transaction_evidence));
            deleteRecoveryIntent(self.io, request.options.state_path) catch |err|
                return api.failureWithPaths(
                    request.operation,
                    .recovery,
                    .recovery_failed,
                    try std.fmt.allocPrint(
                        allocator,
                        "recovery completed but intent cleanup failed: {s}",
                        .{@errorName(err)},
                    ),
                    resultEvidence(transaction_evidence),
                );
            var result = success(request.operation, true, "transaction recovery completed", &.{});
            result.paths = resultEvidence(transaction_evidence);
            return result;
        }
        writeRecoveryIntent(
            allocator,
            self.io,
            request.options.state_path,
            effective_request,
            transaction_evidence,
        ) catch |err| return api.failureWithPaths(
            request.operation,
            .recovery,
            .recovery_failed,
            try std.fmt.allocPrint(
                allocator,
                "recovery intent publication failed: {s}",
                .{@errorName(err)},
            ),
            exactEvidence(transaction_evidence),
        );
        if (transaction_evidence) |paths| {
            writeRecoveryIntent(
                allocator,
                self.io,
                paths.directory_path,
                effective_request,
                transaction_evidence,
            ) catch |err| {
                var evidence = exactEvidence(transaction_evidence);
                evidence.recovery = try std.fmt.allocPrint(
                    allocator,
                    "{s}/recovery-request.json",
                    .{request.options.state_path},
                );
                return api.failureWithPaths(
                    request.operation,
                    .recovery,
                    .recovery_failed,
                    try std.fmt.allocPrint(
                        allocator,
                        "transaction recovery evidence publication failed: {s}",
                        .{@errorName(err)},
                    ),
                    evidence,
                );
            };
        }
        var report = self.executor.executeFn(self.executor.context, allocator, .{
            .plan = plan,
            .install_root = request.options.install_root,
            .artifacts = artifacts.items,
            .policy = executor_policy,
            .exact_lock = effective_lock,
            .exact_lock_v2 = effective_lock_v2,
        }, dependencies) catch |err| return api.failureWithPaths(
            request.operation,
            .transaction,
            .transaction_failed,
            try std.fmt.allocPrint(
                allocator,
                "transaction executor failed before producing a report: {s}",
                .{@errorName(err)},
            ),
            recoveryEvidence(transaction_evidence),
        );
        defer report.deinit();
        if (effective_lock_v2) |value| {
            var verify: transaction_provenance_v2.VerifyDiagnostic = .{};
            writeExecutionProvenanceV2(
                allocator,
                self.io,
                request,
                refreshed,
                value.*,
                report,
                dependencies.status,
                &verify,
                if (transaction_evidence) |paths|
                    paths.provenance_path
                else
                    null,
            ) catch |err| switch (err) {
                error.RepositoryEvidenceMismatch,
                error.MissingPackageEvidence,
                error.PackageDigestMismatch,
                => return api.failureWithPaths(
                    request.operation,
                    .internal,
                    .lock_verification_failed,
                    try std.fmt.allocPrint(
                        allocator,
                        "exact-lock evidence rejected during {s}: {s}",
                        .{ @tagName(request.operation), verify.message() },
                    ),
                    recoveryEvidence(transaction_evidence),
                ),
                else => return api.failureWithPaths(
                    request.operation,
                    .internal,
                    .internal_error,
                    try std.fmt.allocPrint(
                        allocator,
                        "transaction provenance publication failed: {s}",
                        .{@errorName(err)},
                    ),
                    recoveryEvidence(transaction_evidence),
                ),
            };
        }
        if (!report.succeeded())
            return api.failureWithPaths(request.operation, .transaction, .transaction_failed, if (report.failure) |failure|
                try describeExecutorFailure(allocator, "transaction", failure)
            else
                "transaction failed", resultEvidence(transaction_evidence));
        deleteRecoveryIntent(self.io, request.options.state_path) catch |err|
            return api.failureWithPaths(
                request.operation,
                .recovery,
                .recovery_failed,
                try std.fmt.allocPrint(
                    allocator,
                    "transaction completed but recovery intent cleanup failed: {s}",
                    .{@errorName(err)},
                ),
                resultEvidence(transaction_evidence),
            );
        if (effective_lock_v2 == null) if (effective_lock) |value| {
            var verify: transaction_provenance.VerifyDiagnostic = .{};
            writeExecutionProvenance(
                allocator,
                self.io,
                request,
                refreshed,
                value.*,
                report,
                dependencies.status,
                &verify,
                if (transaction_evidence) |paths|
                    paths.provenance_path
                else
                    null,
            ) catch |err| switch (err) {
                error.RepositoryEvidenceMismatch,
                error.MissingPackageEvidence,
                error.PackageDigestMismatch,
                => return api.failureWithPaths(
                    request.operation,
                    .internal,
                    .lock_verification_failed,
                    try std.fmt.allocPrint(
                        allocator,
                        "exact-lock evidence rejected during {s}: {s}",
                        .{ @tagName(request.operation), verify.message() },
                    ),
                    recoveryEvidence(transaction_evidence),
                ),
                else => return api.failureWithPaths(
                    request.operation,
                    .internal,
                    .internal_error,
                    try std.fmt.allocPrint(
                        allocator,
                        "transaction provenance publication failed: {s}",
                        .{@errorName(err)},
                    ),
                    recoveryEvidence(transaction_evidence),
                ),
            };
        };
        var result = try planResultChanged(
            allocator,
            request.operation,
            plan.*,
            true,
            "transaction completed",
        );
        result.paths = resultEvidence(transaction_evidence);
        return result;
    }

    fn loadInstalled(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !dpkg_status.OwnedDatabase {
        const allocated_path = if (request.options.status_path == null)
            if (std.mem.eql(u8, request.options.install_root, "/"))
                try allocator.dupe(u8, "/var/lib/dpkg/status")
            else
                try std.fmt.allocPrint(
                    allocator,
                    "{s}/var/lib/dpkg/status",
                    .{request.options.install_root},
                )
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
        request: api.Request,
    ) !LoadedDocuments {
        var documents: std.ArrayList(repository_policy.SourceDocument) = .empty;
        var bytes: std.ArrayList([]u8) = .empty;
        for (request.options.source_paths) |path| {
            const contents = try readFile(allocator, self.io, path, 8 * 1024 * 1024);
            try bytes.append(allocator, contents);
            try documents.append(allocator, .{
                .bytes = contents,
                .format = sourceFormat(path),
                .policy = basePolicy(request),
            });
        }
        for (request.options.config_paths) |path| {
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
            var policy = basePolicy(request);
            policy.priority = parsed.value.priority;
            policy.default_release = if (parsed.value.default_release) |value|
                try allocator.dupe(u8, value)
            else
                request.options.default_release;
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
    exact_lock_path: ?[]const u8 = null,
    evidence_directory: ?[]const u8 = null,
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

fn readRecoveryIntentIfPresent(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_path: []const u8,
) !?std.json.Parsed(RecoveryIntent) {
    return readRecoveryIntent(allocator, io, state_path) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

fn writeRecoveryIntent(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_path: []const u8,
    request: api.Request,
    evidence: ?TransactionEvidence,
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
    try writer.print("],\"lock_wait_ms\":{d},\"exact_lock_path\":", .{
        request.options.lock_wait_ms,
    });
    if (evidence) |paths|
        try writeJsonString(writer, paths.exact_lock_path)
    else
        try writer.writeAll("null");
    try writer.writeAll(",\"evidence_directory\":");
    if (evidence) |paths|
        try writeJsonString(writer, paths.directory_path)
    else
        try writer.writeAll("null");
    try writer.writeAll("}\n");
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

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) !void {
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

fn basePolicy(request: api.Request) repository_policy.Policy {
    return .{
        .default_release = request.options.default_release,
        .proxy = if (request.options.proxy != null)
            .{ .declared = .{ .id = "cli-proxy" } }
        else
            .direct,
        .credentials = if (request.options.credential_reference) |value|
            .{ .id = value }
        else
            null,
        .deadlines = deadlines(request.options.deadline_ms),
    };
}

fn makeRuntimes(
    allocator: std.mem.Allocator,
    request: api.Request,
    configuration: *const repository_policy.Configuration,
    snapshot: ?*const target_apt_config.Snapshot,
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
        const proxy = try proxyPolicy(request.options.proxy);
        const keyrings = if (snapshot) |recorded| blk: {
            const trust = try recorded.runtimeTrust(allocator, repository);
            break :blk trust.keyrings;
        } else blk: {
            const paths = try allocator.alloc(openpgp.Keyring, repository.signed_by.len);
            for (repository.signed_by, 0..) |path, key_index|
                paths[key_index] = .{ .path = path };
            break :blk paths;
        };
        const auth: repository_refresh.AuthenticationInput = .{ .in_release = .{
            .keyrings = .{ .many = keyrings },
            .accepted_primary_fingerprints = &.{},
            .verification_time = now_unix,
        } };
        runtimes[index] = .{
            .repository_id = repository.id,
            .declared_proxy = if (request.options.proxy != null) .{ .id = "cli-proxy" } else null,
            .declared_credentials = if (request.options.credential_reference) |value| .{ .id = value } else null,
            .declared_keyrings = repository.signed_by,
            .authentication = auth,
            .acquisition = .{
                .proxy = proxy,
                .deadlines = boundedDeadlines(
                    deadlines(request.options.deadline_ms),
                    repository.deadlines,
                ),
                .redirect_limit = 8,
                .retry = productionRetryPolicy(),
                .credentials = credentials,
                .maximum_release_bytes = 16 * 1024 * 1024,
            },
            .refresh = .{
                .mode = if (request.options.offline) .cache_only else .online,
                .compression_order = &.{ .xz, .gzip, .zstd, .uncompressed },
                .by_hash_fallback = .not_found_only,
                .maximum_future_seconds = 300,
                .expiry_policy = repository.freshness,
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
    return try std.fmt.allocPrint(
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

fn executionPolicy(
    allocator: std.mem.Allocator,
    request: api.Request,
    system_profile: bool,
) !transaction_executor.Policy {
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
            .allow_host_root = system_profile,
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

fn boundedDeadlines(
    requested: repository_acquisition.Deadlines,
    configured: repository_acquisition.Deadlines,
) repository_acquisition.Deadlines {
    return .{
        .connect_ms = @min(requested.connect_ms, configured.connect_ms),
        .read_ms = @min(requested.read_ms, configured.read_ms),
        .overall_ms = @min(requested.overall_ms, configured.overall_ms),
        .absolute_ms = requested.absolute_ms,
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
        const policy = try executionPolicy(std.testing.allocator, request, false);
        defer std.testing.allocator.free(policy.risk.force);
        try std.testing.expect(!policy.risk.allow_host_root);
        request.options.install_root = "/alternate";
        const alternate = try executionPolicy(std.testing.allocator, request, false);
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

fn readLock(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !exact_lock.OwnedLock {
    const bytes = try readFile(allocator, io, path, exact_lock.maximum_document_bytes);
    defer allocator.free(bytes);
    return exact_lock.decode(allocator, bytes, exact_lock.maximum_document_bytes);
}

fn readLockV2(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !exact_lock_v2.OwnedLock {
    const bytes = try readFile(
        allocator,
        io,
        path,
        exact_lock_v2.maximum_document_bytes,
    );
    defer allocator.free(bytes);
    return exact_lock_v2.decode(
        allocator,
        bytes,
        exact_lock_v2.maximum_document_bytes,
    );
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

const TransactionEvidence = struct {
    exact_lock_path: []const u8,
    directory_path: []const u8,
    provenance_path: []const u8,
    recovery_path: []const u8,
};

fn resultEvidence(evidence: ?TransactionEvidence) api.EvidencePaths {
    const paths = evidence orelse return .{};
    return .{
        .exact_lock = paths.exact_lock_path,
        .provenance = paths.provenance_path,
        .recovery = paths.recovery_path,
    };
}

fn exactEvidence(evidence: ?TransactionEvidence) api.EvidencePaths {
    const paths = evidence orelse return .{};
    return .{ .exact_lock = paths.exact_lock_path };
}

fn recoveryEvidence(evidence: ?TransactionEvidence) api.EvidencePaths {
    const paths = evidence orelse return .{};
    return .{
        .exact_lock = paths.exact_lock_path,
        .recovery = paths.recovery_path,
    };
}

fn prepareTransactionEvidence(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_path: []const u8,
    lock: exact_lock.Lock,
    existing_lock_path: ?[]const u8,
) !TransactionEvidence {
    const digest_hex = std.fmt.bytesToHex(lock.digest_sha256, .lower);
    const locks_directory = try std.fmt.allocPrint(
        allocator,
        "{s}/locks",
        .{state_path},
    );
    defer allocator.free(locks_directory);
    const retained_lock_path = if (existing_lock_path) |path|
        try allocator.dupe(u8, path)
    else
        try std.fmt.allocPrint(
            allocator,
            "{s}/{s}.json",
            .{ locks_directory, &digest_hex },
        );
    if (existing_lock_path == null)
        try publishLockAt(allocator, io, retained_lock_path, lock);

    const evidence_directory = try std.fmt.allocPrint(
        allocator,
        "{s}/transactions/{s}",
        .{ state_path, &digest_hex },
    );
    var directory = try openOrCreateAbsoluteDirectory(io, evidence_directory);
    directory.close(io);
    const evidence_lock_path = try std.fmt.allocPrint(
        allocator,
        "{s}/exact-lock.json",
        .{evidence_directory},
    );
    try publishLockAt(allocator, io, evidence_lock_path, lock);
    return .{
        .exact_lock_path = retained_lock_path,
        .directory_path = evidence_directory,
        .provenance_path = try std.fmt.allocPrint(
            allocator,
            "{s}/transaction-result.json",
            .{evidence_directory},
        ),
        .recovery_path = try std.fmt.allocPrint(
            allocator,
            "{s}/recovery-request.json",
            .{evidence_directory},
        ),
    };
}

fn prepareTransactionEvidenceV2(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_path: []const u8,
    lock: exact_lock_v2.Lock,
    existing_lock_path: ?[]const u8,
) !TransactionEvidence {
    const digest_hex = std.fmt.bytesToHex(lock.digest_sha256, .lower);
    const locks_directory = try std.fmt.allocPrint(
        allocator,
        "{s}/locks",
        .{state_path},
    );
    defer allocator.free(locks_directory);
    const retained_lock_path = if (existing_lock_path) |path|
        try allocator.dupe(u8, path)
    else
        try std.fmt.allocPrint(
            allocator,
            "{s}/{s}.json",
            .{ locks_directory, &digest_hex },
        );
    if (existing_lock_path == null)
        try publishLockV2At(allocator, io, retained_lock_path, lock);

    const evidence_directory = try std.fmt.allocPrint(
        allocator,
        "{s}/transactions/{s}",
        .{ state_path, &digest_hex },
    );
    var directory = try openOrCreateAbsoluteDirectory(io, evidence_directory);
    directory.close(io);
    const evidence_lock_path = try std.fmt.allocPrint(
        allocator,
        "{s}/exact-lock.json",
        .{evidence_directory},
    );
    try publishLockV2At(allocator, io, evidence_lock_path, lock);
    return .{
        .exact_lock_path = retained_lock_path,
        .directory_path = evidence_directory,
        .provenance_path = try std.fmt.allocPrint(
            allocator,
            "{s}/transaction-result-v3.json",
            .{evidence_directory},
        ),
        .recovery_path = try std.fmt.allocPrint(
            allocator,
            "{s}/recovery-request.json",
            .{evidence_directory},
        ),
    };
}

fn publishLockAt(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    lock: exact_lock.Lock,
) !void {
    const parent = std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath;
    const leaf = std.fs.path.basename(path);
    var dir = try openOrCreateAbsoluteDirectory(io, parent);
    defer dir.close(io);
    const store = try exact_lock.Store.init(io, dir, leaf);
    var existing = store.read(
        allocator,
        exact_lock.maximum_document_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => {
            try store.writeAtomic(allocator, lock);
            return;
        },
        else => return err,
    };
    defer existing.deinit();
    const expected = try lock.canonicalJson(allocator);
    defer allocator.free(expected);
    const actual = try existing.lock.canonicalJson(allocator);
    defer allocator.free(actual);
    if (!std.mem.eql(u8, expected, actual)) return error.LockCollision;
}

fn publishLockV2At(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    lock: exact_lock_v2.Lock,
) !void {
    const parent = std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath;
    const leaf = std.fs.path.basename(path);
    var dir = try openOrCreateAbsoluteDirectory(io, parent);
    defer dir.close(io);
    const store = try exact_lock_v2.Store.init(io, dir, leaf);
    var existing = store.read(
        allocator,
        exact_lock_v2.maximum_document_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => {
            try store.writeAtomic(allocator, lock);
            return;
        },
        else => return err,
    };
    defer existing.deinit();
    const expected = try lock.canonicalJson(allocator);
    defer allocator.free(expected);
    const actual = try existing.lock.canonicalJson(allocator);
    defer allocator.free(actual);
    if (!std.mem.eql(u8, expected, actual)) return error.LockCollision;
}

fn lockV2FromPlan(
    allocator: std.mem.Allocator,
    request: api.Request,
    refreshed: *repository_policy.RefreshResult,
    plan: solver.Plan,
) !exact_lock_v2.OwnedLock {
    var packages: std.ArrayList(exact_lock_v2.Package) = .empty;
    defer packages.deinit(allocator);
    var repository_ids: std.ArrayList([64]u8) = .empty;
    defer repository_ids.deinit(allocator);

    for (plan.actions) |action| {
        const origin = try authenticatedPackageOrigin(action.selected_origin_v2 orelse continue);
        const repository = findRepositoryInput(
            refreshed.universe.repositories,
            origin.repository_id,
        ) orelse return error.MissingRepository;
        const record = repository.packages.records[origin.record_index];
        const snapshot_digest = repository.authenticated_snapshot_sha256 orelse
            return error.MissingRepository;
        var repository_id: [64]u8 = undefined;
        @memcpy(&repository_id, origin.repository_id.slice());
        if (!containsRepositoryId(repository_ids.items, repository_id))
            try repository_ids.append(allocator, repository_id);
        try packages.append(allocator, .{
            .name = action.package,
            .version = action.version,
            .architecture = action.architecture,
            .origin = .{ .authenticated_repository = .{
                .repository_id = repository_id,
                .repository_snapshot_sha256 = snapshot_digest,
            } },
            .sha256 = record.transport.sha256.bytes,
            .declared_size = record.transport.size.value,
            .retention = if (action.requested) .requested else .dependency,
            .dpkg_selection_hold = false,
        });
    }

    var repositories: std.ArrayList(exact_lock_v2.Repository) = .empty;
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
    var policy_hash = std.crypto.hash.sha2.Sha256.init(.{});
    policy_hash.update("debz-solver-policy-v1\x00");
    policy_hash.update(if (request.options.recommends) "recommends\x00" else "no-recommends\x00");
    policy_hash.update(if (request.options.allow_downgrade) "allow-downgrade\x00" else "no-downgrade\x00");
    policy_hash.update(@tagName(request.options.repository_policy));

    return exact_lock_v2.create(allocator, .{
        .target_architecture = request.options.architecture,
        .request_sha256 = request_digest,
        .policy_sha256 = policy_hash.finalResult(),
        .repositories = repositories.items,
        .local_artifacts = &.{},
        .packages = packages.items,
        .verified_origins = true,
    });
}

fn containsRepositoryId(ids: []const [64]u8, wanted: [64]u8) bool {
    for (ids) |id| {
        if (std.mem.eql(u8, &id, &wanted)) return true;
    }
    return false;
}

fn lockFromPlan(
    allocator: std.mem.Allocator,
    request: api.Request,
    refreshed: *repository_policy.RefreshResult,
    installed: []const dpkg_status.Package,
    plan: solver.Plan,
    include_retained: bool,
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
    if (include_retained) {
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
    var policy_hash = std.crypto.hash.sha2.Sha256.init(.{});
    policy_hash.update("debz-solver-policy-v1\x00");
    policy_hash.update(if (request.options.recommends) "recommends\x00" else "no-recommends\x00");
    policy_hash.update(if (request.options.allow_downgrade) "allow-downgrade\x00" else "no-downgrade\x00");
    policy_hash.update(@tagName(request.options.repository_policy));

    return exact_lock.create(allocator, .{
        .target_architecture = request.options.architecture,
        .request_sha256 = request_digest,
        .policy_sha256 = policy_hash.finalResult(),
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

fn dependencyVersionConflict(
    allocator: std.mem.Allocator,
    plan: solver.Plan,
    installed: []const dpkg_status.Package,
    repositories: []const solver.RepositoryInput,
) !?[]u8 {
    for (plan.actions) |action| {
        if (action.kind == .remove) continue;
        const origin = authenticatedPackageOrigin(action.selected_origin_v2 orelse
            continue) catch continue;
        const repository = findRepositoryInput(repositories, origin.repository_id) orelse
            continue;
        const record = repository.packages.records[origin.record_index];
        for ([_]?@import("control_record.zig").RelationValue{
            record.control.pre_depends,
            record.control.depends,
        }) |maybe_relation| {
            const dependency = maybe_relation orelse continue;
            for (dependency.value.groups) |group| {
                var all_alternatives_found = true;
                var satisfied = false;
                for (group.alternatives) |alternative| {
                    const state = finalAlternativeState(
                        plan.actions,
                        installed,
                        repositories,
                        alternative,
                    );
                    if (!state.found) {
                        all_alternatives_found = false;
                        continue;
                    }
                    if (state.satisfied) {
                        satisfied = true;
                        break;
                    }
                }
                if (!satisfied and all_alternatives_found)
                    return try std.fmt.allocPrint(
                        allocator,
                        "{s} dependency is unsatisfied by the final installed identity: {s}",
                        .{
                            action.package,
                            group.span.slice(dependency.source),
                        },
                    );
            }
        }
    }
    return null;
}

const AlternativeState = struct {
    found: bool = false,
    satisfied: bool = false,
};

fn finalAlternativeState(
    actions: []const solver.PlanAction,
    installed: []const dpkg_status.Package,
    repositories: []const solver.RepositoryInput,
    alternative: @import("relation.zig").Alternative,
) AlternativeState {
    if (alternative.package.architecture_qualifier != null or
        alternative.restrictions.architectures != null or
        alternative.restrictions.build_profiles.len != 0)
        return .{};
    const name = alternative.package.name.text;
    for (actions) |action| {
        if (!std.mem.eql(u8, action.package, name)) continue;
        if (action.kind == .remove) return .{ .found = true };
        return .{
            .found = true,
            .satisfied = alternative.version == null or
                versionSatisfies(action.version, alternative.version.?),
        };
    }
    for (installed) |package| {
        if (package.status.isFullyInstalled() and
            std.mem.eql(u8, package.name.value, name))
            return .{
                .found = true,
                .satisfied = alternative.version == null or
                    versionSatisfies(
                        package.version.spelling.value,
                        alternative.version.?,
                    ),
            };
    }

    var found_provider = false;
    for (actions) |action| {
        if (action.kind == .remove) continue;
        const origin = authenticatedPackageOrigin(action.selected_origin_v2 orelse
            continue) catch continue;
        const repository = findRepositoryInput(repositories, origin.repository_id) orelse
            continue;
        const record = repository.packages.records[origin.record_index];
        if (record.control.provides) |provides| {
            const state = providedAlternativeState(
                provides.value,
                name,
                alternative.version,
            );
            found_provider = found_provider or state.found;
            if (state.satisfied) return state;
        }
    }
    for (installed) |package| {
        if (!package.status.isFullyInstalled() or
            planChangesPackage(actions, package.name.value))
            continue;
        if (package.relation(.provides)) |provides| {
            const state = providedAlternativeState(
                provides.relation,
                name,
                alternative.version,
            );
            found_provider = found_provider or state.found;
            if (state.satisfied) return state;
        }
    }
    return .{ .found = found_provider };
}

fn providedAlternativeState(
    provides: @import("relation.zig").Relation,
    name: []const u8,
    constraint: ?@import("relation.zig").VersionConstraint,
) AlternativeState {
    var found = false;
    for (provides.groups) |group| {
        for (group.alternatives) |provided| {
            if (!std.mem.eql(u8, provided.package.name.text, name)) continue;
            found = true;
            if (constraint == null) return .{ .found = true, .satisfied = true };
            const provided_version = provided.version orelse continue;
            if (versionSatisfies(provided_version.version.text, constraint.?))
                return .{ .found = true, .satisfied = true };
        }
    }
    return .{ .found = found };
}

fn planChangesPackage(actions: []const solver.PlanAction, name: []const u8) bool {
    for (actions) |action| {
        if (std.mem.eql(u8, action.package, name)) return true;
    }
    return false;
}

fn versionSatisfies(
    actual_text: []const u8,
    constraint: @import("relation.zig").VersionConstraint,
) bool {
    const actual = debian_version.DebianVersion.parse(actual_text) catch return false;
    const expected = debian_version.DebianVersion.parse(constraint.version.text) catch
        return false;
    return switch (constraint.operator) {
        .less_than => actual.order(expected) == .lt,
        .less_than_or_equal => actual.order(expected) != .gt,
        .equal => actual.order(expected) == .eq,
        .greater_than_or_equal => actual.order(expected) != .lt,
        .greater_than => actual.order(expected) == .gt,
    };
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

fn writeRecoveryProvenanceV2(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: api.Request,
    refreshed: *repository_policy.RefreshResult,
    lock: exact_lock_v2.Lock,
    report: transaction_executor.RecoveryReport,
    status: transaction_recovery.StatusReader,
    verify: *transaction_provenance_v2.VerifyDiagnostic,
    output_path: ?[]const u8,
) !void {
    const repositories = try allocator.alloc(
        transaction_provenance_v2.RepositoryEvidence,
        lock.repositories.len,
    );
    for (lock.repositories, 0..) |locked, index| {
        const snapshot = findSnapshot(refreshed.snapshots, locked.id) orelse
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
        repositories[index] = .{
            .source_config_id = locked.id,
            .snapshot_sha256 = repository_refresh.snapshotDigest(snapshot),
            .release_sha256 = snapshot.snapshot.provenance.release_digest.bytes,
            .signature_sha256 = if (evidence.signature_digest) |digest|
                digest.bytes
            else
                null,
            .metadata_sha256 = snapshot.snapshot.provenance.index_digest.bytes,
            .signer_fingerprints = signers[0..signer_count],
            .signature_verified = true,
        };
    }
    const packages = try allocator.alloc(
        transaction_provenance_v2.PackageEvidence,
        lock.packages.len,
    );
    for (lock.packages, 0..) |package, index| packages[index] = .{
        .name = package.name,
        .version = package.version,
        .architecture = package.architecture,
        .origin = package.origin,
        .package_sha256 = package.sha256,
        .cas_sha256 = package.sha256,
        .declared_size = package.declared_size,
    };
    try transaction_provenance_v2.verifyLockEvidence(
        allocator,
        lock,
        repositories,
        packages,
        verify,
    );
    var status_digest: ?[32]u8 = null;
    var status_bytes: ?[]u8 = null;
    defer if (status_bytes) |bytes| allocator.free(bytes);
    if (report.succeeded()) {
        status_bytes = try status.read(
            allocator,
            request.options.install_root,
            64 * 1024 * 1024,
        );
        status_digest = sha256Bytes(status_bytes.?);
    }
    var provenance = try transaction_provenance_v2.createFromRecovery(
        allocator,
        .{
            .exact_lock = &lock,
            .target_architecture = request.options.architecture,
            .request_sha256 = lock.request_sha256,
            .solver_policy_sha256 = lock.policy_sha256,
            .repositories = repositories,
            .packages = packages,
            .journal_steps = &.{},
            .final_verification = .{
                .status = if (report.succeeded()) .exact_match else .not_run,
                .installed_state_sha256 = status_digest,
                .package_origins_sha256 = if (report.succeeded())
                    lock.digest_sha256
                else
                    null,
                .detail = if (report.succeeded())
                    "recovery and exact-lock verification completed"
                else
                    "recovery failed; exact transaction evidence retained",
            },
        },
        report,
    );
    defer provenance.deinit();
    try writeFreshnessProvenance(
        allocator,
        io,
        request.options.state_path,
        output_path,
        refreshed,
        lock,
        provenance.result,
    );
}

fn writeExecutionProvenanceV2(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: api.Request,
    refreshed: *repository_policy.RefreshResult,
    lock: exact_lock_v2.Lock,
    report: transaction_executor.Report,
    status: transaction_recovery.StatusReader,
    verify: *transaction_provenance_v2.VerifyDiagnostic,
    output_path: ?[]const u8,
) !void {
    const repositories = try allocator.alloc(
        transaction_provenance_v2.RepositoryEvidence,
        lock.repositories.len,
    );
    for (lock.repositories, 0..) |locked, index| {
        const snapshot = findSnapshot(refreshed.snapshots, locked.id) orelse
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
        repositories[index] = .{
            .source_config_id = locked.id,
            .snapshot_sha256 = repository_refresh.snapshotDigest(snapshot),
            .release_sha256 = snapshot.snapshot.provenance.release_digest.bytes,
            .signature_sha256 = if (evidence.signature_digest) |digest|
                digest.bytes
            else
                null,
            .metadata_sha256 = snapshot.snapshot.provenance.index_digest.bytes,
            .signer_fingerprints = signers[0..signer_count],
            .signature_verified = true,
        };
    }
    const packages = try allocator.alloc(
        transaction_provenance_v2.PackageEvidence,
        lock.packages.len,
    );
    for (lock.packages, 0..) |package, index| packages[index] = .{
        .name = package.name,
        .version = package.version,
        .architecture = package.architecture,
        .origin = package.origin,
        .package_sha256 = package.sha256,
        .cas_sha256 = package.sha256,
        .declared_size = package.declared_size,
    };
    try transaction_provenance_v2.verifyLockEvidence(
        allocator,
        lock,
        repositories,
        packages,
        verify,
    );
    var status_digest: ?[32]u8 = null;
    var status_bytes: ?[]u8 = null;
    defer if (status_bytes) |bytes| allocator.free(bytes);
    if (report.succeeded()) {
        status_bytes = try status.read(
            allocator,
            request.options.install_root,
            64 * 1024 * 1024,
        );
        status_digest = sha256Bytes(status_bytes.?);
    }
    var provenance = try transaction_provenance_v2.createFromExecution(
        allocator,
        .{
            .exact_lock = &lock,
            .target_architecture = request.options.architecture,
            .request_sha256 = lock.request_sha256,
            .solver_policy_sha256 = lock.policy_sha256,
            .repositories = repositories,
            .packages = packages,
            .journal_steps = &.{},
            .final_verification = .{
                .status = if (report.succeeded()) .exact_match else .not_run,
                .installed_state_sha256 = status_digest,
                .package_origins_sha256 = if (report.succeeded())
                    lock.digest_sha256
                else
                    null,
                .detail = if (report.succeeded())
                    "executor and exact-lock verification completed"
                else
                    "executor failed; recovery evidence retained",
            },
        },
        report,
    );
    defer provenance.deinit();
    try writeFreshnessProvenance(
        allocator,
        io,
        request.options.state_path,
        output_path,
        refreshed,
        lock,
        provenance.result,
    );
}

fn writeFreshnessProvenance(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_path: []const u8,
    output_path: ?[]const u8,
    refreshed: *repository_policy.RefreshResult,
    lock: exact_lock_v2.Lock,
    execution: transaction_provenance_v2.Result,
) !void {
    const refresh_evidence = try allocator.alloc(
        transaction_provenance_v3.RepositoryRefreshEvidence,
        lock.repositories.len,
    );
    defer allocator.free(refresh_evidence);
    for (lock.repositories, 0..) |locked, index| {
        const snapshot = findSnapshot(refreshed.snapshots, locked.id) orelse
            return error.MissingRepository;
        const policy = snapshot.snapshot.provenance.policy;
        refresh_evidence[index] = .{
            .source_config_id = locked.id,
            .snapshot_sha256 = repository_refresh.snapshotDigest(snapshot),
            .signed_release_date_unix = policy.release_date_unix,
            .valid_until_unix = policy.valid_until_unix,
            .verification_time_unix = policy.verification_time_unix,
            .observed_release_age_seconds = policy.observed_release_age_seconds,
            .expiry_policy = policy.expiry_policy,
            .maximum_release_age_seconds = policy.maximum_release_age_seconds,
            .missing_valid_until_exception_exercised = policy.missing_valid_until_exception_exercised,
            .selected_packages_path = snapshot.snapshot.provenance.selected_path,
            .compression = snapshot.snapshot.provenance.compression,
        };
    }
    var complete_provenance = try transaction_provenance_v3.create(
        allocator,
        execution,
        refresh_evidence,
    );
    defer complete_provenance.deinit();
    const directory_path = if (output_path) |path|
        std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath
    else
        state_path;
    const name = if (output_path) |path|
        std.fs.path.basename(path)
    else
        "transaction-result-v3.json";
    var dir = try openAbsoluteDirectory(io, directory_path);
    defer dir.close(io);
    const store = try transaction_provenance_v3.Store.init(io, dir, name);
    try store.writeAtomic(allocator, complete_provenance.result);
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
    output_path: ?[]const u8,
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
    const directory_path = if (output_path) |path|
        std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath
    else
        request.options.state_path;
    const name = if (output_path) |path|
        std.fs.path.basename(path)
    else
        "transaction-result.json";
    var dir = try openAbsoluteDirectory(io, directory_path);
    defer dir.close(io);
    const store = try transaction_provenance.Store.init(io, dir, name);
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

fn containsString(values: []const []const u8, target: []const u8) bool {
    for (values) |value| if (std.mem.eql(u8, value, target)) return true;
    return false;
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

fn fixedNow(context: ?*anyopaque) i64 {
    return @as(*const i64, @ptrCast(@alignCast(context.?))).*;
}

fn sha256Bytes(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
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
