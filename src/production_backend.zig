const std = @import("std");
const api = @import("product_api.zig");
const debian_version = @import("debian_version.zig");
const deb_payload = @import("deb_payload.zig");
const dpkg_status = @import("dpkg_status.zig");
const metadata_cache = @import("metadata_cache.zig");
const package_acquisition = @import("package_acquisition.zig");
const package_origin = @import("package_origin.zig");
const repository_acquisition = @import("repository_acquisition.zig");
const repository_policy = @import("repository_policy.zig");
const repository_plan = @import("repository_plan.zig");
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
const system_operation_lock = @import("system_operation_lock.zig");

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
    operation_locks: ?transaction_executor.LockManager = null,
    system_operation_guard_held: bool = false,
    recovery_architecture_override: ?[]const u8 = null,

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
        if (self.system_profile and request.operation.mutates() and
            !self.system_operation_guard_held)
        {
            const path = try system_operation_lock.guardPath(
                allocator,
                request.options.install_root,
            );
            defer allocator.free(path);
            var system_locks = transaction_executor.SystemLockManager{
                .allocator = allocator,
                .io = self.io,
            };
            const locks = self.operation_locks orelse system_locks.interface();
            const token = locks.acquire(
                path,
                request.options.lock_wait_ms,
            ) catch |err| return api.failure(
                request.operation,
                .recovery,
                .recovery_required,
                try std.fmt.allocPrint(
                    allocator,
                    "system operation lock is unavailable: {s}",
                    .{@errorName(err)},
                ),
            );
            defer locks.release(token);
            return self.routeUnlocked(allocator, request);
        }
        return self.routeUnlocked(allocator, request);
    }

    fn routeUnlocked(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: api.Request,
    ) !api.Result {
        if (self.system_profile and request.operation == .recover)
            return self.recoverSystemTransaction(allocator, request);
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

    fn recoverSystemTransaction(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: api.Request,
    ) !api.Result {
        const active_intent_state_path = try system_operation_lock.statePath(
            allocator,
            request.options.install_root,
        );
        defer allocator.free(active_intent_state_path);
        var intent = readRecoveryIntent(
            allocator,
            self.io,
            active_intent_state_path,
        ) catch |err| return api.failure(
            request.operation,
            .recovery,
            .recovery_failed,
            try std.fmt.allocPrint(
                allocator,
                "recovery intent is unavailable: {s}",
                .{@errorName(err)},
            ),
        );
        defer intent.deinit();
        var loaded = loadSystemTransactionEvidence(
            allocator,
            self.io,
            request.options.install_root,
            request.options.state_path,
            intent.value,
        ) catch |err| return api.failure(
            request.operation,
            .recovery,
            .recovery_failed,
            try std.fmt.allocPrint(
                allocator,
                "system recovery evidence is invalid: {s}",
                .{@errorName(err)},
            ),
        );
        defer loaded.operation_lock.deinit();
        const operation_lock = loaded.operation_lock.lock;
        const evidence = loaded.evidence;
        if (self.recovery_architecture_override) |architecture| {
            if (!std.mem.eql(
                u8,
                architecture,
                operation_lock.target_architecture,
            ))
                return api.failureWithPaths(
                    request.operation,
                    .usage,
                    .invalid_request,
                    "explicit architecture does not match recovery evidence",
                    exactEvidence(evidence),
                );
        }
        var plan = readPlanAt(
            allocator,
            self.io,
            evidence.plan_path,
        ) catch |err| return api.failureWithPaths(
            request.operation,
            .recovery,
            .recovery_failed,
            try std.fmt.allocPrint(
                allocator,
                "persisted executable plan is invalid: {s}",
                .{@errorName(err)},
            ),
            exactEvidence(evidence),
        );
        defer plan.deinit();

        var effective_request = request;
        effective_request.operation = intent.value.operation;
        effective_request.packages = intent.value.packages;
        effective_request.options.architecture =
            operation_lock.target_architecture;
        effective_request.options.recommends = intent.value.recommends;
        effective_request.options.allow_downgrade =
            intent.value.allow_downgrade;
        effective_request.options.foreign_architectures =
            intent.value.foreign_architectures;
        effective_request.options.repository_policy =
            intent.value.repository_policy;
        effective_request.options.conffile = intent.value.conffile;
        effective_request.options.force = intent.value.force;
        effective_request.options.lock_wait_ms = intent.value.lock_wait_ms;
        effective_request.options.assume_yes = true;
        effective_request.options.noninteractive = true;

        var package_lock_v1: ?exact_lock.OwnedLock = null;
        defer if (package_lock_v1) |*value| value.deinit();
        var package_lock_v2: ?exact_lock_v2.OwnedLock = null;
        defer if (package_lock_v2) |*value| value.deinit();
        switch (operation_lock.package_lock_kind) {
            .none => {},
            .exact_v1 => {
                const path = evidence.package_lock_path orelse
                    return api.failure(
                        request.operation,
                        .recovery,
                        .recovery_failed,
                        "missing exact-lock v1 recovery evidence",
                    );
                package_lock_v1 = readLock(
                    allocator,
                    self.io,
                    path,
                ) catch |err| return api.failure(
                    request.operation,
                    .recovery,
                    .recovery_failed,
                    try std.fmt.allocPrint(
                        allocator,
                        "exact-lock v1 is invalid: {s}",
                        .{@errorName(err)},
                    ),
                );
            },
            .exact_v2 => {
                const path = evidence.package_lock_path orelse
                    return api.failure(
                        request.operation,
                        .recovery,
                        .recovery_failed,
                        "missing exact-lock v2 recovery evidence",
                    );
                package_lock_v2 = readLockV2(
                    allocator,
                    self.io,
                    path,
                ) catch |err| return api.failure(
                    request.operation,
                    .recovery,
                    .recovery_failed,
                    try std.fmt.allocPrint(
                        allocator,
                        "exact-lock v2 is invalid: {s}",
                        .{@errorName(err)},
                    ),
                );
            },
        }
        var executor_policy = try executionPolicy(
            allocator,
            effective_request,
            true,
        );
        defer allocator.free(executor_policy.risk.force);
        if (package_lock_v2 != null)
            executor_policy.exact_lock_verification = .locked_packages;
        validateSystemOperationEvidence(
            operation_lock,
            effective_request,
            executor_policy,
            plan,
            if (package_lock_v1) |*value| &value.lock else null,
            if (package_lock_v2) |*value| &value.lock else null,
        ) catch |err| return api.failureWithPaths(
            request.operation,
            .recovery,
            .lock_verification_failed,
            try std.fmt.allocPrint(
                allocator,
                "recovery evidence does not match: {s}",
                .{@errorName(err)},
            ),
            exactEvidence(evidence),
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
            evidence.directory_path,
            request.options.install_root,
        ) catch |err| return api.failureWithPaths(
            request.operation,
            .recovery,
            .recovery_failed,
            try std.fmt.allocPrint(
                allocator,
                "transaction journal is unavailable: {s}",
                .{@errorName(err)},
            ),
            resultEvidence(evidence),
        );
        defer journal.deinit();
        const journal_bytes = journal.interface().load(
            allocator,
            request.options.install_root,
        ) catch |err| return api.failureWithPaths(
            request.operation,
            .recovery,
            .recovery_failed,
            try std.fmt.allocPrint(
                allocator,
                "transaction journal cannot be read: {s}",
                .{@errorName(err)},
            ),
            resultEvidence(evidence),
        );
        if (journal_bytes == null) {
            clearRecoveryIntents(
                self.io,
                active_intent_state_path,
                evidence,
            ) catch |err| return api.failureWithPaths(
                request.operation,
                .recovery,
                .recovery_required,
                try std.fmt.allocPrint(
                    allocator,
                    "stale intent cleanup failed; recovery evidence was retained: {s}",
                    .{@errorName(err)},
                ),
                recoveryEvidence(evidence),
            );
            return api.failureWithPaths(
                request.operation,
                .recovery,
                .recovery_failed,
                "stale pre-journal recovery intent was cleared",
                exactEvidence(evidence),
            );
        }
        allocator.free(journal_bytes.?);
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
        var report = self.executor.recoverFn(
            self.executor.context,
            allocator,
            .{
                .plan = &plan,
                .install_root = request.options.install_root,
                .policy = executor_policy,
                .exact_lock = if (package_lock_v1) |*value|
                    &value.lock
                else
                    null,
                .exact_lock_v2 = if (package_lock_v2) |*value|
                    &value.lock
                else
                    null,
                .attempt_sha256 = evidence.attempt_id,
            },
            dependencies,
        ) catch |err| return api.failureWithPaths(
            request.operation,
            .recovery,
            .recovery_failed,
            try std.fmt.allocPrint(
                allocator,
                "recovery executor failed before producing a report: {s}",
                .{@errorName(err)},
            ),
            resultEvidence(evidence),
        );
        defer report.deinit();
        if (package_lock_v2) |*value| {
            writeRetainedRecoveryProvenanceV2(
                allocator,
                self.io,
                effective_request,
                operation_lock,
                value.lock,
                report,
                dependencies.status,
                evidence.provenance_path.?,
            ) catch |err| return api.failureWithPaths(
                request.operation,
                .recovery,
                .recovery_required,
                try std.fmt.allocPrint(
                    allocator,
                    "recovery provenance publication failed; recovery evidence was retained: {s}",
                    .{@errorName(err)},
                ),
                resultEvidence(evidence),
            );
        }
        if (!report.succeeded())
            return api.failureWithPaths(
                request.operation,
                .recovery,
                .recovery_failed,
                if (report.failure) |failure|
                    try describeExecutorFailure(
                        allocator,
                        "recovery",
                        failure,
                    )
                else
                    "recovery failed",
                resultEvidence(evidence),
            );
        deleteRecoveryIntent(
            self.io,
            active_intent_state_path,
        ) catch |err| return api.failureWithPaths(
            request.operation,
            .recovery,
            .recovery_failed,
            try std.fmt.allocPrint(
                allocator,
                "recovery completed but intent cleanup failed: {s}",
                .{@errorName(err)},
            ),
            resultEvidence(evidence),
        );
        var result = success(
            request.operation,
            true,
            "transaction recovery completed",
            &.{},
        );
        result.paths = resultEvidence(evidence);
        return result;
    }

    fn withRepositories(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !api.Result {
        const active_intent_state_path: ?[]u8 =
            if (self.system_profile and request.operation.mutates() and
            request.operation != .recover)
                try system_operation_lock.statePath(
                    allocator,
                    request.options.install_root,
                )
            else
                null;
        defer if (active_intent_state_path) |path| allocator.free(path);
        const intent_state_path = active_intent_state_path orelse
            request.options.state_path;
        if (self.system_profile and request.operation.mutates() and
            request.operation != .recover)
        {
            var pending = try readRecoveryIntentIfPresent(
                allocator,
                self.io,
                intent_state_path,
            );
            defer if (pending) |*intent| intent.deinit();
            if (pending) |*intent| {
                var loaded = loadSystemTransactionEvidence(
                    allocator,
                    self.io,
                    request.options.install_root,
                    null,
                    intent.value,
                ) catch |err| return api.failure(
                    request.operation,
                    .recovery,
                    .recovery_required,
                    try std.fmt.allocPrint(
                        allocator,
                        "retained recovery intent is invalid: {s}",
                        .{@errorName(err)},
                    ),
                );
                defer loaded.operation_lock.deinit();
                return api.failureWithPaths(
                    request.operation,
                    .recovery,
                    .recovery_required,
                    "an interrupted transaction is retained; run 'debz recover' before planning another mutation",
                    resultEvidence(loaded.evidence),
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
            effective_request.options.foreign_architectures =
                intent.value.foreign_architectures;
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
            if (lock_v2) |*value| {
                validateSystemPackageLockV2(
                    effective_request,
                    value.lock,
                ) catch
                    return api.failure(
                        request.operation,
                        .planning,
                        .lock_verification_failed,
                        "exact lock request, policy, or architecture does not match",
                    );
            }
        }
        const selectors = try allocator.alloc(solver.PackageSelector, effective_request.packages.len);
        defer allocator.free(selectors);
        for (effective_request.packages, 0..) |value, index| selectors[index] = parseSelector(value);
        var planning = try solver.planTransaction(allocator, .{
            .repositories = refreshed.universe.repositories,
            .installed = installedInput(
                request,
                planning_records,
                policies,
            ),
            .target_architecture = request.options.architecture,
            .mode = if (effective_request.operation == .download) .download_only else .plan_only,
            .request = try planRequestFromSelectors(effective_request.operation, selectors),
            .policy = .{
                .recommends = effective_request.options.recommends,
                .allow_downgrade = effective_request.options.allow_downgrade,
                .strict_repository_priority = effective_request.options.repository_policy == .strict_priority,
            },
            .exact_lock = if (lock) |*value| &value.lock else null,
            .exact_lock_v2 = if (lock_v2) |*value| &value.lock else null,
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
        if (self.system_profile) plan.schema_version = 3;
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
            if (effective_lock) |value|
                try writeLock(allocator, self.io, path, value.*)
            else if (effective_lock_v2) |value|
                try writeLockV2(allocator, self.io, path, value.*)
            else
                return api.failure(
                    request.operation,
                    .planning,
                    .planning_failed,
                    "no exact lock was available for publication",
                );
        }
        var executor_policy = try executionPolicy(
            allocator,
            effective_request,
            self.system_profile,
        );
        defer allocator.free(executor_policy.risk.force);
        if (effective_lock_v2 != null)
            executor_policy.exact_lock_verification = .locked_packages;
        var transaction_evidence: ?TransactionEvidence = null;
        if (self.system_profile and request.operation.mutates() and
            request.operation != .recover)
        {
            const actions = try allocator.alloc(
                system_operation_lock.Action,
                plan.actions.len,
            );
            defer allocator.free(actions);
            for (plan.actions, 0..) |action, index| actions[index] = .{
                .kind = action.kind,
                .package = action.package,
                .version = action.version,
                .architecture = action.architecture,
            };
            const package_lock_kind: system_operation_lock.PackageLockKind =
                if (effective_lock_v2 != null)
                    .exact_v2
                else if (effective_lock != null)
                    .exact_v1
                else
                    .none;
            const package_lock_sha256: ?[32]u8 =
                if (effective_lock_v2) |value|
                    value.digest_sha256
                else if (effective_lock) |value|
                    value.digest_sha256
                else
                    null;
            var attempt_id: [32]u8 = undefined;
            try self.io.randomSecure(&attempt_id);
            const refresh_evidence =
                if (effective_lock_v2) |value|
                    try repositoryRefreshEvidenceFromSnapshots(
                        allocator,
                        refreshed,
                        value.*,
                    )
                else
                    try allocator.alloc(
                        transaction_provenance_v3.RepositoryRefreshEvidence,
                        0,
                    );
            defer allocator.free(refresh_evidence);
            var operation_lock = try system_operation_lock.create(
                allocator,
                .{
                    .attempt_id = attempt_id,
                    .operation = effective_request.operation,
                    .install_root = effective_request.options.install_root,
                    .state_path = effective_request.options.state_path,
                    .target_architecture = effective_request.options.architecture,
                    .request_sha256 = systemRequestDigest(effective_request),
                    .solver_policy_sha256 = systemSolverPolicyDigest(effective_request),
                    .executor_policy_sha256 = transaction_executor.policyDigest(executor_policy),
                    .plan_sha256 = transaction_executor.planDigest(plan.*),
                    .package_lock_kind = package_lock_kind,
                    .package_lock_sha256 = package_lock_sha256,
                    .actions = actions,
                    .repository_refresh = refresh_evidence,
                },
            );
            defer operation_lock.deinit();
            validateSystemOperationEvidence(
                operation_lock.lock,
                effective_request,
                executor_policy,
                plan.*,
                effective_lock,
                effective_lock_v2,
            ) catch |err| return api.failure(
                request.operation,
                .planning,
                .lock_verification_failed,
                try std.fmt.allocPrint(
                    allocator,
                    "system operation evidence is inconsistent: {s}",
                    .{@errorName(err)},
                ),
            );
            transaction_evidence = prepareSystemTransactionEvidence(
                allocator,
                self.io,
                operation_lock.lock,
                plan.*,
                effective_lock,
                effective_lock_v2,
            ) catch |err| return api.failure(
                request.operation,
                .planning,
                .planning_failed,
                try std.fmt.allocPrint(
                    allocator,
                    "exact lock could not be retained before mutation: {s}",
                    .{@errorName(err)},
                ),
            );
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
            if (action.kind == .remove) continue;
            const origin = try authenticatedPackageOrigin(
                action.selected_origin_v2 orelse return error.MissingRepository,
            );
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
                    null,
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
            intent_state_path,
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
                clearRecoveryIntents(
                    self.io,
                    intent_state_path,
                    transaction_evidence,
                ) catch |cleanup_err| return api.failureWithPaths(
                    request.operation,
                    .recovery,
                    .recovery_required,
                    try std.fmt.allocPrint(
                        allocator,
                        "transaction recovery evidence publication failed ({s}) and intent cleanup failed ({s})",
                        .{ @errorName(err), @errorName(cleanup_err) },
                    ),
                    recoveryEvidence(transaction_evidence),
                );
                const evidence = exactEvidence(transaction_evidence);
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
            .attempt_sha256 = if (transaction_evidence) |paths|
                paths.attempt_id
            else
                null,
        }, dependencies) catch |err| {
            const has_journal = probeJournalForCleanup(
                allocator,
                journal.interface(),
                request.options.install_root,
            ) catch |probe_err| return api.failureWithPaths(
                request.operation,
                .recovery,
                .recovery_required,
                try std.fmt.allocPrint(
                    allocator,
                    "transaction executor failed ({s}) and journal state could not be determined ({s}); recovery evidence was retained",
                    .{ @errorName(err), @errorName(probe_err) },
                ),
                recoveryEvidence(transaction_evidence),
            );
            if (!has_journal) {
                clearRecoveryIntents(
                    self.io,
                    intent_state_path,
                    transaction_evidence,
                ) catch |cleanup_err| return api.failureWithPaths(
                    request.operation,
                    .recovery,
                    .recovery_required,
                    try std.fmt.allocPrint(
                        allocator,
                        "transaction failed before journaling but intent cleanup failed: {s}",
                        .{@errorName(cleanup_err)},
                    ),
                    recoveryEvidence(transaction_evidence),
                );
            }
            return api.failureWithPaths(
                request.operation,
                .transaction,
                .transaction_failed,
                try std.fmt.allocPrint(
                    allocator,
                    "transaction executor failed before producing a report: {s}",
                    .{@errorName(err)},
                ),
                if (!has_journal)
                    exactEvidence(transaction_evidence)
                else
                    recoveryEvidence(transaction_evidence),
            );
        };
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
                    paths.attempt_id
                else
                    null,
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
        if (!report.succeeded()) {
            var failure_paths = resultEvidence(transaction_evidence);
            if (report.transaction_state == .not_started) {
                const has_journal = probeJournalForCleanup(
                    allocator,
                    journal.interface(),
                    request.options.install_root,
                ) catch |probe_err| return api.failureWithPaths(
                    request.operation,
                    .recovery,
                    .recovery_required,
                    try std.fmt.allocPrint(
                        allocator,
                        "transaction failed and journal state could not be determined: {s}",
                        .{@errorName(probe_err)},
                    ),
                    recoveryEvidence(transaction_evidence),
                );
                if (!has_journal) {
                    clearRecoveryIntents(
                        self.io,
                        intent_state_path,
                        transaction_evidence,
                    ) catch |cleanup_err| return api.failureWithPaths(
                        request.operation,
                        .recovery,
                        .recovery_required,
                        try std.fmt.allocPrint(
                            allocator,
                            "transaction failed before journaling but intent cleanup failed: {s}",
                            .{@errorName(cleanup_err)},
                        ),
                        recoveryEvidence(transaction_evidence),
                    );
                    failure_paths.recovery = null;
                }
            }
            return api.failureWithPaths(request.operation, .transaction, .transaction_failed, if (report.failure) |failure|
                try describeExecutorFailure(allocator, "transaction", failure)
            else
                "transaction failed", failure_paths);
        }
        deleteRecoveryIntent(self.io, intent_state_path) catch |err|
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
    version: ?u32 = null,
    attempt_id: ?[]const u8 = null,
    operation_lock_sha256: ?[]const u8 = null,
    operation: api.Operation,
    packages: []const []const u8,
    recommends: bool,
    allow_downgrade: bool,
    foreign_architectures: []const []const u8 = &.{},
    repository_policy: api.RepositoryPolicy,
    conffile: api.ConffilePolicy,
    force: []const api.ForcePolicy,
    lock_wait_ms: u64,
    exact_lock_path: ?[]const u8 = null,
    plan_path: ?[]const u8 = null,
    package_lock_path: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
    evidence_directory: ?[]const u8 = null,
};

const recovery_intent_version: u32 = 2;

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
    if (evidence) |paths| {
        const attempt_hex = std.fmt.bytesToHex(paths.attempt_id, .lower);
        const operation_lock_hex = std.fmt.bytesToHex(
            paths.operation_lock_sha256,
            .lower,
        );
        try writer.print(
            "{{\"version\":{},\"attempt_id\":\"{s}\",\"operation_lock_sha256\":\"{s}\",\"operation\":\"{s}\",\"packages\":[",
            .{
                recovery_intent_version,
                &attempt_hex,
                &operation_lock_hex,
                @tagName(request.operation),
            },
        );
    } else {
        try writer.print(
            "{{\"operation\":\"{s}\",\"packages\":[",
            .{@tagName(request.operation)},
        );
    }
    for (request.packages, 0..) |package, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("\"{s}\"", .{package});
    }
    try writer.print(
        "],\"recommends\":{s},\"allow_downgrade\":{s},\"foreign_architectures\":[",
        .{
            if (request.options.recommends) "true" else "false",
            if (request.options.allow_downgrade) "true" else "false",
        },
    );
    for (request.options.foreign_architectures, 0..) |architecture, index| {
        if (index != 0) try writer.writeByte(',');
        try writeJsonString(writer, architecture);
    }
    try writer.print(
        "],\"repository_policy\":\"{s}\",\"conffile\":\"{s}\",\"force\":[",
        .{
            @tagName(request.options.repository_policy),
            @tagName(request.options.conffile),
        },
    );
    for (request.options.force, 0..) |force, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("\"{s}\"", .{@tagName(force)});
    }
    try writer.print("],\"lock_wait_ms\":{d}", .{
        request.options.lock_wait_ms,
    });
    if (evidence == null)
        try writer.writeAll(
            ",\"exact_lock_path\":null,\"plan_path\":null,\"package_lock_path\":null,\"provenance_path\":null,\"evidence_directory\":null",
        );
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

fn clearRecoveryIntents(
    io: std.Io,
    state_path: []const u8,
    evidence: ?TransactionEvidence,
) !void {
    if (evidence) |paths|
        try deleteRecoveryIntent(io, paths.directory_path);
    try deleteRecoveryIntent(io, state_path);
}

fn probeJournalForCleanup(
    allocator: std.mem.Allocator,
    store: transaction_recovery.Store,
    install_root: []const u8,
) !bool {
    const bytes = try store.load(allocator, install_root);
    if (bytes) |value| {
        allocator.free(value);
        return true;
    }
    return false;
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

fn validateSystemPackageLockV2(
    request: api.Request,
    lock: exact_lock_v2.Lock,
) !void {
    if (!std.mem.eql(
        u8,
        lock.target_architecture,
        request.options.architecture,
    ) or !std.mem.eql(
        u8,
        &lock.request_sha256,
        &systemRequestDigest(request),
    ) or !std.mem.eql(
        u8,
        &lock.policy_sha256,
        &systemSolverPolicyDigest(request),
    ))
        return error.PackageLockMismatch;
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

fn installedInput(
    request: api.Request,
    records: []const dpkg_status.Package,
    policies: []const solver.InstalledPolicy,
) solver.ImportInput {
    return .{
        .records = records,
        .native_architecture = request.options.architecture,
        .foreign_architectures = request.options.foreign_architectures,
        .policies = policies,
        .hold_authority = .explicit_policy,
    };
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

fn systemRequestDigest(request: api.Request) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hashPart(&hash, "debz-system-request-v1");
    hashPart(&hash, request.operation.spelling());
    hashPart(&hash, request.options.install_root);
    hashPart(&hash, request.options.state_path);
    hashPart(&hash, request.options.architecture);
    for (request.options.foreign_architectures) |architecture|
        hashPart(&hash, architecture);
    for (request.packages) |package| hashPart(&hash, package);
    return hash.finalResult();
}

fn systemSolverPolicyDigest(request: api.Request) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hashPart(&hash, "debz-system-solver-policy-v1");
    hashPart(
        &hash,
        if (request.options.recommends) "recommends" else "no-recommends",
    );
    hashPart(
        &hash,
        if (request.options.allow_downgrade)
            "allow-downgrade"
        else
            "no-downgrade",
    );
    hashPart(&hash, @tagName(request.options.repository_policy));
    return hash.finalResult();
}

fn hashPart(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, value.len, .big);
    hash.update(&length);
    hash.update(value);
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

test "system solver import retains active foreign architectures" {
    const foreign = [_][]const u8{ "arm64", "i386" };
    const request: api.Request = .{
        .operation = .install,
        .packages = &.{"demo"},
        .options = .{
            .install_root = "/",
            .cache_path = "/var/cache/debz",
            .state_path = "/var/lib/debz",
            .architecture = "amd64",
            .foreign_architectures = &foreign,
        },
    };
    const input = installedInput(request, &.{}, &.{});
    try std.testing.expectEqualStrings(
        "amd64",
        input.native_architecture,
    );
    try std.testing.expectEqual(@as(usize, 2), input.foreign_architectures.len);
    try std.testing.expectEqualStrings(
        "arm64",
        input.foreign_architectures[0],
    );
    try std.testing.expectEqualStrings(
        "i386",
        input.foreign_architectures[1],
    );

    const parsed = try dpkg_status.parseOwned(
        std.testing.allocator,
        "Package: foreign-lib\n" ++
            "Status: install ok installed\n" ++
            "Architecture: arm64\n" ++
            "Version: 1\n",
        .{},
    );
    var database = switch (parsed) {
        .database => |value| value,
        .diagnostic => return error.InvalidTestState,
    };
    defer database.deinit();
    const policies = try installedPolicies(
        std.testing.allocator,
        database.database.packages,
    );
    defer std.testing.allocator.free(policies);
    const foreign_input = installedInput(
        request,
        database.database.packages,
        policies,
    );
    var context = solver.Context.create();
    defer context.destroy();
    const imported = try context.importInstalled(foreign_input);
    switch (imported) {
        .imported => |summary| try std.testing.expectEqual(
            @as(usize, 1),
            summary.installed,
        ),
        .diagnostic => return error.UnexpectedDiagnostic,
    }
}

test "system operation replay rejects wrong action request and policy" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var actions = [_]solver.PlanAction{.{
        .kind = .remove,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .repository = null,
        .sha256 = null,
        .package_size = null,
        .installed_size_delta_bytes = -1,
        .source_package = "demo",
        .prior_installed = null,
        .requested = true,
        .reason = .explicit_request,
        .selected_origin = null,
        .selected_origin_v2 = null,
        .origin = null,
    }};
    var ordered = [_]solver.OrderedAction{.{
        .sequence = 0,
        .kind = .remove,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
    }};
    const plan: solver.Plan = .{
        .schema_version = 3,
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = &actions,
        .ordered_actions = &ordered,
        .summary = .{ .removals = 1 },
        .download_bytes = 0,
        .installed_size_delta_bytes = -1,
        .backing_allocator = std.testing.allocator,
        .arena = &arena,
    };
    const request: api.Request = .{
        .operation = .remove,
        .packages = &.{"demo"},
        .options = .{
            .install_root = "/",
            .cache_path = "/var/cache/debz",
            .state_path = "/var/lib/debz",
            .architecture = "amd64",
            .assume_yes = true,
            .noninteractive = true,
            .conffile = .keep_existing,
        },
    };
    const policy = try executionPolicy(
        std.testing.allocator,
        request,
        true,
    );
    defer std.testing.allocator.free(policy.risk.force);
    var operation_lock = try system_operation_lock.create(
        std.testing.allocator,
        .{
            .attempt_id = @splat(0xaa),
            .operation = .remove,
            .install_root = "/",
            .state_path = "/var/lib/debz",
            .target_architecture = "amd64",
            .request_sha256 = systemRequestDigest(request),
            .solver_policy_sha256 = systemSolverPolicyDigest(request),
            .executor_policy_sha256 = transaction_executor.policyDigest(policy),
            .plan_sha256 = transaction_executor.planDigest(plan),
            .package_lock_kind = .none,
            .package_lock_sha256 = null,
            .actions = &.{.{
                .kind = .remove,
                .package = "demo",
                .version = "1",
                .architecture = "amd64",
            }},
            .repository_refresh = &.{},
        },
    );
    defer operation_lock.deinit();
    try validateSystemOperationEvidence(
        operation_lock.lock,
        request,
        policy,
        plan,
        null,
        null,
    );
    const repository_id: [64]u8 = @splat('a');
    var package_lock_v1 = try exact_lock.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .policy_sha256 = @splat(2),
        .repositories = &.{.{
            .id = repository_id,
            .snapshot_sha256 = @splat(3),
            .release_sha256 = @splat(4),
            .index_sha256 = @splat(5),
            .signer_fingerprints = &.{@splat(6)},
        }},
        .packages = &.{.{
            .name = "retained",
            .version = "1",
            .architecture = "amd64",
            .repository_id = repository_id,
            .repository_snapshot_sha256 = @splat(3),
            .sha256 = @splat(7),
            .declared_size = 1,
            .retention = .retained,
            .dpkg_selection_hold = false,
        }},
        .authenticated_metadata = true,
    });
    defer package_lock_v1.deinit();
    var v1_operation_lock = try system_operation_lock.create(
        std.testing.allocator,
        .{
            .attempt_id = @splat(0xbb),
            .operation = .remove,
            .install_root = "/",
            .state_path = "/var/lib/debz",
            .target_architecture = "amd64",
            .request_sha256 = systemRequestDigest(request),
            .solver_policy_sha256 = systemSolverPolicyDigest(request),
            .executor_policy_sha256 = transaction_executor.policyDigest(
                policy,
            ),
            .plan_sha256 = transaction_executor.planDigest(plan),
            .package_lock_kind = .exact_v1,
            .package_lock_sha256 = package_lock_v1.lock.digest_sha256,
            .actions = operation_lock.lock.actions,
            .repository_refresh = &.{},
        },
    );
    defer v1_operation_lock.deinit();
    try validateSystemOperationEvidence(
        v1_operation_lock.lock,
        request,
        policy,
        plan,
        &package_lock_v1.lock,
        null,
    );

    var wrong_request = request;
    wrong_request.packages = &.{"other"};
    try std.testing.expectError(
        error.OperationLockMismatch,
        validateSystemOperationEvidence(
            operation_lock.lock,
            wrong_request,
            policy,
            plan,
            null,
            null,
        ),
    );
    wrong_request = request;
    wrong_request.options.state_path = "/host-state";
    try std.testing.expectError(
        error.OperationLockMismatch,
        validateSystemOperationEvidence(
            operation_lock.lock,
            wrong_request,
            policy,
            plan,
            null,
            null,
        ),
    );

    var wrong_policy = policy;
    wrong_policy.conffile = .use_package_version;
    try std.testing.expectError(
        error.OperationLockMismatch,
        validateSystemOperationEvidence(
            operation_lock.lock,
            request,
            wrong_policy,
            plan,
            null,
            null,
        ),
    );

    actions[0].version = "2";
    try std.testing.expectError(
        error.OperationLockMismatch,
        validateSystemOperationEvidence(
            operation_lock.lock,
            request,
            policy,
            plan,
            null,
            null,
        ),
    );
}

test "system exact-lock v2 replay validates request and solver policy" {
    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(1);
    const request: api.Request = .{
        .operation = .install,
        .packages = &.{"demo"},
        .options = .{
            .install_root = "/",
            .cache_path = "/var/cache/debz",
            .state_path = "/var/lib/debz",
            .architecture = "amd64",
        },
    };
    var lock = try exact_lock_v2.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = systemRequestDigest(request),
        .policy_sha256 = systemSolverPolicyDigest(request),
        .repositories = &.{.{
            .id = repository_id,
            .snapshot_sha256 = snapshot,
            .release_sha256 = @splat(2),
            .index_sha256 = @splat(3),
            .signer_fingerprints = &.{@splat(4)},
        }},
        .local_artifacts = &.{},
        .packages = &.{.{
            .name = "demo",
            .version = "1",
            .architecture = "amd64",
            .origin = .{ .authenticated_repository = .{
                .repository_id = repository_id,
                .repository_snapshot_sha256 = snapshot,
            } },
            .sha256 = @splat(5),
            .declared_size = 1,
            .retention = .requested,
            .dpkg_selection_hold = false,
        }},
        .verified_origins = true,
    });
    defer lock.deinit();
    try validateSystemPackageLockV2(request, lock.lock);

    var wrong_request = request;
    wrong_request.packages = &.{"other"};
    try std.testing.expectError(
        error.PackageLockMismatch,
        validateSystemPackageLockV2(wrong_request, lock.lock),
    );
    var wrong_policy = request;
    wrong_policy.options.recommends = true;
    try std.testing.expectError(
        error.PackageLockMismatch,
        validateSystemPackageLockV2(wrong_policy, lock.lock),
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

fn readSystemOperationLock(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !system_operation_lock.OwnedLock {
    const bytes = try readFile(
        allocator,
        io,
        path,
        system_operation_lock.maximum_document_bytes,
    );
    defer allocator.free(bytes);
    return system_operation_lock.decode(
        allocator,
        bytes,
        system_operation_lock.maximum_document_bytes,
    );
}

const LoadedSystemTransactionEvidence = struct {
    operation_lock: system_operation_lock.OwnedLock,
    evidence: TransactionEvidence,

    fn deinit(
        self: *LoadedSystemTransactionEvidence,
        allocator: std.mem.Allocator,
    ) void {
        self.operation_lock.deinit();
        freeTransactionEvidence(allocator, self.evidence);
        self.* = undefined;
    }
};

fn loadSystemTransactionEvidence(
    allocator: std.mem.Allocator,
    io: std.Io,
    install_root: []const u8,
    expected_state_path: ?[]const u8,
    intent: RecoveryIntent,
) !LoadedSystemTransactionEvidence {
    try validateSystemRecoveryIntent(intent);
    const attempt_id = try parseSha256Hex(intent.attempt_id.?);
    const expected_lock_digest = try parseSha256Hex(
        intent.operation_lock_sha256.?,
    );
    const root_state = try system_operation_lock.statePath(
        allocator,
        install_root,
    );
    defer allocator.free(root_state);
    const digest_hex = std.fmt.bytesToHex(expected_lock_digest, .lower);
    const lock_path = try std.fmt.allocPrint(
        allocator,
        "{s}/locks/{s}.json",
        .{ root_state, &digest_hex },
    );
    defer allocator.free(lock_path);
    var operation_lock = try readSystemOperationLock(
        allocator,
        io,
        lock_path,
    );
    errdefer operation_lock.deinit();
    if (!std.mem.eql(
        u8,
        &operation_lock.lock.digest_sha256,
        &expected_lock_digest,
    ) or !std.mem.eql(
        u8,
        &operation_lock.lock.attempt_id,
        &attempt_id,
    ) or !std.mem.eql(
        u8,
        operation_lock.lock.install_root,
        install_root,
    ))
        return error.OperationLockMismatch;
    if (expected_state_path) |state_path| {
        if (!std.mem.eql(
            u8,
            operation_lock.lock.state_path,
            state_path,
        )) return error.OperationLockMismatch;
    }
    return .{
        .evidence = try deriveSystemTransactionEvidence(
            allocator,
            operation_lock.lock,
        ),
        .operation_lock = operation_lock,
    };
}

fn validateSystemRecoveryIntent(intent: RecoveryIntent) !void {
    if (intent.version == null or
        intent.version.? != recovery_intent_version or
        intent.attempt_id == null or
        intent.operation_lock_sha256 == null or
        intent.exact_lock_path != null or
        intent.plan_path != null or
        intent.package_lock_path != null or
        intent.provenance_path != null or
        intent.evidence_directory != null or
        !intent.operation.mutates() or
        intent.operation == .refresh or
        intent.operation == .clean or
        intent.operation == .recover)
        return error.InvalidRecoveryIntent;
    _ = try parseSha256Hex(intent.attempt_id.?);
    _ = try parseSha256Hex(intent.operation_lock_sha256.?);
}

fn parseSha256Hex(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.InvalidDigest;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidDigest;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return error.InvalidDigest;
    }
    return result;
}

fn readPlanAt(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !solver.Plan {
    const parent = std.fs.path.dirname(path) orelse
        return error.InvalidAbsolutePath;
    const leaf = std.fs.path.basename(path);
    var dir = try openAbsoluteDirectory(io, parent);
    defer dir.close(io);
    const store = try repository_plan.Store.init(io, dir, leaf);
    return store.read(allocator);
}

fn validateSystemOperationEvidence(
    operation_lock: system_operation_lock.Lock,
    request: api.Request,
    executor_policy: transaction_executor.Policy,
    plan: solver.Plan,
    package_lock_v1: ?*const exact_lock.Lock,
    package_lock_v2: ?*const exact_lock_v2.Lock,
) !void {
    if (operation_lock.operation != request.operation or
        !std.mem.eql(
            u8,
            operation_lock.install_root,
            request.options.install_root,
        ) or !std.mem.eql(
        u8,
        operation_lock.state_path,
        request.options.state_path,
    ) or
        !std.mem.eql(
            u8,
            operation_lock.target_architecture,
            request.options.architecture,
        ) or !std.mem.eql(
        u8,
        &operation_lock.request_sha256,
        &systemRequestDigest(request),
    ) or !std.mem.eql(
        u8,
        &operation_lock.solver_policy_sha256,
        &systemSolverPolicyDigest(request),
    ) or !std.mem.eql(
        u8,
        &operation_lock.executor_policy_sha256,
        &transaction_executor.policyDigest(executor_policy),
    ) or !std.mem.eql(
        u8,
        &operation_lock.plan_sha256,
        &transaction_executor.planDigest(plan),
    ) or operation_lock.actions.len != plan.actions.len)
        return error.OperationLockMismatch;
    for (operation_lock.actions, plan.actions) |locked, action| {
        if (locked.kind != action.kind or
            !std.mem.eql(u8, locked.package, action.package) or
            !std.mem.eql(u8, locked.version, action.version) or
            !std.mem.eql(u8, locked.architecture, action.architecture))
            return error.OperationLockMismatch;
    }
    switch (operation_lock.package_lock_kind) {
        .none => if (package_lock_v1 != null or package_lock_v2 != null or
            operation_lock.package_lock_sha256 != null)
            return error.PackageLockMismatch,
        .exact_v1 => {
            if (package_lock_v1 == null or package_lock_v2 != null or
                operation_lock.package_lock_sha256 == null or
                !std.mem.eql(
                    u8,
                    &operation_lock.package_lock_sha256.?,
                    &package_lock_v1.?.digest_sha256,
                ))
                return error.PackageLockMismatch;
            if (operation_lock.repository_refresh.len != 0)
                return error.PackageLockMismatch;
            for (plan.actions) |action| {
                if (action.kind == .remove) continue;
                if (package_lock_v1.?.findPackage(
                    action.package,
                    action.version,
                    action.architecture,
                ) == null) return error.PackageLockMismatch;
            }
        },
        .exact_v2 => {
            if (package_lock_v2 == null or package_lock_v1 != null or
                operation_lock.package_lock_sha256 == null or
                !std.mem.eql(
                    u8,
                    &operation_lock.package_lock_sha256.?,
                    &package_lock_v2.?.digest_sha256,
                ) or !std.mem.eql(
                u8,
                &package_lock_v2.?.request_sha256,
                &operation_lock.request_sha256,
            ) or !std.mem.eql(
                u8,
                &package_lock_v2.?.policy_sha256,
                &operation_lock.solver_policy_sha256,
            ))
                return error.PackageLockMismatch;
            if (operation_lock.repository_refresh.len !=
                package_lock_v2.?.repositories.len)
                return error.PackageLockMismatch;
            for (
                operation_lock.repository_refresh,
                package_lock_v2.?.repositories,
            ) |refresh, repository| {
                if (!std.mem.eql(
                    u8,
                    &refresh.source_config_id,
                    &repository.id,
                ) or !std.mem.eql(
                    u8,
                    &refresh.snapshot_sha256,
                    &repository.snapshot_sha256,
                ))
                    return error.PackageLockMismatch;
            }
            for (plan.actions) |action| {
                if (action.kind == .remove) continue;
                if (package_lock_v2.?.findPackage(
                    action.package,
                    action.version,
                    action.architecture,
                ) == null) return error.PackageLockMismatch;
            }
            for (package_lock_v2.?.packages) |package| {
                var found = false;
                for (plan.actions) |action| {
                    if (action.kind != .remove and
                        std.mem.eql(u8, action.package, package.name) and
                        std.mem.eql(u8, action.version, package.version) and
                        std.mem.eql(
                            u8,
                            action.architecture,
                            package.architecture,
                        ))
                    {
                        found = true;
                        break;
                    }
                }
                if (!found) return error.PackageLockMismatch;
            }
        },
    }
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

fn writeLockV2(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    lock: exact_lock_v2.Lock,
) !void {
    const parent = std.fs.path.dirname(path) orelse
        return error.InvalidAbsolutePath;
    const leaf = std.fs.path.basename(path);
    var dir = try openAbsoluteDirectory(io, parent);
    defer dir.close(io);
    const store = try exact_lock_v2.Store.init(io, dir, leaf);
    try store.writeAtomic(allocator, lock);
}

const TransactionEvidence = struct {
    attempt_id: [32]u8,
    operation_lock_sha256: [32]u8,
    exact_lock_path: []const u8,
    directory_path: []const u8,
    plan_path: []const u8,
    package_lock_path: ?[]const u8,
    provenance_path: ?[]const u8,
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

fn freeTransactionEvidence(
    allocator: std.mem.Allocator,
    evidence: TransactionEvidence,
) void {
    allocator.free(evidence.exact_lock_path);
    allocator.free(evidence.directory_path);
    allocator.free(evidence.plan_path);
    if (evidence.package_lock_path) |path| allocator.free(path);
    if (evidence.provenance_path) |path| allocator.free(path);
    allocator.free(evidence.recovery_path);
}

fn prepareSystemTransactionEvidence(
    allocator: std.mem.Allocator,
    io: std.Io,
    operation_lock: system_operation_lock.Lock,
    plan: solver.Plan,
    package_lock_v1: ?*const exact_lock.Lock,
    package_lock_v2: ?*const exact_lock_v2.Lock,
) !TransactionEvidence {
    const evidence = try deriveSystemTransactionEvidence(
        allocator,
        operation_lock,
    );
    errdefer freeTransactionEvidence(allocator, evidence);
    try publishSystemOperationLockAt(
        allocator,
        io,
        evidence.exact_lock_path,
        operation_lock,
    );

    var directory = try createPersistentAttemptDirectory(
        io,
        evidence.directory_path,
    );
    defer directory.close(io);
    const operation_store = try system_operation_lock.Store.init(
        io,
        directory,
        "system-operation-lock-v2.json",
    );
    try operation_store.writeAtomic(allocator, operation_lock);
    const plan_store = try repository_plan.Store.init(
        io,
        directory,
        "transaction-plan-v3.json",
    );
    try plan_store.writeAtomic(allocator, plan);
    if (package_lock_v1) |lock| {
        const store = try exact_lock.Store.init(
            io,
            directory,
            "exact-lock-v1.json",
        );
        try store.writeAtomic(allocator, lock.*);
    } else if (package_lock_v2) |lock| {
        const store = try exact_lock_v2.Store.init(
            io,
            directory,
            "exact-lock-v2.json",
        );
        try store.writeAtomic(allocator, lock.*);
    }
    return evidence;
}

fn deriveSystemTransactionEvidence(
    allocator: std.mem.Allocator,
    operation_lock: system_operation_lock.Lock,
) !TransactionEvidence {
    const attempt_hex = std.fmt.bytesToHex(
        operation_lock.attempt_id,
        .lower,
    );
    const digest_hex = std.fmt.bytesToHex(
        operation_lock.digest_sha256,
        .lower,
    );
    const root_state = try system_operation_lock.statePath(
        allocator,
        operation_lock.install_root,
    );
    defer allocator.free(root_state);
    const exact_lock_path = try std.fmt.allocPrint(
        allocator,
        "{s}/locks/{s}.json",
        .{ root_state, &digest_hex },
    );
    errdefer allocator.free(exact_lock_path);
    const directory_path = try std.fmt.allocPrint(
        allocator,
        "{s}/transactions/{s}",
        .{ operation_lock.state_path, &attempt_hex },
    );
    errdefer allocator.free(directory_path);
    const plan_path = try std.fmt.allocPrint(
        allocator,
        "{s}/transaction-plan-v3.json",
        .{directory_path},
    );
    errdefer allocator.free(plan_path);
    const package_lock_path: ?[]const u8 =
        switch (operation_lock.package_lock_kind) {
            .none => null,
            .exact_v1 => try std.fmt.allocPrint(
                allocator,
                "{s}/exact-lock-v1.json",
                .{directory_path},
            ),
            .exact_v2 => try std.fmt.allocPrint(
                allocator,
                "{s}/exact-lock-v2.json",
                .{directory_path},
            ),
        };
    errdefer if (package_lock_path) |path| allocator.free(path);
    const provenance_path: ?[]const u8 =
        switch (operation_lock.package_lock_kind) {
            .none => null,
            .exact_v1 => try std.fmt.allocPrint(
                allocator,
                "{s}/transaction-result.json",
                .{directory_path},
            ),
            .exact_v2 => try std.fmt.allocPrint(
                allocator,
                "{s}/transaction-result-v3.json",
                .{directory_path},
            ),
        };
    errdefer if (provenance_path) |path| allocator.free(path);
    return .{
        .attempt_id = operation_lock.attempt_id,
        .operation_lock_sha256 = operation_lock.digest_sha256,
        .exact_lock_path = exact_lock_path,
        .directory_path = directory_path,
        .plan_path = plan_path,
        .package_lock_path = package_lock_path,
        .provenance_path = provenance_path,
        .recovery_path = try std.fmt.allocPrint(
            allocator,
            "{s}/recovery-request.json",
            .{directory_path},
        ),
    };
}

fn createPersistentAttemptDirectory(
    io: std.Io,
    path: []const u8,
) !std.Io.Dir {
    return createPersistentAttemptDirectoryWithSync(io, path, .{});
}

fn createPersistentAttemptDirectoryWithSync(
    io: std.Io,
    path: []const u8,
    syncer: DirectorySyncer,
) !std.Io.Dir {
    const parent_path = std.fs.path.dirname(path) orelse
        return error.InvalidAbsolutePath;
    const leaf = std.fs.path.basename(path);
    var parent = try openOrCreateAbsoluteDirectoryWithSync(
        io,
        parent_path,
        syncer,
    );
    defer parent.close(io);
    parent.createDir(io, leaf, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return error.AttemptAlreadyExists,
        else => return err,
    };
    try syncer.sync(parent);
    return parent.openDir(io, leaf, .{ .follow_symlinks = false });
}

fn publishSystemOperationLockAt(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    lock: system_operation_lock.Lock,
) !void {
    const parent = std.fs.path.dirname(path) orelse
        return error.InvalidAbsolutePath;
    const leaf = std.fs.path.basename(path);
    var dir = try openOrCreateAbsoluteDirectory(io, parent);
    defer dir.close(io);
    const store = try system_operation_lock.Store.init(io, dir, leaf);
    var existing = store.read(allocator) catch |err| switch (err) {
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
) !?exact_lock_v2.OwnedLock {
    var packages: std.ArrayList(exact_lock_v2.Package) = .empty;
    defer packages.deinit(allocator);
    var repository_ids: std.ArrayList([64]u8) = .empty;
    defer repository_ids.deinit(allocator);

    for (plan.actions) |action| {
        if (action.kind == .remove) continue;
        const origin = try authenticatedPackageOrigin(
            action.selected_origin_v2 orelse return error.MissingRepository,
        );
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
    if (packages.items.len == 0) return null;

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

    return @as(?exact_lock_v2.OwnedLock, try exact_lock_v2.create(allocator, .{
        .target_architecture = request.options.architecture,
        .request_sha256 = systemRequestDigest(request),
        .policy_sha256 = systemSolverPolicyDigest(request),
        .repositories = repositories.items,
        .local_artifacts = &.{},
        .packages = packages.items,
        .verified_origins = true,
    }));
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
    attempt_sha256: ?[32]u8,
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
        attempt_sha256,
        provenance.result,
    );
}

fn writeRetainedRecoveryProvenanceV2(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: api.Request,
    operation_lock: system_operation_lock.Lock,
    lock: exact_lock_v2.Lock,
    report: transaction_executor.RecoveryReport,
    status: transaction_recovery.StatusReader,
    output_path: []const u8,
) !void {
    const repositories = try allocator.alloc(
        transaction_provenance_v2.RepositoryEvidence,
        lock.repositories.len,
    );
    defer allocator.free(repositories);
    for (lock.repositories, 0..) |repository, index| {
        repositories[index] = .{
            .source_config_id = repository.id,
            .snapshot_sha256 = repository.snapshot_sha256,
            .release_sha256 = repository.release_sha256,
            .signature_sha256 = null,
            .metadata_sha256 = repository.index_sha256,
            .signer_fingerprints = repository.signer_fingerprints,
            .signature_verified = true,
        };
    }
    const packages = try allocator.alloc(
        transaction_provenance_v2.PackageEvidence,
        lock.packages.len,
    );
    defer allocator.free(packages);
    for (lock.packages, 0..) |package, index| {
        packages[index] = .{
            .name = package.name,
            .version = package.version,
            .architecture = package.architecture,
            .origin = package.origin,
            .package_sha256 = package.sha256,
            .cas_sha256 = package.sha256,
            .declared_size = package.declared_size,
        };
    }
    try transaction_provenance_v2.verifyLockEvidence(
        allocator,
        lock,
        repositories,
        packages,
        null,
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
    var execution = try transaction_provenance_v2.createFromRecovery(
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
    defer execution.deinit();
    var provenance = try transaction_provenance_v3.create(
        allocator,
        operation_lock.attempt_id,
        execution.result,
        operation_lock.repository_refresh,
    );
    defer provenance.deinit();
    const parent = std.fs.path.dirname(output_path) orelse
        return error.InvalidAbsolutePath;
    const leaf = std.fs.path.basename(output_path);
    var directory = try openAbsoluteDirectory(io, parent);
    defer directory.close(io);
    const store = try transaction_provenance_v3.Store.init(
        io,
        directory,
        leaf,
    );
    try store.writeAtomic(allocator, provenance.result);
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
    attempt_sha256: ?[32]u8,
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
        attempt_sha256,
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
    attempt_sha256: ?[32]u8,
    execution: transaction_provenance_v2.Result,
) !void {
    const refresh_evidence = try repositoryRefreshEvidenceFromSnapshots(
        allocator,
        refreshed,
        lock,
    );
    defer allocator.free(refresh_evidence);
    var complete_provenance = try transaction_provenance_v3.create(
        allocator,
        attempt_sha256,
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

fn repositoryRefreshEvidenceFromSnapshots(
    allocator: std.mem.Allocator,
    refreshed: *repository_policy.RefreshResult,
    lock: exact_lock_v2.Lock,
) ![]transaction_provenance_v3.RepositoryRefreshEvidence {
    const refresh_evidence = try allocator.alloc(
        transaction_provenance_v3.RepositoryRefreshEvidence,
        lock.repositories.len,
    );
    errdefer allocator.free(refresh_evidence);
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
            .maximum_future_seconds = policy.maximum_future_seconds,
            .future_date_accepted = policy.future_date_accepted,
            .observed_release_age_seconds = policy.observed_release_age_seconds,
            .expiry_policy = policy.expiry_policy,
            .maximum_release_age_seconds = policy.maximum_release_age_seconds,
            .missing_valid_until_exception_exercised = policy.missing_valid_until_exception_exercised,
            .selected_packages_path = snapshot.snapshot.provenance.selected_path,
            .compression = snapshot.snapshot.provenance.compression,
        };
    }
    return refresh_evidence;
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

const DirectorySyncer = struct {
    context: ?*anyopaque = null,
    syncFn: *const fn (?*anyopaque, std.Io.Dir) anyerror!void =
        systemDirectorySync,

    fn sync(self: DirectorySyncer, dir: std.Io.Dir) !void {
        try self.syncFn(self.context, dir);
    }
};

fn systemDirectorySync(_: ?*anyopaque, dir: std.Io.Dir) !void {
    try syncDirectory(dir);
}

fn openOrCreateAbsoluteDirectory(io: std.Io, path: []const u8) !std.Io.Dir {
    return openOrCreateAbsoluteDirectoryWithSync(
        io,
        path,
        .{},
    );
}

fn openOrCreateAbsoluteDirectoryWithSync(
    io: std.Io,
    path: []const u8,
    syncer: DirectorySyncer,
) !std.Io.Dir {
    if (!std.fs.path.isAbsolute(path)) return error.InvalidAbsolutePath;
    var current = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false });
    errdefer current.close(io);
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.InvalidAbsolutePath;
        var created = true;
        current.createDir(io, component, .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => created = false,
            else => return err,
        };
        if (created) try syncer.sync(current);
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

const RecoveryPlanProbe = struct {
    observed_plan_sha256: ?[32]u8 = null,
    succeed: bool = false,

    fn executor(self: *RecoveryPlanProbe) Executor {
        return .{
            .context = self,
            .executeFn = rejectExecute,
            .recoverFn = recover,
        };
    }

    fn rejectExecute(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: transaction_executor.Request,
        _: transaction_executor.Dependencies,
    ) !transaction_executor.Report {
        return error.UnexpectedExecute;
    }

    fn recover(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: transaction_executor.RecoveryRequest,
        _: transaction_executor.Dependencies,
    ) !transaction_executor.RecoveryReport {
        const self: *RecoveryPlanProbe = @ptrCast(@alignCast(context));
        self.observed_plan_sha256 = transaction_executor.planDigest(
            request.plan.*,
        );
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = .init(allocator);
        return .{
            .allocator = allocator,
            .arena = arena,
            .state = if (self.succeed) .complete else .interrupted,
            .commands = &.{},
            .plan_sha256 = self.observed_plan_sha256.?,
            .root_identity = transaction_recovery.rootIdentity(
                request.install_root,
            ),
            .policy_sha256 = transaction_executor.policyDigest(request.policy),
            .lock_sha256 = if (request.exact_lock) |lock|
                lock.digest_sha256
            else if (request.exact_lock_v2) |lock|
                lock.digest_sha256
            else
                null,
            .failure = if (self.succeed) null else .{
                .code = .recovery_failed,
                .diagnostic = "probe",
            },
        };
    }
};

const FailingDirectorySync = struct {
    calls: usize = 0,
    fail_at: ?usize = null,

    fn interface(self: *FailingDirectorySync) DirectorySyncer {
        return .{ .context = self, .syncFn = sync };
    }

    fn sync(context: ?*anyopaque, _: std.Io.Dir) !void {
        const self: *FailingDirectorySync = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        if (self.fail_at == self.calls) return error.InjectedSyncFailure;
    }
};

const FailingJournalProbe = struct {
    fn store() transaction_recovery.Store {
        return .{
            .context = @ptrCast(@constCast(&context)),
            .loadFn = load,
            .writeAtomicFn = write,
            .archiveAtomicFn = write,
        };
    }

    fn load(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: []const u8,
    ) !?[]u8 {
        return error.InjectedJournalReadFailure;
    }

    fn write(_: *anyopaque, _: []const u8, _: []const u8) !void {}

    var context: u8 = 0;
};

const FixedStatusReader = struct {
    bytes: []const u8,

    fn interface(self: *FixedStatusReader) transaction_recovery.StatusReader {
        return .{ .context = self, .readFn = read };
    }

    fn read(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        _: []const u8,
        maximum: usize,
    ) ![]u8 {
        const self: *FixedStatusReader = @ptrCast(@alignCast(context));
        if (self.bytes.len > maximum) return error.StreamTooLong;
        return allocator.dupe(u8, self.bytes);
    }
};

test "journal probe errors never prove a pre-mutation state" {
    try std.testing.expectError(
        error.InjectedJournalReadFailure,
        probeJournalForCleanup(
            std.testing.allocator,
            FailingJournalProbe.store(),
            "/root",
        ),
    );
}

test "persistent directory creation fsyncs each new component" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(std.testing.io, &real);
    const nested = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/one/two",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(nested);
    var syncer: FailingDirectorySync = .{ .fail_at = 1 };
    try std.testing.expectError(
        error.InjectedSyncFailure,
        openOrCreateAbsoluteDirectoryWithSync(
            std.testing.io,
            nested,
            syncer.interface(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), syncer.calls);
    try directory.dir.access(std.testing.io, "one", .{});
    try std.testing.expectError(
        error.FileNotFound,
        directory.dir.access(std.testing.io, "one/two", .{}),
    );
}

test "system operation guard serializes intent owners" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root");
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(std.testing.io, &real);
    const root = real[0..length];
    const install_root = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/root",
        .{root},
    );
    defer std.testing.allocator.free(install_root);
    const cache_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/cache",
        .{root},
    );
    defer std.testing.allocator.free(cache_path);
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{root},
    );
    defer std.testing.allocator.free(state_path);
    const lock_path = try system_operation_lock.guardPath(
        std.testing.allocator,
        install_root,
    );
    defer std.testing.allocator.free(lock_path);
    var first_manager = transaction_executor.SystemLockManager{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    var second_manager = transaction_executor.SystemLockManager{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    const first = first_manager.interface();
    const token = try first.acquire(lock_path, 100);
    defer first.release(token);
    var backend: Backend = .{
        .io = std.testing.io,
        .system_profile = true,
        .operation_locks = second_manager.interface(),
    };
    const result = try backend.execute(std.testing.allocator, .{
        .operation = .clean,
        .options = .{
            .install_root = install_root,
            .cache_path = cache_path,
            .state_path = state_path,
            .architecture = "amd64",
            .lock_wait_ms = 1,
            .assume_yes = true,
        },
    });
    try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
    try std.testing.expectEqual(
        api.ErrorId.recovery_required,
        result.diagnostics[0].id,
    );
}

test "pre-journal failure cleanup removes both recovery intents" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "state/evidence");
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(std.testing.io, &real);
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(state_path);
    const evidence_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/evidence",
        .{state_path},
    );
    defer std.testing.allocator.free(evidence_path);
    const evidence: TransactionEvidence = .{
        .attempt_id = @splat(0xaa),
        .operation_lock_sha256 = @splat(0xbb),
        .exact_lock_path = "/lock",
        .directory_path = evidence_path,
        .plan_path = "/plan",
        .package_lock_path = null,
        .provenance_path = null,
        .recovery_path = "/recovery",
    };
    const request: api.Request = .{
        .operation = .remove,
        .packages = &.{"demo"},
        .options = .{
            .install_root = "/root",
            .cache_path = "/cache",
            .state_path = state_path,
            .architecture = "amd64",
        },
    };
    try writeRecoveryIntent(
        std.testing.allocator,
        std.testing.io,
        state_path,
        request,
        evidence,
    );
    try writeRecoveryIntent(
        std.testing.allocator,
        std.testing.io,
        evidence_path,
        request,
        evidence,
    );
    try clearRecoveryIntents(std.testing.io, state_path, evidence);
    try std.testing.expectError(
        error.FileNotFound,
        readRecoveryIntent(
            std.testing.allocator,
            std.testing.io,
            state_path,
        ),
    );
    try std.testing.expectError(
        error.FileNotFound,
        readRecoveryIntent(
            std.testing.allocator,
            std.testing.io,
            evidence_path,
        ),
    );
}

test "cleanup failure retains the root recovery intent" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "state");
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(std.testing.io, &real);
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(state_path);
    const missing_evidence = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/missing",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(missing_evidence);
    const evidence: TransactionEvidence = .{
        .attempt_id = @splat(0xaa),
        .operation_lock_sha256 = @splat(0xbb),
        .exact_lock_path = "/lock",
        .directory_path = missing_evidence,
        .plan_path = "/plan",
        .package_lock_path = null,
        .provenance_path = null,
        .recovery_path = "/recovery",
    };
    const request: api.Request = .{
        .operation = .remove,
        .packages = &.{"demo"},
        .options = .{
            .install_root = "/root",
            .cache_path = "/cache",
            .state_path = state_path,
            .architecture = "amd64",
        },
    };
    try writeRecoveryIntent(
        std.testing.allocator,
        std.testing.io,
        state_path,
        request,
        evidence,
    );
    try std.testing.expectError(
        error.FileNotFound,
        clearRecoveryIntents(std.testing.io, state_path, evidence),
    );
    var retained = try readRecoveryIntent(
        std.testing.allocator,
        std.testing.io,
        state_path,
    );
    retained.deinit();
}

test "system recovery intent cannot redirect evidence outside its bound state" {
    var intent: RecoveryIntent = .{
        .version = recovery_intent_version,
        .attempt_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .operation_lock_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        .operation = .remove,
        .packages = &.{"demo"},
        .recommends = false,
        .allow_downgrade = false,
        .repository_policy = .strict_priority,
        .conffile = .keep_existing,
        .force = &.{},
        .lock_wait_ms = 30_000,
        .evidence_directory = "/etc",
    };
    try std.testing.expectError(
        error.InvalidRecoveryIntent,
        validateSystemRecoveryIntent(intent),
    );
    intent.evidence_directory = null;
    intent.attempt_id = "../../host";
    try std.testing.expectError(
        error.InvalidDigest,
        validateSystemRecoveryIntent(intent),
    );
}

test "tampered system intent never reaches an alternate-root path" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/debz");
    try directory.dir.createDirPath(std.testing.io, "state");
    try directory.dir.createDirPath(std.testing.io, "host");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "host/sentinel",
        .data = "retain",
    });
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(std.testing.io, &real);
    const install_root = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/root",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(install_root);
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(state_path);
    const host_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/host",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(host_path);
    const active_path = try system_operation_lock.statePath(
        std.testing.allocator,
        install_root,
    );
    defer std.testing.allocator.free(active_path);
    var active = try openAbsoluteDirectory(std.testing.io, active_path);
    defer active.close(std.testing.io);
    const malicious = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"version\":2,\"attempt_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"operation_lock_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"operation\":\"remove\",\"packages\":[\"demo\"],\"recommends\":false,\"allow_downgrade\":false,\"foreign_architectures\":[],\"repository_policy\":\"strict_priority\",\"conffile\":\"keep_existing\",\"force\":[],\"lock_wait_ms\":1,\"evidence_directory\":\"{s}\"}}\n",
        .{host_path},
    );
    defer std.testing.allocator.free(malicious);
    try active.writeFile(std.testing.io, .{
        .sub_path = "recovery-request.json",
        .data = malicious,
    });
    var backend: Backend = .{
        .io = std.testing.io,
        .system_profile = true,
    };
    const result = try backend.execute(std.testing.allocator, .{
        .operation = .recover,
        .options = .{
            .install_root = install_root,
            .cache_path = "/cache",
            .state_path = state_path,
            .architecture = "amd64",
            .lock_wait_ms = 10,
            .assume_yes = true,
            .noninteractive = true,
            .conffile = .keep_existing,
        },
    });
    try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
    try std.testing.expectEqual(
        api.ErrorId.recovery_failed,
        result.diagnostics[0].id,
    );
    try directory.dir.access(std.testing.io, "host/sentinel", .{});
    try active.access(std.testing.io, "recovery-request.json", .{});
}

test "system recovery loads persisted plan without repository refresh" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/debz");
    try directory.dir.createDirPath(std.testing.io, "state");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "",
    });
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(std.testing.io, &real);
    const base = real[0..length];
    const install_root = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/root",
        .{base},
    );
    defer std.testing.allocator.free(install_root);
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{base},
    );
    defer std.testing.allocator.free(state_path);
    const active_state_path = try system_operation_lock.statePath(
        std.testing.allocator,
        install_root,
    );
    defer std.testing.allocator.free(active_state_path);
    const request: api.Request = .{
        .operation = .remove,
        .packages = &.{"demo"},
        .options = .{
            .install_root = install_root,
            .cache_path = "/unused-cache",
            .state_path = state_path,
            .architecture = "amd64",
            .assume_yes = true,
            .noninteractive = true,
            .conffile = .keep_existing,
        },
    };
    var plan_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer plan_arena.deinit();
    var actions = [_]solver.PlanAction{.{
        .kind = .remove,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .repository = null,
        .sha256 = null,
        .package_size = null,
        .installed_size_delta_bytes = -1,
        .source_package = "demo",
        .prior_installed = .{
            .package = "demo",
            .version = "1",
            .architecture = "amd64",
            .installed_size_kib = 1,
        },
        .requested = true,
        .reason = .explicit_request,
        .selected_origin = null,
        .selected_origin_v2 = null,
        .origin = null,
    }};
    var ordered = [_]solver.OrderedAction{.{
        .sequence = 0,
        .kind = .remove,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
    }};
    const plan: solver.Plan = .{
        .schema_version = 3,
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = &actions,
        .ordered_actions = &ordered,
        .summary = .{ .removals = 1 },
        .download_bytes = 0,
        .installed_size_delta_bytes = -1,
        .backing_allocator = std.testing.allocator,
        .arena = &plan_arena,
    };
    const executor_policy = try executionPolicy(
        std.testing.allocator,
        request,
        true,
    );
    defer std.testing.allocator.free(executor_policy.risk.force);
    var operation_lock = try system_operation_lock.create(
        std.testing.allocator,
        .{
            .attempt_id = @splat(0xaa),
            .operation = .remove,
            .install_root = install_root,
            .state_path = state_path,
            .target_architecture = "amd64",
            .request_sha256 = systemRequestDigest(request),
            .solver_policy_sha256 = systemSolverPolicyDigest(request),
            .executor_policy_sha256 = transaction_executor.policyDigest(executor_policy),
            .plan_sha256 = transaction_executor.planDigest(plan),
            .package_lock_kind = .none,
            .package_lock_sha256 = null,
            .actions = &.{.{
                .kind = .remove,
                .package = "demo",
                .version = "1",
                .architecture = "amd64",
            }},
            .repository_refresh = &.{},
        },
    );
    defer operation_lock.deinit();
    const evidence = try prepareSystemTransactionEvidence(
        std.testing.allocator,
        std.testing.io,
        operation_lock.lock,
        plan,
        null,
        null,
    );
    defer freeTransactionEvidence(std.testing.allocator, evidence);
    try writeRecoveryIntent(
        std.testing.allocator,
        std.testing.io,
        active_state_path,
        request,
        evidence,
    );
    try writeRecoveryIntent(
        std.testing.allocator,
        std.testing.io,
        evidence.directory_path,
        request,
        evidence,
    );
    var probe: RecoveryPlanProbe = .{};
    var backend: Backend = .{
        .io = std.testing.io,
        .system_profile = true,
        .executor = probe.executor(),
    };
    const recover_request: api.Request = .{
        .operation = .recover,
        .options = .{
            .install_root = install_root,
            .cache_path = "/missing-cache",
            .state_path = state_path,
            .architecture = "amd64",
            .assume_yes = true,
            .noninteractive = true,
            .conffile = .keep_existing,
        },
    };
    const stale = try backend.execute(
        std.testing.allocator,
        recover_request,
    );
    try std.testing.expectEqual(api.ExitStatus.recovery, stale.exit_status);
    try std.testing.expect(probe.observed_plan_sha256 == null);
    try std.testing.expectError(
        error.FileNotFound,
        readRecoveryIntent(
            std.testing.allocator,
            std.testing.io,
            active_state_path,
        ),
    );

    try writeRecoveryIntent(
        std.testing.allocator,
        std.testing.io,
        active_state_path,
        request,
        evidence,
    );
    var evidence_dir = try openAbsoluteDirectory(
        std.testing.io,
        evidence.directory_path,
    );
    defer evidence_dir.close(std.testing.io);
    try evidence_dir.writeFile(std.testing.io, .{
        .sub_path = "transaction.journal",
        .data = "retained",
    });
    const result = try backend.execute(
        std.testing.allocator,
        recover_request,
    );
    try std.testing.expectEqual(api.ExitStatus.recovery, result.exit_status);
    const expected_plan_sha256 = transaction_executor.planDigest(plan);
    try std.testing.expectEqualSlices(
        u8,
        &expected_plan_sha256,
        &probe.observed_plan_sha256.?,
    );
}

test "successful system recovery publishes attempt-bound v3 provenance" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/debz");
    try directory.dir.createDirPath(std.testing.io, "state");
    try directory.dir.createDirPath(std.testing.io, "host-state");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "host-state/sentinel",
        .data = "retain",
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "Package: demo\n" ++
            "Status: install ok installed\n" ++
            "Architecture: amd64\n" ++
            "Version: 1\n",
    });
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(std.testing.io, &real);
    const install_root = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/root",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(install_root);
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(state_path);
    const host_state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/host-state",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(host_state_path);
    const active_state_path = try system_operation_lock.statePath(
        std.testing.allocator,
        install_root,
    );
    defer std.testing.allocator.free(active_state_path);
    const request: api.Request = .{
        .operation = .install,
        .packages = &.{"demo"},
        .options = .{
            .install_root = install_root,
            .cache_path = "/cache",
            .state_path = state_path,
            .architecture = "amd64",
            .assume_yes = true,
            .noninteractive = true,
            .conffile = .keep_existing,
        },
    };
    const artifact: package_origin.LocalArtifactEvidence = .{
        .artifact_id = @splat('a'),
        .sha256 = @splat(0x11),
        .size = 1,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .acquisition_url = "file:///cache/demo.deb",
        .trust_mode = .pinned_sha256,
    };
    var package_lock = try exact_lock_v2.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = systemRequestDigest(request),
        .policy_sha256 = systemSolverPolicyDigest(request),
        .repositories = &.{},
        .local_artifacts = &.{artifact},
        .packages = &.{.{
            .name = "demo",
            .version = "1",
            .architecture = "amd64",
            .origin = .{ .local_artifact = artifact },
            .sha256 = artifact.sha256,
            .declared_size = artifact.size,
            .retention = .requested,
            .dpkg_selection_hold = false,
        }},
        .verified_origins = true,
    });
    defer package_lock.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var actions = [_]solver.PlanAction{.{
        .kind = .install,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .repository = null,
        .sha256 = package_origin.artifactIdFromSha256(artifact.sha256),
        .package_size = artifact.size,
        .installed_size_delta_bytes = 1,
        .source_package = "demo",
        .prior_installed = null,
        .requested = true,
        .reason = .explicit_request,
        .selected_origin = null,
        .selected_origin_v2 = .{ .local_artifact = .{
            .evidence = artifact,
            .solver_priority = 1_000,
            .record_index = 0,
            .source_location = artifact.acquisition_url,
        } },
        .origin = .{ .local_artifact = .{
            .evidence = artifact,
            .solver_priority = 1_000,
        } },
    }};
    var ordered = [_]solver.OrderedAction{
        .{
            .sequence = 0,
            .kind = .unpack,
            .package = "demo",
            .version = "1",
            .architecture = "amd64",
        },
        .{
            .sequence = 1,
            .kind = .configure_pending,
            .package = "demo",
            .version = "1",
            .architecture = "amd64",
        },
    };
    const plan: solver.Plan = .{
        .schema_version = 3,
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = &actions,
        .ordered_actions = &ordered,
        .summary = .{ .installs = 1, .download_bytes = artifact.size },
        .download_bytes = artifact.size,
        .installed_size_delta_bytes = 1,
        .backing_allocator = std.testing.allocator,
        .arena = &arena,
    };
    var policy = try executionPolicy(
        std.testing.allocator,
        request,
        true,
    );
    defer std.testing.allocator.free(policy.risk.force);
    policy.exact_lock_verification = .locked_packages;
    var operation_lock = try system_operation_lock.create(
        std.testing.allocator,
        .{
            .attempt_id = @splat(0xaa),
            .operation = .install,
            .install_root = install_root,
            .state_path = state_path,
            .target_architecture = "amd64",
            .request_sha256 = systemRequestDigest(request),
            .solver_policy_sha256 = systemSolverPolicyDigest(request),
            .executor_policy_sha256 = transaction_executor.policyDigest(
                policy,
            ),
            .plan_sha256 = transaction_executor.planDigest(plan),
            .package_lock_kind = .exact_v2,
            .package_lock_sha256 = package_lock.lock.digest_sha256,
            .actions = &.{.{
                .kind = .install,
                .package = "demo",
                .version = "1",
                .architecture = "amd64",
            }},
            .repository_refresh = &.{},
        },
    );
    defer operation_lock.deinit();
    try validateSystemOperationEvidence(
        operation_lock.lock,
        request,
        policy,
        plan,
        null,
        &package_lock.lock,
    );
    const mismatched_refresh =
        transaction_provenance_v3.RepositoryRefreshEvidence{
            .source_config_id = @splat('b'),
            .snapshot_sha256 = @splat(1),
            .signed_release_date_unix = 1_000,
            .valid_until_unix = 2_000,
            .verification_time_unix = 1_100,
            .maximum_future_seconds = 300,
            .future_date_accepted = false,
            .observed_release_age_seconds = 100,
            .expiry_policy = .require_valid_until,
            .maximum_release_age_seconds = null,
            .missing_valid_until_exception_exercised = false,
            .selected_packages_path = "main/binary-amd64/Packages.gz",
            .compression = .gzip,
        };
    var mismatched_operation_lock = operation_lock.lock;
    mismatched_operation_lock.repository_refresh = &.{mismatched_refresh};
    try std.testing.expectError(
        error.PackageLockMismatch,
        validateSystemOperationEvidence(
            mismatched_operation_lock,
            request,
            policy,
            plan,
            null,
            &package_lock.lock,
        ),
    );
    const evidence = try prepareSystemTransactionEvidence(
        std.testing.allocator,
        std.testing.io,
        operation_lock.lock,
        plan,
        null,
        &package_lock.lock,
    );
    defer freeTransactionEvidence(std.testing.allocator, evidence);
    try writeRecoveryIntent(
        std.testing.allocator,
        std.testing.io,
        active_state_path,
        request,
        evidence,
    );
    try writeRecoveryIntent(
        std.testing.allocator,
        std.testing.io,
        evidence.directory_path,
        request,
        evidence,
    );
    var evidence_dir = try openAbsoluteDirectory(
        std.testing.io,
        evidence.directory_path,
    );
    defer evidence_dir.close(std.testing.io);
    try evidence_dir.writeFile(std.testing.io, .{
        .sub_path = "transaction.journal",
        .data = "retained",
    });
    var probe: RecoveryPlanProbe = .{ .succeed = true };
    var backend: Backend = .{
        .io = std.testing.io,
        .system_profile = true,
        .executor = probe.executor(),
    };
    const recover_request: api.Request = .{
        .operation = .recover,
        .options = .{
            .install_root = install_root,
            .cache_path = "/missing-cache",
            .state_path = state_path,
            .architecture = "amd64",
            .assume_yes = true,
            .noninteractive = true,
            .conffile = .keep_existing,
        },
    };
    var wrong_state_request = recover_request;
    wrong_state_request.options.state_path = host_state_path;
    const wrong_state = try backend.execute(
        std.testing.allocator,
        wrong_state_request,
    );
    try std.testing.expectEqual(
        api.ExitStatus.recovery,
        wrong_state.exit_status,
    );
    try std.testing.expectEqual(
        api.ErrorId.recovery_failed,
        wrong_state.diagnostics[0].id,
    );
    try directory.dir.access(
        std.testing.io,
        "host-state/sentinel",
        .{},
    );
    var retained_intent = try readRecoveryIntent(
        std.testing.allocator,
        std.testing.io,
        active_state_path,
    );
    retained_intent.deinit();

    const result = try backend.execute(
        std.testing.allocator,
        recover_request,
    );
    try std.testing.expectEqual(api.ExitStatus.success, result.exit_status);
    try std.testing.expect(result.paths.provenance != null);
    const provenance = try readFile(
        std.testing.allocator,
        std.testing.io,
        result.paths.provenance.?,
        transaction_provenance_v3.maximum_document_bytes,
    );
    defer std.testing.allocator.free(provenance);
    try std.testing.expect(std.mem.indexOf(
        u8,
        provenance,
        "\"outcome\":\"succeeded\"",
    ) != null);
    const attempt_hex = std.fmt.bytesToHex(evidence.attempt_id, .lower);
    const attempt_field = try std.fmt.allocPrint(
        std.testing.allocator,
        "\"attempt_sha256\":\"{s}\"",
        .{&attempt_hex},
    );
    defer std.testing.allocator.free(attempt_field);
    try std.testing.expect(std.mem.indexOf(
        u8,
        provenance,
        attempt_field,
    ) != null);
    try std.testing.expectError(
        error.FileNotFound,
        readRecoveryIntent(
            std.testing.allocator,
            std.testing.io,
            active_state_path,
        ),
    );
}

test "identical system operations use distinct attempt journals" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.createDirPath(std.testing.io, "state");
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(std.testing.io, &real);
    const install_root = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/root",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(install_root);
    const state_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(state_path);
    const request: api.Request = .{
        .operation = .remove,
        .packages = &.{"demo"},
        .options = .{
            .install_root = install_root,
            .cache_path = "/cache",
            .state_path = state_path,
            .architecture = "amd64",
            .assume_yes = true,
            .noninteractive = true,
            .conffile = .keep_existing,
        },
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var actions = [_]solver.PlanAction{.{
        .kind = .remove,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .repository = null,
        .sha256 = null,
        .package_size = null,
        .installed_size_delta_bytes = -1,
        .source_package = "demo",
        .prior_installed = null,
        .requested = true,
        .reason = .explicit_request,
        .selected_origin = null,
        .selected_origin_v2 = null,
        .origin = null,
    }};
    var ordered = [_]solver.OrderedAction{.{
        .sequence = 0,
        .kind = .remove,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
    }};
    const plan: solver.Plan = .{
        .schema_version = 3,
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = &actions,
        .ordered_actions = &ordered,
        .summary = .{ .removals = 1 },
        .download_bytes = 0,
        .installed_size_delta_bytes = -1,
        .backing_allocator = std.testing.allocator,
        .arena = &arena,
    };
    const policy = try executionPolicy(
        std.testing.allocator,
        request,
        true,
    );
    defer std.testing.allocator.free(policy.risk.force);
    const action = system_operation_lock.Action{
        .kind = .remove,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
    };
    var first_lock = try system_operation_lock.create(
        std.testing.allocator,
        .{
            .attempt_id = @splat(0x11),
            .operation = .remove,
            .install_root = install_root,
            .state_path = state_path,
            .target_architecture = "amd64",
            .request_sha256 = systemRequestDigest(request),
            .solver_policy_sha256 = systemSolverPolicyDigest(request),
            .executor_policy_sha256 = transaction_executor.policyDigest(
                policy,
            ),
            .plan_sha256 = transaction_executor.planDigest(plan),
            .package_lock_kind = .none,
            .package_lock_sha256 = null,
            .actions = &.{action},
            .repository_refresh = &.{},
        },
    );
    defer first_lock.deinit();
    const first = try prepareSystemTransactionEvidence(
        std.testing.allocator,
        std.testing.io,
        first_lock.lock,
        plan,
        null,
        null,
    );
    defer freeTransactionEvidence(std.testing.allocator, first);
    var first_dir = try openAbsoluteDirectory(
        std.testing.io,
        first.directory_path,
    );
    defer first_dir.close(std.testing.io);
    try first_dir.writeFile(std.testing.io, .{
        .sub_path = "transaction.complete",
        .data = "old completed journal",
    });

    var second_lock = try system_operation_lock.create(
        std.testing.allocator,
        .{
            .attempt_id = @splat(0x22),
            .operation = .remove,
            .install_root = install_root,
            .state_path = state_path,
            .target_architecture = "amd64",
            .request_sha256 = systemRequestDigest(request),
            .solver_policy_sha256 = systemSolverPolicyDigest(request),
            .executor_policy_sha256 = transaction_executor.policyDigest(
                policy,
            ),
            .plan_sha256 = transaction_executor.planDigest(plan),
            .package_lock_kind = .none,
            .package_lock_sha256 = null,
            .actions = &.{action},
            .repository_refresh = &.{},
        },
    );
    defer second_lock.deinit();
    const second = try prepareSystemTransactionEvidence(
        std.testing.allocator,
        std.testing.io,
        second_lock.lock,
        plan,
        null,
        null,
    );
    defer freeTransactionEvidence(std.testing.allocator, second);
    try std.testing.expect(!std.mem.eql(
        u8,
        first.directory_path,
        second.directory_path,
    ));
    var second_journal = try transaction_recovery.SystemJournalStore.init(
        std.testing.io,
        second.directory_path,
        install_root,
    );
    defer second_journal.deinit();
    const existing = try second_journal.interface().load(
        std.testing.allocator,
        install_root,
    );
    try std.testing.expect(existing == null);
}

test "retained freshness evidence publishes successful recovery provenance" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "state");
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(std.testing.io, &real);
    const output_path = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/state/transaction-result-v3.json",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(output_path);
    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(7);
    var lock = try exact_lock_v2.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .policy_sha256 = @splat(2),
        .repositories = &.{.{
            .id = repository_id,
            .snapshot_sha256 = snapshot,
            .release_sha256 = @splat(8),
            .index_sha256 = @splat(9),
            .signer_fingerprints = &.{@splat(10)},
        }},
        .local_artifacts = &.{},
        .packages = &.{.{
            .name = "demo",
            .version = "1",
            .architecture = "amd64",
            .origin = .{ .authenticated_repository = .{
                .repository_id = repository_id,
                .repository_snapshot_sha256 = snapshot,
            } },
            .sha256 = @splat(11),
            .declared_size = 1,
            .retention = .requested,
            .dpkg_selection_hold = false,
        }},
        .verified_origins = true,
    });
    defer lock.deinit();
    const refresh = transaction_provenance_v3.RepositoryRefreshEvidence{
        .source_config_id = repository_id,
        .snapshot_sha256 = snapshot,
        .signed_release_date_unix = 1_000,
        .valid_until_unix = null,
        .verification_time_unix = 1_050,
        .maximum_future_seconds = 300,
        .future_date_accepted = false,
        .observed_release_age_seconds = 50,
        .expiry_policy = .{
            .allow_missing_valid_until_with_max_age_seconds = 100,
        },
        .maximum_release_age_seconds = 100,
        .missing_valid_until_exception_exercised = true,
        .selected_packages_path = "main/binary-amd64/Packages.gz",
        .compression = .gzip,
    };
    var operation_lock = try system_operation_lock.create(
        std.testing.allocator,
        .{
            .attempt_id = @splat(0xaa),
            .operation = .install,
            .install_root = "/root",
            .state_path = "/state",
            .target_architecture = "amd64",
            .request_sha256 = lock.lock.request_sha256,
            .solver_policy_sha256 = lock.lock.policy_sha256,
            .executor_policy_sha256 = @splat(3),
            .plan_sha256 = @splat(4),
            .package_lock_kind = .exact_v2,
            .package_lock_sha256 = lock.lock.digest_sha256,
            .actions = &.{.{
                .kind = .install,
                .package = "demo",
                .version = "1",
                .architecture = "amd64",
            }},
            .repository_refresh = &.{refresh},
        },
    );
    defer operation_lock.deinit();
    const request: api.Request = .{
        .operation = .install,
        .packages = &.{"demo"},
        .options = .{
            .install_root = "/root",
            .cache_path = "/cache",
            .state_path = "/state",
            .architecture = "amd64",
        },
    };
    var status = FixedStatusReader{
        .bytes = "Package: demo\n" ++
            "Status: install ok installed\n" ++
            "Architecture: amd64\n" ++
            "Version: 1\n",
    };
    const failed_report: transaction_executor.RecoveryReport = .{
        .allocator = std.testing.allocator,
        .arena = undefined,
        .state = .interrupted,
        .commands = &.{},
        .plan_sha256 = operation_lock.lock.plan_sha256,
        .root_identity = transaction_recovery.rootIdentity("/root"),
        .policy_sha256 = operation_lock.lock.executor_policy_sha256,
        .lock_sha256 = lock.lock.digest_sha256,
        .failure = .{
            .code = .recovery_failed,
            .diagnostic = "first recovery failed",
        },
    };
    try writeRetainedRecoveryProvenanceV2(
        std.testing.allocator,
        std.testing.io,
        request,
        operation_lock.lock,
        lock.lock,
        failed_report,
        status.interface(),
        output_path,
    );
    const failed_bytes = try readFile(
        std.testing.allocator,
        std.testing.io,
        output_path,
        transaction_provenance_v3.maximum_document_bytes,
    );
    defer std.testing.allocator.free(failed_bytes);
    try std.testing.expect(std.mem.indexOf(
        u8,
        failed_bytes,
        "\"outcome\":\"recovery_required\"",
    ) != null);

    const succeeded_report: transaction_executor.RecoveryReport = .{
        .allocator = std.testing.allocator,
        .arena = undefined,
        .state = .complete,
        .commands = &.{},
        .plan_sha256 = operation_lock.lock.plan_sha256,
        .root_identity = transaction_recovery.rootIdentity("/root"),
        .policy_sha256 = operation_lock.lock.executor_policy_sha256,
        .lock_sha256 = lock.lock.digest_sha256,
        .failure = null,
    };
    try writeRetainedRecoveryProvenanceV2(
        std.testing.allocator,
        std.testing.io,
        request,
        operation_lock.lock,
        lock.lock,
        succeeded_report,
        status.interface(),
        output_path,
    );
    const succeeded_bytes = try readFile(
        std.testing.allocator,
        std.testing.io,
        output_path,
        transaction_provenance_v3.maximum_document_bytes,
    );
    defer std.testing.allocator.free(succeeded_bytes);
    try std.testing.expect(std.mem.indexOf(
        u8,
        succeeded_bytes,
        "\"outcome\":\"succeeded\"",
    ) != null);
    var validated = try transaction_provenance_v3.validateDocument(
        std.testing.allocator,
        succeeded_bytes,
        transaction_provenance_v3.maximum_document_bytes,
    );
    validated.deinit();

    var state_dir = try directory.dir.openDir(
        std.testing.io,
        "state",
        .{ .follow_symlinks = false },
    );
    defer state_dir.close(std.testing.io);
    try state_dir.deleteFile(
        std.testing.io,
        "transaction-result-v3.json",
    );
    try writeRetainedRecoveryProvenanceV2(
        std.testing.allocator,
        std.testing.io,
        request,
        operation_lock.lock,
        lock.lock,
        succeeded_report,
        status.interface(),
        output_path,
    );
    try state_dir.access(
        std.testing.io,
        "transaction-result-v3.json",
        .{},
    );
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
        @ptrCast(&context),
        try repository_acquisition.Uri.parse("https://REPO.example/other"),
    )) != null);
    try std.testing.expect((try CredentialContext.get(
        @ptrCast(&context),
        try repository_acquisition.Uri.parse("https://attacker.example/debian"),
    )) == null);
    try std.testing.expect((try CredentialContext.get(
        @ptrCast(&context),
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
