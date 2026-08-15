const std = @import("std");
const api = @import("product_api.zig");
const deb_payload = @import("deb_payload.zig");
const dpkg_status = @import("dpkg_status.zig");
const metadata_cache = @import("metadata_cache.zig");
const package_acquisition = @import("package_acquisition.zig");
const repository_acquisition = @import("repository_acquisition.zig");
const repository_policy = @import("repository_policy.zig");
const repository_refresh = @import("repository_refresh.zig");
const solver = @import("solver.zig");
const source = @import("source.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_recovery = @import("transaction_recovery.zig");
const transaction_provenance = @import("transaction_provenance.zig");
const exact_lock = @import("exact_lock.zig");
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
        return success(request.operation, false, "installed-state reasons evaluated", try items.toOwnedSlice(allocator));
    }

    fn clean(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !api.Result {
        var cache = try package_acquisition.Cache.init(self.io, request.options.cache_path, .{
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
        var metadata = try metadata_cache.Cache.init(self.io, request.options.cache_path, .{});
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

        var loaded = try self.loadRepositoryDocuments(allocator, request);
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

        var metadata = try metadata_cache.Cache.init(self.io, request.options.cache_path, .{});
        defer metadata.deinit();
        var acquisition = repository_acquisition.Production{ .io = self.io };
        const credential_bytes: ?[]u8 = if (request.options.credential_reference) |path|
            try readCredential(allocator, self.io, path)
        else
            null;
        defer if (credential_bytes) |value| allocator.free(value);
        var credential_context = CredentialContext{ .authorization = credential_bytes orelse "" };
        const credentials: repository_acquisition.CredentialsProvider = if (credential_bytes != null)
            .{ .context = &credential_context, .getFn = CredentialContext.get }
        else
            .none;
        var now = self.now_unix orelse realNow(self.io);
        const runtimes = try makeRuntimes(allocator, request, &configuration, now, credentials);
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
        const policies = try installedPolicies(allocator, installed.database.packages);
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
        if (request.options.lock_output_path != null and request.options.lock_input_path == null)
            return api.failure(request.operation, .usage, .configuration_required, "--lock-output requires --lock-input for an exact authenticated closure");
        var lock: ?exact_lock.OwnedLock = if (request.options.lock_input_path) |path|
            try readLock(allocator, self.io, path)
        else
            null;
        defer if (lock) |*value| value.deinit();
        if (request.options.lock_output_path) |path|
            try writeLock(allocator, self.io, path, lock.?.lock);
        var planning = try solver.planTransaction(allocator, .{
            .repositories = refreshed.universe.repositories,
            .installed = .{
                .records = installed.database.packages,
                .native_architecture = request.options.architecture,
                .policies = policies,
                .hold_authority = .explicit_policy,
            },
            .target_architecture = request.options.architecture,
            .mode = if (effective_request.operation == .download) .download_only else .plan_only,
            .request = try planRequest(allocator, effective_request),
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
        if (request.operation == .plan) return planResult(allocator, request.operation, plan.*);

        var package_cache = try package_acquisition.Cache.init(self.io, request.options.cache_path, .{
            .maximum_object_bytes = 1024 * 1024 * 1024,
        });
        defer package_cache.deinit();
        var artifacts: std.ArrayList(transaction_executor.Artifact) = .empty;
        var verified: std.ArrayList(package_acquisition.VerifiedPackage) = .empty;
        defer {
            for (verified.items) |*package| package.deinit();
            verified.deinit(allocator);
        }
        for (plan.actions) |action| {
            const origin = action.selected_origin orelse continue;
            const repository_input = findRepositoryInput(refreshed.universe.repositories, origin.repository_id) orelse
                return error.MissingRepository;
            const normalized_repository = findNormalized(configuration.repositories, origin.repository_id) orelse
                return error.MissingRepository;
            var package = try package_acquisition.acquirePackage(
                allocator,
                &package_cache,
                .{
                    .selected = try package_acquisition.SelectedPackage.fromSolverSelection(
                        repository_input,
                        origin,
                        try repository_acquisition.Uri.parse(normalized_repository.uri),
                    ),
                    .policy = .{
                        .mode = if (request.options.offline or request.options.cache_only) .cache_only else .online,
                        .workflow = if (request.operation == .download) .download_only else .transaction,
                        .maximum_package_bytes = 1024 * 1024 * 1024,
                        .deadlines = deadlines(request.options.deadline_ms),
                        .redirect_limit = 8,
                        .proxy = try proxyPolicy(request.options.proxy),
                        .credentials = credentials,
                    },
                    .exact_lock_package = if (lock) |*value|
                        value.lock.findPackage(action.package, action.version, action.architecture)
                    else
                        null,
                },
                acquisition.dependencies(),
            );
            var validation_result = deb_payload.validate(allocator, package.bytes, .{
                .repository = origin.repository_id.slice(),
                .package = action.package,
                .version = action.version,
                .architecture = action.architecture,
                .requested_package = action.package,
                .requested_version = action.version,
                .requested_architecture = action.architecture,
                .filename = origin.source_location,
                .size = package.provenance.declared_size,
                .sha256 = package.provenance.expected_sha256.bytes,
            }, .{});
            switch (validation_result) {
                .diagnostic => {
                    package.deinit();
                    return error.InvalidPackagePayload;
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
            return planResult(allocator, request.operation, plan.*);

        const executor_policy = try executionPolicy(allocator, effective_request);
        var system_process = transaction_executor.SystemProcessRunner{ .allocator = allocator, .io = self.io };
        defer system_process.deinit();
        var system_files = transaction_executor.SystemFileSystem{ .io = self.io };
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
        var explicit_status = ExplicitStatusReader{
            .io = self.io,
            .expected_root = request.options.install_root,
            .path = request.options.status_path orelse "",
        };
        const dependencies: transaction_executor.Dependencies = .{
            .filesystem = system_files.interface(),
            .locks = system_locks.interface(),
            .process = self.process_runner orelse system_process.interface(),
            .journal = journal.interface(),
            .status = if (request.options.status_path != null)
                explicit_status.interface()
            else
                status_reader.interface(),
        };
        if (request.operation == .recover) {
            var report = try self.executor.recoverFn(self.executor.context, allocator, .{
                .plan = plan,
                .install_root = request.options.install_root,
                .policy = executor_policy,
                .exact_lock = if (lock) |*value| &value.lock else null,
            }, dependencies);
            defer report.deinit();
            if (!report.succeeded())
                return api.failure(request.operation, .recovery, .recovery_failed, if (report.failure) |failure|
                    try allocator.dupe(u8, failure.diagnostic)
                else
                    "recovery failed");
            return success(request.operation, true, "transaction recovery completed", &.{});
        }
        try writeRecoveryIntent(allocator, self.io, request.options.state_path, effective_request);
        var report = try self.executor.executeFn(self.executor.context, allocator, .{
            .plan = plan,
            .install_root = request.options.install_root,
            .artifacts = artifacts.items,
            .policy = executor_policy,
            .exact_lock = if (lock) |*value| &value.lock else null,
        }, dependencies);
        defer report.deinit();
        if (!report.succeeded())
            return api.failure(request.operation, .transaction, .transaction_failed, if (report.failure) |failure|
                try allocator.dupe(u8, failure.diagnostic)
            else
                "transaction failed");
        if (lock) |*value| try writeExecutionProvenance(
            allocator,
            self.io,
            request,
            refreshed,
            value.lock,
            report,
            dependencies.status,
        );
        return planResultChanged(allocator, request.operation, plan.*, true, "transaction completed");
    }

    fn loadInstalled(self: *Backend, allocator: std.mem.Allocator, request: api.Request) !dpkg_status.OwnedDatabase {
        const path = if (request.options.status_path) |value|
            value
        else
            try std.fmt.allocPrint(allocator, "{s}/var/lib/dpkg/status", .{request.options.install_root});
        const parsed = try dpkg_status.parseFile(allocator, self.io, path, .{});
        return switch (parsed) {
            .diagnostic => |diagnostic| {
                _ = diagnostic;
                return error.InvalidInstalledState;
            },
            .database => |database| database,
        };
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

    fn get(context: ?*anyopaque, _: repository_acquisition.Uri) !?repository_acquisition.Credential {
        const self: *CredentialContext = @ptrCast(@alignCast(context.?));
        return .{ .authorization = self.authorization };
    }
};

const ExplicitStatusReader = struct {
    io: std.Io,
    expected_root: []const u8,
    path: []const u8,

    fn interface(self: *ExplicitStatusReader) transaction_recovery.StatusReader {
        return .{ .context = self, .readFn = read };
    }

    fn read(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        root: []const u8,
        maximum: usize,
    ) ![]u8 {
        const self: *ExplicitStatusReader = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, root, self.expected_root)) return error.WrongInstallRoot;
        return readFile(allocator, self.io, self.path, maximum);
    }
};

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
    var dir = try std.Io.Dir.openDirAbsolute(io, state_path, .{ .follow_symlinks = false });
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
    switch (@import("builtin").os.tag) {
        .windows, .wasi => {},
        else => try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io),
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
    now_unix: i64,
    credentials: repository_acquisition.CredentialsProvider,
) ![]repository_policy.Runtime {
    var runtimes = try allocator.alloc(repository_policy.Runtime, configuration.repositories.len);
    for (configuration.repositories, 0..) |repository, index| {
        var keyrings = try allocator.alloc(openpgp.Keyring, repository.signed_by.len);
        for (repository.signed_by, 0..) |path, key_index| keyrings[key_index] = .{ .path = path };
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
                .proxy = try proxyPolicy(request.options.proxy),
                .deadlines = deadlines(request.options.deadline_ms),
                .redirect_limit = 8,
                .credentials = credentials,
                .maximum_release_bytes = 16 * 1024 * 1024,
            },
            .refresh = .{
                .mode = if (request.options.offline) .cache_only else .online,
                .compression_order = &.{ .xz, .gzip, .zstd, .uncompressed },
                .by_hash_fallback = .not_found_only,
                .maximum_future_seconds = 300,
                .expiry_policy = .require_valid_until,
                .maximum_compressed_bytes = 64 * 1024 * 1024,
                .maximum_decompressed_bytes = 256 * 1024 * 1024,
                .maximum_decoder_memory = 256 * 1024 * 1024,
            },
        };
    }
    return runtimes;
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
    return success(request.operation, false, "authenticated repository view queried", try items.toOwnedSlice(allocator));
}

fn recordProvides(record: anytype, requested: []const []const u8) bool {
    for (requested) |name| {
        if (std.mem.eql(u8, record.control.package.text, selectorName(name))) return true;
        if (record.control.provides) |relation| {
            if (std.mem.indexOf(u8, relation.source, selectorName(name)) != null) return true;
        }
    }
    return false;
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

fn planRequest(allocator: std.mem.Allocator, request: api.Request) !solver.PlanRequest {
    const selectors = try allocator.alloc(solver.PackageSelector, request.packages.len);
    for (request.packages, 0..) |value, index| selectors[index] = parseSelector(value);
    return switch (request.operation) {
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

fn deadlines(overall: u64) repository_acquisition.Deadlines {
    return .{
        .connect_ms = @min(overall, 10_000),
        .read_ms = @min(overall, 30_000),
        .overall_ms = overall,
    };
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
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
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

fn writeLock(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    lock: exact_lock.Lock,
) !void {
    const parent = std.fs.path.dirname(path) orelse return error.InvalidAbsolutePath;
    const leaf = std.fs.path.basename(path);
    var dir = try std.Io.Dir.openDirAbsolute(io, parent, .{ .follow_symlinks = false });
    defer dir.close(io);
    const store = try exact_lock.Store.init(io, dir, leaf);
    try store.writeAtomic(allocator, lock);
}

fn writeExecutionProvenance(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: api.Request,
    refreshed: *repository_policy.RefreshResult,
    lock: exact_lock.Lock,
    report: transaction_executor.Report,
    status: transaction_recovery.StatusReader,
) !void {
    var repositories = try allocator.alloc(transaction_provenance.RepositoryEvidence, refreshed.snapshots.len);
    for (refreshed.snapshots, 0..) |snapshot, index| {
        const evidence = snapshot.snapshot.provenance.authentication_evidence;
        const signers = try allocator.alloc([20]u8, evidence.signatures.len);
        var signer_count: usize = 0;
        for (evidence.signatures) |signature| if (signature.primary_fingerprint) |fingerprint| {
            signers[signer_count] = fingerprint;
            signer_count += 1;
        };
        var source_id: [64]u8 = undefined;
        @memcpy(&source_id, snapshot.snapshot.provenance.repository_id.slice());
        repositories[index] = .{
            .source_config_id = source_id,
            .snapshot_sha256 = repository_refresh.snapshotDigest(&snapshot),
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
    var dir = try std.Io.Dir.openDirAbsolute(io, request.options.state_path, .{ .follow_symlinks = false });
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

fn mapRuntimeError(operation: api.Operation, err: anyerror) api.Result {
    return switch (err) {
        error.FileNotFound, error.InvalidRepositoryConfig, error.InvalidInstalledState,
        error.CredentialBearingProxy, error.InvalidCredentialFile, error.InvalidAbsolutePath,
        => api.failure(operation, .usage, .configuration_required, @errorName(err)),
        error.CacheMiss, error.CorruptObject => api.failure(operation, .download, .offline_cache_miss, @errorName(err)),
        error.NoValidAcceptedSignature, error.WrongSigningKey, error.InvalidSignature,
        error.MalformedKeyring, error.NoKeyrings,
        => api.failure(operation, .authentication, .repository_authentication_failed, @errorName(err)),
        error.PackageTooLarge, error.SizeMismatch, error.DigestMismatch =>
        api.failure(operation, .download, .download_failed, @errorName(err)),
        error.InvalidPackagePayload =>
        api.failure(operation, .download, .download_failed, @errorName(err)),
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
    var intent = try directory.dir.openFile(std.testing.io, "state/recovery-request.json", .{});
    intent.close(std.testing.io);
}
