const std = @import("std");
const absolute_path = @import("absolute_path.zig");
const api = @import("repository_api.zig");
const state_module = @import("repository_state.zig");
const local_artifact = @import("local_artifact.zig");
const deb_payload = @import("deb_payload.zig");
const dpkg_status = @import("dpkg_status.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const metadata_cache = @import("metadata_cache.zig");
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
const manifest_name = "apt-config-snapshot-v1.json";

pub const Executor = transaction_engine.Executor;

pub const Backend = struct {
    io: std.Io,
    transaction_backend: transaction_engine.Kind = .legacy_dpkg,
    executor: Executor = .legacy_dpkg,
    native_executor: ?Executor = null,
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
        return self.executeAdd(allocator, request) catch |err|
            api.failure(.internal, .internal_error, "internal", @errorName(err));
    }

    fn executeAdd(
        self: *Backend,
        allocator: std.mem.Allocator,
        request: api.Request,
    ) !api.Result {
        const executor = transaction_engine.select(
            self.transaction_backend,
            self.executor,
            self.native_executor,
        ) catch return api.failure(
            .unavailable,
            .transaction_backend_unavailable,
            "transaction",
            "selected transaction backend is unavailable",
        );
        var paths = try ResolvedPaths.init(allocator, request);
        defer paths.deinit();

        // Rank 0 of the total lock order. Repository bootstrap shares the
        // root's operation namespace with package transactions, so neither can
        // start while the other holds an unresolved attempt. The transaction
        // backend was already selected above, so an unavailable native
        // selection still fails before any root access.
        var guard: RootOperationGuard = .{ .io = self.io, .allocator = allocator };
        defer guard.deinit();
        if (guard.open(request, self.transaction_backend, self.now_unix)) |failure| return failure;

        var production_acquisition = repository_acquisition.Production{ .io = self.io };
        const acquisition_dependencies = self.acquisition_dependencies orelse
            production_acquisition.dependencies();
        var budget = OperationBudget.init(
            acquisition_dependencies.clock,
            request.resources,
            request.network.overall_timeout_ms,
            allocator,
        );

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
        state_store.write_hooks = self.state_write_hooks;

        var prior_state: ?state_module.OwnedState = state_store.read(
            allocator,
            request.state.maximum_operation_state_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return api.failure(.recovery, .state_corrupt, "state", @errorName(err)),
        };
        defer if (prior_state) |*value| value.deinit();

        var target_files = target_apt_config.ProductionFileSystem.init(self.io, request.root) catch
            return api.failure(.usage, .invalid_root, "target", "target root is unsafe or unavailable");
        defer target_files.deinit();
        var architecture_process = target_apt_config.SystemProcessRunner{ .io = self.io };
        var before_snapshot = target_apt_config.snapshot(allocator, .{
            .root_path = request.root,
            .architecture_override = request.architecture,
            .limits = targetLimits(request.resources),
            .dependencies = .{
                .filesystem = target_files.interface(),
                .process = architecture_process.interface(),
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
        if (guard.preflight(architecture)) |failure| return failure;
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
        };
        if (prior_state) |*prior| {
            progress.durable_phase = prior.state.phase;
            progress.acquired = if (phaseAtLeast(prior.state.phase, .acquired))
                .complete
            else
                .pending;
            progress.validated = if (phaseAtLeast(prior.state.phase, .validated))
                .complete
            else
                .pending;
            progress.authenticated = if (phaseAtLeast(
                prior.state.phase,
                .preflight_authenticated,
            ))
                .complete
            else
                .pending;
            progress.planned = if (phaseAtLeast(prior.state.phase, .planned))
                .complete
            else
                .pending;
            if (prior.state.descriptor) |value| progress.descriptor = .{
                .package = value.package,
                .version = value.version,
                .architecture = value.architecture,
                .sha256 = value.sha256,
                .size = value.size,
                .effective_url = value.effective_url,
                .trust_mode = value.trust_mode,
            };
            progress.managed_files = prior.state.managed_files;
            progress.plan_path = prior.state.plan_path;
            progress.plan_sha256 = prior.state.plan_sha256;
            progress.exact_lock_path = prior.state.exact_lock_path;
            progress.provenance_path = prior.state.provenance_path;
            progress.manifest_path = prior.state.manifest_path;
            progress.diagnostic_id = prior.state.diagnostic_id;
            progress.diagnostic = prior.state.diagnostic;
            if (prior.state.installed) {
                progress.installed = true;
                progress.installed_phase = .complete;
                progress.imported = if (phaseAtLeast(prior.state.phase, .imported))
                    .complete
                else
                    .pending;
                progress.refreshed = prior.state.refreshed;
                progress.refreshed_phase = if (prior.state.refreshed)
                    .complete
                else
                    .pending;
            }
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
        const now = self.now_unix orelse realNow(self.io);
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
                if (prior == null or
                    !std.mem.eql(u8, &prior.?.sha256, &artifact.provenance.sha256.bytes))
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
                progress.installed = true;
                progress.installed_phase = .complete;
                if (!prior_state.?.state.refreshed and
                    prior_state.?.state.phase != .complete)
                    resume_refresh = true;
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
        else blk: {
            var planning = try planDescriptor(
                allocator,
                &.{local_repository},
                installed.database.packages,
                installed_policies,
                architecture,
                validation.package,
                validation.version,
                skip_install,
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
                    skip_install,
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
        const plan_sha256 = sha256(plan_json);
        const executable_plan_sha256 = transaction_executor.planDigest(plan);
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
            plan_store.writeAtomic(allocator, plan) catch |err| return progress.fail(
                state_store,
                allocator,
                .planning,
                .lock_publication_failed,
                "plan",
                @errorName(err),
            );
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
            if (skip_install) {
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
        const persisted_lock_required = skip_install or
            if (prior_state) |*prior|
                phaseAtLeast(prior.state.phase, .locked)
            else
                false;
        const execution_policy = repositoryExecutionPolicy(request);
        if (!persisted_lock_required) {
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
        else
            createOperationLock(
                allocator,
                plan,
                local_evidence,
                dependency_published,
                request,
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
        validateLockPolicy(lock.lock) catch |err| return progress.fail(
            state_store,
            allocator,
            .recovery,
            .recovery_required,
            "lock",
            @errorName(err),
        );
        validateLockRequest(allocator, lock.lock, request, plan) catch |err|
            return progress.fail(
                state_store,
                allocator,
                .recovery,
                .recovery_required,
                "lock",
                @errorName(err),
            );
        if (!persisted_lock_required)
            lock_store.writeAtomic(allocator, lock.lock) catch |err|
                return progress.fail(
                    state_store,
                    allocator,
                    .planning,
                    .lock_publication_failed,
                    "lock",
                    @errorName(err),
                );
        var recovery_needed = incomplete_descriptor;
        if (persisted_lock_required) {
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
            if (skip_install) {
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
                recovery_report = executor.recover(
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
                report = executor.execute(allocator, .{
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
                    recovery_report = executor.recover(
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
            const commands_run = if (recovery_report) |value|
                value.commands.len != 0
            else
                report.?.commands.len != 0;
            if (guard.observe(commands_run, succeeded)) |failure| return progress.fail(
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
                .process = architecture_process.interface(),
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

    fn open(
        self: *RootOperationGuard,
        request: api.Request,
        backend: transaction_engine.Kind,
        now_unix: ?i64,
    ) ?api.Result {
        self.owned_root = root_fs.openAbsoluteRoot(self.io, request.root) catch
            return api.failure(
                .usage,
                .invalid_root,
                "target",
                "target root is unsafe or unavailable",
            );
        self.locks = .{ .allocator = self.allocator, .io = self.io };
        self.coordinator = root_operation.Coordinator.open(
            self.io,
            self.owned_root.?.root,
            request.root,
            self.locks.interface(),
        ) catch |err| return mapRootOperationError(err);
        self.coordinator.now_unix = now_unix;
        self.attempt = self.coordinator.acquire(self.allocator, .{
            .intent = .mutation,
            .existing = .reclaim_resolved,
            .backend = backend,
            .operation = .{ .repository_bootstrap = .add },
            .request_sha256 = repositoryRequestDigest(request),
            .policy_sha256 = repositoryPolicyDigest(request),
            .target_architecture = request.architecture orelse "all",
            .wait_ms = request.state.lock_wait_ms,
        }) catch |err| return mapRootOperationError(err);
        return null;
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

    fn preflight(self: *RootOperationGuard, architecture: []const u8) ?api.Result {
        _ = architecture;
        var attempt = self.active() orelse return null;
        if (attempt.record().state != .reserved) return null;
        attempt.advance(self.allocator, .{
            .state = .preflight,
            .phase = .preflight,
        }) catch |err| return mapRootOperationError(err);
        return null;
    }

    fn enterExecutor(self: *RootOperationGuard) ?api.Result {
        var attempt = self.active() orelse return null;
        if (attempt.record().state == .mutation_pending) return null;
        attempt.advance(self.allocator, .{
            .state = .mutation_pending,
            .phase = .mutation,
        }) catch |err| return mapRootOperationError(err);
        attempt.enterRank(.target_database) catch |err| return mapRootOperationError(err);
        return null;
    }

    fn exitRank(self: *RootOperationGuard, rank: root_operation.Rank) void {
        var attempt = self.active() orelse return;
        attempt.exitRank(rank);
    }

    fn observe(self: *RootOperationGuard, mutation_observed: bool, succeeded: bool) ?api.Result {
        var attempt = self.active() orelse return null;
        if (attempt.record().state == .mutation_pending) attempt.witness(
            self.allocator,
            if (mutation_observed) .mutation_observed else .proved_not_started,
        ) catch |err| return mapRootOperationError(err);
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

    fn finish(self: *RootOperationGuard, document_sha256: ?[32]u8) ?api.Result {
        var attempt = self.active() orelse return null;
        if (attempt.record().state == .completed) return null;
        if (attempt.record().state == .verifying) {
            attempt.complete(self.allocator, .succeeded) catch |err|
                return mapRootOperationError(err);
        } else if (attempt.record().state.provenPreMutation()) {
            attempt.complete(self.allocator, .abandoned_before_mutation) catch |err|
                return mapRootOperationError(err);
        } else return null;
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

    fn deinit(self: *RootOperationGuard) void {
        if (self.attempt) |*value| {
            // An attempt that is durably proven never to have mutated the root
            // is released rather than left behind. Anything at or past the
            // executor bridge stays exactly as published, so the next mutation
            // is refused until it is explicitly recovered. A failure here
            // simply leaves the pre-mutation record, which the next attempt
            // reports as an unresolved attempt.
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

fn mapRootOperationError(err: anyerror) api.Result {
    return switch (err) {
        error.LockTimeout, error.LockUnavailable, error.LockCanceled => api.failure(
            .unavailable,
            .recovery_required,
            "root-operation",
            "another debz operation holds the root mutation lock",
        ),
        error.OperationInProgress, error.ResolvedAttemptPresent => api.failure(
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
        error.InvalidRoot, error.RootTooLong, error.NamespaceUnavailable => api.failure(
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
fn repositoryRequestDigest(request: api.Request) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-repository-request-v1\x00");
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

fn repositoryPolicyDigest(request: api.Request) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-repository-policy-v1\x00");
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

    fn init(allocator: std.mem.Allocator, request: api.Request) !ResolvedPaths {
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
        const operation_id = requestOperationId(request);
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
        const provenance_logical = try joinLogical(allocator, operation_logical, provenance_name);
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

fn requestOperationId(request: api.Request) [64]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-repository-add-operation-v1\x00");
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
) ![32]u8 {
    const plan_json = try plan.canonicalJson(allocator);
    defer allocator.free(plan_json);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-repository-add-executable-request-v1\x00");
    hashField(&hash, request.root);
    hashField(&hash, request.descriptor_url);
    if (request.expected_sha256) |digest| {
        hash.update("\x01");
        hash.update(&digest);
    } else hash.update("\x00");
    hash.update(if (request.no_refresh) "\x01" else "\x00");
    hashOptionalField(&hash, request.architecture);
    hashOptionalField(&hash, request.cache.path);
    hashInt(&hash, request.cache.maximum_object_bytes);
    hashOptionalField(&hash, request.state.path);
    hashInt(&hash, request.state.lock_wait_ms);
    hashInt(&hash, request.state.maximum_operation_state_bytes);
    hashOptionalField(&hash, request.network.proxy_url);
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
    }) |value| hashInt(&hash, value);
    hashField(&hash, plan_json);
    return hash.finalResult();
}

fn validateLockRequest(
    allocator: std.mem.Allocator,
    lock: exact_lock_v2.Lock,
    request: api.Request,
    plan: solver.Plan,
) !void {
    const expected = try operationRequestDigest(allocator, request, plan);
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
        if (self.clock.nowMs() -| self.started_ms >= self.overall_timeout_ms)
            return error.ResourceBudgetExceeded;
    }

    fn remainingTime(self: OperationBudget) !u64 {
        try self.checkTime();
        const spent = self.clock.nowMs() -| self.started_ms;
        if (spent >= self.overall_timeout_ms) return error.ResourceBudgetExceeded;
        return self.overall_timeout_ms - spent;
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
            var inspected = openpgp.inspectKeyring(allocator, bytes, .{}) catch
                return error.MalformedPayloadKeyring;
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
            .expiry_policy = if (repository.immutability.kind == .moving)
                .require_valid_until
            else
                .allow_missing_valid_until,
            .maximum_compressed_bytes = network.maximum_compressed_index_bytes,
            .maximum_decompressed_bytes = network.maximum_decompressed_index_bytes,
            .maximum_decoder_memory = network.maximum_decoder_memory,
            .cache_publish_options = .{
                .reservation = budget.cacheReservation(),
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
        } } else .{ .install = .{
            .name = package,
            .version = version,
        } },
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

fn createOperationLock(
    allocator: std.mem.Allocator,
    plan: solver.Plan,
    local_evidence: @import("package_origin.zig").LocalArtifactEvidence,
    refreshed: ?*repository_policy.RefreshResult,
    request: api.Request,
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
        .request_sha256 = try operationRequestDigest(allocator, request, plan),
        .policy_sha256 = repositoryLockPolicyDigest(),
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

fn validateLockPolicy(lock: exact_lock_v2.Lock) !void {
    const expected = repositoryLockPolicyDigest();
    if (!std.mem.eql(u8, &lock.policy_sha256, &expected))
        return error.LockPolicyMismatch;
}

fn repositoryLockPolicyDigest() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-repository-add-solver-policy-v1\x00");
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

test "repository backend maps alternate-root evidence paths without host inference" {
    var paths = try ResolvedPaths.init(std.testing.allocator, .{
        .root = "/srv/roots/noble",
        .descriptor_url = "https://packages.microsoft.test/config.deb",
        .architecture = "amd64",
    });
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
    });
    defer same.deinit();
    try std.testing.expectEqualSlices(u8, &paths.operation_id, &same.operation_id);
    var distinct = try ResolvedPaths.init(std.testing.allocator, .{
        .root = "/srv/roots/noble",
        .descriptor_url = "https://packages.example.test/config.deb",
        .architecture = "amd64",
    });
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
            .kind = .regular,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .owner_name = null,
            .group_name = null,
            .size = source_bytes.len,
            .header_offset = 0,
            .content_offset = 0,
        },
        .{
            .path = @constCast("usr/share/keyrings/microsoft-prod.gpg"),
            .link_target = null,
            .kind = .regular,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .owner_name = null,
            .group_name = null,
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

    fn interface(self: *RepositoryTestExecutor) Executor {
        return .{
            .context = self,
            .executeFn = execute,
            .recoverFn = recover,
        };
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
        const interrupted = self.interrupt_first and self.calls == 1;
        const recovery_required = self.interrupt_first and self.calls > 1;
        if ((!interrupted or !self.interrupt_before_install) and !recovery_required) {
            if (interrupted and self.interrupted_status != null)
                try self.installDescriptorWithStatus(self.interrupted_status.?)
            else
                try self.installDescriptor();
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

    var original_paths = try ResolvedPaths.init(std.testing.allocator, request);
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

        var paths = try ResolvedPaths.init(std.testing.allocator, request);
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

    var paths = try ResolvedPaths.init(std.testing.allocator, request);
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

        var paths = try ResolvedPaths.init(std.testing.allocator, request);
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

        var paths = try ResolvedPaths.init(std.testing.allocator, request);
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
    const refreshed_id = requestOperationId(base);
    const no_refresh_id = requestOperationId(no_refresh);
    try std.testing.expect(!std.mem.eql(u8, &refreshed_id, &no_refresh_id));
    try std.testing.expect(!std.mem.eql(
        u8,
        &requestOperationId(no_refresh),
        &requestOperationId(base),
    ));
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
