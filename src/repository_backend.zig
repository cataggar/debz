const std = @import("std");
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
const repository_refresh = @import("repository_refresh.zig");
const solver = @import("solver.zig");
const source = @import("source.zig");
const target_apt_config = @import("target_apt_config.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_provenance_v2 = @import("transaction_provenance_v2.zig");
const transaction_recovery = @import("transaction_recovery.zig");

const operation_directory_name = "repository";
const operations_directory_name = "operations";
const operation_state_name = "repo-add-state-v1.json";
const operation_lock_name = "repo-add.lock";
const exact_lock_name = "exact-lock-v2.json";
const provenance_name = "transaction-result-v2.json";
const manifest_name = "apt-config-snapshot-v1.json";

pub const Executor = struct {
    context: *anyopaque,
    executeFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        transaction_executor.Request,
        transaction_executor.Dependencies,
    ) anyerror!transaction_executor.Report,

    pub const system: Executor = .{
        .context = @ptrCast(@constCast(&system_executor_context)),
        .executeFn = systemExecute,
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

pub const Backend = struct {
    io: std.Io,
    executor: Executor = .system,
    process_runner: ?transaction_executor.ProcessRunner = null,
    acquisition_dependencies: ?repository_acquisition.Dependencies = null,
    now_unix: ?i64 = null,

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
        var paths = try ResolvedPaths.init(allocator, request);
        defer paths.deinit();

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
        const operation_locks = operation_lock_manager.interface();
        const operation_lock = operation_locks.acquire(
            operation_lock_path,
            request.state.lock_wait_ms,
        ) catch |err| return api.failure(
            .recovery,
            .recovery_required,
            "state",
            @errorName(err),
        );
        defer operation_locks.release(operation_lock);
        var operation_dir = openOrCreateAbsoluteDirectory(self.io, paths.operation_physical) catch
            return api.failure(.usage, .invalid_root, "paths", "repository operation path is unsafe or unavailable");
        defer operation_dir.close(self.io);
        const state_store = try state_module.Store.init(self.io, operation_dir, operation_state_name);

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
        if (prior_state) |*prior| {
            if (!std.mem.eql(u8, prior.state.root, request.root) or
                !std.mem.eql(u8, prior.state.architecture, architecture))
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
            progress.exact_lock_path = prior.state.exact_lock_path;
            progress.provenance_path = prior.state.provenance_path;
            progress.manifest_path = prior.state.manifest_path;
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
            try progress.persist(
                state_store,
                allocator,
                .initialized,
                null,
                &.{},
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
        var production_acquisition = repository_acquisition.Production{ .io = self.io };
        const acquisition_dependencies = self.acquisition_dependencies orelse
            production_acquisition.dependencies();
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
            .expected_sha256 = if (request.expected_sha256) |digest|
                .{ .bytes = digest }
            else
                null,
            .policy = .{
                .maximum_artifact_bytes = request.network.maximum_descriptor_bytes,
                .proxy = proxyPolicy(request.network.proxy_url) catch
                    return progress.fail(
                        state_store,
                        allocator,
                        .usage,
                        .invalid_request,
                        "acquire",
                        "proxy policy is invalid",
                    ),
                .deadlines = deadlines(request.network),
                .redirect_limit = request.network.redirect_limit,
                .retry = retryPolicy(request.network),
            },
        }, acquisition_dependencies) catch |err| return progress.fail(
            state_store,
            allocator,
            .download,
            .acquisition_failed,
            "acquire",
            @errorName(err),
        );
        defer artifact.deinit();
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
        try progress.persist(state_store, allocator, .acquired, null, &.{});

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
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            .usage,
            switch (err) {
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
        const resume_refresh = if (prior_state) |*prior|
            prior.state.installed and
                !prior.state.refreshed and
                prior.state.phase == .imported
        else
            false;
        const repository_material_changed = !snapshotContainsManagedMaterial(
            before_snapshot,
            material.evidence,
        );
        try progress.persist(
            state_store,
            allocator,
            .validated,
            descriptor,
            material.evidence,
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
        var descriptor_refresh = refreshDescriptor(
            allocator,
            &material,
            &material.configuration,
            &metadata,
            acquisition_dependencies,
            request.network,
            now,
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            .authentication,
            .repository_authentication_failed,
            "preflight",
            @errorName(err),
        );
        defer descriptor_refresh.deinit(allocator);
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
            .published => {},
        }
        progress.authenticated = .complete;
        try progress.persist(
            state_store,
            allocator,
            .preflight_authenticated,
            descriptor,
            material.evidence,
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
        if (existing) |package| {
            if (!package.status.isFullyInstalled())
                return progress.fail(
                    state_store,
                    allocator,
                    .recovery,
                    .existing_descriptor_conflict,
                    "conflict",
                    "descriptor package is present in an incomplete dpkg state",
                );
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
            const durable = &prior_state.?.state;
            if (durable.provenance_path == null or
                !std.mem.eql(u8, durable.provenance_path.?, paths.provenance_logical))
                return progress.fail(
                    state_store,
                    allocator,
                    .recovery,
                    .recovery_required,
                    "resume",
                    "installed repository state has no matching transaction provenance",
                );
            validateRecoveryEvidence(
                allocator,
                self.io,
                operation_dir,
                descriptor,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                .recovery,
                .recovery_required,
                "resume",
                @errorName(err),
            );
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
        var planning = try planDescriptor(
            allocator,
            &.{local_repository},
            installed.database.packages,
            installed_policies,
            architecture,
            validation.package,
            validation.version,
            skip_install,
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
                now,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                .authentication,
                .dependency_refresh_failed,
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
                .published => |*value| value,
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
            );
        }
        var plan = switch (planning) {
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
        defer plan.deinit();
        progress.planned = .complete;
        try progress.persist(
            state_store,
            allocator,
            .planned,
            descriptor,
            material.evidence,
        );

        const dependency_published: ?*repository_policy.RefreshResult =
            if (dependency_refresh) |*outcome| switch (outcome.*) {
                .published => |*value| value,
                .failed => null,
            } else null;
        const lock_store = try exact_lock_v2.Store.init(
            self.io,
            operation_dir,
            exact_lock_name,
        );
        var lock = if (skip_install)
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
                request.no_refresh,
            ) catch |err| return progress.fail(
                state_store,
                allocator,
                .planning,
                .lock_publication_failed,
                "lock",
                @errorName(err),
            );
        defer lock.deinit();
        if (!skip_install)
            lock_store.writeAtomic(allocator, lock.lock) catch |err|
                return progress.fail(
                    state_store,
                    allocator,
                    .planning,
                    .lock_publication_failed,
                    "lock",
                    @errorName(err),
                );
        progress.exact_lock_path = paths.exact_lock_logical;
        try progress.persist(
            state_store,
            allocator,
            .locked,
            descriptor,
            material.evidence,
        );

        var artifacts: std.ArrayList(transaction_executor.Artifact) = .empty;
        defer {
            for (artifacts.items) |item| allocator.free(item.path);
            artifacts.deinit(allocator);
        }
        var verified_dependencies: std.ArrayList(package_acquisition.VerifiedPackage) = .empty;
        defer {
            for (verified_dependencies.items) |*item| item.deinit();
            verified_dependencies.deinit(allocator);
        }
        acquirePlanArtifacts(
            allocator,
            request,
            paths.cache_physical,
            &package_cache,
            acquisition_dependencies,
            plan,
            dependency_published,
            &before_snapshot.configuration,
            &artifacts,
            &verified_dependencies,
        ) catch |err| return progress.fail(
            state_store,
            allocator,
            .download,
            .dependency_acquisition_failed,
            "dependency-acquire",
            @errorName(err),
        );

        var report: ?transaction_executor.Report = null;
        defer if (report) |*value| value.deinit();
        if (!skip_install) {
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
                .status = status_reader.interface(),
            };
            report = self.executor.executeFn(self.executor.context, allocator, .{
                .plan = &plan,
                .install_root = request.root,
                .artifacts = artifacts.items,
                .policy = repositoryExecutionPolicy(request),
            }, dependencies) catch |err| return progress.fail(
                state_store,
                allocator,
                .transaction,
                .transaction_failed,
                "install",
                @errorName(err),
            );
            if (!report.?.succeeded()) {
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
                    "install",
                    if (report.?.failure) |failure|
                        failure.diagnostic
                    else
                        "dpkg transaction failed",
                );
            }
            progress.changed = true;
            progress.installed = true;
            progress.installed_phase = .complete;

            publishProvenance(
                allocator,
                self.io,
                operation_dir,
                request.root,
                &lock.lock,
                plan,
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
            try progress.persist(
                state_store,
                allocator,
                .installed,
                descriptor,
                material.evidence,
            );
        } else {
            progress.provenance_path = prior_state.?.state.provenance_path;
        }

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
        const manifest_store = try target_apt_config.Store.init(
            self.io,
            operation_dir,
            manifest_name,
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
        try progress.persist(
            state_store,
            allocator,
            .imported,
            descriptor,
            material.evidence,
        );

        if (request.no_refresh) {
            progress.refreshed = false;
            progress.refreshed_phase = .skipped;
        } else if (!progress.refreshed and
            (resume_refresh or repository_material_changed))
        {
            var changed_configuration: ?repository_policy.Configuration = null;
            defer if (changed_configuration) |*value| value.deinit();
            if (!resume_refresh) changed_configuration = try changedDescriptorConfiguration(
                allocator,
                &material,
                before_snapshot,
                architecture,
                request.network,
            );
            const refresh_configuration: ?*const repository_policy.Configuration =
                if (resume_refresh)
                    &material.configuration
                else if (changed_configuration) |*value|
                    value
                else
                    null;
            if (refresh_configuration) |configuration| {
                var final_refresh = try refreshDescriptor(
                    allocator,
                    &material,
                    configuration,
                    &metadata,
                    acquisition_dependencies,
                    request.network,
                    now,
                );
                defer final_refresh.deinit(allocator);
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
                    .published => {},
                }
                progress.refreshed = true;
                progress.refreshed_phase = .complete;
                try progress.persist(
                    state_store,
                    allocator,
                    .refreshed,
                    descriptor,
                    material.evidence,
                );
            } else {
                progress.refreshed_phase = .skipped;
            }
        } else if (progress.refreshed) {
            progress.refreshed_phase = .complete;
        } else {
            progress.refreshed_phase = .skipped;
        }

        try progress.persist(
            state_store,
            allocator,
            .complete,
            descriptor,
            material.evidence,
        );
        return progress.success(allocator);
    }
};

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
    exact_lock_path: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
    manifest_path: ?[]const u8 = null,
    managed_files: []const state_module.FileEvidence = &.{},
    durable_phase: state_module.Phase = .initialized,

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
        var state = try state_module.create(allocator, .{
            .root = self.root,
            .architecture = self.architecture,
            .no_refresh = self.no_refresh,
            .phase = durable_phase,
            .descriptor = state_descriptor,
            .managed_files = if (files.len != 0) files else self.managed_files,
            .installed = self.installed,
            .refreshed = self.refreshed,
            .exact_lock_path = self.exact_lock_path,
            .provenance_path = self.provenance_path,
            .manifest_path = self.manifest_path,
        });
        defer state.deinit();
        try store.writeAtomic(allocator, state.state, self.maximum_state_bytes);
        self.durable_phase = durable_phase;
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
    var result: [64]u8 = undefined;
    const digest = hash.finalResult();
    formatHex(&result, &digest);
    return result;
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
) !DescriptorMaterial {
    var source_files: std.ArrayList(MaterialFile) = .empty;
    defer source_files.deinit(allocator);
    for (validation.data.entries) |entry| {
        if (entry.kind != .regular or
            (!std.mem.endsWith(u8, entry.path, ".list") and
                !std.mem.endsWith(u8, entry.path, ".sources")))
            continue;
        if (!std.mem.startsWith(u8, entry.path, "etc/apt/sources.list.d/"))
            return error.DynamicRepositoryMaterial;
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
                .deadlines = deadlines(network),
            },
        };
    }
    const normalized = try repository_policy.normalizeBinaryRefresh(
        allocator,
        documents,
        architecture,
        .{},
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
    now: i64,
) !repository_policy.RefreshOutcome {
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
            network,
            now,
        );
    }
    var fixed_now = now;
    return repository_policy.refreshAll(allocator, .{
        .configuration = configuration,
        .runtimes = runtimes,
        .mode = .online,
        .failure_policy = .all_or_nothing,
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
                .deadlines = deadlines(network),
            },
        };
        const normalized = try repository_policy.normalizeBinaryRefresh(
            allocator,
            &.{document},
            architecture,
            .{},
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
        .{},
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
    now: i64,
) !repository_policy.RefreshOutcome {
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
            network,
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
            .deadlines = repository.deadlines,
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
    });
}

fn createOperationLock(
    allocator: std.mem.Allocator,
    plan: solver.Plan,
    local_evidence: @import("package_origin.zig").LocalArtifactEvidence,
    refreshed: ?*repository_policy.RefreshResult,
    no_refresh: bool,
) !exact_lock_v2.OwnedLock {
    var packages: std.ArrayList(exact_lock_v2.Package) = .empty;
    defer packages.deinit(allocator);
    var repository_ids: std.ArrayList([64]u8) = .empty;
    defer repository_ids.deinit(allocator);
    for (plan.actions) |action| {
        if (action.kind == .remove) continue;
        const origin = action.selected_origin_v2 orelse return error.MissingPackageOrigin;
        switch (origin) {
            .local_artifact => |local| {
                if (!@import("package_origin.zig").eqlLocalArtifact(
                    local.evidence,
                    local_evidence,
                )) return error.LocalArtifactMismatch;
                try packages.append(allocator, .{
                    .name = action.package,
                    .version = action.version,
                    .architecture = action.architecture,
                    .origin = .{ .local_artifact = local_evidence },
                    .sha256 = local_evidence.sha256,
                    .declared_size = local_evidence.size,
                    .retention = if (action.requested) .requested else .dependency,
                    .dpkg_selection_hold = false,
                });
            },
            .authenticated_repository => |repository_origin| {
                const published = refreshed orelse return error.MissingRepository;
                const repository = findRepositoryInput(
                    published.universe.repositories,
                    repository_origin.repository_id,
                ) orelse return error.MissingRepository;
                if (repository_origin.record_index >= repository.packages.records.len)
                    return error.MissingRepository;
                const record = repository.packages.records[repository_origin.record_index];
                const snapshot_digest = repository.authenticated_snapshot_sha256 orelse
                    return error.MissingRepository;
                try packages.append(allocator, .{
                    .name = action.package,
                    .version = action.version,
                    .architecture = action.architecture,
                    .origin = .{ .authenticated_repository = .{
                        .repository_id = repository_origin.repository_id.bytes,
                        .repository_snapshot_sha256 = snapshot_digest,
                    } },
                    .sha256 = record.transport.sha256.bytes,
                    .declared_size = record.transport.size.value,
                    .retention = if (action.requested) .requested else .dependency,
                    .dpkg_selection_hold = false,
                });
                if (!containsId(repository_ids.items, repository_origin.repository_id.bytes))
                    try repository_ids.append(
                        allocator,
                        repository_origin.repository_id.bytes,
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
    const plan_json = try plan.canonicalJson(allocator);
    defer allocator.free(plan_json);
    var request_hash = std.crypto.hash.sha2.Sha256.init(.{});
    request_hash.update("debz-repository-add-request-v1\x00");
    request_hash.update(plan_json);
    request_hash.update(if (no_refresh) "\x01" else "\x00");
    var policy_hash = std.crypto.hash.sha2.Sha256.init(.{});
    policy_hash.update("debz-repository-add-solver-policy-v1\x00");
    policy_hash.update("no-recommends\x00no-downgrade\x00strict-priority\x00");
    return exact_lock_v2.create(allocator, .{
        .target_architecture = plan.target_architecture,
        .request_sha256 = request_hash.finalResult(),
        .policy_sha256 = policy_hash.finalResult(),
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
    artifacts: *std.ArrayList(transaction_executor.Artifact),
    verified: *std.ArrayList(package_acquisition.VerifiedPackage),
) !void {
    for (plan.actions) |action| {
        if (action.kind == .remove) continue;
        const origin = action.selected_origin_v2 orelse return error.MissingPackageOrigin;
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
            .authenticated_repository => |repository_origin| {
                const published = refreshed orelse return error.MissingRepository;
                const repository = findRepositoryInput(
                    published.universe.repositories,
                    repository_origin.repository_id,
                ) orelse return error.MissingRepository;
                const normalized = findNormalized(
                    configuration.repositories,
                    repository_origin.repository_id,
                ) orelse return error.MissingRepository;
                const selected = try package_acquisition.SelectedPackage.fromSolverSelection(
                    repository,
                    repository_origin,
                    try repository_acquisition.Uri.parse(normalized.uri),
                );
                var package = try package_acquisition.acquirePackage(
                    allocator,
                    cache,
                    .{
                        .selected = selected,
                        .policy = .{
                            .mode = .online,
                            .workflow = .transaction,
                            .maximum_package_bytes = request.network.maximum_package_bytes,
                            .proxy = try proxyPolicy(request.network.proxy_url),
                            .deadlines = deadlines(request.network),
                            .redirect_limit = request.network.redirect_limit,
                            .retry = retryPolicy(request.network),
                        },
                    },
                    acquisition,
                );
                errdefer package.deinit();
                var payload = deb_payload.validate(allocator, package.bytes, .{
                    .repository = repository_origin.repository_id.slice(),
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
                try verified.append(allocator, package);
            },
        }
    }
}

fn publishProvenance(
    allocator: std.mem.Allocator,
    io: std.Io,
    operation_dir: std.Io.Dir,
    root: []const u8,
    lock: *const exact_lock_v2.Lock,
    plan: solver.Plan,
    report: transaction_executor.Report,
    refreshed: ?*repository_policy.RefreshResult,
) !void {
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
        const published = refreshed orelse return error.MissingRepository;
        const snapshot = findSnapshot(published.snapshots, repository.id) orelse
            return error.MissingRepository;
        const authentication = snapshot.snapshot.provenance.authentication_evidence;
        const signers = try allocator.alloc([20]u8, authentication.signatures.len);
        var signer_count: usize = 0;
        for (authentication.signatures) |signature| {
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
        repositories[index] = .{
            .source_config_id = repository.id,
            .snapshot_sha256 = repository_refresh.snapshotDigest(snapshot),
            .release_sha256 = snapshot.snapshot.provenance.release_digest.bytes,
            .signature_sha256 = if (authentication.signature_digest) |digest|
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
    const commands = try allocator.alloc(
        transaction_provenance_v2.CommandEvidence,
        report.commands.len,
    );
    defer allocator.free(commands);
    var environment_storage: std.ArrayList(
        []transaction_provenance_v2.EnvironmentEntry,
    ) = .empty;
    defer {
        for (environment_storage.items) |entries| allocator.free(entries);
        environment_storage.deinit(allocator);
    }
    for (report.commands, 0..) |command, index| {
        const environment = try allocator.alloc(
            transaction_provenance_v2.EnvironmentEntry,
            command.environment.len,
        );
        for (command.environment, 0..) |entry, entry_index| {
            environment[entry_index] = .{ .key = entry.key, .value = entry.value };
        }
        try environment_storage.append(allocator, environment);
        commands[index] = .{
            .phase = @tagName(command.phase),
            .package = command.package,
            .argv = command.argv,
            .environment = environment,
            .command_sha256 = command.command_sha256,
            .artifact_sha256 = command.artifact_sha256,
        };
    }
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
    var provenance = try transaction_provenance_v2.create(allocator, .{
        .target_architecture = lock.target_architecture,
        .request_sha256 = lock.request_sha256,
        .solver_policy_sha256 = lock.policy_sha256,
        .executor_policy_sha256 = report.policy_sha256,
        .plan_sha256 = report.plan_sha256,
        .lock_sha256 = lock.digest_sha256,
        .repositories = repositories,
        .packages = packages,
        .commands = commands,
        .journal_steps = &.{},
        .final_verification = .{
            .status = .exact_match,
            .installed_state_sha256 = status_digest,
            .package_origins_sha256 = lock.digest_sha256,
            .detail = "repository add transaction and local artifact evidence verified",
        },
        .outcome = .succeeded,
    });
    defer provenance.deinit();
    const store = try transaction_provenance_v2.Store.init(
        io,
        operation_dir,
        provenance_name,
    );
    try store.writeAtomic(allocator, provenance.result);
    _ = plan;
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
    const locked = lock.lock.findPackage(
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

fn deadlines(network: api.NetworkPolicy) repository_acquisition.Deadlines {
    return .{
        .connect_ms = network.connect_timeout_ms,
        .read_ms = network.read_timeout_ms,
        .overall_ms = network.overall_timeout_ms,
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
    if (path.len < 2 or path[0] != '/' or
        std.mem.indexOfScalar(u8, path, 0) != null or
        std.mem.indexOfScalar(u8, path, '\\') != null)
        return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return false;
    }
    return true;
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
    if (!std.fs.path.isAbsolute(path)) return error.InvalidAbsolutePath;
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

    const unsigned_source = "deb file:///synthetic-repository stable main\n";
    const unsigned_payload = try std.mem.concat(
        std.testing.allocator,
        u8,
        &.{ unsigned_source, &fixture.keyring },
    );
    defer std.testing.allocator.free(unsigned_payload);
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
    in_release_requests: usize = 0,
    fail_in_release_request: ?usize = null,
    network_requests: usize = 0,

    fn dependencies(self: *RepositoryTestAcquisition) repository_acquisition.Dependencies {
        return .{
            .transport = .{ .context = self, .requestFn = rejectNetwork },
            .files = .{ .context = self, .readFn = readFile },
            .clock = .{
                .context = null,
                .nowMsFn = zeroMilliseconds,
                .sleepMsFn = noSleep,
            },
        };
    }

    fn rejectNetwork(
        context: ?*anyopaque,
        _: std.mem.Allocator,
        _: repository_acquisition.HttpRequest,
    ) !repository_acquisition.HttpResponse {
        const self: *RepositoryTestAcquisition = @ptrCast(@alignCast(context.?));
        self.network_requests += 1;
        return error.NetworkForbidden;
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
        const bytes: []const u8 = if (std.mem.endsWith(u8, path, "descriptor.deb"))
            self.descriptor
        else if (std.mem.endsWith(u8, path, "/InRelease")) blk: {
            self.in_release_requests += 1;
            if (self.fail_in_release_request == self.in_release_requests)
                break :blk "not a signed release";
            break :blk &fixture.repository_in_release;
        } else if (std.mem.endsWith(u8, path, "/Packages"))
            &fixture.repository_packages
        else
            return error.FileNotFound;
        if (bytes.len > limit) return error.ResponseTooLarge;
        return .{ .bytes = try allocator.dupe(u8, bytes), .regular = true };
    }

    fn zeroMilliseconds(_: ?*anyopaque) u64 {
        return 0;
    }

    fn noSleep(_: ?*anyopaque, _: u64) !void {}
};

const RepositoryTestExecutor = struct {
    io: std.Io,
    directory: std.Io.Dir,
    calls: usize = 0,
    saw_lock_before_install: bool = false,
    last_allow_host_root: bool = false,

    fn interface(self: *RepositoryTestExecutor) Executor {
        return .{ .context = self, .executeFn = execute };
    }

    fn execute(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        request: transaction_executor.Request,
        _: transaction_executor.Dependencies,
    ) !transaction_executor.Report {
        const self: *RepositoryTestExecutor = @ptrCast(@alignCast(context));
        self.calls += 1;
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
            .data = "Package: packages-microsoft-prod\n" ++
                "Status: install ok installed\n" ++
                "Architecture: all\n" ++
                "Version: 1.1\n",
        });
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = .init(allocator);
        return .{
            .allocator = allocator,
            .arena = arena,
            .commands = &.{},
            .plan_sha256 = @splat(0x21),
            .transaction_state = .complete,
            .root_identity = @splat(0x22),
            .policy_sha256 = @splat(0x23),
            .lock_sha256 = null,
            .failure = null,
        };
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
}
