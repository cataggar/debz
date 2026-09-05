const std = @import("std");
const builtin = @import("builtin");
const deb_payload = @import("deb_payload.zig");
const exact_lock = @import("exact_lock.zig");
const package_acquisition = @import("package_acquisition.zig");
const package_cache_archive = @import("package_cache_archive.zig");
const packages_index = @import("packages_index.zig");
const repository_acquisition = @import("repository_acquisition.zig");
const solver = @import("solver.zig");
const source = @import("source.zig");

pub const capability = "package-cache-v1";
pub const fingerprint_schema = "io.github.cataggar.debz.package-cache-fingerprint.v1";
pub const result_schema = "io.github.cataggar.debz.package-cache-result.v1";
pub const error_schema = "io.github.cataggar.debz.package-cache-error.v1";
pub const api_version: u32 = 1;
pub const fingerprint_domain = "debz-package-cache-fingerprint-v1";
pub const abi_identity = "debian-package-archive-v1";
pub const payload_policy = "deb-payload-default-limits-v1";
pub const supported_origin_mode = "exact-lock-v1-authenticated-repository";

pub const RepositoryPolicy = enum {
    strict_priority,
    best_version,

    pub fn spelling(self: RepositoryPolicy) []const u8 {
        return switch (self) {
            .strict_priority => "strict-priority",
            .best_version => "best-version",
        };
    }
};

pub const CorruptCachePolicy = enum {
    fail,
    repair_online,

    pub fn spelling(self: CorruptCachePolicy) []const u8 {
        return switch (self) {
            .fail => "fail",
            .repair_online => "repair-online",
        };
    }
};

pub const RestoredCache = enum { none, partial, exact };

pub const Limits = struct {
    maximum_package_bytes: usize = 1024 * 1024 * 1024,
    maximum_total_package_bytes: u64 = 16 * 1024 * 1024 * 1024,
    maximum_lock_packages: usize = 100_000,
    maximum_repository_records: usize = 1_000_000,
    maximum_staging_entries: usize = 100_000,
    maximum_gc_directory_entries: usize = 100_000,
    maximum_gc_objects_scanned: usize = 100_000,
    maximum_gc_objects_deleted: usize = 100_000,
    maximum_gc_bytes_deleted: u64 = 16 * 1024 * 1024 * 1024,
};

pub const Policy = struct {
    foreign_architectures: []const []const u8 = &.{},
    recommends: bool = false,
    allow_downgrade: bool = false,
    repository_policy: RepositoryPolicy = .strict_priority,
    offline: bool = false,
    corrupt_cache: CorruptCachePolicy = .fail,
    restored_cache: RestoredCache = .none,
    deadline_ms: ?u64 = null,
    lock_wait_ms: u64 = 30_000,
    limits: Limits = .{},
};

pub const Request = struct {
    lock_input_path: []const u8,
    cache_root: []const u8,
    architecture: []const u8,
    source_paths: []const []const u8 = &.{},
    config_paths: []const []const u8 = &.{},
    keyring_paths: []const []const u8 = &.{},
    foreign_architectures: []const []const u8 = &.{},
    default_release: ?[]const u8 = null,
    repository_policy: RepositoryPolicy = .strict_priority,
    recommends: bool = false,
    allow_downgrade: bool = false,
    proxy: ?[]const u8 = null,
    credential_reference: ?[]const u8 = null,
    archive_input_path: ?[]const u8 = null,
    archive_output_path: ?[]const u8 = null,
    offline: bool = false,
    corrupt_cache: CorruptCachePolicy = .fail,
    restored_cache: RestoredCache = .none,
    deadline_ms: ?u64 = null,
    lock_wait_ms: u64 = 30_000,
    limits: Limits = .{},

    pub fn policy(self: Request) Policy {
        return .{
            .foreign_architectures = self.foreign_architectures,
            .recommends = self.recommends,
            .allow_downgrade = self.allow_downgrade,
            .repository_policy = self.repository_policy,
            .offline = self.offline,
            .corrupt_cache = self.corrupt_cache,
            .restored_cache = self.restored_cache,
            .deadline_ms = self.deadline_ms,
            .lock_wait_ms = self.lock_wait_ms,
            .limits = self.limits,
        };
    }
};

pub const Fingerprint = struct {
    lock_digest: [64]u8,
    acceptance_policy_digest: [64]u8,
    fingerprint: [64]u8,
    target_architecture: []u8,
    debz_version: []u8,
    primary_key: []u8,
    restore_prefix: []u8,
    cache_root: []u8,
    cache_path: []u8,
    maximum_archive_bytes: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Fingerprint) void {
        self.allocator.free(self.target_architecture);
        self.allocator.free(self.debz_version);
        self.allocator.free(self.primary_key);
        self.allocator.free(self.restore_prefix);
        self.allocator.free(self.cache_root);
        self.allocator.free(self.cache_path);
        self.* = undefined;
    }

    pub fn canonicalJson(self: Fingerprint, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        const writer = &output.writer;
        try writer.writeAll("{\"schema\":");
        try writeJsonString(writer, fingerprint_schema);
        try writer.print(",\"api_version\":{},\"capability\":", .{api_version});
        try writeJsonString(writer, capability);
        try writer.writeAll(",\"lock_schema\":");
        try writeJsonString(writer, exact_lock.schema_id);
        try writer.print(",\"lock_schema_version\":{},\"lock_digest\":", .{exact_lock.schema_version});
        try writeJsonString(writer, &self.lock_digest);
        try writer.writeAll(",\"target_architecture\":");
        try writeJsonString(writer, self.target_architecture);
        try writer.writeAll(",\"abi\":");
        try writeJsonString(writer, abi_identity);
        try writer.writeAll(",\"debz_version\":");
        try writeJsonString(writer, self.debz_version);
        try writer.writeAll(",\"cas_layout\":");
        try writeJsonString(writer, package_acquisition.namespace);
        try writer.writeAll(",\"archive_format\":");
        try writeJsonString(writer, package_cache_archive.format_id);
        try writer.writeAll(",\"payload_policy\":");
        try writeJsonString(writer, payload_policy);
        try writer.writeAll(",\"origin_mode\":");
        try writeJsonString(writer, supported_origin_mode);
        try writer.writeAll(",\"acceptance_policy_digest\":");
        try writeJsonString(writer, &self.acceptance_policy_digest);
        try writer.writeAll(",\"fingerprint\":");
        try writeJsonString(writer, &self.fingerprint);
        try writer.writeAll(",\"primary_key\":");
        try writeJsonString(writer, self.primary_key);
        try writer.writeAll(",\"restore_prefix\":");
        try writeJsonString(writer, self.restore_prefix);
        try writer.writeAll(",\"cache_root\":");
        try writeJsonString(writer, self.cache_root);
        try writer.writeAll(",\"cache_path\":");
        try writeJsonString(writer, self.cache_path);
        try writer.print(",\"maximum_archive_bytes\":{}", .{self.maximum_archive_bytes});
        try writer.writeAll("}\n");
        return output.toOwnedSlice();
    }
};

pub const RepositoryView = struct {
    input: solver.RepositoryInput,
    base_uri: repository_acquisition.Uri,
    release_sha256: [32]u8,
    index_sha256: [32]u8,
    signer_fingerprint: ?[20]u8,
};

pub const PrepareRequest = struct {
    lock: *const exact_lock.Lock,
    cache: *package_acquisition.Cache,
    repositories: []const RepositoryView,
    architecture: []const u8,
    debz_version: []const u8,
    cache_root: []const u8,
    policy: Policy,
    proxy: repository_acquisition.ProxyPolicy = .direct,
    credentials: repository_acquisition.CredentialsProvider = .none,
    acquisition: repository_acquisition.Dependencies,
};

pub const PreflightResult = struct {
    present: usize,
    missing: usize,
    corrupt_for_repair: usize,
};

pub const PrepareResult = struct {
    lock_digest: [64]u8,
    fingerprint: [64]u8,
    target_architecture: []u8,
    cache_root: []u8,
    cache_path: []u8,
    downloaded_count: usize,
    reused_count: usize,
    staging_scanned: usize,
    staging_deleted: usize,
    gc_scanned: usize,
    gc_deleted: usize,
    gc_bytes_deleted: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PrepareResult) void {
        self.allocator.free(self.target_architecture);
        self.allocator.free(self.cache_root);
        self.allocator.free(self.cache_path);
        self.* = undefined;
    }

    pub fn canonicalJson(self: PrepareResult, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        const writer = &output.writer;
        try writer.writeAll("{\"schema\":");
        try writeJsonString(writer, result_schema);
        try writer.print(",\"api_version\":{},\"capability\":", .{api_version});
        try writeJsonString(writer, capability);
        try writer.writeAll(",\"lock_digest\":");
        try writeJsonString(writer, &self.lock_digest);
        try writer.writeAll(",\"fingerprint\":");
        try writeJsonString(writer, &self.fingerprint);
        try writer.writeAll(",\"target_architecture\":");
        try writeJsonString(writer, self.target_architecture);
        try writer.writeAll(",\"cas_layout\":");
        try writeJsonString(writer, package_acquisition.namespace);
        try writer.writeAll(",\"cache_root\":");
        try writeJsonString(writer, self.cache_root);
        try writer.writeAll(",\"cache_path\":");
        try writeJsonString(writer, self.cache_path);
        try writer.print(
            ",\"downloaded_count\":{},\"reused_count\":{},\"verified_count\":{}",
            .{ self.downloaded_count, self.reused_count, self.downloaded_count + self.reused_count },
        );
        try writer.print(
            ",\"staging\":{{\"scanned\":{},\"deleted\":{},\"complete\":true}}",
            .{ self.staging_scanned, self.staging_deleted },
        );
        try writer.print(
            ",\"gc\":{{\"scanned\":{},\"deleted\":{},\"bytes_deleted\":{},\"complete\":true}}}}\n",
            .{ self.gc_scanned, self.gc_deleted, self.gc_bytes_deleted },
        );
        return output.toOwnedSlice();
    }
};

pub const Error = error{
    InvalidRequest,
    InvalidArchitecture,
    ArchitectureMismatch,
    UnsupportedPackageArchitecture,
    UnsupportedLockSchema,
    LockPolicyMismatch,
    TooManyPackages,
    TooManyRepositoryRecords,
    PackageTooLarge,
    TotalPackageBytesExceeded,
    DuplicatePackageDigest,
    MissingRepository,
    RepositoryEvidenceMismatch,
    MissingPackage,
    AmbiguousPackage,
    PackageEvidenceMismatch,
    InvalidPackagePayload,
    CleanupIncomplete,
    GarbageCollectionIncomplete,
};

pub fn validateRequest(request: Request, require_repositories: bool) Error!void {
    if (!validAbsolutePath(request.lock_input_path) or
        !validAbsolutePath(request.cache_root) or
        !validPaths(request.source_paths) or
        !validPaths(request.config_paths) or
        !validPaths(request.keyring_paths) or
        (request.credential_reference != null and !validAbsolutePath(request.credential_reference.?)))
        return error.InvalidRequest;
    if ((request.archive_input_path != null and !validAbsolutePath(request.archive_input_path.?)) or
        (request.archive_output_path != null and !validAbsolutePath(request.archive_output_path.?)) or
        (request.archive_input_path != null and request.archive_output_path != null and
            std.mem.eql(u8, request.archive_input_path.?, request.archive_output_path.?)) or
        (request.archive_input_path != null and pathWithin(request.cache_root, request.archive_input_path.?)) or
        (request.archive_output_path != null and pathWithin(request.cache_root, request.archive_output_path.?)) or
        ((request.restored_cache == .none) != (request.archive_input_path == null)))
        return error.InvalidRequest;
    try validatePolicy(request.architecture, request.policy());
    if (request.proxy) |value| {
        const uri = repository_acquisition.Uri.parse(value) catch return error.InvalidRequest;
        if ((!std.ascii.eqlIgnoreCase(uri.scheme, "http") and
            !std.ascii.eqlIgnoreCase(uri.scheme, "https")) or
            uri.user != null or uri.password != null or uri.query != null or uri.fragment != null)
            return error.InvalidRequest;
    }
    if (require_repositories and
        ((request.source_paths.len == 0 and request.config_paths.len == 0) or
            request.keyring_paths.len == 0))
        return error.InvalidRequest;
}

pub fn createFingerprint(
    allocator: std.mem.Allocator,
    lock: exact_lock.Lock,
    architecture: []const u8,
    debz_version: []const u8,
    cache_root: []const u8,
    policy: Policy,
) !Fingerprint {
    try validateLock(allocator, lock, architecture, policy);
    _ = std.SemanticVersion.parse(debz_version) catch return error.InvalidRequest;
    if (!validAbsolutePath(cache_root)) return error.InvalidRequest;

    const policy_digest = acceptancePolicyDigest(allocator, architecture, debz_version, policy) catch |err|
        return err;
    const fingerprint_digest = fullFingerprint(lock.digest_sha256, policy_digest);
    var lock_hex: [64]u8 = undefined;
    var policy_hex: [64]u8 = undefined;
    var fingerprint_hex: [64]u8 = undefined;
    formatHex(lock.digest_sha256, &lock_hex);
    formatHex(policy_digest, &policy_hex);
    formatHex(fingerprint_digest, &fingerprint_hex);
    const primary_key = try std.fmt.allocPrint(
        allocator,
        "debz-package-cas-v1-{s}-{s}-{s}",
        .{ architecture, &policy_hex, &lock_hex },
    );
    errdefer allocator.free(primary_key);
    const restore_prefix = try std.fmt.allocPrint(
        allocator,
        "debz-package-cas-v1-{s}-{s}-",
        .{ architecture, &policy_hex },
    );
    errdefer allocator.free(restore_prefix);
    const cache_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}/objects",
        .{ cache_root, package_acquisition.namespace },
    );
    errdefer allocator.free(cache_path);
    const target = try allocator.dupe(u8, architecture);
    errdefer allocator.free(target);
    const version = try allocator.dupe(u8, debz_version);
    errdefer allocator.free(version);
    const owned_root = try allocator.dupe(u8, cache_root);
    const maximum_archive_bytes = try package_cache_archive.maximumArchiveBytes(.{
        .maximum_objects = policy.limits.maximum_lock_packages,
        .maximum_object_bytes = policy.limits.maximum_package_bytes,
        .maximum_total_object_bytes = policy.limits.maximum_total_package_bytes,
    });
    return .{
        .lock_digest = lock_hex,
        .acceptance_policy_digest = policy_hex,
        .fingerprint = fingerprint_hex,
        .target_architecture = target,
        .debz_version = version,
        .primary_key = primary_key,
        .restore_prefix = restore_prefix,
        .cache_root = owned_root,
        .cache_path = cache_path,
        .maximum_archive_bytes = maximum_archive_bytes,
        .allocator = allocator,
    };
}

pub fn prepare(
    allocator: std.mem.Allocator,
    request: PrepareRequest,
) !PrepareResult {
    if (request.cache.limits.maximum_object_bytes != request.policy.limits.maximum_package_bytes)
        return error.InvalidRequest;
    var validated = try createFingerprint(
        allocator,
        request.lock.*,
        request.architecture,
        request.debz_version,
        request.cache_root,
        request.policy,
    );
    validated.deinit();
    var writer_lock = try request.cache.acquireWriter(request.policy.lock_wait_ms);
    defer writer_lock.release();
    const initial_cleanup = try cleanupStagingForPrepare(
        allocator,
        request.cache,
        request.policy,
        &writer_lock,
    );
    _ = try preflight(allocator, request.lock.*, request.cache, request.policy, &writer_lock);
    return prepareWithWriterLockAfterCleanup(
        allocator,
        request,
        &writer_lock,
        initial_cleanup,
    );
}

pub fn preflight(
    allocator: std.mem.Allocator,
    lock: exact_lock.Lock,
    cache: *package_acquisition.Cache,
    policy: Policy,
    writer_lock: *const package_acquisition.Cache.WriterLock,
) !PreflightResult {
    if (writer_lock.cache != cache or writer_lock.file == null or
        cache.limits.maximum_object_bytes != policy.limits.maximum_package_bytes)
        return error.InvalidRequest;
    try validateLock(allocator, lock, lock.target_architecture, policy);
    var result: PreflightResult = .{
        .present = 0,
        .missing = 0,
        .corrupt_for_repair = 0,
    };
    for (lock.packages) |package| {
        const digest: package_acquisition.Digest = .{ .bytes = package.sha256 };
        if (cache.lookup(
            allocator,
            digest,
            package.declared_size,
            .verify_sha256,
        )) |bytes| {
            allocator.free(bytes);
            result.present += 1;
        } else |err| switch (err) {
            error.CacheMiss => {
                if (policy.restored_cache == .exact and
                    policy.corrupt_cache == .fail)
                    return error.CorruptObject;
                if (policy.offline) return error.CacheMiss;
                result.missing += 1;
            },
            error.CorruptObject => {
                if (policy.offline or policy.corrupt_cache == .fail)
                    return error.CorruptObject;
                result.corrupt_for_repair += 1;
            },
            else => |other| return other,
        }
    }
    return result;
}

pub fn prepareWithWriterLock(
    allocator: std.mem.Allocator,
    request: PrepareRequest,
    writer_lock: *const package_acquisition.Cache.WriterLock,
) !PrepareResult {
    const initial_cleanup = try cleanupStagingForPrepare(
        allocator,
        request.cache,
        request.policy,
        writer_lock,
    );
    return prepareWithWriterLockAfterCleanup(
        allocator,
        request,
        writer_lock,
        initial_cleanup,
    );
}

pub fn cleanupStagingForPrepare(
    allocator: std.mem.Allocator,
    cache: *package_acquisition.Cache,
    policy: Policy,
    writer_lock: *const package_acquisition.Cache.WriterLock,
) !package_acquisition.CleanupResult {
    if (writer_lock.cache != cache or writer_lock.file == null)
        return error.InvalidRequest;
    const cleanup = try cache.cleanupStaging(
        allocator,
        policy.limits.maximum_staging_entries,
        .{ .held = writer_lock },
    );
    if (!cleanup.complete) return error.CleanupIncomplete;
    return cleanup;
}

pub fn prepareWithWriterLockAfterCleanup(
    allocator: std.mem.Allocator,
    request: PrepareRequest,
    writer_lock: *const package_acquisition.Cache.WriterLock,
    initial_cleanup: package_acquisition.CleanupResult,
) !PrepareResult {
    if (writer_lock.cache != request.cache or writer_lock.file == null or
        request.cache.limits.maximum_object_bytes != request.policy.limits.maximum_package_bytes)
        return error.InvalidRequest;
    if (!initial_cleanup.complete) return error.CleanupIncomplete;
    var fingerprint = try createFingerprint(
        allocator,
        request.lock.*,
        request.architecture,
        request.debz_version,
        request.cache_root,
        request.policy,
    );
    defer fingerprint.deinit();
    try validateRepositoryEvidence(allocator, request.lock.*, request.repositories);
    const matches = try matchPackages(
        allocator,
        request.lock.*,
        request.repositories,
        request.policy.limits.maximum_repository_records,
    );
    defer allocator.free(matches);

    const retained = try allocator.alloc(package_acquisition.Digest, request.lock.packages.len);
    defer allocator.free(retained);
    for (request.lock.packages, 0..) |package, index|
        retained[index] = .{ .bytes = package.sha256 };
    std.mem.sort(package_acquisition.Digest, retained, {}, lessDigest);

    var downloaded_count: usize = 0;
    var reused_count: usize = 0;
    var transport_bytes: u64 = 0;
    for (request.lock.packages, matches) |locked, match| {
        const view = request.repositories[match.repository_index];
        const record = &view.input.packages.records[match.record_index];
        const origin: solver.PackageOrigin = .{
            .repository_id = view.input.repository_id,
            .repository_priority = view.input.priority,
            .record_index = match.record_index,
            .package = record.control.package.text,
            .version = record.control.version.value.original,
            .architecture = record.control.architecture.text,
            .source_location = record.location.source,
        };
        const selected = try package_acquisition.SelectedPackage.fromSolverSelection(
            view.input,
            origin,
            view.base_uri,
        );
        var package = try package_acquisition.acquirePackage(
            allocator,
            request.cache,
            .{
                .selected = selected,
                .policy = .{
                    .mode = if (request.policy.offline) .cache_only else .online,
                    .workflow = .download_only,
                    .maximum_package_bytes = request.policy.limits.maximum_package_bytes,
                    .corrupt_cache = switch (request.policy.corrupt_cache) {
                        .fail => .fail,
                        .repair_online => .repair_online,
                    },
                    .proxy = request.proxy,
                    .deadlines = deadlines(request.policy.deadline_ms),
                    .redirect_limit = 8,
                    .retry = .{ .max_attempts = 6, .backoff_ms = retryBackoff },
                    .credentials = request.credentials,
                    .cache_lock = .{ .held = writer_lock },
                },
                .exact_lock_package = locked,
            },
            request.acquisition,
        );
        defer package.deinit();
        var validation = deb_payload.validate(allocator, package.bytes, .{
            .repository = view.input.repository_id.slice(),
            .package = locked.name,
            .version = locked.version,
            .architecture = locked.architecture,
            .requested_package = locked.name,
            .requested_version = locked.version,
            .requested_architecture = locked.architecture,
            .filename = record.transport.filename.value,
            .size = locked.declared_size,
            .sha256 = locked.sha256,
        }, .{});
        switch (validation) {
            .diagnostic => return error.InvalidPackagePayload,
            .validation => |*value| value.deinit(),
        }
        switch (package.provenance.outcome) {
            .cache_hit => reused_count += 1,
            .downloaded => {
                downloaded_count += 1;
                transport_bytes = std.math.add(u64, transport_bytes, locked.declared_size) catch
                    return error.TotalPackageBytesExceeded;
                if (transport_bytes > request.policy.limits.maximum_total_package_bytes)
                    return error.TotalPackageBytesExceeded;
            },
        }
    }

    const gc = try request.cache.garbageCollect(allocator, .{
        .retained = retained,
        .maximum_directory_entries = request.policy.limits.maximum_gc_directory_entries,
        .maximum_objects_scanned = request.policy.limits.maximum_gc_objects_scanned,
        .maximum_objects_deleted = request.policy.limits.maximum_gc_objects_deleted,
        .maximum_bytes_deleted = request.policy.limits.maximum_gc_bytes_deleted,
        .lock = .{ .held = writer_lock },
    });
    if (!gc.complete) return error.GarbageCollectionIncomplete;

    const target = try allocator.dupe(u8, request.architecture);
    errdefer allocator.free(target);
    const owned_root = try allocator.dupe(u8, request.cache_root);
    errdefer allocator.free(owned_root);
    const owned_path = try allocator.dupe(u8, fingerprint.cache_path);
    return .{
        .lock_digest = fingerprint.lock_digest,
        .fingerprint = fingerprint.fingerprint,
        .target_architecture = target,
        .cache_root = owned_root,
        .cache_path = owned_path,
        .downloaded_count = downloaded_count,
        .reused_count = reused_count,
        .staging_scanned = initial_cleanup.scanned,
        .staging_deleted = initial_cleanup.deleted,
        .gc_scanned = gc.scanned,
        .gc_deleted = gc.deleted,
        .gc_bytes_deleted = gc.bytes_deleted,
        .allocator = allocator,
    };
}

pub fn solverPolicyDigest(
    recommends: bool,
    allow_downgrade: bool,
    repository_policy: RepositoryPolicy,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("debz-solver-policy-v1\x00");
    hash.update(if (recommends) "recommends\x00" else "no-recommends\x00");
    hash.update(if (allow_downgrade) "allow-downgrade\x00" else "no-downgrade\x00");
    hash.update(@tagName(repository_policy));
    return hash.finalResult();
}

pub fn errorJson(
    allocator: std.mem.Allocator,
    operation: []const u8,
    exit_status: u8,
    id: []const u8,
    message: []const u8,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;
    try writer.writeAll("{\"schema\":");
    try writeJsonString(writer, error_schema);
    try writer.print(",\"api_version\":{},\"operation\":", .{api_version});
    try writeJsonString(writer, operation);
    try writer.print(",\"exit_status\":{},\"diagnostics\":[{{\"id\":", .{exit_status});
    try writeJsonString(writer, id);
    try writer.writeAll(",\"message\":");
    try writeJsonString(writer, message);
    try writer.writeAll("}]}\n");
    return output.toOwnedSlice();
}

fn validatePolicy(architecture: []const u8, policy: Policy) Error!void {
    if (!validArchitecture(architecture)) return error.InvalidArchitecture;
    if (policy.foreign_architectures.len > 16 or
        (policy.deadline_ms != null and
            (policy.deadline_ms.? == 0 or policy.deadline_ms.? > 86_400_000)) or
        policy.lock_wait_ms == 0 or policy.lock_wait_ms > 300_000 or
        !validLimits(policy.limits) or
        (policy.offline and policy.corrupt_cache == .repair_online))
        return error.InvalidRequest;
    for (policy.foreign_architectures, 0..) |foreign, index| {
        if (!validArchitecture(foreign) or std.mem.eql(u8, foreign, architecture))
            return error.InvalidArchitecture;
        for (policy.foreign_architectures[0..index]) |prior|
            if (std.mem.eql(u8, prior, foreign)) return error.InvalidArchitecture;
    }
}

fn validateLock(
    allocator: std.mem.Allocator,
    lock: exact_lock.Lock,
    architecture: []const u8,
    policy: Policy,
) !void {
    try validatePolicy(architecture, policy);
    if (!std.mem.eql(u8, lock.target_architecture, architecture)) return error.ArchitectureMismatch;
    if (lock.packages.len == 0 or lock.packages.len > policy.limits.maximum_lock_packages)
        return error.TooManyPackages;
    const expected_policy = solverPolicyDigest(
        policy.recommends,
        policy.allow_downgrade,
        policy.repository_policy,
    );
    if (!std.mem.eql(u8, &expected_policy, &lock.policy_sha256)) return error.LockPolicyMismatch;
    var total: u64 = 0;
    const digests = try allocator.alloc([32]u8, lock.packages.len);
    defer allocator.free(digests);
    for (lock.packages, 0..) |package, index| {
        if (!architectureAllowed(package.architecture, architecture, policy.foreign_architectures))
            return error.UnsupportedPackageArchitecture;
        if (package.declared_size == 0 or package.declared_size > policy.limits.maximum_package_bytes)
            return error.PackageTooLarge;
        total = std.math.add(u64, total, package.declared_size) catch
            return error.TotalPackageBytesExceeded;
        if (total > policy.limits.maximum_total_package_bytes)
            return error.TotalPackageBytesExceeded;
        digests[index] = package.sha256;
    }
    std.mem.sort([32]u8, digests, {}, lessBytes32);
    for (digests[1..], digests[0 .. digests.len - 1]) |current, prior|
        if (std.mem.eql(u8, &current, &prior)) return error.DuplicatePackageDigest;
}

fn validateRepositoryEvidence(
    allocator: std.mem.Allocator,
    lock: exact_lock.Lock,
    repositories: []const RepositoryView,
) !void {
    var by_id = std.AutoHashMap([64]u8, usize).init(allocator);
    defer by_id.deinit();
    for (repositories, 0..) |repository, index| {
        const id = repository.input.repository_id.bytes;
        const entry = try by_id.getOrPut(id);
        if (entry.found_existing) return error.RepositoryEvidenceMismatch;
        entry.value_ptr.* = index;
    }
    for (lock.repositories) |locked| {
        const index = by_id.get(locked.id) orelse return error.MissingRepository;
        const view = repositories[index];
        if (view.input.eligibility != .verified_refresh or
            view.input.authenticated_snapshot_sha256 == null or
            !std.mem.eql(u8, &view.input.authenticated_snapshot_sha256.?, &locked.snapshot_sha256) or
            !std.mem.eql(u8, &view.release_sha256, &locked.release_sha256) or
            !std.mem.eql(u8, &view.index_sha256, &locked.index_sha256) or
            view.signer_fingerprint == null or
            !containsSigner(locked.signer_fingerprints, view.signer_fingerprint.?))
            return error.RepositoryEvidenceMismatch;
    }
}

const PackageMatch = struct {
    repository_index: usize,
    record_index: usize,
};

fn matchPackages(
    allocator: std.mem.Allocator,
    lock: exact_lock.Lock,
    repositories: []const RepositoryView,
    maximum_records: usize,
) ![]PackageMatch {
    var by_digest = std.AutoHashMap([32]u8, usize).init(allocator);
    defer by_digest.deinit();
    for (lock.packages, 0..) |package, index| try by_digest.put(package.sha256, index);

    const matches = try allocator.alloc(?PackageMatch, lock.packages.len);
    defer allocator.free(matches);
    @memset(matches, null);
    var mismatched = try allocator.alloc(bool, lock.packages.len);
    defer allocator.free(mismatched);
    @memset(mismatched, false);

    var scanned: usize = 0;
    for (repositories, 0..) |repository, repository_index| {
        for (repository.input.packages.records, 0..) |record, record_index| {
            if (scanned == maximum_records) return error.TooManyRepositoryRecords;
            scanned += 1;
            const lock_index = by_digest.get(record.transport.sha256.bytes) orelse continue;
            const locked = lock.packages[lock_index];
            if (!std.mem.eql(u8, repository.input.repository_id.slice(), &locked.repository_id) or
                !std.mem.eql(u8, record.control.package.text, locked.name) or
                !std.mem.eql(u8, record.control.version.value.original, locked.version) or
                !std.mem.eql(u8, record.control.architecture.text, locked.architecture) or
                record.transport.size.value != locked.declared_size)
            {
                mismatched[lock_index] = true;
                continue;
            }
            if (matches[lock_index] != null) return error.AmbiguousPackage;
            matches[lock_index] = .{
                .repository_index = repository_index,
                .record_index = record_index,
            };
        }
    }

    const result = try allocator.alloc(PackageMatch, lock.packages.len);
    errdefer allocator.free(result);
    for (matches, 0..) |match, index| {
        result[index] = match orelse if (mismatched[index])
            return error.PackageEvidenceMismatch
        else
            return error.MissingPackage;
    }
    return result;
}

fn containsSigner(signers: []const [20]u8, wanted: [20]u8) bool {
    for (signers) |signer| if (std.mem.eql(u8, &signer, &wanted)) return true;
    return false;
}

fn acceptancePolicyDigest(
    allocator: std.mem.Allocator,
    architecture: []const u8,
    debz_version: []const u8,
    policy: Policy,
) ![32]u8 {
    const foreign = try allocator.dupe([]const u8, policy.foreign_architectures);
    defer allocator.free(foreign);
    std.mem.sort([]const u8, foreign, {}, lessString);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hashField(&hash, fingerprint_domain);
    hashField(&hash, exact_lock.schema_id);
    hashInt(&hash, exact_lock.schema_version);
    hashField(&hash, architecture);
    hashInt(&hash, foreign.len);
    for (foreign) |value| hashField(&hash, value);
    hashField(&hash, debz_version);
    hashField(&hash, package_acquisition.namespace);
    hashField(&hash, package_cache_archive.format_id);
    hashField(&hash, abi_identity);
    hashField(&hash, payload_policy);
    hashField(&hash, supported_origin_mode);
    hashField(&hash, policy.corrupt_cache.spelling());
    hashInt(&hash, policy.limits.maximum_package_bytes);
    hashInt(&hash, policy.limits.maximum_total_package_bytes);
    return hash.finalResult();
}

fn fullFingerprint(lock_digest: [32]u8, policy_digest: [32]u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(fingerprint_domain);
    hash.update("\x00full\x00");
    hash.update(&policy_digest);
    hash.update(&lock_digest);
    return hash.finalResult();
}

fn hashField(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, value.len, .little);
    hash.update(&length);
    hash.update(value);
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn formatHex(bytes: [32]u8, output: *[64]u8) void {
    _ = std.fmt.bufPrint(output, "{x}", .{bytes}) catch unreachable;
}

fn lessDigest(_: void, left: package_acquisition.Digest, right: package_acquisition.Digest) bool {
    return std.mem.order(u8, &left.bytes, &right.bytes) == .lt;
}

fn lessBytes32(_: void, left: [32]u8, right: [32]u8) bool {
    return std.mem.order(u8, &left, &right) == .lt;
}

fn lessString(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn architectureAllowed(value: []const u8, native: []const u8, foreign: []const []const u8) bool {
    if (std.mem.eql(u8, value, "all") or std.mem.eql(u8, value, native)) return true;
    for (foreign) |candidate| if (std.mem.eql(u8, value, candidate)) return true;
    return false;
}

fn validLimits(limits: Limits) bool {
    return limits.maximum_package_bytes != 0 and
        limits.maximum_package_bytes <= 4 * 1024 * 1024 * 1024 and
        limits.maximum_total_package_bytes != 0 and
        limits.maximum_total_package_bytes <= 1024 * 1024 * 1024 * 1024 and
        limits.maximum_lock_packages != 0 and limits.maximum_lock_packages <= 1_000_000 and
        limits.maximum_repository_records != 0 and limits.maximum_repository_records <= 5_000_000 and
        limits.maximum_staging_entries != 0 and limits.maximum_staging_entries <= 1_000_000 and
        limits.maximum_gc_directory_entries != 0 and limits.maximum_gc_directory_entries <= 1_000_000 and
        limits.maximum_gc_objects_scanned != 0 and limits.maximum_gc_objects_scanned <= 1_000_000 and
        limits.maximum_gc_objects_deleted != 0 and limits.maximum_gc_objects_deleted <= 1_000_000 and
        limits.maximum_gc_bytes_deleted != 0 and
        limits.maximum_gc_bytes_deleted <= 1024 * 1024 * 1024 * 1024;
}

fn validPaths(paths: []const []const u8) bool {
    if (paths.len > 128) return false;
    for (paths) |path| if (!validAbsolutePath(path)) return false;
    return true;
}

fn validAbsolutePath(path: []const u8) bool {
    if (path.len <= 1 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component|
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return false;
    return true;
}

fn validArchitecture(value: []const u8) bool {
    return std.mem.eql(u8, value, "amd64") or std.mem.eql(u8, value, "arm64");
}

fn pathWithin(root: []const u8, candidate: []const u8) bool {
    return std.mem.eql(u8, root, candidate) or
        (candidate.len > root.len and
            std.mem.startsWith(u8, candidate, root) and
            candidate[root.len] == '/');
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

fn retryBackoff(attempt: u16) u64 {
    return @as(u64, attempt) * 2_000;
}

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |character| switch (character) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...8, 11, 12, 14...0x1f => try writer.print("\\u{x:0>4}", .{character}),
        else => try writer.writeByte(character),
    };
    try writer.writeByte('"');
}

fn testLock(
    allocator: std.mem.Allocator,
    package_digest: [32]u8,
    package_size: u64,
    policy: Policy,
) !exact_lock.OwnedLock {
    return testLockForArchitecture(allocator, package_digest, package_size, policy, "amd64");
}

fn testLockForArchitecture(
    allocator: std.mem.Allocator,
    package_digest: [32]u8,
    package_size: u64,
    policy: Policy,
    architecture: []const u8,
) !exact_lock.OwnedLock {
    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(1);
    return exact_lock.create(allocator, .{
        .target_architecture = architecture,
        .request_sha256 = @splat(2),
        .policy_sha256 = solverPolicyDigest(
            policy.recommends,
            policy.allow_downgrade,
            policy.repository_policy,
        ),
        .repositories = &.{.{
            .id = repository_id,
            .snapshot_sha256 = snapshot,
            .release_sha256 = @splat(3),
            .index_sha256 = @splat(4),
            .signer_fingerprints = &.{@splat(5)},
        }},
        .packages = &.{.{
            .name = "demo",
            .version = "1.0-1",
            .architecture = architecture,
            .repository_id = repository_id,
            .repository_snapshot_sha256 = snapshot,
            .sha256 = package_digest,
            .declared_size = package_size,
            .retention = .requested,
            .dpkg_selection_hold = false,
        }},
        .authenticated_metadata = true,
    });
}

test "package_cache_workflow.test.fingerprint is deterministic and policy separated" {
    const policy: Policy = .{};
    var lock = try testLock(std.testing.allocator, @splat(6), 10, policy);
    defer lock.deinit();
    var first = try createFingerprint(
        std.testing.allocator,
        lock.lock,
        "amd64",
        "0.3.0",
        "/runner/cache",
        policy,
    );
    defer first.deinit();
    var second = try createFingerprint(
        std.testing.allocator,
        lock.lock,
        "amd64",
        "0.3.0",
        "/different/path",
        policy,
    );
    defer second.deinit();
    try std.testing.expectEqualStrings(first.primary_key, second.primary_key);
    try std.testing.expectEqualStrings(first.restore_prefix, second.restore_prefix);
    try std.testing.expect(!std.mem.eql(u8, first.cache_path, second.cache_path));

    var changed_policy = policy;
    changed_policy.corrupt_cache = .repair_online;
    var changed = try createFingerprint(
        std.testing.allocator,
        lock.lock,
        "amd64",
        "0.3.0",
        "/runner/cache",
        changed_policy,
    );
    defer changed.deinit();
    try std.testing.expect(!std.mem.eql(u8, first.primary_key, changed.primary_key));
    try std.testing.expect(!std.mem.eql(u8, first.restore_prefix, changed.restore_prefix));

    var exact_restore_policy = policy;
    exact_restore_policy.restored_cache = .exact;
    var exact_restore_fingerprint = try createFingerprint(
        std.testing.allocator,
        lock.lock,
        "amd64",
        "0.3.0",
        "/runner/cache",
        exact_restore_policy,
    );
    defer exact_restore_fingerprint.deinit();
    try std.testing.expectEqualStrings(first.primary_key, exact_restore_fingerprint.primary_key);

    var changed_version = try createFingerprint(
        std.testing.allocator,
        lock.lock,
        "amd64",
        "0.3.1",
        "/runner/cache",
        policy,
    );
    defer changed_version.deinit();
    try std.testing.expect(!std.mem.eql(u8, first.primary_key, changed_version.primary_key));

    var changed_limit_policy = policy;
    changed_limit_policy.limits.maximum_package_bytes += 1;
    var changed_limit = try createFingerprint(
        std.testing.allocator,
        lock.lock,
        "amd64",
        "0.3.0",
        "/runner/cache",
        changed_limit_policy,
    );
    defer changed_limit.deinit();
    try std.testing.expect(!std.mem.eql(u8, first.primary_key, changed_limit.primary_key));

    var changed_lock = try testLock(std.testing.allocator, @splat(7), 10, policy);
    defer changed_lock.deinit();
    var changed_lock_fingerprint = try createFingerprint(
        std.testing.allocator,
        changed_lock.lock,
        "amd64",
        "0.3.0",
        "/runner/cache",
        policy,
    );
    defer changed_lock_fingerprint.deinit();
    try std.testing.expectEqualStrings(first.restore_prefix, changed_lock_fingerprint.restore_prefix);
    try std.testing.expect(!std.mem.eql(u8, first.primary_key, changed_lock_fingerprint.primary_key));

    var arm_lock = try testLockForArchitecture(
        std.testing.allocator,
        @splat(6),
        10,
        policy,
        "arm64",
    );
    defer arm_lock.deinit();
    var arm_fingerprint = try createFingerprint(
        std.testing.allocator,
        arm_lock.lock,
        "arm64",
        "0.3.0",
        "/runner/cache",
        policy,
    );
    defer arm_fingerprint.deinit();
    try std.testing.expect(!std.mem.eql(u8, first.primary_key, arm_fingerprint.primary_key));

    var first_foreign = policy;
    first_foreign.foreign_architectures = &.{"arm64"};
    var foreign_a = try createFingerprint(
        std.testing.allocator,
        lock.lock,
        "amd64",
        "0.3.0",
        "/runner/cache",
        first_foreign,
    );
    defer foreign_a.deinit();
    try std.testing.expect(!std.mem.eql(u8, first.primary_key, foreign_a.primary_key));
}

test "package_cache_workflow.test.fingerprint rejects architecture policy and duplicate object drift" {
    const policy: Policy = .{};
    var lock = try testLock(std.testing.allocator, @splat(6), 10, policy);
    defer lock.deinit();
    try std.testing.expectError(error.ArchitectureMismatch, createFingerprint(
        std.testing.allocator,
        lock.lock,
        "arm64",
        "0.3.0",
        "/runner/cache",
        policy,
    ));
    var wrong_policy = policy;
    wrong_policy.recommends = true;
    try std.testing.expectError(error.LockPolicyMismatch, createFingerprint(
        std.testing.allocator,
        lock.lock,
        "amd64",
        "0.3.0",
        "/runner/cache",
        wrong_policy,
    ));

    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(1);
    var duplicate = try exact_lock.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(2),
        .policy_sha256 = solverPolicyDigest(false, false, .strict_priority),
        .repositories = &.{.{
            .id = repository_id,
            .snapshot_sha256 = snapshot,
            .release_sha256 = @splat(3),
            .index_sha256 = @splat(4),
            .signer_fingerprints = &.{@splat(5)},
        }},
        .packages = &.{
            .{ .name = "one", .version = "1", .architecture = "amd64", .repository_id = repository_id, .repository_snapshot_sha256 = snapshot, .sha256 = @splat(9), .declared_size = 1, .retention = .requested, .dpkg_selection_hold = false },
            .{ .name = "two", .version = "1", .architecture = "amd64", .repository_id = repository_id, .repository_snapshot_sha256 = snapshot, .sha256 = @splat(9), .declared_size = 1, .retention = .dependency, .dpkg_selection_hold = false },
        },
        .authenticated_metadata = true,
    });
    defer duplicate.deinit();
    try std.testing.expectError(error.DuplicatePackageDigest, createFingerprint(
        std.testing.allocator,
        duplicate.lock,
        "amd64",
        "0.3.0",
        "/runner/cache",
        policy,
    ));
}

test "package_cache_workflow.test.fingerprint JSON excludes secret and source path material" {
    const policy: Policy = .{};
    var lock = try testLock(std.testing.allocator, @splat(6), 10, policy);
    defer lock.deinit();
    var value = try createFingerprint(
        std.testing.allocator,
        lock.lock,
        "amd64",
        "0.3.0",
        "/runner/cache",
        policy,
    );
    defer value.deinit();
    const json = try value.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "credential") == null);
    try std.testing.expect(std.mem.indexOf(u8, value.primary_key, "/runner/cache") == null);
    try std.testing.expect(std.mem.startsWith(u8, value.primary_key, "debz-package-cas-v1-amd64-"));
}

const TestTransport = struct {
    payloads: []const []const u8 = &.{},
    calls: usize = 0,
    now_ms: u64 = 0,

    fn dependencies(self: *TestTransport) repository_acquisition.Dependencies {
        return .{
            .transport = .{ .context = self, .requestFn = request },
            .files = .{ .context = self, .readFn = readFile },
            .clock = .{ .context = self, .nowMsFn = nowMs, .sleepMsFn = sleepMs },
        };
    }

    fn request(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        value: repository_acquisition.HttpRequest,
    ) !repository_acquisition.HttpResponse {
        const self: *TestTransport = @ptrCast(@alignCast(context.?));
        if (self.calls >= self.payloads.len) return error.UnexpectedTransport;
        const payload = self.payloads[self.calls];
        self.calls += 1;
        if (payload.len > value.max_response_bytes) return error.ResponseTooLarge;
        return .{
            .status = 200,
            .body = try allocator.dupe(u8, payload),
            .location = null,
        };
    }

    fn readFile(
        _: ?*anyopaque,
        _: std.mem.Allocator,
        _: []const u8,
        _: usize,
        _: repository_acquisition.Deadlines,
    ) !repository_acquisition.FileRead {
        return error.FileNotFound;
    }

    fn nowMs(context: ?*anyopaque) u64 {
        return @as(*TestTransport, @ptrCast(@alignCast(context.?))).now_ms;
    }

    fn sleepMs(context: ?*anyopaque, milliseconds: u64) !void {
        @as(*TestTransport, @ptrCast(@alignCast(context.?))).now_ms += milliseconds;
    }
};

const TestRepository = struct {
    index_bytes: []u8,
    index: packages_index.Index,
    lock: exact_lock.OwnedLock,
    view: RepositoryView,

    fn deinit(self: *TestRepository, allocator: std.mem.Allocator) void {
        self.lock.deinit();
        self.index.deinit();
        allocator.free(self.index_bytes);
        self.* = undefined;
    }
};

fn testRepository(allocator: std.mem.Allocator, payload: []const u8) !TestRepository {
    const digest = package_acquisition.Digest.of(payload);
    var digest_hex: [64]u8 = undefined;
    digest.formatHex(&digest_hex);
    const index_bytes = try std.fmt.allocPrint(
        allocator,
        \\Package: packages-microsoft-prod
        \\Version: 1.1
        \\Architecture: all
        \\Description: package cache workflow fixture
        \\Filename: pool/main/p/packages-microsoft-prod_1.1_all.deb
        \\Size: {d}
        \\SHA256: {s}
        \\
    ,
        .{ payload.len, &digest_hex },
    );
    errdefer allocator.free(index_bytes);
    const repository_id: source.RepositoryId = .{ .bytes = @splat('a') };
    var index = switch (try packages_index.parseBorrowed(allocator, index_bytes, .{
        .repository_id = repository_id,
        .component = "main",
        .architecture = "amd64",
        .source_location = "dists/stable/main/binary-amd64/Packages",
    }, .{})) {
        .index => |value| value,
        .diagnostic => return error.InvalidTestIndex,
    };
    errdefer index.deinit();
    var repository = solver.RepositoryInput.trustedTest(repository_id, 500, &index);
    repository.eligibility = .verified_refresh;
    repository.authenticated_snapshot_sha256 = @splat(1);
    const policy: Policy = .{};
    var lock = try exact_lock.create(allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(2),
        .policy_sha256 = solverPolicyDigest(
            policy.recommends,
            policy.allow_downgrade,
            policy.repository_policy,
        ),
        .repositories = &.{.{
            .id = repository_id.bytes,
            .snapshot_sha256 = @splat(1),
            .release_sha256 = @splat(3),
            .index_sha256 = @splat(4),
            .signer_fingerprints = &.{@splat(5)},
        }},
        .packages = &.{.{
            .name = "packages-microsoft-prod",
            .version = "1.1",
            .architecture = "all",
            .repository_id = repository_id.bytes,
            .repository_snapshot_sha256 = @splat(1),
            .sha256 = digest.bytes,
            .declared_size = payload.len,
            .retention = .requested,
            .dpkg_selection_hold = false,
        }},
        .authenticated_metadata = true,
    });
    errdefer lock.deinit();
    return .{
        .index_bytes = index_bytes,
        .index = index,
        .lock = lock,
        .view = .{
            .input = repository,
            .base_uri = try repository_acquisition.Uri.parse("https://packages.example/repository"),
            .release_sha256 = @splat(3),
            .index_sha256 = @splat(4),
            .signer_fingerprint = @splat(5),
        },
    };
}

test "package_cache_workflow.test.prepare covers cold exact corrupt repair and bounded GC" {
    const payload = @embedFile("fixtures/packages-microsoft-prod-depends_1.1_all.deb");
    var repository = try testRepository(std.testing.allocator, payload);
    defer repository.deinit(std.testing.allocator);
    // The view stores a pointer to the stack index, so refresh it after moving
    // TestRepository into its final variable.
    repository.view.input.packages = &repository.index;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try package_acquisition.Cache.initFromDir(std.testing.io, tmp.dir, .{
        .maximum_object_bytes = 1024 * 1024,
    });
    defer cache.deinit();
    var exact_restore_lock = try cache.acquireWriter(10);
    try std.testing.expectError(error.CorruptObject, preflight(
        std.testing.allocator,
        repository.lock.lock,
        &cache,
        .{ .restored_cache = .exact, .limits = .{
            .maximum_package_bytes = 1024 * 1024,
            .maximum_total_package_bytes = 1024 * 1024,
            .maximum_lock_packages = 10,
            .maximum_staging_entries = 10,
            .maximum_gc_directory_entries = 10,
            .maximum_gc_objects_scanned = 10,
            .maximum_gc_objects_deleted = 10,
            .maximum_gc_bytes_deleted = 1024,
        } },
        &exact_restore_lock,
    ));
    const repairable_missing = try preflight(
        std.testing.allocator,
        repository.lock.lock,
        &cache,
        .{ .restored_cache = .exact, .corrupt_cache = .repair_online, .limits = .{
            .maximum_package_bytes = 1024 * 1024,
            .maximum_total_package_bytes = 1024 * 1024,
            .maximum_lock_packages = 10,
            .maximum_staging_entries = 10,
            .maximum_gc_directory_entries = 10,
            .maximum_gc_objects_scanned = 10,
            .maximum_gc_objects_deleted = 10,
            .maximum_gc_bytes_deleted = 1024,
        } },
        &exact_restore_lock,
    );
    try std.testing.expectEqual(@as(usize, 1), repairable_missing.missing);
    exact_restore_lock.release();

    var extra_view = repository.view;
    extra_view.input.repository_id = .{ .bytes = @splat('b') };
    var bounded_transport: TestTransport = .{};
    try std.testing.expectError(error.TooManyRepositoryRecords, prepare(std.testing.allocator, .{
        .lock = &repository.lock.lock,
        .cache = &cache,
        .repositories = &.{ repository.view, extra_view },
        .architecture = "amd64",
        .debz_version = "0.3.0",
        .cache_root = "/runner/cache",
        .policy = .{ .limits = .{
            .maximum_package_bytes = 1024 * 1024,
            .maximum_total_package_bytes = 1024 * 1024,
            .maximum_lock_packages = 10,
            .maximum_repository_records = 1,
            .maximum_staging_entries = 10,
            .maximum_gc_directory_entries = 10,
            .maximum_gc_objects_scanned = 10,
            .maximum_gc_objects_deleted = 10,
            .maximum_gc_bytes_deleted = 1024,
        } },
        .acquisition = bounded_transport.dependencies(),
    }));
    try std.testing.expectEqual(@as(usize, 0), bounded_transport.calls);

    const unrelated = package_acquisition.Digest.of("unrelated");
    try cache.publish(
        std.testing.allocator,
        unrelated,
        "unrelated".len,
        "unrelated",
        .fail_fast,
        .{},
    );
    var online: TestTransport = .{ .payloads = &.{payload} };
    var cold = try prepare(std.testing.allocator, .{
        .lock = &repository.lock.lock,
        .cache = &cache,
        .repositories = &.{repository.view},
        .architecture = "amd64",
        .debz_version = "0.3.0",
        .cache_root = "/runner/cache",
        .policy = .{ .limits = .{
            .maximum_package_bytes = 1024 * 1024,
            .maximum_total_package_bytes = 1024 * 1024,
            .maximum_lock_packages = 10,
            .maximum_staging_entries = 10,
            .maximum_gc_directory_entries = 10,
            .maximum_gc_objects_scanned = 10,
            .maximum_gc_objects_deleted = 10,
            .maximum_gc_bytes_deleted = 1024,
        } },
        .acquisition = online.dependencies(),
    });
    defer cold.deinit();
    try std.testing.expectEqual(@as(usize, 1), cold.downloaded_count);
    try std.testing.expectEqual(@as(usize, 0), cold.reused_count);
    try std.testing.expectEqual(@as(usize, 1), cold.gc_deleted);
    try std.testing.expectEqual(@as(usize, 1), online.calls);

    var no_network: TestTransport = .{};
    var exact = try prepare(std.testing.allocator, .{
        .lock = &repository.lock.lock,
        .cache = &cache,
        .repositories = &.{repository.view},
        .architecture = "amd64",
        .debz_version = "0.3.0",
        .cache_root = "/runner/cache",
        .policy = .{ .limits = .{
            .maximum_package_bytes = 1024 * 1024,
            .maximum_total_package_bytes = 1024 * 1024,
            .maximum_lock_packages = 10,
            .maximum_staging_entries = 10,
            .maximum_gc_directory_entries = 10,
            .maximum_gc_objects_scanned = 10,
            .maximum_gc_objects_deleted = 10,
            .maximum_gc_bytes_deleted = 1024,
        } },
        .acquisition = no_network.dependencies(),
    });
    defer exact.deinit();
    try std.testing.expectEqual(@as(usize, 0), exact.downloaded_count);
    try std.testing.expectEqual(@as(usize, 1), exact.reused_count);
    try std.testing.expectEqual(@as(usize, 0), no_network.calls);

    var name: [64]u8 = undefined;
    const package_digest: package_acquisition.Digest = .{
        .bytes = repository.lock.lock.packages[0].sha256,
    };
    package_digest.formatHex(&name);
    try cache.objects.writeFile(std.testing.io, .{ .sub_path = &name, .data = "corrupt" });
    try std.testing.expectError(error.CorruptObject, prepare(std.testing.allocator, .{
        .lock = &repository.lock.lock,
        .cache = &cache,
        .repositories = &.{repository.view},
        .architecture = "amd64",
        .debz_version = "0.3.0",
        .cache_root = "/runner/cache",
        .policy = .{ .offline = true, .limits = .{
            .maximum_package_bytes = 1024 * 1024,
            .maximum_total_package_bytes = 1024 * 1024,
            .maximum_lock_packages = 10,
            .maximum_staging_entries = 10,
            .maximum_gc_directory_entries = 10,
            .maximum_gc_objects_scanned = 10,
            .maximum_gc_objects_deleted = 10,
            .maximum_gc_bytes_deleted = 1024,
        } },
        .acquisition = no_network.dependencies(),
    }));

    var repair_transport: TestTransport = .{ .payloads = &.{payload} };
    var repaired = try prepare(std.testing.allocator, .{
        .lock = &repository.lock.lock,
        .cache = &cache,
        .repositories = &.{repository.view},
        .architecture = "amd64",
        .debz_version = "0.3.0",
        .cache_root = "/runner/cache",
        .policy = .{ .corrupt_cache = .repair_online, .limits = .{
            .maximum_package_bytes = 1024 * 1024,
            .maximum_total_package_bytes = 1024 * 1024,
            .maximum_lock_packages = 10,
            .maximum_staging_entries = 10,
            .maximum_gc_directory_entries = 10,
            .maximum_gc_objects_scanned = 10,
            .maximum_gc_objects_deleted = 10,
            .maximum_gc_bytes_deleted = 1024,
        } },
        .acquisition = repair_transport.dependencies(),
    });
    defer repaired.deinit();
    try std.testing.expectEqual(@as(usize, 1), repaired.downloaded_count);
    try std.testing.expectEqual(@as(usize, 1), repair_transport.calls);

    var wrong_view = repository.view;
    wrong_view.release_sha256[0] ^= 1;
    try std.testing.expectError(error.RepositoryEvidenceMismatch, prepare(std.testing.allocator, .{
        .lock = &repository.lock.lock,
        .cache = &cache,
        .repositories = &.{wrong_view},
        .architecture = "amd64",
        .debz_version = "0.3.0",
        .cache_root = "/runner/cache",
        .policy = .{ .offline = true, .limits = .{
            .maximum_package_bytes = 1024 * 1024,
            .maximum_total_package_bytes = 1024 * 1024,
            .maximum_lock_packages = 10,
            .maximum_staging_entries = 10,
            .maximum_gc_directory_entries = 10,
            .maximum_gc_objects_scanned = 10,
            .maximum_gc_objects_deleted = 10,
            .maximum_gc_bytes_deleted = 1024,
        } },
        .acquisition = no_network.dependencies(),
    }));

    try cache.staging.writeFile(std.testing.io, .{ .sub_path = "one", .data = "partial" });
    try cache.staging.writeFile(std.testing.io, .{ .sub_path = "two", .data = "partial" });
    try std.testing.expectError(error.CleanupIncomplete, prepare(std.testing.allocator, .{
        .lock = &repository.lock.lock,
        .cache = &cache,
        .repositories = &.{repository.view},
        .architecture = "amd64",
        .debz_version = "0.3.0",
        .cache_root = "/runner/cache",
        .policy = .{ .offline = true, .limits = .{
            .maximum_package_bytes = 1024 * 1024,
            .maximum_total_package_bytes = 1024 * 1024,
            .maximum_lock_packages = 10,
            .maximum_staging_entries = 1,
            .maximum_gc_directory_entries = 10,
            .maximum_gc_objects_scanned = 10,
            .maximum_gc_objects_deleted = 10,
            .maximum_gc_bytes_deleted = 1024,
        } },
        .acquisition = no_network.dependencies(),
    }));
    const cleaned = try cache.cleanupStaging(std.testing.allocator, 10, .fail_fast);
    try std.testing.expect(cleaned.complete);

    try cache.objects.writeFile(std.testing.io, .{
        .sub_path = "not-a-digest",
        .data = "untrusted",
    });
    try std.testing.expectError(error.GarbageCollectionIncomplete, prepare(std.testing.allocator, .{
        .lock = &repository.lock.lock,
        .cache = &cache,
        .repositories = &.{repository.view},
        .architecture = "amd64",
        .debz_version = "0.3.0",
        .cache_root = "/runner/cache",
        .policy = .{ .offline = true, .limits = .{
            .maximum_package_bytes = 1024 * 1024,
            .maximum_total_package_bytes = 1024 * 1024,
            .maximum_lock_packages = 10,
            .maximum_staging_entries = 10,
            .maximum_gc_directory_entries = 10,
            .maximum_gc_objects_scanned = 10,
            .maximum_gc_objects_deleted = 10,
            .maximum_gc_bytes_deleted = 1024,
        } },
        .acquisition = no_network.dependencies(),
    }));
}

test "package_cache_workflow.test.prepare rejects digest-valid invalid Debian payloads" {
    const payload = "not a Debian archive";
    var repository = try testRepository(std.testing.allocator, payload);
    defer repository.deinit(std.testing.allocator);
    repository.view.input.packages = &repository.index;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try package_acquisition.Cache.initFromDir(std.testing.io, tmp.dir, .{
        .maximum_object_bytes = 1024,
    });
    defer cache.deinit();
    var transport: TestTransport = .{ .payloads = &.{payload} };
    try std.testing.expectError(error.InvalidPackagePayload, prepare(std.testing.allocator, .{
        .lock = &repository.lock.lock,
        .cache = &cache,
        .repositories = &.{repository.view},
        .architecture = "amd64",
        .debz_version = "0.3.0",
        .cache_root = "/runner/cache",
        .policy = .{ .limits = .{
            .maximum_package_bytes = 1024,
            .maximum_total_package_bytes = 1024,
            .maximum_lock_packages = 10,
            .maximum_staging_entries = 10,
            .maximum_gc_directory_entries = 10,
            .maximum_gc_objects_scanned = 10,
            .maximum_gc_objects_deleted = 10,
            .maximum_gc_bytes_deleted = 1024,
        } },
        .acquisition = transport.dependencies(),
    }));
    try std.testing.expectEqual(@as(usize, 1), transport.calls);
}

test "package_cache_workflow.test.preflight rejects directory symlink and FIFO objects" {
    const payload = @embedFile("fixtures/packages-microsoft-prod-depends_1.1_all.deb");
    var repository = try testRepository(std.testing.allocator, payload);
    defer repository.deinit(std.testing.allocator);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try package_acquisition.Cache.initFromDir(std.testing.io, tmp.dir, .{
        .maximum_object_bytes = 1024 * 1024,
    });
    defer cache.deinit();
    const digest: package_acquisition.Digest = .{
        .bytes = repository.lock.lock.packages[0].sha256,
    };
    var name: [64]u8 = undefined;
    digest.formatHex(&name);
    var policy: Policy = .{
        .offline = true,
        .restored_cache = .exact,
    };
    policy.limits.maximum_package_bytes = 1024 * 1024;
    var writer = try cache.acquireWriter(10);
    defer writer.release();

    try cache.objects.createDir(std.testing.io, &name, .default_dir);
    try std.testing.expectError(error.CorruptObject, preflight(
        std.testing.allocator,
        repository.lock.lock,
        &cache,
        policy,
        &writer,
    ));
    try cache.objects.deleteDir(std.testing.io, &name);

    try cache.objects.symLink(std.testing.io, "../../writer.lock", &name, .{});
    try std.testing.expectError(error.CorruptObject, preflight(
        std.testing.allocator,
        repository.lock.lock,
        &cache,
        policy,
        &writer,
    ));
    try cache.objects.deleteFile(std.testing.io, &name);

    if (builtin.os.tag == .linux) {
        var name_z: [65:0]u8 = undefined;
        @memcpy(name_z[0..64], &name);
        name_z[64] = 0;
        const result = std.os.linux.mknodat(
            cache.objects.handle,
            &name_z,
            std.os.linux.S.IFIFO | 0o600,
            0,
        );
        if (std.posix.errno(result) != .SUCCESS) return error.Unexpected;
        try std.testing.expectError(error.CorruptObject, preflight(
            std.testing.allocator,
            repository.lock.lock,
            &cache,
            policy,
            &writer,
        ));
    }
}
