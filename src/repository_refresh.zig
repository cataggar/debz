const std = @import("std");
const acquisition = @import("repository_acquisition.zig");
const cache_module = @import("metadata_cache.zig");
const decompression = @import("metadata_decompression.zig");
const packages_index = @import("packages_index.zig");
const release_metadata = @import("release_metadata.zig");
const source = @import("source.zig");

const snapshot_magic = "debz-repository-snapshot-v1";
const snapshot_id = cache_module.SnapshotId{ .value = "repository-refresh-v1" };
const header_size = snapshot_magic.len + 1 + 8 * 7 + 4 * 3 + 32 * 2 + 6;

pub const Repository = struct {
    id: source.RepositoryId,
    base_uri: acquisition.Uri,
    suite: []const u8,
    component: []const u8,
    architecture: []const u8,
};

pub const Clock = struct {
    context: ?*anyopaque,
    nowUnixFn: *const fn (?*anyopaque) i64,

    pub fn nowUnix(self: Clock) i64 {
        return self.nowUnixFn(self.context);
    }
};

pub const Compression = enum(u8) {
    xz,
    gzip,
    zstd,
    uncompressed,

    fn suffix(self: Compression) []const u8 {
        return switch (self) {
            .xz => ".xz",
            .gzip => ".gz",
            .zstd => ".zst",
            .uncompressed => "",
        };
    }
};

pub const ByHashFallback = enum { disabled, not_found_only };
pub const Mode = enum { online, cache_only };
pub const ExpiryPolicy = enum { require_valid_until, allow_missing_valid_until };

pub const RefreshPolicy = struct {
    mode: Mode,
    compression_order: []const Compression,
    by_hash_fallback: ByHashFallback,
    maximum_future_seconds: u64,
    expiry_policy: ExpiryPolicy,
    expiry_grace_seconds: u64 = 0,
    release_limits: release_metadata.Limits = .{},
    packages_options: packages_index.Options = .{},
    maximum_compressed_bytes: usize,
    maximum_decompressed_bytes: usize,
    maximum_decoder_memory: u64,
    cache_publish_options: cache_module.PublishOptions = .{},
};

pub const AcquisitionPolicy = struct {
    proxy: acquisition.ProxyPolicy = .direct,
    deadlines: acquisition.Deadlines,
    redirect_limit: u16,
    retry: acquisition.RetryPolicy = .{},
    credentials: acquisition.CredentialsProvider = .none,
    maximum_release_bytes: usize,
};

pub const VerifiedRelease = struct {
    bytes: []const u8,
    redacted_effective_uri: []const u8,
    kind: enum { in_release, detached_release },
};

/// Plain Release bytes have digest integrity only. A later OpenPGP layer can
/// supply already-verified bytes without changing the refresh mechanics.
pub const ReleaseInput = union(enum) {
    acquire_plain,
    verified: VerifiedRelease,
};

pub const AuthenticationStatus = enum(u8) { unauthenticated, openpgp_verified };
pub const MetadataSource = enum(u8) { network, cache, supplied };

pub const PolicyDecisions = struct {
    release_date_unix: i64,
    valid_until_unix: ?i64,
    future_date_accepted: bool,
    valid_until_required: bool,
    acquire_by_hash_advertised: bool,
    acquire_by_hash_used: bool,
    fallback_used: bool,
};

pub const Provenance = struct {
    repository_id: source.RepositoryId,
    release_uri: []const u8,
    index_uri: []const u8,
    release_digest: cache_module.Digest,
    index_digest: cache_module.Digest,
    selected_path: []const u8,
    compression: Compression,
    refreshed_at_unix: i64,
    source: MetadataSource,
    authentication: AuthenticationStatus,
    policy: PolicyDecisions,
};

pub const Result = struct {
    bytes: []u8,
    packages_bytes: []u8,
    release: release_metadata.ReleaseMetadata,
    packages: packages_index.Index,
    provenance: Provenance,
    allocator: std.mem.Allocator,

    pub fn solverEligible(self: *const Result) bool {
        return self.provenance.authentication == .openpgp_verified;
    }

    pub fn deinit(self: *Result) void {
        self.packages.deinit();
        self.release.deinit();
        self.allocator.free(self.packages_bytes);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const Dependencies = struct {
    acquisition: acquisition.Dependencies,
    /// Must be initialized by the caller from its explicit cache root.
    cache: *cache_module.Cache,
    clock: Clock,
};

pub const Error = error{
    InvalidConfiguration,
    ReleaseParse,
    ReleaseIdentityMismatch,
    ReleaseMissingDate,
    ReleaseDateInFuture,
    ReleaseMissingValidUntil,
    ReleaseExpired,
    ReleaseValidityInverted,
    IndexNotFound,
    IndexSizeMismatch,
    IndexDigestMismatch,
    PackagesParse,
    CorruptSnapshot,
};

pub fn refresh(
    allocator: std.mem.Allocator,
    repository: Repository,
    release_input: ReleaseInput,
    acquisition_policy: AcquisitionPolicy,
    refresh_policy: RefreshPolicy,
    dependencies: Dependencies,
) !Result {
    try validateConfiguration(repository, acquisition_policy, refresh_policy);
    if (refresh_policy.mode == .cache_only) {
        var record = try dependencies.cache.lookup(
            allocator,
            .{ .value = repository.id.slice() },
            snapshot_id,
        );
        errdefer record.deinit();
        const cached_authentication: AuthenticationStatus = switch (record.provenance.verification) {
            .unauthenticated_release => .unauthenticated,
            .in_release, .detached_release => .openpgp_verified,
            .trusted_snapshot => return error.CorruptSnapshot,
        };
        const snapshot_bytes = record.bytes;
        record.bytes = &.{};
        const result = try loadSnapshot(
            allocator,
            snapshot_bytes,
            repository,
            refresh_policy,
            dependencies.clock.nowUnix(),
            .cache,
        );
        if (result.provenance.authentication != cached_authentication) {
            var invalid = result;
            invalid.deinit();
            return error.CorruptSnapshot;
        }
        return result;
    }

    const refreshed_at = dependencies.clock.nowUnix();
    var release_bytes: []const u8 = undefined;
    var release_owned: ?acquisition.Result = null;
    defer if (release_owned) |*value| value.deinit(allocator);
    var release_uri: []const u8 = undefined;
    var release_uri_owned: ?[]u8 = null;
    defer if (release_uri_owned) |value| allocator.free(value);
    var authentication: AuthenticationStatus = .unauthenticated;
    var cache_verification: cache_module.VerificationKind = .unauthenticated_release;
    var origin_source: MetadataSource = .network;

    switch (release_input) {
        .acquire_plain => {
            const uri_text = try repositoryUri(allocator, repository, "Release");
            defer allocator.free(uri_text);
            const acquired = try acquisition.acquire(allocator, .{
                .uri = try acquisition.Uri.parse(uri_text),
                .proxy = acquisition_policy.proxy,
                .deadlines = acquisition_policy.deadlines,
                .redirect_limit = acquisition_policy.redirect_limit,
                .retry = acquisition_policy.retry,
                .max_response_bytes = acquisition_policy.maximum_release_bytes,
                .credentials = acquisition_policy.credentials,
            }, dependencies.acquisition);
            release_bytes = acquired.bytes;
            release_uri = acquired.provenance.effective_uri;
            release_owned = acquired;
        },
        .verified => |verified| {
            if (verified.bytes.len > acquisition_policy.maximum_release_bytes or
                verified.redacted_effective_uri.len == 0)
                return error.InvalidConfiguration;
            release_bytes = verified.bytes;
            const supplied_uri = acquisition.Uri.parse(verified.redacted_effective_uri) catch
                return error.InvalidConfiguration;
            release_uri_owned = try acquisition.redactUri(allocator, supplied_uri);
            release_uri = release_uri_owned.?;
            authentication = .openpgp_verified;
            cache_verification = switch (verified.kind) {
                .in_release => .in_release,
                .detached_release => .detached_release,
            };
            origin_source = .supplied;
        },
    }

    var parsed_release = try parseRelease(
        allocator,
        release_bytes,
        refresh_policy.release_limits,
    );
    defer parsed_release.deinit();
    const release_policy = try validateRelease(
        &parsed_release,
        repository,
        refresh_policy,
        refreshed_at,
    );
    const selected = try selectIndex(
        &parsed_release,
        repository,
        refresh_policy.compression_order,
    );
    if (selected.entry.size > refresh_policy.maximum_compressed_bytes)
        return decompression.Error.InputLimitExceeded;

    const regular_uri = try repositoryUri(allocator, repository, selected.entry.path.value);
    defer allocator.free(regular_uri);
    var by_hash_uri: ?[]u8 = null;
    defer if (by_hash_uri) |value| allocator.free(value);
    const advertised = parsed_release.acquire_by_hash != null and
        parsed_release.acquire_by_hash.?.value;
    if (advertised) by_hash_uri = try byHashUri(allocator, repository, selected.entry);

    var index_acquired: acquisition.Result = undefined;
    var fallback_used = false;
    if (by_hash_uri) |uri_text| {
        index_acquired = acquisition.acquire(
            allocator,
            indexRequest(
                try acquisition.Uri.parse(uri_text),
                acquisition_policy,
                refresh_policy.maximum_compressed_bytes,
            ),
            dependencies.acquisition,
        ) catch |err| switch (err) {
            error.NotFound, error.FileNotFound => if (refresh_policy.by_hash_fallback == .not_found_only) blk: {
                fallback_used = true;
                break :blk try acquisition.acquire(
                    allocator,
                    indexRequest(
                        try acquisition.Uri.parse(regular_uri),
                        acquisition_policy,
                        refresh_policy.maximum_compressed_bytes,
                    ),
                    dependencies.acquisition,
                );
            } else return err,
            else => |other| return other,
        };
    } else {
        index_acquired = try acquisition.acquire(
            allocator,
            indexRequest(
                try acquisition.Uri.parse(regular_uri),
                acquisition_policy,
                refresh_policy.maximum_compressed_bytes,
            ),
            dependencies.acquisition,
        );
    }
    defer index_acquired.deinit(allocator);

    try verifyIndexBytes(selected.entry, index_acquired.bytes);
    const uncompressed = try decompressIndex(
        allocator,
        selected,
        index_acquired.bytes,
        refresh_policy,
    );
    defer allocator.free(uncompressed);
    var checked_packages = try parsePackages(
        allocator,
        uncompressed,
        repository,
        selected.entry.path.value,
        refresh_policy.packages_options,
    );
    checked_packages.deinit();

    const manifest: SnapshotManifest = .{
        .refreshed_at_unix = refreshed_at,
        .release_date_unix = release_policy.date,
        .valid_until_unix = release_policy.valid_until,
        .release_digest = cache_module.Digest.of(release_bytes),
        .index_digest = cache_module.Digest.of(index_acquired.bytes),
        .authentication = authentication,
        .origin_source = origin_source,
        .compression = selected.compression,
        .future_date_accepted = release_policy.future_date_accepted,
        .valid_until_required = refresh_policy.expiry_policy == .require_valid_until,
        .by_hash_advertised = advertised,
        .by_hash_used = advertised and !fallback_used,
        .fallback_used = fallback_used,
        .selected_path = selected.entry.path.value,
        .release_uri = release_uri,
        .index_uri = index_acquired.provenance.effective_uri,
        .release_bytes = release_bytes,
        .index_bytes = index_acquired.bytes,
    };
    const snapshot = try encodeSnapshot(allocator, manifest);
    defer allocator.free(snapshot);
    const identity: cache_module.ObjectIdentity = .{
        .digest = cache_module.Digest.of(snapshot),
        .size = snapshot.len,
    };
    try dependencies.cache.publish(
        .{ .value = repository.id.slice() },
        snapshot_id,
        .{
            .verification = cache_verification,
            .verified_at_unix = refreshed_at,
            .verifier_input = manifest.release_digest,
        },
        identity,
        snapshot,
        refresh_policy.cache_publish_options,
    );
    return loadSnapshot(
        allocator,
        try allocator.dupe(u8, snapshot),
        repository,
        refresh_policy,
        refreshed_at,
        origin_source,
    );
}

const SelectedIndex = struct {
    entry: release_metadata.Sha256Entry,
    compression: Compression,
    expected_uncompressed_size: ?usize,
};

const ReleasePolicyResult = struct {
    date: i64,
    valid_until: ?i64,
    future_date_accepted: bool,
};

fn validateConfiguration(
    repository: Repository,
    acquisition_policy: AcquisitionPolicy,
    refresh_policy: RefreshPolicy,
) !void {
    if (repository.suite.len == 0 or repository.component.len == 0 or
        repository.architecture.len == 0 or refresh_policy.compression_order.len == 0 or
        acquisition_policy.maximum_release_bytes == 0 or
        refresh_policy.maximum_compressed_bytes == 0 or
        refresh_policy.maximum_decompressed_bytes == 0 or
        refresh_policy.maximum_decoder_memory == 0)
        return error.InvalidConfiguration;
    if (!validPathToken(repository.suite, false) or
        !validPathToken(repository.component, true) or
        !validArchitecture(repository.architecture))
        return error.InvalidConfiguration;
    if (repository.base_uri.user != null or repository.base_uri.password != null or
        repository.base_uri.query != null or repository.base_uri.fragment != null)
        return error.InvalidConfiguration;
    if (!std.ascii.eqlIgnoreCase(repository.base_uri.scheme, "file") and
        !std.ascii.eqlIgnoreCase(repository.base_uri.scheme, "http") and
        !std.ascii.eqlIgnoreCase(repository.base_uri.scheme, "https"))
        return error.InvalidConfiguration;
    var seen: std.EnumSet(Compression) = .initEmpty();
    for (refresh_policy.compression_order) |item| {
        if (seen.contains(item)) return error.InvalidConfiguration;
        seen.insert(item);
    }
}

fn parseRelease(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: release_metadata.Limits,
) !release_metadata.ReleaseMetadata {
    return switch (try release_metadata.parse(allocator, bytes, limits)) {
        .metadata => |metadata| metadata,
        .diagnostic => error.ReleaseParse,
    };
}

fn validateRelease(
    metadata: *const release_metadata.ReleaseMetadata,
    repository: Repository,
    policy: RefreshPolicy,
    now: i64,
) !ReleasePolicyResult {
    const suite = metadata.suite orelse return error.ReleaseIdentityMismatch;
    const codename = metadata.codename orelse return error.ReleaseIdentityMismatch;
    if (!std.mem.eql(u8, repository.suite, suite.value) and
        !std.mem.eql(u8, repository.suite, codename.value))
        return error.ReleaseIdentityMismatch;
    if (!containsLocated(metadata.components, repository.component) or
        !containsLocated(metadata.architectures, repository.architecture))
        return error.ReleaseIdentityMismatch;
    const located_date = metadata.date orelse return error.ReleaseMissingDate;
    const date = timestampUnix(located_date.value);
    const future_limit = saturatingAdd(now, policy.maximum_future_seconds);
    if (date > future_limit) return error.ReleaseDateInFuture;
    const valid_until = if (metadata.valid_until) |value| timestampUnix(value.value) else null;
    if (valid_until == null and policy.expiry_policy == .require_valid_until)
        return error.ReleaseMissingValidUntil;
    if (valid_until) |valid| {
        if (valid < date) return error.ReleaseValidityInverted;
        if (now > saturatingAdd(valid, policy.expiry_grace_seconds))
            return error.ReleaseExpired;
    }
    return .{
        .date = date,
        .valid_until = valid_until,
        .future_date_accepted = date > now,
    };
}

fn selectIndex(
    metadata: *const release_metadata.ReleaseMetadata,
    repository: Repository,
    order: []const Compression,
) !SelectedIndex {
    var base_buffer: [4096]u8 = undefined;
    const base = std.fmt.bufPrint(
        &base_buffer,
        "{s}/binary-{s}/Packages",
        .{ repository.component, repository.architecture },
    ) catch return error.InvalidConfiguration;
    var uncompressed_size: ?usize = null;
    for (metadata.sha256_entries) |entry| {
        if (std.mem.eql(u8, entry.path.value, base)) {
            uncompressed_size = std.math.cast(usize, entry.size) orelse
                return error.InvalidConfiguration;
            break;
        }
    }
    for (order) |compression_kind| {
        var path_buffer: [4104]u8 = undefined;
        const path = std.fmt.bufPrint(
            &path_buffer,
            "{s}{s}",
            .{ base, compression_kind.suffix() },
        ) catch continue;
        for (metadata.sha256_entries) |entry| {
            if (std.mem.eql(u8, entry.path.value, path)) return .{
                .entry = entry,
                .compression = compression_kind,
                .expected_uncompressed_size = if (compression_kind == .uncompressed)
                    std.math.cast(usize, entry.size)
                else
                    uncompressed_size,
            };
        }
    }
    return error.IndexNotFound;
}

fn verifyIndexBytes(entry: release_metadata.Sha256Entry, bytes: []const u8) !void {
    if (bytes.len != entry.size) return error.IndexSizeMismatch;
    const digest = cache_module.Digest.of(bytes);
    if (!std.mem.eql(u8, &digest.bytes, &entry.digest.bytes))
        return error.IndexDigestMismatch;
}

fn decompressIndex(
    allocator: std.mem.Allocator,
    selected: SelectedIndex,
    bytes: []const u8,
    policy: RefreshPolicy,
) ![]u8 {
    if (selected.compression == .uncompressed) {
        if (bytes.len > policy.maximum_decompressed_bytes)
            return decompression.Error.OutputLimitExceeded;
        return allocator.dupe(u8, bytes);
    }
    const kind = try decompression.compressionFromFilename(selected.entry.path.value);
    return decompression.decompress(allocator, kind, bytes, .{
        .maximum_compressed_bytes = policy.maximum_compressed_bytes,
        .maximum_decompressed_bytes = policy.maximum_decompressed_bytes,
        .expected_decompressed_size = selected.expected_uncompressed_size,
        .maximum_decoder_memory = policy.maximum_decoder_memory,
    });
}

fn parsePackages(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    repository: Repository,
    selected_path: []const u8,
    options: packages_index.Options,
) !packages_index.Index {
    return switch (try packages_index.parseBorrowed(allocator, bytes, .{
        .repository_id = repository.id,
        .component = repository.component,
        .architecture = repository.architecture,
        .source_location = selected_path,
    }, options)) {
        .index => |index| index,
        .diagnostic => error.PackagesParse,
    };
}

fn indexRequest(
    uri: acquisition.Uri,
    policy: AcquisitionPolicy,
    maximum_bytes: usize,
) acquisition.Request {
    return .{
        .uri = uri,
        .proxy = policy.proxy,
        .deadlines = policy.deadlines,
        .redirect_limit = policy.redirect_limit,
        .retry = policy.retry,
        .max_response_bytes = maximum_bytes,
        .credentials = policy.credentials,
    };
}

fn repositoryUri(
    allocator: std.mem.Allocator,
    repository: Repository,
    relative: []const u8,
) ![]u8 {
    const base = try acquisition.redactUri(allocator, repository.base_uri);
    defer allocator.free(base);
    return std.fmt.allocPrint(
        allocator,
        "{s}{s}dists/{s}/{s}",
        .{
            base,
            if (std.mem.endsWith(u8, base, "/")) "" else "/",
            repository.suite,
            relative,
        },
    );
}

fn byHashUri(
    allocator: std.mem.Allocator,
    repository: Repository,
    entry: release_metadata.Sha256Entry,
) ![]u8 {
    const slash = std.mem.lastIndexOfScalar(u8, entry.path.value, '/') orelse
        return error.InvalidConfiguration;
    var digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&digest_hex, "{x}", .{entry.digest.bytes}) catch unreachable;
    const relative = try std.fmt.allocPrint(
        allocator,
        "{s}/by-hash/SHA256/{s}",
        .{ entry.path.value[0..slash], &digest_hex },
    );
    defer allocator.free(relative);
    return repositoryUri(allocator, repository, relative);
}

fn containsLocated(values: []const release_metadata.LocatedString, wanted: []const u8) bool {
    for (values) |value| if (std.mem.eql(u8, value.value, wanted)) return true;
    return false;
}

fn validPathToken(value: []const u8, allow_slash: bool) bool {
    var segments = std.mem.splitScalar(u8, value, '/');
    var count: usize = 0;
    while (segments.next()) |segment| {
        count += 1;
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or
            std.mem.eql(u8, segment, ".."))
            return false;
        for (segment) |byte| {
            if (!(std.ascii.isAlphanumeric(byte) or byte == '-' or
                byte == '_' or byte == '.'))
                return false;
        }
    }
    return count == 1 or allow_slash;
}

fn validArchitecture(value: []const u8) bool {
    for (value) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '-')) return false;
    }
    return value.len != 0;
}

fn saturatingAdd(value: i64, seconds: u64) i64 {
    const bounded: i64 = @intCast(@min(seconds, @as(u64, std.math.maxInt(i64))));
    return std.math.add(i64, value, bounded) catch std.math.maxInt(i64);
}

fn timestampUnix(timestamp: release_metadata.Timestamp) i64 {
    const year: i64 = timestamp.year;
    const adjusted_year = year - @intFromBool(timestamp.month <= 2);
    const era = @divFloor(adjusted_year, 400);
    const year_of_era = adjusted_year - era * 400;
    const month: i64 = timestamp.month;
    const shifted_month = month + (if (month > 2) @as(i64, -3) else 9);
    const day_of_year = @divFloor(153 * shifted_month + 2, 5) + timestamp.day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) -
        @divFloor(year_of_era, 100) + day_of_year;
    const days = era * 146097 + day_of_era - 719468;
    return days * 86400 + @as(i64, timestamp.hour) * 3600 +
        @as(i64, timestamp.minute) * 60 + timestamp.second -
        @as(i64, timestamp.utc_offset_minutes) * 60;
}

const SnapshotManifest = struct {
    refreshed_at_unix: i64,
    release_date_unix: i64,
    valid_until_unix: ?i64,
    release_digest: cache_module.Digest,
    index_digest: cache_module.Digest,
    authentication: AuthenticationStatus,
    origin_source: MetadataSource,
    compression: Compression,
    future_date_accepted: bool,
    valid_until_required: bool,
    by_hash_advertised: bool,
    by_hash_used: bool,
    fallback_used: bool,
    selected_path: []const u8,
    release_uri: []const u8,
    index_uri: []const u8,
    release_bytes: []const u8,
    index_bytes: []const u8,
};

fn encodeSnapshot(allocator: std.mem.Allocator, manifest: SnapshotManifest) ![]u8 {
    var total = header_size;
    inline for (.{
        manifest.selected_path.len,
        manifest.release_uri.len,
        manifest.index_uri.len,
        manifest.release_bytes.len,
        manifest.index_bytes.len,
    }) |length| total = std.math.add(usize, total, length) catch
        return error.InvalidConfiguration;
    const bytes = try allocator.alloc(u8, total);
    errdefer allocator.free(bytes);
    var writer: FixedWriter = .{ .bytes = bytes };
    writer.put(snapshot_magic);
    writer.put("\n");
    writer.int(i64, manifest.refreshed_at_unix);
    writer.int(i64, manifest.release_date_unix);
    writer.int(i64, manifest.valid_until_unix orelse 0);
    writer.int(u64, @intCast(manifest.release_bytes.len));
    writer.int(u64, @intCast(manifest.index_bytes.len));
    writer.int(u64, @intCast(manifest.release_uri.len));
    writer.int(u64, @intCast(manifest.index_uri.len));
    writer.int(u32, @intCast(manifest.selected_path.len));
    writer.int(u32, @intFromEnum(manifest.authentication));
    writer.int(u32, @intFromEnum(manifest.compression));
    writer.put(&manifest.release_digest.bytes);
    writer.put(&manifest.index_digest.bytes);
    writer.put(&.{
        @intFromEnum(manifest.origin_source),
        @intFromBool(manifest.valid_until_unix != null),
        @intFromBool(manifest.future_date_accepted),
        @intFromBool(manifest.valid_until_required),
        @intFromBool(manifest.by_hash_advertised),
        (@as(u8, @intFromBool(manifest.by_hash_used)) << 1) |
            @as(u8, @intFromBool(manifest.fallback_used)),
    });
    writer.put(manifest.selected_path);
    writer.put(manifest.release_uri);
    writer.put(manifest.index_uri);
    writer.put(manifest.release_bytes);
    writer.put(manifest.index_bytes);
    std.debug.assert(writer.offset == bytes.len);
    return bytes;
}

fn decodeSnapshot(bytes: []const u8) !SnapshotManifest {
    if (bytes.len < header_size) return error.CorruptSnapshot;
    var reader: FixedReader = .{ .bytes = bytes };
    if (!std.mem.eql(u8, reader.take(snapshot_magic.len), snapshot_magic) or
        !std.mem.eql(u8, reader.take(1), "\n"))
        return error.CorruptSnapshot;
    const refreshed = reader.int(i64);
    const date = reader.int(i64);
    const valid_raw = reader.int(i64);
    const release_len = std.math.cast(usize, reader.int(u64)) orelse
        return error.CorruptSnapshot;
    const index_len = std.math.cast(usize, reader.int(u64)) orelse
        return error.CorruptSnapshot;
    const release_uri_len = std.math.cast(usize, reader.int(u64)) orelse
        return error.CorruptSnapshot;
    const index_uri_len = std.math.cast(usize, reader.int(u64)) orelse
        return error.CorruptSnapshot;
    const path_len = reader.int(u32);
    const authentication: AuthenticationStatus = switch (reader.int(u32)) {
        0 => .unauthenticated,
        1 => .openpgp_verified,
        else => return error.CorruptSnapshot,
    };
    const compression_kind: Compression = switch (reader.int(u32)) {
        0 => .xz,
        1 => .gzip,
        2 => .zstd,
        3 => .uncompressed,
        else => return error.CorruptSnapshot,
    };
    const release_digest: cache_module.Digest = .{ .bytes = reader.array(32) };
    const index_digest: cache_module.Digest = .{ .bytes = reader.array(32) };
    const origin_source: MetadataSource = switch (reader.byte()) {
        0 => .network,
        1 => .cache,
        2 => .supplied,
        else => return error.CorruptSnapshot,
    };
    const has_valid = try boolByte(reader.byte());
    const future = try boolByte(reader.byte());
    const valid_required = try boolByte(reader.byte());
    const advertised = try boolByte(reader.byte());
    const flags = reader.byte();
    if (flags & ~@as(u8, 3) != 0) return error.CorruptSnapshot;
    const selected_path = reader.take(path_len);
    const release_uri = reader.take(release_uri_len);
    const index_uri = reader.take(index_uri_len);
    const release_bytes = reader.take(release_len);
    const index_bytes = reader.take(index_len);
    if (reader.failed or reader.offset != bytes.len or selected_path.len == 0 or
        release_uri.len == 0 or index_uri.len == 0)
        return error.CorruptSnapshot;
    return .{
        .refreshed_at_unix = refreshed,
        .release_date_unix = date,
        .valid_until_unix = if (has_valid) valid_raw else null,
        .release_digest = release_digest,
        .index_digest = index_digest,
        .authentication = authentication,
        .origin_source = origin_source,
        .compression = compression_kind,
        .future_date_accepted = future,
        .valid_until_required = valid_required,
        .by_hash_advertised = advertised,
        .by_hash_used = flags & 2 != 0,
        .fallback_used = flags & 1 != 0,
        .selected_path = selected_path,
        .release_uri = release_uri,
        .index_uri = index_uri,
        .release_bytes = release_bytes,
        .index_bytes = index_bytes,
    };
}

fn loadSnapshot(
    allocator: std.mem.Allocator,
    owned_bytes: []u8,
    repository: Repository,
    policy: RefreshPolicy,
    now: i64,
    source_kind: MetadataSource,
) !Result {
    errdefer allocator.free(owned_bytes);
    const manifest = try decodeSnapshot(owned_bytes);
    if (!cache_module.Digest.of(manifest.release_bytes).eql(manifest.release_digest) or
        !cache_module.Digest.of(manifest.index_bytes).eql(manifest.index_digest))
        return error.CorruptSnapshot;
    var release = try parseRelease(allocator, manifest.release_bytes, policy.release_limits);
    errdefer release.deinit();
    const release_policy = try validateRelease(&release, repository, policy, now);
    const selected = try selectIndex(&release, repository, policy.compression_order);
    if (!std.mem.eql(u8, selected.entry.path.value, manifest.selected_path) or
        selected.compression != manifest.compression)
        return error.CorruptSnapshot;
    try verifyIndexBytes(selected.entry, manifest.index_bytes);
    const uncompressed = try decompressIndex(allocator, selected, manifest.index_bytes, policy);
    errdefer allocator.free(uncompressed);
    var packages = try parsePackages(
        allocator,
        uncompressed,
        repository,
        manifest.selected_path,
        policy.packages_options,
    );
    errdefer packages.deinit();
    if (manifest.release_date_unix != release_policy.date or
        manifest.valid_until_unix != release_policy.valid_until or
        manifest.valid_until_required != (policy.expiry_policy == .require_valid_until))
        return error.CorruptSnapshot;
    return .{
        .bytes = owned_bytes,
        .packages_bytes = uncompressed,
        .release = release,
        .packages = packages,
        .provenance = .{
            .repository_id = repository.id,
            .release_uri = manifest.release_uri,
            .index_uri = manifest.index_uri,
            .release_digest = manifest.release_digest,
            .index_digest = manifest.index_digest,
            .selected_path = manifest.selected_path,
            .compression = manifest.compression,
            .refreshed_at_unix = manifest.refreshed_at_unix,
            .source = source_kind,
            .authentication = manifest.authentication,
            .policy = .{
                .release_date_unix = release_policy.date,
                .valid_until_unix = release_policy.valid_until,
                .future_date_accepted = release_policy.future_date_accepted,
                .valid_until_required = manifest.valid_until_required,
                .acquire_by_hash_advertised = manifest.by_hash_advertised,
                .acquire_by_hash_used = manifest.by_hash_used,
                .fallback_used = manifest.fallback_used,
            },
        },
        .allocator = allocator,
    };
}

fn boolByte(value: u8) !bool {
    return switch (value) {
        0 => false,
        1 => true,
        else => error.CorruptSnapshot,
    };
}

const FixedWriter = struct {
    bytes: []u8,
    offset: usize = 0,

    fn put(self: *FixedWriter, value: []const u8) void {
        @memcpy(self.bytes[self.offset..][0..value.len], value);
        self.offset += value.len;
    }

    fn int(self: *FixedWriter, comptime T: type, value: T) void {
        std.mem.writeInt(T, self.bytes[self.offset..][0..@sizeOf(T)], value, .little);
        self.offset += @sizeOf(T);
    }
};

const FixedReader = struct {
    bytes: []const u8,
    offset: usize = 0,
    failed: bool = false,

    fn take(self: *FixedReader, length: usize) []const u8 {
        const end = std.math.add(usize, self.offset, length) catch {
            self.failed = true;
            return &.{};
        };
        if (end > self.bytes.len) {
            self.failed = true;
            return &.{};
        }
        defer self.offset = end;
        return self.bytes[self.offset..end];
    }

    fn int(self: *FixedReader, comptime T: type) T {
        const value = self.take(@sizeOf(T));
        if (value.len != @sizeOf(T)) return 0;
        return std.mem.readInt(T, value[0..@sizeOf(T)], .little);
    }

    fn array(self: *FixedReader, comptime length: usize) [length]u8 {
        const value = self.take(length);
        if (value.len != length) return @splat(0);
        return value[0..length].*;
    }

    fn byte(self: *FixedReader) u8 {
        const value = self.take(1);
        return if (value.len == 1) value[0] else 0;
    }
};

const test_packages =
    \\Package: hello
    \\Version: 1.0-1
    \\Architecture: amd64
    \\Maintainer: Test <test@example.invalid>
    \\Description: hello
    \\Filename: pool/main/h/hello/hello_1.0-1_amd64.deb
    \\Size: 4
    \\SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    \\
;

const test_packages_wrong_architecture =
    \\Package: hello
    \\Version: 1.0-1
    \\Architecture: arm64
    \\Maintainer: Test <test@example.invalid>
    \\Description: hello
    \\Filename: pool/main/h/hello/hello_1.0-1_arm64.deb
    \\Size: 4
    \\SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    \\
;

const test_packages_gzip = [_]u8{
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x95, 0x8d,
    0x4b, 0x0a, 0xc2, 0x30, 0x18, 0x84, 0xf7, 0x39, 0x45, 0x2e, 0x60, 0x5f,
    0xb6, 0x55, 0x83, 0x88, 0x05, 0x11, 0x37, 0x82, 0x50, 0x71, 0x5b, 0xfe,
    0x26, 0xbf, 0x36, 0x98, 0x47, 0x49, 0xa3, 0x88, 0xa7, 0x37, 0xa4, 0x27,
    0x70, 0x31, 0x03, 0xc3, 0x0c, 0xdf, 0x5c, 0x80, 0x3f, 0xe1, 0x81, 0x8c,
    0x0e, 0xa8, 0x94, 0x25, 0x37, 0x74, 0x93, 0xb4, 0x86, 0xd1, 0x3c, 0xc9,
    0x16, 0x39, 0x69, 0x1c, 0x1f, 0xa4, 0x47, 0xee, 0x5f, 0x2e, 0x4c, 0x40,
    0x8b, 0xba, 0x24, 0x67, 0x90, 0xc6, 0x07, 0xa1, 0x63, 0xf4, 0x8a, 0x93,
    0xa7, 0x5b, 0x1f, 0x7c, 0x8f, 0x1f, 0xd0, 0xa3, 0xc2, 0x44, 0x9a, 0x37,
    0x28, 0x29, 0x76, 0xe4, 0x80, 0x13, 0x77, 0x72, 0xf4, 0x11, 0x37, 0xd3,
    0x8f, 0x52, 0xa1, 0x01, 0x1d, 0x50, 0xa3, 0xb5, 0x2a, 0xd5, 0x81, 0x92,
    0x0e, 0x69, 0xec, 0x66, 0xef, 0xe2, 0x6d, 0x17, 0x8f, 0x12, 0x81, 0x3d,
    0x69, 0xe5, 0x37, 0xac, 0x4b, 0xd2, 0x9e, 0x9a, 0xa2, 0xaa, 0x19, 0xcd,
    0xf2, 0x62, 0x59, 0x56, 0xf5, 0x6a, 0xbd, 0x81, 0x9e, 0x0b, 0xbc, 0xff,
    0x9b, 0xc9, 0x0f, 0x7b, 0xba, 0x25, 0xf4, 0xf0, 0x00, 0x00, 0x00,
};

const TestResponse = struct {
    status: u16,
    body: []const u8,
};

const TestFixture = struct {
    responses: []const TestResponse,
    next_response: usize = 0,
    saw_by_hash: bool = false,
    now_ms: u64 = 0,
    file_bodies: []const []const u8 = &.{},
    next_file: usize = 0,

    fn dependencies(self: *TestFixture) acquisition.Dependencies {
        return .{
            .transport = .{ .context = self, .requestFn = request },
            .files = .{ .context = self, .readFn = readFile },
            .clock = .{ .context = self, .nowMsFn = nowMs, .sleepMsFn = sleepMs },
        };
    }

    fn request(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        request_value: acquisition.HttpRequest,
    ) !acquisition.HttpResponse {
        const self: *TestFixture = @ptrCast(@alignCast(context.?));
        const path = switch (request_value.uri.path) {
            .raw, .percent_encoded => |value| value,
        };
        if (std.mem.indexOf(u8, path, "/by-hash/") != null) self.saw_by_hash = true;
        if (self.next_response >= self.responses.len) return error.ConnectionResetByPeer;
        const response = self.responses[self.next_response];
        self.next_response += 1;
        return .{
            .status = response.status,
            .body = try allocator.dupe(u8, response.body),
        };
    }

    fn readFile(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        _: []const u8,
        limit: usize,
        _: acquisition.Deadlines,
    ) !acquisition.FileRead {
        const self: *TestFixture = @ptrCast(@alignCast(context.?));
        if (self.next_file >= self.file_bodies.len) return error.FileNotFound;
        const body = self.file_bodies[self.next_file];
        self.next_file += 1;
        if (body.len > limit) return error.ResponseTooLarge;
        return .{ .bytes = try allocator.dupe(u8, body), .regular = true };
    }

    fn nowMs(context: ?*anyopaque) u64 {
        const self: *TestFixture = @ptrCast(@alignCast(context.?));
        return self.now_ms;
    }

    fn sleepMs(context: ?*anyopaque, milliseconds: u64) !void {
        const self: *TestFixture = @ptrCast(@alignCast(context.?));
        self.now_ms += milliseconds;
    }
};

fn fixedNow(_: ?*anyopaque) i64 {
    return 1_786_737_600;
}

fn testRepository() !Repository {
    return .{
        .id = .{ .bytes = @splat('a') },
        .base_uri = try acquisition.Uri.parse("https://example.test/repo"),
        .suite = "stable",
        .component = "main",
        .architecture = "amd64",
    };
}

fn testAcquisitionPolicy() AcquisitionPolicy {
    return .{
        .deadlines = .{ .connect_ms = 100, .read_ms = 100, .overall_ms = 1000 },
        .redirect_limit = 0,
        .maximum_release_bytes = 16 * 1024,
    };
}

fn testRefreshPolicy(order: []const Compression) RefreshPolicy {
    return .{
        .mode = .online,
        .compression_order = order,
        .by_hash_fallback = .disabled,
        .maximum_future_seconds = 300,
        .expiry_policy = .require_valid_until,
        .maximum_compressed_bytes = 16 * 1024,
        .maximum_decompressed_bytes = 64 * 1024,
        .maximum_decoder_memory = 4 * 1024 * 1024,
    };
}

fn makeRelease(
    allocator: std.mem.Allocator,
    index_bytes: []const u8,
    path: []const u8,
    acquire_by_hash: bool,
    date: []const u8,
    valid_until: []const u8,
    digest_override: ?[]const u8,
) ![]u8 {
    var digest_hex: [64]u8 = undefined;
    cache_module.Digest.of(index_bytes).formatHex(&digest_hex);
    const digest = digest_override orelse &digest_hex;
    return std.fmt.allocPrint(allocator,
        \\Suite: stable
        \\Codename: bookworm
        \\Date: {s}
        \\Valid-Until: {s}
        \\Architectures: amd64
        \\Components: main
        \\Acquire-By-Hash: {s}
        \\SHA256:
        \\ {s} {d} {s}
        \\
    , .{
        date,
        valid_until,
        if (acquire_by_hash) "yes" else "no",
        digest,
        index_bytes.len,
        path,
    });
}

fn testDependencies(
    fixture: *TestFixture,
    cache: *cache_module.Cache,
) Dependencies {
    return .{
        .acquisition = fixture.dependencies(),
        .cache = cache,
        .clock = .{ .context = null, .nowUnixFn = fixedNow },
    };
}

test "hermetic file acquisition refreshes a complete snapshot" {
    const allocator = std.testing.allocator;
    const release = try makeRelease(
        allocator,
        test_packages,
        "main/binary-amd64/Packages",
        false,
        "Fri, 14 Aug 2026 18:00:00 UTC",
        "Sat, 15 Aug 2026 18:00:00 UTC",
        null,
    );
    defer allocator.free(release);
    var fixture: TestFixture = .{
        .responses = &.{},
        .file_bodies = &.{ release, test_packages },
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try cache_module.Cache.initFromDir(std.testing.io, tmp.dir, .{
        .max_object_bytes = 128 * 1024,
    });
    defer cache.deinit();
    var repository = try testRepository();
    repository.base_uri = try acquisition.Uri.parse("file:///repository");
    var result = try refresh(
        allocator,
        repository,
        .acquire_plain,
        testAcquisitionPolicy(),
        testRefreshPolicy(&.{.uncompressed}),
        testDependencies(&fixture, &cache),
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 2), fixture.next_file);
    try std.testing.expectEqual(@as(usize, 1), result.packages.records.len);
}

test "valid compressed refresh is unauthenticated and offline revalidates cache" {
    const allocator = std.testing.allocator;
    const release = try makeRelease(
        allocator,
        &test_packages_gzip,
        "main/binary-amd64/Packages.gz",
        false,
        "Fri, 14 Aug 2026 18:00:00 UTC",
        "Sat, 15 Aug 2026 18:00:00 UTC",
        null,
    );
    defer allocator.free(release);
    var fixture: TestFixture = .{ .responses = &.{
        .{ .status = 200, .body = release },
        .{ .status = 200, .body = &test_packages_gzip },
    } };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try cache_module.Cache.initFromDir(std.testing.io, tmp.dir, .{
        .max_object_bytes = 128 * 1024,
    });
    defer cache.deinit();
    const repository = try testRepository();
    var policy = testRefreshPolicy(&.{.gzip});
    var result = try refresh(
        allocator,
        repository,
        .acquire_plain,
        testAcquisitionPolicy(),
        policy,
        testDependencies(&fixture, &cache),
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.packages.records.len);
    try std.testing.expectEqual(AuthenticationStatus.unauthenticated, result.provenance.authentication);
    try std.testing.expect(!result.solverEligible());
    try std.testing.expectEqual(MetadataSource.network, result.provenance.source);

    policy.mode = .cache_only;
    var offline_fixture: TestFixture = .{ .responses = &.{} };
    var cached = try refresh(
        allocator,
        repository,
        .acquire_plain,
        testAcquisitionPolicy(),
        policy,
        testDependencies(&offline_fixture, &cache),
    );
    defer cached.deinit();
    try std.testing.expectEqual(MetadataSource.cache, cached.provenance.source);
    try std.testing.expectEqual(@as(usize, 0), offline_fixture.next_response);
}

test "Acquire-By-Hash and explicit not-found fallback policy" {
    const allocator = std.testing.allocator;
    const release = try makeRelease(
        allocator,
        test_packages,
        "main/binary-amd64/Packages",
        true,
        "Fri, 14 Aug 2026 18:00:00 UTC",
        "Sat, 15 Aug 2026 18:00:00 UTC",
        null,
    );
    defer allocator.free(release);
    const repository = try testRepository();

    var direct_fixture: TestFixture = .{ .responses = &.{
        .{ .status = 200, .body = release },
        .{ .status = 200, .body = test_packages },
    } };
    var direct_tmp = std.testing.tmpDir(.{});
    defer direct_tmp.cleanup();
    var direct_cache = try cache_module.Cache.initFromDir(
        std.testing.io,
        direct_tmp.dir,
        .{ .max_object_bytes = 128 * 1024 },
    );
    defer direct_cache.deinit();
    var direct = try refresh(
        allocator,
        repository,
        .acquire_plain,
        testAcquisitionPolicy(),
        testRefreshPolicy(&.{.uncompressed}),
        testDependencies(&direct_fixture, &direct_cache),
    );
    defer direct.deinit();
    try std.testing.expect(direct_fixture.saw_by_hash);
    try std.testing.expect(direct.provenance.policy.acquire_by_hash_used);

    var disabled_fixture: TestFixture = .{ .responses = &.{
        .{ .status = 200, .body = release },
        .{ .status = 404, .body = "" },
    } };
    var disabled_tmp = std.testing.tmpDir(.{});
    defer disabled_tmp.cleanup();
    var disabled_cache = try cache_module.Cache.initFromDir(
        std.testing.io,
        disabled_tmp.dir,
        .{ .max_object_bytes = 128 * 1024 },
    );
    defer disabled_cache.deinit();
    try std.testing.expectError(error.NotFound, refresh(
        allocator,
        repository,
        .acquire_plain,
        testAcquisitionPolicy(),
        testRefreshPolicy(&.{.uncompressed}),
        testDependencies(&disabled_fixture, &disabled_cache),
    ));
    try std.testing.expect(disabled_fixture.saw_by_hash);

    var enabled_fixture: TestFixture = .{ .responses = &.{
        .{ .status = 200, .body = release },
        .{ .status = 404, .body = "" },
        .{ .status = 200, .body = test_packages },
    } };
    var enabled_tmp = std.testing.tmpDir(.{});
    defer enabled_tmp.cleanup();
    var enabled_cache = try cache_module.Cache.initFromDir(
        std.testing.io,
        enabled_tmp.dir,
        .{ .max_object_bytes = 128 * 1024 },
    );
    defer enabled_cache.deinit();
    var enabled_policy = testRefreshPolicy(&.{.uncompressed});
    enabled_policy.by_hash_fallback = .not_found_only;
    var result = try refresh(
        allocator,
        repository,
        .acquire_plain,
        testAcquisitionPolicy(),
        enabled_policy,
        testDependencies(&enabled_fixture, &enabled_cache),
    );
    defer result.deinit();
    try std.testing.expect(result.provenance.policy.fallback_used);
    try std.testing.expect(!result.provenance.policy.acquire_by_hash_used);
}

test "bad digest expiry future date and decompression corruption fail closed" {
    const allocator = std.testing.allocator;
    const repository = try testRepository();
    const cases = [_]struct {
        release: []u8,
        index: []const u8,
        expected: anyerror,
        order: []const Compression,
    }{
        .{
            .release = try makeRelease(
                allocator,
                test_packages,
                "main/binary-amd64/Packages",
                false,
                "Fri, 14 Aug 2026 18:00:00 UTC",
                "Sat, 15 Aug 2026 18:00:00 UTC",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            .index = test_packages,
            .expected = error.IndexDigestMismatch,
            .order = &.{.uncompressed},
        },
        .{
            .release = try makeRelease(
                allocator,
                test_packages,
                "main/binary-amd64/Packages",
                false,
                "Thu, 13 Aug 2026 18:00:00 UTC",
                "Fri, 14 Aug 2026 18:30:00 UTC",
                null,
            ),
            .index = test_packages,
            .expected = error.ReleaseExpired,
            .order = &.{.uncompressed},
        },
        .{
            .release = try makeRelease(
                allocator,
                test_packages,
                "main/binary-amd64/Packages",
                false,
                "Fri, 14 Aug 2026 22:00:00 UTC",
                "Sat, 15 Aug 2026 22:00:00 UTC",
                null,
            ),
            .index = test_packages,
            .expected = error.ReleaseDateInFuture,
            .order = &.{.uncompressed},
        },
        .{
            .release = try makeRelease(
                allocator,
                &.{ 0x1f, 0x8b, 0x00, 0x00 },
                "main/binary-amd64/Packages.gz",
                false,
                "Fri, 14 Aug 2026 18:00:00 UTC",
                "Sat, 15 Aug 2026 18:00:00 UTC",
                null,
            ),
            .index = &.{ 0x1f, 0x8b, 0x00, 0x00 },
            .expected = error.Truncated,
            .order = &.{.gzip},
        },
        .{
            .release = try makeRelease(
                allocator,
                test_packages_wrong_architecture,
                "main/binary-amd64/Packages",
                false,
                "Fri, 14 Aug 2026 18:00:00 UTC",
                "Sat, 15 Aug 2026 18:00:00 UTC",
                null,
            ),
            .index = test_packages_wrong_architecture,
            .expected = error.PackagesParse,
            .order = &.{.uncompressed},
        },
    };
    defer for (cases) |case| allocator.free(case.release);

    for (cases) |case| {
        var fixture: TestFixture = .{ .responses = &.{
            .{ .status = 200, .body = case.release },
            .{ .status = 200, .body = case.index },
        } };
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var cache = try cache_module.Cache.initFromDir(std.testing.io, tmp.dir, .{
            .max_object_bytes = 128 * 1024,
        });
        defer cache.deinit();
        try std.testing.expectError(case.expected, refresh(
            allocator,
            repository,
            .acquire_plain,
            testAcquisitionPolicy(),
            testRefreshPolicy(case.order),
            testDependencies(&fixture, &cache),
        ));
        try std.testing.expectError(error.CacheMiss, cache.lookup(
            allocator,
            .{ .value = repository.id.slice() },
            snapshot_id,
        ));
    }
}

const TestInterrupt = struct {
    fn run(_: ?*anyopaque, point: cache_module.HookPoint) !void {
        if (point == .manifest_staged) return error.Interrupted;
    }
};

test "interrupted publication leaves no snapshot and offline miss fails closed" {
    const allocator = std.testing.allocator;
    const release = try makeRelease(
        allocator,
        test_packages,
        "main/binary-amd64/Packages",
        false,
        "Fri, 14 Aug 2026 18:00:00 UTC",
        "Sat, 15 Aug 2026 18:00:00 UTC",
        null,
    );
    defer allocator.free(release);
    var fixture: TestFixture = .{ .responses = &.{
        .{ .status = 200, .body = release },
        .{ .status = 200, .body = test_packages },
    } };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try cache_module.Cache.initFromDir(std.testing.io, tmp.dir, .{
        .max_object_bytes = 128 * 1024,
    });
    defer cache.deinit();
    const repository = try testRepository();
    var policy = testRefreshPolicy(&.{.uncompressed});
    policy.cache_publish_options.hooks.runFn = TestInterrupt.run;
    try std.testing.expectError(error.Interrupted, refresh(
        allocator,
        repository,
        .acquire_plain,
        testAcquisitionPolicy(),
        policy,
        testDependencies(&fixture, &cache),
    ));
    policy.mode = .cache_only;
    policy.cache_publish_options = .{};
    var offline_fixture: TestFixture = .{ .responses = &.{} };
    try std.testing.expectError(error.CacheMiss, refresh(
        allocator,
        repository,
        .acquire_plain,
        testAcquisitionPolicy(),
        policy,
        testDependencies(&offline_fixture, &cache),
    ));
}
