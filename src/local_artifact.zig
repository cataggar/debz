const std = @import("std");
const repository_acquisition = @import("repository_acquisition.zig");
const package_acquisition = @import("package_acquisition.zig");
const metadata_cache = @import("metadata_cache.zig");
const package_origin = @import("package_origin.zig");

pub const Digest = metadata_cache.Digest;

pub const TrustMode = enum {
    https,
    sha256,
};

pub const Outcome = enum {
    cache_hit,
    acquired,
};

pub const Policy = struct {
    maximum_artifact_bytes: usize,
    proxy: repository_acquisition.ProxyPolicy = .direct,
    deadlines: repository_acquisition.Deadlines,
    redirect_limit: u16,
    retry: repository_acquisition.RetryPolicy = .{},
    credentials: repository_acquisition.CredentialsProvider = .none,
    cache_lock: package_acquisition.LockPolicy = .fail_fast,
};

pub const Request = struct {
    uri: repository_acquisition.Uri,
    expected_sha256: ?Digest = null,
    expected_size: ?u64 = null,
    policy: Policy,
};

pub const Provenance = struct {
    effective_uri: []u8,
    size: u64,
    sha256: Digest,
    cache_key: [64]u8,
    trust_mode: TrustMode,
    outcome: Outcome,
    status: ?u16,
    timing: repository_acquisition.Timing,

    pub fn deinit(self: *Provenance, allocator: std.mem.Allocator) void {
        allocator.free(self.effective_uri);
        self.* = undefined;
    }

    pub fn originEvidence(
        self: Provenance,
        package: []const u8,
        version: []const u8,
        architecture: []const u8,
    ) package_origin.LocalArtifactEvidence {
        return .{
            .artifact_id = package_origin.artifactIdFromSha256(self.sha256.bytes),
            .sha256 = self.sha256.bytes,
            .size = self.size,
            .package = package,
            .version = version,
            .architecture = architecture,
            .acquisition_url = self.effective_uri,
            .trust_mode = switch (self.trust_mode) {
                .sha256 => .pinned_sha256,
                .https => .verified_https,
            },
        };
    }
};

/// Owns the exact acquired bytes. The SHA-256 covers the complete original
/// artifact, including any structurally accepted Debian signature members.
pub const Artifact = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    provenance: Provenance,

    pub fn deinit(self: *Artifact) void {
        self.allocator.free(self.bytes);
        self.provenance.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const Error = error{
    InvalidConfiguration,
    UnsupportedScheme,
    CredentialBearingUri,
    ArtifactTooLarge,
    SizeMismatch,
    DigestMismatch,
};

/// Acquires a local artifact under an explicit initial-trust policy and
/// publishes only verified bytes to the existing package CAS. Unpinned
/// acquisition requires HTTPS. A SHA-256 pin permits HTTPS, HTTP, or file.
pub fn acquire(
    allocator: std.mem.Allocator,
    cache: *package_acquisition.Cache,
    request: Request,
    dependencies: repository_acquisition.Dependencies,
) !Artifact {
    if (request.policy.maximum_artifact_bytes == 0) return error.InvalidConfiguration;
    if (request.uri.user != null or request.uri.password != null)
        return error.CredentialBearingUri;

    const pinned = request.expected_sha256 != null;
    if (!allowedScheme(request.uri, pinned)) return error.UnsupportedScheme;
    if (request.expected_size) |size| {
        if (size > request.policy.maximum_artifact_bytes or
            size > cache.limits.maximum_object_bytes)
            return error.ArtifactTooLarge;
    }

    if (request.expected_sha256) |digest| {
        if (request.expected_size) |size| {
            if (cache.lookup(allocator, digest, size, .verify_sha256)) |bytes| {
                errdefer allocator.free(bytes);
                var cache_key: [64]u8 = undefined;
                digest.formatHex(&cache_key);
                const now = dependencies.clock.nowMs();
                const effective_uri = try repository_acquisition.redactUri(allocator, request.uri);
                return .{
                    .allocator = allocator,
                    .bytes = bytes,
                    .provenance = .{
                        .effective_uri = effective_uri,
                        .size = size,
                        .sha256 = digest,
                        .cache_key = cache_key,
                        .trust_mode = .sha256,
                        .outcome = .cache_hit,
                        .status = null,
                        .timing = .{
                            .started_ms = now,
                            .completed_ms = now,
                            .attempts = 0,
                        },
                    },
                };
            } else |err| switch (err) {
                error.CacheMiss, error.CorruptObject => {},
                error.PackageTooLarge => return error.ArtifactTooLarge,
                else => |other| return other,
            }
        }
    }

    const maximum_transfer_bytes = @min(
        request.policy.maximum_artifact_bytes,
        cache.limits.maximum_object_bytes,
    );
    const response_limit = if (request.expected_size) |size|
        @min(
            maximum_transfer_bytes,
            std.math.cast(usize, std.math.add(u64, size, 1) catch size) orelse
                maximum_transfer_bytes,
        )
    else
        maximum_transfer_bytes;
    var acquired = repository_acquisition.acquire(allocator, .{
        .uri = request.uri,
        .proxy = request.policy.proxy,
        .deadlines = request.policy.deadlines,
        .redirect_limit = request.policy.redirect_limit,
        .retry = request.policy.retry,
        .max_response_bytes = response_limit,
        .credentials = request.policy.credentials,
    }, dependencies) catch |err| switch (err) {
        error.ResponseTooLarge => if (response_limit < maximum_transfer_bytes)
            return error.SizeMismatch
        else
            return error.ArtifactTooLarge,
        else => |other| return other,
    };
    defer acquired.deinit(allocator);

    if (acquired.bytes.len > request.policy.maximum_artifact_bytes or
        acquired.bytes.len > cache.limits.maximum_object_bytes)
        return error.ArtifactTooLarge;
    if (request.expected_size) |size| {
        if (acquired.bytes.len != size) return error.SizeMismatch;
    }
    const digest = Digest.of(acquired.bytes);
    if (request.expected_sha256) |expected| {
        if (!digest.eql(expected)) return error.DigestMismatch;
    }
    try cache.publish(
        allocator,
        digest,
        acquired.bytes.len,
        acquired.bytes,
        request.policy.cache_lock,
        .{},
    );

    var cache_key: [64]u8 = undefined;
    digest.formatHex(&cache_key);
    const bytes = acquired.bytes;
    acquired.bytes = &.{};
    const provenance = acquired.provenance;
    acquired.provenance.effective_uri = &.{};
    return .{
        .allocator = allocator,
        .bytes = bytes,
        .provenance = .{
            .effective_uri = provenance.effective_uri,
            .size = bytes.len,
            .sha256 = digest,
            .cache_key = cache_key,
            .trust_mode = if (pinned) .sha256 else .https,
            .outcome = .acquired,
            .status = provenance.status,
            .timing = provenance.timing,
        },
    };
}

fn allowedScheme(uri: repository_acquisition.Uri, pinned: bool) bool {
    if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) return true;
    if (!pinned) return false;
    return std.ascii.eqlIgnoreCase(uri.scheme, "http") or
        std.ascii.eqlIgnoreCase(uri.scheme, "file");
}

fn testPolicy() Policy {
    return .{
        .maximum_artifact_bytes = 1024,
        .deadlines = .{ .connect_ms = 50, .read_ms = 50, .overall_ms = 500 },
        .redirect_limit = 2,
    };
}

const TestTransport = struct {
    body: []const u8 = "",
    count: usize = 0,
    now_ms: u64 = 0,
    maximum_response_bytes: usize = 0,

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
        self.count += 1;
        self.maximum_response_bytes = value.max_response_bytes;
        if (self.body.len > value.max_response_bytes) return error.ResponseTooLarge;
        return .{ .status = 200, .body = try allocator.dupe(u8, self.body) };
    }

    fn readFile(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        _: []const u8,
        limit: usize,
        _: repository_acquisition.Deadlines,
    ) !repository_acquisition.FileRead {
        const self: *TestTransport = @ptrCast(@alignCast(context.?));
        self.count += 1;
        self.maximum_response_bytes = limit;
        if (self.body.len > limit) return error.ResponseTooLarge;
        return .{ .bytes = try allocator.dupe(u8, self.body), .regular = true };
    }

    fn nowMs(context: ?*anyopaque) u64 {
        const self: *TestTransport = @ptrCast(@alignCast(context.?));
        return self.now_ms;
    }

    fn sleepMs(context: ?*anyopaque, milliseconds: u64) !void {
        const self: *TestTransport = @ptrCast(@alignCast(context.?));
        self.now_ms += milliseconds;
    }
};

fn testCache(tmp: *std.testing.TmpDir) !package_acquisition.Cache {
    return testCacheWithLimit(tmp, 1024);
}

fn testCacheWithLimit(
    tmp: *std.testing.TmpDir,
    maximum_object_bytes: usize,
) !package_acquisition.Cache {
    return package_acquisition.Cache.initFromDir(
        std.testing.io,
        tmp.dir,
        .{ .maximum_object_bytes = maximum_object_bytes },
    );
}

test "unpinned local artifact requires HTTPS" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    var transport: TestTransport = .{ .body = "artifact" };

    inline for (.{ "http://example.test/package.deb", "file:///package.deb" }) |text| {
        try std.testing.expectError(error.UnsupportedScheme, acquire(
            std.testing.allocator,
            &cache,
            .{
                .uri = try repository_acquisition.Uri.parse(text),
                .policy = testPolicy(),
            },
            transport.dependencies(),
        ));
    }
    try std.testing.expectEqual(@as(usize, 0), transport.count);
}

test "SHA-256 pin permits HTTP and publishes exact bytes to package CAS" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    const body = "complete .deb bytes";
    const digest = Digest.of(body);
    var transport: TestTransport = .{ .body = body };

    var artifact = try acquire(std.testing.allocator, &cache, .{
        .uri = try repository_acquisition.Uri.parse("http://example.test/package.deb?bare-secret"),
        .expected_sha256 = digest,
        .expected_size = body.len,
        .policy = testPolicy(),
    }, transport.dependencies());
    defer artifact.deinit();
    try std.testing.expectEqualStrings(body, artifact.bytes);
    try std.testing.expectEqual(TrustMode.sha256, artifact.provenance.trust_mode);
    try std.testing.expectEqualStrings(
        "http://example.test/package.deb?REDACTED",
        artifact.provenance.effective_uri,
    );

    const cached = try cache.lookup(std.testing.allocator, digest, body.len, .verify_sha256);
    defer std.testing.allocator.free(cached);
    try std.testing.expectEqualStrings(body, cached);
}

test "unpinned HTTPS records transport trust and enforces an expected size" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    var transport: TestTransport = .{ .body = "artifact" };

    var artifact = try acquire(std.testing.allocator, &cache, .{
        .uri = try repository_acquisition.Uri.parse("https://example.test/package.deb"),
        .expected_size = "artifact".len,
        .policy = testPolicy(),
    }, transport.dependencies());
    defer artifact.deinit();
    try std.testing.expectEqual(TrustMode.https, artifact.provenance.trust_mode);
    try std.testing.expectEqual(Outcome.acquired, artifact.provenance.outcome);
    const evidence = artifact.provenance.originEvidence("demo", "1", "amd64");
    try package_origin.validateLocalArtifact(evidence);
    try std.testing.expectEqual(
        package_origin.LocalArtifactTrustMode.verified_https,
        evidence.trust_mode,
    );

    transport.body = "wrong";
    try std.testing.expectError(error.SizeMismatch, acquire(
        std.testing.allocator,
        &cache,
        .{
            .uri = try repository_acquisition.Uri.parse("https://example.test/package.deb"),
            .expected_size = "expected".len,
            .policy = testPolicy(),
        },
        transport.dependencies(),
    ));
}

test "unpinned expected-size transfer is capped by package CAS capacity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCacheWithLimit(&tmp, 8);
    defer cache.deinit();
    var transport: TestTransport = .{ .body = "123456789" };

    try std.testing.expectError(error.ArtifactTooLarge, acquire(
        std.testing.allocator,
        &cache,
        .{
            .uri = try repository_acquisition.Uri.parse("https://example.test/package.deb"),
            .expected_size = 8,
            .policy = testPolicy(),
        },
        transport.dependencies(),
    ));
    try std.testing.expectEqual(@as(usize, 8), transport.maximum_response_bytes);
}

test "pinned digest mismatch is not published" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    const expected = Digest.of("expected");
    var transport: TestTransport = .{ .body = "substituted" };

    try std.testing.expectError(error.DigestMismatch, acquire(
        std.testing.allocator,
        &cache,
        .{
            .uri = try repository_acquisition.Uri.parse("file:///package.deb"),
            .expected_sha256 = expected,
            .policy = testPolicy(),
        },
        transport.dependencies(),
    ));
    try std.testing.expectError(
        error.CacheMiss,
        cache.lookup(std.testing.allocator, expected, "expected".len, .verify_sha256),
    );
}

test "pinned size and digest use verified cache without acquisition" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    const body = "cached artifact";
    const digest = Digest.of(body);
    try cache.publish(std.testing.allocator, digest, body.len, body, .fail_fast, .{});
    var transport: TestTransport = .{ .body = "network must not run" };

    var artifact = try acquire(std.testing.allocator, &cache, .{
        .uri = try repository_acquisition.Uri.parse("file:///package.deb"),
        .expected_sha256 = digest,
        .expected_size = body.len,
        .policy = testPolicy(),
    }, transport.dependencies());
    defer artifact.deinit();
    try std.testing.expectEqual(Outcome.cache_hit, artifact.provenance.outcome);
    try std.testing.expectEqual(@as(usize, 0), transport.count);
    try std.testing.expectEqualStrings(body, artifact.bytes);
}
