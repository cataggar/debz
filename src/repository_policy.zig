const std = @import("std");
const acquisition = @import("repository_acquisition.zig");
const cache_module = @import("metadata_cache.zig");
const debian_version = @import("debian_version.zig");
const refresh_module = @import("repository_refresh.zig");
const solver = @import("solver.zig");
const source = @import("source.zig");

const aggregate_snapshot = cache_module.SnapshotId{ .value = "multi-repository-v1" };
const repository_policy_snapshot = cache_module.SnapshotId{ .value = "repository-policy-v1" };

pub const SourceDocument = struct {
    bytes: []const u8,
    format: source.Format,
    policy: Policy = .{},
};

pub const OpaqueReference = struct {
    id: []const u8,
};

pub const Proxy = union(enum) {
    direct,
    declared: OpaqueReference,
};

pub const ImmutabilityKind = enum {
    moving,
    immutable_url,
    snapshot,
};

pub const Immutability = struct {
    kind: ImmutabilityKind = .moving,
    /// Optional caller-declared identity such as a snapshot timestamp. It is
    /// provenance, not a fallback mirror.
    declared_identity: ?[]const u8 = null,
};

pub const PinRule = struct {
    suite: ?[]const u8 = null,
    component: ?[]const u8 = null,
    priority: i32,
};

pub const Policy = struct {
    priority: i32 = 500,
    pins: []const PinRule = &.{},
    default_release: ?[]const u8 = null,
    immutability: Immutability = .{},
    proxy: Proxy = .direct,
    credentials: ?OpaqueReference = null,
    deadlines: acquisition.Deadlines = .{
        .connect_ms = 10_000,
        .read_ms = 30_000,
        .overall_ms = 60_000,
    },
};

pub const Limits = struct {
    source: source.Limits = .{},
    max_documents: usize = 1024,
    max_repositories: usize = 4096,
    max_canonical_bytes: usize = 8 * 1024 * 1024,
};

pub const DiagnosticCode = enum {
    too_many_documents,
    too_many_repositories,
    source_invalid,
    unsupported_source_type,
    unsupported_repository_uri,
    unsupported_exact_suite,
    missing_architecture,
    invalid_policy,
    duplicate_repository,
    conflicting_repository,
    canonical_output_too_large,
    missing_runtime,
    duplicate_runtime,
    aggregate_publication_failed,
};

pub const Diagnostic = struct {
    code: DiagnosticCode,
    document_index: ?usize = null,
    source_diagnostic: ?source.Diagnostic = null,
    repository_id: ?source.RepositoryId = null,

    pub fn message(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .too_many_documents => "repository document limit exceeded",
            .too_many_repositories => "normalized repository limit exceeded",
            .source_invalid => "repository source input is invalid",
            .unsupported_source_type => "only binary repository entries can be refreshed",
            .unsupported_repository_uri => "repository URI must be an explicit file, HTTP, or HTTPS URI without credentials, query, or fragment",
            .unsupported_exact_suite => "exact-path suites are not supported by authenticated refresh",
            .missing_architecture => "repository architecture must be explicit or supplied as the native architecture",
            .invalid_policy => "repository policy is invalid",
            .duplicate_repository => "duplicate normalized repository declaration",
            .conflicting_repository => "conflicting declarations target the same repository",
            .canonical_output_too_large => "canonical DEB822 output exceeds its configured limit",
            .missing_runtime => "enabled repository has no authenticated refresh runtime",
            .duplicate_runtime => "repository refresh runtime is repeated",
            .aggregate_publication_failed => "aggregate manifest publication failed",
        };
    }
};

pub const NormalizedRepository = struct {
    id: source.RepositoryId,
    enabled: bool,
    uri: []const u8,
    suite: []const u8,
    component: []const u8,
    architecture: []const u8,
    signed_by: []const []const u8,
    priority: i32,
    pins: []const PinRule,
    default_release: ?[]const u8,
    immutability: Immutability,
    proxy: Proxy,
    /// Opaque reference only. It is deliberately excluded from IDs,
    /// canonical sources, manifests, diagnostics, and cache keys.
    credentials: ?OpaqueReference,
    deadlines: acquisition.Deadlines,

    pub fn effectivePriority(self: NormalizedRepository) i32 {
        var result = self.priority;
        for (self.pins) |pin| {
            if ((pin.suite == null or std.mem.eql(u8, pin.suite.?, self.suite)) and
                (pin.component == null or std.mem.eql(u8, pin.component.?, self.component)))
                result = pin.priority;
        }
        if (self.default_release) |release| {
            if (std.mem.eql(u8, release, self.suite)) result = @max(result, 990);
        }
        return result;
    }
};

pub const Configuration = struct {
    repositories: []NormalizedRepository,
    canonical_deb822: []const u8,
    identity: source.RepositoryId,
    backing_allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *Configuration) void {
        const backing = self.backing_allocator;
        self.arena.deinit();
        backing.destroy(self.arena);
        self.* = undefined;
    }
};

pub const NormalizeResult = union(enum) {
    configuration: Configuration,
    diagnostic: Diagnostic,
};

pub fn normalize(
    allocator: std.mem.Allocator,
    documents: []const SourceDocument,
    native_architecture: ?[]const u8,
    limits: Limits,
) std.mem.Allocator.Error!NormalizeResult {
    return normalizeInternal(allocator, documents, native_architecture, limits, .reject);
}

/// Normalizes only binary repository declarations. Valid `deb-src`-only
/// declarations are ignored after parsing so callers can retain their source
/// document evidence without making source-package metadata refreshable.
pub fn normalizeBinaryRefresh(
    allocator: std.mem.Allocator,
    documents: []const SourceDocument,
    native_architecture: ?[]const u8,
    limits: Limits,
) std.mem.Allocator.Error!NormalizeResult {
    return normalizeInternal(allocator, documents, native_architecture, limits, .exclude);
}

const SourceOnlyPolicy = enum { reject, exclude };

fn normalizeInternal(
    allocator: std.mem.Allocator,
    documents: []const SourceDocument,
    native_architecture: ?[]const u8,
    limits: Limits,
    source_only: SourceOnlyPolicy,
) std.mem.Allocator.Error!NormalizeResult {
    if (documents.len > limits.max_documents)
        return .{ .diagnostic = .{ .code = .too_many_documents } };

    var arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = .init(allocator);
    errdefer {
        arena.deinit();
        allocator.destroy(arena);
    }
    const owned = arena.allocator();
    var repositories: std.ArrayList(NormalizedRepository) = .empty;

    for (documents, 0..) |document, document_index| {
        if (!validPolicy(document.policy)) return finishDiagnostic(
            allocator,
            arena,
            .{ .code = .invalid_policy, .document_index = document_index },
        );
        const parsed = try source.parse(allocator, document.bytes, document.format, limits.source);
        var source_list = switch (parsed) {
            .diagnostic => |value| return finishDiagnostic(allocator, arena, .{
                .code = .source_invalid,
                .document_index = document_index,
                .source_diagnostic = value,
            }),
            .sources => |value| value,
        };
        defer source_list.deinit();

        for (source_list.repositories) |repository| {
            var has_binary = false;
            for (repository.types) |kind| if (kind == .binary) {
                has_binary = true;
            };
            if (!has_binary) {
                if (source_only == .exclude) continue;
                return finishDiagnostic(allocator, arena, .{
                    .code = .unsupported_source_type,
                    .document_index = document_index,
                });
            }
            const architectures = if (repository.architectures.len == 0) blk: {
                const native = native_architecture orelse return finishDiagnostic(
                    allocator,
                    arena,
                    .{ .code = .missing_architecture, .document_index = document_index },
                );
                break :blk &[_]source.LocatedString{.{
                    .value = native,
                    .span = repository.span,
                }};
            } else repository.architectures;

            for (repository.uris) |uri| {
                if (!validRepositoryUri(uri.value)) return finishDiagnostic(
                    allocator,
                    arena,
                    .{
                        .code = .unsupported_repository_uri,
                        .document_index = document_index,
                    },
                );
            }
            for (repository.suites) |suite| {
                if (std.mem.endsWith(u8, suite.value, "/")) return finishDiagnostic(
                    allocator,
                    arena,
                    .{
                        .code = .unsupported_exact_suite,
                        .document_index = document_index,
                    },
                );
            }
            const component_count = @max(repository.components.len, 1);
            const uri_suite_count = std.math.mul(
                usize,
                repository.uris.len,
                repository.suites.len,
            ) catch return finishDiagnostic(allocator, arena, .{
                .code = .too_many_repositories,
                .document_index = document_index,
            });
            const component_architecture_count = std.math.mul(
                usize,
                component_count,
                architectures.len,
            ) catch return finishDiagnostic(allocator, arena, .{
                .code = .too_many_repositories,
                .document_index = document_index,
            });
            const expanded_count = std.math.mul(
                usize,
                uri_suite_count,
                component_architecture_count,
            ) catch return finishDiagnostic(allocator, arena, .{
                .code = .too_many_repositories,
                .document_index = document_index,
            });
            if (expanded_count > limits.max_repositories -| repositories.items.len)
                return finishDiagnostic(allocator, arena, .{
                    .code = .too_many_repositories,
                    .document_index = document_index,
                });

            for (repository.uris) |uri| for (repository.suites) |suite| {
                if (repository.components.len == 0) {
                    try appendNormalized(
                        owned,
                        &repositories,
                        repository,
                        uri.value,
                        suite.value,
                        "",
                        architectures,
                        document.policy,
                    );
                } else for (repository.components) |component| {
                    try appendNormalized(
                        owned,
                        &repositories,
                        repository,
                        uri.value,
                        suite.value,
                        component.value,
                        architectures,
                        document.policy,
                    );
                }
            };
        }
    }

    std.mem.sort(NormalizedRepository, repositories.items, {}, lessRepository);
    for (repositories.items, 0..) |repository, index| {
        for (repositories.items[0..index]) |previous| {
            if (sameTarget(previous, repository)) {
                return finishDiagnostic(allocator, arena, .{
                    .code = if (equalRepository(previous, repository))
                        .duplicate_repository
                    else
                        .conflicting_repository,
                    .repository_id = repository.id,
                });
            }
        }
    }

    var canonical: std.ArrayList(u8) = .empty;
    for (repositories.items) |repository| {
        try appendCanonical(&canonical, owned, repository);
        if (canonical.items.len > limits.max_canonical_bytes)
            return finishDiagnostic(allocator, arena, .{
                .code = .canonical_output_too_large,
            });
    }
    const canonical_owned = try canonical.toOwnedSlice(owned);
    const configuration_identity = configurationId(repositories.items);
    const result: Configuration = .{
        .repositories = try repositories.toOwnedSlice(owned),
        .canonical_deb822 = canonical_owned,
        .identity = configuration_identity,
        .backing_allocator = allocator,
        .arena = arena,
    };
    return .{ .configuration = result };
}

fn appendNormalized(
    allocator: std.mem.Allocator,
    repositories: *std.ArrayList(NormalizedRepository),
    parsed: source.Repository,
    uri: []const u8,
    suite: []const u8,
    component: []const u8,
    architectures: []const source.LocatedString,
    policy: Policy,
) !void {
    for (architectures) |architecture| {
        var keyrings = try allocator.alloc([]const u8, parsed.signed_by.len);
        for (parsed.signed_by, 0..) |value, index|
            keyrings[index] = try allocator.dupe(u8, value.value);
        std.mem.sort([]const u8, keyrings, {}, lessString);
        const pins = try allocator.alloc(PinRule, policy.pins.len);
        for (policy.pins, 0..) |pin, index| pins[index] = .{
            .suite = if (pin.suite) |value| try allocator.dupe(u8, value) else null,
            .component = if (pin.component) |value| try allocator.dupe(u8, value) else null,
            .priority = pin.priority,
        };
        std.mem.sort(PinRule, pins, {}, lessPin);
        var normalized: NormalizedRepository = .{
            .id = undefined,
            .enabled = parsed.enabled,
            .uri = try allocator.dupe(u8, uri),
            .suite = try allocator.dupe(u8, suite),
            .component = try allocator.dupe(u8, component),
            .architecture = try allocator.dupe(u8, architecture.value),
            .signed_by = keyrings,
            .priority = policy.priority,
            .pins = pins,
            .default_release = if (policy.default_release) |value|
                try allocator.dupe(u8, value)
            else
                null,
            .immutability = .{
                .kind = policy.immutability.kind,
                .declared_identity = if (policy.immutability.declared_identity) |value|
                    try allocator.dupe(u8, value)
                else
                    null,
            },
            .proxy = switch (policy.proxy) {
                .direct => .direct,
                .declared => |value| .{ .declared = .{
                    .id = try allocator.dupe(u8, value.id),
                } },
            },
            .credentials = if (policy.credentials) |value| .{
                .id = try allocator.dupe(u8, value.id),
            } else null,
            .deadlines = policy.deadlines,
        };
        normalized.id = repositoryId(normalized);
        try repositories.append(allocator, normalized);
    }
}

fn validPolicy(policy: Policy) bool {
    if (policy.deadlines.connect_ms == 0 or policy.deadlines.read_ms == 0 or
        policy.deadlines.overall_ms == 0)
        return false;
    if (policy.deadlines.connect_ms > std.math.maxInt(i64) or
        policy.deadlines.read_ms > std.math.maxInt(i64) or
        policy.deadlines.overall_ms > std.math.maxInt(i64))
        return false;
    if (policy.default_release) |value| if (!validToken(value)) return false;
    if (policy.immutability.kind == .snapshot and
        policy.immutability.declared_identity == null)
        return false;
    if (policy.immutability.declared_identity) |value| if (!validToken(value)) return false;
    switch (policy.proxy) {
        .direct => {},
        .declared => |value| if (!validReference(value.id)) return false,
    }

    if (policy.credentials) |value| if (!validReference(value.id)) return false;
    for (policy.pins) |pin| {
        if (pin.suite == null and pin.component == null) return false;
        if (pin.suite) |value| if (!validToken(value)) return false;
        if (pin.component) |value| if (!validToken(value)) return false;
    }
    return true;
}

fn validRepositoryUri(value: []const u8) bool {
    const uri = acquisition.Uri.parse(value) catch return false;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "file") and
        !std.ascii.eqlIgnoreCase(uri.scheme, "http") and
        !std.ascii.eqlIgnoreCase(uri.scheme, "https"))
        return false;
    return uri.user == null and uri.password == null and uri.query == null and
        uri.fragment == null;
}

fn validToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| if (byte <= ' ' or byte == 0x7f) return false;
    return true;
}

fn validReference(value: []const u8) bool {
    if (value.len == 0 or value.len > 256) return false;
    for (value) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.'))
            return false;
    }
    return true;
}

fn finishDiagnostic(
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    diagnostic: Diagnostic,
) NormalizeResult {
    arena.deinit();
    allocator.destroy(arena);
    return .{ .diagnostic = diagnostic };
}

fn repositoryId(repository: NormalizedRepository) source.RepositoryId {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hashPart(&hash, if (repository.enabled) "enabled" else "disabled");
    hashPart(&hash, repository.uri);
    hashPart(&hash, repository.suite);
    hashPart(&hash, repository.component);
    hashPart(&hash, repository.architecture);
    for (repository.signed_by) |value| hashPart(&hash, value);
    hashInt(&hash, repository.priority);
    for (repository.pins) |pin| {
        hashPart(&hash, pin.suite orelse "");
        hashPart(&hash, pin.component orelse "");
        hashInt(&hash, pin.priority);
    }
    hashPart(&hash, repository.default_release orelse "");
    hashPart(&hash, @tagName(repository.immutability.kind));
    hashPart(&hash, repository.immutability.declared_identity orelse "");
    switch (repository.proxy) {
        .direct => hashPart(&hash, "direct"),
        .declared => |value| hashPart(&hash, value.id),
    }
    hashInt(&hash, @intCast(repository.deadlines.connect_ms));
    hashInt(&hash, @intCast(repository.deadlines.read_ms));
    hashInt(&hash, @intCast(repository.deadlines.overall_ms));
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .bytes = std.fmt.bytesToHex(digest, .lower) };
}

fn configurationId(repositories: []const NormalizedRepository) source.RepositoryId {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hashPart(&hash, "debz-multi-repository-configuration-v1");
    for (repositories) |repository| hashPart(&hash, repository.id.slice());
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .bytes = std.fmt.bytesToHex(digest, .lower) };
}

fn hashPart(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, value.len, .big);
    hash.update(&length);
    hash.update(value);
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, value: i64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(i64, &bytes, value, .big);
    hash.update(&bytes);
}

fn appendCanonical(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    repository: NormalizedRepository,
) !void {
    try output.appendSlice(allocator, "Types: deb\nURIs: ");
    try output.appendSlice(allocator, repository.uri);
    try output.appendSlice(allocator, "\nSuites: ");
    try output.appendSlice(allocator, repository.suite);
    if (repository.component.len != 0) {
        try output.appendSlice(allocator, "\nComponents: ");
        try output.appendSlice(allocator, repository.component);
    }
    try output.appendSlice(allocator, "\nArchitectures: ");
    try output.appendSlice(allocator, repository.architecture);
    if (repository.signed_by.len != 0) {
        try output.appendSlice(allocator, "\nSigned-By:");
        for (repository.signed_by) |value| {
            try output.append(allocator, ' ');
            try output.appendSlice(allocator, value);
        }
    }
    try output.appendSlice(
        allocator,
        if (repository.enabled) "\nEnabled: yes\n\n" else "\nEnabled: no\n\n",
    );
}

fn lessRepository(_: void, left: NormalizedRepository, right: NormalizedRepository) bool {
    return std.mem.order(u8, left.id.slice(), right.id.slice()) == .lt;
}

fn lessString(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn lessPin(_: void, left: PinRule, right: PinRule) bool {
    const suite_order = std.mem.order(u8, left.suite orelse "", right.suite orelse "");
    if (suite_order != .eq) return suite_order == .lt;
    const component_order = std.mem.order(
        u8,
        left.component orelse "",
        right.component orelse "",
    );
    if (component_order != .eq) return component_order == .lt;
    return left.priority < right.priority;
}

fn equalRepository(left: NormalizedRepository, right: NormalizedRepository) bool {
    return left.enabled == right.enabled and
        sameTarget(left, right) and
        equalStrings(left.signed_by, right.signed_by) and
        left.priority == right.priority and
        equalPins(left.pins, right.pins) and
        equalOptional(left.default_release, right.default_release) and
        left.immutability.kind == right.immutability.kind and
        equalOptional(
            left.immutability.declared_identity,
            right.immutability.declared_identity,
        ) and
        equalProxy(left.proxy, right.proxy) and
        equalOptionalReference(left.credentials, right.credentials) and
        left.deadlines.connect_ms == right.deadlines.connect_ms and
        left.deadlines.read_ms == right.deadlines.read_ms and
        left.deadlines.overall_ms == right.deadlines.overall_ms;
}

fn sameTarget(left: NormalizedRepository, right: NormalizedRepository) bool {
    return std.mem.eql(u8, left.uri, right.uri) and
        std.mem.eql(u8, left.suite, right.suite) and
        std.mem.eql(u8, left.component, right.component) and
        std.mem.eql(u8, left.architecture, right.architecture);
}

fn equalStrings(left: []const []const u8, right: []const []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.mem.eql(u8, a, b)) return false;
    return true;
}

fn equalPins(left: []const PinRule, right: []const PinRule) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (!equalOptional(a.suite, b.suite) or
            !equalOptional(a.component, b.component) or
            a.priority != b.priority) return false;
    }
    return true;
}

fn equalOptional(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null or right == null) return left == null and right == null;
    return std.mem.eql(u8, left.?, right.?);
}

fn equalProxy(left: Proxy, right: Proxy) bool {
    return switch (left) {
        .direct => switch (right) {
            .direct => true,
            .declared => false,
        },
        .declared => |value| switch (right) {
            .direct => false,
            .declared => |other| std.mem.eql(u8, value.id, other.id),
        },
    };
}

fn equalOptionalReference(left: ?OpaqueReference, right: ?OpaqueReference) bool {
    if (left == null or right == null) return left == null and right == null;
    return std.mem.eql(u8, left.?.id, right.?.id);
}

pub const FailurePolicy = enum {
    all_or_nothing,
    allow_stale_authenticated,
};

pub const RefreshMode = enum {
    online,
    cache_only,
};

pub const Runtime = struct {
    repository_id: source.RepositoryId,
    declared_proxy: ?OpaqueReference = null,
    declared_credentials: ?OpaqueReference = null,
    declared_keyrings: []const []const u8 = &.{},
    authentication: refresh_module.AuthenticationInput,
    acquisition: refresh_module.AcquisitionPolicy,
    refresh: refresh_module.RefreshPolicy,
};

pub const RefreshDiagnostic = struct {
    repository_id: source.RepositoryId,
    stale_attempted: bool,
    error_name: []const u8,
};

pub const PublishedRepositoryState = struct {
    repository_id: source.RepositoryId,
    configuration_id: source.RepositoryId,
    release_digest: cache_module.Digest,
    index_digest: cache_module.Digest,
    signer_fingerprint: ?[20]u8,
    release_suite: []const u8,
    release_codename: []const u8,
    selected_path: []const u8,
    refreshed_at_unix: i64,
    immutable: bool,
    immutable_identity: ?[]const u8,
    stale: bool,
};

pub const RefreshRequest = struct {
    configuration: *const Configuration,
    runtimes: []const Runtime,
    mode: RefreshMode,
    failure_policy: FailurePolicy = .all_or_nothing,
    dependencies: refresh_module.Dependencies,
    aggregate_publish: cache_module.PublishOptions = .{},
};

pub const RefreshResult = struct {
    snapshots: []refresh_module.AuthenticatedResult,
    states: []PublishedRepositoryState,
    diagnostics: []RefreshDiagnostic,
    aggregate_manifest: []u8,
    universe: CombinedUniverse,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *RefreshResult) void {
        self.universe.deinit();
        for (self.snapshots) |*snapshot| snapshot.deinit();
        self.allocator.free(self.snapshots);
        deinitStates(self.allocator, self.states);
        self.allocator.free(self.states);
        self.allocator.free(self.diagnostics);
        self.allocator.free(self.aggregate_manifest);
        self.* = undefined;
    }
};

pub const RefreshOutcome = union(enum) {
    published: RefreshResult,
    failed: []RefreshDiagnostic,

    pub fn deinit(self: *RefreshOutcome, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .published => |*value| value.deinit(),
            .failed => |value| allocator.free(value),
        }
        self.* = undefined;
    }
};

pub fn refreshAll(
    allocator: std.mem.Allocator,
    request: RefreshRequest,
) !RefreshOutcome {
    var snapshots: std.ArrayList(refresh_module.AuthenticatedResult) = .empty;
    errdefer {
        for (snapshots.items) |*snapshot| snapshot.deinit();
        snapshots.deinit(allocator);
    }
    var states: std.ArrayList(PublishedRepositoryState) = .empty;
    errdefer {
        deinitStates(allocator, states.items);
        states.deinit(allocator);
    }
    var diagnostics: std.ArrayList(RefreshDiagnostic) = .empty;
    errdefer diagnostics.deinit(allocator);

    for (request.runtimes, 0..) |runtime, index| {
        for (request.runtimes[0..index]) |previous| {
            if (std.mem.eql(u8, runtime.repository_id.slice(), previous.repository_id.slice())) {
                try diagnostics.append(allocator, .{
                    .repository_id = runtime.repository_id,
                    .stale_attempted = false,
                    .error_name = @errorName(error.InvalidConfiguration),
                });
                const failed = try diagnostics.toOwnedSlice(allocator);
                return .{ .failed = failed };
            }
        }
        if (!isEnabledRepository(request.configuration, runtime.repository_id)) {
            try diagnostics.append(allocator, .{
                .repository_id = runtime.repository_id,
                .stale_attempted = false,
                .error_name = "UnexpectedRuntime",
            });
        }
    }
    if (diagnostics.items.len != 0) {
        const failed = try diagnostics.toOwnedSlice(allocator);
        return .{ .failed = failed };
    }

    for (request.configuration.repositories) |repository| {
        if (!repository.enabled) continue;
        const runtime = findRuntime(request.runtimes, repository.id) orelse {
            try diagnostics.append(allocator, .{
                .repository_id = repository.id,
                .stale_attempted = false,
                .error_name = "MissingRuntime",
            });
            continue;
        };
        if (!runtimeMatches(repository, runtime)) {
            try diagnostics.append(allocator, .{
                .repository_id = repository.id,
                .stale_attempted = false,
                .error_name = "DeclaredPolicyMismatch",
            });
            continue;
        }
        var refresh_policy = runtime.refresh;
        refresh_policy.mode = if (request.mode == .cache_only) .cache_only else .online;
        var stale = false;
        const refresh_repository: refresh_module.Repository = .{
            .id = repository.id,
            .base_uri = try acquisition.Uri.parse(repository.uri),
            .suite = repository.suite,
            .component = repository.component,
            .architecture = repository.architecture,
        };
        var snapshot = refreshRepository(
            allocator,
            repository,
            refresh_repository,
            runtime,
            refresh_policy,
            request.dependencies,
        ) catch |online_error| blk: {
            if (request.mode == .online and
                request.failure_policy == .allow_stale_authenticated and
                repository.immutability.kind == .moving)
            {
                refresh_policy.mode = .cache_only;
                stale = true;
                break :blk refresh_module.refreshAuthenticated(
                    allocator,
                    refresh_repository,
                    runtime.authentication,
                    runtime.acquisition,
                    refresh_policy,
                    request.dependencies,
                ) catch {
                    try diagnostics.append(allocator, .{
                        .repository_id = repository.id,
                        .stale_attempted = true,
                        .error_name = @errorName(online_error),
                    });
                    continue;
                };
            }
            try diagnostics.append(allocator, .{
                .repository_id = repository.id,
                .stale_attempted = false,
                .error_name = @errorName(online_error),
            });
            continue;
        };
        const state = stateFromSnapshot(
            allocator,
            request.configuration.identity,
            repository,
            &snapshot,
            stale,
        ) catch |err| {
            snapshot.deinit();
            return err;
        };
        snapshots.append(allocator, snapshot) catch |err| {
            if (state.immutable_identity) |value| allocator.free(value);
            snapshot.deinit();
            return err;
        };
        states.append(allocator, state) catch |err| {
            if (state.immutable_identity) |value| allocator.free(value);
            return err;
        };
    }

    if (diagnostics.items.len != 0) {
        for (snapshots.items) |*snapshot| snapshot.deinit();
        snapshots.deinit(allocator);
        deinitStates(allocator, states.items);
        states.deinit(allocator);
        const failed = try diagnostics.toOwnedSlice(allocator);
        return .{ .failed = failed };
    }

    std.mem.sort(PublishedRepositoryState, states.items, {}, lessState);
    const snapshot_slice = try snapshots.toOwnedSlice(allocator);
    errdefer {
        for (snapshot_slice) |*snapshot| snapshot.deinit();
        allocator.free(snapshot_slice);
    }
    const state_slice = try states.toOwnedSlice(allocator);
    errdefer {
        deinitStates(allocator, state_slice);
        allocator.free(state_slice);
    }
    const diagnostic_slice = try diagnostics.toOwnedSlice(allocator);
    errdefer allocator.free(diagnostic_slice);
    var universe = try buildUniverse(allocator, request.configuration, snapshot_slice);
    errdefer universe.deinit();
    const manifest = try encodeAggregateManifest(
        allocator,
        request.configuration.identity,
        state_slice,
    );
    errdefer allocator.free(manifest);

    for (state_slice) |state| {
        const repository_manifest = try encodeRepositoryManifest(allocator, state);
        defer allocator.free(repository_manifest);
        const repository_identity: cache_module.ObjectIdentity = .{
            .digest = cache_module.Digest.of(repository_manifest),
            .size = repository_manifest.len,
        };
        try request.dependencies.cache.publish(
            .{ .value = state.repository_id.slice() },
            repository_policy_snapshot,
            .{
                .verification = .trusted_snapshot,
                .verified_at_unix = request.dependencies.clock.nowUnix(),
                .verifier_input = state.release_digest,
            },
            repository_identity,
            repository_manifest,
            request.aggregate_publish,
        );
    }
    const identity: cache_module.ObjectIdentity = .{
        .digest = cache_module.Digest.of(manifest),
        .size = manifest.len,
    };
    request.dependencies.cache.publish(
        .{ .value = request.configuration.identity.slice() },
        aggregate_snapshot,
        .{
            .verification = .trusted_snapshot,
            .verified_at_unix = request.dependencies.clock.nowUnix(),
            .verifier_input = identity.digest,
        },
        identity,
        manifest,
        request.aggregate_publish,
    ) catch {
        return error.AggregatePublicationFailed;
    };

    return .{ .published = .{
        .snapshots = snapshot_slice,
        .states = state_slice,
        .diagnostics = diagnostic_slice,
        .aggregate_manifest = manifest,
        .universe = universe,
        .allocator = allocator,
    } };
}

fn findRuntime(runtimes: []const Runtime, id: source.RepositoryId) ?Runtime {
    for (runtimes) |runtime| {
        if (std.mem.eql(u8, runtime.repository_id.slice(), id.slice())) return runtime;
    }
    return null;
}

fn isEnabledRepository(configuration: *const Configuration, id: source.RepositoryId) bool {
    for (configuration.repositories) |repository| {
        if (repository.enabled and std.mem.eql(u8, repository.id.slice(), id.slice()))
            return true;
    }
    return false;
}

fn refreshRepository(
    allocator: std.mem.Allocator,
    repository: NormalizedRepository,
    refresh_repository: refresh_module.Repository,
    runtime: Runtime,
    refresh_policy: refresh_module.RefreshPolicy,
    dependencies: refresh_module.Dependencies,
) !refresh_module.AuthenticatedResult {
    if (repository.immutability.kind != .moving and refresh_policy.mode == .online) {
        var cached_policy = refresh_policy;
        cached_policy.mode = .cache_only;
        return refresh_module.refreshAuthenticated(
            allocator,
            refresh_repository,
            runtime.authentication,
            runtime.acquisition,
            cached_policy,
            dependencies,
        ) catch |err| switch (err) {
            error.CacheMiss => refresh_module.refreshAuthenticated(
                allocator,
                refresh_repository,
                runtime.authentication,
                runtime.acquisition,
                refresh_policy,
                dependencies,
            ),
            else => |other| other,
        };
    }
    return refresh_module.refreshAuthenticated(
        allocator,
        refresh_repository,
        runtime.authentication,
        runtime.acquisition,
        refresh_policy,
        dependencies,
    );
}

fn runtimeMatches(repository: NormalizedRepository, runtime: Runtime) bool {
    if (repository.deadlines.connect_ms != runtime.acquisition.deadlines.connect_ms or
        repository.deadlines.read_ms != runtime.acquisition.deadlines.read_ms or
        repository.deadlines.overall_ms != runtime.acquisition.deadlines.overall_ms)
        return false;
    switch (repository.proxy) {
        .direct => {
            if (runtime.declared_proxy != null or
                runtime.acquisition.proxy.http != null or
                runtime.acquisition.proxy.https != null) return false;
        },
        .declared => |reference| {
            const runtime_reference = runtime.declared_proxy orelse return false;
            if (!std.mem.eql(u8, reference.id, runtime_reference.id)) return false;
            if (runtime.acquisition.proxy.http == null and
                runtime.acquisition.proxy.https == null) return false;
        },
    }
    if (repository.credentials) |reference| {
        const runtime_reference = runtime.declared_credentials orelse return false;
        if (!std.mem.eql(u8, reference.id, runtime_reference.id)) return false;
    } else if (runtime.declared_credentials != null) return false;
    if (repository.signed_by.len != runtime.declared_keyrings.len) return false;
    for (repository.signed_by, runtime.declared_keyrings) |configured, declared| {
        if (!std.mem.eql(u8, configured, declared)) return false;
    }
    return true;
}

fn stateFromSnapshot(
    allocator: std.mem.Allocator,
    configuration_id: source.RepositoryId,
    repository: NormalizedRepository,
    snapshot: *const refresh_module.AuthenticatedResult,
    stale: bool,
) !PublishedRepositoryState {
    const evidence = snapshot.snapshot.provenance.authentication_evidence;
    const signer = if (evidence.accepted_signature_index) |index|
        evidence.signatures[index].primary_fingerprint
    else
        null;
    return .{
        .repository_id = repository.id,
        .configuration_id = configuration_id,
        .release_digest = snapshot.snapshot.provenance.release_digest,
        .index_digest = snapshot.snapshot.provenance.index_digest,
        .signer_fingerprint = signer,
        .release_suite = snapshot.snapshot.release.suite.?.value,
        .release_codename = snapshot.snapshot.release.codename.?.value,
        .selected_path = snapshot.snapshot.provenance.selected_path,
        .refreshed_at_unix = snapshot.snapshot.provenance.refreshed_at_unix,
        .immutable = repository.immutability.kind != .moving,
        .immutable_identity = if (repository.immutability.declared_identity) |value|
            try allocator.dupe(u8, value)
        else
            null,
        .stale = stale,
    };
}

fn deinitStates(allocator: std.mem.Allocator, states: []PublishedRepositoryState) void {
    for (states) |state| {
        if (state.immutable_identity) |value| allocator.free(value);
    }
}

fn lessState(_: void, left: PublishedRepositoryState, right: PublishedRepositoryState) bool {
    return std.mem.order(u8, left.repository_id.slice(), right.repository_id.slice()) == .lt;
}

fn encodeAggregateManifest(
    allocator: std.mem.Allocator,
    configuration_id: source.RepositoryId,
    states: []const PublishedRepositoryState,
) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.appendSlice(allocator, "debz-multi-repository-manifest-v1\nconfiguration ");
    try output.appendSlice(allocator, configuration_id.slice());
    try output.append(allocator, '\n');
    for (states) |state| {
        var release_hex: [64]u8 = undefined;
        var index_hex: [64]u8 = undefined;
        state.release_digest.formatHex(&release_hex);
        state.index_digest.formatHex(&index_hex);
        try output.appendSlice(allocator, "repository ");
        try output.appendSlice(allocator, state.repository_id.slice());
        try output.appendSlice(allocator, "\nrelease ");
        try output.appendSlice(allocator, &release_hex);
        try output.appendSlice(allocator, "\nindex ");
        try output.appendSlice(allocator, &index_hex);
        try output.appendSlice(allocator, "\nsuite ");
        try output.appendSlice(allocator, state.release_suite);
        try output.appendSlice(allocator, "\ncodename ");
        try output.appendSlice(allocator, state.release_codename);
        try output.appendSlice(allocator, "\npath ");
        try output.appendSlice(allocator, state.selected_path);
        try output.appendSlice(allocator, "\nrefreshed ");
        var number: [32]u8 = undefined;
        const refreshed = try std.fmt.bufPrint(&number, "{d}", .{state.refreshed_at_unix});
        try output.appendSlice(allocator, refreshed);
        try output.appendSlice(allocator, "\nimmutable ");
        try output.appendSlice(allocator, if (state.immutable) "yes" else "no");
        try output.appendSlice(allocator, "\nstale ");
        try output.appendSlice(allocator, if (state.stale) "yes\n" else "no\n");
        if (state.signer_fingerprint) |fingerprint| {
            var fingerprint_hex: [40]u8 = undefined;
            _ = std.fmt.bufPrint(&fingerprint_hex, "{x}", .{fingerprint}) catch unreachable;
            try output.appendSlice(allocator, "signer ");
            try output.appendSlice(allocator, &fingerprint_hex);
            try output.append(allocator, '\n');
        }
        if (state.immutable_identity) |value| {
            try output.appendSlice(allocator, "immutable-identity ");
            try output.appendSlice(allocator, value);
            try output.append(allocator, '\n');
        }
    }
    return output.toOwnedSlice(allocator);
}

fn encodeRepositoryManifest(
    allocator: std.mem.Allocator,
    state: PublishedRepositoryState,
) ![]u8 {
    return encodeAggregateManifest(allocator, state.configuration_id, &.{state});
}

pub const Candidate = struct {
    repository_id: source.RepositoryId,
    priority: i32,
    record_index: usize,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
};

pub const CombinedUniverse = struct {
    repositories: []solver.RepositoryInput,
    candidates: []Candidate,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *CombinedUniverse) void {
        self.allocator.free(self.repositories);
        self.allocator.free(self.candidates);
        self.* = undefined;
    }

    pub fn importInto(self: CombinedUniverse, context: *solver.Context, limits: solver.Limits) !void {
        for (self.repositories) |repository| try context.importAvailable(repository, limits);
    }
};

pub fn buildUniverse(
    allocator: std.mem.Allocator,
    configuration: *const Configuration,
    snapshots: []const refresh_module.AuthenticatedResult,
) !CombinedUniverse {
    var repositories: std.ArrayList(solver.RepositoryInput) = .empty;
    errdefer repositories.deinit(allocator);
    var candidates: std.ArrayList(Candidate) = .empty;
    errdefer candidates.deinit(allocator);

    for (configuration.repositories) |repository| {
        if (!repository.enabled) continue;
        const snapshot = findSnapshot(snapshots, repository.id) orelse
            return error.MissingSnapshot;
        const priority = effectivePriorityFor(repository, snapshot);
        try repositories.append(
            allocator,
            solver.RepositoryInput.fromRefresh(snapshot, priority),
        );
        for (snapshot.snapshot.packages.records, 0..) |record, record_index| {
            try candidates.append(allocator, .{
                .repository_id = repository.id,
                .priority = priority,
                .record_index = record_index,
                .package = record.control.package.text,
                .version = record.control.version.value.original,
                .architecture = record.control.architecture.text,
            });
        }
    }
    std.mem.sort(solver.RepositoryInput, repositories.items, {}, lessSolverRepository);
    std.mem.sort(Candidate, candidates.items, {}, lessCandidate);
    return .{
        .repositories = try repositories.toOwnedSlice(allocator),
        .candidates = try candidates.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

fn findSnapshot(
    snapshots: []const refresh_module.AuthenticatedResult,
    id: source.RepositoryId,
) ?*const refresh_module.AuthenticatedResult {
    for (snapshots) |*snapshot| {
        if (std.mem.eql(
            u8,
            snapshot.snapshot.provenance.repository_id.slice(),
            id.slice(),
        )) return snapshot;
    }
    return null;
}

fn lessSolverRepository(_: void, left: solver.RepositoryInput, right: solver.RepositoryInput) bool {
    return std.mem.order(
        u8,
        left.repository_id.slice(),
        right.repository_id.slice(),
    ) == .lt;
}

fn lessCandidate(_: void, left: Candidate, right: Candidate) bool {
    const package_order = std.mem.order(u8, left.package, right.package);
    if (package_order != .eq) return package_order == .lt;
    const architecture_order = std.mem.order(u8, left.architecture, right.architecture);
    if (architecture_order != .eq) return architecture_order == .lt;
    if (left.priority != right.priority) return left.priority > right.priority;
    const left_version = debian_version.DebianVersion.parse(left.version) catch return false;
    const right_version = debian_version.DebianVersion.parse(right.version) catch return true;
    const version_order = left_version.order(right_version);
    if (version_order != .eq) return version_order == .gt;
    const repository_order = std.mem.order(
        u8,
        left.repository_id.slice(),
        right.repository_id.slice(),
    );
    if (repository_order != .eq) return repository_order == .lt;
    return left.record_index < right.record_index;
}

fn effectivePriorityFor(
    repository: NormalizedRepository,
    snapshot: *const refresh_module.AuthenticatedResult,
) i32 {
    const release_suite = snapshot.snapshot.release.suite.?.value;
    const release_codename = snapshot.snapshot.release.codename.?.value;
    var result = repository.priority;
    for (repository.pins) |pin| {
        const suite_matches = pin.suite == null or
            std.mem.eql(u8, pin.suite.?, repository.suite) or
            std.mem.eql(u8, pin.suite.?, release_suite) or
            std.mem.eql(u8, pin.suite.?, release_codename);
        if (suite_matches and
            (pin.component == null or
                std.mem.eql(u8, pin.component.?, repository.component)))
            result = pin.priority;
    }
    if (repository.default_release) |release| {
        if (std.mem.eql(u8, release, repository.suite) or
            std.mem.eql(u8, release, release_suite) or
            std.mem.eql(u8, release, release_codename))
            result = @max(result, 990);
    }
    return result;
}

test "normalization is order independent canonical and credential redacted" {
    const first = SourceDocument{
        .bytes = "deb [arch=amd64 signed-by=/keys/archive.gpg] https://b.example stable main\n",
        .format = .legacy,
        .policy = .{
            .priority = 700,
            .credentials = .{ .id = "secret-provider" },
            .immutability = .{ .kind = .snapshot, .declared_identity = "20260815T000000Z" },
        },
    };
    const second = SourceDocument{
        .bytes = "Types: deb\nURIs: https://a.example\nSuites: stable\nComponents: main\n" ++
            "Architectures: amd64\nEnabled: no\n",
        .format = .deb822,
    };
    const one_result = try normalize(std.testing.allocator, &.{ first, second }, null, .{});
    var one = switch (one_result) {
        .configuration => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer one.deinit();
    const two_result = try normalize(std.testing.allocator, &.{ second, first }, null, .{});
    var two = switch (two_result) {
        .configuration => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer two.deinit();
    try std.testing.expectEqualStrings(one.identity.slice(), two.identity.slice());
    try std.testing.expectEqualStrings(one.canonical_deb822, two.canonical_deb822);
    try std.testing.expect(std.mem.indexOf(u8, one.canonical_deb822, "secret-provider") == null);
    try std.testing.expect(std.mem.indexOf(u8, one.canonical_deb822, "Enabled: no") != null);
    const round_trip = try source.parseDeb822(
        std.testing.allocator,
        one.canonical_deb822,
        .{},
    );
    var parsed = switch (round_trip) {
        .sources => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.repositories.len);
}

test "binary refresh normalization excludes source-only declarations" {
    const document: SourceDocument = .{
        .bytes = "deb-src [arch=amd64] https://source.example stable main\n" ++
            "# deb-src [arch=amd64] https://disabled-source.example stable main\n" ++
            "deb [arch=amd64] https://binary.example stable main\n",
        .format = .legacy,
    };
    const strict = try normalize(std.testing.allocator, &.{document}, null, .{});
    try std.testing.expectEqual(
        DiagnosticCode.unsupported_source_type,
        strict.diagnostic.code,
    );

    const imported = try normalizeBinaryRefresh(
        std.testing.allocator,
        &.{document},
        null,
        .{},
    );
    var configuration = switch (imported) {
        .configuration => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer configuration.deinit();
    try std.testing.expectEqual(@as(usize, 1), configuration.repositories.len);
    try std.testing.expectEqualStrings(
        "https://binary.example",
        configuration.repositories[0].uri,
    );
}

test "priority pins and default release have deterministic precedence" {
    const result = try normalize(std.testing.allocator, &.{
        .{
            .bytes = "deb [arch=amd64] https://low.example stable main\n",
            .format = .legacy,
            .policy = .{ .priority = 100 },
        },
        .{
            .bytes = "deb [arch=amd64] https://high.example testing main\n",
            .format = .legacy,
            .policy = .{
                .priority = 500,
                .pins = &.{.{ .suite = "testing", .priority = 800 }},
                .default_release = "testing",
            },
        },
    }, null, .{});
    var configuration = switch (result) {
        .configuration => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer configuration.deinit();
    var found_low = false;
    var found_high = false;
    for (configuration.repositories) |repository| {
        if (std.mem.eql(u8, repository.uri, "https://low.example")) {
            found_low = true;
            try std.testing.expectEqual(@as(i32, 100), repository.effectivePriority());
        } else {
            found_high = true;
            try std.testing.expectEqual(@as(i32, 990), repository.effectivePriority());
        }
    }
    try std.testing.expect(found_low and found_high);
}

test "duplicates fail deterministically" {
    const document = SourceDocument{
        .bytes = "deb [arch=amd64] https://example.test stable main\n",
        .format = .legacy,
    };
    const result = try normalize(std.testing.allocator, &.{ document, document }, null, .{});
    switch (result) {
        .configuration => |value| {
            var unexpected = value;
            unexpected.deinit();
            return error.ExpectedDiagnostic;
        },
        .diagnostic => |value| try std.testing.expectEqual(
            DiagnosticCode.duplicate_repository,
            value.code,
        ),
    }
}

test "normalization rejects unsupported locations and bounds expansion before allocation" {
    const invalid_inputs = [_]struct {
        bytes: []const u8,
        expected: DiagnosticCode,
    }{
        .{
            .bytes = "deb [arch=amd64] ftp://example.test stable main\n",
            .expected = .unsupported_repository_uri,
        },
        .{
            .bytes = "deb [arch=amd64] https://user:secret@example.test stable main\n",
            .expected = .unsupported_repository_uri,
        },
        .{
            .bytes = "deb [arch=amd64] https://example.test path/\n",
            .expected = .unsupported_exact_suite,
        },
    };
    for (invalid_inputs) |input| {
        const result = try normalize(std.testing.allocator, &.{.{
            .bytes = input.bytes,
            .format = .legacy,
        }}, null, .{});
        switch (result) {
            .configuration => |value| {
                var unexpected = value;
                unexpected.deinit();
                return error.ExpectedDiagnostic;
            },
            .diagnostic => |diagnostic| try std.testing.expectEqual(
                input.expected,
                diagnostic.code,
            ),
        }
    }

    const expanded = try normalize(std.testing.allocator, &.{.{
        .bytes = "Types: deb\nURIs: https://a.test https://b.test\n" ++
            "Suites: stable testing\nComponents: main contrib\n" ++
            "Architectures: amd64 arm64\n",
        .format = .deb822,
    }}, null, .{ .max_repositories = 15 });
    switch (expanded) {
        .configuration => |value| {
            var unexpected = value;
            unexpected.deinit();
            return error.ExpectedDiagnostic;
        },
        .diagnostic => |diagnostic| try std.testing.expectEqual(
            DiagnosticCode.too_many_repositories,
            diagnostic.code,
        ),
    }

    const excessive_deadline = try normalize(std.testing.allocator, &.{.{
        .bytes = "deb [arch=amd64] https://example.test stable main\n",
        .format = .legacy,
        .policy = .{ .deadlines = .{
            .connect_ms = std.math.maxInt(u64),
            .read_ms = 1,
            .overall_ms = 1,
        } },
    }}, null, .{});
    switch (excessive_deadline) {
        .configuration => |value| {
            var unexpected = value;
            unexpected.deinit();
            return error.ExpectedDiagnostic;
        },
        .diagnostic => |diagnostic| try std.testing.expectEqual(
            DiagnosticCode.invalid_policy,
            diagnostic.code,
        ),
    }
}

test "conflicting policy changes configuration identity" {
    const source_document =
        "deb [arch=amd64] https://example.test stable main\n";
    const low_result = try normalize(std.testing.allocator, &.{.{
        .bytes = source_document,
        .format = .legacy,
        .policy = .{ .priority = 100 },
    }}, null, .{});
    var low = switch (low_result) {
        .configuration => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer low.deinit();
    const high_result = try normalize(std.testing.allocator, &.{.{
        .bytes = source_document,
        .format = .legacy,
        .policy = .{ .priority = 900 },
    }}, null, .{});
    var high = switch (high_result) {
        .configuration => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer high.deinit();
    try std.testing.expect(!std.mem.eql(u8, low.identity.slice(), high.identity.slice()));

    const conflict = try normalize(std.testing.allocator, &.{
        .{ .bytes = source_document, .format = .legacy, .policy = .{ .priority = 100 } },
        .{ .bytes = source_document, .format = .legacy, .policy = .{ .priority = 900 } },
    }, null, .{});
    switch (conflict) {
        .configuration => |value| {
            var unexpected = value;
            unexpected.deinit();
            return error.ExpectedDiagnostic;
        },
        .diagnostic => |value| try std.testing.expectEqual(
            DiagnosticCode.conflicting_repository,
            value.code,
        ),
    }
}

const PolicyTestFixture = struct {
    files: []const []const u8,
    next: usize = 0,

    fn dependencies(self: *PolicyTestFixture) acquisition.Dependencies {
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
        _: ?*anyopaque,
        _: std.mem.Allocator,
        _: acquisition.HttpRequest,
    ) !acquisition.HttpResponse {
        return error.NetworkForbidden;
    }

    fn readFile(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        _: []const u8,
        limit: usize,
        _: acquisition.Deadlines,
    ) !acquisition.FileRead {
        const self: *PolicyTestFixture = @ptrCast(@alignCast(context.?));
        if (self.next >= self.files.len) return error.FileNotFound;
        const bytes = self.files[self.next];
        self.next += 1;
        if (bytes.len > limit) return error.ResponseTooLarge;
        return .{ .bytes = try allocator.dupe(u8, bytes), .regular = true };
    }

    fn zeroMilliseconds(_: ?*anyopaque) u64 {
        return 0;
    }

    fn noSleep(_: ?*anyopaque, _: u64) !void {}
};

fn policyTestNow(_: ?*anyopaque) i64 {
    return @import("fixtures/openpgp.zig").created + 30;
}

fn policyTestRuntime(repository: NormalizedRepository) Runtime {
    const fixture = @import("fixtures/openpgp.zig");
    return .{
        .repository_id = repository.id,
        .declared_credentials = repository.credentials,
        .declared_keyrings = repository.signed_by,
        .authentication = .{ .in_release = .{
            .keyrings = .{ .one = .{ .bytes = &fixture.keyring } },
            .accepted_primary_fingerprints = &.{fixture.primary_fingerprint},
            .verification_time = fixture.created + 30,
        } },
        .acquisition = .{
            .deadlines = repository.deadlines,
            .redirect_limit = 0,
            .maximum_release_bytes = 64 * 1024,
        },
        .refresh = .{
            .mode = .online,
            .compression_order = &.{.uncompressed},
            .by_hash_fallback = .disabled,
            .maximum_future_seconds = 300,
            .expiry_policy = .require_valid_until,
            .maximum_compressed_bytes = 64 * 1024,
            .maximum_decompressed_bytes = 128 * 1024,
            .maximum_decoder_memory = 4 * 1024 * 1024,
        },
    };
}

test "authenticated multi repository refresh is atomic cache reusable and prioritized" {
    const fixture = @import("fixtures/openpgp.zig");
    const result = try normalize(std.testing.allocator, &.{
        .{
            .bytes = "deb [arch=amd64 signed-by=/keys/archive.gpg] file:///low stable main\n",
            .format = .legacy,
            .policy = .{ .priority = 100 },
        },
        .{
            .bytes = "deb [arch=amd64 signed-by=/keys/archive.gpg] file:///high stable main\n",
            .format = .legacy,
            .policy = .{ .priority = 900 },
        },
        .{
            .bytes = "# deb [arch=amd64] file:///disabled stable main\n",
            .format = .legacy,
        },
    }, null, .{});
    var configuration = switch (result) {
        .configuration => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer configuration.deinit();

    var runtimes_storage: [2]Runtime = undefined;
    var runtime_count: usize = 0;
    for (configuration.repositories) |repository| {
        if (!repository.enabled) continue;
        runtimes_storage[runtime_count] = policyTestRuntime(repository);
        runtime_count += 1;
    }

    const runtimes = runtimes_storage[0..runtime_count];
    var files = [_][]const u8{
        &fixture.repository_in_release,
        &fixture.repository_packages,
        &fixture.repository_in_release,
        &fixture.repository_packages,
    };
    var refresh_fixture: PolicyTestFixture = .{ .files = &files };
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var cache = try cache_module.Cache.initFromDir(std.testing.io, temporary.dir, .{
        .max_object_bytes = 512 * 1024,
    });
    defer cache.deinit();
    const dependencies: refresh_module.Dependencies = .{
        .acquisition = refresh_fixture.dependencies(),
        .cache = &cache,
        .clock = .{ .context = null, .nowUnixFn = policyTestNow },
        .io = std.testing.io,
    };
    var outcome = try refreshAll(std.testing.allocator, .{
        .configuration = &configuration,
        .runtimes = runtimes,
        .mode = .online,
        .dependencies = dependencies,
    });
    var online = switch (outcome) {
        .published => |value| value,
        .failed => return error.UnexpectedRefreshFailure,
    };
    outcome = undefined;
    try std.testing.expectEqual(@as(usize, 2), online.snapshots.len);
    try std.testing.expectEqual(@as(usize, 2), online.universe.candidates.len);
    try std.testing.expectEqual(@as(i32, 900), online.universe.candidates[0].priority);
    try std.testing.expectEqualStrings(
        online.universe.candidates[0].version,
        online.universe.candidates[1].version,
    );
    const manifest_copy = try std.testing.allocator.dupe(u8, online.aggregate_manifest);
    defer std.testing.allocator.free(manifest_copy);
    online.deinit();

    var offline_fixture: PolicyTestFixture = .{ .files = &.{} };
    var offline_dependencies = dependencies;
    offline_dependencies.acquisition = offline_fixture.dependencies();
    var offline_outcome = try refreshAll(std.testing.allocator, .{
        .configuration = &configuration,
        .runtimes = runtimes,
        .mode = .cache_only,
        .dependencies = offline_dependencies,
    });
    defer offline_outcome.deinit(std.testing.allocator);
    const offline = switch (offline_outcome) {
        .published => |*value| value,
        .failed => return error.UnexpectedRefreshFailure,
    };
    try std.testing.expectEqualStrings(manifest_copy, offline.aggregate_manifest);
    try std.testing.expectEqual(@as(usize, 0), offline_fixture.next);
}

test "immutable repository reuses its first authenticated generation" {
    const fixture = @import("fixtures/openpgp.zig");
    const normalized = try normalize(std.testing.allocator, &.{.{
        .bytes = "deb [arch=amd64] file:///snapshot stable main\n",
        .format = .legacy,
        .policy = .{ .immutability = .{
            .kind = .snapshot,
            .declared_identity = "20260815T000000Z",
        } },
    }}, null, .{});
    var configuration = switch (normalized) {
        .configuration => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    const runtime = policyTestRuntime(configuration.repositories[0]);
    var files = [_][]const u8{
        &fixture.repository_in_release,
        &fixture.repository_packages,
    };
    var initial_fixture: PolicyTestFixture = .{ .files = &files };
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var cache = try cache_module.Cache.initFromDir(std.testing.io, temporary.dir, .{
        .max_object_bytes = 512 * 1024,
    });
    defer cache.deinit();
    var dependencies: refresh_module.Dependencies = .{
        .acquisition = initial_fixture.dependencies(),
        .cache = &cache,
        .clock = .{ .context = null, .nowUnixFn = policyTestNow },
        .io = std.testing.io,
    };
    var initial = try refreshAll(std.testing.allocator, .{
        .configuration = &configuration,
        .runtimes = &.{runtime},
        .mode = .online,
        .dependencies = dependencies,
    });
    defer initial.deinit(std.testing.allocator);
    const initial_digest = switch (initial) {
        .published => |*published| published.states[0].release_digest,
        .failed => return error.UnexpectedRefreshFailure,
    };

    var no_network_fixture: PolicyTestFixture = .{ .files = &.{} };
    dependencies.acquisition = no_network_fixture.dependencies();
    var reused = try refreshAll(std.testing.allocator, .{
        .configuration = &configuration,
        .runtimes = &.{runtime},
        .mode = .online,
        .dependencies = dependencies,
    });
    configuration.deinit();
    defer reused.deinit(std.testing.allocator);
    const published = switch (reused) {
        .published => |*value| value,
        .failed => return error.UnexpectedRefreshFailure,
    };
    try std.testing.expect(initial_digest.eql(published.states[0].release_digest));
    try std.testing.expectEqual(@as(usize, 0), no_network_fixture.next);
    try std.testing.expectEqualStrings(
        "20260815T000000Z",
        published.states[0].immutable_identity.?,
    );
}

test "ambient only proxy credentials and keyrings are rejected before acquisition" {
    const normalized = try normalize(std.testing.allocator, &.{.{
        .bytes = "deb [arch=amd64] file:///explicit stable main\n",
        .format = .legacy,
    }}, null, .{});
    var configuration = switch (normalized) {
        .configuration => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer configuration.deinit();
    var runtime = policyTestRuntime(configuration.repositories[0]);
    runtime.declared_credentials = .{ .id = "ambient-netrc" };
    runtime.declared_keyrings = &.{"/etc/apt/trusted.gpg"};

    var fixture: PolicyTestFixture = .{ .files = &.{} };
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var cache = try cache_module.Cache.initFromDir(std.testing.io, temporary.dir, .{});
    defer cache.deinit();
    var outcome = try refreshAll(std.testing.allocator, .{
        .configuration = &configuration,
        .runtimes = &.{runtime},
        .mode = .online,
        .dependencies = .{
            .acquisition = fixture.dependencies(),
            .cache = &cache,
            .clock = .{ .context = null, .nowUnixFn = policyTestNow },
            .io = std.testing.io,
        },
    });
    defer outcome.deinit(std.testing.allocator);
    switch (outcome) {
        .failed => |diagnostics| try std.testing.expectEqualStrings(
            "DeclaredPolicyMismatch",
            diagnostics[0].error_name,
        ),
        .published => return error.ExpectedRefreshFailure,
    }
    try std.testing.expectEqual(@as(usize, 0), fixture.next);

    const declared_runtime = policyTestRuntime(configuration.repositories[0]);
    var extra_runtime = declared_runtime;
    extra_runtime.repository_id = .{ .bytes = @splat('a') };
    var extra_outcome = try refreshAll(std.testing.allocator, .{
        .configuration = &configuration,
        .runtimes = &.{ declared_runtime, extra_runtime },
        .mode = .online,
        .dependencies = .{
            .acquisition = fixture.dependencies(),
            .cache = &cache,
            .clock = .{ .context = null, .nowUnixFn = policyTestNow },
            .io = std.testing.io,
        },
    });
    defer extra_outcome.deinit(std.testing.allocator);
    switch (extra_outcome) {
        .failed => |diagnostics| try std.testing.expectEqualStrings(
            "UnexpectedRuntime",
            diagnostics[0].error_name,
        ),
        .published => return error.ExpectedRefreshFailure,
    }
    try std.testing.expectEqual(@as(usize, 0), fixture.next);
}

test "repository failure does not publish a mixed aggregate and stale is explicit" {
    const fixture = @import("fixtures/openpgp.zig");
    const normalized = try normalize(std.testing.allocator, &.{
        .{
            .bytes = "deb [arch=amd64] file:///one stable main\n",
            .format = .legacy,
        },
        .{
            .bytes = "deb [arch=amd64] file:///two stable main\n",
            .format = .legacy,
        },
    }, null, .{});
    var configuration = switch (normalized) {
        .configuration => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer configuration.deinit();
    var runtimes = [_]Runtime{
        policyTestRuntime(configuration.repositories[0]),
        policyTestRuntime(configuration.repositories[1]),
    };
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var cache = try cache_module.Cache.initFromDir(std.testing.io, temporary.dir, .{
        .max_object_bytes = 512 * 1024,
    });
    defer cache.deinit();

    var initial_files = [_][]const u8{
        &fixture.repository_in_release,
        &fixture.repository_packages,
        &fixture.repository_in_release,
        &fixture.repository_packages,
    };
    var initial_fixture: PolicyTestFixture = .{ .files = &initial_files };
    var dependencies: refresh_module.Dependencies = .{
        .acquisition = initial_fixture.dependencies(),
        .cache = &cache,
        .clock = .{ .context = null, .nowUnixFn = policyTestNow },
        .io = std.testing.io,
    };
    var initial = try refreshAll(std.testing.allocator, .{
        .configuration = &configuration,
        .runtimes = &runtimes,
        .mode = .online,
        .dependencies = dependencies,
    });
    defer initial.deinit(std.testing.allocator);
    switch (initial) {
        .published => {},
        .failed => return error.UnexpectedRefreshFailure,
    }

    var failing_files = [_][]const u8{
        &fixture.repository_in_release,
        &fixture.repository_packages,
        "not an inrelease",
    };
    var failing_fixture: PolicyTestFixture = .{ .files = &failing_files };
    dependencies.acquisition = failing_fixture.dependencies();
    var failed = try refreshAll(std.testing.allocator, .{
        .configuration = &configuration,
        .runtimes = &runtimes,
        .mode = .online,
        .failure_policy = .all_or_nothing,
        .dependencies = dependencies,
    });
    defer failed.deinit(std.testing.allocator);
    switch (failed) {
        .failed => |diagnostics| {
            try std.testing.expectEqual(@as(usize, 1), diagnostics.len);
            try std.testing.expect(!diagnostics[0].stale_attempted);
        },
        .published => return error.ExpectedRefreshFailure,
    }
    var retained = try cache.lookup(
        std.testing.allocator,
        .{ .value = configuration.identity.slice() },
        aggregate_snapshot,
    );
    defer retained.deinit();
    const initial_manifest = switch (initial) {
        .published => |*published| published.aggregate_manifest,
        .failed => unreachable,
    };
    try std.testing.expectEqualStrings(initial_manifest, retained.bytes);

    var stale_files = [_][]const u8{
        &fixture.repository_in_release,
        &fixture.repository_packages,
        "not an inrelease",
    };
    var stale_fixture: PolicyTestFixture = .{ .files = &stale_files };
    dependencies.acquisition = stale_fixture.dependencies();
    var stale = try refreshAll(std.testing.allocator, .{
        .configuration = &configuration,
        .runtimes = &runtimes,
        .mode = .online,
        .failure_policy = .allow_stale_authenticated,
        .dependencies = dependencies,
    });
    defer stale.deinit(std.testing.allocator);
    const published = switch (stale) {
        .published => |*value| value,
        .failed => return error.UnexpectedRefreshFailure,
    };
    var stale_count: usize = 0;
    for (published.states) |state| stale_count += @intFromBool(state.stale);
    try std.testing.expectEqual(@as(usize, 1), stale_count);
}
