const std = @import("std");
const absolute_path = @import("absolute_path.zig");

pub const api_version: u32 = 1;
pub const schema_id = "https://debz.dev/schema/repository-operation-result-v1";
pub const schema_version: u32 = 1;
pub const maximum_document_bytes: usize = 1024 * 1024;
pub const maximum_diagnostics: usize = 8;

pub const Operation = enum {
    add,
};

pub const TrustMode = enum {
    verified_https,
    pinned_sha256,
};

pub const PhaseState = enum {
    pending,
    complete,
    skipped,
    failed,
};

pub const ExitStatus = enum(u8) {
    success = 0,
    usage = 2,
    unavailable = 3,
    authentication = 4,
    planning = 5,
    download = 6,
    transaction = 7,
    post_install = 8,
    recovery = 9,
    internal = 70,
};

pub const DiagnosticId = enum {
    unsupported_api_version,
    invalid_request,
    invalid_root,
    invalid_descriptor_url,
    credential_bearing_url,
    insecure_unpinned_url,
    invalid_digest,
    target_configuration_failed,
    architecture_unavailable,
    acquisition_failed,
    descriptor_invalid,
    descriptor_dynamic,
    descriptor_trust_unresolved,
    repository_authentication_failed,
    dependency_planning_failed,
    dependency_refresh_failed,
    dependency_acquisition_failed,
    existing_descriptor_conflict,
    managed_file_conflict,
    lock_publication_failed,
    transaction_failed,
    installed_verification_failed,
    target_import_failed,
    refresh_failed,
    provenance_publication_failed,
    resource_limit_exceeded,
    state_persistence_failed,
    state_corrupt,
    recovery_required,
    internal_error,
};

pub const Diagnostic = struct {
    id: DiagnosticId,
    phase: ?[]const u8 = null,
    message: []const u8,
};

pub const NetworkPolicy = struct {
    proxy_url: ?[]const u8 = null,
    connect_timeout_ms: u64 = 10_000,
    read_timeout_ms: u64 = 30_000,
    overall_timeout_ms: u64 = 5 * 60 * 1000,
    redirect_limit: u16 = 8,
    retry_attempts: u16 = 6,
    retry_backoff_ms: u64 = 2_000,
    maximum_descriptor_bytes: usize = 128 * 1024 * 1024,
    maximum_package_bytes: usize = 1024 * 1024 * 1024,
    maximum_release_bytes: usize = 16 * 1024 * 1024,
    maximum_compressed_index_bytes: usize = 64 * 1024 * 1024,
    maximum_decompressed_index_bytes: usize = 256 * 1024 * 1024,
    maximum_decoder_memory: u64 = 256 * 1024 * 1024,
};

pub const CachePolicy = struct {
    /// Logical absolute path inside `root`; null selects `/var/cache/debz`.
    path: ?[]const u8 = null,
    maximum_object_bytes: usize = 1024 * 1024 * 1024,
};

pub const StatePolicy = struct {
    /// Logical absolute path inside `root`; null selects `/var/lib/debz`.
    path: ?[]const u8 = null,
    lock_wait_ms: u64 = 30_000,
    maximum_operation_state_bytes: usize = 1024 * 1024,
};

pub const ResourcePolicy = struct {
    maximum_repositories: usize = 16,
    maximum_actions: usize = 4096,
    maximum_total_metadata_bytes: u64 = 2 * 1024 * 1024 * 1024,
    maximum_total_package_bytes: u64 = 8 * 1024 * 1024 * 1024,
    maximum_retained_package_bytes: u64 = 1280 * 1024 * 1024,
    maximum_cache_growth_bytes: u64 = 8 * 1024 * 1024 * 1024,
};

pub const Request = struct {
    api_version: u32 = api_version,
    operation: Operation = .add,
    root: []const u8,
    descriptor_url: []const u8,
    expected_sha256: ?[32]u8 = null,
    no_refresh: bool = false,
    architecture: ?[]const u8 = null,
    cache: CachePolicy = .{},
    state: StatePolicy = .{},
    network: NetworkPolicy = .{},
    resources: ResourcePolicy = .{},
};

pub const DescriptorIdentity = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    sha256: [32]u8,
    size: u64,
    effective_url: []const u8,
    trust_mode: TrustMode,
};

pub const EvidencePaths = struct {
    exact_lock: ?[]const u8 = null,
    provenance: ?[]const u8 = null,
    target_manifest: ?[]const u8 = null,
    operation_state: ?[]const u8 = null,
};

pub const Result = struct {
    api_version: u32 = api_version,
    operation: Operation = .add,
    acquired: PhaseState = .pending,
    validated: PhaseState = .pending,
    authenticated: PhaseState = .pending,
    planned: PhaseState = .pending,
    installed_phase: PhaseState = .pending,
    imported: PhaseState = .pending,
    refreshed_phase: PhaseState = .pending,
    changed: bool = false,
    installed: bool = false,
    refreshed: bool = false,
    descriptor: ?DescriptorIdentity = null,
    paths: EvidencePaths = .{},
    exit_status: ExitStatus,
    summary: []const u8,
    diagnostics: [maximum_diagnostics]Diagnostic = undefined,
    diagnostic_count: usize = 0,
    digest_sha256: [32]u8 = @splat(0),
    ownership: ?*ResultOwnership = null,

    pub fn deinit(self: *Result) void {
        const owner = self.ownership orelse return;
        const allocator = owner.backing_allocator;
        owner.arena.deinit();
        allocator.destroy(owner);
        self.* = undefined;
    }

    pub fn canonicalJson(self: Result, allocator: std.mem.Allocator) ![]u8 {
        try validateResult(self);
        if (!std.mem.eql(u8, &self.digest_sha256, &digestPayload(self)))
            return error.DigestMismatch;
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeDocument(self, &output.writer);
        const bytes = try output.toOwnedSlice();
        if (bytes.len > maximum_document_bytes) {
            allocator.free(bytes);
            return error.DocumentTooLarge;
        }
        return bytes;
    }

    pub fn humanSummary(self: Result, allocator: std.mem.Allocator) ![]u8 {
        if (self.descriptor) |descriptor| {
            return std.fmt.allocPrint(
                allocator,
                "{s}: {s}={s}:{s}; installed={s}; refreshed={s}",
                .{
                    self.summary,
                    descriptor.package,
                    descriptor.version,
                    descriptor.architecture,
                    if (self.installed) "yes" else "no",
                    if (self.refreshed) "yes" else "no",
                },
            );
        }
        return allocator.dupe(u8, self.summary);
    }
};

const ResultOwnership = struct {
    arena: std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,
};

pub fn ownResult(allocator: std.mem.Allocator, input: Result) !Result {
    const owner = try allocator.create(ResultOwnership);
    errdefer allocator.destroy(owner);
    owner.* = .{
        .arena = .init(allocator),
        .backing_allocator = allocator,
    };
    errdefer owner.arena.deinit();
    const owned = owner.arena.allocator();
    var result = input;
    result.summary = try owned.dupe(u8, input.summary);
    result.paths.exact_lock = try dupeOptional(owned, input.paths.exact_lock);
    result.paths.provenance = try dupeOptional(owned, input.paths.provenance);
    result.paths.target_manifest = try dupeOptional(owned, input.paths.target_manifest);
    result.paths.operation_state = try dupeOptional(owned, input.paths.operation_state);
    if (input.descriptor) |value| result.descriptor = .{
        .package = try owned.dupe(u8, value.package),
        .version = try owned.dupe(u8, value.version),
        .architecture = try owned.dupe(u8, value.architecture),
        .sha256 = value.sha256,
        .size = value.size,
        .effective_url = try owned.dupe(u8, value.effective_url),
        .trust_mode = value.trust_mode,
    };
    for (result.diagnostics[0..result.diagnostic_count]) |*diagnostic| {
        diagnostic.phase = try dupeOptional(owned, diagnostic.phase);
        diagnostic.message = try owned.dupe(u8, diagnostic.message);
    }
    result.ownership = owner;
    return result;
}

pub const OwnedResult = struct {
    result: Result,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedResult) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const Backend = struct {
    context: *anyopaque,
    executeFn: *const fn (*anyopaque, std.mem.Allocator, Request) anyerror!Result,

    pub fn execute(self: Backend, allocator: std.mem.Allocator, request: Request) !Result {
        return self.executeFn(self.context, allocator, request);
    }
};

pub fn execute(
    allocator: std.mem.Allocator,
    request: Request,
    backend: Backend,
) !Result {
    if (request.api_version != api_version)
        return failure(.usage, .unsupported_api_version, "request", "unsupported repository API version");
    if (!validRoot(request.root))
        return failure(.usage, .invalid_root, "request", "root must be a canonical absolute path");
    if (request.architecture) |architecture| {
        if (!validArchitecture(architecture))
            return failure(.usage, .invalid_request, "request", "architecture is invalid");
    }
    if (request.cache.path) |path| {
        if (!validLogicalPath(path))
            return failure(.usage, .invalid_request, "request", "cache path must be canonical and root-relative");
    }
    if (request.state.path) |path| {
        if (!validLogicalPath(path))
            return failure(.usage, .invalid_request, "request", "state path must be canonical and root-relative");
    }
    if (!validNetworkPolicy(request.network) or
        !validResourcePolicy(request.resources) or
        request.cache.maximum_object_bytes == 0 or
        request.state.lock_wait_ms == 0 or
        request.state.maximum_operation_state_bytes == 0 or
        request.state.maximum_operation_state_bytes > maximum_document_bytes)
        return failure(.usage, .invalid_request, "request", "resource policy is invalid or unbounded");

    const uri = std.Uri.parse(request.descriptor_url) catch
        return failure(.usage, .invalid_descriptor_url, "request", "descriptor URL is invalid");
    if (uri.user != null or uri.password != null)
        return failure(.usage, .credential_bearing_url, "request", "descriptor URL must not contain credentials");
    const pinned = request.expected_sha256 != null;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https") and
        !(pinned and (std.ascii.eqlIgnoreCase(uri.scheme, "http") or
            std.ascii.eqlIgnoreCase(uri.scheme, "file"))))
        return failure(.usage, .insecure_unpinned_url, "request", "unpinned descriptors require HTTPS");
    if (request.network.proxy_url) |proxy| {
        const proxy_uri = std.Uri.parse(proxy) catch
            return failure(.usage, .invalid_request, "request", "proxy URL is invalid");
        if (proxy_uri.user != null or proxy_uri.password != null)
            return failure(.usage, .credential_bearing_url, "request", "proxy URL must not contain credentials");
        if (!std.ascii.eqlIgnoreCase(proxy_uri.scheme, "http") and
            !std.ascii.eqlIgnoreCase(proxy_uri.scheme, "https"))
            return failure(.usage, .invalid_request, "request", "proxy URL scheme is unsupported");
    }
    return backend.execute(allocator, request);
}

pub fn complete(result: Result) !Result {
    var output = result;
    try validateResult(output);
    output.digest_sha256 = digestPayload(output);
    return output;
}

pub fn failure(
    status: ExitStatus,
    id: DiagnosticId,
    phase: []const u8,
    message: []const u8,
) Result {
    var result: Result = .{
        .exit_status = status,
        .summary = message,
        .diagnostics = undefined,
        .diagnostic_count = 1,
    };
    result.diagnostics[0] = .{ .id = id, .phase = phase, .message = message };
    result.digest_sha256 = digestPayload(result);
    return result;
}

pub fn validateResult(result: Result) !void {
    if (result.api_version != api_version) return error.UnsupportedApiVersion;
    if (result.diagnostic_count > maximum_diagnostics) return error.TooManyDiagnostics;
    if (result.summary.len == 0) return error.InvalidSummary;
    inline for (.{
        result.acquired,
        result.validated,
        result.authenticated,
        result.planned,
        result.installed_phase,
        result.imported,
    }) |phase| if (phase == .skipped) return error.InvalidPhaseOrder;
    if (result.validated != .pending and result.acquired != .complete)
        return error.InvalidPhaseOrder;
    if (result.authenticated != .pending and result.validated != .complete)
        return error.InvalidPhaseOrder;
    if (result.planned != .pending and result.authenticated != .complete)
        return error.InvalidPhaseOrder;
    if (result.installed_phase != .pending and result.planned != .complete)
        return error.InvalidPhaseOrder;
    if (result.imported != .pending and result.installed_phase != .complete)
        return error.InvalidPhaseOrder;
    if (result.refreshed_phase != .pending and result.imported != .complete)
        return error.InvalidPhaseOrder;
    if (result.exit_status == .success) {
        if (result.acquired != .complete or
            result.validated != .complete or
            result.authenticated != .complete or
            result.planned != .complete or
            result.installed_phase != .complete or
            result.imported != .complete or
            (result.refreshed_phase != .complete and result.refreshed_phase != .skipped) or
            !result.installed or
            result.descriptor == null or
            result.paths.exact_lock == null or
            result.paths.provenance == null or
            result.paths.target_manifest == null or
            result.paths.operation_state == null or
            result.diagnostic_count != 0)
            return error.PartialSuccess;
        if (result.refreshed_phase == .complete and !result.refreshed)
            return error.PartialSuccess;
        if (result.refreshed_phase == .skipped and result.refreshed)
            return error.PartialSuccess;
    } else if (result.diagnostic_count == 0) {
        return error.MissingDiagnostic;
    }
    if (result.installed != (result.installed_phase == .complete))
        return error.InvalidInstalledState;
    if (result.refreshed != (result.refreshed_phase == .complete))
        return error.InvalidRefreshState;
    if (result.changed and !result.installed) return error.InvalidChangedState;
    if (result.descriptor) |descriptor| {
        if (!validIdentity(descriptor.package) or
            !validIdentity(descriptor.version) or
            !validArchitecture(descriptor.architecture) or
            descriptor.size == 0 or
            descriptor.effective_url.len == 0)
            return error.InvalidDescriptor;
        const uri = std.Uri.parse(descriptor.effective_url) catch return error.InvalidDescriptor;
        if (uri.user != null or uri.password != null) return error.UnredactedCredential;
        if (uri.fragment != null) return error.UnredactedCredential;
        if (uri.query) |query| {
            const value = switch (query) {
                .raw, .percent_encoded => |bytes| bytes,
            };
            if (!std.mem.eql(u8, value, "REDACTED"))
                return error.UnredactedQuery;
        }
    }
    inline for (.{
        result.paths.exact_lock,
        result.paths.provenance,
        result.paths.target_manifest,
        result.paths.operation_state,
    }) |path| if (path) |value| {
        if (!validLogicalPath(value)) return error.InvalidPath;
    };
    for (result.diagnostics[0..result.diagnostic_count]) |diagnostic| {
        if (diagnostic.message.len == 0) return error.InvalidDiagnostic;
    }
}

const WireDescriptor = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    sha256: []const u8,
    size: u64,
    effective_url: []const u8,
    trust_mode: TrustMode,
};

const WirePaths = struct {
    exact_lock: ?[]const u8,
    provenance: ?[]const u8,
    target_manifest: ?[]const u8,
    operation_state: ?[]const u8,
};

const WireDiagnostic = struct {
    id: DiagnosticId,
    phase: ?[]const u8,
    message: []const u8,
};

const WireResult = struct {
    schema: []const u8,
    version: u32,
    api_version: u32,
    operation: Operation,
    acquired: PhaseState,
    validated: PhaseState,
    authenticated: PhaseState,
    planned: PhaseState,
    installed_phase: PhaseState,
    imported: PhaseState,
    refreshed_phase: PhaseState,
    changed: bool,
    installed: bool,
    refreshed: bool,
    descriptor: ?WireDescriptor,
    paths: WirePaths,
    exit_status: u8,
    summary: []const u8,
    diagnostics: []const WireDiagnostic,
    digest_sha256: []const u8,
};

pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !OwnedResult {
    if (maximum_bytes == 0 or maximum_bytes > maximum_document_bytes or
        source.len > maximum_bytes)
        return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(WireResult, allocator, source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    }) catch return error.InvalidDocument;
    defer parsed.deinit();
    const wire = parsed.value;
    if (!std.mem.eql(u8, wire.schema, schema_id) or wire.version != schema_version)
        return error.UnsupportedSchema;
    if (wire.diagnostics.len > maximum_diagnostics) return error.TooManyDiagnostics;
    const exit_status: ExitStatus = switch (wire.exit_status) {
        0 => .success,
        2 => .usage,
        3 => .unavailable,
        4 => .authentication,
        5 => .planning,
        6 => .download,
        7 => .transaction,
        8 => .post_install,
        9 => .recovery,
        70 => .internal,
        else => return error.InvalidExitStatus,
    };
    var digest: [32]u8 = undefined;
    try parseHex(&digest, wire.digest_sha256);
    var descriptor: ?DescriptorIdentity = null;
    if (wire.descriptor) |value| {
        var descriptor_digest: [32]u8 = undefined;
        try parseHex(&descriptor_digest, value.sha256);
        descriptor = .{
            .package = value.package,
            .version = value.version,
            .architecture = value.architecture,
            .sha256 = descriptor_digest,
            .size = value.size,
            .effective_url = value.effective_url,
            .trust_mode = value.trust_mode,
        };
    }
    var result: Result = .{
        .api_version = wire.api_version,
        .operation = wire.operation,
        .acquired = wire.acquired,
        .validated = wire.validated,
        .authenticated = wire.authenticated,
        .planned = wire.planned,
        .installed_phase = wire.installed_phase,
        .imported = wire.imported,
        .refreshed_phase = wire.refreshed_phase,
        .changed = wire.changed,
        .installed = wire.installed,
        .refreshed = wire.refreshed,
        .descriptor = descriptor,
        .paths = .{
            .exact_lock = wire.paths.exact_lock,
            .provenance = wire.paths.provenance,
            .target_manifest = wire.paths.target_manifest,
            .operation_state = wire.paths.operation_state,
        },
        .exit_status = exit_status,
        .summary = wire.summary,
        .diagnostics = undefined,
        .diagnostic_count = wire.diagnostics.len,
        .digest_sha256 = digest,
    };
    for (wire.diagnostics, 0..) |diagnostic, index| result.diagnostics[index] = .{
        .id = diagnostic.id,
        .phase = diagnostic.phase,
        .message = diagnostic.message,
    };
    try validateResult(result);
    if (!std.mem.eql(u8, &result.digest_sha256, &digestPayload(result)))
        return error.DigestMismatch;

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    result.summary = try owned.dupe(u8, result.summary);
    result.paths.exact_lock = try dupeOptional(owned, result.paths.exact_lock);
    result.paths.provenance = try dupeOptional(owned, result.paths.provenance);
    result.paths.target_manifest = try dupeOptional(owned, result.paths.target_manifest);
    result.paths.operation_state = try dupeOptional(owned, result.paths.operation_state);
    if (result.descriptor) |value| result.descriptor = .{
        .package = try owned.dupe(u8, value.package),
        .version = try owned.dupe(u8, value.version),
        .architecture = try owned.dupe(u8, value.architecture),
        .sha256 = value.sha256,
        .size = value.size,
        .effective_url = try owned.dupe(u8, value.effective_url),
        .trust_mode = value.trust_mode,
    };
    for (result.diagnostics[0..result.diagnostic_count]) |*diagnostic| {
        diagnostic.phase = try dupeOptional(owned, diagnostic.phase);
        diagnostic.message = try owned.dupe(u8, diagnostic.message);
    }
    var output: OwnedResult = .{
        .result = result,
        .arena = arena,
        .backing_allocator = allocator,
    };
    errdefer output.deinit();
    const canonical = try output.result.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return output;
}

fn dupeOptional(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
) std.mem.Allocator.Error!?[]const u8 {
    return if (value) |bytes| try allocator.dupe(u8, bytes) else null;
}

fn parseHex(output: []u8, value: []const u8) !void {
    if (value.len != output.len * 2) return error.InvalidDigest;
    for (output, 0..) |*byte, index| {
        byte.* = (@as(u8, try nibble(value[index * 2])) << 4) |
            try nibble(value[index * 2 + 1]);
    }
}

fn nibble(value: u8) !u4 {
    return switch (value) {
        '0'...'9' => @intCast(value - '0'),
        'a'...'f' => @intCast(value - 'a' + 10),
        else => error.InvalidDigest,
    };
}

fn validNetworkPolicy(policy: NetworkPolicy) bool {
    return policy.connect_timeout_ms != 0 and
        policy.read_timeout_ms != 0 and
        policy.overall_timeout_ms != 0 and
        policy.connect_timeout_ms <= policy.overall_timeout_ms and
        policy.read_timeout_ms <= policy.overall_timeout_ms and
        policy.redirect_limit <= 32 and
        policy.retry_attempts != 0 and
        policy.retry_attempts <= 16 and
        policy.maximum_descriptor_bytes != 0 and
        policy.maximum_package_bytes != 0 and
        policy.maximum_release_bytes != 0 and
        policy.maximum_compressed_index_bytes != 0 and
        policy.maximum_decompressed_index_bytes != 0 and
        policy.maximum_decoder_memory != 0;
}

fn validResourcePolicy(policy: ResourcePolicy) bool {
    return policy.maximum_repositories != 0 and
        policy.maximum_actions != 0 and
        policy.maximum_total_metadata_bytes != 0 and
        policy.maximum_total_package_bytes != 0 and
        policy.maximum_retained_package_bytes != 0 and
        policy.maximum_cache_growth_bytes != 0;
}

fn validRoot(path: []const u8) bool {
    return absolute_path.root(path);
}

fn validLogicalPath(path: []const u8) bool {
    return absolute_path.logical(path);
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0 or value.len > 64) return false;
    for (value) |byte| {
        if (!(std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-'))
            return false;
    }
    return true;
}

fn validIdentity(value: []const u8) bool {
    if (value.len == 0 or value.len > 4096 or std.mem.indexOfScalar(u8, value, 0) != null)
        return false;
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return true;
}

fn digestPayload(result: Result) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writePayload(result, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn writeDocument(result: Result, writer: *std.Io.Writer) !void {
    try writePayload(result, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHex(writer, &result.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(result: Result, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeString(writer, schema_id);
    try writer.print(",\"version\":{},\"api_version\":{},\"operation\":\"add\"", .{
        schema_version,
        result.api_version,
    });
    inline for (.{
        .{ "acquired", result.acquired },
        .{ "validated", result.validated },
        .{ "authenticated", result.authenticated },
        .{ "planned", result.planned },
        .{ "installed_phase", result.installed_phase },
        .{ "imported", result.imported },
        .{ "refreshed_phase", result.refreshed_phase },
    }) |field| {
        try writer.print(",\"{s}\":", .{field[0]});
        try writeString(writer, @tagName(field[1]));
    }
    try writer.print(
        ",\"changed\":{},\"installed\":{},\"refreshed\":{},\"descriptor\":",
        .{ result.changed, result.installed, result.refreshed },
    );
    if (result.descriptor) |descriptor| {
        try writer.writeAll("{\"package\":");
        try writeString(writer, descriptor.package);
        try writer.writeAll(",\"version\":");
        try writeString(writer, descriptor.version);
        try writer.writeAll(",\"architecture\":");
        try writeString(writer, descriptor.architecture);
        try writer.writeAll(",\"sha256\":");
        try writeHex(writer, &descriptor.sha256);
        try writer.print(",\"size\":{},\"effective_url\":", .{descriptor.size});
        try writeString(writer, descriptor.effective_url);
        try writer.writeAll(",\"trust_mode\":");
        try writeString(writer, @tagName(descriptor.trust_mode));
        try writer.writeByte('}');
    } else try writer.writeAll("null");
    try writer.writeAll(",\"paths\":{\"exact_lock\":");
    try writeOptionalString(writer, result.paths.exact_lock);
    try writer.writeAll(",\"provenance\":");
    try writeOptionalString(writer, result.paths.provenance);
    try writer.writeAll(",\"target_manifest\":");
    try writeOptionalString(writer, result.paths.target_manifest);
    try writer.writeAll(",\"operation_state\":");
    try writeOptionalString(writer, result.paths.operation_state);
    try writer.print("}},\"exit_status\":{},\"summary\":", .{@intFromEnum(result.exit_status)});
    try writeString(writer, result.summary);
    try writer.writeAll(",\"diagnostics\":[");
    for (result.diagnostics[0..result.diagnostic_count], 0..) |diagnostic, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"id\":");
        try writeString(writer, @tagName(diagnostic.id));
        try writer.writeAll(",\"phase\":");
        try writeOptionalString(writer, diagnostic.phase);
        try writer.writeAll(",\"message\":");
        try writeString(writer, diagnostic.message);
        try writer.writeByte('}');
    }
    try writer.writeAll("]}");
}

fn writeOptionalString(writer: *std.Io.Writer, value: ?[]const u8) !void {
    if (value) |bytes| try writeString(writer, bytes) else try writer.writeAll("null");
}

fn writeString(writer: *std.Io.Writer, value: []const u8) !void {
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

fn writeHex(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
    try writer.writeByte('"');
}

const TestBackend = struct {
    calls: usize = 0,

    fn interface(self: *TestBackend) Backend {
        return .{ .context = self, .executeFn = run };
    }

    fn run(context: *anyopaque, _: std.mem.Allocator, _: Request) !Result {
        const self: *TestBackend = @ptrCast(@alignCast(context));
        self.calls += 1;
        return failure(.unavailable, .internal_error, "test", "not implemented");
    }
};

test "repository API rejects unsafe trust and invalid root before backend" {
    var backend: TestBackend = .{};
    var request: Request = .{
        .root = "/target",
        .descriptor_url = "http://example.test/vendor.deb",
    };
    var result = try execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(ExitStatus.usage, result.exit_status);
    try std.testing.expectEqual(DiagnosticId.insecure_unpinned_url, result.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 0), backend.calls);

    request.root = "/target/../host";
    request.expected_sha256 = @splat(1);
    result = try execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(DiagnosticId.invalid_root, result.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 0), backend.calls);

    request.root = "/target";
    request.descriptor_url = "file:///artifacts/packages-microsoft-prod.deb";
    result = try execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(ExitStatus.unavailable, result.exit_status);
    try std.testing.expectEqual(@as(usize, 1), backend.calls);

    request.descriptor_url = "http://packages.microsoft.test/config.deb?token=secret";
    result = try execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(ExitStatus.unavailable, result.exit_status);
    try std.testing.expectEqual(@as(usize, 2), backend.calls);

    request.network.proxy_url = "https://user" ++ ":value@proxy.test";
    result = try execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(DiagnosticId.credential_bearing_url, result.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 2), backend.calls);

    request.network.proxy_url = null;
    request.resources.maximum_actions = 0;
    result = try execute(std.testing.allocator, request, backend.interface());
    try std.testing.expectEqual(DiagnosticId.invalid_request, result.diagnostics[0].id);
    try std.testing.expectEqual(@as(usize, 2), backend.calls);
}

test "repository API rejects invalid UTF-8 and control-containing absolute paths" {
    const invalid_paths = [_][]const u8{
        "/target\x00child",
        "/target\x1fchild",
        "/target\x7fchild",
        "/target/\xc3\x28",
    };
    for (invalid_paths) |path| {
        var backend: TestBackend = .{};
        var result = try execute(std.testing.allocator, .{
            .root = path,
            .descriptor_url = "file:///descriptor.deb",
        }, backend.interface());
        defer result.deinit();
        try std.testing.expectEqual(DiagnosticId.invalid_root, result.diagnostics[0].id);
        try std.testing.expectEqual(@as(usize, 0), backend.calls);

        result = try execute(std.testing.allocator, .{
            .root = "/target",
            .descriptor_url = "file:///descriptor.deb",
            .cache = .{ .path = path },
        }, backend.interface());
        try std.testing.expectEqual(DiagnosticId.invalid_request, result.diagnostics[0].id);
        try std.testing.expectEqual(@as(usize, 0), backend.calls);
    }
}

test "repository diagnostic enums serialize and exactly match both schemas" {
    const schemas = [_]struct {
        path: []const u8,
        state_schema: bool,
    }{
        .{ .path = "schema/repository-operation-result-v1.json", .state_schema = false },
        .{ .path = "schema/repository-add-state-v1.json", .state_schema = true },
    };
    for (schemas) |schema| {
        const source = try std.Io.Dir.cwd().readFileAlloc(
            std.testing.io,
            schema.path,
            std.testing.allocator,
            .limited(maximum_document_bytes),
        );
        defer std.testing.allocator.free(source);
        var parsed = try std.json.parseFromSlice(
            std.json.Value,
            std.testing.allocator,
            source,
            .{},
        );
        defer parsed.deinit();
        const definitions = parsed.value.object.get("$defs").?.object;
        const path_pattern = if (schema.state_schema)
            definitions.get("path").?.object.get("pattern").?.string
        else
            definitions.get("logicalPath").?.object.get("pattern").?.string;
        try std.testing.expectEqualStrings(absolute_path.schema_pattern, path_pattern);
        const values = if (schema.state_schema)
            definitions.get("diagnosticId").?.object.get("enum").?.array.items
        else
            definitions.get("diagnostic").?.object
                .get("properties").?.object
                .get("id").?.object
                .get("enum").?.array.items;
        try std.testing.expectEqual(std.meta.fields(DiagnosticId).len, values.len);
        inline for (std.meta.fields(DiagnosticId)) |field| {
            var matches: usize = 0;
            for (values) |value| {
                if (value == .string and std.mem.eql(u8, field.name, value.string))
                    matches += 1;
            }
            try std.testing.expectEqual(@as(usize, 1), matches);
        }
    }

    inline for (std.meta.fields(DiagnosticId)) |field| {
        const id: DiagnosticId = @enumFromInt(field.value);
        const result = failure(.internal, id, "test", "diagnostic");
        const document = try result.canonicalJson(std.testing.allocator);
        defer std.testing.allocator.free(document);
        var decoded = try decode(std.testing.allocator, document, maximum_document_bytes);
        defer decoded.deinit();
        try std.testing.expectEqual(id, decoded.result.diagnostics[0].id);
    }
}

test "repository result forbids success-shaped partial state and is deterministic" {
    var partial: Result = .{
        .exit_status = .success,
        .summary = "not complete",
    };
    partial.digest_sha256 = digestPayload(partial);
    try std.testing.expectError(error.PartialSuccess, partial.canonicalJson(std.testing.allocator));
    var invalid_order = failure(
        .usage,
        .descriptor_invalid,
        "validate",
        "invalid descriptor",
    );
    invalid_order.validated = .failed;
    try std.testing.expectError(
        error.InvalidPhaseOrder,
        complete(invalid_order),
    );

    var result = try complete(.{
        .acquired = .complete,
        .validated = .complete,
        .authenticated = .complete,
        .planned = .complete,
        .installed_phase = .complete,
        .imported = .complete,
        .refreshed_phase = .complete,
        .changed = true,
        .installed = true,
        .refreshed = true,
        .descriptor = .{
            .package = "packages-example-prod",
            .version = "1.2-example24.04",
            .architecture = "amd64",
            .sha256 = @splat(0x12),
            .size = 4096,
            .effective_url = "https://packages.example.test/config.deb?REDACTED",
            .trust_mode = .verified_https,
        },
        .paths = .{
            .exact_lock = "/var/lib/debz/repository/exact-lock-v2.json",
            .provenance = "/var/lib/debz/repository/transaction-result-v2.json",
            .target_manifest = "/var/lib/debz/repository/apt-config-snapshot-v1.json",
            .operation_state = "/var/lib/debz/repository/repo-add-state-v1.json",
        },
        .exit_status = .success,
        .summary = "repository added",
    });
    const first = try result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(first);
    const second = try result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualStrings(first, second);
    var decoded = try decode(std.testing.allocator, first, maximum_document_bytes);
    defer decoded.deinit();
    try std.testing.expectEqual(ExitStatus.success, decoded.result.exit_status);
    try std.testing.expectEqualStrings(
        "packages-example-prod",
        decoded.result.descriptor.?.package,
    );
    result.summary = "tampered";
    try std.testing.expectError(error.DigestMismatch, result.canonicalJson(std.testing.allocator));
}

test "repository result rejects unredacted descriptor query data" {
    var result = failure(.download, .acquisition_failed, "acquire", "failed");
    result.descriptor = .{
        .package = "packages-microsoft-prod",
        .version = "1",
        .architecture = "all",
        .sha256 = @splat(1),
        .size = 1,
        .effective_url = "https://packages.example.test/config.deb?token=secret",
        .trust_mode = .verified_https,
    };
    try std.testing.expectError(
        error.UnredactedQuery,
        result.canonicalJson(std.testing.allocator),
    );
}

test "repository result represents explicit no-refresh success" {
    const result = try complete(.{
        .acquired = .complete,
        .validated = .complete,
        .authenticated = .complete,
        .planned = .complete,
        .installed_phase = .complete,
        .imported = .complete,
        .refreshed_phase = .skipped,
        .installed = true,
        .descriptor = .{
            .package = "packages-microsoft-prod",
            .version = "1.1",
            .architecture = "all",
            .sha256 = @splat(0x44),
            .size = 1024,
            .effective_url = "https://packages.microsoft.test/config.deb?REDACTED",
            .trust_mode = .verified_https,
        },
        .paths = .{
            .exact_lock = "/var/lib/debz/repository/exact-lock-v2.json",
            .provenance = "/var/lib/debz/repository/transaction-result-v2.json",
            .target_manifest = "/var/lib/debz/repository/apt-config-snapshot-v1.json",
            .operation_state = "/var/lib/debz/repository/repo-add-state-v1.json",
        },
        .exit_status = .success,
        .summary = "repository added without refresh",
    });
    try std.testing.expect(!result.refreshed);
    try std.testing.expectEqual(PhaseState.skipped, result.refreshed_phase);
}
