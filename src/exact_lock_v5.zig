//! Healthy active-context planning composition, not execution permission.
const std = @import("std");
const archives = @import("exact_lock_v3.zig");
const historical = @import("exact_lock_v4.zig");
const healthy = @import("healthy_installed_prestate.zig");
const engine = @import("transaction_engine.zig");

pub const schema_id = "https://debz.dev/schema/exact-closure-lock-v5";
pub const schema_version: u32 = 5;
pub const maximum_document_bytes = archives.maximum_document_bytes;

pub const ContextBinding = struct {
    configuration_sha256: [64]u8,
    manifest_sha256: [32]u8,
};

const Payload = struct {
    schema: []const u8 = schema_id,
    version: u32 = schema_version,
    backend: engine.Kind,
    usage: enum { healthy_prestate_planning_only } = .healthy_prestate_planning_only,
    context: ContextBinding,
    archive_lock_json: []const u8,
    installed_prestate: healthy.Evidence,
};
const Wire = struct { payload: Payload, digest_sha512: []const u8 };

pub const OwnedLock = struct {
    parsed: std.json.Parsed(Wire),
    archive_lock: archives.OwnedLock,

    pub fn deinit(self: *OwnedLock) void {
        self.archive_lock.deinit();
        self.parsed.deinit();
        self.* = undefined;
    }

    pub fn evidence(self: *const OwnedLock) healthy.Evidence {
        return self.parsed.value.payload.installed_prestate;
    }

    pub fn backend(self: *const OwnedLock) engine.Kind {
        return self.parsed.value.payload.backend;
    }

    pub fn context(self: *const OwnedLock) ContextBinding {
        return self.parsed.value.payload.context;
    }

    pub fn canonicalJson(self: *const OwnedLock, allocator: std.mem.Allocator) ![]u8 {
        return encode(allocator, self.parsed.value.payload);
    }

    pub fn documentDigest(self: *const OwnedLock, allocator: std.mem.Allocator) ![32]u8 {
        const bytes = try self.canonicalJson(allocator);
        defer allocator.free(bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        return digest;
    }
};

fn encode(allocator: std.mem.Allocator, payload: Payload) ![]u8 {
    const bytes = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(bytes);
    var digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(bytes, &digest, .{});
    return std.json.Stringify.valueAlloc(allocator, Wire{
        .payload = payload,
        .digest_sha512 = &std.fmt.bytesToHex(digest, .lower),
    }, .{});
}

pub fn create(
    allocator: std.mem.Allocator,
    backend: engine.Kind,
    context: ContextBinding,
    archive_lock: archives.Lock,
    verified: *const healthy.Verified,
) !OwnedLock {
    const archive_bytes = try archive_lock.canonicalJson(allocator);
    defer allocator.free(archive_bytes);
    const bytes = try encode(allocator, .{
        .backend = backend,
        .context = context,
        .archive_lock_json = archive_bytes,
        .installed_prestate = verified.evidence(),
    });
    defer allocator.free(bytes);
    return decode(allocator, bytes);
}

pub fn rebindArchives(allocator: std.mem.Allocator, current: *const OwnedLock, archive_lock: archives.Lock) !OwnedLock {
    const archive_bytes = try archive_lock.canonicalJson(allocator);
    defer allocator.free(archive_bytes);
    var payload = current.parsed.value.payload;
    payload.archive_lock_json = archive_bytes;
    const bytes = try encode(allocator, payload);
    defer allocator.free(bytes);
    return decode(allocator, bytes);
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !OwnedLock {
    if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
    var parsed = try std.json.parseFromSlice(Wire, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
        .max_value_len = maximum_document_bytes,
    });
    errdefer parsed.deinit();
    const payload = parsed.value.payload;
    if (payload.version != schema_version or !std.mem.eql(u8, payload.schema, schema_id) or
        payload.installed_prestate.version != 1 or
        !std.mem.eql(u8, payload.installed_prestate.schema, healthy.schema_id))
        return error.UnsupportedSchema;
    for (payload.context.configuration_sha256) |byte| {
        if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f'))
            return error.InvalidContextBinding;
    }
    var archive_lock = try archives.decode(allocator, payload.archive_lock_json, maximum_document_bytes);
    errdefer archive_lock.deinit();
    try historical.validateEvidence(allocator, payload.installed_prestate.observed, archive_lock.lock);
    const canonical = try encode(allocator, payload);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes)) return error.NonCanonicalDocument;
    return .{ .parsed = parsed, .archive_lock = archive_lock };
}

pub fn hasSchema(allocator: std.mem.Allocator, bytes: []const u8) !bool {
    if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
    var header = try std.json.parseFromSlice(struct { payload: ?struct { schema: []const u8 } = null }, allocator, bytes, .{
        .ignore_unknown_fields = true,
        .max_value_len = maximum_document_bytes,
    });
    defer header.deinit();
    return if (header.value.payload) |payload| std.mem.eql(u8, payload.schema, schema_id) else false;
}

fn scopedSourceContains(source: []const u8, start: []const u8, end: []const u8, tokens: []const []const u8) bool {
    const first = std.mem.indexOf(u8, source, start) orelse return false;
    const last = std.mem.indexOfPos(u8, source, first + start.len, end) orelse return false;
    const body = source[first..last];
    for (tokens) |token| if (std.mem.indexOf(u8, body, token) == null) return false;
    return true;
}

test "exact_lock_v5.test sourceguards bind actual active resolver and historical execution refusals" {
    const allocator = std.testing.allocator;
    const source = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "src/production_backend.zig", allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(source);
    const resolver_tokens = &[_][]const u8{
        "active_context == null and findRetainedOrigin(",
        "healthy_installed_prestate.capture(",
        "lockFromPlan(exact_lock_v3,",
        "context.validateConfiguration()",
        "exact_lock_v5.create(",
        ".manifest_sha256 = context.snapshot().manifest.digest_sha256",
    };
    try std.testing.expect(scopedSourceContains(source, "fn resolveProductLock(", "fn lockFromPlan(", resolver_tokens));
    const execution_tokens = &[_][]const u8{
        "self.active_context != null and workflowMode(request.operation, workflow) != .plan_only",
        "context.validate() catch",
        "exact_lock_v5.hasSchema(",
        "InstalledPrestateExecutionUnsupported",
    };
    try std.testing.expect(scopedSourceContains(source, "fn withRepositories(", "fn withRepositoriesGuarded(", execution_tokens));
    const mutation = try std.mem.replaceOwned(u8, allocator, source, "context.validate() catch", "unchecked_active_context");
    defer allocator.free(mutation);
    const outside_poison = try std.fmt.allocPrint(allocator, "{s}\n// context.validate() catch\n", .{mutation});
    defer allocator.free(outside_poison);
    try std.testing.expect(!scopedSourceContains(outside_poison, "fn withRepositories(", "fn withRepositoriesGuarded(", execution_tokens));
    const cache_tokens = &[_][]const u8{".active_install => error.UnsupportedLockSchema"};
    try std.testing.expect(scopedSourceContains(source, "pub fn packageCacheFingerprint(", "pub fn packageCachePrepare(", cache_tokens));
    const publication_tokens = &[_][]const u8{
        "healthy_installed_prestate.verify(",
        "output_owner.uid != owned.evidence().observed.root_uid",
        "pinned.observeStableAlloc(",
        ".overwrite = .fail_if_exists",
        "BaselinePublicationCheck.hit",
    };
    try std.testing.expect(scopedSourceContains(source, "fn writeScoped(", "pub fn planningPolicyDigest(", publication_tokens));
    const unpinned = try std.mem.replaceOwned(u8, allocator, source, "pinned.observeStableAlloc(", "unchecked_output_read(");
    defer allocator.free(unpinned);
    const poisoned_publication = try std.fmt.allocPrint(allocator, "{s}\n// pinned.observeStableAlloc(\n", .{unpinned});
    defer allocator.free(poisoned_publication);
    try std.testing.expect(!scopedSourceContains(poisoned_publication, "fn writeScoped(", "pub fn planningPolicyDigest(", publication_tokens));
}
