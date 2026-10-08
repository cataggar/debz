const std = @import("std");
const baseline = @import("installed_baseline.zig");
const archives = @import("exact_lock_v3.zig");
const engine = @import("transaction_engine.zig");
const version = @import("debian_version.zig");
const status = @import("dpkg_status.zig");

pub const schema_id = "https://debz.dev/schema/exact-closure-lock-v4";
pub const schema_version: u32 = 4;
pub const maximum_document_bytes = archives.maximum_document_bytes;

const Payload = struct {
    schema: []const u8 = schema_id,
    version: u32 = schema_version,
    backend: engine.Kind,
    usage: enum { planning_only } = .planning_only,
    archive_lock_json: []const u8,
    installed_baseline: baseline.Evidence,
};

const Wire = struct {
    payload: Payload,
    digest_sha512: []const u8,
};

pub const OwnedLock = struct {
    parsed: std.json.Parsed(Wire),
    archive_lock: archives.OwnedLock,

    pub fn deinit(self: *OwnedLock) void {
        self.archive_lock.deinit();
        self.parsed.deinit();
        self.* = undefined;
    }

    pub fn backend(self: *const OwnedLock) engine.Kind {
        return self.parsed.value.payload.backend;
    }

    pub fn evidence(self: *const OwnedLock) baseline.Evidence {
        return self.parsed.value.payload.installed_baseline;
    }

    pub fn canonicalJson(self: *const OwnedLock, allocator: std.mem.Allocator) ![]u8 {
        return encode(allocator, self.parsed.value.payload);
    }

    pub fn requireExecutionAuthority(_: *const OwnedLock) error{InstalledBaselineExecutionUnsupported}!void {
        return error.InstalledBaselineExecutionUnsupported;
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
    archive_lock: archives.Lock,
    verified: *const baseline.Verified,
) !OwnedLock {
    const archive_bytes = try archive_lock.canonicalJson(allocator);
    defer allocator.free(archive_bytes);
    const bytes = try encode(allocator, .{
        .backend = backend,
        .archive_lock_json = archive_bytes,
        .installed_baseline = verified.evidence(),
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
    if (payload.version != schema_version or !std.mem.eql(u8, payload.schema, schema_id))
        return error.UnsupportedSchema;
    var archive_lock = try archives.decode(allocator, payload.archive_lock_json, maximum_document_bytes);
    errdefer archive_lock.deinit();
    const facts = payload.installed_baseline;
    if (facts.packages.len == 0 or
        facts.packages.len > archives.maximum_packages -| archive_lock.lock.packages.len or
        !std.mem.eql(u8, facts.native_architecture, archive_lock.lock.target_architecture) or
        facts.database_identity.value.len != 128)
        return error.InvalidInstalledBaseline;
    if (facts.root_path.len == 0 or facts.root_path[0] != '/' or
        facts.root_path.len > 4096 or std.mem.indexOfScalar(u8, facts.root_path, 0) != null)
        return error.InvalidInstalledBaseline;
    for (facts.database_identity.value) |byte| {
        if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f'))
            return error.InvalidInstalledBaseline;
    }
    var check_arena: std.heap.ArenaAllocator = .init(allocator);
    defer check_arena.deinit();
    const checking = check_arena.allocator();
    var archive_identities: std.StringHashMap(void) = .init(checking);
    for (archive_lock.lock.packages) |package| {
        try archive_identities.put(try std.fmt.allocPrint(checking, "{s}\x00{s}", .{ package.name, package.architecture }), {});
    }
    for (facts.packages, 0..) |package, index| {
        if (package.name.len == 0 or package.version.len == 0 or package.architecture.len == 0 or
            (package.selection != .install and package.selection != .hold) or
            archive_identities.contains(try std.fmt.allocPrint(checking, "{s}\x00{s}", .{ package.name, package.architecture })))
            return error.InvalidInstalledBaseline;
        const limits: status.Limits = .{};
        if (package.name.len > limits.max_package_name_bytes or
            package.architecture.len > limits.max_architecture_bytes or
            package.version.len > 4096 or
            std.mem.indexOfScalar(u8, package.name, 0) != null or
            std.mem.indexOfScalar(u8, package.architecture, 0) != null)
            return error.InvalidInstalledBaseline;
        _ = version.DebianVersion.parse(package.version) catch return error.InvalidInstalledBaseline;
        if (index != 0) {
            const previous = facts.packages[index - 1];
            const order = std.mem.order(u8, previous.name, package.name);
            if (order == .gt or (order == .eq and
                std.mem.order(u8, previous.architecture, package.architecture) != .lt))
                return error.InvalidInstalledBaseline;
        }
    }
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
    const payload = header.value.payload orelse return false;
    return std.mem.eql(u8, payload.schema, schema_id);
}
