const std = @import("std");
const database = @import("package_database.zig");
const mutation = @import("root_mutation.zig");
const root_fs = @import("root_fs.zig");
const recovery = @import("native_recovery.zig");

pub const maximum_writes = 200_000;
pub const maximum_content_bytes = 64 * 1024 * 1024;

pub const DatabaseEvidence = struct {
    base_generation: database.Generation,
    base_status: database.StatusGeneration,
    resulting_status: database.StatusGeneration,
    digest: [32]u8,
};

pub const File = struct {
    path: []const u8,
    bytes_hex: []const u8,
    sha256: recovery.Digest,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_nanoseconds: i128,
    overwrite: mutation.Overwrite,
};

pub const Write = union(enum) {
    file: File,
    metadata: mutation.MetadataIntent,
    remove: mutation.RemoveIntent,
    remove_directory: mutation.RemoveIntent,

    pub fn path(self: Write) []const u8 {
        return switch (self) {
            inline else => |value| value.path,
        };
    }
};

pub const Plan = struct {
    version: u32 = 1,
    unpack_plan_sha256: recovery.Digest,
    base_generation_sha256: recovery.Digest,
    base_generation_file_count: usize,
    base_generation_total_bytes: u64,
    base_status_sha256: recovery.Digest,
    base_status_size: usize,
    base_status_package_count: usize,
    resulting_status_sha256: recovery.Digest,
    resulting_status_size: usize,
    resulting_status_package_count: usize,
    database_plan_sha256: recovery.Digest,
    writes: []const Write,

    pub fn evidence(self: Plan) !DatabaseEvidence {
        return .{
            .base_generation = .{
                .sha256 = try parseDigest(self.base_generation_sha256),
                .file_count = self.base_generation_file_count,
                .total_bytes = self.base_generation_total_bytes,
            },
            .base_status = .{
                .sha256 = try parseDigest(self.base_status_sha256),
                .size = self.base_status_size,
                .package_count = self.base_status_package_count,
            },
            .resulting_status = .{
                .sha256 = try parseDigest(self.resulting_status_sha256),
                .size = self.resulting_status_size,
                .package_count = self.resulting_status_package_count,
            },
            .digest = try parseDigest(self.database_plan_sha256),
        };
    }
};

fn parseDigest(digest: recovery.Digest) ![32]u8 {
    for (digest) |byte| if (!(byte >= '0' and byte <= '9') and !(byte >= 'a' and byte <= 'f'))
        return error.InvalidUnpackSettlement;
    return recovery.parseDigest(digest) orelse error.InvalidUnpackSettlement;
}

fn encodeBytes(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, bytes.len * 2);
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        result[index * 2] = alphabet[byte >> 4];
        result[index * 2 + 1] = alphabet[byte & 15];
    }
    return result;
}

fn decodeBytes(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    if (text.len % 2 != 0 or text.len / 2 > maximum_content_bytes)
        return error.InvalidUnpackSettlement;
    for (text) |byte| if (!(byte >= '0' and byte <= '9') and !(byte >= 'a' and byte <= 'f'))
        return error.InvalidUnpackSettlement;
    const bytes = try allocator.alloc(u8, text.len / 2);
    errdefer allocator.free(bytes);
    _ = std.fmt.hexToBytes(bytes, text) catch return error.InvalidUnpackSettlement;
    return bytes;
}

pub fn validate(allocator: std.mem.Allocator, plan: Plan) !void {
    if (plan.version != 1 or plan.writes.len == 0 or plan.writes.len > maximum_writes)
        return error.InvalidUnpackSettlement;
    _ = try parseDigest(plan.unpack_plan_sha256);
    _ = try plan.evidence();
    var paths: std.StringHashMapUnmanaged(void) = .empty;
    defer paths.deinit(allocator);
    var total: u64 = 0;
    for (plan.writes) |write| {
        _ = root_fs.Path.initPackage(write.path()) catch return error.InvalidUnpackSettlement;
        const found = try paths.getOrPut(allocator, write.path());
        if (found.found_existing) return error.InvalidUnpackSettlement;
        switch (write) {
            .file => |file| {
                if (!std.mem.startsWith(u8, file.path, database.database_directory ++ "/") or file.mode > 0o7777)
                    return error.InvalidUnpackSettlement;
                if (file.modified_nanoseconds < mutation.minimum_timestamp_nanoseconds or
                    file.modified_nanoseconds > mutation.maximum_timestamp_nanoseconds)
                    return error.InvalidUnpackSettlement;
                total = std.math.add(u64, total, file.bytes_hex.len / 2) catch return error.InvalidUnpackSettlement;
                if (total > maximum_content_bytes) return error.InvalidUnpackSettlement;
                const bytes = try decodeBytes(allocator, file.bytes_hex);
                defer allocator.free(bytes);
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
                if (!std.mem.eql(u8, &digest, &try parseDigest(file.sha256))) return error.InvalidUnpackSettlement;
            },
            .metadata => |metadata| {
                if (metadata.mode == null and metadata.uid == null and metadata.gid == null and metadata.modified_nanoseconds == null)
                    return error.InvalidUnpackSettlement;
                if (metadata.mode) |mode| if (mode > 0o7777) return error.InvalidUnpackSettlement;
                if (metadata.modified_nanoseconds) |time|
                    if (time < mutation.minimum_timestamp_nanoseconds or time > mutation.maximum_timestamp_nanoseconds)
                        return error.InvalidUnpackSettlement;
            },
            .remove, .remove_directory => {},
        }
    }
    const last = plan.writes[plan.writes.len - 1];
    if (last != .file or !std.mem.eql(u8, last.file.path, database.database_directory ++ "/" ++ database.status_path) or
        !std.mem.eql(u8, &last.file.sha256, &plan.resulting_status_sha256) or
        last.file.bytes_hex.len / 2 != plan.resulting_status_size)
        return error.InvalidUnpackSettlement;
}

/// The caller's arena owns the immutable recipe and its binary-safe contents.
pub fn capture(
    allocator: std.mem.Allocator,
    intents: []const mutation.Intent,
    evidence: DatabaseEvidence,
    unpack_plan_sha256: [32]u8,
) !Plan {
    if (intents.len == 0 or intents.len > maximum_writes) return error.InvalidUnpackSettlement;
    var content_bytes: u64 = 0;
    for (intents) |intent| if (intent == .file) {
        content_bytes = std.math.add(u64, content_bytes, intent.file.bytes.len) catch return error.InvalidUnpackSettlement;
        if (content_bytes > maximum_content_bytes) return error.InvalidUnpackSettlement;
    };
    const writes = try allocator.alloc(Write, intents.len);
    for (intents, writes) |intent, *write| {
        write.* = switch (intent) {
            .file => |file| block: {
                if (file.artifact != null or file.bytes.len > maximum_content_bytes)
                    return error.InvalidUnpackSettlement;
                break :block .{ .file = .{
                    .path = try allocator.dupe(u8, file.path),
                    .bytes_hex = try encodeBytes(allocator, file.bytes),
                    .sha256 = recovery.hexDigest(file.expected_sha256 orelse return error.InvalidUnpackSettlement),
                    .mode = file.mode,
                    .uid = file.uid,
                    .gid = file.gid,
                    .modified_nanoseconds = file.modified_nanoseconds,
                    .overwrite = file.overwrite,
                } };
            },
            .metadata => |metadata| block: {
                var owned = metadata;
                owned.path = try allocator.dupe(u8, metadata.path);
                break :block .{ .metadata = owned };
            },
            .remove, .remove_directory => |removal| block: {
                var owned = removal;
                owned.path = try allocator.dupe(u8, removal.path);
                break :block if (intent == .remove) .{ .remove = owned } else .{ .remove_directory = owned };
            },
            else => return error.InvalidUnpackSettlement,
        };
    }
    const result: Plan = .{
        .unpack_plan_sha256 = recovery.hexDigest(unpack_plan_sha256),
        .base_generation_sha256 = recovery.hexDigest(evidence.base_generation.sha256),
        .base_generation_file_count = evidence.base_generation.file_count,
        .base_generation_total_bytes = evidence.base_generation.total_bytes,
        .base_status_sha256 = recovery.hexDigest(evidence.base_status.sha256),
        .base_status_size = evidence.base_status.size,
        .base_status_package_count = evidence.base_status.package_count,
        .resulting_status_sha256 = recovery.hexDigest(evidence.resulting_status.sha256),
        .resulting_status_size = evidence.resulting_status.size,
        .resulting_status_package_count = evidence.resulting_status.package_count,
        .database_plan_sha256 = recovery.hexDigest(evidence.digest),
        .writes = writes,
    };
    try validate(allocator, result);
    return result;
}

/// Reconstitutes only the original late intents; generic preflight still binds
/// their real post-script preimages under the caller's held operation.
pub fn lower(allocator: std.mem.Allocator, plan: Plan) ![]const mutation.Intent {
    try validate(allocator, plan);
    const intents = try allocator.alloc(mutation.Intent, plan.writes.len);
    for (plan.writes, intents) |write, *intent| {
        intent.* = switch (write) {
            .file => |file| .{ .file = .{
                .path = file.path,
                .bytes = try decodeBytes(allocator, file.bytes_hex),
                .expected_sha256 = try parseDigest(file.sha256),
                .mode = file.mode,
                .uid = file.uid,
                .gid = file.gid,
                .modified_nanoseconds = file.modified_nanoseconds,
                .overwrite = file.overwrite,
            } },
            .metadata => |metadata| .{ .metadata = metadata },
            .remove => |removal| .{ .remove = removal },
            .remove_directory => |removal| .{ .remove_directory = removal },
        };
    }
    return intents;
}
