const std = @import("std");
const native_diversion = @import("native_diversion.zig");
const native_diversion_cache = @import("native_diversion_cache.zig");
const native_recovery = @import("native_recovery.zig");

const Digest = native_recovery.Digest;
const schema_name = "https://debz.dev/schema/native-unpack-diversion-v1";
pub const maximum_document_bytes = native_diversion_cache.maximum_document_bytes + 8192;

const Document = struct {
    schema: []const u8 = schema_name,
    version: u32 = 1,
    intent_sha256: Digest,
    program_step: u32,
    cache_json: []const u8,
    digest_sha256: Digest = @splat('0'),
};

pub const Decoded = struct {
    cache: native_diversion.CachedRecords,
    digest_sha256: Digest,

    pub fn deinit(self: *Decoded) void {
        self.cache.deinit();
        self.* = undefined;
    }
};

fn documentDigest(document: Document) Digest {
    var payload = document;
    payload.digest_sha256 = @splat('0');
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-native-unpack-diversion-v1\x00") catch unreachable;
    std.json.Stringify.value(payload, .{ .whitespace = .minified }, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return native_recovery.hexDigest(sink.hasher.finalResult());
}

pub fn encode(
    allocator: std.mem.Allocator,
    cache: native_diversion.CachedRecords,
    intent_sha256: Digest,
    program_step: u32,
) ![]u8 {
    const cache_json = try native_diversion_cache.encode(allocator, cache, intent_sha256);
    defer allocator.free(cache_json);
    var document: Document = .{
        .intent_sha256 = intent_sha256,
        .program_step = program_step,
        .cache_json = cache_json,
    };
    document.digest_sha256 = documentDigest(document);
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    std.json.Stringify.value(document, .{ .whitespace = .minified }, &output.writer) catch
        return error.OutOfMemory;
    if (output.written().len > maximum_document_bytes)
        return error.InvalidUnpackDiversionCache;
    return output.toOwnedSlice();
}

pub fn decode(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    intent_sha256: Digest,
    program_step: u32,
) !Decoded {
    if (bytes.len > maximum_document_bytes)
        return error.InvalidUnpackDiversionCache;
    var parsed = try std.json.parseFromSlice(Document, allocator, bytes, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
    defer parsed.deinit();
    const document = parsed.value;
    if (!std.mem.eql(u8, document.schema, schema_name) or document.version != 1 or
        !std.mem.eql(u8, &document.intent_sha256, &intent_sha256) or
        document.program_step != program_step or
        !std.mem.eql(u8, &document.digest_sha256, &documentDigest(document)))
        return error.InvalidUnpackDiversionCache;
    var decoded = try native_diversion_cache.decode(allocator, document.cache_json, intent_sha256);
    errdefer decoded.deinit();
    const canonical = try encode(allocator, decoded.cache, intent_sha256, program_step);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.InvalidUnpackDiversionCache;
    return .{ .cache = decoded.cache, .digest_sha256 = document.digest_sha256 };
}
