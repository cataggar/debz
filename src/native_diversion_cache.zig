const std = @import("std");
const native_diversion = @import("native_diversion.zig");
const native_recovery = @import("native_recovery.zig");
const package_database = @import("package_database.zig");

const Digest = native_recovery.Digest;
const maximum_contents_bytes = (package_database.Limits{}).max_database_file_bytes;
pub const maximum_document_bytes = std.base64.standard.Encoder.calcSize(maximum_contents_bytes) + 4096;
const schema_name = "https://debz.dev/schema/native-diversion-cache-v1";

const Document = struct {
    schema: []const u8 = schema_name,
    version: u32 = 1,
    intent_sha256: Digest,
    loaded: ?native_diversion.Observation,
    observed: ?native_diversion.Observation,
    contents_base64: ?[]const u8,
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

fn validateIdentities(loaded: ?native_diversion.Observation, observed: ?native_diversion.Observation) !void {
    if (loaded) |source| {
        if (observed == null or !source.sameFile(observed.?))
            return error.InvalidDiversionCache;
    } else if (observed != null) return error.InvalidDiversionCache;
}

fn documentDigest(document: Document) Digest {
    var payload = document;
    payload.digest_sha256 = @splat('0');
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-native-diversion-cache-v1\x00") catch unreachable;
    std.json.Stringify.value(payload, .{ .whitespace = .minified }, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return native_recovery.hexDigest(sink.hasher.finalResult());
}

pub fn encode(
    allocator: std.mem.Allocator,
    cache: native_diversion.CachedRecords,
    intent_sha256: Digest,
) ![]u8 {
    if (native_recovery.parseDigest(intent_sha256) == null)
        return error.InvalidDiversionCache;
    try validateIdentities(cache.loaded, cache.observed);
    const encoded = if (cache.bytes) |bytes| block: {
        if (bytes.len > maximum_contents_bytes or cache.loaded == null)
            return error.InvalidDiversionCache;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        if (!std.mem.eql(u8, &digest, &cache.loaded.?.sha256))
            return error.InvalidDiversionCache;
        const output = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len));
        _ = std.base64.standard.Encoder.encode(output, bytes);
        break :block output;
    } else block: {
        if (cache.loaded != null) return error.InvalidDiversionCache;
        break :block null;
    };
    defer if (encoded) |bytes| allocator.free(bytes);
    var document: Document = .{
        .intent_sha256 = intent_sha256,
        .loaded = cache.loaded,
        .observed = cache.observed,
        .contents_base64 = encoded,
    };
    document.digest_sha256 = documentDigest(document);
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    std.json.Stringify.value(document, .{ .whitespace = .minified }, &output.writer) catch
        return error.OutOfMemory;
    if (output.written().len > maximum_document_bytes)
        return error.InvalidDiversionCache;
    return output.toOwnedSlice();
}

pub fn decode(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    intent_sha256: Digest,
) !Decoded {
    if (bytes.len > maximum_document_bytes)
        return error.InvalidDiversionCache;
    var parsed = try std.json.parseFromSlice(Document, allocator, bytes, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
    defer parsed.deinit();
    const document = parsed.value;
    if (!std.mem.eql(u8, document.schema, schema_name) or document.version != 1 or
        !std.mem.eql(u8, &document.intent_sha256, &intent_sha256) or
        !std.mem.eql(u8, &document.digest_sha256, &documentDigest(document)))
        return error.InvalidDiversionCache;
    try validateIdentities(document.loaded, document.observed);
    const contents = if (document.contents_base64) |encoded| block: {
        const size = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch
            return error.InvalidDiversionCache;
        if (size > maximum_contents_bytes)
            return error.InvalidDiversionCache;
        const output = try allocator.alloc(u8, size);
        errdefer allocator.free(output);
        std.base64.standard.Decoder.decode(output, encoded) catch
            return error.InvalidDiversionCache;
        break :block output;
    } else null;
    defer if (contents) |value| allocator.free(value);
    var cache = try native_diversion.CachedRecords.init(allocator, contents, document.loaded);
    errdefer cache.deinit();
    cache.observed = document.observed;
    const canonical = try encode(allocator, cache, intent_sha256);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.InvalidDiversionCache;
    return .{ .cache = cache, .digest_sha256 = document.digest_sha256 };
}
