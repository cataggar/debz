//! Durable statoverride input for one native unpack invocation.
//!
//! dpkg reads the statoverride database once per `--unpack`/`--install`
//! invocation (`ensure_statoverrides` in `archivefiles`), before any archive
//! in it runs a maintainer script, and applies that resolution to every
//! extracted member. A native run of consecutive unpack steps is one such
//! invocation. When an earlier invocation may have edited the database, the
//! run's resolution is published here before its first step so that a crash
//! replays exactly the input dpkg would have used.

const std = @import("std");
const native_recovery = @import("native_recovery.zig");
const native_statoverride = @import("native_statoverride.zig");
const package_database = @import("package_database.zig");
const root_fs = @import("root_fs.zig");

const Digest = native_recovery.Digest;
const schema_name = "https://debz.dev/schema/native-unpack-statoverride-v1";
pub const maximum_document_bytes = 128 * 1024 * 1024;
const json_options: std.json.Stringify.Options = .{ .whitespace = .minified };

pub const Entry = struct {
    path: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
};

const Document = struct {
    schema: []const u8 = schema_name,
    version: u32 = 1,
    intent_sha256: Digest,
    program_step: u32,
    entries: []const Entry,
    digest_sha256: Digest = @splat('0'),
};

fn validateEntries(entries: []const Entry) !void {
    if (entries.len > (package_database.Limits{}).max_stat_overrides)
        return error.InvalidUnpackStatOverrideInput;
    var previous: ?[]const u8 = null;
    for (entries) |entry| {
        _ = root_fs.Path.initPackage(entry.path) catch
            return error.InvalidUnpackStatOverrideInput;
        if (previous) |path| {
            if (!std.mem.lessThan(u8, path, entry.path))
                return error.InvalidUnpackStatOverrideInput;
        }
        previous = entry.path;
        if (entry.mode > 0o7777 or
            entry.uid == std.math.maxInt(u32) or
            entry.gid == std.math.maxInt(u32))
            return error.InvalidUnpackStatOverrideInput;
    }
}

fn documentDigest(document: Document) Digest {
    var payload = document;
    payload.digest_sha256 = @splat('0');
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-native-unpack-statoverride-v1\x00") catch unreachable;
    std.json.Stringify.value(payload, json_options, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return native_recovery.hexDigest(sink.hasher.finalResult());
}

fn encodeEntries(
    allocator: std.mem.Allocator,
    entries: []const Entry,
    intent_sha256: Digest,
    program_step: u32,
) ![]u8 {
    try validateEntries(entries);
    var document: Document = .{
        .intent_sha256 = intent_sha256,
        .program_step = program_step,
        .entries = entries,
    };
    document.digest_sha256 = documentDigest(document);
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    std.json.Stringify.value(document, json_options, &output.writer) catch
        return error.OutOfMemory;
    if (output.written().len > maximum_document_bytes)
        return error.InvalidUnpackStatOverrideInput;
    return output.toOwnedSlice();
}

/// Encodes the path metadata of `resolved`; observation bookkeeping is not
/// part of the input.
pub fn encode(
    allocator: std.mem.Allocator,
    resolved: native_statoverride.Resolved,
    intent_sha256: Digest,
    program_step: u32,
) ![]u8 {
    const entries = try allocator.alloc(Entry, resolved.paths.count());
    defer allocator.free(entries);
    var iterator = resolved.paths.iterator();
    var index: usize = 0;
    while (iterator.next()) |item| : (index += 1) {
        entries[index] = .{
            .path = item.key_ptr.*,
            .mode = item.value_ptr.mode,
            .uid = item.value_ptr.uid,
            .gid = item.value_ptr.gid,
        };
    }
    std.sort.heap(Entry, entries, {}, struct {
        fn less(_: void, left: Entry, right: Entry) bool {
            return std.mem.lessThan(u8, left.path, right.path);
        }
    }.less);
    return encodeEntries(allocator, entries, intent_sha256, program_step);
}

/// Storage belongs to `arena`; the result carries no observed paths or
/// identity files because the persisted resolution needs neither.
pub fn decode(
    arena: std.mem.Allocator,
    bytes: []const u8,
    intent_sha256: Digest,
    program_step: u32,
) !native_statoverride.Resolved {
    if (bytes.len > maximum_document_bytes)
        return error.InvalidUnpackStatOverrideInput;
    const document = std.json.parseFromSliceLeaky(Document, arena, bytes, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidUnpackStatOverrideInput,
    };
    if (!std.mem.eql(u8, document.schema, schema_name) or document.version != 1 or
        !std.mem.eql(u8, &document.intent_sha256, &intent_sha256) or
        document.program_step != program_step or
        !std.mem.eql(u8, &document.digest_sha256, &documentDigest(document)))
        return error.InvalidUnpackStatOverrideInput;
    const canonical = try encodeEntries(arena, document.entries, intent_sha256, program_step);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.InvalidUnpackStatOverrideInput;
    var result: native_statoverride.Resolved = .{};
    try result.paths.ensureTotalCapacity(arena, @intCast(document.entries.len));
    for (document.entries) |entry|
        result.paths.putAssumeCapacityNoClobber(entry.path, .{
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
        });
    return result;
}

const testing = std.testing;

fn testIntent(fill: u8) Digest {
    return @splat(fill);
}

fn testResolved(arena: std.mem.Allocator) !native_statoverride.Resolved {
    var resolved: native_statoverride.Resolved = .{};
    try resolved.paths.put(arena, "usr/share/b", .{ .mode = 0o4750, .uid = 42420, .gid = 42421 });
    try resolved.paths.put(arena, "etc/a.conf", .{ .mode = 0o640, .uid = 0, .gid = 42421 });
    return resolved;
}

test "native_unpack.test.unpack statoverride input round trips canonically" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const intent = testIntent('a');
    const bytes = try encode(testing.allocator, try testResolved(arena), intent, 7);
    defer testing.allocator.free(bytes);
    try testing.expect(std.mem.indexOf(u8, bytes, "\"path\":\"etc/a.conf\"").? <
        std.mem.indexOf(u8, bytes, "\"path\":\"usr/share/b\"").?);
    const decoded = try decode(arena, bytes, intent, 7);
    try testing.expectEqual(@as(u32, 2), decoded.paths.count());
    try testing.expectEqual(
        native_statoverride.Metadata{ .mode = 0o4750, .uid = 42420, .gid = 42421 },
        decoded.get("usr/share/b").?,
    );
    try testing.expectEqual(
        native_statoverride.Metadata{ .mode = 0o640, .uid = 0, .gid = 42421 },
        decoded.get("etc/a.conf").?,
    );
    try testing.expectEqual(@as(usize, 0), decoded.observed_paths.len);
    const again = try encode(testing.allocator, decoded, intent, 7);
    defer testing.allocator.free(again);
    try testing.expectEqualStrings(bytes, again);

    const empty = try encode(testing.allocator, .{}, intent, 3);
    defer testing.allocator.free(empty);
    try testing.expectEqual(@as(u32, 0), (try decode(arena, empty, intent, 3)).paths.count());
}

test "native_unpack.test.unpack statoverride input rejects rebinding and tampering" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const intent = testIntent('a');
    const bytes = try encode(testing.allocator, try testResolved(arena), intent, 7);
    defer testing.allocator.free(bytes);
    try testing.expectError(error.InvalidUnpackStatOverrideInput, decode(arena, bytes, testIntent('b'), 7));
    try testing.expectError(error.InvalidUnpackStatOverrideInput, decode(arena, bytes, intent, 8));

    const tampered = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(tampered);
    const mode = std.mem.indexOf(u8, tampered, "\"mode\":2536").?;
    tampered[mode + "\"mode\":".len] = '3';
    try testing.expectError(error.InvalidUnpackStatOverrideInput, decode(arena, tampered, intent, 7));

    const spaced = try std.mem.replaceOwned(u8, testing.allocator, bytes, ",\"uid\"", ", \"uid\"");
    defer testing.allocator.free(spaced);
    try testing.expectError(error.InvalidUnpackStatOverrideInput, decode(arena, spaced, intent, 7));

    const unknown = try std.mem.replaceOwned(u8, testing.allocator, bytes, "{\"schema\"", "{\"extra\":1,\"schema\"");
    defer testing.allocator.free(unknown);
    try testing.expectError(error.InvalidUnpackStatOverrideInput, decode(arena, unknown, intent, 7));
}

test "native_unpack.test.unpack statoverride input rejects noncanonical entries" {
    const intent = testIntent('a');
    const sorted = [_]Entry{
        .{ .path = "etc/a", .mode = 0o644, .uid = 0, .gid = 0 },
        .{ .path = "etc/b", .mode = 0o644, .uid = 0, .gid = 0 },
    };
    const valid = try encodeEntries(testing.allocator, &sorted, intent, 1);
    testing.allocator.free(valid);
    for ([_][2]Entry{
        .{ sorted[1], sorted[0] },
        .{ sorted[0], sorted[0] },
        .{ sorted[0], .{ .path = "/etc/c", .mode = 0o644, .uid = 0, .gid = 0 } },
        .{ sorted[0], .{ .path = "etc/c", .mode = 0o10644, .uid = 0, .gid = 0 } },
        .{ sorted[0], .{ .path = "etc/c", .mode = 0o644, .uid = std.math.maxInt(u32), .gid = 0 } },
        .{ sorted[0], .{ .path = "etc/../c", .mode = 0o644, .uid = 0, .gid = 0 } },
    }) |entries| {
        try testing.expectError(
            error.InvalidUnpackStatOverrideInput,
            encodeEntries(testing.allocator, &entries, intent, 1),
        );
    }
}
