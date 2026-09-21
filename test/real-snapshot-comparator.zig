const std = @import("std");

const schema = "https://debz.dev/test/native-transaction-snapshot-v1";
const maximum_snapshot_bytes = 512 * 1024 * 1024;

const Counts = struct {
    filesystem: usize,
    status: usize,
    status_old: usize,
    info: usize,
    triggers: usize,
    updates: usize,
    alternatives: usize,
    parts: usize,
    staging: usize,
    database_files: usize,
    trace: usize,
};

const Summary = struct {
    schema: []const u8 = "https://debz.dev/test/real-snapshot-comparison-v1",
    version: u32 = 1,
    matched: bool = true,
    reference_sha256: [64]u8,
    reference_size: usize,
    candidate_sha256: [64]u8,
    candidate_size: usize,
    counts: Counts,
};

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const command = args.next() orelse return error.InvalidArguments;
    if (!std.mem.eql(u8, command, "compare")) return error.InvalidArguments;
    const reference_path = args.next() orelse return error.InvalidArguments;
    const candidate_path = args.next() orelse return error.InvalidArguments;
    const output_path = args.next() orelse return error.InvalidArguments;
    if (args.next() != null) return error.InvalidArguments;

    const allocator = init.arena.allocator();
    const reference_bytes = try readBounded(
        init.io,
        allocator,
        reference_path,
    );
    const candidate_bytes = try readBounded(
        init.io,
        allocator,
        candidate_path,
    );
    var reference = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        reference_bytes,
        .{ .allocate = .alloc_always },
    );
    defer reference.deinit();
    var candidate = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        candidate_bytes,
        .{ .allocate = .alloc_always },
    );
    defer candidate.deinit();

    const reference_counts = try validateSnapshot(reference.value);
    const candidate_counts = try validateSnapshot(candidate.value);
    if (!std.meta.eql(reference_counts, candidate_counts))
        return error.SnapshotCountMismatch;
    if (!equalValue(reference.value, candidate.value))
        return error.SnapshotMismatch;

    const summary: Summary = .{
        .reference_sha256 = digest(reference_bytes),
        .reference_size = reference_bytes.len,
        .candidate_sha256 = digest(candidate_bytes),
        .candidate_size = candidate_bytes.len,
        .counts = reference_counts,
    };
    const encoded = try std.json.Stringify.valueAlloc(
        allocator,
        summary,
        .{ .whitespace = .indent_2 },
    );
    var file = try std.Io.Dir.createFileAbsolute(
        init.io,
        output_path,
        .{ .truncate = true },
    );
    defer file.close(init.io);
    try file.writeStreamingAll(init.io, encoded);
    try file.writeStreamingAll(init.io, "\n");
    try file.sync(init.io);
}

fn readBounded(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) ![]u8 {
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(
        allocator,
        .limited(maximum_snapshot_bytes),
    );
}

fn digest(bytes: []const u8) [64]u8 {
    var value: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &value, .{});
    return std.fmt.bytesToHex(value, .lower);
}

fn validateSnapshot(value: std.json.Value) !Counts {
    const root = switch (value) {
        .object => |object| object,
        else => return error.InvalidSnapshot,
    };
    if (root.count() != 5 or
        !stringEquals(root.get("schema"), schema) or
        !integerEquals(root.get("version"), 1))
        return error.InvalidSnapshot;
    const filesystem = try arrayLength(root.get("filesystem"));
    const dpkg = switch (root.get("dpkg") orelse return error.InvalidSnapshot) {
        .object => |object| object,
        else => return error.InvalidSnapshot,
    };
    if (dpkg.count() != 10 or
        !isBool(dpkg.get("present")))
        return error.InvalidSnapshot;
    return .{
        .filesystem = filesystem,
        .status = try arrayLength(dpkg.get("status")),
        .status_old = try arrayLength(dpkg.get("status_old")),
        .info = try arrayLength(dpkg.get("info")),
        .triggers = try arrayLength(dpkg.get("triggers")),
        .updates = try arrayLength(dpkg.get("updates")),
        .alternatives = try arrayLength(dpkg.get("alternatives")),
        .parts = try arrayLength(dpkg.get("parts")),
        .staging = try arrayLength(dpkg.get("staging")),
        .database_files = try arrayLength(dpkg.get("files")),
        .trace = try arrayLength(root.get("trace")),
    };
}

fn stringEquals(value: ?std.json.Value, expected: []const u8) bool {
    const actual = value orelse return false;
    return switch (actual) {
        .string => |text| std.mem.eql(u8, text, expected),
        else => false,
    };
}

fn integerEquals(value: ?std.json.Value, expected: i64) bool {
    const actual = value orelse return false;
    return switch (actual) {
        .integer => |number| number == expected,
        else => false,
    };
}

fn isBool(value: ?std.json.Value) bool {
    const actual = value orelse return false;
    return actual == .bool;
}

fn arrayLength(value: ?std.json.Value) !usize {
    const actual = value orelse return error.InvalidSnapshot;
    return switch (actual) {
        .array => |array| array.items.len,
        else => error.InvalidSnapshot,
    };
}

fn equalValue(left: std.json.Value, right: std.json.Value) bool {
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) return false;
    return switch (left) {
        .null => true,
        .bool => |value| value == right.bool,
        .integer => |value| value == right.integer,
        .float => |value| value == right.float,
        .number_string => |value| std.mem.eql(
            u8,
            value,
            right.number_string,
        ),
        .string => |value| std.mem.eql(u8, value, right.string),
        .array => |array| blk: {
            if (array.items.len != right.array.items.len) break :blk false;
            for (array.items, right.array.items) |left_item, right_item|
                if (!equalValue(left_item, right_item)) break :blk false;
            break :blk true;
        },
        .object => |object| blk: {
            if (object.count() != right.object.count()) break :blk false;
            var iterator = object.iterator();
            while (iterator.next()) |entry| {
                const other = right.object.get(entry.key_ptr.*) orelse
                    break :blk false;
                if (!equalValue(entry.value_ptr.*, other)) break :blk false;
            }
            break :blk true;
        },
    };
}

fn fixture(comptime status: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        \\{{"schema":"{s}","version":1,"filesystem":[],"dpkg":{{"present":true,"status":[{{"package":"{s}"}}],"status_old":[],"info":[],"triggers":[],"updates":[],"alternatives":[],"parts":[],"staging":[],"files":[]}},"trace":[]}}
    ,
        .{ schema, status },
    );
}

test "real snapshot comparator accepts identical typed snapshots" {
    var left = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        fixture("installed"),
        .{},
    );
    defer left.deinit();
    var right = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        fixture("installed"),
        .{},
    );
    defer right.deinit();
    try std.testing.expect(equalValue(left.value, right.value));
    const counts = try validateSnapshot(left.value);
    try std.testing.expectEqual(@as(usize, 1), counts.status);
}

test "real snapshot comparator rejects one semantic difference" {
    var left = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        fixture("installed"),
        .{},
    );
    defer left.deinit();
    var right = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        fixture("config-files"),
        .{},
    );
    defer right.deinit();
    try std.testing.expect(!equalValue(left.value, right.value));
}
