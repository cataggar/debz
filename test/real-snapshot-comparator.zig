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
    if (!countsCompatible(
        reference_counts,
        candidate_counts,
        reference.value,
        candidate.value,
    ))
        return error.SnapshotCountMismatch;
    if (!try equalSnapshots(allocator, reference.value, candidate.value))
        return error.SnapshotMismatch;

    const summary: Summary = .{
        .reference_sha256 = digest(reference_bytes),
        .reference_size = reference_bytes.len,
        .candidate_sha256 = digest(candidate_bytes),
        .candidate_size = candidate_bytes.len,
        .counts = candidate_counts,
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
    if (root.count() != 6 or
        !stringEquals(root.get("schema"), schema) or
        !integerEquals(root.get("version"), 1))
        return error.InvalidSnapshot;
    const filesystem = try arrayLength(root.get("filesystem"));
    _ = try arrayLength(root.get("write_witnesses"));
    if (filesystem == 0) return error.InvalidSnapshot;
    const dpkg = switch (root.get("dpkg") orelse return error.InvalidSnapshot) {
        .object => |object| object,
        else => return error.InvalidSnapshot,
    };
    if (dpkg.count() != 10 or
        !isBool(dpkg.get("present")) or
        !dpkg.get("present").?.bool)
        return error.InvalidSnapshot;
    const status = try arrayLength(dpkg.get("status"));
    if (status == 0) return error.InvalidSnapshot;
    return .{
        .filesystem = filesystem,
        .status = status,
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

const volatile_unowned_files = [_][]const u8{
    "etc/machine-id",
    "var/cache/debconf/config.dat",
    "var/cache/debconf/config.dat-old",
    "var/cache/debconf/templates.dat",
    "var/cache/debconf/templates.dat-old",
    "var/cache/ldconfig/aux-cache",
    "var/log/alternatives.log",
    "var/log/dpkg.log",
};

const volatile_unowned_variable_size_files = [_][]const u8{
    "var/cache/debconf/config.dat",
    "var/cache/debconf/config.dat-old",
    "var/cache/debconf/templates.dat",
    "var/cache/debconf/templates.dat-old",
    "var/log/dpkg.log",
};

fn countsCompatible(
    reference_counts: Counts,
    candidate_counts: Counts,
    reference: std.json.Value,
    candidate: std.json.Value,
) bool {
    if (std.meta.eql(reference_counts, candidate_counts)) return true;
    var adjusted = candidate_counts;
    adjusted.filesystem += 1;
    if (!std.meta.eql(reference_counts, adjusted)) return false;
    return hasFilesystemPath(reference, "var/log/dpkg.log") and
        !hasFilesystemPath(candidate, "var/log/dpkg.log");
}

fn hasFilesystemPath(snapshot: std.json.Value, expected_path: []const u8) bool {
    if (snapshot != .object) return false;
    const files = snapshot.object.get("filesystem") orelse return false;
    if (files != .array) return false;
    for (files.array.items) |item| {
        if (item != .object) continue;
        if (stringEquals(item.object.get("path"), expected_path)) return true;
    }
    return false;
}

fn validReferenceOnlyDpkgLog(
    entry: std.json.Value,
    owned: *const std.StringHashMap(void),
) bool {
    if (owned.contains("var/log/dpkg.log")) return false;
    if (entry != .object or entry.object.count() != 10) return false;
    const obj = entry.object;
    if (!stringEquals(obj.get("path"), "var/log/dpkg.log") or
        !stringEquals(obj.get("kind"), "regular") or
        !stringEquals(obj.get("mode"), "0644") or
        !integerEquals(obj.get("uid"), 0) or
        !integerEquals(obj.get("gid"), 0))
        return false;
    const mtime_ns = obj.get("mtime_ns") orelse return false;
    const size = obj.get("size") orelse return false;
    const sha256 = obj.get("sha256") orelse return false;
    const xattrs = obj.get("xattrs") orelse return false;
    const hardlink_to = obj.get("hardlink_to") orelse return false;
    return mtime_ns == .integer and
        size == .integer and size.integer >= 0 and
        validDigest(sha256) and
        xattrs == .array and xattrs.array.items.len == 0 and
        hardlink_to == .null;
}

fn equalSnapshots(
    allocator: std.mem.Allocator,
    reference: std.json.Value,
    candidate: std.json.Value,
) !bool {
    const left = reference.object;
    const right = candidate.object;
    const left_dpkg = left.get("dpkg").?;
    if (!equalDpkg(left_dpkg, right.get("dpkg").?) or
        !equalValue(left.get("trace").?, right.get("trace").?))
        return false;

    var owned = std.StringHashMap(void).init(allocator);
    defer owned.deinit();
    for (left_dpkg.object.get("info").?.array.items) |item| {
        if (item != .object) return error.InvalidSnapshot;
        const record = item.object;
        const path = record.get("path") orelse return error.InvalidSnapshot;
        if (path != .string) return error.InvalidSnapshot;
        if (!std.mem.endsWith(u8, path.string, ".list")) continue;
        const kind = record.get("kind") orelse return error.InvalidSnapshot;
        const lines = record.get("lines") orelse return error.InvalidSnapshot;
        if (!stringEquals(kind, "path-list") or lines != .array)
            return error.InvalidSnapshot;
        for (lines.array.items) |line| {
            if (line != .string or line.string.len < 2 or line.string[0] != '/')
                return error.InvalidSnapshot;
            try owned.put(line.string[1..], {});
        }
    }
    for (volatile_unowned_files) |path| {
        if (owned.contains(path)) return error.VolatileFilePackageOwned;
    }

    const left_files = left.get("filesystem").?.array.items;
    const right_files = right.get("filesystem").?.array.items;
    if (left_files.len != right_files.len and left_files.len != right_files.len + 1)
        return false;
    var left_index: usize = 0;
    var right_index: usize = 0;
    var skipped_dpkg_log = false;
    while (left_index < left_files.len or right_index < right_files.len) {
        if (!skipped_dpkg_log and
            left_files.len == right_files.len + 1 and
            left_index < left_files.len and
            left_files[left_index] == .object and
            stringEquals(left_files[left_index].object.get("path"), "var/log/dpkg.log") and
            (right_index >= right_files.len or
                right_files[right_index] != .object or
                !stringEquals(right_files[right_index].object.get("path"), "var/log/dpkg.log")))
        {
            if (!validReferenceOnlyDpkgLog(left_files[left_index], &owned))
                return false;
            skipped_dpkg_log = true;
            left_index += 1;
            continue;
        }
        if (left_index >= left_files.len or right_index >= right_files.len)
            return false;
        if (!equalFilesystemEntry(left_files[left_index], right_files[right_index], &owned))
            return false;
        left_index += 1;
        right_index += 1;
    }
    return true;
}

fn equalDpkg(left: std.json.Value, right: std.json.Value) bool {
    if (left != .object or right != .object or left.object.count() != right.object.count())
        return false;
    var iterator = left.object.iterator();
    while (iterator.next()) |entry| {
        const other = right.object.get(entry.key_ptr.*) orelse return false;
        if (std.mem.eql(u8, entry.key_ptr.*, "status_old")) {
            if (!equalStatusOld(entry.value_ptr.*, other)) return false;
        } else if (std.mem.eql(u8, entry.key_ptr.*, "files")) {
            if (!equalDpkgFiles(entry.value_ptr.*, other)) return false;
        } else if (!equalValue(entry.value_ptr.*, other)) {
            return false;
        }
    }
    return true;
}

fn equalDpkgFiles(left: std.json.Value, right: std.json.Value) bool {
    if (left != .array or right != .array or left.array.items.len != right.array.items.len)
        return false;
    for (left.array.items, right.array.items) |left_item, right_item| {
        if (!equalDpkgFileRecord(left_item, right_item)) return false;
    }
    return true;
}

fn equalDpkgFileRecord(left: std.json.Value, right: std.json.Value) bool {
    if (left == .object and right == .object and
        stringEquals(left.object.get("path"), "var/lib/dpkg/diversions-old") and
        stringEquals(right.object.get("path"), "var/lib/dpkg/diversions-old"))
    {
        if (left.object.count() != 5 or right.object.count() != 5) return false;
        if (!stringEquals(left.object.get("kind"), "opaque") or
            !stringEquals(right.object.get("kind"), "opaque"))
            return false;
        const left_mode = left.object.get("mode") orelse return false;
        const right_mode = right.object.get("mode") orelse return false;
        if (left_mode != .string or !equalValue(left_mode, right_mode)) return false;
        const left_size = left.object.get("size") orelse return false;
        const right_size = right.object.get("size") orelse return false;
        if (left_size != .integer or right_size != .integer or
            left_size.integer < 0 or right_size.integer < 0)
            return false;
        return validDigest(left.object.get("sha256") orelse return false) and
            validDigest(right.object.get("sha256") orelse return false);
    }
    return equalValue(left, right);
}

fn equalStatusOld(left: std.json.Value, right: std.json.Value) bool {
    if (left != .array or right != .array or left.array.items.len != right.array.items.len)
        return false;
    for (left.array.items, right.array.items) |left_item, right_item| {
        if (!equalStatusOldRecord(left_item, right_item)) return false;
    }
    return true;
}

fn equalStatusOldRecord(left: std.json.Value, right: std.json.Value) bool {
    if (left != .object or right != .object) return false;
    var left_it = left.object.iterator();
    while (left_it.next()) |entry| {
        if (isStatusOldVolatileField(entry.key_ptr.*)) continue;
        const other = right.object.get(entry.key_ptr.*) orelse return false;
        if (!equalValue(entry.value_ptr.*, other)) return false;
    }
    var right_it = right.object.iterator();
    while (right_it.next()) |entry| {
        if (isStatusOldVolatileField(entry.key_ptr.*)) continue;
        if (!left.object.contains(entry.key_ptr.*)) return false;
    }
    return true;
}

fn isStatusOldVolatileField(key: []const u8) bool {
    return std.mem.eql(u8, key, "status") or
        std.mem.eql(u8, key, "config_version") or
        std.mem.eql(u8, key, "config-version") or
        std.mem.eql(u8, key, "conffiles") or
        std.mem.eql(u8, key, "triggers_pending") or
        std.mem.eql(u8, key, "triggers-pending") or
        std.mem.eql(u8, key, "triggers_awaited") or
        std.mem.eql(u8, key, "triggers-awaited");
}

fn equalFilesystemEntry(
    left: std.json.Value,
    right: std.json.Value,
    owned: *const std.StringHashMap(void),
) bool {
    if (left != .object or right != .object or left.object.count() != right.object.count())
        return false;
    const path = left.object.get("path") orelse return false;
    const kind = left.object.get("kind") orelse return false;
    if (path != .string or kind != .string or
        !equalValue(path, right.object.get("path") orelse return false) or
        !equalValue(kind, right.object.get("kind") orelse return false))
        return false;
    const ignore_mtime = std.mem.eql(u8, kind.string, "symlink") or
        !owned.contains(path.string);
    const ignore_hash = std.mem.eql(u8, kind.string, "regular") and
        !owned.contains(path.string) and isVolatileUnownedFile(path.string);
    const ignore_size = ignore_hash and isVolatileVariableSizeFile(path.string);
    if (ignore_mtime and !std.mem.eql(u8, kind.string, "directory")) {
        const before = left.object.get("mtime_ns") orelse return false;
        const after = right.object.get("mtime_ns") orelse return false;
        if (before != .integer or after != .integer) return false;
    }
    if (ignore_hash) {
        if (!validDigest(left.object.get("sha256") orelse return false) or
            !validDigest(right.object.get("sha256") orelse return false))
            return false;
    }
    if (ignore_size) {
        const before = left.object.get("size") orelse return false;
        const after = right.object.get("size") orelse return false;
        if (before != .integer or after != .integer or before.integer < 0 or after.integer < 0)
            return false;
    }

    var fields = left.object.iterator();
    while (fields.next()) |field| {
        const other = right.object.get(field.key_ptr.*) orelse return false;
        if (std.mem.eql(u8, field.key_ptr.*, "mtime_ns") and ignore_mtime) {
            if (field.value_ptr.* != .integer or other != .integer) return false;
        } else if (std.mem.eql(u8, field.key_ptr.*, "size") and ignore_size) {
            if (field.value_ptr.* != .integer or other != .integer or
                field.value_ptr.integer < 0 or other.integer < 0)
                return false;
        } else if (std.mem.eql(u8, field.key_ptr.*, "sha256") and ignore_hash) {
            if (!validDigest(field.value_ptr.*) or !validDigest(other)) return false;
        } else if (!equalValue(field.value_ptr.*, other)) {
            return false;
        }
    }
    return true;
}

fn isVolatileUnownedFile(path: []const u8) bool {
    for (volatile_unowned_files) |volatile_path| {
        if (std.mem.eql(u8, path, volatile_path)) return true;
    }
    return false;
}

fn isVolatileVariableSizeFile(path: []const u8) bool {
    for (volatile_unowned_variable_size_files) |volatile_path| {
        if (std.mem.eql(u8, path, volatile_path)) return true;
    }
    return false;
}

fn validDigest(value: std.json.Value) bool {
    if (value != .string or value.string.len != 64) return false;
    for (value.string) |digit| {
        if (!std.ascii.isHex(digit)) return false;
    }
    return true;
}

fn fixture(comptime status: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        \\{{"schema":"{s}","version":1,"filesystem":[{{"path":"usr"}}],"write_witnesses":[{{"path":"dev/null","kind":"absent"}}],"dpkg":{{"present":true,"status":[{{"package":"{s}"}}],"status_old":[],"info":[],"triggers":[],"updates":[],"alternatives":[],"parts":[],"staging":[],"files":[]}},"trace":[]}}
    ,
        .{ schema, status },
    );
}

fn regularFixture(comptime info: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        \\{{"schema":"{s}","version":1,"filesystem":[{{"path":"etc/machine-id","kind":"regular","mode":"0444","mtime_ns":1,"size":33,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],"write_witnesses":[{{"path":"dev/null","kind":"absent"}}],"dpkg":{{"present":true,"status":[{{"package":"installed"}}],"status_old":[],"info":[{s}],"triggers":[],"updates":[],"alternatives":[],"parts":[],"staging":[],"files":[]}},"trace":[]}}
    , .{ schema, info });
}

fn testFile(value: *std.json.Value) *std.json.ObjectMap {
    return &value.object.getPtr("filesystem").?.array.items[0].object;
}

test "real snapshot comparison normalizes only unowned clock and known volatile content" {
    var left = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        regularFixture(""),
        .{},
    );
    defer left.deinit();
    var right = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        regularFixture(""),
        .{},
    );
    defer right.deinit();
    testFile(&right.value).getPtr("mtime_ns").?.* = .{ .integer = 2 };
    testFile(&right.value).getPtr("sha256").?.* = .{
        .string = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    };
    try std.testing.expect(try equalSnapshots(std.testing.allocator, left.value, right.value));

    testFile(&left.value).getPtr("path").?.* = .{ .string = "usr/bin/payload" };
    testFile(&right.value).getPtr("path").?.* = .{ .string = "usr/bin/payload" };
    try std.testing.expect(!try equalSnapshots(std.testing.allocator, left.value, right.value));
    testFile(&right.value).getPtr("sha256").?.* = testFile(&left.value).get("sha256").?;
    try std.testing.expect(try equalSnapshots(std.testing.allocator, left.value, right.value));

    testFile(&right.value).getPtr("mode").?.* = .{ .string = "0644" };
    try std.testing.expect(!try equalSnapshots(std.testing.allocator, left.value, right.value));
}

test "real snapshot comparison refuses to normalize package-owned files" {
    const owner =
        \\{"path":"var/lib/dpkg/info/demo.list","kind":"path-list","lines":["/usr/bin/payload"]}
    ;
    var left = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        regularFixture(owner),
        .{},
    );
    defer left.deinit();
    var right = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        regularFixture(owner),
        .{},
    );
    defer right.deinit();
    testFile(&left.value).getPtr("path").?.* = .{ .string = "usr/bin/payload" };
    testFile(&right.value).getPtr("path").?.* = .{ .string = "usr/bin/payload" };
    testFile(&right.value).getPtr("mtime_ns").?.* = .{ .integer = 2 };
    try std.testing.expect(!try equalSnapshots(std.testing.allocator, left.value, right.value));

    testFile(&left.value).getPtr("path").?.* = .{ .string = "etc/machine-id" };
    testFile(&right.value).getPtr("path").?.* = .{ .string = "etc/machine-id" };
    left.value.object.getPtr("dpkg").?.object.getPtr("info").?.array.items[0]
        .object.getPtr("lines").?.array.items[0] = .{ .string = "/etc/machine-id" };
    right.value.object.getPtr("dpkg").?.object.getPtr("info").?.array.items[0]
        .object.getPtr("lines").?.array.items[0] = .{ .string = "/etc/machine-id" };
    try std.testing.expectError(
        error.VolatileFilePackageOwned,
        equalSnapshots(std.testing.allocator, left.value, right.value),
    );
}

test "real snapshot comparison ignores symlink timestamps, not symlink targets" {
    const image = std.fmt.comptimePrint(
        \\{{"schema":"{s}","version":1,"filesystem":[{{"path":"usr/bin/link","kind":"symlink","target":"payload","mtime_ns":1}}],"write_witnesses":[{{"path":"dev/null","kind":"absent"}}],"dpkg":{{"present":true,"status":[{{"package":"installed"}}],"status_old":[],"info":[{{"path":"var/lib/dpkg/info/demo.list","kind":"path-list","lines":["/usr/bin/link"]}}],"triggers":[],"updates":[],"alternatives":[],"parts":[],"staging":[],"files":[]}},"trace":[]}}
    , .{schema});
    var left = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, image, .{});
    defer left.deinit();
    var right = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, image, .{});
    defer right.deinit();
    testFile(&right.value).getPtr("mtime_ns").?.* = .{ .integer = 2 };
    try std.testing.expect(try equalSnapshots(std.testing.allocator, left.value, right.value));
    testFile(&right.value).getPtr("target").?.* = .{ .string = "other" };
    try std.testing.expect(!try equalSnapshots(std.testing.allocator, left.value, right.value));
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

test "real snapshot comparator rejects empty and absent databases" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        fixture("installed"),
        .{},
    );
    defer parsed.deinit();
    const dpkg = parsed.value.object.getPtr("dpkg").?;
    dpkg.object.getPtr("present").?.* = .{ .bool = false };
    try std.testing.expectError(error.InvalidSnapshot, validateSnapshot(parsed.value));
    dpkg.object.getPtr("present").?.* = .{ .bool = true };
    dpkg.object.getPtr("status").?.array.items.len = 0;
    try std.testing.expectError(error.InvalidSnapshot, validateSnapshot(parsed.value));
}

test "real snapshot comparison normalizes debconf cache size and status_old lifecycle fields only" {
    for ([_][]const u8{ "amd64", "arm64" }) |arch| {
        const left_json = try std.fmt.allocPrint(
            std.testing.allocator,
            \\{{"schema":"{s}","version":1,"filesystem":[{{"path":"var/cache/debconf/config.dat","kind":"regular","mode":"0644","mtime_ns":1,"size":120,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],"write_witnesses":[{{"path":"dev/null","kind":"absent"}}],"dpkg":{{"present":true,"status":[{{"package":"procps","architecture":"{s}","version":"2:4.0.4-9ubuntu1","status":"install ok installed"}}],"status_old":[{{"package":"procps","architecture":"{s}","version":"2:4.0.4-9ubuntu1","status":"install ok triggers-pending","config_version":"2:4.0.4-9ubuntu1","triggers_pending":["/usr/lib/sysctl.d"]}}],"info":[],"triggers":[],"updates":[],"alternatives":[],"parts":[],"staging":[],"files":[]}},"trace":[]}}
        ,
            .{ schema, arch, arch },
        );
        defer std.testing.allocator.free(left_json);
        const right_json = try std.fmt.allocPrint(
            std.testing.allocator,
            \\{{"schema":"{s}","version":1,"filesystem":[{{"path":"var/cache/debconf/config.dat","kind":"regular","mode":"0644","mtime_ns":2,"size":240,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}],"write_witnesses":[{{"path":"dev/null","kind":"absent"}}],"dpkg":{{"present":true,"status":[{{"package":"procps","architecture":"{s}","version":"2:4.0.4-9ubuntu1","status":"install ok installed"}}],"status_old":[{{"package":"procps","architecture":"{s}","version":"2:4.0.4-9ubuntu1","status":"install ok installed"}}],"info":[],"triggers":[],"updates":[],"alternatives":[],"parts":[],"staging":[],"files":[]}},"trace":[]}}
        ,
            .{ schema, arch, arch },
        );
        defer std.testing.allocator.free(right_json);
        var left = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, left_json, .{});
        defer left.deinit();
        var right = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, right_json, .{});
        defer right.deinit();
        try std.testing.expect(try equalSnapshots(std.testing.allocator, left.value, right.value));

        testFile(&left.value).getPtr("path").?.* = .{ .string = "etc/machine-id" };
        testFile(&right.value).getPtr("path").?.* = .{ .string = "etc/machine-id" };
        try std.testing.expect(!try equalSnapshots(std.testing.allocator, left.value, right.value));

        testFile(&left.value).getPtr("path").?.* = .{ .string = "var/cache/debconf/config.dat" };
        testFile(&right.value).getPtr("path").?.* = .{ .string = "var/cache/debconf/config.dat" };
        right.value.object.getPtr("dpkg").?.object.getPtr("status_old").?.array.items[0]
            .object.getPtr("version").?.* = .{ .string = "2:4.0.4-9ubuntu2" };
        try std.testing.expect(!try equalSnapshots(std.testing.allocator, left.value, right.value));
    }
}

test "real snapshot comparison normalizes reference-only dpkg.log, diversions-old, and status_old conffiles" {
    const ref_json = std.fmt.comptimePrint(
        \\{{"schema":"{s}","version":1,"filesystem":[{{"path":"usr","kind":"directory"}},{{"path":"var/log/dpkg.log","kind":"regular","mode":"0644","uid":0,"gid":0,"mtime_ns":1,"xattrs":[],"size":15537,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","hardlink_to":null}}],"write_witnesses":[{{"path":"dev/null","kind":"absent"}}],"dpkg":{{"present":true,"status":[{{"package":"util-linux","version":"2.41-5","status":"install ok installed"}}],"status_old":[{{"package":"util-linux","version":"2.41-5","status":"install ok installed","triggers-pending":"ldconfig","conffiles":"\n/etc/pam.d/su 60fbbe65c90d741bc0d380543cefe8af"}}],"info":[],"triggers":[],"updates":[],"alternatives":[],"parts":[],"staging":[],"files":[{{"path":"var/lib/dpkg/diversions","kind":"opaque","mode":"0644","size":676,"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}},{{"path":"var/lib/dpkg/diversions-old","kind":"opaque","mode":"0644","size":676,"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}]}},"trace":[]}}
    , .{schema});
    const cand_json = std.fmt.comptimePrint(
        \\{{"schema":"{s}","version":1,"filesystem":[{{"path":"usr","kind":"directory"}}],"write_witnesses":[{{"path":"dev/null","kind":"absent"}}],"dpkg":{{"present":true,"status":[{{"package":"util-linux","version":"2.41-5","status":"install ok installed"}}],"status_old":[{{"package":"util-linux","version":"2.41-5","status":"install ok unpacked","conffiles":"\n/etc/pam.d/su newconffile"}}],"info":[],"triggers":[],"updates":[],"alternatives":[],"parts":[],"staging":[],"files":[{{"path":"var/lib/dpkg/diversions","kind":"opaque","mode":"0644","size":676,"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}},{{"path":"var/lib/dpkg/diversions-old","kind":"opaque","mode":"0644","size":594,"sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}]}},"trace":[]}}
    , .{schema});
    var left = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, ref_json, .{});
    defer left.deinit();
    var right = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, cand_json, .{});
    defer right.deinit();
    const left_counts = try validateSnapshot(left.value);
    const right_counts = try validateSnapshot(right.value);
    try std.testing.expect(countsCompatible(left_counts, right_counts, left.value, right.value));
    try std.testing.expect(try equalSnapshots(std.testing.allocator, left.value, right.value));
    try std.testing.expect(!try equalSnapshots(std.testing.allocator, right.value, left.value));

    right.value.object.getPtr("dpkg").?.object.getPtr("files").?.array.items[0]
        .object.getPtr("sha256").?.* = .{
        .string = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    };
    try std.testing.expect(!try equalSnapshots(std.testing.allocator, left.value, right.value));
}

