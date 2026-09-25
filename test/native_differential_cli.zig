const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const differential = @import("native_differential.zig");

const Value = std.json.Value;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const schema = "https://debz.dev/test/native-transaction-snapshot-v1";

fn object(a: Allocator) Value {
    _ = a;
    return .{ .object = .{} };
}

fn array(a: Allocator) Value {
    return .{ .array = std.json.Array.init(a) };
}

fn put(a: Allocator, value: *Value, key: []const u8, child: Value) !void {
    try value.object.put(a, key, child);
}

fn append(a: Allocator, value: *Value, child: Value) !void {
    _ = a;
    try value.array.append(child);
}

fn field(value: Value, name: []const u8) !Value {
    if (value != .object) return error.InvalidSnapshot;
    return value.object.get(name) orelse error.InvalidSnapshot;
}

fn string(value: Value) ![]const u8 {
    if (value != .string) return error.InvalidSnapshot;
    return value.string;
}

fn text(value: []const u8) Value {
    return .{ .string = value };
}

fn octal(a: Allocator, value: Value) !Value {
    if (value != .integer or value.integer < 0) return error.InvalidSnapshot;
    const digits = try std.fmt.allocPrint(a, "{o}", .{@as(u32, @intCast(value.integer))});
    const output = try a.alloc(u8, @max(4, digits.len));
    @memset(output[0 .. output.len - digits.len], '0');
    @memcpy(output[output.len - digits.len ..], digits);
    return text(output);
}

fn stringArray(a: Allocator, contents: []const u8) !Value {
    var result = array(a);
    var it = std.mem.splitScalar(u8, contents, '\n');
    while (it.next()) |line| {
        if (line.len > 0) try append(a, &result, text(line));
    }
    return result;
}

fn lines(a: Allocator, contents: []const u8) !Value {
    const result = try stringArray(a, contents);
    std.mem.sort(Value, result.array.items, {}, struct {
        fn less(_: void, left: Value, right: Value) bool {
            return std.mem.lessThan(u8, left.string, right.string);
        }
    }.less);
    return result;
}

fn paragraphLess(_: void, left: Value, right: Value) bool {
    for ([_][]const u8{ "package", "architecture", "version" }) |key| {
        const l = left.object.get(key) orelse text("");
        const r = right.object.get(key) orelse text("");
        switch (std.mem.order(u8, l.string, r.string)) {
            .lt => return true,
            .gt => return false,
            .eq => {},
        }
    }
    var l = left.object.iterator();
    var r = right.object.iterator();
    while (l.next()) |entry| {
        const other = r.next() orelse return false;
        switch (std.mem.order(u8, entry.key_ptr.*, other.key_ptr.*)) {
            .lt => return true,
            .gt => return false,
            .eq => {},
        }
        switch (std.mem.order(u8, entry.value_ptr.string, other.value_ptr.string)) {
            .lt => return true,
            .gt => return false,
            .eq => {},
        }
    }
    return r.next() != null;
}

fn paragraphs(a: Allocator, contents: []const u8) !Value {
    var result = array(a);
    if (contents.len == 0) return result;
    var parts = std.mem.splitSequence(u8, contents, "\n\n");
    while (parts.next()) |part| {
        if (part.len == 0) continue;
        var paragraph = object(a);
        var previous: ?[]const u8 = null;
        var it = std.mem.splitScalar(u8, part, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            if (line[0] == ' ' or line[0] == '\t') {
                const key = previous orelse return error.InvalidSnapshot;
                const old = paragraph.object.get(key) orelse return error.InvalidSnapshot;
                try put(a, &paragraph, key, text(try std.fmt.allocPrint(a, "{s}\n{s}", .{ old.string, line[1..] })));
            } else {
                const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidSnapshot;
                const key = line[0..colon];
                if (key.len == 0 or paragraph.object.contains(key)) return error.InvalidSnapshot;
                try put(a, &paragraph, key, text(line[colon + 1 ..]));
                previous = key;
            }
        }
        try append(a, &result, paragraph);
    }
    std.mem.sort(Value, result.array.items, {}, paragraphLess);
    return result;
}

fn records(a: Allocator, kind: []const u8, contents: []const u8) !Value {
    var result = array(a);
    var source = std.mem.splitScalar(u8, contents, '\n');
    while (source.next()) |line| {
        if (line.len == 0) continue;
        var record = object(a);
        if (std.mem.eql(u8, kind, "md5sums")) {
            const separator = std.mem.lastIndexOfScalar(u8, line, ' ') orelse return error.InvalidSnapshot;
            try put(a, &record, "path", text(line[0..separator]));
            try put(a, &record, "md5", text(line[separator + 1 ..]));
        } else if (std.mem.eql(u8, kind, "statoverride")) {
            var fields = std.mem.splitScalar(u8, line, ' ');
            const owner = fields.next() orelse return error.InvalidSnapshot;
            const group = fields.next() orelse return error.InvalidSnapshot;
            const mode = fields.next() orelse return error.InvalidSnapshot;
            const path = fields.rest();
            if (path.len == 0) return error.InvalidSnapshot;
            try put(a, &record, "path", text(path));
            try put(a, &record, "owner", text(owner));
            try put(a, &record, "group", text(group));
            try put(a, &record, "mode", text(mode));
        } else {
            const destination = source.next() orelse return error.InvalidSnapshot;
            const package_name = source.next() orelse return error.InvalidSnapshot;
            try put(a, &record, "path", text(line));
            try put(a, &record, "diverted_to", text(destination));
            try put(a, &record, "package", text(package_name));
        }
        try append(a, &result, record);
    }
    return result;
}

fn convertEntry(a: Allocator, source: Value, filesystem: bool, unknown_file: bool) !Value {
    var result = object(a);
    const kind = try string(try field(source, "kind"));
    try put(a, &result, "path", try field(source, "path"));
    try put(a, &result, "kind", text(kind));
    try put(a, &result, "mode", try octal(a, try field(source, "mode")));
    if (filesystem or !unknown_file) {
        try put(a, &result, "uid", try field(source, "uid"));
        try put(a, &result, "gid", try field(source, "gid"));
    }
    if (filesystem) {
        const stamp = try field(source, "mtime_ns");
        if (stamp != .null) try put(a, &result, "mtime_ns", stamp);
        try put(a, &result, "xattrs", try field(source, "xattrs"));
        if (std.mem.eql(u8, kind, "regular")) {
            try put(a, &result, "size", try field(source, "size"));
            try put(a, &result, "sha256", try field(source, "sha256"));
            try put(a, &result, "hardlink_to", try field(source, "hardlink_to"));
        } else if (std.mem.eql(u8, kind, "symlink")) {
            try put(a, &result, "target", try field(source, "target"));
        } else if (std.mem.eql(u8, kind, "character-device") or std.mem.eql(u8, kind, "block-device")) {
            const major = try field(source, "device_major");
            const minor = try field(source, "device_minor");
            if (major != .null and minor != .null) {
                try put(a, &result, "device_major", major);
                try put(a, &result, "device_minor", minor);
            }
        }
    } else {
        const content = try string(try field(source, "content"));
        if (std.mem.eql(u8, kind, "path-list") or std.mem.eql(u8, kind, "line-set")) {
            try put(a, &result, "lines", try lines(a, content));
        } else if (std.mem.eql(u8, kind, "md5sums") or
            std.mem.eql(u8, kind, "diversions") or std.mem.eql(u8, kind, "statoverride"))
        {
            try put(a, &result, if (std.mem.eql(u8, kind, "md5sums")) "entries" else "records", try records(a, kind, content));
        } else if (std.mem.eql(u8, kind, "deb822")) {
            try put(a, &result, "paragraphs", try paragraphs(a, content));
        } else {
            const size = try field(source, "size");
            if (size == .null) return error.InvalidSnapshot;
            try put(a, &result, "size", size);
            try put(a, &result, "sha256", text(content));
        }
    }
    return result;
}

fn convertEntries(a: Allocator, source: Value, filesystem: bool, unknown_file: bool) !Value {
    if (source != .array) return error.InvalidSnapshot;
    var result = array(a);
    for (source.array.items) |entry| try append(a, &result, try convertEntry(a, entry, filesystem, unknown_file));
    return result;
}

pub fn convertImage(a: Allocator, source: Value) !Value {
    const dpkg = try field(source, "dpkg");
    var database = object(a);
    try put(a, &database, "present", try field(dpkg, "present"));
    try put(a, &database, "status", try paragraphs(a, try string(try field(dpkg, "status"))));
    try put(a, &database, "status_old", try paragraphs(a, try string(try field(dpkg, "status_old"))));
    for ([_][]const u8{ "info", "triggers", "updates", "alternatives", "parts", "staging", "files" }) |name| {
        try put(a, &database, name, try convertEntries(a, try field(dpkg, name), false, std.mem.eql(u8, name, "files")));
    }
    var result = object(a);
    try put(a, &result, "schema", text(schema));
    try put(a, &result, "version", .{ .integer = 1 });
    try put(a, &result, "filesystem", try convertEntries(a, try field(source, "filesystem"), true, false));
    try put(a, &result, "dpkg", database);
    try put(a, &result, "trace", try field(source, "trace"));
    return result;
}

pub fn snapshot(a: Allocator, io: Io, root: []const u8, limits: foundation.SnapshotLimits, excludes: []const []const u8) !Value {
    const raw = try foundation.captureRealRoot(a, io, root, limits, excludes);
    const parsed = try std.json.parseFromSlice(Value, a, raw, .{ .allocate = .alloc_always });
    return convertImage(a, parsed.value);
}

fn readJson(a: Allocator, io: Io, name: []const u8, maximum: usize) !Value {
    const contents = try Io.Dir.cwd().readFileAlloc(io, name, a, .limited(maximum));
    const parsed = try std.json.parseFromSlice(Value, a, contents, .{ .allocate = .alloc_always });
    if (parsed.value != .object) return error.InvalidSnapshot;
    return parsed.value;
}

fn writeJson(a: Allocator, io: Io, name: []const u8, value: Value) !void {
    const data = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    var file = try Io.Dir.cwd().createFile(io, name, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, data);
    try file.writeStreamingAll(io, "\n");
}

fn showDifference(left: Value, right: Value, path: []const u8, remaining: *usize, a: Allocator, report: bool) !void {
    if (remaining.* == 0) return;
    const display_path = path[0..@min(path.len, 256)];
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) {
        if (report) std.debug.print("{s}: type differs\n", .{display_path});
        remaining.* -= 1;
        return;
    }
    switch (left) {
        .object => {
            var keys: std.ArrayList([]const u8) = .empty;
            var it = left.object.iterator();
            while (it.next()) |entry| try keys.append(a, entry.key_ptr.*);
            it = right.object.iterator();
            while (it.next()) |entry| {
                if (!left.object.contains(entry.key_ptr.*)) try keys.append(a, entry.key_ptr.*);
            }
            std.mem.sort([]const u8, keys.items, {}, struct {
                fn less(_: void, lhs: []const u8, rhs: []const u8) bool {
                    return std.mem.lessThan(u8, lhs, rhs);
                }
            }.less);
            for (keys.items) |key| {
                const child = try std.fmt.allocPrint(a, "{s}.{s}", .{ path, key });
                if (left.object.get(key)) |l| {
                    if (right.object.get(key)) |r| {
                        try showDifference(l, r, child, remaining, a, report);
                    } else {
                        if (report) std.debug.print("{s}: missing from candidate\n", .{child[0..@min(child.len, 256)]});
                        remaining.* -= 1;
                    }
                } else {
                    if (report) std.debug.print("{s}: missing from reference\n", .{child[0..@min(child.len, 256)]});
                    remaining.* -= 1;
                }
                if (remaining.* == 0) return;
            }
        },
        .array => {
            if (left.array.items.len != right.array.items.len) {
                if (report) std.debug.print("{s}: length {d} != {d}\n", .{ display_path, left.array.items.len, right.array.items.len });
                remaining.* -= 1;
            }
            for (left.array.items[0..@min(left.array.items.len, right.array.items.len)], right.array.items[0..@min(left.array.items.len, right.array.items.len)], 0..) |l, r, index| {
                if (remaining.* == 0) return;
                try showDifference(l, r, try std.fmt.allocPrint(a, "{s}[{d}]", .{ path, index }), remaining, a, report);
            }
        },
        .string => {
            if (!std.mem.eql(u8, left.string, right.string)) {
                if (report) std.debug.print("{s}: {s} != {s}\n", .{
                    display_path,
                    left.string[0..@min(256, left.string.len)],
                    right.string[0..@min(256, right.string.len)],
                });
                remaining.* -= 1;
            }
        },
        .number_string => {
            if (!std.mem.eql(u8, left.number_string, right.number_string)) {
                if (report) std.debug.print("{s}: number differs\n", .{display_path});
                remaining.* -= 1;
            }
        },
        else => {
            if (!std.meta.eql(left, right)) {
                if (report) std.debug.print("{s}: value differs\n", .{display_path});
                remaining.* -= 1;
            }
        },
    }
}

pub fn compare(a: Allocator, reference: Value, candidate: Value, maximum: usize) !bool {
    return compareWithReport(a, reference, candidate, maximum, true);
}

fn compareWithReport(a: Allocator, reference: Value, candidate: Value, maximum: usize, report: bool) !bool {
    try validateSnapshot(reference);
    try validateSnapshot(candidate);
    var remaining = maximum;
    try showDifference(reference, candidate, "$", &remaining, a, report);
    return remaining == maximum;
}

fn validateSnapshot(value: Value) !void {
    if (value != .object or value.object.count() != 5 or
        !std.mem.eql(u8, try string(try field(value, "schema")), schema))
        return error.UnsupportedSnapshot;
    const version = try field(value, "version");
    if (version != .integer or version.integer != 1) return error.UnsupportedSnapshot;
    if ((try field(value, "filesystem")) != .array or (try field(value, "trace")) != .array)
        return error.InvalidSnapshot;
    const database = try field(value, "dpkg");
    if (database != .object or database.object.count() != 10 or (try field(database, "present")) != .bool)
        return error.InvalidSnapshot;
    for ([_][]const u8{ "status", "status_old", "info", "triggers", "updates", "alternatives", "parts", "staging", "files" }) |key|
        if ((try field(database, key)) != .array) return error.InvalidSnapshot;
}

fn parsePositive(value: []const u8) !usize {
    const parsed = try std.fmt.parseInt(usize, value, 10);
    if (parsed == 0) return error.InvalidLimit;
    return parsed;
}

pub fn run(a: Allocator, io: Io, args: []const []const u8) !u8 {
    if (args.len == 0) return error.Usage;
    if (std.mem.eql(u8, args[0], "capture")) {
        var root: ?[]const u8 = null;
        var output: ?[]const u8 = null;
        var excludes: std.ArrayList([]const u8) = .empty;
        var limits: foundation.SnapshotLimits = .{};
        var index: usize = 1;
        while (index < args.len) : (index += 2) {
            if (index + 1 == args.len) return error.Usage;
            const key = args[index];
            const value = args[index + 1];
            if (std.mem.eql(u8, key, "--root")) root = value else if (std.mem.eql(u8, key, "--output")) output = value else if (std.mem.eql(u8, key, "--exclude")) {
                try excludes.append(a, value);
            } else if (std.mem.eql(u8, key, "--max-entries")) {
                limits.max_entries = try parsePositive(value);
            } else if (std.mem.eql(u8, key, "--max-total-bytes")) {
                limits.max_total_regular_bytes = try parsePositive(value);
            } else if (std.mem.eql(u8, key, "--max-file-bytes")) {
                limits.max_file_bytes = try parsePositive(value);
            } else if (std.mem.eql(u8, key, "--max-database-file-bytes")) {
                limits.max_database_file_bytes = try parsePositive(value);
            } else if (std.mem.eql(u8, key, "--max-trace-bytes")) {
                limits.max_trace_bytes = try parsePositive(value);
            } else return error.Usage;
        }
        try writeJson(a, io, output orelse return error.Usage, try snapshot(a, io, root orelse return error.Usage, limits, excludes.items));
        return 0;
    }
    if (std.mem.eql(u8, args[0], "compare")) {
        var reference: ?[]const u8 = null;
        var candidate: ?[]const u8 = null;
        var maximum: usize = 100;
        var index: usize = 1;
        while (index < args.len) : (index += 2) {
            if (index + 1 == args.len) return error.Usage;
            if (std.mem.eql(u8, args[index], "--reference")) reference = args[index + 1] else if (std.mem.eql(u8, args[index], "--candidate")) candidate = args[index + 1] else if (std.mem.eql(u8, args[index], "--max-differences")) {
                maximum = try parsePositive(args[index + 1]);
                if (maximum > 1000) return error.InvalidLimit;
            } else return error.Usage;
        }
        return if (try compare(a, try readJson(a, io, reference orelse return error.Usage, 512 * 1024 * 1024), try readJson(a, io, candidate orelse return error.Usage, 512 * 1024 * 1024), maximum)) 0 else 1;
    }
    if (std.mem.eql(u8, args[0], "validate-corpus")) {
        if (args.len != 3 or !std.mem.eql(u8, args[1], "--corpus")) return error.Usage;
        const document = try readJson(a, io, args[2], 1024 * 1024);
        _ = try differential.validateCorpus(a, document);
        return 0;
    }
    return error.Usage;
}

test "real-root capture matches the Python snapshot schema and semantics" {
    const options = @import("native_test_options");
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    var fixture = try foundation.Fixture.init(a, io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("root", "arm64");
    try fixture.write("root/var/lib/dpkg/status", "Package: demo\nArchitecture: arm64\nVersion: 2\nDescription: first\n second\n\n", 0o644);
    try fixture.write("root/var/lib/dpkg/info/demo.list", "/usr/share/demo/data\n", 0o644);
    try fixture.write("root/var/lib/dpkg/info/demo.md5sums", "d41d8cd98f00b204e9800998ecf8427e  usr/share/demo/data\n", 0o644);
    try fixture.write("root/var/lib/dpkg/updates/0000", "Package: demo\nVersion: 3\n", 0o644);
    try fixture.write("root/var/lib/dpkg/diversions", "/usr/share/demo/data\n/usr/share/demo/data.distrib\ndemo\n", 0o644);
    try fixture.write("root/var/lib/dpkg/statoverride", "root root 0644 /usr/share/demo/data\n", 0o644);
    try fixture.write("root/usr/share/demo/data", "fixture payload", 0o644);
    try Io.Dir.hardLink(fixture.dir, "root/usr/share/demo/data", fixture.dir, "root/usr/share/demo/hardlink", io, .{});
    try fixture.dir.symLink(io, "data", "root/usr/share/demo/link", .{});
    try fixture.write("root/var/log/debz-native-differential.trace", "install\n\nupgrade\n", 0o644);
    const expected = try fixture.absolute("python.json");
    const program = try std.fs.path.join(a, &.{ options.repository, "tools/native-differential.py" });
    try fixture.run(&.{
        "python3", program, "capture", "--root", root, "--exclude", "dev/null", "--output", expected,
    }, "python.log", 30);
    const python = try readJson(a, io, expected, 1024 * 1024);
    const zig = try snapshot(a, io, root, .{}, &.{"dev/null"});
    try std.testing.expect(try compare(a, python, zig, 20));
}

test "snapshot CLI normalizes semantic status and database order" {
    const options = @import("native_test_options");
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    var fixture = try foundation.Fixture.init(a, io, options.repository);
    defer fixture.deinit();
    const reference = try fixture.makeRoot("reference", "amd64");
    const candidate = try fixture.makeRoot("candidate", "amd64");
    try fixture.write("reference/var/lib/dpkg/status", "Package: demo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n", 0o644);
    try fixture.write("candidate/var/lib/dpkg/status", "Version: 1\nArchitecture: amd64\nStatus: install ok installed\nPackage: demo\n\n", 0o644);
    try fixture.write("reference/var/lib/dpkg/info/demo.list", "/usr/bin/z\n/etc/a\n", 0o644);
    try fixture.write("candidate/var/lib/dpkg/info/demo.list", "/etc/a\n/usr/bin/z\n", 0o644);
    try fixture.write("reference/var/lib/dpkg/triggers/File", "/z demo\n/a demo\n", 0o644);
    try fixture.write("candidate/var/lib/dpkg/triggers/File", "/a demo\n/z demo\n", 0o644);
    try fixture.write("reference/var/lib/dpkg/diversions", "/usr/bin/z\n/usr/bin/z.distrib\npackage-z\n/usr/bin/a\n/usr/bin/a.distrib\npackage-a\n", 0o644);
    try fixture.write("candidate/var/lib/dpkg/diversions", "/usr/bin/a\n/usr/bin/a.distrib\npackage-a\n/usr/bin/z\n/usr/bin/z.distrib\npackage-z\n", 0o644);
    try fixture.write("reference/var/lib/dpkg/statoverride", "root root 4755 /usr/bin/z\nroot root 0755 /usr/bin/a\n", 0o644);
    try fixture.write("candidate/var/lib/dpkg/statoverride", "root root 0755 /usr/bin/a\nroot root 4755 /usr/bin/z\n", 0o644);
    const excludes: []const []const u8 = &.{foundation.guard};
    const left = try snapshot(a, io, reference, .{}, excludes);
    const right = try snapshot(a, io, candidate, .{}, excludes);
    try std.testing.expect(try compare(a, left, right, 4));
    try fixture.write("candidate/var/lib/dpkg/status", "Package: other\n", 0o644);
    const changed = try snapshot(a, io, candidate, .{}, excludes);
    try std.testing.expect(!try compareWithReport(a, left, changed, 2, false));
}

test "real-root capture rejects malformed or unsafe roots and database state" {
    const options = @import("native_test_options");
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    var fixture = try foundation.Fixture.init(a, io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("root", "arm64");
    try std.testing.expectError(error.NotDisposableRoot, snapshot(a, io, "root", .{}, &.{}));
    try std.testing.expectError(error.TraversingPath, snapshot(a, io, root, .{}, &.{"../outside"}));
    try fixture.dir.symLink(io, "root", "alias", .{ .is_directory = true });
    const alias = try fixture.absolute("alias");
    try std.testing.expectError(error.NotDisposableRoot, snapshot(a, io, alias, .{}, &.{}));
    try fixture.write("root/var/lib/dpkg/status", "orphan continuation\n", 0o644);
    try std.testing.expectError(error.InvalidDeb822, snapshot(a, io, root, .{}, &.{}));
    try fixture.write("root/var/lib/dpkg/status", "Package: demo\n", 0o644);
    try fixture.write("root/var/lib/dpkg/info/demo.list", "../outside\n", 0o644);
    try std.testing.expectError(error.UnsafePackagePath, snapshot(a, io, root, .{}, &.{}));
    try fixture.write("root/var/lib/dpkg/info/demo.list", "/usr/share/demo\n", 0o644);
    try fixture.dir.deleteFile(io, "root/var/lib/dpkg/info/demo.list");
    try fixture.dir.symLink(io, "/etc/passwd", "root/var/lib/dpkg/info/demo.list", .{});
    try std.testing.expectError(error.UnsafeDatabaseEntry, snapshot(a, io, root, .{}, &.{}));
    try fixture.dir.deleteFile(io, "root/var/lib/dpkg/info/demo.list");
    try fixture.write("root/var/lib/dpkg/info/demo.list", "/usr/share/demo\n", 0o644);
    try fixture.write("root/usr/share/demo", "payload", 0o644);
    try std.testing.expectError(error.FilesystemFileLimit, snapshot(a, io, root, .{ .max_file_bytes = 1 }, &.{}));
    try std.testing.expectError(error.DatabaseEntryLimit, snapshot(a, io, root, .{ .max_entries = 1 }, &.{ "var", "usr" }));
}

test "snapshot CLI rejects malformed inputs and supports corpus validation" {
    const options = @import("native_test_options");
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    try std.testing.expectError(error.Usage, run(a, io, &.{"capture"}));
    try std.testing.expectError(error.InvalidLimit, run(a, io, &.{
        "compare", "--reference", "unused", "--candidate", "unused", "--max-differences", "0",
    }));
    try std.testing.expectEqual(@as(u8, 0), try run(a, io, &.{
        "validate-corpus", "--corpus", options.corpus,
    }));
    var fixture = try foundation.Fixture.init(a, io, options.repository);
    defer fixture.deinit();
    try fixture.write("bad.json", "not json", 0o644);
    const malformed = try fixture.absolute("bad.json");
    try std.testing.expectError(error.SyntaxError, run(a, io, &.{
        "validate-corpus", "--corpus", malformed,
    }));
    var unsupported = try std.json.parseFromSlice(Value, a,
        \\{"schema":"unexpected","version":1,"filesystem":[],"trace":[],"dpkg":{}}
    , .{});
    defer unsupported.deinit();
    try std.testing.expectError(error.UnsupportedSnapshot, compare(a, unsupported.value, unsupported.value, 3));
    var incomplete = try std.json.parseFromSlice(Value, a,
        \\{"schema":"https://debz.dev/test/native-transaction-snapshot-v1","version":1,"filesystem":[],"trace":[],"dpkg":{}}
    , .{});
    defer incomplete.deinit();
    try std.testing.expectError(error.InvalidSnapshot, compare(a, incomplete.value, incomplete.value, 3));
}

pub fn main(init: std.process.Init) void {
    var arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var arguments: std.ArrayList([]const u8) = .empty;
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    while (iterator.next()) |argument| arguments.append(a, argument) catch {
        std.process.exit(2);
    };
    const code = run(a, init.io, arguments.items) catch |err| {
        std.debug.print("native-differential: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
    std.process.exit(code);
}
