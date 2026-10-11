//! Original deterministic integration archive encoding, not package authority.
const std = @import("std");
const fs = @import("debz").root_fs;
const maximum_bytes = 8 * 1024 * 1024;
const epoch = 1_700_000_000;

const Entry = struct { name: []const u8, hex: []const u8, mode: u16 };
const Request = struct {
    control: []const Entry,
    data: []const Entry,
    origin: ?[]const u8 = null,
};

fn append(allocator: std.mem.Allocator, out: *std.ArrayList(u8), bytes: []const u8) !void {
    if (bytes.len > maximum_bytes - out.items.len) return error.IntegrationArchiveTooLarge;
    try out.appendSlice(allocator, bytes);
}

fn member(allocator: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, data: []const u8, mode: u16, directory: bool) !void {
    if (name.len >= 100 or mode > 0o7777) return error.InvalidIntegrationTarEntry;
    var header: [512]u8 = @splat(0);
    @memcpy(header[0..name.len], name);
    _ = try std.fmt.bufPrint(header[100..107], "{o:0>7}", .{mode});
    @memcpy(header[108..115], "0000000");
    @memcpy(header[116..123], "0000000");
    _ = try std.fmt.bufPrint(header[124..135], "{o:0>11}", .{data.len});
    _ = try std.fmt.bufPrint(header[136..147], "{o:0>11}", .{@as(u32, epoch)});
    @memset(header[148..156], ' ');
    header[156] = if (directory) '5' else '0';
    @memcpy(header[257..265], "ustar\x0000");
    @memcpy(header[265..269], "root");
    @memcpy(header[297..301], "root");
    var checksum: u32 = 0;
    for (header) |byte| checksum += byte;
    _ = try std.fmt.bufPrint(header[148..154], "{o:0>6}", .{checksum});
    header[154] = 0;
    header[155] = ' ';
    try append(allocator, out, &header);
    try append(allocator, out, data);
    const padding = (512 - data.len % 512) % 512;
    const zeros: [512]u8 = @splat(0);
    try append(allocator, out, zeros[0..padding]);
}

fn tar(allocator: std.mem.Allocator, entries: []const Entry) ![]u8 {
    if (entries.len > 64) return error.IntegrationArchiveTooLarge;
    var out: std.ArrayList(u8) = .empty;
    var directories = std.StringHashMap(void).init(allocator);
    defer directories.deinit();
    var files = std.StringHashMap(void).init(allocator);
    defer files.deinit();
    for (entries) |entry| {
        const path = try fs.Path.initPackage(if (std.mem.startsWith(u8, entry.name, "./")) entry.name[2..] else entry.name);
        if (files.contains(path.text) or directories.contains(path.text)) return error.DuplicateIntegrationTarEntry;
        try files.put(path.text, {});
        var end: usize = 0;
        while (std.mem.indexOfScalarPos(u8, path.text, end, '/')) |slash| {
            const parent = path.text[0..slash];
            if (files.contains(parent)) return error.ConflictingIntegrationTarEntry;
            if (!directories.contains(parent)) {
                const name = try std.fmt.allocPrint(allocator, "{s}/", .{parent});
                try member(allocator, &out, name, "", 0o755, true);
                try directories.put(parent, {});
            }
            end = slash + 1;
        }
        if (entry.hex.len % 2 != 0 or entry.hex.len > maximum_bytes * 2) return error.InvalidIntegrationTarBytes;
        const bytes = try allocator.alloc(u8, entry.hex.len / 2);
        _ = std.fmt.hexToBytes(bytes, entry.hex) catch return error.InvalidIntegrationTarBytes;
        try member(allocator, &out, entry.name, bytes, entry.mode, false);
    }
    const padding = 1024 + (10240 - (out.items.len + 1024) % 10240) % 10240;
    const zeros = try allocator.alloc(u8, padding);
    @memset(zeros, 0);
    try append(allocator, &out, zeros);
    return out.toOwnedSlice(allocator);
}

fn gzip(io: std.Io, allocator: std.mem.Allocator, root: fs.Root, workspace: []const u8, name: []const u8, raw: []const u8) ![]u8 {
    const path = try fs.Path.init(name);
    const file = try root.createRegularFile(path, .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    var scratch_exists = true;
    errdefer if (scratch_exists) {
        root.removeFile(path) catch |err| {
            std.log.err("integration compression scratch cleanup failed: {s}", .{@errorName(err)});
        };
    };
    try file.writeStreamingAll(io, raw);
    const absolute = try std.fs.path.join(allocator, &.{ workspace, name });
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "/usr/bin/gzip", "-n", "-9", "-c", absolute },
        .stdout_limit = .limited(maximum_bytes),
        .stderr_limit = .limited(4096),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    });
    try root.removeFile(path);
    scratch_exists = false;
    if (result.term != .exited or result.term.exited != 0) {
        std.log.err("native integration compression failed: {s}", .{result.stderr});
        return error.IntegrationCompressionFailed;
    }
    if (result.stdout.len < 18 or !std.mem.eql(u8, result.stdout[0..10], &.{ 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 3 }))
        return error.InvalidIntegrationCompression;
    const footer = result.stdout[result.stdout.len - 8 ..];
    if (std.mem.readInt(u32, footer[0..4], .little) != std.hash.crc.Crc32.hash(raw) or
        std.mem.readInt(u32, footer[4..8], .little) != raw.len)
        return error.InvalidIntegrationCompression;
    std.mem.writeInt(u32, result.stdout[4..8], epoch, .little);
    result.stdout[9] = 255;
    return result.stdout;
}

fn ar(allocator: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, data: []const u8) !void {
    const label = try std.fmt.allocPrint(allocator, "{s}/", .{name});
    const header = try std.fmt.allocPrint(allocator, "{s:<16}{d:<12}{d:<6}{d:<6}{s:<8}{d:<10}`\n", .{
        label, @as(u32, epoch), @as(u32, 0), @as(u32, 0), "100644", data.len,
    });
    if (header.len != 60) return error.InvalidIntegrationArEntry;
    try append(allocator, out, header);
    try append(allocator, out, data);
    if (data.len % 2 != 0) try append(allocator, out, "\n");
}

fn encode(io: std.Io, allocator: std.mem.Allocator, workspace: []const u8, request: Request) ![]u8 {
    const control = try tar(allocator, request.control);
    const data = try tar(allocator, request.data);
    if (request.origin) |origin| {
        if (origin.len > 4096) return error.IntegrationArchiveTooLarge;
    }
    var root = try fs.openAbsoluteRoot(io, workspace);
    defer root.close();
    for ([_][]const u8{ "control.tar", "data.tar" }) |name|
        if (try root.root.entryIfExists(try fs.Path.init(name)) != null) return error.IntegrationScratchExists;
    const compressed_control = try gzip(io, allocator, root.root, workspace, "control.tar", control);
    const compressed_data = try gzip(io, allocator, root.root, workspace, "data.tar", data);
    var out: std.ArrayList(u8) = .empty;
    try append(allocator, &out, "!<arch>\n");
    try ar(allocator, &out, "debian-binary", "2.0\n");
    try ar(allocator, &out, "control.tar.gz", compressed_control);
    try ar(allocator, &out, "data.tar.gz", compressed_data);
    if (request.origin) |origin| try ar(allocator, &out, "_gpgorigin", origin);
    return out.toOwnedSlice(allocator);
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const workspace = args.next() orelse return error.MissingIntegrationArchiveWorkspace;
    if (args.next() != null or !std.fs.path.isAbsolute(workspace)) return error.InvalidIntegrationArchiveWorkspace;
    var root = try fs.openAbsoluteRoot(init.io, workspace);
    defer root.close();
    var pin = try root.root.pinRegularFile(try fs.Path.init("request.json"));
    defer pin.close();
    const allocator = init.arena.allocator();
    const document = try pin.observeStableAlloc(allocator, maximum_bytes * 2);
    const request = try std.json.parseFromSlice(Request, allocator, document.bytes, .{});
    const output = encode(init.io, allocator, workspace, request.value) catch |err| {
        std.log.err("native integration archive refused: {s}", .{@errorName(err)});
        return err;
    };
    try std.Io.File.stdout().writeStreamingAll(init.io, output);
}

test "integration archive encoder reproduces independently original package tar, gzip and ar bytes with no Python" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const workspace = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const control = "Package: base-dep\nVersion: 1.0-1\nArchitecture: arm64\nMaintainer: debz fixture <fixture.invalid>\nDescription: debz hermetic fixture base-dep\n";
    const payload = "base-dep=1.0-1:arm64\n";
    const request: Request = .{
        .control = &.{.{ .name = "./control", .hex = &std.fmt.bytesToHex(control, .lower), .mode = 0o644 }},
        .data = &.{.{ .name = "./usr/share/debz-fixtures/base-dep", .hex = &std.fmt.bytesToHex(payload, .lower), .mode = 0o644 }},
    };
    const json = try std.json.Stringify.valueAlloc(allocator, request, .{});
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "request.json", .data = json });
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try environment.put("PATH", "/no-host-interpreters");
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ @import("integration_archive_test_options").executable, workspace },
        .environ_map = &environment,
        .stdout_limit = .limited(maximum_bytes),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(result.stdout, &digest, .{});
    try std.testing.expectEqualStrings("e9c466cb01d4a5e0c0eb9e5564f5e7d27859d195eff82beb7745c402f12aaca7", &std.fmt.bytesToHex(digest, .lower));
    try std.testing.expectEqual(@as(usize, 606), result.stdout.len);
    for ([_][]const u8{ "control.tar", "data.tar" }) |name|
        try std.testing.expectError(error.FileNotFound, temporary.dir.statFile(std.testing.io, name, .{}));
}

test "integration archive encoder rejects traversal, duplicate and malformed entries before creating scratch files" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    for ([_][]const u8{ "../escaped", "/absolute", "./a/../../escaped" }) |name| {
        if (tar(allocator, &.{.{ .name = name, .hex = "", .mode = 0o644 }})) |_| return error.TestExpectedError else |_| {}
    }
    try std.testing.expectError(error.DuplicateIntegrationTarEntry, tar(allocator, &.{
        .{ .name = "./control", .hex = "", .mode = 0o644 },
        .{ .name = "control", .hex = "", .mode = 0o644 },
    }));
    try std.testing.expectError(error.InvalidIntegrationTarBytes, tar(allocator, &.{.{ .name = "./control", .hex = "0z", .mode = 0o644 }}));
    try std.testing.expectError(error.InvalidIntegrationTarEntry, tar(allocator, &.{.{ .name = "./control", .hex = "", .mode = 0o10000 }}));
}

test "integration archive encoder refuses existing scratch aliases without changing external bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const workspace = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "outside", .data = "unchanged" });
    try temporary.dir.symLink(std.testing.io, "outside", "data.tar", .{});
    try std.testing.expectError(error.IntegrationScratchExists, encode(std.testing.io, allocator, workspace, .{ .control = &.{}, .data = &.{} }));
    try std.testing.expectEqualStrings("unchanged", try temporary.dir.readFileAlloc(std.testing.io, "outside", allocator, .limited(32)));
    try std.testing.expectError(error.FileNotFound, temporary.dir.statFile(std.testing.io, "control.tar", .{}));
}
