//! Original deterministic integration archive encoding, not package authority.
const std = @import("std");
const debz = @import("debz");
const fs = debz.root_fs;
const maximum_bytes = 8 * 1024 * 1024;
const epoch = 1_700_000_000;

pub const Entry = struct { name: []const u8, hex: []const u8, mode: u16 };
pub const Request = struct {
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
    if (std.mem.readInt(u32, footer[0..4], .little) != std.hash.Crc32.hash(raw) or
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

pub fn encode(io: std.Io, allocator: std.mem.Allocator, workspace: []const u8, request: Request) ![]u8 {
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

pub fn extraControl(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const outer = switch (debz.deb_archive.parse(bytes, .{
        .max_archive_bytes = maximum_bytes,
        .max_member_bytes = maximum_bytes,
    })) {
        .archive => |archive| archive,
        .diagnostic => |diagnostic| {
            std.log.err("extra package outer archive refused: {s}", .{diagnostic.message()});
            return error.InvalidExtraPackageArchive;
        },
    };
    if (outer.control.compression == .zstd) return error.UnsupportedExtraControlCompression;
    const text = switch (debz.deb_payload.inspectControlAlloc(allocator, bytes, .{
        .outer = .{ .max_archive_bytes = maximum_bytes, .max_member_bytes = maximum_bytes },
        .max_control_compressed_bytes = maximum_bytes,
        .max_control_decompressed_bytes = maximum_bytes,
        .max_control_file_bytes = maximum_bytes,
        .max_entries_per_tar = maximum_bytes / 512,
        .max_inventory_bytes_per_tar = maximum_bytes * 2,
    })) {
        .bytes => |text| text,
        .diagnostic => |diagnostic| {
            std.log.err("extra package control refused: stage={s} code={s} {s}", .{
                @tagName(diagnostic.stage), @tagName(diagnostic.code), diagnostic.message(),
            });
            return error.InvalidExtraPackageControl;
        },
    };
    errdefer allocator.free(text);
    if (!std.unicode.utf8ValidateSlice(text) or !std.mem.endsWith(u8, text, "\n") or
        std.mem.indexOf(u8, text, "\n\n") != null)
        return error.InvalidExtraControlParagraph;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        for ([_][]const u8{ "Filename:", "Size:", "SHA256:", "SHA512:", "MD5sum:" }) |field|
            if (std.mem.startsWith(u8, line, field)) return error.ExtraControlRepositoryFields;
    }
    return text;
}

fn extraControlFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(path)) return error.InvalidExtraPackagePath;
    var root = try fs.openAbsoluteRoot(io, std.fs.path.dirname(path) orelse return error.InvalidExtraPackagePath);
    defer root.close();
    var pin = try root.root.pinRegularFile(try fs.Path.init(std.fs.path.basename(path)));
    defer pin.close();
    const source = try pin.observeStableAlloc(allocator, maximum_bytes);
    defer allocator.free(source.bytes);
    return extraControl(allocator, source.bytes);
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const workspace = args.next() orelse return error.MissingIntegrationArchiveWorkspace;
    if (std.mem.eql(u8, workspace, "--extra-control")) {
        const path = args.next() orelse return error.InvalidExtraPackagePath;
        if (args.next() != null) return error.InvalidExtraPackagePath;
        const output = extraControlFile(init.io, init.arena.allocator(), path) catch |err| {
            std.log.err("native extra package parsing refused: {s}", .{@errorName(err)});
            return err;
        };
        try std.Io.File.stdout().writeStreamingAll(init.io, output);
        return;
    }
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

fn extraPackage(allocator: std.mem.Allocator, name: []const u8, control: []const u8) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try append(allocator, &bytes, "!<arch>\n");
    try ar(allocator, &bytes, "debian-binary", "2.0\n");
    try ar(allocator, &bytes, name, control);
    try ar(allocator, &bytes, "data.tar", "data payload is deliberately not decoded");
    return bytes.toOwnedSlice(allocator);
}

fn originalControlFixture(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const path = try std.fs.path.join(allocator, &.{
        @import("integration_archive_test_options").repository, "src/fixtures/deb-payload", name,
    });
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(maximum_bytes));
}

fn expectExtraRefusal(allocator: std.mem.Allocator, bytes: []const u8, message: []const u8) !void {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "extra.deb", .data = bytes });
    const directory = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const path = try std.fs.path.join(allocator, &.{ directory, "extra.deb" });
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ @import("integration_archive_test_options").executable, "--extra-control", path },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(8192),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try std.testing.expectEqual(@as(usize, 0), result.stdout.len);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, message) != null);
    try std.testing.expectEqualSlices(u8, bytes, try temporary.dir.readFileAlloc(std.testing.io, "extra.deb", allocator, .limited(maximum_bytes)));
}

test "extra control parser preserves original raw gzip and xz control bytes with no interpreter or data extraction" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const expected = "Package: demo\nVersion: 1.0\nArchitecture: amd64\n";
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const directory = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const path = try std.fs.path.join(allocator, &.{ directory, "extra.deb" });
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try environment.put("PATH", "/no-host-interpreters");
    for ([_][]const u8{ "control.tar", "control.tar.gz", "control.tar.xz" }) |name| {
        const package = try extraPackage(allocator, name, try originalControlFixture(allocator, name));
        try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "extra.deb", .data = package });
        const result = try std.process.run(allocator, std.testing.io, .{
            .argv = &.{ @import("integration_archive_test_options").executable, "--extra-control", path },
            .environ_map = &environment,
            .stdout_limit = .limited(maximum_bytes),
            .stderr_limit = .limited(4096),
        });
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try std.testing.expectEqualStrings(expected, result.stdout);
    }
}

test "extra control parser rejects malformed archives duplicate controls and repository transport fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const raw = try originalControlFixture(allocator, "control.tar");
    const package = try extraPackage(allocator, "control.tar", raw);
    try expectExtraRefusal(allocator, package[0 .. package.len - 1], "InvalidExtraPackageArchive");
    const corrupted = try allocator.dupe(u8, raw);
    corrupted[0] ^= 1;
    try expectExtraRefusal(allocator, try extraPackage(allocator, "control.tar", corrupted), "tar_bad_checksum");
    const corrupt_gzip = try originalControlFixture(allocator, "control.tar.gz");
    corrupt_gzip[corrupt_gzip.len - 8] ^= 1;
    try expectExtraRefusal(allocator, try extraPackage(allocator, "control.tar.gz", corrupt_gzip), "decompression_failed");
    var duplicates: std.ArrayList(u8) = .empty;
    try member(allocator, &duplicates, "./control", "Package: demo\n", 0o644, false);
    try member(allocator, &duplicates, "control", "Package: demo\n", 0o644, false);
    try append(allocator, &duplicates, &(@as([1024]u8, @splat(0))));
    try expectExtraRefusal(allocator, try extraPackage(allocator, "control.tar", duplicates.items), "duplicate_path");
    for ([_][]const u8{ "Package: demo", "Package: demo\n\nVersion: 1\n", "Package: \xff\n" }) |text| {
        const hex = try std.fmt.allocPrint(allocator, "{x}", .{text});
        const control = try tar(allocator, &.{.{ .name = "./control", .hex = hex, .mode = 0o644 }});
        try std.testing.expectError(error.InvalidExtraControlParagraph, extraControl(allocator, try extraPackage(allocator, "control.tar", control)));
    }
    for ([_][]const u8{ "Filename:", "Size:", "SHA256:", "SHA512:", "MD5sum:" }) |field| {
        const text = try std.fmt.allocPrint(allocator, "Package: demo\n{s} injected\n", .{field});
        const hex = try std.fmt.allocPrint(allocator, "{x}", .{text});
        const control = try tar(allocator, &.{.{ .name = "./control", .hex = hex, .mode = 0o644 }});
        try std.testing.expectError(error.ExtraControlRepositoryFields, extraControl(allocator, try extraPackage(allocator, "control.tar", control)));
    }
    try std.testing.expectError(error.UnsupportedExtraControlCompression, extraControl(allocator, try extraPackage(allocator, "control.tar.zst", "not supported")));
}

test "extra control file refuses relative symlink and oversized inputs without changing files" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "outside", .data = "unchanged" });
    try temporary.dir.symLink(std.testing.io, "outside", "extra.deb", .{});
    const directory = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const path = try std.fs.path.join(allocator, &.{ directory, "extra.deb" });
    try std.testing.expectError(error.InvalidExtraPackagePath, extraControlFile(std.testing.io, allocator, "relative.deb"));
    if (extraControlFile(std.testing.io, allocator, path)) |bytes| {
        allocator.free(bytes);
        return error.TestExpectedError;
    } else |err| try std.testing.expect(err != error.InvalidExtraPackageArchive);
    try std.testing.expectEqualStrings("unchanged", try temporary.dir.readFileAlloc(std.testing.io, "outside", allocator, .limited(32)));
    try temporary.dir.deleteFile(std.testing.io, "extra.deb");
    const file = try temporary.dir.createFile(std.testing.io, "extra.deb", .{});
    defer file.close(std.testing.io);
    try file.setLength(std.testing.io, maximum_bytes + 1);
    try std.testing.expectError(error.FileTooLarge, extraControlFile(std.testing.io, allocator, path));
}
