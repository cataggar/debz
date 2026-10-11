//! Reproduces the original signed baseline fixtures with the existing public,
//! test-only RSA key. Never use this key or signer for production artifacts.
const std = @import("std");
const debz = @import("debz");
const options = @import("baseline_fixture_options");
const fs = debz.root_fs;
const pgp = @import("fixture-openpgp.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const names = [_][]const u8{ "alpha.deb", "beta.deb", "Packages", "keyring.gpg", "InRelease" };
const maximum_fixture_bytes = 64 * 1024;

fn tar(allocator: std.mem.Allocator, name: []const u8, content: []const u8) ![]u8 {
    if (name.len >= 100 or content.len > 512) return error.FixtureTarTooLarge;
    const raw = try allocator.alloc(u8, 10240);
    @memset(raw, 0);
    @memcpy(raw[0..name.len], name);
    @memcpy(raw[100..124], "0000644\x000000000\x000000000\x00");
    _ = try std.fmt.bufPrint(raw[124..135], "{o:0>11}", .{content.len});
    @memcpy(raw[136..147], "00000000000");
    @memset(raw[148..156], ' ');
    raw[156] = '0';
    @memcpy(raw[257..265], "ustar\x0000");
    var checksum: u32 = 0;
    for (raw[0..512]) |byte| checksum += byte;
    _ = try std.fmt.bufPrint(raw[148..154], "{o:0>6}", .{checksum});
    raw[154] = 0;
    raw[155] = ' ';
    @memcpy(raw[512..][0..content.len], content);
    return raw;
}

fn arMember(allocator: std.mem.Allocator, name: []const u8, content: []const u8) ![]u8 {
    const member_name = try std.fmt.allocPrint(allocator, "{s}/", .{name});
    const header = try std.fmt.allocPrint(allocator, "{s:<16}{d:<12}{d:<6}{d:<6}{s:<8}{d:<10}`\n", .{
        member_name, @as(u32, 0), @as(u32, 0), @as(u32, 0), "100644", content.len,
    });
    if (header.len != 60) return error.FixtureArTooLarge;
    return std.mem.concat(allocator, u8, &.{ header, content, if (content.len % 2 == 0) "" else "\n" });
}

fn archive(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const control = try std.fmt.allocPrint(
        allocator,
        "Package: {s}\nVersion: 1.0\nArchitecture: amd64\n" ++
            "Maintainer: Test <test@example.invalid>\nDescription: {s}\n",
        .{ name, name },
    );
    const payload_name = try std.fmt.allocPrint(allocator, "./usr/share/{s}", .{name});
    const payload = try std.fmt.allocPrint(allocator, "{s} signed payload\n", .{name});
    return std.mem.concat(allocator, u8, &.{
        "!<arch>\n",
        try arMember(allocator, "debian-binary", "2.0\n"),
        try arMember(allocator, "control.tar", try tar(allocator, "./control", control)),
        try arMember(allocator, "data.tar", try tar(allocator, payload_name, payload)),
    });
}

fn fixtures(allocator: std.mem.Allocator) ![names.len][]const u8 {
    var result: [names.len][]const u8 = undefined;
    var packages: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "alpha", "beta" }, 0..) |name, index| {
        const deb = try archive(allocator, name);
        result[index] = deb;
        var sha256: [32]u8 = undefined;
        var sha512: [64]u8 = undefined;
        Sha256.hash(deb, &sha256, .{});
        Sha512.hash(deb, &sha512, .{});
        try packages.appendSlice(allocator, try std.fmt.allocPrint(
            allocator,
            "Package: {s}\nVersion: 1.0\nArchitecture: amd64\n" ++
                "Maintainer: Test <test@example.invalid>\nDescription: {s}\n" ++
                "Filename: pool/{s}_1.0_amd64.deb\nSize: {d}\nSHA256: {s}\nSHA512: {s}\n\n",
            .{ name, name, name, deb.len, std.fmt.bytesToHex(sha256, .lower), std.fmt.bytesToHex(sha512, .lower) },
        ));
    }
    result[2] = packages.items[0 .. packages.items.len - 1];
    const public_body = try pgp.Key.primary.publicBody(allocator);
    const key_prefix = try pgp.keyPrefix(allocator, public_body);
    const fingerprint = try pgp.fingerprint(allocator, public_body);
    var uid_prefix: std.ArrayList(u8) = .empty;
    try uid_prefix.append(allocator, 0xb4);
    try pgp.integer(&uid_prefix, allocator, u32, pgp.uid.len);
    try uid_prefix.appendSlice(allocator, pgp.uid);
    result[3] = try std.mem.concat(allocator, u8, &.{
        try pgp.packet(allocator, 6, public_body),
        try pgp.packet(allocator, 13, pgp.uid),
        try pgp.signature(allocator, .primary, 0x13, &.{ key_prefix, uid_prefix.items }, fingerprint, .{
            .extra_hashed = try pgp.subpacket(allocator, 27, &.{0x03}),
        }),
    });
    var sha256: [32]u8 = undefined;
    var sha512: [64]u8 = undefined;
    Sha256.hash(result[2], &sha256, .{});
    Sha512.hash(result[2], &sha512, .{});
    const release = try std.fmt.allocPrint(
        allocator,
        "Origin: debz deterministic native baseline fixture\nSuite: stable\n" ++
            "Codename: stable\nDate: Mon, 07 Sep 2026 00:00:00 +0000\n" ++
            "Valid-Until: Mon, 14 Sep 2026 00:00:00 +0000\n" ++
            "Architectures: amd64\nComponents: main\nAcquire-By-Hash: no\n" ++
            "SHA256:\n {s} {d} main/binary-amd64/Packages\n" ++
            "SHA512:\n {s} {d} main/binary-amd64/Packages\n",
        .{ std.fmt.bytesToHex(sha256, .lower), result[2].len, std.fmt.bytesToHex(sha512, .lower), result[2].len },
    );
    result[4] = try pgp.clearsign(allocator, .primary, fingerprint, release, .{ .timestamp = 1_788_739_200 });
    return result;
}

const Destination = struct {
    root: fs.Root,
    path: fs.Path,
    original: ?fs.Entry,

    fn check(self: Destination) !void {
        const current = try self.root.entryIfExists(self.path);
        if (current) |entry| {
            if (!entry.isRegularFile()) return error.NotRegularFixtureDestination;
            if (entry.link_count != 1) return error.HardLinkedFixtureDestination;
        }
        if (!std.meta.eql(self.original, current)) return error.FixtureDestinationChanged;
    }

    fn observe(context: *anyopaque, point: fs.PublishPoint) !void {
        const self: *Destination = @ptrCast(@alignCast(context));
        if (point == .before_rename) try self.check();
    }
};

fn generate(io: std.Io, allocator: std.mem.Allocator, output: []const u8) !void {
    if (!std.fs.path.isAbsolute(output)) return error.AbsoluteFixturePathRequired;
    var parent = try fs.openAbsoluteRoot(io, std.fs.path.dirname(output) orelse return error.InvalidFixturePath);
    defer parent.close();
    try parent.root.ensureDirectory(try fs.Path.init(std.fs.path.basename(output)), .fromMode(0o755));
    var destination = try fs.openAbsoluteRoot(io, output);
    defer destination.close();
    const bytes = try fixtures(allocator);
    var targets: [names.len]Destination = undefined;
    for (names, 0..) |name, index| {
        const path = try fs.Path.init(name);
        targets[index] = .{ .root = destination.root, .path = path, .original = try destination.root.entryIfExists(path) };
        try targets[index].check();
        if (bytes[index].len > maximum_fixture_bytes) return error.FixtureTooLarge;
    }
    for (&targets, bytes) |*target, content| {
        try target.check();
        try target.root.publishFile(target.path, content, .{
            .permissions = .fromMode(0o644),
            .observer = .{ .context = target, .hitFn = Destination.observe },
        });
    }
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const allocator = init.arena.allocator();
    const output = if (args.next()) |argument| blk: {
        if (!std.mem.eql(u8, argument, "--output")) return error.UnexpectedFixtureArgument;
        break :blk args.next() orelse return error.MissingFixtureArgument;
    } else try std.fs.path.join(allocator, &.{ options.repository, "src/fixtures/native_baseline" });
    if (args.next() != null) return error.UnexpectedFixtureArgument;
    try generate(init.io, allocator, output);
}

test "native baseline generator reproduces every original independently signed fixture byte" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const bytes = try fixtures(allocator);
    for (names, bytes) |name, actual| {
        const path = try std.fs.path.join(allocator, &.{ options.repository, "src/fixtures/native_baseline", name });
        const expected = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(maximum_fixture_bytes));
        try std.testing.expectEqualSlices(u8, expected, actual);
        const generated_path = try std.fs.path.join(allocator, &.{ @import("baseline_fixture_test_options").generated, name });
        const generated = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, generated_path, allocator, .limited(maximum_fixture_bytes));
        try std.testing.expectEqualSlices(u8, expected, generated);
    }
}

test "native baseline generator publishes and regenerates real files without touching unrelated files" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var work = std.testing.tmpDir(.{});
    defer work.cleanup();
    const root = try work.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const output = try std.fs.path.join(allocator, &.{ root, "fixtures" });
    try generate(std.testing.io, allocator, output);
    var directory = try work.dir.openDir(std.testing.io, "fixtures", .{});
    defer directory.close(std.testing.io);
    try directory.writeFile(std.testing.io, .{ .sub_path = "unrelated", .data = "retain" });
    try directory.writeFile(std.testing.io, .{ .sub_path = "Packages", .data = "stale" });
    try generate(std.testing.io, allocator, output);
    const original = try fixtures(allocator);
    for (names, original) |name, bytes| {
        const actual = try directory.readFileAlloc(std.testing.io, name, allocator, .limited(maximum_fixture_bytes));
        try std.testing.expectEqualSlices(u8, bytes, actual);
    }
    try std.testing.expectEqualStrings("retain", try directory.readFileAlloc(std.testing.io, "unrelated", allocator, .limited(32)));
}

test "native baseline generator refuses linked destinations before changing any original or external file" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var work = std.testing.tmpDir(.{});
    defer work.cleanup();
    const root = try work.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const output = try std.fs.path.join(allocator, &.{ root, "fixtures" });
    try generate(std.testing.io, allocator, output);
    var directory = try work.dir.openDir(std.testing.io, "fixtures", .{});
    defer directory.close(std.testing.io);
    try directory.writeFile(std.testing.io, .{ .sub_path = "alpha.deb", .data = "retained first file" });
    try directory.writeFile(std.testing.io, .{ .sub_path = "external", .data = "external bytes" });
    try directory.deleteFile(std.testing.io, "InRelease");
    try directory.symLink(std.testing.io, "external", "InRelease", .{});
    try std.testing.expectError(error.NotRegularFixtureDestination, generate(std.testing.io, allocator, output));
    try std.testing.expectEqualStrings("retained first file", try directory.readFileAlloc(std.testing.io, "alpha.deb", allocator, .limited(64)));
    try std.testing.expectEqualStrings("external bytes", try directory.readFileAlloc(std.testing.io, "external", allocator, .limited(64)));
    try directory.deleteFile(std.testing.io, "InRelease");
    var owned = try fs.openAbsoluteRoot(std.testing.io, output);
    defer owned.close();
    try owned.root.createHardLink(try fs.Path.init("external"), try fs.Path.init("InRelease"));
    try std.testing.expectError(error.HardLinkedFixtureDestination, generate(std.testing.io, allocator, output));
    try std.testing.expectEqualStrings("retained first file", try directory.readFileAlloc(std.testing.io, "alpha.deb", allocator, .limited(64)));
    try std.testing.expectEqualStrings("external bytes", try directory.readFileAlloc(std.testing.io, "external", allocator, .limited(64)));
    try std.testing.expectError(error.AbsoluteFixturePathRequired, generate(std.testing.io, allocator, "fixtures"));
}
