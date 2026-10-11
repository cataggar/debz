//! Reproduces the original signed baseline fixtures with the existing public,
//! test-only RSA key. Never use this key or signer for production artifacts.
const std = @import("std");
const debz = @import("debz");
const options = @import("baseline_fixture_options");
const fs = debz.root_fs;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const created = 1_700_000_000;
const uid = "debz hermetic archive fixture <fixture.invalid>";
const names = [_][]const u8{ "alpha.deb", "beta.deb", "Packages", "keyring.gpg", "InRelease" };
const maximum_fixture_bytes = 64 * 1024;

const modulus_bytes = fixedBytes(
    "e63d9b520091f3e49cad49e7323f1e9298b89a81a8c35641739eb2b1363fbfa7" ++
        "1323fa95ecb19119dfd508354cd81c144559f41b81e31c4a0c71558bdfd0f7d7" ++
        "adc4e84f0a56a0ecf9e627a83faf42a636c0b9d1b20832a889376023984219f5" ++
        "597affd38deb202bc24618b71612fdcb4f58276aa52e1ac1df8ec3e8e90c8391" ++
        "a7418ebbaa0ad2e8d122012d915631192968bed9311fb269173dcf9fce0b846e" ++
        "13e8f6c9bc494a4121dd8834a44de6a17ac3b4e1c65c6993a74b057f2eb2bdcc" ++
        "9f5ac98ab5cdaa495c8d184d8f5547d5318cad77b1e22ad1245cfd906aefcaf5" ++
        "167d1a07ceab995092bd09fd30c8a1a00896bda72c0f9fa31f6af21a83040bdd",
);
const fixture_private_exponent = fixedBytes(
    "0578c257b50ec2ea9474a3d47c43b6c0ca235cfca6db9991ada34060e8c6a411" ++
        "dee9147bfaa78fa8bb428f52e0f423dab1793d4d680d532f49536a328c4ba590" ++
        "391f7c5be08585868c3bd5867099042efa0f237b61cd4312f14be11b87734eb5" ++
        "9f7e46552b42c2bd777cfdfa5fea6ca0a7ce93053c4eb7b112d48c405d45805c" ++
        "eabc9b2876975411f635adb510f5ee3da8c1222b5dad9295a4052c3c7f425785" ++
        "08ef96509d2d4293bf9a511ea529eb6411abce9be266173fdd42319dff3fbd9b" ++
        "c57ef4e6c553facb10aefffcf883ba91a8cdfd9661c5b4fc432d36074c5f4884" ++
        "c1acc45facc60a7dae0cd424351e6eb8a45125fa3f294875eec60e3edd8d5ffb",
);

fn fixedBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

fn integer(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try out.appendSlice(allocator, &bytes);
}

fn mpi(out: *std.ArrayList(u8), allocator: std.mem.Allocator, raw: []const u8) !void {
    const first = std.mem.indexOfNone(u8, raw, &.{0}) orelse raw.len;
    const value = raw[first..];
    const bits = if (value.len == 0) 0 else value.len * 8 - @clz(value[0]);
    try integer(out, allocator, u16, @intCast(bits));
    try out.appendSlice(allocator, value);
}

fn packet(allocator: std.mem.Allocator, tag: u8, body: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(allocator, 0xc0 | tag);
    if (body.len < 192) {
        try out.append(allocator, @intCast(body.len));
    } else if (body.len < 8384) {
        const adjusted = body.len - 192;
        try out.appendSlice(allocator, &.{ @intCast((adjusted >> 8) + 192), @intCast(adjusted & 255) });
    } else {
        return error.FixturePacketTooLarge;
    }
    try out.appendSlice(allocator, body);
    return out.toOwnedSlice(allocator);
}

fn subpacket(allocator: std.mem.Allocator, tag: u8, body: []const u8) ![]u8 {
    if (body.len + 1 >= 192) return error.FixturePacketTooLarge;
    return std.mem.concat(allocator, u8, &.{ &.{ @intCast(body.len + 1), tag }, body });
}

fn keyPrefix(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(allocator, 0x99);
    try integer(&out, allocator, u16, @intCast(body.len));
    try out.appendSlice(allocator, body);
    return out.toOwnedSlice(allocator);
}

fn signature(
    allocator: std.mem.Allocator,
    kind: u8,
    parts: []const []const u8,
    fingerprint: [20]u8,
    timestamp: u32,
    flags: ?u8,
) ![]u8 {
    var time: [4]u8 = undefined;
    std.mem.writeInt(u32, &time, timestamp, .big);
    var issuer: [21]u8 = undefined;
    issuer[0] = 4;
    issuer[1..].* = fingerprint;
    var hashed: std.ArrayList(u8) = .empty;
    try hashed.appendSlice(allocator, try subpacket(allocator, 2, &time));
    try hashed.appendSlice(allocator, try subpacket(allocator, 33, &issuer));
    if (flags) |value| try hashed.appendSlice(allocator, try subpacket(allocator, 27, &.{value}));
    var prefix: std.ArrayList(u8) = .empty;
    try prefix.appendSlice(allocator, &.{ 4, kind, 1, 8 });
    try integer(&prefix, allocator, u16, @intCast(hashed.items.len));
    try prefix.appendSlice(allocator, hashed.items);
    var trailer: [6]u8 = .{ 4, 0xff, 0, 0, 0, 0 };
    std.mem.writeInt(u32, trailer[2..6], @intCast(prefix.items.len), .big);
    var hash = Sha256.init(.{});
    for (parts) |part| hash.update(part);
    hash.update(prefix.items);
    hash.update(&trailer);
    const digest = hash.finalResult();
    const digest_info = fixedBytes("3031300d060960864801650304020105000420");
    var encoded: [256]u8 = @splat(0xff);
    encoded[0] = 0;
    encoded[1] = 1;
    const separator = encoded.len - digest_info.len - digest.len - 1;
    encoded[separator] = 0;
    @memcpy(encoded[separator + 1 ..][0..digest_info.len], &digest_info);
    @memcpy(encoded[encoded.len - digest.len ..], &digest);
    const Modulus = std.crypto.ff.Modulus(2048);
    const modulus = try Modulus.fromBytes(&modulus_bytes, .big);
    const message = try Modulus.Fe.fromBytes(modulus, &encoded, .big);
    const signed = try modulus.powWithEncodedExponent(message, &fixture_private_exponent, .big);
    var raw_signature: [256]u8 = undefined;
    try signed.toBytes(&raw_signature, .big);
    var body: std.ArrayList(u8) = .empty;
    try body.appendSlice(allocator, prefix.items);
    const unhashed = try subpacket(allocator, 16, fingerprint[12..20]);
    try integer(&body, allocator, u16, @intCast(unhashed.len));
    try body.appendSlice(allocator, unhashed);
    try body.appendSlice(allocator, digest[0..2]);
    try mpi(&body, allocator, &raw_signature);
    return packet(allocator, 2, body.items);
}

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
    var public_body: std.ArrayList(u8) = .empty;
    try public_body.append(allocator, 4);
    try integer(&public_body, allocator, u32, created);
    try public_body.append(allocator, 1);
    try mpi(&public_body, allocator, &modulus_bytes);
    try mpi(&public_body, allocator, &.{ 1, 0, 1 });
    const key_prefix = try keyPrefix(allocator, public_body.items);
    var fingerprint: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(key_prefix, &fingerprint, .{});
    var uid_prefix: std.ArrayList(u8) = .empty;
    try uid_prefix.append(allocator, 0xb4);
    try integer(&uid_prefix, allocator, u32, uid.len);
    try uid_prefix.appendSlice(allocator, uid);
    result[3] = try std.mem.concat(allocator, u8, &.{
        try packet(allocator, 6, public_body.items),
        try packet(allocator, 13, uid),
        try signature(allocator, 0x13, &.{ key_prefix, uid_prefix.items }, fingerprint, created, 0x03),
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
    const canonical = try std.mem.replaceOwned(u8, allocator, release[0 .. release.len - 1], "\n", "\r\n");
    const signed = try signature(allocator, 0x01, &.{canonical}, fingerprint, 1_788_739_200, null);
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(signed.len));
    _ = encoder.encode(encoded, signed);
    var envelope: std.ArrayList(u8) = .empty;
    try envelope.appendSlice(allocator, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n");
    try envelope.appendSlice(allocator, release);
    try envelope.appendSlice(allocator, "-----BEGIN PGP SIGNATURE-----\n\n");
    var offset: usize = 0;
    while (offset < encoded.len) : (offset += 64) {
        try envelope.appendSlice(allocator, encoded[offset..@min(offset + 64, encoded.len)]);
        try envelope.append(allocator, '\n');
    }
    try envelope.appendSlice(allocator, "-----END PGP SIGNATURE-----\n");
    result[4] = try envelope.toOwnedSlice(allocator);
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
