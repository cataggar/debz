//! Original, publicly checked-in RSA and Ed25519 keys for hermetic fixtures
//! only. Allocations belong to the caller's generation arena, not production.
const std = @import("std");
pub const created = 1_700_000_000;
pub const uid = "debz hermetic archive fixture <fixture.invalid>";

const Rsa = struct { modulus: [256]u8, exponent: [256]u8 };
const primary = Rsa{
    .modulus = fixedBytes(
        "e63d9b520091f3e49cad49e7323f1e9298b89a81a8c35641739eb2b1363fbfa7" ++
            "1323fa95ecb19119dfd508354cd81c144559f41b81e31c4a0c71558bdfd0f7d7" ++
            "adc4e84f0a56a0ecf9e627a83faf42a636c0b9d1b20832a889376023984219f5" ++
            "597affd38deb202bc24618b71612fdcb4f58276aa52e1ac1df8ec3e8e90c8391" ++
            "a7418ebbaa0ad2e8d122012d915631192968bed9311fb269173dcf9fce0b846e" ++
            "13e8f6c9bc494a4121dd8834a44de6a17ac3b4e1c65c6993a74b057f2eb2bdcc" ++
            "9f5ac98ab5cdaa495c8d184d8f5547d5318cad77b1e22ad1245cfd906aefcaf5" ++
            "167d1a07ceab995092bd09fd30c8a1a00896bda72c0f9fa31f6af21a83040bdd",
    ),
    .exponent = fixedBytes(
        "0578c257b50ec2ea9474a3d47c43b6c0ca235cfca6db9991ada34060e8c6a411" ++
            "dee9147bfaa78fa8bb428f52e0f423dab1793d4d680d532f49536a328c4ba590" ++
            "391f7c5be08585868c3bd5867099042efa0f237b61cd4312f14be11b87734eb5" ++
            "9f7e46552b42c2bd777cfdfa5fea6ca0a7ce93053c4eb7b112d48c405d45805c" ++
            "eabc9b2876975411f635adb510f5ee3da8c1222b5dad9295a4052c3c7f425785" ++
            "08ef96509d2d4293bf9a511ea529eb6411abce9be266173fdd42319dff3fbd9b" ++
            "c57ef4e6c553facb10aefffcf883ba91a8cdfd9661c5b4fc432d36074c5f4884" ++
            "c1acc45facc60a7dae0cd424351e6eb8a45125fa3f294875eec60e3edd8d5ffb",
    ),
};
const subkey = Rsa{
    .modulus = fixedBytes(
        "d3674c12d01584dec3f0137bf975a8a7d6b8a286f563239fc07640031bf22a61" ++
            "77f24a3f95f4e1183ccc49b8e923ab736200fc80feffb4472c5224aae9419ee71" ++
            "1b2a39d07da116d5b626c36107176f13e072056f4a8695be45cb7481a6507efca" ++
            "f446ca1c1ffe516b9cedf1defea520439e078f3bf0f513e414308549b912afc3e6" ++
            "dd083d5782c6ebc4397d2c8f9533311ad3ad3c007d5860e8388ecd5a80482d54" ++
            "b88639d4ed76eeafac42ae3d8ba14b42ec700aefe7a0962d1ed23ea1abb20e790" ++
            "b756cb2cb8ac52d945257b99261eebe0f0147ea26d417463a8d4ed0989570bd639" ++
            "dfaeb23c25059af6d6dbb71df7ca69b1c3a917859b29842d51134083d",
    ),
    .exponent = fixedBytes(
        "09fd08f6a0974bb25ccea4950879db30a6f00d59d4114d9718385e18e7829f27" ++
            "00cc555ec0be93be19ed4b146e0b8de7c33b29b30c995752bf90d803ad46b8f3" ++
            "d0fdc046449f349096af454e9ea345cbeb32d9ffd1ca7d43e6bbccbb1ee824225" ++
            "bd403de3bcaf530b2a57506a713200930b8b041bfc2c8499aceab6638d002466e" ++
            "b90204f76477c237ce18671586304d01a2025c3e6d7a17b27ec6eced40c36797" ++
            "f13597ec4baaa384be912a28698cacfea28000dfb9201bbf4aa6db2f1f8e7f0212" ++
            "ca9a482f4723ab8fd161a118a51667d1099641a8b5a9527581dc63a08878c3a04" ++
            "ccd91b8903cdad0f6720acd6c95f71b0e2d42c53528b8618596768327af",
    ),
};

fn fixedBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(10000);
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

pub const Key = enum {
    primary,
    subkey,
    ed25519,

    fn edPair() !std.crypto.sign.Ed25519.KeyPair {
        var seed: [32]u8 = undefined;
        for (&seed, 1..) |*byte, index| byte.* = @intCast(index);
        return std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    }

    fn rsa(self: Key) Rsa {
        return switch (self) {
            .primary => primary,
            .subkey => subkey,
            .ed25519 => unreachable,
        };
    }

    pub fn publicBody(self: Key, allocator: std.mem.Allocator) ![]u8 {
        var body: std.ArrayList(u8) = .empty;
        try body.append(allocator, 4);
        try integer(&body, allocator, u32, created);
        try body.append(allocator, if (self == .ed25519) 22 else 1);
        if (self == .ed25519) {
            try body.appendSlice(allocator, &fixedBytes("092b06010401da470f01"));
            const pair = try edPair();
            var point: [33]u8 = undefined;
            point[0] = 0x40;
            point[1..].* = pair.public_key.toBytes();
            try mpi(&body, allocator, &point);
        } else {
            try mpi(&body, allocator, &self.rsa().modulus);
            try mpi(&body, allocator, &.{ 1, 0, 1 });
        }
        return body.toOwnedSlice(allocator);
    }
};

pub fn integer(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) !void {
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

fn length(out: *std.ArrayList(u8), allocator: std.mem.Allocator, size: usize) !void {
    if (size < 192) {
        try out.append(allocator, @intCast(size));
    } else if (size < 8384) {
        const adjusted = size - 192;
        try out.appendSlice(allocator, &.{ @intCast((adjusted >> 8) + 192), @intCast(adjusted & 255) });
    } else {
        try out.append(allocator, 255);
        try integer(out, allocator, u32, @intCast(size));
    }
}

pub fn packet(allocator: std.mem.Allocator, tag: u8, body: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(allocator, 0xc0 | tag);
    try length(&out, allocator, body.len);
    try out.appendSlice(allocator, body);
    return out.toOwnedSlice(allocator);
}

pub fn packetBody(encoded: []const u8) ![]const u8 {
    if (encoded.len < 2) return error.InvalidFixturePacket;
    const offset: usize = if (encoded[1] < 192) 2 else if (encoded[1] <= 223) 3 else if (encoded[1] == 255) 6 else return error.InvalidFixturePacket;
    if (encoded.len < offset) return error.InvalidFixturePacket;
    return encoded[offset..];
}

pub fn subpacket(allocator: std.mem.Allocator, tag: u8, body: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try length(&out, allocator, body.len + 1);
    try out.append(allocator, tag);
    try out.appendSlice(allocator, body);
    return out.toOwnedSlice(allocator);
}

pub fn keyPrefix(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(allocator, 0x99);
    try integer(&out, allocator, u16, @intCast(body.len));
    try out.appendSlice(allocator, body);
    return out.toOwnedSlice(allocator);
}

pub fn fingerprint(allocator: std.mem.Allocator, body: []const u8) ![20]u8 {
    var result: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(try keyPrefix(allocator, body), &result, .{});
    return result;
}

pub const SignatureOptions = struct {
    timestamp: u32 = created,
    hash: enum { sha256, sha512 } = .sha256,
    extra_hashed: []const u8 = "",
};

pub fn signature(allocator: std.mem.Allocator, key: Key, kind: u8, parts: []const []const u8, signer: [20]u8, options: SignatureOptions) ![]u8 {
    var time: [4]u8 = undefined;
    std.mem.writeInt(u32, &time, options.timestamp, .big);
    var issuer: [21]u8 = undefined;
    issuer[0] = 4;
    issuer[1..].* = signer;
    var hashed: std.ArrayList(u8) = .empty;
    try hashed.appendSlice(allocator, try subpacket(allocator, 2, &time));
    try hashed.appendSlice(allocator, try subpacket(allocator, 33, &issuer));
    try hashed.appendSlice(allocator, options.extra_hashed);
    var prefix: std.ArrayList(u8) = .empty;
    try prefix.appendSlice(allocator, &.{ 4, kind, if (key == .ed25519) 22 else 1, if (options.hash == .sha256) 8 else 10 });
    try integer(&prefix, allocator, u16, @intCast(hashed.items.len));
    try prefix.appendSlice(allocator, hashed.items);
    var trailer: [6]u8 = .{ 4, 0xff, 0, 0, 0, 0 };
    std.mem.writeInt(u32, trailer[2..6], @intCast(prefix.items.len), .big);
    var digest_buffer: [64]u8 = undefined;
    const digest: []const u8 = if (options.hash == .sha256) blk: {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        for (parts) |part| hash.update(part);
        hash.update(prefix.items);
        hash.update(&trailer);
        digest_buffer[0..32].* = hash.finalResult();
        break :blk digest_buffer[0..32];
    } else blk: {
        var hash = std.crypto.hash.sha2.Sha512.init(.{});
        for (parts) |part| hash.update(part);
        hash.update(prefix.items);
        hash.update(&trailer);
        digest_buffer = hash.finalResult();
        break :blk &digest_buffer;
    };
    var body: std.ArrayList(u8) = .empty;
    try body.appendSlice(allocator, prefix.items);
    const unhashed = try subpacket(allocator, 16, signer[12..20]);
    try integer(&body, allocator, u16, @intCast(unhashed.len));
    try body.appendSlice(allocator, unhashed);
    try body.appendSlice(allocator, digest[0..2]);
    if (key == .ed25519) {
        const pair = try Key.edPair();
        const raw = (try pair.sign(digest, null)).toBytes();
        try mpi(&body, allocator, raw[0..32]);
        try mpi(&body, allocator, raw[32..]);
    } else {
        const digest_info: []const u8 = if (options.hash == .sha256)
            &fixedBytes("3031300d060960864801650304020105000420")
        else
            &fixedBytes("3051300d060960864801650304020305000440");
        var encoded: [256]u8 = @splat(0xff);
        encoded[0] = 0;
        encoded[1] = 1;
        const separator = encoded.len - digest_info.len - digest.len - 1;
        encoded[separator] = 0;
        @memcpy(encoded[separator + 1 ..][0..digest_info.len], digest_info);
        @memcpy(encoded[encoded.len - digest.len ..], digest);
        const Modulus = std.crypto.ff.Modulus(2048);
        const rsa = key.rsa();
        const modulus = try Modulus.fromBytes(&rsa.modulus, .big);
        const message = try Modulus.Fe.fromBytes(modulus, &encoded, .big);
        const signed = try modulus.powWithEncodedExponent(message, &rsa.exponent, .big);
        var raw_signature: [256]u8 = undefined;
        try signed.toBytes(&raw_signature, .big);
        try mpi(&body, allocator, &raw_signature);
    }
    return packet(allocator, 2, body.items);
}

pub fn armorSignature(allocator: std.mem.Allocator, signed: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(signed.len));
    _ = encoder.encode(encoded, signed);
    var envelope: std.ArrayList(u8) = .empty;
    try envelope.appendSlice(allocator, "-----BEGIN PGP SIGNATURE-----\n\n");
    var offset: usize = 0;
    while (offset < encoded.len) : (offset += 64) {
        try envelope.appendSlice(allocator, encoded[offset..@min(offset + 64, encoded.len)]);
        try envelope.append(allocator, '\n');
    }
    try envelope.appendSlice(allocator, "-----END PGP SIGNATURE-----\n");
    return envelope.toOwnedSlice(allocator);
}

pub fn clearsign(allocator: std.mem.Allocator, key: Key, signer: [20]u8, release: []const u8, options: SignatureOptions) ![]u8 {
    if (release.len == 0 or release[release.len - 1] != '\n') return error.InvalidFixtureRelease;
    const lf = try std.mem.replaceOwned(u8, allocator, release, "\r\n", "\n");
    const canonical = try std.mem.replaceOwned(u8, allocator, lf[0 .. lf.len - 1], "\n", "\r\n");
    return std.mem.concat(allocator, u8, &.{
        if (options.hash == .sha256) "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" else "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n",
        release,
        try armorSignature(allocator, try signature(allocator, key, 0x01, &.{canonical}, signer, options)),
    });
}
