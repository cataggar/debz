//! Deterministic Ed25519 OpenPGP signer for hermetic tests only. It produces a
//! self-certified keyring, binary document signatures, and clearsigned
//! InRelease envelopes that the production verifier accepts.
const std = @import("std");

const Sha1 = std.crypto.hash.Sha1;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Ed25519 = std.crypto.sign.Ed25519;

pub const Options = struct {
    uid: []const u8,
    created: u32,
    seed: [Ed25519.KeyPair.seed_length]u8 = @splat(0x42),
};

pub const Signer = struct {
    key_pair: Ed25519.KeyPair,
    fingerprint: [20]u8,
    keyring: []u8,
    created: u32,

    pub fn init(allocator: std.mem.Allocator, options: Options) !Signer {
        const key_pair = try Ed25519.KeyPair.generateDeterministic(options.seed);
        const public_key = key_pair.public_key.toBytes();

        var key_body: std.ArrayList(u8) = .empty;
        defer key_body.deinit(allocator);
        try key_body.append(allocator, 4);
        try appendInt(&key_body, allocator, u32, options.created);
        try key_body.append(allocator, 22);
        const oid = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01 };
        try key_body.append(allocator, oid.len);
        try key_body.appendSlice(allocator, &oid);
        var point: [33]u8 = undefined;
        point[0] = 0x40;
        point[1..].* = public_key;
        try appendMpi(&key_body, allocator, &point);

        var fingerprint_input: std.ArrayList(u8) = .empty;
        defer fingerprint_input.deinit(allocator);
        try fingerprint_input.append(allocator, 0x99);
        try appendInt(&fingerprint_input, allocator, u16, @intCast(key_body.items.len));
        try fingerprint_input.appendSlice(allocator, key_body.items);
        var fingerprint: [20]u8 = undefined;
        Sha1.hash(fingerprint_input.items, &fingerprint, .{});

        var keyring: std.ArrayList(u8) = .empty;
        errdefer keyring.deinit(allocator);
        try appendPacket(&keyring, allocator, 6, key_body.items);
        try appendPacket(&keyring, allocator, 13, options.uid);

        var certification_input: std.ArrayList(u8) = .empty;
        defer certification_input.deinit(allocator);
        try certification_input.appendSlice(allocator, fingerprint_input.items);
        try certification_input.append(allocator, 0xb4);
        try appendInt(&certification_input, allocator, u32, @intCast(options.uid.len));
        try certification_input.appendSlice(allocator, options.uid);
        const certification = try signPacket(
            allocator,
            key_pair,
            fingerprint,
            options.created,
            0x13,
            certification_input.items,
            0x03,
        );
        defer allocator.free(certification);
        try keyring.appendSlice(allocator, certification);

        return .{
            .key_pair = key_pair,
            .fingerprint = fingerprint,
            .keyring = try keyring.toOwnedSlice(allocator),
            .created = options.created,
        };
    }

    pub fn deinit(self: *Signer, allocator: std.mem.Allocator) void {
        allocator.free(self.keyring);
        self.* = undefined;
    }

    /// Binary (type 0x00) detached signature packet over `bytes`.
    pub fn signDocument(self: Signer, allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
        return signPacket(allocator, self.key_pair, self.fingerprint, self.created, 0x00, bytes, null);
    }

    /// Clearsigned `Hash: SHA512` envelope with a canonical-text (type 0x01)
    /// signature. `text` must be LF-terminated lines without trailing
    /// whitespace; lines starting with '-' are dash-escaped.
    pub fn clearsign(self: Signer, allocator: std.mem.Allocator, text: []const u8) ![]u8 {
        if (text.len == 0 or text[text.len - 1] != '\n') return error.TestFixtureInvalid;
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);
        var canonical: std.ArrayList(u8) = .empty;
        defer canonical.deinit(allocator);
        try output.appendSlice(allocator, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n");
        var lines = std.mem.splitScalar(u8, text[0 .. text.len - 1], '\n');
        var first = true;
        while (lines.next()) |line| {
            if (std.mem.indexOfAny(u8, line, "\r") != null or
                std.mem.trimEnd(u8, line, " \t").len != line.len)
                return error.TestFixtureInvalid;
            if (line.len != 0 and line[0] == '-') try output.appendSlice(allocator, "- ");
            try output.appendSlice(allocator, line);
            try output.append(allocator, '\n');
            if (!first) try canonical.appendSlice(allocator, "\r\n");
            try canonical.appendSlice(allocator, line);
            first = false;
        }
        const packet = try signPacket(
            allocator,
            self.key_pair,
            self.fingerprint,
            self.created,
            0x01,
            canonical.items,
            null,
        );
        defer allocator.free(packet);
        try output.appendSlice(allocator, "-----BEGIN PGP SIGNATURE-----\n\n");
        const encoder = std.base64.standard.Encoder;
        const encoded = try allocator.alloc(u8, encoder.calcSize(packet.len));
        defer allocator.free(encoded);
        _ = encoder.encode(encoded, packet);
        var offset: usize = 0;
        while (offset < encoded.len) {
            const end = @min(offset + armor_line_bytes, encoded.len);
            try output.appendSlice(allocator, encoded[offset..end]);
            try output.append(allocator, '\n');
            offset = end;
        }
        const checksum = crc24(packet);
        var checksum_text: [4]u8 = undefined;
        _ = encoder.encode(&checksum_text, &checksum);
        try output.append(allocator, '=');
        try output.appendSlice(allocator, &checksum_text);
        try output.appendSlice(allocator, "\n-----END PGP SIGNATURE-----\n");
        return output.toOwnedSlice(allocator);
    }
};

const armor_line_bytes = 76;

fn signPacket(
    allocator: std.mem.Allocator,
    key_pair: Ed25519.KeyPair,
    fingerprint: [20]u8,
    created: u32,
    signature_type: u8,
    signed_bytes: []const u8,
    key_flags: ?u8,
) ![]u8 {
    var hashed: std.ArrayList(u8) = .empty;
    defer hashed.deinit(allocator);
    var created_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &created_bytes, created, .big);
    try appendSubpacket(&hashed, allocator, 2, &created_bytes);
    var issuer: [21]u8 = undefined;
    issuer[0] = 4;
    issuer[1..].* = fingerprint;
    try appendSubpacket(&hashed, allocator, 33, &issuer);
    if (key_flags) |flags| try appendSubpacket(&hashed, allocator, 27, &.{flags});

    var prefix: std.ArrayList(u8) = .empty;
    defer prefix.deinit(allocator);
    try prefix.appendSlice(allocator, &.{ 4, signature_type, 22, 10 });
    try appendInt(&prefix, allocator, u16, @intCast(hashed.items.len));
    try prefix.appendSlice(allocator, hashed.items);

    var hash = Sha512.init(.{});
    hash.update(signed_bytes);
    hash.update(prefix.items);
    var trailer: [6]u8 = .{ 4, 0xff, 0, 0, 0, 0 };
    std.mem.writeInt(u32, trailer[2..6], @intCast(prefix.items.len), .big);
    hash.update(&trailer);
    const digest = hash.finalResult();
    const signature = try key_pair.sign(&digest, null);
    const encoded = signature.toBytes();

    var unhashed: std.ArrayList(u8) = .empty;
    defer unhashed.deinit(allocator);
    try appendSubpacket(&unhashed, allocator, 16, fingerprint[12..20]);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, prefix.items);
    try appendInt(&body, allocator, u16, @intCast(unhashed.items.len));
    try body.appendSlice(allocator, unhashed.items);
    try body.appendSlice(allocator, digest[0..2]);
    try appendMpi(&body, allocator, encoded[0..32]);
    try appendMpi(&body, allocator, encoded[32..]);

    var packet: std.ArrayList(u8) = .empty;
    errdefer packet.deinit(allocator);
    try appendPacket(&packet, allocator, 2, body.items);
    return packet.toOwnedSlice(allocator);
}

fn appendPacket(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    tag: u8,
    body: []const u8,
) !void {
    try output.append(allocator, 0xc0 | tag);
    if (body.len < 192) {
        try output.append(allocator, @intCast(body.len));
    } else if (body.len < 8384) {
        const adjusted = body.len - 192;
        try output.append(allocator, @intCast((adjusted >> 8) + 192));
        try output.append(allocator, @intCast(adjusted & 0xff));
    } else {
        try output.append(allocator, 0xff);
        try appendInt(output, allocator, u32, @intCast(body.len));
    }
    try output.appendSlice(allocator, body);
}

fn appendSubpacket(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    kind: u8,
    body: []const u8,
) !void {
    const len = body.len + 1;
    if (len >= 192) return error.TestFixtureTooLarge;
    try output.append(allocator, @intCast(len));
    try output.append(allocator, kind);
    try output.appendSlice(allocator, body);
}

fn appendMpi(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    raw: []const u8,
) !void {
    var first: usize = 0;
    while (first < raw.len and raw[first] == 0) : (first += 1) {}
    if (first == raw.len) {
        try appendInt(output, allocator, u16, 0);
        return;
    }
    const significant = raw[first..];
    const leading_bits: u16 = @intCast(8 - @clz(significant[0]));
    const bit_len: u16 = @intCast((significant.len - 1) * 8 + leading_bits);
    try appendInt(output, allocator, u16, bit_len);
    try output.appendSlice(allocator, significant);
}

fn appendInt(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try output.appendSlice(allocator, &bytes);
}

fn crc24(bytes: []const u8) [3]u8 {
    var crc: u32 = 0xB704CE;
    for (bytes) |byte| {
        crc ^= @as(u32, byte) << 16;
        for (0..8) |_| {
            crc <<= 1;
            if (crc & 0x1000000 != 0) crc ^= 0x1864CFB;
        }
    }
    return .{
        @intCast((crc >> 16) & 0xff),
        @intCast((crc >> 8) & 0xff),
        @intCast(crc & 0xff),
    };
}
