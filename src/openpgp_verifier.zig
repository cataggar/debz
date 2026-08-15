const std = @import("std");

pub const Limits = struct {
    max_signed_bytes: usize = 16 * 1024 * 1024,
    max_keyring_bytes: usize = 16 * 1024 * 1024,
    max_signature_bytes: usize = 1024 * 1024,
    max_packet_bytes: usize = 4 * 1024 * 1024,
    max_packets: usize = 4096,
    max_keys: usize = 256,
    max_signatures: usize = 32,
    max_subpackets: usize = 128,
    max_subpacket_bytes: usize = 64 * 1024,
};

pub const Keyring = union(enum) {
    bytes: []const u8,
    path: []const u8,
};

pub const Keyrings = union(enum) {
    one: Keyring,
    many: []const Keyring,
};

pub const Policy = struct {
    verification_time: i64,
    accepted_primary_fingerprints: []const [20]u8 = &.{},
};

pub const Request = struct {
    io: std.Io,
    signed_bytes: []const u8,
    signatures: []const []const u8,
    keyrings: Keyrings,
    policy: Policy,
    limits: Limits = .{},
};

pub const ResultStatus = enum {
    valid,
    bad_signature,
    no_matching_key,
    malformed,
    unknown_critical_subpacket,
    unsupported_signature_type,
    unsupported_public_key_algorithm,
    unsupported_hash_algorithm,
    unsupported_key_size,
    key_not_yet_valid,
    key_expired,
    key_revoked,
    key_not_signing,
    key_not_cross_certified,
    signature_expired,
    signature_not_yet_valid,
    signer_not_accepted,
};

pub const SignatureResult = struct {
    status: ResultStatus,
    primary_fingerprint: ?[20]u8 = null,
    signing_fingerprint: ?[20]u8 = null,
    signature_creation: ?i64 = null,
    signature_expiration: ?i64 = null,
    public_key_algorithm: u8 = 0,
    hash_algorithm: u8 = 0,
};

pub const Report = struct {
    signatures: []SignatureResult,
    accepted_signature_index: ?usize,

    pub fn deinit(self: *Report, allocator: std.mem.Allocator) void {
        allocator.free(self.signatures);
        self.* = undefined;
    }
};

pub const Outcome = union(enum) {
    accepted: Report,
    rejected: Report,

    pub fn report(self: *Outcome) *Report {
        return switch (self.*) {
            .accepted => |*value| value,
            .rejected => |*value| value,
        };
    }

    pub fn deinit(self: *Outcome, allocator: std.mem.Allocator) void {
        self.report().deinit(allocator);
        self.* = undefined;
    }
};

pub const VerifyError = error{
    NoKeyrings,
    NoSignatures,
    TooManySignatures,
    KeyringTooLarge,
    SignedDataTooLarge,
    SignatureTooLarge,
    PacketTooLarge,
    TooManyPackets,
    TooManyKeys,
    MalformedKeyring,
    UnsupportedKeyringArmor,
} || std.Io.Dir.ReadFileAllocError;

const Packet = struct {
    tag: u6,
    body: []const u8,
};

const Key = struct {
    fingerprint: [20]u8,
    primary_fingerprint: [20]u8,
    packet_body: []const u8,
    algorithm: u8,
    modulus: []const u8 = &.{},
    exponent: []const u8 = &.{},
    ed25519_public_key: ?[32]u8 = null,
    created: i64,
    expires: ?i64 = null,
    expiration_signature_created: i64 = std.math.minInt(i64),
    authorization_created: i64,
    authorization_expires: ?i64 = null,
    key_flags: ?u8 = null,
    revoked: bool = false,
    bound: bool,
    cross_certified: bool,
    is_primary: bool,
};

const ParsedSignature = struct {
    signature_type: u8,
    public_key_algorithm: u8,
    hash_algorithm: u8,
    hashed_prefix: []const u8,
    hashed_subpackets: []const u8,
    unhashed_subpackets: []const u8,
    hash_tag: [2]u8,
    signature_mpi: []const u8,
    signature_mpi2: ?[]const u8 = null,
    creation: ?i64 = null,
    expiration_seconds: ?u32 = null,
    key_expiration_seconds: ?u32 = null,
    key_flags: ?u8 = null,
    issuer_fingerprint: ?[20]u8 = null,
    issuer_key_id: ?[8]u8 = null,
    embedded_signature: ?[]const u8 = null,
};

const Parser = struct {
    bytes: []const u8,
    offset: usize = 0,
    count: usize = 0,
    limits: Limits,

    fn next(self: *Parser) !?Packet {
        if (self.offset == self.bytes.len) return null;
        if (self.count >= self.limits.max_packets) return error.TooManyPackets;
        self.count += 1;

        const first = self.bytes[self.offset];
        if (first & 0x80 == 0) return error.MalformedKeyring;
        self.offset += 1;

        var tag: u6 = undefined;
        var len: usize = undefined;
        if (first & 0x40 != 0) {
            tag = @intCast(first & 0x3f);
            len = try self.readNewLength();
        } else {
            tag = @intCast((first >> 2) & 0x0f);
            const length_type = first & 0x03;
            len = switch (length_type) {
                0 => try self.readInteger(u8),
                1 => try self.readInteger(u16),
                2 => try self.readInteger(u32),
                else => return error.MalformedKeyring,
            };
        }
        if (len > self.limits.max_packet_bytes) return error.PacketTooLarge;
        const end = std.math.add(usize, self.offset, len) catch return error.MalformedKeyring;
        if (end > self.bytes.len) return error.MalformedKeyring;
        const packet = Packet{ .tag = tag, .body = self.bytes[self.offset..end] };
        self.offset = end;
        return packet;
    }

    fn readNewLength(self: *Parser) !usize {
        const first = try self.readInteger(u8);
        if (first < 192) return first;
        if (first <= 223) {
            const second = try self.readInteger(u8);
            return (@as(usize, first) - 192) * 256 + second + 192;
        }
        if (first == 255) return try self.readInteger(u32);
        return error.MalformedKeyring; // Partial body lengths are deliberately rejected.
    }

    fn readInteger(self: *Parser, comptime T: type) !T {
        const size = @sizeOf(T);
        if (self.offset + size > self.bytes.len) return error.MalformedKeyring;
        const value = std.mem.readInt(T, self.bytes[self.offset..][0..size], .big);
        self.offset += size;
        return value;
    }
};

const KeyringState = struct {
    allocator: std.mem.Allocator,
    keys: std.ArrayList(Key) = .empty,
    owned_keyrings: std.ArrayList([]u8) = .empty,
    packet_count: usize = 0,

    fn deinit(self: *KeyringState) void {
        self.keys.deinit(self.allocator);
        for (self.owned_keyrings.items) |bytes| self.allocator.free(bytes);
        self.owned_keyrings.deinit(self.allocator);
    }
};

pub fn verify(allocator: std.mem.Allocator, request: Request) VerifyError!Outcome {
    if (request.keyrings == .many and request.keyrings.many.len == 0) return error.NoKeyrings;
    if (request.signatures.len == 0) return error.NoSignatures;
    if (request.signatures.len > request.limits.max_signatures) return error.TooManySignatures;
    if (request.signed_bytes.len > request.limits.max_signed_bytes) return error.SignedDataTooLarge;

    var state = KeyringState{ .allocator = allocator };
    defer state.deinit();

    var total_keyring_bytes: usize = 0;
    switch (request.keyrings) {
        .one => |source| try addKeyring(&state, source, request, &total_keyring_bytes),
        .many => |sources| for (sources) |source| {
            try addKeyring(&state, source, request, &total_keyring_bytes);
        },
    }

    const results = try allocator.alloc(SignatureResult, request.signatures.len);
    errdefer allocator.free(results);
    var accepted: ?usize = null;
    for (request.signatures, 0..) |signature_bytes, index| {
        results[index] = verifyOne(
            allocator,
            request.signed_bytes,
            signature_bytes,
            state.keys.items,
            request.policy,
            request.limits,
        );
        if (accepted == null and results[index].status == .valid) accepted = index;
    }

    const report = Report{ .signatures = results, .accepted_signature_index = accepted };
    return if (accepted != null) .{ .accepted = report } else .{ .rejected = report };
}

fn addKeyring(
    state: *KeyringState,
    source: Keyring,
    request: Request,
    total_keyring_bytes: *usize,
) VerifyError!void {
    const bytes = switch (source) {
        .bytes => |bytes| bytes,
        .path => |path| blk: {
            const bytes = std.Io.Dir.cwd().readFileAlloc(
                request.io,
                path,
                state.allocator,
                .limited(request.limits.max_keyring_bytes),
            ) catch |err| switch (err) {
                error.StreamTooLong => return error.KeyringTooLarge,
                else => return err,
            };
            try state.owned_keyrings.append(state.allocator, bytes);
            break :blk bytes;
        },
    };
    if (bytes.len > request.limits.max_keyring_bytes) return error.KeyringTooLarge;
    total_keyring_bytes.* = std.math.add(usize, total_keyring_bytes.*, bytes.len) catch
        return error.KeyringTooLarge;
    if (total_keyring_bytes.* > request.limits.max_keyring_bytes) return error.KeyringTooLarge;
    if (std.mem.startsWith(u8, bytes, "-----BEGIN PGP")) return error.UnsupportedKeyringArmor;
    try parseKeyring(state, bytes, request.limits);
}

fn parseKeyring(state: *KeyringState, bytes: []const u8, limits: Limits) !void {
    var parser = Parser{ .bytes = bytes, .count = state.packet_count, .limits = limits };
    defer state.packet_count = parser.count;
    var primary_index: ?usize = null;
    var subject_index: ?usize = null;
    var user_id: ?[]const u8 = null;

    while (try parser.next()) |packet| {
        switch (packet.tag) {
            6 => {
                if (state.keys.items.len >= limits.max_keys) return error.TooManyKeys;
                const key = parseKey(packet.body, null, true) catch |err| switch (err) {
                    error.UnsupportedAlgorithm => {
                        primary_index = null;
                        subject_index = null;
                        user_id = null;
                        continue;
                    },
                    else => return error.MalformedKeyring,
                };
                try state.keys.append(state.allocator, key);
                primary_index = state.keys.items.len - 1;
                subject_index = primary_index;
                user_id = null;
            },
            14 => {
                const pi = primary_index orelse {
                    subject_index = null;
                    user_id = null;
                    continue;
                };
                if (state.keys.items.len >= limits.max_keys) return error.TooManyKeys;
                const key = parseKey(packet.body, state.keys.items[pi].fingerprint, false) catch |err| switch (err) {
                    error.UnsupportedAlgorithm => {
                        subject_index = null;
                        user_id = null;
                        continue;
                    },
                    else => return error.MalformedKeyring,
                };
                try state.keys.append(state.allocator, key);
                subject_index = state.keys.items.len - 1;
                user_id = null;
            },
            13 => {
                if (primary_index == null) continue;
                if (packet.body.len == 0) return error.MalformedKeyring;
                subject_index = primary_index;
                user_id = packet.body;
            },
            2 => {
                const pi = primary_index orelse continue;
                const si = subject_index orelse continue;
                applyKeySignature(state.keys.items, pi, si, user_id, packet.body, limits) catch
                    return error.MalformedKeyring;
            },
            else => {},
        }
    }
}

fn parseKey(body: []const u8, primary: ?[20]u8, is_primary: bool) !Key {
    if (body.len < 8 or body.len > std.math.maxInt(u16) or body[0] != 4) return error.InvalidKey;
    const algorithm = body[5];
    var offset: usize = 6;
    var modulus: []const u8 = &.{};
    var exponent: []const u8 = &.{};
    var ed25519_public_key: ?[32]u8 = null;
    switch (algorithm) {
        1, 3 => {
            modulus = try readMpi(body, &offset);
            exponent = try readMpi(body, &offset);
            if (modulus.len == 0 or exponent.len == 0) return error.InvalidKey;
        },
        22 => {
            if (offset >= body.len) return error.InvalidKey;
            const oid_len = body[offset];
            offset += 1;
            const ed25519_oid = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01 };
            if (oid_len != ed25519_oid.len or offset + oid_len > body.len or
                !std.mem.eql(u8, body[offset .. offset + oid_len], &ed25519_oid))
                return error.InvalidKey;
            offset += oid_len;
            const point = try readMpi(body, &offset);
            if (point.len != 33 or point[0] != 0x40) return error.InvalidKey;
            ed25519_public_key = point[1..33].*;
        },
        else => return error.UnsupportedAlgorithm,
    }
    if (offset != body.len) return error.InvalidKey;
    const fingerprint = fingerprintV4(body);
    return .{
        .fingerprint = fingerprint,
        .primary_fingerprint = primary orelse fingerprint,
        .packet_body = body,
        .algorithm = algorithm,
        .modulus = modulus,
        .exponent = exponent,
        .ed25519_public_key = ed25519_public_key,
        .created = std.mem.readInt(u32, body[1..5], .big),
        .authorization_created = std.mem.readInt(u32, body[1..5], .big),
        .bound = is_primary,
        .cross_certified = is_primary,
        .is_primary = is_primary,
    };
}

fn fingerprintV4(body: []const u8) [20]u8 {
    var hash = std.crypto.hash.Sha1.init(.{});
    hash.update(&.{ 0x99, @intCast(body.len >> 8), @intCast(body.len & 0xff) });
    hash.update(body);
    var result: [20]u8 = undefined;
    hash.final(&result);
    return result;
}

fn applyKeySignature(
    keys: []Key,
    primary_index: usize,
    subject_index: usize,
    user_id: ?[]const u8,
    signature_body: []const u8,
    limits: Limits,
) !void {
    const sig = try parseSignatureBody(signature_body, limits);
    if (sig.public_key_algorithm != 1 and sig.public_key_algorithm != 3 and sig.public_key_algorithm != 22) return;
    const primary = &keys[primary_index];
    const subject = &keys[subject_index];
    if (sig.issuer_fingerprint) |issuer| {
        if (!std.mem.eql(u8, &issuer, &primary.fingerprint)) {
            if (sig.signature_type == 0x20 or sig.signature_type == 0x28) subject.revoked = true;
            return;
        }
    }
    if (sig.issuer_key_id) |issuer| {
        if (!std.mem.eql(u8, &issuer, primary.fingerprint[12..20])) {
            if (sig.signature_type == 0x20 or sig.signature_type == 0x28) subject.revoked = true;
            return;
        }
    }

    const valid = switch (sig.signature_type) {
        0x10...0x13 => if (subject_index == primary_index and user_id != null)
            verifyKeyCertification(primary.*, user_id.?, sig)
        else
            false,
        0x1f, 0x20 => if (subject_index == primary_index)
            verifyKeyOnly(primary.*, sig)
        else
            false,
        0x18, 0x28 => if (subject_index != primary_index)
            verifySubkeySignature(primary.*, subject.*, sig)
        else
            false,
        else => false,
    };
    if (!valid) {
        if (sig.signature_type == 0x20 or sig.signature_type == 0x28) subject.revoked = true;
        return;
    }
    if (sig.signature_type == 0x18 and sig.key_flags != null and sig.key_flags.? & 0x02 != 0) {
        const embedded_body = sig.embedded_signature orelse return;
        const embedded = parseSignatureBody(embedded_body, limits) catch return;
        if (embedded.signature_type != 0x19 or
            (embedded.issuer_fingerprint != null and
                !std.mem.eql(u8, &embedded.issuer_fingerprint.?, &subject.fingerprint)) or
            (embedded.issuer_key_id != null and
                !std.mem.eql(u8, &embedded.issuer_key_id.?, subject.fingerprint[12..20])) or
            !verifyPrimaryKeyBinding(primary.*, subject.*, embedded))
            return;
        subject.cross_certified = true;
    }

    switch (sig.signature_type) {
        0x18 => subject.bound = true,
        0x20 => primary.revoked = true,
        0x28 => subject.revoked = true,
        else => {},
    }
    if (sig.signature_type != 0x20 and sig.signature_type != 0x28) {
        const signature_created = sig.creation orelse 0;
        if (signature_created >= subject.expiration_signature_created) {
            subject.expiration_signature_created = signature_created;
            subject.authorization_created = @max(subject.created, signature_created);
            subject.expires = if (sig.key_expiration_seconds) |seconds|
                if (seconds == 0)
                    null
                else
                    std.math.add(i64, subject.created, seconds) catch std.math.maxInt(i64)
            else
                null;
            subject.authorization_expires = if (sig.expiration_seconds) |seconds|
                if (seconds == 0)
                    null
                else
                    std.math.add(i64, signature_created, seconds) catch std.math.maxInt(i64)
            else
                null;
            subject.key_flags = sig.key_flags;
        }
    }
}

fn verifyKeyOnly(primary: Key, sig: ParsedSignature) bool {
    var prefix: [3]u8 = .{ 0x99, @intCast(primary.packet_body.len >> 8), @intCast(primary.packet_body.len & 0xff) };
    return verifyParts(primary, &.{ &prefix, primary.packet_body }, sig);
}

fn verifyKeyCertification(primary: Key, user_id: []const u8, sig: ParsedSignature) bool {
    var key_prefix: [3]u8 = .{ 0x99, @intCast(primary.packet_body.len >> 8), @intCast(primary.packet_body.len & 0xff) };
    var uid_prefix: [5]u8 = .{ 0xb4, 0, 0, 0, 0 };
    std.mem.writeInt(u32, uid_prefix[1..5], @intCast(user_id.len), .big);
    return verifyParts(primary, &.{ &key_prefix, primary.packet_body, &uid_prefix, user_id }, sig);
}

fn verifySubkeySignature(primary: Key, subkey: Key, sig: ParsedSignature) bool {
    var primary_prefix: [3]u8 = .{ 0x99, @intCast(primary.packet_body.len >> 8), @intCast(primary.packet_body.len & 0xff) };
    var subkey_prefix: [3]u8 = .{ 0x99, @intCast(subkey.packet_body.len >> 8), @intCast(subkey.packet_body.len & 0xff) };
    return verifyParts(primary, &.{
        &primary_prefix,
        primary.packet_body,
        &subkey_prefix,
        subkey.packet_body,
    }, sig);
}

fn verifyPrimaryKeyBinding(primary: Key, subkey: Key, sig: ParsedSignature) bool {
    var primary_prefix: [3]u8 = .{ 0x99, @intCast(primary.packet_body.len >> 8), @intCast(primary.packet_body.len & 0xff) };
    var subkey_prefix: [3]u8 = .{ 0x99, @intCast(subkey.packet_body.len >> 8), @intCast(subkey.packet_body.len & 0xff) };
    return verifyParts(subkey, &.{
        &primary_prefix,
        primary.packet_body,
        &subkey_prefix,
        subkey.packet_body,
    }, sig);
}

fn verifyOne(
    allocator: std.mem.Allocator,
    signed_bytes: []const u8,
    signature_packet_bytes: []const u8,
    keys: []const Key,
    policy: Policy,
    limits: Limits,
) SignatureResult {
    var result = SignatureResult{ .status = .malformed };
    if (signature_packet_bytes.len > limits.max_signature_bytes) return result;

    var packet_parser = Parser{ .bytes = signature_packet_bytes, .limits = limits };
    const packet = packet_parser.next() catch return result;
    const signature_packet = packet orelse return result;
    if (signature_packet.tag != 2) return result;
    if ((packet_parser.next() catch return result) != null) return result;
    const sig = parseSignatureBody(signature_packet.body, limits) catch |err| {
        result.status = if (err == error.UnknownCriticalSubpacket)
            .unknown_critical_subpacket
        else
            .malformed;
        return result;
    };

    result.public_key_algorithm = sig.public_key_algorithm;
    result.hash_algorithm = sig.hash_algorithm;
    result.signature_creation = sig.creation;
    if (sig.creation) |created| {
        if (sig.expiration_seconds) |seconds| {
            if (seconds != 0)
                result.signature_expiration = std.math.add(i64, created, seconds) catch std.math.maxInt(i64);
        }
    }
    if (sig.signature_type != 0x00 and sig.signature_type != 0x01) {
        result.status = .unsupported_signature_type;
        return result;
    }
    if (sig.public_key_algorithm != 1 and sig.public_key_algorithm != 3 and sig.public_key_algorithm != 22) {
        result.status = .unsupported_public_key_algorithm;
        return result;
    }
    if (sig.hash_algorithm != 8 and sig.hash_algorithm != 10) {
        result.status = .unsupported_hash_algorithm;
        return result;
    }

    var had_candidate = false;
    var had_bad_signature = false;
    var had_unsupported_size = false;
    for (keys) |key| {
        if (!key.bound) continue;
        if (sig.issuer_fingerprint) |issuer| {
            if (!std.mem.eql(u8, &issuer, &key.fingerprint)) continue;
        }
        if (sig.issuer_key_id) |issuer| {
            if (!std.mem.eql(u8, &issuer, key.fingerprint[12..20])) continue;
        }
        had_candidate = true;
        const verified = if (sig.signature_type == 0x01)
            verifyCanonicalText(allocator, key, signed_bytes, sig)
        else
            verifyParts(key, &.{signed_bytes}, sig);
        if (!verified) {
            if ((key.algorithm == 1 or key.algorithm == 3) and !supportedModulusLength(key.modulus.len))
                had_unsupported_size = true
            else
                had_bad_signature = true;
            continue;
        }

        result.primary_fingerprint = key.primary_fingerprint;
        result.signing_fingerprint = key.fingerprint;
        if (sig.creation != null and sig.creation.? > policy.verification_time) {
            result.status = .signature_not_yet_valid;
        } else if (sig.creation != null and
            (sig.creation.? < key.created or sig.creation.? < key.authorization_created))
        {
            result.status = .key_not_yet_valid;
        } else if (policy.verification_time < key.created or policy.verification_time < key.authorization_created) {
            result.status = .key_not_yet_valid;
        } else if (key.revoked or primaryRevoked(keys, key.primary_fingerprint)) {
            result.status = .key_revoked;
        } else if ((key.expires != null and policy.verification_time >= key.expires.?) or
            (key.authorization_expires != null and policy.verification_time >= key.authorization_expires.?))
        {
            result.status = .key_expired;
        } else if (key.key_flags != null and key.key_flags.? & 0x02 == 0) {
            result.status = .key_not_signing;
        } else if (!key.cross_certified) {
            result.status = .key_not_cross_certified;
        } else if (result.signature_expiration != null and policy.verification_time >= result.signature_expiration.?) {
            result.status = .signature_expired;
        } else if (!fingerprintAccepted(policy, key.primary_fingerprint)) {
            result.status = .signer_not_accepted;
        } else {
            result.status = .valid;
        }
        return result;
    }
    result.status = if (had_unsupported_size)
        .unsupported_key_size
    else if (had_bad_signature)
        .bad_signature
    else if (had_candidate)
        .bad_signature
    else
        .no_matching_key;
    return result;
}

fn primaryRevoked(keys: []const Key, fingerprint: [20]u8) bool {
    for (keys) |key| {
        if (key.is_primary and std.mem.eql(u8, &key.fingerprint, &fingerprint)) return key.revoked;
    }
    return false;
}

fn fingerprintAccepted(policy: Policy, fingerprint: [20]u8) bool {
    if (policy.accepted_primary_fingerprints.len == 0) return true;
    for (policy.accepted_primary_fingerprints) |accepted| {
        if (std.mem.eql(u8, &accepted, &fingerprint)) return true;
    }
    return false;
}

fn parseSignatureBody(body: []const u8, limits: Limits) !ParsedSignature {
    if (body.len < 10 or body[0] != 4) return error.MalformedSignature;
    const hashed_len = std.mem.readInt(u16, body[4..6], .big);
    const hashed_end = 6 + @as(usize, hashed_len);
    if (hashed_end + 2 > body.len) return error.MalformedSignature;
    const unhashed_len = std.mem.readInt(u16, body[hashed_end..][0..2], .big);
    const unhashed_start = hashed_end + 2;
    const unhashed_end = unhashed_start + @as(usize, unhashed_len);
    if (unhashed_end + 4 > body.len) return error.MalformedSignature;
    if (hashed_len > limits.max_subpacket_bytes or unhashed_len > limits.max_subpacket_bytes)
        return error.MalformedSignature;

    var sig = ParsedSignature{
        .signature_type = body[1],
        .public_key_algorithm = body[2],
        .hash_algorithm = body[3],
        .hashed_prefix = body[0..hashed_end],
        .hashed_subpackets = body[6..hashed_end],
        .unhashed_subpackets = body[unhashed_start..unhashed_end],
        .hash_tag = body[unhashed_end..][0..2].*,
        .signature_mpi = undefined,
    };
    try parseSubpackets(&sig, sig.hashed_subpackets, true, limits);
    try parseSubpackets(&sig, sig.unhashed_subpackets, false, limits);
    if (sig.creation == null) return error.MalformedSignature;
    var mpi_offset = unhashed_end + 2;
    if (sig.public_key_algorithm == 1 or sig.public_key_algorithm == 3 or sig.public_key_algorithm == 22) {
        sig.signature_mpi = try readMpi(body, &mpi_offset);
        if (sig.public_key_algorithm == 22) sig.signature_mpi2 = try readMpi(body, &mpi_offset);
    } else {
        if (mpi_offset == body.len) return error.MalformedSignature;
        sig.signature_mpi = body[mpi_offset..];
        mpi_offset = body.len;
    }
    if (mpi_offset != body.len or sig.signature_mpi.len == 0) return error.MalformedSignature;
    return sig;
}

fn parseSubpackets(sig: *ParsedSignature, bytes: []const u8, hashed: bool, limits: Limits) !void {
    var offset: usize = 0;
    var count: usize = 0;
    while (offset < bytes.len) {
        if (count >= limits.max_subpackets) return error.MalformedSignature;
        count += 1;
        const len = try readSubpacketLength(bytes, &offset);
        if (len == 0 or len > limits.max_subpacket_bytes or offset + len > bytes.len)
            return error.MalformedSignature;
        const raw_type = bytes[offset];
        const critical = raw_type & 0x80 != 0;
        const sub_type = raw_type & 0x7f;
        const data = bytes[offset + 1 .. offset + len];
        offset += len;
        switch (sub_type) {
            2 => {
                if (data.len != 4) return error.MalformedSignature;
                if (hashed) {
                    if (sig.creation != null) return error.MalformedSignature;
                    sig.creation = std.mem.readInt(u32, data[0..4], .big);
                }
            },
            3 => {
                if (data.len != 4) return error.MalformedSignature;
                if (hashed) sig.expiration_seconds = std.mem.readInt(u32, data[0..4], .big);
            },
            9 => {
                if (data.len != 4) return error.MalformedSignature;
                if (hashed) sig.key_expiration_seconds = std.mem.readInt(u32, data[0..4], .big);
            },
            16 => {
                if (data.len != 8) return error.MalformedSignature;
                var value: [8]u8 = undefined;
                @memcpy(&value, data);
                if (sig.issuer_key_id) |existing| {
                    if (!std.mem.eql(u8, &existing, &value)) return error.MalformedSignature;
                }
                sig.issuer_key_id = value;
            },
            33 => {
                if (data.len != 21 or data[0] != 4) return error.MalformedSignature;
                var value: [20]u8 = undefined;
                @memcpy(&value, data[1..21]);
                if (sig.issuer_fingerprint) |existing| {
                    if (!std.mem.eql(u8, &existing, &value)) return error.MalformedSignature;
                }
                sig.issuer_fingerprint = value;
            },
            27 => {
                if (data.len == 0) return error.MalformedSignature;
                if (hashed) {
                    var flags: u8 = 0;
                    for (data) |byte| flags |= byte;
                    sig.key_flags = flags;
                }
            },
            32 => {
                if (!hashed or data.len == 0 or sig.embedded_signature != null)
                    return error.MalformedSignature;
                sig.embedded_signature = data;
            },
            // Semantics not needed by this verification boundary, but structurally understood.
            4, 5, 6, 7, 11, 12, 20, 21, 22, 23, 24, 25, 26, 28, 29, 30, 31, 34, 35, 37, 38, 39 => {},
            else => if (critical) return error.UnknownCriticalSubpacket,
        }
    }
}

fn readSubpacketLength(bytes: []const u8, offset: *usize) !usize {
    if (offset.* >= bytes.len) return error.MalformedSignature;
    const first = bytes[offset.*];
    offset.* += 1;
    if (first < 192) return first;
    if (first <= 223) {
        if (offset.* >= bytes.len) return error.MalformedSignature;
        const second = bytes[offset.*];
        offset.* += 1;
        return (@as(usize, first) - 192) * 256 + second + 192;
    }
    if (first == 255) {
        if (offset.* + 4 > bytes.len) return error.MalformedSignature;
        const len = std.mem.readInt(u32, bytes[offset.*..][0..4], .big);
        offset.* += 4;
        return len;
    }
    return error.MalformedSignature;
}

fn readMpi(bytes: []const u8, offset: *usize) ![]const u8 {
    if (offset.* + 2 > bytes.len) return error.MalformedMpi;
    const bits = std.mem.readInt(u16, bytes[offset.*..][0..2], .big);
    offset.* += 2;
    const len = (@as(usize, bits) + 7) / 8;
    if (len == 0 or offset.* + len > bytes.len) return error.MalformedMpi;
    const mpi = bytes[offset.* .. offset.* + len];
    offset.* += len;
    if (mpi[0] == 0 or @clz(mpi[0]) != (8 - (bits % 8)) % 8) return error.MalformedMpi;
    return mpi;
}

fn verifyCanonicalText(allocator: std.mem.Allocator, key: Key, bytes: []const u8, sig: ParsedSignature) bool {
    var canonical: std.ArrayList(u8) = .empty;
    defer canonical.deinit(allocator);
    var previous_cr = false;
    for (bytes) |byte| {
        if (byte == '\n' and !previous_cr) canonical.append(allocator, '\r') catch return false;
        canonical.append(allocator, byte) catch return false;
        previous_cr = byte == '\r';
    }
    return verifyParts(key, &.{canonical.items}, sig);
}

fn verifyParts(key: Key, message_parts: []const []const u8, sig: ParsedSignature) bool {
    if (sig.public_key_algorithm != key.algorithm) return false;
    var trailer: [6]u8 = .{ 4, 0xff, 0, 0, 0, 0 };
    std.mem.writeInt(u32, trailer[2..6], @intCast(sig.hashed_prefix.len), .big);

    var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
    var sha512 = std.crypto.hash.sha2.Sha512.init(.{});
    for (message_parts) |part| {
        if (sig.hash_algorithm == 8) sha256.update(part) else if (sig.hash_algorithm == 10) sha512.update(part) else return false;
    }
    if (sig.hash_algorithm == 8) {
        sha256.update(sig.hashed_prefix);
        sha256.update(&trailer);
        var digest: [32]u8 = undefined;
        sha256.final(&digest);
        if (!std.mem.eql(u8, sig.hash_tag[0..], digest[0..2])) return false;
        return verifyDigest(key, sig, message_parts, &trailer, &digest, std.crypto.hash.sha2.Sha256);
    }
    sha512.update(sig.hashed_prefix);
    sha512.update(&trailer);
    var digest: [64]u8 = undefined;
    sha512.final(&digest);
    if (!std.mem.eql(u8, sig.hash_tag[0..], digest[0..2])) return false;
    return verifyDigest(key, sig, message_parts, &trailer, &digest, std.crypto.hash.sha2.Sha512);
}

fn verifyDigest(
    key: Key,
    sig: ParsedSignature,
    message_parts: []const []const u8,
    trailer: []const u8,
    digest: []const u8,
    comptime Hash: type,
) bool {
    if (key.algorithm == 22) return verifyEd25519(key, sig, digest);
    const public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(key.exponent, key.modulus) catch return false;
    return verifyPkcs1(
        key.modulus.len,
        sig.signature_mpi,
        message_parts,
        sig.hashed_prefix,
        trailer,
        public_key,
        Hash,
    );
}

fn verifyEd25519(key: Key, sig: ParsedSignature, digest: []const u8) bool {
    const second = sig.signature_mpi2 orelse return false;
    if (sig.signature_mpi.len > 32 or second.len > 32) return false;
    var encoded_signature: [64]u8 = @splat(0);
    @memcpy(encoded_signature[32 - sig.signature_mpi.len .. 32], sig.signature_mpi);
    @memcpy(encoded_signature[64 - second.len .. 64], second);
    const public_bytes = key.ed25519_public_key orelse return false;
    const public_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_bytes) catch return false;
    const signature = std.crypto.sign.Ed25519.Signature.fromBytes(encoded_signature);
    signature.verifyStrict(digest, public_key) catch return false;
    return true;
}

fn supportedModulusLength(len: usize) bool {
    return len == 256 or len == 384 or len == 512;
}

fn verifyPkcs1(
    modulus_len: usize,
    signature: []const u8,
    message_parts: []const []const u8,
    hashed_prefix: []const u8,
    trailer: []const u8,
    public_key: std.crypto.Certificate.rsa.PublicKey,
    comptime Hash: type,
) bool {
    return switch (modulus_len) {
        inline 256, 384, 512 => |len| blk: {
            if (signature.len > len) break :blk false;
            var padded: [len]u8 = @splat(0);
            @memcpy(padded[len - signature.len ..], signature);
            var parts: [8][]const u8 = undefined;
            if (message_parts.len + 2 > parts.len) break :blk false;
            @memcpy(parts[0..message_parts.len], message_parts);
            parts[message_parts.len] = hashed_prefix;
            parts[message_parts.len + 1] = trailer;
            std.crypto.Certificate.rsa.PKCS1v1_5Signature.concatVerify(
                len,
                padded,
                parts[0 .. message_parts.len + 2],
                public_key,
                Hash,
            ) catch break :blk false;
            break :blk true;
        },
        else => false,
    };
}

test "bounded packet parser rejects partial lengths" {
    var parser = Parser{ .bytes = &.{ 0xc2, 224 }, .limits = .{} };
    try std.testing.expectError(error.MalformedKeyring, parser.next());
}

test "MPI parser rejects non-canonical leading zero" {
    var offset: usize = 0;
    try std.testing.expectError(error.MalformedMpi, readMpi(&.{ 0, 8, 0 }, &offset));
}

const fixture = @import("fixtures/openpgp.zig");

fn fixtureRequest(keyring: []const u8, signatures: []const []const u8, time: i64) Request {
    return .{
        .io = std.testing.io,
        .signed_bytes = &fixture.message,
        .signatures = signatures,
        .keyrings = .{ .one = .{ .bytes = keyring } },
        .policy = .{ .verification_time = time },
    };
}

test "verifies hermetic RSA SHA-256 signing subkey fixture" {
    var outcome = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.keyring, &.{&fixture.signature}, fixture.created + 30),
    );
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(outcome == .accepted);
    const report = outcome.report();
    try std.testing.expectEqual(@as(?usize, 0), report.accepted_signature_index);
    try std.testing.expectEqual(ResultStatus.valid, report.signatures[0].status);
    try std.testing.expectEqualSlices(u8, &fixture.primary_fingerprint, &report.signatures[0].primary_fingerprint.?);
    try std.testing.expectEqualSlices(u8, &fixture.subkey_fingerprint, &report.signatures[0].signing_fingerprint.?);
    try std.testing.expectEqual(@as(u8, 1), report.signatures[0].public_key_algorithm);
    try std.testing.expectEqual(@as(u8, 8), report.signatures[0].hash_algorithm);
    try std.testing.expectEqual(@as(?i64, fixture.created), report.signatures[0].signature_creation);
}

test "supports RSA SHA-512 and deterministic multiple signature ordering" {
    var outcome = try verify(
        std.testing.allocator,
        fixtureRequest(
            &fixture.keyring,
            &.{ &fixture.sha512_signature, &fixture.signature },
            fixture.created + 30,
        ),
    );
    defer outcome.deinit(std.testing.allocator);
    const report = outcome.report();
    try std.testing.expectEqual(@as(?usize, 0), report.accepted_signature_index);
    try std.testing.expectEqual(@as(u8, 10), report.signatures[0].hash_algorithm);
    try std.testing.expectEqual(ResultStatus.valid, report.signatures[0].status);
    try std.testing.expectEqual(ResultStatus.valid, report.signatures[1].status);
}

test "verifies legacy OpenPGP Ed25519 algorithm 22" {
    var outcome = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.ed25519_keyring, &.{&fixture.ed25519_signature}, fixture.created + 30),
    );
    defer outcome.deinit(std.testing.allocator);
    const result = outcome.report().signatures[0];
    try std.testing.expectEqual(ResultStatus.valid, result.status);
    try std.testing.expectEqual(@as(u8, 22), result.public_key_algorithm);
    try std.testing.expectEqualSlices(u8, &fixture.ed25519_fingerprint, &result.primary_fingerprint.?);
    try std.testing.expectEqualSlices(u8, &fixture.ed25519_fingerprint, &result.signing_fingerprint.?);
}

test "unsupported keys in a declared keyring do not hide supported keys" {
    var unsupported_key = fixture.ed25519_keyring;
    var packet_parser = Parser{ .bytes = &unsupported_key, .limits = .{} };
    const packet = (try packet_parser.next()).?;
    const body_offset = @intFromPtr(packet.body.ptr) - @intFromPtr(unsupported_key[0..].ptr);
    unsupported_key[body_offset + 5] = 19;
    const combined = try std.mem.concat(
        std.testing.allocator,
        u8,
        &.{ &unsupported_key, &fixture.keyring },
    );
    defer std.testing.allocator.free(combined);
    var outcome = try verify(
        std.testing.allocator,
        fixtureRequest(combined, &.{&fixture.signature}, fixture.created + 30),
    );
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultStatus.valid, outcome.report().signatures[0].status);
}

test "canonical text signatures normalize LF to CRLF" {
    var outcome = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.keyring, &.{&fixture.text_signature}, fixture.created + 30),
    );
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultStatus.valid, outcome.report().signatures[0].status);

    var request = fixtureRequest(&fixture.keyring, &.{&fixture.text_signature}, fixture.created + 30);
    request.signed_bytes = "Origin: debz fixture\r\nSuite: stable\r\n";
    var crlf = try verify(std.testing.allocator, request);
    defer crlf.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultStatus.valid, crlf.report().signatures[0].status);
}

test "rejects wrong data and tampered signature" {
    var wrong_data_request = fixtureRequest(&fixture.keyring, &.{&fixture.signature}, fixture.created + 30);
    wrong_data_request.signed_bytes = "wrong";
    var wrong_data = try verify(std.testing.allocator, wrong_data_request);
    defer wrong_data.deinit(std.testing.allocator);
    try std.testing.expect(wrong_data == .rejected);
    try std.testing.expectEqual(ResultStatus.bad_signature, wrong_data.report().signatures[0].status);

    var tampered = fixture.signature;
    tampered[tampered.len - 1] ^= 1;
    var bad_signature = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.keyring, &.{&tampered}, fixture.created + 30),
    );
    defer bad_signature.deinit(std.testing.allocator);
    try std.testing.expect(bad_signature == .rejected);
    try std.testing.expectEqual(ResultStatus.bad_signature, bad_signature.report().signatures[0].status);
}

test "rejects expired and revoked signing keys" {
    var expired = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.expired_keyring, &.{&fixture.signature}, fixture.created + 61),
    );
    defer expired.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultStatus.key_expired, expired.report().signatures[0].status);

    var revoked = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.revoked_keyring, &.{&fixture.signature}, fixture.created + 30),
    );
    defer revoked.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultStatus.key_revoked, revoked.report().signatures[0].status);

    var authorization_expired = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.authorization_expired_keyring, &.{&fixture.signature}, fixture.created + 61),
    );
    defer authorization_expired.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultStatus.key_expired, authorization_expired.report().signatures[0].status);

    var non_signing = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.non_signing_keyring, &.{&fixture.signature}, fixture.created + 30),
    );
    defer non_signing.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultStatus.key_not_signing, non_signing.report().signatures[0].status);

    var uncertified = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.uncertified_keyring, &.{&fixture.signature}, fixture.created + 30),
    );
    defer uncertified.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        ResultStatus.key_not_cross_certified,
        uncertified.report().signatures[0].status,
    );

    var predates_binding = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.late_binding_keyring, &.{&fixture.signature}, fixture.created + 30),
    );
    defer predates_binding.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultStatus.key_not_yet_valid, predates_binding.report().signatures[0].status);
}

test "rejects expired signatures and unaccepted primary fingerprints" {
    var expired = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.keyring, &.{&fixture.expired_signature}, fixture.created + 61),
    );
    defer expired.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultStatus.signature_expired, expired.report().signatures[0].status);

    const rejected_fp: [20]u8 = @splat(0xaa);
    var request = fixtureRequest(&fixture.keyring, &.{&fixture.signature}, fixture.created + 30);
    request.policy.accepted_primary_fingerprints = &.{rejected_fp};
    var rejected = try verify(std.testing.allocator, request);
    defer rejected.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultStatus.signer_not_accepted, rejected.report().signatures[0].status);
}

test "fails explicitly for unsupported algorithms and unknown critical subpackets" {
    var unsupported_public_key = fixture.signature;
    var parser = Parser{ .bytes = &unsupported_public_key, .limits = .{} };
    const packet = (try parser.next()).?;
    const body_offset = @intFromPtr(packet.body.ptr) - @intFromPtr(unsupported_public_key[0..].ptr);
    unsupported_public_key[body_offset + 2] = 19;
    var unsupported_pk = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.keyring, &.{&unsupported_public_key}, fixture.created + 30),
    );
    defer unsupported_pk.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        ResultStatus.unsupported_public_key_algorithm,
        unsupported_pk.report().signatures[0].status,
    );

    var unsupported_hash = fixture.signature;
    unsupported_hash[body_offset + 3] = 2;
    var unsupported_digest = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.keyring, &.{&unsupported_hash}, fixture.created + 30),
    );
    defer unsupported_digest.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        ResultStatus.unsupported_hash_algorithm,
        unsupported_digest.report().signatures[0].status,
    );

    var critical = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.keyring, &.{&fixture.unknown_critical_signature}, fixture.created + 30),
    );
    defer critical.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        ResultStatus.unknown_critical_subpacket,
        critical.report().signatures[0].status,
    );

    var missing_creation = fixture.signature;
    missing_creation[body_offset + 7] = 4;
    var malformed = try verify(
        std.testing.allocator,
        fixtureRequest(&fixture.keyring, &.{&missing_creation}, fixture.created + 30),
    );
    defer malformed.deinit(std.testing.allocator);
    try std.testing.expectEqual(ResultStatus.malformed, malformed.report().signatures[0].status);
}

test "strict keyring and count bounds reject before verification" {
    var request = fixtureRequest(&fixture.keyring, &.{&fixture.signature}, fixture.created + 30);
    request.limits.max_keyring_bytes = fixture.keyring.len - 1;
    try std.testing.expectError(error.KeyringTooLarge, verify(std.testing.allocator, request));

    request = fixtureRequest(&fixture.keyring, &.{&fixture.signature}, fixture.created + 30);
    request.limits.max_packets = 1;
    try std.testing.expectError(error.TooManyPackets, verify(std.testing.allocator, request));

    request = fixtureRequest(&fixture.keyring, &.{&fixture.signature}, fixture.created + 30);
    request.limits.max_signed_bytes = fixture.message.len - 1;
    try std.testing.expectError(error.SignedDataTooLarge, verify(std.testing.allocator, request));
}
