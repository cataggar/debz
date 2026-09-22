const std = @import("std");

pub const Algorithm = enum(u8) {
    sha256 = 1,
    sha512 = 2,

    pub fn parse(value: []const u8) error{UnknownAlgorithm}!Algorithm {
        if (std.mem.eql(u8, value, "sha256")) return .sha256;
        if (std.mem.eql(u8, value, "sha512")) return .sha512;
        return error.UnknownAlgorithm;
    }

    pub fn name(self: Algorithm) []const u8 {
        return @tagName(self);
    }

    pub fn releaseName(self: Algorithm) []const u8 {
        return switch (self) {
            .sha256 => "SHA256",
            .sha512 => "SHA512",
        };
    }

    pub fn byteLength(self: Algorithm) usize {
        return switch (self) {
            .sha256 => 32,
            .sha512 => 64,
        };
    }

    pub fn hexLength(self: Algorithm) usize {
        return self.byteLength() * 2;
    }
};

pub const supported_algorithms = [_]Algorithm{ .sha256, .sha512 };

pub const Value = union(Algorithm) {
    sha256: [32]u8,
    sha512: [64]u8,

    pub fn algorithm(self: Value) Algorithm {
        return std.meta.activeTag(self);
    }

    pub fn of(algorithm_value: Algorithm, bytes: []const u8) Value {
        return switch (algorithm_value) {
            .sha256 => blk: {
                var value: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(bytes, &value, .{});
                break :blk .{ .sha256 = value };
            },
            .sha512 => blk: {
                var value: [64]u8 = undefined;
                std.crypto.hash.sha2.Sha512.hash(bytes, &value, .{});
                break :blk .{ .sha512 = value };
            },
        };
    }

    pub fn parse(
        algorithm_value: Algorithm,
        text: []const u8,
    ) error{InvalidDigest}!Value {
        if (text.len != algorithm_value.hexLength()) return error.InvalidDigest;
        for (text) |byte| {
            if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
                return error.InvalidDigest;
        }
        return switch (algorithm_value) {
            .sha256 => blk: {
                var bytes: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&bytes, text) catch
                    return error.InvalidDigest;
                break :blk .{ .sha256 = bytes };
            },
            .sha512 => blk: {
                var bytes: [64]u8 = undefined;
                _ = std.fmt.hexToBytes(&bytes, text) catch
                    return error.InvalidDigest;
                break :blk .{ .sha512 = bytes };
            },
        };
    }

    pub fn eql(left: Value, right: Value) bool {
        if (left.algorithm() != right.algorithm()) return false;
        return switch (left) {
            .sha256 => |value| std.crypto.timing_safe.eql(
                [32]u8,
                value,
                right.sha256,
            ),
            .sha512 => |value| std.crypto.timing_safe.eql(
                [64]u8,
                value,
                right.sha512,
            ),
        };
    }

    pub fn verify(self: Value, bytes: []const u8) bool {
        return self.eql(Value.of(self.algorithm(), bytes));
    }

    pub fn order(left: Value, right: Value) std.math.Order {
        const algorithm_order = std.math.order(
            @intFromEnum(left.algorithm()),
            @intFromEnum(right.algorithm()),
        );
        if (algorithm_order != .eq) return algorithm_order;
        return switch (left) {
            .sha256 => |value| std.mem.order(u8, &value, &right.sha256),
            .sha512 => |value| std.mem.order(u8, &value, &right.sha512),
        };
    }

    pub fn hex(self: Value, output: *[128]u8) []const u8 {
        return switch (self) {
            .sha256 => |value| blk: {
                const encoded = std.fmt.bytesToHex(value, .lower);
                @memcpy(output[0..encoded.len], &encoded);
                break :blk output[0..encoded.len];
            },
            .sha512 => |value| blk: {
                const encoded = std.fmt.bytesToHex(value, .lower);
                @memcpy(output[0..encoded.len], &encoded);
                break :blk output[0..encoded.len];
            },
        };
    }
};

/// The complete supported digest identity for one byte sequence. Fields are
/// fixed and iteration order is always SHA256 then SHA512.
pub const Set = struct {
    sha256: ?[32]u8 = null,
    sha512: ?[64]u8 = null,

    pub fn init(value: Value) Set {
        var result: Set = .{};
        result.put(value) catch unreachable;
        return result;
    }

    pub fn put(self: *Set, value: Value) error{ DuplicateDigest, ConflictingDigest }!void {
        switch (value) {
            .sha256 => |bytes| {
                if (self.sha256) |existing| {
                    if (std.crypto.timing_safe.eql([32]u8, existing, bytes))
                        return error.DuplicateDigest;
                    return error.ConflictingDigest;
                }
                self.sha256 = bytes;
            },
            .sha512 => |bytes| {
                if (self.sha512) |existing| {
                    if (std.crypto.timing_safe.eql([64]u8, existing, bytes))
                        return error.DuplicateDigest;
                    return error.ConflictingDigest;
                }
                self.sha512 = bytes;
            },
        }
    }

    pub fn count(self: Set) u8 {
        return @as(u8, @intFromBool(self.sha256 != null)) +
            @as(u8, @intFromBool(self.sha512 != null));
    }

    pub fn require(self: Set) error{MissingDigest}!void {
        if (self.count() == 0) return error.MissingDigest;
    }

    pub fn get(self: Set, algorithm_value: Algorithm) ?Value {
        return switch (algorithm_value) {
            .sha256 => if (self.sha256) |value| .{ .sha256 = value } else null,
            .sha512 => if (self.sha512) |value| .{ .sha512 = value } else null,
        };
    }

    pub fn strongest(self: Set) error{MissingDigest}!Algorithm {
        if (self.sha512 != null) return .sha512;
        if (self.sha256 != null) return .sha256;
        return error.MissingDigest;
    }

    pub fn verify(self: Set, bytes: []const u8) error{ MissingDigest, DigestMismatch }!void {
        try self.require();
        if (self.sha256) |expected| {
            var actual: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
            if (!std.crypto.timing_safe.eql([32]u8, expected, actual))
                return error.DigestMismatch;
        }
        if (self.sha512) |expected| {
            var actual: [64]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash(bytes, &actual, .{});
            if (!std.crypto.timing_safe.eql([64]u8, expected, actual))
                return error.DigestMismatch;
        }
    }

    pub fn eql(left: Set, right: Set) bool {
        if ((left.sha256 == null) != (right.sha256 == null) or
            (left.sha512 == null) != (right.sha512 == null))
            return false;
        var equal = true;
        if (left.sha256) |value|
            equal = std.crypto.timing_safe.eql([32]u8, value, right.sha256.?) and equal;
        if (left.sha512) |value|
            equal = std.crypto.timing_safe.eql([64]u8, value, right.sha512.?) and equal;
        return equal;
    }
};

pub const Identity = struct {
    digests: Set,
    primary: Algorithm,

    pub fn init(digests: Set, primary: Algorithm) error{
        MissingDigest,
        PrimaryDigestMissing,
    }!Identity {
        try digests.require();
        if (digests.get(primary) == null) return error.PrimaryDigestMissing;
        return .{ .digests = digests, .primary = primary };
    }

    pub fn strongest(digests: Set) error{MissingDigest}!Identity {
        return .{ .digests = digests, .primary = try digests.strongest() };
    }

    pub fn ofSha256(bytes: []const u8) Identity {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        return .{
            .digests = .{ .sha256 = digest },
            .primary = .sha256,
        };
    }

    /// Compatibility constructor for internal callers that historically used
    /// a SHA256-only CAS identity.
    pub fn of(bytes: []const u8) Identity {
        return ofSha256(bytes);
    }

    pub fn ofSupported(bytes: []const u8) Identity {
        return .{
            .digests = .{
                .sha256 = Value.of(.sha256, bytes).sha256,
                .sha512 = Value.of(.sha512, bytes).sha512,
            },
            .primary = .sha512,
        };
    }

    pub fn primaryValue(self: Identity) Value {
        return self.digests.get(self.primary) orelse unreachable;
    }

    pub fn verify(self: Identity, bytes: []const u8) error{
        MissingDigest,
        PrimaryDigestMissing,
        DigestMismatch,
    }!void {
        if (self.digests.get(self.primary) == null)
            return error.PrimaryDigestMissing;
        try self.digests.verify(bytes);
    }

    pub fn eql(left: Identity, right: Identity) bool {
        return left.primary == right.primary and left.digests.eql(right.digests);
    }

    pub fn cacheKey(self: Identity, output: *[135]u8) []const u8 {
        const name = self.primary.name();
        @memcpy(output[0..name.len], name);
        output[name.len] = '-';
        var hex_buffer: [128]u8 = undefined;
        const hex = self.primaryValue().hex(&hex_buffer);
        @memcpy(output[name.len + 1 .. name.len + 1 + hex.len], hex);
        return output[0 .. name.len + 1 + hex.len];
    }

    pub fn order(left: Identity, right: Identity) std.math.Order {
        const primary_order = std.math.order(
            @intFromEnum(left.primary),
            @intFromEnum(right.primary),
        );
        if (primary_order != .eq) return primary_order;
        inline for (supported_algorithms) |algorithm| {
            const left_value = left.digests.get(algorithm);
            const right_value = right.digests.get(algorithm);
            if (left_value == null and right_value != null) return .lt;
            if (left_value != null and right_value == null) return .gt;
            if (left_value) |value| {
                const digest_order = Value.order(value, right_value.?);
                if (digest_order != .eq) return digest_order;
            }
        }
        return .eq;
    }

    pub fn overlaps(left: Identity, right: Identity) bool {
        inline for (supported_algorithms) |algorithm| {
            if (left.digests.get(algorithm)) |left_value| {
                if (right.digests.get(algorithm)) |right_value| {
                    if (Value.eql(left_value, right_value)) return true;
                }
            }
        }
        return false;
    }
};

test "algorithm tagged digests are strict canonical and not confusable" {
    const sha256 = try Value.parse(
        .sha256,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    const sha512 = try Value.parse(
        .sha512,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ++
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    try std.testing.expect(!sha256.eql(sha512));
    try std.testing.expectError(error.InvalidDigest, Value.parse(
        .sha256,
        "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
    ));
    try std.testing.expectError(error.InvalidDigest, Value.parse(
        .sha512,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ));
    try std.testing.expectError(error.UnknownAlgorithm, Algorithm.parse("SHA256"));
    try std.testing.expectError(error.UnknownAlgorithm, Algorithm.parse("sha384"));
}

test "digest sets verify every published supported digest in canonical order" {
    const bytes = "authenticated archive";
    var set: Set = .{};
    try set.put(Value.of(.sha512, bytes));
    try set.put(Value.of(.sha256, bytes));
    const identity = try Identity.strongest(set);
    try std.testing.expectEqual(Algorithm.sha512, identity.primary);
    try identity.verify(bytes);

    var substituted = set;
    substituted.sha256.?[0] ^= 1;
    try std.testing.expectError(
        error.DigestMismatch,
        (try Identity.init(substituted, .sha512)).verify(bytes),
    );

    var key: [135]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, identity.cacheKey(&key), "sha512-"));
}

test "supported identities are canonical ordered and detect overlapping content keys" {
    const full = Identity.ofSupported("archive");
    const sha512_only = try Identity.init(
        .{ .sha512 = full.digests.sha512.? },
        .sha512,
    );
    try std.testing.expect(full.overlaps(sha512_only));
    try std.testing.expectEqual(std.math.Order.gt, Identity.order(full, sha512_only));
    try full.verify("archive");
}
