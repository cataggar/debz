//! Byte-exact regeneration of the original, non-secret verification fixtures.
const std = @import("std");
const fs = @import("debz").root_fs;
const pgp = @import("fixture-openpgp.zig");
const options = @import("openpgp_fixture_options");
const maximum_source_bytes = 256 * 1024;
const message = "Origin: debz fixture\nSuite: stable\n";
const packages =
    "Package: hello\nVersion: 1.0-1\nArchitecture: amd64\n" ++
    "Maintainer: Test <test@example.invalid>\nDescription: hello\n" ++
    "Filename: pool/main/h/hello/hello_1.0-1_amd64.deb\nSize: 4\n" ++
    "SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
const noble_packages =
    "Package: symcrypt-fixture\nVersion: 1.0-1\nArchitecture: all\n" ++
    "Maintainer: Test <test@example.invalid>\nDescription: Microsoft-shaped moving feed fixture\n" ++
    "Filename: pool/main/s/symcrypt-fixture/symcrypt-fixture_1.0-1_all.deb\nSize: 4\n" ++
    "SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
const frozen_origin = "Origin: debz fixture\nLabel: debz fixture\n";

const Values = struct {
    message: []const u8,
    keyring: []const u8,
    expired_keyring: []const u8,
    authorization_expired_keyring: []const u8,
    non_signing_keyring: []const u8,
    uncertified_keyring: []const u8,
    late_binding_keyring: []const u8,
    revoked_keyring: []const u8,
    signature: []const u8,
    text_signature: []const u8,
    sha512_signature: []const u8,
    expired_signature: []const u8,
    unknown_critical_signature: []const u8,
    ed25519_keyring: []const u8,
    ed25519_signature: []const u8,
    repository_packages: []const u8,
    repository_release: []const u8,
    repository_release_signature: []const u8,
    repository_release_sha512_signature: []const u8,
    repository_release_expired_signature: []const u8,
    repository_in_release: []const u8,
    noble_repository_packages: []const u8,
    noble_repository_in_release: []const u8,
    frozen_release: []const u8,
    frozen_in_release: []const u8,
    frozen_newer_release: []const u8,
    frozen_newer_in_release: []const u8,
    witness_updates_in_release: []const u8,
    witness_security_in_release: []const u8,
    witness_other_origin_in_release: []const u8,
    witness_updates_ed25519_in_release: []const u8,
    primary_fingerprint: []const u8,
    subkey_fingerprint: []const u8,
    ed25519_fingerprint: []const u8,
};

fn checksumLine(allocator: std.mem.Allocator, content: []const u8, architecture: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(content, &digest, .{});
    return std.fmt.allocPrint(allocator, " {s} {d} main/binary-{s}/Packages\n", .{
        std.fmt.bytesToHex(digest, .lower), content.len, architecture,
    });
}

fn frozenRelease(allocator: std.mem.Allocator, suite: []const u8, codename: []const u8, date: []const u8, expiry: ?[]const u8, origin: []const u8) ![]u8 {
    return std.mem.concat(allocator, u8, &.{
        try std.fmt.allocPrint(allocator, "{s}Suite: {s}\nCodename: {s}\nDate: {s}\n", .{ origin, suite, codename, date }),
        if (expiry) |value| try std.fmt.allocPrint(allocator, "Valid-Until: {s}\n", .{value}) else "",
        "Architectures: amd64\nComponents: main\nAcquire-By-Hash: no\nSHA256:\n",
        try checksumLine(allocator, packages, "amd64"),
    });
}

var cached_values: ?Values = null;
var cached_source: ?[]const u8 = null;

fn values(allocator: std.mem.Allocator) !Values {
    _ = allocator;
    if (cached_values) |existing| return existing;
    const result = try computeValues(std.heap.page_allocator);
    cached_values = result;
    return result;
}

fn computeValues(allocator: std.mem.Allocator) !Values {
    const primary_body = try pgp.Key.primary.publicBody(allocator);
    const subkey_body = try pgp.Key.subkey.publicBody(allocator);
    const ed_body = try pgp.Key.ed25519.publicBody(allocator);
    const primary_fp = try allocator.create([20]u8);
    primary_fp.* = try pgp.fingerprint(allocator, primary_body);
    const subkey_fp = try allocator.create([20]u8);
    subkey_fp.* = try pgp.fingerprint(allocator, subkey_body);
    const ed_fp = try allocator.create([20]u8);
    ed_fp.* = try pgp.fingerprint(allocator, ed_body);
    var uid_prefix: std.ArrayList(u8) = .empty;
    try uid_prefix.append(allocator, 0xb4);
    try pgp.integer(&uid_prefix, allocator, u32, pgp.uid.len);
    try uid_prefix.appendSlice(allocator, pgp.uid);
    const primary_prefix = try pgp.keyPrefix(allocator, primary_body);
    const uid_packet = try pgp.packet(allocator, 13, pgp.uid);
    const keyring_prefix = try std.mem.concat(allocator, u8, &.{
        try pgp.packet(allocator, 6, primary_body),
        uid_packet,
        try pgp.signature(allocator, .primary, 0x13, &.{ primary_prefix, uid_prefix.items }, primary_fp.*, .{
            .extra_hashed = try pgp.subpacket(allocator, 27, &.{0x01}),
        }),
        try pgp.packet(allocator, 14, subkey_body),
    });
    const binding_parts = [_][]const u8{ primary_prefix, try pgp.keyPrefix(allocator, subkey_body) };
    const primary_binding = try pgp.signature(allocator, .subkey, 0x19, &binding_parts, subkey_fp.*, .{});
    const signing_binding = try std.mem.concat(allocator, u8, &.{
        try pgp.subpacket(allocator, 27, &.{0x02}),
        try pgp.subpacket(allocator, 32, try pgp.packetBody(primary_binding)),
    });
    const sixty = [_]u8{ 0, 0, 0, 60 };
    const signature_expiry = try pgp.subpacket(allocator, 3, &sixty);
    const binding = try pgp.signature(allocator, .primary, 0x18, &binding_parts, primary_fp.*, .{ .extra_hashed = signing_binding });
    const release = try std.mem.concat(allocator, u8, &.{
        "Suite: stable\nCodename: bookworm\nDate: Tue, 14 Nov 2023 22:13:20 +0000\n" ++
            "Valid-Until: Thu, 16 Nov 2023 22:13:20 +0000\n" ++
            "Architectures: amd64\nComponents: main\nAcquire-By-Hash: no\nSHA256:\n",
        try checksumLine(allocator, packages, "amd64"),
    });
    const noble_release = try std.mem.concat(allocator, u8, &.{
        "Origin: debz Microsoft-shaped fixture noble\nLabel: debz Microsoft-shaped fixture noble\n" ++
            "Suite: noble\nCodename: noble\nDate: Tue, 14 Nov 2023 22:13:20 +0000\n" ++
            "Architectures: amd64 arm64 armhf all\nComponents: main\nAcquire-By-Hash: no\nSHA256:\n",
        try checksumLine(allocator, noble_packages, "amd64"),
        try checksumLine(allocator, noble_packages, "arm64"),
        try checksumLine(allocator, noble_packages, "armhf"),
    });
    const frozen = try frozenRelease(allocator, "stable", "bookworm", "Sat, 01 Apr 2023 00:00:00 +0000", null, frozen_origin);
    const newer = try frozenRelease(allocator, "stable", "bookworm", "Tue, 14 Nov 2023 21:30:00 +0000", null, frozen_origin);
    const updates = try frozenRelease(allocator, "stable-updates", "bookworm-updates", "Tue, 14 Nov 2023 20:00:00 +0000", null, frozen_origin);
    const security = try frozenRelease(allocator, "stable-security", "bookworm-security", "Tue, 14 Nov 2023 21:00:00 +0000", "Tue, 21 Nov 2023 21:00:00 +0000", frozen_origin);
    const other = try frozenRelease(allocator, "stable-updates", "bookworm-updates", "Tue, 14 Nov 2023 20:00:00 +0000", null, "Origin: other fixture\nLabel: other fixture\n");
    return .{
        .message = message,
        .keyring = try std.mem.concat(allocator, u8, &.{ keyring_prefix, binding }),
        .expired_keyring = try std.mem.concat(allocator, u8, &.{ keyring_prefix, try pgp.signature(allocator, .primary, 0x18, &binding_parts, primary_fp.*, .{
            .extra_hashed = try std.mem.concat(allocator, u8, &.{ try pgp.subpacket(allocator, 9, &sixty), signing_binding }),
        }) }),
        .authorization_expired_keyring = try std.mem.concat(allocator, u8, &.{ keyring_prefix, try pgp.signature(allocator, .primary, 0x18, &binding_parts, primary_fp.*, .{
            .extra_hashed = try std.mem.concat(allocator, u8, &.{ signature_expiry, signing_binding }),
        }) }),
        .non_signing_keyring = try std.mem.concat(allocator, u8, &.{ keyring_prefix, try pgp.signature(allocator, .primary, 0x18, &binding_parts, primary_fp.*, .{
            .extra_hashed = try pgp.subpacket(allocator, 27, &.{0x04}),
        }) }),
        .uncertified_keyring = try std.mem.concat(allocator, u8, &.{ keyring_prefix, try pgp.signature(allocator, .primary, 0x18, &binding_parts, primary_fp.*, .{}) }),
        .late_binding_keyring = try std.mem.concat(allocator, u8, &.{ keyring_prefix, try pgp.signature(allocator, .primary, 0x18, &binding_parts, primary_fp.*, .{
            .extra_hashed = signing_binding,
            .timestamp = pgp.created + 20,
        }) }),
        .revoked_keyring = try std.mem.concat(allocator, u8, &.{ keyring_prefix, binding, try pgp.signature(allocator, .primary, 0x28, &binding_parts, primary_fp.*, .{}) }),
        .signature = try pgp.signature(allocator, .subkey, 0x00, &.{message}, subkey_fp.*, .{}),
        .text_signature = try pgp.signature(allocator, .subkey, 0x01, &.{try std.mem.replaceOwned(u8, allocator, message, "\n", "\r\n")}, subkey_fp.*, .{}),
        .sha512_signature = try pgp.signature(allocator, .subkey, 0x00, &.{message}, subkey_fp.*, .{ .hash = .sha512 }),
        .expired_signature = try pgp.signature(allocator, .subkey, 0x00, &.{message}, subkey_fp.*, .{ .extra_hashed = signature_expiry }),
        .unknown_critical_signature = try pgp.signature(allocator, .subkey, 0x00, &.{message}, subkey_fp.*, .{ .extra_hashed = try pgp.subpacket(allocator, 100 | 0x80, &.{1}) }),
        .ed25519_keyring = try std.mem.concat(allocator, u8, &.{
            try pgp.packet(allocator, 6, ed_body),
            uid_packet,
            try pgp.signature(allocator, .ed25519, 0x13, &.{ try pgp.keyPrefix(allocator, ed_body), uid_prefix.items }, ed_fp.*, .{ .extra_hashed = try pgp.subpacket(allocator, 27, &.{0x03}) }),
        }),
        .ed25519_signature = try pgp.signature(allocator, .ed25519, 0x00, &.{message}, ed_fp.*, .{}),
        .repository_packages = packages,
        .repository_release = release,
        .repository_release_signature = try pgp.signature(allocator, .subkey, 0x00, &.{release}, subkey_fp.*, .{}),
        .repository_release_sha512_signature = try pgp.signature(allocator, .subkey, 0x00, &.{release}, subkey_fp.*, .{ .hash = .sha512 }),
        .repository_release_expired_signature = try pgp.signature(allocator, .subkey, 0x00, &.{release}, subkey_fp.*, .{ .extra_hashed = signature_expiry }),
        .repository_in_release = try pgp.clearsign(allocator, .subkey, subkey_fp.*, release, .{}),
        .noble_repository_packages = noble_packages,
        .noble_repository_in_release = try pgp.clearsign(allocator, .subkey, subkey_fp.*, noble_release, .{}),
        .frozen_release = frozen,
        .frozen_in_release = try pgp.clearsign(allocator, .subkey, subkey_fp.*, frozen, .{}),
        .frozen_newer_release = newer,
        .frozen_newer_in_release = try pgp.clearsign(allocator, .subkey, subkey_fp.*, newer, .{}),
        .witness_updates_in_release = try pgp.clearsign(allocator, .subkey, subkey_fp.*, updates, .{}),
        .witness_security_in_release = try pgp.clearsign(allocator, .subkey, subkey_fp.*, security, .{}),
        .witness_other_origin_in_release = try pgp.clearsign(allocator, .subkey, subkey_fp.*, other, .{}),
        .witness_updates_ed25519_in_release = try pgp.clearsign(allocator, .ed25519, ed_fp.*, updates, .{}),
        .primary_fingerprint = primary_fp,
        .subkey_fingerprint = subkey_fp,
        .ed25519_fingerprint = ed_fp,
    };
}

fn source(allocator: std.mem.Allocator) ![]u8 {
    if (cached_source) |existing| return allocator.dupe(u8, existing);
    const computed = try computeSource(std.heap.page_allocator);
    cached_source = computed;
    return allocator.dupe(u8, computed);
}

fn computeSource(allocator: std.mem.Allocator) ![]u8 {
    const fixtures = try values(allocator);
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(allocator, "// Generated by tools/generate-openpgp-fixtures.zig. The private keys are test-only.\n");
    try out.appendSlice(allocator, try std.fmt.allocPrint(allocator, "pub const created: i64 = {d};\n", .{pgp.created}));
    inline for (@typeInfo(Values).@"struct".field_names, 0..) |field_name, index| {
        if (index != 0) try out.appendSlice(allocator, "\n\n");
        try out.appendSlice(allocator, try std.fmt.allocPrint(allocator, "pub const {s} = [_]u8{{\n", .{field_name}));
        const bytes = @field(fixtures, field_name);
        var offset: usize = 0;
        while (offset < bytes.len) : (offset += 16) {
            try out.appendSlice(allocator, "    ");
            for (bytes[offset..@min(offset + 16, bytes.len)], 0..) |byte, column| {
                if (column != 0) try out.append(allocator, ' ');
                try out.appendSlice(allocator, try std.fmt.allocPrint(allocator, "0x{x:0>2},", .{byte}));
            }
            try out.append(allocator, '\n');
        }
        try out.appendSlice(allocator, "};");
    }
    try out.append(allocator, '\n');
    if (out.items.len > maximum_source_bytes) return error.OpenpgpFixtureTooLarge;
    return out.toOwnedSlice(allocator);
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
    const path = try fs.Path.init(std.fs.path.basename(output));
    var target = Destination{ .root = parent.root, .path = path, .original = try parent.root.entryIfExists(path) };
    try target.check();
    const bytes = try source(allocator);
    try target.check();
    try parent.root.publishFile(path, bytes, .{
        .permissions = .fromMode(0o644),
        .observer = .{ .context = &target, .hitFn = Destination.observe },
    });
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const allocator = init.arena.allocator();
    const output = if (args.next()) |argument| blk: {
        if (!std.mem.eql(u8, argument, "--output")) return error.UnexpectedFixtureArgument;
        break :blk args.next() orelse return error.MissingFixtureArgument;
    } else try std.fs.path.join(allocator, &.{ options.repository, "src/fixtures/openpgp.zig" });
    if (args.next() != null) return error.UnexpectedFixtureArgument;
    try generate(init.io, allocator, output);
}

test "OpenPGP generator reproduces every original authentic RSA and Ed25519 byte and compiled output" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const actual = try values(allocator);
    const original = @import("debz").test_fixtures.openpgp;
    inline for (@typeInfo(Values).@"struct".field_names) |field_name|
        try std.testing.expectEqualSlices(u8, &@field(original, field_name), @field(actual, field_name));
    const expected_path = try std.fs.path.join(allocator, &.{ options.repository, "src/fixtures/openpgp.zig" });
    const expected = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, expected_path, allocator, .limited(maximum_source_bytes));
    try std.testing.expectEqualSlices(u8, expected, try source(allocator));
    const generated = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, @import("openpgp_fixture_test_options").generated, allocator, .limited(maximum_source_bytes));
    try std.testing.expectEqualSlices(u8, expected, generated);
}

test "OpenPGP generator atomically regenerates real source without touching unrelated files" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var work = std.testing.tmpDir(.{});
    defer work.cleanup();
    const root = try work.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const output = try std.fs.path.join(allocator, &.{ root, "openpgp.zig" });
    try work.dir.writeFile(std.testing.io, .{ .sub_path = "unrelated", .data = "retain" });
    try generate(std.testing.io, allocator, output);
    try work.dir.writeFile(std.testing.io, .{ .sub_path = "openpgp.zig", .data = "stale" });
    try generate(std.testing.io, allocator, output);
    const actual = try work.dir.readFileAlloc(std.testing.io, "openpgp.zig", allocator, .limited(maximum_source_bytes));
    try std.testing.expectEqualSlices(u8, try source(allocator), actual);
    try std.testing.expectEqualStrings("retain", try work.dir.readFileAlloc(std.testing.io, "unrelated", allocator, .limited(32)));
}

test "OpenPGP generator refuses symbolic and hardlinked destinations without altering external bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var work = std.testing.tmpDir(.{});
    defer work.cleanup();
    const root = try work.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const output = try std.fs.path.join(allocator, &.{ root, "openpgp.zig" });
    try work.dir.writeFile(std.testing.io, .{ .sub_path = "external", .data = "unchanged" });
    try work.dir.symLink(std.testing.io, "external", "openpgp.zig", .{});
    try std.testing.expectError(error.NotRegularFixtureDestination, generate(std.testing.io, allocator, output));
    try work.dir.deleteFile(std.testing.io, "openpgp.zig");
    var owned = try fs.openAbsoluteRoot(std.testing.io, root);
    defer owned.close();
    try owned.root.createHardLink(try fs.Path.init("external"), try fs.Path.init("openpgp.zig"));
    try std.testing.expectError(error.HardLinkedFixtureDestination, generate(std.testing.io, allocator, output));
    try std.testing.expectEqualStrings("unchanged", try work.dir.readFileAlloc(std.testing.io, "external", allocator, .limited(32)));
    try std.testing.expectError(error.AbsoluteFixturePathRequired, generate(std.testing.io, allocator, "openpgp.zig"));
}
