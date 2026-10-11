//! Original public test keys and integration signatures, not package authority.
const std = @import("std");
const fs = @import("debz").root_fs;
const pgp = @import("fixture-openpgp.zig");
const maximum_bytes = 8 * 1024 * 1024;

const Signed = struct { keyring: []const u8, in_release: []const u8, fingerprint: [20]u8 };

fn hex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 15];
    }
    return out;
}

fn sign(allocator: std.mem.Allocator, release: []const u8) !Signed {
    const primary = try pgp.Key.primary.publicBody(allocator);
    const subkey = try pgp.Key.subkey.publicBody(allocator);
    const primary_fingerprint = try pgp.fingerprint(allocator, primary);
    const subkey_fingerprint = try pgp.fingerprint(allocator, subkey);
    const primary_prefix = try pgp.keyPrefix(allocator, primary);
    const subkey_prefix = try pgp.keyPrefix(allocator, subkey);
    var uid_prefix: std.ArrayList(u8) = .empty;
    try uid_prefix.append(allocator, 0xb4);
    try pgp.integer(&uid_prefix, allocator, u32, @intCast(pgp.uid.len));
    try uid_prefix.appendSlice(allocator, pgp.uid);
    const binding_parts = [_][]const u8{ primary_prefix, subkey_prefix };
    const primary_binding = try pgp.signature(allocator, .subkey, 0x19, &binding_parts, subkey_fingerprint, .{});
    return .{
        .keyring = try std.mem.concat(allocator, u8, &.{
            try pgp.packet(allocator, 6, primary),
            try pgp.packet(allocator, 13, pgp.uid),
            try pgp.signature(allocator, .primary, 0x13, &.{ primary_prefix, uid_prefix.items }, primary_fingerprint, .{
                .extra_hashed = try pgp.subpacket(allocator, 27, &.{0x01}),
            }),
            try pgp.packet(allocator, 14, subkey),
            try pgp.signature(allocator, .primary, 0x18, &binding_parts, primary_fingerprint, .{
                .extra_hashed = try std.mem.concat(allocator, u8, &.{
                    try pgp.subpacket(allocator, 27, &.{0x02}),
                    try pgp.subpacket(allocator, 32, try pgp.packetBody(primary_binding)),
                }),
            }),
        }),
        .in_release = try pgp.clearsign(allocator, .subkey, subkey_fingerprint, release, .{}),
        .fingerprint = primary_fingerprint,
    };
}

fn signFile(io: std.Io, allocator: std.mem.Allocator, input: []const u8) !Signed {
    if (!std.fs.path.isAbsolute(input)) return error.InvalidIntegrationSigningInput;
    var root = try fs.openAbsoluteRoot(io, std.fs.path.dirname(input) orelse return error.InvalidIntegrationSigningInput);
    defer root.close();
    var pin = try root.root.pinRegularFile(try fs.Path.init(std.fs.path.basename(input)));
    defer pin.close();
    const document = try pin.observeStableAlloc(allocator, maximum_bytes);
    return sign(allocator, document.bytes);
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const input = args.next() orelse return error.MissingIntegrationSigningInput;
    if (args.next() != null) return error.InvalidIntegrationSigningInput;
    const allocator = init.arena.allocator();
    const signed = signFile(init.io, allocator, input) catch |err| {
        std.log.err("native integration signing refused: {s}", .{@errorName(err)});
        return err;
    };
    const output = try std.json.Stringify.valueAlloc(allocator, .{
        .keyring = try hex(allocator, signed.keyring),
        .in_release = try hex(allocator, signed.in_release),
        .fingerprint = &std.fmt.bytesToHex(signed.fingerprint, .lower),
    }, .{});
    try std.Io.File.stdout().writeStreamingAll(init.io, output);
}

test "integration signer reproduces independently original keyring and clearsigned bytes without interpreters" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "Release", .data = "Origin: debz fixture\nSuite: stable\n" });
    const input = try temporary.dir.realPathFileAlloc(std.testing.io, "Release", allocator);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try environment.put("PATH", "/no-host-interpreters");
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ @import("integration_signing_test_options").executable, input },
        .environ_map = &environment,
        .stdout_limit = .limited(8192),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    const parsed = try std.json.parseFromSlice(struct { keyring: []const u8, in_release: []const u8, fingerprint: []const u8 }, allocator, result.stdout, .{});
    for ([_]struct { hex: []const u8, size: usize, digest: []const u8 }{
        .{ .hex = parsed.value.keyring, .size = 1529, .digest = "3907b432b4746fcd56702acccbf4bfb0308a99b07331c1fa11d7998865796b14" },
        .{ .hex = parsed.value.in_release, .size = 566, .digest = "9cc9b4c7976ea7cdafa5097ad8f2777122b5644479e9828f3c7ae63d81ee4d9f" },
    }) |expected| {
        const bytes = try allocator.alloc(u8, expected.hex.len / 2);
        _ = try std.fmt.hexToBytes(bytes, expected.hex);
        try std.testing.expectEqual(expected.size, bytes.len);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        try std.testing.expectEqualStrings(expected.digest, &std.fmt.bytesToHex(digest, .lower));
    }
    try std.testing.expectEqualStrings("fcd01b8ef26ce414115b1433f5322dace233beb8", parsed.value.fingerprint);
}

test "integration signer preserves original CRLF signatures and refuses incomplete release text" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const lf = try sign(allocator, "Origin: debz fixture\nSuite: stable\n");
    const crlf = try sign(allocator, "Origin: debz fixture\r\nSuite: stable\r\n");
    const marker = "-----BEGIN PGP SIGNATURE-----";
    try std.testing.expectEqualSlices(u8, lf.in_release[std.mem.indexOf(u8, lf.in_release, marker).?..], crlf.in_release[std.mem.indexOf(u8, crlf.in_release, marker).?..]);
    try std.testing.expectError(error.InvalidFixtureRelease, sign(allocator, ""));
    try std.testing.expectError(error.InvalidFixtureRelease, sign(allocator, "missing newline"));
}

test "integration signer refuses symlink and oversized inputs without publishing or modifying files" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "outside", .data = "unchanged\n" });
    try temporary.dir.symLink(std.testing.io, "outside", "Release", .{});
    const directory = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const input = try std.fs.path.join(allocator, &.{ directory, "Release" });
    if (signFile(std.testing.io, allocator, input)) |_| return error.TestExpectedError else |_| {}
    try std.testing.expectEqualStrings("unchanged\n", try temporary.dir.readFileAlloc(std.testing.io, "outside", allocator, .limited(32)));
    try temporary.dir.deleteFile(std.testing.io, "Release");
    const file = try temporary.dir.createFile(std.testing.io, "Release", .{});
    defer file.close(std.testing.io);
    try file.setLength(std.testing.io, maximum_bytes + 1);
    try std.testing.expectError(error.FileTooLarge, signFile(std.testing.io, allocator, input));
}

test "actual repository producer refuses a missing signer before clearing existing output" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "sentinel", .data = "original output\n" });
    const output = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    const missing = try std.fs.path.join(allocator, &.{ output, "missing-native-signer" });
    const script = try std.fs.path.join(allocator, &.{ @import("integration_signing_test_options").repository, "tools/generate-integration-repository.py" });
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ "python3", script, "--output", output, "--suite", "debian-stable", "--architecture", "arm64", "--signing-helper", missing },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "required absolute native integration signer") != null);
    try std.testing.expectEqualStrings("original output\n", try temporary.dir.readFileAlloc(std.testing.io, "sentinel", allocator, .limited(32)));
}
