//! Drives tools/real-snapshot-repin.py against synthetic signed snapshots.
//!
//! Each Release is signed here with a throwaway Ed25519 key, served through
//! file:// URIs and authenticated by the real debz CLI, so the tool's bindings
//! to `debz refresh`, `plan` and `download` run without network access.

const std = @import("std");
const options = @import("real_snapshot_repin_options");
const support = @import("tooling-test-support.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const io = support.io;

const day: i64 = 24 * 60 * 60;
const key_created: u32 = 1_600_000_000;
const archive_mtime: u64 = 1_700_000_000;
const armor_columns = 64;
const tool = "tools/real-snapshot-repin.py";
const reviewed = "#330";
const weekdays = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

const postinst_1_0 = "#!/bin/sh\nset -e\n# alpha 1.0\nexit 0\n";
const postinst_1_1 = "#!/bin/sh\nset -e\n# alpha 1.1\nmkdir -p /var/lib/alpha\nexit 0\n";
const beta_tool = "#!/bin/sh\necho beta\n";

const Member = struct {
    name: []const u8,
    mode: u32 = 0o644,
    bytes: []const u8,
};

const Package = struct {
    name: []const u8,
    version: []const u8,
    depends: ?[]const u8 = null,
    scripts: []const Member = &.{},
    files: []const Member = &.{},
    signed_sha512: bool = true,
};

const Result = struct {
    code: u8,
    stdout: []const u8,
    stderr: []const u8,
};

const Harness = struct {
    arena_state: std.heap.ArenaAllocator,
    work: support.Work,
    signer: Signer,
    now: i64,

    fn init(self: *Harness) !void {
        self.arena_state = .init(std.heap.page_allocator);
        errdefer self.arena_state.deinit();
        self.work = try support.Work.init();
        errdefer self.work.deinit();
        self.signer = try Signer.init(self.arena());
        self.now = @intCast(@divFloor(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
        try self.work.write("keyring.gpg", self.signer.keyring);
    }

    fn deinit(self: *Harness) void {
        self.work.deinit();
        self.arena_state.deinit();
    }

    fn arena(self: *Harness) std.mem.Allocator {
        return self.arena_state.allocator();
    }

    fn print(self: *Harness, comptime format: []const u8, args: anytype) ![]const u8 {
        return std.fmt.allocPrint(self.arena(), format, args);
    }

    fn path(self: *Harness, relative: []const u8) ![]const u8 {
        return self.print("{s}/{s}", .{ self.work.root, relative });
    }

    fn read(self: *Harness, relative: []const u8) ![]const u8 {
        const bytes = try self.work.read(relative);
        defer support.allocator.free(bytes);
        return self.arena().dupe(u8, bytes);
    }

    fn exists(self: *Harness, relative: []const u8) bool {
        self.work.directory.dir.access(io, relative, .{}) catch return false;
        return true;
    }

    /// The newest day boundary that is at least `days` old.
    fn settledDay(self: *Harness, days: i64) i64 {
        return @divFloor(self.now, day) * day - days * day;
    }

    fn timestamp(self: *Harness, seconds: i64) ![]const u8 {
        const epoch: std.time.epoch.EpochSeconds = .{ .secs = @intCast(seconds) };
        const year_day = epoch.getEpochDay().calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const day_seconds = epoch.getDaySeconds();
        return self.print("{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        });
    }

    fn releaseDate(self: *Harness, seconds: i64) ![]const u8 {
        const epoch: std.time.epoch.EpochSeconds = .{ .secs = @intCast(seconds) };
        const epoch_day = epoch.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const day_seconds = epoch.getDaySeconds();
        return self.print("{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} UTC", .{
            weekdays[@intCast(@mod(epoch_day.day, 7))],
            month_day.day_index + 1,
            months[month_day.month.numeric() - 1],
            year_day.year,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        });
    }

    fn fingerprint(self: *Harness) ![]const u8 {
        const hex = std.fmt.bytesToHex(self.signer.fingerprint, .lower);
        return self.arena().dupe(u8, &hex);
    }

    /// Writes `<repository>/<T>/{dists,pool}` with one signed InRelease per suite.
    fn writeSnapshot(
        self: *Harness,
        repository: []const u8,
        seconds: i64,
        suites: []const []const u8,
        packages: []const Package,
    ) !void {
        const arena_allocator = self.arena();
        const stamp = try self.timestamp(seconds);
        var index: std.ArrayList(u8) = .empty;
        for (packages) |package| {
            const deb = try buildDeb(arena_allocator, package);
            const filename = try self.print("pool/main/{s}_{s}_all.deb", .{ package.name, package.version });
            try self.work.write(try self.print("{s}/{s}/{s}", .{ repository, stamp, filename }), deb);
            try index.print(arena_allocator, "Package: {s}\nVersion: {s}\nArchitecture: all\n", .{ package.name, package.version });
            try index.appendSlice(arena_allocator, "Maintainer: debz fixture <fixture.invalid>\nInstalled-Size: 1\n");
            if (package.depends) |depends| try index.print(arena_allocator, "Depends: {s}\n", .{depends});
            try index.print(arena_allocator, "Filename: {s}\nSize: {d}\nSHA256: {s}\n", .{
                filename, deb.len, try sha256Hex(arena_allocator, deb),
            });
            if (package.signed_sha512) try index.print(arena_allocator, "SHA512: {s}\n", .{try sha512Hex(arena_allocator, deb)});
            try index.print(arena_allocator, "Description: synthetic repin fixture {s}\n\n", .{package.name});
        }
        const signed_at: u32 = @intCast(self.now - 600);
        for (suites) |suite| {
            var release: std.ArrayList(u8) = .empty;
            try release.print(arena_allocator, "Origin: Synthetic\nLabel: Synthetic\nSuite: {s}\nCodename: {s}\nDate: {s}\n", .{
                suite, suite, try self.releaseDate(seconds - 3600),
            });
            try release.appendSlice(arena_allocator, "Architectures: amd64 arm64\nComponents: main\nAcquire-By-Hash: no\n");
            inline for (.{ "SHA256", "SHA512" }) |field| {
                try release.print(arena_allocator, "{s}:\n", .{field});
                for ([_][]const u8{ "amd64", "arm64" }) |arch| {
                    const hex = if (comptime std.mem.eql(u8, field, "SHA256"))
                        try sha256Hex(arena_allocator, index.items)
                    else
                        try sha512Hex(arena_allocator, index.items);
                    try release.print(arena_allocator, " {s} {d} main/binary-{s}/Packages\n", .{ hex, index.items.len, arch });
                }
            }
            for ([_][]const u8{ "amd64", "arm64" }) |arch| {
                try self.work.write(try self.print("{s}/{s}/dists/{s}/main/binary-{s}/Packages", .{ repository, stamp, suite, arch }), index.items);
            }
            try self.work.write(
                try self.print("{s}/{s}/dists/{s}/InRelease", .{ repository, stamp, suite }),
                try self.signer.inRelease(arena_allocator, release.items, signed_at),
            );
        }
    }

    fn writeProfile(
        self: *Harness,
        name: []const u8,
        repository: []const u8,
        signer: []const u8,
        pockets: []const u8,
    ) ![]const u8 {
        const profile = try self.print(
            "{{\"name\":\"{s}\",\"uri_root\":\"file://{s}\",\"component\":\"main\"," ++
                "\"architectures\":[\"amd64\",\"arm64\"],\"keyring\":\"{s}\",\"signer\":\"{s}\"," ++
                "\"request\":\"alpha\",\"pockets\":{s}}}",
            .{ name, try self.path(repository), try self.path("keyring.gpg"), signer, pockets },
        );
        try self.work.write(try self.print("{s}.profile.json", .{name}), profile);
        return profile;
    }

    fn writeManifest(self: *Harness, name: []const u8, profile: []const u8, seconds: i64, uri_consumers: []const u8, identities: []const u8) !void {
        try self.work.write(try self.print("{s}.pin.json", .{name}), try self.print(
            "{{\"schema\":\"io.github.cataggar.debz.real-snapshot-pin.v1\",\"series\":{s}," ++
                "\"snapshot\":{{\"timestamp\":\"{s}\",\"status\":\"pending\"}}," ++
                "\"uri_consumers\":{s},\"identities\":{s},\"excluded\":[]}}\n",
            .{ profile, try self.timestamp(seconds), uri_consumers, identities },
        ));
    }

    /// A debz wrapper that logs each operation and optionally runs `after`.
    fn writeDebz(self: *Harness, name: []const u8, after: []const u8) !void {
        const relative = try self.print("debz-{s}", .{name});
        try self.work.write(relative, try self.print(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >>'{s}'\n'{s}' \"$@\"\nstatus=$?\n{s}\nexit \"$status\"\n",
            .{ try self.path(try self.print("calls-{s}", .{name})), options.debz, after },
        ));
        _ = try self.run(&.{ "chmod", "0755", try self.path(relative) }, 0);
    }

    fn calls(self: *Harness, name: []const u8) ![]const u8 {
        const relative = try self.print("calls-{s}", .{name});
        if (!self.exists(relative)) return "";
        return self.read(relative);
    }

    fn run(self: *Harness, argv: []const []const u8, expected: ?u8) !Result {
        const raw = try support.runWithTimeout(argv, .inherit, 600);
        defer raw.deinit();
        const result: Result = .{
            .code = raw.code,
            .stdout = try self.arena().dupe(u8, raw.stdout),
            .stderr = try self.arena().dupe(u8, raw.stderr),
        };
        if (expected) |code| if (result.code != code) {
            std.debug.print("{s}: expected exit {d}, got {d}\nstdout: {s}\nstderr: {s}\n", .{
                argv[@min(argv.len - 1, 2)], code, result.code, result.stdout, result.stderr,
            });
            return error.UnexpectedExitStatus;
        };
        return result;
    }

    fn repin(self: *Harness, arguments: []const []const u8, expected: u8) !Result {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(self.arena(), &.{ "python3", tool });
        try argv.appendSlice(self.arena(), arguments);
        return self.run(argv.items, expected);
    }

    fn probe(self: *Harness, name: []const u8, seconds: i64, workspace: []const u8, expected: u8) !Result {
        return self.repin(&.{
            "probe",                                            "--series",                                                 name,
            "--timestamp",                                      try self.timestamp(seconds),                                "--debz",
            try self.path(try self.print("debz-{s}", .{name})), "--manifest",                                               try self.path(try self.print("{s}.pin.json", .{name})),
            "--profile",                                        try self.path(try self.print("{s}.profile.json", .{name})), "--workspace",
            try self.path(workspace),
        }, expected);
    }
};

const Signer = struct {
    key_pair: Ed25519.KeyPair,
    fingerprint: [20]u8,
    keyring: []u8,

    fn init(allocator: std.mem.Allocator) !Signer {
        const seed: [Ed25519.KeyPair.seed_length]u8 = @splat(0x33);
        const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);
        var body: std.ArrayList(u8) = .empty;
        try body.append(allocator, 4);
        try appendInt(&body, allocator, u32, key_created);
        try body.append(allocator, 22);
        const oid = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01 };
        try body.append(allocator, oid.len);
        try body.appendSlice(allocator, &oid);
        var point: [33]u8 = undefined;
        point[0] = 0x40;
        point[1..].* = key_pair.public_key.toBytes();
        try appendMpi(&body, allocator, &point);

        var prefix: std.ArrayList(u8) = .empty;
        try prefix.append(allocator, 0x99);
        try appendInt(&prefix, allocator, u16, @intCast(body.items.len));
        try prefix.appendSlice(allocator, body.items);
        var fingerprint: [20]u8 = undefined;
        Sha1.hash(prefix.items, &fingerprint, .{});

        const uid = "debz real-snapshot repin fixture <fixture.invalid>";
        var keyring: std.ArrayList(u8) = .empty;
        try appendPacket(&keyring, allocator, 6, body.items);
        try appendPacket(&keyring, allocator, 13, uid);
        var certified: std.ArrayList(u8) = .empty;
        try certified.appendSlice(allocator, prefix.items);
        try certified.append(allocator, 0xb4);
        try appendInt(&certified, allocator, u32, uid.len);
        try certified.appendSlice(allocator, uid);
        try keyring.appendSlice(allocator, try signPacket(allocator, key_pair, fingerprint, 0x13, certified.items, 0x03, key_created));
        return .{ .key_pair = key_pair, .fingerprint = fingerprint, .keyring = keyring.items };
    }

    /// Returns a cleartext-signed InRelease whose text signature covers `release`.
    fn inRelease(self: Signer, allocator: std.mem.Allocator, release: []const u8, created: u32) ![]u8 {
        var canonical: std.ArrayList(u8) = .empty;
        var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, release, "\n"), '\n');
        var first = true;
        while (lines.next()) |line| {
            if (!first) try canonical.appendSlice(allocator, "\r\n");
            first = false;
            try canonical.appendSlice(allocator, std.mem.trimEnd(u8, line, " \t"));
        }
        const packet = try signPacket(allocator, self.key_pair, self.fingerprint, 0x01, canonical.items, null, created);
        const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(packet.len));
        _ = std.base64.standard.Encoder.encode(encoded, packet);
        const crc = crc24(packet);
        var crc_text: [4]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&crc_text, &crc);

        var output: std.ArrayList(u8) = .empty;
        try output.appendSlice(allocator, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n");
        try output.appendSlice(allocator, release);
        try output.appendSlice(allocator, "-----BEGIN PGP SIGNATURE-----\n\n");
        var rest: []const u8 = encoded;
        while (rest.len != 0) {
            const take = @min(rest.len, armor_columns);
            try output.appendSlice(allocator, rest[0..take]);
            try output.append(allocator, '\n');
            rest = rest[take..];
        }
        try output.print(allocator, "={s}\n-----END PGP SIGNATURE-----\n", .{&crc_text});
        return output.items;
    }
};

fn signPacket(
    allocator: std.mem.Allocator,
    key_pair: Ed25519.KeyPair,
    fingerprint: [20]u8,
    signature_type: u8,
    signed_bytes: []const u8,
    key_flags: ?u8,
    created: u32,
) ![]u8 {
    var hashed: std.ArrayList(u8) = .empty;
    var created_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &created_bytes, created, .big);
    try appendSubpacket(&hashed, allocator, 2, &created_bytes);
    var issuer: [21]u8 = undefined;
    issuer[0] = 4;
    issuer[1..].* = fingerprint;
    try appendSubpacket(&hashed, allocator, 33, &issuer);
    if (key_flags) |flags| try appendSubpacket(&hashed, allocator, 27, &.{flags});

    var prefix: std.ArrayList(u8) = .empty;
    try prefix.appendSlice(allocator, &.{ 4, signature_type, 22, 10 });
    try appendInt(&prefix, allocator, u16, @intCast(hashed.items.len));
    try prefix.appendSlice(allocator, hashed.items);

    var hash = Sha512.init(.{});
    hash.update(signed_bytes);
    hash.update(prefix.items);
    var trailer: [6]u8 = .{ 4, 0xff, 0, 0, 0, 0 };
    std.mem.writeInt(u32, trailer[2..6], @intCast(prefix.items.len), .big);
    hash.update(&trailer);
    const message = hash.finalResult();
    const signature = (try key_pair.sign(&message, null)).toBytes();

    var unhashed: std.ArrayList(u8) = .empty;
    try appendSubpacket(&unhashed, allocator, 16, fingerprint[12..20]);
    var body: std.ArrayList(u8) = .empty;
    try body.appendSlice(allocator, prefix.items);
    try appendInt(&body, allocator, u16, @intCast(unhashed.items.len));
    try body.appendSlice(allocator, unhashed.items);
    try body.appendSlice(allocator, message[0..2]);
    try appendMpi(&body, allocator, signature[0..32]);
    try appendMpi(&body, allocator, signature[32..64]);
    var packet: std.ArrayList(u8) = .empty;
    try appendPacket(&packet, allocator, 2, body.items);
    return packet.items;
}

fn appendPacket(output: *std.ArrayList(u8), allocator: std.mem.Allocator, tag: u8, body: []const u8) !void {
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

fn appendSubpacket(output: *std.ArrayList(u8), allocator: std.mem.Allocator, kind: u8, body: []const u8) !void {
    try output.append(allocator, @intCast(body.len + 1));
    try output.append(allocator, kind);
    try output.appendSlice(allocator, body);
}

fn appendMpi(output: *std.ArrayList(u8), allocator: std.mem.Allocator, raw: []const u8) !void {
    var first: usize = 0;
    while (first < raw.len and raw[first] == 0) : (first += 1) {}
    const significant = raw[first..];
    if (significant.len == 0) return appendInt(output, allocator, u16, 0);
    const leading_bits: u16 = @intCast(8 - @clz(significant[0]));
    try appendInt(output, allocator, u16, @intCast((significant.len - 1) * 8 + leading_bits));
    try output.appendSlice(allocator, significant);
}

fn appendInt(output: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) !void {
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
    return .{ @intCast((crc >> 16) & 0xff), @intCast((crc >> 8) & 0xff), @intCast(crc & 0xff) };
}

fn sha256Hex(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var out: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &out, .{});
    const hex = std.fmt.bytesToHex(out, .lower);
    return allocator.dupe(u8, &hex);
}

fn sha512Hex(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var out: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(bytes, &out, .{});
    const hex = std.fmt.bytesToHex(out, .lower);
    return allocator.dupe(u8, &hex);
}

fn zigBytes(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var out: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &out, .{});
    var text: std.ArrayList(u8) = .empty;
    for (out, 0..) |byte, index| {
        if (index != 0) try text.appendSlice(allocator, ", ");
        try text.print(allocator, "0x{x:0>2}", .{byte});
    }
    return text.items;
}

fn ustar(allocator: std.mem.Allocator, members: []const Member) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    for (members) |member| {
        var header: [512]u8 = @splat(0);
        @memcpy(header[0..member.name.len], member.name);
        _ = try std.fmt.bufPrint(header[100..107], "{o:0>7}", .{member.mode});
        _ = try std.fmt.bufPrint(header[108..115], "{o:0>7}", .{0});
        _ = try std.fmt.bufPrint(header[116..123], "{o:0>7}", .{0});
        _ = try std.fmt.bufPrint(header[124..135], "{o:0>11}", .{member.bytes.len});
        _ = try std.fmt.bufPrint(header[136..147], "{o:0>11}", .{archive_mtime});
        header[156] = '0';
        @memcpy(header[257..263], "ustar\x00");
        @memcpy(header[263..265], "00");
        @memcpy(header[265..269], "root");
        @memcpy(header[297..301], "root");
        @memset(header[148..156], ' ');
        var sum: u32 = 0;
        for (header) |byte| sum += byte;
        _ = try std.fmt.bufPrint(header[148..155], "{o:0>6}\x00", .{sum});
        try output.appendSlice(allocator, &header);
        try output.appendSlice(allocator, member.bytes);
        try output.appendNTimes(allocator, 0, (512 - member.bytes.len % 512) % 512);
    }
    try output.appendNTimes(allocator, 0, 1024);
    return output.items;
}

fn arMember(output: *std.ArrayList(u8), allocator: std.mem.Allocator, name: []const u8, bytes: []const u8) !void {
    var header: [60]u8 = @splat(' ');
    @memcpy(header[0..name.len], name);
    _ = try std.fmt.bufPrint(header[16..28], "{d}", .{archive_mtime});
    header[28] = '0';
    header[34] = '0';
    @memcpy(header[40..46], "100644");
    _ = try std.fmt.bufPrint(header[48..58], "{d}", .{bytes.len});
    @memcpy(header[58..60], "`\n");
    try output.appendSlice(allocator, &header);
    try output.appendSlice(allocator, bytes);
    if (bytes.len % 2 != 0) try output.append(allocator, '\n');
}

fn buildDeb(allocator: std.mem.Allocator, package: Package) ![]u8 {
    const control = try std.fmt.allocPrint(
        allocator,
        "Package: {s}\nVersion: {s}\nArchitecture: all\nMaintainer: debz fixture <fixture.invalid>\nDescription: synthetic repin fixture {s}\n",
        .{ package.name, package.version, package.name },
    );
    var control_members: std.ArrayList(Member) = .empty;
    try control_members.append(allocator, .{ .name = "./control", .bytes = control });
    try control_members.appendSlice(allocator, package.scripts);
    var output: std.ArrayList(u8) = .empty;
    try output.appendSlice(allocator, "!<arch>\n");
    try arMember(&output, allocator, "debian-binary", "2.0\n");
    try arMember(&output, allocator, "control.tar", try ustar(allocator, control_members.items));
    try arMember(&output, allocator, "data.tar", try ustar(allocator, package.files));
    return output.items;
}

fn snapshotPackages(
    allocator: std.mem.Allocator,
    alpha: []const u8,
    beta: []const u8,
    gamma_data: []const u8,
    signed_sha512: bool,
) ![3]Package {
    const postinst = if (std.mem.eql(u8, alpha, "1.0")) postinst_1_0 else postinst_1_1;
    return .{
        .{
            .name = "alpha",
            .version = alpha,
            .depends = "beta",
            .scripts = try allocator.dupe(Member, &.{.{ .name = "./postinst", .mode = 0o755, .bytes = postinst }}),
        },
        .{
            .name = "beta",
            .version = beta,
            .files = &.{.{ .name = "./usr/bin/beta-tool", .mode = 0o755, .bytes = beta_tool }},
            .signed_sha512 = signed_sha512,
        },
        .{
            .name = "gamma",
            .version = "1.0",
            .files = try allocator.dupe(Member, &.{.{ .name = "./usr/share/gamma/data", .bytes = gamma_data }}),
        },
    };
}

fn contains(haystack: []const u8, needle: []const u8) !void {
    try support.contains(haystack, needle);
}

fn expectAbsent(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) {
        std.debug.print("unexpected '{s}' in:\n{s}\n", .{ needle, haystack });
        return error.UnexpectedText;
    }
}

const bounded = "[{\"suite\":\"stable\",\"role\":\"bounded\"}]";

/// Writes the in-tree consumers that a checked-in repin manifest pins.
fn writeTree(h: *Harness, uri: []const u8, postinst: []const u8, gamma: []const u8) !void {
    try h.work.write("tree/src/fixtures/ubuntu-alpha-postinst", postinst);
    try h.work.write("tree/src/native_unpack.zig", try h.print(
        "const snapshot_beta_tool_sha256 = .{{ {s} }};\n" ++
            "const beta_inputs = .{{.{{ .path = \"usr/bin/beta-tool\", .size = {d}, .mode = 0o755, .sha256 = \"{s}\" }}}};\n",
        .{ try zigBytes(h.arena(), beta_tool), beta_tool.len, try sha256Hex(h.arena(), beta_tool) },
    ));
    try h.work.write("tree/tools/real-snapshot-acceptance.sh", try h.print(
        "#!/bin/sh\nsnapshot_uri={s}\n# gamma 1.0\ngamma_archive={s}\n",
        .{ uri, gamma },
    ));
}

test "repin: synthetic signed snapshots drive probe, diff, record and check across a reviewed change" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const allocator = h.arena();
    const t2 = h.settledDay(1);
    const t1 = t2 - day;
    const first = try snapshotPackages(h.arena(), "1.0", "1.0", "gamma 1.0 build 1\n", true);
    const second = try snapshotPackages(h.arena(), "1.1", "1.1", "gamma 1.0 build 2\n", true);
    try h.writeSnapshot("main", t1, &.{"stable"}, &first);
    try h.writeSnapshot("main", t2, &.{"stable"}, &second);
    const gamma_1 = try sha512Hex(allocator, try buildDeb(allocator, first[2]));
    const gamma_2 = try sha512Hex(allocator, try buildDeb(allocator, second[2]));
    const profile = try h.writeProfile("synthetic-main", "main", try h.fingerprint(), bounded);
    const identities = try h.print(
        "[{{\"id\":\"script:alpha/postinst\",\"kind\":\"script\",\"package\":\"alpha\",\"architectures\":[\"amd64\",\"arm64\"]," ++
            "\"path\":\"postinst\",\"digest\":\"sha256:{s}\",\"size\":{d},\"mode\":\"0755\",\"version_bound\":false," ++
            "\"provenance\":\"pending\",\"consumers\":[{{\"path\":\"src/fixtures/ubuntu-alpha-postinst\",\"form\":\"fixture\"}}],\"review\":\"#1\"}}," ++
            "{{\"id\":\"file:beta/usr/bin/beta-tool\",\"kind\":\"tool_file\",\"package\":\"beta\",\"architectures\":[\"amd64\",\"arm64\"]," ++
            "\"path\":\"usr/bin/beta-tool\",\"digest\":\"sha256:{s}\",\"size\":{d},\"mode\":\"0755\",\"version_bound\":false," ++
            "\"provenance\":\"pending\",\"consumers\":[{{\"path\":\"src/native_unpack.zig\",\"form\":\"zig_bytes\",\"name\":\"snapshot_beta_tool_sha256\"}}],\"review\":\"#1\"}}," ++
            "{{\"id\":\"archive:gamma\",\"kind\":\"archive\",\"package\":\"gamma\",\"architectures\":[\"amd64\"]," ++
            "\"path\":null,\"digest\":\"sha512:{s}\",\"size\":{d},\"mode\":null,\"version_bound\":false," ++
            "\"provenance\":\"pending\",\"consumers\":[{{\"path\":\"tools/real-snapshot-acceptance.sh\",\"form\":\"hex\"}}],\"review\":\"#1\"}}]",
        .{
            try sha256Hex(allocator, postinst_1_0), postinst_1_0.len,
            try sha256Hex(allocator, beta_tool),    beta_tool.len,
            gamma_1,                                (try buildDeb(allocator, first[2])).len,
        },
    );
    try h.writeManifest("synthetic-main", profile, t1, "[\"tools/real-snapshot-acceptance.sh\"]", identities);
    try h.writeDebz("synthetic-main", "");
    const uri_1 = try h.print("file://{s}/{s}", .{ try h.path("main"), try h.timestamp(t1) });
    const uri_2 = try h.print("file://{s}/{s}", .{ try h.path("main"), try h.timestamp(t2) });
    try writeTree(&h, uri_1, postinst_1_0, gamma_1);
    const manifest = try h.path("synthetic-main.pin.json");
    const tree = try h.path("tree");
    const check_args = [_][]const u8{ "check", "--manifest", manifest, "--root", tree, "--profile", try h.path("synthetic-main.profile.json") };

    // A snapshot time less than 24 hours old is refused before debz runs.
    const recent = try h.probe("synthetic-main", h.settledDay(0), "ws/recent", 2);
    try contains(recent.stderr, "less than 24 hours old");
    try std.testing.expectEqualStrings("", try h.calls("synthetic-main"));
    try std.testing.expect(!h.exists("ws/recent"));

    // The first probe records provenance for every pending identity, including
    // gamma, which is outside the request closure and needs its own plan.
    try contains((try h.probe("synthetic-main", t1, "ws/t1", 0)).stdout, "probe passed");
    const calls = try h.calls("synthetic-main");
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, calls, "refresh\n"));
    // gamma binds only amd64, so arm64 plans and downloads only the closure.
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, calls, "plan\n"));
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, calls, "download\n"));
    const report_1 = try h.path("ws/t1/report.json");
    const diff_1 = try h.repin(&.{ "diff", "--manifest", manifest, "--report", report_1, "--root", tree }, 0);
    try contains(diff_1.stdout, "- amd64: 0 changed, 2 added, 0 removed closure packages");
    try contains(diff_1.stdout, "  - added: alpha 1.0");
    try contains(diff_1.stdout, "| `script:alpha/postinst` | provenance-only | amd64: records first provenance; arm64: records first provenance |");
    try contains(diff_1.stdout, "| `archive:gamma` | provenance-only |");
    try expectAbsent(diff_1.stdout, "added: gamma");
    try contains(
        (try h.repin(&.{ "record", "--manifest", manifest, "--report", report_1, "--root", tree }, 0)).stdout,
        try h.print("recorded {s}: 0 unchanged, 3 provenance-only, 0 changed, 0 missing", .{try h.timestamp(t1)}),
    );
    try contains(
        (try h.repin(&check_args, 0)).stdout,
        try h.print("check passed: 3 identities for synthetic-main {s} (probed)", .{try h.timestamp(t1)}),
    );
    const recorded = try h.read("synthetic-main.pin.json");
    try contains(recorded, try h.print("\"amd64\": \"sha512:{s}\"", .{gamma_1}));

    // alpha's postinst changed with its version, beta's tool kept its bytes and
    // gamma was rebuilt under the same version.
    try contains((try h.probe("synthetic-main", t2, "ws/t2", 0)).stdout, "probe passed");
    const report_2 = try h.path("ws/t2/report.json");
    try h.work.write("pr.diff", try h.print(
        "+++ b/src/stale.zig\n+const pinned = \"{s}\";\n+++ b/src/fresh.zig\n+const kept = \"{s}\";\n",
        .{ try sha256Hex(allocator, postinst_1_0), try sha256Hex(allocator, beta_tool) },
    ));
    const diff_2 = try h.repin(&.{ "diff", "--manifest", manifest, "--report", report_2, "--root", tree, "--pr-diff-file", try h.path("pr.diff") }, 0);
    try contains(diff_2.stdout, "  - changed: alpha 1.0 -> 1.1");
    try contains(diff_2.stdout, "  - changed: beta 1.0 -> 1.1");
    try contains(diff_2.stdout, "| `script:alpha/postinst` | changed | amd64: bound bytes changed:");
    try contains(diff_2.stdout, "(behavioral change; review every hunk)");
    try contains(diff_2.stdout, "| `file:beta/usr/bin/beta-tool` | provenance-only |");
    try contains(diff_2.stdout, "| `archive:gamma` | changed |");
    try contains(diff_2.stdout, "| `src/stale.zig` | `identity:script:alpha/postinst` | yes |");
    try contains(diff_2.stdout, "| `src/fresh.zig` | `identity:file:beta/usr/bin/beta-tool` | no |");
    try contains(try h.read("ws/t2/diff.json"), "+mkdir -p /var/lib/alpha");

    const unreviewed = try h.repin(&.{ "record", "--manifest", manifest, "--report", report_2, "--root", tree }, 2);
    try contains(unreviewed.stderr, "reviewed identities changed without re-review: archive:gamma, script:alpha/postinst;");
    const partial = try h.repin(&.{ "record", "--manifest", manifest, "--report", report_2, "--root", tree, "--reviewed", "script:alpha/postinst=" ++ reviewed }, 2);
    try contains(partial.stderr, "changed without re-review: archive:gamma;");
    try std.testing.expectEqualStrings(recorded, try h.read("synthetic-main.pin.json"));
    try contains((try h.repin(&.{
        "record",     "--manifest",                         manifest,     "--report",                   report_2, "--root", tree,
        "--reviewed", "script:alpha/postinst=" ++ reviewed, "--reviewed", "archive:gamma=" ++ reviewed,
    }, 0)).stdout, try h.print("recorded {s}: 0 unchanged, 1 provenance-only, 2 changed, 0 missing", .{try h.timestamp(t2)}));
    const repinned = try h.read("synthetic-main.pin.json");
    try contains(repinned, "\"path\": \"src/fixtures/ubuntu-alpha-postinst\"");
    try contains(repinned, "\"review\": \"#330\"");

    // The tree still pins the old bytes, so the offline check fails until the
    // consumers carry the reviewed identities.
    const stale = try h.repin(&check_args, 1);
    try contains(stale.stderr, "script:alpha/postinst consumer src/fixtures/ubuntu-alpha-postinst bytes do not match");
    try contains(stale.stderr, try h.print("archive:gamma consumer tools/real-snapshot-acceptance.sh does not pin sha512:{s}", .{gamma_2}));
    try contains(stale.stderr, try h.print("URI consumer tools/real-snapshot-acceptance.sh does not pin {s}", .{uri_2}));
    try contains(stale.stderr, "in-tree pin tools/real-snapshot-acceptance.sh:4");
    const member = try h.read("ws/t2/members/script_alpha_postinst@amd64");
    try std.testing.expectEqualStrings(postinst_1_1, member);
    try writeTree(&h, uri_2, member, gamma_2);
    try contains(
        (try h.repin(&check_args, 0)).stdout,
        try h.print("check passed: 3 identities for synthetic-main {s} (probed)", .{try h.timestamp(t2)}),
    );

    const older = try h.probe("synthetic-main", t1, "ws/older", 2);
    try contains(older.stderr, try h.print("is older than the current pin {s}", .{try h.timestamp(t2)}));
}

test "repin: a closure package without a signed SHA-512 archive identity is refused" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const t1 = h.settledDay(2);
    const packages = try snapshotPackages(h.arena(), "1.0", "1.0", "gamma\n", false);
    try h.writeSnapshot("nosha", t1, &.{"stable"}, &packages);
    const profile = try h.writeProfile("synthetic-nosha", "nosha", try h.fingerprint(), bounded);
    try h.writeManifest("synthetic-nosha", profile, t1, "[]", "[]");
    try h.writeDebz("synthetic-nosha", "");
    const refused = try h.probe("synthetic-nosha", t1, "ws/nosha", 2);
    try contains(refused.stderr, "debz plan failed for amd64 (exit 5)");
    try contains(refused.stderr, "native exact lock requires a SHA-512 archive identity");
}

test "repin: an InRelease that changes between the two fetches is refused" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const t1 = h.settledDay(2);
    const packages = try snapshotPackages(h.arena(), "1.0", "1.0", "gamma\n", true);
    try h.writeSnapshot("mutable", t1, &.{"stable"}, &packages);
    const profile = try h.writeProfile("synthetic-mutable", "mutable", try h.fingerprint(), bounded);
    try h.writeManifest("synthetic-mutable", profile, t1, "[]", "[]");
    const in_release = try h.path(try h.print("mutable/{s}/dists/stable/InRelease", .{try h.timestamp(t1)}));
    try h.writeDebz("synthetic-mutable", try h.print(
        "if [ \"$1\" = download ]; then case \" $* \" in *\" arm64 \"*) printf 'republished\\n' >>'{s}' ;; esac; fi",
        .{in_release},
    ));
    const refused = try h.probe("synthetic-mutable", t1, "ws/mutable", 2);
    try contains(refused.stderr, "stable InRelease changed between the first and second fetch");
    try std.testing.expect(!h.exists("ws/mutable/report.json"));
}

test "repin: a Release authenticated by debz under an unreviewed signer is refused" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const t1 = h.settledDay(2);
    const packages = try snapshotPackages(h.arena(), "1.0", "1.0", "gamma\n", true);
    try h.writeSnapshot("signer", t1, &.{"stable"}, &packages);
    const other = "0123456789abcdef0123456789abcdef01234567";
    const profile = try h.writeProfile("synthetic-signer", "signer", other, bounded);
    try h.writeManifest("synthetic-signer", profile, t1, "[]", "[]");
    try h.writeDebz("synthetic-signer", "");
    const refused = try h.probe("synthetic-signer", t1, "ws/signer", 2);
    try contains(refused.stderr, try h.print("stable is signed by ['{s}'], not the reviewed signer", .{try h.fingerprint()}));
    try contains(try h.calls("synthetic-signer"), "plan\n");
}

test "repin: a frozen Release that differs from the reviewed pin is refused before debz runs" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const t1 = h.settledDay(2);
    const packages = try snapshotPackages(h.arena(), "1.0", "1.0", "gamma\n", true);
    try h.writeSnapshot("frozen", t1, &.{ "stable", "stable-updates" }, &packages);
    const profile = try h.writeProfile(
        "synthetic-frozen",
        "frozen",
        try h.fingerprint(),
        "[{\"suite\":\"stable\",\"role\":\"frozen\"},{\"suite\":\"stable-updates\",\"role\":\"witness\"}]",
    );
    try h.writeManifest("synthetic-frozen", profile, t1, "[]", "[]");
    try h.writeDebz("synthetic-frozen", "");
    const refused = try h.probe("synthetic-frozen", t1, "ws/frozen", 2);
    try contains(refused.stderr, "frozen pocket stable Release sha256:");
    try contains(refused.stderr, "differs from the reviewed manifest value; review the Release delta and pass --accept-frozen-release");
    try std.testing.expectEqualStrings("", try h.calls("synthetic-frozen"));
    try std.testing.expect(!h.exists("ws/frozen"));
}

test "repin: offline source evidence defeats matching stale prestate code and manifest" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const t1 = h.settledDay(2);
    const ownership = "/usr/share/alpha/data\n";
    const packages = [_]Package{.{
        .name = "alpha",
        .version = "1.0",
        .files = &.{.{ .name = "./usr/share/alpha/data", .bytes = "alpha\n" }},
    }};
    try h.writeSnapshot("prestate", t1, &.{"stable"}, &packages);
    const profile = try h.writeProfile("synthetic-prestate", "prestate", try h.fingerprint(), bounded);
    const digest = try sha256Hex(h.arena(), ownership);
    const identities = try h.print(
        "[{{\"id\":\"prestate:alpha/var/lib/dpkg/info/alpha.list\",\"kind\":\"prestate\",\"package\":\"alpha\"," ++
            "\"architectures\":[\"amd64\",\"arm64\"],\"path\":\"var/lib/dpkg/info/alpha.list\"," ++
            "\"digest\":\"sha256:{s}\",\"size\":{d},\"mode\":\"0644\",\"version_bound\":false," ++
            "\"derived_from\":[{{\"package\":\"alpha\",\"version\":\"1.0\"}}],\"provenance\":\"pending\"," ++
            "\"consumers\":[{{\"path\":\"src/native_unpack.zig\",\"form\":\"hex\"}}],\"review\":\"#1\"}}]",
        .{ digest, ownership.len },
    );
    try h.writeManifest("synthetic-prestate", profile, t1, "[]", identities);
    try h.writeDebz("synthetic-prestate", "");
    const source = try h.print(
        "const inputs = .{{.{{ .path = \"var/lib/dpkg/info/alpha.list\", .size = {d}, .mode = 0o644, .sha256 = \"{s}\" }}}};\n",
        .{ ownership.len, digest },
    );
    try h.work.write("tree/src/native_unpack.zig", source);
    _ = try h.probe("synthetic-prestate", t1, "ws/prestate", 0);
    const manifest = try h.path("synthetic-prestate.pin.json");
    const tree = try h.path("tree");
    _ = try h.repin(&.{
        "record", "--manifest", manifest, "--report", try h.path("ws/prestate/report.json"), "--root", tree,
    }, 0);
    const calls = try h.calls("synthetic-prestate");
    const check = [_][]const u8{
        "check", "--manifest", manifest, "--root", tree, "--profile", try h.path("synthetic-prestate.profile.json"),
    };
    _ = try h.repin(&check, 0);
    try std.testing.expect(h.exists("tree/tools/fixtures/real-snapshot/prestate-sources-v1.zip"));
    const stale = try sha256Hex(h.arena(), "stale historical list\n");
    _ = try h.run(&.{
        "python3", "-c",
        "import json,sys; p=sys.argv[1]; m=json.load(open(p)); m['identities'][0]['digest']='sha256:'+sys.argv[2]; " ++
            "open(p,'w').write(json.dumps(m))",
        manifest,  stale,
    }, 0);
    try h.work.write("tree/src/native_unpack.zig", try h.print(
        "const inputs = .{{.{{ .path = \"var/lib/dpkg/info/alpha.list\", .size = {d}, .mode = 0o644, .sha256 = \"{s}\" }}}};\n",
        .{ ownership.len, stale },
    ));
    const refused = try h.repin(&check, 1);
    try contains(refused.stderr, "independent source evidence");
    try contains(refused.stderr, "derived bytes disagree");
    try expectAbsent(refused.stderr, "does not pin");
    try expectAbsent(refused.stderr, "in-tree pin");
    try std.testing.expectEqualStrings(calls, try h.calls("synthetic-prestate"));
}

const two_bounded = "[{\"suite\":\"stable\",\"role\":\"bounded\"},{\"suite\":\"stable-security\",\"role\":\"bounded\"}]";

const architectures = [_][]const u8{ "amd64", "arm64" };

/// Asserts that, on each architecture, only the pocket the closure lock names
/// is `exact_lock` and the other is `refresh_only`; returns the summary lines.
fn expectBindings(h: *Harness, report: std.json.Value, pockets: std.json.Value) ![]const u8 {
    var lines: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "stable", "stable-security" }) |suite| {
        var quiet: std.ArrayList([]const u8) = .empty;
        for (architectures) |arch| {
            const closure_pockets = report.object.get("closures").?.object.get(arch).?.object.get("pockets").?.object;
            try std.testing.expectEqual(@as(usize, 1), closure_pockets.count());
            const locked = std.mem.eql(u8, closure_pockets.keys()[0], suite);
            if (!locked) try quiet.append(h.arena(), arch);
            const pocket = for (pockets.array.items) |candidate| {
                if (std.mem.eql(u8, candidate.object.get("suite").?.string, suite)) break candidate;
            } else return error.MissingPocket;
            try std.testing.expectEqualStrings(
                if (locked) "exact_lock" else "refresh_only",
                pocket.object.get("binding").?.object.get(arch).?.string,
            );
        }
        if (quiet.items.len != 0) try lines.print(h.arena(), "- `{s}` (bounded pocket) on {s}\n", .{
            suite, try std.mem.join(h.arena(), ", ", quiet.items),
        });
    }
    try std.testing.expectEqual(@as(usize, 2), pockets.array.items.len);
    return lines.items;
}

/// Probes a two-pocket snapshot and checks that the quiet pocket is reported,
/// not refused, without any extra debz plan, and that record keeps its binding.
fn expectQuietPocket(h: *Harness, name: []const u8, workspace: []const u8, t1: i64) ![]const u8 {
    _ = try h.probe(name, t1, workspace, 0);
    const report_path = try h.print("{s}/report.json", .{workspace});
    const report = try std.json.parseFromSliceLeaky(std.json.Value, h.arena(), try h.read(report_path), .{});
    const lines = try expectBindings(h, report, report.object.get("pockets").?);
    const summary = try h.read(try h.print("{s}/summary.md", .{workspace}));
    try contains(summary, "Pockets that contribute no locked package. `debz refresh` authenticated them");
    try contains(summary, lines);
    // Per architecture: one refresh, one closure plan and one download.
    try std.testing.expectEqualStrings("refresh\nplan\ndownload\nrefresh\nplan\ndownload\n", try h.calls(name));
    for (architectures) |arch| {
        try expectAbsent(try h.read(try h.print("{s}/debz-{s}.jsonl", .{ workspace, arch })), "--default-release");
    }

    const manifest = try h.print("{s}.pin.json", .{name});
    _ = try h.repin(&.{ "record", "--manifest", try h.path(manifest), "--report", try h.path(report_path) }, 0);
    const recorded = try std.json.parseFromSliceLeaky(std.json.Value, h.arena(), try h.read(manifest), .{});
    try std.testing.expectEqualStrings(lines, try expectBindings(h, report, recorded.object.get("snapshot").?.object.get("pockets").?));
    return lines;
}

test "repin: a pocket whose packages are all shadowed is reported, not refused" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const t1 = h.settledDay(2);
    const packages = try snapshotPackages(h.arena(), "1.0", "1.0", "gamma\n", true);
    try h.writeSnapshot("shadow", t1, &.{ "stable", "stable-security" }, &packages);
    const profile = try h.writeProfile("synthetic-shadow", "shadow", try h.fingerprint(), two_bounded);
    try h.writeManifest("synthetic-shadow", profile, t1, "[]", "[]");
    try h.writeDebz("synthetic-shadow", "");
    const lines = try expectQuietPocket(&h, "synthetic-shadow", "ws/shadow", t1);
    // Exactly one pocket is quiet on each architecture.
    for (architectures) |arch| try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, lines, arch));
}

test "repin: an empty pocket is reported, not refused" {
    var h: Harness = undefined;
    try h.init();
    defer h.deinit();
    const t1 = h.settledDay(2);
    const packages = try snapshotPackages(h.arena(), "1.0", "1.0", "gamma\n", true);
    try h.writeSnapshot("empty", t1, &.{"stable"}, &packages);
    try h.writeSnapshot("empty", t1, &.{"stable-security"}, &.{});
    const profile = try h.writeProfile("synthetic-empty", "empty", try h.fingerprint(), two_bounded);
    try h.writeManifest("synthetic-empty", profile, t1, "[]", "[]");
    try h.writeDebz("synthetic-empty", "");
    try std.testing.expectEqualStrings(
        "- `stable-security` (bounded pocket) on amd64, arm64\n",
        try expectQuietPocket(&h, "synthetic-empty", "ws/empty", t1),
    );
}
