const std = @import("std");
const support = @import("tooling-test-support.zig");
const testing = std.testing;

const root_name = "debz-0.1.0-linux-x64";

const Fixture = struct {
    work: support.Work,
    arena: std.heap.ArenaAllocator,

    fn init() !Fixture {
        return .{ .work = try support.Work.init(), .arena = std.heap.ArenaAllocator.init(support.allocator) };
    }

    fn deinit(self: *Fixture) void {
        self.work.deinit();
        self.arena.deinit();
    }

    fn path(self: *Fixture, relative: []const u8) ![]const u8 {
        return std.fmt.allocPrint(self.arena.allocator(), "{s}/{s}", .{ self.work.root, relative });
    }

    fn prefix(self: *Fixture, name: []const u8, machine: u16) ![]const u8 {
        const runtime = try self.source("security/runtime-dependencies.json");
        const digest_policy = try self.source("security/digest-cutover-policy.json");
        const legacy_policy = try self.source("security/legacy-cutover-policy.json");
        var buffer: [256]u8 = @splat(0);
        buffer[0] = 0x7f;
        @memcpy(buffer[1..4], "ELF");
        buffer[4] = 2;
        buffer[5] = 1;
        buffer[6] = 1;
        int(u16, &buffer, 16, 2);
        int(u16, &buffer, 18, machine);
        int(u32, &buffer, 20, 1);
        int(u64, &buffer, 24, 0x400000);
        int(u64, &buffer, 32, 64);
        int(u16, &buffer, 52, 64);
        int(u16, &buffer, 54, 56);
        int(u16, &buffer, 56, 1);
        int(u32, &buffer, 64, 1); // PT_LOAD
        int(u32, &buffer, 68, 5);
        int(u64, &buffer, 80, 0x400000);
        int(u64, &buffer, 88, 0x400000);
        int(u64, &buffer, 96, buffer.len);
        int(u64, &buffer, 104, buffer.len);
        int(u64, &buffer, 112, 0x1000);

        try self.write(name, "bin/debz", &buffer);
        try self.write(name, "share/doc/debz/LICENSE", "Apache-2.0\n");
        try self.write(name, "share/doc/debz/THIRD_PARTY_NOTICES", "libsolv BSD-3-Clause\n");
        try self.write(name, "share/debz/digest-cutover-policy.json", digest_policy);
        try self.write(name, "share/doc/debz/digest-cutover-policy.json", digest_policy);
        try self.write(name, "share/debz/legacy-cutover-policy.json", legacy_policy);
        try self.write(name, "share/doc/debz/legacy-cutover-policy.json", legacy_policy);
        try self.write(name, "share/debz/runtime-dependencies.json", runtime);
        return self.path(name);
    }

    fn write(self: *Fixture, prefix_name: []const u8, relative: []const u8, bytes: []const u8) !void {
        try self.work.write(try std.fmt.allocPrint(self.arena.allocator(), "{s}/{s}", .{ prefix_name, relative }), bytes);
    }

    fn source(self: *Fixture, relative: []const u8) ![]u8 {
        return std.Io.Dir.cwd().readFileAlloc(support.io, relative, self.arena.allocator(), .limited(support.maximum_file_bytes));
    }

    fn package(self: *Fixture, prefix_path: []const u8, destination: []const u8, arch: []const u8) !support.Result {
        _ = self;
        return release(&.{
            "binary",  "--tag", "v0.1.0",   "--prefix",  prefix_path, "--platform", arch,
            "--epoch", "123",   "--output", destination,
        });
    }

    fn audit(self: *Fixture, archive: []const u8, arch: []const u8) !support.Result {
        _ = self;
        return release(&.{ "audit", "--tag", "v0.1.0", "--archive", archive, "--platform", arch });
    }
};

fn int(comptime T: type, buffer: *[256]u8, offset: usize, value: T) void {
    std.mem.writeInt(T, buffer[offset..][0..@sizeOf(T)], value, .little);
}

fn release(args: []const []const u8) !support.Result {
    var argv: [20][]const u8 = undefined;
    argv[0] = "python3";
    argv[1] = "tools/release.py";
    for (args, 0..) |arg, index| argv[index + 2] = arg;
    return support.run(argv[0 .. args.len + 2]);
}

fn packageOk(f: *Fixture, name: []const u8, arch: []const u8, output_name: []const u8) !void {
    const prefix_path = try f.prefix(name, if (std.mem.eql(u8, arch, "linux-x64")) 62 else 183);
    const result = try f.package(prefix_path, try f.path(output_name), arch);
    defer result.deinit();
    try result.ok();
}

fn checkBinaryFailure(f: *Fixture, prefix_path: []const u8, expected: []const u8) !void {
    const result = try f.package(prefix_path, try f.path("rejected"), "linux-x64");
    defer result.deinit();
    try result.failsWith(expected);
}

fn checkAuditFailure(f: *Fixture, relative: []const u8, expected: []const u8) !void {
    const result = try f.audit(try f.path(relative), "linux-x64");
    defer result.deinit();
    try result.failsWith(expected);
}

fn readBinary(f: *Fixture, prefix_name: []const u8) ![]u8 {
    return f.work.read(try std.fmt.allocPrint(f.arena.allocator(), "{s}/bin/debz", .{prefix_name}));
}

const TarEntry = struct {
    name: []const u8,
    bytes: []const u8 = "x",
    kind: u8 = '0',
    mode: usize = 0o644,
    uid: usize = 0,
    mtime: usize = 123,
    uname: []const u8 = "root",
};

fn makeTar(alloc: std.mem.Allocator, entries: []const TarEntry) ![]u8 {
    var archive: std.ArrayList(u8) = .empty;
    for (entries) |entry| {
        if (entry.name.len >= 100) return error.NameTooLong;
        var header: [512]u8 = @splat(0);
        @memcpy(header[0..entry.name.len], entry.name);
        try putOctal(&header, 100, 8, entry.mode);
        try putOctal(&header, 108, 8, entry.uid);
        try putOctal(&header, 116, 8, 0);
        try putOctal(&header, 124, 12, if (entry.kind == '0') entry.bytes.len else 0);
        try putOctal(&header, 136, 12, entry.mtime);
        @memset(header[148..156], ' ');
        header[156] = entry.kind;
        @memcpy(header[257..263], "ustar ");
        @memcpy(header[265 .. 265 + entry.uname.len], entry.uname);
        @memcpy(header[297..301], "root");
        var sum: usize = 0;
        for (header) |byte| sum += byte;
        try putOctal(&header, 148, 8, sum);
        try archive.appendSlice(alloc, &header);
        if (entry.kind == '0') {
            try archive.appendSlice(alloc, entry.bytes);
            const padded = std.mem.alignForward(usize, entry.bytes.len, 512);
            try archive.appendNTimes(alloc, 0, padded - entry.bytes.len);
        }
    }
    try archive.appendNTimes(alloc, 0, 1024);
    return archive.toOwnedSlice(alloc);
}

fn putOctal(header: *[512]u8, offset: usize, length: usize, number: usize) !void {
    @memset(header[offset .. offset + length - 1], '0');
    const digits = try std.fmt.allocPrint(support.allocator, "{o}", .{number});
    defer support.allocator.free(digits);
    if (digits.len >= length) return error.InvalidTarNumber;
    @memcpy(header[offset + length - 1 - digits.len .. offset + length - 1], digits);
}

fn auditSyntheticTar(f: *Fixture, entries: []const TarEntry, expected: []const u8) !void {
    const bytes = try makeTar(f.arena.allocator(), entries);
    try f.work.write("synthetic.tar", bytes);
    const compressed = try support.run(&.{ "gzip", "-n", "-9", try f.path("synthetic.tar") });
    defer compressed.deinit();
    try compressed.ok();
    try checkAuditFailure(f, "synthetic.tar.gz", expected);
    try f.work.directory.dir.deleteFile(support.io, "synthetic.tar.gz");
}

fn decompressedArchive(f: *Fixture) ![]u8 {
    const path = try f.path("assets/debz-0.1.0-linux-x64.tar.gz");
    const uncompressed = try support.run(&.{ "gzip", "-dc", path });
    defer support.allocator.free(uncompressed.stderr);
    try testing.expectEqual(@as(u8, 0), uncompressed.code);
    return uncompressed.stdout;
}

fn tarEntryData(tar: []u8, name: []const u8) ![]u8 {
    var offset: usize = 0;
    while (offset + 512 <= tar.len) {
        const header = tar[offset..][0..512];
        if (header[0] == 0) break;
        const entry_name = std.mem.sliceTo(header[0..100], 0);
        const size_str = std.mem.trim(u8, header[124..136], "\x00 ");
        const size = try std.fmt.parseInt(usize, size_str, 8);
        const data_start = try std.math.add(usize, offset, 512);
        if (size > tar.len - data_start) return error.TruncatedTarEntry;
        if (std.mem.eql(u8, entry_name, name)) return tar[data_start..][0..size];
        offset = try std.math.add(usize, data_start, std.mem.alignForward(usize, size, 512));
    }
    return error.MissingTarEntry;
}

fn compressTar(f: *Fixture, path: []const u8, bytes: []const u8, format: []const u8, level: []const u8) ![]const u8 {
    const relative = try std.fmt.allocPrint(f.arena.allocator(), "{s}.tar", .{path});
    try f.work.write(relative, bytes);
    const input = try f.path(relative);
    if (std.mem.eql(u8, format, "gz")) {
        const option = try std.fmt.allocPrint(f.arena.allocator(), "-{s}", .{level});
        const result = try support.run(&.{ "gzip", "-n", option, input });
        defer result.deinit();
        try result.ok();
        return f.path(try std.fmt.allocPrint(f.arena.allocator(), "{s}.gz", .{relative}));
    }
    const target = try f.path(try std.fmt.allocPrint(f.arena.allocator(), "{s}.xz", .{relative}));
    const result = try support.run(&.{
        "python3",                                                                                                                                                                            "-c",
        "import lzma,pathlib,sys\nsource=pathlib.Path(sys.argv[1]).read_bytes()\npathlib.Path(sys.argv[2]).write_bytes(lzma.compress(source,format=lzma.FORMAT_XZ,preset=int(sys.argv[3])))", input,
        target,                                                                                                                                                                               level,
    });
    defer result.deinit();
    try result.ok();
    return target;
}

fn verifySchemaManifest(directory: std.Io.Dir, manifest: []const u8) !usize {
    var iterator = directory.iterate();
    var count: usize = 0;
    while (try iterator.next(support.io)) |entry| {
        count += 1;
        if (count > 128) return error.TooManySchemas;
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json"))
            return error.NonRegularSchema;
        const quoted = try std.fmt.allocPrint(support.allocator, "\"{s}\"", .{entry.name});
        defer support.allocator.free(quoted);
        if (std.mem.indexOf(u8, manifest, quoted) == null)
            return error.MissingInstallSchema;
        const schema = try directory.readFileAlloc(support.io, entry.name, support.allocator, .limited(1024 * 1024));
        support.allocator.free(schema);
    }
    return count;
}

fn readSchema(work: *support.Work, directory: []const u8, name: []const u8) ![]u8 {
    var dir = try work.directory.dir.openDir(support.io, directory, .{ .iterate = true });
    defer dir.close(support.io);
    var iterator = dir.iterate();
    var count: usize = 0;
    while (try iterator.next(support.io)) |entry| {
        count += 1;
        if (count > 128) return error.TooManySchemas;
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (entry.kind != .file) return error.NonRegularSchema;
        return dir.readFileAlloc(support.io, name, support.allocator, .limited(1024 * 1024));
    }
    return error.MissingInstalledSchema;
}

fn verifySchemaCopies(work: *support.Work, name: []const u8) !void {
    const source = try readSchema(work, "schema", name);
    defer support.allocator.free(source);
    for ([_][]const u8{ "share/debz/schema", "share/doc/debz/schema" }) |directory| {
        const installed = try readSchema(work, directory, name);
        defer support.allocator.free(installed);
        if (!std.mem.eql(u8, source, installed)) return error.InstalledSchemaMismatch;
    }
}

test "release: strict tags, version consistency, and exact four asset names" {
    for ([_][]const u8{ "v0.1.0", "v1.2.3-alpha.1", "v1.2.3-rc.1+build.7" }) |tag| {
        const result = try release(&.{ "version", tag });
        defer result.deinit();
        try result.ok();
        try testing.expectEqualStrings(tag[1..], std.mem.trimEnd(u8, result.stdout, "\n"));
    }
    for ([_][]const u8{ "0.1.0", "v01.2.3", "v1.02.3", "v1.2", "v1.2.3-01", "v1.2.3_foo", "v" }) |tag| {
        const result = try release(&.{ "version", tag });
        defer result.deinit();
        try result.failsWith("invalid release tag");
    }
    const mismatch = try release(&.{ "version", "v0.1.0", "--expect", "build=0.1.1" });
    defer mismatch.deinit();
    try mismatch.failsWith("version mismatch for build");
    const plan = try release(&.{ "dry-run", "--tag", "v0.1.0" });
    defer plan.deinit();
    try plan.ok();
    var parsed = try std.json.parseFromSlice(std.json.Value, support.allocator, plan.stdout, .{});
    defer parsed.deinit();
    const assets = parsed.value.object.get("assets").?.array.items;
    try testing.expectEqual(@as(usize, 4), assets.len);
    try testing.expectEqualStrings("debz-0.1.0-linux-arm64.tar.gz", assets[0].string);
    try testing.expectEqualStrings("debz-0.1.0-linux-x64.tar.xz", assets[3].string);
}

test "release: deterministic gzip and xz archives retain canonical modes, installed policies, and runtime" {
    var f = try Fixture.init();
    defer f.deinit();
    try packageOk(&f, "prefix", "linux-x64", "first");
    const first_gzip = try f.work.read("first/debz-0.1.0-linux-x64.tar.gz");
    defer support.allocator.free(first_gzip);
    const first_xz = try f.work.read("first/debz-0.1.0-linux-x64.tar.xz");
    defer support.allocator.free(first_xz);
    const bin_path = try f.path("prefix/bin/debz");
    const touch = try support.run(&.{ "touch", "-m", "-d", "@9999", bin_path });
    defer touch.deinit();
    try touch.ok();
    const result = try f.package(try f.path("prefix"), try f.path("second"), "linux-x64");
    defer result.deinit();
    try result.ok();
    const second_gzip = try f.work.read("second/debz-0.1.0-linux-x64.tar.gz");
    defer support.allocator.free(second_gzip);
    const second_xz = try f.work.read("second/debz-0.1.0-linux-x64.tar.xz");
    defer support.allocator.free(second_xz);
    try testing.expectEqualSlices(u8, first_gzip, second_gzip);
    try testing.expectEqualSlices(u8, first_xz, second_xz);
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0x8b, 8, 0, 0, 0, 0, 0 }, first_gzip[0..8]);
    try testing.expectEqualSlices(u8, &.{ 0xfd, '7', 'z', 'X', 'Z', 0 }, first_xz[0..6]);
    const audited = try f.audit(try f.path("first/debz-0.1.0-linux-x64.tar.gz"), "linux-x64");
    defer audited.deinit();
    try audited.ok();
}

test "release: missing and divergent installed licenses, cutover policies, and runtime are rejected" {
    var f = try Fixture.init();
    defer f.deinit();
    const missing = try f.prefix("missing", 62);
    try f.work.directory.dir.deleteFile(support.io, "missing/share/doc/debz/LICENSE");
    try checkBinaryFailure(&f, missing, "missing required files");
    const missing_policy = try f.prefix("missing-policy", 62);
    try f.work.directory.dir.deleteFile(support.io, "missing-policy/share/debz/digest-cutover-policy.json");
    try checkBinaryFailure(&f, missing_policy, "missing required files");
    const different = try f.prefix("different", 62);
    try f.write("different", "share/doc/debz/legacy-cutover-policy.json", "{}");
    try checkBinaryFailure(&f, different, "policy copies differ");
    const previous = try f.prefix("previous", 62);
    const previous_runtime = try f.source("security/runtime-dependencies.json");
    const libc = std.mem.indexOf(u8, previous_runtime, "\"musl\"") orelse return error.MissingLibcMetadata;
    @memcpy(previous_runtime[libc + 1 .. libc + 5], "evil");
    try f.write("previous", "share/debz/runtime-dependencies.json", previous_runtime);
    try checkBinaryFailure(&f, previous, "differs from reviewed policy");
    const forbidden_license = try f.prefix("forbidden-license", 62);
    const policy = try f.path("bad-policy.json");
    try f.work.write("bad-policy.json", "{\"allowed_production_licenses\":[\"MIT\"],\"production_dependencies\":[{\"name\":\"unsafe\",\"version\":\"1\"}]}");
    const license = try release(&.{
        "binary",  "--tag", "v0.1.0",   "--prefix",               forbidden_license, "--platform", "linux-x64",
        "--epoch", "123",   "--output", try f.path("bad-output"), "--policy",        policy,
    });
    defer license.deinit();
    try license.failsWith("dependency is missing a name or license");
}

test "release: ELF architecture, dynamic loader, needed libraries, and malformed headers refuse packaging" {
    var f = try Fixture.init();
    defer f.deinit();
    const wrong = try f.prefix("wrong", 183);
    try checkBinaryFailure(&f, wrong, "does not match linux-x64");
    var invalid = try readBinary(&f, "wrong");
    defer support.allocator.free(invalid);
    int(u16, @ptrCast(invalid.ptr), 18, 62);
    invalid[5] = 0;
    try f.write("wrong", "bin/debz", invalid);
    try checkBinaryFailure(&f, wrong, "unsupported ELF encoding");
    invalid[5] = 1;
    try f.write("wrong", "bin/debz", invalid[0..63]);
    try checkBinaryFailure(&f, wrong, "not an ELF64 executable");
    try f.write("wrong", "bin/debz", invalid);
    int(u64, @ptrCast(invalid.ptr), 32, 264);
    try f.write("wrong", "bin/debz", invalid);
    try checkBinaryFailure(&f, wrong, "malformed ELF program header table");
    int(u64, @ptrCast(invalid.ptr), 32, 64);
    int(u16, @ptrCast(invalid.ptr), 56, 2);
    int(u32, @ptrCast(invalid.ptr), 120, 3); // PT_INTERP
    try f.write("wrong", "bin/debz", invalid);
    try checkBinaryFailure(&f, wrong, "PT_INTERP");
    int(u32, @ptrCast(invalid.ptr), 120, 2); // PT_DYNAMIC
    int(u64, @ptrCast(invalid.ptr), 128, 192);
    int(u64, @ptrCast(invalid.ptr), 136, 0x400000 + 192);
    int(u64, @ptrCast(invalid.ptr), 144, 0x400000 + 192);
    int(u64, @ptrCast(invalid.ptr), 152, 32);
    int(u64, @ptrCast(invalid.ptr), 160, 32);
    int(u64, @ptrCast(invalid.ptr), 192, 1); // DT_NEEDED
    try f.write("wrong", "bin/debz", invalid);
    try checkBinaryFailure(&f, wrong, "DT_NEEDED");
    int(u64, @ptrCast(invalid.ptr), 192, 0);
    int(u64, @ptrCast(invalid.ptr), 136, 0x400000 + 224); // decoy file vs virtual mapping
    int(u64, @ptrCast(invalid.ptr), 224, 1);
    try f.write("wrong", "bin/debz", invalid);
    try checkBinaryFailure(&f, wrong, "PT_DYNAMIC");
    int(u64, @ptrCast(invalid.ptr), 136, 0x400000 + 192);
    int(u64, @ptrCast(invalid.ptr), 152, 17);
    int(u64, @ptrCast(invalid.ptr), 160, 17);
    try f.write("wrong", "bin/debz", invalid);
    try checkBinaryFailure(&f, wrong, "malformed PT_DYNAMIC");
}

test "release: symlinks, special files, cache paths and credential markers refuse packaging" {
    var f = try Fixture.init();
    defer f.deinit();
    const prefix = try f.prefix("unsafe", 62);
    try f.work.directory.dir.symLink(support.io, "LICENSE", "unsafe/share/doc/debz/linked", .{});
    try checkBinaryFailure(&f, prefix, "symlink");
    try f.work.directory.dir.deleteFile(support.io, "unsafe/share/doc/debz/linked");
    const fifo = try support.run(&.{ "mkfifo", try f.path("unsafe/share/debz/pipe") });
    defer fifo.deinit();
    try fifo.ok();
    try checkBinaryFailure(&f, prefix, "special file");
    try f.work.directory.dir.deleteFile(support.io, "unsafe/share/debz/pipe");
    try f.write("unsafe", ".git/HEAD", "ref: heads/main");
    try checkBinaryFailure(&f, prefix, "forbidden generated/cache path");
    try f.work.directory.dir.deleteFile(support.io, "unsafe/.git/HEAD");
    try f.write("unsafe", "share/debz/extra.pyc", "generated");
    try checkBinaryFailure(&f, prefix, "forbidden generated/cache path");
    try f.work.directory.dir.deleteFile(support.io, "unsafe/share/debz/extra.pyc");
    try f.write("unsafe", "share/debz/credential.txt", "-----BEGIN " ++ "PRIVATE KEY-----\nsecret\n");
    try checkBinaryFailure(&f, prefix, "possible secret");
}

test "release: archive container corruption, trailing bytes, and noncanonical gzip metadata are rejected" {
    var f = try Fixture.init();
    defer f.deinit();
    try packageOk(&f, "prefix", "linux-x64", "output");
    for ([_][]const u8{ "tar.gz", "tar.xz" }) |suffix| {
        const archive = try std.fmt.allocPrint(f.arena.allocator(), "output/{s}.{s}", .{ root_name, suffix });
        const bytes = try f.work.read(archive);
        defer support.allocator.free(bytes);
        bytes[bytes.len - 1] ^= 1;
        const corrupt = if (std.mem.eql(u8, suffix, "tar.gz")) "corrupt.tar.gz" else "corrupt.tar.xz";
        try f.work.write(corrupt, bytes);
        const invalid = try f.audit(try f.path(corrupt), "linux-x64");
        defer invalid.deinit();
        try invalid.failsWith(if (std.mem.eql(u8, suffix, "tar.gz"))
            "invalid compressed archive"
        else
            "cannot read archive");
        try support.contains(invalid.stderr, corrupt);
        bytes[bytes.len - 1] ^= 1;
        const trailing = try f.arena.allocator().alloc(u8, bytes.len + 4);
        @memcpy(trailing[0..bytes.len], bytes);
        @memcpy(trailing[bytes.len..], "junk");
        const path = if (std.mem.eql(u8, suffix, "tar.gz")) "trailing.tar.gz" else "trailing.tar.xz";
        try f.work.write(path, trailing);
        try checkAuditFailure(&f, path, if (std.mem.eql(u8, suffix, "tar.gz"))
            "gzip stream has trailing data"
        else
            "xz stream has trailing data");
    }
    const gzip = try f.work.read("output/debz-0.1.0-linux-x64.tar.gz");
    defer support.allocator.free(gzip);
    gzip[4] = 123;
    try f.work.write("timestamp.tar.gz", gzip);
    try checkAuditFailure(&f, "timestamp.tar.gz", "timestamp is not canonical");
    const wrong_format = try f.work.read("output/debz-0.1.0-linux-x64.tar.gz");
    defer support.allocator.free(wrong_format);
    try f.work.write("wrong.tar.xz", wrong_format);
    try checkAuditFailure(&f, "wrong.tar.xz", "not xz");
}

test "release: portable compression levels are accepted but noncanonical tar payloads are refused" {
    var f = try Fixture.init();
    defer f.deinit();
    try packageOk(&f, "prefix", "linux-x64", "assets");
    const tar = try decompressedArchive(&f);
    defer support.allocator.free(tar);
    for ([_][]const u8{ "1", "9" }) |level| {
        for ([_][]const u8{ "gz", "xz" }) |format| {
            const path = try compressTar(&f, try std.fmt.allocPrint(f.arena.allocator(), "portable-{s}-{s}", .{ format, level }), tar, format, level);
            const audited = try f.audit(path, "linux-x64");
            defer audited.deinit();
            try audited.ok();
        }
    }
    const extra = try f.arena.allocator().alloc(u8, tar.len + 512);
    @memcpy(extra[0..tar.len], tar);
    @memset(extra[tar.len..], 0);
    for ([_][]const u8{ "gz", "xz" }) |format| {
        const path = try compressTar(&f, try std.fmt.allocPrint(f.arena.allocator(), "noncanonical-{s}", .{format}), extra, format, "9");
        const audited = try f.audit(path, "linux-x64");
        defer audited.deinit();
        try audited.failsWith("decompressed tar payload is not canonical");
    }
}

test "release: archived binary architecture, dynamic dependencies and runtime are revalidated" {
    var f = try Fixture.init();
    defer f.deinit();
    try packageOk(&f, "prefix", "linux-x64", "assets");
    const original = try decompressedArchive(&f);
    defer support.allocator.free(original);
    const binary_name = root_name ++ "/bin/debz";
    const runtime_name = root_name ++ "/share/debz/runtime-dependencies.json";
    for ([_][]const u8{ "architecture", "runtime", "needed" }) |mutation| {
        const tar = try f.arena.allocator().dupe(u8, original);
        const binary = try tarEntryData(tar, binary_name);
        if (std.mem.eql(u8, mutation, "architecture")) {
            std.mem.writeInt(u16, binary[18..20], 183, .little);
        } else if (std.mem.eql(u8, mutation, "runtime")) {
            const manifest = try tarEntryData(tar, runtime_name);
            const libc = std.mem.indexOf(u8, manifest, "\"musl\"") orelse return error.MissingRuntimeLibc;
            @memcpy(manifest[libc + 1 .. libc + 5], "evil");
        } else {
            std.mem.writeInt(u16, binary[56..58], 2, .little);
            std.mem.writeInt(u32, binary[120..124], 2, .little);
            std.mem.writeInt(u64, binary[128..136], 192, .little);
            std.mem.writeInt(u64, binary[136..144], 0x400000 + 192, .little);
            std.mem.writeInt(u64, binary[144..152], 0x400000 + 192, .little);
            std.mem.writeInt(u64, binary[152..160], 32, .little);
            std.mem.writeInt(u64, binary[160..168], 32, .little);
            std.mem.writeInt(u64, binary[192..200], 1, .little);
        }
        const path = try compressTar(&f, mutation, tar, "gz", "9");
        const audited = try f.audit(path, "linux-x64");
        defer audited.deinit();
        try audited.failsWith(if (std.mem.eql(u8, mutation, "architecture"))
            "does not match"
        else if (std.mem.eql(u8, mutation, "runtime"))
            "differs from reviewed policy"
        else
            "DT_NEEDED");
    }
}

test "release: traversal, duplicate, link, special-file, mode, order, and install-path archive mutations fail with diagnostics" {
    var f = try Fixture.init();
    defer f.deinit();
    try auditSyntheticTar(&f, &.{.{ .name = "../escape" }}, "unsafe archive path");
    try auditSyntheticTar(&f, &.{ .{ .name = "root/file" }, .{ .name = "root/file" } }, "duplicate archive entry");
    try auditSyntheticTar(&f, &.{.{ .name = "root/link", .kind = '2' }}, "archive contains a link");
    try auditSyntheticTar(&f, &.{.{ .name = "root/device", .kind = '3' }}, "special file");
    try auditSyntheticTar(&f, &.{.{ .name = "root/file", .mode = 0o777 }}, "non-canonical mode");
    try auditSyntheticTar(&f, &.{ .{ .name = "root/z" }, .{ .name = "root/a" } }, "not sorted");
    try auditSyntheticTar(&f, &.{.{ .name = "root/file", .uid = 1 }}, "non-canonical ownership");
    try auditSyntheticTar(&f, &.{ .{ .name = "root/a" }, .{ .name = "root/b", .mtime = 124 } }, "archive timestamps differ");
    try auditSyntheticTar(&f, &.{.{ .name = "root/.git/HEAD" }}, "forbidden archive path");
    try auditSyntheticTar(&f, &.{.{ .name = "root/secret", .bytes = "-----BEGIN " ++ "PRIVATE KEY-----" }}, "possible secret");
}

test "release: complete archive with unexpected installation path is rejected after required-file checks" {
    var f = try Fixture.init();
    defer f.deinit();
    _ = try f.prefix("prefix", 62);
    const binary = try f.work.read("prefix/bin/debz");
    defer support.allocator.free(binary);
    const prefix = root_name ++ "/";
    try auditSyntheticTar(&f, &.{
        .{ .name = prefix ++ "bin/debz", .bytes = binary, .mode = 0o755 },
        .{ .name = prefix ++ "share/debz/digest-cutover-policy.json", .bytes = try f.source("security/digest-cutover-policy.json") },
        .{ .name = prefix ++ "share/debz/legacy-cutover-policy.json", .bytes = try f.source("security/legacy-cutover-policy.json") },
        .{ .name = prefix ++ "share/debz/runtime-dependencies.json", .bytes = try f.source("security/runtime-dependencies.json") },
        .{ .name = prefix ++ "share/doc/debz/LICENSE", .bytes = "Apache-2.0\n" },
        .{ .name = prefix ++ "share/doc/debz/THIRD_PARTY_NOTICES", .bytes = "libsolv BSD-3-Clause\n" },
        .{ .name = prefix ++ "share/doc/debz/digest-cutover-policy.json", .bytes = try f.source("security/digest-cutover-policy.json") },
        .{ .name = prefix ++ "share/doc/debz/legacy-cutover-policy.json", .bytes = try f.source("security/legacy-cutover-policy.json") },
        .{ .name = prefix ++ "z/passwd" },
    }, "unexpected install path");
}

test "release: every document and schema is named by release-install manifest and installed schemas match source" {
    const build = try std.Io.Dir.cwd().readFileAlloc(support.io, "build.zig", support.allocator, .limited(256 * 1024));
    defer support.allocator.free(build);
    const docs_start = std.mem.indexOf(u8, build, "const docs = [_][]const u8{") orelse return error.MissingInstallDocuments;
    const docs_end = std.mem.indexOfPos(u8, build, docs_start, "};") orelse return error.MissingInstallDocuments;
    const docs = build[docs_start..docs_end];
    const schemas_start = std.mem.indexOf(u8, build, "const schemas = [_][]const u8{") orelse return error.MissingInstallSchemas;
    const schemas_end = std.mem.indexOfPos(u8, build, schemas_start, "};") orelse return error.MissingInstallSchemas;
    const schemas = build[schemas_start..schemas_end];
    var doc_dir = try std.Io.Dir.cwd().openDir(support.io, "doc", .{ .iterate = true });
    defer doc_dir.close(support.io);
    var doc_count: usize = 0;
    var seen_entries: usize = 0;
    var doc_iterator = doc_dir.iterate();
    while (try doc_iterator.next(support.io)) |item| {
        seen_entries += 1;
        if (seen_entries > 256) return error.TooManyDocuments;
        if (!std.mem.endsWith(u8, item.name, ".md")) continue;
        try testing.expect(item.kind == .file);
        const quoted = try std.fmt.allocPrint(support.allocator, "\"{s}\"", .{item.name});
        defer support.allocator.free(quoted);
        try support.contains(docs, quoted);
        doc_count += 1;
    }
    try testing.expect(doc_count > 30);
    var schema_dir = try std.Io.Dir.cwd().openDir(support.io, "schema", .{ .iterate = true });
    defer schema_dir.close(support.io);
    const schema_count = try verifySchemaManifest(schema_dir, schemas);
    try testing.expect(schema_count > 70);
    try testing.expectEqual(schema_count, std.mem.count(u8, schemas, ".json\""));
    const marker = "\"root-mutation-journal-v1.json\"";
    const marker_start = std.mem.indexOf(u8, schemas, marker) orelse return error.MissingInstallSchema;
    const missing = try std.fmt.allocPrint(support.allocator, "{s}{s}", .{
        schemas[0..marker_start], schemas[marker_start + marker.len ..],
    });
    defer support.allocator.free(missing);
    try testing.expectError(error.MissingInstallSchema, verifySchemaManifest(schema_dir, missing));

    var f = try Fixture.init();
    defer f.deinit();
    for ([_][]const u8{ "root-mutation-journal-v1.json", "native-repository-unchanged-v1.json" }) |name| {
        const source = try f.source(try std.fmt.allocPrint(f.arena.allocator(), "schema/{s}", .{name}));
        try f.work.write(try std.fmt.allocPrint(f.arena.allocator(), "schema/{s}", .{name}), source);
        for ([_][]const u8{ "share/debz/schema", "share/doc/debz/schema" }) |directory| {
            try f.work.write(try std.fmt.allocPrint(f.arena.allocator(), "{s}/{s}", .{ directory, name }), source);
        }
        try verifySchemaCopies(&f.work, name);
    }
    const journal = "root-mutation-journal-v1.json";
    try f.work.write("share/debz/schema/" ++ journal, "{}");
    try testing.expectError(error.InstalledSchemaMismatch, verifySchemaCopies(&f.work, journal));
    try f.work.write("share/debz/schema/" ++ journal, try f.source("schema/" ++ journal));
    try f.work.write("share/doc/debz/schema/" ++ journal, "{}");
    try testing.expectError(error.InstalledSchemaMismatch, verifySchemaCopies(&f.work, journal));
    try f.work.directory.dir.deleteFile(support.io, "share/doc/debz/schema/" ++ journal);
    try testing.expectError(error.MissingInstalledSchema, verifySchemaCopies(&f.work, journal));
    try f.work.directory.dir.symLink(support.io, "../../../schema/" ++ journal, "share/doc/debz/schema/" ++ journal, .{});
    try testing.expectError(error.NonRegularSchema, verifySchemaCopies(&f.work, journal));

    const layout = try std.Io.Dir.cwd().readFileAlloc(support.io, "tools/test-release-install.sh", support.allocator, .limited(32 * 1024));
    defer support.allocator.free(layout);
    try support.contains(layout, "installed documents differ from doc/*.md");
    try support.contains(layout, "cmp \"$schema\" \"$destination/$schema\"");
}

test "release: complete x64/arm64 verification rejects forbidden sidecars and nonregular assets" {
    var f = try Fixture.init();
    defer f.deinit();
    try packageOk(&f, "x64", "linux-x64", "assets");
    try packageOk(&f, "arm", "linux-arm64", "assets");
    const directory = try f.path("assets");
    const verify_args = &.{ "verify", "--tag", "v0.1.0", "--assets", directory };
    const valid = try release(verify_args);
    defer valid.deinit();
    try valid.ok();
    try support.contains(valid.stdout, "verified 4 release assets");
    for ([_][]const u8{
        "debz-0.1.0-linux-x64.tar.gz.sha256", "debz-0.1.0-linux-x64.tar.gz.spdx.json",
        "debz-0.1.0-release-manifest.json",   "debz-0.1.0-source.tar.gz",
    }) |name| {
        const relative = try std.fmt.allocPrint(f.arena.allocator(), "assets/{s}", .{name});
        try f.work.write(relative, "forbidden");
        const extra = try release(verify_args);
        defer extra.deinit();
        try extra.failsWith("forbidden");
        try f.work.directory.dir.deleteFile(support.io, relative);
    }
    try f.work.directory.dir.symLink(support.io, "debz-0.1.0-linux-x64.tar.gz", "assets/linked", .{});
    const linked = try release(verify_args);
    defer linked.deinit();
    try linked.failsWith("non-regular entry");
}
