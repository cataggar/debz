const std = @import("std");
const builtin = @import("builtin");
const debz = @import("debz");
const c = @cImport({
    @cInclude("lzma.h");
});

const Platform = enum {
    @"linux-x64",
    @"linux-arm64",

    fn parse(name: []const u8) !Platform {
        return std.meta.stringToEnum(Platform, name) orelse refuse("unsupported release platform", .{});
    }

    fn machine(self: Platform) u16 {
        return if (self == .@"linux-x64") 62 else 183;
    }
};

fn refuse(comptime message: []const u8, args: anytype) error{InvalidReleaseInput} {
    if (!builtin.is_test) std.log.err("release: " ++ message, args);
    return error.InvalidReleaseInput;
}

fn decimalDigits(bytes: []const u8) bool {
    var iterator = std.unicode.Utf8Iterator{ .bytes = bytes, .i = 0 };
    while (iterator.nextCodepoint()) |codepoint| {
        // Preserve the original Python regex's Unicode 16 decimal-digit matching.
        const zeroes = [_]u21{
            0x30,    0x660,   0x6f0,   0x7c0,   0x966,   0x9e6,   0xa66,   0xae6,
            0xb66,   0xbe6,   0xc66,   0xce6,   0xd66,   0xde6,   0xe50,   0xed0,
            0xf20,   0x1040,  0x1090,  0x17e0,  0x1810,  0x1946,  0x19d0,  0x1a80,
            0x1a90,  0x1b50,  0x1bb0,  0x1c40,  0x1c50,  0xa620,  0xa8d0,  0xa900,
            0xa9d0,  0xa9f0,  0xaa50,  0xabf0,  0xff10,  0x104a0, 0x10d30, 0x10d40,
            0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650,
            0x116c0, 0x116d0, 0x116da, 0x11730, 0x118e0, 0x11950, 0x11bf0, 0x11c50,
            0x11d50, 0x11da0, 0x11f50, 0x16130, 0x16a60, 0x16ac0, 0x16b50, 0x16d70,
            0x1ccf0, 0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0,
            0x1e4f0, 0x1e5f1, 0x1e950, 0x1fbf0,
        };
        const found = for (zeroes) |zero| {
            if (codepoint >= zero and codepoint - zero < 10) break true;
        } else false;
        if (!found) return false;
    }
    return true;
}

fn numeric(bytes: []const u8) bool {
    return std.mem.eql(u8, bytes, "0") or
        (bytes.len != 0 and bytes[0] >= '1' and bytes[0] <= '9' and decimalDigits(bytes[1..]));
}

fn asciiIdentifier(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    for (bytes) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-') return false;
    return true;
}

pub fn parseTag(tag: []const u8) ![]const u8 {
    if (tag.len < 2 or tag[0] != 'v' or !std.unicode.utf8ValidateSlice(tag)) return error.InvalidReleaseTag;
    const version = tag[1..];
    var core_and_metadata = std.mem.splitScalar(u8, version, '+');
    const core_and_prerelease = core_and_metadata.first();
    if (core_and_metadata.next()) |metadata| {
        var identifiers = std.mem.splitScalar(u8, metadata, '.');
        while (identifiers.next()) |identifier| if (!asciiIdentifier(identifier)) return error.InvalidReleaseTag;
        if (core_and_metadata.next() != null) return error.InvalidReleaseTag;
    }
    const dash = std.mem.indexOfScalar(u8, core_and_prerelease, '-');
    const core = core_and_prerelease[0 .. dash orelse core_and_prerelease.len];
    var fields = std.mem.splitScalar(u8, core, '.');
    for (0..3) |_| if (!numeric(fields.next() orelse return error.InvalidReleaseTag)) return error.InvalidReleaseTag;
    if (fields.next() != null) return error.InvalidReleaseTag;
    if (dash) |offset| {
        var identifiers = std.mem.splitScalar(u8, core_and_prerelease[offset + 1 ..], '.');
        while (identifiers.next()) |identifier| {
            if (numeric(identifier)) continue;
            if (!asciiIdentifier(identifier) or (!std.ascii.isAlphabetic(identifier[0]) and identifier[0] != '-'))
                return error.InvalidReleaseTag;
        }
    }
    return version;
}

fn region(bytes: []const u8, offset: u64, length: u64, comptime description: []const u8) ![]const u8 {
    if (offset > bytes.len or length > bytes.len - offset)
        return refuse("malformed ELF " ++ description ++ " offset or size", .{});
    return bytes[@intCast(offset)..][0..@intCast(length)];
}

fn addressEnd(address: u64, size: u64, comptime description: []const u8) !u64 {
    return std.math.add(u64, address, size) catch
        refuse("malformed ELF " ++ description ++ " address or size", .{});
}

fn integer(comptime T: type, bytes: []const u8, offset: usize) T {
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .little);
}

const Load = struct {
    file_start: u64,
    file_end: u64,
    virtual_start: u64,
    virtual_file_end: u64,
    virtual_memory_end: u64,
};

const Dynamic = struct { offset: u64, address: u64, size: u64, memory_size: u64 };

const maximum_tar_bytes = 256 * 1024 * 1024;
const maximum_entries = 4096;
const Entry = struct { name: []const u8, bytes: ?[]const u8, mode: u32 };
const maximum_compressed_bytes = maximum_tar_bytes + 16 * 1024 * 1024;

const Format = enum {
    @"tar.gz",
    @"tar.xz",

    fn parse(value: []const u8) !Format {
        return std.meta.stringToEnum(Format, value) orelse refuse("unsupported archive format: {s}", .{value});
    }
};

fn compressTar(allocator: std.mem.Allocator, input: []const u8, format: Format) ![]u8 {
    if (input.len > maximum_tar_bytes) return refuse("release payload exceeds the bounded256MiB limit", .{});
    if (format == .@"tar.gz") {
        const bound = @min(maximum_compressed_bytes, input.len + input.len / 16 + 8192);
        const output = try allocator.alloc(u8, bound);
        errdefer allocator.free(output);
        var writer = std.Io.Writer.fixed(output);
        const history = try allocator.alloc(u8, std.compress.flate.max_window_len);
        defer allocator.free(history);
        var encoder = try std.compress.flate.Compress.init(&writer, history, .gzip, .best);
        try encoder.writer.writeAll(input);
        try encoder.finish();
        output[8] = 2;
        output[9] = 255;
        return allocator.realloc(output, writer.end);
    }
    if (c.lzma_easy_encoder_memusage(9) > 1024 * 1024 * 1024)
        return refuse("release XZ encoder exceeds its memory limit", .{});
    var stream = std.mem.zeroes(c.lzma_stream);
    const initialized = c.lzma_easy_encoder(&stream, 9, c.LZMA_CHECK_CRC64);
    if (initialized != c.LZMA_OK) return refuse("release XZ encoder initialization failed: {d}", .{initialized});
    defer c.lzma_end(&stream);
    stream.next_in = input.ptr;
    stream.avail_in = input.len;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    var chunk: [16 * 1024]u8 = undefined;
    while (true) {
        const before = stream.avail_in;
        stream.next_out = &chunk;
        stream.avail_out = chunk.len;
        const result = c.lzma_code(&stream, c.LZMA_FINISH);
        const produced = chunk.len - stream.avail_out;
        if (produced > maximum_compressed_bytes - output.items.len)
            return refuse("release compressed payload exceeds its limit", .{});
        try output.appendSlice(allocator, chunk[0..produced]);
        if (result == c.LZMA_STREAM_END) {
            if (stream.avail_in != 0) return refuse("release XZ encoder left unconsumed input", .{});
            return output.toOwnedSlice(allocator);
        }
        if (result != c.LZMA_OK or (produced == 0 and before == stream.avail_in))
            return refuse("release XZ encoder failed: {d}", .{result});
    }
}

fn decompressedTar(allocator: std.mem.Allocator, input: []const u8, name: []const u8) ![]u8 {
    const format: debz.metadata_decompression.Compression = if (std.mem.endsWith(u8, name, ".tar.gz")) blk: {
        if (input.len < 18 or !std.mem.eql(u8, input[0..3], "\x1f\x8b\x08"))
            return refuse("archive is not gzip: {s}", .{name});
        if (input[3] != 0) return refuse("gzip header is not canonical: {s}", .{name});
        if (!std.mem.allEqual(u8, input[4..8], 0)) return refuse("gzip timestamp is not canonical: {s}", .{name});
        break :blk .gzip;
    } else if (std.mem.endsWith(u8, name, ".tar.xz")) blk: {
        if (!std.mem.startsWith(u8, input, "\xfd7zXZ\x00"))
            return refuse("archive is not xz: {s}", .{name});
        break :blk .xz;
    } else return refuse("unsupported archive format: {s}", .{name});
    return debz.metadata_decompression.decompress(allocator, format, input, .{
        .maximum_compressed_bytes = maximum_compressed_bytes,
        .maximum_decompressed_bytes = maximum_tar_bytes,
        .maximum_decoder_memory = 256 * 1024 * 1024,
    }) catch |err| switch (err) {
        error.Truncated => refuse("{s} stream is incomplete: {s}", .{ @tagName(format), name }),
        error.TrailingData => refuse("{s} stream has trailing data: {s}", .{ @tagName(format), name }),
        else => refuse("invalid compressed archive {s}: {s}", .{ name, @errorName(err) }),
    };
}

fn tarNumber(field: []u8, value: i64) !void {
    if (value < 0 or @as(u64, @intCast(value)) >= (@as(u64, 1) << @intCast(3 * (field.len - 1)))) {
        @memset(field, if (value < 0) 0xff else 0);
        std.mem.writeInt(i64, field[field.len - 8 ..][0..8], value, .big);
        field[0] = if (value < 0) 0xff else 0x80;
        return;
    }
    @memset(field, '0');
    field[field.len - 1] = 0;
    var remaining: u64 = @intCast(value);
    var offset = field.len - 1;
    while (remaining != 0) {
        offset -= 1;
        field[offset] = '0' + @as(u8, @intCast(remaining & 7));
        remaining >>= 3;
    }
}

fn tarHeader(name: []const u8, mode: u32, epoch: i64, size: usize, kind: u8, long_name: bool) ![512]u8 {
    var header: [512]u8 = @splat(0);
    @memcpy(header[0..@min(name.len, 100)], name[0..@min(name.len, 100)]);
    try tarNumber(header[100..108], mode);
    try tarNumber(header[108..116], 0);
    try tarNumber(header[116..124], 0);
    try tarNumber(header[124..136], @intCast(size));
    try tarNumber(header[136..148], epoch);
    @memset(header[148..156], ' ');
    header[156] = kind;
    @memcpy(header[257..265], "ustar  \x00");
    if (!long_name) {
        @memcpy(header[265..269], "root");
        @memcpy(header[297..301], "root");
    }
    var sum: u64 = 0;
    for (header) |byte| sum += byte;
    try tarNumber(header[148..155], @intCast(sum));
    header[155] = ' ';
    return header;
}

fn appendTar(allocator: std.mem.Allocator, output: *std.ArrayList(u8), bytes: []const u8) !void {
    if (bytes.len > maximum_tar_bytes - output.items.len)
        return refuse("release tar exceeds the bounded256MiB payload limit", .{});
    try output.appendSlice(allocator, bytes);
}

fn paddedData(allocator: std.mem.Allocator, output: *std.ArrayList(u8), bytes: []const u8) !void {
    try appendTar(allocator, output, bytes);
    const padding = std.mem.alignForward(usize, bytes.len, 512) - bytes.len;
    const zeroes: [512]u8 = @splat(0);
    try appendTar(allocator, output, zeroes[0..padding]);
}

fn validateArchiveName(name: []const u8) !void {
    if (name.len == 0 or name.len > 4096 or name[0] == '/' or
        std.mem.indexOfAny(u8, name, "\x00\\") != null or !std.unicode.utf8ValidateSlice(name))
        return refuse("unsafe archive path: {s}", .{name});
    var components = std.mem.splitScalar(u8, name, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return refuse("unsafe archive path: {s}", .{name});
    }
}

pub fn buildTar(allocator: std.mem.Allocator, entries: []const Entry, epoch: i64) ![]u8 {
    if (entries.len > maximum_entries) return refuse("too many release archive entries", .{});
    var records: std.ArrayList(Entry) = .empty;
    defer records.deinit(allocator);
    var directories = std.StringHashMap(void).init(allocator);
    defer directories.deinit();
    for (entries) |entry| {
        try validateArchiveName(entry.name);
        for (entry.name, 0..) |byte, index| if (byte == '/') {
            if (directories.count() == maximum_entries) return refuse("too many release archive directories", .{});
            try directories.put(entry.name[0..index], {});
        };
    }
    var iterator = directories.keyIterator();
    while (iterator.next()) |name| try records.append(allocator, .{ .name = name.*, .bytes = null, .mode = 0o755 });
    try records.appendSlice(allocator, entries);
    std.mem.sort(Entry, records.items, {}, struct {
        fn less(_: void, left: Entry, right: Entry) bool {
            return std.mem.lessThan(u8, left.name, right.name);
        }
    }.less);
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    for (records.items) |entry| {
        const name = if (entry.bytes == null) try std.mem.concat(allocator, u8, &.{ entry.name, "/" }) else entry.name;
        defer if (entry.bytes == null) allocator.free(name);
        if (name.len > 100) {
            const header = try tarHeader("././@LongLink", 0, 0, name.len + 1, 'L', true);
            try appendTar(allocator, &output, &header);
            const terminated = try std.mem.concat(allocator, u8, &.{ name, "\x00" });
            defer allocator.free(terminated);
            try paddedData(allocator, &output, terminated);
        }
        const header = try tarHeader(name, entry.mode, epoch, if (entry.bytes) |bytes| bytes.len else 0, if (entry.bytes == null) '5' else '0', false);
        try appendTar(allocator, &output, &header);
        if (entry.bytes) |bytes| try paddedData(allocator, &output, bytes);
    }
    const zeroes: [10240]u8 = @splat(0);
    try appendTar(allocator, &output, zeroes[0..1024]);
    const padding = (10240 - output.items.len % 10240) % 10240;
    try appendTar(allocator, &output, zeroes[0..padding]);
    return output.toOwnedSlice(allocator);
}

fn tarValue(field: []const u8) !i64 {
    if (field.len == 0 or field.len > 12) return refuse("cannot read archive: invalid tar numeric field", .{});
    if (field[0] == 0x80 or field[0] == 0xff) {
        var value: i128 = 0;
        for (field[1..]) |byte| value = value * 256 + byte;
        if (field[0] == 0xff) value -= @as(i128, 1) << @intCast(8 * (field.len - 1));
        return std.math.cast(i64, value) orelse refuse("cannot read archive: tar numeric field exceeds signed64 bits", .{});
    }
    const octal = std.mem.trim(u8, std.mem.sliceTo(field, 0), " ");
    if (octal.len == 0) return 0;
    return std.fmt.parseInt(i64, octal, 8) catch refuse("cannot read archive: malformed tar numeric field", .{});
}

const ArchiveEntry = struct { name: []const u8, bytes: ?[]const u8, mode: u32, mtime: i64 };

fn readTar(allocator: std.mem.Allocator, tar: []const u8) ![]ArchiveEntry {
    if (tar.len < 512 or tar.len > maximum_tar_bytes)
        return refuse("cannot read archive: tar input is truncated or exceeds its bound", .{});
    var entries: std.ArrayList(ArchiveEntry) = .empty;
    errdefer entries.deinit(allocator);
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();
    var previous: []const u8 = "";
    var timestamp: ?i64 = null;
    var long_name: ?[]const u8 = null;
    var offset: usize = 0;
    while (offset < tar.len) {
        if (tar.len - offset < 512) return refuse("cannot read archive: truncated tar header", .{});
        const header = tar[offset..][0..512];
        if (std.mem.allEqual(u8, header, 0)) break;
        var checksum: i64 = 0;
        for (header, 0..) |byte, index| checksum += if (index >= 148 and index < 156) 32 else byte;
        if (checksum != try tarValue(header[148..156]))
            return refuse("cannot read archive: tar header checksum differs", .{});
        const signed_size = try tarValue(header[124..136]);
        const start = offset + 512;
        if (signed_size < 0 or signed_size > tar.len - start)
            return refuse("cannot read archive: truncated tar member", .{});
        const size: usize = @intCast(signed_size);
        const padded = std.mem.alignForward(usize, size, 512);
        if (padded > tar.len - start) return refuse("cannot read archive: truncated tar member padding", .{});
        const bytes = tar[start..][0..size];
        offset = start + padded;
        const kind = header[156];
        if (kind == 'L') {
            if (long_name != null or bytes.len == 0 or bytes.len > 4097)
                return refuse("cannot read archive: invalid GNU long name", .{});
            long_name = std.mem.sliceTo(bytes, 0);
            continue;
        }
        const raw_name = long_name orelse blk: {
            const name = std.mem.sliceTo(header[0..100], 0);
            if (std.mem.eql(u8, header[257..263], "ustar\x00")) {
                const prefix = std.mem.sliceTo(header[345..500], 0);
                if (prefix.len != 0) break :blk try std.mem.concat(allocator, u8, &.{ prefix, "/", name });
            }
            break :blk name;
        };
        long_name = null;
        const name = std.mem.trimEnd(u8, raw_name, "/");
        try validateArchiveName(name);
        if ((try seen.getOrPut(name)).found_existing)
            return refuse("duplicate archive entry: {s}", .{name});
        if (std.mem.lessThan(u8, name, previous))
            return refuse("archive entries are not sorted: {s}", .{name});
        previous = name;
        if (kind == '1' or kind == '2' or kind == 'K')
            return refuse("archive contains a link: {s}", .{name});
        const directory = kind == '5';
        if (!directory and kind != '0' and kind != 0 and kind != '7')
            return refuse("archive contains a special file: {s}", .{name});
        if (try tarValue(header[108..116]) != 0 or try tarValue(header[116..124]) != 0 or
            !std.mem.eql(u8, std.mem.sliceTo(header[265..297], 0), "root") or
            !std.mem.eql(u8, std.mem.sliceTo(header[297..329], 0), "root"))
            return refuse("non-canonical ownership: {s}", .{name});
        const mode = std.math.cast(u32, try tarValue(header[100..108])) orelse
            return refuse("non-canonical mode: {s}", .{name});
        if ((directory and mode != 0o755) or (!directory and mode != 0o644 and mode != 0o755))
            return refuse("non-canonical mode: {s}", .{name});
        const mtime = try tarValue(header[136..148]);
        if (timestamp) |first| {
            if (mtime != first) return refuse("archive timestamps differ: {s}", .{name});
        } else timestamp = mtime;
        if (entries.items.len == 2 * maximum_entries)
            return refuse("too many release archive members", .{});
        try entries.append(allocator, .{ .name = name, .bytes = if (directory) null else bytes, .mode = mode, .mtime = mtime });
    }
    if (long_name != null) return refuse("cannot read archive: GNU long name lacks a member", .{});
    return entries.toOwnedSlice(allocator);
}

pub fn validateStaticElf(allocator: std.mem.Allocator, binary: []const u8, platform: Platform) !void {
    if (binary.len < 64 or !std.mem.startsWith(u8, binary, "\x7fELF") or binary[4] != 2)
        return refuse("bin/debz is not an ELF64 executable", .{});
    if (binary[5] != 1 or binary[6] != 1)
        return refuse("bin/debz has an unsupported ELF encoding or version", .{});
    const elf_type = integer(u16, binary, 16);
    const machine = integer(u16, binary, 18);
    const program_offset = integer(u64, binary, 32);
    const section_offset = integer(u64, binary, 40);
    const header_size = integer(u16, binary, 52);
    const program_size = integer(u16, binary, 54);
    const program_count = integer(u16, binary, 56);
    const section_size = integer(u16, binary, 58);
    const section_count = integer(u16, binary, 60);
    const section_names = integer(u16, binary, 62);
    if ((elf_type != 2 and elf_type != 3) or integer(u32, binary, 20) != 1 or header_size != 64)
        return refuse("bin/debz has a malformed ELF64 header", .{});
    if (machine != platform.machine()) return refuse("ELF architecture {d} does not match {s}", .{ machine, @tagName(platform) });
    if (program_count == 0 or program_count == 0xffff or program_size != 56)
        return refuse("bin/debz has a malformed ELF64 program header table", .{});
    if (program_offset < header_size or program_offset % 8 != 0)
        return refuse("bin/debz has a malformed ELF64 program header offset", .{});
    const programs = try region(binary, program_offset, @as(u64, program_count) * program_size, "program header table");
    if (section_offset == 0) {
        if (section_count != 0 or section_names != 0 or (section_size != 0 and section_size != 64))
            return refuse("bin/debz has malformed section-header-less ELF metadata", .{});
    } else {
        if (section_count == 0 or section_names == 0xffff or section_names >= section_count or section_size != 64 or
            section_offset < header_size or section_offset % 8 != 0)
            return refuse("bin/debz has a malformed ELF64 section header table", .{});
        const sections = try region(binary, section_offset, @as(u64, section_count) * section_size, "section header table");
        for (0..section_count) |index| {
            const section = sections[index * section_size ..][0..section_size];
            const alignment = integer(u64, section, 48);
            if (alignment > 1 and alignment & (alignment - 1) != 0)
                return refuse("bin/debz has a malformed ELF64 section alignment", .{});
            const size = integer(u64, section, 32);
            if (integer(u32, section, 4) != 8 and size != 0)
                _ = try region(binary, integer(u64, section, 24), size, "section");
        }
    }
    var loads: std.ArrayList(Load) = .empty;
    defer loads.deinit(allocator);
    var dynamic: ?Dynamic = null;
    var dynamic_count: usize = 0;
    for (0..program_count) |index| {
        const program = programs[index * program_size ..][0..program_size];
        const kind = integer(u32, program, 0);
        const offset = integer(u64, program, 8);
        const address = integer(u64, program, 16);
        const file_size = integer(u64, program, 32);
        const memory_size = integer(u64, program, 40);
        const alignment = integer(u64, program, 48);
        if (file_size > memory_size) return refuse("bin/debz has an ELF segment larger on disk than in memory", .{});
        if (alignment > 1 and alignment & (alignment - 1) != 0)
            return refuse("bin/debz has a malformed ELF segment alignment", .{});
        if (kind == 1 and alignment > 1 and offset % alignment != address % alignment)
            return refuse("bin/debz has a misaligned ELF load segment", .{});
        if (file_size != 0) _ = try region(binary, offset, file_size, "segment");
        if (kind == 1) {
            try loads.append(allocator, .{
                .file_start = offset,
                .file_end = try addressEnd(offset, file_size, "load segment file mapping"),
                .virtual_start = address,
                .virtual_file_end = try addressEnd(address, file_size, "load segment file mapping"),
                .virtual_memory_end = try addressEnd(address, memory_size, "load segment memory mapping"),
            });
        } else if (kind == 2) {
            dynamic_count += 1;
            dynamic = .{ .offset = offset, .address = address, .size = file_size, .memory_size = memory_size };
        } else if (kind == 3) return refuse("bin/debz contains a PT_INTERP dynamic loader", .{});
    }
    if (loads.items.len == 0) return refuse("bin/debz has no ELF load segment", .{});
    if (dynamic_count > 1) return refuse("bin/debz has multiple PT_DYNAMIC segments", .{});
    if (dynamic) |value| {
        if (value.offset % 8 != 0 or value.address % 8 != 0 or value.size == 0 or value.size % 16 != 0 or value.memory_size != value.size)
            return refuse("bin/debz has a malformed PT_DYNAMIC segment", .{});
        const file_end = try addressEnd(value.offset, value.size, "PT_DYNAMIC mapping");
        const virtual_end = try addressEnd(value.address, value.size, "PT_DYNAMIC mapping");
        var file_mapping: ?usize = null;
        var virtual_mapping: ?usize = null;
        for (loads.items, 0..) |load, index| {
            if (value.offset >= load.file_start and file_end <= load.file_end) {
                if (file_mapping != null) return refuse("bin/debz has an ambiguous or unmapped PT_DYNAMIC file/virtual range", .{});
                file_mapping = index;
            }
            if (value.address >= load.virtual_start and virtual_end <= load.virtual_file_end and virtual_end <= load.virtual_memory_end) {
                if (virtual_mapping != null) return refuse("bin/debz has an ambiguous or unmapped PT_DYNAMIC file/virtual range", .{});
                virtual_mapping = index;
            }
        }
        if (file_mapping == null or virtual_mapping == null)
            return refuse("bin/debz has an ambiguous or unmapped PT_DYNAMIC file/virtual range", .{});
        if (file_mapping.? != virtual_mapping.?) return refuse("bin/debz has mismatched PT_DYNAMIC file and virtual mappings", .{});
        const load = loads.items[file_mapping.?];
        if (value.offset - load.file_start != value.address - load.virtual_start)
            return refuse("bin/debz has inconsistent PT_DYNAMIC file and virtual offsets", .{});
        const table = try region(binary, value.offset, value.size, "PT_DYNAMIC segment");
        var terminated = false;
        var offset: usize = 0;
        while (offset < table.len) : (offset += 16) {
            const tag = integer(i64, table, offset);
            if (tag == 1) return refuse("bin/debz contains a DT_NEEDED shared-library dependency", .{});
            if (terminated and tag != 0) return refuse("bin/debz has data after the PT_DYNAMIC terminator", .{});
            if (tag == 0) terminated = true;
        }
        if (!terminated) return refuse("bin/debz has an unterminated PT_DYNAMIC segment", .{});
    }
}

fn execute(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 2) return refuse("a release subcommand is required", .{});
    if (std.mem.eql(u8, args[1], "read-archive")) {
        if (args.len != 4 or !std.mem.eql(u8, args[2], "--name"))
            return refuse("read-archive requires --name and compressed binary stdin", .{});
        var reader = std.Io.File.stdin().reader(init.io, &.{});
        const input = try reader.interface.allocRemaining(allocator, .limited(maximum_compressed_bytes));
        const tar = try decompressedTar(allocator, input, args[3]);
        const entries = try readTar(allocator, tar);
        const Output = struct { name: []const u8, data_base64: ?[]const u8, mode: u32, mtime: i64 };
        const records = try allocator.alloc(Output, entries.len);
        for (entries, records) |entry, *record| {
            const encoded = if (entry.bytes) |bytes| blk: {
                const buffer = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len));
                break :blk std.base64.standard.Encoder.encode(buffer, bytes);
            } else null;
            record.* = .{ .name = entry.name, .data_base64 = encoded, .mode = entry.mode, .mtime = entry.mtime };
        }
        try std.Io.File.stdout().writeStreamingAll(init.io, try std.json.Stringify.valueAlloc(allocator, records, .{}));
        return;
    }
    const compress = std.mem.eql(u8, args[1], "compress-tar");
    const decompress = std.mem.eql(u8, args[1], "decode-tar");
    if (compress or decompress) {
        if (args.len != 4 or !std.mem.eql(u8, args[2], if (compress) "--format" else "--name"))
            return refuse("compression requires a selected format or archive name and binary stdin", .{});
        var reader = std.Io.File.stdin().reader(init.io, &.{});
        const input = try reader.interface.allocRemaining(allocator, .limited(if (compress) maximum_tar_bytes else maximum_compressed_bytes));
        const output = if (compress)
            try compressTar(allocator, input, try Format.parse(args[3]))
        else
            try decompressedTar(allocator, input, args[3]);
        try std.Io.File.stdout().writeStreamingAll(init.io, output);
        return;
    }
    if (std.mem.eql(u8, args[1], "encode-tar")) {
        if (args.len != 4 or !std.mem.eql(u8, args[2], "--epoch")) return refuse("encode-tar requires --epoch and JSON stdin", .{});
        const epoch = try std.fmt.parseInt(i64, args[3], 10);
        const Input = struct { name: []const u8, data_base64: ?[]const u8, mode: u32 };
        var reader = std.Io.File.stdin().reader(init.io, &.{});
        const document = try reader.interface.allocRemaining(allocator, .limited(maximum_tar_bytes));
        const inputs = try std.json.parseFromSlice([]const Input, allocator, document, .{ .max_value_len = maximum_tar_bytes });
        if (inputs.value.len > maximum_entries) return refuse("too many release archive entries", .{});
        const entries = try allocator.alloc(Entry, inputs.value.len);
        var total: usize = 0;
        for (inputs.value, entries) |input, *entry| {
            const bytes = if (input.data_base64) |encoded| blk: {
                const length = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
                total = try std.math.add(usize, total, length);
                if (total > maximum_tar_bytes) return refuse("release payload exceeds the bounded256MiB limit", .{});
                const decoded = try allocator.alloc(u8, length);
                try std.base64.standard.Decoder.decode(decoded, encoded);
                break :blk decoded;
            } else null;
            entry.* = .{ .name = input.name, .bytes = bytes, .mode = input.mode };
        }
        try std.Io.File.stdout().writeStreamingAll(init.io, try buildTar(allocator, entries, epoch));
        return;
    }
    if (std.mem.eql(u8, args[1], "check-elf")) {
        if (args.len != 4 or !std.mem.eql(u8, args[2], "--platform")) return refuse("check-elf requires --platform and binary stdin", .{});
        const platform = try Platform.parse(args[3]);
        var reader = std.Io.File.stdin().reader(init.io, &.{});
        const binary = try reader.interface.allocRemaining(allocator, .limited(128 * 1024 * 1024));
        try validateStaticElf(allocator, binary, platform);
        return;
    }
    const version_command = std.mem.eql(u8, args[1], "version");
    const dry_run = std.mem.eql(u8, args[1], "dry-run");
    if (!version_command and !dry_run) return refuse("unsupported release subcommand", .{});
    const tag = if (version_command) blk: {
        if (args.len < 3) return refuse("version requires a release tag", .{});
        break :blk args[2];
    } else blk: {
        if (args.len != 4 or !std.mem.eql(u8, args[2], "--tag")) return refuse("dry-run requires --tag", .{});
        break :blk args[3];
    };
    const version = parseTag(tag) catch return refuse("invalid release tag: {s}", .{tag});
    if (version_command) {
        var index: usize = 3;
        while (index < args.len) : (index += 2) {
            if (!std.mem.eql(u8, args[index], "--expect") or index + 1 >= args.len)
                return refuse("version accepts only --expect NAME=VERSION", .{});
            const expected = args[index + 1];
            const equals = std.mem.indexOfScalar(u8, expected, '=') orelse
                return refuse("consistency value must be NAME=VERSION: {s}", .{expected});
            if (equals == 0 or !std.mem.eql(u8, expected[equals + 1 ..], version))
                return refuse("version mismatch for {s}: {s} != {s}", .{
                    if (equals == 0) "<empty>" else expected[0..equals], expected[equals + 1 ..], version,
                });
        }
        try std.Io.File.stdout().writeStreamingAll(init.io, try std.mem.concat(allocator, u8, &.{ version, "\n" }));
        return;
    }
    const Architecture = struct { architecture: []const u8, name: []const u8, os: []const u8 = "linux" };
    const Plan = struct {
        assets: [4][]const u8,
        platforms: [2]Architecture = .{
            .{ .architecture = "x86_64", .name = "linux-x64" },
            .{ .architecture = "aarch64", .name = "linux-arm64" },
        },
        schemaVersion: u8 = 1,
        tag: []const u8,
        version: []const u8,
    };
    const plan: Plan = .{
        .assets = .{
            try std.fmt.allocPrint(allocator, "debz-{s}-linux-arm64.tar.gz", .{version}),
            try std.fmt.allocPrint(allocator, "debz-{s}-linux-arm64.tar.xz", .{version}),
            try std.fmt.allocPrint(allocator, "debz-{s}-linux-x64.tar.gz", .{version}),
            try std.fmt.allocPrint(allocator, "debz-{s}-linux-x64.tar.xz", .{version}),
        },
        .tag = tag,
        .version = version,
    };
    try std.Io.File.stdout().writeStreamingAll(init.io, try std.mem.concat(allocator, u8, &.{
        try std.json.Stringify.valueAlloc(allocator, plan, .{}), "\n",
    }));
}

pub fn main(init: std.process.Init) void {
    execute(init) catch |err| {
        if (err != error.InvalidReleaseInput) std.log.err("release: {s}", .{@errorName(err)});
        std.process.exit(2);
    };
}

test "release tag preserves original strict numeric and prerelease identities" {
    for ([_][]const u8{ "v0.1.0", "v1.2.3-alpha.1", "v1.2.3-rc.1+build.7", "v1.2.3--", "v1.2.3+01" }) |tag|
        try std.testing.expectEqualStrings(tag[1..], try parseTag(tag));
    for ([_][]const u8{ "0.1.0", "v01.2.3", "v1.02.3", "v1.2", "v1.2.3-01", "v1.2.3_foo", "v", "v1.2.3-1rc", "v1.2.3+foo..bar", "v1.2.3+foo+bar", "v1.2.3\xff" }) |tag|
        try std.testing.expectError(error.InvalidReleaseTag, parseTag(tag));
}

fn fixtureElf() [256]u8 {
    var bytes: [256]u8 = @splat(0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    std.mem.writeInt(u16, bytes[16..18], 2, .little);
    std.mem.writeInt(u16, bytes[18..20], 62, .little);
    std.mem.writeInt(u32, bytes[20..24], 1, .little);
    std.mem.writeInt(u64, bytes[32..40], 64, .little);
    std.mem.writeInt(u16, bytes[52..54], 64, .little);
    std.mem.writeInt(u16, bytes[54..56], 56, .little);
    std.mem.writeInt(u16, bytes[56..58], 2, .little);
    std.mem.writeInt(u32, bytes[64..68], 1, .little);
    std.mem.writeInt(u64, bytes[80..88], 0x400000, .little);
    std.mem.writeInt(u64, bytes[96..104], bytes.len, .little);
    std.mem.writeInt(u64, bytes[104..112], bytes.len, .little);
    std.mem.writeInt(u32, bytes[120..124], 2, .little);
    std.mem.writeInt(u64, bytes[128..136], 192, .little);
    std.mem.writeInt(u64, bytes[136..144], 0x400000 + 192, .little);
    std.mem.writeInt(u64, bytes[152..160], 32, .little);
    std.mem.writeInt(u64, bytes[160..168], 32, .little);
    return bytes;
}

test "release ELF preserves mapped static dynamic tables and rejects loader and hidden needed entries" {
    var bytes = fixtureElf();
    try validateStaticElf(std.testing.allocator, &bytes, .@"linux-x64");
    std.mem.writeInt(u64, bytes[192..200], 1, .little);
    try std.testing.expectError(error.InvalidReleaseInput, validateStaticElf(std.testing.allocator, &bytes, .@"linux-x64"));
    std.mem.writeInt(u64, bytes[192..200], 0, .little);
    std.mem.writeInt(u64, bytes[136..144], 0x400000 + 224, .little);
    try std.testing.expectError(error.InvalidReleaseInput, validateStaticElf(std.testing.allocator, &bytes, .@"linux-x64"));
    std.mem.writeInt(u64, bytes[136..144], 0x400000 + 192, .little);
    std.mem.writeInt(u64, bytes[208..216], 2, .little);
    try std.testing.expectError(error.InvalidReleaseInput, validateStaticElf(std.testing.allocator, &bytes, .@"linux-x64"));
    std.mem.writeInt(u64, bytes[208..216], 0, .little);
    std.mem.writeInt(u32, bytes[120..124], 3, .little);
    try std.testing.expectError(error.InvalidReleaseInput, validateStaticElf(std.testing.allocator, &bytes, .@"linux-x64"));
}

test "release ELF bounds reject truncated tables and overflowing mappings without reading them" {
    var bytes = fixtureElf();
    try std.testing.expectError(error.InvalidReleaseInput, validateStaticElf(std.testing.allocator, bytes[0..63], .@"linux-x64"));
    std.mem.writeInt(u64, bytes[32..40], 264, .little);
    try std.testing.expectError(error.InvalidReleaseInput, validateStaticElf(std.testing.allocator, &bytes, .@"linux-x64"));
    std.mem.writeInt(u64, bytes[32..40], 64, .little);
    std.mem.writeInt(u64, bytes[80..88], std.math.maxInt(u64) - 16, .little);
    try std.testing.expectError(error.InvalidReleaseInput, validateStaticElf(std.testing.allocator, &bytes, .@"linux-x64"));
}

test "release GNU tar preserves long names, signed epochs and canonical record padding" {
    const allocator = std.testing.allocator;
    const name = "root/" ++ "a" ** 101;
    const tar = try buildTar(allocator, &.{
        .{ .name = name, .bytes = "independent", .mode = 0o644 },
        .{ .name = "root/bin/debz", .bytes = "abc", .mode = 0o755 },
    }, -1);
    defer allocator.free(tar);
    try std.testing.expectEqual(@as(usize, 10240), tar.len);
    try std.testing.expectEqualStrings("././@LongLink", std.mem.sliceTo(tar[512..612], 0));
    try std.testing.expectEqualStrings(name, std.mem.sliceTo(tar[1024..1536], 0));
    try std.testing.expectEqualSlices(u8, &([_]u8{0xff} ** 12), tar[136..148]);
    try std.testing.expectError(error.InvalidReleaseInput, buildTar(allocator, &.{.{ .name = "../escape", .bytes = "x", .mode = 0o644 }}, 123));
}

test "release compression is deterministic and both containers preserve the original tar payload" {
    const allocator = std.testing.allocator;
    const tar = try buildTar(allocator, &.{.{ .name = "root/bin/debz", .bytes = "original payload", .mode = 0o755 }}, 123);
    defer allocator.free(tar);
    for ([_]Format{ .@"tar.gz", .@"tar.xz" }) |format| {
        const name = try std.mem.concat(allocator, u8, &.{ "fixture.", @tagName(format) });
        defer allocator.free(name);
        const first = try compressTar(allocator, tar, format);
        defer allocator.free(first);
        const second = try compressTar(allocator, tar, format);
        defer allocator.free(second);
        try std.testing.expectEqualSlices(u8, first, second);
        const decoded = try decompressedTar(allocator, first, name);
        defer allocator.free(decoded);
        try std.testing.expectEqualSlices(u8, tar, decoded);
    }
}

test "release decoders reject trailing input corruption and noncanonical gzip metadata" {
    const allocator = std.testing.allocator;
    for ([_]Format{ .@"tar.gz", .@"tar.xz" }) |format| {
        const name = try std.mem.concat(allocator, u8, &.{ "fixture.", @tagName(format) });
        defer allocator.free(name);
        const bytes = try compressTar(allocator, "original payload", format);
        defer allocator.free(bytes);
        const trailing = try std.mem.concat(allocator, u8, &.{ bytes, "junk" });
        defer allocator.free(trailing);
        try std.testing.expectError(error.InvalidReleaseInput, decompressedTar(allocator, trailing, name));
        bytes[bytes.len - 1] ^= 1;
        try std.testing.expectError(error.InvalidReleaseInput, decompressedTar(allocator, bytes, name));
        bytes[bytes.len - 1] ^= 1;
        if (format == .@"tar.gz") {
            bytes[4] = 1;
            try std.testing.expectError(error.InvalidReleaseInput, decompressedTar(allocator, bytes, name));
            bytes[4] = 0;
            bytes[3] = 8;
            try std.testing.expectError(error.InvalidReleaseInput, decompressedTar(allocator, bytes, name));
        }
    }
}

test "release member reader preserves original GNU long names signed epochs and all file bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const name = "root/" ++ "a" ** 101;
    for ([_]i64{ -1, 123, std.math.maxInt(i64), std.math.minInt(i64) }) |epoch| {
        const tar = try buildTar(allocator, &.{
            .{ .name = name, .bytes = "independent\x00bytes", .mode = 0o644 },
            .{ .name = "root/bin/debz", .bytes = "original", .mode = 0o755 },
        }, epoch);
        const entries = try readTar(allocator, tar);
        try std.testing.expectEqual(@as(usize, 4), entries.len);
        try std.testing.expectEqualStrings(name, entries[1].name);
        try std.testing.expectEqualStrings("independent\x00bytes", entries[1].bytes.?);
        try std.testing.expectEqualStrings("root/bin/debz", entries[3].name);
        for (entries) |entry| try std.testing.expectEqual(epoch, entry.mtime);
    }
}

test "release member reader rejects checksum size ownership mode order duplicate and link mutations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const first = try tarHeader("root/a", 0o644, 123, 0, '0', false);
    const second = try tarHeader("root/b", 0o644, 123, 0, '0', false);
    const valid = try std.mem.concat(allocator, u8, &.{ &first, &second, &([_]u8{0} ** 1024) });
    try std.testing.expectEqual(@as(usize, 2), (try readTar(allocator, valid)).len);
    const corrupt = try allocator.dupe(u8, valid);
    corrupt[0] ^= 1;
    try std.testing.expectError(error.InvalidReleaseInput, readTar(allocator, corrupt));
    for ([_]struct { name: []const u8 = "root/b", mode: u32 = 0o644, epoch: i64 = 123, size: usize = 0, kind: u8 = '0' }{
        .{ .name = "../escape" }, .{ .name = "root/a" }, .{ .name = "root/0" },
        .{ .mode = 0o777 },       .{ .epoch = 124 },     .{ .size = 8192 },
        .{ .kind = '2' },         .{ .kind = '3' },      .{ .kind = 'L' },
    }) |mutation| {
        const header = try tarHeader(mutation.name, mutation.mode, mutation.epoch, mutation.size, mutation.kind, false);
        const bytes = try std.mem.concat(allocator, u8, &.{ &first, &header, &([_]u8{0} ** 1024) });
        try std.testing.expectError(error.InvalidReleaseInput, readTar(allocator, bytes));
    }
    const wrong_owner = try tarHeader("root/b", 0o644, 123, 0, '0', true);
    const bytes = try std.mem.concat(allocator, u8, &.{ &first, &wrong_owner, &([_]u8{0} ** 1024) });
    try std.testing.expectError(error.InvalidReleaseInput, readTar(allocator, bytes));
}
