const std = @import("std");
const c = @cImport({
    @cInclude("lzma.h");
    @cInclude("zstd.h");
});

pub const Compression = enum {
    gzip,
    xz,
    zstd,
};

pub const Error = error{
    Unsupported,
    CompressionMismatch,
    InputLimitExceeded,
    OutputLimitExceeded,
    MemoryLimitExceeded,
    ExpectedSizeMismatch,
    Truncated,
    Corrupt,
    TrailingData,
    OutOfMemory,
};

pub const Options = struct {
    maximum_compressed_bytes: usize,
    maximum_decompressed_bytes: usize,
    expected_decompressed_size: ?usize = null,
    maximum_decoder_memory: u64 = 64 * 1024 * 1024,
};

/// Selects a compression format only from a trusted, already-selected filename.
/// It never examines content bytes or falls back to magic-number detection.
pub fn compressionFromFilename(filename: []const u8) Error!Compression {
    if (std.mem.endsWith(u8, filename, ".gz")) return .gzip;
    if (std.mem.endsWith(u8, filename, ".xz")) return .xz;
    if (std.mem.endsWith(u8, filename, ".zst") or
        std.mem.endsWith(u8, filename, ".zstd")) return .zstd;
    return error.Unsupported;
}

/// Returns a slice owned by `allocator`; the caller must free it with the same
/// allocator. No output is returned on any validation or decompression error.
pub fn decompress(
    allocator: std.mem.Allocator,
    compression: Compression,
    compressed: []const u8,
    options: Options,
) Error![]u8 {
    if (compressed.len > options.maximum_compressed_bytes)
        return error.InputLimitExceeded;
    if (options.expected_decompressed_size) |expected| {
        if (expected > options.maximum_decompressed_bytes)
            return error.OutputLimitExceeded;
    }

    const output = switch (compression) {
        .gzip => try decompressGzip(allocator, compressed, options),
        .xz => try decompressXz(allocator, compressed, options),
        .zstd => try decompressZstd(allocator, compressed, options),
    };
    errdefer allocator.free(output);

    if (options.expected_decompressed_size) |expected| {
        if (output.len != expected) return error.ExpectedSizeMismatch;
    }
    return output;
}

fn decompressGzip(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    options: Options,
) Error![]u8 {
    if (compressed.len < 2 or compressed[0] != 0x1f or compressed[1] != 0x8b)
        return error.CompressionMismatch;
    _ = try validateGzipHeader(compressed);
    if (options.maximum_decoder_memory < std.compress.flate.max_window_len)
        return error.MemoryLimitExceeded;

    var input = std.Io.Reader.fixed(compressed);
    const history = allocator.alloc(u8, std.compress.flate.max_window_len) catch
        return error.OutOfMemory;
    defer allocator.free(history);
    var decoder: std.compress.flate.Decompress = .init(&input, .gzip, history);
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var scratch: [16 * 1024]u8 = undefined;
    while (true) {
        var writer = std.Io.Writer.fixed(&scratch);
        const produced = decoder.reader.stream(
            &writer,
            .limited(scratch.len),
        ) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => return mapFlateError(decoder.err),
            error.WriteFailed => return error.OutputLimitExceeded,
        };
        const new_len = std.math.add(usize, output.items.len, produced) catch
            return error.OutputLimitExceeded;
        if (new_len > options.maximum_decompressed_bytes)
            return error.OutputLimitExceeded;
        output.appendSlice(allocator, scratch[0..produced]) catch
            return error.OutOfMemory;
    }

    if (input.seek < 8) return error.Truncated;
    const footer = compressed[input.seek - 8 .. input.seek];
    const declared_crc = std.mem.readInt(u32, footer[0..4], .little);
    const declared_size = std.mem.readInt(u32, footer[4..8], .little);
    if (declared_crc != std.hash.Crc32.hash(output.items) or
        declared_size != @as(u32, @truncate(output.items.len)))
        return error.Corrupt;
    if (input.seek != compressed.len) return error.TrailingData;
    return output.toOwnedSlice(allocator) catch error.OutOfMemory;
}

fn validateGzipHeader(compressed: []const u8) Error!usize {
    if (compressed.len < 10) return error.Truncated;
    if (compressed[2] != 8) return error.Unsupported;
    const flags = compressed[3];
    if (flags & 0xe0 != 0) return error.Unsupported;

    var offset: usize = 10;
    if (flags & 0x04 != 0) {
        if (compressed.len - offset < 2) return error.Truncated;
        const extra_length = std.mem.readInt(u16, compressed[offset..][0..2], .little);
        offset += 2;
        if (extra_length > compressed.len - offset) return error.Truncated;
        offset += extra_length;
    }
    inline for (.{ @as(u8, 0x08), @as(u8, 0x10) }) |flag| {
        if (flags & flag != 0) {
            const terminator = std.mem.indexOfScalarPos(u8, compressed, offset, 0) orelse
                return error.Truncated;
            offset = terminator + 1;
        }
    }
    if (flags & 0x02 != 0) {
        if (compressed.len - offset < 2) return error.Truncated;
        const declared = std.mem.readInt(u16, compressed[offset..][0..2], .little);
        const computed: u16 = @truncate(std.hash.Crc32.hash(compressed[0..offset]));
        if (declared != computed) return error.Corrupt;
        offset += 2;
    }
    if (compressed.len - offset < 8) return error.Truncated;
    return offset;
}

fn mapFlateError(err: ?std.compress.flate.Decompress.Error) Error {
    return switch (err orelse return error.Corrupt) {
        error.EndOfStream => error.Truncated,
        else => error.Corrupt,
    };
}

fn decompressZstd(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    options: Options,
) Error![]u8 {
    if (compressed.len < 4 or
        !std.mem.eql(u8, compressed[0..4], &.{ 0x28, 0xb5, 0x2f, 0xfd }))
        return error.CompressionMismatch;

    if (options.maximum_decoder_memory < 1024) return error.MemoryLimitExceeded;
    if (c.ZSTD_getDictID_fromFrame(compressed.ptr, compressed.len) != 0)
        return error.Unsupported;
    const decoder = c.ZSTD_createDStream() orelse return error.OutOfMemory;
    defer _ = c.ZSTD_freeDStream(decoder);
    const window_log: c_int = @intCast(std.math.log2_int(u64, options.maximum_decoder_memory));
    if (c.ZSTD_isError(c.ZSTD_DCtx_setParameter(decoder, c.ZSTD_d_windowLogMax, window_log)) != 0)
        return error.MemoryLimitExceeded;
    if (c.ZSTD_isError(c.ZSTD_initDStream(decoder)) != 0) return error.Corrupt;

    var input = c.ZSTD_inBuffer{
        .src = compressed.ptr,
        .size = compressed.len,
        .pos = 0,
    };
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var scratch: [128 * 1024]u8 = undefined;
    while (true) {
        const previous_input = input.pos;
        var chunk = c.ZSTD_outBuffer{
            .dst = &scratch,
            .size = scratch.len,
            .pos = 0,
        };
        const remaining = c.ZSTD_decompressStream(decoder, &chunk, &input);
        if (c.ZSTD_isError(remaining) != 0) return error.Corrupt;
        const produced: usize = @intCast(chunk.pos);
        const new_len = std.math.add(usize, output.items.len, produced) catch
            return error.OutputLimitExceeded;
        if (new_len > options.maximum_decompressed_bytes)
            return error.OutputLimitExceeded;
        output.appendSlice(allocator, scratch[0..produced]) catch
            return error.OutOfMemory;
        if (remaining == 0) {
            if (input.pos != compressed.len) return error.TrailingData;
            break;
        }
        if (input.pos == previous_input and produced == 0)
            return if (input.pos == compressed.len) error.Truncated else error.Corrupt;
    }

    return output.toOwnedSlice(allocator) catch error.OutOfMemory;
}

fn decompressXz(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    options: Options,
) Error![]u8 {
    const magic = [_]u8{ 0xfd, '7', 'z', 'X', 'Z', 0x00 };
    if (compressed.len < magic.len or !std.mem.eql(u8, compressed[0..magic.len], &magic))
        return error.CompressionMismatch;

    var stream: c.lzma_stream = std.mem.zeroes(c.lzma_stream);
    const init_result = c.lzma_stream_decoder(
        &stream,
        options.maximum_decoder_memory,
        c.LZMA_TELL_UNSUPPORTED_CHECK | c.LZMA_FAIL_FAST,
    );
    if (init_result != c.LZMA_OK) return mapLzmaError(init_result, true);
    defer c.lzma_end(&stream);

    stream.next_in = compressed.ptr;
    stream.avail_in = compressed.len;

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var scratch: [16 * 1024]u8 = undefined;

    while (true) {
        stream.next_out = &scratch;
        stream.avail_out = scratch.len;
        const result = c.lzma_code(&stream, c.LZMA_FINISH);
        const produced = scratch.len - stream.avail_out;

        const new_len = std.math.add(usize, output.items.len, produced) catch
            return error.OutputLimitExceeded;
        if (new_len > options.maximum_decompressed_bytes)
            return error.OutputLimitExceeded;
        output.appendSlice(allocator, scratch[0..produced]) catch
            return error.OutOfMemory;

        switch (result) {
            c.LZMA_OK => {
                if (produced == 0 and stream.avail_in == 0)
                    return error.Truncated;
            },
            c.LZMA_STREAM_END => {
                if (stream.avail_in != 0) return error.TrailingData;
                return output.toOwnedSlice(allocator) catch error.OutOfMemory;
            },
            else => return mapLzmaError(result, stream.avail_in == compressed.len),
        }
    }
}

fn mapLzmaError(result: c.lzma_ret, initializing: bool) Error {
    return switch (result) {
        c.LZMA_MEM_ERROR => error.OutOfMemory,
        c.LZMA_MEMLIMIT_ERROR => error.MemoryLimitExceeded,
        c.LZMA_FORMAT_ERROR => if (initializing) error.CompressionMismatch else error.Corrupt,
        c.LZMA_OPTIONS_ERROR, c.LZMA_UNSUPPORTED_CHECK => error.Unsupported,
        c.LZMA_DATA_ERROR => error.Corrupt,
        c.LZMA_BUF_ERROR => error.Truncated,
        else => error.Corrupt,
    };
}

const plain = "Package: debz\nVersion: 1\n";
const gzip_fixture = [_]u8{
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x0b, 0x48,
    0x4c, 0xce, 0x4e, 0x4c, 0x4f, 0xb5, 0x52, 0x48, 0x49, 0x4d, 0xaa, 0xe2,
    0x0a, 0x4b, 0x2d, 0x2a, 0xce, 0xcc, 0xcf, 0xb3, 0x52, 0x30, 0xe4, 0x02,
    0x00, 0x83, 0x97, 0xf8, 0x48, 0x19, 0x00, 0x00, 0x00,
};
const gzip_named_fixture = [_]u8{
    0x1f, 0x8b, 0x08, 0x08, 0xe5, 0x70, 0xb1, 0x65, 0x00, 0x03, 0x68, 0x65,
    0x6c, 0x6c, 0x6f, 0x2e, 0x74, 0x78, 0x74, 0x00, 0xf3, 0x48, 0xcd, 0xc9,
    0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00, 0xd5, 0xe0,
    0x39, 0xb7, 0x0c, 0x00, 0x00, 0x00,
};
const microsoft_shaped_gzip_fixture = [_]u8{
    0x1f, 0x8b, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x50, 0x61,
    0x63, 0x6b, 0x61, 0x67, 0x65, 0x73, 0x00, 0xed, 0xcb, 0x31, 0x0e, 0x82,
    0x30, 0x00, 0x00, 0xc0, 0xbd, 0xaf, 0xe0, 0x03, 0x12, 0x1a, 0x8d, 0x03,
    0x9b, 0x3f, 0x60, 0x72, 0x6f, 0x4a, 0xa3, 0xc4, 0xa0, 0xa6, 0xd4, 0x81,
    0xdf, 0xeb, 0x3b, 0xcc, 0xed, 0x77, 0x53, 0xca, 0x8f, 0x74, 0x2b, 0x63,
    0xb7, 0xed, 0x6b, 0xae, 0xfb, 0xbb, 0x85, 0x6b, 0xa9, 0xdb, 0xf2, 0x7a,
    0x8e, 0x5d, 0x1c, 0x8e, 0x7d, 0x8c, 0xfd, 0x70, 0x88, 0xe1, 0x52, 0xf3,
    0x7d, 0x69, 0x25, 0xb7, 0x4f, 0xfd, 0xd1, 0xb4, 0xce, 0xe7, 0x53, 0x08,
    0x93, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xea, 0x3f, 0xd7, 0x2f, 0x57, 0xba, 0x40, 0xef, 0x00,
    0x76, 0x00, 0x00,
};
const microsoft_shaped_record =
    "Package: symcrypt\nVersion: 103.11.0-1\nArchitecture: amd64\n\n";
const xz_fixture = [_]u8{
    0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46,
    0x02, 0x00, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3,
    0x01, 0x00, 0x18, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x3a, 0x20,
    0x64, 0x65, 0x62, 0x7a, 0x0a, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
    0x3a, 0x20, 0x31, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x57, 0x2c, 0xfe, 0xc2,
    0x76, 0x8d, 0x70, 0x78, 0x00, 0x01, 0x31, 0x19, 0x59, 0x1a, 0xb0, 0x82,
    0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a,
};
const zstd_fixture = [_]u8{
    0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x68, 0xc9, 0x00, 0x00, 0x50, 0x61, 0x63,
    0x6b, 0x61, 0x67, 0x65, 0x3a, 0x20, 0x64, 0x65, 0x62, 0x7a, 0x0a, 0x56,
    0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x31, 0x0a,
};
const gzip_bomb_fixture = [_]u8{
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xed, 0xc1,
    0x01, 0x0d, 0x00, 0x00, 0x00, 0xc2, 0xa0, 0x6c, 0xef, 0x5f, 0xca, 0x1e,
    0x0e, 0x28, 0x00, 0x00, 0x00, 0xe0, 0xdd, 0x00, 0x40, 0x34, 0xa6, 0xfe,
    0x00, 0x10, 0x00, 0x00,
};
const xz_bomb_fixture = [_]u8{
    0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46,
    0x02, 0x00, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3,
    0xe0, 0x0f, 0xff, 0x00, 0x19, 0x5d, 0x00, 0x20, 0xef, 0xfb, 0xbf, 0xfe,
    0xa3, 0xb1, 0x5e, 0xe5, 0xf8, 0x3f, 0xb2, 0xaa, 0x26, 0x55, 0xf8, 0x68,
    0x70, 0x41, 0x70, 0x15, 0x0e, 0x24, 0x18, 0xcf, 0x00, 0x00, 0x00, 0x00,
    0xa8, 0xfb, 0x2f, 0x0b, 0x80, 0x25, 0xdb, 0x3f, 0x00, 0x01, 0x35, 0x80,
    0x20, 0x00, 0x00, 0x00, 0x6f, 0x5d, 0x36, 0x86, 0xb1, 0xc4, 0x67, 0xfb,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a,
};
const zstd_bomb_fixture = [_]u8{
    0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x68, 0x45, 0x00, 0x00,
    0x08, 0x41, 0x01, 0x00, 0xfc, 0xf7, 0x81, 0x10,
};

fn fixture(compression: Compression) []const u8 {
    return switch (compression) {
        .gzip => &gzip_fixture,
        .xz => &xz_fixture,
        .zstd => &zstd_fixture,
    };
}

fn bombFixture(compression: Compression) []const u8 {
    return switch (compression) {
        .gzip => &gzip_bomb_fixture,
        .xz => &xz_bomb_fixture,
        .zstd => &zstd_bomb_fixture,
    };
}

test "filename selection is explicit" {
    try std.testing.expectEqual(Compression.gzip, try compressionFromFilename("Packages.gz"));
    try std.testing.expectEqual(Compression.xz, try compressionFromFilename("Sources.xz"));
    try std.testing.expectEqual(Compression.zstd, try compressionFromFilename("Packages.zst"));
    try std.testing.expectError(error.Unsupported, compressionFromFilename("Packages"));
}

test "deterministic fixtures decompress for every format" {
    for (std.enums.values(Compression)) |compression| {
        const output = try decompress(std.testing.allocator, compression, fixture(compression), .{
            .maximum_compressed_bytes = 256,
            .maximum_decompressed_bytes = 256,
            .expected_decompressed_size = plain.len,
        });
        defer std.testing.allocator.free(output);
        try std.testing.expectEqualStrings(plain, output);
    }
}

test "gzip accepts original filenames and preserves history across output chunks" {
    const named = try decompress(std.testing.allocator, .gzip, &gzip_named_fixture, .{
        .maximum_compressed_bytes = 256,
        .maximum_decompressed_bytes = 256,
    });
    defer std.testing.allocator.free(named);
    try std.testing.expectEqualStrings("Hello world\n", named);

    const microsoft = try decompress(
        std.testing.allocator,
        .gzip,
        &microsoft_shaped_gzip_fixture,
        .{
            .maximum_compressed_bytes = 1024,
            .maximum_decompressed_bytes = 64 * 1024,
            .expected_decompressed_size = microsoft_shaped_record.len * 512,
        },
    );
    defer std.testing.allocator.free(microsoft);
    try std.testing.expectEqual(@as(usize, microsoft_shaped_record.len * 512), microsoft.len);
    try std.testing.expectEqualStrings(microsoft_shaped_record, microsoft[0..microsoft_shaped_record.len]);
    try std.testing.expectEqualStrings(
        microsoft_shaped_record,
        microsoft[microsoft.len - microsoft_shaped_record.len ..],
    );
}

test "gzip header validation and decoder memory remain bounded" {
    try std.testing.expectError(error.MemoryLimitExceeded, decompress(
        std.testing.allocator,
        .gzip,
        &gzip_fixture,
        .{
            .maximum_compressed_bytes = 256,
            .maximum_decompressed_bytes = 256,
            .maximum_decoder_memory = std.compress.flate.max_window_len - 1,
        },
    ));

    var reserved = gzip_fixture;
    reserved[3] |= 0x20;
    try std.testing.expectError(error.Unsupported, decompress(
        std.testing.allocator,
        .gzip,
        &reserved,
        .{
            .maximum_compressed_bytes = 256,
            .maximum_decompressed_bytes = 256,
        },
    ));

    var unterminated_name = gzip_named_fixture;
    unterminated_name[19] = 'x';
    try std.testing.expectError(error.Truncated, decompress(
        std.testing.allocator,
        .gzip,
        &unterminated_name,
        .{
            .maximum_compressed_bytes = 256,
            .maximum_decompressed_bytes = 256,
        },
    ));
}

test "limits and expected size reject without partial success" {
    for (std.enums.values(Compression)) |compression| {
        const bytes = fixture(compression);
        try std.testing.expectError(error.InputLimitExceeded, decompress(
            std.testing.allocator,
            compression,
            bytes,
            .{
                .maximum_compressed_bytes = bytes.len - 1,
                .maximum_decompressed_bytes = 256,
            },
        ));
        try std.testing.expectError(error.OutputLimitExceeded, decompress(
            std.testing.allocator,
            compression,
            bytes,
            .{
                .maximum_compressed_bytes = 256,
                .maximum_decompressed_bytes = plain.len - 1,
            },
        ));
        try std.testing.expectError(error.ExpectedSizeMismatch, decompress(
            std.testing.allocator,
            compression,
            bytes,
            .{
                .maximum_compressed_bytes = 256,
                .maximum_decompressed_bytes = 256,
                .expected_decompressed_size = plain.len + 1,
            },
        ));
    }
}

fn expectBombLimit(compression: Compression) !void {
    try std.testing.expectError(error.OutputLimitExceeded, decompress(
        std.testing.allocator,
        compression,
        bombFixture(compression),
        .{
            .maximum_compressed_bytes = 256,
            .maximum_decompressed_bytes = 128,
        },
    ));
}

test "gzip compressed bomb stops at the output limit" {
    try expectBombLimit(.gzip);
}

test "xz compressed bomb stops at the output limit" {
    try expectBombLimit(.xz);
}

test "zstd compressed bomb stops at the output limit" {
    try expectBombLimit(.zstd);
}

test "truncation corruption and trailing data are typed for every format" {
    for (std.enums.values(Compression)) |compression| {
        const bytes = fixture(compression);
        try std.testing.expectError(error.Truncated, decompress(
            std.testing.allocator,
            compression,
            bytes[0 .. bytes.len - 2],
            .{
                .maximum_compressed_bytes = 256,
                .maximum_decompressed_bytes = 256,
            },
        ));

        var corrupt: [xz_fixture.len]u8 = undefined;
        @memcpy(corrupt[0..bytes.len], bytes);
        corrupt[
            switch (compression) {
                .gzip => bytes.len - 8,
                .xz => 8,
                .zstd => 6,
            }
        ] ^= if (compression == .zstd) 0x06 else 0x01;
        try std.testing.expectError(error.Corrupt, decompress(
            std.testing.allocator,
            compression,
            corrupt[0..bytes.len],
            .{
                .maximum_compressed_bytes = 256,
                .maximum_decompressed_bytes = 256,
            },
        ));

        var trailing: [xz_fixture.len + 1]u8 = undefined;
        @memcpy(trailing[0..bytes.len], bytes);
        trailing[bytes.len] = 0xaa;
        try std.testing.expectError(error.TrailingData, decompress(
            std.testing.allocator,
            compression,
            trailing[0 .. bytes.len + 1],
            .{
                .maximum_compressed_bytes = 256,
                .maximum_decompressed_bytes = 256,
            },
        ));
    }
}

test "selected compression mismatch never falls back to magic detection" {
    try std.testing.expectError(error.CompressionMismatch, decompress(
        std.testing.allocator,
        .xz,
        &gzip_fixture,
        .{
            .maximum_compressed_bytes = 256,
            .maximum_decompressed_bytes = 256,
        },
    ));
}
