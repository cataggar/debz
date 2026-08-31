const std = @import("std");
const debz = @import("debz");

const plain = "Package: debz\nVersion: 1\n";
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

test "public package supplies source-built compression dependencies" {
    for ([_]struct {
        compression: debz.metadata_decompression.Compression,
        bytes: []const u8,
    }{
        .{ .compression = .xz, .bytes = &xz_fixture },
        .{ .compression = .zstd, .bytes = &zstd_fixture },
    }) |fixture| {
        const output = try debz.metadata_decompression.decompress(
            std.testing.allocator,
            fixture.compression,
            fixture.bytes,
            .{
                .maximum_compressed_bytes = 256,
                .maximum_decompressed_bytes = 256,
                .expected_decompressed_size = plain.len,
            },
        );
        defer std.testing.allocator.free(output);
        try std.testing.expectEqualStrings(plain, output);
    }
}

test "repository package origin remains source compatible beside tagged v2 origin" {
    const repository_id: debz.source.RepositoryId = .{ .bytes = @splat('a') };
    const legacy: debz.SolverPackageOrigin = .{
        .repository_id = repository_id,
        .repository_priority = 500,
        .record_index = 3,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .source_location = "pool/demo.deb",
    };
    const tagged: debz.SolverPackageOriginV2 = .{
        .authenticated_repository = legacy,
    };
    try std.testing.expectEqualStrings("demo", legacy.package);
    try std.testing.expectEqualStrings(
        "demo",
        tagged.authenticated_repository.package,
    );
    _ = debz.PackageSelectedRecord.fromSolverSelection;
    _ = debz.PackageSelectedRecord.fromTaggedSolverSelection;
}

test "repository management API is exported without CLI coupling" {
    const request: debz.RepositoryRequest = .{
        .root = "/target",
        .descriptor_url = "https://packages.example.test/config.deb",
        .architecture = "amd64",
    };
    try std.testing.expectEqual(debz.RepositoryOperation.add, request.operation);
    _ = debz.RepositoryResult;
    _ = debz.ProductionRepositoryBackend;
}
