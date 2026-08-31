const std = @import("std");
const debz = @import("debz");
const fuzz_options = @import("fuzz_options");

const max_input = 32 * 1024;
const text_corpus = &.{
    @embedFile("corpus/deb822/basic"),
    @embedFile("corpus/control/basic"),
    @embedFile("corpus/release/basic"),
    @embedFile("corpus/packages/basic"),
};
const signed_corpus = &.{
    @embedFile("corpus/signed/inrelease"),
    @embedFile("corpus/signed/packet"),
};
const compression_corpus = &.{
    @embedFile("corpus/compression/plain.gz"),
    @embedFile("corpus/compression/plain.xz"),
    @embedFile("corpus/compression/plain.zst"),
};
const archive_corpus = &.{
    @embedFile("corpus/archive/minimal.deb"),
    @embedFile("corpus/archive/signed.deb"),
    @embedFile("corpus/archive/traversal.tar"),
};
const state_corpus = &.{
    @embedFile("corpus/state/lock.json"),
    @embedFile("corpus/state/lock-v2.json"),
    @embedFile("corpus/state/provenance.json"),
    @embedFile("corpus/state/provenance-v2.json"),
    @embedFile("corpus/state/journal"),
    @embedFile("corpus/state/repository-result.json"),
    @embedFile("corpus/state/repository-add-state.json"),
};

fn input(smith: *std.testing.Smith, storage: *[max_input]u8) []const u8 {
    @disableInstrumentation();
    return storage[0..smith.slice(storage)];
}

test "fuzz.external Debian text parsers" {
    try std.testing.fuzz({}, fuzzDebianText, .{ .corpus = text_corpus });
}

fn fuzzDebianText(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input]u8 = undefined;
    try exerciseDebianText(input(smith, &storage));
}

fn exerciseDebianText(bytes: []const u8) !void {
    const allocator = std.testing.allocator;

    const deb822_result = try debz.deb822.parseBorrowed(allocator, bytes, .{
        .limits = .{
            .max_total_bytes = max_input,
            .max_paragraphs = 64,
            .max_fields_per_paragraph = 64,
            .max_field_bytes = 4096,
        },
    });
    switch (deb822_result) {
        .document => |value| {
            var document = value;
            document.deinit();
        },
        .failure => {},
    }

    _ = debz.DebianVersion.parse(bytes) catch {};
    const relation_result = try debz.relation.parse(allocator, bytes, .{
        .max_input_bytes = max_input,
        .max_groups = 64,
        .max_alternatives_per_group = 32,
        .max_total_alternatives = 256,
        .max_version_bytes = 4096,
    });
    switch (relation_result) {
        .relation => |value| {
            var relation = value;
            relation.deinit(allocator);
        },
        .diagnostic => {},
    }

    inline for (.{ debz.source.Format.deb822, debz.source.Format.legacy }) |format| {
        const result = try debz.source.parse(allocator, bytes, format, .{
            .max_input_bytes = max_input,
            .max_sources = 64,
            .max_fields_per_stanza = 32,
            .max_field_bytes = 4096,
            .max_values_per_field = 64,
            .max_value_bytes = 1024,
            .max_legacy_options = 16,
        });
        switch (result) {
            .sources => |value| {
                var sources = value;
                sources.deinit();
            },
            .diagnostic => {},
        }
    }

    const control_result = try debz.control_record.parseBorrowed(allocator, bytes, .{
        .limits = .{
            .deb822 = .{
                .max_total_bytes = max_input,
                .max_paragraphs = 64,
                .max_fields_per_paragraph = 64,
                .max_field_bytes = 4096,
            },
            .max_records = 64,
            .max_unknown_fields_per_record = 32,
        },
    });
    switch (control_result) {
        .document => |value| {
            var document = value;
            document.deinit();
        },
        .diagnostic => {},
    }

    const status_result = try debz.dpkg_status.parseBorrowed(allocator, bytes, .{
        .limits = .{
            .deb822 = .{
                .max_total_bytes = max_input,
                .max_paragraphs = 64,
                .max_fields_per_paragraph = 64,
                .max_field_bytes = 4096,
            },
            .max_packages = 64,
        },
    });
    switch (status_result) {
        .database => |value| {
            var database = value;
            database.deinit();
        },
        .diagnostic => {},
    }

    const release_result = try debz.release_metadata.parse(allocator, bytes, .{
        .max_input_bytes = max_input,
        .max_fields = 64,
        .max_field_bytes = 4096,
        .max_list_items = 64,
        .max_checksum_rows = 128,
    });
    switch (release_result) {
        .metadata => |value| {
            var metadata = value;
            metadata.deinit();
        },
        .diagnostic => {},
    }

    const repository_id = debz.source.RepositoryId{
        .bytes = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".*,
    };
    const packages_result = try debz.packages_index.parseBorrowed(allocator, bytes, .{
        .repository_id = repository_id,
        .component = "main",
        .architecture = "amd64",
        .source_location = "fuzz://packages",
    }, .{ .limits = .{
        .max_total_bytes = max_input,
        .max_records = 64,
        .max_fields_per_record = 64,
        .max_field_bytes = 4096,
        .max_unknown_fields_per_record = 32,
        .max_filename_bytes = 1024,
    } });
    switch (packages_result) {
        .index => |value| {
            var index = value;
            index.deinit();
        },
        .diagnostic => {},
    }
}

test "fuzz.signed envelopes and OpenPGP packets" {
    try std.testing.fuzz({}, fuzzSigned, .{ .corpus = signed_corpus });
}

fn fuzzSigned(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input]u8 = undefined;
    try exerciseSigned(input(smith, &storage));
}

fn exerciseSigned(bytes: []const u8) !void {
    const limits: debz.signed_release_envelope.Limits = .{
        .max_input_bytes = max_input,
        .max_cleartext_bytes = 8192,
        .max_header_count = 16,
        .max_header_bytes = 4096,
        .max_header_line_bytes = 1024,
        .max_signature_count = 8,
        .max_signature_bytes = 8192,
        .max_armor_line_bytes = 128,
    };
    const in_release = try debz.signed_release_envelope.parseInRelease(std.testing.allocator, bytes, limits);
    switch (in_release) {
        .envelope => |value| {
            var envelope = value;
            envelope.deinit();
        },
        .diagnostic => {},
    }
    const detached = try debz.signed_release_envelope.parseDetached(std.testing.allocator, "Release", bytes, limits);
    switch (detached) {
        .envelope => |value| {
            var envelope = value;
            envelope.deinit();
        },
        .diagnostic => {},
    }

    if (debz.openpgp_verifier.inspectKeyring(std.testing.allocator, bytes, .{
        .max_keyring_bytes = max_input,
        .max_packet_bytes = max_input,
        .max_packets = 128,
        .max_keys = 32,
    })) |value| {
        var inspection = value;
        inspection.deinit(std.testing.allocator);
    } else |_| {}

    var outcome = debz.openpgp_verifier.verify(std.testing.allocator, .{
        .io = std.testing.io,
        .signed_bytes = "Release",
        .signatures = &.{bytes},
        .keyrings = .{ .one = .{ .bytes = bytes } },
        .policy = .{ .verification_time = 0 },
        .limits = .{
            .max_signed_bytes = max_input,
            .max_keyring_bytes = max_input,
            .max_signature_bytes = max_input,
            .max_packet_bytes = max_input,
            .max_packets = 128,
            .max_keys = 32,
            .max_signatures = 4,
            .max_subpackets = 64,
            .max_subpacket_bytes = 4096,
        },
    }) catch return;
    outcome.deinit(std.testing.allocator);
}

test "fuzz.metadata decompression" {
    try std.testing.fuzz({}, fuzzCompression, .{ .corpus = compression_corpus });
}

fn fuzzCompression(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input]u8 = undefined;
    try exerciseCompression(input(smith, &storage));
}

fn exerciseCompression(bytes: []const u8) !void {
    for ([_]debz.metadata_decompression.Compression{ .gzip, .xz, .zstd }) |compression| {
        const output = debz.metadata_decompression.decompress(std.testing.allocator, compression, bytes, .{
            .maximum_compressed_bytes = max_input,
            .maximum_decompressed_bytes = 64 * 1024,
            .maximum_decoder_memory = 4 * 1024 * 1024,
        }) catch continue;
        std.testing.allocator.free(output);
    }
}

test "fuzz.ar deb and tar payload validation" {
    try std.testing.fuzz({}, fuzzArchive, .{ .corpus = archive_corpus });
}

fn fuzzArchive(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input]u8 = undefined;
    try exerciseArchive(input(smith, &storage));
}

fn exerciseArchive(bytes: []const u8) !void {
    _ = debz.deb_archive.parse(bytes, .{
        .max_archive_bytes = max_input,
        .max_member_bytes = max_input,
        .max_members = 8,
    });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const result = debz.deb_payload.validate(std.testing.allocator, bytes, .{
        .repository = "fuzz",
        .package = "demo",
        .version = "1.0",
        .architecture = "amd64",
        .requested_package = "demo",
        .filename = "pool/main/d/demo/demo_1.0_amd64.deb",
        .size = bytes.len,
        .sha256 = digest,
    }, .{
        .outer = .{
            .max_archive_bytes = max_input,
            .max_member_bytes = max_input,
            .max_members = 8,
        },
        .max_control_compressed_bytes = max_input,
        .max_control_decompressed_bytes = 64 * 1024,
        .max_data_compressed_bytes = max_input,
        .max_data_decompressed_bytes = 64 * 1024,
        .max_decoder_memory = 4 * 1024 * 1024,
        .max_entries_per_tar = 128,
        .max_path_bytes = 1024,
        .max_link_bytes = 1024,
        .max_inventory_bytes_per_tar = 64 * 1024,
        .max_control_file_bytes = 8192,
        .max_conffiles_bytes = 8192,
        .max_conffiles = 64,
        .max_total_entry_bytes = 64 * 1024,
    });
    switch (result) {
        .validation => |value| {
            var validation = value;
            validation.deinit();
        },
        .diagnostic => {},
    }
    const local_result = debz.deb_payload.inspectLocal(std.testing.allocator, bytes, .{}, .{
        .outer = .{
            .max_archive_bytes = max_input,
            .max_member_bytes = max_input,
            .max_signature_bytes = 8192,
            .max_members = 8,
        },
        .max_control_compressed_bytes = max_input,
        .max_control_decompressed_bytes = 64 * 1024,
        .max_data_compressed_bytes = max_input,
        .max_data_decompressed_bytes = 64 * 1024,
        .max_decoder_memory = 4 * 1024 * 1024,
        .max_entries_per_tar = 128,
        .max_path_bytes = 1024,
        .max_link_bytes = 1024,
        .max_inventory_bytes_per_tar = 64 * 1024,
        .max_control_file_bytes = 8192,
        .max_conffiles_bytes = 8192,
        .max_conffiles = 64,
        .max_maintainer_script_bytes = 8192,
        .max_total_maintainer_script_bytes = 16 * 1024,
        .max_total_entry_bytes = 64 * 1024,
    });
    switch (local_result) {
        .validation => |value| {
            var validation = value;
            validation.deinit();
        },
        .diagnostic => {},
    }
}

test "fuzz.lock provenance and transaction journals" {
    try std.testing.fuzz({}, fuzzState, .{ .corpus = state_corpus });
}

fn fuzzState(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input]u8 = undefined;
    try exerciseState(input(smith, &storage));
}

fn exerciseState(bytes: []const u8) !void {
    if (debz.exact_lock.decode(std.testing.allocator, bytes, max_input)) |value| {
        var lock = value;
        lock.deinit();
    } else |_| {}
    if (debz.exact_lock_v2.decode(std.testing.allocator, bytes, max_input)) |value| {
        var lock = value;
        lock.deinit();
    } else |_| {}
    if (debz.transaction_provenance.validateDocument(std.testing.allocator, bytes, max_input)) |value| {
        var document = value;
        document.deinit();
    } else |_| {}
    if (debz.transaction_provenance_v2.validateDocument(std.testing.allocator, bytes, max_input)) |value| {
        var document = value;
        document.deinit();
    } else |_| {}
    if (debz.transaction_recovery.decode(std.testing.allocator, bytes)) |value| {
        var journal = value;
        journal.deinit();
    } else |_| {}
    if (debz.target_apt_config.decodeManifest(std.testing.allocator, bytes, max_input)) |value| {
        var manifest = value;
        manifest.deinit();
    } else |_| {}
    if (debz.repository_api.decode(std.testing.allocator, bytes, max_input)) |value| {
        var result = value;
        result.deinit();
    } else |_| {}
    if (debz.repository_state.decode(std.testing.allocator, bytes, max_input)) |value| {
        var state = value;
        state.deinit();
    } else |_| {}
}

test "fuzz.deterministic bounded mutation smoke" {
    try smokeCorpus(text_corpus, exerciseDebianText);
    try smokeCorpus(signed_corpus, exerciseSigned);
    try smokeCorpus(compression_corpus, exerciseCompression);
    try smokeCorpus(archive_corpus, exerciseArchive);
    try smokeCorpus(state_corpus, exerciseState);
}

fn smokeCorpus(
    corpus: []const []const u8,
    comptime exercise: fn ([]const u8) anyerror!void,
) !void {
    var storage: [max_input]u8 = undefined;
    for (corpus, 0..) |seed, seed_index| {
        const length = @min(seed.len, storage.len);
        for (0..fuzz_options.smoke_cases) |case_index| {
            @memcpy(storage[0..length], seed[0..length]);
            if (length != 0) {
                const position = (case_index *% 0x9e3779b1 +% seed_index *% 17) % length;
                storage[position] ^= @truncate((case_index *% 131) | 1);
            }
            exercise(storage[0..length]) catch |err| {
                std.debug.print(
                    "bounded fuzz failure: seed={d} case={d} length={d} error={s}\n",
                    .{ seed_index, case_index, length, @errorName(err) },
                );
                return err;
            };
        }
    }
}
