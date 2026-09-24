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
/// `info/*.list` bytes drive the native ownership index: the canonical
/// relative spelling, the sorted order, the exact-owner probe, and the
/// bounded descendant scan all read them, and every one of them is reachable
/// on a compromised root.
const ownership_corpus = &.{
    @embedFile("corpus/ownership/list"),
    @embedFile("corpus/ownership/alias"),
};
const alternatives_corpus = &.{
    @embedFile("corpus/alternatives/record"),
    @embedFile("corpus/alternatives/manual-record"),
    @embedFile("corpus/alternatives/truncated-record"),
    @embedFile("corpus/alternatives/script"),
};
const authorization_v2_seed = @embedFile("corpus/state/authorization-v2.json");
const program_v2_seed = @embedFile("corpus/state/program-v2.json");
const execution_request_v4_seed = @embedFile("corpus/state/execution-request-v4.json");
const recovery_intent_v2_seed = @embedFile("corpus/state/recovery-intent-v2.json");
const progress_v3_seed = @embedFile("corpus/state/progress-v3.json");
const progress_v4_seed = @embedFile("corpus/state/progress-v4.json");
const native_provenance_v2_seed = @embedFile("corpus/state/native-provenance-v2.json");
const root_completion_v2_seed = @embedFile("corpus/state/root-operation-completion-v2.json");
const transaction_result_v3_seed = @embedFile("corpus/state/transaction-result-v3.json");
const transaction_plan_v4_file = @embedFile("corpus/state/transaction-plan-v4.json");
const transaction_plan_v4_seed =
    transaction_plan_v4_file[0 .. transaction_plan_v4_file.len - 1];
const transaction_journal_v4_seed = @embedFile("corpus/state/journal-v4");
const state_corpus = &.{
    @embedFile("corpus/state/lock.json"),
    @embedFile("corpus/state/lock-v2.json"),
    @embedFile("corpus/state/lock-v3.json"),
    @embedFile("corpus/state/authorization.json"),
    authorization_v2_seed,
    @embedFile("corpus/state/program.json"),
    @embedFile("corpus/state/program-wide.json"),
    program_v2_seed,
    execution_request_v4_seed,
    recovery_intent_v2_seed,
    progress_v3_seed,
    progress_v4_seed,
    native_provenance_v2_seed,
    @embedFile("corpus/state/provenance.json"),
    @embedFile("corpus/state/provenance-v2.json"),
    transaction_result_v3_seed,
    @embedFile("corpus/state/journal"),
    transaction_journal_v4_seed,
    transaction_plan_v4_seed,
    @embedFile("corpus/state/repository-result.json"),
    @embedFile("corpus/state/repository-add-state.json"),
    @embedFile("corpus/state/root-operation.json"),
    @embedFile("corpus/state/root-operation-completion.json"),
    root_completion_v2_seed,
    @embedFile("corpus/state/root-mutation-progress"),
    @embedFile("corpus/state/root-mutation-journal.json"),
};

/// The checked-in progress log for the root mutation write-ahead protocol.
/// It is replayed against the module's own fixed synthetic journal, so a
/// mutated record exercises the shape, the chain, and the identity rules the
/// recovery path depends on.
const mutation_progress_seed = @embedFile("corpus/state/root-mutation-progress");

/// The checked-in mutation journal document. Its install root, its step path,
/// and its link target are valid non-ASCII UTF-8, so a mutated copy lands
/// inside a multibyte sequence and drives the decoder across the encoding
/// boundary the mutation layer refuses to publish malformed.
const mutation_journal_seed = @embedFile("corpus/state/root-mutation-journal.json");

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
    debz.archive_application.fuzzOne(std.testing.allocator, bytes, .{ .local = .{} }, .{
        .payload = .{
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
        },
        .max_files = 128,
        .max_control_members = 16,
        .max_checksums_bytes = 8192,
        .max_checksum_entries = 128,
        .max_triggers_bytes = 8192,
        .max_trigger_declarations = 64,
        .max_control_member_bytes = 8192,
    });
}

test "fuzz.native ownership index" {
    try std.testing.fuzz({}, fuzzOwnership, .{ .corpus = ownership_corpus });
}

fn fuzzOwnership(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input]u8 = undefined;
    try exerciseOwnership(input(smith, &storage));
}

fn exerciseOwnership(bytes: []const u8) !void {
    debz.native_unpack.fuzzOwnership(std.testing.allocator, bytes);
}

test "fuzz.native alternatives records" {
    try std.testing.fuzz({}, fuzzAlternatives, .{
        .corpus = alternatives_corpus,
    });
}

fn fuzzAlternatives(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input]u8 = undefined;
    debz.native_alternatives.fuzzOne(
        std.testing.allocator,
        input(smith, &storage),
    );
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
    if (debz.exact_lock_v3.decode(std.testing.allocator, bytes, max_input)) |value| {
        var lock = value;
        lock.deinit();
    } else |_| {}
    if (debz.native_authorization.decode(std.testing.allocator, bytes, max_input)) |value| {
        var authorization = value;
        authorization.deinit();
    } else |_| {}
    if (debz.native_program.decode(std.testing.allocator, bytes, max_input)) |value| {
        var program = value;
        program.deinit();
    } else |_| {}
    if (debz.native_execution_request.decodePersisted(std.testing.allocator, bytes)) |value| {
        var request = value;
        request.deinit();
    } else |_| {}
    if (debz.native_recovery.decodeIntent(std.testing.allocator, bytes)) |value| {
        var intent = value;
        intent.deinit();
    } else |_| {}
    if (debz.native_recovery.decodeProgress(std.testing.allocator, bytes)) |value| {
        var progress = value;
        progress.deinit();
    } else |_| {}
    if (debz.native_provenance.decode(std.testing.allocator, bytes)) |value| {
        var provenance = value;
        provenance.deinit();
    } else |_| {}
    if (debz.transaction_provenance.validateDocument(std.testing.allocator, bytes, max_input)) |value| {
        var document = value;
        document.deinit();
    } else |_| {}
    if (debz.transaction_provenance_v2.validateDocument(std.testing.allocator, bytes, max_input)) |value| {
        var document = value;
        document.deinit();
    } else |_| {}
    if (debz.transaction_provenance_v3.validateDocument(std.testing.allocator, bytes, max_input)) |value| {
        var document = value;
        document.deinit();
    } else |_| {}
    if (debz.transaction_recovery.decode(std.testing.allocator, bytes)) |value| {
        var journal = value;
        journal.deinit();
    } else |_| {}
    if (debz.repository_plan.decode(std.testing.allocator, bytes)) |value| {
        var plan = value;
        plan.deinit();
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
    if (debz.root_operation.decode(std.testing.allocator, bytes, max_input)) |value| {
        var record = value;
        record.deinit();
    } else |_| {}
    if (debz.root_operation_completion.decode(std.testing.allocator, bytes, max_input)) |value| {
        var document = value;
        document.deinit();
    } else |_| {}
    // The mutation journal and its write-ahead log are the durable inputs the
    // recovery path parses, and both are reachable on a compromised root.
    debz.root_mutation.fuzzOne(std.testing.allocator, bytes);
    if (debz.root_mutation.decode(std.testing.allocator, bytes, max_input)) |value| {
        var journal = value;
        defer journal.deinit();
        debz.root_mutation.fuzzProgress(std.testing.allocator, journal.journal, bytes);
    } else |_| {}
    // A progress log is a durable artifact of its own: it is reachable on a
    // compromised root without the journal document beside it, so it is
    // replayed against a fixed journal as well.
    debz.root_mutation.fuzzProgressLog(std.testing.allocator, bytes);
}

test "fuzz.the mutation progress corpus is the exact write-ahead format" {
    var buffer: [debz.root_mutation.fuzz_seed_bytes]u8 = undefined;
    const expected = debz.root_mutation.fuzzSeedLog(&buffer);
    // Regenerate the seed from `fuzzSeedLog` whenever the record format or
    // the chain changes; a corpus that no longer parses fuzzes nothing.
    try std.testing.expectEqualSlices(u8, expected, mutation_progress_seed);

    var progress = try debz.root_mutation.replayProgress(
        std.testing.allocator,
        debz.root_mutation.fuzzJournal(),
        mutation_progress_seed,
    );
    defer progress.deinit();
    try std.testing.expectEqual(mutation_progress_seed.len, progress.accepted_bytes);
    try std.testing.expectEqual(debz.root_mutation.Stage.completed, progress.stage);
    // The verified boundary of each step bound the entry it published, and
    // the second step of the pair inherits its precondition from the first.
    try std.testing.expect(progress.identity(0).bound());
    try std.testing.expectEqual(progress.identity(0).inode, progress.identity(1).inode);
}

test "fuzz.the mutation journal corpus is the exact canonical document" {
    const expected = try debz.root_mutation.fuzzSeedDocument(std.testing.allocator);
    defer std.testing.allocator.free(expected);
    // Regenerate the seed from `fuzzSeedDocument` whenever the document format
    // changes; a corpus entry that no longer decodes fuzzes nothing.
    try std.testing.expectEqualSlices(u8, expected, mutation_journal_seed);

    var decoded = try debz.root_mutation.decode(
        std.testing.allocator,
        mutation_journal_seed,
        max_input,
    );
    defer decoded.deinit();
    // The seed carries text no ASCII-only corpus would reach, so a mutation
    // of it lands inside a multibyte sequence in a path or a link target.
    const path = decoded.journal.steps[0].path;
    try std.testing.expect(!std.unicode.utf8ValidateSlice(path[0 .. path.len - 1]));
    try std.testing.expect(debz.root_mutation.encodableText(path));

    // Every malformed spelling of the same document is refused, so the
    // decoder can never hand the recovery path text the encoder could not
    // write back.
    for ([_][]const u8{
        "\x80",
        "\xc0\xaf",
        "\xed\xa0\x80",
        "\xf4\x90\x80\x80",
        "\xe2\x82",
    }) |malformed| {
        const marker = "etc/caf";
        const index = std.mem.indexOf(u8, mutation_journal_seed, marker).?;
        const corrupted = try std.mem.concat(std.testing.allocator, u8, &.{
            mutation_journal_seed[0 .. index + marker.len],
            malformed,
            mutation_journal_seed[index + marker.len + 2 ..],
        });
        defer std.testing.allocator.free(corrupted);
        try std.testing.expectError(
            error.NonCanonicalDocument,
            debz.root_mutation.decode(std.testing.allocator, corrupted, max_input),
        );
    }
}

test "fuzz.deterministic bounded mutation smoke" {
    try smokeCorpus(text_corpus, exerciseDebianText);
    try smokeCorpus(signed_corpus, exerciseSigned);
    try smokeCorpus(compression_corpus, exerciseCompression);
    try smokeCorpus(archive_corpus, exerciseArchive);
    try smokeCorpus(state_corpus, exerciseState);
    try smokeCorpus(ownership_corpus, exerciseOwnership);
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

test "fuzz.corpus root operation seed stays canonical and self-consistent" {
    var record = try debz.root_operation.decode(
        std.testing.allocator,
        @embedFile("corpus/state/root-operation.json"),
        debz.root_operation.maximum_document_bytes,
    );
    defer record.deinit();
    try std.testing.expect(record.record.mutation_started);
    try std.testing.expect(record.record.state.blocksMutation());
    try std.testing.expect(!record.record.clearable());
}

test "fuzz.corpus root operation completion seed stays canonical and self-consistent" {
    var record = try debz.root_operation.decode(
        std.testing.allocator,
        @embedFile("corpus/state/root-operation.json"),
        debz.root_operation.maximum_document_bytes,
    );
    defer record.deinit();
    var document = try debz.root_operation_completion.decode(
        std.testing.allocator,
        @embedFile("corpus/state/root-operation-completion.json"),
        debz.root_operation_completion.maximum_document_bytes,
    );
    defer document.deinit();
    // The seed describes a completed attempt whose detailed provenance
    // survived, so it binds a document digest and an archived journal.
    try std.testing.expectEqual(
        debz.root_operation_completion.TransactionProvenanceStatus.already_present,
        document.document.transaction_provenance.status,
    );
    try std.testing.expect(document.document.transaction_provenance.document_sha256 != null);
    try std.testing.expectEqual(
        debz.root_operation_completion.JournalStatus.archived,
        document.document.journal.status,
    );
    try std.testing.expect(document.document.mutation_started);
    // It is a statement about another attempt than the record seed, so it must
    // refuse to bind it.
    try std.testing.expect(!document.document.bindsRecord(record.record));
}

test "fuzz.corpus native transaction program seeds stay canonical" {
    for ([_][]const u8{
        @embedFile("corpus/state/program.json"),
        @embedFile("corpus/state/program-wide.json"),
    }) |seed| {
        var program = try debz.native_program.decode(
            std.testing.allocator,
            seed,
            debz.native_program.maximum_document_bytes,
        );
        defer program.deinit();
        try std.testing.expect(program.program.steps.len != 0);
    }
}

fn canonicalJsonForCorpus(value: anytype) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(
        value,
        .{ .whitespace = .minified },
        &output.writer,
    );
    try output.writer.writeByte('\n');
    return output.toOwnedSlice();
}

fn sealProgressForCorpus(document: *debz.native_recovery.ProgressDocument) void {
    const domain = switch (document.version) {
        3 => "debz-native-execution-progress-v3\x00",
        4 => "debz-native-execution-progress-v4\x00",
        else => unreachable,
    };
    document.digest_sha256 = @splat('0');
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    sink.writer.writeAll(domain) catch unreachable;
    std.json.Stringify.value(
        document.*,
        .{ .whitespace = .minified },
        &sink.writer,
    ) catch unreachable;
    sink.writer.flush() catch unreachable;
    document.digest_sha256 = debz.native_recovery.hexDigest(
        sink.hasher.finalResult(),
    );
}

test "fuzz.new native state corpus is the exact canonical encoding" {
    const allocator = std.testing.allocator;
    const archive_identity = try debz.content_digest.Identity.init(.{
        .sha256 = @splat(0x22),
        .sha512 = @splat(0x33),
    }, .sha512);
    const local_artifact: debz.package_origin.LocalArtifactEvidenceV2 = .{
        .artifact_id = debz.package_origin.artifactIdFromIdentity(
            archive_identity,
        ),
        .archive_identity = archive_identity,
        .size = 1,
        .package = "seed",
        .version = "1",
        .architecture = "all",
        .acquisition_url = "https://example.invalid/seed.deb",
        .trust_mode = .pinned_content_digest,
    };
    const locked_package: debz.exact_lock_v3.Package = .{
        .name = local_artifact.package,
        .version = local_artifact.version,
        .architecture = local_artifact.architecture,
        .origin = .{ .local_artifact = local_artifact },
        .archive_identity = archive_identity,
        .declared_size = local_artifact.size,
        .retention = .requested,
        .dpkg_selection_hold = false,
    };
    var lock = try debz.exact_lock_v3.create(allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(0),
        .policy_sha256 = @splat(0x11),
        .repositories = &.{},
        .local_artifacts = &.{local_artifact},
        .packages = &.{locked_package},
        .verified_origins = true,
    });
    defer lock.deinit();
    const package = lock.lock.packages[0];

    const actions = [_]debz.NativeAuthorizationAction{.{
        .sequence = 0,
        .kind = .install,
        .package = package.name,
        .version = package.version,
        .architecture = package.architecture,
        .prior_version = null,
        .artifact = .{
            .archive_identity = package.archive_identity,
            .size = package.declared_size,
            .origin_v2 = package.origin,
        },
    }};
    const final_state = [_]debz.NativeAuthorizationFinalPackage{.{
        .name = package.name,
        .version = package.version,
        .architecture = package.architecture,
        .state = .installed,
        .dpkg_selection_hold = package.dpkg_selection_hold,
    }};
    var authorization = try debz.native_authorization.create(allocator, .{
        .backend = .native,
        .target_architecture = lock.lock.target_architecture,
        .foreign_architectures = &.{},
        .install_root = "/srv/root",
        .request_sha256 = lock.lock.request_sha256,
        .solver_policy_sha256 = lock.lock.policy_sha256,
        .executor_policy_sha256 = @splat(3),
        .plan_sha256 = @splat(4),
        .exact_lock = .{
            .schema = debz.exact_lock_v3.schema_id,
            .version = debz.exact_lock_v3.schema_version,
            .digest_sha256 = lock.lock.digest_sha256,
        },
        .policy = .{
            .conffile = .keep_existing,
            .force = &.{},
            .allow_host_root = false,
        },
        .actions = &actions,
        .final_state = &final_state,
    });
    defer authorization.deinit();
    const authorization_bytes = try authorization.authorization.canonicalJson(
        allocator,
    );
    defer allocator.free(authorization_bytes);
    try std.testing.expectEqualSlices(
        u8,
        authorization_v2_seed,
        authorization_bytes,
    );

    const ordered_actions = [_]debz.SolverOrderedAction{
        .{
            .sequence = 0,
            .kind = .unpack,
            .package = package.name,
            .version = package.version,
            .architecture = package.architecture,
        },
        .{
            .sequence = 1,
            .kind = .configure_pending,
            .package = package.name,
            .version = package.version,
            .architecture = package.architecture,
        },
    };
    const archives = [_]debz.NativeProgramArchive{.{
        .package = package.name,
        .version = package.version,
        .architecture = package.architecture,
        .archive_identity = package.archive_identity,
        .size = package.declared_size,
        .origin_v2 = package.origin,
        .application_sha256 = @splat(0x41),
    }};
    var program = switch (debz.native_program.compile(allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = &ordered_actions,
        .installed = .{ .generation_sha256 = @splat(0x71) },
        .archives = &archives,
    })) {
        .program => |value| value,
        .diagnostic => |diagnostic| {
            std.debug.print(
                "seed program compilation failed: {s}: {s}\n",
                .{ @tagName(diagnostic.code), diagnostic.detail },
            );
            return error.TestUnexpectedResult;
        },
    };
    defer program.deinit();
    const program_bytes = try program.program.canonicalJson(allocator);
    defer allocator.free(program_bytes);
    try std.testing.expectEqualSlices(u8, program_v2_seed, program_bytes);

    var execution: debz.native_execution_request.Document = .{
        .install_root = program.program.install_root,
        .root_identity_sha256 = program.program.root_identity_sha256,
        .root_inode = 42,
        .architecture = program.program.target_architecture,
        .caller = .{
            .attempt_id = @splat('a'),
            .operation = .{ .package_transaction = .install },
            .request_sha256 = program.program.request_sha256,
            .policy_sha256 = program.program.solver_policy_sha256,
        },
        .program = .{
            .request_sha256 = program.program.request_sha256,
            .solver_policy_sha256 = program.program.solver_policy_sha256,
            .executor_policy_sha256 = program.program.executor_policy_sha256,
            .plan_sha256 = program.program.plan_sha256,
            .authorization_sha256 = program.program.authorization_sha256,
            .program_sha256 = program.program.digest_sha256,
            .exact_lock_sha256 = program.program.exact_lock.digest_sha256,
            .artifact_evidence_sha256 = program.program.artifacts_sha256,
            .database_generation_sha256 = program.program.installed_database.generation_sha256,
            .script_policy_sha256 = program.program.script_policy_sha256,
        },
        .operation = .install,
        .policy = .keep_existing,
        .triggers = false,
        .defer_triggers = false,
    };
    debz.native_execution_request.seal(&execution);
    const authority_request = try debz.native_execution_request.withAuthority(
        execution,
        program.program,
        null,
        null,
    );
    const request_bytes = try debz.native_execution_request.encodeWithAuthority(
        allocator,
        authority_request,
    );
    defer allocator.free(request_bytes);
    try std.testing.expectEqualSlices(
        u8,
        execution_request_v4_seed,
        request_bytes,
    );

    var request_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(request_bytes, &request_sha256, .{});
    const request_blob = [_]debz.native_recovery.Blob{.{
        .kind = .request,
        .key = "execution-request",
        .logical_path = debz.native_execution_request.authority_logical_path,
        .storage_path = debz.native_recovery.request_directory ++
            "/native-execution-request-v4.json",
        .size = request_bytes.len,
        .sha256 = debz.native_recovery.hexDigest(request_sha256),
        .mode = 0o600,
        .entry_kind = .regular,
    }};
    const intent_packages = [_]debz.native_recovery.PackageSelection{.{
        .name = package.name,
        .architecture = package.architecture,
    }};
    const intent_actions = [_]debz.native_recovery.OrderedAction{
        .{
            .sequence = 0,
            .kind = "unpack",
            .package = package.name,
            .version = package.version,
            .architecture = package.architecture,
        },
        .{
            .sequence = 1,
            .kind = "configure_pending",
            .package = package.name,
            .version = package.version,
            .architecture = package.architecture,
        },
    };
    var intent: debz.native_recovery.Intent = .{
        .schema = "https://debz.dev/schema/native-execution-intent-v2",
        .version = 2,
        .attempt_id = execution.caller.attempt_id,
        .install_root = execution.install_root,
        .root_identity_sha256 = execution.root_identity_sha256,
        .root_inode = execution.root_inode,
        .operation = execution.operation,
        .architecture = execution.architecture,
        .policy = execution.policy,
        .triggers = execution.triggers,
        .defer_triggers = execution.defer_triggers,
        .staging_directory_initially_present = false,
        .packages = &intent_packages,
        .ordered_actions = &intent_actions,
        .request_sha256 = execution.program.request_sha256,
        .policy_sha256 = execution.program.solver_policy_sha256,
        .authorization_sha256 = execution.program.authorization_sha256,
        .program_sha256 = execution.program.program_sha256,
        .exact_lock_sha256 = execution.program.exact_lock_sha256,
        .artifact_evidence_sha256 = execution.program.artifact_evidence_sha256,
        .database_generation_sha256 = execution.program.database_generation_sha256,
        .initial_trigger_state_sha256 = program.program.installed_database.trigger_state_sha256,
        .authorization_schema = debz.native_authorization.schema_v2_id,
        .authorization_version = debz.native_authorization.schema_v2_version,
        .program_schema = debz.native_program.schema_v2_id,
        .program_version = debz.native_program.schema_v2_version,
        .exact_lock_schema = debz.exact_lock_v3.schema_id,
        .exact_lock_version = debz.exact_lock_v3.schema_version,
        .authorization_path = debz.native_recovery.authorization_v2_name,
        .program_path = debz.native_recovery.program_v2_name,
        .blobs = &request_blob,
        .digest_sha256 = @splat('0'),
    };
    debz.native_recovery.sealIntent(&intent);
    try debz.native_recovery.validateIntent(intent);
    const intent_bytes = try canonicalJsonForCorpus(intent);
    defer allocator.free(intent_bytes);
    try std.testing.expectEqualSlices(
        u8,
        recovery_intent_v2_seed,
        intent_bytes,
    );

    var progress_v3: debz.native_recovery.ProgressDocument = .{
        .schema = debz.native_recovery.authority_progress_schema_id,
        .version = 3,
        .intent_sha256 = intent.digest_sha256,
        .records = &.{},
        .head_sha256 = @splat('0'),
        .digest_sha256 = @splat('0'),
    };
    sealProgressForCorpus(&progress_v3);
    const progress_v3_bytes = try canonicalJsonForCorpus(progress_v3);
    defer allocator.free(progress_v3_bytes);
    try std.testing.expectEqualSlices(u8, progress_v3_seed, progress_v3_bytes);

    var progress_v4 = progress_v3;
    progress_v4.schema =
        debz.native_recovery.authority_bootstrap_progress_schema_id;
    progress_v4.version = 4;
    sealProgressForCorpus(&progress_v4);
    const progress_v4_bytes = try canonicalJsonForCorpus(progress_v4);
    defer allocator.free(progress_v4_bytes);
    try std.testing.expectEqualSlices(u8, progress_v4_seed, progress_v4_bytes);

    const provenance_document = debz.native_provenance.testDocument();
    const provenance_bytes = try provenance_document.canonicalJson(allocator);
    defer allocator.free(provenance_bytes);
    try std.testing.expectEqualSlices(
        u8,
        native_provenance_v2_seed,
        provenance_bytes,
    );

    var legacy_completion = try debz.root_operation_completion.decode(
        allocator,
        @embedFile("corpus/state/root-operation-completion.json"),
        max_input,
    );
    defer legacy_completion.deinit();
    const legacy = legacy_completion.document;
    const completion_record: debz.root_operation.Record = .{
        .attempt_id = legacy.attempt_id,
        .generation = legacy.record_generation,
        .install_root = legacy.install_root,
        .root_identity_sha256 = legacy.root_identity_sha256,
        .backend = legacy.backend,
        .operation = legacy.operation,
        .state = .completed,
        .phase = legacy.phase,
        .step = legacy.step,
        .mutation_started = legacy.mutation_started,
        .outcome = legacy.outcome,
        .provenance = .pending,
        .provenance_sha256 = null,
        .authorization_sha256 = legacy.authorization_sha256,
        .program_sha256 = legacy.program_sha256,
        .plan_sha256 = legacy.plan_sha256,
        .exact_lock = legacy.exact_lock,
        .database_generation_sha256 = legacy.database_generation_sha256,
        .artifact_evidence_sha256 = legacy.artifact_evidence_sha256,
        .request_sha256 = legacy.request_sha256,
        .policy_sha256 = legacy.policy_sha256,
        .target_architecture = legacy.target_architecture,
        .foreign_architectures = legacy.foreign_architectures,
        .reserved_unix = legacy.reserved_unix,
        .updated_unix = legacy.updated_unix,
        .digest_sha256 = legacy.record_digest_sha256,
    };
    var completion_v2 = try debz.root_operation_completion.create(
        allocator,
        .{
            .record = completion_record,
            .transaction_provenance = .{
                .status = legacy.transaction_provenance.status,
                .schema = legacy.transaction_provenance.schema,
                .version = 1,
                .document_sha256 = legacy.transaction_provenance.document_sha256,
                .detail = legacy.transaction_provenance.detail,
            },
            .journal = legacy.journal,
            .discharge = legacy.discharge,
        },
    );
    defer completion_v2.deinit();
    const completion_v2_bytes = try completion_v2.document.canonicalJson(
        allocator,
    );
    defer allocator.free(completion_v2_bytes);
    try std.testing.expectEqualSlices(
        u8,
        root_completion_v2_seed,
        completion_v2_bytes,
    );

    const package_evidence = [_]debz.transaction_provenance_v3.PackageEvidence{.{
        .name = package.name,
        .version = package.version,
        .architecture = package.architecture,
        .origin = package.origin,
        .package_identity = .init(package.archive_identity),
        .cas_identity = .init(package.archive_identity),
        .declared_size = package.declared_size,
    }};
    var result_v3 = try debz.transaction_provenance_v3.create(allocator, .{
        .target_architecture = lock.lock.target_architecture,
        .request_sha256 = lock.lock.request_sha256,
        .solver_policy_sha256 = lock.lock.policy_sha256,
        .executor_policy_sha256 = @splat(3),
        .plan_sha256 = @splat(4),
        .lock_sha256 = lock.lock.digest_sha256,
        .repositories = &.{},
        .packages = &package_evidence,
        .commands = &.{},
        .journal_steps = &.{},
        .final_verification = .{
            .status = .exact_match,
            .installed_state_sha256 = @splat(6),
            .package_origins_sha256 = lock.lock.digest_sha256,
            .detail = "verified",
        },
        .outcome = .succeeded,
    });
    defer result_v3.deinit();
    const result_v3_bytes = try result_v3.result.canonicalJson(allocator);
    defer allocator.free(result_v3_bytes);
    try std.testing.expectEqualSlices(
        u8,
        transaction_result_v3_seed,
        result_v3_bytes,
    );
}

fn expectSeedSha256(bytes: []const u8, expected_hex: []const u8) !void {
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "fuzz.new native state corpus decodes and keeps exact SHA256" {
    {
        var plan = try debz.repository_plan.decode(
            std.testing.allocator,
            transaction_plan_v4_seed,
        );
        defer plan.deinit();
        try std.testing.expectEqual(@as(u32, 4), plan.schema_version);
        try std.testing.expect(
            plan.actions[0].archive_identity.?.digests.sha256 == null,
        );
        try std.testing.expect(
            plan.actions[0].origin_v2.?.local_artifact.evidence
                .archive_identity.digests.sha256 == null,
        );
    }
    {
        var journal = try debz.transaction_recovery.decode(
            std.testing.allocator,
            transaction_journal_v4_seed,
        );
        defer journal.deinit();
        try std.testing.expectEqual(
            debz.transaction_recovery.journal_version,
            journal.journal.version,
        );
        try std.testing.expect(
            journal.journal.commands[0].artifact_identity.?.digests.sha256 ==
                null,
        );
    }
    {
        var authorization = try debz.native_authorization.decode(
            std.testing.allocator,
            authorization_v2_seed,
            max_input,
        );
        defer authorization.deinit();
        try std.testing.expectEqual(
            debz.native_authorization.schema_v2_version,
            authorization.authorization.wire_version,
        );
    }
    {
        var program = try debz.native_program.decode(
            std.testing.allocator,
            program_v2_seed,
            max_input,
        );
        defer program.deinit();
        try std.testing.expectEqual(
            debz.native_program.schema_v2_version,
            program.program.version,
        );
    }
    {
        var request = try debz.native_execution_request.decodePersisted(
            std.testing.allocator,
            execution_request_v4_seed,
        );
        defer request.deinit();
        switch (request) {
            .authority_v2 => |authority| {
                try std.testing.expectEqual(@as(u32, 4), authority.document.version);
                try std.testing.expectEqual(
                    debz.native_authorization.schema_v2_version,
                    authority.document.authority.authorization_version,
                );
                try std.testing.expectEqual(
                    debz.native_program.schema_v2_version,
                    authority.document.authority.program_version,
                );
            },
            else => return error.TestUnexpectedResult,
        }
    }
    {
        var intent = try debz.native_recovery.decodeIntent(
            std.testing.allocator,
            recovery_intent_v2_seed,
        );
        defer intent.deinit();
        try std.testing.expectEqual(@as(u32, 2), intent.intent.version);
        try std.testing.expectEqualStrings(
            debz.native_authorization.schema_v2_id,
            intent.intent.authorization_schema.?,
        );
    }
    {
        var progress = try debz.native_recovery.decodeProgress(
            std.testing.allocator,
            progress_v3_seed,
        );
        defer progress.deinit();
        try std.testing.expectEqual(@as(u32, 3), progress.document.version);
    }
    {
        var progress = try debz.native_recovery.decodeProgress(
            std.testing.allocator,
            progress_v4_seed,
        );
        defer progress.deinit();
        try std.testing.expectEqual(@as(u32, 4), progress.document.version);
    }
    {
        var provenance = try debz.native_provenance.decode(
            std.testing.allocator,
            native_provenance_v2_seed,
        );
        defer provenance.deinit();
        try std.testing.expectEqual(
            debz.native_provenance.schema_version,
            provenance.document.version,
        );
        try std.testing.expectEqual(@as(u32, 4), provenance.document.authority.?.execution_request_version);
    }
    {
        var completion = try debz.root_operation_completion.decode(
            std.testing.allocator,
            root_completion_v2_seed,
            max_input,
        );
        defer completion.deinit();
        try std.testing.expectEqual(
            debz.root_operation_completion.schema_version,
            completion.document.version,
        );
        try std.testing.expectEqual(
            @as(?u32, 1),
            completion.document.transaction_provenance.version,
        );
    }
    {
        var result = try debz.transaction_provenance_v3.validateDocument(
            std.testing.allocator,
            transaction_result_v3_seed,
            max_input,
        );
        defer result.deinit();
        try std.testing.expectEqualSlices(
            u8,
            transaction_result_v3_seed,
            result.bytes,
        );
    }

    for ([_]struct {
        bytes: []const u8,
        sha256: []const u8,
    }{
        .{
            .bytes = authorization_v2_seed,
            .sha256 = "fac02092c4f48a0f0d10d5770f5b4c8b9bff621d233ff3b00153592f3a106ad8",
        },
        .{
            .bytes = program_v2_seed,
            .sha256 = "9dbbeb5ef8d3b0efd8e1c28a1f1b4505c8af7f17301c173c0399b7687743b172",
        },
        .{
            .bytes = execution_request_v4_seed,
            .sha256 = "f97af151b4027b49ba4774d0ef1239bc01f25d1796150cdaa51f072a855303a7",
        },
        .{
            .bytes = recovery_intent_v2_seed,
            .sha256 = "aba35f279872fcfb89d84e26b71c33ff0dc3b9b3e1677fc1e6acb5f8694c2614",
        },
        .{
            .bytes = progress_v3_seed,
            .sha256 = "809309eb17ddeea8d664538cc7ec84672b3fd552871930c6dac61dcebcf27205",
        },
        .{
            .bytes = progress_v4_seed,
            .sha256 = "68274dd9be7c429ae0e30dd0a8e8ad425e35d23420cd537cfcb79bf74f2da0cf",
        },
        .{
            .bytes = native_provenance_v2_seed,
            .sha256 = "e14759efa107056b44eeef55b6e2490937f3e56962200defc587b7f9cf2dc7ab",
        },
        .{
            .bytes = root_completion_v2_seed,
            .sha256 = "ae130977c5fb0b4d4ccce3a34ec1144798a9ac13c316834e70ffd004eb9e6c51",
        },
        .{
            .bytes = transaction_result_v3_seed,
            .sha256 = "0df1317d3a0c8fea9611313b282d0eef7a93d387443cac8610342d1fe1929265",
        },
        .{
            .bytes = transaction_plan_v4_seed,
            .sha256 = "0c970498629ef30f96514a4979110abba8f977717e6f3279ed4aad072c4c5466",
        },
        .{
            .bytes = transaction_journal_v4_seed,
            .sha256 = "6b39b19168b95ed22c9745c0e5c192e4e4b36e47cd5b69765c43724488f32ec6",
        },
    }) |seed| try expectSeedSha256(seed.bytes, seed.sha256);
}
