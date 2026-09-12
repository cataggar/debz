const std = @import("std");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const native_recovery = @import("native_recovery.zig");
const transaction_recovery = @import("transaction_recovery.zig");
const absolute_path = @import("absolute_path.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Digest = [64]u8;

pub fn hexDigest(value: [32]u8) Digest {
    return std.fmt.bytesToHex(value, .lower);
}

fn validDigest(value: Digest) bool {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, &value) catch return false;
    return true;
}

pub const schema_id = "https://debz.dev/schema/native-transaction-provenance-v1";
pub const schema_version: u32 = 1;
pub const document_path = "var/lib/debz/native-transaction-provenance-v1.json";
pub const maximum_document_bytes: usize = 16 * 1024 * 1024;
pub const receipts_directory = "var/lib/debz/native-receipts-v1";
pub const maximum_evidence_files: usize = 1024;
pub const maximum_evidence_file_bytes: usize = 128 * 1024 * 1024;
pub const maximum_evidence_total_bytes: u64 = 512 * 1024 * 1024;

pub const Outcome = enum {
    succeeded,
    failed,
    recovery_required,
};

pub const EvidenceKind = enum {
    helper_binary,
    execution_request,
    authorization,
    program,
    intent,
    progress,
    managed_state,
    trigger_events,
    script_outcome,
    active_script,
    root_operation,
    root_mutation_journal,
    root_mutation_progress,
};

pub const EvidenceAction = struct {
    kind: native_recovery.ActionKind,
    program_step: u32,
    substep: u16,
    ordinal: u32,
};

pub const EvidenceFile = struct {
    kind: EvidenceKind,
    path: []const u8,
    sha256: Digest,
    document_sha256: ?Digest = null,
    action: ?EvidenceAction = null,
    size: u64,
};

pub const EvidenceSource = struct {
    kind: EvidenceKind,
    source_path: []const u8,
    receipt_name: []const u8,
    document_sha256: ?Digest = null,
    expected_sha256: ?Digest = null,
    action: ?native_recovery.Action = null,
    required: bool = true,
};

test "native_provenance.test.retention checks bound bytes before publishing a helper receipt" {
    const testing = std.testing;
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    try root.publishFile(try root_fs.Path.init("helper-input"), "helper bytes", .{});
    const attempt: Digest = @splat('a');
    const sources = [_]EvidenceSource{.{
        .kind = .helper_binary,
        .source_path = "helper-input",
        .receipt_name = "helper.bin",
        .expected_sha256 = @splat('0'),
    }};
    try testing.expectError(error.EvidenceChanged, retainEvidence(testing.allocator, root, attempt, &sources));
    const destination = receipts_directory ++ "/" ++ ("a" ** 64) ++ "/helper.bin";
    try testing.expect(try root.entryIfExists(try root_fs.Path.init(destination)) == null);
}

pub const RetainedEvidence = struct {
    root_path: []const u8,
    files: []const EvidenceFile,
    digest_sha256: Digest,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *RetainedEvidence) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const FinalStateKind = enum {
    package_database_closure_v1,
};

pub const Document = struct {
    schema: []const u8 = schema_id,
    version: u32 = schema_version,
    attempt_id: Digest,
    backend: root_operation.Backend = .native,
    install_root: []const u8,
    root_identity_sha256: Digest,
    root_inode: u64,
    operation: root_operation.Operation,
    request_sha256: Digest,
    policy_sha256: Digest,
    authorization_sha256: Digest,
    program_sha256: Digest,
    exact_lock_sha256: Digest,
    artifact_evidence_sha256: Digest,
    initial_database_generation_sha256: Digest,
    execution_intent_sha256: Digest,
    progress_head_sha256: Digest,
    progress_record_count: u64,
    script_outcomes_sha256: Digest,
    trigger_evidence_sha256: Digest,
    final_database_generation_sha256: Digest,
    final_state_sha256: Digest,
    recovered_phase_count: u64,
    evidence_root: []const u8,
    evidence_files: []const EvidenceFile,
    evidence_files_sha256: Digest,
    final_state_kind: FinalStateKind,
    outcome: Outcome,
    detail: []const u8,
    digest_sha256: Digest,

    pub fn canonicalJson(self: Document, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        std.json.Stringify.value(self, .{ .whitespace = .minified }, &output.writer) catch return error.OutOfMemory;
        output.writer.writeByte('\n') catch return error.OutOfMemory;
        return output.toOwnedSlice();
    }
};

pub const OwnedDocument = struct {
    document: Document,
    parsed: std.json.Parsed(Document),

    pub fn deinit(self: *OwnedDocument) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

fn privatePermissions() std.Io.File.Permissions {
    return if (@import("builtin").os.tag == .windows)
        .default_file
    else
        .fromMode(0o600);
}

fn directoryPermissions() std.Io.File.Permissions {
    return if (@import("builtin").os.tag == .windows)
        .default_file
    else
        .fromMode(0o700);
}

fn evidenceDigest(files: []const EvidenceFile) Digest {
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-native-retained-evidence-v1\x00") catch
        unreachable;
    std.json.Stringify.value(
        files,
        .{ .whitespace = .minified },
        &sink.writer,
    ) catch unreachable;
    sink.writer.flush() catch unreachable;
    return hexDigest(sink.hasher.finalResult());
}

pub fn retainEvidence(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt_id: Digest,
    sources: []const EvidenceSource,
) !RetainedEvidence {
    if (!validDigest(attempt_id) or sources.len > maximum_evidence_files)
        return error.InvalidEvidence;
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    const root_path = try std.fmt.allocPrint(
        owned,
        "{s}/{s}",
        .{ receipts_directory, attempt_id },
    );
    try root.createDirectoryPath(
        try root_fs.Path.init(root_path),
        directoryPermissions(),
    );
    var files: std.ArrayList(EvidenceFile) = .empty;
    var total_bytes: u64 = 0;
    for (sources) |source| {
        if (source.receipt_name.len == 0)
            return error.InvalidEvidence;
        const source_path = try root_fs.Path.init(source.source_path);
        const bytes = root.readFileAlloc(
            owned,
            source_path,
            maximum_evidence_file_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => if (source.required)
                return error.EvidenceMissing
            else
                continue,
            else => return err,
        };
        total_bytes = std.math.add(
            u64,
            total_bytes,
            bytes.len,
        ) catch return error.EvidenceTooLarge;
        if (total_bytes > maximum_evidence_total_bytes)
            return error.EvidenceTooLarge;
        var sha256: [32]u8 = undefined;
        Sha256.hash(bytes, &sha256, .{});
        if (source.expected_sha256) |expected| {
            if (!std.mem.eql(u8, &expected, &hexDigest(sha256)))
                return error.EvidenceChanged;
        }
        const destination = try std.fmt.allocPrint(
            owned,
            "{s}/{s}",
            .{ root_path, source.receipt_name },
        );
        const destination_path = try root_fs.Path.init(destination);
        if (std.mem.lastIndexOfScalar(u8, destination, '/')) |index| {
            try root.createDirectoryPath(
                try root_fs.Path.init(destination[0..index]),
                directoryPermissions(),
            );
        }
        root.publishFile(destination_path, bytes, .{
            .permissions = privatePermissions(),
            .overwrite = .fail_if_exists,
            .durable = true,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                const existing = try root.readFileAlloc(
                    owned,
                    destination_path,
                    maximum_evidence_file_bytes,
                );
                if (!std.mem.eql(u8, existing, bytes))
                    return error.EvidenceChanged;
            },
            else => return err,
        };
        try files.append(owned, .{
            .kind = source.kind,
            .path = destination,
            .sha256 = hexDigest(sha256),
            .document_sha256 = source.document_sha256,
            .action = if (source.action) |action| .{
                .kind = action.kind,
                .program_step = action.program_step,
                .substep = action.substep,
                .ordinal = action.ordinal,
            } else null,
            .size = bytes.len,
        });
    }
    const owned_files = try owned.dupe(EvidenceFile, files.items);
    return .{
        .root_path = root_path,
        .files = owned_files,
        .digest_sha256 = evidenceDigest(owned_files),
        .arena = arena,
        .backing_allocator = allocator,
    };
}

pub fn seal(document: *Document) void {
    document.digest_sha256 = @splat('0');
    document.digest_sha256 = digest(document.*);
}

pub fn validate(document: Document) !void {
    if (!std.mem.eql(u8, document.schema, schema_id) or
        document.version != schema_version or
        document.backend != .native or
        !absolute_path.root(document.install_root) or
        document.install_root.len > 4096 or
        document.detail.len > 4096 or
        document.evidence_files.len > maximum_evidence_files)
        return error.InvalidDocument;
    const root_identity = hexDigest(
        transaction_recovery.rootIdentity(document.install_root),
    );
    if (!std.mem.eql(
        u8,
        &document.root_identity_sha256,
        &root_identity,
    )) return error.InvalidDocument;
    inline for (.{
        document.attempt_id,
        document.root_identity_sha256,
        document.request_sha256,
        document.policy_sha256,
        document.authorization_sha256,
        document.program_sha256,
        document.exact_lock_sha256,
        document.artifact_evidence_sha256,
        document.initial_database_generation_sha256,
        document.execution_intent_sha256,
        document.progress_head_sha256,
        document.script_outcomes_sha256,
        document.trigger_evidence_sha256,
        document.final_database_generation_sha256,
        document.final_state_sha256,
        document.evidence_files_sha256,
        document.digest_sha256,
    }) |value| if (!validDigest(value)) return error.InvalidDigest;
    const evidence_prefix = receipts_directory ++ "/";
    if (!std.mem.startsWith(
        u8,
        document.evidence_root,
        evidence_prefix,
    ) or !std.mem.eql(
        u8,
        document.evidence_root[evidence_prefix.len..],
        &document.attempt_id,
    ) or !std.mem.eql(
        u8,
        &document.evidence_files_sha256,
        &evidenceDigest(document.evidence_files),
    )) return error.InvalidDocument;
    var evidence_kinds = std.EnumSet(EvidenceKind).initEmpty();
    for (document.evidence_files, 0..) |file, index| {
        if (file.path.len <= document.evidence_root.len or
            !std.mem.startsWith(
                u8,
                file.path,
                document.evidence_root,
            ) or file.path[document.evidence_root.len] != '/' or
            !validDigest(file.sha256) or
            (file.document_sha256 != null and
                !validDigest(file.document_sha256.?)))
            return error.InvalidEvidence;
        _ = root_fs.Path.init(file.path) catch return error.InvalidEvidence;
        for (document.evidence_files[0..index]) |prior|
            if (std.mem.eql(u8, prior.path, file.path))
                return error.InvalidEvidence;
        if (file.kind == .script_outcome and file.action == null)
            return error.InvalidEvidence;
        if (file.kind != .script_outcome and file.action != null)
            return error.InvalidEvidence;
        switch (file.kind) {
            .execution_request,
            .authorization,
            .program,
            .intent,
            .progress,
            .managed_state,
            .trigger_events,
            .script_outcome,
            .root_operation,
            => if (file.document_sha256 == null)
                return error.InvalidEvidence,
            .active_script,
            .helper_binary,
            .root_mutation_journal,
            .root_mutation_progress,
            => {},
        }
        if (file.kind != .script_outcome) {
            if (evidence_kinds.contains(file.kind))
                return error.InvalidEvidence;
            evidence_kinds.insert(file.kind);
        }
    }
    inline for (.{
        EvidenceKind.authorization,
        EvidenceKind.program,
        EvidenceKind.intent,
        EvidenceKind.progress,
        EvidenceKind.managed_state,
        EvidenceKind.trigger_events,
    }) |kind| if (!evidence_kinds.contains(kind))
        return error.InvalidEvidence;
    var payload = document;
    const expected = payload.digest_sha256;
    payload.digest_sha256 = @splat('0');
    if (!std.mem.eql(u8, &expected, &digest(payload)))
        return error.DigestMismatch;
}

pub fn publish(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    document: Document,
) !void {
    try validate(document);
    const bytes = try document.canonicalJson(allocator);
    defer allocator.free(bytes);
    if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
    const path = try root_fs.Path.init(document_path);
    const existing_bytes = root.readFileAlloc(
        allocator,
        path,
        maximum_document_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (existing_bytes) |existing| {
        defer allocator.free(existing);
        if (std.mem.eql(u8, existing, bytes)) return;
        var owned = try read(allocator, root) orelse
            return error.ProvenanceChanged;
        defer owned.deinit();
        if (std.mem.eql(
            u8,
            &owned.document.attempt_id,
            &document.attempt_id,
        )) return error.ProvenanceChanged;
    }
    try root.publishFile(path, bytes, .{
        .permissions = if (@import("builtin").os.tag == .windows)
            .default_file
        else
            .fromMode(0o600),
        .overwrite = .replace,
        .durable = true,
    });
}

pub fn read(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
) !?OwnedDocument {
    const path = try root_fs.Path.init(document_path);
    const bytes = root.readFileAlloc(
        allocator,
        path,
        maximum_document_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);
    return try decode(allocator, bytes);
}

/// Checks the canonical receipt document, not its retained files or current root.
pub fn decode(allocator: std.mem.Allocator, source: []const u8) !OwnedDocument {
    if (source.len > maximum_document_bytes) return error.DocumentTooLarge;
    var parsed = try std.json.parseFromSlice(
        Document,
        allocator,
        source,
        .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
    );
    errdefer parsed.deinit();
    try validate(parsed.value);
    const canonical = try parsed.value.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source))
        return error.NonCanonicalDocument;
    return .{ .document = parsed.value, .parsed = parsed };
}

pub fn verifyEvidence(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    document: Document,
) !void {
    try validate(document);
    var total_bytes: u64 = 0;
    for (document.evidence_files) |evidence| {
        const maximum = std.math.cast(usize, evidence.size) orelse
            return error.EvidenceTooLarge;
        if (maximum > maximum_evidence_file_bytes)
            return error.EvidenceTooLarge;
        const bytes = try root.readFileAlloc(
            allocator,
            try root_fs.Path.init(evidence.path),
            maximum,
        );
        defer allocator.free(bytes);
        if (bytes.len != evidence.size)
            return error.EvidenceChanged;
        total_bytes = std.math.add(
            u64,
            total_bytes,
            bytes.len,
        ) catch return error.EvidenceTooLarge;
        if (total_bytes > maximum_evidence_total_bytes)
            return error.EvidenceTooLarge;
        var sha256: [32]u8 = undefined;
        Sha256.hash(bytes, &sha256, .{});
        if (!std.mem.eql(
            u8,
            &hexDigest(sha256),
            &evidence.sha256,
        )) return error.EvidenceChanged;
    }
}

fn digest(document: Document) Digest {
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-native-transaction-provenance-v1\x00") catch
        unreachable;
    std.json.Stringify.value(
        document,
        .{ .whitespace = .minified },
        &sink.writer,
    ) catch unreachable;
    sink.writer.flush() catch unreachable;
    return hexDigest(sink.hasher.finalResult());
}

pub fn testDocument() Document {
    const attempt_id: Digest = @splat('1');
    const evidence_root =
        receipts_directory ++
        "/1111111111111111111111111111111111111111111111111111111111111111";
    const evidence_files = comptime &[_]EvidenceFile{
        .{
            .kind = .authorization,
            .path = evidence_root ++ "/authorization.json",
            .sha256 = @splat('1'),
            .document_sha256 = @splat('2'),
            .size = 1,
        },
        .{
            .kind = .program,
            .path = evidence_root ++ "/program.json",
            .sha256 = @splat('2'),
            .document_sha256 = @splat('3'),
            .size = 1,
        },
        .{
            .kind = .intent,
            .path = evidence_root ++ "/intent.json",
            .sha256 = @splat('3'),
            .document_sha256 = @splat('4'),
            .size = 1,
        },
        .{
            .kind = .progress,
            .path = evidence_root ++ "/progress.json",
            .sha256 = @splat('4'),
            .document_sha256 = @splat('5'),
            .size = 1,
        },
        .{
            .kind = .managed_state,
            .path = evidence_root ++ "/managed-state.json",
            .sha256 = @splat('5'),
            .document_sha256 = @splat('6'),
            .size = 1,
        },
        .{
            .kind = .trigger_events,
            .path = evidence_root ++ "/trigger-events.json",
            .sha256 = @splat('6'),
            .document_sha256 = @splat('7'),
            .size = 1,
        },
    };
    var document: Document = .{
        .attempt_id = attempt_id,
        .install_root = "/srv/root",
        .root_identity_sha256 = hexDigest(
            transaction_recovery.rootIdentity("/srv/root"),
        ),
        .root_inode = 42,
        .operation = .{ .package_transaction = .install },
        .request_sha256 = @splat('3'),
        .policy_sha256 = @splat('4'),
        .authorization_sha256 = @splat('5'),
        .program_sha256 = @splat('6'),
        .exact_lock_sha256 = @splat('7'),
        .artifact_evidence_sha256 = @splat('8'),
        .initial_database_generation_sha256 = @splat('9'),
        .execution_intent_sha256 = @splat('a'),
        .progress_head_sha256 = @splat('b'),
        .progress_record_count = 12,
        .script_outcomes_sha256 = @splat('c'),
        .trigger_evidence_sha256 = @splat('d'),
        .final_database_generation_sha256 = @splat('e'),
        .final_state_sha256 = @splat('f'),
        .recovered_phase_count = 1,
        .evidence_root = evidence_root,
        .evidence_files = evidence_files,
        .evidence_files_sha256 = evidenceDigest(evidence_files),
        .final_state_kind = .package_database_closure_v1,
        .outcome = .succeeded,
        .detail = "recovered",
        .digest_sha256 = @splat('0'),
    };
    seal(&document);
    return document;
}

pub fn testContract() !void {
    var document = testDocument();
    try validate(document);
    document.progress_record_count += 1;
    try std.testing.expectError(error.DigestMismatch, validate(document));
}

test "native_provenance.test.digest binds terminal evidence" {
    try testContract();
}

fn testDecodeAllocation(allocator: std.mem.Allocator, source: []const u8) !void {
    var document = try decode(allocator, source);
    defer document.deinit();
    const canonical = try document.document.canonicalJson(allocator);
    defer allocator.free(canonical);
    try std.testing.expectEqualStrings(source, canonical);
}

test "native_provenance.test.canonical byte decoding preserves outcomes and allocation failures" {
    const allocator = std.testing.allocator;
    const oversized = try allocator.alloc(u8, maximum_document_bytes + 1);
    defer allocator.free(oversized);
    try std.testing.expectError(error.DocumentTooLarge, decode(allocator, oversized));
    for ([_]Outcome{ .succeeded, .failed, .recovery_required }) |outcome| {
        var document = testDocument();
        document.outcome = outcome;
        seal(&document);
        const source = try document.canonicalJson(allocator);
        defer allocator.free(source);
        try std.testing.checkAllAllocationFailures(allocator, testDecodeAllocation, .{source});
        var decoded = try decode(allocator, source);
        defer decoded.deinit();
        try std.testing.expectEqual(outcome, decoded.document.outcome);
        const noncanonical = try std.fmt.allocPrint(allocator, "{s}\n", .{source});
        defer allocator.free(noncanonical);
        try std.testing.expectError(error.NonCanonicalDocument, decode(allocator, noncanonical));
        document.detail = "changed without resealing";
        const changed = try document.canonicalJson(allocator);
        defer allocator.free(changed);
        try std.testing.expectError(error.DigestMismatch, decode(allocator, changed));
    }
}
