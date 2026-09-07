//! Root-operation completion provenance version 1.
//!
//! A mutation of a selected root is over once its terminal `completed`
//! boundary is durable, but the active record may not be removed until the
//! provenance it owes has been published. A crash inside that window — after
//! the completed record, before the provenance transition — leaves a record
//! that blocks every later mutation and an operation whose detailed
//! transaction provenance may or may not have reached the state directory.
//!
//! This module owns the durable statement that discharges exactly that
//! obligation. It never invents an execution: it binds the completed record it
//! discharges, the evidence digests that record already carried, the active
//! record's own generation and digest, and an explicit classification of what
//! survived of the detailed transaction provenance and of the transaction
//! journal. A document that says the detailed provenance was `unavailable`
//! says only that: the transaction completion was durably witnessed and its
//! detailed publication was interrupted. No command, script, package, or
//! verification outcome is ever reconstructed here.
//!
//! The document lives in the root's own `var/lib/debz` namespace beside the
//! active record and is reached only through `root_fs`, so no component of its
//! path is resolved through a symbolic link and nothing is written outside the
//! selected root. Publication is atomic, durable, and idempotent: republishing
//! the same statement rewrites nothing.
const std = @import("std");
const builtin = @import("builtin");
const absolute_path = @import("absolute_path.zig");
const product_api = @import("product_api.zig");
const repository_api = @import("repository_api.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const transaction_recovery = @import("transaction_recovery.zig");

pub const schema_id = "https://debz.dev/schema/root-operation-completion-v1";
pub const schema_version: u32 = 1;

/// The document is small and fixed-shape. The ceiling exists so a hostile or
/// damaged root cannot force an unbounded read before validation.
pub const maximum_document_bytes: usize = 64 * 1024;
pub const maximum_detail_bytes: usize = 256;
pub const maximum_schema_bytes: usize = 256;

pub const document_name = "root-operation-completion-v1.json";
pub const document_path = root_operation.namespace_path ++ "/" ++ document_name;

/// What survived of the detailed transaction provenance for the completed
/// attempt.
pub const TransactionProvenanceStatus = enum {
    /// A detailed provenance document was already published before the
    /// interruption and was verified to bind this attempt.
    already_present,
    /// A detailed provenance document was rebuilt from durable evidence during
    /// recovery and published before this statement.
    recovered,
    /// No detailed provenance document exists for this attempt: publication
    /// was interrupted by the crash window, or the operation never published
    /// one. The transaction completion itself is still durably witnessed by
    /// the record this statement binds.
    unavailable,
};

/// What the transaction journal for the completed attempt looks like now. It
/// is evidence, never authority: the journal is command-level state owned by
/// the executor, so an unreadable journal is reported rather than treated as a
/// missing obligation.
pub const JournalStatus = enum { archived, active, absent, unreadable };

pub const TransactionProvenance = struct {
    status: TransactionProvenanceStatus,
    /// Schema identifier of the bound document. Empty exactly when no document
    /// is bound.
    schema: []const u8 = "",
    document_sha256: ?[32]u8 = null,
    detail: []const u8,
};

pub const Journal = struct {
    status: JournalStatus,
    document_sha256: ?[32]u8 = null,
    detail: []const u8,
};

/// The operation that discharged the obligation. It is recorded separately
/// from the completed attempt's own request so a reader can never mistake the
/// recovering command for the command that mutated the root.
pub const Discharge = struct {
    surface: root_operation.Surface,
    operation: []const u8,
    request_sha256: [32]u8,
};

pub const Document = struct {
    attempt_id: [32]u8,
    /// Generation and digest of the active record this statement discharges,
    /// exactly as observed under the root mutation lock.
    record_generation: u64,
    record_digest_sha256: [32]u8,
    install_root: []const u8,
    root_identity_sha256: [32]u8,
    backend: root_operation.Backend,
    operation: root_operation.Operation,
    phase: root_operation.Phase,
    step: u64,
    mutation_started: bool,
    outcome: root_operation.Outcome,
    request_sha256: [32]u8,
    policy_sha256: [32]u8,
    authorization_sha256: ?[32]u8,
    program_sha256: ?[32]u8,
    plan_sha256: ?[32]u8,
    exact_lock: ?root_operation.LockBinding,
    database_generation_sha256: ?[32]u8,
    artifact_evidence_sha256: ?[32]u8,
    target_architecture: []const u8,
    foreign_architectures: []const []const u8,
    reserved_unix: i64,
    updated_unix: i64,
    transaction_provenance: TransactionProvenance,
    journal: Journal,
    discharge: Discharge,
    digest_sha256: [32]u8,

    /// An allocating writer can only fail by running out of memory, so the
    /// generic write error is translated into the exact one.
    pub fn canonicalJson(
        self: Document,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        writeDocument(self, &output.writer) catch return error.OutOfMemory;
        return output.toOwnedSlice() catch error.OutOfMemory;
    }

    /// Whether this statement describes exactly the attempt behind `record`.
    /// Only fields that are sticky across the provenance transition are
    /// compared, so a statement published before `publishProvenance` still
    /// binds the record that transition produced.
    pub fn bindsRecord(self: Document, record: root_operation.Record) bool {
        return std.mem.eql(u8, &self.attempt_id, &record.attempt_id) and
            std.mem.eql(u8, &self.root_identity_sha256, &record.root_identity_sha256) and
            std.mem.eql(u8, self.install_root, record.install_root) and
            self.backend == record.backend and
            self.operation.eql(record.operation) and
            self.outcome == record.outcome and
            self.mutation_started == record.mutation_started and
            std.mem.eql(u8, &self.request_sha256, &record.request_sha256) and
            std.mem.eql(u8, &self.policy_sha256, &record.policy_sha256) and
            std.mem.eql(u8, self.target_architecture, record.target_architecture) and
            optionalDigestEqual(self.authorization_sha256, record.authorization_sha256) and
            optionalDigestEqual(self.program_sha256, record.program_sha256) and
            optionalDigestEqual(self.plan_sha256, record.plan_sha256) and
            optionalLockEqual(self.exact_lock, record.exact_lock) and
            optionalDigestEqual(
                self.database_generation_sha256,
                record.database_generation_sha256,
            ) and
            optionalDigestEqual(
                self.artifact_evidence_sha256,
                record.artifact_evidence_sha256,
            );
    }
};

pub const OwnedDocument = struct {
    document: Document,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedDocument) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const Input = struct {
    record: root_operation.Record,
    transaction_provenance: TransactionProvenance,
    journal: Journal,
    discharge: Discharge,
};

pub const ValidationError = error{
    InvalidRoot,
    InvalidRecordState,
    InvalidGeneration,
    InvalidOutcome,
    InvalidMutationEvidence,
    InvalidArchitecture,
    DuplicateArchitecture,
    TooManyArchitectures,
    InvalidLockBinding,
    InvalidTransactionProvenance,
    InvalidJournalEvidence,
    InvalidDischarge,
    InvalidDetail,
    InvalidDigest,
    UnsupportedSchema,
    NonCanonicalDocument,
    DigestMismatch,
    DocumentTooLarge,
};

/// Builds a validated statement for a completed attempt that still owes
/// provenance. Every combination of outcome, mutation evidence, and surviving
/// evidence is checked here, so no caller can publish a statement that claims
/// more than the record it discharges proves.
pub fn create(
    allocator: std.mem.Allocator,
    input: Input,
) (ValidationError || error{OutOfMemory})!OwnedDocument {
    const record = input.record;
    if (!absolute_path.root(record.install_root)) return error.InvalidRoot;
    if (record.install_root.len > root_operation.maximum_root_bytes) return error.InvalidRoot;
    if (!std.mem.eql(
        u8,
        &record.root_identity_sha256,
        &transaction_recovery.rootIdentity(record.install_root),
    )) return error.InvalidRoot;
    if (record.state != .completed) return error.InvalidRecordState;
    if (record.generation == 0) return error.InvalidGeneration;
    if (!record.mutation_started) return error.InvalidMutationEvidence;
    switch (record.outcome) {
        .succeeded, .failed_after_mutation, .recovered => {},
        .pending, .abandoned_before_mutation => return error.InvalidOutcome,
    }
    if (!validArchitecture(record.target_architecture)) return error.InvalidArchitecture;
    if (record.foreign_architectures.len > root_operation.maximum_architectures)
        return error.TooManyArchitectures;
    if (record.exact_lock) |binding| {
        if (binding.schema.len == 0 or binding.schema.len > maximum_schema_bytes or
            binding.version == 0) return error.InvalidLockBinding;
    }
    try validateTransactionProvenance(input.transaction_provenance);
    try validateJournal(input.journal);
    try validateDischarge(input.discharge);

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const foreign = try owned.alloc([]const u8, record.foreign_architectures.len);
    for (record.foreign_architectures, 0..) |architecture, index| {
        if (!validArchitecture(architecture)) return error.InvalidArchitecture;
        foreign[index] = try owned.dupe(u8, architecture);
    }
    std.mem.sort([]const u8, foreign, {}, lessText);
    for (foreign, 0..) |architecture, index| {
        if (index != 0 and std.mem.eql(u8, architecture, foreign[index - 1]))
            return error.DuplicateArchitecture;
        if (std.mem.eql(u8, architecture, record.target_architecture))
            return error.DuplicateArchitecture;
    }

    var document: Document = .{
        .attempt_id = record.attempt_id,
        .record_generation = record.generation,
        .record_digest_sha256 = record.digest_sha256,
        .install_root = try owned.dupe(u8, record.install_root),
        .root_identity_sha256 = record.root_identity_sha256,
        .backend = record.backend,
        .operation = record.operation,
        .phase = record.phase,
        .step = record.step,
        .mutation_started = record.mutation_started,
        .outcome = record.outcome,
        .request_sha256 = record.request_sha256,
        .policy_sha256 = record.policy_sha256,
        .authorization_sha256 = record.authorization_sha256,
        .program_sha256 = record.program_sha256,
        .plan_sha256 = record.plan_sha256,
        .exact_lock = null,
        .database_generation_sha256 = record.database_generation_sha256,
        .artifact_evidence_sha256 = record.artifact_evidence_sha256,
        .target_architecture = try owned.dupe(u8, record.target_architecture),
        .foreign_architectures = foreign,
        .reserved_unix = record.reserved_unix,
        .updated_unix = record.updated_unix,
        .transaction_provenance = .{
            .status = input.transaction_provenance.status,
            .schema = try owned.dupe(u8, input.transaction_provenance.schema),
            .document_sha256 = input.transaction_provenance.document_sha256,
            .detail = try owned.dupe(u8, input.transaction_provenance.detail),
        },
        .journal = .{
            .status = input.journal.status,
            .document_sha256 = input.journal.document_sha256,
            .detail = try owned.dupe(u8, input.journal.detail),
        },
        .discharge = .{
            .surface = input.discharge.surface,
            .operation = try owned.dupe(u8, input.discharge.operation),
            .request_sha256 = input.discharge.request_sha256,
        },
        .digest_sha256 = undefined,
    };
    if (record.exact_lock) |binding| document.exact_lock = .{
        .schema = try owned.dupe(u8, binding.schema),
        .version = binding.version,
        .digest_sha256 = binding.digest_sha256,
    };
    document.digest_sha256 = digestPayload(document);
    return .{ .document = document, .arena = arena, .backing_allocator = allocator };
}

fn validateTransactionProvenance(value: TransactionProvenance) ValidationError!void {
    try validateDetail(value.detail);
    switch (value.status) {
        .already_present, .recovered => {
            if (value.document_sha256 == null) return error.InvalidTransactionProvenance;
            if (value.schema.len == 0 or value.schema.len > maximum_schema_bytes)
                return error.InvalidTransactionProvenance;
            if (!printableText(value.schema)) return error.InvalidTransactionProvenance;
        },
        .unavailable => {
            if (value.document_sha256 != null) return error.InvalidTransactionProvenance;
            if (value.schema.len != 0) return error.InvalidTransactionProvenance;
        },
    }
}

fn validateJournal(value: Journal) ValidationError!void {
    try validateDetail(value.detail);
    switch (value.status) {
        .archived, .active => if (value.document_sha256 == null)
            return error.InvalidJournalEvidence,
        .absent, .unreadable => if (value.document_sha256 != null)
            return error.InvalidJournalEvidence,
    }
}

fn validateDischarge(value: Discharge) ValidationError!void {
    if (value.operation.len == 0 or value.operation.len > maximum_detail_bytes)
        return error.InvalidDischarge;
    if (!printableText(value.operation)) return error.InvalidDischarge;
    _ = parseOperation(value.surface, value.operation) catch return error.InvalidDischarge;
}

fn validateDetail(detail: []const u8) ValidationError!void {
    if (detail.len == 0 or detail.len > maximum_detail_bytes) return error.InvalidDetail;
    if (!printableText(detail)) return error.InvalidDetail;
}

/// Details and schema identifiers are read by operators, so they are held to
/// printable ASCII. A damaged or hostile string can never smuggle control
/// bytes into a diagnostic through this document.
fn printableText(value: []const u8) bool {
    for (value) |byte| if (byte < 0x20 or byte > 0x7e) return false;
    return true;
}

fn optionalDigestEqual(left: ?[32]u8, right: ?[32]u8) bool {
    if (left) |value| {
        const other = right orelse return false;
        return std.mem.eql(u8, &value, &other);
    }
    return right == null;
}

fn optionalLockEqual(
    left: ?root_operation.LockBinding,
    right: ?root_operation.LockBinding,
) bool {
    if (left) |value| {
        const other = right orelse return false;
        return value.eql(other);
    }
    return right == null;
}

fn lessText(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0 or value.len > root_operation.maximum_architecture_bytes) return false;
    for (value) |byte| switch (byte) {
        'a'...'z', '0'...'9', '-' => {},
        else => return false,
    };
    return true;
}

fn digestPayload(document: Document) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writePayload(document, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn writeDocument(document: Document, writer: *std.Io.Writer) !void {
    try writePayload(document, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHexString(writer, &document.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(document: Document, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeJsonString(writer, schema_id);
    try writer.print(",\"version\":{},\"attempt_id\":", .{schema_version});
    try writeHexString(writer, &document.attempt_id);
    try writer.print(",\"record_generation\":{},\"record_digest_sha256\":", .{
        document.record_generation,
    });
    try writeHexString(writer, &document.record_digest_sha256);
    try writer.writeAll(",\"install_root\":");
    try writeJsonString(writer, document.install_root);
    try writer.writeAll(",\"root_identity_sha256\":");
    try writeHexString(writer, &document.root_identity_sha256);
    try writer.writeAll(",\"backend\":");
    try writeJsonString(writer, @tagName(document.backend));
    try writer.writeAll(",\"surface\":");
    try writeJsonString(writer, @tagName(std.meta.activeTag(document.operation)));
    try writer.writeAll(",\"operation\":");
    try writeJsonString(writer, document.operation.spelling());
    try writer.writeAll(",\"phase\":");
    try writeJsonString(writer, @tagName(document.phase));
    try writer.print(",\"step\":{},\"mutation_started\":{}", .{
        document.step,
        document.mutation_started,
    });
    try writer.writeAll(",\"outcome\":");
    try writeJsonString(writer, @tagName(document.outcome));
    try writer.writeAll(",\"request_sha256\":");
    try writeHexString(writer, &document.request_sha256);
    try writer.writeAll(",\"policy_sha256\":");
    try writeHexString(writer, &document.policy_sha256);
    try writer.writeAll(",\"authorization_sha256\":");
    try writeOptionalHex(writer, document.authorization_sha256);
    try writer.writeAll(",\"program_sha256\":");
    try writeOptionalHex(writer, document.program_sha256);
    try writer.writeAll(",\"plan_sha256\":");
    try writeOptionalHex(writer, document.plan_sha256);
    try writer.writeAll(",\"exact_lock\":");
    if (document.exact_lock) |binding| {
        try writer.writeAll("{\"schema\":");
        try writeJsonString(writer, binding.schema);
        try writer.print(",\"version\":{},\"digest_sha256\":", .{binding.version});
        try writeHexString(writer, &binding.digest_sha256);
        try writer.writeByte('}');
    } else try writer.writeAll("null");
    try writer.writeAll(",\"database_generation_sha256\":");
    try writeOptionalHex(writer, document.database_generation_sha256);
    try writer.writeAll(",\"artifact_evidence_sha256\":");
    try writeOptionalHex(writer, document.artifact_evidence_sha256);
    try writer.writeAll(",\"target_architecture\":");
    try writeJsonString(writer, document.target_architecture);
    try writer.writeAll(",\"foreign_architectures\":[");
    for (document.foreign_architectures, 0..) |architecture, index| {
        if (index != 0) try writer.writeByte(',');
        try writeJsonString(writer, architecture);
    }
    try writer.print("],\"reserved_unix\":{},\"updated_unix\":{}", .{
        document.reserved_unix,
        document.updated_unix,
    });
    try writer.writeAll(",\"transaction_provenance\":{\"status\":");
    try writeJsonString(writer, @tagName(document.transaction_provenance.status));
    try writer.writeAll(",\"schema\":");
    if (document.transaction_provenance.schema.len == 0)
        try writer.writeAll("null")
    else
        try writeJsonString(writer, document.transaction_provenance.schema);
    try writer.writeAll(",\"document_sha256\":");
    try writeOptionalHex(writer, document.transaction_provenance.document_sha256);
    try writer.writeAll(",\"detail\":");
    try writeJsonString(writer, document.transaction_provenance.detail);
    try writer.writeAll("},\"journal\":{\"status\":");
    try writeJsonString(writer, @tagName(document.journal.status));
    try writer.writeAll(",\"document_sha256\":");
    try writeOptionalHex(writer, document.journal.document_sha256);
    try writer.writeAll(",\"detail\":");
    try writeJsonString(writer, document.journal.detail);
    try writer.writeAll("},\"discharge\":{\"surface\":");
    try writeJsonString(writer, @tagName(document.discharge.surface));
    try writer.writeAll(",\"operation\":");
    try writeJsonString(writer, document.discharge.operation);
    try writer.writeAll(",\"request_sha256\":");
    try writeHexString(writer, &document.discharge.request_sha256);
    try writer.writeAll("}}");
}

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        0x00...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

fn writeHexString(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
    try writer.writeByte('"');
}

fn writeOptionalHex(writer: *std.Io.Writer, value: ?[32]u8) !void {
    if (value) |bytes| try writeHexString(writer, &bytes) else try writer.writeAll("null");
}

fn parseHex(comptime size: usize, value: []const u8) ValidationError![size]u8 {
    if (value.len != size * 2) return error.InvalidDigest;
    var result: [size]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidDigest;
    return result;
}

fn parseOptionalHex(value: ?[]const u8) ValidationError!?[32]u8 {
    const text = value orelse return null;
    return try parseHex(32, text);
}

fn parseOperation(
    surface: root_operation.Surface,
    spelling: []const u8,
) ValidationError!root_operation.Operation {
    return switch (surface) {
        .package_transaction => .{
            .package_transaction = std.meta.stringToEnum(product_api.Operation, spelling) orelse
                return error.NonCanonicalDocument,
        },
        .repository_bootstrap => .{
            .repository_bootstrap = std.meta.stringToEnum(repository_api.Operation, spelling) orelse
                return error.NonCanonicalDocument,
        },
    };
}

const WireLockBinding = struct {
    schema: []const u8,
    version: u32,
    digest_sha256: []const u8,
};

const WireTransactionProvenance = struct {
    status: TransactionProvenanceStatus,
    schema: ?[]const u8,
    document_sha256: ?[]const u8,
    detail: []const u8,
};

const WireJournal = struct {
    status: JournalStatus,
    document_sha256: ?[]const u8,
    detail: []const u8,
};

const WireDischarge = struct {
    surface: root_operation.Surface,
    operation: []const u8,
    request_sha256: []const u8,
};

const WireDocument = struct {
    schema: []const u8,
    version: u32,
    attempt_id: []const u8,
    record_generation: u64,
    record_digest_sha256: []const u8,
    install_root: []const u8,
    root_identity_sha256: []const u8,
    backend: root_operation.Backend,
    surface: root_operation.Surface,
    operation: []const u8,
    phase: root_operation.Phase,
    step: u64,
    mutation_started: bool,
    outcome: root_operation.Outcome,
    request_sha256: []const u8,
    policy_sha256: []const u8,
    authorization_sha256: ?[]const u8,
    program_sha256: ?[]const u8,
    plan_sha256: ?[]const u8,
    exact_lock: ?WireLockBinding,
    database_generation_sha256: ?[]const u8,
    artifact_evidence_sha256: ?[]const u8,
    target_architecture: []const u8,
    foreign_architectures: []const []const u8,
    reserved_unix: i64,
    updated_unix: i64,
    transaction_provenance: WireTransactionProvenance,
    journal: WireJournal,
    discharge: WireDischarge,
    digest_sha256: []const u8,
};

/// Strict bounded decode. Unknown fields, missing fields, an unsupported
/// schema, a mismatched digest, a foreign root identity, and any byte sequence
/// that is not the exact canonical encoding are all rejected.
pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !OwnedDocument {
    if (source.len > maximum_bytes or source.len > maximum_document_bytes)
        return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(WireDocument, allocator, source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.NonCanonicalDocument,
    };
    defer parsed.deinit();
    const wire = parsed.value;
    if (!std.mem.eql(u8, wire.schema, schema_id) or wire.version != schema_version)
        return error.UnsupportedSchema;
    const operation = try parseOperation(wire.surface, wire.operation);
    const record: root_operation.Record = .{
        .attempt_id = try parseHex(32, wire.attempt_id),
        .generation = wire.record_generation,
        .install_root = wire.install_root,
        .root_identity_sha256 = try parseHex(32, wire.root_identity_sha256),
        .backend = wire.backend,
        .operation = operation,
        .state = .completed,
        .phase = wire.phase,
        .step = wire.step,
        .mutation_started = wire.mutation_started,
        .outcome = wire.outcome,
        .provenance = .pending,
        .provenance_sha256 = null,
        .authorization_sha256 = try parseOptionalHex(wire.authorization_sha256),
        .program_sha256 = try parseOptionalHex(wire.program_sha256),
        .plan_sha256 = try parseOptionalHex(wire.plan_sha256),
        .exact_lock = if (wire.exact_lock) |binding| .{
            .schema = binding.schema,
            .version = binding.version,
            .digest_sha256 = try parseHex(32, binding.digest_sha256),
        } else null,
        .database_generation_sha256 = try parseOptionalHex(wire.database_generation_sha256),
        .artifact_evidence_sha256 = try parseOptionalHex(wire.artifact_evidence_sha256),
        .request_sha256 = try parseHex(32, wire.request_sha256),
        .policy_sha256 = try parseHex(32, wire.policy_sha256),
        .target_architecture = wire.target_architecture,
        .foreign_architectures = wire.foreign_architectures,
        .reserved_unix = wire.reserved_unix,
        .updated_unix = wire.updated_unix,
        .digest_sha256 = try parseHex(32, wire.record_digest_sha256),
    };
    var result = try create(allocator, .{
        .record = record,
        .transaction_provenance = .{
            .status = wire.transaction_provenance.status,
            .schema = wire.transaction_provenance.schema orelse "",
            .document_sha256 = try parseOptionalHex(wire.transaction_provenance.document_sha256),
            .detail = wire.transaction_provenance.detail,
        },
        .journal = .{
            .status = wire.journal.status,
            .document_sha256 = try parseOptionalHex(wire.journal.document_sha256),
            .detail = wire.journal.detail,
        },
        .discharge = .{
            .surface = wire.discharge.surface,
            .operation = wire.discharge.operation,
            .request_sha256 = try parseHex(32, wire.discharge.request_sha256),
        },
    });
    errdefer result.deinit();
    const expected = try parseHex(32, wire.digest_sha256);
    if (!std.mem.eql(u8, &expected, &result.document.digest_sha256))
        return error.DigestMismatch;
    const canonical = try result.document.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return result;
}

const document_permissions: std.Io.File.Permissions =
    if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);

/// Root-anchored durable store beside the active record. Reads never follow a
/// symbolic link and never accept a directory or special file; publication
/// stages privately, fsyncs, and renames, so a reader only ever sees a
/// complete statement.
pub const Store = struct {
    root: root_fs.Root,

    pub fn init(root: root_fs.Root) Store {
        return .{ .root = root };
    }

    /// Raw bytes of the published statement, or `null` when none exists.
    pub fn readBytes(self: Store, allocator: std.mem.Allocator) !?[]u8 {
        const path = try root_fs.Path.init(document_path);
        return self.root.readFileAlloc(allocator, path, maximum_document_bytes) catch |err|
            switch (err) {
                error.FileNotFound => null,
                else => err,
            };
    }

    /// `null` only when no statement exists. A statement that cannot be
    /// decoded is an error, never an absent one.
    pub fn read(self: Store, allocator: std.mem.Allocator) !?OwnedDocument {
        const bytes = try self.readBytes(allocator) orelse return null;
        defer allocator.free(bytes);
        return try decode(allocator, bytes, maximum_document_bytes);
    }

    /// Publishes the statement atomically and durably. Republishing an
    /// identical statement rewrites nothing, so a recovery that is retried
    /// after a crash converges on exactly one document.
    pub fn publish(
        self: Store,
        allocator: std.mem.Allocator,
        document: Document,
    ) !void {
        const bytes = try document.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
        if (self.readBytes(allocator) catch null) |existing| {
            defer allocator.free(existing);
            if (std.mem.eql(u8, existing, bytes)) return;
        }
        try self.root.publishFile(try root_fs.Path.init(document_path), bytes, .{
            .permissions = document_permissions,
            .overwrite = .replace,
            .durable = true,
        });
    }
};

const testing = std.testing;

fn testRecord(allocator: std.mem.Allocator) !root_operation.OwnedRecord {
    return root_operation.create(allocator, .{
        .attempt_id = @splat(0x44),
        .generation = 7,
        .install_root = "/target",
        .backend = .legacy_dpkg,
        .operation = .{ .package_transaction = .install },
        .state = .completed,
        .phase = .provenance,
        .step = 6,
        .mutation_started = true,
        .outcome = .succeeded,
        .provenance = .pending,
        .evidence = .{
            .plan_sha256 = @splat(0x33),
            .exact_lock = .{
                .schema = "https://debz.dev/schema/exact-closure-lock-v1",
                .version = 1,
                .digest_sha256 = @splat(0x77),
            },
        },
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .target_architecture = "amd64",
        .foreign_architectures = &.{"i386"},
        .reserved_unix = 1_700_000_000,
        .updated_unix = 1_700_000_042,
    });
}

fn testInput(record: root_operation.Record) Input {
    return .{
        .record = record,
        .transaction_provenance = .{
            .status = .unavailable,
            .detail = "detailed transaction provenance publication was interrupted",
        },
        .journal = .{
            .status = .archived,
            .document_sha256 = @splat(0x99),
            .detail = "transaction.complete",
        },
        .discharge = .{
            .surface = .package_transaction,
            .operation = "recover",
            .request_sha256 = @splat(0x55),
        },
    };
}

test "root_operation_completion.test.canonical statement round-trips and binds its record" {
    var record = try testRecord(testing.allocator);
    defer record.deinit();
    var document = try create(testing.allocator, testInput(record.record));
    defer document.deinit();
    try testing.expect(document.document.bindsRecord(record.record));

    const bytes = try document.document.canonicalJson(testing.allocator);
    defer testing.allocator.free(bytes);
    var decoded = try decode(testing.allocator, bytes, maximum_document_bytes);
    defer decoded.deinit();
    try testing.expectEqualSlices(
        u8,
        &document.document.digest_sha256,
        &decoded.document.digest_sha256,
    );
    try testing.expectEqual(TransactionProvenanceStatus.unavailable, decoded.document.transaction_provenance.status);
    try testing.expectEqual(JournalStatus.archived, decoded.document.journal.status);
    try testing.expectEqualStrings("recover", decoded.document.discharge.operation);
    try testing.expectEqual(@as(u64, 7), decoded.document.record_generation);
    try testing.expect(decoded.document.bindsRecord(record.record));
}

test "root_operation_completion.test.statement binds the record across the provenance transition" {
    var record = try testRecord(testing.allocator);
    defer record.deinit();
    var document = try create(testing.allocator, testInput(record.record));
    defer document.deinit();

    // `publishProvenance` republishes the record at the next generation with a
    // provenance digest. The statement was published before that transition,
    // so it must still bind the record the transition produced.
    var advanced = try root_operation.create(testing.allocator, .{
        .attempt_id = record.record.attempt_id,
        .generation = record.record.generation + 1,
        .install_root = record.record.install_root,
        .backend = record.record.backend,
        .operation = record.record.operation,
        .state = .completed,
        .phase = .provenance,
        .step = record.record.step + 1,
        .mutation_started = true,
        .outcome = record.record.outcome,
        .provenance = .published,
        .provenance_sha256 = @splat(0xee),
        .evidence = record.record.evidence(),
        .request_sha256 = record.record.request_sha256,
        .policy_sha256 = record.record.policy_sha256,
        .target_architecture = record.record.target_architecture,
        .foreign_architectures = record.record.foreign_architectures,
        .reserved_unix = record.record.reserved_unix,
        .updated_unix = record.record.updated_unix + 1,
    });
    defer advanced.deinit();
    try testing.expect(document.document.bindsRecord(advanced.record));
}

test "root_operation_completion.test.statement refuses a different attempt, root, or evidence" {
    var record = try testRecord(testing.allocator);
    defer record.deinit();
    var document = try create(testing.allocator, testInput(record.record));
    defer document.deinit();

    var other_attempt = try root_operation.create(testing.allocator, .{
        .attempt_id = @splat(0x45),
        .generation = 7,
        .install_root = "/target",
        .backend = .legacy_dpkg,
        .operation = .{ .package_transaction = .install },
        .state = .completed,
        .phase = .provenance,
        .step = 6,
        .mutation_started = true,
        .outcome = .succeeded,
        .provenance = .pending,
        .evidence = record.record.evidence(),
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .target_architecture = "amd64",
        .foreign_architectures = &.{"i386"},
        .reserved_unix = 1_700_000_000,
        .updated_unix = 1_700_000_042,
    });
    defer other_attempt.deinit();
    try testing.expect(!document.document.bindsRecord(other_attempt.record));

    var other_root = try root_operation.create(testing.allocator, .{
        .attempt_id = record.record.attempt_id,
        .generation = 7,
        .install_root = "/other-target",
        .backend = .legacy_dpkg,
        .operation = .{ .package_transaction = .install },
        .state = .completed,
        .phase = .provenance,
        .step = 6,
        .mutation_started = true,
        .outcome = .succeeded,
        .provenance = .pending,
        .evidence = record.record.evidence(),
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .target_architecture = "amd64",
        .foreign_architectures = &.{"i386"},
        .reserved_unix = 1_700_000_000,
        .updated_unix = 1_700_000_042,
    });
    defer other_root.deinit();
    try testing.expect(!document.document.bindsRecord(other_root.record));

    var other_plan = try root_operation.create(testing.allocator, .{
        .attempt_id = record.record.attempt_id,
        .generation = 7,
        .install_root = "/target",
        .backend = .legacy_dpkg,
        .operation = .{ .package_transaction = .install },
        .state = .completed,
        .phase = .provenance,
        .step = 6,
        .mutation_started = true,
        .outcome = .succeeded,
        .provenance = .pending,
        .evidence = .{ .plan_sha256 = @splat(0x34) },
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .target_architecture = "amd64",
        .foreign_architectures = &.{"i386"},
        .reserved_unix = 1_700_000_000,
        .updated_unix = 1_700_000_042,
    });
    defer other_plan.deinit();
    try testing.expect(!document.document.bindsRecord(other_plan.record));
}

test "root_operation_completion.test.a rebuilt detailed provenance is a distinct classification" {
    var record = try testRecord(testing.allocator);
    defer record.deinit();
    var input = testInput(record.record);
    input.transaction_provenance = .{
        .status = .recovered,
        .schema = "https://debz.dev/schema/transaction-result-v1",
        .document_sha256 = @splat(0xcd),
        .detail = "detailed transaction provenance was rebuilt from durable evidence",
    };
    input.journal = .{ .status = .absent, .detail = "no transaction journal remains" };
    var document = try create(testing.allocator, input);
    defer document.deinit();
    const bytes = try document.document.canonicalJson(testing.allocator);
    defer testing.allocator.free(bytes);
    var decoded = try decode(testing.allocator, bytes, maximum_document_bytes);
    defer decoded.deinit();
    try testing.expectEqual(
        TransactionProvenanceStatus.recovered,
        decoded.document.transaction_provenance.status,
    );
    try testing.expect(decoded.document.transaction_provenance.document_sha256 != null);
    try testing.expectEqual(JournalStatus.absent, decoded.document.journal.status);
    try testing.expect(decoded.document.journal.document_sha256 == null);
    try testing.expect(decoded.document.bindsRecord(record.record));
}

test "root_operation_completion.test.contradictory evidence is refused" {
    var record = try testRecord(testing.allocator);
    defer record.deinit();

    var unavailable_with_digest = testInput(record.record);
    unavailable_with_digest.transaction_provenance = .{
        .status = .unavailable,
        .document_sha256 = @splat(0x66),
        .detail = "contradiction",
    };
    try testing.expectError(
        error.InvalidTransactionProvenance,
        create(testing.allocator, unavailable_with_digest),
    );

    var present_without_digest = testInput(record.record);
    present_without_digest.transaction_provenance = .{
        .status = .already_present,
        .schema = "https://debz.dev/schema/transaction-result-v1",
        .detail = "verified",
    };
    try testing.expectError(
        error.InvalidTransactionProvenance,
        create(testing.allocator, present_without_digest),
    );

    var archived_without_digest = testInput(record.record);
    archived_without_digest.journal = .{ .status = .archived, .detail = "transaction.complete" };
    try testing.expectError(
        error.InvalidJournalEvidence,
        create(testing.allocator, archived_without_digest),
    );

    var control_detail = testInput(record.record);
    control_detail.journal = .{ .status = .absent, .detail = "line\nbreak" };
    try testing.expectError(error.InvalidDetail, create(testing.allocator, control_detail));

    var foreign_discharge = testInput(record.record);
    foreign_discharge.discharge = .{
        .surface = .package_transaction,
        .operation = "not-an-operation",
        .request_sha256 = @splat(0x55),
    };
    try testing.expectError(
        error.InvalidDischarge,
        create(testing.allocator, foreign_discharge),
    );
}

test "root_operation_completion.test.only a completed mutating attempt may be discharged" {
    var reserved = try root_operation.create(testing.allocator, .{
        .attempt_id = @splat(0x44),
        .generation = 1,
        .install_root = "/target",
        .backend = .legacy_dpkg,
        .operation = .{ .package_transaction = .install },
        .state = .reserved,
        .phase = .reserved,
        .step = 0,
        .mutation_started = false,
        .outcome = .pending,
        .provenance = .pending,
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .target_architecture = "amd64",
        .reserved_unix = 1_700_000_000,
        .updated_unix = 1_700_000_000,
    });
    defer reserved.deinit();
    try testing.expectError(
        error.InvalidRecordState,
        create(testing.allocator, testInput(reserved.record)),
    );

    var abandoned = try root_operation.create(testing.allocator, .{
        .attempt_id = @splat(0x44),
        .generation = 2,
        .install_root = "/target",
        .backend = .legacy_dpkg,
        .operation = .{ .package_transaction = .install },
        .state = .completed,
        .phase = .provenance,
        .step = 1,
        .mutation_started = false,
        .outcome = .abandoned_before_mutation,
        .provenance = .not_required,
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .target_architecture = "amd64",
        .reserved_unix = 1_700_000_000,
        .updated_unix = 1_700_000_000,
    });
    defer abandoned.deinit();
    try testing.expectError(
        error.InvalidMutationEvidence,
        create(testing.allocator, testInput(abandoned.record)),
    );
}

test "root_operation_completion.test.decode rejects tampering and non-canonical bytes" {
    var record = try testRecord(testing.allocator);
    defer record.deinit();
    var document = try create(testing.allocator, testInput(record.record));
    defer document.deinit();
    const bytes = try document.document.canonicalJson(testing.allocator);
    defer testing.allocator.free(bytes);

    const tampered = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(tampered);
    const marker = "\"step\":6";
    const index = std.mem.indexOf(u8, tampered, marker).?;
    tampered[index + marker.len - 1] = '7';
    try testing.expectError(
        error.DigestMismatch,
        decode(testing.allocator, tampered, maximum_document_bytes),
    );

    const spaced = try std.fmt.allocPrint(testing.allocator, "{s} ", .{bytes});
    defer testing.allocator.free(spaced);
    try testing.expectError(
        error.NonCanonicalDocument,
        decode(testing.allocator, spaced, maximum_document_bytes),
    );

    try testing.expectError(
        error.DocumentTooLarge,
        decode(testing.allocator, bytes, bytes.len - 1),
    );
}

test "root_operation_completion.test.allocation failure never leaks or half-publishes" {
    var record = try testRecord(testing.allocator);
    defer record.deinit();
    var reference = try create(testing.allocator, testInput(record.record));
    defer reference.deinit();
    const bytes = try reference.document.canonicalJson(testing.allocator);
    defer testing.allocator.free(bytes);

    var index: usize = 0;
    while (index < 64) : (index += 1) {
        var failing: std.testing.FailingAllocator = .init(testing.allocator, .{
            .fail_index = index,
        });
        if (create(failing.allocator(), testInput(record.record))) |value| {
            var owned = value;
            owned.deinit();
        } else |err| try testing.expectEqual(error.OutOfMemory, err);

        var decoding: std.testing.FailingAllocator = .init(testing.allocator, .{
            .fail_index = index,
        });
        if (decode(decoding.allocator(), bytes, maximum_document_bytes)) |value| {
            var owned = value;
            owned.deinit();
        } else |err| switch (err) {
            error.OutOfMemory, error.NonCanonicalDocument => {},
            else => return err,
        }
    }
}

test "root_operation_completion.test.store publishes atomically and idempotently" {
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var root_directory = try directory.dir.openDir(testing.io, ".", .{ .iterate = true });
    defer root_directory.close(testing.io);
    const root: root_fs.Root = .init(testing.io, root_directory);
    const namespace: root_operation.Store = .init(root);
    try namespace.ensureNamespace();

    var record = try testRecord(testing.allocator);
    defer record.deinit();
    var document = try create(testing.allocator, testInput(record.record));
    defer document.deinit();

    const store: Store = .init(root);
    try testing.expect((try store.readBytes(testing.allocator)) == null);
    try store.publish(testing.allocator, document.document);
    const first = (try store.readBytes(testing.allocator)).?;
    defer testing.allocator.free(first);
    try store.publish(testing.allocator, document.document);
    const second = (try store.readBytes(testing.allocator)).?;
    defer testing.allocator.free(second);
    try testing.expectEqualStrings(first, second);

    var loaded = (try store.read(testing.allocator)).?;
    defer loaded.deinit();
    try testing.expect(loaded.document.bindsRecord(record.record));
    try testing.expectEqualSlices(
        u8,
        &document.document.digest_sha256,
        &loaded.document.digest_sha256,
    );
}

test "root_operation_completion.test.store refuses a symbolic link at the document path" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var directory = testing.tmpDir(.{});
    defer directory.cleanup();
    var root_directory = try directory.dir.openDir(testing.io, ".", .{ .iterate = true });
    defer root_directory.close(testing.io);
    const root: root_fs.Root = .init(testing.io, root_directory);
    const namespace: root_operation.Store = .init(root);
    try namespace.ensureNamespace();
    try directory.dir.writeFile(testing.io, .{
        .sub_path = "var/lib/debz/elsewhere.json",
        .data = "{}",
    });
    try directory.dir.symLink(testing.io, "elsewhere.json", "var/lib/debz/" ++ document_name, .{});

    const store: Store = .init(root);
    try testing.expectError(error.NotRegularFile, store.readBytes(testing.allocator));

    // Publication never writes through the link: it replaces the name.
    var record = try testRecord(testing.allocator);
    defer record.deinit();
    var document = try create(testing.allocator, testInput(record.record));
    defer document.deinit();
    try store.publish(testing.allocator, document.document);
    var loaded = (try store.read(testing.allocator)).?;
    defer loaded.deinit();
    try testing.expect(loaded.document.bindsRecord(record.record));
    const target = try directory.dir.readFileAlloc(
        testing.io,
        "var/lib/debz/elsewhere.json",
        testing.allocator,
        .limited(64),
    );
    defer testing.allocator.free(target);
    try testing.expectEqualStrings("{}", target);
}
