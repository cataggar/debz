//! Durable mapping between a caller-owned operation and its native program.
//! This is not a solver request: its byte hash must never replace the lock's
//! request hash. The unchanged v1 intent retains it as a separately hashed blob.
const std = @import("std");
const absolute_path = @import("absolute_path.zig");
const native_operation = @import("native_operation.zig");
const native_program = @import("native_program.zig");
const native_recovery = @import("native_recovery.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const transaction_recovery = @import("transaction_recovery.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Digest = native_recovery.Digest;
pub const schema_id = "https://debz.dev/schema/native-execution-request-v1";
pub const logical_path = "request/native-execution-request-v1.json";
pub const maximum_document_bytes = 64 * 1024;

pub const Caller = struct {
    attempt_id: Digest,
    operation: root_operation.Operation,
    request_sha256: Digest,
    policy_sha256: Digest,
};

pub const ProgramBinding = struct {
    request_sha256: Digest,
    solver_policy_sha256: Digest,
    executor_policy_sha256: Digest,
    plan_sha256: Digest,
    authorization_sha256: Digest,
    program_sha256: Digest,
    exact_lock_sha256: Digest,
    artifact_evidence_sha256: Digest,
    database_generation_sha256: Digest,
    script_policy_sha256: Digest,
};

pub const Document = struct {
    schema: []const u8 = schema_id,
    version: u32 = 1,
    backend: root_operation.Backend = .native,
    completion_owner: enum { caller } = .caller,
    install_root: []const u8,
    root_identity_sha256: Digest,
    root_inode: u64,
    architecture: []const u8,
    caller: Caller,
    program: ProgramBinding,
    operation: native_recovery.Operation,
    policy: native_recovery.ConffilePolicy,
    triggers: bool,
    defer_triggers: bool,
    digest_sha256: Digest = @splat('0'),
};

pub const OwnedDocument = struct {
    document: Document,
    parsed: std.json.Parsed(Document),

    pub fn deinit(self: *OwnedDocument) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

fn digest(document: Document) Digest {
    var payload = document;
    payload.digest_sha256 = @splat('0');
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-native-execution-request-v1\x00") catch unreachable;
    std.json.Stringify.value(payload, .{ .whitespace = .minified }, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return native_recovery.hexDigest(sink.hasher.finalResult());
}

pub fn seal(document: *Document) void {
    document.digest_sha256 = digest(document.*);
}

fn validDigest(value: Digest) bool {
    for (value) |byte| {
        if ((byte < '0' or byte > '9') and (byte < 'a' or byte > 'f'))
            return false;
    }
    return true;
}

pub fn validate(document: Document) !void {
    if (!std.mem.eql(u8, document.schema, schema_id) or document.version != 1 or
        document.backend != .native or
        !absolute_path.root(document.install_root) or document.install_root.len > 4096 or
        document.architecture.len == 0 or document.architecture.len > 256 or
        (document.defer_triggers and !document.triggers))
        return error.InvalidExecutionRequest;
    inline for (std.meta.fields(ProgramBinding)) |field|
        if (!validDigest(@field(document.program, field.name)))
            return error.InvalidExecutionRequest;
    inline for (.{
        document.caller.attempt_id,
        document.caller.request_sha256,
        document.caller.policy_sha256,
        document.root_identity_sha256,
        document.digest_sha256,
    }) |value| if (!validDigest(value))
        return error.InvalidExecutionRequest;
    if (!std.mem.eql(u8, &document.root_identity_sha256, &native_recovery.hexDigest(
        transaction_recovery.rootIdentity(document.install_root),
    ))) return error.InvalidExecutionRequest;
    if (!std.mem.eql(u8, &document.digest_sha256, &digest(document)))
        return error.DigestMismatch;
}

pub fn encode(allocator: std.mem.Allocator, document: Document) ![]u8 {
    try validate(document);
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    std.json.Stringify.value(document, .{ .whitespace = .minified }, &output.writer) catch
        return error.OutOfMemory;
    output.writer.writeByte('\n') catch return error.OutOfMemory;
    if (output.written().len > maximum_document_bytes) return error.LimitExceeded;
    return output.toOwnedSlice();
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !OwnedDocument {
    if (bytes.len > maximum_document_bytes) return error.LimitExceeded;
    var parsed = try std.json.parseFromSlice(Document, allocator, bytes, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();
    const canonical = try encode(allocator, parsed.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical)) return error.NonCanonicalDocument;
    return .{ .document = parsed.value, .parsed = parsed };
}

/// Returned strings borrow the program and attempt. Encode before advancing
/// the attempt, or decode the canonical bytes to obtain an owned document.
pub fn create(
    root: root_fs.Root,
    attempt: *const root_operation.Attempt,
    program: native_program.Program,
    operation: native_recovery.Operation,
) !Document {
    try native_program.validateDocument(program);
    const plan = try native_operation.boundPlan(root, attempt, program);
    if (!std.mem.eql(u8, &native_recovery.hexDigest(plan), &program.plan_sha256))
        return error.ProductionPlanBindingRequired;
    const record = attempt.record();
    var document: Document = .{
        .install_root = program.install_root,
        .root_identity_sha256 = program.root_identity_sha256,
        .root_inode = (try root.rootEntry()).inode,
        .architecture = program.target_architecture,
        .caller = .{
            .attempt_id = native_recovery.hexDigest(record.attempt_id),
            .operation = record.operation,
            .request_sha256 = native_recovery.hexDigest(record.request_sha256),
            .policy_sha256 = native_recovery.hexDigest(record.policy_sha256),
        },
        .program = .{
            .request_sha256 = program.request_sha256,
            .solver_policy_sha256 = program.solver_policy_sha256,
            .executor_policy_sha256 = program.executor_policy_sha256,
            .plan_sha256 = program.plan_sha256,
            .authorization_sha256 = program.authorization_sha256,
            .program_sha256 = program.digest_sha256,
            .exact_lock_sha256 = program.exact_lock.digest_sha256,
            .artifact_evidence_sha256 = program.artifacts_sha256,
            .database_generation_sha256 = program.installed_database.generation_sha256,
            .script_policy_sha256 = program.script_policy_sha256,
        },
        .operation = operation,
        .policy = switch (program.policy.conffile) {
            .keep_existing => .keep_existing,
            .use_package_version => .use_package_version,
        },
        .triggers = program.trigger_authority != null,
        .defer_triggers = if (program.trigger_authority) |authority| authority.defer_triggers else false,
    };
    seal(&document);
    try validate(document);
    return document;
}

pub fn validateBinding(
    document: Document,
    root: root_fs.Root,
    attempt: *const root_operation.Attempt,
    program: native_program.Program,
) !void {
    try validate(document);
    const expected = try create(root, attempt, program, document.operation);
    if (!std.mem.eql(u8, &document.digest_sha256, &expected.digest_sha256))
        return error.RecoveryRequestBindingMismatch;
}

pub fn validateIntent(document: Document, intent: native_recovery.Intent) !void {
    try validate(document);
    try native_recovery.validateIntent(intent);
    if (!std.mem.eql(u8, &document.caller.attempt_id, &intent.attempt_id) or
        !std.mem.eql(u8, document.install_root, intent.install_root) or
        !std.mem.eql(u8, &document.root_identity_sha256, &intent.root_identity_sha256) or
        document.root_inode != intent.root_inode or
        !std.mem.eql(u8, document.architecture, intent.architecture) or
        document.operation != intent.operation or document.policy != intent.policy or
        document.triggers != intent.triggers or document.defer_triggers != intent.defer_triggers or
        intent.packages.len != 0 or intent.ordered_actions.len != 0)
        return error.RecoveryRequestBindingMismatch;
    inline for (.{
        "request_sha256",           "authorization_sha256",       "program_sha256", "exact_lock_sha256",
        "artifact_evidence_sha256", "database_generation_sha256",
    }) |field| if (!std.mem.eql(u8, &@field(document.program, field), &@field(intent, field)))
        return error.RecoveryRequestBindingMismatch;
    if (!std.mem.eql(u8, &document.program.executor_policy_sha256, &intent.policy_sha256))
        return error.RecoveryRequestBindingMismatch;
}

fn fixtureDocument() Document {
    var program: ProgramBinding = undefined;
    inline for (std.meta.fields(ProgramBinding)) |field|
        @field(program, field.name) = @splat('a');
    var document: Document = .{
        .install_root = "/fixture",
        .root_identity_sha256 = native_recovery.hexDigest(transaction_recovery.rootIdentity("/fixture")),
        .root_inode = 1,
        .architecture = "amd64",
        .caller = .{
            .attempt_id = @splat('b'),
            .operation = .{ .repository_bootstrap = .add },
            .request_sha256 = @splat('c'),
            .policy_sha256 = @splat('d'),
        },
        .program = program,
        .operation = .install,
        .policy = .keep_existing,
        .triggers = false,
        .defer_triggers = false,
    };
    seal(&document);
    return document;
}

fn roundTrip(allocator: std.mem.Allocator) !void {
    const document = fixtureDocument();
    const bytes = try encode(allocator, document);
    defer allocator.free(bytes);
    var parsed = try decode(allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqual(document.digest_sha256, parsed.document.digest_sha256);
    try std.testing.expectEqual(document.caller.request_sha256, parsed.document.caller.request_sha256);
    try std.testing.expect(!std.mem.eql(u8, &parsed.document.caller.request_sha256, &parsed.document.program.request_sha256));
}

test "native_execution_request.test.canonical ownership mapping survives allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, roundTrip, .{});
}

test "native_execution_request.test.rejects rehashed invalid fields and changed policy" {
    var document = fixtureDocument();
    document.policy = .use_package_version;
    try std.testing.expectError(error.DigestMismatch, validate(document));
    seal(&document);
    try validate(document);
    document.backend = .legacy_dpkg;
    seal(&document);
    try std.testing.expectError(error.InvalidExecutionRequest, validate(document));
    document = fixtureDocument();
    document.program.request_sha256 = @splat('A');
    seal(&document);
    try std.testing.expectError(error.InvalidExecutionRequest, validate(document));
    document = fixtureDocument();
    document.defer_triggers = true;
    seal(&document);
    try std.testing.expectError(error.InvalidExecutionRequest, validate(document));
}
