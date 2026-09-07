//! Versioned contract for the deliberately limited apt-shaped system facade.
//!
//! This is not product API v1 and does not alter that API. It describes
//! orchestration over an explicit trusted system profile and the existing
//! authenticated metadata, exact-lock, transaction, recovery, and root
//! operation evidence boundaries.
const std = @import("std");
const absolute_path = @import("absolute_path.zig");
const system_profile = @import("system_profile.zig");

pub const api_version: u32 = 1;
pub const request_schema_id = "https://debz.dev/schema/apt-system-request-v1";
pub const result_schema_id = "https://debz.dev/schema/apt-system-result-v1";
pub const schema_version: u32 = 1;
pub const maximum_document_bytes: usize = 256 * 1024;
pub const maximum_packages: usize = 256;
pub const maximum_diagnostics: usize = 8;
pub const maximum_summary_bytes: usize = 4096;

pub const Operation = enum {
    update,
    install,
    remove,
    upgrade,
    list_installed,

    pub fn mutatesRoot(self: Operation) bool {
        return switch (self) {
            .install, .remove, .upgrade => true,
            .update, .list_installed => false,
        };
    }
};

pub const Request = struct {
    api_version: u32 = api_version,
    operation: Operation,
    profile_path: []const u8 = system_profile.default_profile_path,
    packages: []const []const u8 = &.{},
    assume_yes: bool = false,

    pub fn canonicalJson(
        self: Request,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        try validateRequest(self);
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeRequest(self, &output.writer);
        const bytes = try output.toOwnedSlice();
        if (bytes.len > maximum_document_bytes) {
            allocator.free(bytes);
            return error.DocumentTooLarge;
        }
        return bytes;
    }

    pub fn digest(self: Request) ![32]u8 {
        try validateRequest(self);
        return requestDigestUnchecked(self);
    }
};

pub const Outcome = enum {
    success,
    usage,
    configuration,
    authentication,
    planning,
    download,
    transaction,
    recovery,
    internal,
};

pub const ExitStatus = enum(u8) {
    success = 0,
    usage = 2,
    configuration = 3,
    authentication = 4,
    planning = 5,
    download = 6,
    transaction = 7,
    recovery = 8,
    internal = 70,
};

pub const DiagnosticId = enum {
    unsupported_api_version,
    invalid_request,
    unsupported_syntax,
    confirmation_required,
    profile_not_found,
    profile_untrusted,
    profile_invalid,
    repository_authentication_failed,
    planning_failed,
    exact_lock_publication_failed,
    download_failed,
    transaction_failed,
    transaction_evidence_invalid,
    root_operation_conflict,
    recovery_required,
    recovery_failed,
    state_persistence_failed,
    internal_error,
};

pub const Diagnostic = struct {
    id: DiagnosticId,
    outcome: Outcome,
    phase: ?[]const u8 = null,
    message: []const u8,
};

pub const ProfileBinding = struct {
    path: []const u8,
    sha256: [32]u8,
    reference_evidence_sha256: [32]u8,
};

pub const DocumentBinding = struct {
    path: []const u8,
    schema: []const u8,
    version: u32,
    digest_sha256: [32]u8,
};

pub const CompletionBinding = struct {
    document: DocumentBinding,
    completed_attempt_id: [32]u8,
};

pub const Evidence = struct {
    exact_lock: ?DocumentBinding = null,
    transaction_result: ?DocumentBinding = null,
    root_operation_completion: ?CompletionBinding = null,
    active_operation_state: ?[]const u8 = null,
};

pub const Result = struct {
    api_version: u32 = api_version,
    operation: Operation,
    request_sha256: [32]u8,
    profile: ?ProfileBinding = null,
    outcome: Outcome,
    exit_status: ExitStatus,
    changed: bool = false,
    summary: []const u8,
    evidence: Evidence = .{},
    diagnostics: [maximum_diagnostics]Diagnostic = undefined,
    diagnostic_count: usize = 0,
    digest_sha256: [32]u8 = @splat(0),
    ownership: ?*ResultOwnership = null,

    pub fn canonicalJson(
        self: Result,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        try validateResult(self);
        if (!std.mem.eql(u8, &self.digest_sha256, &digestPayload(self)))
            return error.DigestMismatch;
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeResultDocument(self, &output.writer);
        const bytes = try output.toOwnedSlice();
        if (bytes.len > maximum_document_bytes) {
            allocator.free(bytes);
            return error.DocumentTooLarge;
        }
        return bytes;
    }

    pub fn deinit(self: *Result) void {
        const owner = self.ownership orelse return;
        const allocator = owner.backing_allocator;
        owner.arena.deinit();
        allocator.destroy(owner);
        self.* = undefined;
    }
};

const ResultOwnership = struct {
    arena: std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,
};

pub const Backend = struct {
    context: *anyopaque,
    executeFn: *const fn (*anyopaque, std.mem.Allocator, Request) anyerror!Result,

    pub fn execute(
        self: Backend,
        allocator: std.mem.Allocator,
        request: Request,
    ) !Result {
        return self.executeFn(self.context, allocator, request);
    }
};

pub fn execute(
    allocator: std.mem.Allocator,
    request: Request,
    backend: Backend,
) !Result {
    validateRequest(request) catch |err| {
        const id: DiagnosticId = if (err == error.UnsupportedApiVersion)
            .unsupported_api_version
        else
            .invalid_request;
        return failure(
            request,
            .usage,
            id,
            "request",
            if (err == error.UnsupportedApiVersion)
                "unsupported apt/system API version"
            else
                "invalid apt/system request",
        );
    };
    var result = try backend.execute(allocator, request);
    const expected_request_sha256 = try request.digest();
    if (result.operation != request.operation) {
        result.deinit();
        return error.BackendOperationMismatch;
    }
    if (!std.mem.eql(
        u8,
        &result.request_sha256,
        &expected_request_sha256,
    )) {
        result.deinit();
        return error.BackendRequestMismatch;
    }
    validateCompleteResult(result) catch {
        result.deinit();
        return error.InvalidBackendResult;
    };
    return result;
}

pub fn complete(input: Result) !Result {
    var result = input;
    try validateResult(result);
    result.digest_sha256 = digestPayload(result);
    return result;
}

pub fn failure(
    request: Request,
    outcome: Outcome,
    id: DiagnosticId,
    phase: []const u8,
    message: []const u8,
) Result {
    var result: Result = .{
        .operation = request.operation,
        .request_sha256 = requestDigestUnchecked(request),
        .outcome = outcome,
        .exit_status = exitStatus(outcome),
        .summary = message,
        .diagnostics = undefined,
        .diagnostic_count = 1,
    };
    result.diagnostics[0] = .{
        .id = id,
        .outcome = outcome,
        .phase = phase,
        .message = message,
    };
    result.digest_sha256 = digestPayload(result);
    return result;
}

pub fn ownResult(
    allocator: std.mem.Allocator,
    input: Result,
) !Result {
    try validateResult(input);
    const owner = try allocator.create(ResultOwnership);
    errdefer allocator.destroy(owner);
    owner.* = .{
        .arena = .init(allocator),
        .backing_allocator = allocator,
    };
    errdefer owner.arena.deinit();
    const owned = owner.arena.allocator();
    var result = input;
    result.summary = try owned.dupe(u8, input.summary);
    if (input.profile) |profile| result.profile = .{
        .path = try owned.dupe(u8, profile.path),
        .sha256 = profile.sha256,
        .reference_evidence_sha256 = profile.reference_evidence_sha256,
    };
    result.evidence = try ownEvidence(owned, input.evidence);
    for (result.diagnostics[0..result.diagnostic_count]) |*diagnostic| {
        diagnostic.phase = try dupeOptional(owned, diagnostic.phase);
        diagnostic.message = try owned.dupe(u8, diagnostic.message);
    }
    result.ownership = owner;
    return result;
}

pub fn validateRequest(request: Request) !void {
    if (request.api_version != api_version) return error.UnsupportedApiVersion;
    if (!absolute_path.nonRoot(request.profile_path) or
        request.profile_path.len > system_profile.maximum_path_bytes)
        return error.InvalidProfilePath;
    const count_valid = switch (request.operation) {
        .install, .remove => request.packages.len != 0 and
            request.packages.len <= maximum_packages,
        .update, .upgrade, .list_installed => request.packages.len == 0,
    };
    if (!count_valid) return error.InvalidPackageCount;
    for (request.packages, 0..) |package, index| {
        if (!validPackage(package)) return error.InvalidPackage;
        for (request.packages[0..index]) |previous|
            if (std.mem.eql(u8, package, previous))
                return error.DuplicatePackage;
    }
}

pub fn validateResult(result: Result) !void {
    if (result.api_version != api_version) return error.UnsupportedApiVersion;
    if (result.summary.len == 0 or result.summary.len > maximum_summary_bytes)
        return error.InvalidSummary;
    if (result.diagnostic_count > maximum_diagnostics)
        return error.TooManyDiagnostics;
    if (result.exit_status != exitStatus(result.outcome))
        return error.InvalidExitStatus;
    if (result.profile) |profile| {
        try validateProfileBinding(profile);
    }

    try validateEvidence(result.evidence);
    if (!result.operation.mutatesRoot() and
        (result.evidence.exact_lock != null or
            result.evidence.transaction_result != null or
            result.evidence.root_operation_completion != null))
        return error.UnexpectedTransactionEvidence;
    for (result.diagnostics[0..result.diagnostic_count]) |diagnostic| {
        if (diagnostic.outcome != result.outcome or
            diagnostic.message.len == 0 or
            diagnostic.message.len > maximum_summary_bytes)
            return error.InvalidDiagnostic;
        if (diagnostic.phase) |phase|
            if (!validText(phase, 128)) return error.InvalidDiagnostic;
    }
    if (result.outcome == .success) {
        if (result.exit_status != .success or
            result.profile == null or
            result.diagnostic_count != 0)
            return error.PartialSuccess;
        if (result.operation.mutatesRoot()) {
            if (result.evidence.exact_lock == null or
                result.evidence.transaction_result == null or
                result.evidence.root_operation_completion == null)
                return error.MissingCompletionEvidence;
        }
    } else {
        if (result.diagnostic_count == 0) return error.MissingDiagnostic;
    }
}

pub fn validateCompleteResult(result: Result) !void {
    try validateResult(result);
    if (!std.mem.eql(u8, &result.digest_sha256, &digestPayload(result)))
        return error.DigestMismatch;
}

pub fn validateProfileBinding(profile: ProfileBinding) !void {
    if (!absolute_path.nonRoot(profile.path) or
        profile.path.len > system_profile.maximum_path_bytes)
        return error.InvalidProfileBinding;
}

pub fn validateEvidence(evidence: Evidence) !void {
    if (evidence.exact_lock) |binding| try validateDocumentBinding(binding);
    if (evidence.transaction_result) |binding|
        try validateDocumentBinding(binding);
    if (evidence.root_operation_completion) |binding|
        try validateDocumentBinding(binding.document);
    if (evidence.active_operation_state) |path| {
        if (!absolute_path.nonRoot(path) or
            path.len > system_profile.maximum_path_bytes)
            return error.InvalidEvidencePath;
    }
}

fn validateDocumentBinding(binding: DocumentBinding) !void {
    if (!absolute_path.nonRoot(binding.path) or
        binding.path.len > system_profile.maximum_path_bytes)
        return error.InvalidEvidencePath;
    if (!validText(binding.schema, 256) or binding.version == 0)
        return error.InvalidEvidenceSchema;
}

fn exitStatus(outcome: Outcome) ExitStatus {
    return switch (outcome) {
        .success => .success,
        .usage => .usage,
        .configuration => .configuration,
        .authentication => .authentication,
        .planning => .planning,
        .download => .download,
        .transaction => .transaction,
        .recovery => .recovery,
        .internal => .internal,
    };
}

fn validPackage(package: []const u8) bool {
    if (package.len == 0 or package.len > 255 or package[0] == '-') return false;
    for (package) |byte|
        if (!(std.ascii.isAlphanumeric(byte) or byte == '+' or byte == '-' or
            byte == '.' or byte == ':' or byte == '='))
            return false;
    return true;
}

fn validText(text: []const u8, maximum: usize) bool {
    if (text.len == 0 or text.len > maximum or !std.unicode.utf8ValidateSlice(text))
        return false;
    for (text) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return true;
}

fn digestPayload(result: Result) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writeResultPayload(result, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn requestDigestUnchecked(request: Request) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writeRequest(request, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn writeRequest(request: Request, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeString(writer, request_schema_id);
    try writer.print(",\"version\":{},\"api_version\":{},\"operation\":", .{
        schema_version,
        request.api_version,
    });
    try writeString(writer, @tagName(request.operation));
    try writer.writeAll(",\"profile_path\":");
    try writeString(writer, request.profile_path);
    try writer.writeAll(",\"packages\":[");
    for (request.packages, 0..) |package, index| {
        if (index != 0) try writer.writeByte(',');
        try writeString(writer, package);
    }
    try writer.print("],\"assume_yes\":{}}}", .{request.assume_yes});
}

fn writeResultDocument(result: Result, writer: *std.Io.Writer) !void {
    try writeResultPayload(result, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHex(writer, &result.digest_sha256);
    try writer.writeByte('}');
}

fn writeResultPayload(result: Result, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeString(writer, result_schema_id);
    try writer.print(",\"version\":{},\"api_version\":{},\"operation\":", .{
        schema_version,
        result.api_version,
    });
    try writeString(writer, @tagName(result.operation));
    try writer.writeAll(",\"request_sha256\":");
    try writeHex(writer, &result.request_sha256);
    try writer.writeAll(",\"profile\":");
    if (result.profile) |profile| {
        try writer.writeAll("{\"path\":");
        try writeString(writer, profile.path);
        try writer.writeAll(",\"sha256\":");
        try writeHex(writer, &profile.sha256);
        try writer.writeAll(",\"reference_evidence_sha256\":");
        try writeHex(writer, &profile.reference_evidence_sha256);
        try writer.writeByte('}');
    } else try writer.writeAll("null");
    try writer.writeAll(",\"outcome\":");
    try writeString(writer, @tagName(result.outcome));
    try writer.print(",\"exit_status\":{},\"changed\":{},\"summary\":", .{
        @intFromEnum(result.exit_status),
        result.changed,
    });
    try writeString(writer, result.summary);
    try writer.writeAll(",\"evidence\":");
    try writeEvidence(writer, result.evidence);
    try writer.writeAll(",\"diagnostics\":[");
    for (result.diagnostics[0..result.diagnostic_count], 0..) |diagnostic, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"id\":");
        try writeString(writer, @tagName(diagnostic.id));
        try writer.writeAll(",\"outcome\":");
        try writeString(writer, @tagName(diagnostic.outcome));
        try writer.writeAll(",\"phase\":");
        try writeOptionalString(writer, diagnostic.phase);
        try writer.writeAll(",\"message\":");
        try writeString(writer, diagnostic.message);
        try writer.writeByte('}');
    }
    try writer.writeAll("]}");
}

fn writeEvidence(writer: *std.Io.Writer, evidence: Evidence) !void {
    try writer.writeAll("{\"exact_lock\":");
    try writeOptionalDocument(writer, evidence.exact_lock);
    try writer.writeAll(",\"transaction_result\":");
    try writeOptionalDocument(writer, evidence.transaction_result);
    try writer.writeAll(",\"root_operation_completion\":");
    if (evidence.root_operation_completion) |completion| {
        try writer.writeAll("{\"document\":");
        try writeDocumentBinding(writer, completion.document);
        try writer.writeAll(",\"completed_attempt_id\":");
        try writeHex(writer, &completion.completed_attempt_id);
        try writer.writeByte('}');
    } else try writer.writeAll("null");
    try writer.writeAll(",\"active_operation_state\":");
    try writeOptionalString(writer, evidence.active_operation_state);
    try writer.writeByte('}');
}

fn writeOptionalDocument(
    writer: *std.Io.Writer,
    binding: ?DocumentBinding,
) !void {
    if (binding) |value|
        try writeDocumentBinding(writer, value)
    else
        try writer.writeAll("null");
}

fn writeDocumentBinding(writer: *std.Io.Writer, binding: DocumentBinding) !void {
    try writer.writeAll("{\"path\":");
    try writeString(writer, binding.path);
    try writer.writeAll(",\"schema\":");
    try writeString(writer, binding.schema);
    try writer.print(",\"version\":{},\"digest_sha256\":", .{binding.version});
    try writeHex(writer, &binding.digest_sha256);
    try writer.writeByte('}');
}

fn writeOptionalString(writer: *std.Io.Writer, value: ?[]const u8) !void {
    if (value) |bytes| try writeString(writer, bytes) else try writer.writeAll("null");
}

fn writeString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...8, 11, 12, 14...31 => try writer.print("\\u00{x:0>2}", .{byte}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

fn writeHex(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
    try writer.writeByte('"');
}

fn ownEvidence(
    allocator: std.mem.Allocator,
    evidence: Evidence,
) !Evidence {
    return .{
        .exact_lock = if (evidence.exact_lock) |binding|
            try ownDocumentBinding(allocator, binding)
        else
            null,
        .transaction_result = if (evidence.transaction_result) |binding|
            try ownDocumentBinding(allocator, binding)
        else
            null,
        .root_operation_completion = if (evidence.root_operation_completion) |completion|
            .{
                .document = try ownDocumentBinding(allocator, completion.document),
                .completed_attempt_id = completion.completed_attempt_id,
            }
        else
            null,
        .active_operation_state = try dupeOptional(
            allocator,
            evidence.active_operation_state,
        ),
    };
}

fn ownDocumentBinding(
    allocator: std.mem.Allocator,
    binding: DocumentBinding,
) !DocumentBinding {
    return .{
        .path = try allocator.dupe(u8, binding.path),
        .schema = try allocator.dupe(u8, binding.schema),
        .version = binding.version,
        .digest_sha256 = binding.digest_sha256,
    };
}

fn dupeOptional(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
) std.mem.Allocator.Error!?[]const u8 {
    return if (value) |bytes| try allocator.dupe(u8, bytes) else null;
}

fn successfulResult(request: Request) !Result {
    const document: DocumentBinding = .{
        .path = "/var/lib/debz/apt/exact-lock-v2.json",
        .schema = "https://debz.dev/schema/exact-closure-lock-v2",
        .version = 2,
        .digest_sha256 = @splat(0x33),
    };
    return complete(.{
        .operation = request.operation,
        .request_sha256 = try request.digest(),
        .profile = .{
            .path = request.profile_path,
            .sha256 = @splat(0x22),
            .reference_evidence_sha256 = @splat(0x23),
        },
        .outcome = .success,
        .exit_status = .success,
        .changed = true,
        .summary = "transaction completed",
        .evidence = .{
            .exact_lock = document,
            .transaction_result = .{
                .path = "/var/lib/debz/transaction-result.json",
                .schema = "https://debz.dev/schema/transaction-result-v2",
                .version = 2,
                .digest_sha256 = @splat(0x44),
            },
            .root_operation_completion = .{
                .document = .{
                    .path = "/var/lib/debz/root-operation-completion-v1.json",
                    .schema = "https://debz.dev/schema/root-operation-completion-v1",
                    .version = 1,
                    .digest_sha256 = @splat(0x55),
                },
                .completed_attempt_id = @splat(0x66),
            },
            .active_operation_state = "/var/lib/debz/apt/active-operation-v1.json",
        },
    });
}

test "apt_system_api.test.multi-package request is one versioned request digest" {
    const request: Request = .{
        .operation = .install,
        .packages = &.{ "curl", "ca-certificates" },
        .assume_yes = true,
    };
    const first = try request.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(first);
    const second = try request.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualStrings(first, second);
    const first_digest = try request.digest();
    const second_digest = try request.digest();
    try std.testing.expectEqualSlices(u8, &first_digest, &second_digest);
}

test "apt_system_api.test.facade rejects unsupported package shapes before backend" {
    var called = false;
    const Fake = struct {
        fn run(context: *anyopaque, _: std.mem.Allocator, request: Request) !Result {
            const value: *bool = @ptrCast(@alignCast(context));
            value.* = true;
            return failure(request, .internal, .internal_error, "test", "called");
        }
    };
    const result = try execute(std.testing.allocator, .{
        .operation = .update,
        .packages = &.{"ignored"},
    }, .{ .context = &called, .executeFn = Fake.run });
    try std.testing.expectEqual(Outcome.usage, result.outcome);
    try std.testing.expectEqual(DiagnosticId.invalid_request, result.diagnostics[0].id);
    try std.testing.expect(!called);
}

test "apt_system_api.test.backend results bind the exact submitted request" {
    const Fake = struct {
        fn run(context: *anyopaque, _: std.mem.Allocator, _: Request) !Result {
            const result: *Result = @ptrCast(@alignCast(context));
            return result.*;
        }
    };
    const request: Request = .{
        .operation = .install,
        .packages = &.{"curl"},
        .assume_yes = true,
    };
    const previous: Request = .{
        .operation = .install,
        .packages = &.{"wget"},
        .assume_yes = true,
    };

    var stale = failure(
        previous,
        .planning,
        .planning_failed,
        "plan",
        "stale result",
    );
    try std.testing.expectError(
        error.BackendRequestMismatch,
        execute(std.testing.allocator, request, .{
            .context = &stale,
            .executeFn = Fake.run,
        }),
    );

    var wrong_operation = failure(
        request,
        .planning,
        .planning_failed,
        "plan",
        "wrong operation",
    );
    wrong_operation.operation = .remove;
    wrong_operation.digest_sha256 = digestPayload(wrong_operation);
    try std.testing.expectError(
        error.BackendOperationMismatch,
        execute(std.testing.allocator, request, .{
            .context = &wrong_operation,
            .executeFn = Fake.run,
        }),
    );

    var wrong_digest = failure(
        request,
        .planning,
        .planning_failed,
        "plan",
        "wrong digest",
    );
    wrong_digest.digest_sha256 = @splat(0xaa);
    try std.testing.expectError(
        error.InvalidBackendResult,
        execute(std.testing.allocator, request, .{
            .context = &wrong_digest,
            .executeFn = Fake.run,
        }),
    );

    var malformed: Result = .{
        .operation = request.operation,
        .request_sha256 = try request.digest(),
        .outcome = .success,
        .exit_status = .success,
        .summary = "missing profile and evidence",
    };
    malformed.digest_sha256 = digestPayload(malformed);
    try std.testing.expectError(
        error.InvalidBackendResult,
        execute(std.testing.allocator, request, .{
            .context = &malformed,
            .executeFn = Fake.run,
        }),
    );

    var valid_failure = failure(
        request,
        .planning,
        .planning_failed,
        "plan",
        "planning failed",
    );
    const returned = try execute(std.testing.allocator, request, .{
        .context = &valid_failure,
        .executeFn = Fake.run,
    });
    try std.testing.expectEqual(Outcome.planning, returned.outcome);
}

test "apt_system_api.test.success binds profile lock transaction and completion" {
    const request: Request = .{
        .operation = .install,
        .packages = &.{ "curl", "ca-certificates" },
        .assume_yes = true,
    };
    const result = try successfulResult(request);
    const bytes = try result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "\"exact_lock\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "\"completed_attempt_id\"") != null);

    var missing = result;
    missing.evidence.transaction_result = null;
    missing.digest_sha256 = digestPayload(missing);
    try std.testing.expectError(
        error.MissingCompletionEvidence,
        missing.canonicalJson(std.testing.allocator),
    );
}

test "apt_system_api.test.outcomes have stable exit classifications" {
    inline for (std.meta.fields(Outcome)) |field| {
        const outcome: Outcome = @enumFromInt(field.value);
        const status = exitStatus(outcome);
        try std.testing.expectEqualStrings(field.name, @tagName(status));
    }
}

test "apt_system_api.test.result schema matches enums and absolute paths" {
    const source = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "schema/apt-system-result-v1.json",
        std.testing.allocator,
        .limited(maximum_document_bytes),
    );
    defer std.testing.allocator.free(source);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, source, .{});
    defer parsed.deinit();
    const definitions = parsed.value.object.get("$defs").?.object;
    try std.testing.expectEqualStrings(
        absolute_path.schema_pattern,
        definitions.get("absolutePath").?.object.get("pattern").?.string,
    );
    const outcomes = definitions.get("outcome").?.object.get("enum").?.array.items;
    try std.testing.expectEqual(std.meta.fields(Outcome).len, outcomes.len);
    const diagnostic_ids = definitions.get("diagnosticId").?.object.get("enum").?.array.items;
    try std.testing.expectEqual(std.meta.fields(DiagnosticId).len, diagnostic_ids.len);
}
