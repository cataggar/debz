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
pub const result_items_schema_id =
    "https://debz.dev/schema/apt-system-result-v2";
pub const schema_version: u32 = 1;
pub const result_items_schema_version: u32 = 2;
pub const maximum_document_bytes: usize = 256 * 1024;
pub const maximum_packages: usize = 256;
pub const maximum_result_items: usize = 4096;
pub const maximum_diagnostics: usize = 8;
pub const maximum_summary_characters: usize = 4096;
pub const maximum_path_bytes: usize = system_profile.maximum_path_bytes;
pub const rejected_request_binding_label =
    "debz:apt-system-api-v1:rejected-unbound-request";

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

pub const OwnedRequest = struct {
    request: Request,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedRequest) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

const WireRequest = struct {
    schema: []const u8,
    version: u32,
    api_version: u32,
    operation: Operation,
    profile_path: []const u8,
    packages: []const []const u8,
    assume_yes: bool,
};

/// Decodes the canonical request retained with an operation. Recovery uses
/// this boundary instead of reconstructing selectors from human diagnostics
/// or mutable caller input.
pub fn decodeRequest(
    allocator: std.mem.Allocator,
    source: []const u8,
) !OwnedRequest {
    if (source.len > maximum_document_bytes) return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(WireRequest, allocator, source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    }) catch return error.InvalidDocument;
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.schema, request_schema_id) or
        parsed.value.version != schema_version)
        return error.UnsupportedSchema;
    const decoded: Request = .{
        .api_version = parsed.value.api_version,
        .operation = parsed.value.operation,
        .profile_path = parsed.value.profile_path,
        .packages = parsed.value.packages,
        .assume_yes = parsed.value.assume_yes,
    };
    try validateRequest(decoded);

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    const packages = try owned.alloc([]const u8, decoded.packages.len);
    for (decoded.packages, 0..) |package, index|
        packages[index] = try owned.dupe(u8, package);
    var result: OwnedRequest = .{
        .request = .{
            .api_version = decoded.api_version,
            .operation = decoded.operation,
            .profile_path = try owned.dupe(u8, decoded.profile_path),
            .packages = packages,
            .assume_yes = decoded.assume_yes,
        },
        .arena = arena,
        .backing_allocator = allocator,
    };
    const canonical = try result.request.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return result;
}

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

pub const MutationStatus = enum {
    unknown,
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

pub const Item = struct {
    package: []const u8,
    version: ?[]const u8 = null,
    architecture: ?[]const u8 = null,
    detail: ?[]const u8 = null,
};

pub const Result = struct {
    api_version: u32 = api_version,
    operation: Operation,
    request_sha256: [32]u8,
    profile: ?ProfileBinding = null,
    outcome: Outcome,
    exit_status: ExitStatus,
    changed: bool = false,
    mutation_status: ?MutationStatus = null,
    summary: []const u8,
    items: []const Item = &.{},
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
        return rejectedRequestFailure(
            request.operation,
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
) !Result {
    try validateRequest(request);
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
    return complete(result);
}

fn rejectedRequestFailure(
    operation: Operation,
    outcome: Outcome,
    id: DiagnosticId,
    phase: []const u8,
    message: []const u8,
) !Result {
    var result: Result = .{
        .operation = operation,
        .request_sha256 = rejectedRequestDigest(),
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
    return complete(result);
}

fn rejectedRequestDigest() [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        rejected_request_binding_label,
        &digest,
        .{},
    );
    return digest;
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
    const items = try owned.alloc(Item, input.items.len);
    for (input.items, 0..) |item, index| {
        items[index] = .{
            .package = try owned.dupe(u8, item.package),
            .version = try dupeOptional(owned, item.version),
            .architecture = try dupeOptional(owned, item.architecture),
            .detail = try dupeOptional(owned, item.detail),
        };
    }
    result.items = items;
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
    if (!absolute_path.nonRootBounded(
        request.profile_path,
        maximum_path_bytes,
    ))
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
    if (!validText(result.summary, maximum_summary_characters))
        return error.InvalidSummary;
    if (result.items.len > maximum_result_items) return error.TooManyItems;
    if (result.items.len != 0 and !resultAllowsItems(result))
        return error.UnexpectedItems;
    if (result.mutation_status) |status| switch (status) {
        .unknown => {
            if (result.changed or result.outcome != .recovery or
                result.profile != null or
                result.evidence.exact_lock != null or
                result.evidence.transaction_result != null or
                result.evidence.root_operation_completion != null or
                result.evidence.active_operation_state != null)
                return error.InvalidMutationStatus;
        },
    };
    for (result.items) |item| {
        if (!validPackage(item.package)) return error.InvalidItem;
        if (item.version) |version|
            if (!validText(version, 1024)) return error.InvalidItem;
        if (item.architecture) |architecture|
            if (!validText(architecture, 64)) return error.InvalidItem;
        if (item.detail) |detail|
            if (!validText(detail, maximum_summary_characters))
                return error.InvalidItem;
    }

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
            !validText(diagnostic.message, maximum_summary_characters))
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
    if (encodedDocumentSize(result) > maximum_document_bytes)
        return error.DocumentTooLarge;
}

fn resultAllowsItems(result: Result) bool {
    if (result.operation == .list_installed) return true;
    if (!result.operation.mutatesRoot() or
        result.outcome != .usage or
        result.diagnostic_count != 1)
        return false;
    return result.diagnostics[0].id == .confirmation_required;
}

pub fn validateCompleteResult(result: Result) !void {
    try validateResult(result);
    if (!std.mem.eql(u8, &result.digest_sha256, &digestPayload(result)))
        return error.DigestMismatch;
}

pub fn validateProfileBinding(profile: ProfileBinding) !void {
    if (!absolute_path.nonRootBounded(
        profile.path,
        maximum_path_bytes,
    ))
        return error.InvalidProfileBinding;
}

pub fn validateEvidence(evidence: Evidence) !void {
    if (evidence.exact_lock) |binding| try validateDocumentBinding(binding);
    if (evidence.transaction_result) |binding|
        try validateDocumentBinding(binding);
    if (evidence.root_operation_completion) |binding|
        try validateDocumentBinding(binding.document);
    if (evidence.active_operation_state) |path| {
        if (!absolute_path.nonRootBounded(
            path,
            maximum_path_bytes,
        ))
            return error.InvalidEvidencePath;
    }
}

fn validateDocumentBinding(binding: DocumentBinding) !void {
    if (!absolute_path.nonRootBounded(
        binding.path,
        maximum_path_bytes,
    ))
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
    if (package.len == 0 or package.len > 255 or
        !std.ascii.isAlphanumeric(package[0]))
        return false;
    for (package[1..]) |byte|
        if (!(std.ascii.isAlphanumeric(byte) or byte == '+' or byte == '-' or
            byte == '.' or byte == ':' or byte == '='))
            return false;
    return true;
}

fn validText(text: []const u8, maximum: usize) bool {
    validateBoundedText(text, maximum) catch return false;
    return true;
}

fn validateBoundedText(text: []const u8, maximum: usize) !void {
    if (text.len == 0) return error.EmptyText;
    const maximum_bytes = std.math.mul(usize, maximum, 4) catch
        return error.TextTooLong;
    if (text.len > maximum_bytes) return error.TextTooLong;
    var index: usize = 0;
    var characters: usize = 0;
    while (index < text.len) {
        const sequence_length: usize = std.unicode.utf8ByteSequenceLength(
            text[index],
        ) catch return error.InvalidUtf8;
        if (sequence_length > text.len - index) return error.InvalidUtf8;
        const codepoint = std.unicode.utf8Decode(
            text[index..][0..sequence_length],
        ) catch return error.InvalidUtf8;
        characters += 1;
        if (characters > maximum) return error.TextTooLong;
        if (codepoint < 0x20 or codepoint == 0x7f)
            return error.ControlCharacter;
        index += sequence_length;
    }
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
    try writeResultPayloadPrefix(result, writer);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHex(writer, &result.digest_sha256);
    try writer.writeByte('}');
}

fn encodedDocumentSize(result: Result) usize {
    var buffer: [256]u8 = undefined;
    var discarding: std.Io.Writer.Discarding = .init(&buffer);
    writeResultDocument(result, &discarding.writer) catch unreachable;
    return @intCast(discarding.fullCount());
}

fn writeResultPayload(result: Result, writer: *std.Io.Writer) !void {
    try writeResultPayloadPrefix(result, writer);
    try writer.writeByte('}');
}

fn writeResultPayloadPrefix(result: Result, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeString(
        writer,
        if (result.items.len == 0 and result.mutation_status == null)
            result_schema_id
        else
            result_items_schema_id,
    );
    try writer.print(",\"version\":{},\"api_version\":{},\"operation\":", .{
        if (result.items.len == 0 and result.mutation_status == null)
            schema_version
        else
            result_items_schema_version,
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
    try writer.print(",\"exit_status\":{},\"changed\":{}", .{
        @intFromEnum(result.exit_status),
        result.changed,
    });
    if (result.items.len != 0 or result.mutation_status != null) {
        try writer.writeAll(",\"mutation_status\":");
        try writeString(
            writer,
            if (result.mutation_status != null)
                "unknown"
            else if (result.changed)
                "changed"
            else
                "unchanged",
        );
    }
    try writer.writeAll(",\"summary\":");
    try writeString(writer, result.summary);
    if (result.items.len != 0) {
        try writer.writeAll(",\"items\":[");
        for (result.items, 0..) |item, index| {
            if (index != 0) try writer.writeByte(',');
            try writer.writeAll("{\"package\":");
            try writeString(writer, item.package);
            try writer.writeAll(",\"version\":");
            try writeOptionalString(writer, item.version);
            try writer.writeAll(",\"architecture\":");
            try writeOptionalString(writer, item.architecture);
            try writer.writeAll(",\"detail\":");
            try writeOptionalString(writer, item.detail);
            try writer.writeByte('}');
        }
        try writer.writeByte(']');
    }
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
    try writer.writeByte(']');
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
            return try failure(request, .internal, .internal_error, "test", "called");
        }
    };
    const result = try execute(std.testing.allocator, .{
        .operation = .update,
        .packages = &.{"ignored"},
    }, .{ .context = &called, .executeFn = Fake.run });
    try std.testing.expectEqual(Outcome.usage, result.outcome);
    try std.testing.expectEqual(DiagnosticId.invalid_request, result.diagnostics[0].id);
    const rejected_digest = rejectedRequestDigest();
    try std.testing.expectEqualSlices(
        u8,
        &rejected_digest,
        &result.request_sha256,
    );
    try std.testing.expect(!called);
}

test "apt_system_api.test.rejected envelopes are never traversed or hashed" {
    var called = false;
    const Fake = struct {
        fn run(context: *anyopaque, _: std.mem.Allocator, request: Request) !Result {
            const value: *bool = @ptrCast(@alignCast(context));
            value.* = true;
            return try failure(request, .internal, .internal_error, "test", "called");
        }
    };
    const inaccessible_path = @as(
        [*]const u8,
        @ptrFromInt(1),
    )[0 .. system_profile.maximum_path_bytes + 1];
    const path_result = try execute(std.testing.allocator, .{
        .operation = .update,
        .profile_path = inaccessible_path,
    }, .{ .context = &called, .executeFn = Fake.run });
    const rejected_digest = rejectedRequestDigest();
    try std.testing.expectEqualSlices(
        u8,
        &rejected_digest,
        &path_result.request_sha256,
    );
    try std.testing.expect(!called);

    const inaccessible_package = @as(
        [*]const u8,
        @ptrFromInt(1),
    )[0..256];
    const package_result = try execute(std.testing.allocator, .{
        .operation = .install,
        .packages = &.{inaccessible_package},
    }, .{ .context = &called, .executeFn = Fake.run });
    try std.testing.expectEqualSlices(
        u8,
        &rejected_digest,
        &package_result.request_sha256,
    );
    try std.testing.expect(!called);

    const inaccessible_packages = @as(
        [*]const []const u8,
        @ptrFromInt(@alignOf([]const u8)),
    )[0 .. maximum_packages + 1];
    const count_result = try execute(std.testing.allocator, .{
        .operation = .install,
        .packages = inaccessible_packages,
    }, .{ .context = &called, .executeFn = Fake.run });
    try std.testing.expectEqualSlices(
        u8,
        &rejected_digest,
        &count_result.request_sha256,
    );
    try std.testing.expect(!called);

    try std.testing.expectError(
        error.InvalidPackage,
        failure(
            .{
                .operation = .install,
                .packages = &.{inaccessible_package},
            },
            .usage,
            .invalid_request,
            "request",
            "invalid request",
        ),
    );
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

    var stale = try failure(
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

    var wrong_operation = try failure(
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

    var wrong_digest = try failure(
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

    var valid_failure = try failure(
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

test "apt_system_api.test.runtime rejects exit and diagnostic outcome mismatches" {
    const request: Request = .{
        .operation = .install,
        .packages = &.{"curl"},
    };
    var result = try failure(
        request,
        .planning,
        .planning_failed,
        "planning",
        "planning failed",
    );
    result.exit_status = .download;
    try std.testing.expectError(error.InvalidExitStatus, validateResult(result));
    result.exit_status = .planning;
    result.diagnostics[0].outcome = .download;
    try std.testing.expectError(error.InvalidDiagnostic, validateResult(result));
}

test "apt_system_api.test.invalid UTF-8 cannot be completed executed or serialized" {
    const Fake = struct {
        fn run(context: *anyopaque, _: std.mem.Allocator, _: Request) !Result {
            const result: *Result = @ptrCast(@alignCast(context));
            return result.*;
        }
    };
    const request: Request = .{
        .operation = .install,
        .packages = &.{"curl"},
    };
    const invalid_utf8 = [_]u8{0xff};
    try std.testing.expectError(
        error.InvalidSummary,
        failure(
            request,
            .planning,
            .planning_failed,
            "planning",
            &invalid_utf8,
        ),
    );
    try std.testing.expectError(
        error.InvalidDiagnostic,
        failure(
            request,
            .planning,
            .planning_failed,
            &invalid_utf8,
            "planning failed",
        ),
    );
    var result = try failure(
        request,
        .planning,
        .planning_failed,
        "planning",
        "planning failed",
    );
    result.summary = &invalid_utf8;
    try std.testing.expectError(error.InvalidSummary, validateResult(result));
    try std.testing.expectError(error.InvalidSummary, complete(result));
    result.digest_sha256 = digestPayload(result);
    try std.testing.expectError(
        error.InvalidSummary,
        result.canonicalJson(std.testing.allocator),
    );
    try std.testing.expectError(
        error.InvalidBackendResult,
        execute(std.testing.allocator, request, .{
            .context = &result,
            .executeFn = Fake.run,
        }),
    );

    result.summary = "planning failed";
    result.diagnostics[0].message = &invalid_utf8;
    try std.testing.expectError(error.InvalidDiagnostic, validateResult(result));
}

test "apt_system_api.test.summary limits count Unicode characters" {
    const request: Request = .{
        .operation = .install,
        .packages = &.{"curl"},
    };
    const valid = try std.testing.allocator.alloc(
        u8,
        maximum_summary_characters * 2,
    );
    defer std.testing.allocator.free(valid);
    for (0..maximum_summary_characters) |index| {
        valid[index * 2] = 0xc3;
        valid[index * 2 + 1] = 0xa9;
    }
    var result = try failure(
        request,
        .planning,
        .planning_failed,
        "planning",
        "planning failed",
    );
    result.summary = valid;
    try validateResult(result);

    const too_long = try std.testing.allocator.alloc(
        u8,
        (maximum_summary_characters + 1) * 2,
    );
    defer std.testing.allocator.free(too_long);
    @memcpy(too_long[0..valid.len], valid);
    too_long[valid.len] = 0xc3;
    too_long[valid.len + 1] = 0xa9;
    result.summary = too_long;
    try std.testing.expectError(error.InvalidSummary, validateResult(result));

    const ascii_too_long = try std.testing.allocator.alloc(
        u8,
        maximum_summary_characters + 1,
    );
    defer std.testing.allocator.free(ascii_too_long);
    @memset(ascii_too_long, 'a');
    try std.testing.expectError(
        error.InvalidSummary,
        failure(
            request,
            .planning,
            .planning_failed,
            "planning",
            ascii_too_long,
        ),
    );
}

test "apt_system_api.test.text validation stops at bounded limits" {
    const over_byte_bound = try std.testing.allocator.alloc(
        u8,
        maximum_summary_characters * 4 + 1,
    );
    defer std.testing.allocator.free(over_byte_bound);
    @memset(over_byte_bound, 'a');
    try std.testing.expectError(
        error.TextTooLong,
        validateBoundedText(over_byte_bound, maximum_summary_characters),
    );

    const over_character_bound = try std.testing.allocator.alloc(
        u8,
        maximum_summary_characters + 2,
    );
    defer std.testing.allocator.free(over_character_bound);
    @memset(over_character_bound, 'a');
    over_character_bound[over_character_bound.len - 1] = 0xff;
    try std.testing.expectError(
        error.TextTooLong,
        validateBoundedText(over_character_bound, maximum_summary_characters),
    );
}

test "apt_system_api.test.item-bearing results are owned and bind the canonical digest" {
    var package = [_]u8{ 'a', 'l', 'p', 'h', 'a' };
    var version = [_]u8{ '1', '.', '2' };
    var architecture = [_]u8{ 'a', 'm', 'd', '6', '4' };
    const items = [_]Item{.{
        .package = &package,
        .version = &version,
        .architecture = &architecture,
    }};
    const input = try complete(.{
        .operation = .list_installed,
        .request_sha256 = @splat(0x11),
        .profile = .{
            .path = "/profile.json",
            .sha256 = @splat(0x22),
            .reference_evidence_sha256 = @splat(0x33),
        },
        .outcome = .success,
        .exit_status = .success,
        .summary = "one installed package",
        .items = &items,
    });
    var owned = try ownResult(std.testing.allocator, input);
    defer owned.deinit();
    @memset(&package, 'x');
    @memset(&version, 'x');
    @memset(&architecture, 'x');
    try std.testing.expectEqualStrings("alpha", owned.items[0].package);
    try std.testing.expectEqualStrings("1.2", owned.items[0].version.?);
    try std.testing.expectEqualStrings("amd64", owned.items[0].architecture.?);
    const canonical = try owned.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(canonical);
    try std.testing.expect(std.mem.indexOf(
        u8,
        canonical,
        "\"schema\":\"https://debz.dev/schema/apt-system-result-v2\",\"version\":2",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        canonical,
        "\"items\":[{\"package\":\"alpha\",\"version\":\"1.2\",\"architecture\":\"amd64\",\"detail\":null}]",
    ) != null);

    var changed = owned;
    const replacement = [_]Item{.{ .package = "beta" }};
    changed.items = &replacement;
    try std.testing.expectError(
        error.DigestMismatch,
        changed.canonicalJson(std.testing.allocator),
    );
    var non_list = input;
    non_list.operation = .update;
    try std.testing.expectError(error.UnexpectedItems, validateResult(non_list));

    var confirmation = try failure(
        .{
            .operation = .install,
            .profile_path = "/profile.json",
            .packages = &.{"alpha"},
        },
        .usage,
        .confirmation_required,
        "confirmation",
        "confirmation required",
    );
    confirmation.profile = input.profile;
    confirmation.items = &items;
    confirmation.evidence.exact_lock = .{
        .path = "/state/exact-lock.json",
        .schema = "io.github.cataggar.debz.exact-closure-lock.v2",
        .version = 2,
        .digest_sha256 = @splat(0x44),
    };
    _ = try complete(confirmation);
    confirmation.diagnostic_count = 2;
    confirmation.diagnostics[1] = confirmation.diagnostics[0];
    try std.testing.expectError(
        error.UnexpectedItems,
        validateResult(confirmation),
    );
}

test "apt_system_api.test.package grammar requires alphanumeric first byte across requests and items" {
    const valid = [_][]const u8{
        "a", "Z", "0", "a+", "a-", "a.", "a:", "a=",
    };
    const invalid = [_][]const u8{
        "+a", "-a", ".a", ":a", "=a", "a_b", "a/b", "\xc3\xa9", "\x1f",
    };
    for (valid) |package| {
        try validateRequest(.{
            .operation = .install,
            .profile_path = "/profile.json",
            .packages = &.{package},
        });
        const result = try complete(.{
            .operation = .list_installed,
            .request_sha256 = @splat(0x11),
            .profile = .{
                .path = "/profile.json",
                .sha256 = @splat(0x22),
                .reference_evidence_sha256 = @splat(0x33),
            },
            .outcome = .success,
            .exit_status = .success,
            .summary = "installed",
            .items = &.{.{ .package = package }},
        });
        const document = try result.canonicalJson(std.testing.allocator);
        defer std.testing.allocator.free(document);
        try std.testing.expect(std.mem.indexOf(
            u8,
            document,
            "\"mutation_status\":\"unchanged\"",
        ) != null);
    }
    for (invalid) |package| {
        try std.testing.expectError(error.InvalidPackage, validateRequest(.{
            .operation = .install,
            .profile_path = "/profile.json",
            .packages = &.{package},
        }));
        try std.testing.expectError(error.InvalidItem, validateResult(.{
            .operation = .list_installed,
            .request_sha256 = @splat(0x11),
            .profile = .{
                .path = "/profile.json",
                .sha256 = @splat(0x22),
                .reference_evidence_sha256 = @splat(0x33),
            },
            .outcome = .success,
            .exit_status = .success,
            .summary = "installed",
            .items = &.{.{ .package = package }},
        }));
    }
    const too_long = "a" ** 256;
    try std.testing.expectError(error.InvalidPackage, validateRequest(.{
        .operation = .install,
        .profile_path = "/profile.json",
        .packages = &.{too_long},
    }));
}

test "apt_system_api.test.unknown mutation status rejects all unverified evidence" {
    const request: Request = .{
        .operation = .install,
        .profile_path = "/profile.json",
        .packages = &.{"alpha"},
    };
    var unknown = try failure(
        request,
        .recovery,
        .recovery_required,
        "recovery",
        "mutation status unknown",
    );
    unknown.mutation_status = .unknown;
    _ = try complete(unknown);
    unknown.profile = .{
        .path = "/profile.json",
        .sha256 = @splat(0x11),
        .reference_evidence_sha256 = @splat(0x22),
    };
    try std.testing.expectError(
        error.InvalidMutationStatus,
        validateResult(unknown),
    );
}

test "apt_system_api.test.itemless results preserve exact v1 wire contract" {
    const result = try complete(.{
        .operation = .update,
        .request_sha256 = @splat(0x11),
        .profile = .{
            .path = "/profile.json",
            .sha256 = @splat(0x22),
            .reference_evidence_sha256 = @splat(0x33),
        },
        .outcome = .success,
        .exit_status = .success,
        .changed = true,
        .summary = "updated",
    });
    const canonical = try result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(canonical);
    try std.testing.expect(std.mem.startsWith(
        u8,
        canonical,
        "{\"schema\":\"https://debz.dev/schema/apt-system-result-v1\",\"version\":1,",
    ));
    try std.testing.expect(std.mem.indexOf(u8, canonical, "\"items\"") == null);
}

test "apt_system_api.test.result encoded-size budget accepts maximum and rejects one over" {
    var items: [64]Item = undefined;
    for (&items) |*item| item.* = .{ .package = "p" };
    const full_detail = try std.testing.allocator.alloc(
        u8,
        maximum_summary_characters,
    );
    defer std.testing.allocator.free(full_detail);
    @memset(full_detail, 'd');

    var candidate: Result = .{
        .operation = .list_installed,
        .request_sha256 = @splat(0x11),
        .profile = .{
            .path = "/profile.json",
            .sha256 = @splat(0x22),
            .reference_evidence_sha256 = @splat(0x33),
        },
        .outcome = .success,
        .exit_status = .success,
        .summary = "x",
        .items = &items,
    };
    var index: usize = 0;
    while (index < items.len) : (index += 1) {
        items[index].detail = full_detail;
        if (encodedDocumentSize(candidate) > maximum_document_bytes) {
            items[index].detail = null;
            break;
        }
    }
    const remainder = maximum_document_bytes - encodedDocumentSize(candidate);
    const exact_summary = try std.testing.allocator.alloc(u8, 1 + remainder);
    defer std.testing.allocator.free(exact_summary);
    @memset(exact_summary, 's');
    candidate.summary = exact_summary;
    try std.testing.expectEqual(
        maximum_document_bytes,
        encodedDocumentSize(candidate),
    );
    const completed = try complete(candidate);
    var owned = try ownResult(std.testing.allocator, completed);
    defer owned.deinit();
    const source = try owned.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(source);
    try std.testing.expectEqual(maximum_document_bytes, source.len);

    const oversized_summary = try std.testing.allocator.alloc(
        u8,
        exact_summary.len + 1,
    );
    defer std.testing.allocator.free(oversized_summary);
    @memset(oversized_summary, 's');
    candidate.summary = oversized_summary;
    try std.testing.expectEqual(
        maximum_document_bytes + 1,
        encodedDocumentSize(candidate),
    );
    try std.testing.expectError(error.DocumentTooLarge, complete(candidate));
    try std.testing.expectError(
        error.DocumentTooLarge,
        ownResult(std.testing.allocator, candidate),
    );
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
    const required = parsed.value.object.get("required").?.array.items;
    for (required) |field|
        try std.testing.expect(!std.mem.eql(u8, field.string, "items"));
    try std.testing.expect(
        parsed.value.object.get("properties").?.object.get("items") == null,
    );
    try std.testing.expectEqualStrings(
        absolute_path.schema_pattern,
        definitions.get("absolutePath").?.object.get("pattern").?.string,
    );
    const outcomes = definitions.get("outcome").?.object.get("enum").?.array.items;
    try std.testing.expectEqual(std.meta.fields(Outcome).len, outcomes.len);
    const diagnostic_ids = definitions.get("diagnosticId").?.object.get("enum").?.array.items;
    try std.testing.expectEqual(std.meta.fields(DiagnosticId).len, diagnostic_ids.len);

    const conditions = parsed.value.object.get("allOf").?.array.items;
    inline for (std.meta.fields(Outcome)) |field| {
        const outcome: Outcome = @enumFromInt(field.value);
        const expected_status: i64 = @intFromEnum(exitStatus(outcome));
        var found = false;
        for (conditions) |condition| {
            const condition_object = condition.object;
            const if_object = condition_object.get("if") orelse continue;
            const if_properties = if_object.object.get("properties") orelse continue;
            const outcome_property = if_properties.object.get("outcome") orelse continue;
            const outcome_const = outcome_property.object.get("const") orelse continue;
            if (!std.mem.eql(u8, outcome_const.string, field.name)) continue;
            const then_object = condition_object.get("then").?.object;
            const then_properties = then_object.get("properties").?.object;
            const schema_status = then_properties.get("exit_status").?
                .object.get("const").?.integer;
            try std.testing.expectEqual(expected_status, schema_status);
            const wrong_status = if (expected_status == 70)
                @as(i64, 0)
            else
                expected_status + 1;
            try std.testing.expect(schema_status != wrong_status);
            if (outcome != .success) {
                const diagnostic_items = then_properties.get("diagnostics").?
                    .object.get("items").?.object;
                const item_conditions = diagnostic_items.get("allOf").?.array.items;
                const diagnostic_outcome = item_conditions[1].object
                    .get("properties").?.object
                    .get("outcome").?.object
                    .get("const").?.string;
                try std.testing.expectEqualStrings(field.name, diagnostic_outcome);
                const wrong_outcome_index =
                    (@as(usize, @intCast(field.value)) + 1) %
                    std.meta.fields(Outcome).len;
                try std.testing.expect(!std.mem.eql(
                    u8,
                    std.meta.fields(Outcome)[wrong_outcome_index].name,
                    diagnostic_outcome,
                ));
            }

            found = true;
            break;
        }
        try std.testing.expect(found);
    }
}

test "apt_system_api.test.result v2 schema is an explicit bounded item extension" {
    const source = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "schema/apt-system-result-v2.json",
        std.testing.allocator,
        .limited(maximum_document_bytes),
    );
    defer std.testing.allocator.free(source);
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        source,
        .{},
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        result_items_schema_id,
        parsed.value.object.get("$id").?.string,
    );
    const properties = parsed.value.object.get("properties").?.object;
    try std.testing.expectEqual(
        @as(i64, result_items_schema_version),
        properties.get("version").?.object.get("const").?.integer,
    );
    try std.testing.expectEqual(
        @as(i64, @intCast(maximum_result_items)),
        properties.get("items").?.object.get("maxItems").?.integer,
    );
    try std.testing.expectEqual(
        @as(i64, 1),
        properties.get("items").?.object.get("minItems").?.integer,
    );
}
