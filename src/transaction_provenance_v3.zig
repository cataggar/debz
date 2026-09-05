const std = @import("std");
const repository_refresh = @import("repository_refresh.zig");
const transaction_provenance_v2 = @import("transaction_provenance_v2.zig");

pub const schema_id = "https://debz.dev/schema/transaction-result-v3";
pub const schema_version: u32 = 3;
pub const maximum_document_bytes: usize = 40 * 1024 * 1024;
pub const maximum_repositories: usize = 16_384;
pub const maximum_selected_path_bytes: usize = 4096;

pub const RepositoryRefreshEvidence = struct {
    source_config_id: [64]u8,
    snapshot_sha256: [32]u8,
    signed_release_date_unix: i64,
    valid_until_unix: ?i64,
    verification_time_unix: i64,
    maximum_future_seconds: u64,
    future_date_accepted: bool,
    observed_release_age_seconds: u64,
    expiry_policy: repository_refresh.ExpiryPolicy,
    maximum_release_age_seconds: ?u64,
    missing_valid_until_exception_exercised: bool,
    selected_packages_path: []const u8,
    compression: repository_refresh.Compression,
};

pub const Result = struct {
    attempt_sha256: ?[32]u8,
    execution_v2_json: []const u8,
    execution_v2_sha256: [32]u8,
    repository_refresh: []const RepositoryRefreshEvidence,
    digest_sha256: [32]u8,

    pub fn canonicalJson(self: Result, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeDocument(self, &output.writer);
        const bytes = try output.toOwnedSlice();
        if (bytes.len > maximum_document_bytes) {
            allocator.free(bytes);
            return error.DocumentTooLarge;
        }
        return bytes;
    }
};

pub const OwnedResult = struct {
    result: Result,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedResult) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const ValidatedDocument = struct {
    bytes: []u8,
    digest_sha256: [32]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ValidatedDocument) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub fn create(
    allocator: std.mem.Allocator,
    attempt_sha256: ?[32]u8,
    execution: transaction_provenance_v2.Result,
    refresh_evidence: []const RepositoryRefreshEvidence,
) !OwnedResult {
    const execution_json = try execution.canonicalJson(allocator);
    defer allocator.free(execution_json);
    if (refresh_evidence.len != execution.repositories.len)
        return error.RepositoryEvidenceMismatch;

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    const repositories = try owned.alloc(
        RepositoryRefreshEvidence,
        refresh_evidence.len,
    );
    for (refresh_evidence, 0..) |evidence, index| {
        try validateRepositoryRefreshEvidence(evidence);
        repositories[index] = evidence;
        repositories[index].selected_packages_path = try owned.dupe(
            u8,
            evidence.selected_packages_path,
        );
    }
    std.mem.sort(
        RepositoryRefreshEvidence,
        repositories,
        {},
        lessRepository,
    );
    for (repositories, 0..) |repository, index| {
        if (index != 0 and std.mem.eql(
            u8,
            &repository.source_config_id,
            &repositories[index - 1].source_config_id,
        )) return error.RepositoryEvidenceMismatch;
    }
    try validateRepositoryCorrespondence(
        execution.repositories,
        repositories,
    );

    var result: Result = .{
        .attempt_sha256 = attempt_sha256,
        .execution_v2_json = try owned.dupe(u8, execution_json),
        .execution_v2_sha256 = sha256(execution_json),
        .repository_refresh = repositories,
        .digest_sha256 = undefined,
    };
    result.digest_sha256 = digestPayload(result);
    return .{
        .result = result,
        .arena = arena,
        .backing_allocator = allocator,
    };
}

pub fn validateDocument(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !ValidatedDocument {
    if (source.len > maximum_bytes or source.len > maximum_document_bytes)
        return error.DocumentTooLarge;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, source, .{
        .allocate = .alloc_always,
        .parse_numbers = true,
    });
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |value| value,
        else => return error.NonCanonicalDocument,
    };
    if (object.count() != 7 or hasJsonWhitespace(source))
        return error.NonCanonicalDocument;
    const schema = object.get("schema") orelse return error.UnsupportedSchema;
    const version = object.get("version") orelse return error.UnsupportedSchema;
    if (schema != .string or !std.mem.eql(u8, schema.string, schema_id) or
        version != .integer or version.integer != schema_version)
        return error.UnsupportedSchema;

    const digest_value = object.get("digest_sha256") orelse return error.InvalidDigest;
    if (digest_value != .string) return error.InvalidDigest;
    const expected = try parseDigest(digest_value.string);
    const digest_marker = ",\"digest_sha256\":\"";
    const digest_index = std.mem.lastIndexOf(u8, source, digest_marker) orelse
        return error.NonCanonicalDocument;
    if (digest_index + digest_marker.len + 64 + 2 != source.len or
        source[source.len - 2] != '"' or source[source.len - 1] != '}')
        return error.NonCanonicalDocument;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(source[0..digest_index]);
    hash.update("}");
    const actual = hash.finalResult();
    if (!std.mem.eql(u8, &expected, &actual)) return error.DigestMismatch;

    const execution_marker = "\"execution\":";
    const refresh_marker = ",\"repository_refresh\":";
    const execution_start = (std.mem.indexOf(u8, source, execution_marker) orelse
        return error.NonCanonicalDocument) + execution_marker.len;
    const execution_end = std.mem.indexOfPos(
        u8,
        source,
        execution_start,
        refresh_marker,
    ) orelse return error.NonCanonicalDocument;
    const execution = source[execution_start..execution_end];
    var validated_execution = try transaction_provenance_v2.validateDocument(
        allocator,
        execution,
        transaction_provenance_v2.maximum_document_bytes,
    );
    defer validated_execution.deinit();
    const execution_digest_value = object.get("execution_v2_sha256") orelse
        return error.InvalidDigest;
    if (execution_digest_value != .string) return error.InvalidDigest;
    const expected_execution_digest = try parseDigest(execution_digest_value.string);
    const actual_execution_digest = sha256(execution);
    if (!std.mem.eql(
        u8,
        &expected_execution_digest,
        &actual_execution_digest,
    )) return error.DigestMismatch;
    const attempt_value = object.get("attempt_sha256") orelse
        return error.InvalidDigest;
    const attempt_sha256: ?[32]u8 = switch (attempt_value) {
        .null => null,
        .string => |value| try parseDigest(value),
        else => return error.InvalidDigest,
    };

    const refresh_value = object.get("repository_refresh") orelse
        return error.InvalidRefreshEvidence;
    const refresh_array = switch (refresh_value) {
        .array => |value| value.items,
        else => return error.InvalidRefreshEvidence,
    };
    if (refresh_array.len > maximum_repositories)
        return error.TooManyRepositories;
    const refresh_evidence = try allocator.alloc(
        RepositoryRefreshEvidence,
        refresh_array.len,
    );
    defer allocator.free(refresh_evidence);
    for (refresh_array, 0..) |value, index| {
        refresh_evidence[index] = try parseRepositoryRefreshEvidence(value);
        try validateRepositoryRefreshEvidence(refresh_evidence[index]);
    }
    std.mem.sort(
        RepositoryRefreshEvidence,
        refresh_evidence,
        {},
        lessRepository,
    );
    for (refresh_evidence, 0..) |evidence, index| {
        if (index != 0 and std.mem.eql(
            u8,
            &evidence.source_config_id,
            &refresh_evidence[index - 1].source_config_id,
        )) return error.RepositoryEvidenceMismatch;
    }
    try crossCheckExecutionRepositories(
        allocator,
        execution,
        refresh_evidence,
    );
    const canonical_result: Result = .{
        .attempt_sha256 = attempt_sha256,
        .execution_v2_json = execution,
        .execution_v2_sha256 = actual_execution_digest,
        .repository_refresh = refresh_evidence,
        .digest_sha256 = expected,
    };
    const canonical = try canonical_result.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source))
        return error.NonCanonicalDocument;

    return .{
        .bytes = try allocator.dupe(u8, source),
        .digest_sha256 = expected,
        .allocator = allocator,
    };
}

pub fn validateRepositoryRefreshEvidence(
    evidence: RepositoryRefreshEvidence,
) !void {
    if (!repository_refresh.validExpiryPolicy(evidence.expiry_policy) or
        repository_refresh.expiryPolicyMaxAge(evidence.expiry_policy) !=
            evidence.maximum_release_age_seconds or
        evidence.observed_release_age_seconds != releaseAgeSeconds(
            evidence.verification_time_unix,
            evidence.signed_release_date_unix,
        ) or
        evidence.selected_packages_path.len == 0 or
        evidence.selected_packages_path.len >
            maximum_selected_path_bytes)
        return error.InvalidRefreshEvidence;
    const future_date_accepted = repository_refresh.validateFutureDate(
        evidence.signed_release_date_unix,
        evidence.verification_time_unix,
        evidence.maximum_future_seconds,
    ) catch return error.InvalidRefreshEvidence;
    if (future_date_accepted != evidence.future_date_accepted)
        return error.InvalidRefreshEvidence;
    if (evidence.valid_until_unix) |valid_until| {
        if (valid_until < evidence.signed_release_date_unix or
            evidence.verification_time_unix > valid_until or
            evidence.missing_valid_until_exception_exercised)
            return error.InvalidRefreshEvidence;
    }
    switch (evidence.expiry_policy) {
        .require_valid_until => {
            if (evidence.valid_until_unix == null or
                evidence.maximum_release_age_seconds != null or
                evidence.missing_valid_until_exception_exercised)
                return error.InvalidRefreshEvidence;
        },
        .allow_missing_valid_until_with_max_age_seconds => |maximum_age| {
            if (evidence.valid_until_unix == null) {
                if (!evidence.missing_valid_until_exception_exercised or
                    evidence.observed_release_age_seconds > maximum_age)
                    return error.InvalidRefreshEvidence;
                const deadline = std.math.add(
                    i64,
                    evidence.signed_release_date_unix,
                    @intCast(maximum_age),
                ) catch return error.InvalidRefreshEvidence;
                if (evidence.verification_time_unix > deadline)
                    return error.InvalidRefreshEvidence;
            } else if (evidence.missing_valid_until_exception_exercised) {
                return error.InvalidRefreshEvidence;
            }
        },
    }
    const expected_suffix = switch (evidence.compression) {
        .xz => ".xz",
        .gzip => ".gz",
        .zstd => ".zst",
        .uncompressed => "",
    };
    if (!std.mem.endsWith(
        u8,
        evidence.selected_packages_path,
        expected_suffix,
    )) return error.InvalidRefreshEvidence;
}

pub fn parseRepositoryRefreshEvidence(
    value: std.json.Value,
) !RepositoryRefreshEvidence {
    const object = switch (value) {
        .object => |result| result,
        else => return error.InvalidRefreshEvidence,
    };
    if (object.count() != 13) return error.InvalidRefreshEvidence;
    const policy_name = try jsonString(object, "expiry_policy");
    const policy: repository_refresh.ExpiryPolicy =
        if (std.mem.eql(u8, policy_name, "require_valid_until"))
            .require_valid_until
        else if (std.mem.eql(
            u8,
            policy_name,
            "allow_missing_valid_until_with_max_age_seconds",
        ))
            .{
                .allow_missing_valid_until_with_max_age_seconds = try jsonOptionalU64(
                    object,
                    "maximum_release_age_seconds",
                ) orelse return error.InvalidRefreshEvidence,
            }
        else
            return error.InvalidRefreshEvidence;
    return .{
        .source_config_id = try parseId(
            try jsonString(object, "source_config_id"),
        ),
        .snapshot_sha256 = try parseDigest(
            try jsonString(object, "snapshot_sha256"),
        ),
        .signed_release_date_unix = try jsonI64(
            object,
            "signed_release_date_unix",
        ),
        .valid_until_unix = try jsonOptionalI64(
            object,
            "valid_until_unix",
        ),
        .verification_time_unix = try jsonI64(
            object,
            "verification_time_unix",
        ),
        .maximum_future_seconds = try jsonU64(
            object,
            "maximum_future_seconds",
        ),
        .future_date_accepted = try jsonBool(
            object,
            "future_date_accepted",
        ),
        .observed_release_age_seconds = try jsonU64(
            object,
            "observed_release_age_seconds",
        ),
        .expiry_policy = policy,
        .maximum_release_age_seconds = try jsonOptionalU64(
            object,
            "maximum_release_age_seconds",
        ),
        .missing_valid_until_exception_exercised = try jsonBool(
            object,
            "missing_valid_until_exception_exercised",
        ),
        .selected_packages_path = try jsonString(
            object,
            "selected_packages_path",
        ),
        .compression = std.meta.stringToEnum(
            repository_refresh.Compression,
            try jsonString(object, "compression"),
        ) orelse return error.InvalidRefreshEvidence,
    };
}

fn crossCheckExecutionRepositories(
    allocator: std.mem.Allocator,
    execution: []const u8,
    refresh_evidence: []const RepositoryRefreshEvidence,
) !void {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, execution, .{
        .allocate = .alloc_always,
        .parse_numbers = true,
    });
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |value| value,
        else => return error.RepositoryEvidenceMismatch,
    };
    const repository_value = root.get("repositories") orelse
        return error.RepositoryEvidenceMismatch;
    const repositories = switch (repository_value) {
        .array => |value| value.items,
        else => return error.RepositoryEvidenceMismatch,
    };
    if (repositories.len != refresh_evidence.len)
        return error.RepositoryEvidenceMismatch;
    for (repositories, refresh_evidence) |value, evidence| {
        const repository = switch (value) {
            .object => |result| result,
            else => return error.RepositoryEvidenceMismatch,
        };
        const id = try parseId(
            try jsonString(repository, "source_config_id"),
        );
        const snapshot = try parseDigest(
            try jsonString(repository, "snapshot_sha256"),
        );
        if (!std.mem.eql(u8, &id, &evidence.source_config_id) or
            !std.mem.eql(u8, &snapshot, &evidence.snapshot_sha256))
            return error.RepositoryEvidenceMismatch;
    }
}

fn validateRepositoryCorrespondence(
    repositories: []const transaction_provenance_v2.RepositoryEvidence,
    refresh_evidence: []const RepositoryRefreshEvidence,
) !void {
    if (repositories.len != refresh_evidence.len)
        return error.RepositoryEvidenceMismatch;
    for (repositories, refresh_evidence, 0..) |repository, evidence, index| {
        if (index != 0 and std.mem.order(
            u8,
            &repositories[index - 1].source_config_id,
            &repository.source_config_id,
        ) != .lt)
            return error.RepositoryEvidenceMismatch;
        if (!std.mem.eql(
            u8,
            &repository.source_config_id,
            &evidence.source_config_id,
        ) or !std.mem.eql(
            u8,
            &repository.snapshot_sha256,
            &evidence.snapshot_sha256,
        ))
            return error.RepositoryEvidenceMismatch;
    }
}

pub const Store = struct {
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,

    pub fn init(io: std.Io, dir: std.Io.Dir, name: []const u8) !Store {
        if (!safeLeaf(name)) return error.InvalidPath;
        return .{ .io = io, .dir = dir, .name = name };
    }

    pub fn writeAtomic(
        self: Store,
        allocator: std.mem.Allocator,
        result: Result,
    ) !void {
        const bytes = try result.canonicalJson(allocator);
        defer allocator.free(bytes);
        const stage = ".transaction-result-v3.new";
        self.dir.deleteFile(self.io, stage) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        {
            var file = try self.dir.createFile(self.io, stage, .{
                .exclusive = true,
                .permissions = if (@import("builtin").os.tag == .windows)
                    .default_file
                else
                    .fromMode(0o600),
                .resolve_beneath = true,
            });
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, bytes);
            try file.sync(self.io);
        }
        try self.dir.rename(stage, self.dir, self.name, self.io);
        switch (@import("builtin").os.tag) {
            .linux => if (std.posix.errno(std.os.linux.fsync(self.dir.handle)) != .SUCCESS)
                return error.Unexpected,
            else => {},
        }
    }
};

fn writeDocument(result: Result, writer: *std.Io.Writer) !void {
    try writePayload(result, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHex(writer, &result.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(result: Result, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeString(writer, schema_id);
    try writer.print(",\"version\":{},\"attempt_sha256\":", .{schema_version});
    if (result.attempt_sha256) |digest|
        try writeHex(writer, &digest)
    else
        try writer.writeAll("null");
    try writer.writeAll(",\"execution_v2_sha256\":");
    try writeHex(writer, &result.execution_v2_sha256);
    try writer.writeAll(",\"execution\":");
    try writer.writeAll(result.execution_v2_json);
    try writer.writeAll(",\"repository_refresh\":[");
    for (result.repository_refresh, 0..) |repository, index| {
        if (index != 0) try writer.writeByte(',');
        try writeRepositoryRefreshEvidence(writer, repository);
    }
    try writer.writeAll("]}");
}

pub fn writeRepositoryRefreshEvidence(
    writer: *std.Io.Writer,
    repository: RepositoryRefreshEvidence,
) !void {
    try writer.writeAll("{\"source_config_id\":");
    try writeString(writer, &repository.source_config_id);
    try writer.writeAll(",\"snapshot_sha256\":");
    try writeHex(writer, &repository.snapshot_sha256);
    try writer.print(
        ",\"signed_release_date_unix\":{d},\"valid_until_unix\":",
        .{repository.signed_release_date_unix},
    );
    if (repository.valid_until_unix) |value|
        try writer.print("{d}", .{value})
    else
        try writer.writeAll("null");
    try writer.print(
        ",\"verification_time_unix\":{d},\"maximum_future_seconds\":{d},\"future_date_accepted\":{s},\"observed_release_age_seconds\":{d},\"expiry_policy\":",
        .{
            repository.verification_time_unix,
            repository.maximum_future_seconds,
            if (repository.future_date_accepted) "true" else "false",
            repository.observed_release_age_seconds,
        },
    );
    try writeString(writer, @tagName(repository.expiry_policy));
    try writer.writeAll(",\"maximum_release_age_seconds\":");
    if (repository.maximum_release_age_seconds) |value|
        try writer.print("{d}", .{value})
    else
        try writer.writeAll("null");
    try writer.writeAll(",\"missing_valid_until_exception_exercised\":");
    try writer.writeAll(
        if (repository.missing_valid_until_exception_exercised)
            "true"
        else
            "false",
    );
    try writer.writeAll(",\"selected_packages_path\":");
    try writeString(writer, repository.selected_packages_path);
    try writer.writeAll(",\"compression\":");
    try writeString(writer, @tagName(repository.compression));
    try writer.writeByte('}');
}

fn digestPayload(result: Result) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writePayload(result, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

pub fn lessRepository(
    _: void,
    left: RepositoryRefreshEvidence,
    right: RepositoryRefreshEvidence,
) bool {
    return std.mem.order(
        u8,
        &left.source_config_id,
        &right.source_config_id,
    ) == .lt;
}

fn releaseAgeSeconds(now: i64, date: i64) u64 {
    if (now <= date) return 0;
    return @intCast(std.math.sub(i64, now, date) catch std.math.maxInt(i64));
}

fn sha256(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn safeLeaf(value: []const u8) bool {
    if (value.len == 0 or std.mem.eql(u8, value, ".") or
        std.mem.eql(u8, value, ".."))
        return false;
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7f or byte == '/' or byte == '\\')
            return false;
    }
    return true;
}

fn parseDigest(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.InvalidDigest;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, value) catch return error.InvalidDigest;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return error.InvalidDigest;
    }
    return digest;
}

fn parseId(value: []const u8) ![64]u8 {
    if (value.len != 64) return error.InvalidIdentity;
    var result: [64]u8 = undefined;
    for (value, 0..) |byte, index| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return error.InvalidIdentity;
        result[index] = byte;
    }
    return result;
}

fn jsonString(
    object: std.json.ObjectMap,
    name: []const u8,
) ![]const u8 {
    return switch (object.get(name) orelse return error.InvalidRefreshEvidence) {
        .string => |value| value,
        else => error.InvalidRefreshEvidence,
    };
}

fn jsonBool(object: std.json.ObjectMap, name: []const u8) !bool {
    return switch (object.get(name) orelse return error.InvalidRefreshEvidence) {
        .bool => |value| value,
        else => error.InvalidRefreshEvidence,
    };
}

fn jsonI64(object: std.json.ObjectMap, name: []const u8) !i64 {
    return switch (object.get(name) orelse return error.InvalidRefreshEvidence) {
        .integer => |value| value,
        else => error.InvalidRefreshEvidence,
    };
}

fn jsonU64(object: std.json.ObjectMap, name: []const u8) !u64 {
    const value = try jsonI64(object, name);
    if (value < 0) return error.InvalidRefreshEvidence;
    return @intCast(value);
}

fn jsonOptionalI64(
    object: std.json.ObjectMap,
    name: []const u8,
) !?i64 {
    const value = object.get(name) orelse return error.InvalidRefreshEvidence;
    if (value == .null) return null;
    return switch (value) {
        .integer => |number| number,
        else => error.InvalidRefreshEvidence,
    };
}

fn jsonOptionalU64(
    object: std.json.ObjectMap,
    name: []const u8,
) !?u64 {
    const value = try jsonOptionalI64(object, name);
    if (value == null) return null;
    if (value.? < 0) return error.InvalidRefreshEvidence;
    return @intCast(value.?);
}

fn hasJsonWhitespace(source: []const u8) bool {
    var in_string = false;
    var escaped = false;
    for (source) |byte| {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (byte == '\\') {
                escaped = true;
            } else if (byte == '"') {
                in_string = false;
            }
        } else if (byte == '"') {
            in_string = true;
        } else if (byte == ' ' or byte == '\t' or byte == '\r' or byte == '\n') {
            return true;
        }
    }
    return in_string or escaped;
}

fn writeHex(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 0x0f]);
    }
    try writer.writeByte('"');
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

test "transaction_provenance_v3 rejects unbounded missing-expiry evidence" {
    const policy: repository_refresh.ExpiryPolicy = .{
        .allow_missing_valid_until_with_max_age_seconds = repository_refresh.maximum_missing_valid_until_age_seconds + 1,
    };
    try std.testing.expect(!repository_refresh.validExpiryPolicy(policy));
    try std.testing.expectEqual(
        @as(u64, 10),
        releaseAgeSeconds(20, 10),
    );
}

test "transaction_provenance_v3 canonically embeds v2 execution evidence" {
    var execution = try transaction_provenance_v2.create(
        std.testing.allocator,
        .{
            .target_architecture = "amd64",
            .request_sha256 = @splat(1),
            .solver_policy_sha256 = @splat(2),
            .executor_policy_sha256 = @splat(3),
            .plan_sha256 = @splat(4),
            .lock_sha256 = @splat(5),
            .repositories = &.{},
            .packages = &.{},
            .commands = &.{},
            .journal_steps = &.{},
            .final_verification = .{
                .status = .not_run,
                .installed_state_sha256 = null,
                .package_origins_sha256 = null,
                .detail = "failed before verification",
            },
            .outcome = .failed,
            .diagnostic = "fixture",
        },
    );
    defer execution.deinit();
    var result = try create(
        std.testing.allocator,
        null,
        execution.result,
        &.{},
    );
    defer result.deinit();
    const json = try result.result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, schema_id) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        json,
        transaction_provenance_v2.schema_id,
    ) != null);
    var validated = try validateDocument(
        std.testing.allocator,
        json,
        maximum_document_bytes,
    );
    defer validated.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &result.result.digest_sha256,
        &validated.digest_sha256,
    );
}

fn testExecutionWithRepository(
    allocator: std.mem.Allocator,
) !transaction_provenance_v2.OwnedResult {
    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(7);
    const repository: transaction_provenance_v2.RepositoryEvidence = .{
        .source_config_id = repository_id,
        .snapshot_sha256 = snapshot,
        .release_sha256 = @splat(8),
        .signature_sha256 = @splat(9),
        .metadata_sha256 = @splat(10),
        .signer_fingerprints = &.{@splat(11)},
        .signature_verified = true,
    };
    const package: transaction_provenance_v2.PackageEvidence = .{
        .name = "demo",
        .version = "1",
        .architecture = "amd64",
        .origin = .{ .authenticated_repository = .{
            .repository_id = repository_id,
            .repository_snapshot_sha256 = snapshot,
        } },
        .package_sha256 = @splat(12),
        .cas_sha256 = @splat(12),
        .declared_size = 1,
    };
    return transaction_provenance_v2.create(allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .solver_policy_sha256 = @splat(2),
        .executor_policy_sha256 = @splat(3),
        .plan_sha256 = @splat(4),
        .lock_sha256 = @splat(5),
        .repositories = &.{repository},
        .packages = &.{package},
        .commands = &.{},
        .journal_steps = &.{},
        .final_verification = .{
            .status = .not_run,
            .installed_state_sha256 = null,
            .package_origins_sha256 = null,
            .detail = "fixture",
        },
        .outcome = .failed,
    });
}

fn validRefreshEvidence() RepositoryRefreshEvidence {
    return .{
        .source_config_id = @splat('a'),
        .snapshot_sha256 = @splat(7),
        .signed_release_date_unix = 1_000,
        .valid_until_unix = null,
        .verification_time_unix = 1_050,
        .maximum_future_seconds = 300,
        .future_date_accepted = false,
        .observed_release_age_seconds = 50,
        .expiry_policy = .{
            .allow_missing_valid_until_with_max_age_seconds = 100,
        },
        .maximum_release_age_seconds = 100,
        .missing_valid_until_exception_exercised = true,
        .selected_packages_path = "main/binary-amd64/Packages.gz",
        .compression = .gzip,
    };
}

test "transaction_provenance_v3 validates bounded future-date evidence" {
    var evidence = validRefreshEvidence();
    evidence.signed_release_date_unix = 1_100;
    evidence.valid_until_unix = 1_500;
    evidence.verification_time_unix = 1_000;
    evidence.maximum_future_seconds = 100;
    evidence.future_date_accepted = true;
    evidence.observed_release_age_seconds = 0;
    evidence.missing_valid_until_exception_exercised = false;
    try validateRepositoryRefreshEvidence(evidence);

    evidence.signed_release_date_unix = 1_101;
    try std.testing.expectError(
        error.InvalidRefreshEvidence,
        validateRepositoryRefreshEvidence(evidence),
    );

    evidence.signed_release_date_unix = std.math.maxInt(i64);
    evidence.verification_time_unix = std.math.maxInt(i64) - 10;
    evidence.maximum_future_seconds = 300;
    try std.testing.expectError(
        error.InvalidRefreshEvidence,
        validateRepositoryRefreshEvidence(evidence),
    );
}

test "transaction_provenance_v3 rejects invalid freshness relationships" {
    var execution = try testExecutionWithRepository(std.testing.allocator);
    defer execution.deinit();
    var evidence = validRefreshEvidence();

    evidence.verification_time_unix = 1_101;
    evidence.observed_release_age_seconds = 101;
    try std.testing.expectError(
        error.InvalidRefreshEvidence,
        create(std.testing.allocator, null, execution.result, &.{evidence}),
    );

    evidence = validRefreshEvidence();
    evidence.valid_until_unix = 999;
    evidence.missing_valid_until_exception_exercised = false;
    try std.testing.expectError(
        error.InvalidRefreshEvidence,
        create(std.testing.allocator, null, execution.result, &.{evidence}),
    );

    evidence = validRefreshEvidence();
    evidence.expiry_policy = .require_valid_until;
    evidence.maximum_release_age_seconds = null;
    evidence.missing_valid_until_exception_exercised = false;
    try std.testing.expectError(
        error.InvalidRefreshEvidence,
        create(std.testing.allocator, null, execution.result, &.{evidence}),
    );

    evidence = validRefreshEvidence();
    evidence.snapshot_sha256 = @splat(99);
    try std.testing.expectError(
        error.RepositoryEvidenceMismatch,
        create(std.testing.allocator, null, execution.result, &.{evidence}),
    );
}

test "transaction_provenance_v3 validation rejects null bound and is canonical" {
    var execution = try testExecutionWithRepository(std.testing.allocator);
    defer execution.deinit();
    const evidence = validRefreshEvidence();
    var valid = try create(
        std.testing.allocator,
        @splat(0xaa),
        execution.result,
        &.{evidence},
    );
    defer valid.deinit();
    const valid_json = try valid.result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(valid_json);
    var validated = try validateDocument(
        std.testing.allocator,
        valid_json,
        maximum_document_bytes,
    );
    defer validated.deinit();

    var invalid_result = valid.result;
    var invalid_evidence = [_]RepositoryRefreshEvidence{evidence};
    invalid_evidence[0].maximum_release_age_seconds = null;
    invalid_result.repository_refresh = &invalid_evidence;
    invalid_result.digest_sha256 = digestPayload(invalid_result);
    const invalid_json = try invalid_result.canonicalJson(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(invalid_json);
    try std.testing.expectError(
        error.InvalidRefreshEvidence,
        validateDocument(
            std.testing.allocator,
            invalid_json,
            maximum_document_bytes,
        ),
    );

    invalid_evidence[0] = evidence;
    invalid_evidence[0].snapshot_sha256 = @splat(42);
    invalid_result.repository_refresh = &invalid_evidence;
    invalid_result.digest_sha256 = digestPayload(invalid_result);
    const mismatch_json = try invalid_result.canonicalJson(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(mismatch_json);
    try std.testing.expectError(
        error.RepositoryEvidenceMismatch,
        validateDocument(
            std.testing.allocator,
            mismatch_json,
            maximum_document_bytes,
        ),
    );
}

test "transaction_provenance_v3 cross-checks the maximum repository set linearly" {
    const repositories = try std.testing.allocator.alloc(
        transaction_provenance_v2.RepositoryEvidence,
        maximum_repositories,
    );
    defer std.testing.allocator.free(repositories);
    const refresh = try std.testing.allocator.alloc(
        RepositoryRefreshEvidence,
        maximum_repositories,
    );
    defer std.testing.allocator.free(refresh);
    for (repositories, refresh, 0..) |*repository, *evidence, index| {
        var id: [64]u8 = @splat('0');
        _ = try std.fmt.bufPrint(
            id[48..],
            "{x:0>16}",
            .{index},
        );
        var snapshot: [32]u8 = @splat(0);
        std.mem.writeInt(u64, snapshot[24..32], index, .big);
        repository.* = .{
            .source_config_id = id,
            .snapshot_sha256 = snapshot,
            .release_sha256 = @splat(1),
            .signature_sha256 = null,
            .metadata_sha256 = @splat(2),
            .signer_fingerprints = &.{},
            .signature_verified = true,
        };
        evidence.* = validRefreshEvidence();
        evidence.source_config_id = id;
        evidence.snapshot_sha256 = snapshot;
    }
    try validateRepositoryCorrespondence(repositories, refresh);
    refresh[maximum_repositories - 1].snapshot_sha256 = @splat(0xff);
    try std.testing.expectError(
        error.RepositoryEvidenceMismatch,
        validateRepositoryCorrespondence(repositories, refresh),
    );
}
