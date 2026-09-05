const std = @import("std");
const exact_lock = @import("exact_lock.zig");
const transaction_provenance = @import("transaction_provenance.zig");

pub const schema_id = "io.github.cataggar.debz.transaction-result-summary.v1";
pub const api_version: u32 = 1;

pub const Summary = struct {
    target_architecture: []const u8,
    request_sha256: [32]u8,
    solver_policy_sha256: [32]u8,
    lock_sha256: [32]u8,
    transaction_digest_sha256: [32]u8,
    package_count: usize,

    pub fn canonicalJson(self: Summary, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        const writer = &output.writer;
        try writer.writeAll("{\"schema\":");
        try writeString(writer, schema_id);
        try writer.print(",\"api_version\":{},\"transaction_schema\":", .{api_version});
        try writeString(writer, transaction_provenance.schema_id);
        try writer.print(",\"transaction_schema_version\":{},\"target_architecture\":", .{
            transaction_provenance.schema_version,
        });
        try writeString(writer, self.target_architecture);
        try writer.writeAll(",\"request_sha256\":");
        try writeHex(writer, &self.request_sha256);
        try writer.writeAll(",\"solver_policy_sha256\":");
        try writeHex(writer, &self.solver_policy_sha256);
        try writer.writeAll(",\"lock_sha256\":");
        try writeHex(writer, &self.lock_sha256);
        try writer.writeAll(",\"transaction_digest_sha256\":");
        try writeHex(writer, &self.transaction_digest_sha256);
        try writer.print(",\"package_count\":{},\"outcome\":\"succeeded\",\"final_verification_status\":\"exact_match\",\"lock_evidence\":\"exact_match\"}}\n", .{
            self.package_count,
        });
        return output.toOwnedSlice();
    }
};

pub const Error = error{
    InvalidTransactionResult,
    TransactionNotSuccessful,
    ArchitectureMismatch,
    LockEvidenceMismatch,
};

pub fn verify(
    allocator: std.mem.Allocator,
    source: []const u8,
    lock: exact_lock.Lock,
    expected_architecture: []const u8,
) !Summary {
    var validated = try transaction_provenance.validateDocument(
        allocator,
        source,
        transaction_provenance.maximum_document_bytes,
    );
    defer validated.deinit();
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, validated.bytes, .{
        .allocate = .alloc_always,
        .parse_numbers = true,
        .duplicate_field_behavior = .@"error",
    });
    defer parsed.deinit();
    const document = try asObject(parsed.value);
    try exactKeys(document, &.{
        "schema",
        "version",
        "target_architecture",
        "request_sha256",
        "solver_policy_sha256",
        "executor_policy_sha256",
        "plan_sha256",
        "lock_sha256",
        "repositories",
        "packages",
        "commands",
        "journal_steps",
        "recovery_steps",
        "final_verification",
        "outcome",
        "diagnostic",
        "digest_sha256",
    });
    try expectString(document, "schema", transaction_provenance.schema_id);
    try expectInteger(document, "version", transaction_provenance.schema_version);
    try expectString(document, "target_architecture", expected_architecture);
    if (!std.mem.eql(u8, lock.target_architecture, expected_architecture))
        return error.ArchitectureMismatch;
    try expectHex(document, "request_sha256", &lock.request_sha256);
    try expectHex(document, "solver_policy_sha256", &lock.policy_sha256);
    try expectHex(document, "lock_sha256", &lock.digest_sha256);
    try requireHex(document, "executor_policy_sha256", 32);
    try requireHex(document, "plan_sha256", 32);
    if (!std.mem.eql(u8, try boundedString(document, "outcome", 32), "succeeded"))
        return error.TransactionNotSuccessful;
    try expectString(document, "diagnostic", "");

    try verifyRepositories(try fieldArray(document, "repositories"), lock.repositories);
    const packages = try fieldArray(document, "packages");
    try verifyPackages(packages, lock.packages);
    try verifyCommands(try fieldArray(document, "commands"));
    try verifyJournal(try fieldArray(document, "journal_steps"));
    try verifyJournal(try fieldArray(document, "recovery_steps"));

    const final = try fieldObject(document, "final_verification");
    try exactKeys(final, &.{
        "status",
        "installed_state_sha256",
        "package_origins_sha256",
        "detail",
    });
    if (!std.mem.eql(u8, try boundedString(final, "status", 32), "exact_match"))
        return error.TransactionNotSuccessful;
    try requireHex(final, "installed_state_sha256", 32);
    try expectHex(final, "package_origins_sha256", &lock.digest_sha256);
    _ = try boundedString(final, "detail", 4096);

    try expectHex(document, "digest_sha256", &validated.digest_sha256);
    return .{
        .target_architecture = expected_architecture,
        .request_sha256 = lock.request_sha256,
        .solver_policy_sha256 = lock.policy_sha256,
        .lock_sha256 = lock.digest_sha256,
        .transaction_digest_sha256 = validated.digest_sha256,
        .package_count = packages.items.len,
    };
}

fn verifyRepositories(
    values: std.json.Array,
    expected: []const exact_lock.Repository,
) !void {
    if (values.items.len != expected.len) return error.LockEvidenceMismatch;
    for (values.items, expected) |value, repository| {
        const object = try asObject(value);
        try exactKeys(object, &.{
            "source_config_id",
            "snapshot_sha256",
            "release_sha256",
            "signature_sha256",
            "metadata_sha256",
            "signer_fingerprints",
            "signature_verified",
        });
        try expectString(object, "source_config_id", &repository.id);
        try expectHex(object, "snapshot_sha256", &repository.snapshot_sha256);
        try expectHex(object, "release_sha256", &repository.release_sha256);
        try optionalHex(object, "signature_sha256", 32);
        try expectHex(object, "metadata_sha256", &repository.index_sha256);
        const signers = try fieldArray(object, "signer_fingerprints");
        if (signers.items.len != repository.signer_fingerprints.len)
            return error.LockEvidenceMismatch;
        for (signers.items, repository.signer_fingerprints) |signer, fingerprint| {
            if (signer != .string or !equalHex(signer.string, &fingerprint))
                return error.LockEvidenceMismatch;
        }
        const verified = object.get("signature_verified") orelse
            return error.InvalidTransactionResult;
        if (verified != .bool or !verified.bool)
            return error.LockEvidenceMismatch;
    }
}

fn verifyPackages(
    values: std.json.Array,
    expected: []const exact_lock.Package,
) !void {
    if (values.items.len != expected.len or values.items.len == 0)
        return error.LockEvidenceMismatch;
    for (values.items, expected) |value, package| {
        const object = try asObject(value);
        try exactKeys(object, &.{
            "name",
            "version",
            "architecture",
            "repository_id",
            "repository_snapshot_sha256",
            "package_sha256",
            "cas_sha256",
            "declared_size",
        });
        try expectString(object, "name", package.name);
        try expectString(object, "version", package.version);
        try expectString(object, "architecture", package.architecture);
        try expectString(object, "repository_id", &package.repository_id);
        try expectHex(
            object,
            "repository_snapshot_sha256",
            &package.repository_snapshot_sha256,
        );
        try expectHex(object, "package_sha256", &package.sha256);
        try expectHex(object, "cas_sha256", &package.sha256);
        const declared_size = try fieldInteger(object, "declared_size");
        if (declared_size < 0 or @as(u64, @intCast(declared_size)) != package.declared_size)
            return error.LockEvidenceMismatch;
    }
}

fn verifyCommands(values: std.json.Array) !void {
    if (values.items.len > 1_000_000) return error.InvalidTransactionResult;
    for (values.items) |value| {
        const object = try asObject(value);
        try exactKeys(object, &.{
            "phase",
            "package",
            "argv",
            "environment",
            "command_sha256",
            "artifact_sha256",
        });
        _ = try boundedString(object, "phase", 128);
        try optionalBoundedString(object, "package", 255);
        const argv = try fieldArray(object, "argv");
        if (argv.items.len == 0 or argv.items.len > 4096)
            return error.InvalidTransactionResult;
        for (argv.items) |argument| try validateStringValue(argument, 16 * 1024);
        const environment = try fieldArray(object, "environment");
        if (environment.items.len > 1024) return error.InvalidTransactionResult;
        for (environment.items) |entry| {
            const item = try asObject(entry);
            try exactKeys(item, &.{ "key", "value" });
            _ = try boundedString(item, "key", 256);
            _ = try boundedString(item, "value", 16 * 1024);
        }
        try requireHex(object, "command_sha256", 32);
        try optionalHex(object, "artifact_sha256", 32);
    }
}

fn verifyJournal(values: std.json.Array) !void {
    if (values.items.len > 1_000_000) return error.InvalidTransactionResult;
    for (values.items) |value| {
        const object = try asObject(value);
        try exactKeys(object, &.{
            "sequence",
            "boundary",
            "state",
            "command_index",
            "recovered",
        });
        if (try fieldInteger(object, "sequence") < 0 or
            try fieldInteger(object, "command_index") < 0)
            return error.InvalidTransactionResult;
        _ = try boundedString(object, "boundary", 256);
        _ = try boundedString(object, "state", 256);
        const recovered = object.get("recovered") orelse
            return error.InvalidTransactionResult;
        if (recovered != .bool) return error.InvalidTransactionResult;
    }
}

fn asObject(value: std.json.Value) !std.json.ObjectMap {
    return switch (value) {
        .object => |object| object,
        else => error.InvalidTransactionResult,
    };
}

fn exactKeys(object: std.json.ObjectMap, keys: []const []const u8) !void {
    if (object.count() != keys.len) return error.InvalidTransactionResult;
    var iterator = object.iterator();
    for (keys) |key| {
        const entry = iterator.next() orelse return error.InvalidTransactionResult;
        if (!std.mem.eql(u8, entry.key_ptr.*, key))
            return error.InvalidTransactionResult;
    }
    if (iterator.next() != null) return error.InvalidTransactionResult;
}

fn fieldObject(object: std.json.ObjectMap, name: []const u8) !std.json.ObjectMap {
    return asObject(object.get(name) orelse return error.InvalidTransactionResult);
}

fn fieldArray(object: std.json.ObjectMap, name: []const u8) !std.json.Array {
    const value = object.get(name) orelse return error.InvalidTransactionResult;
    return switch (value) {
        .array => |array| array,
        else => error.InvalidTransactionResult,
    };
}

fn fieldInteger(object: std.json.ObjectMap, name: []const u8) !i64 {
    const value = object.get(name) orelse return error.InvalidTransactionResult;
    return switch (value) {
        .integer => |integer| integer,
        else => error.InvalidTransactionResult,
    };
}

fn expectInteger(object: std.json.ObjectMap, name: []const u8, expected: anytype) !void {
    if (try fieldInteger(object, name) != @as(i64, @intCast(expected)))
        return error.InvalidTransactionResult;
}

fn boundedString(
    object: std.json.ObjectMap,
    name: []const u8,
    maximum: usize,
) ![]const u8 {
    const value = object.get(name) orelse return error.InvalidTransactionResult;
    if (value != .string) return error.InvalidTransactionResult;
    try validateString(value.string, maximum);
    return value.string;
}

fn optionalBoundedString(
    object: std.json.ObjectMap,
    name: []const u8,
    maximum: usize,
) !void {
    const value = object.get(name) orelse return error.InvalidTransactionResult;
    switch (value) {
        .null => {},
        .string => |string| try validateString(string, maximum),
        else => return error.InvalidTransactionResult,
    }
}

fn validateStringValue(value: std.json.Value, maximum: usize) !void {
    if (value != .string) return error.InvalidTransactionResult;
    try validateString(value.string, maximum);
}

fn validateString(value: []const u8, maximum: usize) !void {
    if (value.len > maximum or
        std.mem.indexOfAny(u8, value, "\x00\r\n") != null)
        return error.InvalidTransactionResult;
}

fn expectString(
    object: std.json.ObjectMap,
    name: []const u8,
    expected: []const u8,
) !void {
    const value = try boundedString(object, name, 16 * 1024);
    if (!std.mem.eql(u8, value, expected)) return error.LockEvidenceMismatch;
}

fn requireHex(object: std.json.ObjectMap, name: []const u8, bytes: usize) !void {
    const value = object.get(name) orelse return error.InvalidTransactionResult;
    if (value != .string or !validHex(value.string, bytes))
        return error.InvalidTransactionResult;
}

fn optionalHex(object: std.json.ObjectMap, name: []const u8, bytes: usize) !void {
    const value = object.get(name) orelse return error.InvalidTransactionResult;
    switch (value) {
        .null => {},
        .string => |string| if (!validHex(string, bytes))
            return error.InvalidTransactionResult,
        else => return error.InvalidTransactionResult,
    }
}

fn expectHex(
    object: std.json.ObjectMap,
    name: []const u8,
    expected: []const u8,
) !void {
    const value = object.get(name) orelse return error.InvalidTransactionResult;
    if (value != .string or !equalHex(value.string, expected))
        return error.LockEvidenceMismatch;
}

fn equalHex(value: []const u8, expected: []const u8) bool {
    if (!validHex(value, expected.len)) return false;
    for (expected, 0..) |byte, index| {
        if (value[index * 2] != hexCharacter(byte >> 4) or
            value[index * 2 + 1] != hexCharacter(byte & 0x0f))
            return false;
    }
    return true;
}

fn validHex(value: []const u8, bytes: usize) bool {
    if (value.len != bytes * 2) return false;
    for (value) |character| if (!std.ascii.isDigit(character) and
        !(character >= 'a' and character <= 'f'))
        return false;
    return true;
}

fn hexCharacter(value: u8) u8 {
    return "0123456789abcdef"[value];
}

fn writeHex(writer: *std.Io.Writer, bytes: []const u8) !void {
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(hexCharacter(byte >> 4));
        try writer.writeByte(hexCharacter(byte & 0x0f));
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

test "transaction result summary binds successful canonical evidence to the exact lock" {
    const repository_id: [64]u8 = @splat('a');
    const repositories = [_]exact_lock.Repository{.{
        .id = repository_id,
        .snapshot_sha256 = @splat(1),
        .release_sha256 = @splat(2),
        .index_sha256 = @splat(3),
        .signer_fingerprints = &.{@splat(4)},
    }};
    const packages = [_]exact_lock.Package{.{
        .name = "demo",
        .version = "1.0-1",
        .architecture = "amd64",
        .repository_id = repository_id,
        .repository_snapshot_sha256 = @splat(1),
        .sha256 = @splat(5),
        .declared_size = 99,
        .retention = .requested,
        .dpkg_selection_hold = false,
    }};
    var lock = try exact_lock.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(6),
        .policy_sha256 = @splat(7),
        .repositories = &repositories,
        .packages = &packages,
        .authenticated_metadata = true,
    });
    defer lock.deinit();

    const evidence_repositories = [_]transaction_provenance.RepositoryEvidence{.{
        .source_config_id = repository_id,
        .snapshot_sha256 = @splat(1),
        .release_sha256 = @splat(2),
        .signature_sha256 = @splat(8),
        .metadata_sha256 = @splat(3),
        .signer_fingerprints = &.{@splat(4)},
        .signature_verified = true,
    }};
    const evidence_packages = [_]transaction_provenance.PackageEvidence{.{
        .name = "demo",
        .version = "1.0-1",
        .architecture = "amd64",
        .repository_id = repository_id,
        .repository_snapshot_sha256 = @splat(1),
        .package_sha256 = @splat(5),
        .cas_sha256 = @splat(5),
        .declared_size = 99,
    }};
    const command = [_]transaction_provenance.CommandEvidence{.{
        .phase = "unpack",
        .package = "demo",
        .argv = &.{ "dpkg", "--unpack", "/cache/demo.deb" },
        .environment = &.{},
        .command_sha256 = @splat(9),
        .artifact_sha256 = @splat(5),
    }};
    var result = try transaction_provenance.create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = lock.lock.request_sha256,
        .solver_policy_sha256 = lock.lock.policy_sha256,
        .executor_policy_sha256 = @splat(10),
        .plan_sha256 = @splat(11),
        .lock_sha256 = lock.lock.digest_sha256,
        .repositories = &evidence_repositories,
        .packages = &evidence_packages,
        .commands = &command,
        .journal_steps = &.{},
        .final_verification = .{
            .status = .exact_match,
            .installed_state_sha256 = @splat(12),
            .package_origins_sha256 = lock.lock.digest_sha256,
            .detail = "verified",
        },
        .outcome = .succeeded,
    });
    defer result.deinit();
    const json = try result.result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    const summary = try verify(std.testing.allocator, json, lock.lock, "amd64");
    try std.testing.expectEqual(@as(usize, 1), summary.package_count);
    try std.testing.expectEqualSlices(u8, &lock.lock.digest_sha256, &summary.lock_sha256);
    try std.testing.expectError(
        error.ArchitectureMismatch,
        verify(std.testing.allocator, json, lock.lock, "arm64"),
    );
    var wrong_policy = lock.lock;
    wrong_policy.policy_sha256 = @splat(0xff);
    try std.testing.expectError(
        error.LockEvidenceMismatch,
        verify(std.testing.allocator, json, wrong_policy, "amd64"),
    );
    var wrong_package = lock.lock;
    var changed_packages = packages;
    changed_packages[0].sha256 = @splat(0xee);
    wrong_package.packages = &changed_packages;
    try std.testing.expectError(
        error.LockEvidenceMismatch,
        verify(std.testing.allocator, json, wrong_package, "amd64"),
    );
}
