//! Compatibility policy for the legacy dpkg execution boundary.
//!
//! Classification is exact: schema, version, and (where the document carries
//! one) backend are evaluated together. A legacy identity is never promoted to
//! native authority. Native-only releases may retain bounded, read-only
//! verification of completed historical documents, but active legacy evidence
//! always requires a legacy-capable release.
const std = @import("std");

pub const policy_schema_id =
    "https://debz.dev/schema/legacy-compatibility-policy-v1";
pub const policy_schema_version: u32 = 1;
pub const evidence_schema_id =
    "https://debz.dev/schema/legacy-capability-evidence-v1";
pub const evidence_schema_version: u32 = 1;
pub const maximum_evidence_bytes: usize = 4096;
pub const legacy_release_range = ">=0.3.0,<0.4.0";
pub const legacy_capability = "legacy-dpkg-execution-deprecated-v1";
pub const native_capability = "native-transaction-execution-v1";
pub const recovery_guidance =
    "Recover this operation with debz >=0.3.0,<0.4.0 before installing a native-only release.";
pub const deprecation_message =
    "legacy_dpkg execution is deprecated; generate and validate native v2 inputs before the native-only cutover.";

pub const Backend = enum {
    legacy_dpkg,
    native,
};

pub const RuntimeMode = enum {
    legacy_capable,
    native_only,
};

pub const Lifecycle = enum {
    new_execution,
    active_recovery,
    completed_historical_verification,
};

pub const Family = enum {
    system_profile,
    exact_lock,
    transaction_result,
    transaction_journal,
    root_operation,
    root_operation_completion,
    apt_system_operation,
    package_cache_fingerprint,
    package_cache_result,
    package_family_capability,
    native_provenance,
};

pub const Identity = struct {
    schema: []const u8,
    version: u32,
    backend: ?Backend = null,
};

pub const Classification = struct {
    family: Family,
    backend: Backend,
    historical_read_only_after_cutover: bool,
};

pub const Disposition = enum {
    legacy_execution_deprecated,
    legacy_recovery,
    native_execution,
    native_recovery,
    historical_read_only,
};

pub const PolicyError = error{
    UnsupportedIdentity,
    BackendRequired,
    BackendMismatch,
    LegacyCapabilityRequired,
};

pub fn classify(identity: Identity) PolicyError!Classification {
    if (matches(identity, "https://debz.dev/schema/system-profile-v1", 1)) {
        try requireBackend(identity.backend, .legacy_dpkg);
        return legacy(.system_profile);
    }
    if (matches(identity, "https://debz.dev/schema/system-profile-v2", 2)) {
        const backend = identity.backend orelse return error.BackendRequired;
        return .{
            .family = .system_profile,
            .backend = backend,
            .historical_read_only_after_cutover = true,
        };
    }
    if (matches(identity, "https://debz.dev/schema/exact-closure-lock-v1", 1)) {
        try requireBackend(identity.backend, .legacy_dpkg);
        return legacy(.exact_lock);
    }
    if (matches(identity, "https://debz.dev/schema/exact-closure-lock-v2", 2)) {
        try requireBackend(identity.backend, .native);
        return native(.exact_lock);
    }
    if (matches(identity, "https://debz.dev/schema/transaction-result-v1", 1) or
        matches(identity, "https://debz.dev/schema/transaction-result-v2", 2))
    {
        try requireBackend(identity.backend, .legacy_dpkg);
        return legacy(.transaction_result);
    }
    if (std.mem.eql(u8, identity.schema, "debz:transaction-journal") and
        identity.version >= 1 and identity.version <= 3)
    {
        try requireBackend(identity.backend, .legacy_dpkg);
        return legacy(.transaction_journal);
    }
    if (matches(identity, "https://debz.dev/schema/root-operation-record-v1", 1)) {
        return explicit(.root_operation, identity.backend);
    }
    if (matches(identity, "https://debz.dev/schema/root-operation-completion-v1", 1)) {
        return explicit(.root_operation_completion, identity.backend);
    }
    if (matches(identity, "https://debz.dev/schema/apt-system-operation-state-v1", 1)) {
        return explicit(.apt_system_operation, identity.backend);
    }
    if (matches(identity, "io.github.cataggar.debz.package-cache-fingerprint.v1", 1)) {
        try requireBackend(identity.backend, .legacy_dpkg);
        return legacy(.package_cache_fingerprint);
    }
    if (matches(identity, "io.github.cataggar.debz.package-cache-fingerprint.v2", 2)) {
        try requireBackend(identity.backend, .native);
        return native(.package_cache_fingerprint);
    }
    if (matches(identity, "io.github.cataggar.debz.package-cache-result.v1", 1)) {
        try requireBackend(identity.backend, .legacy_dpkg);
        return legacy(.package_cache_result);
    }
    if (matches(identity, "io.github.cataggar.debz.package-cache-result.v2", 2)) {
        try requireBackend(identity.backend, .native);
        return native(.package_cache_result);
    }
    if (matches(identity, "io.github.cataggar.debz.package-family.capabilities.v1", 1)) {
        try requireBackend(identity.backend, .legacy_dpkg);
        return legacy(.package_family_capability);
    }
    if (matches(identity, "io.github.cataggar.debz.package-family.capabilities.v2", 2)) {
        try requireBackend(identity.backend, .native);
        return native(.package_family_capability);
    }
    if (matches(identity, "https://debz.dev/schema/native-transaction-provenance-v1", 1)) {
        try requireBackend(identity.backend, .native);
        return native(.native_provenance);
    }
    return error.UnsupportedIdentity;
}

pub fn decide(
    runtime: RuntimeMode,
    requested_backend: Backend,
    lifecycle: Lifecycle,
    identity: Identity,
) PolicyError!Disposition {
    const classified = try classify(identity);
    if (classified.backend != requested_backend) return error.BackendMismatch;
    if (lifecycle == .completed_historical_verification) {
        if (!classified.historical_read_only_after_cutover)
            return error.UnsupportedIdentity;
        return .historical_read_only;
    }
    if (classified.backend == .legacy_dpkg) {
        if (runtime == .native_only) return error.LegacyCapabilityRequired;
        return if (lifecycle == .active_recovery)
            .legacy_recovery
        else
            .legacy_execution_deprecated;
    }
    return if (lifecycle == .active_recovery)
        .native_recovery
    else
        .native_execution;
}

fn matches(identity: Identity, schema: []const u8, version: u32) bool {
    return identity.version == version and std.mem.eql(u8, identity.schema, schema);
}

fn requireBackend(actual: ?Backend, expected: Backend) PolicyError!void {
    if (actual) |backend| {
        if (backend != expected) return error.BackendMismatch;
    }
}

fn explicit(family: Family, backend: ?Backend) PolicyError!Classification {
    return .{
        .family = family,
        .backend = backend orelse return error.BackendRequired,
        .historical_read_only_after_cutover = true,
    };
}

fn legacy(family: Family) Classification {
    return .{
        .family = family,
        .backend = .legacy_dpkg,
        .historical_read_only_after_cutover = true,
    };
}

fn native(family: Family) Classification {
    return .{
        .family = family,
        .backend = .native,
        .historical_read_only_after_cutover = true,
    };
}

pub const Evidence = struct {
    artifact_schema: []const u8,
    artifact_version: u32,
    artifact_sha256: [32]u8,
    digest_sha256: [32]u8,

    pub fn canonicalJson(
        self: Evidence,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        _ = try classify(.{
            .schema = self.artifact_schema,
            .version = self.artifact_version,
            .backend = .legacy_dpkg,
        });
        if (!std.mem.eql(u8, &self.digest_sha256, &evidenceDigest(self)))
            return error.DigestMismatch;
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeEvidence(self, &output.writer);
        const bytes = try output.toOwnedSlice();
        if (bytes.len > maximum_evidence_bytes) {
            allocator.free(bytes);
            return error.DocumentTooLarge;
        }
        return bytes;
    }
};

pub fn createEvidence(
    artifact: Identity,
    exact_artifact_bytes: []const u8,
) !Evidence {
    const classified = try classify(artifact);
    if (classified.backend != .legacy_dpkg) return error.BackendMismatch;
    var result: Evidence = .{
        .artifact_schema = canonicalSchema(artifact),
        .artifact_version = artifact.version,
        .artifact_sha256 = sha256(exact_artifact_bytes),
        .digest_sha256 = undefined,
    };
    result.digest_sha256 = evidenceDigest(result);
    return result;
}

fn canonicalSchema(identity: Identity) []const u8 {
    const known = [_][]const u8{
        "https://debz.dev/schema/system-profile-v1",
        "https://debz.dev/schema/system-profile-v2",
        "https://debz.dev/schema/exact-closure-lock-v1",
        "https://debz.dev/schema/exact-closure-lock-v2",
        "https://debz.dev/schema/transaction-result-v1",
        "https://debz.dev/schema/transaction-result-v2",
        "debz:transaction-journal",
        "https://debz.dev/schema/root-operation-record-v1",
        "https://debz.dev/schema/root-operation-completion-v1",
        "https://debz.dev/schema/apt-system-operation-state-v1",
        "io.github.cataggar.debz.package-cache-fingerprint.v1",
        "io.github.cataggar.debz.package-cache-fingerprint.v2",
        "io.github.cataggar.debz.package-cache-result.v1",
        "io.github.cataggar.debz.package-cache-result.v2",
        "io.github.cataggar.debz.package-family.capabilities.v1",
        "io.github.cataggar.debz.package-family.capabilities.v2",
        "https://debz.dev/schema/native-transaction-provenance-v1",
    };
    for (known) |schema|
        if (std.mem.eql(u8, identity.schema, schema)) return schema;
    unreachable;
}

const WireEvidence = struct {
    schema: []const u8,
    version: u32,
    artifact_schema: []const u8,
    artifact_version: u32,
    artifact_sha256: []const u8,
    backend: Backend,
    execution: []const u8,
    active_recovery: []const u8,
    historical_verification: []const u8,
    native_reinterpretation: bool,
    legacy_release_range: []const u8,
    guidance: []const u8,
    digest_sha256: []const u8,
};

pub fn decodeEvidence(
    allocator: std.mem.Allocator,
    source: []const u8,
) !Evidence {
    if (source.len > maximum_evidence_bytes) return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(WireEvidence, allocator, source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
        .duplicate_field_behavior = .@"error",
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidDocument,
    };
    defer parsed.deinit();
    const wire = parsed.value;
    if (!std.mem.eql(u8, wire.schema, evidence_schema_id) or
        wire.version != evidence_schema_version or
        wire.backend != .legacy_dpkg or
        !std.mem.eql(u8, wire.execution, "deprecated_but_available") or
        !std.mem.eql(u8, wire.active_recovery, "requires_legacy_capable_release") or
        !std.mem.eql(u8, wire.historical_verification, "read_only_exact_bytes") or
        wire.native_reinterpretation or
        !std.mem.eql(u8, wire.legacy_release_range, legacy_release_range) or
        !std.mem.eql(u8, wire.guidance, recovery_guidance))
        return error.InvalidDocument;
    const classified = try classify(.{
        .schema = wire.artifact_schema,
        .version = wire.artifact_version,
        .backend = .legacy_dpkg,
    });
    if (classified.backend != .legacy_dpkg) return error.BackendMismatch;
    const result: Evidence = .{
        .artifact_schema = canonicalSchema(.{
            .schema = wire.artifact_schema,
            .version = wire.artifact_version,
        }),
        .artifact_version = wire.artifact_version,
        .artifact_sha256 = try parseHex32(wire.artifact_sha256),
        .digest_sha256 = try parseHex32(wire.digest_sha256),
    };
    if (!std.mem.eql(u8, &result.digest_sha256, &evidenceDigest(result)))
        return error.DigestMismatch;
    const canonical = try result.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return result;
}

pub const Store = struct {
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,

    pub fn init(io: std.Io, dir: std.Io.Dir, name: []const u8) !Store {
        if (!safeLeaf(name)) return error.AmbiguousPath;
        return .{ .io = io, .dir = dir, .name = name };
    }

    pub fn writeAtomic(
        self: Store,
        allocator: std.mem.Allocator,
        evidence: Evidence,
    ) !void {
        const bytes = try evidence.canonicalJson(allocator);
        defer allocator.free(bytes);
        const stage = try std.fmt.allocPrint(allocator, ".{s}.new", .{self.name});
        defer allocator.free(stage);
        if (!safeLeaf(stage)) return error.AmbiguousPath;
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

fn evidenceDigest(evidence: Evidence) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writeEvidencePayload(evidence, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn writeEvidence(evidence: Evidence, writer: *std.Io.Writer) !void {
    try writeEvidencePayload(evidence, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHex(writer, &evidence.digest_sha256);
    try writer.writeByte('}');
}

fn writeEvidencePayload(evidence: Evidence, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeString(writer, evidence_schema_id);
    try writer.print(",\"version\":{},\"artifact_schema\":", .{evidence_schema_version});
    try writeString(writer, evidence.artifact_schema);
    try writer.print(",\"artifact_version\":{},\"artifact_sha256\":", .{evidence.artifact_version});
    try writeHex(writer, &evidence.artifact_sha256);
    try writer.writeAll(",\"backend\":\"legacy_dpkg\",\"execution\":\"deprecated_but_available\"");
    try writer.writeAll(",\"active_recovery\":\"requires_legacy_capable_release\"");
    try writer.writeAll(",\"historical_verification\":\"read_only_exact_bytes\"");
    try writer.writeAll(",\"native_reinterpretation\":false,\"legacy_release_range\":");
    try writeString(writer, legacy_release_range);
    try writer.writeAll(",\"guidance\":");
    try writeString(writer, recovery_guidance);
    try writer.writeByte('}');
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

fn parseHex32(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.InvalidDigest;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, text) catch return error.InvalidDigest;
    return result;
}

fn writeHex(writer: *std.Io.Writer, bytes: *const [32]u8) !void {
    const encoded = std.fmt.bytesToHex(bytes.*, .lower);
    try writeString(writer, &encoded);
}

fn writeString(writer: *std.Io.Writer, value: []const u8) !void {
    try std.json.Stringify.encodeJsonString(value, .{}, writer);
}

fn safeLeaf(name: []const u8) bool {
    return name.len != 0 and name.len <= 255 and
        !std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..") and
        std.mem.indexOfAny(u8, name, "/\\\x00") == null;
}

test "legacy_compat.test.exact identities never cross backend boundaries" {
    const cases = [_]struct {
        identity: Identity,
        family: Family,
        backend: Backend,
    }{
        .{
            .identity = .{ .schema = "https://debz.dev/schema/system-profile-v1", .version = 1 },
            .family = .system_profile,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/system-profile-v2", .version = 2, .backend = .legacy_dpkg },
            .family = .system_profile,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/system-profile-v2", .version = 2, .backend = .native },
            .family = .system_profile,
            .backend = .native,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/exact-closure-lock-v1", .version = 1 },
            .family = .exact_lock,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/exact-closure-lock-v2", .version = 2 },
            .family = .exact_lock,
            .backend = .native,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/transaction-result-v1", .version = 1 },
            .family = .transaction_result,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/transaction-result-v2", .version = 2 },
            .family = .transaction_result,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "debz:transaction-journal", .version = 1 },
            .family = .transaction_journal,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "debz:transaction-journal", .version = 2 },
            .family = .transaction_journal,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "debz:transaction-journal", .version = 3 },
            .family = .transaction_journal,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/root-operation-record-v1", .version = 1, .backend = .legacy_dpkg },
            .family = .root_operation,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/root-operation-record-v1", .version = 1, .backend = .native },
            .family = .root_operation,
            .backend = .native,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/root-operation-completion-v1", .version = 1, .backend = .legacy_dpkg },
            .family = .root_operation_completion,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/root-operation-completion-v1", .version = 1, .backend = .native },
            .family = .root_operation_completion,
            .backend = .native,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/apt-system-operation-state-v1", .version = 1, .backend = .legacy_dpkg },
            .family = .apt_system_operation,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/apt-system-operation-state-v1", .version = 1, .backend = .native },
            .family = .apt_system_operation,
            .backend = .native,
        },
        .{
            .identity = .{ .schema = "io.github.cataggar.debz.package-cache-fingerprint.v1", .version = 1 },
            .family = .package_cache_fingerprint,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "io.github.cataggar.debz.package-cache-fingerprint.v2", .version = 2 },
            .family = .package_cache_fingerprint,
            .backend = .native,
        },
        .{
            .identity = .{ .schema = "io.github.cataggar.debz.package-cache-result.v1", .version = 1 },
            .family = .package_cache_result,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "io.github.cataggar.debz.package-cache-result.v2", .version = 2 },
            .family = .package_cache_result,
            .backend = .native,
        },
        .{
            .identity = .{ .schema = "io.github.cataggar.debz.package-family.capabilities.v1", .version = 1 },
            .family = .package_family_capability,
            .backend = .legacy_dpkg,
        },
        .{
            .identity = .{ .schema = "io.github.cataggar.debz.package-family.capabilities.v2", .version = 2 },
            .family = .package_family_capability,
            .backend = .native,
        },
        .{
            .identity = .{ .schema = "https://debz.dev/schema/native-transaction-provenance-v1", .version = 1 },
            .family = .native_provenance,
            .backend = .native,
        },
    };
    for (cases) |case| {
        const classified = try classify(case.identity);
        try std.testing.expectEqual(case.family, classified.family);
        try std.testing.expectEqual(case.backend, classified.backend);
        const other: Backend = if (case.backend == .native) .legacy_dpkg else .native;
        try std.testing.expectError(
            error.BackendMismatch,
            decide(.legacy_capable, other, .new_execution, case.identity),
        );
        if (case.backend == .legacy_dpkg) {
            try std.testing.expectEqual(
                Disposition.legacy_execution_deprecated,
                try decide(
                    .legacy_capable,
                    case.backend,
                    .new_execution,
                    case.identity,
                ),
            );
            try std.testing.expectError(
                error.LegacyCapabilityRequired,
                decide(
                    .native_only,
                    case.backend,
                    .new_execution,
                    case.identity,
                ),
            );
        } else {
            try std.testing.expectEqual(
                Disposition.native_execution,
                try decide(
                    .native_only,
                    case.backend,
                    .new_execution,
                    case.identity,
                ),
            );
        }
        try std.testing.expectEqual(
            Disposition.historical_read_only,
            try decide(
                .native_only,
                case.backend,
                .completed_historical_verification,
                case.identity,
            ),
        );
    }
    try std.testing.expectError(
        error.BackendMismatch,
        classify(.{
            .schema = "https://debz.dev/schema/exact-closure-lock-v1",
            .version = 1,
            .backend = .native,
        }),
    );
}

test "legacy_compat.test.active legacy evidence requires a capable release while history remains readable" {
    const identity: Identity = .{
        .schema = "https://debz.dev/schema/root-operation-record-v1",
        .version = 1,
        .backend = .legacy_dpkg,
    };
    try std.testing.expectEqual(
        Disposition.legacy_recovery,
        try decide(.legacy_capable, .legacy_dpkg, .active_recovery, identity),
    );
    try std.testing.expectError(
        error.LegacyCapabilityRequired,
        decide(.native_only, .legacy_dpkg, .active_recovery, identity),
    );
    try std.testing.expectEqual(
        Disposition.historical_read_only,
        try decide(
            .native_only,
            .legacy_dpkg,
            .completed_historical_verification,
            identity,
        ),
    );
}

test "legacy_compat.test.capability evidence binds exact historical bytes canonically" {
    const source =
        "{\"schema\":\"https://debz.dev/schema/exact-closure-lock-v1\",\"version\":1}\n";
    const identity: Identity = .{
        .schema = "https://debz.dev/schema/exact-closure-lock-v1",
        .version = 1,
    };
    const evidence = try createEvidence(identity, source);
    const source_sha256 = sha256(source);
    try std.testing.expectEqualSlices(u8, &source_sha256, &evidence.artifact_sha256);
    const encoded = try evidence.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    const decoded = try decodeEvidence(std.testing.allocator, encoded);
    const round_trip = try decoded.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(round_trip);
    try std.testing.expectEqualSlices(u8, encoded, round_trip);
    try std.testing.expectEqualSlices(
        u8,
        &evidence.artifact_sha256,
        &decoded.artifact_sha256,
    );
}

test "legacy_compat.test.unknown versions and mixed explicit profiles fail closed" {
    try std.testing.expectError(
        error.UnsupportedIdentity,
        classify(.{
            .schema = "https://debz.dev/schema/transaction-result-v1",
            .version = 2,
        }),
    );
    try std.testing.expectError(
        error.BackendRequired,
        classify(.{
            .schema = "https://debz.dev/schema/system-profile-v2",
            .version = 2,
        }),
    );
    try std.testing.expectError(
        error.BackendMismatch,
        classify(.{
            .schema = "https://debz.dev/schema/system-profile-v1",
            .version = 1,
            .backend = .native,
        }),
    );
}
