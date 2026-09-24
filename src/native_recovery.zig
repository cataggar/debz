const std = @import("std");
const content_digest = @import("content_digest.zig");
const maintainer_script = @import("maintainer_script.zig");
const native_helper = @import("native_helper.zig");
const absolute_path = @import("absolute_path.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Digest = [64]u8;

pub fn hexDigest(value: [32]u8) Digest {
    return std.fmt.bytesToHex(value, .lower);
}

pub fn parseDigest(value: Digest) ?[32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, &value) catch return null;
    return result;
}

pub const intent_path = root_operation.native_intent_path;
pub const progress_path = "var/lib/debz/native-execution-progress-v1.log";
pub const progress_schema_id = "https://debz.dev/schema/native-execution-progress-v1";
pub const bootstrap_progress_schema_id = "https://debz.dev/schema/native-execution-progress-v2";
pub const authority_progress_schema_id = "https://debz.dev/schema/native-execution-progress-v3";
pub const authority_bootstrap_progress_schema_id = "https://debz.dev/schema/native-execution-progress-v4";
pub const authorization_name = "native-transaction-authorization-v1.json";
pub const program_name = "native-transaction-program-v1.json";
pub const authorization_v2_name = "native-transaction-authorization-v2.json";
pub const program_v2_name = "native-transaction-program-v2.json";
pub const blob_prefix = "native-recovery-v1-blob-";
pub const workspace_directory = native_helper.bootstrap_directory;
pub const artifact_directory = workspace_directory ++ "/artifacts";
pub const database_directory = workspace_directory ++ "/database";
pub const scripts_directory = workspace_directory ++ "/scripts";
pub const request_directory = workspace_directory ++ "/request";
pub const script_outcome_prefix = "native-script-outcome-v1-";
pub const trigger_events_path = "var/lib/debz/native-trigger-events-v1.json";
pub const managed_state_path = "var/lib/debz/native-managed-state-v1.json";
pub const diversion_cache_path = "var/lib/debz/native-diversion-cache-v1.json";
pub const unpack_diversion_prefix = "native-unpack-diversion-v1-";
pub const unpack_route_settlement_prefix =
    "native-unpack-route-settlement-v1-";
pub const maximum_intent_bytes: usize = 16 * 1024 * 1024;
pub const maximum_progress_bytes: usize = 64 * 1024 * 1024;
pub const maximum_records: usize = 200_000;
pub const maximum_blobs: usize = 200_000;
pub const crash_exit_code: u8 = 86;

pub fn unpackDiversionPath(program_step: u32, buffer: *[128]u8) ![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        root_operation.namespace_path ++ "/" ++ unpack_diversion_prefix ++ "{d}.json",
        .{program_step},
    );
}

pub fn unpackDiversionStep(path: []const u8) !?u32 {
    const prefix = root_operation.namespace_path ++ "/" ++ unpack_diversion_prefix;
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    if (!std.mem.endsWith(u8, path, ".json") or path.len <= prefix.len + ".json".len)
        return error.InvalidUnpackDiversionPath;
    const step = std.fmt.parseUnsigned(u32, path[prefix.len .. path.len - ".json".len], 10) catch
        return error.InvalidUnpackDiversionPath;
    var buffer: [128]u8 = undefined;
    if (!std.mem.eql(u8, path, try unpackDiversionPath(step, &buffer)))
        return error.InvalidUnpackDiversionPath;
    return step;
}

pub fn unpackRouteSettlementPath(
    program_step: u32,
    buffer: *[128]u8,
) ![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        root_operation.namespace_path ++ "/" ++
            unpack_route_settlement_prefix ++ "{d}.json",
        .{program_step},
    );
}

pub fn unpackRouteSettlementStep(path: []const u8) !?u32 {
    const prefix = root_operation.namespace_path ++ "/" ++
        unpack_route_settlement_prefix;
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    if (!std.mem.endsWith(u8, path, ".json") or
        path.len <= prefix.len + ".json".len)
        return error.InvalidUnpackRouteSettlementPath;
    const step = std.fmt.parseUnsigned(
        u32,
        path[prefix.len .. path.len - ".json".len],
        10,
    ) catch return error.InvalidUnpackRouteSettlementPath;
    var buffer: [128]u8 = undefined;
    if (!std.mem.eql(
        u8,
        path,
        try unpackRouteSettlementPath(step, &buffer),
    ))
        return error.InvalidUnpackRouteSettlementPath;
    return step;
}

pub const CrashPoint = enum {
    after_execution_intent,
    after_helper_source_prepared,
    during_helper_source_publication,
    after_helper_source_publication,
    after_helper_probe_prepared,
    after_helper_probe_in_flight,
    after_helper_probe_return_before_outcome,
    after_helper_probe_outcome,
    after_helper_probe_completed,
    after_helper_cleanup_prepared,
    during_helper_cleanup,
    after_helper_cleanup_completed,
    during_filesystem_publication,
    during_database_publication,
    during_bootstrap_config_staging,
    after_bootstrap_config_stage,
    after_subsequent_bootstrap_config_stage,
    after_bootstrap_payload_before_config_cleanup,
    during_bootstrap_config_cleanup,
    after_bootstrap_config_cleanup,
    after_script_prepared,
    after_script_outcome,
    after_script_return_before_outcome,
    after_upgrade_postrm_return_before_outcome,
    after_upgrade_postrm_route_publication,
    after_upgrade_postrm_cache_refresh,
    after_upgrade_postrm_route_checkpoint,
    after_upgrade_postrm_outcome,
    after_upgrade_unwind_outcome,
    after_upgrade_pre_rollback_compensation_outcome,
    after_upgrade_postrm_marker_cleared,
    after_upgrade_postrm_completed,
    after_upgrade_unwind_completed,
    after_upgrade_pre_rollback_compensation_completed,
    during_known_unpack_rollback,
    after_known_unpack_rollback,
    after_failure_outcome,
    after_trigger_outcome,
    after_provenance,
    after_active_clear,
    before_scriptless_trigger_completion,
    after_scriptless_trigger_completion,
    after_unpack_backups,
    during_unpack_backup_publication,
    during_unpack_backup_cleanup,
    during_failed_unpack_publication,
    before_failed_unpack_publication,
    after_failed_unpack_publication,
    before_unpack_backup_cleanup,
    after_unpack_backup_cleanup,
    during_unpack_obsolete_removal,
    after_unpack_payload,
    after_unpack_payload_commit,
    during_unpack_settlement,
    after_unpack_settlement,
    after_unpack_settlement_commit,
    after_unpack_settlement_rollback,
};

pub const CrashController = struct {
    selected: ?CrashPoint = null,

    pub fn hit(self: CrashController, point: CrashPoint) void {
        if (self.selected == point) std.process.exit(crash_exit_code);
    }
};

pub const Operation = enum {
    install,
    upgrade,
    downgrade,
    reinstall,
    configure,
    remove,
    purge,
    process_triggers,
};

pub const ConffilePolicy = enum { keep_existing, use_package_version };

pub const PackageSelection = struct {
    name: []const u8,
    architecture: []const u8,
};

pub const OrderedAction = struct {
    sequence: usize,
    kind: []const u8,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
};

pub const BlobKind = enum {
    request,
    artifact,
    installed_script,
    database,
};

pub const EntryKind = enum {
    regular,
    directory,
    symlink,
    other,
};

pub const Blob = struct {
    kind: BlobKind,
    key: []const u8,
    logical_path: []const u8,
    storage_path: []const u8,
    size: u64,
    sha256: Digest = @splat('0'),
    archive_identity: ?content_digest.JsonIdentity = null,
    mode: u32,
    entry_kind: EntryKind,

    pub fn identity(self: Blob) ?content_digest.Identity {
        if (self.archive_identity) |archive_identity| return archive_identity.value;
        const digest = parseDigest(self.sha256) orelse return null;
        return content_digest.Identity.init(.{ .sha256 = digest }, .sha256) catch null;
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !Blob {
        const Wire = struct {
            kind: BlobKind,
            key: []const u8,
            logical_path: []const u8,
            storage_path: []const u8,
            size: u64,
            sha256: ?Digest = null,
            archive_identity: ?content_digest.JsonIdentity = null,
            mode: u32,
            entry_kind: EntryKind,
        };
        const wire = try std.json.innerParse(Wire, allocator, source, options);
        if ((wire.sha256 == null) == (wire.archive_identity == null))
            return error.UnexpectedToken;
        return .{
            .kind = wire.kind,
            .key = wire.key,
            .logical_path = wire.logical_path,
            .storage_path = wire.storage_path,
            .size = wire.size,
            .sha256 = wire.sha256 orelse @splat('0'),
            .archive_identity = wire.archive_identity,
            .mode = wire.mode,
            .entry_kind = wire.entry_kind,
        };
    }

    pub fn jsonStringify(self: Blob, writer: anytype) !void {
        if (self.archive_identity) |archive_identity| {
            try writer.write(.{
                .kind = self.kind,
                .key = self.key,
                .logical_path = self.logical_path,
                .storage_path = self.storage_path,
                .size = self.size,
                .archive_identity = archive_identity,
                .mode = self.mode,
                .entry_kind = self.entry_kind,
            });
        } else {
            try writer.write(.{
                .kind = self.kind,
                .key = self.key,
                .logical_path = self.logical_path,
                .storage_path = self.storage_path,
                .size = self.size,
                .sha256 = self.sha256,
                .mode = self.mode,
                .entry_kind = self.entry_kind,
            });
        }
    }
};

pub const Intent = struct {
    schema: []const u8 = "https://debz.dev/schema/native-execution-intent-v1",
    version: u32 = 1,
    attempt_id: Digest,
    install_root: []const u8,
    root_identity_sha256: Digest,
    root_inode: u64,
    operation: Operation,
    architecture: []const u8,
    policy: ConffilePolicy,
    triggers: bool,
    defer_triggers: bool,
    staging_directory_initially_present: bool,
    packages: []const PackageSelection,
    ordered_actions: []const OrderedAction,
    request_sha256: Digest,
    policy_sha256: Digest,
    authorization_sha256: Digest,
    program_sha256: Digest,
    exact_lock_sha256: Digest,
    artifact_evidence_sha256: Digest,
    database_generation_sha256: Digest,
    initial_trigger_state_sha256: Digest,
    authorization_schema: ?[]const u8 = null,
    authorization_version: ?u32 = null,
    program_schema: ?[]const u8 = null,
    program_version: ?u32 = null,
    exact_lock_schema: ?[]const u8 = null,
    exact_lock_version: ?u32 = null,
    authorization_path: []const u8,
    program_path: []const u8,
    blobs: []const Blob,
    digest_sha256: Digest,

    pub fn jsonStringify(self: Intent, writer: anytype) !void {
        if (self.version == 1) {
            try writer.write(.{
                .schema = self.schema,
                .version = self.version,
                .attempt_id = self.attempt_id,
                .install_root = self.install_root,
                .root_identity_sha256 = self.root_identity_sha256,
                .root_inode = self.root_inode,
                .operation = self.operation,
                .architecture = self.architecture,
                .policy = self.policy,
                .triggers = self.triggers,
                .defer_triggers = self.defer_triggers,
                .staging_directory_initially_present = self.staging_directory_initially_present,
                .packages = self.packages,
                .ordered_actions = self.ordered_actions,
                .request_sha256 = self.request_sha256,
                .policy_sha256 = self.policy_sha256,
                .authorization_sha256 = self.authorization_sha256,
                .program_sha256 = self.program_sha256,
                .exact_lock_sha256 = self.exact_lock_sha256,
                .artifact_evidence_sha256 = self.artifact_evidence_sha256,
                .database_generation_sha256 = self.database_generation_sha256,
                .initial_trigger_state_sha256 = self.initial_trigger_state_sha256,
                .authorization_path = self.authorization_path,
                .program_path = self.program_path,
                .blobs = self.blobs,
                .digest_sha256 = self.digest_sha256,
            });
        } else {
            try writer.write(.{
                .schema = self.schema,
                .version = self.version,
                .attempt_id = self.attempt_id,
                .install_root = self.install_root,
                .root_identity_sha256 = self.root_identity_sha256,
                .root_inode = self.root_inode,
                .operation = self.operation,
                .architecture = self.architecture,
                .policy = self.policy,
                .triggers = self.triggers,
                .defer_triggers = self.defer_triggers,
                .staging_directory_initially_present = self.staging_directory_initially_present,
                .packages = self.packages,
                .ordered_actions = self.ordered_actions,
                .request_sha256 = self.request_sha256,
                .policy_sha256 = self.policy_sha256,
                .authorization_sha256 = self.authorization_sha256,
                .program_sha256 = self.program_sha256,
                .exact_lock_sha256 = self.exact_lock_sha256,
                .artifact_evidence_sha256 = self.artifact_evidence_sha256,
                .database_generation_sha256 = self.database_generation_sha256,
                .initial_trigger_state_sha256 = self.initial_trigger_state_sha256,
                .authorization_schema = self.authorization_schema.?,
                .authorization_version = self.authorization_version.?,
                .program_schema = self.program_schema.?,
                .program_version = self.program_version.?,
                .exact_lock_schema = self.exact_lock_schema.?,
                .exact_lock_version = self.exact_lock_version.?,
                .authorization_path = self.authorization_path,
                .program_path = self.program_path,
                .blobs = self.blobs,
                .digest_sha256 = self.digest_sha256,
            });
        }
    }
};

pub const OwnedIntent = struct {
    intent: Intent,
    parsed: std.json.Parsed(Intent),

    pub fn deinit(self: *OwnedIntent) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub fn sealIntent(intent: *Intent) void {
    intent.digest_sha256 = @splat('0');
    intent.digest_sha256 = digestValue(
        if (intent.version == 2)
            "debz-native-execution-intent-v2\x00"
        else
            "debz-native-execution-intent-v1\x00",
        intent.*,
    );
}

pub fn validateIntent(intent: Intent) !void {
    const is_v1 = std.mem.eql(
        u8,
        intent.schema,
        "https://debz.dev/schema/native-execution-intent-v1",
    ) and intent.version == 1;
    const is_v2 = std.mem.eql(
        u8,
        intent.schema,
        "https://debz.dev/schema/native-execution-intent-v2",
    ) and intent.version == 2;
    if (!is_v1 and !is_v2)
        return error.UnsupportedSchema;
    if (!absolute_path.root(intent.install_root) or
        intent.install_root.len > 4096 or
        !std.mem.eql(
            u8,
            intent.authorization_path,
            if (is_v2) authorization_v2_name else authorization_name,
        ) or
        !std.mem.eql(
            u8,
            intent.program_path,
            if (is_v2) program_v2_name else program_name,
        ) or
        intent.packages.len > maximum_records or
        intent.ordered_actions.len > maximum_records)
        return error.InvalidIntent;
    if ((is_v1 and (intent.authorization_schema != null or
        intent.authorization_version != null or intent.program_schema != null or
        intent.program_version != null or intent.exact_lock_schema != null or
        intent.exact_lock_version != null)) or
        (is_v2 and (intent.authorization_schema == null or
            intent.authorization_version == null or intent.program_schema == null or
            intent.program_version == null or intent.exact_lock_schema == null or
            intent.exact_lock_version == null)))
        return error.InvalidIntent;
    const root_identity = hexDigest(
        @import("transaction_recovery.zig").rootIdentity(intent.install_root),
    );
    if (!std.mem.eql(
        u8,
        &intent.root_identity_sha256,
        &root_identity,
    )) return error.RootMismatch;
    inline for (.{
        intent.attempt_id,
        intent.root_identity_sha256,
        intent.request_sha256,
        intent.policy_sha256,
        intent.authorization_sha256,
        intent.program_sha256,
        intent.exact_lock_sha256,
        intent.artifact_evidence_sha256,
        intent.database_generation_sha256,
        intent.initial_trigger_state_sha256,
        intent.digest_sha256,
    }) |digest| if (parseDigest(digest) == null)
        return error.InvalidDigest;
    if (intent.blobs.len > maximum_blobs) return error.LimitExceeded;
    var total_blob_bytes: u64 = 0;
    var request_blobs: usize = 0;
    for (intent.blobs, 0..) |blob, index| {
        request_blobs += @intFromBool(blob.kind == .request);
        total_blob_bytes = std.math.add(
            u64,
            total_blob_bytes,
            blob.size,
        ) catch return error.LimitExceeded;
        if (blob.storage_path.len == 0 or
            !std.mem.startsWith(u8, blob.storage_path, "var/lib/debz/") or
            blob.size > std.math.maxInt(usize) or
            blob.identity() == null or
            blob.entry_kind != .regular or
            blob.key.len == 0 or blob.key.len > 4096 or
            blob.logical_path.len == 0 or blob.logical_path.len > 4096)
            return error.InvalidBlob;
        if ((is_v1 and blob.archive_identity != null) or
            (is_v2 and blob.kind == .artifact and blob.archive_identity == null) or
            (is_v2 and blob.kind != .artifact and blob.archive_identity != null))
            return error.InvalidBlob;
        _ = root_fs.Path.init(blob.storage_path) catch return error.InvalidBlob;
        _ = root_fs.Path.initPackage(blob.logical_path) catch return error.InvalidBlob;
        const valid_storage = switch (blob.kind) {
            .request => std.mem.startsWith(
                u8,
                blob.storage_path,
                request_directory ++ "/",
            ) and std.mem.endsWith(u8, blob.storage_path, ".json"),
            .artifact => std.mem.startsWith(
                u8,
                blob.storage_path,
                artifact_directory ++ "/",
            ) and std.mem.endsWith(u8, blob.storage_path, ".deb"),
            .installed_script => std.mem.startsWith(
                u8,
                blob.storage_path,
                scripts_directory ++ "/",
            ) and std.mem.endsWith(u8, blob.storage_path, ".script"),
            .database => std.mem.startsWith(
                u8,
                blob.storage_path,
                database_directory ++ "/",
            ) and std.mem.endsWith(u8, blob.storage_path, ".blob"),
        };
        if (!valid_storage) return error.InvalidBlob;
        for (intent.blobs[0..index]) |previous| {
            if (std.mem.eql(u8, previous.storage_path, blob.storage_path) or
                (previous.kind == blob.kind and
                    std.mem.eql(u8, previous.key, blob.key)))
                return error.InvalidBlob;
        }
        if (request_blobs != 1) return error.InvalidBlob;
    }
    if (request_blobs != 1) return error.InvalidBlob;
    if (total_blob_bytes > 8 * 1024 * 1024 * 1024)
        return error.LimitExceeded;
    var payload = intent;
    const expected = payload.digest_sha256;
    payload.digest_sha256 = @splat('0');
    if (!std.mem.eql(
        u8,
        &expected,
        &digestValue(if (is_v2)
            "debz-native-execution-intent-v2\x00"
        else
            "debz-native-execution-intent-v1\x00", payload),
    )) return error.DigestMismatch;
}

pub fn publishIntent(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent: Intent,
) !void {
    try validateIntent(intent);
    const bytes = try canonicalJson(allocator, intent);
    defer allocator.free(bytes);
    if (bytes.len > maximum_intent_bytes) return error.LimitExceeded;
    try root.publishFile(try root_fs.Path.init(intent_path), bytes, .{
        .permissions = privatePermissions(),
        .overwrite = .fail_if_exists,
        .durable = true,
    });
}

pub fn readIntent(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
) !OwnedIntent {
    const bytes = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init(intent_path),
        maximum_intent_bytes,
    );
    defer allocator.free(bytes);
    return decodeIntent(allocator, bytes);
}

pub fn decodeIntent(allocator: std.mem.Allocator, bytes: []const u8) !OwnedIntent {
    if (bytes.len > maximum_intent_bytes) return error.LimitExceeded;
    var parsed = try std.json.parseFromSlice(
        Intent,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
    );
    errdefer parsed.deinit();
    try validateIntent(parsed.value);
    const canonical = try canonicalJson(allocator, parsed.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical))
        return error.NonCanonicalDocument;
    return .{ .intent = parsed.value, .parsed = parsed };
}

pub const ActionKind = enum {
    filesystem,
    database,
    helper,
    script,
    compensation,
    trigger,
    verification,
    provenance,
    cleanup,
};

pub const Action = struct {
    kind: ActionKind,
    program_step: u32,
    substep: u16,
    ordinal: u32,
};

pub const helper_source_substep = std.math.maxInt(u16) - 1;
pub const helper_probe_substep = std.math.maxInt(u16);

pub fn validateHelperActions(
    progress: ProgressDocument,
    bootstrap: ?native_helper.Bootstrap,
) !void {
    const bootstrap_progress = (std.mem.eql(
        u8,
        progress.schema,
        bootstrap_progress_schema_id,
    ) and progress.version == 2) or (std.mem.eql(
        u8,
        progress.schema,
        authority_bootstrap_progress_schema_id,
    ) and progress.version == 4);
    if (bootstrap_progress != (bootstrap != null))
        return error.InvalidNativeHelperBootstrapState;
    for (progress.records) |record| {
        if (record.action.kind != .helper) continue;
        const authority = bootstrap orelse
            return error.InvalidNativeHelperBootstrapState;
        const source: Action = .{
            .kind = .helper,
            .program_step = authority.owner.program_step,
            .substep = helper_source_substep,
            .ordinal = 0,
        };
        const probe: Action = .{
            .kind = .helper,
            .program_step = authority.owner.program_step,
            .substep = helper_probe_substep,
            .ordinal = 0,
        };
        if (!std.meta.eql(record.action, source) and
            !std.meta.eql(record.action, probe))
            return error.InvalidNativeHelperBootstrapState;
    }
}

pub const Stage = enum {
    prepared,
    in_flight,
    outcome,
    completed,
    activation,
    terminal,
};

pub const Result = enum {
    none,
    applied,
    rolled_back,
    exited,
    not_started,
    failed,
    succeeded,
    recovered,
    recovery_required,
};

pub const Record = struct {
    sequence: u64,
    action: Action,
    stage: Stage,
    result: Result = .none,
    evidence_sha256: ?Digest = null,
    previous_sha256: Digest,
    digest_sha256: Digest,
};

pub const ProgressDocument = struct {
    schema: []const u8 = progress_schema_id,
    version: u32 = 1,
    intent_sha256: Digest,
    records: []const Record,
    head_sha256: Digest,
    digest_sha256: Digest,
};

pub fn summarizeProgress(progress: ProgressDocument) struct {
    script_outcomes_sha256: [32]u8,
    recovered_phase_count: u64,
} {
    var script_hash = Sha256.init(.{});
    script_hash.update("debz-native-script-outcomes-v1\x00");
    var recovered_phases: u64 = 0;
    for (progress.records) |entry| {
        if ((entry.action.kind == .script or entry.action.kind == .trigger or
            entry.action.kind == .compensation) and entry.stage == .outcome)
        {
            script_hash.update(&entry.digest_sha256);
            if (entry.evidence_sha256) |value| script_hash.update(&value);
        }
        if (entry.result == .recovered) recovered_phases += 1;
    }
    return .{
        .script_outcomes_sha256 = script_hash.finalResult(),
        .recovered_phase_count = recovered_phases,
    };
}

pub const OwnedProgress = struct {
    document: ProgressDocument,
    parsed: std.json.Parsed(ProgressDocument),

    pub fn deinit(self: *OwnedProgress) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

fn progressRecordDomain(version: u32) []const u8 {
    return switch (version) {
        1 => "debz-native-execution-progress-record-v1\x00",
        2 => "debz-native-execution-progress-record-v2\x00",
        3 => "debz-native-execution-progress-record-v3\x00",
        4 => "debz-native-execution-progress-record-v4\x00",
        else => unreachable,
    };
}

fn progressDocumentDomain(version: u32) []const u8 {
    return switch (version) {
        1 => "debz-native-execution-progress-v1\x00",
        2 => "debz-native-execution-progress-v2\x00",
        3 => "debz-native-execution-progress-v3\x00",
        4 => "debz-native-execution-progress-v4\x00",
        else => unreachable,
    };
}

fn sealRecord(record: *Record, version: u32) void {
    record.digest_sha256 = @splat('0');
    record.digest_sha256 = digestValue(progressRecordDomain(version), record.*);
}

fn validateProgress(document: ProgressDocument) !void {
    const bootstrap = if (std.mem.eql(u8, document.schema, progress_schema_id) and
        document.version == 1)
        false
    else if (std.mem.eql(u8, document.schema, bootstrap_progress_schema_id) and
        document.version == 2)
        true
    else if (std.mem.eql(u8, document.schema, authority_progress_schema_id) and
        document.version == 3)
        false
    else if (std.mem.eql(
        u8,
        document.schema,
        authority_bootstrap_progress_schema_id,
    ) and document.version == 4)
        true
    else
        return error.InvalidProgress;
    if (document.records.len > maximum_records)
        return error.InvalidProgress;
    var previous: Digest = @splat('0');
    var terminal_seen = false;
    for (document.records, 0..) |record, index| {
        if (record.sequence != index or terminal_seen or
            !std.mem.eql(u8, &record.previous_sha256, &previous))
            return error.InvalidProgress;
        if (record.action.kind == .helper and !bootstrap)
            return error.InvalidProgress;
        if (parseDigest(record.previous_sha256) == null or
            parseDigest(record.digest_sha256) == null or
            (record.evidence_sha256 != null and
                parseDigest(record.evidence_sha256.?) == null))
            return error.InvalidProgress;
        var prior: ?Record = null;
        var prior_index = index;
        while (prior_index != 0) {
            prior_index -= 1;
            if (std.meta.eql(
                document.records[prior_index].action,
                record.action,
            )) {
                prior = document.records[prior_index];
                break;
            }
        }
        switch (record.stage) {
            .prepared => if (record.result != .none or
                (prior != null and
                    !(prior.?.stage == .completed and
                        prior.?.result == .rolled_back)) or
                (record.action.kind == .helper and
                    record.action.substep != helper_source_substep and
                    record.action.substep != helper_probe_substep))
                return error.InvalidProgress,
            .in_flight => if (record.result != .none or prior == null or
                prior.?.stage != .prepared or
                (record.action.kind != .helper and
                    record.action.kind != .script and
                    record.action.kind != .compensation and
                    record.action.kind != .trigger) or
                (record.action.kind == .helper and
                    record.action.substep != helper_probe_substep))
                return error.InvalidProgress,
            .outcome => if (prior == null or prior.?.stage != .in_flight or
                (record.result != .exited and
                    record.result != .not_started and
                    record.result != .recovery_required) or
                record.evidence_sha256 == null or
                (record.action.kind == .helper and
                    record.action.substep != helper_probe_substep))
                return error.InvalidProgress,
            .completed => {
                if (record.result == .none or prior == null)
                    return error.InvalidProgress;
                switch (record.action.kind) {
                    .script, .compensation, .trigger => if (prior.?.stage != .outcome)
                        return error.InvalidProgress,
                    .helper => {
                        if ((record.action.substep == helper_source_substep and
                            prior.?.stage != .prepared) or
                            (record.action.substep == helper_probe_substep and
                                prior.?.stage != .outcome) or
                            (record.action.substep != helper_source_substep and
                                record.action.substep != helper_probe_substep))
                            return error.InvalidProgress;
                    },
                    .filesystem, .database => if (prior.?.stage != .prepared)
                        return error.InvalidProgress,
                    .verification, .provenance, .cleanup => return error.InvalidProgress,
                }
            },
            .activation => if (record.action.kind != .trigger or
                record.evidence_sha256 == null or prior != null)
                return error.InvalidProgress,
            .terminal => {
                if (record.action.kind != .provenance or
                    prior != null or
                    (record.result != .succeeded and
                        record.result != .failed and
                        record.result != .recovered))
                    return error.InvalidProgress;
                terminal_seen = true;
            },
        }
        var payload = record;
        const digest = payload.digest_sha256;
        payload.digest_sha256 = @splat('0');
        if (!std.mem.eql(
            u8,
            &digest,
            &digestValue(progressRecordDomain(document.version), payload),
        )) return error.InvalidProgress;
        previous = digest;
    }
    if (!std.mem.eql(u8, &previous, &document.head_sha256))
        return error.InvalidProgress;
    if (parseDigest(document.intent_sha256) == null or
        parseDigest(document.head_sha256) == null or
        parseDigest(document.digest_sha256) == null)
        return error.InvalidProgress;
    var payload = document;
    const digest = payload.digest_sha256;
    payload.digest_sha256 = @splat('0');
    if (!std.mem.eql(
        u8,
        &digest,
        &digestValue(progressDocumentDomain(document.version), payload),
    )) return error.DigestMismatch;
}

pub fn initializeProgress(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !void {
    return initializeProgressVersion(allocator, root, intent_sha256, false, false);
}

pub fn initializeBootstrapProgress(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !void {
    return initializeProgressVersion(allocator, root, intent_sha256, true, false);
}

pub fn initializeAuthorityProgress(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !void {
    return initializeProgressVersion(allocator, root, intent_sha256, false, true);
}

pub fn initializeAuthorityBootstrapProgress(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !void {
    return initializeProgressVersion(allocator, root, intent_sha256, true, true);
}

fn initializeProgressVersion(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    bootstrap: bool,
    authority: bool,
) !void {
    const version: u32 = if (authority)
        if (bootstrap) 4 else 3
    else if (bootstrap)
        2
    else
        1;
    var document: ProgressDocument = .{
        .schema = switch (version) {
            1 => progress_schema_id,
            2 => bootstrap_progress_schema_id,
            3 => authority_progress_schema_id,
            4 => authority_bootstrap_progress_schema_id,
            else => unreachable,
        },
        .version = version,
        .intent_sha256 = intent_sha256,
        .records = &.{},
        .head_sha256 = @splat('0'),
        .digest_sha256 = @splat('0'),
    };
    document.digest_sha256 = digestValue(progressDocumentDomain(version), document);
    try validateProgress(document);
    const bytes = try canonicalJson(allocator, document);
    defer allocator.free(bytes);
    try root.publishFile(try root_fs.Path.init(progress_path), bytes, .{
        .permissions = privatePermissions(),
        .overwrite = .fail_if_exists,
        .durable = true,
    });
}

pub fn readProgress(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
) !OwnedProgress {
    const bytes = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init(progress_path),
        maximum_progress_bytes,
    );
    defer allocator.free(bytes);
    return decodeProgress(allocator, bytes);
}

pub fn decodeProgress(allocator: std.mem.Allocator, bytes: []const u8) !OwnedProgress {
    if (bytes.len > maximum_progress_bytes) return error.LimitExceeded;
    var parsed = try std.json.parseFromSlice(
        ProgressDocument,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
    );
    errdefer parsed.deinit();
    try validateProgress(parsed.value);
    const canonical = try canonicalJson(allocator, parsed.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical))
        return error.NonCanonicalDocument;
    return .{ .document = parsed.value, .parsed = parsed };
}

pub fn appendProgress(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    action: Action,
    stage: Stage,
    result: Result,
    evidence_sha256: ?Digest,
) !void {
    var current = try readProgress(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(
        u8,
        &current.document.intent_sha256,
        &intent_sha256,
    ) or current.document.records.len >= maximum_records)
        return error.InvalidProgress;
    const records = try allocator.alloc(
        Record,
        current.document.records.len + 1,
    );
    defer allocator.free(records);
    @memcpy(records[0..current.document.records.len], current.document.records);
    var record: Record = .{
        .sequence = current.document.records.len,
        .action = action,
        .stage = stage,
        .result = result,
        .evidence_sha256 = evidence_sha256,
        .previous_sha256 = current.document.head_sha256,
        .digest_sha256 = @splat('0'),
    };
    const bootstrap = std.mem.eql(
        u8,
        current.document.schema,
        bootstrap_progress_schema_id,
    ) or std.mem.eql(
        u8,
        current.document.schema,
        authority_bootstrap_progress_schema_id,
    );
    sealRecord(&record, current.document.version);
    records[records.len - 1] = record;
    var document: ProgressDocument = .{
        .schema = current.document.schema,
        .version = current.document.version,
        .intent_sha256 = intent_sha256,
        .records = records,
        .head_sha256 = record.digest_sha256,
        .digest_sha256 = @splat('0'),
    };
    _ = bootstrap;
    document.digest_sha256 = digestValue(
        progressDocumentDomain(document.version),
        document,
    );
    try validateProgress(document);
    const bytes = try canonicalJson(allocator, document);
    defer allocator.free(bytes);
    if (bytes.len > maximum_progress_bytes) return error.LimitExceeded;
    try root.publishFile(try root_fs.Path.init(progress_path), bytes, .{
        .permissions = privatePermissions(),
        .overwrite = .replace,
        .durable = true,
    });
}

pub fn latest(
    progress: ProgressDocument,
    action: Action,
) ?Record {
    var index = progress.records.len;
    while (index != 0) {
        index -= 1;
        const record = progress.records[index];
        if (std.meta.eql(record.action, action)) return record;
    }
    return null;
}

pub fn isCompleted(progress: ProgressDocument, action: Action) bool {
    const record = latest(progress, action) orelse return false;
    return record.stage == .completed;
}

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    crash: CrashController = .{},
    recovering: bool = false,
    recovered_phase_count: u64 = 0,
    staging_directory_initially_present: bool = false,
    caller_owned: bool = false,
    helper_binding: ?native_helper.Binding = null,
    helper_bootstrap: ?native_helper.Bootstrap = null,
    helper_source: ?native_helper.Source = null,

    pub fn append(
        self: *Runtime,
        action: Action,
        stage: Stage,
        result: Result,
        evidence_sha256: ?Digest,
    ) !void {
        try appendProgress(
            self.allocator,
            self.root,
            self.intent_sha256,
            action,
            stage,
            result,
            evidence_sha256,
        );
    }

    pub fn latest(self: Runtime, action: Action) !?Record {
        var progress = try readProgress(self.allocator, self.root);
        defer progress.deinit();
        return native_recoveryLatest(progress.document, action);
    }

    pub fn completed(self: Runtime, action: Action) !bool {
        const record = try self.latest(action) orelse return false;
        return record.stage == .completed;
    }
};

fn native_recoveryLatest(
    progress: ProgressDocument,
    action: Action,
) ?Record {
    return latest(progress, action);
}

pub const TriggerEventOrigin = enum { automatic, dynamic };
pub const TriggerAwaitMode = enum { awaited, noawait };

pub const TriggerListener = struct {
    trigger: []const u8,
    package: []const u8,
    architecture: []const u8,
    await_mode: TriggerAwaitMode,
};

pub const TriggerEvent = struct {
    origin: TriggerEventOrigin,
    source_package: []const u8,
    source_architecture: []const u8,
    trigger: []const u8,
    activation_awaits: bool,
    listeners: []const TriggerListener,
};

pub const TriggerEventsDocument = struct {
    schema: []const u8 = "https://debz.dev/schema/native-trigger-events-v1",
    version: u32 = 1,
    intent_sha256: Digest,
    events: []const TriggerEvent,
    digest_sha256: Digest,
};

pub const OwnedTriggerEvents = struct {
    document: TriggerEventsDocument,
    parsed: std.json.Parsed(TriggerEventsDocument),

    pub fn deinit(self: *OwnedTriggerEvents) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

fn triggerListenerEqual(left: TriggerListener, right: TriggerListener) bool {
    return std.mem.eql(u8, left.trigger, right.trigger) and
        std.mem.eql(u8, left.package, right.package) and
        std.mem.eql(u8, left.architecture, right.architecture) and
        left.await_mode == right.await_mode;
}

fn triggerEventEqual(left: TriggerEvent, right: TriggerEvent) bool {
    if (left.origin != right.origin or
        !std.mem.eql(u8, left.source_package, right.source_package) or
        !std.mem.eql(u8, left.source_architecture, right.source_architecture) or
        !std.mem.eql(u8, left.trigger, right.trigger) or
        left.activation_awaits != right.activation_awaits or
        left.listeners.len != right.listeners.len)
        return false;
    for (left.listeners, right.listeners) |a, b|
        if (!triggerListenerEqual(a, b)) return false;
    return true;
}

fn validateTriggerEvents(document: TriggerEventsDocument) !void {
    if (!std.mem.eql(
        u8,
        document.schema,
        "https://debz.dev/schema/native-trigger-events-v1",
    ) or document.version != 1 or document.events.len > maximum_records or
        parseDigest(document.intent_sha256) == null or
        parseDigest(document.digest_sha256) == null)
        return error.InvalidTriggerEvents;
    for (document.events) |event| {
        if (!validBoundedText(event.trigger, 4096) or
            event.source_package.len > 256 or
            event.source_architecture.len > 128 or
            event.listeners.len > maximum_records)
            return error.InvalidTriggerEvents;
        for (event.listeners) |listener| {
            if (!std.mem.eql(u8, listener.trigger, event.trigger) or
                !validBoundedText(listener.package, 256) or
                listener.architecture.len > 128)
                return error.InvalidTriggerEvents;
        }
    }
    var payload = document;
    const expected = payload.digest_sha256;
    payload.digest_sha256 = @splat('0');
    if (!std.mem.eql(
        u8,
        &expected,
        &digestValue("debz-native-trigger-events-v1\x00", payload),
    )) return error.DigestMismatch;
}

pub fn initializeTriggerEvents(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !void {
    var document: TriggerEventsDocument = .{
        .intent_sha256 = intent_sha256,
        .events = &.{},
        .digest_sha256 = @splat('0'),
    };
    document.digest_sha256 = digestValue(
        "debz-native-trigger-events-v1\x00",
        document,
    );
    const bytes = try canonicalJson(allocator, document);
    defer allocator.free(bytes);
    try root.publishFile(try root_fs.Path.init(trigger_events_path), bytes, .{
        .permissions = privatePermissions(),
        .overwrite = .fail_if_exists,
        .durable = true,
    });
}

pub fn readTriggerEvents(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
) !OwnedTriggerEvents {
    const bytes = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init(trigger_events_path),
        maximum_progress_bytes,
    );
    defer allocator.free(bytes);
    return decodeTriggerEvents(allocator, bytes);
}

pub fn decodeTriggerEvents(allocator: std.mem.Allocator, bytes: []const u8) !OwnedTriggerEvents {
    if (bytes.len > maximum_progress_bytes) return error.LimitExceeded;
    var parsed = try std.json.parseFromSlice(
        TriggerEventsDocument,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
    );
    errdefer parsed.deinit();
    try validateTriggerEvents(parsed.value);
    const canonical = try canonicalJson(allocator, parsed.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical))
        return error.NonCanonicalDocument;
    return .{ .document = parsed.value, .parsed = parsed };
}

pub fn publishTriggerEvents(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    events: []const TriggerEvent,
) !void {
    var current = try readTriggerEvents(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(
        u8,
        &current.document.intent_sha256,
        &intent_sha256,
    ) or current.document.events.len > events.len)
        return error.InvalidTriggerEvents;
    for (current.document.events, events[0..current.document.events.len]) |a, b|
        if (!triggerEventEqual(a, b)) return error.TriggerEventsChanged;
    if (current.document.events.len == events.len) return;
    var document: TriggerEventsDocument = .{
        .intent_sha256 = intent_sha256,
        .events = events,
        .digest_sha256 = @splat('0'),
    };
    document.digest_sha256 = digestValue(
        "debz-native-trigger-events-v1\x00",
        document,
    );
    try validateTriggerEvents(document);
    const bytes = try canonicalJson(allocator, document);
    defer allocator.free(bytes);
    if (bytes.len > maximum_progress_bytes) return error.LimitExceeded;
    try root.publishFile(try root_fs.Path.init(trigger_events_path), bytes, .{
        .permissions = privatePermissions(),
        .overwrite = .replace,
        .durable = true,
    });
}

pub const maximum_managed_paths: usize = 200_000;
pub const maximum_managed_generations: usize = 4096;
pub const maximum_managed_file_bytes: usize = 1024 * 1024 * 1024;
pub const maximum_managed_observation_bytes: u64 = 8 * 1024 * 1024 * 1024;
pub const maximum_managed_directory_entries: usize = 200_000;
pub const maximum_managed_directory_name_bytes: usize = 64 * 1024 * 1024;
pub const maximum_managed_state_bytes: usize = 128 * 1024 * 1024;

pub const ManagedKind = enum {
    absent,
    regular,
    symlink,
    directory,
};

pub const ManagedEntry = struct {
    path: []const u8,
    kind: ManagedKind,
    mode: u32 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    device: u64 = 0,
    inode: u64 = 0,
    link_count: u64 = 0,
    modified_nanoseconds: i128 = 0,
    change_nanoseconds: i128 = 0,
    size: u64 = 0,
    content_sha256: ?Digest = null,
    link_target: ?[]const u8 = null,
    directory_sha256: ?Digest = null,
    directory_entries: ?u64 = null,
};

pub const ManagedSnapshot = struct {
    action: Action,
    progress_head_sha256: Digest,
    entries: []const ManagedEntry,
    digest_sha256: Digest,
};

pub const ManagedBoundary = struct {
    generation: u64,
    action: Action,
    snapshot_sha256: Digest,
    transient: bool,
};

pub const ManagedStateDocument = struct {
    schema: []const u8 = "https://debz.dev/schema/native-managed-state-v1",
    version: u32 = 1,
    intent_sha256: Digest,
    generation: u64,
    history: []const ManagedBoundary,
    stable: ?ManagedSnapshot,
    transient: ?ManagedSnapshot,
    digest_sha256: Digest,
};

pub const OwnedManagedState = struct {
    document: ManagedStateDocument,
    parsed: std.json.Parsed(ManagedStateDocument),

    pub fn deinit(self: *OwnedManagedState) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

fn lessManagedPath(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn lessDirectoryMember(
    _: void,
    left: root_fs.DirectoryMember,
    right: root_fs.DirectoryMember,
) bool {
    const order = std.mem.order(u8, left.name, right.name);
    if (order != .eq) return order == .lt;
    return std.mem.order(u8, @tagName(left.kind), @tagName(right.kind)) == .lt;
}

fn managedEntryEqual(left: ManagedEntry, right: ManagedEntry) bool {
    if (!std.mem.eql(u8, left.path, right.path) or
        left.kind != right.kind or left.mode != right.mode or
        left.uid != right.uid or left.gid != right.gid or
        left.device != right.device or left.inode != right.inode or
        left.link_count != right.link_count or
        left.modified_nanoseconds != right.modified_nanoseconds or
        left.change_nanoseconds != right.change_nanoseconds or
        left.size != right.size)
        return false;
    if (left.content_sha256) |digest| {
        if (right.content_sha256 == null or
            !std.mem.eql(u8, &digest, &right.content_sha256.?))
            return false;
    } else if (right.content_sha256 != null) return false;
    if (left.directory_sha256) |digest| {
        if (right.directory_sha256 == null or
            !std.mem.eql(u8, &digest, &right.directory_sha256.?))
            return false;
    } else if (right.directory_sha256 != null) return false;
    if (left.link_target) |target| {
        if (right.link_target == null or
            !std.mem.eql(u8, target, right.link_target.?))
            return false;
    } else if (right.link_target != null) return false;
    return left.directory_entries == right.directory_entries;
}

fn managedRegularEntry(path: []const u8, observation: root_fs.RegularFileObservation) ManagedEntry {
    var digest: [32]u8 = undefined;
    Sha256.hash(observation.bytes, &digest, .{});
    return .{
        .path = path,
        .kind = .regular,
        .mode = observation.entry.mode,
        .uid = observation.entry.uid,
        .gid = observation.entry.gid,
        .device = observation.entry.device,
        .inode = observation.entry.inode,
        .link_count = observation.entry.link_count,
        .modified_nanoseconds = observation.entry.modified_nanoseconds,
        .change_nanoseconds = observation.change_nanoseconds,
        .size = observation.entry.size,
        .content_sha256 = hexDigest(digest),
    };
}

const ManagedDirectoryMember = struct { name: []const u8, kind: []const u8 };

fn managedDirectoryDigest(allocator: std.mem.Allocator, members: []const root_fs.DirectoryMember) !Digest {
    const wire = try allocator.alloc(ManagedDirectoryMember, members.len);
    defer allocator.free(wire);
    for (members, wire) |member, *entry|
        entry.* = .{ .name = member.name, .kind = @tagName(member.kind) };
    return digestValue("debz-native-managed-directory-v1\x00", wire);
}

fn observeManagedEntry(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path_text: []const u8,
    observed_bytes: *u64,
) !ManagedEntry {
    const path = try root_fs.Path.initPackage(path_text);
    const found = try root.entryIfExists(path) orelse return .{
        .path = path_text,
        .kind = .absent,
    };
    if (!found.modeled or !found.isSupportedKind())
        return error.UnmodeledManagedState;
    const base: ManagedEntry = .{
        .path = path_text,
        .kind = if (found.isRegularFile())
            .regular
        else if (found.isSymbolicLink())
            .symlink
        else
            .directory,
        .mode = found.mode,
        .uid = found.uid,
        .gid = found.gid,
        .device = found.device,
        .inode = found.inode,
        .link_count = found.link_count,
        .modified_nanoseconds = found.modified_nanoseconds,
        .size = found.size,
    };
    return switch (base.kind) {
        .absent => unreachable,
        .regular => block: {
            if (found.size > maximum_managed_file_bytes)
                return error.ManagedStateLimit;
            observed_bytes.* = std.math.add(
                u64,
                observed_bytes.*,
                found.size,
            ) catch return error.ManagedStateLimit;
            if (observed_bytes.* > maximum_managed_observation_bytes)
                return error.ManagedStateLimit;
            var pinned = try root.pinRegularFile(path);
            defer pinned.close();
            const observation = try pinned.observeStableAlloc(
                allocator,
                maximum_managed_file_bytes,
            );
            defer allocator.free(observation.bytes);
            break :block managedRegularEntry(path_text, observation);
        },
        .symlink => block: {
            var pinned = try root.pinSymbolicLink(path);
            defer pinned.close();
            var buffer: [root_fs.maximum_link_target_bytes]u8 = undefined;
            const observation = try pinned.observe(&buffer);
            var result = base;
            result.mode = observation.entry.mode;
            result.uid = observation.entry.uid;
            result.gid = observation.entry.gid;
            result.device = observation.entry.device;
            result.inode = observation.entry.inode;
            result.link_count = observation.entry.link_count;
            result.modified_nanoseconds =
                observation.entry.modified_nanoseconds;
            result.change_nanoseconds = observation.change_nanoseconds;
            result.size = observation.entry.size;
            result.link_target = try allocator.dupe(u8, observation.target);
            break :block result;
        },
        .directory => block: {
            var pinned = try root.pinDirectory(path);
            defer pinned.close();
            var observation = try pinned.observeAlloc(
                allocator,
                maximum_managed_directory_entries,
                maximum_managed_directory_name_bytes,
            );
            defer observation.deinit();
            std.mem.sort(
                root_fs.DirectoryMember,
                observation.members,
                {},
                lessDirectoryMember,
            );
            var result = base;
            result.mode = observation.entry.mode;
            result.uid = observation.entry.uid;
            result.gid = observation.entry.gid;
            result.device = observation.entry.device;
            result.inode = observation.entry.inode;
            result.link_count = observation.entry.link_count;
            result.modified_nanoseconds =
                observation.entry.modified_nanoseconds;
            result.change_nanoseconds = observation.change_nanoseconds;
            result.size = observation.entry.size;
            result.directory_sha256 = try managedDirectoryDigest(allocator, observation.members);
            result.directory_entries = observation.members.len;
            break :block result;
        },
    };
}

fn sealManagedSnapshot(snapshot: *ManagedSnapshot) void {
    snapshot.digest_sha256 = @splat('0');
    snapshot.digest_sha256 = digestValue(
        "debz-native-managed-snapshot-v1\x00",
        snapshot.*,
    );
}

fn validateManagedSnapshot(snapshot: ManagedSnapshot) !void {
    if (snapshot.entries.len > maximum_managed_paths or
        parseDigest(snapshot.progress_head_sha256) == null or
        parseDigest(snapshot.digest_sha256) == null)
        return error.InvalidManagedState;
    var previous: ?[]const u8 = null;
    for (snapshot.entries) |entry| {
        _ = root_fs.Path.initPackage(entry.path) catch
            return error.InvalidManagedState;
        if (previous) |path| {
            if (std.mem.order(u8, path, entry.path) != .lt)
                return error.InvalidManagedState;
        }
        previous = entry.path;
        switch (entry.kind) {
            .absent => if (entry.content_sha256 != null or
                entry.link_target != null or entry.directory_sha256 != null or
                entry.directory_entries != null)
                return error.InvalidManagedState,
            .regular => if (entry.content_sha256 == null or
                parseDigest(entry.content_sha256.?) == null or
                entry.link_target != null or entry.directory_sha256 != null or
                entry.directory_entries != null)
                return error.InvalidManagedState,
            .symlink => if (entry.link_target == null or
                entry.content_sha256 != null or
                entry.directory_sha256 != null or
                entry.directory_entries != null)
                return error.InvalidManagedState,
            .directory => if (entry.directory_sha256 == null or
                parseDigest(entry.directory_sha256.?) == null or
                entry.directory_entries == null or
                entry.content_sha256 != null or entry.link_target != null)
                return error.InvalidManagedState,
        }
    }
    var payload = snapshot;
    const digest = payload.digest_sha256;
    payload.digest_sha256 = @splat('0');
    if (!std.mem.eql(
        u8,
        &digest,
        &digestValue("debz-native-managed-snapshot-v1\x00", payload),
    )) return error.DigestMismatch;
}

fn validateManagedDocument(document: ManagedStateDocument) !void {
    if (!std.mem.eql(
        u8,
        document.schema,
        "https://debz.dev/schema/native-managed-state-v1",
    ) or document.version != 1 or
        parseDigest(document.intent_sha256) == null or
        parseDigest(document.digest_sha256) == null)
        return error.InvalidManagedState;
    if (document.history.len > maximum_managed_generations or
        document.generation > maximum_managed_generations)
        return error.InvalidManagedState;
    for (document.history, 0..) |boundary, index| {
        if (boundary.generation == 0 or
            boundary.generation > document.generation or
            (index != 0 and boundary.generation <=
                document.history[index - 1].generation) or
            parseDigest(boundary.snapshot_sha256) == null)
            return error.InvalidManagedState;
    }
    if (document.stable) |snapshot| {
        try validateManagedSnapshot(snapshot);
        var bound = false;
        for (document.history) |boundary| {
            if (!boundary.transient and
                std.meta.eql(boundary.action, snapshot.action) and
                std.mem.eql(
                    u8,
                    &boundary.snapshot_sha256,
                    &snapshot.digest_sha256,
                ))
                bound = true;
        }
        if (!bound) return error.InvalidManagedState;
    }
    if (document.transient) |snapshot| {
        try validateManagedSnapshot(snapshot);
        var bound = false;
        for (document.history) |boundary| {
            if (boundary.transient and
                std.meta.eql(boundary.action, snapshot.action) and
                std.mem.eql(
                    u8,
                    &boundary.snapshot_sha256,
                    &snapshot.digest_sha256,
                ))
                bound = true;
        }
        if (!bound) return error.InvalidManagedState;
    }
    var payload = document;
    const digest = payload.digest_sha256;
    payload.digest_sha256 = @splat('0');
    if (!std.mem.eql(
        u8,
        &digest,
        &digestValue("debz-native-managed-state-v1\x00", payload),
    )) return error.DigestMismatch;
}

fn publishManagedDocument(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    document: ManagedStateDocument,
    policy: root_fs.OverwritePolicy,
) !void {
    try validateManagedDocument(document);
    const bytes = try canonicalJson(allocator, document);
    defer allocator.free(bytes);
    if (bytes.len > maximum_managed_state_bytes)
        return error.ManagedStateLimit;
    try root.publishFile(try root_fs.Path.init(managed_state_path), bytes, .{
        .permissions = privatePermissions(),
        .overwrite = policy,
        .durable = true,
    });
}

pub fn initializeManagedState(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !void {
    var document: ManagedStateDocument = .{
        .intent_sha256 = intent_sha256,
        .generation = 0,
        .history = &.{},
        .stable = null,
        .transient = null,
        .digest_sha256 = @splat('0'),
    };
    document.digest_sha256 = digestValue(
        "debz-native-managed-state-v1\x00",
        document,
    );
    try publishManagedDocument(
        allocator,
        root,
        document,
        .fail_if_exists,
    );
}

pub fn readManagedState(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
) !OwnedManagedState {
    const bytes = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init(managed_state_path),
        maximum_managed_state_bytes,
    );
    defer allocator.free(bytes);
    return decodeManagedState(allocator, bytes);
}

pub fn decodeManagedState(allocator: std.mem.Allocator, bytes: []const u8) !OwnedManagedState {
    if (bytes.len > maximum_managed_state_bytes) return error.LimitExceeded;
    var parsed = try std.json.parseFromSlice(
        ManagedStateDocument,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
    );
    errdefer parsed.deinit();
    try validateManagedDocument(parsed.value);
    const canonical = try canonicalJson(allocator, parsed.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical))
        return error.NonCanonicalDocument;
    return .{ .document = parsed.value, .parsed = parsed };
}

pub fn updateManagedState(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    action: Action,
    additional_paths: []const []const u8,
    transient: bool,
) !Digest {
    var current = try readManagedState(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(
        u8,
        &current.document.intent_sha256,
        &intent_sha256,
    )) return error.InvalidManagedState;
    var progress = try readProgress(allocator, root);
    defer progress.deinit();
    if (!std.mem.eql(
        u8,
        &progress.document.intent_sha256,
        &intent_sha256,
    )) return error.InvalidManagedState;

    const base = current.document.transient orelse
        current.document.stable;
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(allocator);
    if (base) |snapshot| {
        for (snapshot.entries) |entry|
            try paths.append(allocator, entry.path);
    }
    for (additional_paths) |path| {
        _ = try root_fs.Path.initPackage(path);
        var duplicate = false;
        for (paths.items) |existing| {
            if (std.mem.eql(u8, existing, path)) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) try paths.append(allocator, path);
    }
    if (paths.items.len > maximum_managed_paths)
        return error.ManagedStateLimit;
    std.mem.sort([]const u8, paths.items, {}, lessManagedPath);
    const entries = try allocator.alloc(ManagedEntry, paths.items.len);
    var initialized: usize = 0;
    defer {
        for (entries[0..initialized]) |entry| {
            if (entry.link_target) |target| allocator.free(target);
        }
        allocator.free(entries);
    }
    var observed_bytes: u64 = 0;
    for (paths.items, 0..) |path, index| {
        entries[index] = try observeManagedEntry(
            allocator,
            root,
            path,
            &observed_bytes,
        );
        initialized += 1;
        const route_input_step = try unpackRouteSettlementStep(path);
        const immutable_input_step =
            try unpackDiversionStep(path) orelse route_input_step;
        if (immutable_input_step) |program_step| {
            const previous: ?ManagedEntry = if (base) |snapshot| block: {
                const previous_index = managedEntryLowerBound(snapshot.entries, path);
                break :block if (previous_index < snapshot.entries.len and std.mem.eql(u8, snapshot.entries[previous_index].path, path))
                    snapshot.entries[previous_index]
                else
                    null;
            } else null;
            if (previous) |entry| {
                if (managedEntryEqual(entry, entries[index])) continue;
                // The initial unpack anchor may publish an observed absent
                // input once; later scripts and journals cannot rebind it.
                const initial_anchor = !transient and
                    action.kind == .filesystem and
                    action.program_step == program_step and
                    action.substep == 0 and action.ordinal == 0;
                const route_script_publication = route_input_step != null and
                    transient and action.kind == .script and
                    action.ordinal == 0;
                if (entry.kind != .absent or
                    entries[index].kind != .regular or
                    (!initial_anchor and !route_script_publication))
                    return error.ManagedStateChanged;
            } else if (entries[index].kind != .absent) {
                const initial_anchor = route_input_step != null and
                    entries[index].kind == .regular and !transient and
                    action.kind == .filesystem and
                    action.program_step == program_step and
                    action.substep == 0 and action.ordinal == 0;
                if (!initial_anchor)
                    return error.ManagedStateChanged;
            }
        }
    }
    var snapshot: ManagedSnapshot = .{
        .action = action,
        .progress_head_sha256 = progress.document.head_sha256,
        .entries = entries,
        .digest_sha256 = @splat('0'),
    };
    sealManagedSnapshot(&snapshot);
    const next_generation = std.math.add(
        u64,
        current.document.generation,
        1,
    ) catch return error.ManagedStateLimit;
    if (next_generation > maximum_managed_generations)
        return error.ManagedStateLimit;
    const history = try allocator.alloc(
        ManagedBoundary,
        current.document.history.len + 1,
    );
    defer allocator.free(history);
    @memcpy(
        history[0..current.document.history.len],
        current.document.history,
    );
    history[history.len - 1] = .{
        .generation = next_generation,
        .action = action,
        .snapshot_sha256 = snapshot.digest_sha256,
        .transient = transient,
    };
    var document: ManagedStateDocument = .{
        .intent_sha256 = intent_sha256,
        .generation = next_generation,
        .history = history,
        .stable = if (transient) current.document.stable else snapshot,
        .transient = if (transient) snapshot else null,
        .digest_sha256 = @splat('0'),
    };
    document.digest_sha256 = digestValue(
        "debz-native-managed-state-v1\x00",
        document,
    );
    try publishManagedDocument(allocator, root, document, .replace);
    return snapshot.digest_sha256;
}

pub fn discardTransientManagedState(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !void {
    var current = try readManagedState(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(
        u8,
        &current.document.intent_sha256,
        &intent_sha256,
    )) return error.InvalidManagedState;
    if (current.document.transient == null) return;
    var document = current.document;
    document.generation = std.math.add(
        u64,
        document.generation,
        1,
    ) catch return error.ManagedStateLimit;
    if (document.generation > maximum_managed_generations)
        return error.ManagedStateLimit;
    document.transient = null;
    document.digest_sha256 = @splat('0');
    document.digest_sha256 = digestValue(
        "debz-native-managed-state-v1\x00",
        document,
    );
    try publishManagedDocument(allocator, root, document, .replace);
}

pub fn validateStableManagedState(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !void {
    var current = try readManagedState(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(
        u8,
        &current.document.intent_sha256,
        &intent_sha256,
    ) or current.document.transient != null)
        return error.InvalidManagedState;
    const stable = current.document.stable orelse return;
    var observed_bytes: u64 = 0;
    for (stable.entries) |expected| {
        const observed = try observeManagedEntry(
            allocator,
            root,
            expected.path,
            &observed_bytes,
        );
        defer if (observed.link_target) |target| allocator.free(target);
        if (!managedEntryEqual(expected, observed))
            return error.ManagedStateChanged;
    }
}

/// Only call after the mutation engine has verified its recorded rollback.
/// Payload, ownership, times and link counts remain exact; restored nonregular
/// identities and authorized hard-link ctime changes are checkpointed anew.
pub fn checkpointRolledBackMutation(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    action: Action,
    steps: []const @import("root_mutation.zig").Step,
    journal_device: u64,
) !Digest {
    var current = try readManagedState(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(u8, &current.document.intent_sha256, &intent_sha256))
        return error.InvalidManagedState;
    const snapshot = current.document.stable orelse return error.InvalidManagedState;
    const script_snapshot = if (current.document.transient != null)
        try recordedScriptSnapshot(allocator, root, current.document)
    else
        null;
    var originals: std.StringHashMapUnmanaged(ManagedEntry) = .empty;
    defer originals.deinit(allocator);
    for (snapshot.entries) |entry| try originals.put(allocator, entry.path, entry);
    var targets: std.StringHashMapUnmanaged(@import("root_mutation.zig").Step) = .empty;
    defer targets.deinit(allocator);
    var linked: std.AutoHashMapUnmanaged(u128, void) = .empty;
    defer linked.deinit(allocator);
    var restored: std.StringHashMapUnmanaged(bool) = .empty;
    defer restored.deinit(allocator);
    for (steps) |step| {
        const target = try targets.getOrPut(allocator, step.path);
        if (!target.found_existing) target.value_ptr.* = step;
        if (step.expected == .present) {
            const previous = step.expected.present;
            if (originals.get(step.path)) |entry| {
                if (entry.kind == .regular and previous.kind == .regular and entry.inode == previous.inode)
                    try linked.put(allocator, (@as(u128, entry.device) << 64) | entry.inode, {});
                if ((entry.kind == .symlink and previous.kind == .symlink) or
                    (entry.kind == .directory and previous.kind == .directory))
                {
                    const identity = try restored.getOrPut(allocator, step.path);
                    if (!identity.found_existing) identity.value_ptr.* = false;
                    identity.value_ptr.* = identity.value_ptr.* or step.kind != .set_metadata;
                }
            }
        }
        if (step.kind == .publish_hard_link) {
            const source = step.source orelse return error.InvalidManagedState;
            if (originals.get(source)) |entry| {
                if (entry.kind == .regular)
                    try linked.put(allocator, (@as(u128, entry.device) << 64) | entry.inode, {});
            }
        }
    }
    var observed_bytes: u64 = 0;
    for (if (script_snapshot) |script| script.entries else snapshot.entries) |entry| {
        const observed = try observeManagedEntry(allocator, root, entry.path, &observed_bytes);
        defer if (observed.link_target) |target| allocator.free(target);
        var expected = entry;
        if (targets.get(entry.path)) |step| {
            if (originals.get(entry.path)) |original| {
                expected = original;
            } else {
                expected = try restoredJournalEntry(entry, observed, step, journal_device);
            }
        } else if (originals.get(entry.path)) |original| {
            if (original.kind == .regular and linked.contains((@as(u128, original.device) << 64) | original.inode))
                expected = original;
        }
        if (managedEntryEqual(expected, observed)) continue;
        var adjusted = observed;
        if (expected.kind == .regular and linked.contains((@as(u128, expected.device) << 64) | expected.inode)) {
            adjusted.change_nanoseconds = expected.change_nanoseconds;
        } else if (restored.get(expected.path)) |recreated| {
            if (recreated) adjusted.inode = expected.inode;
            adjusted.change_nanoseconds = expected.change_nanoseconds;
        } else return error.ManagedStateChanged;
        if (!managedEntryEqual(expected, adjusted))
            return error.ManagedStateChanged;
    }
    return updateManagedState(allocator, root, intent_sha256, action, &.{}, false);
}

fn recordedScriptSnapshot(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    document: ManagedStateDocument,
) !ManagedSnapshot {
    const snapshot = document.transient orelse return error.InvalidManagedState;
    if (snapshot.action.kind != .script) return error.InvalidManagedState;
    var outcome = (try readScriptOutcome(allocator, root, snapshot.action)) orelse return error.InvalidManagedState;
    defer outcome.deinit();
    if (!std.mem.eql(u8, &outcome.outcome.intent_sha256, &document.intent_sha256) or
        !std.meta.eql(outcome.outcome.action, snapshot.action) or
        (outcome.outcome.disposition != .exited and outcome.outcome.spawned))
        return error.InvalidManagedState;
    var progress = try readProgress(allocator, root);
    defer progress.deinit();
    if (!std.mem.eql(u8, &progress.document.intent_sha256, &document.intent_sha256))
        return error.InvalidManagedState;
    const latest_record = latest(progress.document, snapshot.action) orelse return error.InvalidManagedState;
    var index = progress.document.records.len;
    while (index != 0) {
        index -= 1;
        const record = progress.document.records[index];
        if (record.action.kind != .script and record.action.kind != .compensation and record.action.kind != .trigger)
            continue;
        if (!std.meta.eql(record.action, snapshot.action)) return error.InvalidManagedState;
        break;
    }
    const expected_evidence = switch (latest_record.stage) {
        .in_flight => null,
        .outcome => outcome.outcome.digest_sha256,
        .completed => snapshot.digest_sha256,
        else => return error.InvalidManagedState,
    };
    if (expected_evidence) |digest|
        if (latest_record.evidence_sha256 == null or
            !std.mem.eql(u8, &digest, &latest_record.evidence_sha256.?))
            return error.InvalidManagedState;
    for (progress.document.records) |record| {
        if (std.mem.eql(u8, &record.digest_sha256, &snapshot.progress_head_sha256) and
            record.stage == .in_flight and std.meta.eql(record.action, snapshot.action))
            return snapshot;
    }
    return error.InvalidManagedState;
}

pub fn recordedTransientScriptAction(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !?Action {
    if (try root.entryIfExists(try root_fs.Path.init(managed_state_path)) == null) return null;
    var current = try readManagedState(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(u8, &current.document.intent_sha256, &intent_sha256))
        return error.InvalidManagedState;
    if (current.document.transient == null) return null;
    return (try recordedScriptSnapshot(allocator, root, current.document)).action;
}

pub fn validateScriptMutationCheckpoint(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    action: Action,
    steps: []const @import("root_mutation.zig").Step,
    journal_device: u64,
    rolling_back: bool,
    rebase_journal_directories: bool,
) !void {
    var current = try readManagedState(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(u8, &current.document.intent_sha256, &intent_sha256))
        return error.InvalidManagedState;
    const snapshot = try recordedScriptSnapshot(allocator, root, current.document);
    if (!std.meta.eql(snapshot.action, action)) return error.InvalidManagedState;
    try validateMutationSnapshot(allocator, root, snapshot, steps, journal_device, rolling_back, rebase_journal_directories);
}

pub fn validateStableMutationCheckpoint(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    steps: []const @import("root_mutation.zig").Step,
    journal_device: u64,
) !void {
    var current = try readManagedState(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(u8, &current.document.intent_sha256, &intent_sha256) or current.document.transient != null)
        return error.InvalidManagedState;
    try validateMutationSnapshot(
        allocator,
        root,
        current.document.stable orelse return error.InvalidManagedState,
        steps,
        journal_device,
        true,
        true,
    );
}

fn validateMutationSnapshot(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    snapshot: ManagedSnapshot,
    steps: []const @import("root_mutation.zig").Step,
    journal_device: u64,
    rolling_back: bool,
    rebase_journal_directories: bool,
) !void {
    var paths: std.StringHashMapUnmanaged(void) = .empty;
    defer paths.deinit(allocator);
    var parents: std.StringHashMapUnmanaged(void) = .empty;
    defer parents.deinit(allocator);
    var linked: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer linked.deinit(allocator);
    if (rolling_back) {
        for (steps) |step| {
            try paths.put(allocator, step.path, {});
            var path = step.path;
            while (std.mem.lastIndexOfScalar(u8, path, '/')) |separator| {
                path = path[0..separator];
                try parents.put(allocator, path, {});
            }
            if (step.expected == .present and step.expected.present.kind == .regular)
                try linked.put(allocator, step.expected.present.inode, {});
        }
    }
    var observed_bytes: u64 = 0;
    for (snapshot.entries) |entry| {
        const observed = try observeManagedEntry(allocator, root, entry.path, &observed_bytes);
        defer if (observed.link_target) |target| allocator.free(target);
        if (managedEntryEqual(entry, observed)) continue;
        if (!rolling_back) return error.ManagedStateChanged;
        if (entry.kind == .directory and observed.kind == .directory and
            (entry.directory_entries != observed.directory_entries or
                entry.directory_sha256 == null or observed.directory_sha256 == null or
                !std.mem.eql(u8, &entry.directory_sha256.?, &observed.directory_sha256.?)))
        {
            if (!rebase_journal_directories or
                !try journalDirectoryMembership(allocator, root, snapshot.entries, entry, observed, &paths))
                return error.ManagedStateChanged;
        }
        // The generic journal owns intermediate states of its paths. Other
        // recorded script effects must remain unchanged during its rollback.
        if (paths.contains(entry.path)) continue;
        if (entry.kind == .directory and parents.contains(entry.path) and
            observed.kind == .directory and observed.mode == entry.mode and
            observed.uid == entry.uid and observed.gid == entry.gid and
            observed.device == entry.device and observed.inode == entry.inode)
            continue;
        var adjusted = observed;
        if (entry.kind == .regular and entry.device == journal_device and linked.contains(entry.inode))
            adjusted.change_nanoseconds = entry.change_nanoseconds;
        if (!managedEntryEqual(entry, adjusted)) return error.ManagedStateChanged;
    }
}

fn managedEntryLowerBound(entries: []const ManagedEntry, path: []const u8) usize {
    var first: usize = 0;
    var last = entries.len;
    while (first < last) {
        const middle = first + (last - first) / 2;
        if (std.mem.lessThan(u8, entries[middle].path, path)) first = middle + 1 else last = middle;
    }
    return first;
}

fn journalDirectoryMembership(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    entries: []const ManagedEntry,
    expected: ManagedEntry,
    observed: ManagedEntry,
    paths: *const std.StringHashMapUnmanaged(void),
) !bool {
    // Reconstruct only journal-owned child names and kinds. Every other live
    // member must still match the original script checkpoint.
    var pinned = try root.pinDirectory(try root_fs.Path.initPackage(expected.path));
    defer pinned.close();
    var directory = try pinned.observeAlloc(allocator, maximum_managed_directory_entries, maximum_managed_directory_name_bytes);
    defer directory.deinit();
    std.mem.sort(root_fs.DirectoryMember, directory.members, {}, lessDirectoryMember);
    const live_digest = try managedDirectoryDigest(allocator, directory.members);
    if (observed.directory_sha256 == null or
        !std.mem.eql(u8, &live_digest, &observed.directory_sha256.?))
        return error.ManagedStateChanged;
    var normalized: std.ArrayList(ManagedDirectoryMember) = .empty;
    defer normalized.deinit(allocator);
    for (directory.members) |member| {
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ expected.path, member.name });
        defer allocator.free(path);
        if (paths.contains(path)) {
            const index = managedEntryLowerBound(entries, path);
            if (index == entries.len or !std.mem.eql(u8, entries[index].path, path))
                return false;
        } else try normalized.append(allocator, .{ .name = member.name, .kind = @tagName(member.kind) });
    }
    const prefix = try std.fmt.allocPrint(allocator, "{s}/", .{expected.path});
    defer allocator.free(prefix);
    var index = managedEntryLowerBound(entries, prefix);
    while (index < entries.len and std.mem.startsWith(u8, entries[index].path, prefix)) : (index += 1) {
        const entry = entries[index];
        const name = entry.path[prefix.len..];
        if (std.mem.indexOfScalar(u8, name, '/') != null or !paths.contains(entry.path) or entry.kind == .absent)
            continue;
        try normalized.append(allocator, .{ .name = name, .kind = switch (entry.kind) {
            .regular => "file",
            .symlink => "sym_link",
            .directory => "directory",
            .absent => unreachable,
        } });
    }
    if (normalized.items.len > maximum_managed_directory_entries) return error.ManagedStateLimit;
    std.mem.sort(ManagedDirectoryMember, normalized.items, {}, struct {
        fn less(_: void, left: ManagedDirectoryMember, right: ManagedDirectoryMember) bool {
            return std.mem.lessThan(u8, left.name, right.name);
        }
    }.less);
    const digest = digestValue("debz-native-managed-directory-v1\x00", normalized.items);
    return normalized.items.len == expected.directory_entries and expected.directory_sha256 != null and
        std.mem.eql(u8, &digest, &expected.directory_sha256.?);
}

fn restoredJournalEntry(
    script_entry: ManagedEntry,
    observed: ManagedEntry,
    step: @import("root_mutation.zig").Step,
    device: u64,
) !ManagedEntry {
    const previous = switch (step.expected) {
        .absent => return .{ .path = step.path, .kind = .absent },
        .present => |value| value,
    };
    if (previous.inode == 0) return error.InvalidManagedState;
    var expected: ManagedEntry = .{
        .path = step.path,
        .kind = switch (previous.kind) {
            .regular => .regular,
            .symlink => .symlink,
            .directory => .directory,
        },
        .mode = previous.metadata.mode,
        .uid = previous.metadata.uid,
        .gid = previous.metadata.gid,
        .device = device,
        .inode = if (previous.kind == .regular or step.kind == .set_metadata) previous.inode else observed.inode,
        .link_count = previous.link_count,
        .modified_nanoseconds = previous.metadata.modified_nanoseconds,
        .change_nanoseconds = observed.change_nanoseconds,
        .size = previous.size,
        .content_sha256 = if (previous.content_sha256) |digest| hexDigest(digest) else null,
        .link_target = previous.link_target,
    };
    if (previous.kind == .symlink) expected.size = (previous.link_target orelse return error.InvalidManagedState).len;
    if (previous.kind == .directory) {
        if (script_entry.kind != .directory or script_entry.inode != previous.inode)
            return error.InvalidManagedState;
        expected.size = script_entry.size;
        expected.directory_sha256 = script_entry.directory_sha256;
        expected.directory_entries = script_entry.directory_entries;
    }
    return expected;
}

test "native_recovery.test.verified rollback refreshes only journal-authorized identities" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const testing = std.testing;
    const mutation = @import("root_mutation.zig");
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    for ([_][]const u8{ "var", "var/lib", root_operation.namespace_path }) |path|
        try root.ensureDirectory(try root_fs.Path.init(path), root_fs.default_directory_permissions);
    const intent: Digest = @splat('0');
    const action: Action = .{ .kind = .filesystem, .program_step = 7, .substep = 1, .ordinal = 0 };
    try initializeProgress(testing.allocator, root, intent);
    try initializeManagedState(testing.allocator, root, intent);
    const data = try root_fs.Path.init("data");
    const backup = try root_fs.Path.init("data.dpkg-tmp");
    const unrelated = try root_fs.Path.init("unrelated");
    try root.publishFile(data, "original", .{});
    try root.createHardLink(data, backup);
    try root.publishFile(unrelated, "protected", .{});
    _ = try updateManagedState(testing.allocator, root, intent, action, &.{ data.text, backup.text, unrelated.text }, false);
    const old = try root.entry(data);
    var plan = switch (try mutation.preflight(testing.allocator, root, .{ .intents = &.{.{ .file = .{
        .path = data.text,
        .bytes = "incoming",
        .mode = old.mode,
        .uid = old.uid,
        .gid = old.gid,
        .modified_nanoseconds = old.modified_nanoseconds,
    } }} })) {
        .plan => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer plan.deinit();
    const private = try root_fs.Path.init("private");
    try root.createHardLink(data, private);
    try root.removeFile(private);
    _ = try checkpointRolledBackMutation(testing.allocator, root, intent, action, plan.steps, old.device);
    try validateStableManagedState(testing.allocator, root, intent);
    const before = try root.readFileAlloc(testing.allocator, try root_fs.Path.init(managed_state_path), maximum_managed_state_bytes);
    defer testing.allocator.free(before);
    try root.publishFile(unrelated, "external drift", .{ .overwrite = .replace });
    try testing.expectError(error.ManagedStateChanged, checkpointRolledBackMutation(testing.allocator, root, intent, action, plan.steps, old.device));
    const after = try root.readFileAlloc(testing.allocator, try root_fs.Path.init(managed_state_path), maximum_managed_state_bytes);
    defer testing.allocator.free(after);
    try testing.expectEqualStrings(before, after);
    _ = try updateManagedState(testing.allocator, root, intent, action, &.{}, false);
    const symbolic = try root_fs.Path.init("symbolic");
    try root.createSymbolicLink(symbolic, data.text);
    try root.applyMetadata(symbolic, .{ .modified_nanoseconds = 123 });
    _ = try updateManagedState(testing.allocator, root, intent, action, &.{symbolic.text}, false);
    var metadata_plan = switch (try mutation.preflight(testing.allocator, root, .{ .intents = &.{.{ .metadata = .{
        .path = symbolic.text,
        .uid = old.uid,
        .gid = old.gid,
        .modified_nanoseconds = 456,
    } }} })) {
        .plan => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer metadata_plan.deinit();
    var link_plan = switch (try mutation.preflight(testing.allocator, root, .{ .intents = &.{.{ .symlink = .{
        .path = symbolic.text,
        .target = "different",
        .uid = old.uid,
        .gid = old.gid,
        .modified_nanoseconds = 456,
    } }} })) {
        .plan => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer link_plan.deinit();
    var pinned = try root.pinSymbolicLink(symbolic);
    defer pinned.close();
    try root.removeFile(symbolic);
    try root.createSymbolicLink(symbolic, data.text);
    try root.applyMetadata(symbolic, .{ .modified_nanoseconds = 123 });
    try testing.expectError(error.ManagedStateChanged, checkpointRolledBackMutation(testing.allocator, root, intent, action, metadata_plan.steps, old.device));
    _ = try checkpointRolledBackMutation(testing.allocator, root, intent, action, link_plan.steps, old.device);
    try root.publishFile(data, "original", .{ .overwrite = .replace });
    try testing.expectError(error.ManagedStateChanged, checkpointRolledBackMutation(testing.allocator, root, intent, action, plan.steps, old.device));
}

/// A null result means the checkpoint does not authorize this path, not that
/// the live path is absent.
pub fn readManagedFile(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    path: []const u8,
    maximum_bytes: usize,
) !?[]u8 {
    if (maximum_bytes > maximum_managed_file_bytes)
        return error.ManagedStateLimit;
    var current = try readManagedState(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(u8, &current.document.intent_sha256, &intent_sha256))
        return error.InvalidManagedState;
    const snapshot = current.document.transient orelse current.document.stable orelse return null;
    for (snapshot.entries) |expected| {
        if (!std.mem.eql(u8, expected.path, path)) continue;
        if (expected.kind != .regular) return error.InvalidManagedState;
        var pinned = root.pinRegularFile(try root_fs.Path.initPackage(path)) catch |err| switch (err) {
            error.FileNotFound => return error.ManagedStateChanged,
            else => return err,
        };
        defer pinned.close();
        const observation = try pinned.observeStableAlloc(allocator, maximum_bytes);
        errdefer allocator.free(observation.bytes);
        if (!observation.entry.modeled) return error.UnmodeledManagedState;
        if (!managedEntryEqual(expected, managedRegularEntry(path, observation)))
            return error.ManagedStateChanged;
        return observation.bytes;
    }
    return null;
}

pub fn managedCheckpointMatchesAction(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    action: Action,
) !bool {
    var current = try readManagedState(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(
        u8,
        &current.document.intent_sha256,
        &intent_sha256,
    )) return error.InvalidManagedState;
    var index = current.document.history.len;
    while (index != 0) {
        index -= 1;
        if (std.meta.eql(current.document.history[index].action, action))
            return true;
    }
    return false;
}

pub fn managedCheckpointDigestForAction(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
    action: Action,
) !?Digest {
    var current = try readManagedState(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(
        u8,
        &current.document.intent_sha256,
        &intent_sha256,
    )) return error.InvalidManagedState;
    var index = current.document.history.len;
    while (index != 0) {
        index -= 1;
        const boundary = current.document.history[index];
        if (std.meta.eql(boundary.action, action))
            return boundary.snapshot_sha256;
    }
    return null;
}

pub fn managedStateHasTransient(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !bool {
    var current = try readManagedState(allocator, root);
    defer current.deinit();
    if (!std.mem.eql(
        u8,
        &current.document.intent_sha256,
        &intent_sha256,
    )) return error.InvalidManagedState;
    return current.document.transient != null;
}

pub const ScriptDisposition = enum {
    exited,
    signaled,
    timed_out,
    cancelled,
    setup_failed,
    output_limit_exceeded,
    rejected,
};

pub const EnvironmentEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const ScriptOutcome = struct {
    schema: []const u8 = "https://debz.dev/schema/native-script-outcome-v1",
    version: u32 = 1,
    intent_sha256: Digest,
    action: Action,
    package: []const u8,
    package_version: []const u8,
    architecture: []const u8,
    kind: maintainer_script.Kind,
    source: []const u8,
    script_sha256: Digest,
    arguments: []const []const u8,
    environment: []const EnvironmentEntry,
    disposition: ScriptDisposition,
    exit_code: ?u8 = null,
    signal: ?u32 = null,
    setup_stage: ?maintainer_script.SetupStage = null,
    setup_errno: ?u32 = null,
    rejection_reason: ?maintainer_script.RejectionReason = null,
    spawned: bool,
    invocation_sha256: Digest,
    stdout_sha256: Digest,
    stderr_sha256: Digest,
    combined_sha256: Digest,
    stdout_hex: []const u8,
    stderr_hex: []const u8,
    combined_hex: []const u8,
    output_bytes: usize,
    output_limit: usize,
    terminated_process_group: bool,
    escalated_to_kill: bool,
    issued_descendant_sweep: bool,
    digest_sha256: Digest,
};

pub const OwnedScriptOutcome = struct {
    outcome: ScriptOutcome,
    parsed: std.json.Parsed(ScriptOutcome),

    pub fn deinit(self: *OwnedScriptOutcome) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub fn scriptOutcomePath(
    action: Action,
    buffer: *[128]u8,
) ![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "var/lib/debz/{s}{s}-{}-{}-{}.json",
        .{
            script_outcome_prefix,
            @tagName(action.kind),
            action.program_step,
            action.substep,
            action.ordinal,
        },
    );
}

pub fn sealScriptOutcome(outcome: *ScriptOutcome) void {
    outcome.digest_sha256 = @splat('0');
    outcome.digest_sha256 = digestValue(
        "debz-native-script-outcome-v1\x00",
        outcome.*,
    );
}

fn validBoundedText(value: []const u8, maximum: usize) bool {
    if (value.len == 0 or value.len > maximum) return false;
    for (value) |byte| if (byte == 0) return false;
    return true;
}

fn digestHexPayload(value: []const u8) ?Digest {
    if (value.len % 2 != 0) return null;
    var hash = Sha256.init(.{});
    var index: usize = 0;
    while (index < value.len) : (index += 2) {
        var encoded: [2]u8 = .{ value[index], value[index + 1] };
        var decoded: [1]u8 = undefined;
        _ = std.fmt.hexToBytes(&decoded, &encoded) catch return null;
        hash.update(&decoded);
    }
    return hexDigest(hash.finalResult());
}

pub fn validateScriptOutcome(outcome: ScriptOutcome) !void {
    if (!std.mem.eql(
        u8,
        outcome.schema,
        "https://debz.dev/schema/native-script-outcome-v1",
    ) or outcome.version != 1 or
        !validBoundedText(outcome.package, 256) or
        !validBoundedText(outcome.package_version, 4096) or
        !validBoundedText(outcome.architecture, 128) or
        !validBoundedText(outcome.source, 64) or
        outcome.arguments.len > 256 or outcome.environment.len > 256 or
        outcome.output_bytes > outcome.output_limit or
        outcome.stdout_hex.len > outcome.output_limit *| 2 or
        outcome.stderr_hex.len > outcome.output_limit *| 2 or
        outcome.combined_hex.len > outcome.output_limit *| 2 or
        (outcome.action.kind != .script and
            outcome.action.kind != .compensation and
            outcome.action.kind != .trigger))
        return error.InvalidScriptOutcome;
    inline for (.{
        outcome.intent_sha256,
        outcome.script_sha256,
        outcome.invocation_sha256,
        outcome.stdout_sha256,
        outcome.stderr_sha256,
        outcome.combined_sha256,
        outcome.digest_sha256,
    }) |digest| if (parseDigest(digest) == null)
        return error.InvalidScriptOutcome;
    const stdout_sha256 = digestHexPayload(outcome.stdout_hex) orelse
        return error.InvalidScriptOutcome;
    const stderr_sha256 = digestHexPayload(outcome.stderr_hex) orelse
        return error.InvalidScriptOutcome;
    const combined_sha256 = digestHexPayload(outcome.combined_hex) orelse
        return error.InvalidScriptOutcome;
    if (!std.mem.eql(
        u8,
        &stdout_sha256,
        &outcome.stdout_sha256,
    ) or !std.mem.eql(
        u8,
        &stderr_sha256,
        &outcome.stderr_sha256,
    ) or !std.mem.eql(
        u8,
        &combined_sha256,
        &outcome.combined_sha256,
    )) return error.InvalidScriptOutcome;
    for (outcome.arguments) |argument|
        if (argument.len > 4096 or std.mem.indexOfScalar(u8, argument, 0) != null)
            return error.InvalidScriptOutcome;
    for (outcome.environment, 0..) |entry, index| {
        if (!validBoundedText(entry.key, 256) or entry.value.len > 4096 or
            std.mem.indexOfScalar(u8, entry.value, 0) != null)
            return error.InvalidScriptOutcome;
        for (outcome.environment[0..index]) |prior|
            if (std.mem.eql(u8, prior.key, entry.key))
                return error.InvalidScriptOutcome;
    }
    switch (outcome.disposition) {
        .exited => if (outcome.exit_code == null or outcome.signal != null or
            outcome.setup_stage != null or outcome.setup_errno != null or
            outcome.rejection_reason != null or !outcome.spawned)
            return error.InvalidScriptOutcome,
        .signaled => if (outcome.exit_code != null or outcome.signal == null or
            outcome.setup_stage != null or outcome.setup_errno != null or
            outcome.rejection_reason != null or !outcome.spawned)
            return error.InvalidScriptOutcome,
        .setup_failed => if (outcome.exit_code != null or outcome.signal != null or
            outcome.setup_stage == null or outcome.setup_errno == null or
            outcome.rejection_reason != null)
            return error.InvalidScriptOutcome,
        .rejected => if (outcome.exit_code != null or outcome.signal != null or
            outcome.setup_stage != null or outcome.setup_errno != null or
            outcome.rejection_reason == null or outcome.spawned)
            return error.InvalidScriptOutcome,
        .timed_out, .cancelled, .output_limit_exceeded => if (outcome.exit_code != null or outcome.signal != null or
            outcome.setup_stage != null or outcome.setup_errno != null or
            outcome.rejection_reason != null or !outcome.spawned)
            return error.InvalidScriptOutcome,
    }
    var payload = outcome;
    const digest = payload.digest_sha256;
    payload.digest_sha256 = @splat('0');
    if (!std.mem.eql(
        u8,
        &digest,
        &digestValue("debz-native-script-outcome-v1\x00", payload),
    )) return error.DigestMismatch;
}

pub fn publishScriptOutcome(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    outcome: ScriptOutcome,
) !void {
    try validateScriptOutcome(outcome);
    const bytes = try canonicalJson(allocator, outcome);
    defer allocator.free(bytes);
    if (bytes.len > maximum_intent_bytes) return error.LimitExceeded;
    var path_buffer: [128]u8 = undefined;
    root.publishFile(
        try root_fs.Path.init(try scriptOutcomePath(outcome.action, &path_buffer)),
        bytes,
        .{
            .permissions = privatePermissions(),
            .overwrite = .fail_if_exists,
            .durable = true,
        },
    ) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const existing = try root.readFileAlloc(
                allocator,
                try root_fs.Path.init(try scriptOutcomePath(
                    outcome.action,
                    &path_buffer,
                )),
                maximum_intent_bytes,
            );
            defer allocator.free(existing);
            if (!std.mem.eql(u8, existing, bytes))
                return error.ScriptOutcomeChanged;
        },
        else => return err,
    };
}

pub fn readScriptOutcome(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    action: Action,
) !?OwnedScriptOutcome {
    var path_buffer: [128]u8 = undefined;
    const path = try root_fs.Path.init(try scriptOutcomePath(action, &path_buffer));
    const bytes = root.readFileAlloc(
        allocator,
        path,
        maximum_intent_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(
        ScriptOutcome,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
    );
    errdefer parsed.deinit();
    if (!std.meta.eql(parsed.value.action, action))
        return error.InvalidScriptOutcome;
    try validateScriptOutcome(parsed.value);
    const canonical = try canonicalJson(allocator, parsed.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical))
        return error.NonCanonicalDocument;
    return .{ .outcome = parsed.value, .parsed = parsed };
}

pub fn blobPath(index: usize, buffer: *[128]u8) ![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "var/lib/debz/{s}{d:0>8}",
        .{ blob_prefix, index },
    );
}

pub fn publishBlob(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: []const u8,
    bytes: []const u8,
    expected_sha256: [32]u8,
) !void {
    var digest: [32]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &digest, &expected_sha256))
        return error.BlobDigestMismatch;
    _ = allocator;
    try root.publishFile(try root_fs.Path.init(path), bytes, .{
        .permissions = privatePermissions(),
        .overwrite = .fail_if_exists,
        .durable = true,
    });
}

pub fn verifyBlob(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    blob: Blob,
) ![]u8 {
    const maximum = std.math.cast(usize, blob.size) orelse
        return error.LimitExceeded;
    const bytes = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init(blob.storage_path),
        maximum,
    );
    errdefer allocator.free(bytes);
    if (bytes.len != blob.size) return error.BlobDigestMismatch;
    const identity = blob.identity() orelse return error.BlobDigestMismatch;
    identity.verify(bytes) catch return error.BlobDigestMismatch;
    return bytes;
}

fn cleanupDiversionEvidence(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !void {
    var namespace = try root.pinDirectory(try root_fs.Path.init(root_operation.namespace_path));
    defer namespace.close();
    var observed = try namespace.observeAlloc(allocator, maximum_records, 64 * 1024 * 1024);
    defer observed.deinit();
    for (observed.members) |member| {
        const unpack = std.mem.startsWith(
            u8,
            member.name,
            unpack_diversion_prefix,
        );
        const route = std.mem.startsWith(
            u8,
            member.name,
            unpack_route_settlement_prefix,
        );
        if (!unpack and !route) continue;
        var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&buffer, root_operation.namespace_path ++ "/{s}", .{member.name});
        _ = if (unpack)
            (try unpackDiversionStep(path)) orelse
                return error.InvalidManagedState
        else
            (try unpackRouteSettlementStep(path)) orelse
                return error.InvalidManagedState;
        const bytes = (try readManagedFile(
            allocator,
            root,
            intent_sha256,
            path,
            maximum_managed_state_bytes,
        )) orelse return error.InvalidManagedState;
        allocator.free(bytes);
    }
    const cache_path = try root_fs.Path.init(diversion_cache_path);
    const cache_present = try root.entryIfExists(cache_path) != null;
    if (cache_present) {
        const bytes = (try readManagedFile(
            allocator,
            root,
            intent_sha256,
            diversion_cache_path,
            maximum_managed_state_bytes,
        )) orelse return error.InvalidManagedState;
        allocator.free(bytes);
    }
    for (observed.members) |member| {
        if (!std.mem.startsWith(u8, member.name, unpack_diversion_prefix) and
            !std.mem.startsWith(
                u8,
                member.name,
                unpack_route_settlement_prefix,
            ))
            continue;
        var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&buffer, root_operation.namespace_path ++ "/{s}", .{member.name});
        try root.removeFile(try root_fs.Path.init(path));
    }
    if (cache_present) try root.removeFile(cache_path);
}

pub fn cleanup(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent: Intent,
) !void {
    try cleanupDiversionEvidence(allocator, root, intent.digest_sha256);
    for (intent.blobs) |blob| {
        root.removeFile(try root_fs.Path.init(blob.storage_path)) catch |err|
            switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
    }
    var authorization_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
    const authorization_path = try std.fmt.bufPrint(
        &authorization_buffer,
        root_operation.namespace_path ++ "/{s}",
        .{intent.authorization_path},
    );
    var program_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
    const program_path = try std.fmt.bufPrint(
        &program_buffer,
        root_operation.namespace_path ++ "/{s}",
        .{intent.program_path},
    );
    for ([_][]const u8{
        progress_path,
        trigger_events_path,
        managed_state_path,
        intent_path,
        authorization_path,
        program_path,
    }) |path| {
        root.removeFile(try root_fs.Path.init(path)) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
    for ([_][]const u8{
        artifact_directory,
        database_directory,
        scripts_directory,
        request_directory,
        workspace_directory,
    }) |path| {
        root.removeDirectory(try root_fs.Path.init(path)) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
    try root.syncDirectory(try root_fs.Path.init(root_operation.namespace_path));
}

test "native_recovery.test.diversion cleanup validates every cache before deleting evidence" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const testing = std.testing;
    for (0..3) |case| {
        var temporary = testing.tmpDir(.{ .iterate = true });
        defer temporary.cleanup();
        const root = root_fs.Root.init(testing.io, temporary.dir);
        for ([_][]const u8{ "var", "var/lib", root_operation.namespace_path }) |path|
            try root.ensureDirectory(try root_fs.Path.init(path), root_fs.default_directory_permissions);
        const intent: Digest = @splat('0');
        try initializeProgress(testing.allocator, root, intent);
        try initializeManagedState(testing.allocator, root, intent);
        var buffer: [128]u8 = undefined;
        const unpack = try root_fs.Path.init(try unpackDiversionPath(7, &buffer));
        const cache = try root_fs.Path.init(diversion_cache_path);
        const action: Action = .{ .kind = .verification, .program_step = 0, .substep = 0, .ordinal = 0 };
        const publication: Action = .{ .kind = .filesystem, .program_step = 7, .substep = 0, .ordinal = 0 };
        _ = try updateManagedState(testing.allocator, root, intent, action, &.{ unpack.text, cache.text }, false);
        try root.publishFile(unpack, "bound unpack bytes", .{});
        try root.publishFile(cache, "bound current bytes", .{});
        _ = try updateManagedState(testing.allocator, root, intent, publication, &.{}, false);
        try root.publishFile(cache, "legitimate cache refresh", .{ .overwrite = .replace });
        _ = try updateManagedState(testing.allocator, root, intent, action, &.{}, false);
        if (case != 0) {
            try root.publishFile(if (case == 1) unpack else cache, "external drift", .{ .overwrite = .replace });
            try testing.expectError(error.ManagedStateChanged, cleanupDiversionEvidence(testing.allocator, root, intent));
            try testing.expect(try root.entryIfExists(unpack) != null);
            try testing.expect(try root.entryIfExists(cache) != null);
        } else {
            try cleanupDiversionEvidence(testing.allocator, root, intent);
            try cleanupDiversionEvidence(testing.allocator, root, intent);
            try testing.expect(try root.entryIfExists(unpack) == null);
            try testing.expect(try root.entryIfExists(cache) == null);
        }
    }
}

fn canonicalJson(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(
        value,
        .{ .whitespace = .minified },
        &output.writer,
    );
    try output.writer.writeByte('\n');
    return output.toOwnedSlice();
}

fn digestValue(domain: []const u8, value: anytype) Digest {
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(Sha256) = .init(&buffer);
    sink.writer.writeAll(domain) catch unreachable;
    std.json.Stringify.value(
        value,
        .{ .whitespace = .minified },
        &sink.writer,
    ) catch unreachable;
    sink.writer.flush() catch unreachable;
    return hexDigest(sink.hasher.finalResult());
}

fn privatePermissions() std.Io.File.Permissions {
    return if (@import("builtin").os.tag == .windows)
        .default_file
    else
        .fromMode(0o600);
}

fn checkProgressChain() !void {
    var first: Record = .{
        .sequence = 0,
        .action = .{
            .kind = .filesystem,
            .program_step = 4,
            .substep = 0,
            .ordinal = 0,
        },
        .stage = .prepared,
        .previous_sha256 = @splat('0'),
        .digest_sha256 = @splat('0'),
    };
    sealRecord(&first, 1);
    var second: Record = .{
        .sequence = 1,
        .action = first.action,
        .stage = .completed,
        .result = .applied,
        .previous_sha256 = first.digest_sha256,
        .digest_sha256 = @splat('0'),
    };
    sealRecord(&second, 1);
    var records = [_]Record{ first, second };
    var progress: ProgressDocument = .{
        .intent_sha256 = @splat('1'),
        .records = &records,
        .head_sha256 = second.digest_sha256,
        .digest_sha256 = @splat('0'),
    };
    progress.digest_sha256 = digestValue(
        "debz-native-execution-progress-v1\x00",
        progress,
    );
    try validateProgress(progress);
    records[0] = second;
    try std.testing.expectError(error.InvalidProgress, validateProgress(progress));
}

fn checkIntentBinding() !void {
    const install_root = "/srv/native-root";
    const empty_sha256 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".*;
    const blobs = [_]Blob{.{
        .kind = .request,
        .key = "request",
        .logical_path = "request/native-lifecycle.json",
        .storage_path = request_directory ++ "/native-lifecycle.json",
        .size = 0,
        .sha256 = empty_sha256,
        .mode = 0o600,
        .entry_kind = .regular,
    }};
    var intent: Intent = .{
        .attempt_id = @splat('1'),
        .install_root = install_root,
        .root_identity_sha256 = hexDigest(
            @import("transaction_recovery.zig").rootIdentity(install_root),
        ),
        .root_inode = 42,
        .operation = .install,
        .architecture = "amd64",
        .policy = .keep_existing,
        .triggers = true,
        .defer_triggers = false,
        .staging_directory_initially_present = false,
        .packages = &.{.{ .name = "demo", .architecture = "amd64" }},
        .ordered_actions = &.{},
        .request_sha256 = empty_sha256,
        .policy_sha256 = @splat('3'),
        .authorization_sha256 = @splat('4'),
        .program_sha256 = @splat('5'),
        .exact_lock_sha256 = @splat('6'),
        .artifact_evidence_sha256 = @splat('7'),
        .database_generation_sha256 = @splat('8'),
        .initial_trigger_state_sha256 = @splat('9'),
        .authorization_path = authorization_name,
        .program_path = program_name,
        .blobs = &blobs,
        .digest_sha256 = @splat('0'),
    };
    sealIntent(&intent);
    try validateIntent(intent);
    intent.blobs = &.{};
    sealIntent(&intent);
    try std.testing.expectError(error.InvalidBlob, validateIntent(intent));
    intent.blobs = &blobs;
    sealIntent(&intent);
    intent.defer_triggers = true;
    try std.testing.expectError(error.DigestMismatch, validateIntent(intent));
}

fn testScriptOutcome() ScriptOutcome {
    const empty_sha256 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".*;
    var outcome: ScriptOutcome = .{
        .intent_sha256 = @splat('1'),
        .action = .{
            .kind = .script,
            .program_step = 7,
            .substep = 1,
            .ordinal = 2,
        },
        .package = "demo",
        .package_version = "1",
        .architecture = "amd64",
        .kind = .postinst,
        .source = "new_package",
        .script_sha256 = @splat('2'),
        .arguments = &.{"configure"},
        .environment = &.{.{ .key = "PATH", .value = "/usr/bin" }},
        .disposition = .exited,
        .exit_code = 0,
        .spawned = true,
        .invocation_sha256 = @splat('3'),
        .stdout_sha256 = empty_sha256,
        .stderr_sha256 = empty_sha256,
        .combined_sha256 = empty_sha256,
        .stdout_hex = "",
        .stderr_hex = "",
        .combined_hex = "",
        .output_bytes = 0,
        .output_limit = 4096,
        .terminated_process_group = false,
        .escalated_to_kill = false,
        .issued_descendant_sweep = true,
        .digest_sha256 = @splat('0'),
    };
    sealScriptOutcome(&outcome);
    return outcome;
}

fn checkScriptOutcomeBinding() !void {
    var outcome = testScriptOutcome();
    try validateScriptOutcome(outcome);
    outcome.exit_code = null;
    try std.testing.expectError(
        error.InvalidScriptOutcome,
        validateScriptOutcome(outcome),
    );
}

test "native_recovery.test.rollback preserves only authenticated script observations" {
    try checkScriptRollback(null);
    try checkScriptRollback("external drift");
    try checkScriptRollback("recorded effect");
}

fn checkScriptRollback(drift: ?[]const u8) !void {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const testing = std.testing;
    const mutation = @import("root_mutation.zig");
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    for ([_][]const u8{ "var", "var/lib", root_operation.namespace_path }) |path|
        try root.ensureDirectory(try root_fs.Path.init(path), root_fs.default_directory_permissions);
    const outcome = testScriptOutcome();
    const intent = outcome.intent_sha256;
    const action: Action = .{ .kind = .filesystem, .program_step = 6, .substep = 1, .ordinal = 0 };
    try initializeProgress(testing.allocator, root, intent);
    try initializeManagedState(testing.allocator, root, intent);
    const payload = try root_fs.Path.init("payload");
    const script_effect = try root_fs.Path.init("script-effect");
    const private_backup = try root_fs.Path.init("private-backup");
    const introduced = try root_fs.Path.init("introduced");
    try root.publishFile(payload, "original", .{});
    try root.publishFile(script_effect, "before", .{});
    _ = try updateManagedState(testing.allocator, root, intent, action, &.{ payload.text, script_effect.text }, false);
    const original = try root.entry(payload);
    var plan = switch (try mutation.preflight(testing.allocator, root, .{ .intents = &.{ .{ .file = .{
        .path = payload.text,
        .bytes = "incoming",
        .mode = original.mode,
        .uid = original.uid,
        .gid = original.gid,
        .modified_nanoseconds = original.modified_nanoseconds,
    } }, .{ .file = .{
        .path = introduced.text,
        .bytes = "new file",
        .mode = original.mode,
        .uid = original.uid,
        .gid = original.gid,
        .modified_nanoseconds = original.modified_nanoseconds,
    } } } })) {
        .plan => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer plan.deinit();
    try root.createHardLink(payload, private_backup);
    try root.publishFile(payload, "incoming", .{ .overwrite = .replace });
    try root.publishFile(introduced, "new file", .{});
    try root.publishFile(script_effect, "recorded effect", .{ .overwrite = .replace });
    try appendProgress(testing.allocator, root, intent, outcome.action, .prepared, .none, null);
    try publishScriptOutcome(testing.allocator, root, outcome);
    _ = try updateManagedState(testing.allocator, root, intent, outcome.action, &.{}, true);
    {
        var current = try readManagedState(testing.allocator, root);
        defer current.deinit();
        try testing.expectError(error.InvalidManagedState, recordedScriptSnapshot(testing.allocator, root, current.document));
    }
    try appendProgress(testing.allocator, root, intent, outcome.action, .in_flight, .none, null);
    const checkpoint = try updateManagedState(testing.allocator, root, intent, outcome.action, &.{introduced.text}, true);
    try appendProgress(testing.allocator, root, intent, outcome.action, .outcome, .exited, outcome.digest_sha256);
    {
        var current = try readManagedState(testing.allocator, root);
        defer current.deinit();
        _ = try recordedScriptSnapshot(testing.allocator, root, current.document);
    }
    try appendProgress(testing.allocator, root, intent, outcome.action, .completed, .succeeded, checkpoint);
    try root.rename(private_backup, payload, .replace);
    try root.removeFile(introduced);
    if (drift) |bytes| {
        try root.publishFile(script_effect, bytes, .{ .overwrite = .replace });
        try testing.expectError(error.ManagedStateChanged, checkpointRolledBackMutation(
            testing.allocator,
            root,
            intent,
            action,
            plan.steps,
            original.device,
        ));
        return;
    }
    _ = try checkpointRolledBackMutation(testing.allocator, root, intent, action, plan.steps, original.device);
    try validateStableManagedState(testing.allocator, root, intent);
    const effect = try root.readFileAlloc(testing.allocator, script_effect, 64);
    defer testing.allocator.free(effect);
    try testing.expectEqualStrings("recorded effect", effect);
    try root.publishFile(script_effect, "external drift", .{ .overwrite = .replace });
    try testing.expectError(error.ManagedStateChanged, checkpointRolledBackMutation(
        testing.allocator,
        root,
        intent,
        action,
        plan.steps,
        original.device,
    ));
}

test "native_recovery.test.script checkpoints bind outcome and latest invocation" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const testing = std.testing;
    const Case = enum {
        in_flight,
        outcome,
        completed,
        missing,
        wrong_intent,
        wrong_action,
        before_invocation,
        wrong_head,
        wrong_evidence,
        wrong_completion,
        newer_invocation,
        cancelled,
    };
    for (std.enums.values(Case)) |case| {
        var temporary = testing.tmpDir(.{ .iterate = true });
        defer temporary.cleanup();
        const root = root_fs.Root.init(testing.io, temporary.dir);
        for ([_][]const u8{ "var", "var/lib", root_operation.namespace_path }) |path|
            try root.ensureDirectory(try root_fs.Path.init(path), root_fs.default_directory_permissions);
        var outcome = testScriptOutcome();
        const intent = outcome.intent_sha256;
        const action = outcome.action;
        try initializeProgress(testing.allocator, root, intent);
        try initializeManagedState(testing.allocator, root, intent);
        try appendProgress(testing.allocator, root, intent, action, .prepared, .none, null);
        if (case == .before_invocation)
            _ = try updateManagedState(testing.allocator, root, intent, action, &.{}, true);
        try appendProgress(testing.allocator, root, intent, action, .in_flight, .none, null);
        if (case == .wrong_head)
            try appendProgress(testing.allocator, root, intent, .{
                .kind = .filesystem,
                .program_step = 8,
                .substep = 0,
                .ordinal = 0,
            }, .prepared, .none, null);
        const checkpoint = if (case != .before_invocation)
            try updateManagedState(testing.allocator, root, intent, action, &.{}, true)
        else
            @as(Digest, @splat('0'));
        if (case == .wrong_intent) outcome.intent_sha256 = @splat('2');
        if (case == .wrong_action) outcome.action.ordinal += 1;
        if (case == .cancelled) {
            outcome.disposition = .cancelled;
            outcome.exit_code = null;
            outcome.terminated_process_group = true;
        }
        sealScriptOutcome(&outcome);
        if (case != .missing) try publishScriptOutcome(testing.allocator, root, outcome);
        if (case != .in_flight)
            try appendProgress(testing.allocator, root, intent, action, .outcome, .exited, if (case == .wrong_evidence) @as(Digest, @splat('0')) else outcome.digest_sha256);
        if (case == .completed or case == .wrong_completion)
            try appendProgress(testing.allocator, root, intent, action, .completed, .succeeded, if (case == .wrong_completion) @as(Digest, @splat('0')) else checkpoint);
        if (case == .newer_invocation) {
            const newer: Action = .{
                .kind = .script,
                .program_step = 7,
                .substep = 1,
                .ordinal = 3,
            };
            try appendProgress(testing.allocator, root, intent, newer, .prepared, .none, null);
            try appendProgress(testing.allocator, root, intent, newer, .in_flight, .none, null);
        }
        if (case == .in_flight or case == .outcome or case == .completed) {
            try testing.expectEqual(action, (try recordedTransientScriptAction(testing.allocator, root, intent)).?);
        } else try testing.expectError(error.InvalidManagedState, recordedTransientScriptAction(testing.allocator, root, intent));
    }
}

test "native_recovery.test.directory membership recovery is limited to recorded journal paths" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const testing = std.testing;
    const mutation = @import("root_mutation.zig");
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    for ([_][]const u8{ "var", "var/lib", root_operation.namespace_path, "tracked" }) |path|
        try root.ensureDirectory(try root_fs.Path.init(path), root_fs.default_directory_permissions);
    const payload = try root_fs.Path.init("tracked/payload");
    try root.publishFile(payload, "original", .{});
    const original = try root.entry(payload);
    var plan = switch (try mutation.preflight(testing.allocator, root, .{ .intents = &.{.{ .file = .{
        .path = payload.text,
        .bytes = "incoming",
        .mode = original.mode,
        .uid = original.uid,
        .gid = original.gid,
        .modified_nanoseconds = original.modified_nanoseconds,
    } }} })) {
        .plan => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer plan.deinit();
    const outcome = testScriptOutcome();
    const intent = outcome.intent_sha256;
    try initializeProgress(testing.allocator, root, intent);
    try initializeManagedState(testing.allocator, root, intent);
    try appendProgress(testing.allocator, root, intent, outcome.action, .prepared, .none, null);
    try appendProgress(testing.allocator, root, intent, outcome.action, .in_flight, .none, null);
    try publishScriptOutcome(testing.allocator, root, outcome);
    _ = try updateManagedState(testing.allocator, root, intent, outcome.action, &.{ "tracked", payload.text }, true);
    try appendProgress(testing.allocator, root, intent, outcome.action, .outcome, .exited, outcome.digest_sha256);
    try validateScriptMutationCheckpoint(testing.allocator, root, intent, outcome.action, plan.steps, original.device, true, false);
    try root.removeFile(payload);
    try testing.expectError(error.ManagedStateChanged, validateScriptMutationCheckpoint(
        testing.allocator,
        root,
        intent,
        outcome.action,
        plan.steps,
        original.device,
        true,
        false,
    ));
    try validateScriptMutationCheckpoint(testing.allocator, root, intent, outcome.action, plan.steps, original.device, true, true);
    try root.publishFile(try root_fs.Path.init("tracked/unrecorded"), "unexpected member", .{});
    try testing.expectError(error.ManagedStateChanged, validateScriptMutationCheckpoint(
        testing.allocator,
        root,
        intent,
        outcome.action,
        plan.steps,
        original.device,
        true,
        false,
    ));
    try testing.expectError(error.ManagedStateChanged, validateScriptMutationCheckpoint(
        testing.allocator,
        root,
        intent,
        outcome.action,
        plan.steps,
        original.device,
        true,
        true,
    ));
}

test "native_recovery.test.unpack inputs cannot be rebound by script or publication checkpoints" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const testing = std.testing;
    for (0..4) |change| {
        var temporary = testing.tmpDir(.{ .iterate = true });
        defer temporary.cleanup();
        const root = root_fs.Root.init(testing.io, temporary.dir);
        for ([_][]const u8{ "var", "var/lib", root_operation.namespace_path }) |path|
            try root.ensureDirectory(try root_fs.Path.init(path), root_fs.default_directory_permissions);
        const intent: Digest = @splat('1');
        const initial: Action = .{ .kind = .verification, .program_step = 0, .substep = 0, .ordinal = 0 };
        const publication: Action = .{ .kind = .filesystem, .program_step = 7, .substep = 0, .ordinal = 0 };
        const script: Action = .{ .kind = .script, .program_step = 8, .substep = 0, .ordinal = 0 };
        var buffer: [128]u8 = undefined;
        const path = try root_fs.Path.init(try unpackDiversionPath(7, &buffer));
        try initializeProgress(testing.allocator, root, intent);
        try initializeManagedState(testing.allocator, root, intent);
        try root.publishFile(path, "unobserved input", .{});
        try testing.expectError(error.ManagedStateChanged, updateManagedState(testing.allocator, root, intent, publication, &.{path.text}, false));
        try root.removeFile(path);
        _ = try updateManagedState(testing.allocator, root, intent, initial, &.{path.text}, false);
        try root.publishFile(path, "original bound input", .{});
        try testing.expectError(error.ManagedStateChanged, updateManagedState(testing.allocator, root, intent, script, &.{}, true));
        for ([_]Action{
            .{ .kind = .filesystem, .program_step = 8, .substep = 0, .ordinal = 0 },
            .{ .kind = .filesystem, .program_step = 7, .substep = 1, .ordinal = 0 },
            .{ .kind = .filesystem, .program_step = 7, .substep = 0, .ordinal = 1 },
        }) |wrong_anchor|
            try testing.expectError(error.ManagedStateChanged, updateManagedState(testing.allocator, root, intent, wrong_anchor, &.{}, false));
        try testing.expectError(error.ManagedStateChanged, updateManagedState(testing.allocator, root, intent, publication, &.{}, true));
        _ = try updateManagedState(testing.allocator, root, intent, publication, &.{}, false);
        _ = try updateManagedState(testing.allocator, root, intent, script, &.{}, true);
        try discardTransientManagedState(testing.allocator, root, intent);
        switch (change) {
            0 => try root.publishFile(path, "replacement recipe", .{ .overwrite = .replace }),
            1 => try root.applyMetadata(path, .{ .mode = (try root.entry(path)).mode ^ 0o040 }),
            2 => try root.removeFile(path),
            3 => try root.publishFile(path, "original bound input", .{ .overwrite = .replace }),
            else => unreachable,
        }
        for ([_]Action{ script, publication }) |action| {
            for ([_]bool{ false, true }) |transient|
                try testing.expectError(error.ManagedStateChanged, updateManagedState(testing.allocator, root, intent, action, &.{}, transient));
        }
    }
}

test "native_recovery.test.route settlement inputs bind once at their unpack anchor" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const testing = std.testing;
    for (0..3) |change| {
        var temporary = testing.tmpDir(.{ .iterate = true });
        defer temporary.cleanup();
        const root = root_fs.Root.init(testing.io, temporary.dir);
        for ([_][]const u8{
            "var",
            "var/lib",
            root_operation.namespace_path,
        }) |path|
            try root.ensureDirectory(
                try root_fs.Path.init(path),
                root_fs.default_directory_permissions,
            );
        const intent: Digest = @splat('1');
        const publication: Action = .{
            .kind = .filesystem,
            .program_step = 7,
            .substep = 0,
            .ordinal = 0,
        };
        const script: Action = .{
            .kind = .script,
            .program_step = 8,
            .substep = 0,
            .ordinal = 0,
        };
        var buffer: [128]u8 = undefined;
        const path = try root_fs.Path.init(
            try unpackRouteSettlementPath(7, &buffer),
        );
        try initializeProgress(testing.allocator, root, intent);
        try initializeManagedState(testing.allocator, root, intent);
        try root.publishFile(path, "bound route contract", .{});
        try testing.expectError(
            error.ManagedStateChanged,
            updateManagedState(
                testing.allocator,
                root,
                intent,
                script,
                &.{path.text},
                true,
            ),
        );
        _ = try updateManagedState(
            testing.allocator,
            root,
            intent,
            publication,
            &.{path.text},
            false,
        );
        _ = try updateManagedState(
            testing.allocator,
            root,
            intent,
            script,
            &.{},
            true,
        );
        try discardTransientManagedState(
            testing.allocator,
            root,
            intent,
        );
        switch (change) {
            0 => try root.publishFile(
                path,
                "replacement contract",
                .{ .overwrite = .replace },
            ),
            1 => try root.applyMetadata(
                path,
                .{ .mode = (try root.entry(path)).mode ^ 0o040 },
            ),
            2 => try root.removeFile(path),
            else => unreachable,
        }
        for ([_]Action{ publication, script }) |action|
            try testing.expectError(
                error.ManagedStateChanged,
                updateManagedState(
                    testing.allocator,
                    root,
                    intent,
                    action,
                    &.{},
                    action.kind == .script,
                ),
            );
    }
}

test "native_recovery.test.route settlement script publication requires an absent anchor" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const testing = std.testing;
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    for ([_][]const u8{
        "var",
        "var/lib",
        root_operation.namespace_path,
    }) |path|
        try root.ensureDirectory(
            try root_fs.Path.init(path),
            root_fs.default_directory_permissions,
        );
    const intent: Digest = @splat('1');
    const initial: Action = .{
        .kind = .verification,
        .program_step = 0,
        .substep = 0,
        .ordinal = 0,
    };
    const script: Action = .{
        .kind = .script,
        .program_step = 8,
        .substep = 0,
        .ordinal = 0,
    };
    var buffer: [128]u8 = undefined;
    const path = try root_fs.Path.init(
        try unpackRouteSettlementPath(7, &buffer),
    );
    try initializeProgress(testing.allocator, root, intent);
    try initializeManagedState(testing.allocator, root, intent);
    _ = try updateManagedState(
        testing.allocator,
        root,
        intent,
        initial,
        &.{path.text},
        false,
    );
    try root.publishFile(path, "bound route contract", .{});
    _ = try updateManagedState(
        testing.allocator,
        root,
        intent,
        script,
        &.{path.text},
        true,
    );
    const bytes = (try readManagedFile(
        testing.allocator,
        root,
        intent,
        path.text,
        1024,
    )).?;
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("bound route contract", bytes);
}

test "native_recovery.test.route settlement cleanup validates all inputs before removal" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const testing = std.testing;
    for ([_]bool{ false, true }) |drift| {
        var temporary = testing.tmpDir(.{ .iterate = true });
        defer temporary.cleanup();
        const root = root_fs.Root.init(testing.io, temporary.dir);
        try root.createDirectoryPath(
            try root_fs.Path.init(root_operation.namespace_path),
            .fromMode(0o755),
        );
        const intent: Digest = @splat('1');
        const anchor: Action = .{
            .kind = .filesystem,
            .program_step = 7,
            .substep = 0,
            .ordinal = 0,
        };
        try initializeProgress(testing.allocator, root, intent);
        try initializeManagedState(testing.allocator, root, intent);
        var unpack_buffer: [128]u8 = undefined;
        const unpack_path = try unpackDiversionPath(7, &unpack_buffer);
        _ = try updateManagedState(
            testing.allocator,
            root,
            intent,
            .{
                .kind = .verification,
                .program_step = 0,
                .substep = 0,
                .ordinal = 0,
            },
            &.{unpack_path},
            false,
        );
        var route_buffer: [128]u8 = undefined;
        const route_path = try unpackRouteSettlementPath(7, &route_buffer);
        try root.publishFile(
            try root_fs.Path.init(unpack_path),
            "bound unpack input",
            .{},
        );
        try root.publishFile(
            try root_fs.Path.init(route_path),
            "bound route input",
            .{},
        );
        _ = try updateManagedState(
            testing.allocator,
            root,
            intent,
            anchor,
            &.{ unpack_path, route_path },
            false,
        );
        if (drift)
            try root.publishFile(
                try root_fs.Path.init(route_path),
                "drifted route input",
                .{ .overwrite = .replace },
            );
        if (drift) {
            try testing.expectError(
                error.ManagedStateChanged,
                cleanupDiversionEvidence(
                    testing.allocator,
                    root,
                    intent,
                ),
            );
            try testing.expect(
                try root.entryIfExists(
                    try root_fs.Path.init(unpack_path),
                ) != null,
            );
            try testing.expect(
                try root.entryIfExists(
                    try root_fs.Path.init(route_path),
                ) != null,
            );
        } else {
            try cleanupDiversionEvidence(
                testing.allocator,
                root,
                intent,
            );
            try testing.expect(
                try root.entryIfExists(
                    try root_fs.Path.init(unpack_path),
                ) == null,
            );
            try testing.expect(
                try root.entryIfExists(
                    try root_fs.Path.init(route_path),
                ) == null,
            );
        }
    }
}

test "native_recovery.test.stable late-journal checkpoint rejects unrelated drift before replay" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const testing = std.testing;
    const mutation = @import("root_mutation.zig");
    var temporary = testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    for ([_][]const u8{ "var", "var/lib", root_operation.namespace_path, "tracked" }) |path|
        try root.ensureDirectory(try root_fs.Path.init(path), root_fs.default_directory_permissions);
    const obsolete = try root_fs.Path.init("tracked/obsolete");
    const payload = try root_fs.Path.init("payload");
    try root.publishFile(obsolete, "old", .{});
    try root.publishFile(payload, "committed", .{});
    const device = (try root.entry(obsolete)).device;
    var plan = switch (try mutation.preflight(testing.allocator, root, .{
        .intents = &.{.{ .remove = .{ .path = obsolete.text } }},
    })) {
        .plan => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer plan.deinit();
    const intent: Digest = @splat('1');
    const action: Action = .{ .kind = .filesystem, .program_step = 7, .substep = 1, .ordinal = 0 };
    try initializeProgress(testing.allocator, root, intent);
    try initializeManagedState(testing.allocator, root, intent);
    _ = try updateManagedState(testing.allocator, root, intent, action, &.{ "tracked", obsolete.text, payload.text }, false);
    try root.removeFile(obsolete);
    try validateStableMutationCheckpoint(testing.allocator, root, intent, plan.steps, device);
    const drift = try root_fs.Path.init("tracked/unrecorded");
    try root.publishFile(drift, "unrelated", .{});
    try testing.expectError(error.ManagedStateChanged, validateStableMutationCheckpoint(testing.allocator, root, intent, plan.steps, device));
    try root.removeFile(drift);
    try validateStableMutationCheckpoint(testing.allocator, root, intent, plan.steps, device);
    try root.publishFile(payload, "external payload", .{ .overwrite = .replace });
    try testing.expectError(error.ManagedStateChanged, validateStableMutationCheckpoint(testing.allocator, root, intent, plan.steps, device));
}

fn checkTriggerEventBinding() !void {
    const listeners = [_]TriggerListener{.{
        .trigger = "demo-trigger",
        .package = "receiver",
        .architecture = "amd64",
        .await_mode = .noawait,
    }};
    var events = [_]TriggerEvent{.{
        .origin = .dynamic,
        .source_package = "source",
        .source_architecture = "amd64",
        .trigger = "demo-trigger",
        .activation_awaits = false,
        .listeners = &listeners,
    }};
    var document: TriggerEventsDocument = .{
        .intent_sha256 = @splat('1'),
        .events = &events,
        .digest_sha256 = @splat('0'),
    };
    document.digest_sha256 = digestValue(
        "debz-native-trigger-events-v1\x00",
        document,
    );
    try validateTriggerEvents(document);
    events[0].activation_awaits = true;
    try std.testing.expectError(
        error.DigestMismatch,
        validateTriggerEvents(document),
    );
}

fn checkManagedStateBinding() !void {
    const entries = [_]ManagedEntry{.{
        .path = "usr/share/demo/data",
        .kind = .regular,
        .mode = 0o644,
        .uid = 0,
        .gid = 0,
        .device = 1,
        .inode = 2,
        .link_count = 1,
        .modified_nanoseconds = 3,
        .change_nanoseconds = 4,
        .size = 5,
        .content_sha256 = @splat('a'),
    }};
    var snapshot: ManagedSnapshot = .{
        .action = .{
            .kind = .filesystem,
            .program_step = 4,
            .substep = 0,
            .ordinal = 0,
        },
        .progress_head_sha256 = @splat('b'),
        .entries = &entries,
        .digest_sha256 = @splat('0'),
    };
    sealManagedSnapshot(&snapshot);
    const history = [_]ManagedBoundary{.{
        .generation = 1,
        .action = snapshot.action,
        .snapshot_sha256 = snapshot.digest_sha256,
        .transient = false,
    }};
    var document: ManagedStateDocument = .{
        .intent_sha256 = @splat('c'),
        .generation = 1,
        .history = &history,
        .stable = snapshot,
        .transient = null,
        .digest_sha256 = @splat('0'),
    };
    document.digest_sha256 = digestValue(
        "debz-native-managed-state-v1\x00",
        document,
    );
    try validateManagedDocument(document);
    document.generation += 1;
    try std.testing.expectError(
        error.DigestMismatch,
        validateManagedDocument(document),
    );
}

pub fn testContracts() !void {
    try checkProgressChain();
    try checkIntentBinding();
    try checkScriptOutcomeBinding();
    try checkTriggerEventBinding();
    try checkManagedStateBinding();
}

test "native_recovery.test.progress chain rejects reordered records" {
    try checkProgressChain();
}

test "native_recovery.test.helper publication probe and unknown outcome transitions are exact" {
    const testing = std.testing;
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    try root.createDirectoryPath(
        try root_fs.Path.init(root_operation.namespace_path),
        root_fs.default_directory_permissions,
    );
    const intent: Digest = @splat('a');
    try initializeBootstrapProgress(testing.allocator, root, intent);
    const source: Action = .{
        .kind = .helper,
        .program_step = 7,
        .substep = helper_source_substep,
        .ordinal = 0,
    };
    const probe: Action = .{
        .kind = .helper,
        .program_step = 7,
        .substep = helper_probe_substep,
        .ordinal = 0,
    };
    try appendProgress(testing.allocator, root, intent, source, .prepared, .none, null);
    try appendProgress(testing.allocator, root, intent, source, .completed, .applied, null);
    try appendProgress(testing.allocator, root, intent, probe, .prepared, .none, null);
    try appendProgress(testing.allocator, root, intent, probe, .in_flight, .none, null);
    try appendProgress(testing.allocator, root, intent, probe, .outcome, .exited, @splat('b'));
    try appendProgress(testing.allocator, root, intent, probe, .completed, .succeeded, null);
    var progress = try readProgress(testing.allocator, root);
    defer progress.deinit();
    try testing.expectEqual(Stage.completed, latest(progress.document, source).?.stage);
    try testing.expectEqual(Stage.completed, latest(progress.document, probe).?.stage);
    try testing.expectError(
        error.InvalidProgress,
        appendProgress(testing.allocator, root, intent, source, .in_flight, .none, null),
    );
    var invalid_probe = probe;
    invalid_probe.ordinal = 1;
    try appendProgress(testing.allocator, root, intent, invalid_probe, .prepared, .none, null);
    try appendProgress(testing.allocator, root, intent, invalid_probe, .in_flight, .none, null);
    try testing.expectError(
        error.InvalidProgress,
        appendProgress(testing.allocator, root, intent, invalid_probe, .outcome, .exited, null),
    );
    const wrong: Action = .{
        .kind = .helper,
        .program_step = 7,
        .substep = 1,
        .ordinal = 0,
    };
    try testing.expectError(
        error.InvalidProgress,
        appendProgress(testing.allocator, root, intent, wrong, .prepared, .none, null),
    );
}

test "native_recovery.test.intent binds immutable execution evidence" {
    try checkIntentBinding();
}

test "native_recovery.test.script outcome rejects changed disposition evidence" {
    try checkScriptOutcomeBinding();
}

test "native_recovery.test.trigger events bind ordered activation evidence" {
    try checkTriggerEventBinding();
}
