const std = @import("std");
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
pub const authorization_name = "native-transaction-authorization-v1.json";
pub const program_name = "native-transaction-program-v1.json";
pub const blob_prefix = "native-recovery-v1-blob-";
pub const workspace_directory = "var/lib/debz/native-recovery-v1";
pub const artifact_directory = workspace_directory ++ "/artifacts";
pub const database_directory = workspace_directory ++ "/database";
pub const scripts_directory = workspace_directory ++ "/scripts";
pub const request_directory = workspace_directory ++ "/request";
pub const script_outcome_prefix = "native-script-outcome-v1-";
pub const trigger_events_path = "var/lib/debz/native-trigger-events-v1.json";
pub const managed_state_path = "var/lib/debz/native-managed-state-v1.json";
pub const maximum_intent_bytes: usize = 16 * 1024 * 1024;
pub const maximum_progress_bytes: usize = 64 * 1024 * 1024;
pub const maximum_records: usize = 200_000;
pub const maximum_blobs: usize = 200_000;
pub const crash_exit_code: u8 = 86;

pub const CrashPoint = enum {
    after_execution_intent,
    during_filesystem_publication,
    during_database_publication,
    after_script_prepared,
    after_script_outcome,
    after_script_return_before_outcome,
    after_upgrade_postrm_return_before_outcome,
    after_failure_outcome,
    after_trigger_outcome,
    after_provenance,
    after_active_clear,
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
    sha256: Digest,
    mode: u32,
    entry_kind: EntryKind,
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
    authorization_path: []const u8,
    program_path: []const u8,
    blobs: []const Blob,
    digest_sha256: Digest,
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
        "debz-native-execution-intent-v1\x00",
        intent.*,
    );
}

pub fn validateIntent(intent: Intent) !void {
    if (!std.mem.eql(
        u8,
        intent.schema,
        "https://debz.dev/schema/native-execution-intent-v1",
    ) or intent.version != 1)
        return error.UnsupportedSchema;
    if (!absolute_path.root(intent.install_root) or
        intent.install_root.len > 4096 or
        !std.mem.eql(u8, intent.authorization_path, authorization_name) or
        !std.mem.eql(u8, intent.program_path, program_name) or
        intent.packages.len > maximum_records or
        intent.ordered_actions.len > maximum_records)
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
            parseDigest(blob.sha256) == null or
            blob.entry_kind != .regular or
            blob.key.len == 0 or blob.key.len > 4096 or
            blob.logical_path.len == 0 or blob.logical_path.len > 4096)
            return error.InvalidBlob;
        _ = root_fs.Path.init(blob.storage_path) catch return error.InvalidBlob;
        _ = root_fs.Path.init(blob.logical_path) catch return error.InvalidBlob;
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
    if (total_blob_bytes > 8 * 1024 * 1024 * 1024)
        return error.LimitExceeded;
    var payload = intent;
    const expected = payload.digest_sha256;
    payload.digest_sha256 = @splat('0');
    if (!std.mem.eql(
        u8,
        &expected,
        &digestValue("debz-native-execution-intent-v1\x00", payload),
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
    schema: []const u8 = "https://debz.dev/schema/native-execution-progress-v1",
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

fn sealRecord(record: *Record) void {
    record.digest_sha256 = @splat('0');
    record.digest_sha256 = digestValue(
        "debz-native-execution-progress-record-v1\x00",
        record.*,
    );
}

fn validateProgress(document: ProgressDocument) !void {
    if (!std.mem.eql(
        u8,
        document.schema,
        "https://debz.dev/schema/native-execution-progress-v1",
    ) or document.version != 1 or document.records.len > maximum_records)
        return error.InvalidProgress;
    var previous: Digest = @splat('0');
    var terminal_seen = false;
    for (document.records, 0..) |record, index| {
        if (record.sequence != index or terminal_seen or
            !std.mem.eql(u8, &record.previous_sha256, &previous))
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
                        prior.?.result == .rolled_back)))
                return error.InvalidProgress,
            .in_flight => if (record.result != .none or prior == null or
                prior.?.stage != .prepared or
                (record.action.kind != .script and
                    record.action.kind != .compensation and
                    record.action.kind != .trigger))
                return error.InvalidProgress,
            .outcome => if (prior == null or prior.?.stage != .in_flight or
                (record.result != .exited and
                    record.result != .not_started and
                    record.result != .recovery_required) or
                record.evidence_sha256 == null)
                return error.InvalidProgress,
            .completed => {
                if (record.result == .none or prior == null)
                    return error.InvalidProgress;
                switch (record.action.kind) {
                    .script, .compensation, .trigger => if (prior.?.stage != .outcome)
                        return error.InvalidProgress,
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
            &digestValue(
                "debz-native-execution-progress-record-v1\x00",
                payload,
            ),
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
        &digestValue("debz-native-execution-progress-v1\x00", payload),
    )) return error.DigestMismatch;
}

pub fn initializeProgress(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent_sha256: Digest,
) !void {
    var document: ProgressDocument = .{
        .intent_sha256 = intent_sha256,
        .records = &.{},
        .head_sha256 = @splat('0'),
        .digest_sha256 = @splat('0'),
    };
    document.digest_sha256 = digestValue(
        "debz-native-execution-progress-v1\x00",
        document,
    );
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
    sealRecord(&record);
    records[records.len - 1] = record;
    var document: ProgressDocument = .{
        .intent_sha256 = intent_sha256,
        .records = records,
        .head_sha256 = record.digest_sha256,
        .digest_sha256 = @splat('0'),
    };
    document.digest_sha256 = digestValue(
        "debz-native-execution-progress-v1\x00",
        document,
    );
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

fn observeManagedEntry(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path_text: []const u8,
    observed_bytes: *u64,
) !ManagedEntry {
    const path = try root_fs.Path.init(path_text);
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
            var digest: [32]u8 = undefined;
            Sha256.hash(observation.bytes, &digest, .{});
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
            result.content_sha256 = hexDigest(digest);
            break :block result;
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
            const DirectoryMember = struct {
                name: []const u8,
                kind: []const u8,
            };
            const members = try allocator.alloc(
                DirectoryMember,
                observation.members.len,
            );
            defer allocator.free(members);
            for (observation.members, 0..) |member, index| {
                members[index] = .{
                    .name = member.name,
                    .kind = @tagName(member.kind),
                };
            }
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
            result.directory_sha256 = digestValue(
                "debz-native-managed-directory-v1\x00",
                members,
            );
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
        _ = root_fs.Path.init(entry.path) catch
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
        _ = try root_fs.Path.init(path);
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
    var digest: [32]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &hexDigest(digest), &blob.sha256))
        return error.BlobDigestMismatch;
    return bytes;
}

pub fn cleanup(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent: Intent,
) !void {
    _ = allocator;
    for (intent.blobs) |blob| {
        root.removeFile(try root_fs.Path.init(blob.storage_path)) catch |err|
            switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
    }
    for ([_][]const u8{
        progress_path,
        trigger_events_path,
        managed_state_path,
        intent_path,
        root_operation.namespace_path ++ "/" ++ authorization_name,
        root_operation.namespace_path ++ "/" ++ program_name,
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
    sealRecord(&first);
    var second: Record = .{
        .sequence = 1,
        .action = first.action,
        .stage = .completed,
        .result = .applied,
        .previous_sha256 = first.digest_sha256,
        .digest_sha256 = @splat('0'),
    };
    sealRecord(&second);
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
    intent.defer_triggers = true;
    try std.testing.expectError(error.DigestMismatch, validateIntent(intent));
}

fn checkScriptOutcomeBinding() !void {
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
    try validateScriptOutcome(outcome);
    outcome.exit_code = null;
    try std.testing.expectError(
        error.InvalidScriptOutcome,
        validateScriptOutcome(outcome),
    );
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

test "native_recovery.test.intent binds immutable execution evidence" {
    try checkIntentBinding();
}

test "native_recovery.test.script outcome rejects changed disposition evidence" {
    try checkScriptOutcomeBinding();
}

test "native_recovery.test.trigger events bind ordered activation evidence" {
    try checkTriggerEventBinding();
}
