//! Crash-safe native mutation layer for one selected root.
//!
//! Everything the native transaction engine writes into a root goes through
//! this module. A caller states a complete, ordered set of typed intents;
//! preflight resolves each one against the current root into an exact
//! precondition and an exact desired state, and the result is published as a
//! versioned durable journal plus a chained write-ahead progress log before
//! the first target byte changes. Application then walks explicit durability
//! boundaries - staged, backup captured, published, metadata applied, parent
//! synced, verified, completed - and every boundary compares the observed
//! state to the recorded expectation instead of assuming it.
//!
//! The layer is deliberately reversible. A backup is captured before a target
//! is replaced or removed and is released only after the whole transaction
//! verifies, so an interrupted transaction can always be restored to the
//! recorded old state without re-supplying any content. Recovery therefore
//! either restores the old state, finishes releasing a transaction that was
//! already verified, or publishes a durable typed recovery requirement; it
//! never guesses, and an unresolved journal refuses every further mutation.
//!
//! What this module deliberately does not do: it does not run maintainer
//! scripts, process triggers, decide package ownership, or interpret unpack
//! semantics. Those slices compose the primitives here. Arbitrary maintainer
//! script side effects are not rollbackable and are never journalled as if
//! they were; only filesystem and package-database mutations this layer
//! performs itself are recorded, and the handoff boundary to script and
//! trigger work stays explicit.

const std = @import("std");
const builtin = @import("builtin");
const absolute_path = @import("absolute_path.zig");
const archive_application = @import("archive_application.zig");
const package_database = @import("package_database.zig");
const package_database_changes = @import("package_database_changes.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const transaction_executor = @import("transaction_executor.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Io = std.Io;

pub const schema_id = "https://debz.dev/schema/root-mutation-journal-v1";
pub const schema_version: u32 = 1;

/// Progress records are a separate append-only log so publishing a boundary
/// costs one bounded append and one fsync rather than a rewrite of the whole
/// journal. Its own version travels with every record.
pub const progress_schema_id = "https://debz.dev/schema/root-mutation-progress-v1";
pub const progress_schema_version: u32 = 1;

/// Absolute ceilings. `Limits` may tighten them; nothing may raise them.
pub const maximum_document_bytes: usize = 64 * 1024 * 1024;
pub const maximum_progress_bytes: usize = 128 * 1024 * 1024;
pub const maximum_steps: usize = 100_000;
pub const maximum_step_dependencies: usize = 8;
pub const maximum_path_bytes: usize = root_fs.maximum_path_bytes;
pub const maximum_link_target_bytes: usize = root_fs.maximum_link_target_bytes;
/// One progress record is fixed shape, so its length is a hard constant.
pub const progress_record_bytes: usize = 16 + 1 + 7 + 1 + 8 + 1 + 24 + 1 + 64 + 1;
/// Permission and special mode bits only; a file-type bit never appears in a
/// modeled mode.
pub const maximum_mode: u32 = 0o7777;
/// The kernel timestamp range this layer can publish. `std.Io.Timestamp` is
/// 96-bit, so a wider journal value could never be applied and is refused
/// while it is still only data.
pub const maximum_timestamp_nanoseconds: i128 = std.math.maxInt(i96);
pub const minimum_timestamp_nanoseconds: i128 = std.math.minInt(i96);

/// Durable namespace, shared with `root_operation` so one root has exactly one
/// debz-owned directory.
pub const namespace_path = root_operation.namespace_path;
pub const journal_name = "root-mutation-v1.json";
pub const progress_name = "root-mutation-v1.log";
pub const workspace_name = "mutation";
pub const staging_name = "staging";
pub const backup_name = "backup";

pub const journal_path = namespace_path ++ "/" ++ journal_name;
pub const progress_path = namespace_path ++ "/" ++ progress_name;
pub const workspace_path = namespace_path ++ "/" ++ workspace_name;
pub const staging_path = workspace_path ++ "/" ++ staging_name;
pub const backup_path = workspace_path ++ "/" ++ backup_name;

/// The workspace is private to root. Staging and backup entries are created
/// exclusively, so a planted entry fails closed instead of being followed.
const workspace_permissions: Io.File.Permissions =
    if (builtin.os.tag == .windows) .default_dir else .fromMode(0o700);
const journal_permissions: Io.File.Permissions =
    if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);
const staged_permissions: Io.File.Permissions =
    if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);

pub const Limits = struct {
    max_steps: usize = maximum_steps,
    /// Total bytes the staging area may hold for one transaction.
    max_staging_bytes: u64 = 8 * 1024 * 1024 * 1024,
    max_document_bytes: usize = maximum_document_bytes,
    max_progress_bytes: usize = maximum_progress_bytes,
    /// Bound on the bytes one `copy_file` source may hold.
    max_copy_bytes: usize = 512 * 1024 * 1024,
};

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

pub const Surface = enum {
    journal,
    progress,
    preflight,
    workspace,
    staging,
    backup,
    publication,
    metadata,
    verification,
    recovery,
    database,
};

pub const Code = enum {
    // Preflight refusals. Every one of these happens before a target byte
    // can change.
    invalid_path,
    unsupported_kind,
    path_collision,
    path_alias,
    ancestor_conflict,
    symbolic_link_component,
    hard_link_ambiguous,
    hard_link_source_invalid,
    directory_not_empty,
    target_present,
    target_absent,
    cross_device,
    capacity_exceeded,
    numeric_overflow,
    step_limit,
    dependency_invalid,
    content_digest_mismatch,
    artifact_binding_mismatch,
    database_plan_mismatch,
    metadata_unsupported,

    // Durable state refusals.
    journal_corrupt,
    journal_present,
    journal_absent,
    progress_corrupt,
    progress_stale,
    schema_unsupported,
    document_too_large,
    attempt_mismatch,
    stale_attempt,
    lock_lost,
    root_mismatch,

    // Application and recovery failures.
    external_modification,
    precondition_failed,
    verification_failed,
    backup_missing,
    staging_missing,
    io_failed,
    recovery_required,
    canceled,
    deadline_exceeded,
    out_of_memory,
};

/// A typed refusal. Diagnostics never own memory: `path` references caller
/// input, the plan arena, or static text.
pub const Diagnostic = struct {
    surface: Surface,
    code: Code,
    /// Index of the step the failure belongs to, when there is one.
    step: ?u32 = null,
    path: []const u8 = "",
    /// The durability boundary that failed, when the failure happened during
    /// application or recovery.
    boundary: ?Boundary = null,
};

pub const Error = error{
    OutOfMemory,
    /// Injected power-loss point. The engine returns without cleaning up, so
    /// the durable state is exactly what a real crash would have left.
    SimulatedCrash,
    IoFailed,
    Rejected,
    JournalCorrupt,
    JournalPresent,
    JournalAbsent,
    ProgressCorrupt,
    StaleWriter,
    AttemptMismatch,
    AttemptNotMutable,
    StaleAttempt,
    LockLost,
    RootMismatch,
    RecoveryRequired,
    ExternalModification,
    VerificationFailed,
    Canceled,
    DeadlineExceeded,
    StoreFailed,
    ContentUnavailable,
    ContentMismatch,
    UnsupportedSchema,
    DocumentTooLarge,
    NonCanonicalDocument,
    DigestMismatch,
};

// ---------------------------------------------------------------------------
// Modeled state
// ---------------------------------------------------------------------------

/// The only path kinds the native engine acts on. Every other kind fails
/// closed during preflight.
pub const Kind = enum {
    regular,
    directory,
    symlink,

    fn fromFileKind(kind: Io.File.Kind) ?Kind {
        return switch (kind) {
            .file => .regular,
            .directory => .directory,
            .sym_link => .symlink,
            else => null,
        };
    }
};

/// Exact metadata a step expects or publishes.
///
/// `modified_nanoseconds` is meaningful for regular files and symbolic links
/// only. A directory's modification time is derived from its own entries, so
/// the plan's later steps would invalidate it the moment they publish a child;
/// it is therefore normalized to zero for directories and is neither applied
/// nor asserted rather than being published and then quietly ignored.
pub const Metadata = struct {
    mode: u32,
    uid: u32,
    gid: u32,
    modified_nanoseconds: i128,

    pub fn eql(self: Metadata, other: Metadata) bool {
        return self.mode == other.mode and self.uid == other.uid and
            self.gid == other.gid and
            self.modified_nanoseconds == other.modified_nanoseconds;
    }
};

/// The exact observed or desired state of one path.
pub const State = struct {
    kind: Kind,
    metadata: Metadata,
    /// Regular files only. Byte length of the content.
    size: u64 = 0,
    /// Regular files only. SHA-256 over the exact bytes.
    content_sha256: ?[32]u8 = null,
    /// Symbolic links only. The exact stored target bytes.
    link_target: ?[]const u8 = null,
    /// Link identity of the observed inode. Zero in a desired state, which
    /// cannot predict an inode number.
    inode: u64 = 0,
    link_count: u64 = 0,
};

/// A precondition, which is either "nothing is here" or an exact state.
pub const Expectation = union(enum) {
    absent,
    present: State,
};

pub const Overwrite = enum {
    /// The target must not exist when the step runs.
    require_absent,
    /// An existing target is backed up and replaced.
    replace,
};

pub const Removal = enum {
    /// The target must exist when the step runs.
    require_present,
    /// An already absent target satisfies the step without any mutation.
    allow_absent,
};

pub const StepKind = enum {
    /// Publish exact regular-file content supplied by the caller.
    publish_file,
    /// Publish regular-file content copied from another path in the same root
    /// before that path is itself republished.
    copy_file,
    publish_symlink,
    publish_hard_link,
    create_directory,
    /// Change only the mode, ownership, or modification time of an existing
    /// path.
    set_metadata,
    /// Remove a regular file, hard link, or symbolic link.
    remove_path,
    remove_directory,
};

/// Binding of one step's content back to the validated archive it came from.
/// The engine reproves it immediately before the content is staged.
pub const ArtifactBinding = struct {
    index: u32,
    application_sha256: [32]u8,
};

/// One fully resolved mutation intent. Everything an executor or a recovery
/// pass needs is here; nothing is recomputed from the caller's inputs.
pub const Step = struct {
    index: u32,
    kind: StepKind,
    /// Root-relative canonical path.
    path: []const u8,
    /// Steps that must have completed before this one runs. Every entry is
    /// strictly smaller than `index`, so the graph is acyclic by construction.
    requires: []const u32,
    overwrite: Overwrite,
    removal: Removal,
    expected: Expectation,
    desired: Expectation,
    /// `copy_file` and `publish_hard_link` source, root-relative.
    source: ?[]const u8 = null,
    source_sha256: ?[32]u8 = null,
    artifact: ?ArtifactBinding = null,
    /// Name inside `staging/`, when the step materializes new content.
    staging_entry: ?[]const u8 = null,
    /// Name inside `backup/`, when the step captures replaceable content.
    backup_entry: ?[]const u8 = null,

    /// True when the step reaches its desired state without touching the
    /// root, which happens for an already satisfied removal or directory.
    pub fn satisfied(self: Step) bool {
        return switch (self.expected) {
            .absent => switch (self.desired) {
                .absent => true,
                .present => false,
            },
            .present => |expected| switch (self.desired) {
                .absent => false,
                .present => |desired| statesEqual(expected, desired),
            },
        };
    }

    /// The durability boundaries this step passes through, in order.
    pub fn boundaries(self: Step) []const StepState {
        if (self.satisfied()) return &.{.verified};
        return switch (self.kind) {
            .publish_file, .copy_file, .publish_symlink, .publish_hard_link => if (self.needsBackup())
                &.{ .staged, .backup_captured, .published, .parent_synced, .verified }
            else
                &.{ .staged, .published, .parent_synced, .verified },
            .create_directory => if (self.needsBackup())
                &.{ .backup_captured, .published, .metadata_applied, .parent_synced, .verified }
            else
                &.{ .published, .metadata_applied, .parent_synced, .verified },
            .set_metadata => &.{ .metadata_applied, .verified },
            .remove_path => if (self.needsBackup())
                &.{ .backup_captured, .published, .parent_synced, .verified }
            else
                &.{ .published, .parent_synced, .verified },
            .remove_directory => &.{ .published, .parent_synced, .verified },
        };
    }

    /// True when an existing entry must be preserved in the backup area
    /// before the target name is taken over. Directories carry no content, so
    /// their exact old state is preserved by the journal itself.
    pub fn needsBackup(self: Step) bool {
        const expected = switch (self.expected) {
            .absent => return false,
            .present => |value| value,
        };
        return switch (expected.kind) {
            // Only regular-file content needs a physical backup: a symbolic
            // link and a directory are restored exactly from the journal, and
            // hard-linking a symbolic link is not portable.
            .regular => self.kind != .set_metadata,
            .symlink, .directory => false,
        };
    }
};

fn statesEqual(left: State, right: State) bool {
    if (left.kind != right.kind) return false;
    if (!left.metadata.eql(right.metadata)) return false;
    switch (left.kind) {
        .regular => {
            if (left.size != right.size) return false;
            const left_digest = left.content_sha256 orelse return false;
            const right_digest = right.content_sha256 orelse return false;
            if (!std.mem.eql(u8, &left_digest, &right_digest)) return false;
        },
        .symlink => {
            const left_target = left.link_target orelse return false;
            const right_target = right.link_target orelse return false;
            if (!std.mem.eql(u8, left_target, right_target)) return false;
        },
        .directory => {},
    }
    return true;
}

// ---------------------------------------------------------------------------
// Write-ahead protocol
// ---------------------------------------------------------------------------

/// Transaction-level durable stage. The stage decides the direction recovery
/// takes, so it is always published before the work it authorizes.
pub const Stage = enum {
    /// Intents are durable; nothing has been applied.
    prepared,
    /// Application is in progress; recovery restores the recorded old state.
    applying,
    /// A failure, cancellation, or deadline was observed; recovery restores
    /// the recorded old state.
    rolling_back,
    /// Every step reached its desired state; recovery finishes the release.
    verified,
    /// Staging and backup entries are being released after a verified
    /// application.
    completing,
    /// Nothing is owed and the root holds the new state. The journal may be
    /// cleared.
    completed,
    /// Every step was restored; staging and backup entries are being
    /// released. This is a separate stage from `completing` so a crash during
    /// the release still says which state the root holds.
    releasing_rollback,
    /// Nothing is owed and the root holds the recorded old state. The journal
    /// may be cleared.
    rolled_back,
    /// The observed state matches neither the recorded old state nor the
    /// recorded new state. No further mutation is permitted.
    recovery_required,

    /// True while the journal must be resolved before another mutation may
    /// start.
    pub fn blocksMutation(self: Stage) bool {
        return switch (self) {
            .completed, .rolled_back => false,
            else => true,
        };
    }

    /// The direction a recovery pass takes from this stage.
    pub fn direction(self: Stage) Direction {
        return switch (self) {
            .prepared, .applying, .rolling_back => .restore_old,
            .verified, .completing, .completed => .finish_new,
            .releasing_rollback, .rolled_back => .finish_rollback,
            .recovery_required => .refuse,
        };
    }

    /// The terminal stage the release of this stage's direction reaches.
    pub fn terminal(self: Stage) Stage {
        return switch (self.direction()) {
            .finish_new => .completed,
            .restore_old, .finish_rollback => .rolled_back,
            .refuse => .recovery_required,
        };
    }
};

pub const Direction = enum { restore_old, finish_new, finish_rollback, refuse };

/// Per-step durable boundary. The order is total; a step only publishes the
/// boundaries `Step.boundaries` lists for its kind.
pub const StepState = enum(u8) {
    prepared = 0,
    staged = 1,
    backup_captured = 2,
    published = 3,
    metadata_applied = 4,
    parent_synced = 5,
    verified = 6,
    completed = 7,
    /// The step was undone and the recorded old state is back in place.
    reverted = 8,

    pub fn rank(self: StepState) u8 {
        return @intFromEnum(self);
    }
};

/// Every syscall and durability boundary the engine can stop at. The crash
/// injection harness names points with this enum, so a test can prove the
/// outcome of an interruption at each one.
pub const Boundary = enum {
    journal_write,
    journal_sync,
    progress_append,
    progress_sync,
    workspace_create,
    stage_create,
    stage_write,
    stage_sync,
    stage_metadata,
    stage_dir_sync,
    backup_link,
    backup_dir_sync,
    precondition_check,
    target_remove,
    publish_rename,
    publish_create,
    metadata_apply,
    parent_sync,
    verify,
    release_staging,
    release_backup,
    restore_rename,
    restore_create,
};

// ---------------------------------------------------------------------------
// Journal document
// ---------------------------------------------------------------------------

pub const LockBinding = root_operation.LockBinding;

/// Evidence the journal binds. Every digest is sticky: a journal is written
/// exactly once, so no later writer can rebind it to different authorization,
/// program, plan, database, or artifact evidence.
pub const Evidence = struct {
    authorization_sha256: ?[32]u8 = null,
    program_sha256: ?[32]u8 = null,
    plan_sha256: ?[32]u8 = null,
    exact_lock: ?LockBinding = null,
    database_generation_sha256: ?[32]u8 = null,
    database_plan_sha256: ?[32]u8 = null,
    artifact_evidence_sha256: ?[32]u8 = null,
};

/// The durable, versioned description of one mutation transaction.
pub const Journal = struct {
    attempt_id: [32]u8,
    /// Root-operation record generation at the moment the journal was
    /// published. A later caller must present the same attempt at that
    /// generation or a newer one.
    attempt_generation: u64,
    attempt_digest_sha256: [32]u8,
    install_root: []const u8,
    root_identity_sha256: [32]u8,
    evidence: Evidence,
    /// Device every mutated path and the workspace must share.
    device: u64,
    staging_bytes: u64,
    budget_bytes: u64,
    steps: []const Step,
    steps_sha256: [32]u8,
    digest_sha256: [32]u8,

    pub fn canonicalJson(
        self: Journal,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]u8 {
        var output: Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        writeDocument(self, &output.writer) catch return error.OutOfMemory;
        return output.toOwnedSlice() catch error.OutOfMemory;
    }

    pub fn step(self: Journal, index: u32) ?Step {
        if (index >= self.steps.len) return null;
        return self.steps[index];
    }

    /// True when the journal was published by exactly this attempt and the
    /// attempt has not been rewound.
    pub fn matchesAttempt(self: Journal, record: root_operation.Record) bool {
        if (!std.mem.eql(u8, &self.attempt_id, &record.attempt_id)) return false;
        if (!std.mem.eql(u8, &self.root_identity_sha256, &record.root_identity_sha256))
            return false;
        if (record.generation < self.attempt_generation) return false;
        if (record.generation == self.attempt_generation)
            return std.mem.eql(u8, &self.attempt_digest_sha256, &record.digest_sha256);
        return true;
    }
};

pub const OwnedJournal = struct {
    journal: Journal,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedJournal) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

fn writeDocument(journal: Journal, writer: *Io.Writer) !void {
    try writePayload(journal, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHexString(writer, &journal.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(journal: Journal, writer: *Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeJsonString(writer, schema_id);
    try writer.print(",\"version\":{},\"attempt_id\":", .{schema_version});
    try writeHexString(writer, &journal.attempt_id);
    try writer.print(",\"attempt_generation\":{},\"attempt_digest_sha256\":", .{
        journal.attempt_generation,
    });
    try writeHexString(writer, &journal.attempt_digest_sha256);
    try writer.writeAll(",\"install_root\":");
    try writeJsonString(writer, journal.install_root);
    try writer.writeAll(",\"root_identity_sha256\":");
    try writeHexString(writer, &journal.root_identity_sha256);
    try writer.writeAll(",\"authorization_sha256\":");
    try writeOptionalHex(writer, journal.evidence.authorization_sha256);
    try writer.writeAll(",\"program_sha256\":");
    try writeOptionalHex(writer, journal.evidence.program_sha256);
    try writer.writeAll(",\"plan_sha256\":");
    try writeOptionalHex(writer, journal.evidence.plan_sha256);
    try writer.writeAll(",\"exact_lock\":");
    if (journal.evidence.exact_lock) |binding| {
        try writer.writeAll("{\"schema\":");
        try writeJsonString(writer, binding.schema);
        try writer.print(",\"version\":{},\"digest_sha256\":", .{binding.version});
        try writeHexString(writer, &binding.digest_sha256);
        try writer.writeByte('}');
    } else try writer.writeAll("null");
    try writer.writeAll(",\"database_generation_sha256\":");
    try writeOptionalHex(writer, journal.evidence.database_generation_sha256);
    try writer.writeAll(",\"database_plan_sha256\":");
    try writeOptionalHex(writer, journal.evidence.database_plan_sha256);
    try writer.writeAll(",\"artifact_evidence_sha256\":");
    try writeOptionalHex(writer, journal.evidence.artifact_evidence_sha256);
    try writer.print(",\"device\":{},\"staging_bytes\":{},\"budget_bytes\":{},\"steps\":[", .{
        journal.device,
        journal.staging_bytes,
        journal.budget_bytes,
    });
    for (journal.steps, 0..) |value, index| {
        if (index != 0) try writer.writeByte(',');
        try writeStep(value, writer);
    }
    try writer.writeAll("],\"steps_sha256\":");
    try writeHexString(writer, &journal.steps_sha256);
    try writer.writeByte('}');
}

fn writeStep(step: Step, writer: *Io.Writer) !void {
    try writer.print("{{\"index\":{},\"kind\":", .{step.index});
    try writeJsonString(writer, @tagName(step.kind));
    try writer.writeAll(",\"path\":");
    try writeJsonString(writer, step.path);
    try writer.writeAll(",\"requires\":[");
    for (step.requires, 0..) |value, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{}", .{value});
    }
    try writer.writeAll("],\"overwrite\":");
    try writeJsonString(writer, @tagName(step.overwrite));
    try writer.writeAll(",\"removal\":");
    try writeJsonString(writer, @tagName(step.removal));
    try writer.writeAll(",\"expected\":");
    try writeExpectation(step.expected, writer);
    try writer.writeAll(",\"desired\":");
    try writeExpectation(step.desired, writer);
    try writer.writeAll(",\"source\":");
    try writeOptionalString(writer, step.source);
    try writer.writeAll(",\"source_sha256\":");
    try writeOptionalHex(writer, step.source_sha256);
    try writer.writeAll(",\"artifact\":");
    if (step.artifact) |binding| {
        try writer.print("{{\"index\":{},\"application_sha256\":", .{binding.index});
        try writeHexString(writer, &binding.application_sha256);
        try writer.writeByte('}');
    } else try writer.writeAll("null");
    try writer.writeAll(",\"staging_entry\":");
    try writeOptionalString(writer, step.staging_entry);
    try writer.writeAll(",\"backup_entry\":");
    try writeOptionalString(writer, step.backup_entry);
    try writer.writeByte('}');
}

fn writeExpectation(value: Expectation, writer: *Io.Writer) !void {
    switch (value) {
        .absent => try writer.writeAll("null"),
        .present => |state| {
            try writer.writeAll("{\"kind\":");
            try writeJsonString(writer, @tagName(state.kind));
            try writer.print(
                ",\"mode\":{},\"uid\":{},\"gid\":{},\"modified_nanoseconds\":{},\"size\":{}",
                .{
                    state.metadata.mode,
                    state.metadata.uid,
                    state.metadata.gid,
                    state.metadata.modified_nanoseconds,
                    state.size,
                },
            );
            try writer.writeAll(",\"content_sha256\":");
            try writeOptionalHex(writer, state.content_sha256);
            try writer.writeAll(",\"link_target\":");
            try writeOptionalString(writer, state.link_target);
            try writer.print(",\"inode\":{},\"link_count\":{}}}", .{
                state.inode,
                state.link_count,
            });
        },
    }
}

fn writeJsonString(writer: *Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        0x00...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

fn writeOptionalString(writer: *Io.Writer, value: ?[]const u8) !void {
    if (value) |text| try writeJsonString(writer, text) else try writer.writeAll("null");
}

fn writeHexString(writer: *Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
    try writer.writeByte('"');
}

fn writeOptionalHex(writer: *Io.Writer, value: ?[32]u8) !void {
    if (value) |bytes| try writeHexString(writer, &bytes) else try writer.writeAll("null");
}

/// Stable digest over the ordered intents alone. It lets a caller bind a plan
/// to provenance without serializing the whole journal.
pub fn stepsDigest(steps: []const Step) [32]u8 {
    var buffer: [4096]u8 = undefined;
    var sink: Io.Writer.Hashing(Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-root-mutation-steps-v1\x00") catch unreachable;
    sink.writer.print("{}\x00", .{steps.len}) catch unreachable;
    for (steps) |step| writeStep(step, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn journalDigest(journal: Journal) [32]u8 {
    var buffer: [4096]u8 = undefined;
    var sink: Io.Writer.Hashing(Sha256) = .init(&buffer);
    writePayload(journal, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn parseHex(comptime size: usize, value: []const u8) Error![size]u8 {
    if (value.len != size * 2) return error.DigestMismatch;
    var result: [size]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.DigestMismatch;
    return result;
}

fn parseOptionalHex(value: ?[]const u8) Error!?[32]u8 {
    const text = value orelse return null;
    return try parseHex(32, text);
}

const WireState = struct {
    kind: Kind,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_nanoseconds: i128,
    size: u64,
    content_sha256: ?[]const u8,
    link_target: ?[]const u8,
    inode: u64,
    link_count: u64,
};

const WireArtifact = struct {
    index: u32,
    application_sha256: []const u8,
};

const WireStep = struct {
    index: u32,
    kind: StepKind,
    path: []const u8,
    requires: []const u32,
    overwrite: Overwrite,
    removal: Removal,
    expected: ?WireState,
    desired: ?WireState,
    source: ?[]const u8,
    source_sha256: ?[]const u8,
    artifact: ?WireArtifact,
    staging_entry: ?[]const u8,
    backup_entry: ?[]const u8,
};

const WireLockBinding = struct {
    schema: []const u8,
    version: u32,
    digest_sha256: []const u8,
};

const WireJournal = struct {
    schema: []const u8,
    version: u32,
    attempt_id: []const u8,
    attempt_generation: u64,
    attempt_digest_sha256: []const u8,
    install_root: []const u8,
    root_identity_sha256: []const u8,
    authorization_sha256: ?[]const u8,
    program_sha256: ?[]const u8,
    plan_sha256: ?[]const u8,
    exact_lock: ?WireLockBinding,
    database_generation_sha256: ?[]const u8,
    database_plan_sha256: ?[]const u8,
    artifact_evidence_sha256: ?[]const u8,
    device: u64,
    staging_bytes: u64,
    budget_bytes: u64,
    steps: []const WireStep,
    steps_sha256: []const u8,
    digest_sha256: []const u8,
};

/// Strict bounded decode. Unknown fields, missing fields, an unsupported
/// schema, a mismatched digest, a step whose recorded shape contradicts its
/// kind, and any byte sequence that is not the exact canonical encoding are
/// all rejected.
pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) Error!OwnedJournal {
    if (source.len > maximum_bytes or source.len > maximum_document_bytes)
        return error.DocumentTooLarge;
    var parsed = std.json.parseFromSlice(WireJournal, allocator, source, .{
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
    if (wire.steps.len > maximum_steps) return error.DocumentTooLarge;

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const steps = try owned.alloc(Step, wire.steps.len);
    for (wire.steps, 0..) |value, index| {
        if (value.index != index) return error.NonCanonicalDocument;
        steps[index] = try decodeStep(owned, value);
    }

    const journal: Journal = .{
        .attempt_id = try parseHex(32, wire.attempt_id),
        .attempt_generation = wire.attempt_generation,
        .attempt_digest_sha256 = try parseHex(32, wire.attempt_digest_sha256),
        .install_root = try owned.dupe(u8, wire.install_root),
        .root_identity_sha256 = try parseHex(32, wire.root_identity_sha256),
        .evidence = .{
            .authorization_sha256 = try parseOptionalHex(wire.authorization_sha256),
            .program_sha256 = try parseOptionalHex(wire.program_sha256),
            .plan_sha256 = try parseOptionalHex(wire.plan_sha256),
            .exact_lock = if (wire.exact_lock) |binding| .{
                .schema = try owned.dupe(u8, binding.schema),
                .version = binding.version,
                .digest_sha256 = try parseHex(32, binding.digest_sha256),
            } else null,
            .database_generation_sha256 = try parseOptionalHex(wire.database_generation_sha256),
            .database_plan_sha256 = try parseOptionalHex(wire.database_plan_sha256),
            .artifact_evidence_sha256 = try parseOptionalHex(wire.artifact_evidence_sha256),
        },
        .device = wire.device,
        .staging_bytes = wire.staging_bytes,
        .budget_bytes = wire.budget_bytes,
        .steps = steps,
        .steps_sha256 = try parseHex(32, wire.steps_sha256),
        .digest_sha256 = try parseHex(32, wire.digest_sha256),
    };
    if (!std.mem.eql(u8, &journal.steps_sha256, &stepsDigest(steps)))
        return error.DigestMismatch;
    var checked = journal;
    checked.digest_sha256 = @splat(0);
    checked.digest_sha256 = journalDigest(checked);
    if (!std.mem.eql(u8, &checked.digest_sha256, &journal.digest_sha256))
        return error.DigestMismatch;
    const canonical = try journal.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return .{ .journal = journal, .arena = arena, .backing_allocator = allocator };
}

fn decodeStep(allocator: std.mem.Allocator, wire: WireStep) Error!Step {
    if (wire.requires.len > maximum_step_dependencies) return error.NonCanonicalDocument;
    if (wire.path.len == 0 or wire.path.len > maximum_path_bytes)
        return error.NonCanonicalDocument;
    _ = root_fs.Path.init(wire.path) catch return error.NonCanonicalDocument;
    for (wire.requires) |value| {
        if (value >= wire.index) return error.NonCanonicalDocument;
    }
    const step: Step = .{
        .index = wire.index,
        .kind = wire.kind,
        .path = try allocator.dupe(u8, wire.path),
        .requires = try allocator.dupe(u32, wire.requires),
        .overwrite = wire.overwrite,
        .removal = wire.removal,
        .expected = try decodeExpectation(allocator, wire.expected),
        .desired = try decodeExpectation(allocator, wire.desired),
        .source = if (wire.source) |text| try allocator.dupe(u8, text) else null,
        .source_sha256 = try parseOptionalHex(wire.source_sha256),
        .artifact = if (wire.artifact) |value| .{
            .index = value.index,
            .application_sha256 = try parseHex(32, value.application_sha256),
        } else null,
        .staging_entry = if (wire.staging_entry) |text| try allocator.dupe(u8, text) else null,
        .backup_entry = if (wire.backup_entry) |text| try allocator.dupe(u8, text) else null,
    };
    try validateStepShape(step);
    return step;
}

fn decodeExpectation(
    allocator: std.mem.Allocator,
    wire: ?WireState,
) Error!Expectation {
    const value = wire orelse return .absent;
    if (value.link_target) |text| {
        if (text.len == 0 or text.len > maximum_link_target_bytes)
            return error.NonCanonicalDocument;
    }
    return .{ .present = .{
        .kind = value.kind,
        .metadata = .{
            .mode = value.mode,
            .uid = value.uid,
            .gid = value.gid,
            .modified_nanoseconds = value.modified_nanoseconds,
        },
        .size = value.size,
        .content_sha256 = try parseOptionalHex(value.content_sha256),
        .link_target = if (value.link_target) |text| try allocator.dupe(u8, text) else null,
        .inode = value.inode,
        .link_count = value.link_count,
    } };
}

/// Structural consistency of one decoded step. A journal that survives this
/// can be executed without ever inferring a missing field.
fn validateStepShape(step: Step) Error!void {
    switch (step.expected) {
        .absent => {},
        .present => |state| try validateStateShape(state),
    }
    switch (step.desired) {
        .absent => {},
        .present => |state| try validateStateShape(state),
    }
    const desired: ?State = switch (step.desired) {
        .absent => null,
        .present => |state| state,
    };
    switch (step.kind) {
        .publish_file, .copy_file => {
            const value = desired orelse return error.NonCanonicalDocument;
            if (value.kind != .regular) return error.NonCanonicalDocument;
            if (step.kind == .copy_file and (step.source == null or step.source_sha256 == null))
                return error.NonCanonicalDocument;
        },
        .publish_symlink => {
            const value = desired orelse return error.NonCanonicalDocument;
            if (value.kind != .symlink) return error.NonCanonicalDocument;
        },
        .publish_hard_link => {
            const value = desired orelse return error.NonCanonicalDocument;
            if (value.kind != .regular) return error.NonCanonicalDocument;
            if (step.source == null) return error.NonCanonicalDocument;
        },
        .create_directory => {
            const value = desired orelse return error.NonCanonicalDocument;
            if (value.kind != .directory) return error.NonCanonicalDocument;
        },
        .set_metadata => {
            const value = desired orelse return error.NonCanonicalDocument;
            const previous = switch (step.expected) {
                .absent => return error.NonCanonicalDocument,
                .present => |state| state,
            };
            if (value.kind != previous.kind) return error.NonCanonicalDocument;
        },
        .remove_path, .remove_directory => {
            if (desired != null) return error.NonCanonicalDocument;
        },
    }
    if (step.staging_entry) |name| {
        if (!validWorkspaceName(name)) return error.NonCanonicalDocument;
    }
    if (step.backup_entry) |name| {
        if (!validWorkspaceName(name)) return error.NonCanonicalDocument;
    }
    if (step.source) |text| {
        _ = root_fs.Path.init(text) catch return error.NonCanonicalDocument;
    }
}

fn validateStateShape(state: State) Error!void {
    if (state.metadata.mode > maximum_mode) return error.NonCanonicalDocument;
    if (state.metadata.modified_nanoseconds > maximum_timestamp_nanoseconds or
        state.metadata.modified_nanoseconds < minimum_timestamp_nanoseconds)
        return error.NonCanonicalDocument;
    switch (state.kind) {
        .regular => {
            if (state.content_sha256 == null) return error.NonCanonicalDocument;
            if (state.link_target != null) return error.NonCanonicalDocument;
        },
        .symlink => {
            if (state.link_target == null) return error.NonCanonicalDocument;
            if (state.content_sha256 != null) return error.NonCanonicalDocument;
        },
        .directory => {
            if (state.content_sha256 != null or state.link_target != null)
                return error.NonCanonicalDocument;
            if (state.size != 0) return error.NonCanonicalDocument;
        },
    }
}

/// Workspace names are derived from the step index alone, so they cannot
/// collide and can never name anything outside the private workspace.
fn validWorkspaceName(name: []const u8) bool {
    if (name.len != 8) return false;
    for (name) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

fn workspaceName(buffer: *[8]u8, index: u32) []const u8 {
    return std.fmt.bufPrint(buffer, "{x:0>8}", .{index}) catch unreachable;
}

// ---------------------------------------------------------------------------
// Chained write-ahead progress log
// ---------------------------------------------------------------------------

pub const Scope = enum { journal, step };

/// One durable boundary. Records are fixed shape and hash-chained to the
/// journal digest, so a torn trailing write, a reordered record, a record from
/// another journal, and a truncated log are all detectable, and the last
/// complete record is the last boundary that was durable.
pub const ProgressRecord = struct {
    sequence: u64,
    scope: Scope,
    /// Step index, or `no_index` for a journal-scoped record.
    index: u32,
    stage: Stage,
    state: StepState,
    chain_sha256: [32]u8,

    pub const no_index: u32 = std.math.maxInt(u32);

    /// `sequence`, `scope`, `index`, and the published name, chained onto the
    /// previous record. The first record chains onto the journal digest, so a
    /// log can never be replayed against a different journal.
    pub fn chain(
        previous: [32]u8,
        sequence: u64,
        scope: Scope,
        index: u32,
        boundary: []const u8,
    ) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update("debz-root-mutation-progress-v1\x00");
        hash.update(&previous);
        var scratch: [8]u8 = undefined;
        std.mem.writeInt(u64, &scratch, sequence, .big);
        hash.update(&scratch);
        hash.update(@tagName(scope));
        hash.update("\x00");
        var index_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &index_bytes, index, .big);
        hash.update(&index_bytes);
        hash.update(boundary);
        hash.update("\x00");
        return hash.finalResult();
    }

    fn name(self: ProgressRecord) []const u8 {
        return switch (self.scope) {
            .journal => @tagName(self.stage),
            .step => @tagName(self.state),
        };
    }

    /// Fixed-width canonical spelling. Every field has a constant width so a
    /// bounded reader can validate a record without scanning.
    pub fn encode(self: ProgressRecord, buffer: *[progress_record_bytes]u8) []const u8 {
        var padded: [24]u8 = @splat(' ');
        const text = self.name();
        @memcpy(padded[0..text.len], text);
        const digest = std.fmt.bytesToHex(self.chain_sha256, .lower);
        return std.fmt.bufPrint(buffer, "{x:0>16} {s} {x:0>8} {s} {s}\n", .{
            self.sequence,
            switch (self.scope) {
                .journal => "journal",
                .step => "step   ",
            },
            self.index,
            padded,
            digest,
        }) catch unreachable;
    }
};

pub const ProgressError = error{ProgressCorrupt};

fn decodeProgressRecord(line: []const u8) ProgressError!ProgressRecord {
    if (line.len != progress_record_bytes - 1) return error.ProgressCorrupt;
    if (line[16] != ' ' or line[24] != ' ' or line[33] != ' ' or line[58] != ' ')
        return error.ProgressCorrupt;
    const sequence = std.fmt.parseUnsigned(u64, line[0..16], 16) catch
        return error.ProgressCorrupt;
    const scope: Scope = if (std.mem.eql(u8, line[17..24], "journal"))
        .journal
    else if (std.mem.eql(u8, line[17..24], "step   "))
        .step
    else
        return error.ProgressCorrupt;
    const index = std.fmt.parseUnsigned(u32, line[25..33], 16) catch
        return error.ProgressCorrupt;
    const padded = line[34..58];
    const text = std.mem.trimEnd(u8, padded, " ");
    var record: ProgressRecord = .{
        .sequence = sequence,
        .scope = scope,
        .index = index,
        .stage = .prepared,
        .state = .prepared,
        .chain_sha256 = undefined,
    };
    switch (scope) {
        .journal => {
            if (index != ProgressRecord.no_index) return error.ProgressCorrupt;
            record.stage = std.meta.stringToEnum(Stage, text) orelse
                return error.ProgressCorrupt;
        },
        .step => {
            if (index == ProgressRecord.no_index) return error.ProgressCorrupt;
            record.state = std.meta.stringToEnum(StepState, text) orelse
                return error.ProgressCorrupt;
        },
    }
    if (std.mem.indexOfScalar(u8, text, ' ') != null) return error.ProgressCorrupt;
    record.chain_sha256 = parseHex(32, line[59..123]) catch return error.ProgressCorrupt;
    return record;
}

/// Replayed progress. `states` is dense over the journal's steps, so lookups
/// are indexed rather than searched.
pub const Progress = struct {
    allocator: std.mem.Allocator,
    stage: Stage,
    sequence: u64,
    chain_sha256: [32]u8,
    states: []StepState,
    /// Bytes of the log that decoded cleanly. A torn trailing record is left
    /// out, so the next append overwrites it.
    accepted_bytes: u64,

    pub fn deinit(self: *Progress) void {
        self.allocator.free(self.states);
        self.* = undefined;
    }

    pub fn state(self: Progress, index: u32) StepState {
        if (index >= self.states.len) return .prepared;
        return self.states[index];
    }
};

/// Replays a bounded log against `journal`. Every record must chain onto its
/// predecessor and name a boundary the journal's step of that index can
/// actually publish; the first record that does not is the end of the durable
/// prefix only when it is an incomplete trailing line, and is otherwise
/// corruption.
pub fn replayProgress(
    allocator: std.mem.Allocator,
    journal: Journal,
    bytes: []const u8,
) Error!Progress {
    const states = try allocator.alloc(StepState, journal.steps.len);
    errdefer allocator.free(states);
    @memset(states, .prepared);
    var progress: Progress = .{
        .allocator = allocator,
        .stage = .prepared,
        .sequence = 0,
        .chain_sha256 = journal.digest_sha256,
        .states = states,
        .accepted_bytes = 0,
    };
    var offset: usize = 0;
    while (offset < bytes.len) {
        const remaining = bytes.len - offset;
        if (remaining < progress_record_bytes) {
            // A trailing partial record was never durable, so it is discarded
            // instead of being trusted or treated as corruption.
            break;
        }
        const line = bytes[offset .. offset + progress_record_bytes - 1];
        if (bytes[offset + progress_record_bytes - 1] != '\n') return error.ProgressCorrupt;
        const record = decodeProgressRecord(line) catch return error.ProgressCorrupt;
        const expected_sequence = progress.sequence + 1;
        if (record.sequence != expected_sequence) return error.ProgressCorrupt;
        const expected_chain = ProgressRecord.chain(
            progress.chain_sha256,
            record.sequence,
            record.scope,
            record.index,
            record.name(),
        );
        if (!std.mem.eql(u8, &expected_chain, &record.chain_sha256))
            return error.ProgressCorrupt;
        switch (record.scope) {
            .journal => progress.stage = record.stage,
            .step => {
                if (record.index >= states.len) return error.ProgressCorrupt;
                states[record.index] = record.state;
            },
        }
        progress.sequence = record.sequence;
        progress.chain_sha256 = record.chain_sha256;
        offset += progress_record_bytes;
        progress.accepted_bytes = offset;
    }
    return progress;
}

// ---------------------------------------------------------------------------
// Root-anchored durable store
// ---------------------------------------------------------------------------

/// Every durable artifact this module owns lives under the root's `var/lib/debz`
/// namespace and is reached only through no-follow root-relative resolution.
pub const Store = struct {
    root: root_fs.Root,
    limits: Limits = .{},

    pub fn init(root: root_fs.Root) Store {
        return .{ .root = root };
    }

    /// Creates the private workspace. Every existing component must already be
    /// a real directory owned by root; a symbolic link fails closed.
    pub fn ensureWorkspace(self: Store) !void {
        try self.root.createDirectoryPath(
            try root_fs.Path.init(namespace_path),
            root_fs.default_directory_permissions,
        );
        try self.root.ensureDirectory(
            try root_fs.Path.init(workspace_path),
            workspace_permissions,
        );
        try self.root.ensureDirectory(
            try root_fs.Path.init(staging_path),
            workspace_permissions,
        );
        try self.root.ensureDirectory(
            try root_fs.Path.init(backup_path),
            workspace_permissions,
        );
        try self.root.syncDirectory(try root_fs.Path.init(workspace_path));
    }

    /// `null` only when no journal exists. A journal that cannot be decoded is
    /// an error, never an absent journal.
    pub fn readJournal(self: Store, allocator: std.mem.Allocator) Error!?OwnedJournal {
        const path = root_fs.Path.init(journal_path) catch return error.StoreFailed;
        const bytes = self.root.readFileAlloc(
            allocator,
            path,
            self.limits.max_document_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => return null,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.JournalCorrupt,
        };
        defer allocator.free(bytes);
        return decode(allocator, bytes, self.limits.max_document_bytes) catch |err|
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.UnsupportedSchema => return error.UnsupportedSchema,
                error.DocumentTooLarge => return error.DocumentTooLarge,
                else => return error.JournalCorrupt,
            };
    }

    /// Publishes the journal atomically. It is written exactly once per
    /// transaction, before any target byte changes.
    pub fn writeJournal(
        self: Store,
        allocator: std.mem.Allocator,
        journal: Journal,
    ) Error!void {
        const bytes = try journal.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > self.limits.max_document_bytes) return error.DocumentTooLarge;
        const path = root_fs.Path.init(journal_path) catch return error.StoreFailed;
        self.root.publishFile(path, bytes, .{
            .permissions = journal_permissions,
            .overwrite = .fail_if_exists,
            .durable = true,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => return error.JournalPresent,
            else => return error.StoreFailed,
        };
    }

    pub fn readProgressBytes(self: Store, allocator: std.mem.Allocator) Error![]u8 {
        const path = root_fs.Path.init(progress_path) catch return error.StoreFailed;
        return self.root.readFileAlloc(
            allocator,
            path,
            self.limits.max_progress_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => return allocator.alloc(u8, 0),
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.ProgressCorrupt,
        };
    }

    /// Creates an empty log. A leftover log from an unresolved transaction is
    /// never appended to; it is only ever replayed or cleared.
    pub fn createProgress(self: Store) Error!void {
        const path = root_fs.Path.init(progress_path) catch return error.StoreFailed;
        self.root.writeNewFile(path, "", .{ .permissions = journal_permissions }, true) catch |err|
            switch (err) {
                error.PathAlreadyExists => return error.JournalPresent,
                else => return error.StoreFailed,
            };
        self.root.syncDirectory(root_fs.Path.init(namespace_path) catch
            return error.StoreFailed) catch return error.StoreFailed;
    }

    /// A journal published without its log, which is what a crash between the
    /// two writes leaves, still has to be resolvable. The log is recreated
    /// empty, which replays as a transaction that never started.
    pub fn ensureProgress(self: Store) Error!void {
        self.createProgress() catch |err| switch (err) {
            error.JournalPresent => {},
            else => return err,
        };
    }

    /// Removes every durable artifact and every workspace entry. Only a
    /// completed or never-started transaction may be cleared.
    pub fn clear(self: Store, allocator: std.mem.Allocator) Error!void {
        try self.clearWorkspaceEntries(allocator, staging_path);
        try self.clearWorkspaceEntries(allocator, backup_path);
        const namespace = root_fs.Path.init(namespace_path) catch return error.StoreFailed;
        self.removeIfPresent(progress_path) catch return error.StoreFailed;
        self.removeIfPresent(journal_path) catch return error.StoreFailed;
        self.root.syncDirectory(namespace) catch return error.StoreFailed;
    }

    fn removeIfPresent(self: Store, text: []const u8) !void {
        const path = try root_fs.Path.init(text);
        self.root.removeFile(path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    fn clearWorkspaceEntries(
        self: Store,
        allocator: std.mem.Allocator,
        directory: []const u8,
    ) Error!void {
        const path = root_fs.Path.init(directory) catch return error.StoreFailed;
        var dir = self.root.openDirectory(path) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return error.StoreFailed,
        };
        defer dir.close(self.root.io);
        var names: std.ArrayList([]u8) = .empty;
        defer {
            for (names.items) |name| allocator.free(name);
            names.deinit(allocator);
        }
        var iterator = dir.iterate();
        while (iterator.next(self.root.io) catch return error.StoreFailed) |candidate| {
            try names.append(allocator, try allocator.dupe(u8, candidate.name));
        }
        for (names.items) |name| {
            dir.deleteFile(self.root.io, name) catch |err| switch (err) {
                error.FileNotFound => {},
                error.IsDir => dir.deleteDir(self.root.io, name) catch
                    return error.StoreFailed,
                else => return error.StoreFailed,
            };
        }
        self.root.syncDirectory(path) catch return error.StoreFailed;
    }
};

// ---------------------------------------------------------------------------
// Caller intents
// ---------------------------------------------------------------------------

pub const FileIntent = struct {
    /// Root-relative canonical path.
    path: []const u8,
    /// Exact bytes to publish. Borrowed for the lifetime of the plan.
    bytes: []const u8,
    mode: u32 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
    modified_nanoseconds: i128 = 0,
    overwrite: Overwrite = .replace,
    /// Digest the caller already authorized for these bytes. Preflight
    /// refuses a mismatch instead of publishing whatever it was handed.
    expected_sha256: ?[32]u8 = null,
    artifact: ?ArtifactBinding = null,
};

pub const CopyIntent = struct {
    path: []const u8,
    /// Root-relative path whose current bytes become the new content.
    source: []const u8,
    /// Digest the source must currently have.
    source_sha256: [32]u8,
    mode: u32 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
    modified_nanoseconds: i128 = 0,
    overwrite: Overwrite = .replace,
};

pub const SymlinkIntent = struct {
    path: []const u8,
    target: []const u8,
    uid: u32 = 0,
    gid: u32 = 0,
    modified_nanoseconds: i128 = 0,
    overwrite: Overwrite = .replace,
};

pub const HardLinkIntent = struct {
    path: []const u8,
    /// Root-relative path of the regular file whose inode is linked.
    source: []const u8,
    overwrite: Overwrite = .replace,
};

pub const DirectoryIntent = struct {
    path: []const u8,
    mode: u32 = 0o755,
    uid: u32 = 0,
    gid: u32 = 0,
    overwrite: Overwrite = .replace,
};

pub const MetadataIntent = struct {
    path: []const u8,
    mode: ?u32 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
    modified_nanoseconds: ?i128 = null,
};

pub const RemoveIntent = struct {
    path: []const u8,
    removal: Removal = .require_present,
};

pub const Intent = union(enum) {
    file: FileIntent,
    copy: CopyIntent,
    symlink: SymlinkIntent,
    hard_link: HardLinkIntent,
    directory: DirectoryIntent,
    metadata: MetadataIntent,
    remove: RemoveIntent,
    remove_directory: RemoveIntent,

    pub fn path(self: Intent) []const u8 {
        return switch (self) {
            inline else => |value| value.path,
        };
    }
};

/// A complete, validated, ordered mutation plan. Content slices are borrowed
/// from the caller's already validated model, so the plan never copies a
/// payload and never owns untrusted bytes.
pub const Plan = struct {
    steps: []const Step,
    /// Dense over `steps`. Non-empty only for `publish_file`.
    contents: []const []const u8,
    steps_sha256: [32]u8,
    device: u64,
    staging_bytes: u64,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn content(self: Plan, index: u32) []const u8 {
        if (index >= self.contents.len) return &.{};
        return self.contents[index];
    }
};

pub const PlanResult = union(enum) {
    plan: Plan,
    diagnostic: Diagnostic,
};

pub const PreflightRequest = struct {
    intents: []const Intent,
    limits: Limits = .{},
};

const PathModel = struct {
    path: []const u8,
    /// State the plan has modeled for this path after the last step that
    /// touched it, or the observed on-disk state when nothing has.
    state: Expectation,
    /// Index of the last step that touches the path, or null when the path is
    /// only referenced as an ancestor.
    last_step: ?u32,
    /// True when the plan itself produced the modeled state.
    produced: bool,
};

const Builder = struct {
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    root: root_fs.Root,
    limits: Limits,
    steps: std.ArrayList(Step) = .empty,
    contents: std.ArrayList([]const u8) = .empty,
    models: std.ArrayList(PathModel) = .empty,
    index: std.StringHashMapUnmanaged(u32) = .empty,
    devices: std.StringHashMapUnmanaged(u64) = .empty,
    aliases: std.AutoHashMapUnmanaged(u128, u32) = .empty,
    workspace_device: u64 = 0,
    staging_bytes: u64 = 0,
    diagnostic: ?Diagnostic = null,

    fn deinit(self: *Builder) void {
        self.steps.deinit(self.allocator);
        self.contents.deinit(self.allocator);
        self.models.deinit(self.allocator);
        self.index.deinit(self.allocator);
        self.devices.deinit(self.allocator);
        self.aliases.deinit(self.allocator);
    }

    fn fail(self: *Builder, surface: Surface, code: Code, path: []const u8) error{Rejected} {
        self.diagnostic = .{
            .surface = surface,
            .code = code,
            .step = @intCast(self.steps.items.len),
            .path = path,
        };
        return error.Rejected;
    }
};

const BuildError = error{ Rejected, OutOfMemory };

/// Resolves every intent against the current root into an exact precondition,
/// an exact desired state, staging and backup names, and dependency order.
/// Nothing is mutated outside the private workspace, and every refusal
/// happens here, before any target byte can change.
pub fn preflight(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    request: PreflightRequest,
) Error!PlanResult {
    const store: Store = .{ .root = root, .limits = request.limits };
    store.ensureWorkspace() catch return error.StoreFailed;

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();

    var builder: Builder = .{
        .allocator = allocator,
        .arena = arena.allocator(),
        .root = root,
        .limits = request.limits,
    };
    defer builder.deinit();

    build(&builder, request) catch |err| switch (err) {
        // The arena is released by the error defers above; releasing it here
        // as well would free it twice.
        error.OutOfMemory => return error.OutOfMemory,
        error.Rejected => {
            // A diagnostic is returned as a value, so the error defers do not
            // run and the arena is released here. Every string a diagnostic
            // names references caller input or static text, never the arena,
            // and the builder's own scratch structures are allocated from the
            // caller's allocator, so the deferred release stays valid.
            const diagnostic = builder.diagnostic.?;
            arena.deinit();
            allocator.destroy(arena);
            return .{ .diagnostic = diagnostic };
        },
    };

    const steps = try builder.arena.dupe(Step, builder.steps.items);
    const contents = try builder.arena.dupe([]const u8, builder.contents.items);
    return .{ .plan = .{
        .steps = steps,
        .contents = contents,
        .steps_sha256 = stepsDigest(steps),
        .device = builder.workspace_device,
        .staging_bytes = builder.staging_bytes,
        .arena = arena,
        .backing_allocator = allocator,
    } };
}

fn build(builder: *Builder, request: PreflightRequest) BuildError!void {
    if (request.intents.len > request.limits.max_steps or request.intents.len > maximum_steps)
        return builder.fail(.preflight, .step_limit, "");
    const workspace = builder.root.deviceOfDirectory(
        root_fs.Path.init(workspace_path) catch unreachable,
    ) catch return builder.fail(.workspace, .io_failed, workspace_path);
    builder.workspace_device = workspace;

    for (request.intents) |intent| try appendIntent(builder, intent);
    try validateHardLinks(builder, request);
}

fn appendIntent(builder: *Builder, intent: Intent) BuildError!void {
    const text = intent.path();
    const path = root_fs.Path.init(text) catch
        return builder.fail(.preflight, .invalid_path, text);
    if (withinNamespace(path.text)) return builder.fail(.preflight, .path_collision, text);

    const index: u32 = @intCast(builder.steps.items.len);
    var requires: Requirements = .{};
    const model_index = try resolveModel(builder, path.text, &requires);
    try requireAncestors(builder, path, &requires);

    const expected = builder.models.items[model_index].state;
    switch (expected) {
        .absent => {},
        .present => |state| {
            if (builder.models.items[model_index].produced) {
                // The plan itself produced this state, so it is exact by
                // construction and cannot be an alias of another target.
            } else try recordAlias(builder, state, path.text, index);
        },
    }

    const step = try buildStep(builder, intent, path, expected, index, &requires);
    try builder.steps.append(builder.allocator, step);
    try builder.contents.append(builder.allocator, switch (intent) {
        .file => |value| value.bytes,
        else => &.{},
    });
    builder.models.items[model_index].state = step.desired;
    builder.models.items[model_index].last_step = index;
    builder.models.items[model_index].produced = true;
}

/// Journal, progress log, staging, and backup entries are never mutation
/// targets. A plan that names one would corrupt its own recovery evidence.
fn withinNamespace(path: []const u8) bool {
    if (std.mem.eql(u8, path, namespace_path)) return true;
    return std.mem.startsWith(u8, path, namespace_path ++ "/");
}

fn resolveModel(
    builder: *Builder,
    path: []const u8,
    requires: *Requirements,
) BuildError!u32 {
    if (builder.index.get(path)) |existing| {
        if (builder.models.items[existing].last_step) |previous| requires.append(previous);
        return existing;
    }
    const observed = try observe(builder, path);
    const owned_path = try builder.arena.dupe(u8, path);
    const model_index: u32 = @intCast(builder.models.items.len);
    try builder.models.append(builder.allocator, .{
        .path = owned_path,
        .state = observed,
        .last_step = null,
        .produced = false,
    });
    try builder.index.put(builder.allocator, owned_path, model_index);
    return model_index;
}

/// Bounded, duplicate-free dependency set. It never grows past the recorded
/// bound: execution order is already total, so the recorded set is evidence
/// about which earlier steps a step depends on, not the schedule itself.
const Requirements = struct {
    items: [maximum_step_dependencies]u32 = undefined,
    length: usize = 0,

    fn append(self: *Requirements, value: u32) void {
        for (self.items[0..self.length]) |existing| {
            if (existing == value) return;
        }
        if (self.length == self.items.len) return;
        self.items[self.length] = value;
        self.length += 1;
    }

    fn slice(self: *const Requirements) []const u32 {
        return self.items[0..self.length];
    }
};

/// Every ancestor of a target must be a real directory when the step runs.
/// An ancestor the plan turns into a file, a symbolic link, or nothing at all
/// is refused here rather than discovered halfway through a transaction.
fn requireAncestors(
    builder: *Builder,
    path: root_fs.Path,
    requires: *Requirements,
) BuildError!void {
    var cursor = path.parent();
    while (cursor) |ancestor| : (cursor = ancestor.parent()) {
        const existing = builder.index.get(ancestor.text) orelse continue;
        const model = builder.models.items[existing];
        switch (model.state) {
            .absent => return builder.fail(.preflight, .ancestor_conflict, ancestor.text),
            .present => |state| if (state.kind != .directory)
                return builder.fail(.preflight, .ancestor_conflict, ancestor.text),
        }
        if (model.last_step) |step| requires.append(step);
    }
}

fn recordAlias(
    builder: *Builder,
    state: State,
    path: []const u8,
    index: u32,
) BuildError!void {
    if (state.kind == .directory) return;
    if (state.inode == 0) return;
    const key = (@as(u128, builder.workspace_device) << 64) | state.inode;
    const found = try builder.aliases.getOrPut(builder.allocator, key);
    if (found.found_existing) return builder.fail(.preflight, .path_alias, path);
    found.value_ptr.* = index;
}

/// One no-follow observation of a target path, translated into either an
/// exact state or an explicit absence. Every unsupported kind, symbolic-link
/// component, and cross-device target fails here.
fn observe(builder: *Builder, path: []const u8) BuildError!Expectation {
    const resolved = root_fs.Path.init(path) catch
        return builder.fail(.preflight, .invalid_path, path);
    try requireSameDevice(builder, resolved);
    const observed = builder.root.entryIfExists(resolved) catch |err| return switch (err) {
        error.SymbolicLinkComponent => builder.fail(.preflight, .symbolic_link_component, path),
        error.NotDirectory => builder.fail(.preflight, .ancestor_conflict, path),
        error.OutOfMemory => error.OutOfMemory,
        else => builder.fail(.preflight, .io_failed, path),
    };
    const found = observed orelse return .absent;
    const kind = Kind.fromFileKind(found.kind) orelse
        return builder.fail(.preflight, .unsupported_kind, path);
    if (found.modeled and found.device != builder.workspace_device)
        return builder.fail(.preflight, .cross_device, path);
    var state: State = .{
        .kind = kind,
        .metadata = .{
            .mode = found.mode,
            .uid = found.uid,
            .gid = found.gid,
            .modified_nanoseconds = found.modified_nanoseconds,
        },
        .size = found.size,
        .inode = found.inode,
        .link_count = found.link_count,
    };
    switch (kind) {
        .regular => state.content_sha256 = try digestFile(builder, resolved),
        .symlink => state.link_target = try readLink(builder, resolved),
        .directory => {
            state.size = 0;
            state.metadata.modified_nanoseconds = 0;
        },
    }
    return .{ .present = state };
}

/// The deepest existing ancestor decides which filesystem the target will be
/// created on, and every staged or backed-up entry must share it so that
/// publication and restoration are atomic renames rather than copies.
fn requireSameDevice(builder: *Builder, path: root_fs.Path) BuildError!void {
    var cursor: ?root_fs.Path = path.parent();
    while (cursor) |ancestor| : (cursor = ancestor.parent()) {
        if (builder.devices.get(ancestor.text)) |device| {
            if (device != builder.workspace_device)
                return builder.fail(.preflight, .cross_device, ancestor.text);
            return;
        }
        const device = builder.root.deviceOfDirectory(ancestor) catch |err| switch (err) {
            error.FileNotFound => continue,
            error.SymbolicLinkComponent => return builder.fail(
                .preflight,
                .symbolic_link_component,
                ancestor.text,
            ),
            error.NotDirectory => return builder.fail(
                .preflight,
                .ancestor_conflict,
                ancestor.text,
            ),
            else => return builder.fail(.preflight, .io_failed, ancestor.text),
        };
        const owned = try builder.arena.dupe(u8, ancestor.text);
        try builder.devices.put(builder.allocator, owned, device);
        if (device != builder.workspace_device)
            return builder.fail(.preflight, .cross_device, ancestor.text);
        return;
    }
    const root_device = builder.root.rootEntry() catch
        return builder.fail(.preflight, .io_failed, "");
    if (root_device.modeled and root_device.device != builder.workspace_device)
        return builder.fail(.preflight, .cross_device, "");
}

fn digestFile(builder: *Builder, path: root_fs.Path) BuildError![32]u8 {
    var file = builder.root.openRegularFile(path) catch
        return builder.fail(.preflight, .io_failed, path.text);
    defer file.close(builder.root.io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(builder.root.io, &buffer);
    var hash = Sha256.init(.{});
    while (true) {
        const chunk = reader.interface.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return builder.fail(.preflight, .io_failed, path.text),
        };
        hash.update(chunk);
        reader.interface.toss(chunk.len);
    }
    return hash.finalResult();
}

fn readLink(builder: *Builder, path: root_fs.Path) BuildError![]const u8 {
    var buffer: [maximum_link_target_bytes]u8 = undefined;
    const target = builder.root.readSymbolicLink(path, &buffer) catch
        return builder.fail(.preflight, .io_failed, path.text);
    return builder.arena.dupe(u8, target);
}

fn buildStep(
    builder: *Builder,
    intent: Intent,
    path: root_fs.Path,
    expected: Expectation,
    index: u32,
    requires: *Requirements,
) BuildError!Step {
    var staging_buffer: [8]u8 = undefined;
    var backup_buffer: [8]u8 = undefined;
    const staging_entry = try builder.arena.dupe(u8, workspaceName(&staging_buffer, index));
    const backup_entry = try builder.arena.dupe(u8, workspaceName(&backup_buffer, index));
    const owned_path = try builder.arena.dupe(u8, path.text);
    const owned_requires = try builder.arena.dupe(u32, requires.slice());

    var step: Step = .{
        .index = index,
        .kind = undefined,
        .path = owned_path,
        .requires = owned_requires,
        .overwrite = .replace,
        .removal = .require_present,
        .expected = expected,
        .desired = .absent,
    };

    switch (intent) {
        .file => |value| {
            step.kind = .publish_file;
            step.overwrite = value.overwrite;
            try requireOverwrite(builder, expected, value.overwrite, path.text);
            var digest: [32]u8 = undefined;
            Sha256.hash(value.bytes, &digest, .{});
            if (value.expected_sha256) |authorized| {
                if (!std.mem.eql(u8, &digest, &authorized))
                    return builder.fail(.preflight, .content_digest_mismatch, path.text);
            }
            try accountStaging(builder, value.bytes.len, path.text);
            step.artifact = value.artifact;
            step.desired = .{ .present = .{
                .kind = .regular,
                .metadata = .{
                    .mode = try validMode(builder, value.mode, path.text),
                    .uid = value.uid,
                    .gid = value.gid,
                    .modified_nanoseconds = try validTimestamp(
                        builder,
                        value.modified_nanoseconds,
                        path.text,
                    ),
                },
                .size = value.bytes.len,
                .content_sha256 = digest,
            } };
            step.staging_entry = staging_entry;
        },
        .copy => |value| {
            step.kind = .copy_file;
            step.overwrite = value.overwrite;
            try requireOverwrite(builder, expected, value.overwrite, path.text);
            const source = root_fs.Path.init(value.source) catch
                return builder.fail(.preflight, .invalid_path, value.source);
            const source_state = try resolveSource(builder, source.text, requires);
            const present = switch (source_state) {
                .absent => return builder.fail(.preflight, .target_absent, value.source),
                .present => |state| state,
            };
            if (present.kind != .regular)
                return builder.fail(.preflight, .unsupported_kind, value.source);
            const source_digest = present.content_sha256 orelse
                return builder.fail(.preflight, .content_digest_mismatch, value.source);
            if (!std.mem.eql(u8, &source_digest, &value.source_sha256))
                return builder.fail(.preflight, .content_digest_mismatch, value.source);
            try accountStaging(builder, present.size, path.text);
            step.source = try builder.arena.dupe(u8, source.text);
            step.source_sha256 = value.source_sha256;
            step.desired = .{ .present = .{
                .kind = .regular,
                .metadata = .{
                    .mode = try validMode(builder, value.mode, path.text),
                    .uid = value.uid,
                    .gid = value.gid,
                    .modified_nanoseconds = try validTimestamp(
                        builder,
                        value.modified_nanoseconds,
                        path.text,
                    ),
                },
                .size = present.size,
                .content_sha256 = source_digest,
            } };
            step.staging_entry = staging_entry;
        },
        .symlink => |value| {
            step.kind = .publish_symlink;
            step.overwrite = value.overwrite;
            try requireOverwrite(builder, expected, value.overwrite, path.text);
            if (value.target.len == 0 or value.target.len > maximum_link_target_bytes)
                return builder.fail(.preflight, .invalid_path, value.target);
            for (value.target) |byte| {
                if (byte < 0x20 or byte == 0x7f)
                    return builder.fail(.preflight, .invalid_path, value.target);
            }
            step.desired = .{
                .present = .{
                    .kind = .symlink,
                    .metadata = .{
                        // A symbolic link has no independent mode on any system
                        // the native engine supports, so the modeled value is the
                        // constant the kernel reports.
                        .mode = symlink_mode,
                        .uid = value.uid,
                        .gid = value.gid,
                        .modified_nanoseconds = try validTimestamp(
                            builder,
                            value.modified_nanoseconds,
                            path.text,
                        ),
                    },
                    .link_target = try builder.arena.dupe(u8, value.target),
                },
            };
            step.staging_entry = staging_entry;
        },
        .hard_link => |value| {
            step.kind = .publish_hard_link;
            step.overwrite = value.overwrite;
            try requireOverwrite(builder, expected, value.overwrite, path.text);
            const source = root_fs.Path.init(value.source) catch
                return builder.fail(.preflight, .invalid_path, value.source);
            if (std.mem.eql(u8, source.text, path.text))
                return builder.fail(.preflight, .hard_link_ambiguous, value.source);
            const source_state = try resolveSource(builder, source.text, requires);
            const present = switch (source_state) {
                .absent => return builder.fail(.preflight, .hard_link_source_invalid, value.source),
                .present => |state| state,
            };
            if (present.kind != .regular)
                return builder.fail(.preflight, .hard_link_source_invalid, value.source);
            step.source = try builder.arena.dupe(u8, source.text);
            step.source_sha256 = present.content_sha256;
            var desired = present;
            desired.inode = 0;
            desired.link_count = 0;
            step.desired = .{ .present = desired };
            step.staging_entry = staging_entry;
        },
        .directory => |value| {
            step.kind = .create_directory;
            step.overwrite = value.overwrite;
            const metadata: Metadata = .{
                .mode = try validMode(builder, value.mode, path.text),
                .uid = value.uid,
                .gid = value.gid,
                .modified_nanoseconds = 0,
            };
            switch (expected) {
                .absent => {},
                .present => |state| {
                    if (state.kind != .directory)
                        try requireOverwrite(builder, expected, value.overwrite, path.text);
                    if (value.overwrite == .require_absent)
                        return builder.fail(.preflight, .target_present, path.text);
                },
            }
            step.desired = .{ .present = .{ .kind = .directory, .metadata = metadata } };
        },
        .metadata => |value| {
            step.kind = .set_metadata;
            const present = switch (expected) {
                .absent => return builder.fail(.preflight, .target_absent, path.text),
                .present => |state| state,
            };
            if (present.kind == .symlink and value.mode != null)
                return builder.fail(.preflight, .metadata_unsupported, path.text);
            var desired = present;
            desired.metadata = .{
                .mode = if (value.mode) |mode|
                    try validMode(builder, mode, path.text)
                else
                    present.metadata.mode,
                .uid = value.uid orelse present.metadata.uid,
                .gid = value.gid orelse present.metadata.gid,
                .modified_nanoseconds = if (present.kind == .directory)
                    0
                else if (value.modified_nanoseconds) |requested|
                    try validTimestamp(builder, requested, path.text)
                else
                    present.metadata.modified_nanoseconds,
            };
            step.desired = .{ .present = desired };
        },
        .remove => |value| {
            step.kind = .remove_path;
            step.removal = value.removal;
            switch (expected) {
                .absent => if (value.removal == .require_present)
                    return builder.fail(.preflight, .target_absent, path.text),
                .present => |state| if (state.kind == .directory)
                    return builder.fail(.preflight, .unsupported_kind, path.text),
            }
            step.desired = .absent;
        },
        .remove_directory => |value| {
            step.kind = .remove_directory;
            step.removal = value.removal;
            switch (expected) {
                .absent => if (value.removal == .require_present)
                    return builder.fail(.preflight, .target_absent, path.text),
                .present => |state| {
                    if (state.kind != .directory)
                        return builder.fail(.preflight, .unsupported_kind, path.text);
                    try requireEmptyDirectory(builder, path);
                },
            }
            step.desired = .absent;
        },
    }

    step.backup_entry = if (step.needsBackup()) backup_entry else null;
    if (step.satisfied()) {
        step.staging_entry = null;
        step.backup_entry = null;
    }
    // Replacing a directory means the directory has to disappear first, so it
    // must be empty exactly like an explicit removal.
    switch (step.expected) {
        .present => |state| if (state.kind == .directory and !step.satisfied() and
            step.kind != .set_metadata and step.kind != .remove_directory and
            step.kind != .create_directory)
            try requireEmptyDirectory(builder, path),
        .absent => {},
    }
    switch (step.desired) {
        .present => |state| if (state.kind != .directory) {
            switch (step.expected) {
                .present => |previous| if (previous.kind == .directory)
                    try requireEmptyDirectory(builder, path),
                .absent => {},
            }
        },
        .absent => {},
    }
    return step;
}

const symlink_mode: u32 = 0o777;

fn validMode(builder: *Builder, mode: u32, path: []const u8) BuildError!u32 {
    if (mode > maximum_mode) return builder.fail(.preflight, .metadata_unsupported, path);
    return mode;
}

/// A timestamp the kernel cannot express is refused while it is still an
/// intent rather than discovered when the syscall would truncate it.
fn validTimestamp(builder: *Builder, value: i128, path: []const u8) BuildError!i128 {
    if (value > maximum_timestamp_nanoseconds or value < minimum_timestamp_nanoseconds)
        return builder.fail(.preflight, .metadata_unsupported, path);
    return value;
}

fn requireOverwrite(
    builder: *Builder,
    expected: Expectation,
    overwrite: Overwrite,
    path: []const u8,
) BuildError!void {
    switch (expected) {
        .absent => {},
        .present => if (overwrite == .require_absent)
            return builder.fail(.preflight, .target_present, path),
    }
}

fn accountStaging(builder: *Builder, bytes: u64, path: []const u8) BuildError!void {
    builder.staging_bytes = std.math.add(u64, builder.staging_bytes, bytes) catch
        return builder.fail(.preflight, .numeric_overflow, path);
    if (builder.staging_bytes > builder.limits.max_staging_bytes)
        return builder.fail(.preflight, .capacity_exceeded, path);
}

/// A source referenced by a copy or hard link participates in the same model
/// as a target, so a source the plan republishes later is seen here.
fn resolveSource(
    builder: *Builder,
    path: []const u8,
    requires: *Requirements,
) BuildError!Expectation {
    if (withinNamespace(path)) return builder.fail(.preflight, .path_collision, path);
    const model_index = try resolveModel(builder, path, requires);
    return builder.models.items[model_index].state;
}

fn requireEmptyDirectory(builder: *Builder, path: root_fs.Path) BuildError!void {
    var dir = builder.root.openDirectory(path) catch |err| switch (err) {
        error.FileNotFound => return,
        error.SymbolicLinkComponent => return builder.fail(
            .preflight,
            .symbolic_link_component,
            path.text,
        ),
        else => return builder.fail(.preflight, .io_failed, path.text),
    };
    defer dir.close(builder.root.io);
    var iterator = dir.iterate();
    const first = iterator.next(builder.root.io) catch
        return builder.fail(.preflight, .io_failed, path.text);
    if (first != null) return builder.fail(.preflight, .directory_not_empty, path.text);
}

/// A hard link whose source is republished after the link is taken would name
/// whichever inode happened to win, so the plan is refused rather than
/// executed with an ambiguous identity.
///
/// A copy is not ambiguous the same way: it materializes the source bytes at
/// its own step, before any later step can republish them, and its recorded
/// source digest is re-proven at that moment. That is exactly what the
/// database plan's `status-old` capture depends on.
fn validateHardLinks(builder: *Builder, request: PreflightRequest) BuildError!void {
    // Steps and intents are one to one and in order, so the caller's own
    // source text is available here. A diagnostic never references the plan
    // arena, which is released before a rejection is returned.
    for (builder.steps.items, request.intents) |step, intent| {
        if (step.kind != .publish_hard_link) continue;
        const source = switch (intent) {
            .hard_link => |value| value.source,
            else => continue,
        };
        const model_index = builder.index.get(source) orelse continue;
        const model = builder.models.items[model_index];
        const last = model.last_step orelse continue;
        if (last > step.index) {
            builder.diagnostic = .{
                .surface = .preflight,
                .code = .hard_link_ambiguous,
                .step = step.index,
                .path = source,
            };
            return error.Rejected;
        }
    }
}

// ---------------------------------------------------------------------------
// Fault injection seam
// ---------------------------------------------------------------------------

/// Failures a harness may inject at a boundary. `SimulatedCrash` models power
/// loss: the engine returns immediately and performs no in-process cleanup, so
/// the durable state is exactly what a real crash would have left.
pub const HookError = error{
    SimulatedCrash,
    NoSpaceLeft,
    ShortWrite,
    SyncFailed,
    RenameFailed,
    UnlinkFailed,
    LinkFailed,
    AccessDenied,
    SystemResources,
};

/// Called immediately before the engine performs the named boundary. Only
/// tests install one; production callers leave it empty and the branch is a
/// single null check.
pub const Hooks = struct {
    context: ?*anyopaque = null,
    beforeFn: ?*const fn (?*anyopaque, Boundary, u32) HookError!void = null,

    fn before(self: Hooks, boundary: Boundary, index: u32) HookError!void {
        const call = self.beforeFn orelse return;
        try call(self.context, boundary, index);
    }
};

pub const Options = struct {
    hooks: Hooks = .{},
    cancellation: transaction_executor.Cancellation = transaction_executor.Cancellation.never(),
    deadline: ?transaction_executor.Deadline = null,
    limits: Limits = .{},
};

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub const Outcome = enum {
    /// Every step reached its desired state and the workspace was released.
    applied,
    /// The recorded old state is back in place and the workspace was released.
    rolled_back,
    /// The observed state matched neither expectation. Nothing else may
    /// mutate the root until an operator resolves it.
    recovery_required,
};

pub const Report = struct {
    outcome: Outcome,
    stage: Stage,
    steps: usize,
    /// Steps whose target actually changed during this pass.
    applied_steps: usize,
    /// Steps this pass restored to their recorded old state.
    reverted_steps: usize,
    /// Borrowed from the engine that produced the report: a diagnostic path
    /// references the engine's decoded journal, so it is valid exactly as long
    /// as that engine is.
    diagnostic: ?Diagnostic = null,
};

/// Content for one step. The default provider reads the plan's borrowed
/// slices; an alternative provider lets a caller stream archive payloads
/// without materializing them, and every provider is re-proven against the
/// step's recorded digest immediately before staging.
pub const Content = struct {
    context: ?*anyopaque = null,
    lookupFn: ?*const fn (?*anyopaque, Step) error{ContentUnavailable}![]const u8 = null,

    pub fn bytes(self: Content, step: Step) error{ContentUnavailable}![]const u8 {
        const call = self.lookupFn orelse return error.ContentUnavailable;
        return call(self.context, step);
    }

    pub fn fromPlan(plan: *const Plan) Content {
        return .{ .context = @constCast(plan), .lookupFn = planContent };
    }

    fn planContent(context: ?*anyopaque, step: Step) error{ContentUnavailable}![]const u8 {
        const plan: *const Plan = @ptrCast(@alignCast(context orelse
            return error.ContentUnavailable));
        if (step.index >= plan.contents.len) return error.ContentUnavailable;
        return plan.contents[step.index];
    }
};

/// Owns one transaction's durable state for the lifetime of the call. The
/// attempt, the root, and the plan are borrowed; the engine never closes the
/// root descriptor and never releases the attempt.
pub const Engine = struct {
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
    owned: OwnedJournal,
    progress: Progress,
    options: Options,
    diagnostic: ?Diagnostic = null,

    pub fn deinit(self: *Engine) void {
        self.progress.deinit();
        self.owned.deinit();
        self.* = undefined;
    }

    pub fn journal(self: *const Engine) Journal {
        return self.owned.journal;
    }

    pub fn stage(self: *const Engine) Stage {
        return self.progress.stage;
    }

    fn store(self: *const Engine) Store {
        return .{ .root = self.root, .limits = self.options.limits };
    }

    /// Publishes a boundary. The append is compare-and-set against the log's
    /// durable tail: a writer whose view is older than the file's chain is
    /// stale and is refused rather than allowed to fork the history.
    fn publish(self: *Engine, scope: Scope, index: u32, name: []const u8) Error!void {
        if (!self.attempt.locked()) return self.reject(.journal, .lock_lost, null, null);
        const record: ProgressRecord = .{
            .sequence = self.progress.sequence + 1,
            .scope = scope,
            .index = index,
            .stage = if (scope == .journal)
                std.meta.stringToEnum(Stage, name).?
            else
                self.progress.stage,
            .state = if (scope == .step)
                std.meta.stringToEnum(StepState, name).?
            else
                .prepared,
            .chain_sha256 = ProgressRecord.chain(
                self.progress.chain_sha256,
                self.progress.sequence + 1,
                scope,
                index,
                name,
            ),
        };
        var buffer: [progress_record_bytes]u8 = undefined;
        const encoded = record.encode(&buffer);
        try self.hook(.progress_append, index);
        const path = root_fs.Path.init(progress_path) catch unreachable;
        if (std.math.add(u64, self.progress.accepted_bytes, encoded.len) catch null == null)
            return self.reject(.progress, .numeric_overflow, null, null);
        if (self.progress.accepted_bytes + encoded.len > self.options.limits.max_progress_bytes)
            return self.reject(.progress, .capacity_exceeded, null, null);
        try self.compareAndSet();
        self.root.appendAt(path, self.progress.accepted_bytes, encoded, true) catch
            return self.reject(.progress, .io_failed, null, .progress_append);
        try self.hook(.progress_sync, index);
        self.progress.sequence = record.sequence;
        self.progress.chain_sha256 = record.chain_sha256;
        self.progress.accepted_bytes += encoded.len;
        switch (scope) {
            .journal => self.progress.stage = record.stage,
            .step => self.progress.states[index] = record.state,
        }
    }

    /// Compare-and-set against the log's durable tail. A writer whose view is
    /// older or newer than what the file actually holds would fork the
    /// history, so it is refused instead of appending. The comparison is the
    /// chain digest of the last complete record, which binds the whole prefix
    /// and the journal it belongs to.
    fn compareAndSet(self: *Engine) Error!void {
        const path = root_fs.Path.init(progress_path) catch unreachable;
        var buffer: [progress_record_bytes]u8 = undefined;
        const tail = self.root.readTail(path, &buffer) catch
            return self.reject(.progress, .io_failed, null, .progress_append);
        if (tail.size != self.progress.accepted_bytes)
            return self.reject(.progress, .progress_stale, null, .progress_append);
        if (self.progress.accepted_bytes == 0) {
            if (!std.mem.eql(u8, &self.progress.chain_sha256, &self.owned.journal.digest_sha256))
                return self.reject(.progress, .progress_stale, null, .progress_append);
            return;
        }
        if (tail.bytes.len != progress_record_bytes)
            return self.reject(.progress, .progress_corrupt, null, .progress_append);
        const decoded = decodeProgressRecord(tail.bytes[0 .. progress_record_bytes - 1]) catch
            return self.reject(.progress, .progress_corrupt, null, .progress_append);
        if (decoded.sequence != self.progress.sequence or
            !std.mem.eql(u8, &decoded.chain_sha256, &self.progress.chain_sha256))
            return self.reject(.progress, .progress_stale, null, .progress_append);
    }

    fn publishStage(self: *Engine, value: Stage) Error!void {
        if (self.progress.stage == value) return;
        try self.publish(.journal, ProgressRecord.no_index, @tagName(value));
    }

    fn publishState(self: *Engine, index: u32, value: StepState) Error!void {
        if (self.progress.states[index] == value) return;
        try self.publish(.step, index, @tagName(value));
    }

    /// Runs the harness seam for one boundary. A simulated crash propagates
    /// untouched so no cleanup runs; every other injected failure is an
    /// ordinary boundary failure and takes the same path a real one would.
    fn hook(self: *Engine, boundary: Boundary, index: u32) Error!void {
        self.options.hooks.before(boundary, index) catch |err| switch (err) {
            error.SimulatedCrash => return error.SimulatedCrash,
            else => {
                if (self.diagnostic == null) self.diagnostic = .{
                    .surface = .publication,
                    .code = .io_failed,
                    .step = if (index == ProgressRecord.no_index) null else index,
                    .path = if (index < self.owned.journal.steps.len)
                        self.owned.journal.steps[index].path
                    else
                        "",
                    .boundary = boundary,
                };
                return error.IoFailed;
            },
        };
    }

    fn reject(
        self: *Engine,
        surface: Surface,
        code: Code,
        index: ?u32,
        boundary: ?Boundary,
    ) Error {
        if (self.diagnostic == null) self.diagnostic = .{
            .surface = surface,
            .code = code,
            .step = index,
            .path = if (index) |value| self.owned.journal.steps[value].path else "",
            .boundary = boundary,
        };
        return switch (code) {
            .lock_lost => error.LockLost,
            .external_modification => error.ExternalModification,
            .verification_failed => error.VerificationFailed,
            .recovery_required => error.RecoveryRequired,
            .canceled => error.Canceled,
            .deadline_exceeded => error.DeadlineExceeded,
            .out_of_memory => error.OutOfMemory,
            .progress_corrupt => error.ProgressCorrupt,
            .progress_stale => error.StaleWriter,
            .journal_corrupt => error.JournalCorrupt,
            .io_failed => error.IoFailed,
            else => error.StoreFailed,
        };
    }
};

/// Publishes the complete plan as a durable journal and an empty progress log.
/// Nothing outside the private workspace has changed when this returns, and
/// after it returns nothing may change without a progress record.
pub fn prepare(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
    plan: *const Plan,
    evidence: Evidence,
    options: Options,
) Error!Engine {
    if (!attempt.locked()) return error.LockLost;
    const store: Store = .{ .root = root, .limits = options.limits };
    store.ensureWorkspace() catch return error.StoreFailed;
    if (try store.readJournal(allocator)) |existing| {
        var owned = existing;
        owned.deinit();
        return error.JournalPresent;
    }

    // The coordinator learns the evidence before the journal binds itself to
    // the attempt, so the record the journal names already carries the
    // authorization, program, plan, lock, database, and artifact digests this
    // transaction was compiled from.
    switch (attempt.record().state) {
        .reserved, .preflight => attempt.advance(allocator, .{
            .state = .preflight,
            .phase = .preflight,
            .evidence = attemptEvidence(evidence),
        }) catch |err| return mapAttemptError(err),
        // A transaction may be split into several journalled phases under one
        // attempt; the attempt keeps its mutation evidence and only gains the
        // new phase's digests.
        .mutating => attempt.advance(allocator, .{
            .state = .mutating,
            .phase = .mutation,
            .evidence = attemptEvidence(evidence),
        }) catch |err| return mapAttemptError(err),
        else => return error.AttemptNotMutable,
    }
    const record = attempt.record();

    var journal: Journal = .{
        .attempt_id = record.attempt_id,
        .attempt_generation = record.generation,
        .attempt_digest_sha256 = record.digest_sha256,
        .install_root = record.install_root,
        .root_identity_sha256 = record.root_identity_sha256,
        .evidence = evidence,
        .device = plan.device,
        .staging_bytes = plan.staging_bytes,
        .budget_bytes = options.limits.max_staging_bytes,
        .steps = plan.steps,
        .steps_sha256 = plan.steps_sha256,
        .digest_sha256 = @splat(0),
    };
    journal.digest_sha256 = journalDigest(journal);

    options.hooks.before(.journal_write, ProgressRecord.no_index) catch |err| switch (err) {
        error.SimulatedCrash => return error.SimulatedCrash,
        else => return error.IoFailed,
    };
    try store.writeJournal(allocator, journal);
    // A simulated crash must leave exactly what a real one would, so the
    // journal is only withdrawn when preparation failed for an ordinary
    // reason and nothing durable can depend on it yet.
    errdefer |err| if (err != error.SimulatedCrash) store.clear(allocator) catch {};
    options.hooks.before(.journal_sync, ProgressRecord.no_index) catch |err| switch (err) {
        error.SimulatedCrash => return error.SimulatedCrash,
        else => return error.IoFailed,
    };
    try store.createProgress();

    const bytes = try journal.canonicalJson(allocator);
    defer allocator.free(bytes);
    var owned = try decode(allocator, bytes, options.limits.max_document_bytes);
    errdefer owned.deinit();
    var progress = try replayProgress(allocator, owned.journal, &.{});
    errdefer progress.deinit();

    var engine: Engine = .{
        .allocator = allocator,
        .root = root,
        .attempt = attempt,
        .owned = owned,
        .progress = progress,
        .options = options,
    };
    // The prepared boundary is published explicitly rather than assumed from
    // an empty log, so the log always states which journal it belongs to.
    try engine.publish(.journal, ProgressRecord.no_index, @tagName(Stage.prepared));
    return engine;
}

/// Reopens the durable transaction for this root. `null` when no journal
/// exists. The caller must present the attempt the journal was published
/// under, or a newer generation of it.
pub fn open(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
    options: Options,
) Error!?Engine {
    if (!attempt.locked()) return error.LockLost;
    const store: Store = .{ .root = root, .limits = options.limits };
    var owned = (try store.readJournal(allocator)) orelse return null;
    errdefer owned.deinit();
    try store.ensureProgress();
    const record = attempt.record();
    if (!std.mem.eql(u8, &owned.journal.attempt_id, &record.attempt_id))
        return error.AttemptMismatch;
    if (!std.mem.eql(u8, &owned.journal.root_identity_sha256, &record.root_identity_sha256))
        return error.RootMismatch;
    if (!owned.journal.matchesAttempt(record)) return error.StaleAttempt;

    const bytes = try store.readProgressBytes(allocator);
    defer allocator.free(bytes);
    var progress = try replayProgress(allocator, owned.journal, bytes);
    errdefer progress.deinit();
    return .{
        .allocator = allocator,
        .root = root,
        .attempt = attempt,
        .owned = owned,
        .progress = progress,
        .options = options,
    };
}

/// Applies every step in order. On any failure the transaction is rolled back
/// to the recorded old state; on a failure during rollback the journal
/// durably requires recovery and no further mutation is permitted.
pub fn apply(engine: *Engine, content: Content) Error!Report {
    if (!engine.attempt.locked()) return error.LockLost;
    switch (engine.progress.stage) {
        // An unresolved ambiguity blocks every further mutation.
        .recovery_required => return error.RecoveryRequired,
        .completed => return finishedReport(engine, .applied),
        .rolled_back => return finishedReport(engine, .rolled_back),
        // A transaction that already turned around is never pushed forward
        // again; the recorded direction is resumed instead.
        .rolling_back => return rollback(engine),
        .releasing_rollback => {
            try release(engine, .rolled_back);
            return finishedReport(engine, .rolled_back);
        },
        .verified, .completing => {
            try release(engine, .completed);
            return finishedReport(engine, .applied);
        },
        .prepared, .applying => {},
    }
    // Staging, backups, and every target change are mutations of the selected
    // root, so the coordinator learns about them before the first one.
    engine.attempt.markMutationStarted(engine.allocator, .mutation) catch |err|
        return mapAttemptError(err);
    try engine.publishStage(.applying);

    var applied: usize = 0;
    forward(engine, content, &applied) catch |err| switch (err) {
        error.SimulatedCrash => return error.SimulatedCrash,
        error.LockLost => return error.LockLost,
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            const failure = engine.diagnostic;
            var report = rollback(engine) catch |recovery_error| switch (recovery_error) {
                error.SimulatedCrash => return error.SimulatedCrash,
                else => return recovery_error,
            };
            report.diagnostic = failure orelse report.diagnostic;
            return report;
        },
    };

    try engine.publishStage(.verified);
    try release(engine, .completed);
    var report = finishedReport(engine, .applied);
    report.applied_steps = applied;
    return report;
}

fn forward(engine: *Engine, content: Content, applied: *usize) Error!void {
    for (engine.owned.journal.steps) |step| {
        if (engine.options.cancellation.cancelled())
            return engine.reject(.publication, .canceled, step.index, null);
        if (engine.options.deadline) |deadline| {
            if (deadline.expired())
                return engine.reject(.publication, .deadline_exceeded, step.index, null);
        }
        if (!engine.attempt.locked())
            return engine.reject(.publication, .lock_lost, step.index, null);
        if (engine.progress.state(step.index).rank() >= StepState.verified.rank()) continue;
        try applyStep(engine, step, content);
        applied.* += 1;
    }
}

fn applyStep(engine: *Engine, step: Step, content: Content) Error!void {
    for (step.boundaries()) |boundary| {
        if (engine.progress.state(step.index).rank() >= boundary.rank()) continue;
        switch (boundary) {
            .staged => try stageStep(engine, step, content),
            .backup_captured => try captureBackup(engine, step),
            .published => try publishStep(engine, step),
            .metadata_applied => try applyStepMetadata(engine, step),
            .parent_synced => try syncParent(engine, step),
            .verified => try verifyStep(engine, step),
            .prepared, .completed, .reverted => unreachable,
        }
        try engine.publishState(step.index, boundary);
    }
}

// ---------------------------------------------------------------------------
// Durability boundaries
// ---------------------------------------------------------------------------

const WorkspacePath = struct {
    buffer: [staging_path.len + 1 + 8]u8,
    length: usize,

    fn path(self: *const WorkspacePath) root_fs.Path {
        return .{ .text = self.buffer[0..self.length] };
    }
};

fn workspacePath(directory: []const u8, name: []const u8) WorkspacePath {
    var result: WorkspacePath = .{ .buffer = undefined, .length = 0 };
    const written = std.fmt.bufPrint(&result.buffer, "{s}/{s}", .{ directory, name }) catch
        unreachable;
    result.length = written.len;
    return result;
}

fn stagingFor(step: Step) ?WorkspacePath {
    const name = step.staging_entry orelse return null;
    return workspacePath(staging_path, name);
}

fn backupFor(step: Step) ?WorkspacePath {
    const name = step.backup_entry orelse return null;
    return workspacePath(backup_path, name);
}

fn targetPath(step: Step) root_fs.Path {
    return .{ .text = step.path };
}

/// Materializes the new content inside the private workspace. The staged
/// entry is created exclusively, fsynced, and given its exact final metadata
/// before it is ever visible at the target name, so publication is a single
/// atomic rename of a fully formed entry.
fn stageStep(engine: *Engine, step: Step, content: Content) Error!void {
    const staging = stagingFor(step) orelse return;
    const desired = switch (step.desired) {
        .absent => return,
        .present => |value| value,
    };
    try engine.hook(.stage_create, step.index);
    removeWorkspaceEntry(engine, staging.path()) catch
        return engine.reject(.staging, .io_failed, step.index, .stage_create);

    switch (step.kind) {
        .publish_file, .copy_file => {
            const bytes = if (step.kind == .publish_file)
                content.bytes(step) catch
                    return engine.reject(.staging, .io_failed, step.index, .stage_create)
            else
                try readSource(engine, step);
            defer if (step.kind == .copy_file) engine.allocator.free(@constCast(bytes));
            try proveContent(engine, step, desired, bytes);
            try engine.hook(.stage_write, step.index);
            engine.root.writeNewFile(
                staging.path(),
                bytes,
                .{ .permissions = staged_permissions },
                false,
            ) catch return engine.reject(.staging, .io_failed, step.index, .stage_write);
            try engine.hook(.stage_sync, step.index);
            engine.root.syncRegularFile(staging.path()) catch
                return engine.reject(.staging, .io_failed, step.index, .stage_sync);
        },
        .publish_symlink => {
            const target = desired.link_target orelse
                return engine.reject(.staging, .precondition_failed, step.index, .stage_create);
            engine.root.createSymbolicLink(staging.path(), target) catch
                return engine.reject(.staging, .io_failed, step.index, .stage_create);
        },
        .publish_hard_link => {
            const source = step.source orelse
                return engine.reject(.staging, .precondition_failed, step.index, .stage_create);
            try engine.hook(.backup_link, step.index);
            engine.root.createHardLink(.{ .text = source }, staging.path()) catch
                return engine.reject(.staging, .io_failed, step.index, .stage_create);
        },
        else => return,
    }

    if (step.kind != .publish_hard_link) {
        try engine.hook(.stage_metadata, step.index);
        applyDesiredMetadata(engine, staging.path(), desired) catch
            return engine.reject(.staging, .metadata_unsupported, step.index, .stage_metadata);
    }
    try engine.hook(.stage_dir_sync, step.index);
    engine.root.syncDirectory(root_fs.Path.init(staging_path) catch unreachable) catch
        return engine.reject(.staging, .io_failed, step.index, .stage_dir_sync);
}

/// The content that will be published must still hash to the exact digest the
/// plan authorized, and an archive-backed step must still name the exact
/// validated application it was compiled from.
fn proveContent(engine: *Engine, step: Step, desired: State, bytes: []const u8) Error!void {
    const expected = desired.content_sha256 orelse
        return engine.reject(.staging, .content_digest_mismatch, step.index, .stage_write);
    if (bytes.len != desired.size)
        return engine.reject(.staging, .content_digest_mismatch, step.index, .stage_write);
    var digest: [32]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    if (!std.crypto.timing_safe.eql([32]u8, digest, expected))
        return engine.reject(.staging, .content_digest_mismatch, step.index, .stage_write);
}

fn readSource(engine: *Engine, step: Step) Error![]const u8 {
    const source = step.source orelse
        return engine.reject(.staging, .precondition_failed, step.index, .stage_create);
    return engine.root.readFileAlloc(
        engine.allocator,
        .{ .text = source },
        engine.options.limits.max_copy_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => engine.reject(.staging, .io_failed, step.index, .stage_create),
    };
}

/// Preserves the exact replaceable content before the target name is taken
/// over. The backup is a hard link, so it costs no data copy and holds the
/// old inode until the whole transaction verifies.
fn captureBackup(engine: *Engine, step: Step) Error!void {
    const backup = backupFor(step) orelse return;
    const expected = switch (step.expected) {
        .absent => return,
        .present => |value| value,
    };
    var observation: Observation = .{};
    try requirePrecondition(engine, step, &observation);
    if (engine.root.entryIfExists(backup.path()) catch null) |existing| {
        if (existing.inode == expected.inode) return;
        removeWorkspaceEntry(engine, backup.path()) catch
            return engine.reject(.backup, .io_failed, step.index, .backup_link);
    }
    try engine.hook(.backup_link, step.index);
    engine.root.createHardLink(targetPath(step), backup.path()) catch
        return engine.reject(.backup, .io_failed, step.index, .backup_link);
    try engine.hook(.backup_dir_sync, step.index);
    engine.root.syncDirectory(root_fs.Path.init(backup_path) catch unreachable) catch
        return engine.reject(.backup, .io_failed, step.index, .backup_dir_sync);
}

/// Scratch for one observation. The link target is borrowed from this buffer,
/// so observing a target never allocates and a long transaction cannot grow
/// the engine's memory with every comparison it makes.
const Observation = struct {
    link_buffer: [maximum_link_target_bytes]u8 = undefined,
    state: Expectation = .absent,
};

/// Compares the target to its recorded precondition. A retry after an
/// interruption is satisfied by the recorded desired state, and anything else
/// is an external modification, never a guess.
fn requirePrecondition(engine: *Engine, step: Step, observation: *Observation) Error!void {
    try engine.hook(.precondition_check, step.index);
    try observeTarget(engine, step, targetPath(step), observation);
    if (matches(observation.state, step.expected)) return;
    if (matches(observation.state, step.desired)) return;
    return engine.reject(.publication, .external_modification, step.index, .precondition_check);
}

fn observeTarget(
    engine: *Engine,
    step: Step,
    path: root_fs.Path,
    observation: *Observation,
) Error!void {
    observation.state = .absent;
    const found = engine.root.entryIfExists(path) catch
        return engine.reject(.publication, .io_failed, step.index, .precondition_check);
    const value = found orelse return;
    const kind = Kind.fromFileKind(value.kind) orelse
        return engine.reject(.publication, .unsupported_kind, step.index, .precondition_check);
    var state: State = .{
        .kind = kind,
        .metadata = .{
            .mode = value.mode,
            .uid = value.uid,
            .gid = value.gid,
            .modified_nanoseconds = value.modified_nanoseconds,
        },
        .size = if (kind == .regular) value.size else 0,
        .inode = value.inode,
        .link_count = value.link_count,
    };
    switch (kind) {
        .regular => state.content_sha256 = hashPath(engine, path) catch
            return engine.reject(.publication, .io_failed, step.index, .precondition_check),
        .symlink => state.link_target = engine.root.readSymbolicLink(
            path,
            &observation.link_buffer,
        ) catch
            return engine.reject(.publication, .io_failed, step.index, .precondition_check),
        .directory => state.metadata.modified_nanoseconds = 0,
    }
    observation.state = .{ .present = state };
}

fn matches(actual: Expectation, expected: Expectation) bool {
    return switch (expected) {
        .absent => actual == .absent,
        .present => |wanted| switch (actual) {
            .absent => false,
            .present => |found| statesEqual(found, wanted),
        },
    };
}

fn hashPath(engine: *Engine, path: root_fs.Path) ![32]u8 {
    var file = try engine.root.openRegularFile(path);
    defer file.close(engine.root.io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(engine.root.io, &buffer);
    var hash = Sha256.init(.{});
    while (true) {
        const chunk = reader.interface.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return error.IoFailed,
        };
        hash.update(chunk);
        reader.interface.toss(chunk.len);
    }
    return hash.finalResult();
}

/// Takes over the target name. Staged publications are one atomic rename;
/// transitions that a rename cannot express remove the old entry first and are
/// resumable because the recorded expectation and desired state disagree about
/// exactly one thing.
fn publishStep(engine: *Engine, step: Step) Error!void {
    var observation: Observation = .{};
    try requirePrecondition(engine, step, &observation);
    const actual = observation.state;
    if (matches(actual, step.desired) and step.kind != .create_directory) return;

    switch (step.kind) {
        .publish_file, .copy_file, .publish_symlink, .publish_hard_link => {
            const staging = stagingFor(step) orelse
                return engine.reject(.publication, .staging_missing, step.index, .publish_rename);
            if (engine.root.entryIfExists(staging.path()) catch null == null)
                return engine.reject(.publication, .staging_missing, step.index, .publish_rename);
            try removeDirectoryTarget(engine, step, actual);
            try engine.hook(.publish_rename, step.index);
            engine.root.rename(staging.path(), targetPath(step), .replace) catch
                return engine.reject(.publication, .io_failed, step.index, .publish_rename);
        },
        .create_directory => {
            switch (actual) {
                .present => |state| if (state.kind != .directory) {
                    try engine.hook(.target_remove, step.index);
                    engine.root.removeFile(targetPath(step)) catch
                        return engine.reject(.publication, .io_failed, step.index, .target_remove);
                } else return,
                .absent => {},
            }
            try engine.hook(.publish_create, step.index);
            const desired = switch (step.desired) {
                .absent => unreachable,
                .present => |value| value,
            };
            engine.root.createDirectory(
                targetPath(step),
                .fromMode(@intCast(desired.metadata.mode)),
            ) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return engine.reject(.publication, .io_failed, step.index, .publish_create),
            };
        },
        .remove_path => {
            try engine.hook(.target_remove, step.index);
            engine.root.removeFile(targetPath(step)) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return engine.reject(.publication, .io_failed, step.index, .target_remove),
            };
        },
        .remove_directory => {
            try engine.hook(.target_remove, step.index);
            engine.root.removeDirectory(targetPath(step)) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return engine.reject(.publication, .io_failed, step.index, .target_remove),
            };
        },
        .set_metadata => {},
    }
}

/// A directory cannot be renamed over, so a directory-to-file or
/// directory-to-symlink transition removes the empty directory first.
fn removeDirectoryTarget(engine: *Engine, step: Step, actual: Expectation) Error!void {
    const state = switch (actual) {
        .absent => return,
        .present => |value| value,
    };
    if (state.kind != .directory) return;
    try engine.hook(.target_remove, step.index);
    engine.root.removeDirectory(targetPath(step)) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return engine.reject(.publication, .io_failed, step.index, .target_remove),
    };
}

fn applyStepMetadata(engine: *Engine, step: Step) Error!void {
    const desired = switch (step.desired) {
        .absent => return,
        .present => |value| value,
    };
    // A metadata-only step never takes the target name over, so whatever
    // inode is at the path right now is the one that would be changed. It
    // must still be the recorded one; a directory this step just created is
    // exempt because it has not received its metadata yet.
    if (step.kind == .set_metadata) {
        var observation: Observation = .{};
        try requirePrecondition(engine, step, &observation);
    }
    try engine.hook(.metadata_apply, step.index);
    applyDesiredMetadata(engine, targetPath(step), desired) catch
        return engine.reject(.metadata, .io_failed, step.index, .metadata_apply);
    switch (desired.kind) {
        .regular => engine.root.syncRegularFile(targetPath(step)) catch
            return engine.reject(.metadata, .io_failed, step.index, .metadata_apply),
        .directory => engine.root.syncDirectory(targetPath(step)) catch
            return engine.reject(.metadata, .io_failed, step.index, .metadata_apply),
        .symlink => {},
    }
}

/// Only the components that actually differ are written, so an unprivileged
/// caller that models the ownership it already has never issues a `chown` it
/// is not allowed to make.
fn applyDesiredMetadata(engine: *Engine, path: root_fs.Path, desired: State) !void {
    const current = try engine.root.entry(path);
    // Never write metadata onto a kind the plan did not model, which would
    // mean the entry was replaced since it was observed.
    if (Kind.fromFileKind(current.kind) != desired.kind) return error.UnexpectedPathKind;
    var update: root_fs.MetadataUpdate = .{};
    if (desired.kind != .symlink and current.mode != desired.metadata.mode)
        update.mode = desired.metadata.mode;
    if (current.modeled and current.uid != desired.metadata.uid) update.uid = desired.metadata.uid;
    if (current.modeled and current.gid != desired.metadata.gid) update.gid = desired.metadata.gid;
    if (desired.kind != .directory and
        current.modified_nanoseconds != desired.metadata.modified_nanoseconds)
        update.modified_nanoseconds = desired.metadata.modified_nanoseconds;
    try engine.root.applyMetadata(path, update);
}

fn syncParent(engine: *Engine, step: Step) Error!void {
    try engine.hook(.parent_sync, step.index);
    const path = targetPath(step);
    if (path.parent()) |parent| {
        engine.root.syncDirectory(parent) catch
            return engine.reject(.publication, .io_failed, step.index, .parent_sync);
    } else engine.root.syncRoot() catch
        return engine.reject(.publication, .io_failed, step.index, .parent_sync);
}

fn verifyStep(engine: *Engine, step: Step) Error!void {
    try engine.hook(.verify, step.index);
    var observation: Observation = .{};
    try observeTarget(engine, step, targetPath(step), &observation);
    if (!matches(observation.state, step.desired))
        return engine.reject(.verification, .verification_failed, step.index, .verify);
}

fn removeWorkspaceEntry(engine: *Engine, path: root_fs.Path) !void {
    engine.root.removeFile(path) catch |err| switch (err) {
        error.FileNotFound => {},
        error.IsDir => try engine.root.removeDirectory(path),
        else => return err,
    };
}

// ---------------------------------------------------------------------------
// Rollback, release, and recovery
// ---------------------------------------------------------------------------

/// Restores the recorded old state of every step in reverse order. Backups
/// are still intact because they are released only after the whole
/// transaction verifies, so a rollback never needs the original content back.
fn rollback(engine: *Engine) Error!Report {
    try engine.publishStage(.rolling_back);
    var reverted: usize = 0;
    var index = engine.owned.journal.steps.len;
    while (index > 0) {
        index -= 1;
        const step = engine.owned.journal.steps[index];
        if (engine.progress.state(step.index) == .reverted) continue;
        revertStep(engine, step) catch |err| switch (err) {
            error.SimulatedCrash => return error.SimulatedCrash,
            error.OutOfMemory => return error.OutOfMemory,
            else => return requireRecovery(engine),
        };
        try engine.publishState(step.index, .reverted);
        reverted += 1;
    }
    release(engine, .rolled_back) catch |err| switch (err) {
        error.SimulatedCrash => return error.SimulatedCrash,
        error.OutOfMemory => return error.OutOfMemory,
        else => return requireRecovery(engine),
    };
    var report = finishedReport(engine, .rolled_back);
    report.reverted_steps = reverted;
    return report;
}

fn revertStep(engine: *Engine, step: Step) Error!void {
    var observation: Observation = .{};
    try observeTarget(engine, step, targetPath(step), &observation);
    const actual = observation.state;
    if (matches(actual, step.expected)) return;
    if (!matches(actual, step.desired))
        return engine.reject(.recovery, .recovery_required, step.index, .restore_rename);

    // A metadata-only step never took the target name over, so undoing it is
    // republishing the recorded old mode, ownership, and timestamp.
    if (step.kind == .set_metadata) {
        const expected = switch (step.expected) {
            .absent => return engine.reject(.recovery, .recovery_required, step.index, null),
            .present => |value| value,
        };
        try engine.hook(.metadata_apply, step.index);
        applyDesiredMetadata(engine, targetPath(step), expected) catch
            return engine.reject(.recovery, .io_failed, step.index, .metadata_apply);
        try observeTarget(engine, step, targetPath(step), &observation);
        if (!matches(observation.state, step.expected))
            return engine.reject(.recovery, .recovery_required, step.index, .verify);
        return;
    }

    switch (step.expected) {
        .absent => switch (step.kind) {
            .create_directory => {
                try engine.hook(.target_remove, step.index);
                engine.root.removeDirectory(targetPath(step)) catch |err| switch (err) {
                    error.FileNotFound => {},
                    else => return engine.reject(.recovery, .io_failed, step.index, .target_remove),
                };
            },
            else => {
                try engine.hook(.target_remove, step.index);
                engine.root.removeFile(targetPath(step)) catch |err| switch (err) {
                    error.FileNotFound => {},
                    else => return engine.reject(.recovery, .io_failed, step.index, .target_remove),
                };
            },
        },
        .present => |expected| switch (expected.kind) {
            .regular => {
                const backup = backupFor(step) orelse
                    return engine.reject(.recovery, .backup_missing, step.index, .restore_rename);
                if (engine.root.entryIfExists(backup.path()) catch null == null)
                    return engine.reject(.recovery, .backup_missing, step.index, .restore_rename);
                try removeDirectoryTarget(engine, step, actual);
                try engine.hook(.restore_rename, step.index);
                engine.root.rename(backup.path(), targetPath(step), .replace) catch
                    return engine.reject(.recovery, .io_failed, step.index, .restore_rename);
            },
            .symlink => {
                const target = expected.link_target orelse
                    return engine.reject(.recovery, .backup_missing, step.index, .restore_create);
                try engine.hook(.restore_create, step.index);
                engine.root.publishSymbolicLink(targetPath(step), target, .{
                    .overwrite = .replace,
                    .durable = true,
                }) catch return engine.reject(.recovery, .io_failed, step.index, .restore_create);
            },
            .directory => {
                switch (actual) {
                    .present => |state| if (state.kind != .directory) {
                        try engine.hook(.target_remove, step.index);
                        engine.root.removeFile(targetPath(step)) catch
                            return engine.reject(.recovery, .io_failed, step.index, .target_remove);
                    },
                    .absent => {},
                }
                try engine.hook(.restore_create, step.index);
                engine.root.createDirectory(
                    targetPath(step),
                    .fromMode(@intCast(expected.metadata.mode)),
                ) catch |err| switch (err) {
                    error.PathAlreadyExists => {},
                    else => return engine.reject(.recovery, .io_failed, step.index, .restore_create),
                };
            },
        },
    }

    switch (step.expected) {
        .absent => {},
        .present => |expected| {
            try engine.hook(.metadata_apply, step.index);
            applyDesiredMetadata(engine, targetPath(step), expected) catch
                return engine.reject(.recovery, .io_failed, step.index, .metadata_apply);
        },
    }
    try syncParent(engine, step);
    try observeTarget(engine, step, targetPath(step), &observation);
    if (!matches(observation.state, step.expected))
        return engine.reject(.recovery, .recovery_required, step.index, .verify);
}

/// Releases every staging and backup entry. It runs only after the whole
/// transaction verified or was fully restored, so no released entry can still
/// be needed.
fn release(engine: *Engine, terminal: Stage) Error!void {
    if (engine.progress.stage == terminal) return;
    try engine.publishStage(switch (terminal) {
        .completed => .completing,
        else => .releasing_rollback,
    });
    for (engine.owned.journal.steps) |step| {
        if (stagingFor(step)) |staging| {
            try engine.hook(.release_staging, step.index);
            removeWorkspaceEntry(engine, staging.path()) catch
                return engine.reject(.staging, .io_failed, step.index, .release_staging);
        }
        if (backupFor(step)) |backup| {
            try engine.hook(.release_backup, step.index);
            removeWorkspaceEntry(engine, backup.path()) catch
                return engine.reject(.backup, .io_failed, step.index, .release_backup);
        }
    }
    engine.root.syncDirectory(root_fs.Path.init(staging_path) catch unreachable) catch
        return engine.reject(.staging, .io_failed, null, .release_staging);
    engine.root.syncDirectory(root_fs.Path.init(backup_path) catch unreachable) catch
        return engine.reject(.backup, .io_failed, null, .release_backup);
    try engine.publishStage(terminal);
}

/// Durably records that the observed state matches neither expectation. The
/// root-operation attempt is told as well, so no other caller can start a
/// mutation while this is unresolved.
fn requireRecovery(engine: *Engine) Error!Report {
    engine.publishStage(.recovery_required) catch |err| switch (err) {
        error.SimulatedCrash => return error.SimulatedCrash,
        else => {},
    };
    engine.attempt.requireRecovery(engine.allocator, .mutation) catch {};
    var report = finishedReport(engine, .recovery_required);
    report.diagnostic = engine.diagnostic orelse .{
        .surface = .recovery,
        .code = .recovery_required,
    };
    return report;
}

fn finishedReport(engine: *const Engine, outcome: Outcome) Report {
    return .{
        .outcome = outcome,
        .stage = engine.progress.stage,
        .steps = engine.owned.journal.steps.len,
        .applied_steps = 0,
        .reverted_steps = 0,
        .diagnostic = engine.diagnostic,
    };
}

fn mapAttemptError(err: root_operation.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.LockLost => error.LockLost,
        error.StaleAttempt => error.StaleAttempt,
        error.AttemptMismatch => error.AttemptMismatch,
        error.RecoveryRequired => error.RecoveryRequired,
        error.InvalidTransition, error.MutationEvidenceRequired => error.AttemptNotMutable,
        else => error.StoreFailed,
    };
}

/// The subset of this module's evidence the shared root-operation record can
/// carry. The database publication plan digest stays in the journal, which is
/// the only document that describes the intents it authorizes.
fn attemptEvidence(evidence: Evidence) root_operation.Evidence {
    return .{
        .authorization_sha256 = evidence.authorization_sha256,
        .program_sha256 = evidence.program_sha256,
        .plan_sha256 = evidence.plan_sha256,
        .exact_lock = evidence.exact_lock,
        .database_generation_sha256 = evidence.database_generation_sha256,
        .artifact_evidence_sha256 = evidence.artifact_evidence_sha256,
    };
}

/// Resolves an interrupted transaction. The recorded stage decides the
/// direction: everything up to and including `rolling_back` restores the
/// recorded old state, `verified` and later finish releasing the workspace,
/// and `recovery_required` refuses. Ambiguity anywhere publishes a durable
/// recovery requirement instead of guessing.
pub fn recover(engine: *Engine) Error!Report {
    if (!engine.attempt.locked()) return error.LockLost;
    if (engine.attempt.record().state.blocksMutation())
        engine.attempt.beginRecovery(engine.allocator, .mutation) catch |err|
            return mapAttemptError(err);
    return switch (engine.progress.stage.direction()) {
        .restore_old => rollback(engine),
        .finish_new => finish: {
            release(engine, .completed) catch |err| switch (err) {
                error.SimulatedCrash => return error.SimulatedCrash,
                error.OutOfMemory => return error.OutOfMemory,
                else => break :finish try requireRecovery(engine),
            };
            break :finish finishedReport(engine, .applied);
        },
        // The restoration already finished; only the workspace release is
        // owed, and the root holds the recorded old state.
        .finish_rollback => finish: {
            release(engine, .rolled_back) catch |err| switch (err) {
                error.SimulatedCrash => return error.SimulatedCrash,
                error.OutOfMemory => return error.OutOfMemory,
                else => break :finish try requireRecovery(engine),
            };
            break :finish finishedReport(engine, .rolled_back);
        },
        .refuse => blk: {
            var report = finishedReport(engine, .recovery_required);
            report.diagnostic = .{ .surface = .recovery, .code = .recovery_required };
            break :blk report;
        },
    };
}

/// Removes the journal, the progress log, and the workspace entries. Only a
/// completed transaction may be cleared, so evidence is never dropped while
/// anything is still owed.
pub fn clear(engine: *Engine) Error!void {
    if (!engine.attempt.locked()) return error.LockLost;
    if (engine.progress.stage.blocksMutation()) return error.RecoveryRequired;
    try engine.store().clear(engine.allocator);
}

/// Read-only classification of a root for a caller that has not taken the
/// mutation lock. It never gates a mutation on its own; the lock and the
/// journal do.
pub fn inspect(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    limits: Limits,
) Error!?Stage {
    const store: Store = .{ .root = root, .limits = limits };
    var owned = (try store.readJournal(allocator)) orelse return null;
    defer owned.deinit();
    const bytes = try store.readProgressBytes(allocator);
    defer allocator.free(bytes);
    var progress = try replayProgress(allocator, owned.journal, bytes);
    defer progress.deinit();
    return progress.stage;
}

// ---------------------------------------------------------------------------
// Package database publication adapter
// ---------------------------------------------------------------------------

/// Ordered, path-joined intents lowered from one package-database publication
/// plan, plus the evidence that binds them to the consumed generation.
pub const DatabaseIntents = struct {
    intents: []const Intent,
    evidence: Evidence,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *DatabaseIntents) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const DatabaseResult = union(enum) {
    intents: DatabaseIntents,
    diagnostic: Diagnostic,
};

/// Where the database lives and who owns it. Ownership is explicit rather
/// than assumed so a hermetic root can be published by the user that owns it
/// and a production root by `root`.
pub const DatabaseOptions = struct {
    directory: []const u8 = package_database.database_directory,
    uid: u32 = 0,
    gid: u32 = 0,
    modified_nanoseconds: i128 = 0,
};

/// Typed adapter from `package_database_changes.Plan` to mutation intents.
///
/// The plan's own ordering is the durable contract: `status-old` is captured
/// first, then every `info` file, then architectures and triggers, and
/// `status` last, so a crash before the final publication leaves the previous
/// generation intact. This adapter preserves that order exactly, joins every
/// path under the database directory, and refuses a plan whose shape does not
/// match, instead of reinterpreting it.
pub fn lowerDatabasePlan(
    allocator: std.mem.Allocator,
    plan: package_database_changes.Plan,
    options: DatabaseOptions,
) Error!DatabaseResult {
    const directory = options.directory;
    if (plan.writes.len == 0) return .{ .diagnostic = .{
        .surface = .database,
        .code = .database_plan_mismatch,
        .path = directory,
    } };
    const first = plan.writes[0];
    if (first.kind != .copy or !std.mem.eql(u8, first.path, package_database.status_old_path) or
        !std.mem.eql(u8, first.source, package_database.status_path))
        return .{ .diagnostic = .{
            .surface = .database,
            .code = .database_plan_mismatch,
            .path = first.path,
        } };
    const last = plan.writes[plan.writes.len - 1];
    if (last.kind != .replace or !std.mem.eql(u8, last.path, package_database.status_path))
        return .{ .diagnostic = .{
            .surface = .database,
            .code = .database_plan_mismatch,
            .path = last.path,
        } };

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const intents = try owned.alloc(Intent, plan.writes.len);
    for (plan.writes, 0..) |write, index| {
        const path = try std.fmt.allocPrint(owned, "{s}/{s}", .{ directory, write.path });
        intents[index] = switch (write.kind) {
            .replace => .{ .file = .{
                .path = path,
                .bytes = write.bytes,
                .mode = write.mode,
                .uid = options.uid,
                .gid = options.gid,
                .modified_nanoseconds = options.modified_nanoseconds,
                .expected_sha256 = write.sha256,
            } },
            .copy => .{ .copy = .{
                .path = path,
                .source = try std.fmt.allocPrint(owned, "{s}/{s}", .{ directory, write.source }),
                .source_sha256 = write.sha256,
                .mode = write.mode,
                .uid = options.uid,
                .gid = options.gid,
                .modified_nanoseconds = options.modified_nanoseconds,
            } },
            .remove => .{ .remove = .{ .path = path, .removal = .allow_absent } },
        };
    }
    return .{ .intents = .{
        .intents = intents,
        .evidence = databaseEvidence(plan),
        .arena = arena,
        .backing_allocator = allocator,
    } };
}

/// Evidence that binds a journal to the exact consumed database generation and
/// the exact publication plan compiled from it.
pub fn databaseEvidence(plan: package_database_changes.Plan) Evidence {
    return .{
        .database_generation_sha256 = plan.base_generation.sha256,
        .database_plan_sha256 = plan.digest,
    };
}

// ---------------------------------------------------------------------------
// Archive binding
// ---------------------------------------------------------------------------

pub const ArchiveBindingError = error{ArtifactBindingMismatch};

/// Re-proves that the in-memory archive bytes still carry the authenticated
/// size and digest recorded at acquisition and that the model still reproduces
/// the exact authorized application digest. Callers run this immediately
/// before the archive's content is staged, so no stale inventory and no
/// substituted payload can reach a staging entry.
pub fn bindArchive(
    model: *const archive_application.Model,
    bytes: []const u8,
    artifact: u32,
    authorized_application_sha256: [32]u8,
) ArchiveBindingError!ArtifactBinding {
    model.verifyArtifactBinding(bytes) catch return error.ArtifactBindingMismatch;
    if (!std.crypto.timing_safe.eql([32]u8, model.digest, authorized_application_sha256))
        return error.ArtifactBindingMismatch;
    return .{ .index = artifact, .application_sha256 = model.digest };
}

/// Converts one modeled archive entry into the exact intent that publishes it.
///
/// This is a typed conversion only. Which paths a package may own, how
/// conflicting ownership is resolved, conffile decisions, and the unpack
/// lifecycle stay with the package layer; nothing here decides them.
pub fn archiveFileIntent(
    path: []const u8,
    model: *const archive_application.Model,
    file: archive_application.File,
    binding: ArtifactBinding,
) error{ UnsupportedArchiveEntry, MissingContent }!Intent {
    return switch (file.kind) {
        .regular => .{ .file = .{
            .path = path,
            .bytes = model.fileBytes(file) catch return error.MissingContent,
            .mode = file.permissions() | (file.mode & 0o7000),
            .uid = std.math.cast(u32, file.uid) orelse return error.UnsupportedArchiveEntry,
            .gid = std.math.cast(u32, file.gid) orelse return error.UnsupportedArchiveEntry,
            .modified_nanoseconds = @as(i128, file.mtime) * std.time.ns_per_s,
            .expected_sha256 = file.sha256 orelse return error.MissingContent,
            .artifact = binding,
        } },
        .directory => .{ .directory = .{
            .path = path,
            .mode = file.permissions() | (file.mode & 0o7000),
            .uid = std.math.cast(u32, file.uid) orelse return error.UnsupportedArchiveEntry,
            .gid = std.math.cast(u32, file.gid) orelse return error.UnsupportedArchiveEntry,
        } },
        .symlink => .{ .symlink = .{
            .path = path,
            .target = file.link_literal orelse return error.UnsupportedArchiveEntry,
            .uid = std.math.cast(u32, file.uid) orelse return error.UnsupportedArchiveEntry,
            .gid = std.math.cast(u32, file.gid) orelse return error.UnsupportedArchiveEntry,
            .modified_nanoseconds = @as(i128, file.mtime) * std.time.ns_per_s,
        } },
        .hardlink => .{ .hard_link = .{
            .path = path,
            .source = file.link_target orelse return error.UnsupportedArchiveEntry,
        } },
    };
}

// ---------------------------------------------------------------------------
// Fuzz boundary
// ---------------------------------------------------------------------------

/// Side-effect-free decode boundary. Journal and progress bytes are the only
/// durable inputs this module parses, and both are attacker-reachable on a
/// compromised root, so both are fuzzed through the exact production paths.
pub fn fuzzOne(allocator: std.mem.Allocator, bytes: []const u8) void {
    var decoded = decode(allocator, bytes, maximum_document_bytes) catch return;
    defer decoded.deinit();
    const canonical = decoded.journal.canonicalJson(allocator) catch return;
    defer allocator.free(canonical);
    std.debug.assert(std.mem.eql(u8, canonical, bytes));
    var progress = replayProgress(allocator, decoded.journal, bytes) catch return;
    progress.deinit();
}

/// Fuzz boundary for the progress log alone, replayed against a journal the
/// harness built from the same bytes.
pub fn fuzzProgress(allocator: std.mem.Allocator, journal: Journal, bytes: []const u8) void {
    var progress = replayProgress(allocator, journal, bytes) catch return;
    progress.deinit();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_root = "/target";

const Fixture = struct {
    tmp: std.testing.TmpDir,
    locks: root_operation.TestLockBackend,
    coordinator: root_operation.Coordinator,
    attempt: root_operation.Attempt,

    fn init(fixture: *Fixture) !void {
        fixture.tmp = testing.tmpDir(.{ .iterate = true });
        errdefer fixture.tmp.cleanup();
        fixture.locks = .{ .allocator = testing.allocator };
        fixture.coordinator = try root_operation.Coordinator.open(
            testing.io,
            .init(testing.io, fixture.tmp.dir),
            test_root,
            fixture.locks.interface(),
        );
        fixture.coordinator.now_unix = 1_700_000_000;
        fixture.attempt = try fixture.coordinator.acquire(testing.allocator, .{
            .backend = .native,
            .operation = .{ .package_transaction = .install },
            .request_sha256 = @splat(0x11),
            .policy_sha256 = @splat(0x22),
            .target_architecture = "amd64",
            .attempt_id = @splat(0x44),
        });
    }

    fn deinit(self: *Fixture) void {
        self.attempt.release();
        self.locks.deinit();
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn root(self: *Fixture) root_fs.Root {
        return .init(testing.io, self.tmp.dir);
    }
};

fn testMetadata() Metadata {
    return .{ .mode = 0o644, .uid = currentUid(), .gid = currentGid(), .modified_nanoseconds = 0 };
}

fn currentUid() u32 {
    return if (builtin.os.tag == .linux) std.os.linux.getuid() else 0;
}

fn currentGid() u32 {
    return if (builtin.os.tag == .linux) std.os.linux.getgid() else 0;
}

fn fileIntent(path: []const u8, bytes: []const u8) Intent {
    return .{ .file = .{
        .path = path,
        .bytes = bytes,
        .mode = 0o644,
        .uid = currentUid(),
        .gid = currentGid(),
        .modified_nanoseconds = 1_000_000_000,
    } };
}

fn directoryIntent(path: []const u8) Intent {
    return .{ .directory = .{
        .path = path,
        .mode = 0o755,
        .uid = currentUid(),
        .gid = currentGid(),
    } };
}

fn symlinkIntent(path: []const u8, target: []const u8) Intent {
    return .{ .symlink = .{
        .path = path,
        .target = target,
        .uid = currentUid(),
        .gid = currentGid(),
        .modified_nanoseconds = 1_000_000_000,
    } };
}

fn writeExisting(root: root_fs.Root, path: []const u8, bytes: []const u8) !void {
    const resolved = try root_fs.Path.init(path);
    if (resolved.parent()) |parent|
        try root.createDirectoryPath(parent, root_fs.default_directory_permissions);
    try root.publishFile(resolved, bytes, .{});
}

fn readExisting(root: root_fs.Root, path: []const u8) ![]u8 {
    return root.readFileAlloc(testing.allocator, try root_fs.Path.init(path), 1 << 20);
}

fn expectContent(root: root_fs.Root, path: []const u8, expected: []const u8) !void {
    const bytes = try readExisting(root, path);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(expected, bytes);
}

fn expectAbsent(root: root_fs.Root, path: []const u8) !void {
    const found = try root.entryIfExists(try root_fs.Path.init(path));
    try testing.expect(found == null);
}

fn planFor(fixture: *Fixture, intents: []const Intent) !Plan {
    const result = try preflight(testing.allocator, fixture.root(), .{ .intents = intents });
    switch (result) {
        .plan => |value| return value,
        .diagnostic => |diagnostic| {
            std.debug.print("unexpected preflight diagnostic: {any}\n", .{diagnostic});
            return error.UnexpectedDiagnostic;
        },
    }
}

fn expectDiagnostic(fixture: *Fixture, intents: []const Intent, code: Code) !void {
    const result = try preflight(testing.allocator, fixture.root(), .{ .intents = intents });
    switch (result) {
        .plan => |value| {
            var owned = value;
            owned.deinit();
            return error.ExpectedDiagnostic;
        },
        .diagnostic => |diagnostic| try testing.expectEqual(code, diagnostic.code),
    }
}

test "root_mutation.test.journal round trips through its canonical encoding" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    var plan = try planFor(&fixture, &.{
        directoryIntent("usr"),
        fileIntent("usr/hello", "hello\n"),
        symlinkIntent("usr/link", "hello"),
    });
    defer plan.deinit();

    var engine = try prepare(
        testing.allocator,
        fixture.root(),
        &fixture.attempt,
        &plan,
        .{ .plan_sha256 = @splat(0x33) },
        .{},
    );
    defer engine.deinit();

    const bytes = try engine.journal().canonicalJson(testing.allocator);
    defer testing.allocator.free(bytes);
    var decoded = try decode(testing.allocator, bytes, maximum_document_bytes);
    defer decoded.deinit();
    try testing.expectEqualSlices(
        u8,
        &engine.journal().digest_sha256,
        &decoded.journal.digest_sha256,
    );
    try testing.expectEqual(@as(usize, 3), decoded.journal.steps.len);
    try testing.expectEqualStrings("usr/hello", decoded.journal.steps[1].path);

    const tampered = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(tampered);
    const marker = "\"path\":\"usr/hello\"";
    const index = std.mem.indexOf(u8, tampered, marker).?;
    tampered[index + marker.len - 2] = 'a';
    try testing.expectError(
        error.DigestMismatch,
        decode(testing.allocator, tampered, maximum_document_bytes),
    );

    const padded = try std.fmt.allocPrint(testing.allocator, "{s} ", .{bytes});
    defer testing.allocator.free(padded);
    try testing.expectError(
        error.NonCanonicalDocument,
        decode(testing.allocator, padded, maximum_document_bytes),
    );
}

test "root_mutation.test.applies creates, replacements, links, and removals" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();

    try writeExisting(root, "etc/existing", "old\n");
    try writeExisting(root, "etc/doomed", "gone\n");

    var plan = try planFor(&fixture, &.{
        directoryIntent("usr"),
        directoryIntent("usr/bin"),
        fileIntent("usr/bin/tool", "#!/bin/sh\n"),
        fileIntent("etc/existing", "new\n"),
        symlinkIntent("usr/bin/alias", "tool"),
        .{ .hard_link = .{ .path = "usr/bin/clone", .source = "usr/bin/tool" } },
        .{ .remove = .{ .path = "etc/doomed" } },
        .{ .remove = .{ .path = "etc/never", .removal = .allow_absent } },
    });
    defer plan.deinit();

    var engine = try prepare(
        testing.allocator,
        fixture.root(),
        &fixture.attempt,
        &plan,
        .{},
        .{},
    );
    defer engine.deinit();

    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.applied, report.outcome);
    try testing.expectEqual(Stage.completed, report.stage);

    try expectContent(root, "usr/bin/tool", "#!/bin/sh\n");
    try expectContent(root, "etc/existing", "new\n");
    try expectContent(root, "usr/bin/clone", "#!/bin/sh\n");
    try expectAbsent(root, "etc/doomed");

    var buffer: [64]u8 = undefined;
    const target = try root.readSymbolicLink(try root_fs.Path.init("usr/bin/alias"), &buffer);
    try testing.expectEqualStrings("tool", target);

    const tool = try root.entry(try root_fs.Path.init("usr/bin/tool"));
    const clone = try root.entry(try root_fs.Path.init("usr/bin/clone"));
    try testing.expectEqual(tool.inode, clone.inode);
    try testing.expectEqual(@as(i128, 1_000_000_000), tool.modified_nanoseconds);

    try clear(&engine);
    try expectAbsent(root, journal_path);
    try expectAbsent(root, progress_path);
}

/// Crash and error injection harness. Every fault names an exact durability
/// boundary, so a scenario proves what happens when the machine stops or the
/// filesystem fails at precisely that syscall.
const Fault = struct {
    boundary: Boundary,
    /// `null` matches any step.
    step: ?u32 = null,
    /// Fire on the nth matching arrival, counting from one.
    occurrence: usize = 1,
    err: HookError = error.SimulatedCrash,
};

const Injector = struct {
    faults: []const Fault,
    seen: [24]usize = @splat(0),
    fired: [24]bool = @splat(false),

    fn interface(self: *Injector) Hooks {
        return .{ .context = self, .beforeFn = before };
    }

    fn before(context: ?*anyopaque, boundary: Boundary, index: u32) HookError!void {
        const self: *Injector = @ptrCast(@alignCast(context.?));
        for (self.faults, 0..) |fault, slot| {
            if (fault.boundary != boundary) continue;
            if (fault.step) |wanted| {
                if (wanted != index) continue;
            }
            self.seen[slot] += 1;
            if (self.seen[slot] != fault.occurrence) continue;
            self.fired[slot] = true;
            return fault.err;
        }
    }

    fn allFired(self: *const Injector) bool {
        for (self.faults, 0..) |_, slot| {
            if (!self.fired[slot]) return false;
        }
        return true;
    }
};

/// The shared adversarial root: an existing file that gets replaced, an
/// existing file that gets removed, an empty directory that gets removed, and
/// a file whose metadata changes.
fn seedRoot(root: root_fs.Root) !void {
    try writeExisting(root, "etc/keep", "old\n");
    try writeExisting(root, "etc/doomed", "gone\n");
    try writeExisting(root, "etc/meta", "meta\n");
    try root.createDirectory(
        try root_fs.Path.init("etc/empty"),
        root_fs.default_directory_permissions,
    );
}

fn seedIntents() [8]Intent {
    return .{
        directoryIntent("opt"),
        fileIntent("opt/new", "created\n"),
        fileIntent("etc/keep", "replaced\n"),
        symlinkIntent("opt/link", "new"),
        .{ .hard_link = .{ .path = "opt/clone", .source = "opt/new" } },
        .{ .remove = .{ .path = "etc/doomed" } },
        .{ .remove_directory = .{ .path = "etc/empty" } },
        .{ .metadata = .{ .path = "etc/meta", .mode = 0o600 } },
    };
}

fn expectSeededState(root: root_fs.Root) !void {
    try expectContent(root, "etc/keep", "old\n");
    try expectContent(root, "etc/doomed", "gone\n");
    try expectContent(root, "etc/meta", "meta\n");
    const empty = try root.entry(try root_fs.Path.init("etc/empty"));
    try testing.expect(empty.isDirectory());
    try expectAbsent(root, "opt/new");
    try expectAbsent(root, "opt/link");
    try expectAbsent(root, "opt/clone");
    const meta = try root.entry(try root_fs.Path.init("etc/meta"));
    try testing.expectEqual(@as(u32, 0o644), meta.mode);
}

fn expectAppliedState(root: root_fs.Root) !void {
    try expectContent(root, "etc/keep", "replaced\n");
    try expectContent(root, "opt/new", "created\n");
    try expectContent(root, "opt/clone", "created\n");
    try expectAbsent(root, "etc/doomed");
    try expectAbsent(root, "etc/empty");
    const meta = try root.entry(try root_fs.Path.init("etc/meta"));
    try testing.expectEqual(@as(u32, 0o600), meta.mode);
}

/// No staging or backup entry may survive a resolved transaction.
fn expectWorkspaceEmpty(root: root_fs.Root) !void {
    for ([_][]const u8{ staging_path, backup_path }) |directory| {
        var dir = try root.openDirectory(try root_fs.Path.init(directory));
        defer dir.close(root.io);
        var iterator = dir.iterate();
        try testing.expect(try iterator.next(root.io) == null);
    }
}

const CrashExpectation = enum { old_state, new_state };

fn runCrashScenario(faults: []const Fault, expectation: CrashExpectation) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    var injector: Injector = .{ .faults = faults };
    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    const options: Options = .{ .hooks = injector.interface() };
    var crashed = prepare(
        testing.allocator,
        root,
        &fixture.attempt,
        &plan,
        .{},
        options,
    ) catch |err| {
        try testing.expectEqual(error.SimulatedCrash, err);
        try testing.expect(injector.allFired());
        try recoverAndCheck(&fixture, .old_state);
        return;
    };
    const outcome = apply(&crashed, .fromPlan(&plan));
    crashed.deinit();
    try testing.expectError(error.SimulatedCrash, outcome);
    // A fault that never fired would silently weaken the scenario.
    try testing.expect(injector.allFired());
    try recoverAndCheck(&fixture, expectation);
}

fn recoverAndCheck(fixture: *Fixture, expectation: CrashExpectation) !void {
    const root = fixture.root();
    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})) orelse {
        // No journal survived, so nothing was applied.
        try expectSeededState(root);
        return;
    };
    defer engine.deinit();
    const report = try recover(&engine);
    switch (expectation) {
        .old_state => {
            try testing.expectEqual(Outcome.rolled_back, report.outcome);
            try expectSeededState(root);
        },
        .new_state => {
            try testing.expectEqual(Outcome.applied, report.outcome);
            try expectAppliedState(root);
        },
    }
    try expectWorkspaceEmpty(root);
    try clear(&engine);
    try expectAbsent(root, journal_path);
}

test "root_mutation.test.crash at every durability boundary recovers exactly" {
    const rollback_boundaries = [_]Boundary{
        .journal_write,
        .journal_sync,
        .progress_append,
        .progress_sync,
        .stage_create,
        .stage_write,
        .stage_sync,
        .stage_metadata,
        .stage_dir_sync,
        .backup_link,
        .backup_dir_sync,
        .precondition_check,
        .target_remove,
        .publish_rename,
        .publish_create,
        .metadata_apply,
        .parent_sync,
        .verify,
    };
    for (rollback_boundaries) |boundary| {
        const faults = [_]Fault{.{ .boundary = boundary }};
        runCrashScenario(&faults, .old_state) catch |err| {
            std.debug.print("crash scenario failed at {t}\n", .{boundary});
            return err;
        };
    }

    // The release boundaries only run after every step verified, so a crash
    // there finishes forward instead of undoing a proven-good transaction.
    for ([_]Boundary{ .release_staging, .release_backup }) |boundary| {
        const faults = [_]Fault{.{ .boundary = boundary }};
        runCrashScenario(&faults, .new_state) catch |err| {
            std.debug.print("release scenario failed at {t}\n", .{boundary});
            return err;
        };
    }

    // Restoration boundaries are only reachable once a failure has already
    // turned the transaction around, so they need a first fault to get there.
    for ([_]Boundary{ .restore_rename, .restore_create }) |boundary| {
        const faults = [_]Fault{
            .{ .boundary = .verify, .step = 7, .err = error.RenameFailed },
            .{ .boundary = boundary },
        };
        runCrashScenario(&faults, .old_state) catch |err| {
            std.debug.print("restore scenario failed at {t}\n", .{boundary});
            return err;
        };
    }
}

test "root_mutation.test.filesystem failures roll the transaction back" {
    const failures = [_]Fault{
        .{ .boundary = .stage_write, .err = error.NoSpaceLeft },
        .{ .boundary = .stage_write, .err = error.ShortWrite },
        .{ .boundary = .stage_sync, .err = error.SyncFailed },
        .{ .boundary = .publish_rename, .err = error.RenameFailed },
        .{ .boundary = .target_remove, .err = error.UnlinkFailed },
        .{ .boundary = .backup_link, .err = error.LinkFailed },
        .{ .boundary = .parent_sync, .err = error.SyncFailed },
        .{ .boundary = .metadata_apply, .err = error.AccessDenied },
        .{ .boundary = .verify, .err = error.SystemResources },
    };
    for (failures) |failure| {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        const root = fixture.root();
        try seedRoot(root);

        var injector: Injector = .{ .faults = &.{failure} };
        const intents = seedIntents();
        var plan = try planFor(&fixture, &intents);
        defer plan.deinit();

        var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
            .hooks = injector.interface(),
        });
        defer engine.deinit();
        const report = try apply(&engine, .fromPlan(&plan));
        try testing.expectEqual(Outcome.rolled_back, report.outcome);
        try testing.expect(report.diagnostic != null);
        try expectSeededState(root);
        try expectWorkspaceEmpty(root);
        try clear(&engine);
    }
}

test "root_mutation.test.external modification and symlink swaps are refused" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);
    try writeExisting(root, "etc/secret", "sensitive\n");

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    // Between preflight and application an attacker swaps the replaced target
    // for a symbolic link pointing at a file the transaction must not touch.
    try root.removeFile(try root_fs.Path.init("etc/keep"));
    try root.createSymbolicLink(try root_fs.Path.init("etc/keep"), "secret");

    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.recovery_required, report.outcome);
    try testing.expectEqual(Code.external_modification, report.diagnostic.?.code);

    // Nothing was written through the planted link.
    try expectContent(root, "etc/secret", "sensitive\n");
    var buffer: [64]u8 = undefined;
    const target = try root.readSymbolicLink(try root_fs.Path.init("etc/keep"), &buffer);
    try testing.expectEqualStrings("secret", target);

    // An unresolved journal refuses every further mutation.
    try testing.expectError(error.RecoveryRequired, apply(&engine, .fromPlan(&plan)));
    try testing.expectError(error.RecoveryRequired, clear(&engine));
    try testing.expectEqual(Outcome.recovery_required, (try recover(&engine)).outcome);
    try testing.expectError(
        error.JournalPresent,
        prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{}),
    );
}

test "root_mutation.test.ambiguous state during recovery publishes a recovery requirement" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    var injector: Injector = .{ .faults = &.{.{ .boundary = .verify, .step = 2 }} };
    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();

    // The replaced target is now neither the recorded old state nor the
    // recorded new one, so recovery must refuse instead of guessing.
    try root.publishFile(try root_fs.Path.init("etc/keep"), "third party\n", .{});

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    const report = try recover(&engine);
    try testing.expectEqual(Outcome.recovery_required, report.outcome);
    try testing.expectEqual(Stage.recovery_required, engine.stage());
    try testing.expectEqual(
        root_operation.State.recovery_required,
        fixture.attempt.record().state,
    );
    try testing.expectError(error.RecoveryRequired, clear(&engine));
    try testing.expectEqual(
        Stage.recovery_required,
        (try inspect(testing.allocator, root, .{})).?,
    );
}

test "root_mutation.test.cancellation and deadlines leave a recovered root" {
    var flag = std.atomic.Value(bool).init(false);
    const Cancel = struct {
        fn cancelled(context: *anyopaque) bool {
            const value: *std.atomic.Value(bool) = @ptrCast(@alignCast(context));
            const observed = value.load(.monotonic);
            value.store(true, .monotonic);
            return observed;
        }
    };

    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .cancellation = .{ .context = &flag, .cancelledFn = Cancel.cancelled },
    });
    defer engine.deinit();
    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.rolled_back, report.outcome);
    try testing.expectEqual(Code.canceled, report.diagnostic.?.code);
    try expectSeededState(root);
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

test "root_mutation.test.a lost root lock refuses every boundary" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();
    fixture.locks.loseAll();
    try testing.expectError(error.LockLost, apply(&engine, .fromPlan(&plan)));
    try testing.expectError(error.LockLost, recover(&engine));
    try testing.expectError(error.LockLost, clear(&engine));
    try testing.expectError(
        error.LockLost,
        open(testing.allocator, root, &fixture.attempt, .{}),
    );
    try testing.expectError(
        error.LockLost,
        prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{}),
    );
}

test "root_mutation.test.journals bind exactly one root operation attempt" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    const store: Store = .init(root);
    try store.ensureWorkspace();

    const record = fixture.attempt.record();
    var journal: Journal = .{
        .attempt_id = @splat(0x99),
        .attempt_generation = record.generation,
        .attempt_digest_sha256 = record.digest_sha256,
        .install_root = record.install_root,
        .root_identity_sha256 = record.root_identity_sha256,
        .evidence = .{},
        .device = 0,
        .staging_bytes = 0,
        .budget_bytes = 0,
        .steps = &.{},
        .steps_sha256 = stepsDigest(&.{}),
        .digest_sha256 = @splat(0),
    };
    journal.digest_sha256 = journalDigest(journal);
    try store.writeJournal(testing.allocator, journal);
    try testing.expectError(
        error.AttemptMismatch,
        open(testing.allocator, root, &fixture.attempt, .{}),
    );

    try store.clear(testing.allocator);
    journal.attempt_id = record.attempt_id;
    journal.attempt_generation = record.generation + 5;
    journal.digest_sha256 = @splat(0);
    journal.digest_sha256 = journalDigest(journal);
    try store.writeJournal(testing.allocator, journal);
    try testing.expectError(
        error.StaleAttempt,
        open(testing.allocator, root, &fixture.attempt, .{}),
    );

    try store.clear(testing.allocator);
    journal.attempt_generation = record.generation;
    journal.root_identity_sha256 = @splat(0x77);
    journal.digest_sha256 = @splat(0);
    journal.digest_sha256 = journalDigest(journal);
    try store.writeJournal(testing.allocator, journal);
    try testing.expectError(
        error.RootMismatch,
        open(testing.allocator, root, &fixture.attempt, .{}),
    );
}

test "root_mutation.test.corrupt journals and progress logs fail closed" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    const canonical = try engine.journal().canonicalJson(testing.allocator);
    defer testing.allocator.free(canonical);
    engine.deinit();

    const journal_file = try root_fs.Path.init(journal_path);
    const progress_file = try root_fs.Path.init(progress_path);

    // Truncation, tampering, and an unsupported schema are all refused.
    try root.publishFile(journal_file, canonical[0 .. canonical.len / 2], .{});
    try testing.expectError(
        error.JournalCorrupt,
        open(testing.allocator, root, &fixture.attempt, .{}),
    );

    const unsupported = try testing.allocator.dupe(u8, canonical);
    defer testing.allocator.free(unsupported);
    const marker = "root-mutation-journal-v1";
    const index = std.mem.indexOf(u8, unsupported, marker).?;
    unsupported[index + marker.len - 1] = '9';
    try root.publishFile(journal_file, unsupported, .{});
    try testing.expectError(
        error.UnsupportedSchema,
        open(testing.allocator, root, &fixture.attempt, .{}),
    );

    try root.publishFile(journal_file, canonical, .{});

    // A torn trailing record was never durable, so it is discarded rather
    // than trusted.
    const log = try root.readFileAlloc(testing.allocator, progress_file, maximum_progress_bytes);
    defer testing.allocator.free(log);
    const torn = try std.fmt.allocPrint(testing.allocator, "{s}0000000000000002 ste", .{log});
    defer testing.allocator.free(torn);
    try root.publishFile(progress_file, torn, .{});
    var reopened = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    try testing.expectEqual(Stage.prepared, reopened.stage());
    try testing.expectEqual(@as(u64, log.len), reopened.progress.accepted_bytes);
    reopened.deinit();

    // A broken chain, a replayed record, and an unknown boundary name are
    // corruption, not a torn write.
    const broken = try testing.allocator.dupe(u8, log);
    defer testing.allocator.free(broken);
    broken[broken.len - 2] = if (broken[broken.len - 2] == 'a') 'b' else 'a';
    try root.publishFile(progress_file, broken, .{});
    try testing.expectError(
        error.ProgressCorrupt,
        open(testing.allocator, root, &fixture.attempt, .{}),
    );

    const replayed = try std.fmt.allocPrint(testing.allocator, "{s}{s}", .{ log, log });
    defer testing.allocator.free(replayed);
    try root.publishFile(progress_file, replayed, .{});
    try testing.expectError(
        error.ProgressCorrupt,
        open(testing.allocator, root, &fixture.attempt, .{}),
    );
}

test "root_mutation.test.preflight refuses every unsafe or ambiguous intent" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);
    try writeExisting(root, "etc/linked", "shared\n");
    try root.createHardLink(
        try root_fs.Path.init("etc/linked"),
        try root_fs.Path.init("etc/alias"),
    );
    try root.createSymbolicLink(try root_fs.Path.init("etc/tolink"), "keep");

    try expectDiagnostic(&fixture, &.{fileIntent("/absolute", "x")}, .invalid_path);
    try expectDiagnostic(&fixture, &.{fileIntent("etc/../escape", "x")}, .invalid_path);
    try expectDiagnostic(
        &fixture,
        &.{fileIntent(namespace_path ++ "/stolen", "x")},
        .path_collision,
    );
    try expectDiagnostic(&fixture, &.{fileIntent("etc/tolink/child", "x")}, .symbolic_link_component);
    try expectDiagnostic(
        &fixture,
        &.{ fileIntent("etc/leaf", "x"), fileIntent("etc/leaf/child", "y") },
        .ancestor_conflict,
    );
    try expectDiagnostic(
        &fixture,
        &.{ fileIntent("etc/linked", "x"), fileIntent("etc/alias", "y") },
        .path_alias,
    );
    try expectDiagnostic(
        &fixture,
        &.{
            .{ .hard_link = .{ .path = "etc/clone", .source = "etc/keep" } },
            fileIntent("etc/keep", "changed\n"),
        },
        .hard_link_ambiguous,
    );
    try expectDiagnostic(
        &fixture,
        &.{.{ .hard_link = .{ .path = "etc/self", .source = "etc/self" } }},
        .hard_link_ambiguous,
    );
    try expectDiagnostic(
        &fixture,
        &.{.{ .hard_link = .{ .path = "etc/fromdir", .source = "etc/empty" } }},
        .hard_link_source_invalid,
    );
    try expectDiagnostic(
        &fixture,
        &.{.{ .file = .{ .path = "etc/keep", .bytes = "x", .overwrite = .require_absent } }},
        .target_present,
    );
    try expectDiagnostic(&fixture, &.{.{ .remove = .{ .path = "etc/missing" } }}, .target_absent);
    try expectDiagnostic(
        &fixture,
        &.{.{ .remove = .{ .path = "etc/empty" } }},
        .unsupported_kind,
    );
    try expectDiagnostic(
        &fixture,
        &.{.{ .remove_directory = .{ .path = "etc" } }},
        .directory_not_empty,
    );
    try expectDiagnostic(
        &fixture,
        &.{.{ .file = .{
            .path = "etc/wrong",
            .bytes = "x",
            .expected_sha256 = @splat(0x00),
        } }},
        .content_digest_mismatch,
    );
    try expectDiagnostic(
        &fixture,
        &.{.{ .copy = .{
            .path = "etc/copy",
            .source = "etc/keep",
            .source_sha256 = @splat(0x00),
        } }},
        .content_digest_mismatch,
    );
    try expectDiagnostic(
        &fixture,
        &.{.{ .metadata = .{ .path = "etc/tolink", .mode = 0o600 } }},
        .metadata_unsupported,
    );
    try expectDiagnostic(
        &fixture,
        &.{.{ .metadata = .{ .path = "etc/missing", .mode = 0o600 } }},
        .target_absent,
    );

    const oversized = try preflight(testing.allocator, root, .{
        .intents = &.{fileIntent("etc/big", "0123456789")},
        .limits = .{ .max_staging_bytes = 4 },
    });
    try testing.expectEqual(Code.capacity_exceeded, oversized.diagnostic.code);

    const too_many = try preflight(testing.allocator, root, .{
        .intents = &.{ fileIntent("etc/a", "a"), fileIntent("etc/b", "b") },
        .limits = .{ .max_steps = 1 },
    });
    try testing.expectEqual(Code.step_limit, too_many.diagnostic.code);
}

test "root_mutation.test.special files fail closed before mutation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    if (std.os.linux.errno(std.os.linux.mknodat(
        fixture.tmp.dir.handle,
        "fifo",
        std.posix.S.IFIFO | 0o600,
        0,
    )) != .SUCCESS) return error.SkipZigTest;

    try expectDiagnostic(&fixture, &.{fileIntent("fifo", "x")}, .unsupported_kind);
    try expectDiagnostic(&fixture, &.{.{ .remove = .{ .path = "fifo" } }}, .unsupported_kind);
    try expectDiagnostic(
        &fixture,
        &.{.{ .metadata = .{ .path = "fifo", .mode = 0o600 } }},
        .unsupported_kind,
    );
}

test "root_mutation.test.repeated application of the same plan is idempotent" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    const first = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.applied, first.outcome);
    try expectAppliedState(root);

    // Replaying an already completed transaction publishes nothing new and
    // reports the same outcome, so an interrupted caller can retry safely.
    const second = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.applied, second.outcome);
    try testing.expectEqual(@as(usize, 0), second.applied_steps);
    try expectAppliedState(root);
    try clear(&engine);
}

test "root_mutation.test.directory, file, and symlink transitions publish exactly" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();

    try root.createDirectory(
        try root_fs.Path.init("becomes-file"),
        root_fs.default_directory_permissions,
    );
    try writeExisting(root, "becomes-dir", "file\n");
    try writeExisting(root, "becomes-link", "file\n");
    try root.createSymbolicLink(try root_fs.Path.init("becomes-regular"), "becomes-link");

    const intents = [_]Intent{
        fileIntent("becomes-file", "now a file\n"),
        directoryIntent("becomes-dir"),
        symlinkIntent("becomes-link", "becomes-file"),
        fileIntent("becomes-regular", "now regular\n"),
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();
    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.applied, report.outcome);

    try expectContent(root, "becomes-file", "now a file\n");
    try testing.expect((try root.entry(try root_fs.Path.init("becomes-dir"))).isDirectory());
    try testing.expect((try root.entry(try root_fs.Path.init("becomes-link"))).isSymbolicLink());
    try expectContent(root, "becomes-regular", "now regular\n");
    try clear(&engine);
}

test "root_mutation.test.transitions roll back to their exact original kinds" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();

    try root.createDirectory(
        try root_fs.Path.init("becomes-file"),
        root_fs.default_directory_permissions,
    );
    try writeExisting(root, "becomes-dir", "file\n");
    try writeExisting(root, "becomes-link", "file\n");

    const intents = [_]Intent{
        fileIntent("becomes-file", "now a file\n"),
        directoryIntent("becomes-dir"),
        symlinkIntent("becomes-link", "becomes-file"),
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var injector: Injector = .{ .faults = &.{.{ .boundary = .verify, .step = 2 }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(Outcome.rolled_back, (try recover(&engine)).outcome);
    try testing.expect((try root.entry(try root_fs.Path.init("becomes-file"))).isDirectory());
    try expectContent(root, "becomes-dir", "file\n");
    try expectContent(root, "becomes-link", "file\n");
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

/// Materializes a captured database generation into a real root so the
/// publication path is exercised end to end instead of simulated.
fn materializeDatabase(root: root_fs.Root, snapshot: package_database.Snapshot) !void {
    const directory = package_database.database_directory;
    var buffer: [256]u8 = undefined;
    for ([_]struct { name: []const u8, entry: ?package_database.FileEntry }{
        .{ .name = package_database.status_path, .entry = snapshot.status },
        .{ .name = package_database.status_old_path, .entry = snapshot.status_old },
        .{ .name = package_database.arch_path, .entry = snapshot.arch },
        .{ .name = package_database.triggers_file_path, .entry = snapshot.triggers_file },
        .{ .name = package_database.triggers_unincorp_path, .entry = snapshot.triggers_unincorp },
    }) |item| {
        const entry = item.entry orelse continue;
        const text = try std.fmt.bufPrint(&buffer, "{s}/{s}", .{ directory, item.name });
        try writeExisting(root, text, entry.bytes);
    }
    for (snapshot.info) |entry| {
        const text = try std.fmt.bufPrint(&buffer, "{s}/{s}/{s}", .{
            directory,
            package_database.info_directory,
            entry.name,
        });
        try writeExisting(root, text, entry.bytes);
        try root.applyMetadata(try root_fs.Path.init(text), .{ .mode = entry.mode });
    }
    try root.ensureDirectory(
        try root_fs.Path.init(directory ++ "/" ++ package_database.updates_directory),
        root_fs.default_directory_permissions,
    );
}

/// Reads a published generation back out of a real root.
fn captureDatabase(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    arena: std.mem.Allocator,
) !package_database.Snapshot {
    const directory = package_database.database_directory;
    var buffer: [256]u8 = undefined;
    const read = struct {
        fn one(
            owned: std.mem.Allocator,
            source: root_fs.Root,
            text: []const u8,
        ) !?package_database.FileEntry {
            const bytes = source.readFileAlloc(
                owned,
                try root_fs.Path.init(text),
                16 * 1024 * 1024,
            ) catch |err| switch (err) {
                error.FileNotFound => return null,
                else => return err,
            };
            return .{ .bytes = bytes };
        }
    };
    var snapshot: package_database.Snapshot = .{ .status = .{ .bytes = "" } };
    snapshot.status = (try read.one(
        arena,
        root,
        try std.fmt.bufPrint(&buffer, "{s}/{s}", .{ directory, package_database.status_path }),
    )).?;
    snapshot.status_old = try read.one(
        arena,
        root,
        try std.fmt.bufPrint(&buffer, "{s}/{s}", .{ directory, package_database.status_old_path }),
    );
    snapshot.arch = try read.one(
        arena,
        root,
        try std.fmt.bufPrint(&buffer, "{s}/{s}", .{ directory, package_database.arch_path }),
    );
    snapshot.triggers_file = try read.one(arena, root, try std.fmt.bufPrint(
        &buffer,
        "{s}/{s}",
        .{ directory, package_database.triggers_file_path },
    ));
    snapshot.triggers_unincorp = try read.one(arena, root, try std.fmt.bufPrint(
        &buffer,
        "{s}/{s}",
        .{ directory, package_database.triggers_unincorp_path },
    ));

    var entries: std.ArrayList(package_database.InfoEntry) = .empty;
    const info_text = try std.fmt.bufPrint(&buffer, "{s}/{s}", .{
        directory,
        package_database.info_directory,
    });
    var dir = try root.openDirectory(try root_fs.Path.init(info_text));
    defer dir.close(root.io);
    var iterator = dir.iterate();
    while (try iterator.next(root.io)) |candidate| {
        const name = try arena.dupe(u8, candidate.name);
        var joined: [512]u8 = undefined;
        const text = try std.fmt.bufPrint(&joined, "{s}/{s}", .{ info_text, name });
        const entry = (try read.one(arena, root, text)).?;
        const observed = try root.entry(try root_fs.Path.init(text));
        try entries.append(arena, .{
            .name = name,
            .bytes = entry.bytes,
            .mode = observed.mode,
        });
    }
    _ = allocator;
    std.mem.sort(package_database.InfoEntry, entries.items, {}, struct {
        fn less(_: void, left: package_database.InfoEntry, right: package_database.InfoEntry) bool {
            return std.mem.order(u8, left.name, right.name) == .lt;
        }
    }.less);
    snapshot.info = entries.items;
    return snapshot;
}

test "root_mutation.test.package database plans publish in their exact order" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try materializeDatabase(root, package_database.test_fixtures.snapshot());

    const imported = try package_database.importSnapshot(
        testing.allocator,
        package_database.test_fixtures.request(),
        .{},
    );
    var source = switch (imported) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer source.deinit();

    const planned = try package_database_changes.plan(testing.allocator, source, &.{
        .{ .set_state = .{
            .identity = .{ .name = "libfoo", .architecture = "amd64" },
            .want = .install,
            .error_state = .ok,
            .current = .half_configured,
        } },
    }, .{});
    var database_plan = switch (planned) {
        .diagnostic => return error.TestUnexpectedResult,
        .plan => |value| value,
    };
    defer database_plan.deinit();

    var lowered = switch (try lowerDatabasePlan(testing.allocator, database_plan, .{
        .uid = currentUid(),
        .gid = currentGid(),
    })) {
        .diagnostic => return error.TestUnexpectedResult,
        .intents => |value| value,
    };
    defer lowered.deinit();

    // The plan's own ordering survives lowering: status-old is captured first
    // and status is published last.
    try testing.expectEqual(database_plan.writes.len, lowered.intents.len);
    try testing.expectEqualStrings(
        "var/lib/dpkg/status-old",
        lowered.intents[0].path(),
    );
    try testing.expectEqualStrings(
        "var/lib/dpkg/status",
        lowered.intents[lowered.intents.len - 1].path(),
    );
    try testing.expectEqualSlices(
        u8,
        &source.generation.sha256,
        &lowered.evidence.database_generation_sha256.?,
    );
    try testing.expectEqualSlices(
        u8,
        &database_plan.digest,
        &lowered.evidence.database_plan_sha256.?,
    );

    var plan = try planFor(&fixture, lowered.intents);
    defer plan.deinit();
    var engine = try prepare(
        testing.allocator,
        root,
        &fixture.attempt,
        &plan,
        lowered.evidence,
        .{},
    );
    defer engine.deinit();
    try testing.expectEqualSlices(
        u8,
        &source.generation.sha256,
        &engine.journal().evidence.database_generation_sha256.?,
    );
    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.applied, report.outcome);

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const snapshot = try captureDatabase(testing.allocator, root, arena.allocator());
    const republished = try package_database.importSnapshot(testing.allocator, .{
        .native_architecture = "amd64",
        .snapshot = snapshot,
    }, .{});
    var result = switch (republished) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer result.deinit();
    try testing.expectEqualSlices(
        u8,
        &database_plan.resulting_status.sha256,
        &result.model.status.sha256,
    );
    var previous: [32]u8 = undefined;
    Sha256.hash(package_database.test_fixtures.status, &previous, .{});
    try testing.expectEqualSlices(u8, &previous, &result.model.status_old.?.sha256);
    try clear(&engine);
}

test "root_mutation.test.database publication rolls back to the consumed generation" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try materializeDatabase(root, package_database.test_fixtures.snapshot());

    const imported = try package_database.importSnapshot(
        testing.allocator,
        package_database.test_fixtures.request(),
        .{},
    );
    var source = switch (imported) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer source.deinit();

    const planned = try package_database_changes.plan(testing.allocator, source, &.{
        .{ .remove_package = .{ .name = "oldpkg", .architecture = "amd64" } },
    }, .{});
    var database_plan = switch (planned) {
        .diagnostic => return error.TestUnexpectedResult,
        .plan => |value| value,
    };
    defer database_plan.deinit();

    var lowered = switch (try lowerDatabasePlan(testing.allocator, database_plan, .{
        .uid = currentUid(),
        .gid = currentGid(),
    })) {
        .diagnostic => return error.TestUnexpectedResult,
        .intents => |value| value,
    };
    defer lowered.deinit();

    var plan = try planFor(&fixture, lowered.intents);
    defer plan.deinit();

    const last: u32 = @intCast(plan.steps.len - 1);
    var injector: Injector = .{ .faults = &.{.{ .boundary = .verify, .step = last }} };
    var crashed = try prepare(
        testing.allocator,
        root,
        &fixture.attempt,
        &plan,
        lowered.evidence,
        .{ .hooks = injector.interface() },
    );
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(Outcome.rolled_back, (try recover(&engine)).outcome);

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const snapshot = try captureDatabase(testing.allocator, root, arena.allocator());
    const republished = try package_database.importSnapshot(testing.allocator, .{
        .native_architecture = "amd64",
        .snapshot = snapshot,
    }, .{});
    var result = switch (republished) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer result.deinit();
    try testing.expectEqualSlices(
        u8,
        &source.generation.sha256,
        &result.generation.sha256,
    );
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

test "root_mutation.test.database lowering refuses a plan with the wrong shape" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    var forged: package_database_changes.Plan = .{
        .base_generation = .{ .sha256 = @splat(0), .file_count = 0, .total_bytes = 0 },
        .base_status = .{ .sha256 = @splat(0), .size = 0, .package_count = 0 },
        .resulting_status = .{ .sha256 = @splat(0), .size = 0, .package_count = 0 },
        .writes = &.{},
        .digest = @splat(0),
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    switch (try lowerDatabasePlan(testing.allocator, forged, .{})) {
        .diagnostic => |diagnostic| try testing.expectEqual(
            Code.database_plan_mismatch,
            diagnostic.code,
        ),
        .intents => return error.TestUnexpectedResult,
    }

    const writes = try owned.alloc(package_database_changes.PlannedWrite, 2);
    writes[0] = .{ .path = "status", .kind = .replace, .bytes = "" };
    writes[1] = .{ .path = "status-old", .kind = .copy, .source = "status" };
    forged.writes = writes;
    switch (try lowerDatabasePlan(testing.allocator, forged, .{})) {
        .diagnostic => |diagnostic| try testing.expectEqual(
            Code.database_plan_mismatch,
            diagnostic.code,
        ),
        .intents => return error.TestUnexpectedResult,
    }
}

test "root_mutation.test.staged content is re-proven against the authorized digest" {
    const Substitute = struct {
        fn lookup(_: ?*anyopaque, _: Step) error{ContentUnavailable}![]const u8 {
            return "substituted\n";
        }
    };

    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    const report = try apply(&engine, .{ .lookupFn = Substitute.lookup });
    try testing.expectEqual(Outcome.rolled_back, report.outcome);
    try testing.expectEqual(Code.content_digest_mismatch, report.diagnostic.?.code);
    try expectSeededState(root);
    try clear(&engine);

    // A provider that cannot supply the content at all is refused the same way.
    var second = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer second.deinit();
    const missing = try apply(&second, .{});
    try testing.expectEqual(Outcome.rolled_back, missing.outcome);
    try expectSeededState(root);
    try clear(&second);
}

test "root_mutation.test.preflight and decode stay sound when every allocation fails" {
    const Case = struct {
        fn preflightOnce(allocator: std.mem.Allocator, root: root_fs.Root) !void {
            const intents = seedIntents();
            var result = try preflight(allocator, root, .{ .intents = &intents });
            switch (result) {
                .plan => |*value| value.deinit(),
                .diagnostic => {},
            }
        }

        fn decodeOnce(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var owned = decode(allocator, bytes, maximum_document_bytes) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return,
            };
            owned.deinit();
        }

        fn replayOnce(allocator: std.mem.Allocator, journal: Journal, log: []const u8) !void {
            var progress = replayProgress(allocator, journal, log) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return,
            };
            progress.deinit();
        }
    };

    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    try testing.checkAllAllocationFailures(
        testing.allocator,
        Case.preflightOnce,
        .{root},
    );

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();
    const canonical = try engine.journal().canonicalJson(testing.allocator);
    defer testing.allocator.free(canonical);
    const log = try root.readFileAlloc(
        testing.allocator,
        try root_fs.Path.init(progress_path),
        maximum_progress_bytes,
    );
    defer testing.allocator.free(log);

    try testing.checkAllAllocationFailures(testing.allocator, Case.decodeOnce, .{canonical});
    try testing.checkAllAllocationFailures(
        testing.allocator,
        Case.replayOnce,
        .{ engine.journal(), log },
    );
}

test "root_mutation.test.archive content is bound and published exactly" {
    const payload = "example payload\n";
    const checksums = try archive_application.test_fixtures.checksumLine(
        testing.allocator,
        payload,
        "usr/share/demo/file",
    );
    defer testing.allocator.free(checksums);
    const bytes = try archive_application.test_fixtures.build(testing.allocator, .{
        .control = &.{.{ .path = "md5sums", .content = checksums }},
        .data = &.{
            .{ .path = "usr", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/share", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/share/demo", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/share/demo/file", .mode = 0o644, .content = payload },
            .{ .path = "usr/share/demo/link", .kind = '2', .link = "file" },
        },
    });
    defer testing.allocator.free(bytes);

    var model = switch (archive_application.prepare(
        testing.allocator,
        bytes,
        .{ .local = .{} },
        .{},
    )) {
        .model => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer model.deinit();

    const binding = try bindArchive(&model, bytes, 7, model.digest);
    try testing.expectEqual(@as(u32, 7), binding.index);
    try testing.expectError(
        error.ArtifactBindingMismatch,
        bindArchive(&model, bytes[0 .. bytes.len - 1], 7, model.digest),
    );
    try testing.expectError(
        error.ArtifactBindingMismatch,
        bindArchive(&model, bytes, 7, @splat(0xCD)),
    );

    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();

    var intents: std.ArrayList(Intent) = .empty;
    defer intents.deinit(testing.allocator);
    for (model.files) |file| {
        var intent = try archiveFileIntent(file.path, &model, file, binding);
        // The archive is owned by root; a hermetic root is owned by the user
        // running the test, and ownership resolution is not this layer's job.
        switch (intent) {
            .file => |*value| {
                value.uid = currentUid();
                value.gid = currentGid();
            },
            .directory => |*value| {
                value.uid = currentUid();
                value.gid = currentGid();
            },
            .symlink => |*value| {
                value.uid = currentUid();
                value.gid = currentGid();
            },
            else => {},
        }
        try intents.append(testing.allocator, intent);
    }

    var plan = try planFor(&fixture, intents.items);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{
        .artifact_evidence_sha256 = model.digest,
    }, .{});
    defer engine.deinit();

    // Every archive-backed step carries the application digest it was
    // compiled from.
    for (engine.journal().steps) |step| {
        if (step.kind != .publish_file) continue;
        try testing.expectEqualSlices(
            u8,
            &model.digest,
            &step.artifact.?.application_sha256,
        );
    }

    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.applied, report.outcome);
    try expectContent(root, "usr/share/demo/file", payload);
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "file",
        try root.readSymbolicLink(try root_fs.Path.init("usr/share/demo/link"), &buffer),
    );
    const published = try root.entry(try root_fs.Path.init("usr/share/demo/file"));
    try testing.expectEqual(@as(u32, 0o644), published.mode);
    try testing.expectEqual(
        @as(i128, archive_application.test_fixtures.mtime) * std.time.ns_per_s,
        published.modified_nanoseconds,
    );
    try clear(&engine);
}

test "root_mutation.test.progress records have one fixed canonical shape" {
    const record: ProgressRecord = .{
        .sequence = 0x1234,
        .scope = .step,
        .index = 7,
        .stage = .applying,
        .state = .backup_captured,
        .chain_sha256 = @splat(0xAB),
    };
    var buffer: [progress_record_bytes]u8 = undefined;
    const encoded = record.encode(&buffer);
    try testing.expectEqual(progress_record_bytes, encoded.len);
    try testing.expectEqual(@as(u8, '\n'), encoded[encoded.len - 1]);

    const decoded = try decodeProgressRecord(encoded[0 .. encoded.len - 1]);
    try testing.expectEqual(record.sequence, decoded.sequence);
    try testing.expectEqual(record.scope, decoded.scope);
    try testing.expectEqual(record.index, decoded.index);
    try testing.expectEqual(record.state, decoded.state);
    try testing.expectEqualSlices(u8, &record.chain_sha256, &decoded.chain_sha256);

    // Every longest boundary name still fits the fixed field.
    inline for (@typeInfo(StepState).@"enum".fields) |field| {
        var wide: ProgressRecord = record;
        wide.state = @field(StepState, field.name);
        try testing.expectEqual(progress_record_bytes, wide.encode(&buffer).len);
        _ = try decodeProgressRecord(buffer[0 .. progress_record_bytes - 1]);
    }
    inline for (@typeInfo(Stage).@"enum".fields) |field| {
        var wide: ProgressRecord = record;
        wide.scope = .journal;
        wide.index = ProgressRecord.no_index;
        wide.stage = @field(Stage, field.name);
        try testing.expectEqual(progress_record_bytes, wide.encode(&buffer).len);
        _ = try decodeProgressRecord(buffer[0 .. progress_record_bytes - 1]);
    }

    // Shape violations are corruption, never a shorter valid record.
    _ = record.encode(&buffer);
    try testing.expectError(
        error.ProgressCorrupt,
        decodeProgressRecord(buffer[0 .. progress_record_bytes - 2]),
    );
    var damaged = buffer;
    damaged[16] = 'x';
    try testing.expectError(
        error.ProgressCorrupt,
        decodeProgressRecord(damaged[0 .. progress_record_bytes - 1]),
    );
    damaged = buffer;
    @memcpy(damaged[34..41], "unknown");
    try testing.expectError(
        error.ProgressCorrupt,
        decodeProgressRecord(damaged[0 .. progress_record_bytes - 1]),
    );
    damaged = buffer;
    @memcpy(damaged[17..24], "journal");
    try testing.expectError(
        error.ProgressCorrupt,
        decodeProgressRecord(damaged[0 .. progress_record_bytes - 1]),
    );
}

test "root_mutation.test.hostile journal values are refused before any syscall" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    // Modes outside the permission and special bits, and timestamps the kernel
    // cannot represent, are refused while they are still only intents.
    try expectDiagnostic(
        &fixture,
        &.{.{ .file = .{ .path = "etc/wide", .bytes = "x", .mode = 0o10000 } }},
        .metadata_unsupported,
    );
    try expectDiagnostic(
        &fixture,
        &.{.{ .file = .{
            .path = "etc/late",
            .bytes = "x",
            .modified_nanoseconds = maximum_timestamp_nanoseconds + 1,
        } }},
        .metadata_unsupported,
    );
    try expectDiagnostic(
        &fixture,
        &.{.{ .symlink = .{
            .path = "etc/link",
            .target = "target",
            .modified_nanoseconds = minimum_timestamp_nanoseconds - 1,
        } }},
        .metadata_unsupported,
    );

    // The same bounds are enforced on decode, so a tampered journal cannot
    // smuggle a value preflight would never produce.
    const root = fixture.root();
    var plan = try planFor(&fixture, &.{fileIntent("etc/plain", "x")});
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    const canonical = try engine.journal().canonicalJson(testing.allocator);
    defer testing.allocator.free(canonical);
    engine.deinit();

    const marker = "\"mode\":420";
    const index = std.mem.indexOf(u8, canonical, marker).?;
    const tampered = try std.fmt.allocPrint(testing.allocator, "{s}\"mode\":99999{s}", .{
        canonical[0..index],
        canonical[index + marker.len ..],
    });
    defer testing.allocator.free(tampered);
    try testing.expectError(
        error.NonCanonicalDocument,
        decode(testing.allocator, tampered, maximum_document_bytes),
    );
}

test "root_mutation.test.a released rollback never reports as applied" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var injector: Injector = .{ .faults = &.{.{ .boundary = .verify, .step = 7 }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();

    var rolled = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    try testing.expectEqual(Outcome.rolled_back, (try recover(&rolled)).outcome);
    try testing.expectEqual(Stage.rolled_back, rolled.stage());
    rolled.deinit();

    // The transaction finished and released its workspace, but the journal was
    // never cleared. Reopening must still say the root holds the recorded old
    // state, not the new one.
    var reopened = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer reopened.deinit();
    try testing.expectEqual(Stage.rolled_back, reopened.stage());
    try testing.expectEqual(Outcome.rolled_back, (try recover(&reopened)).outcome);
    try testing.expectEqual(Outcome.rolled_back, (try apply(&reopened, .fromPlan(&plan))).outcome);
    try expectSeededState(root);
    try testing.expectEqual(
        Stage.rolled_back,
        (try inspect(testing.allocator, root, .{})).?,
    );
    try clear(&reopened);
}

test "root_mutation.test.a released rollback interrupted mid-release stays a rollback" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var injector: Injector = .{ .faults = &.{
        .{ .boundary = .verify, .step = 7, .err = error.RenameFailed },
        .{ .boundary = .release_backup },
    } };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(Stage.releasing_rollback, engine.stage());
    try testing.expectEqual(Outcome.rolled_back, (try recover(&engine)).outcome);
    try expectSeededState(root);
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

test "root_mutation.test.metadata steps refuse a substituted target" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try writeExisting(root, "etc/meta", "meta\n");
    try writeExisting(root, "etc/secret", "sensitive\n");

    var plan = try planFor(&fixture, &.{
        .{ .metadata = .{ .path = "etc/meta", .mode = 0o600 } },
    });
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    // The modeled inode is replaced by a different one after preflight. The
    // metadata boundary must refuse instead of stamping the plan's mode onto
    // whatever now occupies the name.
    try root.removeFile(try root_fs.Path.init("etc/meta"));
    try root.createHardLink(
        try root_fs.Path.init("etc/secret"),
        try root_fs.Path.init("etc/meta"),
    );

    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.recovery_required, report.outcome);
    try testing.expectEqual(Code.external_modification, report.diagnostic.?.code);
    try testing.expectEqual(@as(u32, 0o644), (try root.entry(try root_fs.Path.init("etc/secret"))).mode);
}

test "root_mutation.test.rejection diagnostics outlive the plan arena" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try writeExisting(root, "etc/keep", "old\n");

    const source: []const u8 = "etc/keep";
    const result = try preflight(testing.allocator, root, .{ .intents = &.{
        .{ .hard_link = .{ .path = "etc/clone", .source = source } },
        fileIntent("etc/keep", "changed\n"),
    } });
    const diagnostic = switch (result) {
        .plan => return error.TestUnexpectedResult,
        .diagnostic => |value| value,
    };
    try testing.expectEqual(Code.hard_link_ambiguous, diagnostic.code);
    // The reported path must be the caller's own text, which outlives the
    // released plan arena.
    try testing.expectEqual(source.ptr, diagnostic.path.ptr);
    try testing.expectEqualStrings("etc/keep", diagnostic.path);
}

test "root_mutation.test.a journal published without its log is still resolvable" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    // A crash between publishing the journal and creating its log must leave
    // the journal exactly as a real power loss would, not withdraw it.
    var injector: Injector = .{ .faults = &.{.{ .boundary = .journal_sync }} };
    try testing.expectError(error.SimulatedCrash, prepare(
        testing.allocator,
        root,
        &fixture.attempt,
        &plan,
        .{},
        .{ .hooks = injector.interface() },
    ));
    try testing.expect(try root.entryIfExists(try root_fs.Path.init(journal_path)) != null);
    try testing.expect(try root.entryIfExists(try root_fs.Path.init(progress_path)) == null);

    // A second transaction is refused while that journal is unresolved.
    try testing.expectError(
        error.JournalPresent,
        prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{}),
    );

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(Stage.prepared, engine.stage());
    try testing.expectEqual(Outcome.rolled_back, (try recover(&engine)).outcome);
    try expectSeededState(root);
    try clear(&engine);

    // An ordinary preparation failure withdraws the journal instead, so a
    // caller that never reached a durable boundary leaves nothing behind.
    var second = try planFor(&fixture, &.{fileIntent("etc/plain", "x")});
    defer second.deinit();
    var refused: Injector = .{ .faults = &.{.{
        .boundary = .journal_sync,
        .err = error.NoSpaceLeft,
    }} };
    try testing.expectError(error.IoFailed, prepare(
        testing.allocator,
        root,
        &fixture.attempt,
        &second,
        .{},
        .{ .hooks = refused.interface() },
    ));
    try expectAbsent(root, journal_path);
}

test "root_mutation.test.a stale writer cannot fork the progress log" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    // Another writer advanced the durable log after this engine read it. The
    // stale view must be refused rather than overwriting newer boundaries.
    var other = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer other.deinit();
    try other.publishStage(.applying);

    try testing.expectError(error.StaleWriter, engine.publishStage(.applying));
    try expectSeededState(root);
    try testing.expectError(error.StaleWriter, apply(&engine, .fromPlan(&plan)));

    // The writer that actually holds the durable tail still works.
    const report = try apply(&other, .fromPlan(&plan));
    try testing.expectEqual(Outcome.applied, report.outcome);
    try clear(&other);
}
