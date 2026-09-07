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
//! Metadata is published as ownership, then mode, then modification time,
//! because Linux clears the set-user-ID and set-group-ID bits and drops
//! `security.capability` on every `chown` of a non-directory. Neither that
//! sequence nor a directory creation is atomic, so each step also states the
//! exact, closed set of intermediate states the transaction itself could have
//! produced from its last durable boundary. A half-applied boundary is
//! finished or undone deterministically; anything outside that set is still an
//! external modification and still becomes a recovery requirement.
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
///
/// Version 2 widened the record with the runtime identity a boundary binds to
/// the state it published, because a desired state cannot predict an inode
/// and a later step on the same path has nothing else to authenticate its own
/// precondition against.
pub const progress_schema_id = "https://debz.dev/schema/root-mutation-progress-v2";
pub const progress_schema_version: u32 = 2;

/// Absolute ceilings. `Limits` may tighten them; nothing may raise them.
pub const maximum_document_bytes: usize = 64 * 1024 * 1024;
pub const maximum_progress_bytes: usize = 128 * 1024 * 1024;
pub const maximum_steps: usize = 100_000;
pub const maximum_step_dependencies: usize = 8;
pub const maximum_path_bytes: usize = root_fs.maximum_path_bytes;
pub const maximum_link_target_bytes: usize = root_fs.maximum_link_target_bytes;
/// One progress record is fixed shape, so its length is a hard constant. The
/// three identity columns are as wide as the values they carry, so a record
/// that binds an inode is exactly as long as one that binds nothing and a
/// torn tail stays exactly as detectable.
pub const progress_record_bytes: usize = 16 + 1 + 7 + 1 + 8 + 1 + 24 + 1 +
    16 + 1 + 16 + 1 + 16 + 1 + 64 + 1;
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
pub const progress_name = "root-mutation-v2.log";
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
    invalid_encoding,
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
    /// cannot predict an inode number; the boundary that verifies such a
    /// state binds the entry it landed on in the progress log instead, and
    /// `precondition` resolves it from there.
    inode: u64 = 0,
    link_count: u64 = 0,
};

/// A precondition, which is either "nothing is here" or an exact state.
pub const Expectation = union(enum) {
    absent,
    present: State,
};

/// The runtime identity of one entry: the device that holds it, the inode
/// number that names it, and the link count that inode carried at the moment
/// a durable boundary observed it.
///
/// A journal cannot contain this for a state the plan produces - no plan can
/// predict an inode - so it is bound at run time by the boundary that makes
/// the state authoritative and published in that boundary's own progress
/// record. Everything that later has to tell the entry this transaction
/// produced from an entry somebody else substituted for it compares against
/// the bound identity rather than against a zero.
pub const Identity = struct {
    device: u64 = 0,
    inode: u64 = 0,
    link_count: u64 = 0,

    /// Nothing was bound. It is the only identity a record may carry at a
    /// boundary that publishes no state.
    pub const unbound: Identity = .{};

    /// True when a boundary actually observed an inode. Zero is not a valid
    /// inode number on any filesystem this layer supports, so it is the
    /// unambiguous spelling of "nothing is bound here" and is never treated
    /// as a wildcard.
    pub fn bound(self: Identity) bool {
        return self.inode != 0;
    }

    pub fn eql(self: Identity, other: Identity) bool {
        return self.device == other.device and self.inode == other.inode and
            self.link_count == other.link_count;
    }
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
    return identityEqual(left, right);
}

/// Everything about a state that no metadata write can change: the kind, and
/// the exact content of a regular file or the exact target of a symbolic
/// link. Two observations with equal identity are the same bytes; the caller
/// compares the inode separately when it also needs the same inode.
fn identityEqual(left: State, right: State) bool {
    if (left.kind != right.kind) return false;
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
// Reachable intermediate states
// ---------------------------------------------------------------------------
//
// Applying metadata is three ordered syscalls, not one atomic step, and
// creating a directory publishes an inode whose mode and ownership are
// whatever `mkdir` produced under the caller's umask and the parent's
// set-group-ID bit until the metadata boundary rewrites them. Power loss can
// therefore leave a target in a state that is neither the recorded old state
// nor the recorded new one, and refusing every such state would wedge a
// transaction on its own half-finished work.
//
// The answer is not to relax the comparison but to enumerate it. For each
// step this module states the exact, closed set of states the transaction
// itself could have produced from its last durable boundary, and accepts
// nothing else. Every member of the set keeps the identity - kind, content
// digest, link target, and, wherever an inode survives the transition, the
// inode bound to the recorded state, its link count, and the containing
// device - that the recorded states share, so an entry an external writer
// replaced, truncated, or retargeted is still `external_modification` and
// still becomes `recovery_required`.
//
// A state the plan itself produces carries no inode, because no plan can
// predict one; the boundary that verified it bound the entry it landed on, and
// a precondition that names such a state resolves to that binding rather than
// to a zero. See `precondition`.

/// The bits Linux can clear from a regular file's mode when it is chowned.
/// The set-user-ID bit always goes; the set-group-ID bit goes when the entry
/// is group executable, and kernels have differed about the exact condition,
/// so both outcomes are modeled rather than assumed. A directory keeps its
/// bits, and a symbolic link has no mode of its own to lose.
const privilege_bits: u32 = 0o6000;

/// True when a `chown` of this kind and mode could drop a bit, which is
/// exactly when the mode has to be rewritten afterwards even though it
/// already equals the desired one.
fn privilegeBitsAtRisk(kind: Kind, mode: u32) bool {
    return kind == .regular and mode & privilege_bits != 0;
}

/// True when applying `to` onto an entry of `kind` that currently holds
/// `from` issues a `chmod`. It mirrors `applyDesiredMetadata` exactly, so the
/// reachable set and the writer can never disagree.
fn writesMode(kind: Kind, from: Metadata, to: Metadata) bool {
    if (kind == .symlink) return false;
    if (from.mode != to.mode) return true;
    return writesOwner(from, to) and privilegeBitsAtRisk(kind, from.mode);
}

fn writesOwner(from: Metadata, to: Metadata) bool {
    return from.uid != to.uid or from.gid != to.gid;
}

fn writesTimestamp(kind: Kind, from: Metadata, to: Metadata) bool {
    return kind != .directory and from.modified_nanoseconds != to.modified_nanoseconds;
}

/// A bounded, deduplicated set of metadata combinations. One application
/// issues at most three ordered writes and branches only on whether the
/// `chown` cleared a privilege bit, so a single chain is at most six entries;
/// the closure a restore adds converges after one round. The capacity is
/// deliberately larger than that proven bound, and a set that somehow filled
/// would only ever refuse more.
const MetadataSet = struct {
    items: [32]Metadata = undefined,
    len: usize = 0,

    fn add(self: *MetadataSet, value: Metadata) void {
        if (self.contains(value)) return;
        if (self.len == self.items.len) return;
        self.items[self.len] = value;
        self.len += 1;
    }

    fn contains(self: MetadataSet, value: Metadata) bool {
        for (self.items[0..self.len]) |item| {
            if (item.eql(value)) return true;
        }
        return false;
    }
};

/// Adds every combination one interrupted application from `from` toward `to`
/// can leave, in the fixed order ownership, mode, modification time.
fn addMetadataChain(set: *MetadataSet, kind: Kind, from: Metadata, to: Metadata) void {
    set.add(from);
    var current = from;
    if (writesOwner(from, to)) {
        current.uid = to.uid;
        current.gid = to.gid;
        set.add(current);
        if (privilegeBitsAtRisk(kind, current.mode)) {
            var cleared = current;
            cleared.mode = current.mode & ~@as(u32, 0o4000);
            set.add(cleared);
            cleared.mode = current.mode & ~privilege_bits;
            set.add(cleared);
            // Ownership that can clear a bit always forces the mode write, so
            // the branch converges on the desired mode at the next step.
            std.debug.assert(writesMode(kind, from, to));
        }
    }
    if (writesMode(kind, from, to)) {
        current.mode = to.mode;
        set.add(current);
    }
    if (writesTimestamp(kind, from, to)) {
        current.modified_nanoseconds = to.modified_nanoseconds;
        set.add(current);
    }
}

/// Every metadata combination this transaction could have left on one inode
/// while moving it from `expected` toward `desired`, plus - once the
/// transaction has turned around - every combination an interrupted
/// restoration back to `expected` could leave. The restoration walks the same
/// three ordered writes from wherever the forward pass stopped, so the union
/// closes after one round: each restored state already owns `expected`'s
/// ownership, so no further `chown` and therefore no further branch is
/// possible.
fn reachableMetadata(kind: Kind, expected: Metadata, desired: Metadata, phase: Phase) MetadataSet {
    var set: MetadataSet = .{};
    addMetadataChain(&set, kind, expected, desired);
    if (phase == .forward) return set;
    var rounds: usize = 0;
    while (rounds < 4) : (rounds += 1) {
        const before = set.len;
        const snapshot = set;
        for (snapshot.items[0..snapshot.len]) |start|
            addMetadataChain(&set, kind, start, expected);
        if (set.len == before) break;
    }
    return set;
}

/// The direction the transaction is durably committed to. It decides which
/// intermediate states are reachable: only a transaction that has already
/// published `rolling_back` can be part way through a restoration.
const Phase = enum { forward, restore };

/// Classification of one observed target against everything this transaction
/// could itself have left there.
const Reach = enum {
    /// Exactly the recorded old state.
    expected,
    /// Exactly the recorded new state.
    desired,
    /// A state only this transaction's own partially applied boundary can
    /// have produced. It is resolved by finishing or undoing that boundary,
    /// never by adopting it.
    intermediate,
    /// Nothing this transaction did could have produced it.
    foreign,
};

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
/// outcome of an interruption at each one. Metadata is deliberately split into
/// its three ordered syscalls, because power loss between any two of them
/// leaves a state the recovery model has to name.
pub const Boundary = enum {
    journal_write,
    journal_sync,
    progress_append,
    progress_sync,
    /// Repair of a trailing write that was proven never to have completed.
    progress_truncate,
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
    /// The ownership change, which is issued first because it can clear mode
    /// bits and drop `security.capability`.
    metadata_chown,
    /// The mode change, which is issued after ownership so a cleared
    /// set-user-ID or set-group-ID bit is always written back.
    metadata_chmod,
    /// The modification-time change, which is issued last.
    metadata_utimens,
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

/// A canonical journal is a JSON document, and a JSON string carries text, not
/// bytes: `std.json` refuses a string whose bytes are not valid UTF-8, and so
/// does this module's decoder, which reads the document back through it. Text
/// that is not valid UTF-8 therefore has no journal spelling at all.
///
/// Nothing below this layer guarantees that encoding. `root_fs.Path` bounds a
/// path's grammar - no absolute, traversing, empty, control-byte, over-long,
/// or over-deep spelling - but every byte at or above `0x80` passes it, and
/// the payload and archive layers above accept the same bytes, because a
/// Debian archive may legitimately carry a path the kernel treats as an opaque
/// byte string. Publishing one would write a journal that the very next read -
/// `prepare`'s own decode, or recovery's after a crash - refuses as corrupt,
/// which is a transaction whose workspace is already durable and whose
/// recovery evidence is unreadable. Every such string is proven encodable
/// before anything durable exists, and the refusal is a typed preflight
/// diagnostic rather than a decode failure discovered after publication.
pub fn encodableText(text: []const u8) bool {
    return std.unicode.utf8ValidateSlice(text);
}

/// The first string a journal would have to carry that canonical JSON cannot
/// encode, as the exact refusal, or `null` when the whole document is
/// encodable. Preflight proves every intent-derived string, and `prepare`
/// proves the assembled document - evidence included - before the attempt
/// record or the journal is written.
pub fn unencodableText(
    install_root: []const u8,
    evidence: Evidence,
    steps: []const Step,
) ?Diagnostic {
    if (!encodableText(install_root))
        return .{ .surface = .preflight, .code = .invalid_encoding, .path = install_root };
    if (evidence.exact_lock) |binding| {
        if (!encodableText(binding.schema)) return .{
            .surface = .preflight,
            .code = .invalid_encoding,
            .path = binding.schema,
        };
    }
    for (steps, 0..) |step, index| {
        if (unencodableStep(step, @intCast(index))) |diagnostic| return diagnostic;
    }
    return null;
}

fn unencodableStep(step: Step, index: u32) ?Diagnostic {
    const texts = [_]?[]const u8{
        step.path,
        step.source,
        step.staging_entry,
        step.backup_entry,
        linkTarget(step.expected),
        linkTarget(step.desired),
    };
    for (texts) |candidate| {
        const text = candidate orelse continue;
        if (!encodableText(text)) return .{
            .surface = .preflight,
            .code = .invalid_encoding,
            .step = index,
            .path = text,
        };
    }
    return null;
}

fn linkTarget(value: Expectation) ?[]const u8 {
    return switch (value) {
        .absent => null,
        .present => |state| state.link_target,
    };
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
    /// The entry this boundary bound to the state it published, or
    /// `Identity.unbound` at every boundary that publishes no state. It is
    /// part of the chained preimage, so it cannot be edited, spliced in, or
    /// moved to another record without breaking the chain.
    identity: Identity = .unbound,
    chain_sha256: [32]u8,

    pub const no_index: u32 = std.math.maxInt(u32);

    /// `sequence`, `scope`, `index`, the published name, and the bound
    /// identity, chained onto the previous record. The first record chains
    /// onto the journal digest, so a log can never be replayed against a
    /// different journal.
    pub fn chain(
        previous: [32]u8,
        sequence: u64,
        scope: Scope,
        index: u32,
        boundary: []const u8,
        identity: Identity,
    ) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update("debz-root-mutation-progress-v2\x00");
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
        var identity_bytes: [24]u8 = undefined;
        std.mem.writeInt(u64, identity_bytes[0..8], identity.device, .big);
        std.mem.writeInt(u64, identity_bytes[8..16], identity.inode, .big);
        std.mem.writeInt(u64, identity_bytes[16..24], identity.link_count, .big);
        hash.update(&identity_bytes);
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
        return std.fmt.bufPrint(
            buffer,
            "{x:0>16} {s} {x:0>8} {s} {x:0>16} {x:0>16} {x:0>16} {s}\n",
            .{
                self.sequence,
                switch (self.scope) {
                    .journal => "journal",
                    .step => "step   ",
                },
                self.index,
                padded,
                self.identity.device,
                self.identity.inode,
                self.identity.link_count,
                digest,
            },
        ) catch unreachable;
    }
};

pub const ProgressError = error{ProgressCorrupt};

fn decodeProgressRecord(line: []const u8) ProgressError!ProgressRecord {
    if (line.len != progress_record_bytes - 1) return error.ProgressCorrupt;
    if (line[16] != ' ' or line[24] != ' ' or line[33] != ' ' or line[58] != ' ' or
        line[75] != ' ' or line[92] != ' ' or line[109] != ' ')
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
        .identity = .{
            .device = std.fmt.parseUnsigned(u64, line[59..75], 16) catch
                return error.ProgressCorrupt,
            .inode = std.fmt.parseUnsigned(u64, line[76..92], 16) catch
                return error.ProgressCorrupt,
            .link_count = std.fmt.parseUnsigned(u64, line[93..109], 16) catch
                return error.ProgressCorrupt,
        },
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
    record.chain_sha256 = parseHex(32, line[110..174]) catch return error.ProgressCorrupt;
    return record;
}

/// Refuses a record that binds an identity the boundary it names cannot have
/// produced. Authentication proves a record is this log's; this proves the
/// evidence inside it is about a state the journal says that step publishes,
/// so a forged or misplaced inode is corruption rather than a fact a later
/// step could resolve its own precondition against.
fn validateRecordIdentity(journal: Journal, record: ProgressRecord) ProgressError!void {
    const identity = record.identity;
    if (!identity.bound()) {
        // A partly filled identity names no entry and is not an absence
        // either, so it is never silently rounded to one.
        if (identity.device != 0 or identity.link_count != 0) return error.ProgressCorrupt;
        return;
    }
    // Only the boundary that makes a published state authoritative may bind
    // the inode that state landed on.
    if (record.scope != .step or record.state != .verified) return error.ProgressCorrupt;
    // Every entry that exists has at least one link, and every path in the
    // plan lives on the one device the journal pinned.
    if (identity.link_count == 0) return error.ProgressCorrupt;
    if (identity.device != journal.device) return error.ProgressCorrupt;
    if (record.index >= journal.steps.len) return error.ProgressCorrupt;
    switch (journal.steps[record.index].desired) {
        // A step whose desired state is an absence publishes no entry, so
        // there is no inode for it to have bound.
        .absent => return error.ProgressCorrupt,
        .present => {},
    }
}

/// Replayed progress. `states` is dense over the journal's steps, so lookups
/// are indexed rather than searched.
pub const Progress = struct {
    allocator: std.mem.Allocator,
    stage: Stage,
    sequence: u64,
    chain_sha256: [32]u8,
    states: []StepState,
    /// Dense over the journal's steps: the entry each step's verified
    /// boundary bound to the state it published. It is evidence about what
    /// this transaction did rather than about what is at the path now, so a
    /// step that has not verified binds nothing and a step whose restoration
    /// gives its published state back keeps the binding - the backup and
    /// staging links it took are still links on that very inode until the
    /// workspace is released.
    identities: []Identity,
    /// Bytes of the log that decoded cleanly. A torn trailing record is left
    /// out, so the next append overwrites it.
    accepted_bytes: u64,

    pub fn deinit(self: *Progress) void {
        self.allocator.free(self.states);
        self.allocator.free(self.identities);
        self.* = undefined;
    }

    pub fn state(self: Progress, index: u32) StepState {
        if (index >= self.states.len) return .prepared;
        return self.states[index];
    }

    /// The entry the step's own verified boundary bound, or `Identity.unbound`
    /// when no boundary has bound one.
    pub fn identity(self: Progress, index: u32) Identity {
        if (index >= self.identities.len) return .unbound;
        return self.identities[index];
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
    const identities = try allocator.alloc(Identity, journal.steps.len);
    errdefer allocator.free(identities);
    @memset(identities, .unbound);
    var progress: Progress = .{
        .allocator = allocator,
        .stage = .prepared,
        .sequence = 0,
        .chain_sha256 = journal.digest_sha256,
        .states = states,
        .identities = identities,
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
            record.identity,
        );
        if (!std.mem.eql(u8, &expected_chain, &record.chain_sha256))
            return error.ProgressCorrupt;
        try validateRecordIdentity(journal, record);
        switch (record.scope) {
            .journal => progress.stage = record.stage,
            .step => {
                if (record.index >= states.len) return error.ProgressCorrupt;
                states[record.index] = record.state;
                // Only a verified boundary binds an entry, and what it bound
                // stays bound: the links this transaction took on that inode
                // outlive the step's own restoration.
                if (record.identity.bound()) identities[record.index] = record.identity;
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
        // The last gate before the document becomes durable. Preflight and
        // `prepare` have both proven this already; proving it here as well
        // means no path into the store can publish a journal that this
        // module's own decoder would refuse.
        if (unencodableText(journal.install_root, journal.evidence, journal.steps) != null)
            return error.Rejected;
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
    try requireEncodable(builder, path.text);
    if (withinNamespace(path.text)) return builder.fail(.preflight, .path_collision, text);

    const index: u32 = @intCast(builder.steps.items.len);
    var requires: Requirements = .{};
    const model_index = try resolveModel(builder, path.text, &requires);
    try requireAncestors(builder, path, &requires);

    try recordAlias(builder, model_index, path.text);

    const expected = builder.models.items[model_index].state;
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

/// Refuses a plan that models one inode under two names.
///
/// Two names for one inode make the plan ambiguous about identity, and they
/// make its own effect on that inode's link count underivable: the journal
/// records a step's path, not the inode its source or backup happens to
/// share, so a hard link staged from one name changes the link count the
/// other name's metadata step recorded and nothing in the journal says it
/// did. Every path the plan models is registered, sources included, so the
/// ambiguity is refused before anything is mutated rather than discovered as
/// a wedged recovery afterwards. A state the plan itself produced is exact by
/// construction, and a path registered again is the same entry, not an alias
/// of it.
fn recordAlias(builder: *Builder, model_index: u32, path: []const u8) BuildError!void {
    const model = builder.models.items[model_index];
    if (model.produced) return;
    const state = switch (model.state) {
        .absent => return,
        .present => |value| value,
    };
    if (state.kind == .directory) return;
    if (state.inode == 0) return;
    const key = (@as(u128, builder.workspace_device) << 64) | state.inode;
    const found = try builder.aliases.getOrPut(builder.allocator, key);
    if (found.found_existing) {
        if (found.value_ptr.* == model_index) return;
        return builder.fail(.preflight, .path_alias, path);
    }
    found.value_ptr.* = model_index;
}

/// Every string a step will carry into the journal is proven encodable at the
/// moment it enters the plan, so a refusal is a preflight diagnostic naming
/// the exact caller input rather than a corrupt document discovered later.
fn requireEncodable(builder: *Builder, text: []const u8) BuildError!void {
    if (!encodableText(text)) return builder.fail(.preflight, .invalid_encoding, text);
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

/// An existing symbolic link's target is recorded as this path's expected old
/// state, so the root itself can supply text the journal has to carry. A
/// target the kernel accepted but canonical JSON cannot encode is refused
/// here, with the link's own path, rather than published inside a document
/// recovery could not read back.
fn readLink(builder: *Builder, path: root_fs.Path) BuildError![]const u8 {
    var buffer: [maximum_link_target_bytes]u8 = undefined;
    const target = builder.root.readSymbolicLink(path, &buffer) catch
        return builder.fail(.preflight, .io_failed, path.text);
    if (!encodableText(target))
        return builder.fail(.preflight, .invalid_encoding, path.text);
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
            try requireEncodable(builder, source.text);
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
            try requireEncodable(builder, value.target);
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
            try requireEncodable(builder, source.text);
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
            // Changing the ownership of a regular file in place drops its
            // `security.capability` attribute, which this layer does not
            // model and could not restore. The intent is refused before
            // anything changes rather than published and then discovered.
            // A directory keeps its attributes across a `chown`, and a
            // symbolic link cannot carry one.
            if (present.kind == .regular and writesOwner(present.metadata, desired.metadata)) {
                const carries = builder.root.hasCapabilityAttribute(path) catch true;
                if (carries)
                    return builder.fail(.preflight, .metadata_unsupported, path.text);
            }
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
    try recordAlias(builder, model_index, path);
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
    /// Receives the typed refusal when `prepare` fails closed before anything
    /// durable exists. The diagnostic borrows caller input, never the plan
    /// arena, so it outlives the refused call.
    refusal: ?*?Diagnostic = null,
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
    /// For every step, its neighbours on its own path. They are what turn a
    /// precondition the plan produced - and therefore could not give an inode
    /// - into the exact entry a durable boundary bound.
    path_links: []const PathLink,
    options: Options,
    diagnostic: ?Diagnostic = null,

    pub fn deinit(self: *Engine) void {
        self.progress.deinit();
        self.allocator.free(self.path_links);
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

    /// Publishes a boundary, together with the entry that boundary bound. The
    /// append is compare-and-set against the log's durable tail: a writer
    /// whose view is older than the file's chain is stale and is refused
    /// rather than allowed to fork the history.
    fn publish(
        self: *Engine,
        scope: Scope,
        index: u32,
        name: []const u8,
        identity: Identity,
    ) Error!void {
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
            .identity = identity,
            .chain_sha256 = ProgressRecord.chain(
                self.progress.chain_sha256,
                self.progress.sequence + 1,
                scope,
                index,
                name,
                identity,
            ),
        };
        // The writer never emits evidence its own replay would refuse.
        validateRecordIdentity(self.owned.journal, record) catch
            return self.reject(.progress, .progress_corrupt, null, .progress_append);
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
            .step => {
                self.progress.states[index] = record.state;
                if (record.identity.bound()) self.progress.identities[index] = record.identity;
            },
        }
    }

    /// Compare-and-set against the log's durable tail, plus the repair of a
    /// trailing write that provably never completed.
    ///
    /// The last complete record is read at exactly `accepted_bytes - one
    /// record`, never from the physical end, so a torn trailing write can
    /// never shift the window and make a complete record decode as garbage.
    /// The comparison is that record's sequence and chain digest, which bind
    /// the whole prefix and the journal it belongs to, so a writer whose view
    /// is older or newer than what the file actually holds is refused instead
    /// of forking the history.
    ///
    /// Only bytes past the compared record can be discarded, and only when
    /// there are fewer of them than one record, which is exactly the shape a
    /// half-written append leaves and a shape no complete record can have. A
    /// full extra record - replayed, reordered, foreign, or written by
    /// another writer - is never repaired away: it means this writer's view
    /// is stale. The repair is `fsync`ed before the append, so a crash during
    /// it leaves either the same torn tail or the truncated prefix, and both
    /// replay to the same accepted prefix.
    fn compareAndSet(self: *Engine) Error!void {
        const path = root_fs.Path.init(progress_path) catch unreachable;
        var buffer: [progress_record_bytes]u8 = undefined;
        const accepted = self.progress.accepted_bytes;
        const offset = if (accepted == 0) 0 else accepted - progress_record_bytes;
        const window = self.root.readWindowAt(path, offset, &buffer) catch
            return self.reject(.progress, .io_failed, null, .progress_append);
        // The durable prefix this writer proved can never shrink; a shorter
        // file is a different history.
        if (window.size < accepted)
            return self.reject(.progress, .progress_stale, null, .progress_append);
        const trailing = window.size - accepted;
        // One whole record or more past the accepted prefix is another
        // writer's append, not a torn one.
        if (trailing >= progress_record_bytes)
            return self.reject(.progress, .progress_stale, null, .progress_append);
        if (accepted == 0) {
            if (!std.mem.eql(u8, &self.progress.chain_sha256, &self.owned.journal.digest_sha256))
                return self.reject(.progress, .progress_stale, null, .progress_append);
        } else {
            if (window.bytes.len < progress_record_bytes)
                return self.reject(.progress, .progress_corrupt, null, .progress_append);
            const line = window.bytes[0 .. progress_record_bytes - 1];
            if (window.bytes[progress_record_bytes - 1] != '\n')
                return self.reject(.progress, .progress_corrupt, null, .progress_append);
            const decoded = decodeProgressRecord(line) catch
                return self.reject(.progress, .progress_corrupt, null, .progress_append);
            if (decoded.sequence != self.progress.sequence or
                !std.mem.eql(u8, &decoded.chain_sha256, &self.progress.chain_sha256))
                return self.reject(.progress, .progress_stale, null, .progress_append);
        }
        if (trailing == 0) return;
        try self.hook(.progress_truncate, ProgressRecord.no_index);
        self.root.truncateFile(path, accepted, true) catch
            return self.reject(.progress, .io_failed, null, .progress_truncate);
    }

    fn publishStage(self: *Engine, value: Stage) Error!void {
        if (self.progress.stage == value) return;
        try self.publish(.journal, ProgressRecord.no_index, @tagName(value), .unbound);
    }

    fn publishState(self: *Engine, index: u32, value: StepState, identity: Identity) Error!void {
        if (self.progress.states[index] == value) return;
        try self.publish(.step, index, @tagName(value), identity);
    }

    /// The step whose desired state is `index`'s recorded precondition, or
    /// null when preflight observed that precondition on disk.
    fn producer(self: *const Engine, index: u32) ?u32 {
        if (index >= self.path_links.len) return null;
        const value = self.path_links[index].previous;
        return if (value == no_producer) null else value;
    }

    /// The next step of the plan that touches the same path as `index`, or
    /// null when nothing does.
    fn successor(self: *const Engine, index: u32) ?u32 {
        if (index >= self.path_links.len) return null;
        const value = self.path_links[index].next;
        return if (value == no_producer) null else value;
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

    // Preflight proved every string its own intents produced. The evidence and
    // the install root arrive here instead, and a plan is a public value, so
    // the assembled document is proven encodable once more before the attempt
    // record advances and before the journal is written. A refusal here is a
    // typed diagnostic and leaves no durable state at all; a document that is
    // written first and refused on read back would leave a workspace whose
    // recovery evidence cannot be decoded.
    if (unencodableText(attempt.record().install_root, evidence, plan.steps)) |diagnostic| {
        if (options.refusal) |slot| slot.* = diagnostic;
        return error.Rejected;
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
    const path_links = try linkPaths(allocator, owned.journal);
    errdefer allocator.free(path_links);

    var engine: Engine = .{
        .allocator = allocator,
        .root = root,
        .attempt = attempt,
        .owned = owned,
        .progress = progress,
        .path_links = path_links,
        .options = options,
    };
    // The prepared boundary is published explicitly rather than assumed from
    // an empty log, so the log always states which journal it belongs to.
    try engine.publish(.journal, ProgressRecord.no_index, @tagName(Stage.prepared), .unbound);
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
    const path_links = try linkPaths(allocator, owned.journal);
    errdefer allocator.free(path_links);
    return .{
        .allocator = allocator,
        .root = root,
        .attempt = attempt,
        .owned = owned,
        .progress = progress,
        .path_links = path_links,
        .options = options,
    };
}

/// Sentinel for a step with no earlier or later step on its own path.
const no_producer: u32 = std.math.maxInt(u32);

/// The neighbours of one step on its own path.
const PathLink = struct {
    /// The step whose desired state is this step's recorded precondition.
    previous: u32 = no_producer,
    /// The next step of the plan that touches the same path.
    next: u32 = no_producer,
};

/// Links every step whose recorded precondition is a state this plan itself
/// produces to the step that produces it, and every step to the next one on
/// its own path.
///
/// Preflight models each path once: the state a step expects is either the
/// observation it made before the transaction started or, when an earlier
/// step already touched the path, exactly that step's desired state. The
/// journal therefore already says which steps share a path, and the link is
/// proven rather than assumed - a step whose recorded precondition is not its
/// predecessor's recorded desired state describes a history no plan can
/// produce, and a journal that says that cannot be resolved at all.
fn linkPaths(allocator: std.mem.Allocator, journal: Journal) Error![]PathLink {
    const links = try allocator.alloc(PathLink, journal.steps.len);
    errdefer allocator.free(links);
    @memset(links, .{});
    var latest: std.StringHashMapUnmanaged(u32) = .empty;
    defer latest.deinit(allocator);
    for (journal.steps) |step| {
        const found = try latest.getOrPut(allocator, step.path);
        if (found.found_existing) {
            const previous = found.value_ptr.*;
            if (!expectationsEqual(journal.steps[previous].desired, step.expected))
                return error.JournalCorrupt;
            links[step.index].previous = previous;
            links[previous].next = step.index;
        }
        found.value_ptr.* = step.index;
    }
    return links;
}

/// Exact equality of two recorded expectations, identity numbers included. It
/// is the journal's own consistency check, not an observation comparison, so
/// it compares every recorded field rather than only what a metadata write
/// can change.
fn expectationsEqual(left: Expectation, right: Expectation) bool {
    return switch (left) {
        .absent => right == .absent,
        .present => |value| switch (right) {
            .absent => false,
            .present => |other| statesEqual(value, other) and value.inode == other.inode and
                value.link_count == other.link_count,
        },
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
        var identity: Identity = .unbound;
        switch (boundary) {
            .staged => try stageStep(engine, step, content),
            .backup_captured => try captureBackup(engine, step),
            .published => try publishStep(engine, step),
            .metadata_applied => try applyStepMetadata(engine, step),
            .parent_synced => try syncParent(engine, step),
            // Verification is the boundary that makes the published state
            // authoritative, so the entry it proved is bound in the very
            // record that publishes it. A crash before that record leaves the
            // step unverified, and no later step on the same path can start
            // until it verifies, so no successor can ever advance on an
            // identity this transaction did not durably bind.
            .verified => identity = try verifyStep(engine, step),
            .prepared, .completed, .reverted => unreachable,
        }
        try engine.publishState(step.index, boundary, identity);
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
        try applyDesiredMetadata(engine, step.index, .staging, staging.path(), desired);
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
    switch (step.expected) {
        .absent => return,
        .present => {},
    }
    var observation: Observation = .{};
    try requirePrecondition(engine, step, &observation, false);
    // The precondition just proved the target is the recorded old entry, so
    // the inode it is holding right now is the one a backup has to name. A
    // recorded state cannot be compared here instead: the state an earlier
    // step of this plan produced carries no inode of its own.
    const held = switch (observation.state) {
        .absent => return engine.reject(.backup, .precondition_failed, step.index, .backup_link),
        .present => |value| value,
    };
    if (engine.root.entryIfExists(backup.path()) catch null) |existing| {
        if (existing.inode == held.inode and held.inode != 0) return;
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
    /// Containing device of an observed entry, which the journal pins for the
    /// whole plan. It is not part of `State` because a desired state cannot
    /// predict one, but an intermediate state must still be on the device the
    /// transaction was compiled against.
    device: u64 = 0,
    /// False when the platform cannot report ownership and device, so the
    /// classifier never reads a zero as an observation.
    modeled: bool = false,
};

/// Compares the target to its recorded precondition. A retry after an
/// interruption is satisfied by the recorded desired state or, when the
/// boundary that was interrupted is one this transaction can only have left
/// part way through itself, by a state in that boundary's closed reachable
/// set. Anything else is an external modification, never a guess.
fn requirePrecondition(
    engine: *Engine,
    step: Step,
    observation: *Observation,
    accept_intermediate: bool,
) Error!void {
    try engine.hook(.precondition_check, step.index);
    try observeTarget(engine, step, targetPath(step), observation);
    switch (try classify(engine, step, observation.*, .forward)) {
        .expected, .desired => return,
        .intermediate => if (accept_intermediate) return,
        .foreign => {},
    }
    return engine.reject(.publication, .external_modification, step.index, .precondition_check);
}

/// Classifies one observed target against the recorded states and against the
/// closed set of states this transaction itself could have produced.
fn classify(engine: *Engine, step: Step, observation: Observation, phase: Phase) Error!Reach {
    const actual = observation.state;
    const bound = precondition(engine, step);
    if (matchesPrecondition(actual, step.expected, bound)) return .expected;
    if (matches(actual, step.desired)) return .desired;
    return if (try selfProduced(engine, step, observation, phase, bound))
        .intermediate
    else
        .foreign;
}

/// Where the inode behind one step's recorded precondition comes from.
///
/// A journal states the shape of a precondition - kind, content, metadata -
/// but it can only state the inode of a state preflight observed. The state
/// an earlier step of the same plan produces has no inode until that step
/// runs, so its identity is whatever the producing step's verified boundary
/// durably bound.
const Precondition = union(enum) {
    /// The step expects nothing at its path, so there is no inode to bind.
    absent,
    /// The exact entry the recorded precondition names.
    bound: Bound,
    /// The precondition is a state an earlier step of this plan produces and
    /// no verified boundary has bound an inode to it. That is only true
    /// before the producing step verified, and the forward pass reaches a
    /// step only after every earlier step verified, so it is also proof that
    /// this step has not run.
    pending,
    /// The precondition names an entry whose inode the platform never
    /// reported. Nothing can be authenticated against it, so nothing is.
    unreported,
};

/// One resolved identity, plus the step that bound it. Contributions to a
/// link count from steps at or before that step are already inside
/// `link_count`, which is what keeps a count observed part way through a
/// transaction from being double counted.
const Bound = struct {
    device: u64,
    inode: u64,
    link_count: u64,
    /// The step whose verified boundary observed `link_count`, or null when
    /// preflight observed it before the transaction started.
    since: ?u32,
};

/// The identity an observation of `step`'s own path is compared against, or
/// null when the recorded precondition names no entry at all.
///
/// A platform that reports no inode numbers yields the degenerate identity
/// zero, which is exactly the structural comparison such a platform has
/// always had: it still refuses every entry whose inode *is* reported, so it
/// admits nothing a platform with inodes would admit.
fn comparableIdentity(bound: Precondition, old: State, device: u64) ?Bound {
    return switch (bound) {
        .bound => |value| value,
        .unreported => .{
            .device = device,
            .inode = 0,
            .link_count = old.link_count,
            .since = null,
        },
        // Nothing is recorded at the path, or the step that owes it the
        // recorded state has not run, so there is nothing to compare.
        .absent, .pending => null,
    };
}

fn precondition(engine: *const Engine, step: Step) Precondition {
    const expected = switch (step.expected) {
        .absent => return .absent,
        .present => |value| value,
    };
    const producer = engine.producer(step.index) orelse {
        if (expected.inode == 0) return .unreported;
        return .{ .bound = .{
            .device = engine.owned.journal.device,
            .inode = expected.inode,
            .link_count = expected.link_count,
            .since = null,
        } };
    };
    const recorded = engine.progress.identity(producer);
    if (!recorded.bound()) return .pending;
    // A `set_metadata` step publishes the inode it found, so a recorded
    // precondition can carry an inode number of its own even when the plan
    // produced the state. The boundary that actually observed the entry wins:
    // a journal states a prediction, and only a durable boundary states what
    // the transaction really published.
    return .{ .bound = .{
        .device = recorded.device,
        .inode = recorded.inode,
        .link_count = recorded.link_count,
        .since = producer,
    } };
}

/// The recorded old state, on the exact inode a boundary bound to it.
///
/// An entry of the same kind holding the same bytes with the same metadata is
/// still not the recorded entry when it is a different inode: that is exactly
/// what an external replacement looks like, and admitting it would let a
/// metadata step stamp the plan's ownership onto a substituted file and let a
/// rollback restore over one. The inode is only compared when a boundary
/// actually bound one, so a platform that reports no inodes keeps the
/// structural comparison it always had.
fn matchesPrecondition(actual: Expectation, expected: Expectation, bound: Precondition) bool {
    if (!matches(actual, expected)) return false;
    const identity = switch (bound) {
        .bound => |value| value,
        .absent, .pending, .unreported => return true,
    };
    const found = switch (actual) {
        .absent => return true,
        .present => |value| value,
    };
    return found.inode == identity.inode;
}

/// The complete reachable-state model. Everything it accepts, this
/// transaction wrote itself between two durable boundaries; everything it
/// refuses becomes `recovery_required`.
fn selfProduced(
    engine: *Engine,
    step: Step,
    observation: Observation,
    phase: Phase,
    bound: Precondition,
) Error!bool {
    const expected = switch (step.expected) {
        .absent => null,
        .present => |value| value,
    };
    const found = switch (observation.state) {
        // Nothing is at the path. The transaction removes an old entry itself
        // only when the transition it is making cannot be a single rename.
        .absent => return removalReachable(engine, step, phase),
        .present => |value| value,
    };
    // Every path in the plan shares one device, so an entry that arrived from
    // a different filesystem was never this transaction's work.
    if (observation.modeled and observation.device != engine.owned.journal.device) return false;

    // The bound inode is still there, so only its metadata can have moved,
    // and the ordered writes say exactly how far. Its link count may have
    // moved too, but only by the exact amount this transaction's own
    // journaled progress accounts for.
    if (expected) |old| {
        if (comparableIdentity(bound, old, engine.owned.journal.device)) |identity| {
            if (found.inode == identity.inode and
                (identity.device == 0 or !observation.modeled or
                    observation.device == identity.device) and
                linkCountReachable(engine, step, old, identity, found.link_count, phase) and
                identityEqual(found, old))
            {
                const desired = switch (step.desired) {
                    // A removal writes no metadata, so the recorded old
                    // metadata is the only combination reachable, and that is
                    // already `expected`.
                    .absent => return false,
                    .present => |value| value,
                };
                if (!writesMetadataInPlace(step)) return false;
                if (!identityEqual(found, desired)) return false;
                const set = reachableMetadata(old.kind, old.metadata, desired.metadata, phase);
                return set.contains(found.metadata);
            }
        }
    }

    // A directory the transaction created itself. `mkdir` publishes whatever
    // the caller's umask and the parent's set-group-ID bit produce, and the
    // metadata boundary rewrites it, so the intermediate mode and ownership
    // are not predictable from the journal - the evidence is that only this
    // transaction can have created a directory at this path in this
    // direction, and that the directory is still empty and therefore still
    // exactly as removable as when it was made.
    if (found.kind == .directory and directoryCreationReachable(engine, step, phase, found, bound))
        return emptyDirectory(engine, step);

    // A symbolic link the transaction re-created from the journal while
    // restoring. The link target is the whole content of a symbolic link, so
    // an exact target plus a pending metadata write is the recorded old state
    // part way through being republished.
    if (phase == .restore and found.kind == .symlink) {
        if (expected) |old| {
            if (old.kind == .symlink and identityEqual(found, old)) return true;
        }
    }
    return false;
}

/// True for the steps that write metadata onto the inode they found, rather
/// than onto a replacement they publish by rename.
fn writesMetadataInPlace(step: Step) bool {
    return switch (step.kind) {
        .set_metadata, .create_directory => true,
        else => false,
    };
}

/// The durable state that immediately precedes `boundary` in this step's own
/// ordered boundary list, or null when the step never publishes `boundary` at
/// all.
fn boundaryPredecessor(step: Step, boundary: StepState) ?StepState {
    var previous: StepState = .prepared;
    for (step.boundaries()) |item| {
        if (item == boundary) return previous;
        previous = item;
    }
    return null;
}

/// True when the engine can be part way through `boundary` of `step` right
/// now, which is what makes a half-made transition this transaction's own
/// work rather than somebody else's. The journal proves every part of it: the
/// transaction durably authorized mutation, every earlier boundary of this
/// step is durable, and `boundary` itself is not. A step that has not
/// published the boundary before `boundary` never entered it, and a step that
/// published `boundary` finished it, so neither can be holding it open.
fn insideBoundary(engine: *const Engine, step: Step, boundary: StepState) bool {
    switch (engine.progress.stage) {
        // Nothing outside the private workspace has been touched yet, or
        // everything that was owed has already been released.
        .prepared, .completed, .rolled_back => return false,
        else => {},
    }
    const state = engine.progress.state(step.index);
    // A reverted step's recorded old state was observed back in place.
    if (state == .reverted) return false;
    const previous = boundaryPredecessor(step, boundary) orelse return false;
    return state.rank() == previous.rank();
}

/// True when the step's own transition has to remove the entry that is there
/// before it can create the entry that replaces it, which is the only reason
/// this transaction ever leaves a target name empty.
///
/// That is exactly a transition that crosses the directory boundary, in
/// either direction: `mkdir` cannot take a name a non-directory holds, and a
/// directory cannot be renamed over. The test is symmetric because the
/// transition is - the forward pass removes the recorded old entry before it
/// publishes the new one, and the restoration removes the new entry before it
/// puts the recorded old one back. Everything else is a single rename or an
/// in-place write and never empties the name, and a removal's absence is its
/// own desired state rather than an intermediate.
fn crossesDirectoryBoundary(step: Step) bool {
    const expected = switch (step.expected) {
        .absent => return false,
        .present => |value| value,
    };
    const desired = switch (step.desired) {
        // An absent target is the desired state of a removal, which
        // `matches` already accepted.
        .absent => return false,
        .present => |value| value,
    };
    return (expected.kind == .directory) != (desired.kind == .directory);
}

/// True when this transaction itself can have left the path empty.
///
/// Forward, the removal and the creation that replaces it are the two halves
/// of one publication boundary, so the window is exactly the one the journal
/// delimits: the step has published every earlier boundary of its own and has
/// not published `published`. An absence outside that window - a target that
/// vanished before this step could have removed anything, or one on a step
/// whose publication removes nothing at all - is somebody else's work and
/// stays `external_modification`.
///
/// While restoring, the same transition runs backwards: `revertStep` removes
/// whatever it finds before it re-creates the recorded old entry, and it does
/// that for every step it has not already recorded as reverted, so the window
/// is the whole restoration. A forward window that was still open when the
/// transaction turned around stays open, because the absence the forward pass
/// left is still there to be undone.
fn removalReachable(engine: *const Engine, step: Step, phase: Phase) bool {
    if (!crossesDirectoryBoundary(step)) return false;
    if (insideBoundary(engine, step, .published)) return true;
    return phase == .restore and engine.progress.stage == .rolling_back;
}

/// True when this transaction itself can have created the directory it is
/// looking at. Forward, that is a `create_directory` step whose recorded old
/// state is not already a directory, between the `mkdir` inside its
/// publication boundary and the rewrite inside its metadata boundary - the
/// two boundaries the journal shows are still owed. While restoring, it is
/// additionally any step whose recorded old state is a directory the
/// restoration has to re-create from the journal, which is provably a
/// different inode from the one bound to that recorded state.
///
/// "Different from nothing" proves nothing, so a recorded directory no
/// boundary has bound an inode to admits no directory at all: without a bound
/// inode this test would accept any empty directory an outside writer left at
/// the path, which is exactly the substitution the model exists to refuse.
fn directoryCreationReachable(
    engine: *const Engine,
    step: Step,
    phase: Phase,
    found: State,
    bound: Precondition,
) bool {
    const created_forward = step.kind == .create_directory and switch (step.expected) {
        .absent => true,
        .present => |old| old.kind != .directory,
    } and switch (step.desired) {
        .absent => false,
        .present => |value| value.kind == .directory,
    };
    if (created_forward and (insideBoundary(engine, step, .published) or
        insideBoundary(engine, step, .metadata_applied))) return true;
    if (phase != .restore) return false;
    switch (step.expected) {
        .absent => return false,
        .present => |old| if (old.kind != .directory) return false,
    }
    const identity = switch (bound) {
        .bound => |value| value,
        .absent, .pending, .unreported => return false,
    };
    return found.inode != identity.inode;
}

// ---------------------------------------------------------------------------
// Reachable link counts
// ---------------------------------------------------------------------------
//
// A link count is part of an inode's identity: it is what refuses an entry
// that gained a hard link, lost one, or was replaced behind the transaction's
// back. This transaction changes link counts itself, though. Every direct
// subdirectory it creates or removes moves the containing directory's count
// by one through the subdirectory's own `..`, and every hard link it stages,
// publishes, or holds as a backup adds one to the inode it links.
//
// Neither is a guess: the plan names the entries that do it and the progress
// log says how far each of them got. The model below therefore computes the
// exact set of counts this transaction can have produced on one bound inode -
// a closed interval, because each contributing entry moves the count by
// exactly one and does so independently - and refuses everything outside it.
// It is consulted only after the bound inode number itself matched, so
// nothing it accepts is a different inode wearing the recorded identity.
//
// The baseline is the count the boundary that bound the inode observed, which
// is not always the count that existed before the transaction started: a
// contribution taken before that boundary is already inside it, so what the
// model asks about those is whether the link has since been given back.

/// How much of one contributing step's effect on a link count is durably
/// known. `uncertain` is a boundary that may or may not have run, and
/// contributes either nothing or its whole delta.
const Certainty = enum { none, uncertain, applied };

/// The closed set of link counts one bound inode can hold: every integer
/// from `lower` to `upper`. The arithmetic is signed and wide so a plan that
/// removes more links than a count holds can never wrap into acceptance.
const LinkCounts = struct {
    lower: i128,
    upper: i128,

    /// `counted` says the contribution was already inside the count the
    /// identity recorded, in which case what is open is whether it has since
    /// been given back rather than whether it was ever made. Certainty is
    /// therefore read backwards for it: a contribution still in place moves
    /// nothing, and one provably gone moves the count by its own delta the
    /// other way.
    fn add(self: *LinkCounts, delta: i64, certainty: Certainty, counted: bool) void {
        const effective = if (counted) -delta else delta;
        const reached: Certainty = if (!counted) certainty else switch (certainty) {
            .applied => .none,
            .none => .applied,
            .uncertain => .uncertain,
        };
        switch (reached) {
            .none => {},
            .applied => {
                self.lower += effective;
                self.upper += effective;
            },
            .uncertain => if (effective < 0) {
                self.lower += effective;
            } else {
                self.upper += effective;
            },
        }
    }

    fn contains(self: LinkCounts, value: u64) bool {
        const found: i128 = value;
        return found >= self.lower and found <= self.upper;
    }
};

/// True when `found` is a link count this transaction itself can have
/// produced on the bound inode.
fn linkCountReachable(
    engine: *const Engine,
    step: Step,
    old: State,
    identity: Bound,
    found: u64,
    phase: Phase,
) bool {
    // The bound count is always admissible: it is the count a boundary
    // actually observed, and a filesystem that does not maintain directory
    // link counts reports it unchanged however many subdirectories this plan
    // makes.
    if (found == identity.link_count) return true;
    return reachableLinkCounts(engine, step, old, identity, phase).contains(found);
}

/// Every link count the bound inode behind `step` can hold right now, derived
/// from this transaction's plan and its journaled progress.
///
/// The baseline is the count the boundary that bound the inode observed, so a
/// contribution that was already inside it is modeled by whether it has since
/// been given back rather than by whether it was ever made. Counting it a
/// second time would shift the whole interval and admit exactly one outside
/// hard link.
fn reachableLinkCounts(
    engine: *const Engine,
    step: Step,
    old: State,
    identity: Bound,
    phase: Phase,
) LinkCounts {
    var counts: LinkCounts = .{ .lower = identity.link_count, .upper = identity.link_count };
    if (old.kind == .symlink) return counts;
    const frontier = forwardFrontier(engine);
    for (engine.owned.journal.steps) |other| {
        const counted = if (identity.since) |already| other.index <= already else false;
        switch (old.kind) {
            .directory => {
                if (!directChild(other.path, step.path)) continue;
                const delta = subdirectoryDelta(other);
                if (delta == 0) continue;
                // The `mkdir` and the `rmdir` both happen inside the child
                // step's publication boundary.
                counts.add(
                    delta,
                    treeCertainty(engine, other, .published, step, phase, frontier),
                    counted,
                );
            },
            .regular => {
                // A hard link this plan stages from the bound inode adds a
                // link the moment it is staged and keeps it when the
                // publication renames the staged link into place.
                if (linksFromTarget(engine, other, step, identity.inode))
                    counts.add(1, workspaceCertainty(
                        engine,
                        other,
                        .staged,
                        step,
                        phase,
                        frontier,
                    ), counted);
                // A backup of the bound inode is a hard link to the very
                // inode being classified, held until the workspace is
                // released.
                if (backsUpTarget(engine, other, step, identity.inode))
                    counts.add(1, workspaceCertainty(
                        engine,
                        other,
                        .backup_captured,
                        step,
                        phase,
                        frontier,
                    ), counted);
            },
            .symlink => unreachable,
        }
    }
    return counts;
}

/// The highest step index the forward pass can have reached. It applies steps
/// in index order and never leaves one behind, so no step past the first one
/// that has not verified has done any work at all.
fn forwardFrontier(engine: *const Engine) u32 {
    for (engine.owned.journal.steps) |step| {
        if (engine.progress.state(step.index).rank() < StepState.verified.rank())
            return step.index;
    }
    return @intCast(engine.owned.journal.steps.len);
}

/// True when `child` names an entry directly inside `parent`. Paths are
/// canonical, root-relative, and carry no trailing separator, so this is an
/// exact containment test rather than a prefix guess.
fn directChild(child: []const u8, parent: []const u8) bool {
    if (child.len <= parent.len + 1) return false;
    if (!std.mem.startsWith(u8, child, parent)) return false;
    if (child[parent.len] != '/') return false;
    return std.mem.indexOfScalar(u8, child[parent.len + 1 ..], '/') == null;
}

/// The change one step makes to the link count of the directory that contains
/// it. A directory holds one link to its parent through its own `..`, so
/// creating one adds a link, removing one drops it, and every other
/// transition leaves the parent's count alone.
fn subdirectoryDelta(step: Step) i64 {
    const before: i64 = switch (step.expected) {
        .absent => 0,
        .present => |value| if (value.kind == .directory) 1 else 0,
    };
    const after: i64 = switch (step.desired) {
        .absent => 0,
        .present => |value| if (value.kind == .directory) 1 else 0,
    };
    return after - before;
}

/// True when `other` stages a hard link from the exact inode `step` is being
/// classified on.
///
/// The link names whatever the source path was holding when it was staged,
/// which is the entry the last step on that path before it published. That
/// step's verified boundary bound it, and no link can have been staged before
/// that boundary at all, so a link taken after some intervening step of the
/// same plan republished the source is attributed to the inode that step
/// published and never to the one under examination.
fn linksFromTarget(engine: *const Engine, other: Step, step: Step, inode: u64) bool {
    if (other.kind != .publish_hard_link) return false;
    const source = other.source orelse return false;
    if (!std.mem.eql(u8, source, step.path)) return false;
    var holder = step.index;
    while (engine.successor(holder)) |next| {
        if (next >= other.index) break;
        holder = next;
    }
    return engine.progress.identity(holder).inode == inode;
}

/// True when `other` holds a backup hard link to the exact inode `step` is
/// being classified on.
///
/// A backup is a hard link to whatever `other.path` was holding when `other`
/// captured it, so it counts only when that path is this step's path and the
/// entry `other`'s own recorded precondition names is this very inode. That
/// precondition is resolved exactly as this step's is - by the boundary that
/// bound it - so a backup of an inode some intervening step published at the
/// same path is attributed to that inode and never to this one, and a backup
/// whose own precondition nothing has bound yet is attributed to nothing at
/// all rather than to whichever inode happens to be under examination.
fn backsUpTarget(engine: *const Engine, other: Step, step: Step, inode: u64) bool {
    if (other.backup_entry == null) return false;
    if (!std.mem.eql(u8, other.path, step.path)) return false;
    const old = switch (other.expected) {
        .absent => return false,
        .present => |value| value,
    };
    const identity = comparableIdentity(
        precondition(engine, other),
        old,
        engine.owned.journal.device,
    ) orelse return false;
    return identity.inode == inode;
}

/// How far a contributing step got toward the boundary that makes its link
/// appear or disappear, for a link that lives in the published tree.
fn treeCertainty(
    engine: *const Engine,
    other: Step,
    boundary: StepState,
    step: Step,
    phase: Phase,
    frontier: u32,
) Certainty {
    // Nothing outside the private workspace has been touched yet.
    if (engine.progress.stage == .prepared) return .none;
    const state = engine.progress.state(other.index);
    // A reverted step's recorded old state was observed back in place, so
    // whatever it did to the count is undone.
    if (state == .reverted) return .none;
    const reached = boundaryCertainty(other, state, boundary, frontier);
    // Rollback undoes steps in reverse index order, so by the time this step
    // is being restored every later step is already recorded as reverted. One
    // that is not is a restoration in flight, whose link may already be gone.
    if (phase == .restore and other.index > step.index and reached == .applied)
        return .uncertain;
    return reached;
}

/// The same question for a link that lives in the private workspace. A
/// staging or backup entry is created at its own boundary and survives until
/// the workspace is released, including across the restoration of the step
/// that made it, so it outlives the step's own recorded progress.
fn workspaceCertainty(
    engine: *const Engine,
    other: Step,
    boundary: StepState,
    step: Step,
    phase: Phase,
    frontier: u32,
) Certainty {
    switch (engine.progress.stage) {
        // Nothing has been staged or captured yet.
        .prepared => return .none,
        // The release removed every staging and backup entry.
        .completed, .rolled_back => return .none,
        // The release is running: an entry may or may not be gone already.
        .completing, .releasing_rollback => {
            const state = engine.progress.state(other.index);
            return if (boundaryCertainty(other, state, boundary, frontier) == .none and
                state != .reverted) .none else .uncertain;
        },
        else => {},
    }
    const state = engine.progress.state(other.index);
    // A reverted step no longer says how far it got before it was undone, and
    // a staged entry it never published is still in the workspace, so its
    // link is uncertain until the release removes it.
    if (state == .reverted) return .uncertain;
    const reached = boundaryCertainty(other, state, boundary, frontier);
    if (phase == .restore and other.index > step.index and reached == .applied)
        return .uncertain;
    return reached;
}

/// Whether a step at durable state `state` has passed `boundary`, is inside
/// it, or has not reached it. A step past the forward pass's frontier has not
/// started at all, which is what keeps the first boundary of a later step from
/// being counted as in flight for the whole transaction.
fn boundaryCertainty(step: Step, state: StepState, boundary: StepState, frontier: u32) Certainty {
    const previous = boundaryPredecessor(step, boundary) orelse return .none;
    if (state.rank() >= boundary.rank()) return .applied;
    if (step.index > frontier) return .none;
    return if (state.rank() == previous.rank()) .uncertain else .none;
}

/// A directory with entries is not the directory this transaction made, and a
/// directory this transaction made is still empty, so emptiness is the proof
/// that removing or re-moding it is exactly the recorded transition.
fn emptyDirectory(engine: *Engine, step: Step) Error!bool {
    var dir = engine.root.openDirectory(targetPath(step)) catch
        return engine.reject(.publication, .io_failed, step.index, .precondition_check);
    defer dir.close(engine.root.io);
    var iterator = dir.iterate();
    const first = iterator.next(engine.root.io) catch
        return engine.reject(.publication, .io_failed, step.index, .precondition_check);
    return first == null;
}

fn observeTarget(
    engine: *Engine,
    step: Step,
    path: root_fs.Path,
    observation: *Observation,
) Error!void {
    observation.state = .absent;
    observation.device = 0;
    observation.modeled = false;
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
    observation.device = value.device;
    observation.modeled = value.modeled;
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
    try requirePrecondition(engine, step, &observation, true);
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
    // A step that writes metadata onto the inode it finds - a metadata-only
    // step, or a directory creation that has already taken the name - would
    // otherwise stamp the plan's mode, ownership, and timestamp onto whatever
    // entry now occupies the name. The entry must still be the recorded one,
    // on the inode bound to it, or a state only this step's own interrupted
    // boundaries can have produced: the ordered metadata writes on that
    // inode, or the still-empty directory this step's own publication
    // boundary created.
    if (writesMetadataInPlace(step)) {
        var observation: Observation = .{};
        try requirePrecondition(engine, step, &observation, true);
    }
    try engine.hook(.metadata_apply, step.index);
    try applyDesiredMetadata(engine, step.index, .metadata, targetPath(step), desired);
    switch (desired.kind) {
        .regular => engine.root.syncRegularFile(targetPath(step)) catch
            return engine.reject(.metadata, .io_failed, step.index, .metadata_apply),
        .directory => engine.root.syncDirectory(targetPath(step)) catch
            return engine.reject(.metadata, .io_failed, step.index, .metadata_apply),
        .symlink => {},
    }
}

/// Publishes exact metadata in the only order that cannot lose a bit: the
/// ownership first, the mode second, and the modification time last.
///
/// Linux clears the set-user-ID bit of a non-directory on every `chown`, the
/// set-group-ID bit of a group-executable one, and the `security.capability`
/// attribute with them, whatever the caller's privilege. Writing the mode
/// first would therefore publish `04755` as `0755` and wedge verification and
/// rollback on a state neither side recorded. Writing ownership first fixes
/// the order; the mode is additionally rewritten whenever a `chown` was
/// issued and the desired mode keeps a bit that `chown` can clear, even
/// though the mode already matches, so the final chmod is never skipped.
///
/// Only components that actually differ are written, so an unprivileged
/// caller that models the ownership it already has never issues a `chown` it
/// is not allowed to make. Each write is a separate durability boundary, so a
/// power loss between any two of them is an injectable, modeled state rather
/// than an unknown one.
fn applyDesiredMetadata(
    engine: *Engine,
    index: u32,
    surface: Surface,
    path: root_fs.Path,
    desired: State,
) Error!void {
    const current = engine.root.entry(path) catch
        return engine.reject(surface, .io_failed, index, .metadata_apply);
    // Never write metadata onto a kind the plan did not model, which would
    // mean the entry was replaced since it was observed.
    if (Kind.fromFileKind(current.kind) != desired.kind)
        return engine.reject(surface, .external_modification, index, .metadata_apply);
    const found: Metadata = .{
        .mode = current.mode,
        .uid = current.uid,
        .gid = current.gid,
        .modified_nanoseconds = current.modified_nanoseconds,
    };
    const owner = current.modeled and writesOwner(found, desired.metadata);
    if (owner) {
        // A `chown` silently drops `security.capability`, which this layer
        // does not model and cannot restore, so an entry that carries one is
        // refused before the ownership changes instead of after. Only a
        // regular file can carry one.
        if (desired.kind == .regular) {
            const carries = engine.root.hasCapabilityAttribute(path) catch true;
            if (carries)
                return engine.reject(surface, .metadata_unsupported, index, .metadata_chown);
        }
        try engine.hook(.metadata_chown, index);
        engine.root.applyMetadata(path, .{
            .uid = desired.metadata.uid,
            .gid = desired.metadata.gid,
        }) catch return engine.reject(surface, .io_failed, index, .metadata_chown);
    }
    if (writesMode(desired.kind, found, desired.metadata)) {
        try engine.hook(.metadata_chmod, index);
        engine.root.applyMetadata(path, .{ .mode = desired.metadata.mode }) catch
            return engine.reject(surface, .io_failed, index, .metadata_chmod);
    }
    if (writesTimestamp(desired.kind, found, desired.metadata)) {
        try engine.hook(.metadata_utimens, index);
        engine.root.applyMetadata(path, .{
            .modified_nanoseconds = desired.metadata.modified_nanoseconds,
        }) catch return engine.reject(surface, .io_failed, index, .metadata_utimens);
    }
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

/// Proves the step reached its desired state and binds the entry that state
/// landed on. The bound identity is what a later step on the same path
/// authenticates its own recorded precondition against, so it is observed
/// here, at the one moment the state is known to be exactly the recorded one,
/// and never inferred afterwards.
fn verifyStep(engine: *Engine, step: Step) Error!Identity {
    try engine.hook(.verify, step.index);
    var observation: Observation = .{};
    try observeTarget(engine, step, targetPath(step), &observation);
    if (!matches(observation.state, step.desired))
        return engine.reject(.verification, .verification_failed, step.index, .verify);
    const state = switch (observation.state) {
        // A removal publishes no entry, so it binds none.
        .absent => return .unbound,
        .present => |value| value,
    };
    // Every path in the plan lives on the device the journal pinned, so an
    // entry that verified on another one is not the entry the plan compiled
    // against, whatever it now holds.
    if (observation.modeled and observation.device != engine.owned.journal.device)
        return engine.reject(.verification, .verification_failed, step.index, .verify);
    // A platform that cannot report an inode binds nothing rather than
    // binding a zero that would later read as a wildcard.
    if (state.inode == 0 or state.link_count == 0) return .unbound;
    return .{
        .device = engine.owned.journal.device,
        .inode = state.inode,
        .link_count = state.link_count,
    };
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

/// True when `step` cannot have touched its target at all, so its reversal is
/// nothing rather than a restoration of a state that was never published.
fn untouchedStep(engine: *const Engine, step: Step) bool {
    switch (precondition(engine, step)) {
        .pending => {},
        .absent, .bound, .unreported => return false,
    }
    if (engine.progress.state(step.index) != .prepared) return false;
    return step.index > forwardFrontier(engine);
}

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
        try engine.publishState(step.index, .reverted, .unbound);
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
    // A step whose recorded precondition is a state an earlier step of this
    // plan produces, and to which no verified boundary ever bound an inode,
    // has provably done nothing at all: the forward pass reaches a step only
    // after every earlier one verified, and a verified boundary binds the
    // entry it published in the very record that publishes it. There is
    // nothing of this step's to undo, and the path is owed the state the
    // producing step is about to give back on its own turn further down the
    // same reverse pass.
    //
    // Both halves of that proof are required. The step must still be at its
    // own prepared boundary, and the forward pass must not have been able to
    // reach it, so a platform that reports no inodes - where a producing step
    // verifies without binding one - takes the ordinary classification and
    // fails closed instead of skipping real work.
    if (untouchedStep(engine, step)) return;
    var observation: Observation = .{};
    try observeTarget(engine, step, targetPath(step), &observation);
    const actual = observation.state;
    switch (try classify(engine, step, observation, .restore)) {
        // The recorded old state is already back in place.
        .expected => return,
        // The recorded new state, or a state only this transaction's own
        // interrupted boundary can have produced. Both are undone by the
        // same deterministic restoration below.
        .desired, .intermediate => {},
        .foreign => return engine.reject(
            .recovery,
            .recovery_required,
            step.index,
            .restore_rename,
        ),
    }

    // A metadata-only step never took the target name over, so undoing it is
    // republishing the recorded old mode, ownership, and timestamp.
    if (step.kind == .set_metadata) {
        const expected = switch (step.expected) {
            .absent => return engine.reject(.recovery, .recovery_required, step.index, null),
            .present => |value| value,
        };
        try engine.hook(.metadata_apply, step.index);
        try applyDesiredMetadata(engine, step.index, .recovery, targetPath(step), expected);
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
                // A symbolic link is published by renaming a staged link over
                // the name, and a rename cannot take a name a directory
                // holds, so a directory the forward pass created there is
                // removed first exactly as it is for a recorded regular file.
                try removeDirectoryTarget(engine, step, actual);
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
            try applyDesiredMetadata(engine, step.index, .recovery, targetPath(step), expected);
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
    // A decoded document is text, so every string it carries must be text the
    // encoder can write back. The decoder inherits that from JSON itself; the
    // assertion states it so a future decoder that stopped parsing through
    // JSON could not silently accept a journal it cannot reproduce.
    std.debug.assert(unencodableText(
        decoded.journal.install_root,
        decoded.journal.evidence,
        decoded.journal.steps,
    ) == null);
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

/// The journal the progress-log corpus is replayed against: two steps on one
/// path, which is the shape whose second step can only resolve its own
/// recorded precondition against the entry the first one bound. Everything it
/// names has static lifetime, so a checked-in log stays meaningful across
/// runs and a mutated one exercises the record decoder, the chain, and the
/// identity rules through the exact production replay.
const fuzz_published: State = .{
    .kind = .regular,
    .metadata = .{ .mode = 0o644, .uid = 0, .gid = 0, .modified_nanoseconds = 0 },
    .size = 4,
    .content_sha256 = @splat(0x11),
};

const fuzz_remodeled: State = .{
    .kind = .regular,
    .metadata = .{ .mode = 0o600, .uid = 0, .gid = 0, .modified_nanoseconds = 0 },
    .size = 4,
    .content_sha256 = @splat(0x11),
};

const fuzz_steps = [_]Step{
    .{
        .index = 0,
        .kind = .publish_file,
        .path = "etc/fuzz",
        .requires = &.{},
        .overwrite = .replace,
        .removal = .require_present,
        .expected = .absent,
        .desired = .{ .present = fuzz_published },
        .staging_entry = "00000000",
    },
    .{
        .index = 1,
        .kind = .set_metadata,
        .path = "etc/fuzz",
        .requires = &.{0},
        .overwrite = .replace,
        .removal = .require_present,
        .expected = .{ .present = fuzz_published },
        .desired = .{ .present = fuzz_remodeled },
    },
};

pub fn fuzzJournal() Journal {
    var journal: Journal = .{
        .attempt_id = @splat(0x22),
        .attempt_generation = 1,
        .attempt_digest_sha256 = @splat(0x33),
        .install_root = "/",
        .root_identity_sha256 = @splat(0x44),
        .evidence = .{},
        .device = 0x55,
        .staging_bytes = 4,
        .budget_bytes = 4096,
        .steps = &fuzz_steps,
        .steps_sha256 = stepsDigest(&fuzz_steps),
        .digest_sha256 = @splat(0),
    };
    journal.digest_sha256 = journalDigest(journal);
    return journal;
}

/// A symbolic-link step whose path, link target, and install root are valid
/// non-ASCII UTF-8. The journal document corpus is built from it, so a
/// mutation of the checked-in seed lands inside a multibyte sequence and
/// drives the decoder across exactly the boundary this module refuses to
/// publish malformed: text that is not valid UTF-8 has no JSON spelling, and
/// a decoder that accepted one would accept a journal it cannot reproduce.
const fuzz_text_steps = [_]Step{.{
    .index = 0,
    .kind = .publish_symlink,
    .path = "etc/caf\u{e9}/\u{65e5}\u{672c}",
    .requires = &.{},
    .overwrite = .replace,
    .removal = .require_present,
    .expected = .absent,
    .desired = .{ .present = .{
        .kind = .symlink,
        .metadata = .{ .mode = 0o777, .uid = 0, .gid = 0, .modified_nanoseconds = 0 },
        .link_target = "\u{1f680}",
    } },
    .staging_entry = "00000000",
}};

fn fuzzTextJournal() Journal {
    var journal: Journal = .{
        .attempt_id = @splat(0x22),
        .attempt_generation = 1,
        .attempt_digest_sha256 = @splat(0x33),
        .install_root = "/\u{e9}",
        .root_identity_sha256 = @splat(0x44),
        .evidence = .{ .exact_lock = .{
            .schema = "https://debz.dev/schema/exact-closure-lock-v2",
            .version = 2,
            .digest_sha256 = @splat(0x66),
        } },
        .device = 0x55,
        .staging_bytes = 0,
        .budget_bytes = 4096,
        .steps = &fuzz_text_steps,
        .steps_sha256 = stepsDigest(&fuzz_text_steps),
        .digest_sha256 = @splat(0),
    };
    journal.digest_sha256 = journalDigest(journal);
    return journal;
}

/// The exact canonical document the journal corpus seed holds. Regenerate the
/// seed from this whenever the document format changes; a corpus entry that no
/// longer decodes fuzzes nothing.
pub fn fuzzSeedDocument(allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    return fuzzTextJournal().canonicalJson(allocator);
}

/// One boundary of the corpus seed. A journal-scoped record names no step and
/// binds no entry, so both default.
const SeedBoundary = struct {
    scope: Scope,
    index: u32 = ProgressRecord.no_index,
    name: []const u8,
    identity: Identity = .unbound,
};

/// The bound entry both verified boundaries of the seed publish: one inode,
/// because the second step re-modes what the first one published.
const fuzz_seed_identity: Identity = .{ .device = 0x55, .inode = 0x1234, .link_count = 1 };

/// Boundaries of one complete transaction over `fuzzJournal`, in the exact
/// order the engine publishes them.
const fuzz_seed_boundaries = [_]SeedBoundary{
    .{ .scope = .journal, .name = "prepared" },
    .{ .scope = .journal, .name = "applying" },
    .{ .scope = .step, .index = 0, .name = "staged" },
    .{ .scope = .step, .index = 0, .name = "published" },
    .{ .scope = .step, .index = 0, .name = "parent_synced" },
    .{ .scope = .step, .index = 0, .name = "verified", .identity = fuzz_seed_identity },
    .{ .scope = .step, .index = 1, .name = "metadata_applied" },
    .{ .scope = .step, .index = 1, .name = "verified", .identity = fuzz_seed_identity },
    .{ .scope = .journal, .name = "verified" },
    .{ .scope = .journal, .name = "completing" },
    .{ .scope = .journal, .name = "completed" },
};

/// Byte length of the checked-in progress-log corpus seed.
pub const fuzz_seed_bytes: usize = fuzz_seed_boundaries.len * progress_record_bytes;

/// Builds the exact log a complete transaction over `fuzzJournal` leaves
/// behind. The checked-in corpus seed is compared against it, so a change to
/// the record format or the chain is a failing test with a regenerated seed
/// rather than a corpus that quietly stops parsing.
pub fn fuzzSeedLog(buffer: *[fuzz_seed_bytes]u8) []const u8 {
    const journal = fuzzJournal();
    var chain = journal.digest_sha256;
    var offset: usize = 0;
    for (fuzz_seed_boundaries, 1..) |boundary, sequence| {
        const record: ProgressRecord = .{
            .sequence = sequence,
            .scope = boundary.scope,
            .index = boundary.index,
            .stage = if (boundary.scope == .journal)
                std.meta.stringToEnum(Stage, boundary.name).?
            else
                .applying,
            .state = if (boundary.scope == .step)
                std.meta.stringToEnum(StepState, boundary.name).?
            else
                .prepared,
            .identity = boundary.identity,
            .chain_sha256 = ProgressRecord.chain(
                chain,
                sequence,
                boundary.scope,
                boundary.index,
                boundary.name,
                boundary.identity,
            ),
        };
        chain = record.chain_sha256;
        var scratch: [progress_record_bytes]u8 = undefined;
        @memcpy(buffer[offset..][0..progress_record_bytes], record.encode(&scratch));
        offset += progress_record_bytes;
    }
    return buffer[0..offset];
}

/// Fuzz boundary for a progress log on its own, without a journal document in
/// the same bytes. Every attacker-reachable log is replayed against the fixed
/// synthetic journal, so record shape, chaining, and identity validation are
/// all exercised by mutated corpus bytes.
pub fn fuzzProgressLog(allocator: std.mem.Allocator, bytes: []const u8) void {
    fuzzProgress(allocator, fuzzJournal(), bytes);
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

/// The entry one step's recorded precondition resolves to, which is either
/// preflight's own observation or the identity a producing step bound.
fn boundPrecondition(engine: *const Engine, index: u32) !Bound {
    return switch (precondition(engine, engine.journal().steps[index])) {
        .bound => |value| value,
        else => error.PreconditionUnbound,
    };
}

/// Publishes a step's verified boundary with the entry its path is actually
/// holding, exactly as `applyStep` does after `verifyStep` proved it.
fn publishVerified(engine: *Engine, index: u32) !void {
    const step = engine.journal().steps[index];
    const found = try engine.root.entry(.{ .text = step.path });
    try engine.publishState(index, .verified, .{
        .device = engine.journal().device,
        .inode = found.inode,
        .link_count = found.link_count,
    });
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

test "root_mutation.test.a forged identity record is refused even when it chains" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    const journal = engine.journal();
    const sequence = engine.progress.sequence;
    const chain = engine.progress.chain_sha256;
    const device = journal.device;
    engine.deinit();

    const progress_file = try root_fs.Path.init(progress_path);
    const log = try root.readFileAlloc(testing.allocator, progress_file, maximum_progress_bytes);
    defer testing.allocator.free(log);

    // Everything a forger can reach is chained, so the only forgeries left to
    // refuse are the ones that chain correctly and still say something the
    // journal contradicts. Step 5 removes `etc/doomed` and step 7 re-modes
    // `etc/meta`; only a boundary that publishes an entry may bind one.
    const forgeries = [_]struct {
        name: []const u8,
        record: ProgressRecord,
    }{
        .{ .name = "a stage record binding an entry", .record = .{
            .sequence = sequence + 1,
            .scope = .journal,
            .index = ProgressRecord.no_index,
            .stage = .applying,
            .state = .prepared,
            .identity = .{ .device = device, .inode = 0x2a, .link_count = 1 },
            .chain_sha256 = undefined,
        } },
        .{ .name = "an unverified boundary binding an entry", .record = .{
            .sequence = sequence + 1,
            .scope = .step,
            .index = 7,
            .stage = .applying,
            .state = .metadata_applied,
            .identity = .{ .device = device, .inode = 0x2a, .link_count = 1 },
            .chain_sha256 = undefined,
        } },
        .{ .name = "a removal binding an entry", .record = .{
            .sequence = sequence + 1,
            .scope = .step,
            .index = 5,
            .stage = .applying,
            .state = .verified,
            .identity = .{ .device = device, .inode = 0x2a, .link_count = 1 },
            .chain_sha256 = undefined,
        } },
        .{ .name = "an entry on another device", .record = .{
            .sequence = sequence + 1,
            .scope = .step,
            .index = 7,
            .stage = .applying,
            .state = .verified,
            .identity = .{ .device = device +% 1, .inode = 0x2a, .link_count = 1 },
            .chain_sha256 = undefined,
        } },
        .{ .name = "an inode with no links", .record = .{
            .sequence = sequence + 1,
            .scope = .step,
            .index = 7,
            .stage = .applying,
            .state = .verified,
            .identity = .{ .device = device, .inode = 0x2a, .link_count = 0 },
            .chain_sha256 = undefined,
        } },
        .{ .name = "a link count with no inode", .record = .{
            .sequence = sequence + 1,
            .scope = .step,
            .index = 7,
            .stage = .applying,
            .state = .verified,
            .identity = .{ .device = 0, .inode = 0, .link_count = 2 },
            .chain_sha256 = undefined,
        } },
        .{ .name = "a device with no inode", .record = .{
            .sequence = sequence + 1,
            .scope = .step,
            .index = 7,
            .stage = .applying,
            .state = .verified,
            .identity = .{ .device = device, .inode = 0, .link_count = 0 },
            .chain_sha256 = undefined,
        } },
    };
    for (forgeries) |forgery| {
        var record = forgery.record;
        record.chain_sha256 = ProgressRecord.chain(
            chain,
            record.sequence,
            record.scope,
            record.index,
            record.name(),
            record.identity,
        );
        var buffer: [progress_record_bytes]u8 = undefined;
        const forged = try std.fmt.allocPrint(testing.allocator, "{s}{s}", .{
            log,
            record.encode(&buffer),
        });
        defer testing.allocator.free(forged);
        try root.publishFile(progress_file, forged, .{});
        testing.expectError(
            error.ProgressCorrupt,
            open(testing.allocator, root, &fixture.attempt, .{}),
        ) catch |err| {
            std.debug.print("forgery accepted: {s}\n", .{forgery.name});
            return err;
        };
    }

    // The same record with an identity the journal does allow chains, decodes,
    // and is accepted, so the refusals above are about the evidence rather
    // than about the shape.
    var honest: ProgressRecord = forgeries[1].record;
    honest.state = .verified;
    honest.chain_sha256 = ProgressRecord.chain(
        chain,
        honest.sequence,
        honest.scope,
        honest.index,
        honest.name(),
        honest.identity,
    );
    var buffer: [progress_record_bytes]u8 = undefined;
    const accepted = try std.fmt.allocPrint(testing.allocator, "{s}{s}", .{
        log,
        honest.encode(&buffer),
    });
    defer testing.allocator.free(accepted);
    try root.publishFile(progress_file, accepted, .{});
    var reopened = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer reopened.deinit();
    try testing.expectEqual(@as(u64, 0x2a), reopened.progress.identity(7).inode);

    // Editing a bound identity without rebuilding the chain is corruption:
    // the evidence is part of the chained preimage, not a comment beside it.
    const tampered = try testing.allocator.dupe(u8, accepted);
    defer testing.allocator.free(tampered);
    const identity_digit = accepted.len - progress_record_bytes + 91;
    tampered[identity_digit] = if (tampered[identity_digit] == 'a') 'b' else 'a';
    try root.publishFile(progress_file, tampered, .{});
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
    // A source is modeled exactly like a target, so a link staged from one
    // name for an inode whose other name the plan also touches is refused
    // here rather than left to wedge recovery: the extra link it puts on that
    // inode is not derivable from the journal, which records paths.
    try expectDiagnostic(
        &fixture,
        &.{
            .{ .metadata = .{ .path = "etc/linked", .mode = 0o600 } },
            .{ .hard_link = .{ .path = "etc/clone", .source = "etc/alias" } },
        },
        .path_alias,
    );
    try expectDiagnostic(
        &fixture,
        &.{
            .{ .metadata = .{ .path = "etc/linked", .mode = 0o600 } },
            .{ .copy = .{
                .path = "etc/copy",
                .source = "etc/alias",
                .source_sha256 = @splat(0x00),
            } },
        },
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

/// Every way a byte sequence can fail to be UTF-8, one case per class. A JSON
/// string cannot carry any of them, so a journal that recorded one could never
/// be decoded again, and the whole class has to be refused before publication
/// rather than after it.
const unencodable_texts = [_][]const u8{
    // An isolated continuation byte, which no sequence may start with.
    "\x80",
    // Overlong two- and three-byte encodings of `/` and of `.`, the shape a
    // decoder that normalized before validating would turn into a separator.
    "\xc0\xaf",
    "\xe0\x80\xae",
    // Both ends of the UTF-16 surrogate range, which UTF-8 never encodes.
    "\xed\xa0\x80",
    "\xed\xbf\xbf",
    // The first code point above U+10FFFF and a lead byte no code point uses.
    "\xf4\x90\x80\x80",
    "\xf5\x80\x80\x80",
    // Multibyte sequences truncated at every width.
    "\xc3",
    "\xe2\x82",
    "\xf0\x9f\x92",
    // A byte that is not part of the encoding at all.
    "\xfe",
};

/// Text that is valid UTF-8 and not ASCII, at every sequence width. A path or
/// link target spelled this way is ordinary text: it encodes, decodes, and
/// names an entry under the root exactly like an ASCII one.
const non_ascii_texts = [_][]const u8{ "café", "日本語", "🚀" };

/// A refusal leaves nothing durable behind: no journal, no write-ahead log,
/// and no staged or backed-up entry. The private workspace directories
/// themselves are created by preflight before it inspects anything, so they
/// may exist, but they must be empty.
fn expectNoDurableState(root: root_fs.Root) !void {
    try expectAbsent(root, journal_path);
    try expectAbsent(root, progress_path);
    try expectWorkspaceEmpty(root);
}

/// Modeled archive entries whose text upstream validation permits: a tar path
/// and a link literal are byte strings, and every byte at or above `0x80`
/// passes the payload grammar.
fn archiveEntry(path: []const u8, kind: archive_application.FileKind) archive_application.File {
    return .{
        .path = path,
        .kind = kind,
        .mode = if (kind == .directory) 0o755 else 0o644,
        .uid = currentUid(),
        .gid = currentGid(),
        .owner_name = null,
        .group_name = null,
        .mtime = 0,
        .size = 0,
        .content = null,
        .sha256 = null,
        .md5 = null,
        .link_target = null,
        .link_literal = null,
        .conffile = false,
        .entry_index = 0,
    };
}

fn archiveDirectory(path: []const u8) archive_application.File {
    return archiveEntry(path, .directory);
}

fn archiveSymlink(path: []const u8, literal: []const u8) archive_application.File {
    var file = archiveEntry(path, .symlink);
    file.mode = 0o777;
    file.link_literal = literal;
    file.link_target = path;
    return file;
}

fn archiveHardLink(path: []const u8, target: []const u8) archive_application.File {
    var file = archiveEntry(path, .hardlink);
    file.link_target = target;
    return file;
}

test "root_mutation.test.preflight refuses text a canonical journal cannot encode" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);
    try writeExisting(root, "etc/source", "shared\n");

    var buffer: [64]u8 = undefined;
    for (unencodable_texts) |text| {
        const leaf = try std.fmt.bufPrint(&buffer, "etc/{s}", .{text});
        // The target path of every intent kind. The path grammar accepts all
        // of these - none of them is a control byte, a separator, or a
        // traversal - so only the encoding rule refuses them.
        try testing.expect(root_fs.Path.init(leaf) catch null != null);
        try expectDiagnostic(&fixture, &.{fileIntent(leaf, "x")}, .invalid_encoding);
        try expectDiagnostic(&fixture, &.{directoryIntent(leaf)}, .invalid_encoding);
        try expectDiagnostic(&fixture, &.{symlinkIntent(leaf, "keep")}, .invalid_encoding);
        try expectDiagnostic(
            &fixture,
            &.{.{ .metadata = .{ .path = leaf, .mode = 0o600 } }},
            .invalid_encoding,
        );
        try expectDiagnostic(&fixture, &.{.{ .remove = .{ .path = leaf } }}, .invalid_encoding);
        try expectDiagnostic(
            &fixture,
            &.{.{ .remove_directory = .{ .path = leaf } }},
            .invalid_encoding,
        );
        // A copy source and a hard link source are recorded in the journal
        // exactly like a target.
        try expectDiagnostic(&fixture, &.{.{ .copy = .{
            .path = "etc/copy",
            .source = leaf,
            .source_sha256 = @splat(0),
            .uid = currentUid(),
            .gid = currentGid(),
        } }}, .invalid_encoding);
        try expectDiagnostic(
            &fixture,
            &.{.{ .hard_link = .{ .path = "etc/link", .source = leaf } }},
            .invalid_encoding,
        );
        // A symbolic link's literal target is the state the step publishes.
        try expectDiagnostic(&fixture, &.{symlinkIntent("etc/link", text)}, .invalid_encoding);
        // A refused plan never reaches the journal, the log, or the workspace.
        try expectNoDurableState(root);
    }
}

test "root_mutation.test.preflight refuses a link target the root itself cannot encode" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const link = try root_fs.Path.init("etc/observed");
    for (unencodable_texts) |text| {
        root.removeFile(link) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        root.createSymbolicLink(link, text) catch |err| switch (err) {
            // A filesystem that refuses the bytes outright has already failed
            // closed for this case.
            error.InvalidUtf8, error.BadPathName => continue,
            else => return err,
        };
        // The link's target becomes this path's expected old state, so a
        // target the kernel accepted but the journal cannot carry is refused
        // whichever way the plan touches the path.
        try expectDiagnostic(&fixture, &.{fileIntent(link.text, "x")}, .invalid_encoding);
        try expectDiagnostic(
            &fixture,
            &.{.{ .remove = .{ .path = link.text } }},
            .invalid_encoding,
        );
        try expectDiagnostic(
            &fixture,
            &.{.{ .metadata = .{ .path = link.text, .uid = currentUid() } }},
            .invalid_encoding,
        );
        // A source is observed exactly like a target.
        try expectDiagnostic(&fixture, &.{.{ .hard_link = .{
            .path = "etc/link",
            .source = link.text,
        } }}, .invalid_encoding);
        try expectNoDurableState(root);
    }
}

test "root_mutation.test.database and archive adapters cannot smuggle unencodable text" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    // The database plan's own compiler validates its paths, so this forged
    // plan states what the mutation layer must refuse on its own: an info
    // path and a database directory that upstream validation did not prove.
    var forged: package_database_changes.Plan = .{
        .base_generation = .{ .sha256 = @splat(0), .file_count = 0, .total_bytes = 0 },
        .base_status = .{ .sha256 = @splat(0), .size = 0, .package_count = 0 },
        .resulting_status = .{ .sha256 = @splat(0), .size = 0, .package_count = 0 },
        .writes = &.{
            .{ .path = "status-old", .kind = .copy, .source = "status" },
            .{ .path = "info/demo.\xed\xa0\x80list", .kind = .replace, .bytes = "" },
            .{ .path = "status", .kind = .replace, .bytes = "" },
        },
        .digest = @splat(0),
        .arena = undefined,
        .backing_allocator = testing.allocator,
    };
    var lowered = switch (try lowerDatabasePlan(testing.allocator, forged, .{
        .uid = currentUid(),
        .gid = currentGid(),
    })) {
        .diagnostic => return error.TestUnexpectedResult,
        .intents => |value| value,
    };
    defer lowered.deinit();
    try expectDiagnostic(&fixture, lowered.intents[1..2], .invalid_encoding);

    // A database directory the caller chose is joined onto every path, so it
    // is refused the same way.
    forged.writes = &.{
        .{ .path = "status-old", .kind = .copy, .source = "status" },
        .{ .path = "status", .kind = .replace, .bytes = "" },
    };
    var rooted = switch (try lowerDatabasePlan(testing.allocator, forged, .{
        .directory = "var/lib/\xc0\xafdpkg",
        .uid = currentUid(),
        .gid = currentGid(),
    })) {
        .diagnostic => return error.TestUnexpectedResult,
        .intents => |value| value,
    };
    defer rooted.deinit();
    try expectDiagnostic(&fixture, rooted.intents, .invalid_encoding);

    // A Debian archive may carry any non-control byte in a path, a symbolic
    // link literal, or a hard link target, so the archive adapter's intents
    // are refused at the same boundary.
    // Only a regular file's bytes are read out of the model, and none of
    // these entries is one, so the adapter never touches it.
    const model: archive_application.Model = undefined;
    const binding: ArtifactBinding = .{ .index = 0, .application_sha256 = @splat(0) };
    const smuggled = try archiveFileIntent(
        "usr/share/demo/\xf5\x80\x80\x80",
        &model,
        archiveDirectory("usr/share/demo/\xf5\x80\x80\x80"),
        binding,
    );
    try expectDiagnostic(&fixture, &.{smuggled}, .invalid_encoding);

    const literal = try archiveFileIntent(
        "usr/share/demo/link",
        &model,
        archiveSymlink("usr/share/demo/link", "\xe2\x82"),
        binding,
    );
    try expectDiagnostic(&fixture, &.{literal}, .invalid_encoding);

    const hardlink = try archiveFileIntent(
        "usr/share/demo/clone",
        &model,
        archiveHardLink("usr/share/demo/clone", "usr/share/demo/\x80"),
        binding,
    );
    try expectDiagnostic(&fixture, &.{hardlink}, .invalid_encoding);
    try expectNoDurableState(root);
}

test "root_mutation.test.prepare refuses evidence a canonical journal cannot encode" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    var plan = try planFor(&fixture, &.{fileIntent("etc/keep", "new\n")});
    defer plan.deinit();

    for (unencodable_texts) |text| {
        var refusal: ?Diagnostic = null;
        try testing.expectError(error.Rejected, prepare(
            testing.allocator,
            root,
            &fixture.attempt,
            &plan,
            .{ .exact_lock = .{
                .schema = text,
                .version = 1,
                .digest_sha256 = @splat(0x11),
            } },
            .{ .refusal = &refusal },
        ));
        // The refusal is the typed preflight diagnostic, produced before the
        // attempt record advanced and before the journal existed, not a
        // decode failure discovered after publication.
        try testing.expectEqual(Surface.preflight, refusal.?.surface);
        try testing.expectEqual(Code.invalid_encoding, refusal.?.code);
        try testing.expectEqualStrings(text, refusal.?.path);
        try expectNoDurableState(root);
    }

    // A step whose text was never proven - a plan value a caller assembled
    // rather than one preflight produced - is refused at the same boundary.
    var forged = plan;
    var steps = try testing.allocator.dupe(Step, plan.steps);
    defer testing.allocator.free(steps);
    steps[0].path = "etc/\xed\xa0\x80";
    forged.steps = steps;
    var refusal: ?Diagnostic = null;
    try testing.expectError(error.Rejected, prepare(
        testing.allocator,
        root,
        &fixture.attempt,
        &forged,
        .{},
        .{ .refusal = &refusal },
    ));
    try testing.expectEqual(Code.invalid_encoding, refusal.?.code);
    try testing.expectEqual(@as(?u32, 0), refusal.?.step);
    try expectNoDurableState(root);

    // The store is the last gate: a document assembled outside preflight and
    // handed straight to the writer is refused at the write, not published and
    // then refused on read back.
    const store: Store = .{ .root = root };
    var hostile = fuzzJournal();
    hostile.install_root = "/\xed\xa0\x80";
    try testing.expectError(error.Rejected, store.writeJournal(testing.allocator, hostile));
    try expectNoDurableState(root);
}

test "root_mutation.test.valid non-ASCII text publishes, decodes, and stays rooted" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();

    var buffer: [64]u8 = undefined;
    var intents: std.ArrayList(Intent) = .empty;
    defer intents.deinit(testing.allocator);
    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |name| testing.allocator.free(name);
        names.deinit(testing.allocator);
    }
    try root.createDirectory(
        try root_fs.Path.init("etc"),
        root_fs.default_directory_permissions,
    );
    for (non_ascii_texts) |text| {
        const leaf = try std.fmt.bufPrint(&buffer, "etc/{s}", .{text});
        // A filesystem that cannot hold these exact bytes in a name is not
        // what this test is about, so the name itself is what probes it.
        const probe = try root_fs.Path.init(leaf);
        root.publishFile(probe, "", .{}) catch return error.SkipZigTest;
        try root.removeFile(probe);
        const owned = try testing.allocator.dupe(u8, leaf);
        try names.append(testing.allocator, owned);
        try intents.append(testing.allocator, fileIntent(owned, "text\n"));
        const link = try std.fmt.bufPrint(&buffer, "etc/link-{s}", .{text});
        const owned_link = try testing.allocator.dupe(u8, link);
        try names.append(testing.allocator, owned_link);
        // The link target is the leaf name alone, so a published link resolves
        // beside the file it names and nowhere else.
        try intents.append(testing.allocator, symlinkIntent(owned_link, owned["etc/".len..]));
    }

    var plan = try planFor(&fixture, intents.items);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    // The document round trips through its own canonical encoding with the
    // exact bytes intact: valid UTF-8 is ordinary text here.
    const bytes = try engine.journal().canonicalJson(testing.allocator);
    defer testing.allocator.free(bytes);
    var decoded = try decode(testing.allocator, bytes, maximum_document_bytes);
    defer decoded.deinit();
    for (decoded.journal.steps, engine.journal().steps) |left, right|
        try testing.expectEqualStrings(right.path, left.path);

    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.applied, report.outcome);
    for (non_ascii_texts) |text| {
        const leaf = try std.fmt.bufPrint(&buffer, "etc/{s}", .{text});
        try expectContent(root, leaf, "text\n");
        // The published entry is the one the plan named, resolved through the
        // root and nowhere else.
        const found = try root.entry(try root_fs.Path.init(leaf));
        try testing.expectEqual(Io.File.Kind.file, found.kind);
        const link = try std.fmt.bufPrint(&buffer, "etc/link-{s}", .{text});
        var target: [maximum_link_target_bytes]u8 = undefined;
        try testing.expectEqualStrings(
            text,
            try root.readSymbolicLink(try root_fs.Path.init(link), &target),
        );
    }
    try clear(&engine);
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

        fn openOnce(
            allocator: std.mem.Allocator,
            root: root_fs.Root,
            attempt: *root_operation.Attempt,
        ) !void {
            var engine = open(allocator, root, attempt, .{}) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return,
            } orelse return;
            engine.deinit();
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
    // Reopening reads the journal, replays the log, and links every step
    // whose precondition an earlier step produces, so it is the path a
    // recovery takes and every allocation on it must fail closed.
    try testing.checkAllAllocationFailures(
        testing.allocator,
        Case.openOnce,
        .{ root, &fixture.attempt },
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
    try testing.expect(!decoded.identity.bound());
    try testing.expectEqualSlices(u8, &record.chain_sha256, &decoded.chain_sha256);

    // A bound identity is the same fixed width as an unbound one, whatever
    // the values, so binding an entry never changes a record's length.
    var identified: ProgressRecord = record;
    identified.state = .verified;
    identified.identity = .{
        .device = std.math.maxInt(u64),
        .inode = std.math.maxInt(u64),
        .link_count = std.math.maxInt(u64),
    };
    const wide = identified.encode(&buffer);
    try testing.expectEqual(progress_record_bytes, wide.len);
    const wide_decoded = try decodeProgressRecord(wide[0 .. wide.len - 1]);
    try testing.expect(wide_decoded.identity.eql(identified.identity));
    identified.identity = .{ .device = 0x2a, .inode = 0x1b, .link_count = 3 };
    const narrow = identified.encode(&buffer);
    try testing.expectEqual(progress_record_bytes, narrow.len);
    try testing.expect((try decodeProgressRecord(narrow[0 .. narrow.len - 1]))
        .identity.eql(identified.identity));

    // Every longest boundary name still fits the fixed field.
    inline for (@typeInfo(StepState).@"enum".fields) |field| {
        var state_record: ProgressRecord = record;
        state_record.state = @field(StepState, field.name);
        try testing.expectEqual(progress_record_bytes, state_record.encode(&buffer).len);
        _ = try decodeProgressRecord(buffer[0 .. progress_record_bytes - 1]);
    }
    inline for (@typeInfo(Stage).@"enum".fields) |field| {
        var stage_record: ProgressRecord = record;
        stage_record.scope = .journal;
        stage_record.index = ProgressRecord.no_index;
        stage_record.stage = @field(Stage, field.name);
        try testing.expectEqual(progress_record_bytes, stage_record.encode(&buffer).len);
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
    // Each identity column has its own separator, and a non-hexadecimal digit
    // in any of them is corruption rather than a zero.
    for ([_]usize{ 75, 92, 109 }) |separator| {
        damaged = buffer;
        damaged[separator] = 'x';
        try testing.expectError(
            error.ProgressCorrupt,
            decodeProgressRecord(damaged[0 .. progress_record_bytes - 1]),
        );
    }
    for ([_]usize{ 60, 77, 94 }) |digit| {
        damaged = buffer;
        damaged[digit] = 'g';
        try testing.expectError(
            error.ProgressCorrupt,
            decodeProgressRecord(damaged[0 .. progress_record_bytes - 1]),
        );
    }
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

// ---------------------------------------------------------------------------
// Ownership, privileged mode bits, and self-created intermediate states
// ---------------------------------------------------------------------------

/// A group this process may actually move an entry to, so an ownership change
/// is a real `chown` and not a modeled one. `null` when the environment
/// cannot offer a second group, which is the only case where the end-to-end
/// scenarios below cannot run; the ordering contract itself is proven without
/// a second group by `root_fs.test.ownership is written before a mode that
/// carries privileged bits`.
fn alternateGid() ?u32 {
    if (builtin.os.tag != .linux) return null;
    const linux = std.os.linux;
    const current = linux.getgid();
    var buffer: [64]std.posix.gid_t = undefined;
    const result = linux.getgroups(buffer.len, &buffer);
    if (linux.errno(result) == .SUCCESS) {
        for (buffer[0..result]) |value| {
            if (value != current) return value;
        }
    }
    // Only a privileged caller may name a group it does not belong to.
    if (linux.getuid() == 0) return if (current == 0) 1 else 0;
    return null;
}

fn expectMetadata(root: root_fs.Root, path: []const u8, mode: u32, uid: u32, gid: u32) !void {
    const found = try root.entry(try root_fs.Path.init(path));
    testing.expectEqual(mode, found.mode) catch |err| {
        std.debug.print("{s}: mode {o} expected {o}\n", .{ path, found.mode, mode });
        return err;
    };
    try testing.expectEqual(uid, found.uid);
    try testing.expectEqual(gid, found.gid);
}

test "root_mutation.test.privileged mode bits survive a real ownership change" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const other = alternateGid() orelse return error.SkipZigTest;
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    const uid = currentUid();
    const gid = currentGid();

    // Two existing entries whose mode already carries exactly the bits the
    // plan wants. Only their group changes, so a writer that skipped the
    // final `chmod` because the mode "already matched" would publish 0755,
    // fail verification, and then wedge rollback on a state neither side
    // recorded.
    try writeExisting(root, "usr/bin/suid", "old\n");
    try root.applyMetadata(try root_fs.Path.init("usr/bin/suid"), .{ .mode = 0o4755 });
    try writeExisting(root, "usr/bin/sgid", "old\n");
    try root.applyMetadata(try root_fs.Path.init("usr/bin/sgid"), .{ .mode = 0o2755 });
    try root.createSymbolicLink(try root_fs.Path.init("usr/bin/alias"), "suid");
    try root.createDirectoryPath(
        try root_fs.Path.init("usr/lib"),
        root_fs.default_directory_permissions,
    );

    const intents = [_]Intent{
        .{ .file = .{
            .path = "usr/bin/fresh",
            .bytes = "payload\n",
            .mode = 0o4755,
            .uid = uid,
            .gid = other,
            .modified_nanoseconds = 1_000_000_000,
        } },
        .{ .metadata = .{ .path = "usr/bin/suid", .mode = 0o4755, .gid = other } },
        .{ .metadata = .{ .path = "usr/bin/sgid", .mode = 0o2755, .gid = other } },
        .{ .directory = .{ .path = "usr/lib/drop", .mode = 0o2775, .uid = uid, .gid = other } },
        // Neither a symbolic link nor a directory can lose a capability
        // attribute to a `chown`, so neither is refused for carrying one.
        .{ .metadata = .{ .path = "usr/bin/alias", .gid = other } },
        .{ .metadata = .{ .path = "usr/lib", .gid = other } },
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();
    try testing.expectEqual(Outcome.applied, (try apply(&engine, .fromPlan(&plan))).outcome);

    try expectMetadata(root, "usr/bin/fresh", 0o4755, uid, other);
    try expectMetadata(root, "usr/bin/suid", 0o4755, uid, other);
    try expectMetadata(root, "usr/bin/sgid", 0o2755, uid, other);
    try expectMetadata(root, "usr/lib/drop", 0o2775, uid, other);
    try testing.expectEqual(other, (try root.entry(try root_fs.Path.init("usr/bin/alias"))).gid);
    try testing.expectEqual(other, (try root.entry(try root_fs.Path.init("usr/lib"))).gid);
    try clear(&engine);

    // The same transition backwards, rolled back part way through, restores
    // the exact recorded mode and ownership including the privileged bits.
    const back = [_]Intent{
        .{ .metadata = .{ .path = "usr/bin/suid", .mode = 0o4755, .gid = gid } },
        .{ .metadata = .{ .path = "usr/bin/sgid", .mode = 0o2755, .gid = gid } },
        fileIntent("usr/bin/fresh", "replaced\n"),
    };
    var second = try planFor(&fixture, &back);
    defer second.deinit();
    var injector: Injector = .{ .faults = &.{.{
        .boundary = .verify,
        .step = 2,
        .err = error.RenameFailed,
    }} };
    var rolled = try prepare(testing.allocator, root, &fixture.attempt, &second, .{}, .{
        .hooks = injector.interface(),
    });
    defer rolled.deinit();
    try testing.expectEqual(Outcome.rolled_back, (try apply(&rolled, .fromPlan(&second))).outcome);
    try expectMetadata(root, "usr/bin/suid", 0o4755, uid, other);
    try expectMetadata(root, "usr/bin/sgid", 0o2755, uid, other);
    try expectMetadata(root, "usr/bin/fresh", 0o4755, uid, other);
    try expectContent(root, "usr/bin/fresh", "payload\n");
    try expectWorkspaceEmpty(root);
    try clear(&rolled);
}

/// A parent whose set-group-ID bit is set gives every entry created inside it
/// the parent's group instead of the caller's, so `mkdir` and the staging
/// area publish intermediate ownership that matches neither recorded state.
fn seedGroupRoot(root: root_fs.Root, other: u32) !void {
    try root.createDirectoryPath(
        try root_fs.Path.init("srv/shared"),
        root_fs.default_directory_permissions,
    );
    try root.applyMetadata(try root_fs.Path.init("srv/shared"), .{ .mode = 0o2775, .gid = other });
    try writeExisting(root, "srv/shared/tool", "old\n");
    try root.applyMetadata(try root_fs.Path.init("srv/shared/tool"), .{ .mode = 0o4755 });
    try writeExisting(root, "srv/shared/doomed", "gone\n");
}

fn groupIntents(other: u32) [4]Intent {
    return .{
        .{ .directory = .{
            .path = "srv/shared/sub",
            .mode = 0o2755,
            .uid = currentUid(),
            .gid = currentGid(),
        } },
        .{ .file = .{
            .path = "srv/shared/new",
            .bytes = "created\n",
            .mode = 0o4755,
            .uid = currentUid(),
            .gid = other,
            .modified_nanoseconds = 1_000_000_000,
        } },
        .{ .metadata = .{ .path = "srv/shared/tool", .mode = 0o4755, .gid = currentGid() } },
        .{ .remove = .{ .path = "srv/shared/doomed" } },
    };
}

fn expectGroupSeeded(root: root_fs.Root, other: u32) !void {
    try expectMetadata(root, "srv/shared/tool", 0o4755, currentUid(), other);
    try expectContent(root, "srv/shared/doomed", "gone\n");
    try expectAbsent(root, "srv/shared/sub");
    try expectAbsent(root, "srv/shared/new");
}

fn expectGroupApplied(root: root_fs.Root, other: u32) !void {
    try expectMetadata(root, "srv/shared/tool", 0o4755, currentUid(), currentGid());
    try expectAbsent(root, "srv/shared/doomed");
    try expectMetadata(root, "srv/shared/new", 0o4755, currentUid(), other);
    try expectContent(root, "srv/shared/new", "created\n");
    const sub = try root.entry(try root_fs.Path.init("srv/shared/sub"));
    try testing.expect(sub.isDirectory());
    try testing.expectEqual(currentGid(), sub.gid);
    try testing.expectEqual(@as(u32, 0o2755), sub.mode);
}

fn runGroupCrashScenario(
    other: u32,
    faults: []const Fault,
    expectation: CrashExpectation,
) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedGroupRoot(root, other);

    var injector: Injector = .{ .faults = faults };
    const intents = groupIntents(other);
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var crashed = prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    }) catch |err| {
        try testing.expectEqual(error.SimulatedCrash, err);
        try testing.expect(injector.allFired());
        try recoverGroup(&fixture, other, .old_state);
        return;
    };
    const outcome = apply(&crashed, .fromPlan(&plan));
    crashed.deinit();
    try testing.expectError(error.SimulatedCrash, outcome);
    try testing.expect(injector.allFired());
    try recoverGroup(&fixture, other, expectation);
}

fn recoverGroup(fixture: *Fixture, other: u32, expectation: CrashExpectation) !void {
    const root = fixture.root();
    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})) orelse {
        try expectGroupSeeded(root, other);
        return;
    };
    defer engine.deinit();
    const report = try recover(&engine);
    switch (expectation) {
        .old_state => {
            try testing.expectEqual(Outcome.rolled_back, report.outcome);
            try expectGroupSeeded(root, other);
        },
        .new_state => {
            try testing.expectEqual(Outcome.applied, report.outcome);
            try expectGroupApplied(root, other);
        },
    }
    try expectWorkspaceEmpty(root);
    try clear(&engine);
    try expectAbsent(root, journal_path);
}

test "root_mutation.test.crash at every metadata syscall under a set-group-ID parent recovers exactly" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const other = alternateGid() orelse return error.SkipZigTest;

    // Every one of these leaves a state that is neither the recorded old one
    // nor the recorded new one: a directory carrying the parent's inherited
    // group, an inode whose ownership moved but whose mode has not caught up
    // yet, or a mode written without its timestamp.
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
        .metadata_chown,
        .metadata_chmod,
        .metadata_utimens,
        .parent_sync,
        .verify,
    };
    for (rollback_boundaries) |boundary| {
        const faults = [_]Fault{.{ .boundary = boundary }};
        runGroupCrashScenario(other, &faults, .old_state) catch |err| {
            std.debug.print("set-group-ID crash scenario failed at {t}\n", .{boundary});
            return err;
        };
    }

    // The same boundaries reached a second time, which is where an ownership
    // change has already happened once and the mode write has not.
    for ([_]Boundary{ .metadata_chown, .metadata_chmod }) |boundary| {
        const faults = [_]Fault{.{ .boundary = boundary, .occurrence = 2 }};
        runGroupCrashScenario(other, &faults, .old_state) catch |err| {
            std.debug.print("second-occurrence scenario failed at {t}\n", .{boundary});
            return err;
        };
    }

    for ([_]Boundary{ .release_staging, .release_backup }) |boundary| {
        const faults = [_]Fault{.{ .boundary = boundary }};
        runGroupCrashScenario(other, &faults, .new_state) catch |err| {
            std.debug.print("set-group-ID release scenario failed at {t}\n", .{boundary});
            return err;
        };
    }

    // Restoration boundaries need a first fault to turn the transaction
    // around, and then interrupt the restoration itself part way through its
    // own ordered metadata writes.
    for ([_]Boundary{ .restore_rename, .metadata_chown, .metadata_chmod }) |boundary| {
        const faults = [_]Fault{
            .{ .boundary = .verify, .step = 3, .err = error.RenameFailed },
            .{
                .boundary = boundary,
                .step = if (boundary == .restore_rename) null else 2,
                .occurrence = if (boundary == .restore_rename) 1 else 2,
            },
        };
        runGroupCrashScenario(other, &faults, .old_state) catch |err| {
            std.debug.print("set-group-ID restore scenario failed at {t}\n", .{boundary});
            return err;
        };
    }

    // Nothing injected at all still produces the exact recorded new state.
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedGroupRoot(root, other);
    const intents = groupIntents(other);
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();
    try testing.expectEqual(Outcome.applied, (try apply(&engine, .fromPlan(&plan))).outcome);
    try expectGroupApplied(root, other);
    try clear(&engine);
}

test "root_mutation.test.a directory the transaction created is removable before its metadata" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const other = alternateGid() orelse return error.SkipZigTest;
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();

    // A set-group-ID parent makes `mkdir` publish the parent's group, so the
    // state between the directory's creation and its metadata boundary is
    // provably an intermediate one rather than either recorded state.
    try root.createDirectoryPath(
        try root_fs.Path.init("opt"),
        root_fs.default_directory_permissions,
    );
    try root.applyMetadata(try root_fs.Path.init("opt"), .{ .mode = 0o2775, .gid = other });
    const intents = [_]Intent{
        .{ .directory = .{
            .path = "opt/tree",
            .mode = 0o2755,
            .uid = currentUid(),
            .gid = currentGid(),
        } },
        fileIntent("opt/tree/child", "leaf\n"),
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var injector: Injector = .{ .faults = &.{.{ .boundary = .metadata_apply, .step = 0 }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();
    // The directory exists and does not hold its planned ownership yet.
    const partial = try root.entry(try root_fs.Path.init("opt/tree"));
    try testing.expect(partial.isDirectory());
    try testing.expectEqual(other, partial.gid);

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(Outcome.rolled_back, (try recover(&engine)).outcome);
    try expectAbsent(root, "opt/tree");
    try clear(&engine);

    // A directory that is no longer this transaction's own empty creation is
    // never removed on a guess.
    var planted: Fixture = undefined;
    try planted.init();
    defer planted.deinit();
    const planted_root = planted.root();
    try planted_root.createDirectoryPath(
        try root_fs.Path.init("opt"),
        root_fs.default_directory_permissions,
    );
    try planted_root.applyMetadata(
        try root_fs.Path.init("opt"),
        .{ .mode = 0o2775, .gid = other },
    );
    var second = try planFor(&planted, &intents);
    defer second.deinit();
    var again: Injector = .{ .faults = &.{.{ .boundary = .metadata_apply, .step = 0 }} };
    var interrupted = try prepare(
        testing.allocator,
        planted_root,
        &planted.attempt,
        &second,
        .{},
        .{ .hooks = again.interface() },
    );
    try testing.expectError(error.SimulatedCrash, apply(&interrupted, .fromPlan(&second)));
    interrupted.deinit();
    try planted_root.writeNewFile(try root_fs.Path.init("opt/tree/planted"), "x", .{}, true);

    var blocked = (try open(testing.allocator, planted_root, &planted.attempt, .{})).?;
    defer blocked.deinit();
    try testing.expectEqual(Outcome.recovery_required, (try recover(&blocked)).outcome);
    try testing.expectEqual(Stage.recovery_required, blocked.stage());
    try testing.expectError(error.RecoveryRequired, apply(&blocked, .fromPlan(&second)));
}

test "root_mutation.test.the reachable metadata set is exactly the ordered writes" {
    const expected: Metadata = .{
        .mode = 0o4755,
        .uid = 10,
        .gid = 20,
        .modified_nanoseconds = 5,
    };
    const desired: Metadata = .{
        .mode = 0o4755,
        .uid = 10,
        .gid = 30,
        .modified_nanoseconds = 9,
    };
    // Ownership that can clear a privileged bit always forces the mode write,
    // so the desired mode is never left behind even though it already
    // matches.
    try testing.expect(writesMode(.regular, expected, desired));
    try testing.expect(!writesMode(.symlink, expected, desired));
    try testing.expect(!writesMode(.directory, expected, desired));

    const applying = reachableMetadata(.regular, expected, desired, .forward);
    // Nothing applied, ownership applied with the bit still set or already
    // cleared, mode rewritten, and finally the timestamp.
    try testing.expect(applying.contains(expected));
    try testing.expect(applying.contains(.{
        .mode = 0o4755,
        .uid = 10,
        .gid = 30,
        .modified_nanoseconds = 5,
    }));
    try testing.expect(applying.contains(.{
        .mode = 0o0755,
        .uid = 10,
        .gid = 30,
        .modified_nanoseconds = 5,
    }));
    try testing.expect(applying.contains(desired));
    try testing.expectEqual(@as(usize, 4), applying.len);
    // A combination none of the three writes can produce is refused, however
    // close it looks.
    try testing.expect(!applying.contains(.{
        .mode = 0o0700,
        .uid = 10,
        .gid = 30,
        .modified_nanoseconds = 5,
    }));
    try testing.expect(!applying.contains(.{
        .mode = 0o4755,
        .uid = 11,
        .gid = 30,
        .modified_nanoseconds = 9,
    }));
    try testing.expect(!applying.contains(.{
        .mode = 0o0755,
        .uid = 10,
        .gid = 20,
        .modified_nanoseconds = 5,
    }));

    // Once the transaction has turned around, an interrupted restoration is
    // reachable from wherever the forward pass stopped, and the union is
    // closed: walking the ordered writes back to the recorded old metadata
    // from every member adds nothing new.
    const restore = reachableMetadata(.regular, expected, desired, .restore);
    for (applying.items[0..applying.len]) |value| try testing.expect(restore.contains(value));
    try testing.expect(restore.contains(.{
        .mode = 0o4755,
        .uid = 10,
        .gid = 20,
        .modified_nanoseconds = 9,
    }));
    try testing.expect(restore.contains(.{
        .mode = 0o0755,
        .uid = 10,
        .gid = 20,
        .modified_nanoseconds = 9,
    }));
    var closed = restore;
    for (restore.items[0..restore.len]) |start|
        addMetadataChain(&closed, .regular, start, expected);
    try testing.expectEqual(restore.len, closed.len);
    try testing.expect(restore.len < closed.items.len);
    try testing.expect(!restore.contains(.{
        .mode = 0o0700,
        .uid = 10,
        .gid = 20,
        .modified_nanoseconds = 9,
    }));

    // A directory keeps its privileged bits across an ownership change and
    // never publishes a modification time, so its chain is shorter.
    const directory = reachableMetadata(.directory, .{
        .mode = 0o2755,
        .uid = 10,
        .gid = 20,
        .modified_nanoseconds = 0,
    }, .{
        .mode = 0o2755,
        .uid = 10,
        .gid = 30,
        .modified_nanoseconds = 0,
    }, .forward);
    try testing.expectEqual(@as(usize, 2), directory.len);
}

test "root_mutation.test.a transition that unlinks before it publishes stays resumable" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();

    try root.createDirectory(
        try root_fs.Path.init("becomes-file"),
        root_fs.default_directory_permissions,
    );
    const intents = [_]Intent{fileIntent("becomes-file", "now a file\n")};
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    // Power loss between the `rmdir` a rename cannot express and the rename
    // itself leaves the name empty, which is neither recorded state.
    var injector: Injector = .{ .faults = &.{.{ .boundary = .publish_rename, .step = 0 }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();
    try expectAbsent(root, "becomes-file");

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(Outcome.rolled_back, (try recover(&engine)).outcome);
    try testing.expect((try root.entry(try root_fs.Path.init("becomes-file"))).isDirectory());
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

test "root_mutation.test.an external metadata change is never mistaken for an intermediate" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();

    try writeExisting(root, "etc/meta", "meta\n");
    const intents = [_]Intent{
        .{ .metadata = .{ .path = "etc/meta", .mode = 0o600 } },
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    // A mode nobody in this plan could have written is an external
    // modification, not a partially applied boundary.
    try root.applyMetadata(try root_fs.Path.init("etc/meta"), .{ .mode = 0o640 });
    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.recovery_required, report.outcome);
    try testing.expectEqual(Code.external_modification, report.diagnostic.?.code);
    try testing.expectEqual(@as(u32, 0o640), (try root.entry(try root_fs.Path.init("etc/meta"))).mode);

    // A replacement that carries exactly the recorded metadata but a
    // different inode is refused for the same reason.
    var second: Fixture = undefined;
    try second.init();
    defer second.deinit();
    const other_root = second.root();
    try writeExisting(other_root, "etc/meta", "meta\n");
    var swap = try planFor(&second, &intents);
    defer swap.deinit();
    var swapped = try prepare(testing.allocator, other_root, &second.attempt, &swap, .{}, .{});
    defer swapped.deinit();
    try other_root.publishFile(try root_fs.Path.init("etc/meta"), "meta\n", .{});
    const swap_report = try apply(&swapped, .fromPlan(&swap));
    try testing.expectEqual(Outcome.recovery_required, swap_report.outcome);
}

// ---------------------------------------------------------------------------
// Transitions that cross the directory boundary
// ---------------------------------------------------------------------------

/// The recorded old state of a target a `create_directory` step takes over.
/// A directory can be neither renamed over nor renamed away, so both of these
/// are unlinked before `mkdir` can take the name.
const Replaced = enum { regular, symlink };

fn seedReplaced(root: root_fs.Root, kind: Replaced) !void {
    try root.createDirectoryPath(
        try root_fs.Path.init("etc"),
        root_fs.default_directory_permissions,
    );
    switch (kind) {
        .regular => try writeExisting(root, "etc/thing", "old\n"),
        .symlink => try root.createSymbolicLink(try root_fs.Path.init("etc/thing"), "elsewhere"),
    }
}

fn expectReplacedSeed(root: root_fs.Root, kind: Replaced) !void {
    switch (kind) {
        .regular => try expectContent(root, "etc/thing", "old\n"),
        .symlink => {
            var buffer: [64]u8 = undefined;
            const target = try root.readSymbolicLink(try root_fs.Path.init("etc/thing"), &buffer);
            try testing.expectEqualStrings("elsewhere", target);
        },
    }
    try expectAbsent(root, "etc/other");
}

/// The transition intents: a non-directory becomes a directory that the next
/// step immediately fills, so a resumed transaction has to finish both.
fn replacedIntents() [2]Intent {
    return .{
        directoryIntent("etc/thing"),
        fileIntent("etc/other", "content\n"),
    };
}

/// Crashes at `boundary` of the transition step and resumes with `apply`,
/// which is the path a re-run of the same transaction takes: the recorded
/// direction is still forward, so the interrupted transition must be finished
/// rather than refused as somebody else's work.
fn runForwardTransitionResume(kind: Replaced, boundary: Boundary) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedReplaced(root, kind);

    const intents = replacedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var injector: Injector = .{ .faults = &.{.{ .boundary = boundary, .step = 0 }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();
    try testing.expect(injector.allFired());

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.applied, report.outcome);
    const entry = try root.entry(try root_fs.Path.init("etc/thing"));
    try testing.expect(entry.isDirectory());
    try testing.expectEqual(@as(u32, 0o755), entry.mode);
    try expectContent(root, "etc/other", "content\n");
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

/// The same interruption resolved backwards, which restores the recorded old
/// non-directory over the directory the transaction created.
fn runForwardTransitionRollback(kind: Replaced, boundary: Boundary) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedReplaced(root, kind);

    const intents = replacedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var injector: Injector = .{ .faults = &.{.{ .boundary = boundary, .step = 0 }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();
    try testing.expect(injector.allFired());

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(Outcome.rolled_back, (try recover(&engine)).outcome);
    try expectReplacedSeed(root, kind);
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

test "root_mutation.test.a non-directory becoming a directory resumes from every boundary" {
    // `target_remove` stops before the old entry is unlinked, `publish_create`
    // after the unlink and before the `mkdir`, `metadata_apply` after the
    // `mkdir`, and `parent_sync` after the directory is complete. Every one of
    // them is resumable forwards and backwards.
    const boundaries = [_]Boundary{
        .target_remove,
        .publish_create,
        .metadata_apply,
        .parent_sync,
    };
    for ([_]Replaced{ .regular, .symlink }) |kind| {
        for (boundaries) |boundary| {
            runForwardTransitionResume(kind, boundary) catch |err| {
                std.debug.print("resume of {t} at {t} failed\n", .{ kind, boundary });
                return err;
            };
            runForwardTransitionRollback(kind, boundary) catch |err| {
                std.debug.print("rollback of {t} at {t} failed\n", .{ kind, boundary });
                return err;
            };
        }
    }
}

test "root_mutation.test.an absence outside a step's own removal window is foreign" {
    // A target that disappears before the step could have removed anything.
    // The regular file the transition would have replaced is recorded in the
    // backup boundary, which has not run, so the absence is nobody's work but
    // an outsider's - and, with no backup captured, no rollback can put the
    // vanished content back either.
    {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        const root = fixture.root();
        try seedReplaced(root, .regular);

        const intents = replacedIntents();
        var plan = try planFor(&fixture, &intents);
        defer plan.deinit();
        var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
        defer engine.deinit();

        try root.removeFile(try root_fs.Path.init("etc/thing"));
        const report = try apply(&engine, .fromPlan(&plan));
        try testing.expectEqual(Outcome.recovery_required, report.outcome);
        try testing.expectEqual(Code.external_modification, report.diagnostic.?.code);
        try testing.expectEqual(@as(u32, 0), report.diagnostic.?.step.?);
    }

    // A step whose publication removes nothing at all never leaves the name
    // empty, so an absence is external however far the step has got.
    {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        const root = fixture.root();
        try writeExisting(root, "etc/plain", "old\n");

        const intents = [_]Intent{fileIntent("etc/plain", "new\n")};
        var plan = try planFor(&fixture, &intents);
        defer plan.deinit();
        var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
        defer engine.deinit();

        try root.removeFile(try root_fs.Path.init("etc/plain"));
        const report = try apply(&engine, .fromPlan(&plan));
        try testing.expectEqual(Outcome.recovery_required, report.outcome);
        try testing.expectEqual(Code.external_modification, report.diagnostic.?.code);
    }

    // Neither does a metadata step, nor a directory creation that finds the
    // directory already there: both write onto the entry that is present, and
    // an entry that vanished is not one this transaction removed.
    for ([_]Intent{
        .{ .metadata = .{ .path = "etc/empty", .mode = 0o700 } },
        .{ .directory = .{ .path = "etc/empty", .mode = 0o700, .uid = currentUid(), .gid = currentGid() } },
    }) |intent| {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        const root = fixture.root();
        try root.createDirectoryPath(
            try root_fs.Path.init("etc/empty"),
            root_fs.default_directory_permissions,
        );

        const intents = [_]Intent{intent};
        var plan = try planFor(&fixture, &intents);
        defer plan.deinit();
        var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
        defer engine.deinit();

        try root.removeDirectory(try root_fs.Path.init("etc/empty"));
        const report = try apply(&engine, .fromPlan(&plan));
        try testing.expectEqual(Outcome.recovery_required, report.outcome);
        try testing.expectEqual(Code.external_modification, report.diagnostic.?.code);
    }
}

test "root_mutation.test.a directory removed after this transaction made it is foreign" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedReplaced(root, .regular);

    const intents = replacedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    // Power loss after the `mkdir` and before the metadata boundary. The
    // removal window is closed: the step published its publication boundary,
    // so an absence now is somebody else's removal of the directory this
    // transaction created, not a transition it is still part way through.
    var injector: Injector = .{ .faults = &.{.{ .boundary = .metadata_apply, .step = 0 }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();
    try root.removeDirectory(try root_fs.Path.init("etc/thing"));

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Code.external_modification, report.diagnostic.?.code);
    // The backup still holds the recorded regular file, so the transaction is
    // not wedged: it turns around and puts the recorded old state back.
    try testing.expectEqual(Outcome.rolled_back, report.outcome);
    try expectReplacedSeed(root, .regular);
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

// ---------------------------------------------------------------------------
// Link counts this transaction changes itself
// ---------------------------------------------------------------------------

test "root_mutation.test.a hard link this plan stages does not wedge its source's metadata" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try writeExisting(root, "etc/tool", "payload\n");
    try root.applyMetadata(try root_fs.Path.init("etc/tool"), .{ .modified_nanoseconds = 5 });

    // A metadata step on the very inode a later step hard-links. The link is
    // staged before it is published, so the source gains a link the recorded
    // state does not have while the transaction is still running.
    const intents = [_]Intent{
        .{ .metadata = .{ .path = "etc/tool", .mode = 0o600, .modified_nanoseconds = 9 } },
        .{ .hard_link = .{ .path = "etc/clone", .source = "etc/tool" } },
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var injector: Injector = .{ .faults = &.{.{ .boundary = .publish_rename, .step = 1 }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();
    // The staged link is real and still holds the source's inode.
    try testing.expectEqual(
        @as(u64, 2),
        (try root.entry(try root_fs.Path.init("etc/tool"))).link_count,
    );

    // The rollback restores the recorded metadata in the same three ordered
    // writes, and power loss between two of them leaves the source carrying a
    // partially restored state and the extra staged link at once.
    var second: Injector = .{ .faults = &.{.{ .boundary = .metadata_utimens, .step = 0 }} };
    var restoring = (try open(testing.allocator, root, &fixture.attempt, .{
        .hooks = second.interface(),
    })).?;
    try testing.expectError(error.SimulatedCrash, recover(&restoring));
    restoring.deinit();
    try testing.expect(second.allFired());
    const partial = try root.entry(try root_fs.Path.init("etc/tool"));
    try testing.expectEqual(@as(u32, 0o644), partial.mode);
    try testing.expectEqual(@as(i128, 9), partial.modified_nanoseconds);
    try testing.expectEqual(@as(u64, 2), partial.link_count);

    // The count is exactly the recorded one plus this transaction's own
    // staged link, so the partially restored state is the transaction's own
    // work and the restoration finishes it.
    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(Outcome.rolled_back, (try recover(&engine)).outcome);
    const restored = try root.entry(try root_fs.Path.init("etc/tool"));
    try testing.expectEqual(@as(u32, 0o644), restored.mode);
    try testing.expectEqual(@as(i128, 5), restored.modified_nanoseconds);
    try testing.expectEqual(@as(u64, 1), restored.link_count);
    try expectAbsent(root, "etc/clone");
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

test "root_mutation.test.a hard link nobody planned still wedges its source's metadata" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try writeExisting(root, "etc/tool", "payload\n");
    try root.applyMetadata(try root_fs.Path.init("etc/tool"), .{ .modified_nanoseconds = 5 });

    const intents = [_]Intent{
        .{ .metadata = .{ .path = "etc/tool", .mode = 0o600, .modified_nanoseconds = 9 } },
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var injector: Injector = .{ .faults = &.{.{ .boundary = .metadata_utimens, .step = 0 }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();

    // This plan links nothing, so a link that appeared belongs to somebody
    // else and the partially applied metadata is no longer provably this
    // transaction's own work.
    try root.createHardLink(
        try root_fs.Path.init("etc/tool"),
        try root_fs.Path.init("etc/stolen"),
    );

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    const report = try recover(&engine);
    try testing.expectEqual(Outcome.recovery_required, report.outcome);
    try testing.expectEqual(Stage.recovery_required, engine.stage());
}

test "root_mutation.test.a subdirectory this plan creates does not wedge its parent's metadata" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // A directory publishes at most an ownership change and a mode change, so
    // a real second group is what makes the two writes - and the state
    // between them - reachable at all.
    const other = alternateGid() orelse return error.SkipZigTest;
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try root.createDirectoryPath(
        try root_fs.Path.init("etc/conf"),
        root_fs.default_directory_permissions,
    );

    // The plan creates a subdirectory of the directory whose metadata it also
    // rewrites, so the parent gains a link through the child's `..` before the
    // metadata boundary runs.
    const intents = [_]Intent{
        directoryIntent("etc/conf/sub"),
        .{ .metadata = .{ .path = "etc/conf", .mode = 0o700, .gid = other } },
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var injector: Injector = .{ .faults = &.{.{ .boundary = .metadata_chmod, .step = 1 }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();
    const partial = try root.entry(try root_fs.Path.init("etc/conf"));
    try testing.expectEqual(other, partial.gid);
    try testing.expectEqual(@as(u64, 3), partial.link_count);

    // The count is exactly the recorded one plus the subdirectory this plan
    // made, so the half-written metadata is this transaction's own and the
    // forward pass finishes it.
    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(Outcome.applied, (try apply(&engine, .fromPlan(&plan))).outcome);
    try expectMetadata(root, "etc/conf", 0o700, currentUid(), other);
    try testing.expect((try root.entry(try root_fs.Path.init("etc/conf/sub"))).isDirectory());
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

test "root_mutation.test.a subdirectory nobody planned still wedges its parent's metadata" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const other = alternateGid() orelse return error.SkipZigTest;
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try root.createDirectoryPath(
        try root_fs.Path.init("etc/conf"),
        root_fs.default_directory_permissions,
    );

    const intents = [_]Intent{
        directoryIntent("etc/conf/sub"),
        .{ .metadata = .{ .path = "etc/conf", .mode = 0o700, .gid = other } },
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    var injector: Injector = .{ .faults = &.{.{ .boundary = .metadata_chmod, .step = 1 }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();

    // One more subdirectory than this plan accounts for is one link outside
    // the exact set the transaction can have produced.
    try root.createDirectory(
        try root_fs.Path.init("etc/conf/foreign"),
        root_fs.default_directory_permissions,
    );

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.recovery_required, report.outcome);
    try testing.expectEqual(Code.external_modification, report.diagnostic.?.code);
    try testing.expectEqual(Stage.recovery_required, engine.stage());
}

test "root_mutation.test.the reachable link counts are exactly this plan's own links" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try root.createDirectoryPath(
        try root_fs.Path.init("etc/conf"),
        root_fs.default_directory_permissions,
    );
    try writeExisting(root, "etc/tool", "payload\n");
    try writeExisting(root, "etc/conf/file", "old\n");

    const intents = [_]Intent{
        // 0: a subdirectory of `etc/conf` made before its parent's metadata.
        directoryIntent("etc/conf/early"),
        // 1: the parent's own metadata, the step being classified.
        .{ .metadata = .{ .path = "etc/conf", .mode = 0o700 } },
        // 2: a second subdirectory, made after it.
        directoryIntent("etc/conf/late"),
        // 3: a file replacing a file, which changes no count at all.
        fileIntent("etc/conf/file", "new\n"),
        // 4: the metadata of the file a later step hard-links.
        .{ .metadata = .{ .path = "etc/tool", .mode = 0o600 } },
        // 5: that hard link, which adds a link to `etc/tool`'s inode.
        .{ .hard_link = .{ .path = "etc/clone", .source = "etc/tool" } },
        // 6: a deeper path, which is not a direct child of `etc/conf`.
        directoryIntent("etc/conf/early/deeper"),
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    const steps = engine.journal().steps;
    const directory = switch (steps[1].expected) {
        .absent => return error.UnexpectedAbsence,
        .present => |state| state,
    };
    const file = switch (steps[4].expected) {
        .absent => return error.UnexpectedAbsence,
        .present => |state| state,
    };
    try testing.expectEqual(@as(u64, 2), directory.link_count);
    try testing.expectEqual(@as(u64, 1), file.link_count);
    // No two of these steps share a path, so every precondition here is
    // preflight's own observation and binds the inode it observed.
    const directory_bound = try boundPrecondition(&engine, 1);
    const file_bound = try boundPrecondition(&engine, 4);
    try testing.expectEqual(directory.inode, directory_bound.inode);
    try testing.expect(directory_bound.since == null);

    // Nothing has been applied, so nothing but the recorded count is
    // reachable - and the recorded count is always reachable.
    for ([_]Phase{ .forward, .restore }) |phase| {
        const counts = reachableLinkCounts(&engine, steps[1], directory, directory_bound, phase);
        try testing.expectEqual(@as(i128, 2), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
        try testing.expect(!linkCountReachable(
            &engine,
            steps[1],
            directory,
            directory_bound,
            3,
            phase,
        ));
        try testing.expect(linkCountReachable(
            &engine,
            steps[1],
            directory,
            directory_bound,
            2,
            phase,
        ));
    }

    // Once mutation is authorized the first step is inside its own
    // publication boundary: its `mkdir` may or may not have run. Every later
    // step is still past the forward pass's frontier and has done nothing.
    try engine.publishStage(.applying);
    {
        const counts = reachableLinkCounts(&engine, steps[1], directory, directory_bound, .forward);
        try testing.expectEqual(@as(i128, 2), counts.lower);
        try testing.expectEqual(@as(i128, 3), counts.upper);
    }
    // Once the `mkdir` is durable the extra link is certain, and one more
    // than that is refused.
    try engine.publishState(0, .published, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[1], directory, directory_bound, .forward);
        try testing.expectEqual(@as(i128, 3), counts.lower);
        try testing.expectEqual(@as(i128, 3), counts.upper);
        try testing.expect(!linkCountReachable(
            &engine,
            steps[1],
            directory,
            directory_bound,
            4,
            .forward,
        ));
        // The recorded count stays admissible: a filesystem that does not
        // maintain directory link counts reports it unchanged.
        try testing.expect(linkCountReachable(
            &engine,
            steps[1],
            directory,
            directory_bound,
            2,
            .forward,
        ));
    }

    // The second subdirectory is only reachable once the pass has actually
    // got to it, and it adds exactly one more link.
    try engine.publishState(0, .verified, .unbound);
    try engine.publishState(1, .verified, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[1], directory, directory_bound, .forward);
        try testing.expectEqual(@as(i128, 3), counts.lower);
        try testing.expectEqual(@as(i128, 4), counts.upper);
    }
    try engine.publishState(2, .verified, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[1], directory, directory_bound, .forward);
        try testing.expectEqual(@as(i128, 4), counts.lower);
        try testing.expectEqual(@as(i128, 4), counts.upper);
        try testing.expect(!linkCountReachable(
            &engine,
            steps[1],
            directory,
            directory_bound,
            5,
            .forward,
        ));
    }
    // A file replacing a file and a directory two levels down are not links
    // on this directory at all.
    try engine.publishState(3, .verified, .unbound);
    try engine.publishState(6, .verified, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[1], directory, directory_bound, .forward);
        try testing.expectEqual(@as(i128, 4), counts.lower);
        try testing.expectEqual(@as(i128, 4), counts.upper);
    }

    // A hard link is a link on its source's inode from the moment it is
    // staged. Before the pass reaches the linking step, nothing is staged.
    {
        const counts = reachableLinkCounts(&engine, steps[4], file, file_bound, .forward);
        try testing.expectEqual(@as(i128, 1), counts.lower);
        try testing.expectEqual(@as(i128, 1), counts.upper);
    }
    // The linking step names the inode the metadata step's verified boundary
    // bound, so the link is attributed only once that boundary is durable.
    try publishVerified(&engine, 4);
    {
        const counts = reachableLinkCounts(&engine, steps[4], file, file_bound, .forward);
        try testing.expectEqual(@as(i128, 1), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
    }
    try engine.publishState(5, .staged, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[4], file, file_bound, .forward);
        try testing.expectEqual(@as(i128, 2), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
        try testing.expect(!linkCountReachable(
            &engine,
            steps[4],
            file,
            file_bound,
            3,
            .forward,
        ));
    }
    // Publication renames the staged link into place; the link itself stays.
    try engine.publishState(5, .published, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[4], file, file_bound, .forward);
        try testing.expectEqual(@as(i128, 2), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
    }

    // Rollback undoes steps in reverse index order, so while a step is being
    // restored every later step has already given its links back and every
    // earlier one still holds them.
    try engine.publishStage(.rolling_back);
    try engine.publishState(6, .reverted, .unbound);
    try engine.publishState(5, .reverted, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[4], file, file_bound, .restore);
        // The published link went with the step, but the staged entry it was
        // renamed from is only released after the whole restoration.
        try testing.expectEqual(@as(i128, 1), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
    }
    try engine.publishState(4, .reverted, .unbound);
    try engine.publishState(3, .reverted, .unbound);
    try engine.publishState(2, .reverted, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[1], directory, directory_bound, .restore);
        // The later subdirectory is gone; the earlier one is still there.
        try testing.expectEqual(@as(i128, 3), counts.lower);
        try testing.expectEqual(@as(i128, 3), counts.upper);
        try testing.expect(!linkCountReachable(
            &engine,
            steps[1],
            directory,
            directory_bound,
            4,
            .restore,
        ));
    }
    try engine.publishState(1, .reverted, .unbound);
    try engine.publishState(0, .reverted, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[1], directory, directory_bound, .restore);
        try testing.expectEqual(@as(i128, 2), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
    }

    // The release removes every staging and backup entry, so a workspace link
    // is uncertain while it runs and gone once it is finished.
    try engine.publishStage(.releasing_rollback);
    {
        const counts = reachableLinkCounts(&engine, steps[4], file, file_bound, .restore);
        try testing.expectEqual(@as(i128, 1), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
    }
    try engine.publishStage(.rolled_back);
    {
        const counts = reachableLinkCounts(&engine, steps[4], file, file_bound, .restore);
        try testing.expectEqual(@as(i128, 1), counts.lower);
        try testing.expectEqual(@as(i128, 1), counts.upper);
    }
}

test "root_mutation.test.a backup is a link on the inode it preserves" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try writeExisting(root, "etc/tool", "payload\n");

    // The metadata step and the replacement name the same path, so the
    // backup the replacement captures is a hard link to the very inode the
    // metadata step is writing on.
    const intents = [_]Intent{
        .{ .metadata = .{ .path = "etc/tool", .mode = 0o600 } },
        fileIntent("etc/tool", "replaced\n"),
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    const steps = engine.journal().steps;
    const file = switch (steps[0].expected) {
        .absent => return error.UnexpectedAbsence,
        .present => |state| state,
    };
    try testing.expect(steps[1].backup_entry != null);
    const file_bound = try boundPrecondition(&engine, 0);
    try engine.publishStage(.applying);
    // The replacement's own precondition is the metadata step's desired
    // state, which carries no inode of its own: until the metadata step's
    // verified boundary binds the entry it published, the backup that step
    // will capture is attributed to nothing.
    try testing.expectEqual(Precondition.pending, precondition(&engine, steps[1]));
    try engine.publishState(1, .staged, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[0], file, file_bound, .forward);
        try testing.expectEqual(@as(i128, 1), counts.lower);
        try testing.expectEqual(@as(i128, 1), counts.upper);
    }
    try publishVerified(&engine, 0);
    {
        const counts = reachableLinkCounts(&engine, steps[0], file, file_bound, .forward);
        // Inside the backup boundary the link may or may not exist yet.
        try testing.expectEqual(@as(i128, 1), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
    }
    try engine.publishState(1, .backup_captured, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[0], file, file_bound, .forward);
        try testing.expectEqual(@as(i128, 2), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
        try testing.expect(!linkCountReachable(
            &engine,
            steps[0],
            file,
            file_bound,
            3,
            .forward,
        ));
    }
}

test "root_mutation.test.a backup is attributed to the inode it actually preserves" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try writeExisting(root, "etc/tool", "payload\n");

    // Three steps on one path: the original inode is replaced, the
    // replacement's metadata is rewritten, and the replacement is itself
    // replaced. The last step's backup is a hard link to the inode the first
    // replacement published, and to nothing else - attributing it to the
    // original inode as well would admit exactly one outside hard link on an
    // entry the plan is about to restore.
    const intents = [_]Intent{
        fileIntent("etc/tool", "one\n"),
        .{ .metadata = .{ .path = "etc/tool", .mode = 0o600 } },
        fileIntent("etc/tool", "two\n"),
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    const steps = engine.journal().steps;
    const original = switch (steps[0].expected) {
        .absent => return error.UnexpectedAbsence,
        .present => |state| state,
    };
    try testing.expect(steps[0].backup_entry != null);
    try testing.expect(steps[2].backup_entry != null);
    const original_bound = try boundPrecondition(&engine, 0);
    try engine.publishStage(.applying);

    // The first step's own backup is a link on the original inode.
    try engine.publishState(0, .staged, .unbound);
    try engine.publishState(0, .backup_captured, .unbound);
    {
        const counts = reachableLinkCounts(&engine, steps[0], original, original_bound, .forward);
        try testing.expectEqual(@as(i128, 2), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
    }

    // The replacement publishes a different inode, which the verified
    // boundary binds. The metadata step's precondition resolves to it, and so
    // does the last step's, so the backup the last step captures is a link on
    // that inode and never on the original.
    try engine.publishState(0, .published, .unbound);
    try root.removeFile(try root_fs.Path.init("etc/tool"));
    try writeExisting(root, "etc/tool", "one\n");
    try engine.publishState(0, .parent_synced, .unbound);
    try publishVerified(&engine, 0);
    const published = try boundPrecondition(&engine, 1);
    try testing.expect(published.inode != original.inode);
    try testing.expectEqual(@as(?u32, 0), published.since);
    try publishVerified(&engine, 1);
    try engine.publishState(2, .staged, .unbound);
    try engine.publishState(2, .backup_captured, .unbound);
    {
        // One link for the name, one for the first step's backup. The last
        // step's backup belongs to the inode the plan published in between.
        const counts = reachableLinkCounts(&engine, steps[0], original, original_bound, .forward);
        try testing.expectEqual(@as(i128, 2), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
        try testing.expect(!linkCountReachable(
            &engine,
            steps[0],
            original,
            original_bound,
            3,
            .forward,
        ));
    }

    // On the published inode the same backup is certain, and the count the
    // binding boundary observed is not counted twice.
    const replacement = try boundPrecondition(&engine, 2);
    const replaced_state = switch (steps[1].desired) {
        .absent => return error.UnexpectedAbsence,
        .present => |state| state,
    };
    {
        const counts =
            reachableLinkCounts(&engine, steps[2], replaced_state, replacement, .forward);
        try testing.expectEqual(@as(i128, 2), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
    }
}

test "root_mutation.test.a hard link is attributed to the inode it actually names" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try writeExisting(root, "etc/tool", "payload\n");

    // The plan replaces the file, re-modes the replacement, and then
    // hard-links it. The link names the inode the replacement published, so
    // it is a link on that inode and never on the one the plan found.
    const intents = [_]Intent{
        fileIntent("etc/tool", "one\n"),
        .{ .metadata = .{ .path = "etc/tool", .mode = 0o600 } },
        .{ .hard_link = .{ .path = "etc/clone", .source = "etc/tool" } },
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    const steps = engine.journal().steps;
    const original = switch (steps[0].expected) {
        .absent => return error.UnexpectedAbsence,
        .present => |state| state,
    };
    const original_bound = try boundPrecondition(&engine, 0);
    try engine.publishStage(.applying);
    try engine.publishState(0, .staged, .unbound);
    try engine.publishState(0, .backup_captured, .unbound);
    try engine.publishState(0, .published, .unbound);
    try root.removeFile(try root_fs.Path.init("etc/tool"));
    try writeExisting(root, "etc/tool", "one\n");
    try engine.publishState(0, .parent_synced, .unbound);
    try publishVerified(&engine, 0);
    try publishVerified(&engine, 1);
    try engine.publishState(2, .staged, .unbound);

    const replacement = try boundPrecondition(&engine, 1);
    const remodeled = switch (steps[1].expected) {
        .absent => return error.UnexpectedAbsence,
        .present => |state| state,
    };
    try testing.expect(replacement.inode != original.inode);
    {
        // On the published inode: its own name plus the staged link.
        const counts = reachableLinkCounts(&engine, steps[1], remodeled, replacement, .forward);
        try testing.expectEqual(@as(i128, 2), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
    }
    {
        // On the inode the plan found: its own name plus the backup the first
        // step captured, and nothing from a link that names another inode.
        const counts = reachableLinkCounts(&engine, steps[0], original, original_bound, .forward);
        try testing.expectEqual(@as(i128, 2), counts.lower);
        try testing.expectEqual(@as(i128, 2), counts.upper);
        try testing.expect(!linkCountReachable(
            &engine,
            steps[0],
            original,
            original_bound,
            3,
            .forward,
        ));
    }
}

test "root_mutation.test.a bound count already holds the links taken before it" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try root.createDirectoryPath(
        try root_fs.Path.init("etc/conf"),
        root_fs.default_directory_permissions,
    );

    // The subdirectory is created before the step that binds the parent's
    // identity, so the link it adds is already inside the count that boundary
    // observed. Counting it again would move the whole interval up by one and
    // admit an outside subdirectory as this transaction's own work.
    const intents = [_]Intent{
        directoryIntent("etc/conf/child"),
        directoryIntent("etc/conf"),
        .{ .metadata = .{ .path = "etc/conf", .mode = 0o700 } },
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    const steps = engine.journal().steps;
    const directory = switch (steps[2].expected) {
        .absent => return error.UnexpectedAbsence,
        .present => |state| state,
    };
    try engine.publishStage(.applying);
    try engine.publishState(0, .published, .unbound);
    try root.createDirectory(
        try root_fs.Path.init("etc/conf/child"),
        root_fs.default_directory_permissions,
    );
    try engine.publishState(0, .metadata_applied, .unbound);
    try engine.publishState(0, .parent_synced, .unbound);
    try publishVerified(&engine, 0);
    try engine.publishState(1, .published, .unbound);
    try engine.publishState(1, .metadata_applied, .unbound);
    try engine.publishState(1, .parent_synced, .unbound);
    try publishVerified(&engine, 1);

    const bound = try boundPrecondition(&engine, 2);
    try testing.expectEqual(@as(?u32, 1), bound.since);
    const observed = try root.entry(try root_fs.Path.init("etc/conf"));
    try testing.expectEqual(observed.link_count, bound.link_count);
    const counts = reachableLinkCounts(&engine, steps[2], directory, bound, .forward);
    try testing.expectEqual(bound.link_count, @as(u64, @intCast(counts.lower)));
    try testing.expectEqual(bound.link_count, @as(u64, @intCast(counts.upper)));
    // One more subdirectory than the plan accounts for is still refused, both
    // above the bound count and below it.
    try testing.expect(!linkCountReachable(
        &engine,
        steps[2],
        directory,
        bound,
        bound.link_count + 1,
        .forward,
    ));
    try testing.expect(!linkCountReachable(
        &engine,
        steps[2],
        directory,
        bound,
        bound.link_count - 1,
        .forward,
    ));
}

test "root_mutation.test.a link taken after the binding boundary widens the interval" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try root.createDirectoryPath(
        try root_fs.Path.init("etc/conf"),
        root_fs.default_directory_permissions,
    );

    // The same three steps in the order that binds the parent's identity
    // before the subdirectory exists. The link the subdirectory adds is then
    // outside the bound count and is added to it exactly once.
    const intents = [_]Intent{
        directoryIntent("etc/conf"),
        directoryIntent("etc/conf/child"),
        .{ .metadata = .{ .path = "etc/conf", .mode = 0o700 } },
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();

    const steps = engine.journal().steps;
    const directory = switch (steps[2].expected) {
        .absent => return error.UnexpectedAbsence,
        .present => |state| state,
    };
    try engine.publishStage(.applying);
    try engine.publishState(0, .published, .unbound);
    try engine.publishState(0, .metadata_applied, .unbound);
    try engine.publishState(0, .parent_synced, .unbound);
    try publishVerified(&engine, 0);
    const bound = try boundPrecondition(&engine, 2);
    try testing.expectEqual(@as(?u32, 0), bound.since);

    try engine.publishState(1, .published, .unbound);
    try root.createDirectory(
        try root_fs.Path.init("etc/conf/child"),
        root_fs.default_directory_permissions,
    );
    try engine.publishState(1, .metadata_applied, .unbound);
    try engine.publishState(1, .parent_synced, .unbound);
    try publishVerified(&engine, 1);

    const counts = reachableLinkCounts(&engine, steps[2], directory, bound, .forward);
    try testing.expectEqual(bound.link_count + 1, @as(u64, @intCast(counts.lower)));
    try testing.expectEqual(bound.link_count + 1, @as(u64, @intCast(counts.upper)));
    try testing.expect(linkCountReachable(
        &engine,
        steps[2],
        directory,
        bound,
        bound.link_count + 1,
        .forward,
    ));
    try testing.expect(!linkCountReachable(
        &engine,
        steps[2],
        directory,
        bound,
        bound.link_count + 2,
        .forward,
    ));
}

test "root_mutation.test.direct containment decides which links count" {
    try testing.expect(directChild("etc/conf/sub", "etc/conf"));
    try testing.expect(!directChild("etc/conf/sub/deeper", "etc/conf"));
    try testing.expect(!directChild("etc/conf", "etc/conf"));
    try testing.expect(!directChild("etc/confetti", "etc/conf"));
    try testing.expect(!directChild("etc/conf", "etc/conf/sub"));
    try testing.expect(!directChild("other/conf/sub", "etc/conf"));
    // No step targets the root itself, so the root is never a parent here.
    try testing.expect(!directChild("etc", ""));
}

// ---------------------------------------------------------------------------
// Several steps on one path
// ---------------------------------------------------------------------------

/// What the seeded same-path root held before the transaction, so a
/// restoration can be checked against the exact entries rather than against
/// their shape.
const SamePathSeed = struct {
    tool_inode: u64,
    tool_mode: u32,
    tool_modified: i128,
    directory_inode: u64,
    directory_mode: u32,
};

/// A regular file a plan republishes and then re-modes, and a populated
/// directory two steps of the same plan both ship - the shape every package
/// that owns a shared documentation directory produces.
fn seedSamePath(root: root_fs.Root) !SamePathSeed {
    try writeExisting(root, "etc/tool", "old\n");
    try root.createDirectoryPath(
        try root_fs.Path.init("usr/share/doc"),
        root_fs.default_directory_permissions,
    );
    try root.applyMetadata(try root_fs.Path.init("usr/share/doc"), .{ .mode = 0o700 });
    try writeExisting(root, "usr/share/doc/keep", "kept\n");
    const tool = try root.entry(try root_fs.Path.init("etc/tool"));
    const directory = try root.entry(try root_fs.Path.init("usr/share/doc"));
    return .{
        .tool_inode = tool.inode,
        .tool_mode = tool.mode,
        .tool_modified = tool.modified_nanoseconds,
        .directory_inode = directory.inode,
        .directory_mode = directory.mode,
    };
}

fn directoryIntentWithMode(path: []const u8, mode: u32) Intent {
    return .{ .directory = .{
        .path = path,
        .mode = mode,
        .uid = currentUid(),
        .gid = currentGid(),
    } };
}

/// Two steps on the file and two on the directory. Every later step's
/// recorded precondition is the earlier step's desired state, which carries
/// no inode of its own.
fn samePathIntents() [4]Intent {
    return .{
        fileIntent("etc/tool", "new\n"),
        .{ .metadata = .{
            .path = "etc/tool",
            .mode = 0o600,
            .modified_nanoseconds = 2_000_000_000,
        } },
        directoryIntentWithMode("usr/share/doc", 0o755),
        directoryIntentWithMode("usr/share/doc", 0o750),
    };
}

fn expectSamePathSeeded(root: root_fs.Root, seed: SamePathSeed) !void {
    try expectContent(root, "etc/tool", "old\n");
    const tool = try root.entry(try root_fs.Path.init("etc/tool"));
    // The backup is a hard link, so the restored file is the very inode the
    // transaction found, not a copy of it.
    try testing.expectEqual(seed.tool_inode, tool.inode);
    try testing.expectEqual(seed.tool_mode, tool.mode);
    try testing.expectEqual(seed.tool_modified, tool.modified_nanoseconds);
    const directory = try root.entry(try root_fs.Path.init("usr/share/doc"));
    try testing.expectEqual(seed.directory_inode, directory.inode);
    try testing.expectEqual(seed.directory_mode, directory.mode);
    try expectContent(root, "usr/share/doc/keep", "kept\n");
}

fn expectSamePathApplied(root: root_fs.Root, seed: SamePathSeed) !void {
    try expectContent(root, "etc/tool", "new\n");
    const tool = try root.entry(try root_fs.Path.init("etc/tool"));
    try testing.expectEqual(@as(u32, 0o600), tool.mode);
    try testing.expectEqual(@as(i128, 2_000_000_000), tool.modified_nanoseconds);
    const directory = try root.entry(try root_fs.Path.init("usr/share/doc"));
    // A repeated directory step re-modes the directory that is there; it
    // never replaces it and never empties it.
    try testing.expectEqual(seed.directory_inode, directory.inode);
    try testing.expectEqual(@as(u32, 0o750), directory.mode);
    try expectContent(root, "usr/share/doc/keep", "kept\n");
}

/// How an interrupted transaction is picked up: by pushing the same pass
/// forward, or by a fresh process resolving the journal it found.
const Resumption = enum { forward, restart };

fn runSamePathScenario(
    faults: []const Fault,
    resumption: Resumption,
    expectation: CrashExpectation,
) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    const seed = try seedSamePath(root);

    var injector: Injector = .{ .faults = faults };
    const intents = samePathIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    const outcome = apply(&crashed, .fromPlan(&plan));
    crashed.deinit();
    try testing.expectError(error.SimulatedCrash, outcome);
    try testing.expect(injector.allFired());

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    const report = switch (resumption) {
        .forward => try apply(&engine, .fromPlan(&plan)),
        .restart => try recover(&engine),
    };
    switch (expectation) {
        .new_state => {
            try testing.expectEqual(Outcome.applied, report.outcome);
            try expectSamePathApplied(root, seed);
        },
        .old_state => {
            try testing.expectEqual(Outcome.rolled_back, report.outcome);
            try expectSamePathSeeded(root, seed);
        },
    }
    try expectWorkspaceEmpty(root);
    try clear(&engine);
    try expectAbsent(root, journal_path);
}

test "root_mutation.test.a later step on one path resumes on the inode the earlier step bound" {
    // Every boundary the second step of each path passes through, including
    // each metadata syscall on its own. The state left between two of them is
    // neither the recorded precondition - which carries no inode at all - nor
    // the recorded desired state, so it is resolvable only against the entry
    // the earlier step's verified boundary bound.
    const points = [_]Fault{
        .{ .boundary = .precondition_check, .step = 1 },
        .{ .boundary = .metadata_apply, .step = 1 },
        .{ .boundary = .metadata_chmod, .step = 1 },
        .{ .boundary = .metadata_utimens, .step = 1 },
        .{ .boundary = .verify, .step = 1 },
        .{ .boundary = .precondition_check, .step = 3 },
        .{ .boundary = .metadata_apply, .step = 3 },
        .{ .boundary = .metadata_chmod, .step = 3 },
        .{ .boundary = .parent_sync, .step = 3 },
        .{ .boundary = .verify, .step = 3 },
    };
    for (points) |point| {
        const faults = [_]Fault{point};
        // A resumed forward pass finishes the transaction it was making.
        runSamePathScenario(&faults, .forward, .new_state) catch |err| {
            std.debug.print(
                "forward resume failed at {t} of step {?d}\n",
                .{ point.boundary, point.step },
            );
            return err;
        };
        // A fresh process restores the recorded old state instead, and gets
        // the same classification of the same half-finished work.
        runSamePathScenario(&faults, .restart, .old_state) catch |err| {
            std.debug.print(
                "restart rollback failed at {t} of step {?d}\n",
                .{ point.boundary, point.step },
            );
            return err;
        };
    }
}

test "root_mutation.test.an interrupted rollback of a same-path chain resumes" {
    // The first fault turns the transaction around, the second stops the
    // restoration part way through it. Recovery then resumes a rollback whose
    // remaining steps still have to classify what the forward pass and the
    // restoration each left on one path. Every stop names the restoration's
    // own arrival at the boundary, never the forward pass's.
    const stops = [_]Fault{
        .{ .boundary = .metadata_apply, .step = 3, .occurrence = 2 },
        .{ .boundary = .metadata_apply, .step = 2, .occurrence = 2 },
        .{ .boundary = .metadata_apply, .step = 1, .occurrence = 2 },
        .{ .boundary = .restore_rename, .step = 0 },
        .{ .boundary = .parent_sync, .step = 0, .occurrence = 2 },
    };
    for (stops) |stop| {
        const faults = [_]Fault{
            .{ .boundary = .verify, .step = 3, .err = error.RenameFailed },
            stop,
        };
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        const root = fixture.root();
        const seed = try seedSamePath(root);

        var injector: Injector = .{ .faults = &faults };
        const intents = samePathIntents();
        var plan = try planFor(&fixture, &intents);
        defer plan.deinit();
        var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
            .hooks = injector.interface(),
        });
        const outcome = apply(&crashed, .fromPlan(&plan));
        crashed.deinit();
        try testing.expectError(error.SimulatedCrash, outcome);
        testing.expect(injector.allFired()) catch |err| {
            std.debug.print("rollback stop at {t} never fired\n", .{stop.boundary});
            return err;
        };

        var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
        defer engine.deinit();
        try testing.expectEqual(Stage.rolling_back, engine.stage());
        const report = recover(&engine) catch |err| {
            std.debug.print("rollback resume failed after {t}\n", .{stop.boundary});
            return err;
        };
        testing.expectEqual(Outcome.rolled_back, report.outcome) catch |err| {
            std.debug.print(
                "rollback resume after {t}: {any}\n",
                .{ stop.boundary, report.diagnostic },
            );
            return err;
        };
        try expectSamePathSeeded(root, seed);
        try expectWorkspaceEmpty(root);
        try clear(&engine);
    }
}

test "root_mutation.test.a compatible repeated directory step is not work" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    const seed = try seedSamePath(root);

    // Two packages shipping the same documentation directory produce two
    // identical directory steps on one path. The second is satisfied by the
    // first's desired state and reaches its verified boundary without
    // touching the root, rather than being refused as a repeat.
    const intents = [_]Intent{
        directoryIntentWithMode("usr/share/doc", 0o755),
        directoryIntentWithMode("usr/share/doc", 0o755),
        directoryIntentWithMode("usr/share/doc/debz", 0o755),
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    const steps = plan.steps;
    try testing.expect(!steps[0].satisfied());
    try testing.expect(steps[1].satisfied());
    try testing.expectEqualSlices(StepState, &.{.verified}, steps[1].boundaries());

    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{});
    defer engine.deinit();
    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.applied, report.outcome);
    const directory = try root.entry(try root_fs.Path.init("usr/share/doc"));
    try testing.expectEqual(seed.directory_inode, directory.inode);
    try testing.expectEqual(@as(u32, 0o755), directory.mode);
    // The repeated step neither emptied the directory nor replaced it.
    try expectContent(root, "usr/share/doc/keep", "kept\n");
    const child = try root.entry(try root_fs.Path.init("usr/share/doc/debz"));
    try testing.expect(child.isDirectory());
    // The verified boundary of the satisfied step bound the same entry the
    // step before it published.
    try testing.expectEqual(directory.inode, engine.progress.identity(1).inode);
    try testing.expectEqual(directory.inode, engine.progress.identity(0).inode);
    try clear(&engine);
}

test "root_mutation.test.an external inode substitution is never resumed as this plan's own" {
    for ([_]Resumption{ .forward, .restart }) |resumption| {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        const root = fixture.root();
        _ = try seedSamePath(root);

        const intents = samePathIntents();
        var plan = try planFor(&fixture, &intents);
        defer plan.deinit();
        var injector: Injector = .{ .faults = &.{.{ .boundary = .metadata_chmod, .step = 1 }} };
        var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
            .hooks = injector.interface(),
        });
        try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
        crashed.deinit();

        // An outside writer replaces the published file with a different
        // inode of the same kind holding the same bytes, and copies the
        // metadata the step expects to find. Nothing about its shape says it
        // is not the entry the plan published; only the inode the verified
        // boundary bound does.
        const target = try root_fs.Path.init("etc/tool");
        const published = try root.entry(target);
        const substitute = try root_fs.Path.init("etc/tool.substitute");
        try root.writeNewFile(substitute, "new\n", .{}, true);
        try root.applyMetadata(substitute, .{ .mode = published.mode });
        try root.applyMetadata(substitute, .{
            .modified_nanoseconds = published.modified_nanoseconds,
        });
        try root.rename(substitute, target, .replace);
        const swapped = try root.entry(target);
        try testing.expect(swapped.inode != published.inode);

        var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
        defer engine.deinit();
        const report = switch (resumption) {
            .forward => try apply(&engine, .fromPlan(&plan)),
            .restart => try recover(&engine),
        };
        try testing.expectEqual(Outcome.recovery_required, report.outcome);
        try testing.expectEqual(Stage.recovery_required, engine.stage());
        // The substituted entry is left exactly as found: an unresolved
        // journal is never resolved by guessing.
        try testing.expectEqual(swapped.inode, (try root.entry(target)).inode);
        try testing.expectError(error.RecoveryRequired, clear(&engine));
    }
}

test "root_mutation.test.a restored directory is re-created on a new inode" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try root.createDirectoryPath(
        try root_fs.Path.init("etc"),
        root_fs.default_directory_permissions,
    );

    // The first step creates a directory, the second replaces it with a file.
    // Restoring the second re-creates the directory the first published,
    // which is provably a different inode from the one that step bound - and,
    // without a bound inode, could not be told from any empty directory an
    // outside writer happened to leave at the path. The restoration is
    // interrupted after the `mkdir`, so the resumed pass has to classify
    // exactly that re-created directory.
    const intents = [_]Intent{
        directoryIntentWithMode("etc/fresh", 0o755),
        fileIntent("etc/fresh", "newer\n"),
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var injector: Injector = .{ .faults = &.{
        .{ .boundary = .verify, .step = 1, .err = error.RenameFailed },
        .{ .boundary = .metadata_apply, .step = 1 },
    } };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    const outcome = apply(&crashed, .fromPlan(&plan));
    crashed.deinit();
    try testing.expectError(error.SimulatedCrash, outcome);
    try testing.expect(injector.allFired());

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    const restored = try root.entry(try root_fs.Path.init("etc/fresh"));
    const created = engine.progress.identity(0);
    try testing.expect(restored.isDirectory());
    try testing.expect(created.bound());
    try testing.expect(restored.inode != created.inode);

    const report = try recover(&engine);
    try testing.expectEqual(Outcome.rolled_back, report.outcome);
    try expectAbsent(root, "etc/fresh");
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

test "root_mutation.test.a step whose producer never verified is not restored over" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    const seed = try seedSamePath(root);

    // The producing step fails at its own verification, so the step after it
    // on the same path never ran and no boundary ever bound the entry its
    // precondition names. Its reversal is nothing at all, and the path is
    // restored by the producing step's own reversal.
    const intents = samePathIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var injector: Injector = .{ .faults = &.{
        .{ .boundary = .verify, .step = 0, .err = error.RenameFailed },
    } };
    var engine = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    defer engine.deinit();

    const report = try apply(&engine, .fromPlan(&plan));
    try testing.expectEqual(Outcome.rolled_back, report.outcome);
    try testing.expectEqual(Precondition.pending, precondition(&engine, engine.journal().steps[1]));
    try expectSamePathSeeded(root, seed);
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}

test "root_mutation.test.a platform that reports no inode keeps its structural comparison" {
    const old: State = .{
        .kind = .regular,
        .metadata = testMetadata(),
        .size = 1,
        .content_sha256 = @splat(0),
        .inode = 0,
        .link_count = 3,
    };
    // A precondition preflight could not attach an inode to compares zero to
    // zero, which is exactly the comparison a platform without inode numbers
    // has always had: it still refuses every entry whose inode is reported,
    // and it still admits the ordered metadata writes on the entry itself.
    const degenerate = comparableIdentity(.unreported, old, 7).?;
    try testing.expectEqual(@as(u64, 0), degenerate.inode);
    try testing.expectEqual(@as(u64, 7), degenerate.device);
    try testing.expectEqual(old.link_count, degenerate.link_count);
    try testing.expect(degenerate.since == null);

    // A precondition an earlier step of the plan owes and no boundary has
    // bound names no entry at all, and neither does an absence.
    try testing.expect(comparableIdentity(.pending, old, 7) == null);
    try testing.expect(comparableIdentity(.absent, old, 7) == null);

    // A bound precondition is passed through with the step that bound it.
    const bound = comparableIdentity(.{ .bound = .{
        .device = 7,
        .inode = 0x2a,
        .link_count = 1,
        .since = 4,
    } }, old, 7).?;
    try testing.expectEqual(@as(u64, 0x2a), bound.inode);
    try testing.expectEqual(@as(?u32, 4), bound.since);
}

// ---------------------------------------------------------------------------
// Torn, extra, and foreign progress records
// ---------------------------------------------------------------------------

/// Writes `bytes` straight past the end of the durable log, which is exactly
/// what a half-completed append leaves behind.
fn appendPastProgress(root: root_fs.Root, bytes: []const u8) !void {
    const path = try root_fs.Path.init(progress_path);
    const size = (try root.entry(path)).size;
    try root.appendAt(path, size, bytes, true);
}

fn progressSize(root: root_fs.Root) !u64 {
    return (try root.entry(try root_fs.Path.init(progress_path))).size;
}

/// The first `partial` bytes of a record that would have been valid, which is
/// the hardest torn tail to tell from a complete one.
fn tornRecordPrefix(buffer: *[progress_record_bytes]u8, partial: usize) []const u8 {
    const torn: ProgressRecord = .{
        .sequence = 0x5a5a,
        .scope = .journal,
        .index = ProgressRecord.no_index,
        .stage = .verified,
        .state = .prepared,
        .chain_sha256 = @splat(0xab),
    };
    return torn.encode(buffer)[0..partial];
}

fn runTornTailScenario(partial: usize, fault: Boundary, expectation: CrashExpectation) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var injector: Injector = .{ .faults = &.{.{ .boundary = fault }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();

    const durable = try progressSize(root);
    try testing.expectEqual(@as(u64, 0), durable % progress_record_bytes);
    var buffer: [progress_record_bytes]u8 = undefined;
    try appendPastProgress(root, tornRecordPrefix(&buffer, partial));
    try testing.expectEqual(durable + partial, try progressSize(root));

    // The torn tail is neither trusted nor fatal: replay stops at the last
    // complete record, the next append repairs the file, and recovery still
    // reaches a terminal stage.
    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(durable, engine.progress.accepted_bytes);
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
    const repaired = try progressSize(root);
    try testing.expect(repaired > durable);
    try testing.expectEqual(@as(u64, 0), repaired % progress_record_bytes);
    try expectWorkspaceEmpty(root);
    try testing.expectEqual(engine.stage(), (try inspect(testing.allocator, root, .{})).?);
    try clear(&engine);
    try expectAbsent(root, journal_path);
    try expectAbsent(root, progress_path);
}

test "root_mutation.test.a torn trailing progress record is repaired instead of wedging" {
    // Every length a half-completed append can leave, from one byte to one
    // byte short of a whole record.
    var partial: usize = 1;
    while (partial < progress_record_bytes) : (partial += 1) {
        runTornTailScenario(partial, .publish_rename, .old_state) catch |err| {
            std.debug.print("torn tail of {d} bytes failed\n", .{partial});
            return err;
        };
    }

    // The same repair on a transaction that already verified finishes forward
    // instead of undoing proven-good work.
    for ([_]usize{ 1, progress_record_bytes / 2, progress_record_bytes - 1 }) |length|
        try runTornTailScenario(length, .release_staging, .new_state);
}

test "root_mutation.test.a complete extra progress record is never repaired away" {
    var buffer: [progress_record_bytes]u8 = undefined;
    const cases = [_]struct { name: []const u8, extra: usize }{
        .{ .name = "one whole garbage record", .extra = progress_record_bytes },
        .{ .name = "a whole record and a torn one", .extra = progress_record_bytes + 7 },
        .{ .name = "two whole garbage records", .extra = 2 * progress_record_bytes },
    };
    for (cases) |case| {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        const root = fixture.root();
        try seedRoot(root);

        const intents = seedIntents();
        var plan = try planFor(&fixture, &intents);
        defer plan.deinit();
        var injector: Injector = .{ .faults = &.{.{ .boundary = .publish_rename }} };
        var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
            .hooks = injector.interface(),
        });
        try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
        crashed.deinit();

        var garbage: [3 * progress_record_bytes]u8 = @splat('z');
        try appendPastProgress(root, garbage[0..case.extra]);
        // A record-sized run of bytes is a complete record, so it is
        // corruption rather than a torn write, and the journal stays
        // unresolvable rather than being silently truncated.
        try testing.expectError(
            error.ProgressCorrupt,
            open(testing.allocator, root, &fixture.attempt, .{}),
        );
        try testing.expectError(
            error.ProgressCorrupt,
            inspect(testing.allocator, root, .{}),
        );
        try expectSeededState(root);
    }

    // A well-formed record that simply repeats the durable tail is a replay,
    // not a torn write.
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);
    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var injector: Injector = .{ .faults = &.{.{ .boundary = .publish_rename }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();

    const tail = try root.readTail(try root_fs.Path.init(progress_path), &buffer);
    try appendPastProgress(root, tail.bytes);
    try testing.expectError(
        error.ProgressCorrupt,
        open(testing.allocator, root, &fixture.attempt, .{}),
    );
}

test "root_mutation.test.a stale writer is refused even when the tail is torn" {
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

    // Another writer advanced the durable log and then lost power part way
    // through its own next append. The stale view holds neither the complete
    // record nor the torn one, so it is refused rather than repairing away a
    // boundary it never saw.
    var other = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer other.deinit();
    try other.publishStage(.applying);
    var buffer: [progress_record_bytes]u8 = undefined;
    try appendPastProgress(root, tornRecordPrefix(&buffer, 11));

    try testing.expectError(error.StaleWriter, engine.publishStage(.applying));
    try expectSeededState(root);

    // The writer that actually holds the durable tail repairs it and
    // continues.
    const report = try apply(&other, .fromPlan(&plan));
    try testing.expectEqual(Outcome.applied, report.outcome);
    try testing.expectEqual(@as(u64, 0), try progressSize(root) % progress_record_bytes);
    try expectAppliedState(root);
    try clear(&other);
}

test "root_mutation.test.a crash during the repair of a torn tail is itself safe" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();
    try seedRoot(root);

    const intents = seedIntents();
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();
    var injector: Injector = .{ .faults = &.{.{ .boundary = .publish_rename }} };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();

    const durable = try progressSize(root);
    var buffer: [progress_record_bytes]u8 = undefined;
    try appendPastProgress(root, tornRecordPrefix(&buffer, 40));

    // Power loss at the repair itself leaves the same torn tail, which the
    // next pass repairs again.
    var repairing: Injector = .{ .faults = &.{.{ .boundary = .progress_truncate }} };
    var interrupted = (try open(testing.allocator, root, &fixture.attempt, .{
        .hooks = repairing.interface(),
    })).?;
    try testing.expectError(error.SimulatedCrash, recover(&interrupted));
    interrupted.deinit();
    try testing.expect(repairing.allFired());
    try testing.expectEqual(durable + 40, try progressSize(root));

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(Outcome.rolled_back, (try recover(&engine)).outcome);
    try expectSeededState(root);
    try testing.expectEqual(@as(u64, 0), try progressSize(root) % progress_record_bytes);
    try clear(&engine);
}

test "root_mutation.test.a symbolic link re-created while restoring is finished, not refused" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const root = fixture.root();

    try root.createDirectoryPath(
        try root_fs.Path.init("etc"),
        root_fs.default_directory_permissions,
    );
    try root.createSymbolicLink(try root_fs.Path.init("etc/link"), "first");
    try root.applyMetadata(try root_fs.Path.init("etc/link"), .{
        .modified_nanoseconds = 3_000_000_000,
    });

    const intents = [_]Intent{
        symlinkIntent("etc/link", "second"),
        fileIntent("etc/other", "payload\n"),
    };
    var plan = try planFor(&fixture, &intents);
    defer plan.deinit();

    // Restoring a symbolic link is a fresh inode plus a timestamp write, so
    // power loss between them leaves the exact recorded target with a
    // timestamp that matches neither recorded state.
    var injector: Injector = .{ .faults = &.{
        .{ .boundary = .verify, .step = 1, .err = error.RenameFailed },
        .{ .boundary = .metadata_utimens, .step = 0, .occurrence = 2 },
    } };
    var crashed = try prepare(testing.allocator, root, &fixture.attempt, &plan, .{}, .{
        .hooks = injector.interface(),
    });
    try testing.expectError(error.SimulatedCrash, apply(&crashed, .fromPlan(&plan)));
    crashed.deinit();
    try testing.expect(injector.allFired());

    var buffer: [maximum_link_target_bytes]u8 = undefined;
    const interrupted = try root.entry(try root_fs.Path.init("etc/link"));
    try testing.expectEqualStrings(
        "first",
        try root.readSymbolicLink(try root_fs.Path.init("etc/link"), &buffer),
    );
    try testing.expect(interrupted.modified_nanoseconds != 3_000_000_000);

    var engine = (try open(testing.allocator, root, &fixture.attempt, .{})).?;
    defer engine.deinit();
    try testing.expectEqual(Outcome.rolled_back, (try recover(&engine)).outcome);
    const restored = try root.entry(try root_fs.Path.init("etc/link"));
    try testing.expectEqual(@as(i128, 3_000_000_000), restored.modified_nanoseconds);
    try testing.expectEqualStrings(
        "first",
        try root.readSymbolicLink(try root_fs.Path.init("etc/link"), &buffer),
    );
    try expectAbsent(root, "etc/other");
    try expectWorkspaceEmpty(root);
    try clear(&engine);
}
