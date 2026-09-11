//! Native unpack and file ownership for data-only package transactions.
//!
//! This implements roadmap item 10 of the native transaction engine. Its private
//! planner consumes a validated [`native_program.Program`], authenticated
//! archive bytes, one package-database snapshot, and read-only root
//! observations. It produces the exact immutable filesystem description and
//! [`package_database_changes.Plan`] for the payload and package information
//! files. Nothing is mutated while planning: every ownership
//! decision, path transition, alias rewrite, and deferred-feature refusal
//! happens before the first byte can change, and no `dpkg` or `dpkg-deb`
//! process is ever involved.
//!
//! The planner describes the supported data-only subset of `dpkg --unpack`:
//! bootstrap materialization and normal unpack, merged-`/usr` normalization, file
//! ownership and conflict resolution, `Replaces`, hard links, symbolic links,
//! modes, ownership, modification times, directory transitions, the package
//! `.list`, and `md5sums`. A private, isolated-root materialization adapter
//! composes the existing mutation engine for real-dpkg data, conffile, removal,
//! and lifecycle fixtures. The lifecycle interpreter consumes a compiled
//! native program, runs validated scripts in an isolated root, and retains
//! durable evidence for ambiguous outcomes. Its private trigger extension
//! models named/file interests, deferred queues, dynamic helper activation,
//! failures, and bounded cycle detection. The experimental Runtime exposes
//! caller-owned typed execution with mandatory helper isolation; fixture
//! adapters remain private and unsupported work never falls back to dpkg.

const std = @import("std");
const builtin = @import("builtin");
const absolute_path = @import("absolute_path.zig");
const archive_application = @import("archive_application.zig");
const control_record = @import("control_record.zig");
const dpkg_status = @import("dpkg_status.zig");
const exact_lock_v2 = @import("exact_lock_v2.zig");
const maintainer_script = @import("maintainer_script.zig");
const native_authorization = @import("native_authorization.zig");
const native_program = @import("native_program.zig");
const native_preparation = @import("native_preparation.zig");
const native_execution_request = @import("native_execution_request.zig");
const native_helper = @import("native_helper.zig");
const native_operation = @import("native_operation.zig");
const native_provenance = @import("native_provenance.zig");
const native_recovery = @import("native_recovery.zig");
const native_trigger = @import("native_trigger.zig");
const root_operation_completion = @import("root_operation_completion.zig");
const package_database = @import("package_database.zig");
const package_database_changes = @import("package_database_changes.zig");
const product_api = @import("product_api.zig");
const relation = @import("relation.zig");
const root_fs = @import("root_fs.zig");
const root_mutation = @import("root_mutation.zig");
const root_operation = @import("root_operation.zig");
const solver = @import("solver.zig");
const transaction_executor = @import("transaction_executor.zig");
const transaction_recovery = @import("transaction_recovery.zig");
const version_module = @import("debian_version.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

const ExecutionState = struct {
    recovery: ?*native_recovery.Runtime = null,
    action: ?native_recovery.Action = null,
    program_step: u32 = 0,
    phase_ordinal: u16 = 0,
    script_ordinal: u32 = 0,
    phase_steps: ?[]const root_mutation.Step = null,
};

fn nativeAction(
    kind: native_recovery.ActionKind,
    program_step: u32,
    substep: u16,
    ordinal: u32,
) native_recovery.Action {
    return .{
        .kind = kind,
        .program_step = program_step,
        .substep = substep,
        .ordinal = ordinal,
    };
}

fn recoveredActionApplied(execution: *ExecutionState) !bool {
    const runtime = execution.recovery orelse return false;
    const action = execution.action orelse return false;
    const record = try runtime.latest(action) orelse return false;
    return record.stage == .completed and
        (record.result == .applied or record.result == .succeeded or
            record.result == .recovered);
}

fn beginNativePhase(execution: *ExecutionState, kind: native_recovery.ActionKind) ?native_recovery.Action {
    if (execution.recovery == null) return null;
    const action = nativeAction(
        kind,
        execution.program_step,
        execution.phase_ordinal,
        0,
    );
    execution.phase_ordinal +%= 1;
    execution.action = action;
    return action;
}

fn beginNativeProgramStep(
    execution: *ExecutionState,
    step: native_program.Step,
) native_program.Operation {
    execution.program_step = step.sequence;
    execution.phase_ordinal = 0;
    execution.script_ordinal = 0;
    return step.operation;
}

fn checkpointManagedPaths(
    allocator: std.mem.Allocator,
    runtime: *native_recovery.Runtime,
    action: native_recovery.Action,
    steps: []const root_mutation.Step,
    transient: bool,
) !native_recovery.Digest {
    const paths = try allocator.alloc([]const u8, steps.len);
    defer allocator.free(paths);
    for (steps, 0..) |step, index| paths[index] = step.path;
    return native_recovery.updateManagedState(
        allocator,
        runtime.root,
        runtime.intent_sha256,
        action,
        paths,
        transient,
    );
}

const CombinedMutationHooks = struct {
    original: root_mutation.Hooks,
    runtime: ?*native_recovery.Runtime,
    action: ?native_recovery.Action,

    fn before(
        context: ?*anyopaque,
        boundary: root_mutation.Boundary,
        index: u32,
    ) root_mutation.HookError!void {
        const self: *CombinedMutationHooks = @ptrCast(@alignCast(context.?));
        if (self.original.beforeFn) |call|
            try call(self.original.context, boundary, index);
        const runtime = self.runtime orelse return;
        const action = self.action orelse return;
        const selected = runtime.crash.selected orelse return;
        const matches = switch (selected) {
            .during_filesystem_publication => action.kind == .filesystem,
            .during_database_publication => action.kind == .database,
            else => false,
        };
        if (matches and
            (boundary == .publish_rename or boundary == .publish_create))
            std.process.exit(native_recovery.crash_exit_code);
    }
};

pub const model_version: u32 = 1;

/// Domain separator of the deterministic unpack-plan digest. It never
/// collides with another debz digest over the same bytes.
pub const digest_domain = "debz.native-unpack.v1";

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// Every bound is explicit and every scan is linear or index-assisted, so a
/// hostile archive or database cannot turn planning into quadratic work.
pub const Limits = struct {
    max_packages: usize = 4096,
    max_artifacts: usize = 4096,
    max_paths_per_package: usize = 200_000,
    max_total_paths: usize = 2_000_000,
    max_removals: usize = 1_000_000,
    max_intents: usize = 2_000_000,
    max_archive_bytes: u64 = 8 * 1024 * 1024 * 1024,
    max_model_bytes: u64 = 16 * 1024 * 1024 * 1024,
    max_compare_bytes: usize = 512 * 1024 * 1024,
    max_compared_bytes: u64 = 2 * 1024 * 1024 * 1024,
    max_work: usize = 16_000_000,
    /// Bound on one descendant probe of the ownership index.
    max_descendant_scan: usize = 1_000_000,
    max_status_fields: usize = 256,
    max_deferred: usize = 512,
    max_case_aliases: usize = 100_000,
    max_case_index_bytes: usize = 64 * 1024 * 1024,
    max_trigger_index_bytes: usize = 64 * 1024 * 1024,
    archive: archive_application.Limits = .{},
    database: package_database.Options = .{},
    changes: package_database_changes.Limits = .{},
};

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

pub const Surface = enum {
    program,
    authorization,
    artifact,
    archive,
    database,
    ownership,
    alias,
    transition,
    lowering,
    publication,
};

pub const Code = enum {
    // Program and evidence binding. Every one of these is refused before a
    // filesystem change is described.
    schema_unsupported,
    backend_unsupported,
    authorization_mismatch,
    root_identity_mismatch,
    database_generation_mismatch,
    database_generation_drift,
    updates_pending,
    program_incomplete,
    artifact_missing,
    artifact_duplicate,
    artifact_unbound,
    artifact_mismatch,
    archive_binding_mismatch,
    package_mismatch,
    architecture_unknown,
    package_limit,
    deferred_limit,

    // Ownership.
    ownership_conflict,
    duplicate_claim,
    duplicate_archive_path,
    unowned_path_refused,
    multi_arch_content_mismatch,
    replaces_unsatisfied,
    invalid_replaces,
    forced_overwrite_unsupported,
    holder_state_unsupported,

    // Paths, aliases, and transitions.
    invalid_path,
    alias_escape,
    alias_kind_conflict,
    symbolic_link_ancestor,
    case_alias,
    directory_transition_unsafe,
    prefix_transition_unsafe,
    hard_link_target_missing,
    symlink_target_invalid,
    unsupported_entry,
    reserved_path,
    casefold_unknown,
    case_alias_limit,
    path_limit,

    // Publication.
    status_field_invalid,
    database_plan_rejected,
    root_unreadable,
    out_of_memory,
};

/// A typed refusal. Every slice references caller input, static text, or the
/// planning arena a `Refusal` keeps alive.
pub const Diagnostic = struct {
    surface: Surface,
    code: Code,
    /// Root-relative path, absolute database path, or database directory.
    path: []const u8 = "",
    package: []const u8 = "",
    architecture: []const u8 = "",
    /// Current owner of a contested path.
    holder: []const u8 = "",
    holder_architecture: []const u8 = "",
    database: ?package_database.Diagnostic = null,
};

// ---------------------------------------------------------------------------
// Deferred features
// ---------------------------------------------------------------------------

/// A capability this roadmap item deliberately does not implement. Detecting
/// one is a refusal before mutation plus an explicit handoff record, never a
/// silent approximation: a conffile in particular is never published as an
/// ordinary payload file.
pub const DeferredFeature = enum {
    maintainer_script,
    conffile,
    trigger,
    package_metadata,
    package_disappearance,
    diversion,
    stat_override,
    alternatives,
    database_surface,
    dpkg_interoperability,
    selection_change,
    config_version,
    package_removal,
    package_purge,
    conffile_decision,
    forced_overwrite,
    configure_barrier,
    unsupported_root_feature,

    pub fn spelling(self: DeferredFeature) []const u8 {
        return @tagName(self);
    }
};

pub const DeferredItem = struct {
    feature: DeferredFeature,
    package: []const u8 = "",
    architecture: []const u8 = "",
    /// Conffile path, trigger name, script name, or diverted path.
    detail: []const u8 = "",
};

/// The complete set of deferred features one refused transaction needs, so a
/// caller can route it to the lifecycle engine instead of rediscovering them.
pub const Handoff = struct {
    items: []const DeferredItem,
    /// Deterministic digest over the ordered handoff items.
    digest: [32]u8,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *Handoff) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn requires(self: Handoff, feature: DeferredFeature) bool {
        for (self.items) |item| {
            if (item.feature == feature) return true;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Merged-/usr aliases
// ---------------------------------------------------------------------------

/// Directories a merged-`/usr` root replaces with a symbolic link into
/// `/usr`. The table is fixed and ordered so normalization is deterministic
/// and never derived from archive content.
pub const alias_directories = [_][]const u8{
    "bin",
    "lib",
    "lib32",
    "lib64",
    "libo32",
    "libx32",
    "sbin",
};

/// One proven alias. `link_target` is the exact bytes the root holds, so the
/// evidence for the rewrite is recorded rather than assumed.
pub const Alias = struct {
    /// Root-relative alias directory, for example `lib`.
    from: []const u8,
    /// Root-relative canonical directory, for example `usr/lib`.
    to: []const u8,
    link_target: []const u8,
    device: u64,
    inode: u64,
    link_count: u64,
    modified_nanoseconds: i128,
    change_nanoseconds: i128,
};

/// Root evidence about every alias directory. An entry that exists but is not
/// the expected `usr/<name>` link is recorded as `foreign` so a payload that
/// would be written through it is refused instead of escaping the root.
pub const AliasEvidence = struct {
    aliases: []const Alias,
    /// Alias-table names the root holds as some other symbolic link.
    foreign: []const []const u8,

    pub fn find(self: AliasEvidence, component: []const u8) ?Alias {
        for (self.aliases) |alias| {
            if (std.mem.eql(u8, alias.from, component)) return alias;
        }
        return null;
    }

    pub fn foreignLink(self: AliasEvidence, component: []const u8) bool {
        for (self.foreign) |name| {
            if (std.mem.eql(u8, name, component)) return true;
        }
        return false;
    }
};

/// Observes the fixed alias table in one root. Only a symbolic link whose
/// stored target names exactly `usr/<name>` counts, in any of the three
/// spellings Debian roots use; everything else is either absent or foreign.
const AliasDetectionError = error{ OutOfMemory, RootUnreadable };

fn detectAliases(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
) AliasDetectionError!AliasEvidence {
    var aliases: std.ArrayList(Alias) = .empty;
    errdefer {
        for (aliases.items) |alias| {
            allocator.free(alias.to);
            allocator.free(alias.link_target);
        }
        aliases.deinit(allocator);
    }
    var foreign: std.ArrayList([]const u8) = .empty;
    errdefer foreign.deinit(allocator);

    for (alias_directories) |name| {
        const path = root_fs.Path.init(name) catch return error.RootUnreadable;
        var pinned = root.pinSymbolicLink(path) catch |err| switch (err) {
            error.FileNotFound, error.NotSymbolicLink => continue,
            else => return error.RootUnreadable,
        };
        defer pinned.close();
        var buffer: [root_fs.maximum_link_target_bytes]u8 = undefined;
        const observed = pinned.observe(&buffer) catch
            return error.RootUnreadable;
        const target = observed.target;
        const canonical = canonicalAliasTarget(target) orelse {
            try foreign.append(allocator, name);
            continue;
        };
        if (canonical.len <= 4 or !std.mem.startsWith(u8, canonical, "usr/") or
            !std.mem.eql(u8, canonical["usr/".len..], name))
        {
            try foreign.append(allocator, name);
            continue;
        }
        try aliases.ensureUnusedCapacity(allocator, 1);
        const to = try std.fmt.allocPrint(allocator, "usr/{s}", .{name});
        errdefer allocator.free(to);
        const link_target = try allocator.dupe(u8, target);
        errdefer allocator.free(link_target);
        aliases.appendAssumeCapacity(.{
            .from = name,
            .to = to,
            .link_target = link_target,
            .device = observed.entry.device,
            .inode = observed.entry.inode,
            .link_count = observed.entry.link_count,
            .modified_nanoseconds = observed.entry.modified_nanoseconds,
            .change_nanoseconds = observed.change_nanoseconds,
        });
    }
    const owned_aliases = try aliases.toOwnedSlice(allocator);
    errdefer {
        for (owned_aliases) |alias| {
            allocator.free(alias.to);
            allocator.free(alias.link_target);
        }
        allocator.free(owned_aliases);
    }
    const owned_foreign = try foreign.toOwnedSlice(allocator);
    return .{
        .aliases = owned_aliases,
        .foreign = owned_foreign,
    };
}

fn normalizeCapturedNativeArchitecture(
    snapshot: *package_database.Snapshot,
    architecture: []const u8,
) void {
    const entry = snapshot.arch orelse return;
    if (entry.kind != .regular or entry.bytes.len != architecture.len + 1)
        return;
    if (entry.bytes[entry.bytes.len - 1] != '\n' or
        !std.mem.eql(u8, entry.bytes[0..architecture.len], architecture))
        return;
    snapshot.arch = null;
}

/// `usr/lib`, `/usr/lib`, and `./usr/lib` are the three spellings a Debian
/// root uses for the same alias. Anything else, including a target that
/// traverses, is not an alias.
fn canonicalAliasTarget(target: []const u8) ?[]const u8 {
    var text = target;
    if (std.mem.startsWith(u8, text, "./")) text = text[2..];
    if (std.mem.startsWith(u8, text, "/")) text = text[1..];
    while (text.len != 0 and text[text.len - 1] == '/') text = text[0 .. text.len - 1];
    if (text.len == 0) return null;
    if (std.mem.indexOf(u8, text, "..") != null) return null;
    return text;
}

fn deinitAliasEvidence(
    allocator: std.mem.Allocator,
    evidence: AliasEvidence,
) void {
    for (evidence.aliases) |alias| {
        allocator.free(alias.to);
        allocator.free(alias.link_target);
    }
    allocator.free(evidence.aliases);
    allocator.free(evidence.foreign);
}

// ---------------------------------------------------------------------------
// Ownership index
// ---------------------------------------------------------------------------

/// One installed package that can own paths.
pub const Owner = struct {
    identity: package_database.Identity,
    record: *const package_database.PackageRecord,
};

/// One owned path of one installed package, in the canonical spelling the
/// filesystem actually uses plus the exact spelling the database published.
pub const OwnedEntry = struct {
    /// Root-relative canonical path, merged-`/usr` aliases already applied.
    path: []const u8,
    /// Absolute spelling `info/<stem>.list` holds, retained verbatim so a
    /// republished list and a diagnostic name what the database says.
    listed: []const u8,
    owner: u32,
    /// The canonical path differs from the listed spelling.
    aliased: bool,
};

fn lessOwnedEntry(_: void, left: OwnedEntry, right: OwnedEntry) bool {
    return switch (std.mem.order(u8, left.path, right.path)) {
        .lt => true,
        .gt => false,
        .eq => left.owner < right.owner,
    };
}

/// Sorted, index-assisted view of every path the consumed database
/// generation says is owned, in the canonical spelling the root uses.
///
/// Exact lookups are a binary search and descendant probes are a bounded
/// forward scan from a binary search, so no query is quadratic in the number
/// of installed paths, and no query silently truncates: every owner of a path
/// is contiguous in the sorted array and is returned as one slice.
pub const Ownership = struct {
    owners: []const Owner,
    entries: []const OwnedEntry,
    /// Entry indexes grouped by owner. `owned_by(owner)` answers what one
    /// package publishes without a pass over the whole root.
    by_owner: []const u32,
    /// Dense offsets into `by_owner`, one per owner plus a terminator.
    owner_offsets: []const u32,
    /// Canonical spellings this index had to allocate because an alias
    /// rewrote them.
    rewritten: []const []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Ownership) void {
        for (self.rewritten) |text| self.allocator.free(text);
        self.allocator.free(self.rewritten);
        self.allocator.free(self.owners);
        self.allocator.free(self.entries);
        self.allocator.free(self.by_owner);
        self.allocator.free(self.owner_offsets);
        self.* = undefined;
    }

    /// Every entry one owner publishes, in canonical path order.
    pub fn ownedBy(self: Ownership, owner: u32) []const u32 {
        if (owner + 1 >= self.owner_offsets.len) return &.{};
        return self.by_owner[self.owner_offsets[owner]..self.owner_offsets[owner + 1]];
    }

    fn lowerBound(self: Ownership, path: []const u8) usize {
        var low: usize = 0;
        var high: usize = self.entries.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (std.mem.order(u8, self.entries[middle].path, path) == .lt) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        return low;
    }

    /// Every entry that currently owns `path`, in stable owner order. The
    /// slice is complete: there is no probe buffer to overflow.
    pub fn ownersOf(self: Ownership, path: []const u8) []const OwnedEntry {
        const first = self.lowerBound(path);
        var last = first;
        while (last < self.entries.len and
            std.mem.eql(u8, self.entries[last].path, path)) : (last += 1)
        {}
        return self.entries[first..last];
    }

    pub fn owned(self: Ownership, path: []const u8) bool {
        return self.ownersOf(path).len != 0;
    }

    /// True when some package other than the excluded owners still owns a
    /// strict descendant of `path`. The scan is bounded; an overrun is
    /// reported so the caller fails closed instead of guessing.
    pub fn hasSurvivingDescendant(
        self: Ownership,
        path: []const u8,
        retiring: []const u32,
        budget: usize,
        prefix_buffer: []u8,
    ) error{ScanExhausted}!bool {
        const prefix = std.fmt.bufPrint(prefix_buffer, "{s}/", .{path}) catch
            return error.ScanExhausted;
        var index = self.lowerBound(prefix);
        var scanned: usize = 0;
        while (index < self.entries.len) : (index += 1) {
            const entry = self.entries[index];
            if (!std.mem.startsWith(u8, entry.path, prefix)) return false;
            scanned += 1;
            if (scanned > budget) return error.ScanExhausted;
            if (!containsOwner(retiring, entry.owner)) return true;
        }
        return false;
    }
};

fn containsOwner(list: []const u32, value: u32) bool {
    for (list) |item| {
        if (item == value) return true;
    }
    return false;
}

pub const OwnershipError = error{ OutOfMemory, AliasCollision };

/// Builds the ownership index of one imported generation.
///
/// Every published path is normalized through the same proven merged-`/usr`
/// aliases the payload is normalized through, so an installed package that
/// published `/lib/x` and a payload that ships `usr/lib/x` are recognized as
/// the same path instead of silently becoming two owners of one file. The
/// exact published spelling is retained beside the canonical one. `/.` is the
/// root itself, which no mutation ever targets, so it is not indexed.
///
/// Two spellings of one package that normalize onto the same canonical path
/// are a collision the caller must fail on: the database would claim one file
/// twice and its checksums could not both be true.
pub fn indexOwnership(
    allocator: std.mem.Allocator,
    model: package_database.Model,
    aliases: AliasEvidence,
) OwnershipError!Ownership {
    var owners = try allocator.alloc(Owner, model.packages.len);
    errdefer allocator.free(owners);
    var total: usize = 0;
    for (model.packages, 0..) |*record, index| {
        owners[index] = .{ .identity = record.identity(), .record = record };
        if (record.paths) |paths| total += paths.len;
    }

    var rewritten: std.ArrayList([]u8) = .empty;
    errdefer {
        for (rewritten.items) |text| allocator.free(text);
        rewritten.deinit(allocator);
    }
    var entries: std.ArrayList(OwnedEntry) = .empty;
    errdefer entries.deinit(allocator);
    try entries.ensureTotalCapacity(allocator, total);

    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);
    for (model.packages, 0..) |record, index| {
        const paths = record.paths orelse continue;
        seen.clearRetainingCapacity();
        for (paths) |listed| {
            const relative = relativeListPath(listed) orelse continue;
            const canonical = try canonicalOwnedPath(
                allocator,
                aliases,
                relative,
                &rewritten,
            );
            if ((try seen.getOrPut(allocator, canonical)).found_existing)
                return error.AliasCollision;
            entries.appendAssumeCapacity(.{
                .path = canonical,
                .listed = listed,
                .owner = @intCast(index),
                .aliased = canonical.ptr != relative.ptr,
            });
        }
    }
    const items = try entries.toOwnedSlice(allocator);
    errdefer allocator.free(items);
    std.mem.sort(OwnedEntry, items, {}, lessOwnedEntry);

    // One counting pass plus one placement pass groups every entry under its
    // owner, so answering "what does this package publish" never scans the
    // whole root.
    const offsets = try allocator.alloc(u32, model.packages.len + 1);
    errdefer allocator.free(offsets);
    @memset(offsets, 0);
    for (items) |entry| offsets[entry.owner + 1] += 1;
    for (1..offsets.len) |index| offsets[index] += offsets[index - 1];
    const grouped = try allocator.alloc(u32, items.len);
    errdefer allocator.free(grouped);
    var cursor = try allocator.alloc(u32, model.packages.len);
    defer allocator.free(cursor);
    @memcpy(cursor, offsets[0..model.packages.len]);
    for (items, 0..) |entry, index| {
        grouped[cursor[entry.owner]] = @intCast(index);
        cursor[entry.owner] += 1;
    }

    return .{
        .owners = owners,
        .entries = items,
        .by_owner = grouped,
        .owner_offsets = offsets,
        .rewritten = try rewritten.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

fn canonicalOwnedPath(
    allocator: std.mem.Allocator,
    aliases: AliasEvidence,
    relative: []const u8,
    rewritten: *std.ArrayList([]u8),
) std.mem.Allocator.Error![]const u8 {
    const first = std.mem.sliceTo(relative, '/');
    const alias = aliases.find(first) orelse return relative;
    const owned = try std.fmt.allocPrint(allocator, "{s}{s}", .{
        alias.to,
        relative[first.len..],
    });
    errdefer allocator.free(owned);
    try rewritten.append(allocator, owned);
    return owned;
}

fn canonicalAliasPath(
    aliases: AliasEvidence,
    relative: []const u8,
    buffer: []u8,
) ?[]const u8 {
    const first = std.mem.sliceTo(relative, '/');
    const alias = aliases.find(first) orelse return relative;
    return std.fmt.bufPrint(buffer, "{s}{s}", .{
        alias.to,
        relative[first.len..],
    }) catch null;
}

/// `/usr/bin/x` becomes `usr/bin/x`. The root spellings `/.` and `/` have no
/// relative form and return null.
pub fn relativeListPath(listed: []const u8) ?[]const u8 {
    const logical = package_database.logicalListPath(listed);
    if (logical.len < 2 or logical[0] != '/') return null;
    var text = logical[1..];
    while (text.len != 0 and text[text.len - 1] == '/') text = text[0 .. text.len - 1];
    if (text.len == 0) return null;
    return text;
}

// ---------------------------------------------------------------------------
// Plan model
// ---------------------------------------------------------------------------

pub const Operation = enum {
    /// No generation of the package is installed.
    install,
    /// An Essential payload materialized before the lifecycle can run.
    bootstrap,
    upgrade,
    downgrade,
    reinstall,
};

pub const Kind = enum { regular, directory, symlink, hardlink };

/// Why a claim on an already owned or already present path is allowed.
pub const Disposition = enum {
    /// Nothing was at the path.
    create,
    /// The path exists but no package owns it. dpkg replaces it.
    replace_unowned,
    /// An earlier generation of the same package identity owns it.
    replace_same_package,
    /// An exact `Replaces` on the current owner authorizes the claim.
    replace_replaces,
    /// Every installed owner retires this path in the same authorized
    /// transaction, so the final claimant may replace it without Replaces.
    replace_retired,
    /// A directory another package legitimately co-owns.
    share_directory,
    /// A `Multi-Arch: same` sibling owns identical content, metadata, and
    /// hard-link topology.
    share_multi_arch,
};

/// The exact root state a claim replaces, recorded for provenance and for the
/// transition rules.
pub const PreviousState = struct {
    kind: Kind,
    owned: bool,
    modeled: bool,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    device: u64,
    inode: u64,
    link_count: u64,
    modified_nanoseconds: i128,
    /// Inode status-change time paired with the content observation. It is
    /// present only when metadata and bytes/target came from one pinned inode.
    change_nanoseconds: ?i128 = null,
    content_sha256: ?[32]u8 = null,
    link_target: ?[]const u8 = null,
    /// Canonically sorted name/kind digest for a coherently pinned directory.
    directory_sha256: ?[32]u8 = null,
    directory_entries: ?u64 = null,
};

pub const PlannedPath = struct {
    /// Root-relative canonical path.
    path: []const u8,
    /// Absolute spelling published in `info/<stem>.list`.
    absolute: []const u8,
    /// Exact archive path before merged-`/usr` normalization.
    archive_path: []const u8,
    kind: Kind,
    mode: u32,
    uid: u32,
    gid: u32,
    /// Null only for a synthesized parent whose timestamp is deliberately
    /// unspecified.
    modified_nanoseconds: ?i128,
    /// Regular files, and the linked file of a hard link.
    sha256: ?[32]u8 = null,
    md5: ?[16]u8 = null,
    /// Symbolic links only: the exact bytes published.
    link_literal: ?[]const u8 = null,
    /// Hard links only: root-relative path of the linked regular file.
    link_source: ?[]const u8 = null,
    /// Existing source evidence captured by the same combined pinned
    /// observation as `previous` when an installed hard-link group is shared.
    link_source_previous: ?PreviousState = null,
    /// Index of the archive payload entry this path publishes, or null for a
    /// synthesized parent directory.
    archive_entry: ?usize = null,
    /// Index into `Plan.packages`.
    package: u32,
    disposition: Disposition,
    previous: ?PreviousState = null,
    /// The path was rewritten by a proven merged-`/usr` alias.
    aliased: bool = false,
    /// A parent directory the payload does not ship and the root lacks.
    synthesized: bool = false,
    /// False when the plan only updates ownership and must leave the existing
    /// root object and its metadata untouched.
    publish: bool = true,
};

pub const Removal = struct {
    path: []const u8,
    absolute: []const u8,
    directory: bool,
    package: u32,
    previous: PreviousState,
};

/// A real directory retained because a final descendant still requires it.
/// It is evidence only and never a metadata write.
pub const RetainedDirectory = struct {
    path: []const u8,
    previous: PreviousState,
};

/// Ordered, descriptive filesystem work. It carries no root handle, writer,
/// journal, or execution callback.
pub const FilesystemChange = union(enum) {
    remove: Removal,
    directory: MetadataChange,
    file: FileChange,
    symlink: SymlinkChange,
    hardlink: HardlinkChange,

    pub const MetadataChange = struct {
        path: []const u8,
        mode: u32,
        uid: u32,
        gid: u32,
        /// Archive timestamp for a real published directory; null for a
        /// synthesized parent.
        modified_nanoseconds: ?i128,
    };

    pub const FileChange = struct {
        path: []const u8,
        artifact: u32,
        archive_entry: u32,
        sha256: [32]u8,
        mode: u32,
        uid: u32,
        gid: u32,
        modified_nanoseconds: i128,
    };

    pub const SymlinkChange = struct {
        path: []const u8,
        target: []const u8,
        uid: u32,
        gid: u32,
        modified_nanoseconds: i128,
    };

    pub const HardlinkChange = struct {
        path: []const u8,
        source: []const u8,
    };
};

/// One resolved ownership claim, in the exact shape the compiled program
/// asserts it in.
pub const Resolution = struct {
    path: []const u8,
    holder: package_database.Identity,
    claimant: package_database.Identity,
    resolution: native_program.OwnershipResolution,
};

/// Ownership removed from a still-installed package by an exact Replaces.
pub const Displacement = struct {
    path: []const u8,
    holder: package_database.Identity,
    holder_index: u32,
    claimant: package_database.Identity,
};

/// Two paths that differ only by ASCII case. Such ambiguity is refused until
/// target-filesystem case semantics can be authenticated.
pub const CaseAlias = struct {
    first: []const u8,
    second: []const u8,
};

pub const PlannedConffile = struct {
    /// Canonical root-relative live path.
    path: []const u8,
    /// Physical package staging path used during unpack, when shipped.
    staged_path: ?[]const u8 = null,
    action: native_program.ConffileAction,
    packaged_md5: ?[16]u8 = null,
    recorded: ?package_database.ConffileEntry = null,
};

pub const PackagePlan = struct {
    identity: native_program.PackageIdentity,
    /// `name` or `name:architecture`, exactly as `info` spells it.
    stem: []const u8,
    artifact: u32,
    operation: Operation,
    /// The payload was materialized by an Essential bootstrap step.
    bootstrapped: bool,
    prior_version: ?[]const u8 = null,
    /// Version most recently configured before this unpack, preserved as
    /// dpkg's `Config-Version` while the new package is merely unpacked.
    configured_version: ?[]const u8 = null,
    application_sha256: [32]u8,
    paths: []const PlannedPath,
    removals: []const Removal,
    /// Canonical `.list` content, sorted, with dpkg's `/.` root record.
    list_paths: []const []const u8,
    md5sums: []const package_database.Md5sumEntry,
    conffiles: []const PlannedConffile = &.{},
    resolutions: []const Resolution,
    /// Status the transaction publishes. Item 10 leaves every package where
    /// `dpkg --unpack` leaves it.
    state: dpkg_status.CurrentState,
};

/// A complete, validated, pre-mutation unpack plan.
///
/// `filesystem` is one ordered, immutable description: obsolete removals
/// deepest first, directories parents first, then payload content in archive
/// order. `database` is the separately staged final package-database change.
/// No field can execute either half.
pub const Plan = struct {
    filesystem: []const FilesystemChange,
    database: package_database_changes.Plan,
    packages: []const PackagePlan,
    aliases: []const Alias,
    case_aliases: []const CaseAlias,
    displacements: []const Displacement,
    retained_directories: []const RetainedDirectory,
    /// Packages that still require configuration by the lifecycle engine.
    pending_configuration: []const native_program.PackageRef,
    program_sha256: [32]u8,
    authorization_sha256: [32]u8,
    /// Limit telemetry. These counters are not authoritative plan semantics
    /// and are deliberately excluded from `digest`.
    path_count: usize,
    model_bytes: u64,
    compared_bytes: u64,
    work_units: usize,
    /// Deterministic digest over semantic plan fields only.
    digest: [32]u8,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *Plan) void {
        self.database.deinit();
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn findPackage(self: Plan, name: []const u8, architecture: []const u8) ?*const PackagePlan {
        for (self.packages) |*item| {
            if (std.mem.eql(u8, item.identity.name, name) and
                std.mem.eql(u8, item.identity.architecture, architecture)) return item;
        }
        return null;
    }
};

/// A typed refusal plus the arena that owns the text it names.
///
/// Planning can name a path that exists nowhere else: a merged-`/usr` rewrite
/// produces a spelling neither the archive nor the database contains. The
/// refusal therefore keeps that memory alive instead of handing back a slice
/// into a released arena.
pub const Refusal = struct {
    diagnostic: Diagnostic,
    digest: [32]u8,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *Refusal) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const Result = union(enum) {
    plan: Plan,
    /// The transaction needs a capability a later roadmap item owns.
    handoff: Handoff,
    refusal: Refusal,
};

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// One artifact the program names plus its exact authenticated bytes.
///
/// The private planner always rebuilds the archive model from these bytes;
/// callers cannot supply a stale or edited inventory.
pub const ArchiveInput = struct {
    artifact: u32,
    bytes: []const u8,
};

pub const UnownedPolicy = enum {
    /// dpkg's behavior: a path no package owns is replaced.
    replace,
    /// Fail closed instead, for roots that must never lose foreign state.
    refuse,
};

/// Whether another package manager may observe the root between this item and
/// the later recovery/lifecycle integration.
pub const Interoperability = enum {
    shared_root,
    isolated_root,
};

const Request = struct {
    program: *const native_program.Program,
    /// Reviewed authorization the program must have been compiled for.
    authorization: ?*const native_authorization.Authorization = null,
    /// Complete immutable package-database bytes. The planner imports and
    /// validates them itself rather than accepting a caller-built model.
    snapshot: package_database.Snapshot,
    archives: []const ArchiveInput,
    root: root_fs.Root,
    /// Root identity digest the program is bound to.
    root_identity_sha256: ?[32]u8 = null,
    unowned: UnownedPolicy = .replace,
    interoperability: Interoperability = .shared_root,
    /// Names found under `var/lib/dpkg` that the importer does not model.
    unmodeled_database_entries: []const []const u8 = &.{},
    /// Paths whose filesystem metadata/features the descriptive snapshot
    /// cannot reproduce safely.
    unsupported_root_features: []const []const u8 = &.{},
    conffiles: ConffileCapability = .handoff,
    conffile_policy: transaction_executor.ConffilePolicy = .keep_existing,
    /// Private lifecycle execution may interpret one compiled data step at a
    /// time while retaining the complete parent program as authority.
    lifecycle_execution: bool = false,
    trigger_execution: bool = false,
    lifecycle_sequences: []const u32 = &.{},
    limits: Limits = .{},
};

const ConffileCapability = enum {
    handoff,
    unpack,
};

// ---------------------------------------------------------------------------
// Planner
// ---------------------------------------------------------------------------

const Md5 = std.crypto.hash.Md5;

const PlanError = error{ Rejected, Deferred, OutOfMemory };

/// One archive entry after merged-`/usr` normalization, before ownership is
/// resolved. Claims are the only thing the ownership rules ever look at.
const Claim = struct {
    path: []const u8,
    archive_path: []const u8,
    kind: Kind,
    file: usize,
    aliased: bool,
};

const PackageWork = struct {
    identity: native_program.PackageIdentity,
    stem: []const u8,
    artifact: u32,
    archive: usize,
    model: *const archive_application.Model,
    application_sha256: [32]u8,
    operation: Operation,
    bootstrapped: bool,
    /// Earliest authorized program step that introduces this package. This
    /// selects the physical publisher when otherwise-compatible claims share
    /// a path; canonical package sorting must not erase unpack order.
    sequence: u32,
    prior: ?*const package_database.PackageRecord,
    prior_version: ?[]const u8,
    configured_version: ?[]const u8,
    owner_index: ?u32,
    replaces: std.StringHashMapUnmanaged(
        std.ArrayListUnmanaged(ReplacementRule),
    ) = .empty,
    file_index: std.StringHashMapUnmanaged(usize) = .empty,
    effective_files: []?EffectiveFile = &.{},
    hardlink_group_digests: std.AutoHashMapUnmanaged(usize, [32]u8) = .empty,
    claims: []Claim,
    paths: std.ArrayList(PlannedPath) = .empty,
    removals: std.ArrayList(Removal) = .empty,
    resolutions: std.ArrayList(Resolution) = .empty,
    list_paths: std.ArrayList([]const u8) = .empty,
    md5sums: std.ArrayList(package_database.Md5sumEntry) = .empty,
    conffiles: std.ArrayList(PlannedConffile) = .empty,
    conffile_records: std.ArrayList(package_database.ConffileEntry) = .empty,
    declared_conffiles: std.ArrayList([]const u8) = .empty,
};

const ReplacementRule = struct {
    architecture: ?[]const u8,
    version: ?relation.VersionConstraint,
};

const TransactionClaim = struct {
    package: u32,
    sequence: u32,
    name: []const u8,
    architecture: []const u8,
    multi_arch_same: bool,
    kind: Kind,
    sha256: ?[32]u8,
    link_target: ?[]const u8,
    /// Canonical regular-file source for a hard-link claim.
    link_source: ?[]const u8,
    /// Canonical source identifying the complete hard-link group, present for
    /// both its regular source and every linked member.
    hardlink_group: ?[]const u8,
    hardlink_group_size: u64,
    hardlink_group_digest: ?[32]u8,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_nanoseconds: i128,
};

const TransactionClaims = struct {
    representative: TransactionClaim,
    publisher: TransactionClaim,
    count: usize,
    by_package: std.AutoHashMapUnmanaged(u32, TransactionClaim) = .empty,
    directory_groups: std.StringHashMapUnmanaged(TransactionClaim) = .empty,
};

const PrefixRequirement = struct {
    kind: Kind = .directory,
    descendants: usize = 0,
};

const FoldedPath = struct {
    spelling: []const u8,
    kind: ?Kind,
    requires_directory: bool,
};

/// Exact live-allocation budget used only for rebuilt archive models and
/// their path/effective-content indexes. Because archive parsing receives
/// this allocator directly, decompression, control ASTs, provenance, array
/// capacities, strings, and indexes are bounded while they are constructed,
/// rather than estimated after an unbounded build.
const ModelAllocator = struct {
    backing: std.mem.Allocator,
    limit: u64,
    live: u64 = 0,
    peak: u64 = 0,
    exhausted: bool = false,

    fn init(backing: std.mem.Allocator, limit: u64) ModelAllocator {
        return .{ .backing = backing, .limit = limit };
    }

    fn allocator(self: *ModelAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn allowGrowth(self: *ModelAllocator, amount: usize) bool {
        const next = std.math.add(u64, self.live, amount) catch {
            self.exhausted = true;
            return false;
        };
        if (next > self.limit) {
            self.exhausted = true;
            return false;
        }
        return true;
    }

    fn recordResize(self: *ModelAllocator, old_len: usize, new_len: usize) void {
        if (new_len >= old_len) {
            self.live += new_len - old_len;
            self.peak = @max(self.peak, self.live);
        } else {
            self.live -= old_len - new_len;
        }
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *ModelAllocator = @ptrCast(@alignCast(context));
        if (!self.allowGrowth(len)) return null;
        const result = self.backing.rawAlloc(len, alignment, return_address) orelse
            return null;
        self.recordResize(0, len);
        return result;
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *ModelAllocator = @ptrCast(@alignCast(context));
        if (new_len > memory.len and !self.allowGrowth(new_len - memory.len))
            return false;
        if (!self.backing.rawResize(
            memory,
            alignment,
            new_len,
            return_address,
        )) return false;
        self.recordResize(memory.len, new_len);
        return true;
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const self: *ModelAllocator = @ptrCast(@alignCast(context));
        if (new_len > memory.len and !self.allowGrowth(new_len - memory.len))
            return null;
        const result = self.backing.rawRemap(
            memory,
            alignment,
            new_len,
            return_address,
        ) orelse return null;
        self.recordResize(memory.len, new_len);
        return result;
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *ModelAllocator = @ptrCast(@alignCast(context));
        self.backing.rawFree(memory, alignment, return_address);
        self.live -= memory.len;
    }
};

const Builder = struct {
    allocator: std.mem.Allocator,
    model_allocator: ModelAllocator,
    arena: std.mem.Allocator,
    request: Request,
    limits: Limits,
    database: *const package_database.Database,
    ownership: Ownership,
    aliases: AliasEvidence,
    models: std.ArrayList(*archive_application.Model) = .empty,
    deferred: std.ArrayList(DeferredItem) = .empty,
    work: std.ArrayList(PackageWork) = .empty,
    /// Root-relative path claimed by this transaction to the package that
    /// claimed it, so a second claim on the same non-directory path is caught
    /// in one lookup instead of a scan.
    claimed: std.StringHashMapUnmanaged(u32) = .empty,
    transaction_claims: std.StringHashMapUnmanaged(TransactionClaims) = .empty,
    /// Every strict ancestor of a final transaction claim. Obsolete
    /// directories in this set survive so a later child publication never
    /// loses the parent it was planned beneath.
    final_claim_ancestors: std.StringHashMapUnmanaged(PrefixRequirement) = .empty,
    owner_work: std.AutoHashMapUnmanaged(u32, u32) = .empty,
    /// Installed owners that lose at least one path to an exact Replaces.
    displaced: std.AutoHashMapUnmanaged(u32, void) = .empty,
    displaced_paths: std.StringHashMapUnmanaged(void) = .empty,
    displacements: std.ArrayList(Displacement) = .empty,
    retained_directories: std.ArrayList(RetainedDirectory) = .empty,
    retained_directory_paths: std.StringHashMapUnmanaged(void) = .empty,
    directory_observations: std.StringHashMapUnmanaged(PreviousState) = .empty,
    /// Case-folded key to the first spelling that used it.
    folded: std.StringHashMapUnmanaged(FoldedPath) = .empty,
    folded_keys: std.ArrayList([]u8) = .empty,
    case_index_bytes: usize = 0,
    trigger_index_bytes: usize = 0,
    case_aliases: std.ArrayList(CaseAlias) = .empty,
    published: std.StringHashMapUnmanaged(Kind) = .empty,
    planned_removals: std.StringHashMapUnmanaged(Kind) = .empty,
    installed_conffiles: std.StringHashMapUnmanaged(
        std.ArrayListUnmanaged(package_database.Identity),
    ) = .empty,
    /// One lazily built checksum index per installed Multi-Arch owner.
    checksums: std.AutoHashMapUnmanaged(
        u32,
        std.StringHashMapUnmanaged([16]u8),
    ) = .empty,
    diagnostic: ?Diagnostic = null,
    total_paths: usize = 0,
    intent_count: usize = 0,
    removal_count: usize = 0,
    work_units: usize = 0,
    compared_bytes: u64 = 0,
    /// Entries every directory-transition probe has scanned so far. One
    /// shared budget keeps the whole transaction linear even when a hostile
    /// payload asks for a transition on every path it ships.
    transition_scans: usize = 0,

    fn deinit(self: *Builder) void {
        for (self.work.items) |*item| {
            var replacement_lists = item.replaces.valueIterator();
            while (replacement_lists.next()) |list| list.deinit(self.allocator);
            item.replaces.deinit(self.allocator);
            item.file_index.deinit(self.model_allocator.allocator());
            item.hardlink_group_digests.deinit(
                self.model_allocator.allocator(),
            );
            if (item.effective_files.len != 0)
                self.model_allocator.allocator().free(item.effective_files);
            item.paths.deinit(self.allocator);
            item.removals.deinit(self.allocator);
            item.resolutions.deinit(self.allocator);
            item.list_paths.deinit(self.allocator);
            item.md5sums.deinit(self.allocator);
            item.conffiles.deinit(self.allocator);
            item.conffile_records.deinit(self.allocator);
            item.declared_conffiles.deinit(self.allocator);
        }
        self.work.deinit(self.allocator);
        for (self.models.items) |model| {
            model.deinit();
            self.model_allocator.allocator().destroy(model);
        }
        self.models.deinit(self.allocator);
        self.deferred.deinit(self.allocator);
        self.claimed.deinit(self.allocator);
        var claims = self.transaction_claims.valueIterator();
        while (claims.next()) |items| {
            items.by_package.deinit(self.allocator);
            items.directory_groups.deinit(self.allocator);
        }
        self.transaction_claims.deinit(self.allocator);
        self.final_claim_ancestors.deinit(self.allocator);
        self.owner_work.deinit(self.allocator);
        self.displaced.deinit(self.allocator);
        self.displaced_paths.deinit(self.allocator);
        self.displacements.deinit(self.allocator);
        self.retained_directories.deinit(self.allocator);
        self.retained_directory_paths.deinit(self.allocator);
        self.directory_observations.deinit(self.allocator);
        self.folded.deinit(self.allocator);
        for (self.folded_keys.items) |key| self.allocator.free(key);
        self.folded_keys.deinit(self.allocator);
        self.case_aliases.deinit(self.allocator);
        self.published.deinit(self.allocator);
        self.planned_removals.deinit(self.allocator);
        var conffiles = self.installed_conffiles.valueIterator();
        while (conffiles.next()) |owners| owners.deinit(self.allocator);
        self.installed_conffiles.deinit(self.allocator);
        var checksum_maps = self.checksums.valueIterator();
        while (checksum_maps.next()) |map| map.deinit(self.allocator);
        self.checksums.deinit(self.allocator);
        std.debug.assert(self.model_allocator.live == 0);
    }

    fn fail(self: *Builder, diagnostic: Diagnostic) error{Rejected} {
        self.diagnostic = diagnostic;
        return error.Rejected;
    }

    fn chargeWork(self: *Builder, amount: usize, diagnostic: Diagnostic) PlanError!void {
        self.work_units = std.math.add(usize, self.work_units, amount) catch
            return self.fail(diagnostic);
        if (self.work_units > self.limits.max_work) return self.fail(diagnostic);
    }

    fn chargePath(self: *Builder, diagnostic: Diagnostic) PlanError!void {
        self.total_paths = std.math.add(usize, self.total_paths, 1) catch
            return self.fail(diagnostic);
        if (self.total_paths > self.limits.max_total_paths)
            return self.fail(diagnostic);
        try self.chargeWork(1, diagnostic);
    }

    fn chargeIntent(self: *Builder, diagnostic: Diagnostic) PlanError!void {
        self.intent_count = std.math.add(usize, self.intent_count, 1) catch
            return self.fail(diagnostic);
        if (self.intent_count > self.limits.max_intents)
            return self.fail(diagnostic);
    }

    fn deferFeature(self: *Builder, item: DeferredItem) PlanError!void {
        for (self.deferred.items) |existing| {
            if (existing.feature == item.feature and
                std.mem.eql(u8, existing.package, item.package) and
                std.mem.eql(u8, existing.architecture, item.architecture) and
                std.mem.eql(u8, existing.detail, item.detail)) return;
        }
        if (self.deferred.items.len >= self.limits.max_deferred)
            return self.fail(.{
                .surface = .program,
                .code = .deferred_limit,
                .package = item.package,
                .architecture = item.architecture,
                .path = item.detail,
            });
        try self.deferred.append(self.allocator, item);
    }

    fn modelAllocationFailure(self: *Builder, diagnostic: Diagnostic) PlanError {
        if (self.model_allocator.exhausted) return self.fail(diagnostic);
        return error.OutOfMemory;
    }

    fn chargeTriggerIndex(
        self: *Builder,
        amount: usize,
        diagnostic: Diagnostic,
    ) PlanError!void {
        self.trigger_index_bytes = std.math.add(
            usize,
            self.trigger_index_bytes,
            amount,
        ) catch return self.fail(diagnostic);
        if (self.trigger_index_bytes > self.limits.max_trigger_index_bytes)
            return self.fail(diagnostic);
    }
};

/// Builds one descriptive data-only plan from a validated program, raw
/// archives, an imported database snapshot, and read-only root observations.
///
/// Nothing here touches the root except to read it. Every refusal is typed
/// and happens before the caller can begin a mutation.
fn plan(allocator: std.mem.Allocator, request: Request) std.mem.Allocator.Error!Result {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = .init(allocator);
    errdefer {
        arena.deinit();
        allocator.destroy(arena);
    }

    if (try preflightRequest(arena.allocator(), request)) |diagnostic| {
        const owned = try ownDiagnostic(arena.allocator(), diagnostic);
        return refusalResult(arena, allocator, owned);
    }

    const aliases = detectAliases(allocator, request.root) catch |err| switch (err) {
        error.OutOfMemory => return outOfMemory(arena, allocator),
        error.RootUnreadable => return refusalResult(arena, allocator, .{
            .surface = .alias,
            .code = .root_unreadable,
        }),
    };
    defer deinitAliasEvidence(allocator, aliases);

    var imported = switch (package_database.importSnapshot(allocator, .{
        .native_architecture = request.program.target_architecture,
        .snapshot = request.snapshot,
    }, request.limits.database) catch return outOfMemory(arena, allocator)) {
        .database => |value| value,
        .diagnostic => |diagnostic| {
            if (diagnostic.code == .out_of_memory)
                return outOfMemory(arena, allocator);
            return refusalResult(arena, allocator, .{
                .surface = .database,
                .code = .database_generation_drift,
                .path = package_database.database_directory,
            });
        },
    };
    defer imported.deinit();

    var ownership = indexOwnership(allocator, imported.model, aliases) catch |err| switch (err) {
        error.OutOfMemory => return outOfMemory(arena, allocator),
        error.AliasCollision => return refusalResult(arena, allocator, .{
            .surface = .alias,
            .code = .duplicate_archive_path,
            .path = package_database.database_directory,
        }),
    };
    defer ownership.deinit();

    var builder: Builder = .{
        .allocator = allocator,
        .model_allocator = .init(allocator, request.limits.max_model_bytes),
        .arena = arena.allocator(),
        .request = request,
        .limits = request.limits,
        .database = &imported,
        .ownership = ownership,
        .aliases = aliases,
    };
    defer builder.deinit();

    const outcome = run(&builder, arena) catch |err| switch (err) {
        error.OutOfMemory => return outOfMemory(arena, allocator),
        error.Rejected => {
            const diagnostic = ownDiagnostic(
                arena.allocator(),
                builder.diagnostic.?,
            ) catch return outOfMemory(arena, allocator);
            return refusalResult(arena, allocator, diagnostic);
        },
        error.Deferred => {
            const handoff = buildHandoff(allocator, builder.deferred.items) catch
                return outOfMemory(arena, allocator);
            arena.deinit();
            allocator.destroy(arena);
            return .{ .handoff = handoff };
        },
    };
    return .{ .plan = outcome };
}

fn preflightRequest(
    allocator: std.mem.Allocator,
    request: Request,
) std.mem.Allocator.Error!?Diagnostic {
    if (request.program.artifacts.len > request.limits.max_artifacts or
        request.archives.len > request.limits.max_artifacts)
        return .{ .surface = .artifact, .code = .artifact_mismatch };

    var artifact_ids: std.AutoHashMapUnmanaged(u32, void) = .empty;
    defer artifact_ids.deinit(allocator);
    var packages: std.StringHashMapUnmanaged(void) = .empty;
    defer packages.deinit(allocator);
    for (request.program.artifacts) |artifact| {
        if ((try artifact_ids.getOrPut(allocator, artifact.index)).found_existing)
            return .{
                .surface = .artifact,
                .code = .artifact_duplicate,
                .package = artifact.package.name,
                .architecture = artifact.package.architecture,
            };
        const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{
            artifact.package.name,
            artifact.package.architecture,
        });
        _ = try packages.getOrPut(allocator, key);
        if (packages.count() > request.limits.max_packages)
            return .{ .surface = .program, .code = .package_limit };
    }

    artifact_ids.clearRetainingCapacity();
    var archive_bytes: u64 = 0;
    for (request.archives) |archive| {
        if ((try artifact_ids.getOrPut(allocator, archive.artifact)).found_existing)
            return .{ .surface = .artifact, .code = .artifact_duplicate };
        archive_bytes = std.math.add(u64, archive_bytes, archive.bytes.len) catch
            return .{ .surface = .artifact, .code = .path_limit };
        if (archive_bytes > request.limits.max_archive_bytes)
            return .{ .surface = .artifact, .code = .path_limit };
    }
    return null;
}

fn ownDiagnostic(
    allocator: std.mem.Allocator,
    diagnostic: Diagnostic,
) std.mem.Allocator.Error!Diagnostic {
    var owned = diagnostic;
    owned.path = try allocator.dupe(u8, diagnostic.path);
    owned.package = try allocator.dupe(u8, diagnostic.package);
    owned.architecture = try allocator.dupe(u8, diagnostic.architecture);
    owned.holder = try allocator.dupe(u8, diagnostic.holder);
    owned.holder_architecture = try allocator.dupe(u8, diagnostic.holder_architecture);
    if (diagnostic.database) |nested| {
        var copy = nested;
        copy.path = try allocator.dupe(u8, nested.path);
        copy.package = try allocator.dupe(u8, nested.package);
        copy.field_name = if (nested.field_name) |name|
            try allocator.dupe(u8, name)
        else
            null;
        owned.database = copy;
    }
    return owned;
}

fn refusalResult(
    arena: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,
    diagnostic: Diagnostic,
) Result {
    return .{ .refusal = .{
        .diagnostic = diagnostic,
        .digest = diagnosticDigest(diagnostic),
        .arena = arena,
        .backing_allocator = allocator,
    } };
}

fn outOfMemory(arena: *std.heap.ArenaAllocator, allocator: std.mem.Allocator) Result {
    return refusalResult(arena, allocator, .{
        .surface = .lowering,
        .code = .out_of_memory,
        .path = package_database.database_directory,
    });
}

fn buildHandoff(
    allocator: std.mem.Allocator,
    items: []const DeferredItem,
) std.mem.Allocator.Error!Handoff {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    const ordered = try allocator.dupe(DeferredItem, items);
    defer allocator.free(ordered);
    std.mem.sort(DeferredItem, ordered, {}, lessDeferredItem);
    const copied = try owned.alloc(DeferredItem, ordered.len);
    var hash = Sha256.init(.{});
    hash.update(digest_domain);
    hash.update("handoff");
    hashNumber(&hash, ordered.len);
    for (ordered, 0..) |item, index| {
        copied[index] = .{
            .feature = item.feature,
            .package = try owned.dupe(u8, item.package),
            .architecture = try owned.dupe(u8, item.architecture),
            .detail = try owned.dupe(u8, item.detail),
        };
        hashText(&hash, item.feature.spelling());
        hashText(&hash, item.package);
        hashText(&hash, item.architecture);
        hashText(&hash, item.detail);
    }
    return .{
        .items = copied,
        .digest = hash.finalResult(),
        .arena = arena,
        .backing_allocator = allocator,
    };
}

fn lessDeferredItem(_: void, left: DeferredItem, right: DeferredItem) bool {
    const fields = [_]std.math.Order{
        std.math.order(@intFromEnum(left.feature), @intFromEnum(right.feature)),
        std.mem.order(u8, left.package, right.package),
        std.mem.order(u8, left.architecture, right.architecture),
        std.mem.order(u8, left.detail, right.detail),
    };
    for (fields) |order| switch (order) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    };
    return false;
}

fn hashText(hash: *Sha256, text: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, text.len, .big);
    hash.update(&length);
    hash.update(text);
}

fn run(builder: *Builder, arena: *std.heap.ArenaAllocator) PlanError!Plan {
    try validateProgram(builder);
    if (builder.request.interoperability == .shared_root)
        try builder.deferFeature(.{
            .feature = .dpkg_interoperability,
            .detail = package_database.database_directory,
        });
    try collectSteps(builder);
    if (builder.deferred.items.len != 0) return error.Deferred;

    std.mem.sort(PackageWork, builder.work.items, {}, lessPackageWork);
    for (builder.work.items, 0..) |item, index| {
        if (item.owner_index) |owner|
            try builder.owner_work.put(
                builder.allocator,
                owner,
                @intCast(index),
            );
    }
    for (builder.work.items) |*item| try preparePackageClaims(builder, item);
    try indexFinalClaims(builder);
    try indexInstalledConffiles(builder);
    try indexCaseGraph(builder);
    if (builder.request.conffiles == .handoff)
        try inspectTouchedConffiles(builder);
    try inspectDeferredState(builder);
    if (builder.deferred.items.len != 0) return error.Deferred;
    try proveCaseEvidence(builder);
    for (builder.work.items, 0..) |*item, index|
        try planPackageClaims(builder, item, @intCast(index));
    try planFinalRemovals(builder);
    try observeFinalDirectoryPrefixes(builder);
    for (builder.work.items, 0..) |*item, index|
        try synthesizeAncestors(builder, item, @intCast(index));
    sortRetainedDirectories(builder);
    for (builder.work.items) |*item| try publishRecords(builder, item);
    try inspectDisappearance(builder);
    try inspectPublicationTriggers(builder);
    if (builder.deferred.items.len != 0) return error.Deferred;
    return try lower(builder, arena);
}

fn lessPackageWork(_: void, left: PackageWork, right: PackageWork) bool {
    return switch (std.mem.order(u8, left.identity.name, right.identity.name)) {
        .lt => true,
        .gt => false,
        .eq => std.mem.order(
            u8,
            left.identity.architecture,
            right.identity.architecture,
        ) == .lt,
    };
}

// ---------------------------------------------------------------------------
// Program and evidence binding
// ---------------------------------------------------------------------------

fn validateProgram(builder: *Builder) PlanError!void {
    const program = builder.request.program;
    if (!std.mem.eql(u8, program.schema, native_program.schema_id) or
        program.version != native_program.schema_version)
        return builder.fail(.{ .surface = .program, .code = .schema_unsupported });
    if (program.backend != .native)
        return builder.fail(.{ .surface = .program, .code = .backend_unsupported });

    if (builder.request.authorization) |authorization| {
        if (!program.matchesAuthorization(authorization.*))
            return builder.fail(.{ .surface = .authorization, .code = .authorization_mismatch });
    }
    if (builder.request.root_identity_sha256) |identity| {
        if (!std.mem.eql(u8, &program.root_identity_sha256, &hex(32, identity)))
            return builder.fail(.{ .surface = .authorization, .code = .root_identity_mismatch });
    }

    const database = builder.database;
    if (!builder.request.lifecycle_execution) {
        if (!std.mem.eql(
            u8,
            &program.installed_database.generation_sha256,
            &hex(32, database.generation.sha256),
        ))
            return builder.fail(.{
                .surface = .database,
                .code = .database_generation_mismatch,
                .path = package_database.database_directory,
            });
        if (program.installed_database.package_count != database.model.packages.len)
            return builder.fail(.{
                .surface = .database,
                .code = .database_generation_mismatch,
                .path = package_database.database_directory,
            });
    }
    if (database.model.pending_updates.len != 0)
        return builder.fail(.{
            .surface = .database,
            .code = .updates_pending,
            .path = package_database.updates_directory,
        });
}

/// Walks the compiled program once, binds every artifact it materializes or
/// unpacks to a supplied archive, and classifies every step this roadmap item
/// does not implement.
fn collectSteps(builder: *Builder) PlanError!void {
    const program = builder.request.program;
    const lifecycle = builder.request.lifecycle_execution;
    var unpacks: usize = 0;
    var barrier_seen = false;
    var removal_handoff = false;
    for (program.steps) |step| {
        switch (step.operation) {
            .materialize_bootstrap_payload => |intent| {
                if (lifecycle and !containsSequence(
                    builder.request.lifecycle_sequences,
                    step.sequence,
                )) continue;
                if (!lifecycle and barrier_seen) try builder.deferFeature(.{
                    .feature = .configure_barrier,
                    .package = intent.package.name,
                    .architecture = intent.package.architecture,
                });
                _ = try openWork(
                    builder,
                    intent.package,
                    intent.artifact,
                    true,
                    null,
                    step.sequence,
                );
            },
            .unpack_package => |intent| {
                if (lifecycle and !containsSequence(
                    builder.request.lifecycle_sequences,
                    step.sequence,
                )) continue;
                unpacks += 1;
                if (!lifecycle and barrier_seen) try builder.deferFeature(.{
                    .feature = .configure_barrier,
                    .package = intent.package.name,
                    .architecture = intent.package.architecture,
                });
                const index = try openWork(
                    builder,
                    intent.package,
                    intent.artifact,
                    intent.bootstrapped,
                    intent.prior_version,
                    step.sequence,
                );
                const item = &builder.work.items[index];
                if (item.bootstrapped != intent.bootstrapped)
                    return builder.fail(.{
                        .surface = .program,
                        .code = .program_incomplete,
                        .package = intent.package.name,
                        .architecture = intent.package.architecture,
                    });
            },
            .configure_barrier => if (!lifecycle) {
                barrier_seen = true;
            },
            .remove_package_files => |intent| {
                if (lifecycle) continue;
                removal_handoff = true;
                try builder.deferFeature(.{
                    .feature = .package_removal,
                    .package = intent.package.name,
                    .architecture = intent.package.architecture,
                });
            },
            .purge_package_files => |intent| {
                if (lifecycle) continue;
                removal_handoff = true;
                try builder.deferFeature(.{
                    .feature = .package_purge,
                    .package = intent.package.name,
                    .architecture = intent.package.architecture,
                });
            },
            .run_maintainer_script => |call| if (!lifecycle)
                try builder.deferFeature(.{
                    .feature = .maintainer_script,
                    .package = call.package.name,
                    .architecture = call.package.architecture,
                    .detail = @tagName(call.kind),
                }),
            .apply_conffile_decision => |decision| if (!lifecycle)
                try builder.deferFeature(.{
                    .feature = .conffile_decision,
                    .package = decision.package.name,
                    .architecture = decision.package.architecture,
                    .detail = decision.path,
                }),
            .record_trigger_interests => |record| if (!builder.request.trigger_execution)
                try builder.deferFeature(.{
                    .feature = .trigger,
                    .package = record.package.name,
                    .architecture = record.package.architecture,
                }),
            .activate_trigger => |activation| if (!builder.request.trigger_execution)
                try builder.deferFeature(.{
                    .feature = .trigger,
                    .package = activation.source.name,
                    .architecture = activation.source.architecture,
                    .detail = activation.trigger,
                }),
            .process_deferred_triggers => if (!builder.request.trigger_execution)
                try builder.deferFeature(.{ .feature = .trigger }),
            .assert_path_ownership => |assertion| if (assertion.resolution == .forced_overwrite)
                try builder.deferFeature(.{
                    .feature = .forced_overwrite,
                    .package = assertion.claimant.name,
                    .architecture = assertion.claimant.architecture,
                    .detail = assertion.path,
                }),
            else => {},
        }
    }
    if (!removal_handoff and
        ((!lifecycle and unpacks == 0) or builder.work.items.len == 0))
        return builder.fail(.{ .surface = .program, .code = .program_incomplete });
    if (removal_handoff) return;
    if (builder.work.items.len > builder.limits.max_packages)
        return builder.fail(.{ .surface = .program, .code = .package_limit });
    // Every supplied archive must be consumed. An unbound artifact means the
    // caller and the program disagree about what this transaction applies.
    for (builder.request.archives) |input| {
        var bound = false;
        for (builder.work.items) |item| {
            if (item.artifact == input.artifact) bound = true;
        }

        if (!bound) return builder.fail(.{
            .surface = .artifact,
            .code = .artifact_unbound,
        });
    }
}

fn containsSequence(sequences: []const u32, sequence: u32) bool {
    for (sequences) |candidate| {
        if (candidate == sequence) return true;
    }
    return false;
}

/// Finds or creates the work entry for one package, binding its artifact,
/// archive, and operation exactly once.
fn openWork(
    builder: *Builder,
    identity: native_program.PackageIdentity,
    artifact: u32,
    bootstrapped: bool,
    prior_version: ?[]const u8,
    sequence: u32,
) PlanError!usize {
    for (builder.work.items, 0..) |*item, index| {
        if (std.mem.eql(u8, item.identity.name, identity.name) and
            std.mem.eql(u8, item.identity.architecture, identity.architecture))
        {
            if (item.artifact != artifact) return builder.fail(.{
                .surface = .program,
                .code = .artifact_mismatch,
                .package = identity.name,
                .architecture = identity.architecture,
            });
            item.sequence = @min(item.sequence, sequence);
            return index;
        }
    }

    const archive = try bindArtifact(builder, identity, artifact);
    const model = try rebuildArchive(builder, identity, artifact, archive);
    const database = builder.database;
    const prior = database.model.find(identity.name, identity.architecture);
    if (prior) |record| {
        if (record.status.want == .hold) try builder.deferFeature(.{
            .feature = .selection_change,
            .package = identity.name,
            .architecture = identity.architecture,
            .detail = "hold",
        });
    }
    var owner_index: ?u32 = null;
    for (database.model.packages, 0..) |*record, index| {
        if (record == prior) owner_index = @intCast(index);
    }

    const operation: Operation = if (prior) |record| blk: {
        if (!package_database.stateOwnsFiles(record.status.current))
            return builder.fail(.{
                .surface = .database,
                .code = .holder_state_unsupported,
                .package = identity.name,
                .architecture = identity.architecture,
            });
        const installed = record.parsed_version;
        const incoming = version_module.DebianVersion.parse(identity.version) catch
            return builder.fail(.{
                .surface = .program,
                .code = .package_mismatch,
                .package = identity.name,
                .architecture = identity.architecture,
            });
        break :blk switch (installed.order(incoming)) {
            .lt => .upgrade,
            .gt => .downgrade,
            .eq => .reinstall,
        };
    } else if (bootstrapped) .bootstrap else .install;

    var configured_version: ?[]const u8 = null;
    if (prior) |record| {
        if (prior_version) |declared| {
            if (!std.mem.eql(u8, declared, record.version)) return builder.fail(.{
                .surface = .program,
                .code = .package_mismatch,
                .package = identity.name,
                .architecture = identity.architecture,
            });
        }
        configured_version = switch (record.status.current) {
            .installed, .triggers_awaited, .triggers_pending => record.version,
            .unpacked => switch (configVersionField(record.*)) {
                .absent => null,
                .valid => |value| value,
                .invalid => blk: {
                    try builder.deferFeature(.{
                        .feature = .config_version,
                        .package = identity.name,
                        .architecture = identity.architecture,
                    });
                    break :blk null;
                },
            },
            else => blk: {
                try builder.deferFeature(.{
                    .feature = .config_version,
                    .package = identity.name,
                    .architecture = identity.architecture,
                });
                break :blk null;
            },
        };
    }
    if (!database.model.knowsArchitecture(model.facts.architecture))
        return builder.fail(.{
            .surface = .database,
            .code = .architecture_unknown,
            .package = identity.name,
            .architecture = model.facts.architecture,
        });

    try builder.work.append(builder.allocator, .{
        .identity = identity,
        .stem = if (model.facts.multi_arch == .same)
            try std.fmt.allocPrint(builder.arena, "{s}:{s}", .{
                identity.name,
                identity.architecture,
            })
        else
            try builder.arena.dupe(u8, identity.name),
        .artifact = artifact,
        .archive = archive,
        .model = model,
        .application_sha256 = try rebindArchive(
            builder,
            identity,
            artifact,
            archive,
            model,
        ),
        .operation = operation,
        .bootstrapped = bootstrapped,
        .sequence = sequence,
        .prior = prior,
        .prior_version = if (prior) |record| record.version else null,
        .configured_version = configured_version,
        .owner_index = owner_index,
        .claims = &.{},
    });
    return builder.work.items.len - 1;
}

const ConfigVersionField = union(enum) {
    absent,
    valid: []const u8,
    invalid,
};

fn configVersionField(
    record: package_database.PackageRecord,
) ConfigVersionField {
    const field = record.field("Config-Version") orelse return .absent;
    if (field.value_lines.len != 1) return .invalid;
    const value = field.value_lines[0];
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0 or !std.mem.eql(u8, trimmed, value)) return .invalid;
    _ = version_module.DebianVersion.parse(value) catch return .invalid;
    return .{ .valid = value };
}

fn bindArtifact(
    builder: *Builder,
    identity: native_program.PackageIdentity,
    artifact: u32,
) PlanError!usize {
    const program = builder.request.program;
    var declared: ?native_program.ProgramArtifact = null;
    for (program.artifacts) |entry| {
        if (entry.index == artifact) declared = entry;
    }
    const record = declared orelse return builder.fail(.{
        .surface = .artifact,
        .code = .artifact_missing,
        .package = identity.name,
        .architecture = identity.architecture,
    });
    if (!std.mem.eql(u8, record.package.name, identity.name) or
        !std.mem.eql(u8, record.package.version, identity.version) or
        !std.mem.eql(u8, record.package.architecture, identity.architecture))
        return builder.fail(.{
            .surface = .artifact,
            .code = .artifact_mismatch,
            .package = identity.name,
            .architecture = identity.architecture,
        });

    var found: ?usize = null;
    for (builder.request.archives, 0..) |input, index| {
        if (input.artifact != artifact) continue;
        if (found != null) return builder.fail(.{
            .surface = .artifact,
            .code = .artifact_duplicate,
            .package = identity.name,
            .architecture = identity.architecture,
        });
        found = index;
    }
    const index = found orelse return builder.fail(.{
        .surface = .artifact,
        .code = .artifact_missing,
        .package = identity.name,
        .architecture = identity.architecture,
    });
    if (builder.request.archives[index].bytes.len != record.size) return builder.fail(.{
        .surface = .artifact,
        .code = .artifact_mismatch,
        .package = identity.name,
        .architecture = identity.architecture,
    });
    return index;
}

/// Rebuilds one archive model from its own authenticated bytes.
fn rebuildArchive(
    builder: *Builder,
    identity: native_program.PackageIdentity,
    artifact: u32,
    archive: usize,
) PlanError!*const archive_application.Model {
    var declared: ?native_program.ProgramArtifact = null;
    for (builder.request.program.artifacts) |entry| {
        if (entry.index == artifact) declared = entry;
    }
    const record = declared orelse return builder.fail(.{
        .surface = .artifact,
        .code = .artifact_missing,
        .package = identity.name,
        .architecture = identity.architecture,
    });
    const expected_application = parseHex(32, &record.application_sha256) orelse
        return builder.fail(.{
            .surface = .artifact,
            .code = .artifact_mismatch,
            .package = identity.name,
            .architecture = identity.architecture,
        });
    const expected_archive = parseHex(32, &record.sha256) orelse
        return builder.fail(.{
            .surface = .artifact,
            .code = .artifact_mismatch,
            .package = identity.name,
            .architecture = identity.architecture,
        });
    const bytes = builder.request.archives[archive].bytes;
    const diagnostic: Diagnostic = .{
        .surface = .archive,
        .code = .path_limit,
        .package = identity.name,
    };
    switch (archive_application.revalidate(
        builder.model_allocator.allocator(),
        bytes,
        .{ .local = .{
            .size = record.size,
            .sha256 = expected_archive,
            .identity = .{
                .package = identity.name,
                .version = identity.version,
                .architecture = identity.architecture,
            },
        } },
        builder.limits.archive,
        expected_application,
    )) {
        .model => |value| {
            if (value.files.len > builder.limits.max_paths_per_package) {
                var released = value;
                released.deinit();
                return builder.fail(.{
                    .surface = .archive,
                    .code = .path_limit,
                    .package = identity.name,
                });
            }
            const owned = builder.model_allocator.allocator().create(
                archive_application.Model,
            ) catch {
                var released = value;
                released.deinit();
                return builder.modelAllocationFailure(diagnostic);
            };
            errdefer builder.model_allocator.allocator().destroy(owned);
            owned.* = value;
            errdefer owned.deinit();
            try builder.chargeWork(owned.files.len, .{
                .surface = .archive,
                .code = .path_limit,
                .package = identity.name,
            });
            try builder.models.append(builder.allocator, owned);
            return owned;
        },
        .diagnostic => |archive_diagnostic| {
            if (archive_diagnostic.code == .out_of_memory)
                return builder.modelAllocationFailure(.{
                    .surface = .archive,
                    .code = .path_limit,
                    .package = identity.name,
                });
            if (archive_diagnostic.payload) |payload| {
                if (payload.code == .out_of_memory)
                    return builder.modelAllocationFailure(.{
                        .surface = .archive,
                        .code = .path_limit,
                        .package = identity.name,
                    });
                if (payload.decompression_error) |err| {
                    if (err == error.OutOfMemory)
                        return builder.modelAllocationFailure(.{
                            .surface = .archive,
                            .code = .path_limit,
                            .package = identity.name,
                        });
                }
            }
            return builder.fail(.{
                .surface = .archive,
                .code = .archive_binding_mismatch,
                .package = identity.name,
                .architecture = identity.architecture,
            });
        },
    }
}

/// Immediate descriptive binding between a rebuilt model and its bytes.
fn rebindArchive(
    builder: *Builder,
    identity: native_program.PackageIdentity,
    artifact: u32,
    archive: usize,
    model: *const archive_application.Model,
) PlanError![32]u8 {
    const program = builder.request.program;
    const input = builder.request.archives[archive];
    var authorized: ?[32]u8 = null;
    for (program.artifacts) |entry| {
        if (entry.index != artifact) continue;
        authorized = parseHex(32, &entry.application_sha256) orelse return builder.fail(.{
            .surface = .artifact,
            .code = .artifact_mismatch,
            .package = identity.name,
            .architecture = identity.architecture,
        });
        const declared_sha = parseHex(32, &entry.sha256) orelse return builder.fail(.{
            .surface = .artifact,
            .code = .artifact_mismatch,
            .package = identity.name,
            .architecture = identity.architecture,
        });
        if (!std.crypto.timing_safe.eql([32]u8, declared_sha, model.provenance().sha256))
            return builder.fail(.{
                .surface = .artifact,
                .code = .artifact_mismatch,
                .package = identity.name,
                .architecture = identity.architecture,
            });
    }
    const expected = authorized orelse return builder.fail(.{
        .surface = .artifact,
        .code = .artifact_missing,
        .package = identity.name,
        .architecture = identity.architecture,
    });
    model.verifyArtifactBinding(input.bytes) catch return builder.fail(.{
        .surface = .artifact,
        .code = .archive_binding_mismatch,
        .package = identity.name,
        .architecture = identity.architecture,
    });
    if (!std.crypto.timing_safe.eql([32]u8, model.digest, expected))
        return builder.fail(.{
            .surface = .artifact,
            .code = .archive_binding_mismatch,
            .package = identity.name,
            .architecture = identity.architecture,
        });
    return model.digest;
}

/// Classifies every archive and database feature this roadmap item defers.
fn inspectDeferredState(builder: *Builder) PlanError!void {
    const model = builder.database.model;
    for (builder.request.unmodeled_database_entries) |name|
        try builder.deferFeature(.{
            .feature = .database_surface,
            .detail = name,
        });
    for (builder.request.unsupported_root_features) |path|
        try builder.deferFeature(.{
            .feature = .unsupported_root_feature,
            .detail = path,
        });
    if (!builder.request.trigger_execution)
        for (model.triggers.pending) |queued| {
            if (queued.packages.len == 0)
                try builder.deferFeature(.{ .feature = .trigger, .detail = queued.trigger });
            for (queued.packages) |awaiting| try builder.deferFeature(.{
                .feature = .trigger,
                .package = awaiting.package.name,
                .architecture = awaiting.package.architecture,
                .detail = queued.trigger,
            });
        };
    for (model.diversions) |record| try builder.deferFeature(.{
        .feature = .diversion,
        .package = record.package orelse "",
        .detail = record.from,
    });
    for (model.stat_overrides) |record| try builder.deferFeature(.{
        .feature = .stat_override,
        .detail = record.path,
    });
    for (model.opaque_info) |entry| {
        if (std.mem.endsWith(u8, entry.name, ".alternatives"))
            try builder.deferFeature(.{ .feature = .alternatives, .detail = entry.name })
        else
            try builder.deferFeature(.{ .feature = .package_metadata, .detail = entry.name });
    }

    for (builder.work.items) |item| {
        const archive = item.model;
        if (builder.request.conffiles == .handoff)
            for (archive.conffiles) |conffile| try builder.deferFeature(.{
                .feature = .conffile,
                .package = item.identity.name,
                .architecture = item.identity.architecture,
                .detail = conffile.path,
            });
        if (!builder.request.lifecycle_execution)
            for (archive.scripts) |script| try builder.deferFeature(.{
                .feature = .maintainer_script,
                .package = item.identity.name,
                .architecture = item.identity.architecture,
                .detail = script.name,
            });
        if (!builder.request.trigger_execution)
            for (archive.triggers) |trigger| try builder.deferFeature(.{
                .feature = .trigger,
                .package = item.identity.name,
                .architecture = item.identity.architecture,
                .detail = trigger.target,
            });
        for (archive.metadata) |member| try builder.deferFeature(.{
            .feature = .package_metadata,
            .package = item.identity.name,
            .architecture = item.identity.architecture,
            .detail = member.name,
        });
        const prior = item.prior orelse continue;
        if (builder.request.conffiles == .handoff)
            for (prior.conffiles) |conffile| try builder.deferFeature(.{
                .feature = .conffile,
                .package = prior.name,
                .architecture = prior.architecture,
                .detail = conffile.path,
            });
        if (!builder.request.lifecycle_execution)
            for (prior.scripts) |script| try builder.deferFeature(.{
                .feature = .maintainer_script,
                .package = prior.name,
                .architecture = prior.architecture,
                .detail = script.kind.suffix(),
            });
        if (!builder.request.trigger_execution) if (prior.trigger_declarations) |declarations| {
            for (declarations) |declaration| try builder.deferFeature(.{
                .feature = .trigger,
                .package = prior.name,
                .architecture = prior.architecture,
                .detail = declaration.name,
            });
        };
        if (!builder.request.trigger_execution)
            for (prior.triggers_pending) |trigger| try builder.deferFeature(.{
                .feature = .trigger,
                .package = prior.name,
                .architecture = prior.architecture,
                .detail = trigger,
            });
        if (!builder.request.trigger_execution)
            for (prior.triggers_awaited) |trigger| try builder.deferFeature(.{
                .feature = .trigger,
                .package = prior.name,
                .architecture = prior.architecture,
                .detail = trigger,
            });
    }
}

fn indexInstalledConffiles(builder: *Builder) PlanError!void {
    for (builder.database.model.packages) |record| {
        if (record.status.current == .not_installed) continue;
        for (record.conffiles) |conffile| {
            try builder.chargeWork(1, .{
                .surface = .database,
                .code = .path_limit,
                .path = conffile.path,
                .package = record.name,
            });
            const relative = relativeListPath(conffile.path) orelse
                return builder.fail(.{
                    .surface = .database,
                    .code = .invalid_path,
                    .path = conffile.path,
                    .package = record.name,
                });
            var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
            const canonical = canonicalAliasPath(
                builder.aliases,
                relative,
                &buffer,
            ) orelse return builder.fail(.{
                .surface = .database,
                .code = .invalid_path,
                .path = conffile.path,
                .package = record.name,
            });
            _ = root_fs.Path.init(canonical) catch return builder.fail(.{
                .surface = .database,
                .code = .invalid_path,
                .path = conffile.path,
                .package = record.name,
            });
            const found = try builder.installed_conffiles.getOrPut(
                builder.allocator,
                try builder.arena.dupe(u8, canonical),
            );
            if (!found.found_existing) found.value_ptr.* = .empty;
            try found.value_ptr.append(
                builder.allocator,
                record.identity(),
            );
        }
    }
}

fn inspectTouchedConffiles(builder: *Builder) PlanError!void {
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(builder.allocator);
    var keys = builder.installed_conffiles.keyIterator();
    while (keys.next()) |path| try paths.append(builder.allocator, path.*);
    std.mem.sort([]const u8, paths.items, {}, lessPath);
    for (paths.items) |path| {
        const owners = builder.installed_conffiles.get(path).?;
        var claimed = builder.transaction_claims.contains(path) or
            builder.final_claim_ancestors.contains(path);
        var removed = !claimed and finalPathRemoved(builder, path);
        var parent = (root_fs.Path.init(path) catch
            return builder.fail(.{
                .surface = .database,
                .code = .invalid_path,
                .path = path,
            })).parent();
        while (parent) |ancestor| : (parent = ancestor.parent()) {
            if (builder.transaction_claims.contains(ancestor.text))
                claimed = true;
            if (finalPathRemoved(builder, ancestor.text))
                removed = true;
        }
        if (!claimed and !removed) continue;
        for (owners.items) |identity| try builder.deferFeature(.{
            .feature = .conffile,
            .package = identity.name,
            .architecture = identity.architecture,
            .detail = path,
        });
    }
}

fn finalPathRemoved(builder: *const Builder, path: []const u8) bool {
    const owners = builder.ownership.ownersOf(path);
    if (owners.len == 0) return false;
    for (owners) |owned| {
        if (!ownerRetiresPath(builder, owned.owner, path)) return false;
    }
    return true;
}

/// Hands off package disappearance instead of leaving an installed record
/// whose only real files were taken by Replaces.
fn inspectDisappearance(builder: *Builder) PlanError!void {
    for (builder.ownership.owners, 0..) |holder, owner_index| {
        const owner: u32 = @intCast(owner_index);
        const acted = builder.owner_work.get(owner);
        if (acted == null and !builder.displaced.contains(owner)) continue;
        var saved = false;
        if (acted) |work_index| {
            for (builder.work.items[work_index].paths.items) |path| {
                if (path.kind != .directory) {
                    saved = true;
                    break;
                }
            }
        }
        for (builder.ownership.ownedBy(owner)) |entry_index| {
            if (saved) break;
            const entry = builder.ownership.entries[entry_index];
            try builder.chargeWork(1, .{
                .surface = .ownership,
                .code = .path_limit,
                .path = entry.path,
            });
            if (acted != null and
                !transactionPackageClaims(builder, entry.path, acted.?)) continue;
            if (displacesOwnerPath(builder, owner, entry.path)) continue;
            const path = root_fs.Path.init(entry.path) catch
                return builder.fail(.{
                    .surface = .ownership,
                    .code = .invalid_path,
                    .path = entry.path,
                });
            const found = builder.request.root.entryIfExists(path) catch
                return builder.fail(.{
                    .surface = .ownership,
                    .code = .root_unreadable,
                    .path = entry.path,
                });
            const observed = found orelse continue;
            if (observed.kind == .directory) continue;
            saved = true;
            break;
        }
        if (saved) continue;
        try builder.deferFeature(.{
            .feature = .package_disappearance,
            .package = holder.identity.name,
            .architecture = holder.identity.architecture,
        });
    }
}

fn displacesOwnerPath(builder: *const Builder, owner: u32, path: []const u8) bool {
    var buffer: [root_fs.maximum_path_bytes + 32]u8 = undefined;
    const key = std.fmt.bufPrint(&buffer, "{x}\x00{s}", .{ owner, path }) catch
        return false;
    return builder.displaced_paths.contains(key);
}

// ---------------------------------------------------------------------------
// Canonical path normalization
// ---------------------------------------------------------------------------

/// Rewrites one archive path through the proven merged-`/usr` aliases.
///
/// Only the first component is rewritten, and only when the root itself
/// proves the alias. A payload under an alias-table name the root holds as
/// some other symbolic link is refused, because publishing it would write
/// through a link the package does not own.
fn normalizePath(builder: *Builder, archive_path: []const u8) PlanError!Claim {
    const first = std.mem.sliceTo(archive_path, '/');
    if (builder.aliases.foreignLink(first)) return builder.fail(.{
        .surface = .alias,
        .code = .alias_escape,
        .path = archive_path,
    });
    const alias = builder.aliases.find(first) orelse return .{
        .path = archive_path,
        .archive_path = archive_path,
        .kind = undefined,
        .file = 0,
        .aliased = false,
    };
    const rest = archive_path[first.len..];
    return .{
        .path = try std.fmt.allocPrint(builder.arena, "{s}{s}", .{ alias.to, rest }),
        .archive_path = archive_path,
        .kind = undefined,
        .file = 0,
        .aliased = true,
    };
}

fn absoluteSpelling(builder: *Builder, path: []const u8) PlanError![]const u8 {
    return std.fmt.allocPrint(builder.arena, "/{s}", .{path});
}

fn kindOf(kind: archive_application.FileKind) Kind {
    return switch (kind) {
        .regular => .regular,
        .directory => .directory,
        .symlink => .symlink,
        .hardlink => .hardlink,
    };
}

fn plannedConffile(
    item: *const PackageWork,
    path: []const u8,
) ?PlannedConffile {
    for (item.conffiles.items) |conffile| {
        if (std.mem.eql(u8, conffile.path, path)) return conffile;
    }
    return null;
}

fn findRecordedConffile(
    builder: *Builder,
    record: *const package_database.PackageRecord,
    canonical: []const u8,
) ?package_database.ConffileEntry {
    for (record.conffiles) |conffile| {
        const relative = relativeListPath(conffile.path) orelse continue;
        var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        const normalized = canonicalAliasPath(
            builder.aliases,
            relative,
            &buffer,
        ) orelse continue;
        if (std.mem.eql(u8, normalized, canonical)) return conffile;
    }
    return null;
}

fn observeConffileMd5(
    builder: *Builder,
    path: []const u8,
    item: *const PackageWork,
) PlanError!?[16]u8 {
    const resolved = root_fs.Path.init(path) catch
        return builder.fail(.{
            .surface = .transition,
            .code = .invalid_path,
            .path = path,
            .package = item.identity.name,
        });
    const entry = builder.request.root.entryIfExists(resolved) catch
        return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = path,
            .package = item.identity.name,
        });
    const found = entry orelse return null;
    if (!found.isRegularFile() or !found.modeled or found.link_count != 1) {
        try builder.deferFeature(.{
            .feature = .unsupported_root_feature,
            .package = item.identity.name,
            .architecture = item.identity.architecture,
            .detail = path,
        });
        return null;
    }
    try chargeComparedBytes(builder, found.size, .{
        .surface = .transition,
        .code = .path_limit,
        .path = path,
        .package = item.identity.name,
    });
    const bytes = builder.request.root.readFileAlloc(
        builder.allocator,
        resolved,
        builder.limits.max_compare_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = path,
            .package = item.identity.name,
        }),
    };
    defer builder.allocator.free(bytes);
    return digestMd5(bytes);
}

fn validateGeneratedConffilePath(
    builder: *Builder,
    item: *const PackageWork,
    path: []const u8,
    allow_existing: bool,
) PlanError!void {
    if (builder.ownership.owned(path)) {
        try builder.deferFeature(.{
            .feature = .conffile,
            .package = item.identity.name,
            .architecture = item.identity.architecture,
            .detail = path,
        });
        return;
    }
    const entry = builder.request.root.entryIfExists(
        root_fs.Path.init(path) catch
            return builder.fail(.{
                .surface = .transition,
                .code = .invalid_path,
                .path = path,
                .package = item.identity.name,
            }),
    ) catch return builder.fail(.{
        .surface = .transition,
        .code = .root_unreadable,
        .path = path,
        .package = item.identity.name,
    });
    if (entry) |found| {
        if (!allow_existing or !found.isRegularFile() or
            !found.modeled or found.link_count != 1)
            try builder.deferFeature(.{
                .feature = .conffile,
                .package = item.identity.name,
                .architecture = item.identity.architecture,
                .detail = path,
            });
    }
}

fn prepareUnpackConffiles(
    builder: *Builder,
    item: *PackageWork,
) PlanError!void {
    if (builder.request.conffiles != .unpack) return;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(builder.allocator);
    for (item.model.conffiles) |conffile| {
        const normalized = try normalizePath(builder, conffile.path);
        const live = normalized.path;
        const absolute = try absoluteSpelling(builder, live);
        try seen.put(builder.allocator, live, {});
        const recorded = if (item.prior) |prior|
            findRecordedConffile(builder, prior, live)
        else
            null;
        if (conffile.remove_on_upgrade) {
            const declaration = try std.fmt.allocPrint(
                builder.arena,
                "remove-on-upgrade {s}",
                .{absolute},
            );
            try item.declared_conffiles.append(
                builder.allocator,
                declaration,
            );
            var action: native_program.ConffileAction = .skip_not_shipped;
            if (recorded) |old| {
                var retained = old;
                retained.obsolete = false;
                retained.remove_on_upgrade = true;
                try item.conffile_records.append(builder.allocator, retained);
                action = switch (old.digest) {
                    .new_conffile => .skip_not_shipped,
                    .md5 => |digest| native_program.conffileDecision(
                        builder.request.conffile_policy,
                        .{
                            .path = conffile.path,
                            .md5 = null,
                            .remove_on_upgrade = true,
                        },
                        .{
                            .path = old.path,
                            .recorded_md5 = digest,
                            .on_disk_md5 = try observeConffileMd5(
                                builder,
                                live,
                                item,
                            ),
                            .obsolete = old.obsolete,
                        },
                    ),
                };
                if (action == .remove_on_upgrade_stage_old) {
                    const old_path = try std.fmt.allocPrint(
                        builder.arena,
                        "{s}.dpkg-old",
                        .{live},
                    );
                    try validateGeneratedConffilePath(
                        builder,
                        item,
                        old_path,
                        false,
                    );
                }
            } else {
                try item.conffile_records.append(builder.allocator, .{
                    .path = absolute,
                    .digest = .new_conffile,
                    .remove_on_upgrade = true,
                });
            }
            try item.conffiles.append(builder.allocator, .{
                .path = live,
                .action = action,
                .recorded = recorded,
            });
            continue;
        }

        const file_index = conffile.file_index orelse
            return builder.fail(.{
                .surface = .archive,
                .code = .unsupported_entry,
                .path = live,
                .package = item.identity.name,
            });
        const file = item.model.files[file_index];
        const packaged_md5 = file.md5 orelse digestMd5(
            item.model.fileBytes(file) catch
                return builder.fail(.{
                    .surface = .archive,
                    .code = .unsupported_entry,
                    .path = live,
                    .package = item.identity.name,
                }),
        );
        if (recorded != null)
            _ = try observeConffileMd5(builder, live, item);
        if (recorded == null and
            (builder.request.root.entryIfExists(
                root_fs.Path.init(live) catch unreachable,
            ) catch return builder.fail(.{
                .surface = .transition,
                .code = .root_unreadable,
                .path = live,
                .package = item.identity.name,
            })) != null)
            try builder.deferFeature(.{
                .feature = .conffile,
                .package = item.identity.name,
                .architecture = item.identity.architecture,
                .detail = live,
            });
        const staged = try std.fmt.allocPrint(
            builder.arena,
            "{s}.dpkg-new",
            .{live},
        );
        try validateGeneratedConffilePath(
            builder,
            item,
            staged,
            item.prior != null and item.prior.?.status.current == .unpacked,
        );
        try item.declared_conffiles.append(builder.allocator, absolute);
        try item.conffile_records.append(builder.allocator, if (recorded) |old| .{
            .path = old.path,
            .digest = old.digest,
            .obsolete = false,
            .remove_on_upgrade = false,
        } else .{
            .path = absolute,
            .digest = .new_conffile,
        });
        try item.conffiles.append(builder.allocator, .{
            .path = live,
            .staged_path = staged,
            .action = .install_new,
            .packaged_md5 = packaged_md5,
            .recorded = recorded,
        });
    }
    if (item.prior) |prior| {
        for (prior.conffiles) |old| {
            const relative = relativeListPath(old.path) orelse continue;
            var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
            const live = canonicalAliasPath(
                builder.aliases,
                relative,
                &buffer,
            ) orelse continue;
            if (seen.contains(live)) continue;
            if (try observeConffileMd5(builder, live, item) == null)
                continue;
            const owned = try builder.arena.dupe(u8, live);
            var obsolete = old;
            obsolete.obsolete = true;
            try item.conffile_records.append(builder.allocator, obsolete);
            try item.conffiles.append(builder.allocator, .{
                .path = owned,
                .action = .mark_obsolete,
                .recorded = old,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Per-package planning
// ---------------------------------------------------------------------------

fn preparePackageClaims(
    builder: *Builder,
    item: *PackageWork,
) PlanError!void {
    const model = item.model;
    try prepareUnpackConffiles(builder, item);
    try indexReplaces(builder, item, model);
    if (model.files.len > builder.limits.max_paths_per_package)
        return builder.fail(.{
            .surface = .archive,
            .code = .path_limit,
            .package = item.identity.name,
        });
    if (model.files.len > builder.limits.max_total_paths -| builder.total_paths)
        return builder.fail(.{
            .surface = .archive,
            .code = .path_limit,
            .package = item.identity.name,
        });

    try prepareEffectiveFiles(builder, item);
    const claims = try builder.arena.alloc(Claim, model.files.len);
    var owned_paths: std.StringHashMapUnmanaged(void) = .empty;
    defer owned_paths.deinit(builder.allocator);

    for (model.files, 0..) |file, index| {
        var claim = try normalizePath(builder, file.path);
        if (builder.request.conffiles == .unpack and file.conffile) {
            const conffile = plannedConffile(item, claim.path) orelse
                return builder.fail(.{
                    .surface = .archive,
                    .code = .program_incomplete,
                    .path = claim.path,
                    .package = item.identity.name,
                });
            claim.path = conffile.staged_path orelse
                return builder.fail(.{
                    .surface = .archive,
                    .code = .program_incomplete,
                    .path = claim.path,
                    .package = item.identity.name,
                });
        }
        claim.kind = kindOf(file.kind);
        claim.file = index;
        _ = root_fs.Path.init(claim.path) catch return builder.fail(.{
            .surface = .archive,
            .code = .invalid_path,
            .path = claim.path,
            .package = item.identity.name,
        });
        for (claim.path) |byte| {
            if (byte >= 0x80) return builder.fail(.{
                .surface = .alias,
                .code = .casefold_unknown,
                .path = claim.path,
                .package = item.identity.name,
            });
        }
        if (reservedDatabasePath(claim.path)) return builder.fail(.{
            .surface = .archive,
            .code = .reserved_path,
            .path = claim.path,
            .package = item.identity.name,
        });
        claims[index] = claim;

        // Aliasing is the only way one archive can name a path twice, and a
        // second name for the same non-directory entry is unresolvable.
        const found = try owned_paths.getOrPut(builder.allocator, claim.path);
        if (found.found_existing) {
            if (claim.kind != .directory) return builder.fail(.{
                .surface = .alias,
                .code = .duplicate_archive_path,
                .path = claim.path,
                .package = item.identity.name,
            });
        }
    }

    // Directory duplicates left by aliasing collapse to one claim so the same
    // path is never owned twice by the same package.
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(builder.allocator);
    var kinds: std.StringHashMapUnmanaged(Kind) = .empty;
    defer kinds.deinit(builder.allocator);
    for (claims) |claim| {
        const found = try kinds.getOrPut(builder.allocator, claim.path);
        if (found.found_existing) {
            if (found.value_ptr.* != claim.kind) return builder.fail(.{
                .surface = .alias,
                .code = .alias_kind_conflict,
                .path = claim.path,
                .package = item.identity.name,
            });
        } else found.value_ptr.* = claim.kind;
    }

    item.claims = claims;
    try prepareHardlinkGroupDigests(builder, item);
}

fn planPackageClaims(
    builder: *Builder,
    item: *PackageWork,
    package: u32,
) PlanError!void {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(builder.allocator);
    for (item.claims) |claim| {
        const duplicate = try seen.getOrPut(builder.allocator, claim.path);
        if (duplicate.found_existing) continue;
        try planClaim(builder, item, package, claim, item.model);
    }
}

fn indexReplaces(
    builder: *Builder,
    item: *PackageWork,
    model: *const archive_application.Model,
) PlanError!void {
    const declared = model.relationship(.replaces) orelse return;
    try builder.chargeWork(declared.groups.len, .{
        .surface = .ownership,
        .code = .path_limit,
        .package = item.identity.name,
    });
    for (declared.groups) |group| {
        if (group.alternatives.len != 1)
            return builder.fail(.{
                .surface = .ownership,
                .code = .invalid_replaces,
                .package = item.identity.name,
            });
        const alternative = group.alternatives[0];
        if (alternative.restrictions.architectures != null or
            alternative.restrictions.build_profiles.len != 0)
            return builder.fail(.{
                .surface = .ownership,
                .code = .invalid_replaces,
                .package = item.identity.name,
            });
        if (alternative.package.architecture_qualifier) |qualifier| {
            if (!std.mem.eql(u8, qualifier.text, "any") and
                !std.mem.eql(u8, qualifier.text, "native") and
                !builder.database.model.knowsArchitecture(qualifier.text))
                return builder.fail(.{
                    .surface = .ownership,
                    .code = .invalid_replaces,
                    .package = item.identity.name,
                    .architecture = qualifier.text,
                });
        }
        const found = try item.replaces.getOrPut(
            builder.allocator,
            alternative.package.name.text,
        );
        if (!found.found_existing) found.value_ptr.* = .empty;
        try found.value_ptr.append(builder.allocator, .{
            .architecture = if (alternative.package.architecture_qualifier) |value|
                value.text
            else
                null,
            .version = alternative.version,
        });
    }
}

fn indexFinalClaims(builder: *Builder) PlanError!void {
    for (builder.work.items, 0..) |item, package| {
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        defer seen.deinit(builder.allocator);
        for (item.claims) |claim| {
            if ((try seen.getOrPut(builder.allocator, claim.path)).found_existing)
                continue;
            const current = try describeTransactionClaim(
                builder,
                &item,
                @intCast(package),
                claim,
            );
            const found = try builder.transaction_claims.getOrPut(
                builder.allocator,
                claim.path,
            );
            if (!found.found_existing) {
                found.value_ptr.* = .{
                    .representative = current,
                    .publisher = current,
                    .count = 0,
                };
            }
            try addTransactionClaim(builder, found.value_ptr, current, claim.path);
            const ancestor = root_fs.Path.init(claim.path) catch
                return builder.fail(.{
                    .surface = .archive,
                    .code = .invalid_path,
                    .path = claim.path,
                    .package = item.identity.name,
                });
            var parent = ancestor.parent();
            while (parent) |value| : (parent = value.parent()) {
                try builder.chargeWork(1, .{
                    .surface = .ownership,
                    .code = .path_limit,
                    .path = claim.path,
                    .package = item.identity.name,
                });
                const prefix = try builder.final_claim_ancestors.getOrPut(
                    builder.allocator,
                    value.text,
                );
                if (!prefix.found_existing) prefix.value_ptr.* = .{};
                prefix.value_ptr.descendants = std.math.add(
                    usize,
                    prefix.value_ptr.descendants,
                    1,
                ) catch return builder.fail(.{
                    .surface = .ownership,
                    .code = .path_limit,
                    .path = claim.path,
                    .package = item.identity.name,
                });
            }
            if (claim.kind != .directory) {
                const owner = try builder.claimed.getOrPut(
                    builder.allocator,
                    claim.path,
                );
                if (!owner.found_existing) owner.value_ptr.* = @intCast(package);
            }
        }
    }
}

fn addTransactionClaim(
    builder: *Builder,
    aggregate: *TransactionClaims,
    current: TransactionClaim,
    path: []const u8,
) PlanError!void {
    const mismatch = Diagnostic{
        .surface = .ownership,
        .code = if (std.mem.eql(u8, current.name, aggregate.representative.name))
            .multi_arch_content_mismatch
        else
            .duplicate_claim,
        .path = path,
        .package = current.name,
        .architecture = current.architecture,
        .holder = aggregate.representative.name,
        .holder_architecture = aggregate.representative.architecture,
    };
    try builder.chargeWork(1, mismatch);
    if (aggregate.count != 0) {
        if (aggregate.representative.kind != current.kind)
            return builder.fail(mismatch);
        if (current.kind == .directory) {
            if (current.multi_arch_same) {
                const group = try aggregate.directory_groups.getOrPut(
                    builder.allocator,
                    current.name,
                );
                if (group.found_existing) {
                    if (!transactionClaimsCompatible(group.value_ptr.*, current))
                        return builder.fail(mismatch);
                } else group.value_ptr.* = current;
            }
        } else if (!transactionClaimsCompatible(
            aggregate.representative,
            current,
        )) return builder.fail(mismatch);
    } else if (current.kind == .directory and current.multi_arch_same) {
        try aggregate.directory_groups.put(
            builder.allocator,
            current.name,
            current,
        );
    }
    try aggregate.by_package.put(builder.allocator, current.package, current);
    aggregate.count += 1;
    const precedes = if (current.kind == .directory)
        current.sequence < aggregate.publisher.sequence or
            (current.sequence == aggregate.publisher.sequence and
                current.package < aggregate.publisher.package)
    else
        current.package < aggregate.publisher.package;
    if (precedes) aggregate.publisher = current;
}

fn describeTransactionClaim(
    builder: *Builder,
    item: *const PackageWork,
    package: u32,
    claim: Claim,
) PlanError!TransactionClaim {
    const file = item.model.files[claim.file];
    var result: TransactionClaim = .{
        .package = package,
        .sequence = item.sequence,
        .name = item.identity.name,
        .architecture = item.identity.architecture,
        .multi_arch_same = item.model.facts.multi_arch == .same,
        .kind = claim.kind,
        .sha256 = null,
        .link_target = null,
        .link_source = null,
        .hardlink_group = null,
        .hardlink_group_size = 1,
        .hardlink_group_digest = null,
        .mode = file.permissions() | (file.mode & 0o7000),
        .uid = std.math.cast(u32, file.uid) orelse
            return builder.fail(.{
                .surface = .archive,
                .code = .unsupported_entry,
                .path = claim.path,
                .package = item.identity.name,
            }),
        .gid = std.math.cast(u32, file.gid) orelse
            return builder.fail(.{
                .surface = .archive,
                .code = .unsupported_entry,
                .path = claim.path,
                .package = item.identity.name,
            }),
        .modified_nanoseconds = @as(i128, file.mtime) * std.time.ns_per_s,
    };
    switch (claim.kind) {
        .regular, .hardlink => {
            const effective = effectiveFile(item, claim) orelse
                return builder.fail(.{
                    .surface = .archive,
                    .code = .unsupported_entry,
                    .path = claim.path,
                    .package = item.identity.name,
                });
            result.sha256 = effective.sha256;
            result.mode = effective.mode;
            result.uid = effective.uid;
            result.gid = effective.gid;
            result.modified_nanoseconds = effective.modified_nanoseconds;
            if (effective.group_size > 1) {
                const group = try normalizePath(builder, effective.source_path);
                result.hardlink_group = group.path;
                result.hardlink_group_size = effective.group_size;
                result.hardlink_group_digest =
                    item.hardlink_group_digests.get(effective.source_index) orelse
                    return builder.fail(.{
                        .surface = .archive,
                        .code = .hard_link_target_missing,
                        .path = claim.path,
                        .package = item.identity.name,
                    });
                if (claim.kind == .hardlink) result.link_source = group.path;
            }
            if (claim.kind == .hardlink and result.link_source == null) {
                const source = try normalizePath(builder, effective.source_path);
                result.link_source = source.path;
            }
        },
        .symlink => result.link_target = file.link_literal orelse
            return builder.fail(.{
                .surface = .archive,
                .code = .symlink_target_invalid,
                .path = claim.path,
                .package = item.identity.name,
            }),
        .directory => result.modified_nanoseconds = 0,
    }
    return result;
}

fn transactionClaimsCompatible(
    left: TransactionClaim,
    right: TransactionClaim,
) bool {
    if (left.kind == .directory and right.kind == .directory) {
        if (!left.multi_arch_same or !right.multi_arch_same or
            !std.mem.eql(u8, left.name, right.name) or
            std.mem.eql(u8, left.architecture, right.architecture))
            return true;
        return left.mode == right.mode and left.uid == right.uid and
            left.gid == right.gid;
    }
    if (!left.multi_arch_same or !right.multi_arch_same or
        !std.mem.eql(u8, left.name, right.name) or
        std.mem.eql(u8, left.architecture, right.architecture))
        return false;
    const file_pair = (left.kind == .regular or left.kind == .hardlink) and
        (right.kind == .regular or right.kind == .hardlink);
    const link_pair = left.kind == .symlink and right.kind == .symlink;
    if (!file_pair and !link_pair) return false;
    if (file_pair and left.kind != right.kind) return false;
    if (!optionalDigestEqual(left.sha256, right.sha256)) return false;
    if (!optionalTextEqual(left.hardlink_group, right.hardlink_group) or
        left.hardlink_group_size != right.hardlink_group_size)
        return false;
    if (!optionalDigestEqual(
        left.hardlink_group_digest,
        right.hardlink_group_digest,
    )) return false;
    if (left.kind == .hardlink) {
        const first = left.link_source orelse return false;
        const second = right.link_source orelse return false;
        if (!std.mem.eql(u8, first, second)) return false;
    }
    if (link_pair) {
        const first = left.link_target orelse return false;
        const second = right.link_target orelse return false;
        if (!std.mem.eql(u8, first, second)) return false;
    }
    return left.mode == right.mode and left.uid == right.uid and
        left.gid == right.gid and
        left.modified_nanoseconds == right.modified_nanoseconds;
}

fn reservedDatabasePath(path: []const u8) bool {
    const reserved = package_database.database_directory;
    if (path.len == reserved.len)
        return std.ascii.eqlIgnoreCase(path, reserved);
    return path.len > reserved.len and path[reserved.len] == '/' and
        std.ascii.eqlIgnoreCase(path[0..reserved.len], reserved);
}

fn planClaim(
    builder: *Builder,
    item: *PackageWork,
    package: u32,
    claim: Claim,
    model: *const archive_application.Model,
) PlanError!void {
    const capacity_diagnostic: Diagnostic = .{
        .surface = .ownership,
        .code = .path_limit,
        .path = claim.path,
        .package = item.identity.name,
    };
    try builder.chargePath(capacity_diagnostic);

    const file = model.files[claim.file];
    var previous = try observePrevious(
        builder,
        claim.path,
        item,
        claim.kind != .hardlink or
            !requiresCombinedHardlinkObservation(
                builder,
                item,
                claim,
                model,
            ),
    );
    var link_source_previous: ?PreviousState = null;
    const decision = try resolveOwnership(
        builder,
        item,
        package,
        claim,
        model,
        &previous,
        &link_source_previous,
    );
    try requireSafeTransition(builder, item, claim, previous);

    const uid = std.math.cast(u32, file.uid) orelse return builder.fail(.{
        .surface = .archive,
        .code = .unsupported_entry,
        .path = claim.path,
        .package = item.identity.name,
    });
    const gid = std.math.cast(u32, file.gid) orelse return builder.fail(.{
        .surface = .archive,
        .code = .unsupported_entry,
        .path = claim.path,
        .package = item.identity.name,
    });

    var planned: PlannedPath = .{
        .path = claim.path,
        .absolute = try absoluteSpelling(builder, claim.path),
        .archive_path = claim.archive_path,
        .kind = claim.kind,
        .mode = file.permissions() | (file.mode & 0o7000),
        .uid = uid,
        .gid = gid,
        .modified_nanoseconds = @as(i128, file.mtime) * std.time.ns_per_s,
        .archive_entry = claim.file,
        .package = package,
        .disposition = decision.disposition,
        .previous = previous,
        .link_source_previous = link_source_previous,
        .aliased = claim.aliased,
        .publish = decision.publish,
    };

    switch (claim.kind) {
        .regular => {
            const effective = effectiveFile(item, claim) orelse
                return builder.fail(.{
                    .surface = .archive,
                    .code = .unsupported_entry,
                    .path = claim.path,
                    .package = item.identity.name,
                });
            planned.sha256 = effective.sha256;
            planned.md5 = effective.md5;
        },
        .directory => {},
        .symlink => {
            const literal = file.link_literal orelse return builder.fail(.{
                .surface = .archive,
                .code = .symlink_target_invalid,
                .path = claim.path,
                .package = item.identity.name,
            });
            if (literal.len == 0 or literal.len > root_fs.maximum_link_target_bytes)
                return builder.fail(.{
                    .surface = .archive,
                    .code = .symlink_target_invalid,
                    .path = claim.path,
                    .package = item.identity.name,
                });
            planned.link_literal = literal;
        },
        .hardlink => {
            const effective = effectiveFile(item, claim) orelse return builder.fail(.{
                .surface = .archive,
                .code = .hard_link_target_missing,
                .path = claim.path,
                .package = item.identity.name,
            });
            const source = try normalizePath(builder, effective.source_path);
            planned.link_source = source.path;
            planned.sha256 = effective.sha256;
            planned.md5 = effective.md5;
            planned.mode = effective.mode;
            planned.uid = effective.uid;
            planned.gid = effective.gid;
            planned.modified_nanoseconds = effective.modified_nanoseconds;
        },
    }
    if (planned.kind == .directory and
        planned.previous != null and
        planned.previous.?.kind == .directory)
        planned.publish = false;
    try registerTransactionClaim(builder, package, &planned);
    if (planned.publish) try builder.chargeIntent(capacity_diagnostic);
    try builder.published.put(builder.allocator, claim.path, claim.kind);
    try item.paths.append(builder.allocator, planned);
}

fn requiresCombinedHardlinkObservation(
    builder: *const Builder,
    item: *const PackageWork,
    claim: Claim,
    model: *const archive_application.Model,
) bool {
    if (claim.kind != .hardlink or model.facts.multi_arch != .same)
        return false;
    for (builder.ownership.ownersOf(claim.path)) |owned| {
        const holder = builder.ownership.owners[owned.owner];
        if (!builder.owner_work.contains(owned.owner) and
            std.mem.eql(u8, holder.identity.name, item.identity.name) and
            !std.mem.eql(
                u8,
                holder.identity.architecture,
                item.identity.architecture,
            ) and
            holder.record.multi_arch == .same)
            return true;
    }
    return false;
}

fn registerTransactionClaim(
    builder: *Builder,
    package: u32,
    planned: *PlannedPath,
) PlanError!void {
    const claims = builder.transaction_claims.get(planned.path) orelse
        return builder.fail(.{
            .surface = .ownership,
            .code = .program_incomplete,
            .path = planned.path,
        });
    if (claims.count <= 1) return;
    if (planned.kind == .directory)
        planned.disposition = .share_directory
    else
        planned.disposition = .share_multi_arch;
    planned.publish = planned.publish and package == claims.publisher.package;
}

fn optionalDigestEqual(left: ?[32]u8, right: ?[32]u8) bool {
    const first = left orelse return right == null;
    const second = right orelse return false;
    return std.mem.eql(u8, &first, &second);
}

fn optionalTextEqual(left: ?[]const u8, right: ?[]const u8) bool {
    const first = left orelse return right == null;
    const second = right orelse return false;
    return std.mem.eql(u8, first, second);
}

/// True when every ancestor of `path` is either already a real directory or
/// is published as one by this transaction before the path itself.
fn plannedDirectoryAncestors(
    builder: *Builder,
    path: root_fs.Path,
) PlanError!bool {
    var ancestors: [root_fs.maximum_path_components]root_fs.Path = undefined;
    var count: usize = 0;
    var cursor = path.parent();
    while (cursor) |ancestor| : (cursor = ancestor.parent()) {
        ancestors[count] = ancestor;
        count += 1;
    }
    var virtual = false;
    while (count != 0) {
        count -= 1;
        const ancestor = ancestors[count];
        if (builder.transaction_claims.get(ancestor.text)) |claims| {
            if (claims.representative.kind != .directory) return false;
            virtual = true;
            continue;
        }
        if (virtual) continue;
        const found = builder.request.root.entryIfExists(ancestor) catch
            return builder.fail(.{
                .surface = .transition,
                .code = .root_unreadable,
                .path = ancestor.text,
            });
        const entry = found orelse {
            virtual = true;
            continue;
        };
        if (entry.kind == .directory) {
            var observed = try rootDirectoryObservation(
                builder,
                ancestor,
                "",
            );
            defer observed.deinit();
            try retainDirectoryEvidence(builder, ancestor.text, .{
                .kind = .directory,
                .owned = builder.ownership.owned(ancestor.text),
                .modeled = observed.entry.modeled,
                .mode = observed.entry.mode,
                .uid = observed.entry.uid,
                .gid = observed.entry.gid,
                .size = observed.entry.size,
                .device = observed.entry.device,
                .inode = observed.entry.inode,
                .link_count = observed.entry.link_count,
                .modified_nanoseconds = observed.entry.modified_nanoseconds,
                .change_nanoseconds = observed.change_nanoseconds,
                .directory_sha256 = observed.digest,
                .directory_entries = observed.members.len,
            });
            continue;
        }
        if (builder.final_claim_ancestors.get(ancestor.text)) |requirement| {
            if (requirement.kind != .directory) return false;
            if (!pathOwnedOnlyByRetiringPackages(builder, ancestor.text))
                return false;
            virtual = true;
            continue;
        }
        return false;
    }
    return true;
}

fn digestMd5(bytes: []const u8) [16]u8 {
    var digest: [16]u8 = undefined;
    Md5.hash(bytes, &digest, .{});
    return digest;
}

const RootFileObservation = struct {
    entry: root_fs.Entry,
    change_nanoseconds: i128,
    digest: [32]u8,
};

const RootDirectoryObservation = struct {
    entry: root_fs.Entry,
    change_nanoseconds: i128,
    digest: [32]u8,
    members: []root_fs.DirectoryMember,
    allocator: std.mem.Allocator,

    fn deinit(self: *RootDirectoryObservation) void {
        for (self.members) |member| self.allocator.free(member.name);
        self.allocator.free(self.members);
        self.* = undefined;
    }
};

fn rootFileObservation(
    builder: *Builder,
    path: root_fs.Path,
    package: []const u8,
) PlanError!RootFileObservation {
    var pinned = builder.request.root.pinRegularFile(path) catch
        return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = path.text,
            .package = package,
        });
    defer pinned.close();
    const metadata = pinned.metadata() catch
        return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = path.text,
            .package = package,
        });
    const entry = metadata.entry;
    if (!entry.modeled or !entry.isRegularFile())
        return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = path.text,
            .package = package,
        });
    const diagnostic: Diagnostic = .{
        .surface = .transition,
        .code = .path_limit,
        .path = path.text,
        .package = package,
    };
    try chargeComparedBytes(builder, entry.size, diagnostic);
    const observation = pinned.observeAlloc(
        builder.allocator,
        builder.limits.max_compare_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = path.text,
            .package = package,
        }),
    };
    defer builder.allocator.free(observation.bytes);
    var digest: [32]u8 = undefined;
    Sha256.hash(observation.bytes, &digest, .{});
    return .{
        .entry = observation.entry,
        .change_nanoseconds = observation.change_nanoseconds,
        .digest = digest,
    };
}

fn lessDirectoryMember(
    _: void,
    left: root_fs.DirectoryMember,
    right: root_fs.DirectoryMember,
) bool {
    return switch (std.mem.order(u8, left.name, right.name)) {
        .lt => true,
        .gt => false,
        .eq => @intFromEnum(left.kind) < @intFromEnum(right.kind),
    };
}

fn rootDirectoryObservation(
    builder: *Builder,
    path: root_fs.Path,
    package: []const u8,
) PlanError!RootDirectoryObservation {
    var pinned = builder.request.root.pinDirectory(path) catch
        return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = path.text,
            .package = package,
        });
    defer pinned.close();
    const remaining_work = builder.limits.max_work -| builder.work_units;
    const remaining_bytes = builder.limits.max_compared_bytes -|
        builder.compared_bytes;
    var observed = pinned.observeAlloc(
        builder.allocator,
        @min(builder.limits.max_descendant_scan, remaining_work),
        @intCast(@min(
            @as(u64, builder.limits.max_compare_bytes),
            remaining_bytes,
        )),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return builder.fail(.{
            .surface = .transition,
            .code = if (err == error.DirectoryTooLarge)
                .path_limit
            else
                .root_unreadable,
            .path = path.text,
            .package = package,
        }),
    };
    errdefer observed.deinit();
    if (!observed.entry.modeled or !observed.entry.isDirectory())
        return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = path.text,
            .package = package,
        });
    var name_bytes: u64 = 0;
    for (observed.members) |member| {
        name_bytes = std.math.add(u64, name_bytes, member.name.len) catch
            return builder.fail(.{
                .surface = .transition,
                .code = .path_limit,
                .path = path.text,
                .package = package,
            });
    }
    const diagnostic: Diagnostic = .{
        .surface = .transition,
        .code = .path_limit,
        .path = path.text,
        .package = package,
    };
    try builder.chargeWork(observed.members.len, diagnostic);
    try chargeComparedBytes(builder, name_bytes, diagnostic);
    std.mem.sort(
        root_fs.DirectoryMember,
        observed.members,
        {},
        lessDirectoryMember,
    );
    var hash = Sha256.init(.{});
    hash.update(digest_domain);
    hashText(&hash, "root-directory");
    hashNumber(&hash, observed.members.len);
    for (observed.members) |member| {
        hashText(&hash, member.name);
        hashText(&hash, @tagName(member.kind));
    }
    return .{
        .entry = observed.entry,
        .change_nanoseconds = observed.change_nanoseconds,
        .digest = hash.finalResult(),
        .members = observed.members,
        .allocator = observed.allocator,
    };
}

const ObservedRoot = struct {
    state: PreviousState,
    directory_members: []root_fs.DirectoryMember = &.{},
    directory_allocator: ?std.mem.Allocator = null,

    fn deinit(self: *ObservedRoot) void {
        if (self.directory_allocator) |allocator| {
            for (self.directory_members) |member| allocator.free(member.name);
            allocator.free(self.directory_members);
        }
        self.* = undefined;
    }
};

/// Coherent no-follow observation of one path. File bytes, link target, or
/// directory members come from the same pinned inode as the recorded
/// metadata and change time.
fn observeRootState(
    builder: *Builder,
    path: []const u8,
    package: []const u8,
    allow_planned_ancestors: bool,
    read_regular_content: bool,
) PlanError!?ObservedRoot {
    const resolved = root_fs.Path.init(path) catch return builder.fail(.{
        .surface = .archive,
        .code = .invalid_path,
        .path = path,
        .package = package,
    });
    const found = builder.request.root.entryIfExists(resolved) catch |err| switch (err) {
        error.SymbolicLinkComponent, error.NotDirectory => {
            if (allow_planned_ancestors and
                try plannedDirectoryAncestors(builder, resolved)) return null;
            return builder.fail(.{
                .surface = .alias,
                .code = .symbolic_link_ancestor,
                .path = path,
                .package = package,
            });
        },
        error.OutOfMemory => return error.OutOfMemory,
        else => return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = path,
            .package = package,
        }),
    };
    var entry = found orelse return null;
    if (!entry.modeled) return builder.fail(.{
        .surface = .transition,
        .code = .root_unreadable,
        .path = path,
        .package = package,
    });
    const kind: Kind = switch (entry.kind) {
        .file => .regular,
        .directory => .directory,
        .sym_link => .symlink,
        else => return builder.fail(.{
            .surface = .transition,
            .code = .unsupported_entry,
            .path = path,
            .package = package,
        }),
    };
    var content_sha256: ?[32]u8 = null;
    var link_target: ?[]const u8 = null;
    var change_nanoseconds: ?i128 = null;
    var directory_sha256: ?[32]u8 = null;
    var directory_entries: ?u64 = null;
    switch (kind) {
        .regular => {
            if (read_regular_content) {
                const observation = try rootFileObservation(
                    builder,
                    resolved,
                    package,
                );
                entry = observation.entry;
                change_nanoseconds = observation.change_nanoseconds;
                content_sha256 = observation.digest;
            } else {
                var pinned = builder.request.root.pinRegularFile(resolved) catch
                    return builder.fail(.{
                        .surface = .transition,
                        .code = .root_unreadable,
                        .path = path,
                        .package = package,
                    });
                defer pinned.close();
                const observation = pinned.metadata() catch
                    return builder.fail(.{
                        .surface = .transition,
                        .code = .root_unreadable,
                        .path = path,
                        .package = package,
                    });
                entry = observation.entry;
                change_nanoseconds = observation.change_nanoseconds;
            }
        },
        .symlink => {
            var pinned = builder.request.root.pinSymbolicLink(resolved) catch
                return builder.fail(.{
                    .surface = .transition,
                    .code = .root_unreadable,
                    .path = path,
                    .package = package,
                });
            defer pinned.close();
            var buffer: [root_fs.maximum_link_target_bytes]u8 = undefined;
            const observation = pinned.observe(&buffer) catch
                return builder.fail(.{
                    .surface = .transition,
                    .code = .root_unreadable,
                    .path = path,
                    .package = package,
                });
            entry = observation.entry;
            change_nanoseconds = observation.change_nanoseconds;
            link_target = try builder.arena.dupe(u8, observation.target);
        },
        .directory => {
            const observation = try rootDirectoryObservation(
                builder,
                resolved,
                package,
            );
            entry = observation.entry;
            change_nanoseconds = observation.change_nanoseconds;
            directory_sha256 = observation.digest;
            directory_entries = observation.members.len;
            const state: PreviousState = .{
                .kind = kind,
                .owned = builder.ownership.owned(path),
                .modeled = entry.modeled,
                .mode = entry.mode,
                .uid = entry.uid,
                .gid = entry.gid,
                .size = entry.size,
                .device = entry.device,
                .inode = entry.inode,
                .link_count = entry.link_count,
                .modified_nanoseconds = entry.modified_nanoseconds,
                .change_nanoseconds = change_nanoseconds,
                .directory_sha256 = directory_sha256,
                .directory_entries = directory_entries,
            };
            return .{
                .state = state,
                .directory_members = observation.members,
                .directory_allocator = observation.allocator,
            };
        },
        .hardlink => {},
    }
    return .{ .state = .{
        .kind = kind,
        .owned = builder.ownership.owned(path),
        .modeled = entry.modeled,
        .mode = entry.mode,
        .uid = entry.uid,
        .gid = entry.gid,
        .size = entry.size,
        .device = entry.device,
        .inode = entry.inode,
        .link_count = entry.link_count,
        .modified_nanoseconds = entry.modified_nanoseconds,
        .change_nanoseconds = change_nanoseconds,
        .content_sha256 = content_sha256,
        .link_target = link_target,
        .directory_sha256 = directory_sha256,
        .directory_entries = directory_entries,
    } };
}

/// No-follow observation of one claimed path. A symbolic link anywhere above
/// the final component is refused unless this transaction first retires that
/// component and synthesizes the required directory.
fn observePrevious(
    builder: *Builder,
    path: []const u8,
    item: *PackageWork,
    read_regular_content: bool,
) PlanError!?PreviousState {
    if (builder.directory_observations.get(path)) |cached| return cached;
    var observed = try observeRootState(
        builder,
        path,
        item.identity.name,
        true,
        read_regular_content,
    ) orelse return null;
    defer observed.deinit();
    if (observed.state.kind == .directory) try builder.directory_observations.put(
        builder.allocator,
        path,
        observed.state,
    );
    return observed.state;
}

// ---------------------------------------------------------------------------
// Ownership rules
// ---------------------------------------------------------------------------

/// Decides whether one claim may take a path, using only the semantics dpkg
/// documents: a newer generation of the same package, a directory several
/// packages legitimately share, byte-identical content shared by a
/// `Multi-Arch: same` sibling, or an exact `Replaces` on the current owner.
/// Everything else is a conflict refused before mutation.
const OwnershipDecision = struct {
    disposition: Disposition,
    publish: bool = true,
};

fn resolveOwnership(
    builder: *Builder,
    item: *PackageWork,
    package: u32,
    claim: Claim,
    model: *const archive_application.Model,
    previous: *?PreviousState,
    link_source_previous: *?PreviousState,
) PlanError!OwnershipDecision {
    const owners = builder.ownership.ownersOf(claim.path);
    try builder.chargeWork(owners.len, .{
        .surface = .ownership,
        .code = .path_limit,
        .path = claim.path,
        .package = item.identity.name,
    });
    if (claim.kind == .hardlink and previous.* != null) {
        for (owners) |owned| {
            const holder = builder.ownership.owners[owned.owner];
            if (builder.owner_work.contains(owned.owner) or
                !std.mem.eql(u8, holder.identity.name, item.identity.name) or
                std.mem.eql(
                    u8,
                    holder.identity.architecture,
                    item.identity.architecture,
                ) or
                model.facts.multi_arch != .same or
                holder.record.multi_arch != .same)
                continue;
            const aggregate = builder.transaction_claims.get(claim.path) orelse
                return builder.fail(ownershipConflict(item, claim.path, holder));
            const incoming = aggregate.by_package.get(package) orelse
                return builder.fail(ownershipConflict(item, claim.path, holder));
            const source = incoming.link_source orelse
                return builder.fail(ownershipConflict(item, claim.path, holder));
            const combined = try combinedHardlinkObservation(
                builder,
                claim.path,
                source,
                incoming.hardlink_group_size,
                item.identity.name,
            );
            previous.* = combined.destination;
            link_source_previous.* = combined.source;
            break;
        }
    }
    const observed_previous = previous.*;
    var self_owned = false;
    var shared_directory = false;
    var shared_multi_arch_existing = false;
    var shared_multi_arch_transaction = false;
    var retired_owner = false;
    var replacements: std.ArrayList(u32) = .empty;
    defer replacements.deinit(builder.allocator);

    for (owners) |owned| {
        const owner = owned.owner;
        if (ownerRetiresPath(builder, owner, claim.path)) {
            retired_owner = true;
            continue;
        }
        if (item.owner_index) |own| {
            if (owner == own) {
                self_owned = true;
                continue;
            }
        }
        const holder = builder.ownership.owners[owner];

        if (claim.kind == .directory) {
            if (observed_previous == null or observed_previous.?.kind == .directory) {
                shared_directory = true;
                continue;
            }
        } else switch (try sharedMultiArch(
            builder,
            item,
            package,
            claim,
            model,
            owner,
            owned,
            holder,
            observed_previous,
        )) {
            .none => {},
            .existing => {
                shared_multi_arch_existing = true;
                continue;
            },
            .transaction => {
                shared_multi_arch_transaction = true;
                continue;
            },
        }
        if (replacesHolder(builder, item, holder.record)) {
            try replacements.append(builder.allocator, owner);
            continue;
        }
        return builder.fail(ownershipConflict(item, claim.path, holder));
    }

    if ((shared_multi_arch_existing or shared_multi_arch_transaction) and
        replacements.items.len != 0)
    {
        const holder = builder.ownership.owners[replacements.items[0]];
        return builder.fail(ownershipConflict(item, claim.path, holder));
    }

    // Nothing durable is appended until every co-owner has independently
    // passed. A late failing owner therefore cannot leave partial
    // displacement evidence behind.
    for (replacements.items) |owner| {
        const holder = builder.ownership.owners[owner];
        try builder.displaced.put(builder.allocator, owner, {});
        const key = try std.fmt.allocPrint(builder.arena, "{x}\x00{s}", .{
            owner,
            claim.path,
        });
        try builder.displaced_paths.put(builder.allocator, key, {});
        try builder.displacements.append(builder.allocator, .{
            .path = claim.path,
            .holder = holder.identity,
            .holder_index = owner,
            .claimant = .{
                .name = item.identity.name,
                .architecture = item.identity.architecture,
            },
        });
        try item.resolutions.append(builder.allocator, .{
            .path = claim.path,
            .holder = holder.identity,
            .claimant = .{
                .name = item.identity.name,
                .architecture = item.identity.architecture,
            },
            .resolution = .replaces,
        });
    }

    if (self_owned) {
        try item.resolutions.append(builder.allocator, .{
            .path = claim.path,
            .holder = .{
                .name = item.identity.name,
                .architecture = item.identity.architecture,
            },
            .claimant = .{
                .name = item.identity.name,
                .architecture = item.identity.architecture,
            },
            .resolution = .same_package,
        });
    }
    if (replacements.items.len != 0)
        return .{ .disposition = .replace_replaces };
    if (shared_multi_arch_existing)
        return .{ .disposition = .share_multi_arch, .publish = false };
    if (shared_multi_arch_transaction)
        return .{ .disposition = .share_multi_arch };
    if (shared_directory)
        return .{
            .disposition = .share_directory,
            .publish = observed_previous == null,
        };
    if (self_owned) return .{ .disposition = .replace_same_package };
    if (retired_owner)
        return .{ .disposition = if (observed_previous == null)
            .create
        else
            .replace_retired };
    if (observed_previous != null) {
        if (builder.request.unowned == .refuse) return builder.fail(.{
            .surface = .ownership,
            .code = .unowned_path_refused,
            .path = claim.path,
            .package = item.identity.name,
        });
        return .{ .disposition = .replace_unowned };
    }

    return .{ .disposition = .create };
}

fn ownerRetiresPath(builder: *const Builder, owner: u32, path: []const u8) bool {
    const work = builder.owner_work.get(owner) orelse return false;
    return !transactionPackageClaims(builder, path, work);
}

fn pathOwnedOnlyByRetiringPackages(
    builder: *const Builder,
    path: []const u8,
) bool {
    const owners = builder.ownership.ownersOf(path);
    if (owners.len == 0) return false;
    for (owners) |owned| {
        if (!ownerRetiresPath(builder, owned.owner, path)) return false;
    }
    return true;
}

fn preservesConffilePath(item: *const PackageWork, path: []const u8) bool {
    for (item.conffiles.items) |conffile| {
        if (!std.mem.eql(u8, conffile.path, path)) continue;
        return conffile.action != .remove_on_upgrade and
            conffile.action != .remove_on_upgrade_stage_old and
            conffile.action != .skip_not_shipped;
    }
    return false;
}

fn ownershipConflict(item: *const PackageWork, path: []const u8, holder: Owner) Diagnostic {
    return .{
        .surface = .ownership,
        .code = .ownership_conflict,
        .path = path,
        .package = item.identity.name,
        .architecture = item.identity.architecture,
        .holder = holder.identity.name,
        .holder_architecture = holder.identity.architecture,
    };
}

/// `Multi-Arch: same` siblings share only byte-identical files. The digest
/// the holder published is compared against the digest this payload ships;
/// anything else is a conflict, exactly as dpkg reports it.
const MultiArchShare = enum { none, existing, transaction };

fn sharedMultiArch(
    builder: *Builder,
    item: *PackageWork,
    package: u32,
    claim: Claim,
    model: *const archive_application.Model,
    owner: u32,
    owned: OwnedEntry,
    holder: Owner,
    previous: ?PreviousState,
) PlanError!MultiArchShare {
    if (!std.mem.eql(u8, holder.identity.name, item.identity.name)) return .none;
    if (std.mem.eql(u8, holder.identity.architecture, item.identity.architecture)) return .none;
    if (model.facts.multi_arch != .same) return .none;
    if (holder.record.multi_arch != .same) return .none;

    const mismatch: Diagnostic = .{
        .surface = .ownership,
        .code = .multi_arch_content_mismatch,
        .path = claim.path,
        .package = item.identity.name,
        .architecture = item.identity.architecture,
        .holder = holder.identity.name,
        .holder_architecture = holder.identity.architecture,
    };

    if (builder.owner_work.get(owner)) |holder_work| {
        const claims = builder.transaction_claims.get(claim.path) orelse
            return builder.fail(mismatch);
        const incoming = claims.by_package.get(package) orelse
            return builder.fail(mismatch);
        const final_holder = claims.by_package.get(holder_work);
        if (final_holder) |other| {
            if (!transactionClaimsCompatible(incoming, other))
                return builder.fail(mismatch);
        }
        return .transaction;
    }

    const observed = previous orelse return builder.fail(mismatch);
    const aggregate = builder.transaction_claims.get(claim.path) orelse
        return builder.fail(mismatch);
    const incoming = aggregate.by_package.get(package) orelse
        return builder.fail(mismatch);
    switch (claim.kind) {
        .regular, .hardlink => {
            const desired = effectiveFile(item, claim) orelse
                return builder.fail(mismatch);
            const recorded = try holderChecksum(
                builder,
                owner,
                holder,
                owned,
                claim.path,
            ) orelse
                return builder.fail(mismatch);
            if (!std.mem.eql(u8, &recorded, &desired.md5) or
                observed.kind != .regular or
                !optionalDigestEqual(observed.content_sha256, desired.sha256) or
                !modeledMetadataMatches(
                    observed,
                    desired.mode,
                    desired.uid,
                    desired.gid,
                    desired.modified_nanoseconds,
                ))
                return builder.fail(mismatch);
            if (claim.kind == .regular) {
                if (incoming.hardlink_group == null) {
                    if (observed.link_count != 1) return builder.fail(mismatch);
                } else if (observed.link_count != incoming.hardlink_group_size) {
                    return builder.fail(mismatch);
                }
            } else {
                const source = incoming.link_source orelse
                    return builder.fail(mismatch);
                var holder_owns_source = false;
                const source_owners = builder.ownership.ownersOf(source);
                try builder.chargeWork(source_owners.len, mismatch);
                for (source_owners) |source_owner| {
                    if (source_owner.owner == owner) holder_owns_source = true;
                }
                if (!holder_owns_source) return builder.fail(mismatch);
            }
        },
        .symlink => {
            const entry = model.files[claim.file];
            const target = entry.link_literal orelse return builder.fail(mismatch);
            const uid = std.math.cast(u32, entry.uid) orelse
                return builder.fail(mismatch);
            const gid = std.math.cast(u32, entry.gid) orelse
                return builder.fail(mismatch);
            if (observed.kind != .symlink or
                observed.link_target == null or
                !std.mem.eql(u8, observed.link_target.?, target) or
                !modeledMetadataMatches(
                    observed,
                    entry.permissions() | (entry.mode & 0o7000),
                    uid,
                    gid,
                    @as(i128, entry.mtime) * std.time.ns_per_s,
                ))
                return builder.fail(mismatch);
        },
        .directory => return .none,
    }
    try builder.chargeWork(1, mismatch);
    return .existing;
}

const CombinedHardlinkObservation = struct {
    destination: PreviousState,
    source: PreviousState,
};

fn combinedHardlinkObservation(
    builder: *Builder,
    destination: []const u8,
    source: []const u8,
    expected_links: u64,
    package: []const u8,
) PlanError!CombinedHardlinkObservation {
    const destination_path = root_fs.Path.init(destination) catch
        return builder.fail(.{
            .surface = .archive,
            .code = .invalid_path,
            .path = destination,
            .package = package,
        });
    const source_path = root_fs.Path.init(source) catch
        return builder.fail(.{
            .surface = .archive,
            .code = .invalid_path,
            .path = source,
            .package = package,
        });
    var destination_file = builder.request.root.pinRegularFile(
        destination_path,
    ) catch return builder.fail(.{
        .surface = .transition,
        .code = .root_unreadable,
        .path = destination,
        .package = package,
    });
    defer destination_file.close();
    var source_file = builder.request.root.pinRegularFile(source_path) catch
        return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = source,
            .package = package,
        });
    defer source_file.close();
    const destination_before = destination_file.metadata() catch
        return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = destination,
            .package = package,
        });
    const source_before = source_file.metadata() catch
        return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = source,
            .package = package,
        });
    if (!destination_before.entry.modeled or !source_before.entry.modeled or
        destination_before.entry.device != source_before.entry.device or
        destination_before.entry.inode != source_before.entry.inode or
        destination_before.entry.link_count != expected_links or
        source_before.entry.link_count != expected_links)
        return builder.fail(.{
            .surface = .ownership,
            .code = .multi_arch_content_mismatch,
            .path = destination,
            .package = package,
        });
    const comparison_diagnostic: Diagnostic = .{
        .surface = .transition,
        .code = .path_limit,
        .path = destination,
        .package = package,
    };
    try chargeComparedBytes(
        builder,
        destination_before.entry.size,
        comparison_diagnostic,
    );
    try chargeComparedBytes(
        builder,
        destination_before.entry.size,
        comparison_diagnostic,
    );
    const observed = destination_file.observeStableAlloc(
        builder.allocator,
        builder.limits.max_compare_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = destination,
            .package = package,
        }),
    };
    defer builder.allocator.free(observed.bytes);
    const source_after = source_file.metadata() catch
        return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = source,
            .package = package,
        });
    if (!rootMetadataEqual(source_before, source_after) or
        observed.entry.device != source_after.entry.device or
        observed.entry.inode != source_after.entry.inode or
        observed.entry.link_count != expected_links)
        return builder.fail(.{
            .surface = .ownership,
            .code = .multi_arch_content_mismatch,
            .path = destination,
            .package = package,
        });
    try builder.chargeWork(2, .{
        .surface = .ownership,
        .code = .path_limit,
        .path = destination,
        .package = package,
    });
    var digest: [32]u8 = undefined;
    Sha256.hash(observed.bytes, &digest, .{});
    const destination_state: PreviousState = .{
        .kind = .regular,
        .owned = builder.ownership.owned(destination),
        .modeled = observed.entry.modeled,
        .mode = observed.entry.mode,
        .uid = observed.entry.uid,
        .gid = observed.entry.gid,
        .size = observed.entry.size,
        .device = observed.entry.device,
        .inode = observed.entry.inode,
        .link_count = observed.entry.link_count,
        .modified_nanoseconds = observed.entry.modified_nanoseconds,
        .change_nanoseconds = observed.change_nanoseconds,
        .content_sha256 = digest,
    };
    const source_state: PreviousState = .{
        .kind = .regular,
        .owned = builder.ownership.owned(source),
        .modeled = source_after.entry.modeled,
        .mode = source_after.entry.mode,
        .uid = source_after.entry.uid,
        .gid = source_after.entry.gid,
        .size = source_after.entry.size,
        .device = source_after.entry.device,
        .inode = source_after.entry.inode,
        .link_count = source_after.entry.link_count,
        .modified_nanoseconds = source_after.entry.modified_nanoseconds,
        .change_nanoseconds = source_after.change_nanoseconds,
        .content_sha256 = digest,
    };
    return .{
        .destination = destination_state,
        .source = source_state,
    };
}

fn rootMetadataEqual(left: anytype, right: @TypeOf(left)) bool {
    return left.entry.kind == right.entry.kind and
        left.entry.size == right.entry.size and
        left.entry.mode == right.entry.mode and
        left.entry.uid == right.entry.uid and
        left.entry.gid == right.entry.gid and
        left.entry.device == right.entry.device and
        left.entry.inode == right.entry.inode and
        left.entry.link_count == right.entry.link_count and
        left.entry.modified_nanoseconds == right.entry.modified_nanoseconds and
        left.entry.modeled == right.entry.modeled and
        left.change_nanoseconds == right.change_nanoseconds;
}

fn rootMetadataMatchesPrevious(
    observed: anytype,
    previous: PreviousState,
) bool {
    const expected_kind: std.Io.File.Kind = switch (previous.kind) {
        .regular, .hardlink => .file,
        .directory => .directory,
        .symlink => .sym_link,
    };
    return previous.change_nanoseconds != null and
        observed.entry.modeled and
        observed.entry.kind == expected_kind and
        observed.entry.size == previous.size and
        observed.entry.mode == previous.mode and
        observed.entry.uid == previous.uid and
        observed.entry.gid == previous.gid and
        observed.entry.device == previous.device and
        observed.entry.inode == previous.inode and
        observed.entry.link_count == previous.link_count and
        observed.entry.modified_nanoseconds == previous.modified_nanoseconds and
        observed.change_nanoseconds == previous.change_nanoseconds.?;
}

fn revalidateDirectoryObservations(builder: *Builder) PlanError!void {
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(builder.allocator);
    var keys = builder.directory_observations.keyIterator();
    while (keys.next()) |path| try paths.append(builder.allocator, path.*);
    std.mem.sort([]const u8, paths.items, {}, lessPath);
    for (paths.items) |path| {
        const resolved = root_fs.Path.init(path) catch
            return builder.fail(.{
                .surface = .transition,
                .code = .invalid_path,
                .path = path,
            });
        var pinned = builder.request.root.pinDirectory(resolved) catch
            return builder.fail(.{
                .surface = .transition,
                .code = .root_unreadable,
                .path = path,
            });
        defer pinned.close();
        const metadata = pinned.metadata() catch
            return builder.fail(.{
                .surface = .transition,
                .code = .root_unreadable,
                .path = path,
            });
        if (!rootMetadataMatchesPrevious(
            metadata,
            builder.directory_observations.get(path).?,
        )) return builder.fail(.{
            .surface = .transition,
            .code = .root_unreadable,
            .path = path,
        });
    }
}

fn modeledMetadataMatches(
    observed: PreviousState,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_nanoseconds: i128,
) bool {
    return observed.modeled and observed.mode == mode and observed.uid == uid and
        observed.gid == gid and
        observed.modified_nanoseconds == modified_nanoseconds;
}

const EffectiveFile = struct {
    bytes: []const u8,
    sha256: [32]u8,
    md5: [16]u8,
    source_path: []const u8,
    source_index: usize,
    group_size: u64 = 1,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_nanoseconds: i128,
};

const EffectiveState = enum { unseen, visiting, done };

const HardlinkGroupAccumulator = struct {
    count: u64 = 0,
    sum: u256 = 0,
    xor: [32]u8 = @splat(0),
};

fn prepareHardlinkGroupDigests(
    builder: *Builder,
    item: *PackageWork,
) PlanError!void {
    const diagnostic: Diagnostic = .{
        .surface = .archive,
        .code = .path_limit,
        .package = item.identity.name,
    };
    const allocator = builder.model_allocator.allocator();
    var groups: std.AutoHashMapUnmanaged(
        usize,
        HardlinkGroupAccumulator,
    ) = .empty;
    defer groups.deinit(allocator);
    for (item.claims) |claim| {
        const effective = item.effective_files[claim.file] orelse continue;
        if (effective.group_size <= 1) continue;
        var member_hash = Sha256.init(.{});
        member_hash.update(digest_domain);
        hashText(&member_hash, "hardlink-member");
        hashText(&member_hash, claim.path);
        hashText(&member_hash, @tagName(claim.kind));
        const digest = member_hash.finalResult();
        const group = groups.getOrPut(
            allocator,
            effective.source_index,
        ) catch return builder.modelAllocationFailure(diagnostic);
        if (!group.found_existing) group.value_ptr.* = .{};
        group.value_ptr.count = std.math.add(
            u64,
            group.value_ptr.count,
            1,
        ) catch return builder.fail(diagnostic);
        group.value_ptr.sum +%= std.mem.readInt(u256, &digest, .big);
        for (&group.value_ptr.xor, digest) |*byte, value| byte.* ^= value;
        try builder.chargeWork(1, diagnostic);
    }
    var entries = groups.iterator();
    while (entries.next()) |entry| {
        const accumulator = entry.value_ptr.*;
        var sum: [32]u8 = undefined;
        std.mem.writeInt(u256, &sum, accumulator.sum, .big);
        var hash = Sha256.init(.{});
        hash.update(digest_domain);
        hashText(&hash, "hardlink-group");
        hashNumber(&hash, accumulator.count);
        hashText(&hash, &sum);
        hashText(&hash, &accumulator.xor);
        item.hardlink_group_digests.put(
            allocator,
            entry.key_ptr.*,
            hash.finalResult(),
        ) catch return builder.modelAllocationFailure(diagnostic);
    }
}

fn chargeComparedBytes(
    builder: *Builder,
    bytes: u64,
    diagnostic: Diagnostic,
) PlanError!void {
    if (bytes > builder.limits.max_compare_bytes) return builder.fail(diagnostic);
    const next = std.math.add(u64, builder.compared_bytes, bytes) catch
        return builder.fail(diagnostic);
    if (next > builder.limits.max_compared_bytes)
        return builder.fail(diagnostic);
    builder.compared_bytes = next;
}

/// Builds the archive path index and resolves every regular/hard-link payload
/// exactly once. The archive validator currently requires hard links to name
/// an earlier regular file, but this proof still detects cycles and excessive
/// chains so a future model change cannot silently reintroduce repeated
/// linear scans or recursive resolution.
fn prepareEffectiveFiles(builder: *Builder, item: *PackageWork) PlanError!void {
    if (item.effective_files.len != 0 or item.model.files.len == 0) return;
    const diagnostic: Diagnostic = .{
        .surface = .archive,
        .code = .path_limit,
        .package = item.identity.name,
    };
    const allocator = builder.model_allocator.allocator();
    item.file_index.ensureTotalCapacity(
        allocator,
        std.math.cast(u32, item.model.files.len) orelse
            return builder.fail(diagnostic),
    ) catch
        return builder.modelAllocationFailure(diagnostic);
    for (item.model.files, 0..) |file, index| {
        item.file_index.putAssumeCapacity(file.path, index);
    }
    item.effective_files = allocator.alloc(
        ?EffectiveFile,
        item.model.files.len,
    ) catch return builder.modelAllocationFailure(diagnostic);
    @memset(item.effective_files, null);
    const states = allocator.alloc(
        EffectiveState,
        item.model.files.len,
    ) catch return builder.modelAllocationFailure(diagnostic);
    defer allocator.free(states);
    @memset(states, .unseen);
    var chain: std.ArrayListUnmanaged(usize) = .empty;
    defer chain.deinit(allocator);

    for (item.model.files, 0..) |file, start| {
        if (file.kind == .directory or file.kind == .symlink) {
            states[start] = .done;
            continue;
        }
        if (states[start] == .done) continue;
        chain.clearRetainingCapacity();
        var cursor = start;
        while (states[cursor] != .done) {
            if (states[cursor] == .visiting)
                return builder.fail(.{
                    .surface = .archive,
                    .code = .hard_link_target_missing,
                    .path = item.model.files[cursor].path,
                    .package = item.identity.name,
                });
            states[cursor] = .visiting;
            chain.append(allocator, cursor) catch
                return builder.modelAllocationFailure(diagnostic);
            if (chain.items.len > builder.limits.max_paths_per_package)
                return builder.fail(diagnostic);
            try builder.chargeWork(1, diagnostic);
            const current = item.model.files[cursor];
            switch (current.kind) {
                .regular => {
                    const bytes = item.model.fileBytes(current) catch
                        return builder.fail(.{
                            .surface = .archive,
                            .code = .unsupported_entry,
                            .path = current.path,
                            .package = item.identity.name,
                        });
                    const sha256 = current.sha256 orelse
                        return builder.fail(.{
                            .surface = .archive,
                            .code = .unsupported_entry,
                            .path = current.path,
                            .package = item.identity.name,
                        });
                    const md5 = current.md5 orelse blk: {
                        try chargeComparedBytes(builder, bytes.len, diagnostic);
                        break :blk digestMd5(bytes);
                    };
                    item.effective_files[cursor] = .{
                        .bytes = bytes,
                        .sha256 = sha256,
                        .md5 = md5,
                        .source_path = current.path,
                        .source_index = cursor,
                        .mode = current.permissions() | (current.mode & 0o7000),
                        .uid = std.math.cast(u32, current.uid) orelse
                            return builder.fail(.{
                                .surface = .archive,
                                .code = .unsupported_entry,
                                .path = current.path,
                                .package = item.identity.name,
                            }),
                        .gid = std.math.cast(u32, current.gid) orelse
                            return builder.fail(.{
                                .surface = .archive,
                                .code = .unsupported_entry,
                                .path = current.path,
                                .package = item.identity.name,
                            }),
                        .modified_nanoseconds = @as(i128, current.mtime) *
                            std.time.ns_per_s,
                    };
                    states[cursor] = .done;
                },
                .hardlink => {
                    const target = current.link_target orelse
                        return builder.fail(.{
                            .surface = .archive,
                            .code = .hard_link_target_missing,
                            .path = current.path,
                            .package = item.identity.name,
                        });
                    cursor = item.file_index.get(target) orelse
                        return builder.fail(.{
                            .surface = .archive,
                            .code = .hard_link_target_missing,
                            .path = current.path,
                            .package = item.identity.name,
                        });
                },
                .directory, .symlink => return builder.fail(.{
                    .surface = .archive,
                    .code = .hard_link_target_missing,
                    .path = current.path,
                    .package = item.identity.name,
                }),
            }
        }
        const resolved = item.effective_files[cursor] orelse
            return builder.fail(.{
                .surface = .archive,
                .code = .hard_link_target_missing,
                .path = item.model.files[start].path,
                .package = item.identity.name,
            });
        var remaining = chain.items.len;
        while (remaining != 0) {
            remaining -= 1;
            const index = chain.items[remaining];
            item.effective_files[index] = resolved;
            states[index] = .done;
        }
    }

    var groups: std.AutoHashMapUnmanaged(usize, u64) = .empty;
    defer groups.deinit(allocator);
    for (item.effective_files) |effective| {
        const value = effective orelse continue;
        const group = groups.getOrPut(
            allocator,
            value.source_index,
        ) catch return builder.modelAllocationFailure(diagnostic);
        if (!group.found_existing) group.value_ptr.* = 0;
        group.value_ptr.* = std.math.add(u64, group.value_ptr.*, 1) catch
            return builder.fail(diagnostic);
        try builder.chargeWork(1, diagnostic);
    }
    for (item.effective_files) |*effective| {
        if (effective.*) |*value| {
            value.group_size = groups.get(value.source_index) orelse
                return builder.fail(diagnostic);
        }
    }
}

fn effectiveFile(
    item: *const PackageWork,
    claim: Claim,
) ?EffectiveFile {
    return item.effective_files[claim.file];
}

/// The digest the holder published for one path.
///
/// A `Multi-Arch: same` sibling can co-own every path it ships, so the
/// manifest is indexed once per holder instead of scanned per claim; a linear
/// scan here would be quadratic in the shared path count.
fn holderChecksum(
    builder: *Builder,
    owner: u32,
    holder: Owner,
    owned: OwnedEntry,
    path: []const u8,
) PlanError!?[16]u8 {
    const found = try builder.checksums.getOrPut(builder.allocator, owner);
    if (!found.found_existing) {
        found.value_ptr.* = .empty;
        const recorded = holder.record.md5sums orelse return null;
        for (recorded) |entry| {
            try found.value_ptr.put(
                builder.allocator,
                entry.path,
                entry.digest,
            );
        }
    }
    const listed = relativeListPath(owned.listed) orelse return null;
    var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
    const canonical = canonicalAliasPath(
        builder.aliases,
        listed,
        &buffer,
    ) orelse return null;
    if (!std.mem.eql(u8, canonical, path)) return null;
    return found.value_ptr.get(listed);
}

/// True when the claimant declares an exact `Replaces` that the holder's
/// installed identity and version satisfy. An architecture qualifier must
/// match the holder, and a version constraint is evaluated against the exact
/// installed version rather than assumed.
fn replacesHolder(
    builder: *const Builder,
    item: *const PackageWork,
    holder: *const package_database.PackageRecord,
) bool {
    const rules = item.replaces.get(holder.name) orelse return false;
    for (rules.items) |rule| {
        if (rule.architecture) |qualifier| {
            if (std.mem.eql(u8, qualifier, "native")) {
                if (!std.mem.eql(
                    u8,
                    holder.architecture,
                    builder.request.program.target_architecture,
                )) continue;
            } else if (!std.mem.eql(u8, qualifier, "any") and
                !std.mem.eql(u8, qualifier, holder.architecture)) continue;
        }
        const constraint = rule.version orelse return true;
        const wanted = version_module.DebianVersion.parse(constraint.version.text) catch
            continue;
        const order = holder.parsed_version.order(wanted);
        const satisfied = switch (constraint.operator) {
            .less_than => order == .lt,
            .less_than_or_equal => order != .gt,
            .equal => order == .eq,
            .greater_than_or_equal => order != .lt,
            .greater_than => order == .gt,
        };
        if (satisfied) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Path and directory transitions
// ---------------------------------------------------------------------------

/// Refuses a transition whose result would orphan or hide state the
/// transaction does not own.
///
/// Turning a directory into a file or a symbolic link is only safe when
/// nothing that survives the transaction lives under it, because every
/// surviving descendant would become unreachable. Turning a file or a
/// symbolic link into a directory is representable in the descriptive plan.
fn requireSafeTransition(
    builder: *Builder,
    item: *PackageWork,
    claim: Claim,
    previous: ?PreviousState,
) PlanError!void {
    const state = previous orelse return;
    if (claim.kind == .directory and state.kind == .symlink)
        return builder.fail(.{
            .surface = .transition,
            .code = .directory_transition_unsafe,
            .path = claim.path,
            .package = item.identity.name,
        });
    if (state.kind != .directory) return;
    if (claim.kind == .directory) return;

    var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
    const entries = state.directory_entries orelse
        return builder.fail(.{
            .surface = .transition,
            .code = .directory_transition_unsafe,
            .path = claim.path,
            .package = item.identity.name,
        });
    if (entries != 0) return builder.fail(.{
        .surface = .transition,
        .code = .directory_transition_unsafe,
        .path = claim.path,
        .package = item.identity.name,
    });

    var retiring: [1]u32 = undefined;
    var retiring_slice: []const u32 = &.{};
    if (item.owner_index) |own| {
        retiring[0] = own;
        retiring_slice = retiring[0..1];
    }
    const surviving = builder.ownership.hasSurvivingDescendant(
        claim.path,
        retiring_slice,
        builder.limits.max_descendant_scan,
        &buffer,
    ) catch return builder.fail(.{
        .surface = .transition,
        .code = .path_limit,
        .path = claim.path,
        .package = item.identity.name,
    });
    if (surviving) return builder.fail(.{
        .surface = .transition,
        .code = .prefix_transition_unsafe,
        .path = claim.path,
        .package = item.identity.name,
    });

    // A path this same transaction publishes under the directory would be
    // published into something that is no longer a directory.
    const prefix = std.fmt.bufPrint(&buffer, "{s}/", .{claim.path}) catch
        return builder.fail(.{
            .surface = .transition,
            .code = .invalid_path,
            .path = claim.path,
            .package = item.identity.name,
        });
    builder.transition_scans += builder.published.count() + item.claims.len;
    if (builder.transition_scans > builder.limits.max_descendant_scan) return builder.fail(.{
        .surface = .transition,
        .code = .path_limit,
        .path = claim.path,
        .package = item.identity.name,
    });
    var published = builder.published.keyIterator();
    while (published.next()) |key| {
        if (std.mem.startsWith(u8, key.*, prefix)) return builder.fail(.{
            .surface = .transition,
            .code = .directory_transition_unsafe,
            .path = claim.path,
            .package = item.identity.name,
        });
    }
    for (item.claims) |other| {
        if (std.mem.startsWith(u8, other.path, prefix)) return builder.fail(.{
            .surface = .transition,
            .code = .directory_transition_unsafe,
            .path = claim.path,
            .package = item.identity.name,
        });
    }
}

/// Creates the parent directories a payload needs but neither ships nor
/// finds. They are published with dpkg's default `0755 root:root` and are
/// deliberately not recorded as owned paths, exactly like the directories
/// dpkg creates on the way to an archive entry.
fn synthesizeAncestors(builder: *Builder, item: *PackageWork, package: u32) PlanError!void {
    var missing: std.ArrayList([]const u8) = .empty;
    defer missing.deinit(builder.allocator);
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(builder.allocator);

    for (item.paths.items) |planned| {
        const resolved = root_fs.Path.init(planned.path) catch
            return builder.fail(.{
                .surface = .transition,
                .code = .invalid_path,
                .path = planned.path,
                .package = item.identity.name,
            });
        var cursor = resolved.parent();
        while (cursor) |ancestor| : (cursor = ancestor.parent()) {
            // An ancestor this transaction publishes as something other than
            // a directory would swallow every path below it, so it is refused
            // here rather than discovered as a failed syscall.
            if (builder.published.get(ancestor.text)) |kind| {
                if (kind != .directory) return builder.fail(.{
                    .surface = .transition,
                    .code = .prefix_transition_unsafe,
                    .path = ancestor.text,
                    .package = item.identity.name,
                });
                break;
            }
            if (seen.contains(ancestor.text)) break;
            if (builder.retained_directory_paths.contains(ancestor.text))
                break;
            if (builder.planned_removals.contains(ancestor.text) or
                hasPlannedRemovalAncestor(builder, ancestor))
            {
                try seen.put(builder.allocator, ancestor.text, {});
                const diagnostic: Diagnostic = .{
                    .surface = .transition,
                    .code = .path_limit,
                    .path = ancestor.text,
                    .package = item.identity.name,
                };
                try builder.chargePath(diagnostic);
                try builder.chargeIntent(diagnostic);
                try missing.append(builder.allocator, ancestor.text);
                continue;
            }
            const found = builder.request.root.entryIfExists(ancestor) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return builder.fail(.{
                    .surface = .transition,
                    .code = .root_unreadable,
                    .path = ancestor.text,
                    .package = item.identity.name,
                }),
            };
            if (found) |entry| {
                if (entry.kind == .directory) {
                    var observed = try rootDirectoryObservation(
                        builder,
                        ancestor,
                        item.identity.name,
                    );
                    defer observed.deinit();
                    try retainDirectoryEvidence(builder, ancestor.text, .{
                        .kind = .directory,
                        .owned = builder.ownership.owned(ancestor.text),
                        .modeled = observed.entry.modeled,
                        .mode = observed.entry.mode,
                        .uid = observed.entry.uid,
                        .gid = observed.entry.gid,
                        .size = observed.entry.size,
                        .device = observed.entry.device,
                        .inode = observed.entry.inode,
                        .link_count = observed.entry.link_count,
                        .modified_nanoseconds = observed.entry.modified_nanoseconds,
                        .change_nanoseconds = observed.change_nanoseconds,
                        .directory_sha256 = observed.digest,
                        .directory_entries = observed.members.len,
                    });
                    break;
                }
                return builder.fail(.{
                    .surface = .transition,
                    .code = .prefix_transition_unsafe,
                    .path = ancestor.text,
                    .package = item.identity.name,
                });
            }
            try seen.put(builder.allocator, ancestor.text, {});
            const diagnostic: Diagnostic = .{
                .surface = .transition,
                .code = .path_limit,
                .path = ancestor.text,
                .package = item.identity.name,
            };
            try builder.chargePath(diagnostic);
            try builder.chargeIntent(diagnostic);
            try missing.append(builder.allocator, ancestor.text);
        }
    }
    if (missing.items.len == 0) return;
    std.mem.sort([]const u8, missing.items, {}, lessPath);
    for (missing.items) |path| {
        const owned = try builder.arena.dupe(u8, path);
        try builder.published.put(builder.allocator, owned, .directory);
        try item.paths.append(builder.allocator, .{
            .path = owned,
            .absolute = try absoluteSpelling(builder, owned),
            .archive_path = owned,
            .kind = .directory,
            .mode = 0o755,
            .uid = 0,
            .gid = 0,
            .modified_nanoseconds = null,
            .package = package,
            .disposition = .create,
            .synthesized = true,
        });
    }
}

fn hasPlannedRemovalAncestor(builder: *const Builder, path: root_fs.Path) bool {
    var cursor = path.parent();
    while (cursor) |ancestor| : (cursor = ancestor.parent()) {
        if (builder.planned_removals.contains(ancestor.text)) return true;
    }
    return false;
}

fn lessPath(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn greaterPath(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .gt;
}

// ---------------------------------------------------------------------------
// Obsolete paths
// ---------------------------------------------------------------------------

/// Every path the replaced generation owned that the new payload does not
/// ship. Files go first and directories deepest-first, so a directory this
/// transaction empties can still be removed while a directory somebody else
/// still uses is left exactly as dpkg leaves it.
const FinalRemoval = struct {
    path: []const u8,
    package: u32,
};

fn planFinalRemovals(builder: *Builder) PlanError!void {
    var candidates: std.ArrayList(FinalRemoval) = .empty;
    defer candidates.deinit(builder.allocator);
    var index: usize = 0;
    while (index < builder.ownership.entries.len) {
        const path = builder.ownership.entries[index].path;
        var last = index;
        while (last < builder.ownership.entries.len and
            std.mem.eql(u8, builder.ownership.entries[last].path, path)) : (last += 1)
        {}
        try builder.chargeWork(1, .{
            .surface = .ownership,
            .code = .path_limit,
            .path = path,
        });
        var retiring_package: ?u32 = null;
        var survives = builder.transaction_claims.get(path) != null;
        for (builder.ownership.entries[index..last]) |owned| {
            if (builder.owner_work.get(owned.owner)) |work_index| {
                if (transactionPackageClaims(builder, path, work_index) or
                    preservesConffilePath(&builder.work.items[work_index], path))
                {
                    survives = true;
                } else if (retiring_package == null or
                    work_index < retiring_package.?)
                {
                    retiring_package = work_index;
                }
            } else if (!displacesOwnerPath(builder, owned.owner, path)) {
                survives = true;
            }
        }
        if (!survives and retiring_package != null)
            try candidates.append(builder.allocator, .{
                .path = path,
                .package = retiring_package.?,
            });
        index = last;
    }
    std.mem.sort(FinalRemoval, candidates.items, {}, struct {
        fn greater(_: void, left: FinalRemoval, right: FinalRemoval) bool {
            return switch (std.mem.order(u8, left.path, right.path)) {
                .gt => true,
                .lt => false,
                .eq => left.package < right.package,
            };
        }
    }.greater);

    var removing: std.StringHashMapUnmanaged(void) = .empty;
    defer removing.deinit(builder.allocator);
    for (candidates.items) |candidate| {
        const item = &builder.work.items[candidate.package];
        const path = candidate.path;
        var observed = try observeRootState(
            builder,
            path,
            item.identity.name,
            false,
            true,
        ) orelse continue;
        defer observed.deinit();
        const previous = observed.state;
        if (builder.final_claim_ancestors.get(path)) |requirement| {
            if (requirement.kind != .directory)
                return builder.fail(.{
                    .surface = .transition,
                    .code = .prefix_transition_unsafe,
                    .path = path,
                });
            if (previous.kind == .directory) {
                try retainDirectoryEvidence(builder, path, previous);
                continue;
            }
        }
        if (builder.removal_count >= builder.limits.max_removals)
            return builder.fail(.{
                .surface = .ownership,
                .code = .path_limit,
                .path = path,
                .package = item.identity.name,
            });
        if (previous.kind == .directory) {
            if (!try emptiedDirectory(
                builder,
                path,
                observed.directory_members,
                removing,
                item,
            )) continue;
            const diagnostic: Diagnostic = .{
                .surface = .ownership,
                .code = .path_limit,
                .path = path,
                .package = item.identity.name,
            };
            try builder.chargePath(diagnostic);
            try builder.chargeIntent(diagnostic);
            builder.removal_count += 1;
            try removing.put(builder.allocator, path, {});
            try builder.planned_removals.put(
                builder.allocator,
                path,
                .directory,
            );
            try item.removals.append(builder.allocator, .{
                .path = path,
                .absolute = try absoluteSpelling(builder, path),
                .directory = true,
                .package = candidate.package,
                .previous = previous,
            });
            continue;
        }
        const diagnostic: Diagnostic = .{
            .surface = .ownership,
            .code = .path_limit,
            .path = path,
            .package = item.identity.name,
        };
        try builder.chargePath(diagnostic);
        try builder.chargeIntent(diagnostic);
        builder.removal_count += 1;
        try removing.put(builder.allocator, path, {});
        try builder.planned_removals.put(
            builder.allocator,
            path,
            previous.kind,
        );
        try item.removals.append(builder.allocator, .{
            .path = path,
            .absolute = try absoluteSpelling(builder, path),
            .directory = false,
            .package = candidate.package,
            .previous = previous,
        });
    }
}

fn retainDirectoryEvidence(
    builder: *Builder,
    path: []const u8,
    previous: PreviousState,
) PlanError!void {
    const found = try builder.retained_directory_paths.getOrPut(
        builder.allocator,
        path,
    );
    if (found.found_existing) return;
    try builder.chargePath(.{
        .surface = .transition,
        .code = .path_limit,
        .path = path,
    });
    try builder.directory_observations.put(
        builder.allocator,
        path,
        previous,
    );
    try builder.retained_directories.append(builder.allocator, .{
        .path = path,
        .previous = previous,
    });
}

fn observeFinalDirectoryPrefixes(builder: *Builder) PlanError!void {
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(builder.allocator);
    var keys = builder.final_claim_ancestors.keyIterator();
    while (keys.next()) |path| try paths.append(builder.allocator, path.*);
    std.mem.sort([]const u8, paths.items, {}, lessPath);
    for (paths.items) |path| {
        if (builder.final_claim_ancestors.get(path).?.kind != .directory)
            return builder.fail(.{
                .surface = .transition,
                .code = .prefix_transition_unsafe,
                .path = path,
            });
        if (!builder.ownership.owned(path)) continue;
        if (builder.transaction_claims.get(path)) |claims| {
            if (claims.representative.kind == .directory) continue;
        }
        if (builder.planned_removals.contains(path) or
            builder.retained_directory_paths.contains(path))
            continue;
        const resolved = root_fs.Path.init(path) catch
            return builder.fail(.{
                .surface = .transition,
                .code = .invalid_path,
                .path = path,
            });
        if (hasPlannedRemovalAncestor(builder, resolved)) continue;
        var observed = try observeRootState(
            builder,
            path,
            "",
            false,
            true,
        ) orelse
            continue;
        defer observed.deinit();
        if (observed.state.kind != .directory)
            return builder.fail(.{
                .surface = .transition,
                .code = .prefix_transition_unsafe,
                .path = path,
            });
        try retainDirectoryEvidence(builder, path, observed.state);
    }
}

fn sortRetainedDirectories(builder: *Builder) void {
    std.mem.sort(
        RetainedDirectory,
        builder.retained_directories.items,
        {},
        lessRetainedDirectory,
    );
}

fn lessRetainedDirectory(
    _: void,
    left: RetainedDirectory,
    right: RetainedDirectory,
) bool {
    return std.mem.order(u8, left.path, right.path) == .lt;
}

fn transactionPackageClaims(
    builder: *const Builder,
    path: []const u8,
    package: u32,
) bool {
    const claims = builder.transaction_claims.get(path) orelse return false;
    return claims.by_package.contains(package);
}

/// True when a directory holds nothing but entries this transaction has
/// already decided to remove. dpkg leaves a directory that still holds
/// anything else, and so does this planner: the removal is simply not
/// planned, instead of being planned and then refused.
fn emptiedDirectory(
    builder: *Builder,
    path: []const u8,
    members: []const root_fs.DirectoryMember,
    removing: std.StringHashMapUnmanaged(void),
    item: *const PackageWork,
) PlanError!bool {
    for (members) |child| {
        var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        const spelling = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ path, child.name }) catch
            return builder.fail(.{
                .surface = .ownership,
                .code = .invalid_path,
                .path = path,
                .package = item.identity.name,
            });
        if (!removing.contains(spelling)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Case aliases
// ---------------------------------------------------------------------------

fn indexCaseGraph(builder: *Builder) PlanError!void {
    for (alias_directories) |name|
        try recordPathPrefixes(builder, name, null);
    for (builder.aliases.aliases) |alias|
        try recordPathPrefixes(builder, alias.to, .directory);
    try recordPathPrefixes(
        builder,
        package_database.database_directory,
        .directory,
    );
    for (builder.ownership.entries) |entry|
        try recordPathPrefixes(builder, entry.path, null);
    var conffile_paths: std.ArrayList([]const u8) = .empty;
    defer conffile_paths.deinit(builder.allocator);
    var conffiles = builder.installed_conffiles.keyIterator();
    while (conffiles.next()) |path|
        try conffile_paths.append(builder.allocator, path.*);
    std.mem.sort([]const u8, conffile_paths.items, {}, lessPath);
    for (conffile_paths.items) |path|
        try recordPathPrefixes(builder, path, null);
    for (builder.work.items) |item| {
        for (item.claims) |claim|
            try recordPathPrefixes(builder, claim.path, claim.kind);
    }
}

fn recordPathPrefixes(
    builder: *Builder,
    path: []const u8,
    final_kind: ?Kind,
) PlanError!void {
    var index: usize = 0;
    while (index < path.len) : (index += 1) {
        if (path[index] != '/') continue;
        try recordCasePath(builder, path[0..index], null, true);
    }
    try recordCasePath(builder, path, final_kind, false);
}

/// Records every typed path prefix. Item 10 has no authenticated casefold
/// capability, so distinct folded spellings are refused even when both are
/// directories; type information additionally catches an exact non-directory
/// that another final path requires as an ancestor.
fn recordCasePath(
    builder: *Builder,
    path: []const u8,
    kind: ?Kind,
    requires_directory: bool,
) PlanError!void {
    try builder.chargeWork(1, .{
        .surface = .alias,
        .code = .path_limit,
        .path = path,
    });
    for (path) |byte| {
        if (byte >= 0x80) return builder.fail(.{
            .surface = .alias,
            .code = .casefold_unknown,
            .path = path,
        });
    }
    var scratch: [root_fs.maximum_path_bytes]u8 = undefined;
    const folded = scratch[0..path.len];
    for (path, 0..) |byte, index| folded[index] = std.ascii.toLower(byte);
    const existing = builder.folded.getPtr(folded);
    if (existing == null) {
        const entry_bytes = std.math.add(
            usize,
            folded.len,
            @sizeOf(FoldedPath) + @sizeOf([]u8) + 32,
        ) catch return builder.fail(.{
            .surface = .alias,
            .code = .case_alias_limit,
            .path = path,
        });
        const next = std.math.add(
            usize,
            builder.case_index_bytes,
            entry_bytes,
        ) catch return builder.fail(.{
            .surface = .alias,
            .code = .case_alias_limit,
            .path = path,
        });
        if (next > builder.limits.max_case_index_bytes)
            return builder.fail(.{
                .surface = .alias,
                .code = .case_alias_limit,
                .path = path,
            });
        const key = try builder.allocator.dupe(u8, folded);
        errdefer builder.allocator.free(key);
        try builder.folded_keys.append(builder.allocator, key);
        errdefer _ = builder.folded_keys.pop();
        try builder.folded.put(builder.allocator, key, .{
            .spelling = path,
            .kind = kind,
            .requires_directory = requires_directory,
        });
        builder.case_index_bytes = next;
        return;
    }
    const found = existing.?;
    if (std.mem.eql(u8, found.spelling, path)) {
        const existing_kind = found.kind;
        if ((found.requires_directory and
            kind != null and kind.? != .directory) or
            (requires_directory and
                existing_kind != null and existing_kind.? != .directory))
            return builder.fail(.{
                .surface = .transition,
                .code = .prefix_transition_unsafe,
                .path = path,
            });
        if (existing_kind) |value| {
            if (kind) |incoming| {
                if (value != incoming) return builder.fail(.{
                    .surface = .alias,
                    .code = .alias_kind_conflict,
                    .path = path,
                });
            }
        } else found.kind = kind;
        found.requires_directory = found.requires_directory or requires_directory;
        return;
    }
    if (builder.case_aliases.items.len >= builder.limits.max_case_aliases)
        return builder.fail(.{
            .surface = .alias,
            .code = .case_alias_limit,
            .path = path,
            .holder = found.spelling,
        });
    try builder.case_aliases.append(builder.allocator, .{
        .first = found.spelling,
        .second = path,
    });
}

/// The item-10 planner has no authenticated casefold capability. Any two
/// distinct spellings that ASCII-fold together are therefore ambiguous and
/// refused rather than guessed from the host filesystem.
fn proveCaseEvidence(builder: *Builder) PlanError!void {
    for (builder.case_aliases.items) |pair| {
        return builder.fail(.{
            .surface = .alias,
            .code = .case_alias,
            .path = pair.second,
            .holder = pair.first,
        });
    }
}

// ---------------------------------------------------------------------------
// File triggers
// ---------------------------------------------------------------------------

/// A file trigger interested in a path this transaction publishes would have
/// to be activated. Trigger processing belongs to a later roadmap item, so
/// the transaction is handed off instead of silently skipping the activation.
fn inspectPublicationTriggers(builder: *Builder) PlanError!void {
    if (builder.request.trigger_execution) return;
    const state = builder.database.model.triggers;
    if (state.interests.len == 0) return;
    var packages_by_name: std.StringHashMapUnmanaged(
        std.ArrayListUnmanaged(u32),
    ) = .empty;
    defer {
        var lists = packages_by_name.valueIterator();
        while (lists.next()) |list| list.deinit(builder.allocator);
        packages_by_name.deinit(builder.allocator);
    }
    var identities: std.StringHashMapUnmanaged(u32) = .empty;
    defer identities.deinit(builder.allocator);
    for (builder.database.model.packages, 0..) |record, index| {
        const diagnostic: Diagnostic = .{
            .surface = .ownership,
            .code = .path_limit,
            .package = record.name,
        };
        try builder.chargeWork(1, diagnostic);
        const identity_bytes = std.math.add(
            usize,
            record.name.len,
            record.architecture.len,
        ) catch return builder.fail(diagnostic);
        const charged_identity_bytes = std.math.add(
            usize,
            identity_bytes,
            1 + @sizeOf(u32) * 3 + 64,
        ) catch return builder.fail(diagnostic);
        try builder.chargeTriggerIndex(charged_identity_bytes, diagnostic);
        const group = try packages_by_name.getOrPut(
            builder.allocator,
            record.name,
        );
        if (!group.found_existing) group.value_ptr.* = .empty;
        try group.value_ptr.append(builder.allocator, @intCast(index));
        const key = try std.fmt.allocPrint(
            builder.arena,
            "{s}\x00{s}",
            .{ record.name, record.architecture },
        );
        try identities.put(builder.allocator, key, @intCast(index));
    }

    var affected: std.StringHashMapUnmanaged(void) = .empty;
    defer affected.deinit(builder.allocator);
    var affected_paths: std.ArrayList([]const u8) = .empty;
    defer affected_paths.deinit(builder.allocator);
    var published = builder.published.keyIterator();
    while (published.next()) |path|
        try affected_paths.append(builder.allocator, path.*);
    for (builder.work.items) |item| {
        for (item.removals.items) |removal|
            try affected_paths.append(builder.allocator, removal.path);
    }
    std.mem.sort([]const u8, affected_paths.items, {}, lessPath);
    for (affected_paths.items) |path| {
        var cursor: ?root_fs.Path = root_fs.Path.init(path) catch
            return builder.fail(.{
                .surface = .transition,
                .code = .invalid_path,
                .path = path,
            });
        while (cursor) |current| : (cursor = current.parent()) {
            try builder.chargeWork(1, .{
                .surface = .ownership,
                .code = .path_limit,
                .path = current.text,
            });
            if (!affected.contains(current.text)) {
                try builder.chargeTriggerIndex(current.text.len + 48, .{
                    .surface = .ownership,
                    .code = .path_limit,
                    .path = current.text,
                });
                try affected.put(builder.allocator, current.text, {});
            }
        }
    }

    var emitted: std.StringHashMapUnmanaged(
        std.AutoHashMapUnmanaged(u32, void),
    ) = .empty;
    defer {
        var sets = emitted.valueIterator();
        while (sets.next()) |set| set.deinit(builder.allocator);
        emitted.deinit(builder.allocator);
    }
    for (state.interests) |interest| {
        try builder.chargeWork(1, .{
            .surface = .ownership,
            .code = .path_limit,
            .path = interest.trigger,
            .package = interest.package.name,
        });
        const relative = relativeListPath(interest.trigger) orelse continue;
        var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        const canonical = canonicalAliasPath(
            builder.aliases,
            relative,
            &buffer,
        ) orelse return builder.fail(.{
            .surface = .transition,
            .code = .invalid_path,
            .path = relative,
        });
        if (!affected.contains(canonical)) continue;
        const identity_set = emitted.getPtr(canonical) orelse create: {
            try builder.chargeTriggerIndex(canonical.len + 64, .{
                .surface = .ownership,
                .code = .path_limit,
                .path = canonical,
            });
            const owned = try builder.arena.dupe(u8, canonical);
            try emitted.put(builder.allocator, owned, .empty);
            break :create emitted.getPtr(owned).?;
        };
        if (interest.package.architecture.len == 0) {
            const matches = packages_by_name.get(interest.package.name) orelse
                continue;
            for (matches.items) |package_index| {
                try emitTriggerHandoff(
                    builder,
                    identity_set,
                    package_index,
                    canonical,
                );
            }
        } else {
            var key_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
            const key = std.fmt.bufPrint(
                &key_buffer,
                "{s}\x00{s}",
                .{
                    interest.package.name,
                    interest.package.architecture,
                },
            ) catch return builder.fail(.{
                .surface = .ownership,
                .code = .path_limit,
                .package = interest.package.name,
                .architecture = interest.package.architecture,
            });
            const package_index = identities.get(key) orelse continue;
            try emitTriggerHandoff(
                builder,
                identity_set,
                package_index,
                canonical,
            );
        }
    }
}

fn emitTriggerHandoff(
    builder: *Builder,
    emitted: *std.AutoHashMapUnmanaged(u32, void),
    package_index: u32,
    trigger: []const u8,
) PlanError!void {
    try builder.chargeWork(1, .{
        .surface = .ownership,
        .code = .path_limit,
        .path = trigger,
    });
    if (emitted.contains(package_index)) return;
    try builder.chargeTriggerIndex(@sizeOf(u32) + 32, .{
        .surface = .ownership,
        .code = .path_limit,
        .path = trigger,
    });
    try emitted.put(builder.allocator, package_index, {});
    const record = builder.database.model.packages[package_index];
    try builder.deferFeature(.{
        .feature = .trigger,
        .package = record.name,
        .architecture = record.architecture,
        .detail = trigger,
    });
}

// ---------------------------------------------------------------------------
// Published package records
// ---------------------------------------------------------------------------

/// Canonical `.list` and `md5sums` content for one unpacked package.
///
/// The list is dpkg's exact ownership publication: the root record `/.` plus
/// every archive-owned path in canonical absolute spelling. Synthesized
/// parent directories are not published, because the package does not own
/// them. `md5sums` covers the regular payload files and the hard links that
/// share their content, and never a directory or a symbolic link.
fn publishRecords(builder: *Builder, item: *PackageWork) PlanError!void {
    try item.list_paths.append(builder.allocator, package_database.root_list_path);
    for (item.paths.items) |planned| {
        if (planned.synthesized) continue;
        const archive_file = if (planned.archive_entry) |index|
            item.model.files[index]
        else
            null;
        const conffile = if (archive_file) |file|
            file.conffile and builder.request.conffiles == .unpack
        else
            false;
        const logical_path = if (conffile)
            (plannedConffile(item, (try normalizePath(
                builder,
                archive_file.?.path,
            )).path) orelse return builder.fail(.{
                .surface = .publication,
                .code = .program_incomplete,
                .path = planned.path,
                .package = item.identity.name,
            })).path
        else
            planned.path;
        try item.list_paths.append(
            builder.allocator,
            if (conffile)
                try absoluteSpelling(builder, logical_path)
            else
                planned.absolute,
        );
        switch (planned.kind) {
            .regular, .hardlink => try item.md5sums.append(builder.allocator, .{
                .path = logical_path,
                .digest = planned.md5.?,
            }),
            .directory, .symlink => {},
        }
    }
    for (item.conffiles.items) |conffile| {
        if (conffile.action != .mark_obsolete) continue;
        try item.list_paths.append(
            builder.allocator,
            try absoluteSpelling(builder, conffile.path),
        );
    }
    std.mem.sort([]const u8, item.list_paths.items[1..], {}, lessPath);
    std.mem.sort(package_database.Md5sumEntry, item.md5sums.items, {}, lessMd5sum);
}

fn lessMd5sum(
    _: void,
    left: package_database.Md5sumEntry,
    right: package_database.Md5sumEntry,
) bool {
    return std.mem.order(u8, left.path, right.path) == .lt;
}

/// dpkg's `status` field order. Unknown but well-formed control fields are
/// retained after it, in their archive order, so nothing a maintainer shipped
/// is silently dropped.
const status_field_order = [_][]const u8{
    "Package",
    "Essential",
    "Protected",
    "Important",
    "Status",
    "Priority",
    "Section",
    "Installed-Size",
    "Origin",
    "Maintainer",
    "Bugs",
    "Architecture",
    "Multi-Arch",
    "Source",
    "Version",
    "Config-Version",
    "Conffiles",
    "Replaces",
    "Provides",
    "Depends",
    "Pre-Depends",
    "Recommends",
    "Suggests",
    "Breaks",
    "Conflicts",
    "Enhances",
    "Description",
    "Homepage",
};

/// Fields the package database owns rather than the archive, plus the
/// repository index fields that never belong in `status`.
const status_excluded_fields = [_][]const u8{
    "Status",
    "Config-Version",
    "Conffiles",
    "Triggers-Pending",
    "Triggers-Awaited",
    "Filename",
    "Size",
    "MD5sum",
    "SHA1",
    "SHA256",
    "SHA512",
    "Description-md5",
};

fn excludedStatusField(name: []const u8) bool {
    for (status_excluded_fields) |excluded| {
        if (std.ascii.eqlIgnoreCase(excluded, name)) return true;
    }
    return false;
}

fn orderedStatusField(name: []const u8) bool {
    for (status_field_order) |ordered| {
        if (std.ascii.eqlIgnoreCase(ordered, name)) return true;
    }
    return false;
}

fn statusFields(
    builder: *Builder,
    item: *PackageWork,
    model: *const archive_application.Model,
    state: dpkg_status.CurrentState,
) PlanError![]const package_database.StatusField {
    const paragraphs = model.document.deb822_document.paragraphs;
    if (paragraphs.len == 0) return builder.fail(.{
        .surface = .publication,
        .code = .status_field_invalid,
        .package = item.identity.name,
    });
    const control = paragraphs[0];

    var field_count: usize = 1 +
        @as(usize, @intFromBool(item.configured_version != null)) +
        @as(usize, @intFromBool(item.conffile_records.items.len != 0));
    for (status_field_order) |name| {
        if (std.ascii.eqlIgnoreCase(name, "Status") or
            std.ascii.eqlIgnoreCase(name, "Config-Version") or
            std.ascii.eqlIgnoreCase(name, "Conffiles")) continue;
        const field = control.get(name) orelse continue;
        if (!excludedStatusField(field.name)) field_count += 1;
    }
    for (control.fields) |field| {
        if (!excludedStatusField(field.name) and
            !orderedStatusField(field.name)) field_count += 1;
    }
    if (field_count > builder.limits.max_status_fields) return builder.fail(.{
        .surface = .publication,
        .code = .status_field_invalid,
        .package = item.identity.name,
    });

    var fields: std.ArrayList(package_database.StatusField) = .empty;
    defer fields.deinit(builder.allocator);
    try fields.ensureTotalCapacity(builder.allocator, field_count);

    const status_value = try std.fmt.allocPrint(builder.arena, "install ok {s}", .{
        package_database.currentStateSpelling(state),
    });
    const status_lines = try builder.arena.alloc([]const u8, 1);
    status_lines[0] = status_value;

    for (status_field_order) |name| {
        if (std.ascii.eqlIgnoreCase(name, "Status")) {
            try fields.append(builder.allocator, .{
                .name = "Status",
                .value_lines = status_lines,
            });
            continue;
        }
        if (std.ascii.eqlIgnoreCase(name, "Config-Version")) {
            if (item.configured_version) |version| {
                const lines = try builder.arena.alloc([]const u8, 1);
                lines[0] = version;
                try fields.append(builder.allocator, .{
                    .name = "Config-Version",
                    .value_lines = lines,
                });
            }
            continue;
        }
        if (std.ascii.eqlIgnoreCase(name, "Conffiles")) {
            if (item.conffile_records.items.len != 0)
                try fields.append(
                    builder.allocator,
                    try package_database.conffilesField(
                        builder.arena,
                        item.conffile_records.items,
                    ),
                );
            continue;
        }
        const field = control.get(name) orelse continue;
        if (excludedStatusField(field.name)) continue;
        try fields.append(builder.allocator, .{
            .name = field.name,
            .value_lines = try valueLines(builder, field.value_lines),
        });
    }
    for (control.fields) |field| {
        if (excludedStatusField(field.name)) continue;
        if (orderedStatusField(field.name)) continue;
        try fields.append(builder.allocator, .{
            .name = field.name,
            .value_lines = try valueLines(builder, field.value_lines),
        });
    }
    std.debug.assert(fields.items.len == field_count);
    return builder.arena.dupe(package_database.StatusField, fields.items);
}

fn valueLines(
    builder: *Builder,
    lines: []const @import("deb822.zig").ValueLine,
) PlanError![]const []const u8 {
    const owned = try builder.arena.alloc([]const u8, lines.len);
    for (lines, 0..) |line, index| owned[index] = line.text;
    return owned;
}

// ---------------------------------------------------------------------------
// Lowering
// ---------------------------------------------------------------------------

const OrderedPath = struct {
    package: u32,
    path: u32,
};

fn lessOrderedDirectory(context: []const PackageWork, left: OrderedPath, right: OrderedPath) bool {
    const left_path = context[left.package].paths.items[left.path].path;
    const right_path = context[right.package].paths.items[right.path].path;
    return switch (std.mem.order(u8, left_path, right_path)) {
        .lt => true,
        .gt => false,
        .eq => left.package < right.package,
    };
}

const OrderedRemoval = struct {
    package: u32,
    removal: u32,
};

fn greaterOrderedRemoval(
    context: []const PackageWork,
    left: OrderedRemoval,
    right: OrderedRemoval,
) bool {
    const left_path = context[left.package].removals.items[left.removal].path;
    const right_path = context[right.package].removals.items[right.removal].path;
    return switch (std.mem.order(u8, left_path, right_path)) {
        .gt => true,
        .lt => false,
        .eq => left.package < right.package,
    };
}

fn ownPackageIdentity(
    allocator: std.mem.Allocator,
    identity: native_program.PackageIdentity,
) std.mem.Allocator.Error!native_program.PackageIdentity {
    return .{
        .name = try allocator.dupe(u8, identity.name),
        .version = try allocator.dupe(u8, identity.version),
        .architecture = try allocator.dupe(u8, identity.architecture),
    };
}

fn ownDatabaseIdentity(
    allocator: std.mem.Allocator,
    identity: package_database.Identity,
) std.mem.Allocator.Error!package_database.Identity {
    return .{
        .name = try allocator.dupe(u8, identity.name),
        .architecture = try allocator.dupe(u8, identity.architecture),
    };
}

fn ownRemoval(
    allocator: std.mem.Allocator,
    removal: Removal,
) std.mem.Allocator.Error!Removal {
    var owned = removal;
    owned.path = try allocator.dupe(u8, removal.path);
    owned.absolute = try allocator.dupe(u8, removal.absolute);
    owned.previous = try ownPreviousState(allocator, removal.previous);
    return owned;
}

fn ownPreviousState(
    allocator: std.mem.Allocator,
    previous: PreviousState,
) std.mem.Allocator.Error!PreviousState {
    var copy = previous;
    copy.link_target = if (previous.link_target) |value|
        try allocator.dupe(u8, value)
    else
        null;
    return copy;
}

fn ownPlannedPath(
    allocator: std.mem.Allocator,
    planned: PlannedPath,
) std.mem.Allocator.Error!PlannedPath {
    var owned = planned;
    owned.path = try allocator.dupe(u8, planned.path);
    owned.absolute = try allocator.dupe(u8, planned.absolute);
    owned.archive_path = try allocator.dupe(u8, planned.archive_path);
    owned.link_literal = if (planned.link_literal) |value|
        try allocator.dupe(u8, value)
    else
        null;
    owned.link_source = if (planned.link_source) |value|
        try allocator.dupe(u8, value)
    else
        null;
    if (planned.link_source_previous) |previous|
        owned.link_source_previous = try ownPreviousState(
            allocator,
            previous,
        );
    if (planned.previous) |previous| {
        owned.previous = try ownPreviousState(allocator, previous);
    }
    return owned;
}

fn ownResolution(
    allocator: std.mem.Allocator,
    resolution: Resolution,
) std.mem.Allocator.Error!Resolution {
    return .{
        .path = try allocator.dupe(u8, resolution.path),
        .holder = try ownDatabaseIdentity(allocator, resolution.holder),
        .claimant = try ownDatabaseIdentity(allocator, resolution.claimant),
        .resolution = resolution.resolution,
    };
}

fn ownFilesystemChange(
    allocator: std.mem.Allocator,
    change: FilesystemChange,
) std.mem.Allocator.Error!FilesystemChange {
    return switch (change) {
        .remove => |value| .{ .remove = try ownRemoval(allocator, value) },
        .directory => |value| .{ .directory = .{
            .path = try allocator.dupe(u8, value.path),
            .mode = value.mode,
            .uid = value.uid,
            .gid = value.gid,
            .modified_nanoseconds = value.modified_nanoseconds,
        } },
        .file => |value| .{ .file = .{
            .path = try allocator.dupe(u8, value.path),
            .artifact = value.artifact,
            .archive_entry = value.archive_entry,
            .sha256 = value.sha256,
            .mode = value.mode,
            .uid = value.uid,
            .gid = value.gid,
            .modified_nanoseconds = value.modified_nanoseconds,
        } },
        .symlink => |value| .{ .symlink = .{
            .path = try allocator.dupe(u8, value.path),
            .target = try allocator.dupe(u8, value.target),
            .uid = value.uid,
            .gid = value.gid,
            .modified_nanoseconds = value.modified_nanoseconds,
        } },
        .hardlink => |value| .{ .hardlink = .{
            .path = try allocator.dupe(u8, value.path),
            .source = try allocator.dupe(u8, value.source),
        } },
    };
}

/// Turns the resolved package plans into one ordered filesystem description
/// and one database publication plan.
///
/// The order is the whole contract: obsolete paths are removed deepest first,
/// then every directory is published parents first, then payload content in
/// archive order so a hard link never precedes the file it links, and finally
/// the database generation in its own order. Nothing is reordered afterwards
/// by this planning slice.
fn lower(builder: *Builder, arena: *std.heap.ArenaAllocator) PlanError!Plan {
    var kinds: std.StringHashMapUnmanaged(Kind) = .empty;
    defer kinds.deinit(builder.allocator);
    var directories: std.ArrayList(OrderedPath) = .empty;
    defer directories.deinit(builder.allocator);
    var removals: std.ArrayList(OrderedRemoval) = .empty;
    defer removals.deinit(builder.allocator);

    for (builder.work.items, 0..) |item, package| {
        for (item.paths.items, 0..) |planned, index| {
            const found = try kinds.getOrPut(builder.allocator, planned.path);
            if (found.found_existing) {
                if (found.value_ptr.* != planned.kind) return builder.fail(.{
                    .surface = .lowering,
                    .code = .alias_kind_conflict,
                    .path = planned.path,
                    .package = item.identity.name,
                });
            } else found.value_ptr.* = planned.kind;
            if (planned.kind != .directory or !planned.publish) continue;
            try directories.append(builder.allocator, .{
                .package = @intCast(package),
                .path = @intCast(index),
            });
        }
        for (item.removals.items, 0..) |_, index| {
            try removals.append(builder.allocator, .{
                .package = @intCast(package),
                .removal = @intCast(index),
            });
        }
    }
    std.mem.sort(OrderedPath, directories.items, builder.work.items, lessOrderedDirectory);
    std.mem.sort(OrderedRemoval, removals.items, builder.work.items, greaterOrderedRemoval);

    var changes: std.ArrayList(FilesystemChange) = .empty;
    defer changes.deinit(builder.allocator);

    for (removals.items) |ordered| {
        const removal = builder.work.items[ordered.package].removals.items[ordered.removal];
        try changes.append(builder.allocator, .{ .remove = removal });
    }
    for (directories.items) |ordered| {
        const planned = builder.work.items[ordered.package].paths.items[ordered.path];
        try changes.append(builder.allocator, .{ .directory = .{
            .path = planned.path,
            .mode = planned.mode,
            .uid = planned.uid,
            .gid = planned.gid,
            .modified_nanoseconds = planned.modified_nanoseconds,
        } });
    }
    for (builder.work.items) |item| {
        for (item.paths.items) |planned| {
            if (!planned.publish) continue;
            switch (planned.kind) {
                .directory => continue,
                .regular => try changes.append(builder.allocator, .{ .file = .{
                    .path = planned.path,
                    .artifact = item.artifact,
                    .archive_entry = @intCast(planned.archive_entry orelse
                        return builder.fail(.{
                            .surface = .lowering,
                            .code = .unsupported_entry,
                            .path = planned.path,
                            .package = item.identity.name,
                        })),
                    .sha256 = planned.sha256 orelse return builder.fail(.{
                        .surface = .lowering,
                        .code = .unsupported_entry,
                        .path = planned.path,
                        .package = item.identity.name,
                    }),
                    .mode = planned.mode,
                    .uid = planned.uid,
                    .gid = planned.gid,
                    .modified_nanoseconds = planned.modified_nanoseconds orelse
                        return builder.fail(.{
                            .surface = .lowering,
                            .code = .unsupported_entry,
                            .path = planned.path,
                            .package = item.identity.name,
                        }),
                } }),
                .symlink => try changes.append(builder.allocator, .{ .symlink = .{
                    .path = planned.path,
                    .target = planned.link_literal.?,
                    .uid = planned.uid,
                    .gid = planned.gid,
                    .modified_nanoseconds = planned.modified_nanoseconds orelse
                        return builder.fail(.{
                            .surface = .lowering,
                            .code = .unsupported_entry,
                            .path = planned.path,
                            .package = item.identity.name,
                        }),
                } }),
                .hardlink => try changes.append(builder.allocator, .{ .hardlink = .{
                    .path = planned.path,
                    .source = planned.link_source.?,
                } }),
            }
        }
    }
    if (changes.items.len != builder.intent_count)
        return builder.fail(.{
            .surface = .lowering,
            .code = .path_limit,
        });

    var database_plan = try stageDatabase(builder);
    errdefer database_plan.deinit();

    const packages = try builder.arena.alloc(PackagePlan, builder.work.items.len);
    for (builder.work.items, 0..) |*item, index| {
        const paths = try builder.arena.alloc(PlannedPath, item.paths.items.len);
        for (item.paths.items, 0..) |planned, path_index|
            paths[path_index] = try ownPlannedPath(builder.arena, planned);
        const item_removals = try builder.arena.alloc(Removal, item.removals.items.len);
        for (item.removals.items, 0..) |removal, removal_index|
            item_removals[removal_index] = try ownRemoval(builder.arena, removal);
        const list_paths = try builder.arena.alloc([]const u8, item.list_paths.items.len);
        for (item.list_paths.items, 0..) |path, path_index|
            list_paths[path_index] = try builder.arena.dupe(u8, path);
        const md5sums = try builder.arena.alloc(
            package_database.Md5sumEntry,
            item.md5sums.items.len,
        );
        for (item.md5sums.items, 0..) |entry, md5_index| {
            md5sums[md5_index] = entry;
            md5sums[md5_index].path = try builder.arena.dupe(u8, entry.path);
        }
        const conffiles = try builder.arena.alloc(
            PlannedConffile,
            item.conffiles.items.len,
        );
        for (item.conffiles.items, 0..) |conffile, conffile_index| {
            conffiles[conffile_index] = conffile;
            conffiles[conffile_index].path = try builder.arena.dupe(
                u8,
                conffile.path,
            );
            conffiles[conffile_index].staged_path = if (conffile.staged_path) |path|
                try builder.arena.dupe(u8, path)
            else
                null;
            if (conffile.recorded) |recorded| {
                var copy = recorded;
                copy.path = try builder.arena.dupe(u8, recorded.path);
                conffiles[conffile_index].recorded = copy;
            }
        }
        const resolutions = try builder.arena.alloc(
            Resolution,
            item.resolutions.items.len,
        );
        for (item.resolutions.items, 0..) |resolution, resolution_index|
            resolutions[resolution_index] = try ownResolution(
                builder.arena,
                resolution,
            );
        packages[index] = .{
            .identity = try ownPackageIdentity(builder.arena, item.identity),
            .stem = try builder.arena.dupe(u8, item.stem),
            .artifact = item.artifact,
            .operation = item.operation,
            .bootstrapped = item.bootstrapped,
            .prior_version = if (item.prior_version) |value|
                try builder.arena.dupe(u8, value)
            else
                null,
            .configured_version = if (item.configured_version) |value|
                try builder.arena.dupe(u8, value)
            else
                null,
            .application_sha256 = item.application_sha256,
            .paths = paths,
            .removals = item_removals,
            .list_paths = list_paths,
            .md5sums = md5sums,
            .conffiles = conffiles,
            .resolutions = resolutions,
            .state = .unpacked,
        };
    }

    const pending = try builder.arena.alloc(native_program.PackageRef, packages.len);
    for (packages, 0..) |item, index| {
        pending[index] = .{
            .name = try builder.arena.dupe(u8, item.identity.name),
            .architecture = try builder.arena.dupe(u8, item.identity.architecture),
        };
    }

    const owned_aliases = try builder.arena.alloc(Alias, builder.aliases.aliases.len);
    for (owned_aliases, builder.aliases.aliases) |*copy, source| {
        copy.* = source;
        copy.from = try builder.arena.dupe(u8, source.from);
        copy.to = try builder.arena.dupe(u8, source.to);
        copy.link_target = try builder.arena.dupe(u8, source.link_target);
    }

    const owned_case_aliases = try builder.arena.alloc(
        CaseAlias,
        builder.case_aliases.items.len,
    );
    for (builder.case_aliases.items, 0..) |item, index| {
        owned_case_aliases[index] = .{
            .first = try builder.arena.dupe(u8, item.first),
            .second = try builder.arena.dupe(u8, item.second),
        };
    }
    const owned_displacements = try builder.arena.alloc(
        Displacement,
        builder.displacements.items.len,
    );
    for (builder.displacements.items, 0..) |item, index| {
        owned_displacements[index] = .{
            .path = try builder.arena.dupe(u8, item.path),
            .holder = try ownDatabaseIdentity(builder.arena, item.holder),
            .holder_index = item.holder_index,
            .claimant = try ownDatabaseIdentity(builder.arena, item.claimant),
        };
    }
    const owned_retained_directories = try builder.arena.alloc(
        RetainedDirectory,
        builder.retained_directories.items.len,
    );
    for (builder.retained_directories.items, 0..) |item, index| {
        owned_retained_directories[index] = .{
            .path = try builder.arena.dupe(u8, item.path),
            .previous = try ownPreviousState(builder.arena, item.previous),
        };
    }
    const owned_filesystem = try builder.arena.alloc(
        FilesystemChange,
        changes.items.len,
    );
    for (changes.items, 0..) |change, index|
        owned_filesystem[index] = try ownFilesystemChange(
            builder.arena,
            change,
        );

    const program_sha256 = parseHex(32, &builder.request.program.digest_sha256) orelse
        return builder.fail(.{ .surface = .program, .code = .program_incomplete });
    const authorization_sha256 = parseHex(
        32,
        &builder.request.program.authorization_sha256,
    ) orelse return builder.fail(.{
        .surface = .authorization,
        .code = .authorization_mismatch,
    });
    try revalidateDirectoryObservations(builder);
    const result: Plan = .{
        .filesystem = owned_filesystem,
        .database = database_plan,
        .packages = packages,
        .aliases = owned_aliases,
        .case_aliases = owned_case_aliases,
        .displacements = owned_displacements,
        .retained_directories = owned_retained_directories,
        .pending_configuration = pending,
        .program_sha256 = program_sha256,
        .authorization_sha256 = authorization_sha256,
        .path_count = builder.total_paths,
        .model_bytes = builder.model_allocator.peak,
        .compared_bytes = builder.compared_bytes,
        .work_units = builder.work_units,
        .digest = @splat(0),
        .arena = arena,
        .backing_allocator = builder.allocator,
    };
    var completed = result;
    completed.digest = planDigest(completed);
    return completed;
}

fn stageDatabase(builder: *Builder) PlanError!package_database_changes.Plan {
    var changes: std.ArrayList(package_database_changes.Change) = .empty;
    defer changes.deinit(builder.allocator);
    var displaced_owners: std.ArrayList(u32) = .empty;
    defer displaced_owners.deinit(builder.allocator);
    var displaced = builder.displaced.keyIterator();
    while (displaced.next()) |slot|
        try displaced_owners.append(builder.allocator, slot.*);
    std.mem.sort(u32, displaced_owners.items, builder.ownership, struct {
        fn less(ownership: Ownership, left: u32, right: u32) bool {
            const first = ownership.owners[left].identity;
            const second = ownership.owners[right].identity;
            return switch (std.mem.order(u8, first.name, second.name)) {
                .lt => true,
                .gt => false,
                .eq => std.mem.order(
                    u8,
                    first.architecture,
                    second.architecture,
                ) == .lt,
            };
        }
    }.less);
    for (displaced_owners.items) |owner| {
        const record = builder.ownership.owners[owner].record;
        var acted = false;
        for (builder.work.items) |item| {
            if (std.mem.eql(u8, item.identity.name, record.name) and
                std.mem.eql(u8, item.identity.architecture, record.architecture))
                acted = true;
        }
        if (acted) continue;

        var paths: std.ArrayList([]const u8) = .empty;
        defer paths.deinit(builder.allocator);
        for (record.paths orelse &.{}) |listed| {
            try builder.chargeWork(1, .{
                .surface = .lowering,
                .code = .path_limit,
                .path = listed,
                .package = record.name,
            });
            const relative = relativeListPath(listed) orelse {
                try paths.append(builder.allocator, listed);
                continue;
            };
            var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
            const canonical = canonicalAliasPath(
                builder.aliases,
                relative,
                &buffer,
            ) orelse return builder.fail(.{
                .surface = .lowering,
                .code = .invalid_path,
                .path = listed,
                .package = record.name,
            });
            if (displacesOwnerPath(builder, owner, canonical)) continue;
            try paths.append(builder.allocator, listed);
        }
        const owned_paths = try builder.arena.dupe([]const u8, paths.items);

        // dpkg's md5sums file describes the package as shipped; losing one
        // path to Replaces changes only the live ownership list. Rewriting
        // the old manifest would erase provenance for the installed package.
        try changes.append(builder.allocator, .{ .put_file_list = .{
            .identity = record.identity(),
            .paths = owned_paths,
        } });
    }
    for (builder.work.items) |*item| {
        const model = item.model;
        const lifecycle_scripts = if (builder.request.lifecycle_execution) block: {
            const scripts = try builder.arena.alloc(
                package_database_changes.StagedScript,
                model.scripts.len,
            );
            for (model.scripts, 0..) |script, index| {
                const kind = databaseScriptKind(script.kind) orelse
                    return builder.fail(.{
                        .surface = .publication,
                        .code = .program_incomplete,
                        .package = item.identity.name,
                    });
                scripts[index] = .{
                    .kind = kind,
                    .bytes = model.scriptBytes(script),
                    .mode = script.mode,
                };
            }
            break :block scripts;
        } else &.{};
        const trigger_declarations = if (builder.request.trigger_execution) block: {
            const declarations = try builder.arena.alloc(
                package_database.TriggerDeclaration,
                model.triggers.len,
            );
            for (model.triggers, 0..) |trigger, index| {
                declarations[index] = .{
                    .kind = switch (trigger.directive) {
                        .interest => .interest,
                        .interest_await => .interest_await,
                        .interest_noawait => .interest_noawait,
                        .activate => .activate,
                        .activate_await => .activate_await,
                        .activate_noawait => .activate_noawait,
                    },
                    .name = trigger.target,
                };
            }
            break :block if (declarations.len == 0) null else declarations;
        } else null;
        try changes.append(builder.allocator, .{ .put_package = .{
            .fields = try statusFields(builder, item, model, .unpacked),
            .paths = item.list_paths.items,
            .md5sums = item.md5sums.items,
            .declared_conffiles = if (item.declared_conffiles.items.len == 0)
                null
            else
                item.declared_conffiles.items,
            .trigger_declarations = trigger_declarations,
            .scripts = lifecycle_scripts,
        } });
    }
    const result = package_database_changes.plan(
        builder.allocator,
        builder.database.*,
        changes.items,
        .{ .database = builder.limits.database, .limits = builder.limits.changes },
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    return switch (result) {
        .plan => |value| value,
        // The change planner reports exhaustion as a typed diagnostic; it is
        // an allocation failure here, not a rejected plan, so a caller under
        // memory pressure sees the same error every other layer reports.
        .diagnostic => |diagnostic| if (diagnostic.code == .out_of_memory)
            error.OutOfMemory
        else
            builder.fail(.{
                .surface = .publication,
                .code = .database_plan_rejected,
                .path = package_database.database_directory,
                .database = diagnostic,
            }),
    };
}

// ---------------------------------------------------------------------------
// Deterministic plan digest
// ---------------------------------------------------------------------------

/// Stable across processes and machines for identical inputs, and sensitive
/// to every decision the planner made: identity, operation, published
/// metadata, content digests, link identity, ownership resolution, removals,
/// aliases, and the database publication plan.
pub fn planDigest(value: Plan) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(digest_domain);
    hashField(&hash, "model_version");
    hashNumber(&hash, model_version);
    hashField(&hash, "program_sha256");
    hashText(&hash, &value.program_sha256);
    hashField(&hash, "authorization_sha256");
    hashText(&hash, &value.authorization_sha256);

    hashField(&hash, "aliases");
    hashNumber(&hash, value.aliases.len);
    for (value.aliases) |alias| {
        hashText(&hash, alias.from);
        hashText(&hash, alias.to);
        hashText(&hash, alias.link_target);
        hashNumber(&hash, alias.device);
        hashNumber(&hash, alias.inode);
        hashNumber(&hash, alias.link_count);
        hashI128(&hash, alias.modified_nanoseconds);
        hashI128(&hash, alias.change_nanoseconds);
    }
    hashField(&hash, "case_aliases");
    hashNumber(&hash, value.case_aliases.len);
    for (value.case_aliases) |alias| {
        hashText(&hash, alias.first);
        hashText(&hash, alias.second);
    }

    hashField(&hash, "filesystem");
    hashNumber(&hash, value.filesystem.len);
    for (value.filesystem) |change| switch (change) {
        .remove => |item| {
            hashText(&hash, "remove");
            hashRemoval(&hash, item);
        },
        .directory => |item| {
            hashText(&hash, "directory");
            hashText(&hash, item.path);
            hashNumber(&hash, item.mode);
            hashNumber(&hash, item.uid);
            hashNumber(&hash, item.gid);
            hashOptionalI128(&hash, item.modified_nanoseconds);
        },
        .file => |item| {
            hashText(&hash, "file");
            hashText(&hash, item.path);
            hashNumber(&hash, item.artifact);
            hashNumber(&hash, item.archive_entry);
            hashText(&hash, &item.sha256);
            hashNumber(&hash, item.mode);
            hashNumber(&hash, item.uid);
            hashNumber(&hash, item.gid);
            hashI128(&hash, item.modified_nanoseconds);
        },
        .symlink => |item| {
            hashText(&hash, "symlink");
            hashText(&hash, item.path);
            hashText(&hash, item.target);
            hashNumber(&hash, item.uid);
            hashNumber(&hash, item.gid);
            hashI128(&hash, item.modified_nanoseconds);
        },
        .hardlink => |item| {
            hashText(&hash, "hardlink");
            hashText(&hash, item.path);
            hashText(&hash, item.source);
        },
    };

    hashField(&hash, "database");
    hashGeneration(&hash, value.database.base_generation);
    hashStatusGeneration(&hash, value.database.base_status);
    hashStatusGeneration(&hash, value.database.resulting_status);
    hashNumber(&hash, value.database.writes.len);
    for (value.database.writes) |write| {
        hashText(&hash, @tagName(write.kind));
        hashText(&hash, write.path);
        hashText(&hash, write.source);
        hashText(&hash, write.bytes);
        hashText(&hash, &write.sha256);
        hashNumber(&hash, write.mode);
    }
    hashText(&hash, &value.database.digest);

    hashField(&hash, "packages");
    hashNumber(&hash, value.packages.len);
    for (value.packages) |item| {
        hashText(&hash, item.identity.name);
        hashText(&hash, item.identity.version);
        hashText(&hash, item.identity.architecture);
        hashText(&hash, item.stem);
        hashNumber(&hash, item.artifact);
        hashText(&hash, @tagName(item.operation));
        hashBool(&hash, item.bootstrapped);
        hashOptionalText(&hash, item.prior_version);
        hashOptionalText(&hash, item.configured_version);
        hashText(&hash, &item.application_sha256);
        hashText(&hash, @tagName(item.state));

        hashNumber(&hash, item.paths.len);
        for (item.paths) |planned| hashPlannedPath(&hash, planned);
        hashNumber(&hash, item.removals.len);
        for (item.removals) |removal| hashRemoval(&hash, removal);
        hashNumber(&hash, item.list_paths.len);
        for (item.list_paths) |path| hashText(&hash, path);
        hashNumber(&hash, item.md5sums.len);
        for (item.md5sums) |entry| {
            hashText(&hash, entry.path);
            hashText(&hash, &entry.digest);
        }
        hashNumber(&hash, item.conffiles.len);
        for (item.conffiles) |conffile| {
            hashText(&hash, conffile.path);
            hashOptionalText(&hash, conffile.staged_path);
            hashText(&hash, @tagName(conffile.action));
            hashOptionalDigest(16, &hash, conffile.packaged_md5);
            if (conffile.recorded) |recorded| {
                hashByte(&hash, 1);
                hashText(&hash, recorded.path);
                switch (recorded.digest) {
                    .new_conffile => hashText(&hash, "newconffile"),
                    .md5 => |digest| hashText(&hash, &digest),
                }
                hashBool(&hash, recorded.obsolete);
                hashBool(&hash, recorded.remove_on_upgrade);
            } else hashByte(&hash, 0);
        }
        hashNumber(&hash, item.resolutions.len);
        for (item.resolutions) |resolution| {
            hashText(&hash, resolution.path);
            hashText(&hash, resolution.holder.name);
            hashText(&hash, resolution.holder.architecture);
            hashText(&hash, resolution.claimant.name);
            hashText(&hash, resolution.claimant.architecture);
            hashText(&hash, @tagName(resolution.resolution));
        }
    }

    hashField(&hash, "displacements");
    hashNumber(&hash, value.displacements.len);
    for (value.displacements) |item| {
        hashText(&hash, item.path);
        hashText(&hash, item.holder.name);
        hashText(&hash, item.holder.architecture);
        hashNumber(&hash, item.holder_index);
        hashText(&hash, item.claimant.name);
        hashText(&hash, item.claimant.architecture);
    }
    hashField(&hash, "retained_directories");
    hashNumber(&hash, value.retained_directories.len);
    for (value.retained_directories) |item| {
        hashText(&hash, item.path);
        hashPreviousState(&hash, item.previous);
    }
    hashField(&hash, "pending_configuration");
    hashNumber(&hash, value.pending_configuration.len);
    for (value.pending_configuration) |item| {
        hashText(&hash, item.name);
        hashText(&hash, item.architecture);
    }
    return hash.finalResult();
}

fn hashPlannedPath(hash: *Sha256, planned: PlannedPath) void {
    hashText(hash, planned.path);
    hashText(hash, planned.absolute);
    hashText(hash, planned.archive_path);
    hashText(hash, @tagName(planned.kind));
    hashNumber(hash, planned.mode);
    hashNumber(hash, planned.uid);
    hashNumber(hash, planned.gid);
    hashOptionalI128(hash, planned.modified_nanoseconds);
    hashOptionalDigest(32, hash, planned.sha256);
    hashOptionalDigest(16, hash, planned.md5);
    hashOptionalText(hash, planned.link_literal);
    hashOptionalText(hash, planned.link_source);
    if (planned.link_source_previous) |previous| {
        hashByte(hash, 1);
        hashPreviousState(hash, previous);
    } else hashByte(hash, 0);
    if (planned.archive_entry) |index| {
        hashByte(hash, 1);
        hashNumber(hash, index);
    } else hashByte(hash, 0);
    hashNumber(hash, planned.package);
    hashText(hash, @tagName(planned.disposition));
    if (planned.previous) |previous| {
        hashByte(hash, 1);
        hashPreviousState(hash, previous);
    } else hashByte(hash, 0);
    hashBool(hash, planned.aliased);
    hashBool(hash, planned.synthesized);
    hashBool(hash, planned.publish);
}

fn diagnosticDigest(diagnostic: Diagnostic) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(digest_domain);
    hashText(&hash, "diagnostic");
    hashText(&hash, @tagName(diagnostic.surface));
    hashText(&hash, @tagName(diagnostic.code));
    hashText(&hash, diagnostic.path);
    hashText(&hash, diagnostic.package);
    hashText(&hash, diagnostic.architecture);
    hashText(&hash, diagnostic.holder);
    hashText(&hash, diagnostic.holder_architecture);
    if (diagnostic.database) |nested| {
        hashByte(&hash, 1);
        hashText(&hash, @tagName(nested.surface));
        hashText(&hash, @tagName(nested.code));
        hashText(&hash, nested.path);
        hashText(&hash, nested.package);
        if (nested.line) |line| {
            hashByte(&hash, 1);
            hashNumber(&hash, line);
        } else hashByte(&hash, 0);
        hashOptionalText(&hash, nested.field_name);
        if (nested.status_syntax) |syntax| {
            hashByte(&hash, 1);
            hashText(&hash, @tagName(syntax));
        } else hashByte(&hash, 0);
    } else hashByte(&hash, 0);
    return hash.finalResult();
}

fn hashPreviousState(hash: *Sha256, previous: PreviousState) void {
    hashText(hash, @tagName(previous.kind));
    hashBool(hash, previous.owned);
    hashBool(hash, previous.modeled);
    hashNumber(hash, previous.mode);
    hashNumber(hash, previous.uid);
    hashNumber(hash, previous.gid);
    hashNumber(hash, previous.size);
    hashNumber(hash, previous.device);
    hashNumber(hash, previous.inode);
    hashNumber(hash, previous.link_count);
    hashI128(hash, previous.modified_nanoseconds);
    hashOptionalI128(hash, previous.change_nanoseconds);
    hashOptionalDigest(32, hash, previous.content_sha256);
    hashOptionalText(hash, previous.link_target);
    hashOptionalDigest(32, hash, previous.directory_sha256);
    if (previous.directory_entries) |count| {
        hashByte(hash, 1);
        hashNumber(hash, count);
    } else hashByte(hash, 0);
}

fn hashRemoval(hash: *Sha256, removal: Removal) void {
    hashText(hash, removal.path);
    hashText(hash, removal.absolute);
    hashBool(hash, removal.directory);
    hashNumber(hash, removal.package);
    hashPreviousState(hash, removal.previous);
}

fn hashGeneration(hash: *Sha256, generation: package_database.Generation) void {
    hashText(hash, &generation.sha256);
    hashNumber(hash, generation.file_count);
    hashNumber(hash, generation.total_bytes);
}

fn hashStatusGeneration(
    hash: *Sha256,
    generation: package_database.StatusGeneration,
) void {
    hashText(hash, &generation.sha256);
    hashNumber(hash, generation.size);
    hashNumber(hash, generation.package_count);
}

fn hashOptionalText(hash: *Sha256, value: ?[]const u8) void {
    if (value) |text| {
        hashByte(hash, 1);
        hashText(hash, text);
    } else hashByte(hash, 0);
}

fn hashOptionalI128(hash: *Sha256, value: ?i128) void {
    if (value) |number| {
        hashByte(hash, 1);
        hashI128(hash, number);
    } else hashByte(hash, 0);
}

fn hashOptionalDigest(
    comptime size: usize,
    hash: *Sha256,
    value: ?[size]u8,
) void {
    if (value) |digest| {
        hashByte(hash, 1);
        hashText(hash, &digest);
    } else hashByte(hash, 0);
}

fn hashField(hash: *Sha256, field: []const u8) void {
    hashByte(hash, 0xff);
    hashText(hash, field);
}

fn hashBool(hash: *Sha256, value: bool) void {
    hashByte(hash, @intFromBool(value));
}

fn hashByte(hash: *Sha256, value: u8) void {
    hash.update(&.{value});
}

fn hashI128(hash: *Sha256, value: i128) void {
    var buffer: [16]u8 = undefined;
    std.mem.writeInt(i128, &buffer, value, .big);
    hash.update(&buffer);
}

fn hashNumber(hash: *Sha256, value: u64) void {
    var buffer: [8]u8 = undefined;
    std.mem.writeInt(u64, &buffer, value, .big);
    hash.update(&buffer);
}

fn hex(comptime size: usize, bytes: [size]u8) [size * 2]u8 {
    const alphabet = "0123456789abcdef";
    var out: [size * 2]u8 = undefined;
    for (bytes, 0..) |byte, index| {
        out[index * 2] = alphabet[byte >> 4];
        out[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return out;
}

fn parseHex(comptime size: usize, value: []const u8) ?[size]u8 {
    if (value.len != size * 2) return null;
    var out: [size]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, value) catch return null;
    return out;
}

// ---------------------------------------------------------------------------
// Internal data-only materialization adapter
// ---------------------------------------------------------------------------

const MaterializationOutcome = enum {
    applied,
    rolled_back,
    recovery_required,
    handoff,
    refused,
};

const MaterializationResult = struct {
    outcome: MaterializationOutcome,
    detail: []const u8,
};

const MaterializationRequest = struct {
    io: std.Io,
    root: root_fs.Root,
    install_root: []const u8,
    planning: Request,
    locks: root_operation.LockBackend,
    operation: product_api.Operation,
    borrowed_attempt: ?*root_operation.Attempt = null,
    execution: ?*ExecutionState = null,
    raw_status_verification: bool = false,
    mutation_last_step: ?*u32 = null,
    hooks: root_mutation.Hooks = .{},
    mutation_limits: root_mutation.Limits = .{},
};

const CapturedDatabase = struct {
    snapshot: package_database.Snapshot,
    arena: *std.heap.ArenaAllocator,
    budget: *ModelAllocator,
    backing_allocator: std.mem.Allocator,

    fn deinit(self: *CapturedDatabase) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.backing_allocator.destroy(self.budget);
        self.* = undefined;
    }
};

fn captureDatabaseFile(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: []const u8,
    maximum_bytes: usize,
) !?package_database.FileEntry {
    const resolved = try root_fs.Path.init(path);
    const observed = (try root.entryIfExists(resolved)) orelse return null;
    const kind: package_database.EntryKind = switch (observed.kind) {
        .file => .regular,
        .directory => .directory,
        .sym_link => .symlink,
        else => .other,
    };
    const bytes = if (kind == .regular)
        try root.readFileAlloc(allocator, resolved, maximum_bytes)
    else
        &.{};
    return .{ .bytes = bytes, .kind = kind, .mode = observed.mode };
}

fn captureDatabaseSnapshot(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    options: package_database.Options,
) !CapturedDatabase {
    return captureDatabaseSnapshotBounded(allocator, root, options, 256 * 1024 * 1024);
}

fn captureDatabaseSnapshotBounded(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    options: package_database.Options,
    maximum_bytes: u64,
) !CapturedDatabase {
    const budget = try allocator.create(ModelAllocator);
    errdefer allocator.destroy(budget);
    budget.* = .init(allocator, maximum_bytes);
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(budget.allocator());
    errdefer arena.deinit();
    const snapshot = captureDatabaseSnapshotInto(
        arena.allocator(),
        root,
        options,
    ) catch |err| switch (err) {
        error.OutOfMemory => return if (budget.exhausted)
            error.DatabaseCaptureLimit
        else
            error.OutOfMemory,
        else => return err,
    };
    return .{
        .snapshot = snapshot,
        .arena = arena,
        .budget = budget,
        .backing_allocator = allocator,
    };
}

fn captureDatabaseSnapshotInto(
    owned: std.mem.Allocator,
    root: root_fs.Root,
    options: package_database.Options,
) !package_database.Snapshot {
    const limits = options.limits;

    const status = (try captureDatabaseFile(
        owned,
        root,
        package_database.database_directory ++ "/" ++ package_database.status_path,
        limits.max_status_bytes,
    )) orelse return error.DatabaseStatusMissing;
    var snapshot: package_database.Snapshot = .{ .status = status };
    snapshot.status_old = try captureDatabaseFile(
        owned,
        root,
        package_database.database_directory ++ "/" ++ package_database.status_old_path,
        limits.max_status_bytes,
    );
    snapshot.arch = try captureDatabaseFile(
        owned,
        root,
        package_database.database_directory ++ "/" ++ package_database.arch_path,
        limits.max_database_file_bytes,
    );
    snapshot.diversions = try captureDatabaseFile(
        owned,
        root,
        package_database.database_directory ++ "/" ++ package_database.diversions_path,
        limits.max_database_file_bytes,
    );
    snapshot.statoverride = try captureDatabaseFile(
        owned,
        root,
        package_database.database_directory ++ "/" ++ package_database.statoverride_path,
        limits.max_database_file_bytes,
    );
    snapshot.triggers_file = try captureDatabaseFile(
        owned,
        root,
        package_database.database_directory ++ "/" ++ package_database.triggers_file_path,
        limits.max_database_file_bytes,
    );
    snapshot.triggers_unincorp = try captureDatabaseFile(
        owned,
        root,
        package_database.database_directory ++ "/" ++ package_database.triggers_unincorp_path,
        limits.max_database_file_bytes,
    );
    var named_triggers: std.ArrayList(package_database.NamedTriggerEntry) = .empty;
    defer named_triggers.deinit(owned);
    var triggers_dir = try root.openDirectory(try root_fs.Path.init(
        package_database.database_directory ++ "/" ++ package_database.triggers_directory,
    ));
    defer triggers_dir.close(root.io);
    var triggers_iterator = triggers_dir.iterate();
    while (try triggers_iterator.next(root.io)) |entry| {
        if (std.mem.eql(u8, entry.name, "File") or
            std.mem.eql(u8, entry.name, "Unincorp") or
            std.mem.eql(u8, entry.name, "Lock"))
            continue;
        if (named_triggers.items.len >= limits.max_named_trigger_files)
            return error.DatabaseCaptureLimit;
        const name = try owned.dupe(u8, entry.name);
        const path = try std.fmt.allocPrint(
            owned,
            "{s}/{s}/{s}",
            .{
                package_database.database_directory,
                package_database.triggers_directory,
                name,
            },
        );
        const file = (try captureDatabaseFile(
            owned,
            root,
            path,
            limits.max_database_file_bytes,
        )) orelse return error.DatabaseCaptureChanged;
        try named_triggers.append(owned, .{
            .name = name,
            .bytes = file.bytes,
            .kind = file.kind,
            .mode = file.mode,
        });
    }
    std.mem.sort(
        package_database.NamedTriggerEntry,
        named_triggers.items,
        {},
        struct {
            fn less(
                _: void,
                left: package_database.NamedTriggerEntry,
                right: package_database.NamedTriggerEntry,
            ) bool {
                return std.mem.order(u8, left.name, right.name) == .lt;
            }
        }.less,
    );
    snapshot.triggers_named = try owned.dupe(
        package_database.NamedTriggerEntry,
        named_triggers.items,
    );

    var info: std.ArrayList(package_database.InfoEntry) = .empty;
    defer info.deinit(owned);
    var info_dir = try root.openDirectory(try root_fs.Path.init(
        package_database.database_directory ++ "/" ++ package_database.info_directory,
    ));
    defer info_dir.close(root.io);
    var info_iterator = info_dir.iterate();
    while (try info_iterator.next(root.io)) |entry| {
        if (info.items.len >= limits.max_info_entries)
            return error.DatabaseCaptureLimit;
        const name = try owned.dupe(u8, entry.name);
        const path = try std.fmt.allocPrint(
            owned,
            "{s}/{s}/{s}",
            .{
                package_database.database_directory,
                package_database.info_directory,
                name,
            },
        );
        const file = (try captureDatabaseFile(
            owned,
            root,
            path,
            limits.max_info_file_bytes,
        )) orelse return error.DatabaseCaptureChanged;
        try info.append(owned, .{
            .name = name,
            .bytes = file.bytes,
            .kind = file.kind,
            .mode = file.mode,
        });
    }
    std.mem.sort(package_database.InfoEntry, info.items, {}, struct {
        fn less(
            _: void,
            left: package_database.InfoEntry,
            right: package_database.InfoEntry,
        ) bool {
            return std.mem.order(u8, left.name, right.name) == .lt;
        }
    }.less);
    snapshot.info = try owned.dupe(package_database.InfoEntry, info.items);

    var updates: std.ArrayList(package_database.UpdateEntry) = .empty;
    defer updates.deinit(owned);
    var updates_dir = try root.openDirectory(try root_fs.Path.init(
        package_database.database_directory ++ "/" ++ package_database.updates_directory,
    ));
    defer updates_dir.close(root.io);
    var updates_iterator = updates_dir.iterate();
    while (try updates_iterator.next(root.io)) |entry| {
        if (updates.items.len >= limits.max_update_fragments)
            return error.DatabaseCaptureLimit;
        const name = try owned.dupe(u8, entry.name);
        const path = try std.fmt.allocPrint(
            owned,
            "{s}/{s}/{s}",
            .{
                package_database.database_directory,
                package_database.updates_directory,
                name,
            },
        );
        const file = (try captureDatabaseFile(
            owned,
            root,
            path,
            limits.max_database_file_bytes,
        )) orelse return error.DatabaseCaptureChanged;
        try updates.append(owned, .{
            .name = name,
            .bytes = file.bytes,
            .kind = file.kind,
            .mode = file.mode,
        });
    }
    std.mem.sort(package_database.UpdateEntry, updates.items, {}, struct {
        fn less(
            _: void,
            left: package_database.UpdateEntry,
            right: package_database.UpdateEntry,
        ) bool {
            return std.mem.order(u8, left.name, right.name) == .lt;
        }
    }.less);
    snapshot.updates = try owned.dupe(package_database.UpdateEntry, updates.items);
    return snapshot;
}

const BoundArchive = struct {
    artifact: u32,
    bytes: []const u8,
    model: archive_application.Model,
    binding: root_mutation.ArtifactBinding,
};

const BoundArchives = struct {
    items: []BoundArchive,
    allocator: std.mem.Allocator,

    fn deinit(self: *BoundArchives) void {
        for (self.items) |*item| item.model.deinit();
        self.allocator.free(self.items);
        self.* = undefined;
    }

    fn find(self: *const BoundArchives, artifact: u32) ?*const BoundArchive {
        for (self.items) |*item| {
            if (item.artifact == artifact) return item;
        }
        return null;
    }
};

fn bindMaterializationArchives(
    allocator: std.mem.Allocator,
    request: Request,
) !?BoundArchives {
    const lifecycle = request.lifecycle_execution;
    const items = try allocator.alloc(
        BoundArchive,
        if (lifecycle) request.archives.len else request.program.artifacts.len,
    );
    var initialized: usize = 0;
    var transferred = false;
    defer if (!transferred) {
        for (items[0..initialized]) |*item| item.model.deinit();
        allocator.free(items);
    };
    for (request.program.artifacts) |artifact| {
        const input = for (request.archives) |candidate| {
            if (candidate.artifact == artifact.index) break candidate;
        } else {
            if (lifecycle) continue;
            return null;
        };
        const archive_sha256 = parseHex(32, &artifact.sha256) orelse return null;
        const application_sha256 = parseHex(
            32,
            &artifact.application_sha256,
        ) orelse return null;
        var model = switch (archive_application.revalidate(
            allocator,
            input.bytes,
            .{ .local = .{
                .size = artifact.size,
                .sha256 = archive_sha256,
                .identity = .{
                    .package = artifact.package.name,
                    .version = artifact.package.version,
                    .architecture = artifact.package.architecture,
                },
            } },
            request.limits.archive,
            application_sha256,
        )) {
            .model => |value| value,
            .diagnostic => return null,
        };
        var model_transferred = false;
        defer if (!model_transferred) model.deinit();
        const binding = root_mutation.bindArchive(
            &model,
            input.bytes,
            artifact.index,
            application_sha256,
        ) catch return null;
        items[initialized] = .{
            .artifact = artifact.index,
            .bytes = input.bytes,
            .model = model,
            .binding = binding,
        };
        initialized += 1;
        model_transferred = true;
    }
    if (initialized != items.len) return null;
    transferred = true;
    return .{ .items = items, .allocator = allocator };
}

fn artifactEvidenceDigest(bound: *const BoundArchives) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(digest_domain);
    hashText(&hash, "materialization-artifacts");
    hashNumber(&hash, bound.items.len);
    for (bound.items) |item| {
        hashNumber(&hash, item.artifact);
        hashText(&hash, &item.model.provenance().sha256);
        hashText(&hash, &item.model.digest);
    }
    return hash.finalResult();
}

fn materializationOverwrite(
    publications: *const std.StringHashMapUnmanaged(PlannedPath),
    path: []const u8,
) !root_mutation.Overwrite {
    const planned = publications.get(path) orelse
        return error.MaterializationPlanMismatch;
    return if (planned.previous == null) .require_absent else .replace;
}

const MaterializationIntents = struct {
    intents: std.ArrayList(root_mutation.Intent),
    database: root_mutation.DatabaseIntents,
    arena: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,

    fn deinit(self: *MaterializationIntents) void {
        self.intents.deinit(self.allocator);
        self.database.deinit();
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }
};

fn rootFileSha256(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: []const u8,
    maximum_bytes: usize,
) ![32]u8 {
    const resolved = try root_fs.Path.init(path);
    const entry = try root.entry(resolved);
    if (!entry.isRegularFile() or !entry.modeled or entry.link_count != 1)
        return error.UnsupportedConffile;
    const bytes = try root.readFileAlloc(allocator, resolved, maximum_bytes);
    defer allocator.free(bytes);
    var digest: [32]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn lowerMaterializationIntents(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    plan_value: Plan,
    bound: *const BoundArchives,
) !MaterializationIntents {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var intents: std.ArrayList(root_mutation.Intent) = .empty;
    errdefer intents.deinit(allocator);
    var directory_metadata: std.ArrayList(root_mutation.Intent) = .empty;
    defer directory_metadata.deinit(allocator);
    var publications: std.StringHashMapUnmanaged(PlannedPath) = .empty;
    defer publications.deinit(allocator);
    var conffiles: std.StringHashMapUnmanaged(PlannedConffile) = .empty;
    defer conffiles.deinit(allocator);
    for (plan_value.packages) |package| {
        for (package.paths) |planned| {
            if (!planned.publish) continue;
            const found = try publications.getOrPut(allocator, planned.path);
            if (found.found_existing)
                return error.MaterializationPlanMismatch;
            found.value_ptr.* = planned;
        }
        for (package.conffiles) |conffile| {
            const found = try conffiles.getOrPut(allocator, conffile.path);
            if (found.found_existing)
                return error.MaterializationPlanMismatch;
            found.value_ptr.* = conffile;
        }
    }

    for (plan_value.filesystem) |change| switch (change) {
        .remove => |removal| {
            if (conffiles.get(removal.path)) |conffile| switch (conffile.action) {
                .remove_on_upgrade_stage_old => {
                    const old_path = try std.fmt.allocPrint(
                        owned,
                        "{s}.dpkg-old",
                        .{removal.path},
                    );
                    const source_sha256 = try rootFileSha256(
                        allocator,
                        root,
                        removal.path,
                        512 * 1024 * 1024,
                    );
                    try intents.append(allocator, .{ .copy = .{
                        .path = old_path,
                        .source = removal.path,
                        .source_sha256 = source_sha256,
                        .mode = removal.previous.mode,
                        .uid = removal.previous.uid,
                        .gid = removal.previous.gid,
                        .modified_nanoseconds = removal.previous.modified_nanoseconds,
                        .overwrite = .require_absent,
                    } });
                },
                .skip_not_shipped, .mark_obsolete => continue,
                else => {},
            };
            try intents.append(allocator, if (removal.directory)
                .{ .remove_directory = .{
                    .path = removal.path,
                    .removal = .require_present,
                } }
            else
                .{ .remove = .{
                    .path = removal.path,
                    .removal = .require_present,
                } });
        },
        .directory => |directory| {
            try intents.append(allocator, .{
                .directory = .{
                    .path = directory.path,
                    // Keep a fresh directory searchable until every child is
                    // published; the exact archive mode and timestamp are one
                    // final journalled metadata step below.
                    .mode = directory.mode | 0o700,
                    .uid = directory.uid,
                    .gid = directory.gid,
                    .overwrite = try materializationOverwrite(
                        &publications,
                        directory.path,
                    ),
                },
            });
            if (directory.modified_nanoseconds) |modified| {
                if (modified == 0)
                    return error.ZeroDirectoryTimestampUnsupported;
                try directory_metadata.append(allocator, .{ .metadata = .{
                    .path = directory.path,
                    .mode = directory.mode,
                    .uid = directory.uid,
                    .gid = directory.gid,
                    .modified_nanoseconds = modified,
                } });
            }
        },
        .file => |file| {
            const archive = bound.find(file.artifact) orelse
                return error.MaterializationArchiveMissing;
            if (file.archive_entry >= archive.model.files.len)
                return error.MaterializationPlanMismatch;
            const modeled = archive.model.files[file.archive_entry];
            if (modeled.kind != .regular)
                return error.MaterializationPlanMismatch;
            var intent = try root_mutation.archiveFileIntent(
                file.path,
                &archive.model,
                modeled,
                archive.binding,
            );
            intent.file.overwrite = try materializationOverwrite(
                &publications,
                file.path,
            );
            try intents.append(allocator, intent);
        },
        .symlink => |link| try intents.append(allocator, .{ .symlink = .{
            .path = link.path,
            .target = link.target,
            .uid = link.uid,
            .gid = link.gid,
            .modified_nanoseconds = link.modified_nanoseconds,
            .overwrite = try materializationOverwrite(&publications, link.path),
        } }),
        .hardlink => |link| try intents.append(allocator, .{ .hard_link = .{
            .path = link.path,
            .source = link.source,
            .overwrite = try materializationOverwrite(&publications, link.path),
        } }),
    };
    std.mem.reverse(root_mutation.Intent, directory_metadata.items);
    try intents.appendSlice(allocator, directory_metadata.items);

    const database_directory = try root.entry(
        try root_fs.Path.init(package_database.database_directory),
    );
    const unincorp_path = package_database.database_directory ++ "/" ++
        package_database.triggers_unincorp_path;
    if (try root.entryIfExists(try root_fs.Path.init(unincorp_path)) == null) {
        var empty_sha256: [32]u8 = undefined;
        Sha256.hash("", &empty_sha256, .{});
        try intents.append(allocator, .{ .file = .{
            .path = unincorp_path,
            .bytes = "",
            .mode = 0o644,
            .uid = database_directory.uid,
            .gid = database_directory.gid,
            .modified_nanoseconds = 0,
            .overwrite = .require_absent,
            .expected_sha256 = empty_sha256,
        } });
    }
    var database = switch (try root_mutation.lowerDatabasePlan(
        allocator,
        plan_value.database,
        .{
            .uid = database_directory.uid,
            .gid = database_directory.gid,
        },
    )) {
        .intents => |value| value,
        .diagnostic => return error.MaterializationDatabaseMismatch,
    };
    errdefer database.deinit();
    try intents.appendSlice(allocator, database.intents);
    return .{
        .intents = intents,
        .database = database,
        .arena = arena,
        .allocator = allocator,
    };
}

fn verifyMaterializedFilesystem(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    plan_value: Plan,
) !void {
    for (plan_value.filesystem) |change| switch (change) {
        .remove => |removal| if (try root.entryIfExists(
            try root_fs.Path.init(removal.path),
        ) != null) return error.MaterializationVerificationFailed,
        .directory => |directory| {
            const entry = try root.entry(try root_fs.Path.init(directory.path));
            if (!entry.isDirectory() or entry.mode != directory.mode or
                entry.uid != directory.uid or entry.gid != directory.gid)
                return error.MaterializationVerificationFailed;
            if (directory.modified_nanoseconds) |modified| {
                if (entry.modified_nanoseconds != modified)
                    return error.MaterializationVerificationFailed;
            }
        },
        .file => |file| {
            const path = try root_fs.Path.init(file.path);
            const entry = try root.entry(path);
            if (!entry.isRegularFile() or entry.mode != file.mode or
                entry.uid != file.uid or entry.gid != file.gid or
                entry.modified_nanoseconds != file.modified_nanoseconds)
                return error.MaterializationVerificationFailed;
            const maximum = std.math.cast(usize, entry.size) orelse
                return error.MaterializationVerificationFailed;
            const bytes = try root.readFileAlloc(allocator, path, maximum);
            defer allocator.free(bytes);
            var digest: [32]u8 = undefined;
            Sha256.hash(bytes, &digest, .{});
            if (!std.mem.eql(u8, &digest, &file.sha256))
                return error.MaterializationVerificationFailed;
        },
        .symlink => |link| {
            const path = try root_fs.Path.init(link.path);
            const entry = try root.entry(path);
            if (!entry.isSymbolicLink() or entry.uid != link.uid or
                entry.gid != link.gid or
                entry.modified_nanoseconds != link.modified_nanoseconds)
                return error.MaterializationVerificationFailed;
            var target: [root_fs.maximum_link_target_bytes]u8 = undefined;
            if (!std.mem.eql(
                u8,
                try root.readSymbolicLink(path, &target),
                link.target,
            )) return error.MaterializationVerificationFailed;
        },
        .hardlink => |link| {
            const target = try root.entry(try root_fs.Path.init(link.path));
            const source = try root.entry(try root_fs.Path.init(link.source));
            if (!target.isRegularFile() or !source.isRegularFile() or
                target.device != source.device or target.inode != source.inode)
                return error.MaterializationVerificationFailed;
        },
    };
}

const DatabasePhaseEvidence = struct {
    base_generation: package_database.Generation,
    base_status: package_database.StatusGeneration,
    resulting_status: package_database.StatusGeneration,
    digest: [32]u8,
};

fn databasePhaseEvidence(
    plan_value: package_database_changes.Plan,
) DatabasePhaseEvidence {
    return .{
        .base_generation = plan_value.base_generation,
        .base_status = plan_value.base_status,
        .resulting_status = plan_value.resulting_status,
        .digest = plan_value.digest,
    };
}

fn verifyMaterializedDatabase(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    architecture: []const u8,
    options: package_database.Options,
    evidence: DatabasePhaseEvidence,
    require_status_old: bool,
) !void {
    var captured = try captureDatabaseSnapshot(allocator, root, options);
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, architecture);
    var imported = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = architecture,
            .snapshot = captured.snapshot,
        },
        options,
    )) {
        .database => |value| value,
        .diagnostic => return error.MaterializationVerificationFailed,
    };
    defer imported.deinit();

    var status_digest: [32]u8 = undefined;
    Sha256.hash(captured.snapshot.status.bytes, &status_digest, .{});
    if (captured.snapshot.status.bytes.len !=
        evidence.resulting_status.size or
        !std.mem.eql(
            u8,
            &status_digest,
            &evidence.resulting_status.sha256,
        ))
        return error.MaterializationVerificationFailed;
    if (require_status_old) {
        const old = captured.snapshot.status_old orelse
            return error.MaterializationVerificationFailed;
        var old_digest: [32]u8 = undefined;
        Sha256.hash(old.bytes, &old_digest, .{});
        if (old.bytes.len != evidence.base_status.size or
            !std.mem.eql(u8, &old_digest, &evidence.base_status.sha256))
            return error.MaterializationVerificationFailed;
    }
}

fn materialize(
    allocator: std.mem.Allocator,
    request: MaterializationRequest,
) !MaterializationResult {
    var standalone_execution: ExecutionState = .{};
    const execution = request.execution orelse &standalone_execution;
    const previous_action = execution.action;
    _ = beginNativePhase(execution, .filesystem);
    defer execution.action = previous_action;
    if (try recoveredActionApplied(execution))
        return .{ .outcome = .applied, .detail = "recovered_phase" };

    var planned = switch (try plan(allocator, request.planning)) {
        .handoff => |value| {
            var handoff = value;
            defer handoff.deinit();
            return .{
                .outcome = .handoff,
                .detail = if (handoff.items.len == 0)
                    "handoff"
                else
                    handoff.items[0].feature.spelling(),
            };
        },
        .refusal => |value| {
            var refusal = value;
            defer refusal.deinit();
            return .{
                .outcome = .refused,
                .detail = @tagName(refusal.diagnostic.code),
            };
        },
        .plan => |value| value,
    };
    defer planned.deinit();

    var fresh_database = try captureDatabaseSnapshot(
        allocator,
        request.root,
        request.planning.limits.database,
    );
    defer fresh_database.deinit();
    normalizeCapturedNativeArchitecture(
        &fresh_database.snapshot,
        request.planning.program.target_architecture,
    );
    const fresh_generation = try package_database.generation(
        allocator,
        fresh_database.snapshot,
    );
    if (!fresh_generation.eql(planned.database.base_generation))
        return .{ .outcome = .refused, .detail = "database_generation_drift" };

    var bound = (try bindMaterializationArchives(
        allocator,
        request.planning,
    )) orelse return .{
        .outcome = .refused,
        .detail = "archive_binding_mismatch",
    };
    defer bound.deinit();
    const artifact_evidence = artifactEvidenceDigest(&bound);

    var lowered = lowerMaterializationIntents(
        allocator,
        request.root,
        planned,
        &bound,
    ) catch |err| switch (err) {
        error.ZeroDirectoryTimestampUnsupported => return .{
            .outcome = .refused,
            .detail = "zero_directory_timestamp_unsupported",
        },
        else => return err,
    };
    defer lowered.deinit();

    const program_sha256 = parseHex(
        32,
        &request.planning.program.digest_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const authorization_sha256 = parseHex(
        32,
        &request.planning.program.authorization_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const request_sha256 = parseHex(
        32,
        &request.planning.program.request_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const policy_sha256 = parseHex(
        32,
        &request.planning.program.executor_policy_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const lock_digest = parseHex(
        32,
        &request.planning.program.exact_lock.digest_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const exact_lock: root_operation.LockBinding = .{
        .version = request.planning.program.exact_lock.version,
        .schema = request.planning.program.exact_lock.schema,
        .digest_sha256 = lock_digest,
    };
    const borrowed = request.borrowed_attempt != null;
    const operation_plan = if (request.borrowed_attempt) |attempt|
        try native_operation.boundPlan(request.root, attempt, request.planning.program.*)
    else
        planned.digest;
    const lifecycle_artifacts = parseHex(
        32,
        &request.planning.program.artifacts_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const operation_evidence: root_operation.Evidence = .{
        .authorization_sha256 = authorization_sha256,
        .program_sha256 = program_sha256,
        .plan_sha256 = operation_plan,
        .exact_lock = exact_lock,
        .database_generation_sha256 = planned.database.base_generation.sha256,
        .artifact_evidence_sha256 = if (borrowed)
            lifecycle_artifacts
        else
            artifact_evidence,
    };
    const mutation_evidence: root_mutation.Evidence = .{
        .authorization_sha256 = authorization_sha256,
        .program_sha256 = program_sha256,
        .plan_sha256 = operation_plan,
        .exact_lock = exact_lock,
        .database_generation_sha256 = if (borrowed)
            null
        else
            planned.database.base_generation.sha256,
        .database_plan_sha256 = planned.database.digest,
        .artifact_evidence_sha256 = if (borrowed)
            lifecycle_artifacts
        else
            artifact_evidence,
    };

    var owned_attempt: root_operation.Attempt = undefined;
    var owns_attempt = false;
    if (request.borrowed_attempt == null) {
        var coordinator = try root_operation.Coordinator.open(
            request.io,
            request.root,
            request.install_root,
            request.locks,
        );
        owned_attempt = try coordinator.acquire(allocator, .{
            .intent = .mutation,
            .existing = .reclaim_resolved,
            .backend = .native,
            .operation = .{ .package_transaction = request.operation },
            .request_sha256 = request_sha256,
            .policy_sha256 = policy_sha256,
            .evidence = operation_evidence,
            .target_architecture = request.planning.program.target_architecture,
            .foreign_architectures = request.planning.program.foreign_architectures,
        });
        owns_attempt = true;
    }
    const attempt = request.borrowed_attempt orelse &owned_attempt;
    defer if (owns_attempt) attempt.release();

    const preflight_result = root_mutation.preflight(
        allocator,
        request.root,
        .{
            .intents = lowered.intents.items,
            .limits = request.mutation_limits,
        },
    ) catch |err| {
        if (owns_attempt) try attempt.abandonIfPreMutation(allocator);
        return err;
    };
    var mutation_plan = switch (preflight_result) {
        .diagnostic => |diagnostic| {
            if (owns_attempt) try attempt.abandonIfPreMutation(allocator);
            return .{
                .outcome = .refused,
                .detail = @tagName(diagnostic.code),
            };
        },
        .plan => |value| value,
    };
    defer mutation_plan.deinit();
    if (request.mutation_last_step) |slot|
        slot.* = if (mutation_plan.steps.len == 0)
            0
        else
            @intCast(mutation_plan.steps.len - 1);

    if (execution.recovery) |runtime| {
        if (execution.action) |action|
            try runtime.append(action, .prepared, .none, null);
    }
    var combined_hooks: CombinedMutationHooks = .{
        .original = request.hooks,
        .runtime = execution.recovery,
        .action = execution.action,
    };
    var refusal: ?root_mutation.Diagnostic = null;
    var engine = root_mutation.prepare(
        allocator,
        request.root,
        attempt,
        &mutation_plan,
        mutation_evidence,
        .{
            .hooks = .{
                .context = &combined_hooks,
                .beforeFn = CombinedMutationHooks.before,
            },
            .allow_recovery_continuation = execution.recovery != null,
            .limits = request.mutation_limits,
            .refusal = &refusal,
        },
    ) catch |err| switch (err) {
        error.Rejected => {
            if (owns_attempt) try attempt.abandonIfPreMutation(allocator);
            return .{
                .outcome = .refused,
                .detail = if (refusal) |diagnostic|
                    @tagName(diagnostic.code)
                else
                    "mutation_prepare_refused",
            };
        },
        error.SimulatedCrash => return .{
            .outcome = .recovery_required,
            .detail = "simulated_crash",
        },
        else => return err,
    };
    defer engine.deinit();

    const mutation_report = block: {
        const previous_steps = execution.phase_steps;
        execution.phase_steps = mutation_plan.steps;
        defer execution.phase_steps = previous_steps;
        break :block root_mutation.apply(
            &engine,
            .fromPlan(&mutation_plan),
        ) catch |err| switch (err) {
            error.SimulatedCrash => return .{
                .outcome = .recovery_required,
                .detail = "simulated_crash",
            },
            error.RecoveryRequired,
            error.ExternalModification,
            error.VerificationFailed,
            => return .{
                .outcome = .recovery_required,
                .detail = @errorName(err),
            },
            else => return err,
        };
    };
    if (mutation_report.outcome == .recovery_required) {
        return .{
            .outcome = .recovery_required,
            .detail = if (mutation_report.diagnostic) |diagnostic|
                @tagName(diagnostic.code)
            else
                "recovery_required",
        };
    }

    if (mutation_report.outcome == .applied) {
        verifyMaterializedFilesystem(
            allocator,
            request.root,
            planned,
        ) catch |err| {
            try attempt.requireRecovery(allocator, .verification);
            return .{
                .outcome = .recovery_required,
                .detail = @errorName(err),
            };
        };
        verifyMaterializedDatabase(
            allocator,
            request.root,
            request.planning.program.target_architecture,
            request.planning.limits.database,
            databasePhaseEvidence(planned.database),
            true,
        ) catch |err| {
            try attempt.requireRecovery(allocator, .verification);
            return .{
                .outcome = .recovery_required,
                .detail = @errorName(err),
            };
        };
    }

    if (execution.recovery) |runtime| {
        if (execution.action) |action| {
            const checkpoint_sha256 = switch (mutation_report.outcome) {
                .applied => try checkpointManagedPaths(
                    allocator,
                    runtime,
                    action,
                    mutation_plan.steps,
                    false,
                ),
                .rolled_back => block: {
                    try native_recovery.discardTransientManagedState(
                        allocator,
                        request.root,
                        runtime.intent_sha256,
                    );
                    try native_recovery.validateStableManagedState(
                        allocator,
                        request.root,
                        runtime.intent_sha256,
                    );
                    break :block native_recovery.hexDigest(
                        mutation_plan.steps_sha256,
                    );
                },
                .recovery_required => unreachable,
            };
            try runtime.append(
                action,
                .completed,
                switch (mutation_report.outcome) {
                    .applied => .applied,
                    .rolled_back => .rolled_back,
                    .recovery_required => unreachable,
                },
                checkpoint_sha256,
            );
            runtime.recovered_phase_count += @intFromBool(runtime.recovering);
        }
    }

    if (!owns_attempt) {
        try root_mutation.clear(&engine);
        return .{
            .outcome = switch (mutation_report.outcome) {
                .applied => .applied,
                .rolled_back => .rolled_back,
                .recovery_required => unreachable,
            },
            .detail = @tagName(mutation_report.stage),
        };
    }
    try attempt.advance(allocator, .{
        .state = .verifying,
        .phase = .verification,
    });
    try attempt.complete(allocator, switch (mutation_report.outcome) {
        .applied => .succeeded,
        .rolled_back => .failed_after_mutation,
        .recovery_required => unreachable,
    });
    try attempt.publishProvenance(allocator, planned.digest);
    try root_mutation.clear(&engine);
    try attempt.clear();
    return .{
        .outcome = switch (mutation_report.outcome) {
            .applied => .applied,
            .rolled_back => .rolled_back,
            .recovery_required => unreachable,
        },
        .detail = @tagName(mutation_report.stage),
    };
}

fn materializationHashValue(domain: []const u8, value: anytype) [32]u8 {
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(Sha256) = .init(&buffer);
    sink.writer.writeAll(domain) catch unreachable;
    std.json.Stringify.value(
        value,
        .{ .whitespace = .minified },
        &sink.writer,
    ) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn materializationProgramDigest(program: native_program.Program) [32]u8 {
    var payload = program;
    payload.digest_sha256 = @splat('0');
    return materializationHashValue(
        "debz-native-transaction-program-v1\x00",
        payload,
    );
}

fn phasePreflight(
    request: MaterializationRequest,
    database: package_database.Database,
) ?MaterializationResult {
    const program = request.planning.program;
    if (request.planning.interoperability != .isolated_root)
        return .{ .outcome = .handoff, .detail = "shared_root" };
    if (!std.mem.eql(u8, program.schema, native_program.schema_id) or
        program.version != native_program.schema_version or
        program.backend != .native or
        !std.mem.eql(u8, program.install_root, request.install_root))
        return .{ .outcome = .refused, .detail = "program_mismatch" };
    const root_identity = transaction_recovery.rootIdentity(
        request.install_root,
    );
    if (!std.mem.eql(
        u8,
        &program.root_identity_sha256,
        &hex(32, root_identity),
    ) or
        !std.mem.eql(
            u8,
            &program.digest_sha256,
            &hex(32, materializationProgramDigest(program.*)),
        ) or
        (request.borrowed_attempt == null and
            (!std.mem.eql(
                u8,
                &program.installed_database.generation_sha256,
                &hex(32, database.generation.sha256),
            ) or
                program.installed_database.package_count != database.model.packages.len)))
        return .{ .outcome = .refused, .detail = "program_binding_mismatch" };
    if (request.planning.root_identity_sha256) |expected| {
        if (!std.mem.eql(u8, &expected, &root_identity))
            return .{ .outcome = .refused, .detail = "root_identity_mismatch" };
    }
    if (program.policy.conffile != request.planning.conffile_policy)
        return .{ .outcome = .refused, .detail = "conffile_policy_mismatch" };
    if (database.model.pending_updates.len != 0)
        return .{ .outcome = .refused, .detail = "updates_pending" };
    if (!request.planning.trigger_execution and
        (database.model.triggers.interests.len != 0 or
            database.model.triggers.pending.len != 0))
        return .{ .outcome = .handoff, .detail = "trigger" };
    if (database.model.diversions.len != 0)
        return .{ .outcome = .handoff, .detail = "diversion" };
    if (database.model.stat_overrides.len != 0)
        return .{ .outcome = .handoff, .detail = "statoverride" };
    if (database.model.opaque_info.len != 0)
        return .{ .outcome = .handoff, .detail = "package_metadata" };
    return null;
}

fn executePhaseMaterialization(
    allocator: std.mem.Allocator,
    request: MaterializationRequest,
    intents: []const root_mutation.Intent,
    database_evidence: DatabasePhaseEvidence,
    phase_seed: [32]u8,
    artifact_evidence: ?[32]u8,
    require_status_old: bool,
) !MaterializationResult {
    var standalone_execution: ExecutionState = .{};
    const execution = request.execution orelse &standalone_execution;
    const previous_action = execution.action;
    _ = beginNativePhase(execution, .database);
    defer execution.action = previous_action;
    if (try recoveredActionApplied(execution))
        return .{ .outcome = .applied, .detail = "recovered_phase" };

    const program_sha256 = parseHex(
        32,
        &request.planning.program.digest_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const authorization_sha256 = parseHex(
        32,
        &request.planning.program.authorization_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const request_sha256 = parseHex(
        32,
        &request.planning.program.request_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const policy_sha256 = parseHex(
        32,
        &request.planning.program.executor_policy_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const lock_digest = parseHex(
        32,
        &request.planning.program.exact_lock.digest_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const exact_lock: root_operation.LockBinding = .{
        .version = request.planning.program.exact_lock.version,
        .schema = request.planning.program.exact_lock.schema,
        .digest_sha256 = lock_digest,
    };
    const borrowed = request.borrowed_attempt != null;
    const operation_plan = if (request.borrowed_attempt) |attempt|
        try native_operation.boundPlan(request.root, attempt, request.planning.program.*)
    else
        null;
    const lifecycle_artifacts = parseHex(
        32,
        &request.planning.program.artifacts_sha256,
    ) orelse return error.MaterializationProgramDigest;
    const operation_evidence: root_operation.Evidence = .{
        .authorization_sha256 = authorization_sha256,
        .program_sha256 = program_sha256,
        .plan_sha256 = operation_plan,
        .exact_lock = exact_lock,
        .database_generation_sha256 = database_evidence.base_generation.sha256,
        .artifact_evidence_sha256 = if (borrowed)
            lifecycle_artifacts
        else
            artifact_evidence,
    };
    var owned_attempt: root_operation.Attempt = undefined;
    var owns_attempt = false;
    if (request.borrowed_attempt == null) {
        var coordinator = try root_operation.Coordinator.open(
            request.io,
            request.root,
            request.install_root,
            request.locks,
        );
        owned_attempt = try coordinator.acquire(allocator, .{
            .intent = .mutation,
            .existing = .reclaim_resolved,
            .backend = .native,
            .operation = .{ .package_transaction = request.operation },
            .request_sha256 = request_sha256,
            .policy_sha256 = policy_sha256,
            .evidence = operation_evidence,
            .target_architecture = request.planning.program.target_architecture,
            .foreign_architectures = request.planning.program.foreign_architectures,
        });
        owns_attempt = true;
    }
    const attempt = request.borrowed_attempt orelse &owned_attempt;
    defer if (owns_attempt) attempt.release();
    const preflight_result = root_mutation.preflight(
        allocator,
        request.root,
        .{ .intents = intents, .limits = request.mutation_limits },
    ) catch |err| {
        if (owns_attempt) try attempt.abandonIfPreMutation(allocator);
        return err;
    };
    var mutation_plan = switch (preflight_result) {
        .diagnostic => |diagnostic| {
            if (owns_attempt) try attempt.abandonIfPreMutation(allocator);
            return .{
                .outcome = .refused,
                .detail = @tagName(diagnostic.code),
            };
        },
        .plan => |value| value,
    };
    defer mutation_plan.deinit();
    const phase_digest = boundConffilePhaseDigest(
        phase_seed,
        mutation_plan.steps_sha256,
    );
    const mutation_evidence: root_mutation.Evidence = .{
        .authorization_sha256 = authorization_sha256,
        .program_sha256 = program_sha256,
        .plan_sha256 = operation_plan orelse phase_digest,
        .exact_lock = exact_lock,
        .database_generation_sha256 = if (borrowed)
            null
        else
            database_evidence.base_generation.sha256,
        .database_plan_sha256 = database_evidence.digest,
        .artifact_evidence_sha256 = if (borrowed)
            lifecycle_artifacts
        else
            artifact_evidence,
    };
    if (execution.recovery) |runtime| {
        if (execution.action) |action|
            try runtime.append(action, .prepared, .none, null);
    }
    var combined_hooks: CombinedMutationHooks = .{
        .original = request.hooks,
        .runtime = execution.recovery,
        .action = execution.action,
    };
    var refusal: ?root_mutation.Diagnostic = null;
    var engine = root_mutation.prepare(
        allocator,
        request.root,
        attempt,
        &mutation_plan,
        mutation_evidence,
        .{
            .hooks = .{
                .context = &combined_hooks,
                .beforeFn = CombinedMutationHooks.before,
            },
            .allow_recovery_continuation = execution.recovery != null,
            .limits = request.mutation_limits,
            .refusal = &refusal,
        },
    ) catch |err| switch (err) {
        error.Rejected => {
            if (owns_attempt) try attempt.abandonIfPreMutation(allocator);
            return .{
                .outcome = .refused,
                .detail = if (refusal) |diagnostic|
                    @tagName(diagnostic.code)
                else
                    "mutation_prepare_refused",
            };
        },
        error.SimulatedCrash => return .{
            .outcome = .recovery_required,
            .detail = "simulated_crash",
        },
        else => return err,
    };
    var engine_open = true;
    defer if (engine_open) engine.deinit();
    const report = block: {
        const previous_steps = execution.phase_steps;
        execution.phase_steps = mutation_plan.steps;
        defer execution.phase_steps = previous_steps;
        break :block root_mutation.apply(
            &engine,
            .fromPlan(&mutation_plan),
        ) catch |err| switch (err) {
            error.SimulatedCrash => return .{
                .outcome = .recovery_required,
                .detail = "simulated_crash",
            },
            error.RecoveryRequired,
            error.ExternalModification,
            error.VerificationFailed,
            => return .{
                .outcome = .recovery_required,
                .detail = @errorName(err),
            },
            else => return err,
        };
    };
    if (report.outcome == .recovery_required)
        return .{
            .outcome = .recovery_required,
            .detail = if (report.diagnostic) |diagnostic|
                @tagName(diagnostic.code)
            else
                "recovery_required",
        };
    if (report.outcome == .applied) {
        const verified = if (request.raw_status_verification) block: {
            const status_path = package_database.database_directory ++ "/" ++
                package_database.status_path;
            const status_digest = rootFileSha256(
                allocator,
                request.root,
                status_path,
                request.planning.limits.database.limits.max_status_bytes,
            ) catch break :block false;
            if (!std.mem.eql(
                u8,
                &status_digest,
                &database_evidence.resulting_status.sha256,
            )) break :block false;
            if (require_status_old) {
                const old_path = package_database.database_directory ++ "/" ++
                    package_database.status_old_path;
                const old_digest = rootFileSha256(
                    allocator,
                    request.root,
                    old_path,
                    request.planning.limits.database.limits.max_status_bytes,
                ) catch break :block false;
                if (!std.mem.eql(
                    u8,
                    &old_digest,
                    &database_evidence.base_status.sha256,
                )) break :block false;
            }
            break :block true;
        } else block: {
            verifyMaterializedDatabase(
                allocator,
                request.root,
                request.planning.program.target_architecture,
                request.planning.limits.database,
                database_evidence,
                require_status_old,
            ) catch break :block false;
            break :block true;
        };
        if (!verified) {
            try attempt.requireRecovery(allocator, .verification);
            return .{
                .outcome = .recovery_required,
                .detail = "database_verification_failed",
            };
        }
    }
    if (execution.recovery) |runtime| {
        if (execution.action) |action| {
            const checkpoint_sha256 = switch (report.outcome) {
                .applied => try checkpointManagedPaths(
                    allocator,
                    runtime,
                    action,
                    mutation_plan.steps,
                    false,
                ),
                .rolled_back => block: {
                    try native_recovery.discardTransientManagedState(
                        allocator,
                        request.root,
                        runtime.intent_sha256,
                    );
                    try native_recovery.validateStableManagedState(
                        allocator,
                        request.root,
                        runtime.intent_sha256,
                    );
                    break :block native_recovery.hexDigest(phase_digest);
                },
                .recovery_required => unreachable,
            };
            try runtime.append(
                action,
                .completed,
                switch (report.outcome) {
                    .applied => .applied,
                    .rolled_back => .rolled_back,
                    .recovery_required => unreachable,
                },
                checkpoint_sha256,
            );
            runtime.recovered_phase_count += @intFromBool(runtime.recovering);
        }
    }
    if (!owns_attempt) {
        try root_mutation.clear(&engine);
        engine.deinit();
        engine_open = false;
        return .{
            .outcome = if (report.outcome == .applied) .applied else .rolled_back,
            .detail = @tagName(report.stage),
        };
    }
    try attempt.advance(allocator, .{
        .state = .verifying,
        .phase = .verification,
    });
    try attempt.complete(allocator, switch (report.outcome) {
        .applied => .succeeded,
        .rolled_back => .failed_after_mutation,
        .recovery_required => unreachable,
    });
    try attempt.publishProvenance(allocator, phase_digest);
    try root_mutation.clear(&engine);
    try attempt.clear();
    engine.deinit();
    engine_open = false;
    return .{
        .outcome = if (report.outcome == .applied) .applied else .rolled_back,
        .detail = @tagName(report.stage),
    };
}

fn phaseStatusFields(
    allocator: std.mem.Allocator,
    record: package_database.PackageRecord,
    want: package_database.Want,
    error_state: package_database.ErrorState,
    current: package_database.CurrentState,
    config_version: ?[]const u8,
    conffiles: []const package_database.ConffileEntry,
) ![]const package_database.StatusField {
    var fields: std.ArrayList(package_database.StatusField) = .empty;
    defer fields.deinit(allocator);
    var status_seen = false;
    var conffiles_written = false;
    var config_written = false;
    for (record.fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, "Status")) {
            const lines = try allocator.alloc([]const u8, 1);
            lines[0] = try std.fmt.allocPrint(
                allocator,
                "{s} {s} {s}",
                .{
                    @tagName(want),
                    switch (error_state) {
                        .ok => "ok",
                        .reinst_required => "reinstreq",
                    },
                    package_database.currentStateSpelling(current),
                },
            );
            try fields.append(allocator, .{
                .name = "Status",
                .value_lines = lines,
            });
            status_seen = true;
        } else if (std.ascii.eqlIgnoreCase(field.name, "Config-Version")) {
            if (!config_written) if (config_version) |version| {
                const lines = try allocator.alloc([]const u8, 1);
                lines[0] = version;
                try fields.append(allocator, .{
                    .name = "Config-Version",
                    .value_lines = lines,
                });
                config_written = true;
            };
        } else if (std.ascii.eqlIgnoreCase(field.name, "Conffiles")) {
            if (!conffiles_written and conffiles.len != 0) {
                try fields.append(
                    allocator,
                    try package_database.conffilesField(allocator, conffiles),
                );
                conffiles_written = true;
            }
        } else {
            try fields.append(allocator, field);
        }
        if (std.ascii.eqlIgnoreCase(field.name, "Version")) {
            if (!config_written) if (config_version) |version| {
                const lines = try allocator.alloc([]const u8, 1);
                lines[0] = version;
                try fields.append(allocator, .{
                    .name = "Config-Version",
                    .value_lines = lines,
                });
                config_written = true;
            };
            if (!conffiles_written and conffiles.len != 0) {
                try fields.append(
                    allocator,
                    try package_database.conffilesField(allocator, conffiles),
                );
                conffiles_written = true;
            }
        }
    }
    if (!status_seen) return error.MaterializationDatabaseMismatch;
    if (!conffiles_written and conffiles.len != 0)
        try fields.append(
            allocator,
            try package_database.conffilesField(allocator, conffiles),
        );
    return allocator.dupe(package_database.StatusField, fields.items);
}

fn triggerStatusFields(
    allocator: std.mem.Allocator,
    record: package_database.PackageRecord,
    want: package_database.Want,
    error_state: package_database.ErrorState,
    current: package_database.CurrentState,
    config_version: ?[]const u8,
    pending: []const []const u8,
    awaited: []const []const u8,
) ![]const package_database.StatusField {
    const base = try phaseStatusFields(
        allocator,
        record,
        want,
        error_state,
        current,
        config_version,
        record.conffiles,
    );
    var fields: std.ArrayList(package_database.StatusField) = .empty;
    defer fields.deinit(allocator);
    for (base) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, "Triggers-Pending") or
            std.ascii.eqlIgnoreCase(field.name, "Triggers-Awaited"))
            continue;
        try fields.append(allocator, field);
    }
    if (pending.len != 0) {
        const lines = try allocator.alloc([]const u8, 1);
        lines[0] = try std.mem.join(allocator, " ", pending);
        try fields.append(allocator, .{
            .name = "Triggers-Pending",
            .value_lines = lines,
        });
    }
    if (awaited.len != 0) {
        const lines = try allocator.alloc([]const u8, 1);
        lines[0] = try std.mem.join(allocator, " ", awaited);
        try fields.append(allocator, .{
            .name = "Triggers-Awaited",
            .value_lines = lines,
        });
    }
    return allocator.dupe(package_database.StatusField, fields.items);
}

fn findDatabaseConffile(
    record: package_database.PackageRecord,
    path: []const u8,
) ?package_database.ConffileEntry {
    for (record.conffiles) |conffile| {
        if (std.mem.eql(u8, conffile.path, path)) return conffile;
    }
    return null;
}

const RootConffileDigest = struct {
    md5: [16]u8,
    sha256: [32]u8,
};

fn rootMd5ForConffile(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    path: []const u8,
    maximum_bytes: usize,
    compared_bytes: *u64,
    maximum_total: u64,
) !?RootConffileDigest {
    const resolved = try root_fs.Path.init(path);
    const observed = (try root.entryIfExists(resolved)) orelse return null;
    if (!observed.isRegularFile() or !observed.modeled or
        observed.link_count != 1)
        return error.UnsupportedConffile;
    if (observed.size > maximum_bytes)
        return error.ConffileObservationLimit;
    compared_bytes.* = std.math.add(
        u64,
        compared_bytes.*,
        observed.size,
    ) catch return error.ConffileObservationLimit;
    if (compared_bytes.* > maximum_total)
        return error.ConffileObservationLimit;
    const maximum = std.math.cast(usize, observed.size) orelse
        return error.UnsupportedConffile;
    const bytes = try root.readFileAlloc(allocator, resolved, maximum);
    defer allocator.free(bytes);
    var sha256: [32]u8 = undefined;
    Sha256.hash(bytes, &sha256, .{});
    return .{ .md5 = digestMd5(bytes), .sha256 = sha256 };
}

fn requireAbsentConffileArtifact(
    root: root_fs.Root,
    model: package_database.Model,
    path: []const u8,
) !void {
    for (model.packages) |record| {
        for (record.paths orelse &.{}) |listed| {
            const relative = relativeListPath(listed) orelse continue;
            if (std.mem.eql(u8, relative, path))
                return error.ConffileArtifactCollision;
        }
    }
    if (try root.entryIfExists(try root_fs.Path.init(path)) != null)
        return error.ConffileArtifactCollision;
}

fn boundConffileFile(
    archive: *const BoundArchive,
    conffile: archive_application.Conffile,
) !archive_application.File {
    const index = conffile.file_index orelse return error.UnsupportedConffile;
    if (index >= archive.model.files.len) return error.UnsupportedConffile;
    const file = archive.model.files[index];
    if (file.kind != .regular or !file.conffile)
        return error.UnsupportedConffile;
    return file;
}

fn appendArchiveConffileIntent(
    intents: *std.ArrayList(root_mutation.Intent),
    allocator: std.mem.Allocator,
    path: []const u8,
    archive: *const BoundArchive,
    file: archive_application.File,
    overwrite: root_mutation.Overwrite,
    metadata: ?root_fs.Entry,
) !void {
    var intent = try root_mutation.archiveFileIntent(
        path,
        &archive.model,
        file,
        archive.binding,
    );
    intent.file.overwrite = overwrite;
    if (metadata) |entry| {
        intent.file.mode = entry.mode;
        intent.file.uid = entry.uid;
        intent.file.gid = entry.gid;
    }
    try intents.append(allocator, intent);
}

fn databaseScriptKind(kind: archive_application.ScriptKind) ?package_database.ScriptKind {
    return switch (kind) {
        .preinst => .preinst,
        .postinst => .postinst,
        .prerm => .prerm,
        .postrm => .postrm,
        .config => null,
    };
}

fn stagedArchiveScripts(
    allocator: std.mem.Allocator,
    archive: *const BoundArchive,
) ![]const package_database_changes.StagedScript {
    const scripts = try allocator.alloc(
        package_database_changes.StagedScript,
        archive.model.scripts.len,
    );
    var count: usize = 0;
    errdefer allocator.free(scripts);
    for (archive.model.scripts) |script| {
        const kind = databaseScriptKind(script.kind) orelse
            return error.UnsupportedMaintainerScript;
        scripts[count] = .{
            .kind = kind,
            .bytes = archive.model.scriptBytes(script),
            .mode = script.mode,
        };
        count += 1;
    }
    return scripts[0..count];
}

fn conffilePhaseDigest(
    operation: []const u8,
    database_plan: package_database_changes.Plan,
    artifact_evidence: ?[32]u8,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(digest_domain);
    hashText(&hash, "conffile-phase");
    hashText(&hash, operation);
    hashText(&hash, &database_plan.digest);
    hashOptionalDigest(32, &hash, artifact_evidence);
    return hash.finalResult();
}

fn boundConffilePhaseDigest(
    phase_seed: [32]u8,
    steps_sha256: [32]u8,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(digest_domain);
    hashText(&hash, "bound-conffile-phase");
    hashText(&hash, &phase_seed);
    hashText(&hash, &steps_sha256);
    return hash.finalResult();
}

fn materializeConfigure(
    allocator: std.mem.Allocator,
    request: MaterializationRequest,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(
        allocator,
        request.root,
        request.planning.limits.database,
    );
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(
        &captured.snapshot,
        request.planning.program.target_architecture,
    );
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = request.planning.program.target_architecture,
            .snapshot = captured.snapshot,
        },
        request.planning.limits.database,
    )) {
        .database => |value| value,
        .diagnostic => return .{
            .outcome = .refused,
            .detail = "database_rejected",
        },
    };
    defer database.deinit();
    if (phasePreflight(request, database)) |result| return result;
    var bound = (try bindMaterializationArchives(
        allocator,
        request.planning,
    )) orelse return .{
        .outcome = .refused,
        .detail = "archive_binding_mismatch",
    };
    defer bound.deinit();
    const artifact_evidence = artifactEvidenceDigest(&bound);

    const arena = try allocator.create(std.heap.ArenaAllocator);
    defer allocator.destroy(arena);
    arena.* = .init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    var intents: std.ArrayList(root_mutation.Intent) = .empty;
    defer intents.deinit(allocator);
    var changes: std.ArrayList(package_database_changes.Change) = .empty;
    defer changes.deinit(allocator);
    var compared_bytes: u64 = 0;

    for (bound.items) |*archive| {
        if ((request.borrowed_attempt == null and archive.model.scripts.len != 0) or
            (!request.planning.trigger_execution and
                archive.model.triggers.len != 0) or
            archive.model.metadata.len != 0)
            return .{ .outcome = .handoff, .detail = "script_or_trigger" };
        const record = database.model.find(
            archive.model.facts.package,
            archive.model.facts.architecture,
        ) orelse return .{
            .outcome = .refused,
            .detail = "package_not_installed",
        };
        if ((record.status.current != .unpacked and
            !(request.borrowed_attempt != null and
                record.status.current == .half_configured)) or
            !std.mem.eql(u8, record.version, archive.model.facts.version) or
            record.status.error_state != .ok or
            record.status.want == .hold or
            (request.borrowed_attempt == null and record.scripts.len != 0) or
            (!request.planning.trigger_execution and
                record.trigger_declarations != null) or
            record.triggers_pending.len != 0 or
            record.triggers_awaited.len != 0)
            return .{ .outcome = .refused, .detail = "package_not_unpacked" };
        var resulting: std.ArrayList(package_database.ConffileEntry) = .empty;
        defer resulting.deinit(allocator);
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        defer seen.deinit(allocator);

        for (archive.model.conffiles) |conffile| {
            const absolute = try std.fmt.allocPrint(
                owned,
                "/{s}",
                .{conffile.path},
            );
            try seen.put(allocator, absolute, {});
            const old = findDatabaseConffile(record.*, absolute);
            if (conffile.remove_on_upgrade) {
                if (old) |entry| try resulting.append(allocator, entry);
                continue;
            }
            const file = try boundConffileFile(archive, conffile);
            const packaged_md5 = file.md5 orelse digestMd5(
                archive.model.fileBytes(file) catch
                    return error.UnsupportedConffile,
            );
            const staged = try std.fmt.allocPrint(
                owned,
                "{s}.dpkg-new",
                .{conffile.path},
            );
            const staged_md5 = try rootMd5ForConffile(
                allocator,
                request.root,
                staged,
                request.planning.limits.max_compare_bytes,
                &compared_bytes,
                request.planning.limits.max_compared_bytes,
            );
            const expected_sha256 = file.sha256 orelse
                return error.UnsupportedConffile;
            if (staged_md5 == null or
                !std.mem.eql(u8, &staged_md5.?.md5, &packaged_md5) or
                !std.mem.eql(u8, &staged_md5.?.sha256, &expected_sha256))
                return .{
                    .outcome = .refused,
                    .detail = "staged_conffile_mismatch",
                };
            var live_digest: ?RootConffileDigest = null;
            if (old) |entry| switch (entry.digest) {
                .new_conffile => {},
                .md5 => live_digest = try rootMd5ForConffile(
                    allocator,
                    request.root,
                    conffile.path,
                    request.planning.limits.max_compare_bytes,
                    &compared_bytes,
                    request.planning.limits.max_compared_bytes,
                ),
            };
            const installed: ?native_program.InstalledConffile = if (old) |entry|
                switch (entry.digest) {
                    .new_conffile => null,
                    .md5 => |digest| .{
                        .path = entry.path,
                        .recorded_md5 = digest,
                        .on_disk_md5 = if (live_digest) |observed|
                            observed.md5
                        else
                            null,
                        .obsolete = entry.obsolete,
                    },
                }
            else
                null;
            const action = native_program.conffileDecision(
                request.planning.conffile_policy,
                .{
                    .path = conffile.path,
                    .md5 = packaged_md5,
                },
                installed,
            );
            switch (action) {
                .install_new, .restore_missing => try appendArchiveConffileIntent(
                    &intents,
                    allocator,
                    conffile.path,
                    archive,
                    file,
                    .require_absent,
                    null,
                ),
                .replace_unmodified => try appendArchiveConffileIntent(
                    &intents,
                    allocator,
                    conffile.path,
                    archive,
                    file,
                    .replace,
                    null,
                ),
                .keep_existing_stage_dist => {
                    const dist = try std.fmt.allocPrint(
                        owned,
                        "{s}.dpkg-dist",
                        .{conffile.path},
                    );
                    if (archive.model.findFile(dist) != null)
                        return error.ConffileArtifactCollision;
                    try requireAbsentConffileArtifact(
                        request.root,
                        database.model,
                        dist,
                    );
                    const live_metadata = request.root.entryIfExists(
                        try root_fs.Path.init(conffile.path),
                    ) catch return error.UnsupportedConffile;
                    try appendArchiveConffileIntent(
                        &intents,
                        allocator,
                        dist,
                        archive,
                        file,
                        .require_absent,
                        live_metadata,
                    );
                },
                .install_stage_old => {
                    const old_path = try std.fmt.allocPrint(
                        owned,
                        "{s}.dpkg-old",
                        .{conffile.path},
                    );
                    if (archive.model.findFile(old_path) != null)
                        return error.ConffileArtifactCollision;
                    try requireAbsentConffileArtifact(
                        request.root,
                        database.model,
                        old_path,
                    );
                    const source_sha256 = (live_digest orelse
                        return error.UnsupportedConffile).sha256;
                    const current = try request.root.entry(
                        try root_fs.Path.init(conffile.path),
                    );
                    try intents.append(allocator, .{ .copy = .{
                        .path = old_path,
                        .source = conffile.path,
                        .source_sha256 = source_sha256,
                        .mode = current.mode,
                        .uid = current.uid,
                        .gid = current.gid,
                        .modified_nanoseconds = current.modified_nanoseconds,
                        .overwrite = .require_absent,
                    } });
                    try appendArchiveConffileIntent(
                        &intents,
                        allocator,
                        conffile.path,
                        archive,
                        file,
                        .replace,
                        current,
                    );
                },
                .identical_no_op,
                .keep_user_modified,
                .keep_user_deleted,
                => {},
                .skip_not_shipped,
                .remove_on_upgrade,
                .remove_on_upgrade_stage_old,
                .mark_obsolete,
                .retain_on_remove,
                .delete_on_purge,
                => return error.UnsupportedConffile,
            }
            try intents.append(allocator, .{ .remove = .{
                .path = staged,
                .removal = .require_present,
            } });
            try resulting.append(allocator, .{
                .path = absolute,
                .digest = .{ .md5 = packaged_md5 },
            });
        }
        for (record.conffiles) |old| {
            if (!seen.contains(old.path))
                try resulting.append(allocator, old);
        }
        const fields = try phaseStatusFields(
            owned,
            record.*,
            .install,
            .ok,
            .installed,
            null,
            resulting.items,
        );
        const lifecycle_scripts: []const package_database_changes.StagedScript =
            if (request.borrowed_attempt != null)
                try stagedArchiveScripts(owned, archive)
            else
                &.{};
        try changes.append(allocator, .{ .put_package = .{
            .fields = fields,
            .paths = record.paths,
            .md5sums = record.md5sums,
            .declared_conffiles = record.declared_conffiles,
            .trigger_declarations = record.trigger_declarations,
            .scripts = lifecycle_scripts,
        } });
    }
    var database_plan = switch (try package_database_changes.plan(
        allocator,
        database,
        changes.items,
        .{ .database = request.planning.limits.database },
    )) {
        .plan => |value| value,
        .diagnostic => |diagnostic| {
            return .{
                .outcome = .refused,
                .detail = @tagName(diagnostic.code),
            };
        },
    };
    defer database_plan.deinit();
    const directory = try request.root.entry(
        try root_fs.Path.init(package_database.database_directory),
    );
    var database_intents = switch (try root_mutation.lowerDatabasePlan(
        allocator,
        database_plan,
        .{ .uid = directory.uid, .gid = directory.gid },
    )) {
        .intents => |value| value,
        .diagnostic => return error.MaterializationDatabaseMismatch,
    };
    defer database_intents.deinit();
    try intents.appendSlice(allocator, database_intents.intents);
    return executePhaseMaterialization(
        allocator,
        request,
        intents.items,
        databasePhaseEvidence(database_plan),
        conffilePhaseDigest("configure", database_plan, artifact_evidence),
        artifact_evidence,
        true,
    );
}

fn pathRetainedForConffiles(
    relative: []const u8,
    conffiles: []const package_database.ConffileEntry,
) bool {
    for (conffiles) |conffile| {
        const live = relativeListPath(conffile.path) orelse continue;
        if (std.mem.eql(u8, relative, live)) return true;
        if (live.len > relative.len and live[relative.len] == '/' and
            std.mem.eql(u8, live[0..relative.len], relative))
            return true;
    }
    return false;
}

fn removableDirectory(
    root: root_fs.Root,
    path: []const u8,
    removing: *const std.StringHashMapUnmanaged(void),
) !bool {
    var directory = try root.openDirectory(try root_fs.Path.init(path));
    defer directory.close(root.io);
    var iterator = directory.iterate();
    while (try iterator.next(root.io)) |entry| {
        var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        const child = try std.fmt.bufPrint(
            &buffer,
            "{s}/{s}",
            .{ path, entry.name },
        );
        if (!removing.contains(child)) return false;
    }
    return true;
}

fn removalConfigVersion(
    record: package_database.PackageRecord,
) ?[]const u8 {
    return switch (record.status.current) {
        .installed, .triggers_awaited, .triggers_pending => record.version,
        .unpacked, .config_files => switch (configVersionField(record)) {
            .valid => |value| value,
            .absent, .invalid => null,
        },
        else => null,
    };
}

const RemovalCandidate = struct {
    path: []const u8,
    directory: bool,
};

fn retainedPostrmScript(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    record: package_database.PackageRecord,
    maximum_bytes: usize,
) ![]const package_database_changes.StagedScript {
    for (record.scripts) |script| {
        if (script.kind != .postrm) continue;
        const path = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}/{s}.postrm",
            .{
                package_database.database_directory,
                package_database.info_directory,
                record.info_stem,
            },
        );
        const bytes = try root.readFileAlloc(
            allocator,
            try root_fs.Path.init(path),
            maximum_bytes,
        );
        if (bytes.len != script.size) return error.InstalledScriptMismatch;
        var digest: [32]u8 = undefined;
        Sha256.hash(bytes, &digest, .{});
        if (!std.mem.eql(u8, &digest, &script.sha256))
            return error.InstalledScriptMismatch;
        const result = try allocator.alloc(
            package_database_changes.StagedScript,
            1,
        );
        result[0] = .{
            .kind = .postrm,
            .bytes = bytes,
            .mode = script.mode,
        };
        return result;
    }
    return &.{};
}

fn stagedInstalledScripts(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    record: package_database.PackageRecord,
    maximum_bytes: usize,
) ![]const package_database_changes.StagedScript {
    const result = try allocator.alloc(
        package_database_changes.StagedScript,
        record.scripts.len,
    );
    for (record.scripts, 0..) |script, index| {
        const path = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}/{s}.{s}",
            .{
                package_database.database_directory,
                package_database.info_directory,
                record.info_stem,
                script.kind.suffix(),
            },
        );
        const bytes = try root.readFileAlloc(
            allocator,
            try root_fs.Path.init(path),
            maximum_bytes,
        );
        if (bytes.len != script.size) return error.InstalledScriptMismatch;
        var digest: [32]u8 = undefined;
        Sha256.hash(bytes, &digest, .{});
        if (!std.mem.eql(u8, &digest, &script.sha256))
            return error.InstalledScriptMismatch;
        result[index] = .{
            .kind = script.kind,
            .bytes = bytes,
            .mode = script.mode,
        };
    }
    return result;
}

fn materializeRemoval(
    allocator: std.mem.Allocator,
    request: MaterializationRequest,
    selections: []const ExternalPackageSelection,
    purge: bool,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(
        allocator,
        request.root,
        request.planning.limits.database,
    );
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(
        &captured.snapshot,
        request.planning.program.target_architecture,
    );
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = request.planning.program.target_architecture,
            .snapshot = captured.snapshot,
        },
        request.planning.limits.database,
    )) {
        .database => |value| value,
        .diagnostic => return .{
            .outcome = .refused,
            .detail = "database_rejected",
        },
    };
    defer database.deinit();
    if (phasePreflight(request, database)) |result| return result;
    const arena = try allocator.create(std.heap.ArenaAllocator);
    defer allocator.destroy(arena);
    arena.* = .init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    var intents: std.ArrayList(root_mutation.Intent) = .empty;
    defer intents.deinit(allocator);
    var changes: std.ArrayList(package_database_changes.Change) = .empty;
    defer changes.deinit(allocator);
    var selected_seen: std.StringHashMapUnmanaged(void) = .empty;
    defer selected_seen.deinit(allocator);
    var selected_owners: std.AutoHashMapUnmanaged(u32, void) = .empty;
    defer selected_owners.deinit(allocator);
    var selected_records: std.ArrayList(u32) = .empty;
    defer selected_records.deinit(allocator);
    for (selections) |selection| {
        const selection_key = try std.fmt.allocPrint(
            owned,
            "{s}\x00{s}",
            .{ selection.name, selection.architecture },
        );
        if ((try selected_seen.getOrPut(allocator, selection_key)).found_existing)
            return .{ .outcome = .refused, .detail = "duplicate_package" };
        var record_index: ?u32 = null;
        for (database.model.packages, 0..) |record, index| {
            if (std.mem.eql(u8, record.name, selection.name) and
                std.mem.eql(u8, record.architecture, selection.architecture))
                record_index = @intCast(index);
        }
        const index = record_index orelse continue;
        try selected_owners.put(allocator, index, {});
        try selected_records.append(allocator, index);
    }
    if (selected_records.items.len == 0) {
        var hash = Sha256.init(.{});
        hash.update(digest_domain);
        hashText(&hash, "remove-already-absent");
        hashText(&hash, &database.generation.sha256);
        const no_op_evidence: DatabasePhaseEvidence = .{
            .base_generation = database.generation,
            .base_status = database.model.status,
            .resulting_status = database.model.status,
            .digest = hash.finalResult(),
        };
        const no_op_intents = [_]root_mutation.Intent{.{ .remove = .{
            .path = package_database.database_directory ++ "/" ++
                package_database.status_old_path,
            .removal = .allow_absent,
        } }};
        return executePhaseMaterialization(
            allocator,
            request,
            &no_op_intents,
            no_op_evidence,
            no_op_evidence.digest,
            null,
            false,
        );
    }

    const aliases = detectAliases(allocator, request.root) catch
        return .{ .outcome = .handoff, .detail = "root_alias" };
    defer deinitAliasEvidence(allocator, aliases);
    var ownership = indexOwnership(
        allocator,
        database.model,
        aliases,
    ) catch return .{
        .outcome = .refused,
        .detail = "ownership_index",
    };
    defer ownership.deinit();
    var retained: std.StringHashMapUnmanaged(void) = .empty;
    defer retained.deinit(allocator);
    if (!purge) for (selected_records.items) |index| {
        const record = database.model.packages[index];
        for (record.conffiles) |conffile| {
            const relative = relativeListPath(conffile.path) orelse continue;
            var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
            const canonical = canonicalAliasPath(
                aliases,
                relative,
                &buffer,
            ) orelse return .{
                .outcome = .refused,
                .detail = "invalid_conffile",
            };
            const stored = try owned.dupe(u8, canonical);
            try retained.put(allocator, stored, {});
            var cursor = (root_fs.Path.init(stored) catch unreachable).parent();
            while (cursor) |parent| : (cursor = parent.parent())
                try retained.put(
                    allocator,
                    try owned.dupe(u8, parent.text),
                    {},
                );
        }
    };
    var removing: std.StringHashMapUnmanaged(void) = .empty;
    defer removing.deinit(allocator);
    var files: std.ArrayList([]const u8) = .empty;
    defer files.deinit(allocator);
    var directories: std.ArrayList([]const u8) = .empty;
    defer directories.deinit(allocator);

    for (selected_records.items) |record_index| {
        const record = &database.model.packages[record_index];
        if (record.status.error_state != .ok or record.status.want == .hold)
            return .{ .outcome = .refused, .detail = "package_state_unsupported" };
        switch (record.status.current) {
            .installed, .unpacked, .config_files => {},
            else => return .{
                .outcome = .refused,
                .detail = "package_state_unsupported",
            },
        }
        if (record.field("Config-Version") != null and
            configVersionField(record.*) == .invalid)
            return .{ .outcome = .refused, .detail = "config_version" };
        if ((request.borrowed_attempt == null and record.scripts.len != 0) or
            (!request.planning.trigger_execution and
                record.trigger_declarations != null) or
            record.triggers_pending.len != 0 or record.triggers_awaited.len != 0)
            return .{ .outcome = .handoff, .detail = "script_or_trigger" };

        var retained_paths: std.ArrayList([]const u8) = .empty;
        defer retained_paths.deinit(allocator);

        for (record.paths orelse &.{}) |listed| {
            const relative = relativeListPath(listed) orelse {
                if (!purge and record.conffiles.len != 0)
                    try retained_paths.append(allocator, listed);
                continue;
            };
            var alias_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
            const canonical = canonicalAliasPath(
                aliases,
                relative,
                &alias_buffer,
            ) orelse return .{ .outcome = .refused, .detail = "invalid_path" };
            if (!purge and retained.contains(canonical)) {
                try retained_paths.append(allocator, listed);
                continue;
            }
            var surviving_owner = false;
            for (ownership.ownersOf(canonical)) |owned_path| {
                if (!selected_owners.contains(owned_path.owner))
                    surviving_owner = true;
            }
            if (surviving_owner or removing.contains(canonical)) continue;
            const stored = try owned.dupe(u8, canonical);
            const observed = (try request.root.entryIfExists(
                try root_fs.Path.init(stored),
            )) orelse continue;
            switch (observed.kind) {
                .directory => try directories.append(allocator, stored),
                .file, .sym_link => {
                    try files.append(allocator, stored);
                    try removing.put(allocator, stored, {});
                },
                else => return .{
                    .outcome = .handoff,
                    .detail = "unsupported_root_feature",
                },
            }
        }

        if (purge) for (record.conffiles) |conffile| {
            const relative = relativeListPath(conffile.path) orelse
                return .{ .outcome = .refused, .detail = "invalid_conffile" };
            for ([_][]const u8{ "", ".dpkg-old", ".dpkg-dist", ".dpkg-new" }) |suffix| {
                // dpkg deliberately leaves the saved administrator version
                // created by remove-on-upgrade outside package ownership.
                if (conffile.remove_on_upgrade and
                    std.mem.eql(u8, suffix, ".dpkg-old"))
                    continue;
                const path = try std.fmt.allocPrint(
                    owned,
                    "{s}{s}",
                    .{ relative, suffix },
                );
                if (removing.contains(path)) continue;
                for (ownership.ownersOf(path)) |owned_path| {
                    if (!selected_owners.contains(owned_path.owner))
                        return .{
                            .outcome = .handoff,
                            .detail = "foreign_owned_conffile",
                        };
                }
                const observed = (try request.root.entryIfExists(
                    try root_fs.Path.init(path),
                )) orelse continue;
                if (!observed.isRegularFile() or !observed.modeled or
                    observed.link_count != 1)
                    return .{
                        .outcome = .handoff,
                        .detail = "unsupported_conffile",
                    };
                try files.append(allocator, path);
                try removing.put(allocator, path, {});
            }
        };

        if (purge or record.conffiles.len == 0) {
            if (purge or request.borrowed_attempt == null or record.scripts.len == 0) {
                try changes.append(allocator, .{
                    .remove_package = record.identity(),
                });
            } else {
                if (retained_paths.items.len == 0 and
                    !request.planning.trigger_execution)
                    try retained_paths.append(
                        allocator,
                        package_database.root_list_path,
                    );
                const fields = try phaseStatusFields(
                    owned,
                    record.*,
                    .deinstall,
                    .ok,
                    .config_files,
                    removalConfigVersion(record.*),
                    record.conffiles,
                );
                try changes.append(allocator, .{ .put_package = .{
                    .fields = fields,
                    .paths = try owned.dupe([]const u8, retained_paths.items),
                    .md5sums = null,
                    .declared_conffiles = null,
                    .trigger_declarations = null,
                    .scripts = try retainedPostrmScript(
                        owned,
                        request.root,
                        record.*,
                        request.planning.limits.database.limits.max_info_file_bytes,
                    ),
                } });
            }
        } else {
            const fields = try phaseStatusFields(
                owned,
                record.*,
                .deinstall,
                .ok,
                .config_files,
                removalConfigVersion(record.*),
                record.conffiles,
            );
            try changes.append(allocator, .{ .put_package = .{
                .fields = fields,
                .paths = try owned.dupe([]const u8, retained_paths.items),
                .md5sums = null,
                .declared_conffiles = null,
                .trigger_declarations = null,
                .scripts = if (request.borrowed_attempt != null)
                    try retainedPostrmScript(
                        owned,
                        request.root,
                        record.*,
                        request.planning.limits.database.limits.max_info_file_bytes,
                    )
                else
                    &.{},
            } });
        }
    }

    std.mem.sort([]const u8, files.items, {}, lessPath);
    for (files.items) |path| try intents.append(allocator, .{ .remove = .{
        .path = path,
        .removal = .allow_absent,
    } });
    std.mem.sort([]const u8, directories.items, {}, greaterPath);
    for (directories.items) |path| {
        if (removing.contains(path)) continue;
        if (!try removableDirectory(request.root, path, &removing))
            continue;
        try removing.put(allocator, path, {});
        try intents.append(allocator, .{ .remove_directory = .{
            .path = path,
            .removal = .allow_absent,
        } });
    }
    if (request.planning.trigger_execution) {
        var interests: std.ArrayList(package_database.TriggerInterest) = .empty;
        defer interests.deinit(allocator);
        for (database.model.triggers.interests) |interest| {
            var owner: ?u32 = null;
            for (database.model.packages, 0..) |record, index| {
                if (!std.mem.eql(u8, record.name, interest.package.name))
                    continue;
                if (interest.package.architecture.len != 0 and
                    !std.mem.eql(
                        u8,
                        record.architecture,
                        interest.package.architecture,
                    ))
                    continue;
                if (owner != null and interest.package.architecture.len == 0)
                    return .{
                        .outcome = .refused,
                        .detail = "ambiguous_trigger_owner",
                    };
                owner = @intCast(index);
            }
            if (owner != null and selected_owners.contains(owner.?)) continue;
            try interests.append(allocator, interest);
        }
        try changes.append(allocator, .{ .set_trigger_state = .{
            .interests = try owned.dupe(
                package_database.TriggerInterest,
                interests.items,
            ),
            .pending = database.model.triggers.pending,
        } });
    }
    var database_plan = switch (try package_database_changes.plan(
        allocator,
        database,
        changes.items,
        .{ .database = request.planning.limits.database },
    )) {
        .plan => |value| value,
        .diagnostic => |diagnostic| return .{
            .outcome = .refused,
            .detail = @tagName(diagnostic.code),
        },
    };
    defer database_plan.deinit();
    const directory = try request.root.entry(
        try root_fs.Path.init(package_database.database_directory),
    );
    var database_intents = switch (try root_mutation.lowerDatabasePlan(
        allocator,
        database_plan,
        .{ .uid = directory.uid, .gid = directory.gid },
    )) {
        .intents => |value| value,
        .diagnostic => return error.MaterializationDatabaseMismatch,
    };
    defer database_intents.deinit();
    try intents.appendSlice(allocator, database_intents.intents);
    return executePhaseMaterialization(
        allocator,
        request,
        intents.items,
        databasePhaseEvidence(database_plan),
        conffilePhaseDigest(
            if (purge) "purge" else "remove",
            database_plan,
            null,
        ),
        null,
        false,
    );
}

fn unchangedDatabaseEvidence(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    architecture: []const u8,
    options: package_database.Options,
) !DatabasePhaseEvidence {
    var captured = try captureDatabaseSnapshot(allocator, root, options);
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{ .native_architecture = architecture, .snapshot = captured.snapshot },
        options,
    )) {
        .database => |value| value,
        .diagnostic => return error.MaterializationDatabaseMismatch,
    };
    defer database.deinit();
    const generation = database.generation;
    var digest = Sha256.init(.{});
    digest.update(digest_domain);
    hashText(&digest, "lifecycle-unchanged-database");
    hashText(&digest, &generation.sha256);
    return .{
        .base_generation = generation,
        .base_status = database.model.status,
        .resulting_status = database.model.status,
        .digest = digest.finalResult(),
    };
}

fn lifecycleAuxiliaryMutation(
    allocator: std.mem.Allocator,
    request: MaterializationRequest,
    intents: []const root_mutation.Intent,
    label: []const u8,
) !MaterializationResult {
    const evidence = try unchangedDatabaseEvidence(
        allocator,
        request.root,
        request.planning.program.target_architecture,
        request.planning.limits.database,
    );
    var digest = Sha256.init(.{});
    digest.update(digest_domain);
    hashText(&digest, "lifecycle-auxiliary");
    hashText(&digest, label);
    hashText(&digest, &evidence.base_generation.sha256);
    return executePhaseMaterialization(
        allocator,
        request,
        intents,
        evidence,
        digest.finalResult(),
        null,
        false,
    );
}

fn materializeStateRecord(
    allocator: std.mem.Allocator,
    request: MaterializationRequest,
    state: native_program.StateRecord,
    want_override: ?package_database.Want,
    error_override: ?package_database.ErrorState,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(
        allocator,
        request.root,
        request.planning.limits.database,
    );
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(
        &captured.snapshot,
        request.planning.program.target_architecture,
    );
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = request.planning.program.target_architecture,
            .snapshot = captured.snapshot,
        },
        request.planning.limits.database,
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "database_rejected" },
    };
    defer database.deinit();
    if (phasePreflight(request, database)) |result| return result;
    const record = database.model.find(
        state.package.name,
        state.package.architecture,
    );
    if (record == null) {
        if (state.remove_entry) return .{ .outcome = .applied, .detail = "already_absent" };
        return .{ .outcome = .refused, .detail = "package_not_installed" };
    }
    const change: package_database_changes.Change = if (state.remove_entry)
        .{ .remove_package = record.?.identity() }
    else
        .{ .set_state = .{
            .identity = record.?.identity(),
            .want = want_override orelse if (state.hold)
                .hold
            else if (state.state == .config_files)
                .deinstall
            else
                .install,
            .error_state = error_override orelse .ok,
            .current = state.state,
        } };
    var database_plan = switch (try package_database_changes.plan(
        allocator,
        database,
        &.{change},
        .{ .database = request.planning.limits.database },
    )) {
        .plan => |value| value,
        .diagnostic => |diagnostic| return .{
            .outcome = .refused,
            .detail = @tagName(diagnostic.code),
        },
    };
    defer database_plan.deinit();
    const directory = try request.root.entry(
        try root_fs.Path.init(package_database.database_directory),
    );
    var database_intents = switch (try root_mutation.lowerDatabasePlan(
        allocator,
        database_plan,
        .{ .uid = directory.uid, .gid = directory.gid },
    )) {
        .intents => |value| value,
        .diagnostic => return error.MaterializationDatabaseMismatch,
    };
    defer database_intents.deinit();
    return executePhaseMaterialization(
        allocator,
        request,
        database_intents.intents,
        databasePhaseEvidence(database_plan),
        conffilePhaseDigest("lifecycle-state", database_plan, null),
        null,
        true,
    );
}

fn materializeFreshFailureRecord(
    allocator: std.mem.Allocator,
    request: MaterializationRequest,
    package: native_program.PackageIdentity,
    unwind_succeeded: bool,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(
        allocator,
        request.root,
        request.planning.limits.database,
    );
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(
        &captured.snapshot,
        request.planning.program.target_architecture,
    );
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = request.planning.program.target_architecture,
            .snapshot = captured.snapshot,
        },
        request.planning.limits.database,
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "database_rejected" },
    };
    defer database.deinit();
    if (database.model.find(package.name, package.architecture) != null)
        return .{ .outcome = .refused, .detail = "package_already_present" };

    const status = if (unwind_succeeded)
        try std.fmt.allocPrint(
            allocator,
            "{s}Package: {s}\nStatus: install ok not-installed\nArchitecture: {s}\n\n",
            .{
                captured.snapshot.status.bytes,
                package.name,
                package.architecture,
            },
        )
    else
        try std.fmt.allocPrint(
            allocator,
            "{s}Package: {s}\nStatus: install reinstreq half-installed\n" ++
                "Architecture: {s}\nVersion: {s}\n\n",
            .{
                captured.snapshot.status.bytes,
                package.name,
                package.architecture,
                package.version,
            },
        );
    defer allocator.free(status);
    var status_sha256: [32]u8 = undefined;
    Sha256.hash(status, &status_sha256, .{});
    const status_path = package_database.database_directory ++ "/" ++
        package_database.status_path;
    const status_old_path = package_database.database_directory ++ "/" ++
        package_database.status_old_path;
    const status_entry = try request.root.entry(try root_fs.Path.init(status_path));
    const old_entry = try request.root.entryIfExists(
        try root_fs.Path.init(status_old_path),
    );
    var empty_sha256: [32]u8 = undefined;
    Sha256.hash("", &empty_sha256, .{});
    const trigger_lock_path = package_database.database_directory ++
        "/triggers/Lock";
    const trigger_unincorp_path = package_database.database_directory ++
        "/triggers/Unincorp";
    const trigger_lock = try request.root.entryIfExists(
        try root_fs.Path.init(trigger_lock_path),
    );
    const trigger_unincorp = try request.root.entryIfExists(
        try root_fs.Path.init(trigger_unincorp_path),
    );
    const intents = [_]root_mutation.Intent{
        .{ .file = .{
            .path = status_path,
            .bytes = status,
            .mode = status_entry.mode,
            .uid = status_entry.uid,
            .gid = status_entry.gid,
            .overwrite = .replace,
            .expected_sha256 = status_sha256,
        } },
        .{ .file = .{
            .path = status_old_path,
            .bytes = captured.snapshot.status.bytes,
            .mode = if (old_entry) |entry| entry.mode else status_entry.mode,
            .uid = if (old_entry) |entry| entry.uid else status_entry.uid,
            .gid = if (old_entry) |entry| entry.gid else status_entry.gid,
            .overwrite = if (old_entry == null) .require_absent else .replace,
            .expected_sha256 = database.model.status.sha256,
        } },
        .{ .file = .{
            .path = trigger_lock_path,
            .bytes = "",
            .mode = 0o600,
            .uid = 0,
            .gid = 0,
            .overwrite = if (trigger_lock == null) .require_absent else .replace,
            .expected_sha256 = empty_sha256,
        } },
        .{ .file = .{
            .path = trigger_unincorp_path,
            .bytes = "",
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .overwrite = if (trigger_unincorp == null) .require_absent else .replace,
            .expected_sha256 = empty_sha256,
        } },
    };
    var phase_digest = Sha256.init(.{});
    phase_digest.update(digest_domain);
    hashText(&phase_digest, "fresh-script-failure");
    hashText(&phase_digest, &database.generation.sha256);
    hashText(&phase_digest, &status_sha256);
    const evidence: DatabasePhaseEvidence = .{
        .base_generation = database.generation,
        .base_status = database.model.status,
        .resulting_status = .{
            .sha256 = status_sha256,
            .size = status.len,
            .package_count = database.model.status.package_count + 1,
        },
        .digest = phase_digest.finalResult(),
    };
    return executePhaseMaterialization(
        allocator,
        request,
        &intents,
        evidence,
        evidence.digest,
        null,
        true,
    );
}

fn materializeDetailedState(
    allocator: std.mem.Allocator,
    request: MaterializationRequest,
    package: native_program.PackageIdentity,
    want: package_database.Want,
    error_state: package_database.ErrorState,
    current: package_database.CurrentState,
    config_version: ?[]const u8,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(
        allocator,
        request.root,
        request.planning.limits.database,
    );
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(
        &captured.snapshot,
        request.planning.program.target_architecture,
    );
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = request.planning.program.target_architecture,
            .snapshot = captured.snapshot,
        },
        request.planning.limits.database,
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "database_rejected" },
    };
    defer database.deinit();
    const record = database.model.find(
        package.name,
        package.architecture,
    ) orelse return .{ .outcome = .refused, .detail = "package_not_installed" };
    const arena = try allocator.create(std.heap.ArenaAllocator);
    defer allocator.destroy(arena);
    arena.* = .init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    const fields = try phaseStatusFields(
        owned,
        record.*,
        want,
        error_state,
        current,
        config_version,
        record.conffiles,
    );
    const scripts = try stagedInstalledScripts(
        owned,
        request.root,
        record.*,
        request.planning.limits.database.limits.max_info_file_bytes,
    );
    const change: package_database_changes.Change = .{ .put_package = .{
        .fields = fields,
        .paths = record.paths,
        .md5sums = record.md5sums,
        .declared_conffiles = record.declared_conffiles,
        .trigger_declarations = record.trigger_declarations,
        .scripts = scripts,
    } };
    var database_plan = switch (try package_database_changes.plan(
        allocator,
        database,
        &.{change},
        .{ .database = request.planning.limits.database },
    )) {
        .plan => |value| value,
        .diagnostic => |diagnostic| return .{
            .outcome = .refused,
            .detail = @tagName(diagnostic.code),
        },
    };
    defer database_plan.deinit();
    const directory = try request.root.entry(
        try root_fs.Path.init(package_database.database_directory),
    );
    var database_intents = switch (try root_mutation.lowerDatabasePlan(
        allocator,
        database_plan,
        .{ .uid = directory.uid, .gid = directory.gid },
    )) {
        .intents => |value| value,
        .diagnostic => return error.MaterializationDatabaseMismatch,
    };
    defer database_intents.deinit();
    return executePhaseMaterialization(
        allocator,
        request,
        database_intents.intents,
        databasePhaseEvidence(database_plan),
        conffilePhaseDigest("lifecycle-detailed-state", database_plan, null),
        null,
        true,
    );
}

fn snapshotScripts(
    allocator: std.mem.Allocator,
    snapshot: package_database.Snapshot,
    record: package_database.PackageRecord,
) ![]const package_database_changes.StagedScript {
    const scripts = try allocator.alloc(
        package_database_changes.StagedScript,
        record.scripts.len,
    );
    for (record.scripts, 0..) |script, index| {
        const name = try std.fmt.allocPrint(
            allocator,
            "{s}.{s}",
            .{ record.info_stem, script.kind.suffix() },
        );
        const entry = for (snapshot.info) |candidate| {
            if (std.mem.eql(u8, candidate.name, name)) break candidate;
        } else return error.InstalledScriptMissing;
        if (entry.kind != .regular or entry.bytes.len != script.size)
            return error.InstalledScriptMismatch;
        var digest: [32]u8 = undefined;
        Sha256.hash(entry.bytes, &digest, .{});
        if (!std.mem.eql(u8, &digest, &script.sha256))
            return error.InstalledScriptMismatch;
        scripts[index] = .{
            .kind = script.kind,
            .bytes = entry.bytes,
            .mode = entry.mode,
        };
    }
    return scripts;
}

fn materializeRestoredPackageState(
    allocator: std.mem.Allocator,
    request: MaterializationRequest,
    initial_snapshot: package_database.Snapshot,
    initial_model: package_database.Model,
    package: native_program.PackageIdentity,
    want: package_database.Want,
    error_state: package_database.ErrorState,
    current: package_database.CurrentState,
    config_version: ?[]const u8,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(
        allocator,
        request.root,
        request.planning.limits.database,
    );
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(
        &captured.snapshot,
        request.planning.program.target_architecture,
    );
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = request.planning.program.target_architecture,
            .snapshot = captured.snapshot,
        },
        request.planning.limits.database,
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "database_rejected" },
    };
    defer database.deinit();
    const initial = initial_model.find(
        package.name,
        package.architecture,
    ) orelse return .{ .outcome = .refused, .detail = "initial_package_missing" };
    const current_record = database.model.find(
        package.name,
        package.architecture,
    );
    const arena = try allocator.create(std.heap.ArenaAllocator);
    defer allocator.destroy(arena);
    arena.* = .init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    const fields = try phaseStatusFields(
        owned,
        initial.*,
        want,
        error_state,
        current,
        config_version,
        initial.conffiles,
    );
    const change: package_database_changes.Change = .{ .put_package = .{
        .fields = fields,
        .paths = if (current_record) |record| record.paths else initial.paths,
        .md5sums = initial.md5sums,
        .declared_conffiles = initial.declared_conffiles,
        .trigger_declarations = initial.trigger_declarations,
        .scripts = try snapshotScripts(owned, initial_snapshot, initial.*),
    } };
    var database_plan = switch (try package_database_changes.plan(
        allocator,
        database,
        &.{change},
        .{ .database = request.planning.limits.database },
    )) {
        .plan => |value| value,
        .diagnostic => |diagnostic| return .{
            .outcome = .refused,
            .detail = @tagName(diagnostic.code),
        },
    };
    defer database_plan.deinit();
    const directory = try request.root.entry(
        try root_fs.Path.init(package_database.database_directory),
    );
    var database_intents = switch (try root_mutation.lowerDatabasePlan(
        allocator,
        database_plan,
        .{ .uid = directory.uid, .gid = directory.gid },
    )) {
        .intents => |value| value,
        .diagnostic => return error.MaterializationDatabaseMismatch,
    };
    defer database_intents.deinit();
    return executePhaseMaterialization(
        allocator,
        request,
        database_intents.intents,
        databasePhaseEvidence(database_plan),
        conffilePhaseDigest("lifecycle-restored-state", database_plan, null),
        null,
        true,
    );
}

const TriggerPackageUpdate = struct {
    package: package_database.Identity,
    want: package_database.Want = .install,
    error_state: package_database.ErrorState = .ok,
    current: package_database.CurrentState,
    config_version: ?[]const u8,
    pending: []const []const u8 = &.{},
    awaited: []const []const u8 = &.{},
};

fn materializeTriggerDatabase(
    allocator: std.mem.Allocator,
    request: MaterializationRequest,
    updates: []const TriggerPackageUpdate,
    trigger_state: ?package_database.TriggerState,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(
        allocator,
        request.root,
        request.planning.limits.database,
    );
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(
        &captured.snapshot,
        request.planning.program.target_architecture,
    );
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = request.planning.program.target_architecture,
            .snapshot = captured.snapshot,
        },
        request.planning.limits.database,
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "database_rejected" },
    };
    defer database.deinit();
    const arena = try allocator.create(std.heap.ArenaAllocator);
    defer allocator.destroy(arena);
    arena.* = .init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    var changes: std.ArrayList(package_database_changes.Change) = .empty;
    defer changes.deinit(allocator);
    for (updates) |update| {
        const record = database.model.find(
            update.package.name,
            update.package.architecture,
        ) orelse return .{
            .outcome = .refused,
            .detail = "trigger_package_missing",
        };
        const fields = try triggerStatusFields(
            owned,
            record.*,
            update.want,
            update.error_state,
            update.current,
            update.config_version,
            update.pending,
            update.awaited,
        );
        try changes.append(allocator, .{ .put_package = .{
            .fields = fields,
            .paths = record.paths,
            .md5sums = record.md5sums,
            .declared_conffiles = record.declared_conffiles,
            .trigger_declarations = record.trigger_declarations,
            .scripts = try stagedInstalledScripts(
                owned,
                request.root,
                record.*,
                request.planning.limits.database.limits.max_info_file_bytes,
            ),
        } });
    }
    if (trigger_state) |state|
        try changes.append(allocator, .{ .set_trigger_state = state });
    if (changes.items.len == 0)
        return .{ .outcome = .applied, .detail = "trigger_database_unchanged" };
    var database_plan = switch (try package_database_changes.plan(
        allocator,
        database,
        changes.items,
        .{ .database = request.planning.limits.database },
    )) {
        .plan => |value| value,
        .diagnostic => |diagnostic| return .{
            .outcome = .refused,
            .detail = @tagName(diagnostic.code),
        },
    };
    defer database_plan.deinit();
    const directory = try request.root.entry(
        try root_fs.Path.init(package_database.database_directory),
    );
    var database_intents = switch (try root_mutation.lowerDatabasePlan(
        allocator,
        database_plan,
        .{ .uid = directory.uid, .gid = directory.gid },
    )) {
        .intents => |value| value,
        .diagnostic => return error.MaterializationDatabaseMismatch,
    };
    defer database_intents.deinit();
    return executePhaseMaterialization(
        allocator,
        request,
        database_intents.intents,
        databasePhaseEvidence(database_plan),
        conffilePhaseDigest("trigger-database", database_plan, null),
        null,
        true,
    );
}

// ---------------------------------------------------------------------------
// Fuzz boundary
// ---------------------------------------------------------------------------

/// Side-effect-free ownership boundary.
///
/// `info/*.list` bytes are attacker-reachable on a compromised root, and the
/// ownership index, the canonical relative spelling, the sorted order, and
/// the descendant probe all read them. This drives that exact code with
/// arbitrary bytes and releases everything it builds.
pub fn fuzzOwnership(allocator: std.mem.Allocator, bytes: []const u8) void {
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(allocator);
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        count += 1;
        if (count > 4096) break;
        paths.append(allocator, line) catch return;
    }
    if (paths.items.len == 0) return;

    const record: package_database.PackageRecord = .{
        .name = "fuzz",
        .architecture = "amd64",
        .version = "1",
        .parsed_version = version_module.DebianVersion.parse("1") catch return,
        .status = .{ .want = .install, .error_state = .ok, .current = .unpacked },
        .multi_arch = null,
        .essential = false,
        .protected = false,
        .fields = &.{},
        .conffiles = &.{},
        .triggers_pending = &.{},
        .triggers_awaited = &.{},
        .info_stem = "fuzz",
        .paths = paths.items,
        .md5sums = null,
        .declared_conffiles = null,
        .trigger_declarations = null,
        .scripts = &.{},
    };
    const packages = [_]package_database.PackageRecord{record};
    const model: package_database.Model = .{
        .native_architecture = "amd64",
        .status = .{ .sha256 = @splat(0), .size = 0, .package_count = 1 },
        .packages = &packages,
    };
    var ownership = indexOwnership(
        allocator,
        model,
        .{ .aliases = &.{}, .foreign = &.{} },
    ) catch return;
    defer ownership.deinit();

    var prefix: [root_fs.maximum_path_bytes]u8 = undefined;
    for (paths.items) |listed| {
        const relative = relativeListPath(listed) orelse continue;
        _ = ownership.ownersOf(relative);
        _ = ownership.owned(relative);
        _ = ownership.hasSurvivingDescendant(relative, &.{}, 4096, &prefix) catch {};
    }
    _ = canonicalAliasTarget(bytes);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const deb822 = @import("deb822.zig");

const test_install_root = "/target";
const test_mtime_ns: i128 = @as(i128, archive_application.test_fixtures.mtime) *
    std.time.ns_per_s;

fn zeroDigest() native_program.Digest {
    return @splat('0');
}

/// A disposable read-only planning root holding one database generation.
const Fixture = struct {
    tmp: std.testing.TmpDir,
    status: []const u8,
    info: []const package_database.InfoEntry,
    arch: ?[]const u8,
    /// `info` plus the `format` marker the root also holds, so the imported
    /// generation covers exactly the bytes on disk.
    full_info: []package_database.InfoEntry,

    fn init(
        self: *Fixture,
        status: []const u8,
        info: []const package_database.InfoEntry,
    ) !void {
        return self.initFull(status, info, null);
    }

    fn initFull(
        self: *Fixture,
        status: []const u8,
        info: []const package_database.InfoEntry,
        arch: ?[]const u8,
    ) !void {
        self.tmp = testing.tmpDir(.{ .iterate = true });
        errdefer self.tmp.cleanup();
        self.status = status;
        self.info = info;
        self.arch = arch;
        self.full_info = try testing.allocator.alloc(
            package_database.InfoEntry,
            info.len + 1,
        );
        errdefer testing.allocator.free(self.full_info);
        self.full_info[0] = .{
            .name = package_database.info_format_name,
            .bytes = package_database.supported_info_format ++ "\n",
        };
        for (info, 0..) |entry, index| self.full_info[index + 1] = entry;

        try self.materialize();
    }

    fn deinit(self: *Fixture) void {
        testing.allocator.free(self.full_info);
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn root(self: *Fixture) root_fs.Root {
        return .init(testing.io, self.tmp.dir);
    }

    fn materialize(self: *Fixture) !void {
        const target = self.root();
        for ([_][]const u8{
            "var",
            "var/lib",
            "var/lib/dpkg",
            "var/lib/dpkg/info",
            "var/lib/dpkg/updates",
            "var/lib/dpkg/triggers",
        }) |path| {
            try target.ensureDirectory(
                try root_fs.Path.init(path),
                root_fs.default_directory_permissions,
            );
        }
        try target.publishFile(
            try root_fs.Path.init("var/lib/dpkg/status"),
            self.status,
            .{},
        );
        if (self.arch) |text| try target.publishFile(
            try root_fs.Path.init("var/lib/dpkg/arch"),
            text,
            .{},
        );
        for (self.full_info) |entry| try writeInfo(target, entry.name, entry.bytes, entry.mode);
    }

    fn snapshot(self: *Fixture) package_database.Snapshot {
        return .{
            .status = package_database.regularFile(self.status),
            .arch = if (self.arch) |text| package_database.regularFile(text) else null,
            .info = self.full_info,
        };
    }

    fn database(self: *Fixture) !package_database.Database {
        return switch (try package_database.importSnapshot(testing.allocator, .{
            .native_architecture = "amd64",
            .snapshot = self.snapshot(),
        }, .{})) {
            .database => |value| value,
            .diagnostic => |diagnostic| {
                std.debug.print("unexpected database diagnostic: {any}\n", .{diagnostic});
                return error.TestUnexpectedResult;
            },
        };
    }
};

fn writeInfo(target: root_fs.Root, name: []const u8, bytes: []const u8, mode: u32) !void {
    var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
    const spelling = try std.fmt.bufPrint(&buffer, "var/lib/dpkg/info/{s}", .{name});
    const path = try root_fs.Path.init(spelling);
    try target.publishFile(path, bytes, .{});
    try target.applyMetadata(path, .{ .mode = mode });
}

fn currentUid() u32 {
    return if (builtin.os.tag == .linux) std.os.linux.getuid() else 0;
}

fn currentGid() u32 {
    return if (builtin.os.tag == .linux) std.os.linux.getgid() else 0;
}

/// Fixture payloads are owned by the user running the tests, so a hermetic
/// root can be published without privilege while every other metadata rule
/// stays exactly the production one.
fn buildOwnedArchive(
    options: archive_application.test_fixtures.Archive,
    data: []archive_application.test_fixtures.Entry,
) ![]u8 {
    for (data) |*entry| {
        entry.uid = currentUid();
        entry.gid = currentGid();
    }
    var owned = options;
    owned.data = data;
    return archive_application.test_fixtures.build(testing.allocator, owned);
}

fn modelOf(bytes: []const u8) !archive_application.Model {
    return switch (archive_application.prepare(
        testing.allocator,
        bytes,
        .{ .local = .{} },
        .{},
    )) {
        .model => |value| value,
        .diagnostic => |diagnostic| {
            std.debug.print("unexpected archive diagnostic: {s}\n", .{diagnostic.message()});
            return error.TestUnexpectedResult;
        },
    };
}

fn testArtifact(
    index: u32,
    model: *const archive_application.Model,
    size: u64,
) native_program.ProgramArtifact {
    return .{
        .index = index,
        .package = .{
            .name = model.facts.package,
            .version = model.facts.version,
            .architecture = model.facts.architecture,
        },
        .sha256 = hex(32, model.provenance().sha256),
        .size = size,
        .application_sha256 = hex(32, model.digest),
        .origin = .{ .local_artifact = .{
            .artifact_id = @splat('0'),
            .sha256 = hex(32, model.provenance().sha256),
            .size = size,
            .package = .{
                .name = model.facts.package,
                .version = model.facts.version,
                .architecture = model.facts.architecture,
            },
            .acquisition_url = "file:///fixture.deb",
            .trust_mode = .pinned_sha256,
        } },
    };
}

fn unpackStep(
    sequence: u32,
    model: *const archive_application.Model,
    artifact: u32,
    prior_version: ?[]const u8,
    bootstrapped: bool,
) native_program.Step {
    return .{
        .sequence = sequence,
        .phase = .unpack,
        .requires = &.{},
        .operation = .{ .unpack_package = .{
            .package = .{
                .name = model.facts.package,
                .version = model.facts.version,
                .architecture = model.facts.architecture,
            },
            .prior_version = prior_version,
            .artifact = artifact,
            .application_sha256 = hex(32, model.digest),
            .bootstrapped = bootstrapped,
            .prior_owned_paths_sha256 = null,
        } },
    };
}

fn bootstrapStep(
    sequence: u32,
    model: *const archive_application.Model,
    artifact: u32,
) native_program.Step {
    return .{
        .sequence = sequence,
        .phase = .bootstrap,
        .requires = &.{},
        .operation = .{ .materialize_bootstrap_payload = .{
            .package = .{
                .name = model.facts.package,
                .version = model.facts.version,
                .architecture = model.facts.architecture,
            },
            .artifact = artifact,
            .application_sha256 = hex(32, model.digest),
        } },
    };
}

fn testProgram(
    generation: [32]u8,
    package_count: u64,
    artifacts: []const native_program.ProgramArtifact,
    steps: []const native_program.Step,
) native_program.Program {
    return .{
        .schema = native_program.schema_id,
        .version = native_program.schema_version,
        .backend = .native,
        .install_root = test_install_root,
        .root_identity_sha256 = zeroDigest(),
        .target_architecture = "amd64",
        .foreign_architectures = &.{},
        .request_sha256 = zeroDigest(),
        .solver_policy_sha256 = zeroDigest(),
        .executor_policy_sha256 = zeroDigest(),
        .plan_sha256 = zeroDigest(),
        .exact_lock = .{
            .schema = "https://debz.dev/schema/exact-closure-lock-v2",
            .version = 2,
            .digest_sha256 = zeroDigest(),
        },
        .authorization_sha256 = zeroDigest(),
        .final_state_sha256 = zeroDigest(),
        .policy = .{ .conffile = .keep_existing, .force = &.{}, .allow_host_root = false },
        .script_policy_sha256 = zeroDigest(),
        .installed_database = .{
            .generation_sha256 = hex(32, generation),
            .evidence_sha256 = zeroDigest(),
            .package_count = package_count,
        },
        .artifacts = artifacts,
        .artifacts_sha256 = zeroDigest(),
        .steps = steps,
        .steps_sha256 = zeroDigest(),
        .digest_sha256 = zeroDigest(),
    };
}

fn expectPlan(result: Result) !Plan {
    return switch (result) {
        .plan => |value| value,
        .handoff => |value| {
            var owned = value;
            defer owned.deinit();
            std.debug.print("unexpected handoff: {any}\n", .{owned.items});
            return error.TestUnexpectedResult;
        },
        .refusal => |value| {
            var owned = value;
            defer owned.deinit();
            std.debug.print("unexpected refusal: {any}\n", .{owned.diagnostic});
            return error.TestUnexpectedResult;
        },
    };
}

fn expectRefusal(result: Result, code: Code) !void {
    switch (result) {
        .plan => |value| {
            var owned = value;
            owned.deinit();
            return error.TestUnexpectedResult;
        },
        .handoff => |value| {
            var owned = value;
            owned.deinit();
            return error.TestUnexpectedResult;
        },
        .refusal => |value| {
            var owned = value;
            defer owned.deinit();
            try testing.expectEqual(code, owned.diagnostic.code);
        },
    }
}

fn expectHandoff(result: Result, feature: DeferredFeature) !void {
    switch (result) {
        .plan => |value| {
            var owned = value;
            owned.deinit();
            return error.TestUnexpectedResult;
        },
        .refusal => |value| {
            var owned = value;
            defer owned.deinit();
            std.debug.print("unexpected refusal: {any}\n", .{owned.diagnostic});
            return error.TestUnexpectedResult;
        },
        .handoff => |value| {
            var owned = value;
            defer owned.deinit();
            try testing.expect(owned.requires(feature));
            try testing.expect(!std.mem.eql(u8, &owned.digest, &[_]u8{0} ** 32));
        },
    }
}

fn expectConffileHandoff(
    result: Result,
    package: []const u8,
    path: []const u8,
) !void {
    switch (result) {
        .plan => |value| {
            var owned = value;
            owned.deinit();
            return error.TestUnexpectedResult;
        },
        .refusal => |value| {
            var owned = value;
            defer owned.deinit();
            return error.TestUnexpectedResult;
        },
        .handoff => |value| {
            var owned = value;
            defer owned.deinit();
            for (owned.items) |item| {
                if (item.feature == .conffile and
                    std.mem.eql(u8, item.package, package) and
                    std.mem.eql(u8, item.detail, path)) return;
            }
            return error.TestUnexpectedResult;
        },
    }
}

const Entry = archive_application.test_fixtures.Entry;

const empty_status = "";

fn planFor(
    fixture: *Fixture,
    program: *const native_program.Program,
    archives: []const ArchiveInput,
) std.mem.Allocator.Error!Result {
    return plan(testing.allocator, .{
        .program = program,
        .snapshot = fixture.snapshot(),
        .archives = archives,
        .root = fixture.root(),
        .interoperability = .isolated_root,
    });
}

fn planWith(
    fixture: *Fixture,
    program: *const native_program.Program,
    archives: []const ArchiveInput,
    interoperability: Interoperability,
    unmodeled_database_entries: []const []const u8,
    unsupported_root_features: []const []const u8,
) std.mem.Allocator.Error!Result {
    return plan(testing.allocator, .{
        .program = program,
        .snapshot = fixture.snapshot(),
        .archives = archives,
        .root = fixture.root(),
        .interoperability = interoperability,
        .unmodeled_database_entries = unmodeled_database_entries,
        .unsupported_root_features = unsupported_root_features,
    });
}

fn planLimited(
    fixture: *Fixture,
    program: *const native_program.Program,
    archives: []const ArchiveInput,
    limits: Limits,
) std.mem.Allocator.Error!Result {
    return plan(testing.allocator, .{
        .program = program,
        .snapshot = fixture.snapshot(),
        .archives = archives,
        .root = fixture.root(),
        .interoperability = .isolated_root,
        .limits = limits,
    });
}

fn planSnapshot(
    fixture: *Fixture,
    program: *const native_program.Program,
    archives: []const ArchiveInput,
    snapshot: package_database.Snapshot,
    limits: Limits,
) std.mem.Allocator.Error!Result {
    return plan(testing.allocator, .{
        .program = program,
        .snapshot = snapshot,
        .archives = archives,
        .root = fixture.root(),
        .interoperability = .isolated_root,
        .limits = limits,
    });
}

fn seedFile(root: root_fs.Root, path: []const u8, bytes: []const u8) !void {
    const resolved = try root_fs.Path.init(path);
    var components = std.mem.splitScalar(u8, resolved.text, '/');
    var buffer: [root_fs.maximum_path_bytes]u8 = undefined;
    var length: usize = 0;
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(testing.allocator);
    while (components.next()) |component| try parts.append(testing.allocator, component);
    for (parts.items[0 .. parts.items.len - 1]) |component| {
        if (length != 0) {
            buffer[length] = '/';
            length += 1;
        }
        @memcpy(buffer[length .. length + component.len], component);
        length += component.len;
        try root.ensureDirectory(
            try root_fs.Path.init(buffer[0..length]),
            root_fs.default_directory_permissions,
        );
    }
    try root.publishFile(resolved, bytes, .{});
}

fn singleProgram(
    fixture: *Fixture,
    model: *const archive_application.Model,
    bytes: []const u8,
    steps: []const native_program.Step,
    artifacts: *[1]native_program.ProgramArtifact,
) !native_program.Program {
    var database = try fixture.database();
    defer database.deinit();
    artifacts.* = .{testArtifact(0, model, bytes.len)};
    return testProgram(database.generation.sha256, database.model.packages.len, artifacts, steps);
}

fn fixtureInstallRoot(fixture: *Fixture, buffer: []u8) ![]const u8 {
    const length = try fixture.tmp.dir.realPath(testing.io, buffer);
    return buffer[0..length];
}

fn fixtureHashValue(domain: []const u8, value: anytype) [32]u8 {
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(Sha256) = .init(&buffer);
    sink.writer.writeAll(domain) catch unreachable;
    std.json.Stringify.value(
        value,
        .{ .whitespace = .minified },
        &sink.writer,
    ) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn finalizeFixtureProgram(program: *native_program.Program) void {
    program.artifacts_sha256 = hex(32, fixtureHashValue(
        "debz-native-transaction-program-artifacts-v1\x00",
        program.artifacts,
    ));
    program.steps_sha256 = hex(32, fixtureHashValue(
        "debz-native-transaction-program-steps-v1\x00",
        program.steps,
    ));
    var payload = program.*;
    payload.digest_sha256 = @splat('0');
    program.digest_sha256 = hex(32, fixtureHashValue(
        "debz-native-transaction-program-v1\x00",
        payload,
    ));
}

fn bindFixtureProgramRoot(
    program: *native_program.Program,
    install_root: []const u8,
) [32]u8 {
    const identity = transaction_recovery.rootIdentity(install_root);
    program.install_root = install_root;
    program.root_identity_sha256 = hex(32, identity);
    finalizeFixtureProgram(program);
    return identity;
}

fn materializeFixture(
    fixture: *Fixture,
    program: *native_program.Program,
    snapshot: package_database.Snapshot,
    archives: []const ArchiveInput,
    locks: root_operation.LockBackend,
    operation: product_api.Operation,
    hooks: root_mutation.Hooks,
) !MaterializationResult {
    var root_buffer: [4096]u8 = undefined;
    const install_root = try fixtureInstallRoot(fixture, &root_buffer);
    const root_identity = bindFixtureProgramRoot(program, install_root);
    return materialize(testing.allocator, .{
        .io = testing.io,
        .root = fixture.root(),
        .install_root = install_root,
        .planning = .{
            .program = program,
            .snapshot = snapshot,
            .archives = archives,
            .root = fixture.root(),
            .root_identity_sha256 = root_identity,
            .interoperability = .isolated_root,
        },
        .locks = locks,
        .operation = operation,
        .hooks = hooks,
    });
}

const ExternalMaterializationOperation = enum {
    install,
    upgrade,
    downgrade,
    reinstall,
    configure,
    remove,
    purge,
    process_triggers,
    recover,
};

const ExternalConffilePolicy = enum {
    keep_existing,
    use_package_version,
};

const ExternalPackageSelection = struct {
    name: []const u8,
    architecture: []const u8,
};

const ExternalMaterializationRequest = struct {
    root: []const u8,
    architecture: []const u8,
    archives: []const []const u8,
    operation: ExternalMaterializationOperation,
    report: []const u8,
    conffiles: bool = false,
    policy: ExternalConffilePolicy = .keep_existing,
    packages: []const ExternalPackageSelection = &.{},
};

const ExternalLifecycleAction = struct {
    sequence: usize,
    kind: solver.OrderedActionKind,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
};

const ExternalLifecycleRequest = struct {
    root: []const u8,
    architecture: []const u8,
    archives: []const []const u8,
    operation: ExternalMaterializationOperation,
    report: []const u8,
    policy: ExternalConffilePolicy = .keep_existing,
    packages: []const ExternalPackageSelection = &.{},
    ordered_actions: ?[]const ExternalLifecycleAction = null,
    fault: ?[]const u8 = null,
    triggers: bool = false,
    defer_triggers: bool = false,
    recovery: bool = false,
    crash_at: ?native_recovery.CrashPoint = null,
    caller_owned: bool = false,
    acknowledge_native: bool = false,
    core_product: bool = false,
    core_completion_crash: ?@import("production_backend.zig").CompletionPoint = null,
    isolated_helper: bool = false,
};

const LifecycleOutcome = enum {
    applied,
    script_failed,
    trigger_failed,
    recovery_required,
    handoff,
    refused,
};

const LifecycleResult = struct {
    outcome: LifecycleOutcome,
    detail: []const u8,
    program_sha256: ?[64]u8 = null,
    attempt_id: ?[64]u8 = null,
    provenance_path: ?[]const u8 = null,
};

const CompiledLifecycle = native_preparation.Prepared;

fn lifecycleScriptKind(kind: package_database.ScriptKind) maintainer_script.Kind {
    return switch (kind) {
        .preinst => .preinst,
        .postinst => .postinst,
        .prerm => .prerm,
        .postrm => .postrm,
    };
}

fn lifecycleArchiveScriptKind(
    kind: archive_application.ScriptKind,
) ?maintainer_script.Kind {
    return switch (kind) {
        .preinst => .preinst,
        .postinst => .postinst,
        .prerm => .prerm,
        .postrm => .postrm,
        .config => null,
    };
}

fn lifecycleTriggerKind(
    kind: package_database.TriggerDeclarationKind,
) native_program.TriggerKind {
    return switch (kind) {
        .interest => .interest,
        .interest_await => .interest_await,
        .interest_noawait => .interest_noawait,
        .activate => .activate,
        .activate_await => .activate_await,
        .activate_noawait => .activate_noawait,
    };
}

fn lifecycleArchiveTriggerKind(
    kind: archive_application.TriggerDirective,
) native_program.TriggerKind {
    return switch (kind) {
        .interest => .interest,
        .interest_await => .interest_await,
        .interest_noawait => .interest_noawait,
        .activate => .activate,
        .activate_await => .activate_await,
        .activate_noawait => .activate_noawait,
    };
}

fn lifecycleDeclarationsDigest(
    allocator: std.mem.Allocator,
    declarations: []const native_program.TriggerDeclaration,
) ![32]u8 {
    const sorted = try allocator.dupe(
        native_program.TriggerDeclaration,
        declarations,
    );
    defer allocator.free(sorted);
    std.mem.sort(
        native_program.TriggerDeclaration,
        sorted,
        {},
        struct {
            fn less(
                _: void,
                left: native_program.TriggerDeclaration,
                right: native_program.TriggerDeclaration,
            ) bool {
                const name = std.mem.order(u8, left.name, right.name);
                if (name != .eq) return name == .lt;
                return @intFromEnum(left.kind) < @intFromEnum(right.kind);
            }
        }.less,
    );
    var hash = Sha256.init(.{});
    hash.update("debz-native-transaction-program-trigger-declarations-v1\x00");
    for (sorted) |declaration| {
        hash.update(&[_]u8{@intFromEnum(declaration.kind)});
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, declaration.name.len, .little);
        hash.update(&length);
        hash.update(declaration.name);
    }
    return hash.finalResult();
}

fn lifecycleOwnedPathsDigest(record: package_database.PackageRecord) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(digest_domain);
    hashText(&hash, "lifecycle-owned-paths");
    for (record.paths orelse &.{}) |path| hashText(&hash, path);
    return hash.finalResult();
}

fn lifecycleConfiguredVersion(
    record: package_database.PackageRecord,
) ?[]const u8 {
    return switch (record.status.current) {
        .installed, .triggers_awaited, .triggers_pending, .config_files => record.version,
        .unpacked, .half_configured => switch (configVersionField(record)) {
            .valid => |value| value,
            .absent, .invalid => null,
        },
        else => null,
    };
}

fn lifecycleInstalledEvidence(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    model: package_database.Model,
) ![]const native_program.InstalledPackage {
    const result = try allocator.alloc(
        native_program.InstalledPackage,
        model.packages.len,
    );
    var compared_bytes: u64 = 0;
    for (model.packages, 0..) |record, index| {
        const scripts = try allocator.alloc(
            native_program.InstalledScript,
            record.scripts.len,
        );
        for (record.scripts, 0..) |script, script_index| {
            scripts[script_index] = .{
                .kind = lifecycleScriptKind(script.kind),
                .sha256 = script.sha256,
            };
        }
        const conffiles = try allocator.alloc(
            native_program.InstalledConffile,
            record.conffiles.len,
        );
        for (record.conffiles, 0..) |conffile, conffile_index| {
            const recorded = switch (conffile.digest) {
                .md5 => |value| value,
                .new_conffile => return error.UnsupportedLifecycleConffile,
            };
            const observed = try rootMd5ForConffile(
                allocator,
                root,
                relativeListPath(conffile.path) orelse return error.UnsupportedLifecycleConffile,
                (Limits{}).max_compare_bytes,
                &compared_bytes,
                (Limits{}).max_compared_bytes,
            );
            conffiles[conffile_index] = .{
                .path = conffile.path,
                .recorded_md5 = recorded,
                .on_disk_md5 = if (observed) |value| value.md5 else null,
                .obsolete = conffile.obsolete,
            };
        }
        const triggers = try allocator.alloc(
            native_program.TriggerDeclaration,
            if (record.trigger_declarations) |value| value.len else 0,
        );
        if (record.trigger_declarations) |declarations| {
            for (declarations, 0..) |declaration, trigger_index| {
                triggers[trigger_index] = .{
                    .kind = lifecycleTriggerKind(declaration.kind),
                    .name = declaration.name,
                };
            }
        }
        result[index] = .{
            .name = record.name,
            .version = record.version,
            .architecture = record.architecture,
            .state = record.status.current,
            .configured_version = lifecycleConfiguredVersion(record),
            .hold = record.status.want == .hold,
            .essential = record.essential,
            .owned_paths_sha256 = lifecycleOwnedPathsDigest(record),
            .scripts = scripts,
            .conffiles = conffiles,
            .triggers = triggers,
            .triggers_pending = record.triggers_pending,
            .triggers_awaited = record.triggers_awaited,
        };
    }
    return result;
}

fn lifecycleArchiveEvidence(
    allocator: std.mem.Allocator,
    models: []archive_application.Model,
    archive_bytes: []const []const u8,
) ![]const native_program.Archive {
    if (models.len != archive_bytes.len) return error.ArchiveEvidenceMismatch;
    const origins = try allocator.alloc(exact_lock_v2.PackageOrigin, models.len);
    defer allocator.free(origins);
    for (models, archive_bytes, 0..) |model, bytes, index| {
        origins[index] = .{ .local_artifact = .{
            .artifact_id = hex(32, model.provenance().sha256),
            .sha256 = model.provenance().sha256,
            .size = bytes.len,
            .package = model.facts.package,
            .version = model.facts.version,
            .architecture = model.facts.architecture,
            .acquisition_url = "file:///native-lifecycle-fixture.deb",
            .trust_mode = .pinned_sha256,
        } };
    }
    return programArchiveEvidence(allocator, models, archive_bytes, origins);
}

fn programArchiveEvidence(
    allocator: std.mem.Allocator,
    models: []archive_application.Model,
    archive_bytes: []const []const u8,
    origins: []const exact_lock_v2.PackageOrigin,
) ![]const native_program.Archive {
    if (models.len != archive_bytes.len or models.len != origins.len)
        return error.ArchiveEvidenceMismatch;
    const result = try allocator.alloc(native_program.Archive, models.len);
    for (models, archive_bytes, origins, 0..) |*model, bytes, origin, index| {
        try model.verifyArtifactBinding(bytes);
        const scripts = try allocator.alloc(
            native_program.ArchiveScript,
            model.scripts.len,
        );
        var script_count: usize = 0;
        for (model.scripts) |script| {
            const kind = lifecycleArchiveScriptKind(script.kind) orelse
                return error.UnsupportedMaintainerScript;
            scripts[script_count] = .{
                .kind = kind,
                .sha256 = script.sha256,
                .size = script.size,
            };
            script_count += 1;
        }
        const conffiles = try allocator.alloc(
            native_program.ArchiveConffile,
            model.conffiles.len,
        );
        for (model.conffiles, 0..) |conffile, conffile_index| {
            const path = try std.fmt.allocPrint(allocator, "/{s}", .{conffile.path});
            const file = model.findFile(conffile.path);
            conffiles[conffile_index] = .{
                .path = path,
                .md5 = if (conffile.remove_on_upgrade)
                    null
                else if (file) |entry|
                    entry.md5 orelse digestMd5(try model.fileBytes(entry.*))
                else
                    return error.UnsupportedLifecycleConffile,
                .remove_on_upgrade = conffile.remove_on_upgrade,
            };
        }
        const triggers = try allocator.alloc(
            native_program.TriggerDeclaration,
            model.triggers.len,
        );
        for (model.triggers, 0..) |trigger, trigger_index| {
            triggers[trigger_index] = .{
                .kind = lifecycleArchiveTriggerKind(trigger.directive),
                .name = trigger.target,
            };
        }
        result[index] = .{
            .package = model.facts.package,
            .version = model.facts.version,
            .architecture = model.facts.architecture,
            .sha256 = model.provenance().sha256,
            .size = bytes.len,
            .origin = origin,
            .application_sha256 = model.digest,
            .scripts = scripts[0..script_count],
            .conffiles = conffiles,
            .triggers = triggers,
            .essential = model.facts.essential,
        };
    }
    return result;
}

const TriggerPreparation = struct {
    enabled: bool,
    mode: native_authorization.TriggerMode = .transaction,
    defer_triggers: bool = false,
};

fn lifecycleTriggerAuthority(
    allocator: std.mem.Allocator,
    options: TriggerPreparation,
    database: package_database.Database,
    installed: []const native_program.InstalledPackage,
    archives: []const native_program.Archive,
    base_final_state: []const native_authorization.FinalPackage,
) !?native_authorization.TriggerAuthority {
    if (!options.enabled) return null;
    var handlers: std.ArrayList(native_authorization.TriggerHandler) = .empty;
    var callers: std.ArrayList(native_authorization.TriggerCaller) = .empty;
    var allowed: std.ArrayList([]const u8) = .empty;
    var incoming: std.StringHashMapUnmanaged(void) = .empty;
    defer incoming.deinit(allocator);
    for (archives) |archive| {
        const key = try std.fmt.allocPrint(
            allocator,
            "{s}\x00{s}",
            .{ archive.package, archive.architecture },
        );
        try incoming.put(allocator, key, {});
        var postinst: ?native_program.ArchiveScript = null;
        for (archive.scripts) |script| {
            try callers.append(allocator, .{
                .package = archive.package,
                .version = archive.version,
                .architecture = archive.architecture,
                .source = .new_package,
                .kind = script.kind,
                .script_sha256 = script.sha256,
            });
            if (script.kind == .postinst) postinst = script;
        }
        var interested = false;
        for (archive.triggers) |declaration| {
            if (!declaration.kind.isInterest()) continue;
            interested = true;
            try appendUniqueText(allocator, &allowed, declaration.name);
        }
        if (interested) {
            const script = postinst orelse return error.TriggerHandlerMissing;
            try handlers.append(allocator, .{
                .package = archive.package,
                .version = archive.version,
                .architecture = archive.architecture,
                .source = .new_package,
                .postinst_sha256 = script.sha256,
                .declarations_sha256 = try lifecycleDeclarationsDigest(
                    allocator,
                    archive.triggers,
                ),
            });
        }
    }
    for (installed) |package| {
        const key = try std.fmt.allocPrint(
            allocator,
            "{s}\x00{s}",
            .{ package.name, package.architecture },
        );
        var postinst: ?native_program.InstalledScript = null;
        for (package.scripts) |script| {
            try callers.append(allocator, .{
                .package = package.name,
                .version = package.version,
                .architecture = package.architecture,
                .source = .installed_package,
                .kind = script.kind,
                .script_sha256 = script.sha256,
            });
            if (script.kind == .postinst) postinst = script;
        }
        if (incoming.contains(key)) continue;
        var interested = false;
        for (package.triggers) |declaration| {
            if (!declaration.kind.isInterest()) continue;
            interested = true;
            try appendUniqueText(allocator, &allowed, declaration.name);
        }
        if (interested) {
            const script = postinst orelse return error.TriggerHandlerMissing;
            try handlers.append(allocator, .{
                .package = package.name,
                .version = package.version,
                .architecture = package.architecture,
                .source = .installed_package,
                .postinst_sha256 = script.sha256,
                .declarations_sha256 = try lifecycleDeclarationsDigest(
                    allocator,
                    package.triggers,
                ),
            });
        }
    }
    if (handlers.items.len == 0 or allowed.items.len == 0)
        return error.TriggerAuthorityEmpty;
    return .{
        .mode = options.mode,
        .defer_triggers = options.defer_triggers,
        .initial_state_sha256 = native_trigger.stateDigest(database.model),
        .handlers = try allocator.dupe(
            native_authorization.TriggerHandler,
            handlers.items,
        ),
        .callers = try allocator.dupe(
            native_authorization.TriggerCaller,
            callers.items,
        ),
        .allowed_triggers = try allocator.dupe([]const u8, allowed.items),
        .maximum_invocations = 256,
        .final_mode = if (options.defer_triggers)
            .derive_from_activations
        else
            .exact,
        .base_final_state_sha256 = if (options.defer_triggers)
            native_authorization.finalStateDigest(base_final_state)
        else
            null,
        .maximum_activations = if (options.defer_triggers) 256 else 0,
    };
}

fn lifecycleActionKind(
    operation: ExternalMaterializationOperation,
) solver.ActionKind {
    return switch (operation) {
        .install => .install,
        .upgrade => .upgrade,
        .downgrade => .downgrade,
        .reinstall, .configure => .reinstall,
        .remove => .remove,
        .purge => .purge,
        .process_triggers => .reinstall,
        .recover => unreachable,
    };
}

fn lifecycleFinalState(
    allocator: std.mem.Allocator,
    external: ExternalLifecycleRequest,
    database: package_database.Database,
    models: []archive_application.Model,
) ![]native_authorization.FinalPackage {
    var result: std.ArrayList(native_authorization.FinalPackage) = .empty;
    for (database.model.packages) |record| {
        var replaced = false;
        for (models) |model| {
            if (std.mem.eql(u8, record.name, model.facts.package) and
                std.mem.eql(u8, record.architecture, model.facts.architecture))
            {
                replaced = true;
                break;
            }
        }
        var selected_removal = false;
        for (external.packages) |selection| {
            if (std.mem.eql(u8, record.name, selection.name) and
                std.mem.eql(u8, record.architecture, selection.architecture))
            {
                selected_removal = true;
                break;
            }
        }
        if (replaced) continue;
        if (selected_removal) {
            if (external.operation == .remove and
                (record.conffiles.len != 0 or record.script(.postrm) != null))
                try result.append(allocator, .{
                    .name = record.name,
                    .version = record.version,
                    .architecture = record.architecture,
                    .state = .config_files,
                    .dpkg_selection_hold = record.status.want == .hold,
                });
            continue;
        }
        const state: native_authorization.FinalState = switch (record.status.current) {
            .installed, .triggers_awaited, .triggers_pending => .installed,
            .config_files => .config_files,
            else => continue,
        };
        try result.append(allocator, .{
            .name = record.name,
            .version = record.version,
            .architecture = record.architecture,
            .state = state,
            .dpkg_selection_hold = record.status.want == .hold,
        });
    }
    for (models) |model| try result.append(allocator, .{
        .name = model.facts.package,
        .version = model.facts.version,
        .architecture = model.facts.architecture,
        .state = .installed,
        .dpkg_selection_hold = false,
    });
    return result.toOwnedSlice(allocator);
}

const SimulatedTriggerPackage = struct {
    name: []const u8,
    architecture: []const u8,
    values: std.ArrayList([]const u8) = .empty,
};

const RuntimeTriggerEvent = struct {
    origin: enum { automatic, dynamic },
    source: package_database.Identity,
    trigger: []const u8,
    activation_awaits: bool,
    listeners: []const package_database.TriggerInterest,
};

fn appendRuntimeTriggerEvent(
    allocator: std.mem.Allocator,
    events: *std.ArrayList(RuntimeTriggerEvent),
    source: package_database.Identity,
    trigger: []const u8,
    activation_awaits: bool,
    interests: []const package_database.TriggerInterest,
    origin: @FieldType(RuntimeTriggerEvent, "origin"),
) !void {
    var listeners: std.ArrayList(package_database.TriggerInterest) = .empty;
    defer listeners.deinit(allocator);
    for (interests) |interest| {
        if (std.mem.eql(u8, interest.trigger, trigger))
            try listeners.append(allocator, .{
                .trigger = try allocator.dupe(u8, interest.trigger),
                .package = .{
                    .name = try allocator.dupe(u8, interest.package.name),
                    .architecture = try allocator.dupe(
                        u8,
                        interest.package.architecture,
                    ),
                },
                .await_mode = interest.await_mode,
            });
    }
    if (listeners.items.len == 0) return;
    for (events.items) |event| {
        if (event.origin != origin or
            !std.mem.eql(u8, event.source.name, source.name) or
            !std.mem.eql(u8, event.source.architecture, source.architecture) or
            !std.mem.eql(u8, event.trigger, trigger) or
            event.activation_awaits != activation_awaits or
            event.listeners.len != listeners.items.len)
            continue;
        var equal = true;
        for (event.listeners, listeners.items) |left, right| {
            if (!std.mem.eql(u8, left.trigger, right.trigger) or
                !std.mem.eql(u8, left.package.name, right.package.name) or
                !std.mem.eql(
                    u8,
                    left.package.architecture,
                    right.package.architecture,
                ) or left.await_mode != right.await_mode)
            {
                equal = false;
                break;
            }
        }
        if (equal) return;
    }
    try events.append(allocator, .{
        .origin = origin,
        .source = .{
            .name = try allocator.dupe(u8, source.name),
            .architecture = try allocator.dupe(u8, source.architecture),
        },
        .trigger = try allocator.dupe(u8, trigger),
        .activation_awaits = activation_awaits,
        .listeners = try allocator.dupe(
            package_database.TriggerInterest,
            listeners.items,
        ),
    });
}

fn persistRuntimeTriggerEvents(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    events: []const RuntimeTriggerEvent,
) !void {
    const runtime = execution.recovery orelse return;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    const persisted = try owned.alloc(
        native_recovery.TriggerEvent,
        events.len,
    );
    for (events, 0..) |event, event_index| {
        const listeners = try owned.alloc(
            native_recovery.TriggerListener,
            event.listeners.len,
        );
        for (event.listeners, 0..) |listener, listener_index|
            listeners[listener_index] = .{
                .trigger = listener.trigger,
                .package = listener.package.name,
                .architecture = listener.package.architecture,
                .await_mode = switch (listener.await_mode) {
                    .awaited => .awaited,
                    .noawait => .noawait,
                },
            };
        persisted[event_index] = .{
            .origin = switch (event.origin) {
                .automatic => .automatic,
                .dynamic => .dynamic,
            },
            .source_package = event.source.name,
            .source_architecture = event.source.architecture,
            .trigger = event.trigger,
            .activation_awaits = event.activation_awaits,
            .listeners = listeners,
        };
    }
    try native_recovery.publishTriggerEvents(
        owned,
        root,
        runtime.intent_sha256,
        persisted,
    );
}

fn restoreRuntimeTriggerEvents(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    events: *std.ArrayList(RuntimeTriggerEvent),
) !void {
    if (execution.recovery == null) return;
    var persisted = try native_recovery.readTriggerEvents(allocator, root);
    defer persisted.deinit();
    for (persisted.document.events) |event| {
        const listeners = try allocator.alloc(
            package_database.TriggerInterest,
            event.listeners.len,
        );
        for (event.listeners, 0..) |listener, index| listeners[index] = .{
            .trigger = try allocator.dupe(u8, listener.trigger),
            .package = .{
                .name = try allocator.dupe(u8, listener.package),
                .architecture = try allocator.dupe(u8, listener.architecture),
            },
            .await_mode = switch (listener.await_mode) {
                .awaited => .awaited,
                .noawait => .noawait,
            },
        };
        try events.append(allocator, .{
            .origin = switch (event.origin) {
                .automatic => .automatic,
                .dynamic => .dynamic,
            },
            .source = .{
                .name = try allocator.dupe(u8, event.source_package),
                .architecture = try allocator.dupe(
                    u8,
                    event.source_architecture,
                ),
            },
            .trigger = try allocator.dupe(u8, event.trigger),
            .activation_awaits = event.activation_awaits,
            .listeners = listeners,
        });
    }
}

fn collectArchiveTriggerEvents(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    architecture: []const u8,
    model: *const archive_application.Model,
    events: *std.ArrayList(RuntimeTriggerEvent),
) !void {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{ .native_architecture = architecture, .snapshot = captured.snapshot },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return error.InvalidExternalDatabase,
    };
    defer database.deinit();
    const source: package_database.Identity = .{
        .name = model.facts.package,
        .architecture = model.facts.architecture,
    };
    var work: usize = 0;
    for (model.triggers) |declaration| {
        if (declaration.kind != .activate) continue;
        try appendRuntimeTriggerEvent(
            allocator,
            events,
            source,
            declaration.target,
            declaration.await_policy == .awaited,
            database.model.triggers.interests,
            .automatic,
        );
    }
    var seen_file: std.StringHashMapUnmanaged(void) = .empty;
    defer seen_file.deinit(allocator);
    for (database.model.triggers.interests) |interest| {
        if (interest.trigger.len == 0 or interest.trigger[0] != '/' or
            !(try archiveTouchesFileTrigger(
                model,
                interest.trigger,
                &work,
                (Limits{}).max_work,
            )))
            continue;
        if ((try seen_file.getOrPut(allocator, interest.trigger)).found_existing)
            continue;
        try appendRuntimeTriggerEvent(
            allocator,
            events,
            source,
            interest.trigger,
            true,
            database.model.triggers.interests,
            .automatic,
        );
    }
}

fn collectRemovalTriggerEvents(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    architecture: []const u8,
    package: native_program.PackageRef,
    expected_owned_paths: native_program.Digest,
    events: *std.ArrayList(RuntimeTriggerEvent),
) !void {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{ .native_architecture = architecture, .snapshot = captured.snapshot },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return error.InvalidExternalDatabase,
    };
    defer database.deinit();
    const record = database.model.find(package.name, package.architecture) orelse return;
    const expected = parseHex(32, &expected_owned_paths) orelse
        return error.InvalidLifecycleProgram;
    if (!std.mem.eql(
        u8,
        &expected,
        &lifecycleOwnedPathsDigest(record.*),
    )) return error.MaterializationProgramDigest;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);
    var work: usize = 0;
    for (database.model.triggers.interests) |interest| {
        if (interest.trigger.len == 0 or interest.trigger[0] != '/') continue;
        const prefix = interest.trigger[1..];
        var touched = false;
        for (record.paths orelse &.{}) |listed| {
            work = std.math.add(usize, work, 1) catch
                return error.TriggerWorkLimit;
            if (work > (Limits{}).max_work) return error.TriggerWorkLimit;
            const path = relativeListPath(listed) orelse continue;
            if (std.mem.eql(u8, path, prefix) or
                (path.len > prefix.len and path[prefix.len] == '/' and
                    std.mem.startsWith(u8, path, prefix)))
                touched = true;
        }
        if (!touched or (try seen.getOrPut(allocator, interest.trigger)).found_existing)
            continue;
        try appendRuntimeTriggerEvent(
            allocator,
            events,
            record.identity(),
            interest.trigger,
            true,
            database.model.triggers.interests,
            .automatic,
        );
    }
}

fn simulatedTriggerPackage(
    allocator: std.mem.Allocator,
    packages: *std.ArrayList(SimulatedTriggerPackage),
    index: *std.StringHashMapUnmanaged(usize),
    name: []const u8,
    architecture: []const u8,
) !*SimulatedTriggerPackage {
    var key_buffer: [512]u8 = undefined;
    const key = try std.fmt.bufPrint(
        &key_buffer,
        "{s}\x00{s}",
        .{ name, architecture },
    );
    if (index.get(key)) |position| return &packages.items[position];
    const stored = try allocator.dupe(u8, key);
    const position = packages.items.len;
    try packages.append(allocator, .{
        .name = name,
        .architecture = architecture,
    });
    try index.put(allocator, stored, position);
    return &packages.items[position];
}

fn appendUniqueText(
    allocator: std.mem.Allocator,
    values: *std.ArrayList([]const u8),
    text: []const u8,
) !void {
    for (values.items) |value| {
        if (std.mem.eql(u8, value, text)) return;
    }
    try values.append(allocator, text);
}

fn simulateTriggerActivation(
    allocator: std.mem.Allocator,
    registry: []const package_database.TriggerInterest,
    pending: *std.ArrayList(SimulatedTriggerPackage),
    pending_index: *std.StringHashMapUnmanaged(usize),
    awaited: *std.ArrayList(SimulatedTriggerPackage),
    awaited_index: *std.StringHashMapUnmanaged(usize),
    source_name: []const u8,
    source_architecture: []const u8,
    trigger: []const u8,
    activation_awaits: bool,
) !void {
    for (registry) |listener| {
        if (!std.mem.eql(u8, listener.trigger, trigger)) continue;
        const handler = try simulatedTriggerPackage(
            allocator,
            pending,
            pending_index,
            listener.package.name,
            if (listener.package.architecture.len == 0)
                source_architecture
            else
                listener.package.architecture,
        );
        try appendUniqueText(allocator, &handler.values, trigger);
        if (activation_awaits and listener.await_mode == .awaited) {
            const source = try simulatedTriggerPackage(
                allocator,
                awaited,
                awaited_index,
                source_name,
                source_architecture,
            );
            try appendUniqueText(allocator, &source.values, listener.package.name);
        }
    }
}

fn archiveTouchesFileTrigger(
    model: *const archive_application.Model,
    trigger: []const u8,
    work: *usize,
    maximum_work: usize,
) !bool {
    if (trigger.len < 2 or trigger[0] != '/') return false;
    const relative = trigger[1..];
    for (model.files) |file| {
        work.* = std.math.add(usize, work.*, 1) catch
            return error.TriggerWorkLimit;
        if (work.* > maximum_work) return error.TriggerWorkLimit;
        if (std.mem.eql(u8, file.path, relative) or
            (file.path.len > relative.len and
                file.path[relative.len] == '/' and
                std.mem.startsWith(u8, file.path, relative)))
            return true;
    }
    return false;
}

fn derivedHandlerAuthorized(
    authority: native_authorization.TriggerAuthority,
    listener: package_database.TriggerInterest,
    architecture: []const u8,
) bool {
    for (authority.handlers) |handler| {
        if (std.mem.eql(u8, handler.package, listener.package.name) and
            std.mem.eql(
                u8,
                handler.architecture,
                if (listener.package.architecture.len == 0)
                    architecture
                else
                    listener.package.architecture,
            ))
            return true;
    }
    return false;
}

fn derivedTriggerAllowed(
    authority: native_authorization.TriggerAuthority,
    trigger: []const u8,
) bool {
    for (authority.allowed_triggers) |allowed| {
        if (std.mem.eql(u8, allowed, trigger)) return true;
    }
    return false;
}

fn deriveDeferredFinalState(
    allocator: std.mem.Allocator,
    authorization: native_authorization.Authorization,
    initial_model: package_database.Model,
    events: []const RuntimeTriggerEvent,
) ![]native_authorization.FinalPackage {
    const authority = authorization.trigger_authority orelse
        return error.InvalidTriggerAuthority;
    var activation_count: usize = events.len;
    for (initial_model.triggers.pending) |queued| {
        activation_count = std.math.add(
            usize,
            activation_count,
            queued.packages.len + @intFromBool(queued.noawait),
        ) catch return error.InvalidTriggerAuthority;
    }
    if (authority.final_mode != .derive_from_activations or
        authority.base_final_state_sha256 == null or
        authority.maximum_activations == 0 or
        activation_count > authority.maximum_activations)
        return error.InvalidTriggerAuthority;
    const base_digest = native_authorization.finalStateDigest(
        authorization.final_state,
    );
    if (!std.mem.eql(
        u8,
        &base_digest,
        &authority.base_final_state_sha256.?,
    )) return error.InvalidTriggerAuthority;
    const final_state = try allocator.dupe(
        native_authorization.FinalPackage,
        authorization.final_state,
    );
    for (final_state) |*package| {
        if ((package.state != .installed and package.state != .config_files) or
            package.triggers_pending.len != 0 or
            package.triggers_awaited.len != 0)
            return error.InvalidTriggerAuthority;
        package.triggers_pending = &.{};
        package.triggers_awaited = &.{};
    }
    var pending: std.ArrayList(SimulatedTriggerPackage) = .empty;
    defer {
        for (pending.items) |*entry| entry.values.deinit(allocator);
        pending.deinit(allocator);
    }
    var pending_index: std.StringHashMapUnmanaged(usize) = .empty;
    defer pending_index.deinit(allocator);
    var awaited: std.ArrayList(SimulatedTriggerPackage) = .empty;
    defer {
        for (awaited.items) |*entry| entry.values.deinit(allocator);
        awaited.deinit(allocator);
    }
    var awaited_index: std.StringHashMapUnmanaged(usize) = .empty;
    defer awaited_index.deinit(allocator);
    for (initial_model.packages) |record| {
        if (authorization.findAction(record.name, record.architecture) != null)
            continue;
        if (record.triggers_pending.len != 0) {
            const entry = try simulatedTriggerPackage(
                allocator,
                &pending,
                &pending_index,
                record.name,
                record.architecture,
            );
            var index = record.triggers_pending.len;
            while (index != 0) {
                index -= 1;
                try appendUniqueText(
                    allocator,
                    &entry.values,
                    record.triggers_pending[index],
                );
            }
        }
        if (record.triggers_awaited.len != 0) {
            const entry = try simulatedTriggerPackage(
                allocator,
                &awaited,
                &awaited_index,
                record.name,
                record.architecture,
            );
            for (record.triggers_awaited) |name|
                try appendUniqueText(allocator, &entry.values, name);
        }
    }
    for (initial_model.triggers.pending) |queued| {
        if (!derivedTriggerAllowed(authority, queued.trigger))
            return error.InvalidTriggerActivation;
        for (initial_model.triggers.interests) |listener| {
            if (!std.mem.eql(u8, listener.trigger, queued.trigger)) continue;
            if (!derivedHandlerAuthorized(
                authority,
                listener,
                authorization.target_architecture,
            )) return error.InvalidTriggerActivation;
        }
        if (queued.packages.len == 0) {
            try simulateTriggerActivation(
                allocator,
                initial_model.triggers.interests,
                &pending,
                &pending_index,
                &awaited,
                &awaited_index,
                "",
                authorization.target_architecture,
                queued.trigger,
                false,
            );
        } else {
            for (queued.packages) |source| {
                try simulateTriggerActivation(
                    allocator,
                    initial_model.triggers.interests,
                    &pending,
                    &pending_index,
                    &awaited,
                    &awaited_index,
                    source.package.name,
                    if (source.package.architecture.len == 0)
                        authorization.target_architecture
                    else
                        source.package.architecture,
                    queued.trigger,
                    true,
                );
            }
        }
    }
    for (events) |event| {
        if (!derivedTriggerAllowed(authority, event.trigger))
            return error.InvalidTriggerActivation;
        for (event.listeners) |listener| {
            if (!derivedHandlerAuthorized(
                authority,
                listener,
                authorization.target_architecture,
            )) return error.InvalidTriggerActivation;
        }
        if (event.origin == .automatic and
            authorization.findAction(
                event.source.name,
                event.source.architecture,
            ) == null)
            return error.InvalidTriggerActivation;
        if (event.origin == .dynamic and event.source.name.len != 0) {
            var caller = false;
            for (authority.callers) |candidate| {
                if (std.mem.eql(u8, candidate.package, event.source.name) and
                    std.mem.eql(
                        u8,
                        candidate.architecture,
                        event.source.architecture,
                    ))
                    caller = true;
            }
            if (!caller) return error.InvalidTriggerActivation;
        }
        try simulateTriggerActivation(
            allocator,
            event.listeners,
            &pending,
            &pending_index,
            &awaited,
            &awaited_index,
            event.source.name,
            if (event.source.architecture.len == 0)
                authorization.target_architecture
            else
                event.source.architecture,
            event.trigger,
            event.activation_awaits,
        );
    }
    for (final_state) |*package| {
        var key_buffer: [512]u8 = undefined;
        const key = try std.fmt.bufPrint(
            &key_buffer,
            "{s}\x00{s}",
            .{ package.name, package.architecture },
        );
        if (pending_index.get(key)) |position| {
            const values = pending.items[position].values.items;
            const reversed = try allocator.alloc([]const u8, values.len);
            for (values, 0..) |value, index|
                reversed[values.len - index - 1] = value;
            package.triggers_pending = reversed;
            package.state = .triggers_pending;
        }
        if (awaited_index.get(key)) |position| {
            package.triggers_awaited = try allocator.dupe(
                []const u8,
                awaited.items[position].values.items,
            );
            package.state = .triggers_awaited;
        }
    }
    return final_state;
}

fn compileLifecycleProgram(
    allocator: std.mem.Allocator,
    raw_request: []const u8,
    external: ExternalLifecycleRequest,
    root: root_fs.Root,
    database: package_database.Database,
    models: []archive_application.Model,
    archive_bytes: []const []const u8,
) !?CompiledLifecycle {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    defer allocator.destroy(arena);
    arena.* = .init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();

    const installed = try lifecycleInstalledEvidence(owned, root, database.model);
    const archives = try lifecycleArchiveEvidence(owned, models, archive_bytes);
    var actions: std.ArrayList(native_authorization.Action) = .empty;
    for (archives, 0..) |archive, index| {
        const prior = database.model.find(archive.package, archive.architecture);
        const kind = lifecycleActionKind(external.operation);
        try actions.append(owned, .{
            .sequence = index,
            .kind = kind,
            .package = archive.package,
            .version = archive.version,
            .architecture = archive.architecture,
            .prior_version = if (kind == .install)
                null
            else if (prior) |record|
                record.version
            else
                return error.InvalidExternalOperation,
            .artifact = .{
                .sha256 = archive.sha256,
                .size = archive.size,
                .origin = archive.origin,
            },
        });
    }
    if (models.len == 0) for (external.packages) |selection| {
        const record = database.model.find(
            selection.name,
            selection.architecture,
        ) orelse continue;
        try actions.append(owned, .{
            .sequence = actions.items.len,
            .kind = lifecycleActionKind(external.operation),
            .package = record.name,
            .version = record.version,
            .architecture = record.architecture,
            .prior_version = record.version,
            .artifact = null,
        });
    };
    if (actions.items.len == 0 and external.operation != .process_triggers)
        return null;

    var ordered: std.ArrayList(solver.OrderedAction) = .empty;
    if (external.ordered_actions) |reviewed| {
        for (reviewed) |entry| try ordered.append(owned, .{
            .sequence = entry.sequence,
            .kind = entry.kind,
            .package = entry.package,
            .version = entry.version,
            .architecture = entry.architecture,
        });
    } else switch (external.operation) {
        .install, .upgrade, .downgrade, .reinstall => {
            for (actions.items) |action| try ordered.append(owned, .{
                .sequence = ordered.items.len,
                .kind = .unpack,
                .package = action.package,
                .version = action.version,
                .architecture = action.architecture,
            });
            const action = actions.items[actions.items.len - 1];
            try ordered.append(owned, .{
                .sequence = ordered.items.len,
                .kind = .configure_pending,
                .package = action.package,
                .version = action.version,
                .architecture = action.architecture,
            });
        },
        .configure => for (actions.items) |action| try ordered.append(owned, .{
            .sequence = ordered.items.len,
            .kind = .configure_pending,
            .package = action.package,
            .version = action.version,
            .architecture = action.architecture,
        }),
        .remove, .purge => for (actions.items) |action| try ordered.append(owned, .{
            .sequence = ordered.items.len,
            .kind = if (external.operation == .purge) .purge else .remove,
            .package = action.package,
            .version = action.version,
            .architecture = action.architecture,
        }),
        .process_triggers => {},
        .recover => unreachable,
    }
    const final_state = try lifecycleFinalState(
        owned,
        external,
        database,
        models,
    );
    const trigger_authority = try lifecycleTriggerAuthority(
        owned,
        .{
            .enabled = external.triggers,
            .mode = if (external.operation == .process_triggers) .process_pending else .transaction,
            .defer_triggers = external.defer_triggers,
        },
        database,
        installed,
        archives,
        final_state,
    );
    var request_sha256: [32]u8 = undefined;
    Sha256.hash(raw_request, &request_sha256, .{});
    var binding_hash = Sha256.init(.{});
    binding_hash.update(digest_domain);
    hashText(&binding_hash, "lifecycle-authorization");
    hashText(&binding_hash, &request_sha256);
    hashText(&binding_hash, &database.generation.sha256);
    for (archives) |archive| hashText(&binding_hash, &archive.sha256);
    const binding = binding_hash.finalResult();
    var authorization = try native_authorization.create(allocator, .{
        .backend = .native,
        .target_architecture = external.architecture,
        .foreign_architectures = database.model.foreign_architectures,
        .install_root = external.root,
        .request_sha256 = request_sha256,
        .solver_policy_sha256 = binding,
        .executor_policy_sha256 = binding,
        .plan_sha256 = binding,
        .exact_lock = .{
            .schema = exact_lock_v2.schema_id,
            .version = exact_lock_v2.schema_version,
            .digest_sha256 = binding,
        },
        .policy = .{
            .conffile = switch (external.policy) {
                .keep_existing => .keep_existing,
                .use_package_version => .use_package_version,
            },
        },
        .actions = actions.items,
        .final_state = final_state,
        .trigger_authority = trigger_authority,
    });
    errdefer authorization.deinit();
    const compiled = native_program.compile(allocator, .{
        .authorization = &authorization.authorization,
        .ordered_actions = ordered.items,
        .installed = .{
            .generation_sha256 = database.generation.sha256,
            .packages = installed,
            .trigger_state_sha256 = native_trigger.stateDigest(database.model),
            .updates_pending = database.model.pending_updates.len != 0,
        },
        .archives = archives,
        .script_policy = lifecycleScriptPolicy(),
    });
    var program = switch (compiled) {
        .program => |value| value,
        .diagnostic => {
            authorization.deinit();
            return null;
        },
    };
    errdefer program.deinit();
    if (!program.program.matchesAuthorization(authorization.authorization))
        return error.InvalidLifecycleProgram;
    return .{ .authorization = authorization, .program = program };
}

fn lifecycleArchiveIndex(
    models: []archive_application.Model,
    package: native_program.PackageIdentity,
) ?usize {
    for (models, 0..) |model, index| {
        if (std.mem.eql(u8, model.facts.package, package.name) and
            std.mem.eql(u8, model.facts.version, package.version) and
            std.mem.eql(u8, model.facts.architecture, package.architecture))
            return index;
    }
    return null;
}

fn lifecycleProgramArtifact(
    program: native_program.Program,
    package: native_program.PackageIdentity,
) ?native_program.ProgramArtifact {
    for (program.artifacts) |artifact| {
        if (std.mem.eql(u8, artifact.package.name, package.name) and
            std.mem.eql(u8, artifact.package.version, package.version) and
            std.mem.eql(u8, artifact.package.architecture, package.architecture))
            return artifact;
    }
    return null;
}

fn lifecyclePhaseRequest(
    execution: *ExecutionState,
    root: root_fs.Root,
    install_root: []const u8,
    snapshot: package_database.Snapshot,
    archives: []const ArchiveInput,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    sequences: []const u32,
) MaterializationRequest {
    return .{
        .io = root.io,
        .root = root,
        .install_root = install_root,
        .planning = .{
            .program = program,
            .authorization = authorization,
            .snapshot = snapshot,
            .archives = archives,
            .root = root,
            .root_identity_sha256 = transaction_recovery.rootIdentity(install_root),
            .interoperability = .isolated_root,
            .conffiles = .unpack,
            .conffile_policy = policy,
            .lifecycle_execution = true,
            .trigger_execution = program.trigger_authority != null,
            .lifecycle_sequences = sequences,
        },
        .locks = locks,
        .operation = operation,
        .borrowed_attempt = attempt,
        .execution = execution,
    };
}

fn lifecycleDataStep(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    models: []archive_application.Model,
    archive_bytes: []const []const u8,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    sequence: u32,
    package: native_program.PackageIdentity,
    hooks: root_mutation.Hooks,
    mutation_last_step: ?*u32,
) !MaterializationResult {
    const model_index = lifecycleArchiveIndex(models, package) orelse
        return .{ .outcome = .refused, .detail = "archive_missing" };
    const artifact = lifecycleProgramArtifact(program.*, package) orelse
        return .{ .outcome = .refused, .detail = "artifact_missing" };
    const input = [_]ArchiveInput{.{
        .artifact = artifact.index,
        .bytes = archive_bytes[model_index],
    }};
    const sequences = [_]u32{sequence};
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    var request = lifecyclePhaseRequest(
        execution,
        root,
        install_root,
        captured.snapshot,
        &input,
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        &sequences,
    );
    request.hooks = hooks;
    request.mutation_last_step = mutation_last_step;
    return materialize(allocator, request);
}

fn lifecycleConfigurePackage(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    models: []archive_application.Model,
    archive_bytes: []const []const u8,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    package: native_program.PackageRef,
) !MaterializationResult {
    var artifact: ?native_program.ProgramArtifact = null;
    var model_index: ?usize = null;
    for (program.artifacts) |candidate| {
        if (std.mem.eql(u8, candidate.package.name, package.name) and
            std.mem.eql(u8, candidate.package.architecture, package.architecture))
        {
            artifact = candidate;
            model_index = lifecycleArchiveIndex(models, candidate.package);
            break;
        }
    }
    const selected = artifact orelse
        return .{ .outcome = .refused, .detail = "artifact_missing" };
    const index = model_index orelse
        return .{ .outcome = .refused, .detail = "archive_missing" };
    const input = [_]ArchiveInput{.{
        .artifact = selected.index,
        .bytes = archive_bytes[index],
    }};
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    return materializeConfigure(allocator, lifecyclePhaseRequest(
        execution,
        root,
        install_root,
        captured.snapshot,
        &input,
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        &.{},
    ));
}

fn lifecycleRemovePackage(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    package: native_program.PackageRef,
    purge: bool,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    const selection = [_]ExternalPackageSelection{.{
        .name = package.name,
        .architecture = package.architecture,
    }};
    return materializeRemoval(
        allocator,
        lifecyclePhaseRequest(
            execution,
            root,
            install_root,
            captured.snapshot,
            &.{},
            program,
            authorization,
            locks,
            attempt,
            operation,
            policy,
            &.{},
        ),
        &selection,
        purge,
    );
}

fn lifecycleStateStep(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    state: native_program.StateRecord,
    want: ?package_database.Want,
    error_state: ?package_database.ErrorState,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    var current = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = program.target_architecture,
            .snapshot = captured.snapshot,
        },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "database_rejected" },
    };
    defer current.deinit();
    const record = current.model.find(state.package.name, state.package.architecture);
    const expected_want: package_database.Want = want orelse if (state.hold)
        .hold
    else if (state.state == .config_files)
        .deinstall
    else
        .install;
    const expected_error: package_database.ErrorState = error_state orelse .ok;
    if ((state.remove_entry and record == null) or
        (!state.remove_entry and record != null and
            record.?.status.current == state.state and
            record.?.status.want == expected_want and
            record.?.status.error_state == expected_error))
        return .{ .outcome = .applied, .detail = "state_already_recorded" };
    return materializeStateRecord(
        allocator,
        lifecyclePhaseRequest(
            execution,
            root,
            install_root,
            captured.snapshot,
            &.{},
            program,
            authorization,
            locks,
            attempt,
            operation,
            policy,
            &.{},
        ),
        state,
        want,
        error_state,
    );
}

fn lifecycleFreshFailure(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    package: native_program.PackageIdentity,
    unwind_succeeded: bool,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    var request = lifecyclePhaseRequest(
        execution,
        root,
        install_root,
        captured.snapshot,
        &.{},
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        &.{},
    );
    request.raw_status_verification = true;
    return materializeFreshFailureRecord(
        allocator,
        request,
        package,
        unwind_succeeded,
    );
}

fn lifecycleDetailedState(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    package: native_program.PackageIdentity,
    want: package_database.Want,
    error_state: package_database.ErrorState,
    current: package_database.CurrentState,
    config_version: ?[]const u8,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    return materializeDetailedState(
        allocator,
        lifecyclePhaseRequest(
            execution,
            root,
            install_root,
            captured.snapshot,
            &.{},
            program,
            authorization,
            locks,
            attempt,
            operation,
            policy,
            &.{},
        ),
        package,
        want,
        error_state,
        current,
        config_version,
    );
}

fn lifecycleRestoredPackageState(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    initial_snapshot: package_database.Snapshot,
    initial_model: package_database.Model,
    package: native_program.PackageIdentity,
    want: package_database.Want,
    error_state: package_database.ErrorState,
    current: package_database.CurrentState,
    config_version: ?[]const u8,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    return materializeRestoredPackageState(
        allocator,
        lifecyclePhaseRequest(
            execution,
            root,
            install_root,
            captured.snapshot,
            &.{},
            program,
            authorization,
            locks,
            attempt,
            operation,
            policy,
            &.{},
        ),
        initial_snapshot,
        initial_model,
        package,
        want,
        error_state,
        current,
        config_version,
    );
}

fn lifecycleTriggerDatabase(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    updates: []const TriggerPackageUpdate,
    trigger_state: ?package_database.TriggerState,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    return materializeTriggerDatabase(
        allocator,
        lifecyclePhaseRequest(
            execution,
            root,
            install_root,
            captured.snapshot,
            &.{},
            program,
            authorization,
            locks,
            attempt,
            operation,
            policy,
            &.{},
        ),
        updates,
        trigger_state,
    );
}

fn lifecycleSyncTriggerRegistry(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = program.target_architecture,
            .snapshot = captured.snapshot,
        },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "database_rejected" },
    };
    defer database.deinit();
    const arena = try allocator.create(std.heap.ArenaAllocator);
    defer allocator.destroy(arena);
    arena.* = .init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    var interests: std.ArrayList(package_database.TriggerInterest) = .empty;
    defer interests.deinit(allocator);
    for (database.model.packages) |record| {
        for (record.trigger_declarations orelse &.{}) |declaration| {
            if (!declaration.kind.isInterest()) continue;
            try interests.append(allocator, .{
                .trigger = try owned.dupe(u8, declaration.name),
                .package = .{
                    .name = try owned.dupe(u8, record.name),
                    .architecture = if (std.mem.eql(
                        u8,
                        record.info_stem,
                        record.name,
                    ))
                        ""
                    else
                        try owned.dupe(u8, record.architecture),
                },
                .await_mode = declaration.kind.awaitMode(),
            });
        }
    }
    return lifecycleTriggerDatabase(
        execution,
        allocator,
        root,
        install_root,
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        &.{},
        .{
            .interests = try owned.dupe(
                package_database.TriggerInterest,
                interests.items,
            ),
            .pending = database.model.triggers.pending,
        },
    );
}

fn lifecycleApplyTriggerEvents(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    events: []const RuntimeTriggerEvent,
    clear_queue: bool,
) !MaterializationResult {
    if (events.len == 0 and !clear_queue)
        return .{ .outcome = .applied, .detail = "no_trigger_events" };
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{ .native_architecture = program.target_architecture, .snapshot = captured.snapshot },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "database_rejected" },
    };
    defer database.deinit();
    const arena = try allocator.create(std.heap.ArenaAllocator);
    defer allocator.destroy(arena);
    arena.* = .init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    var pending: std.ArrayList(SimulatedTriggerPackage) = .empty;
    defer {
        for (pending.items) |*entry| entry.values.deinit(owned);
        pending.deinit(owned);
    }
    var pending_index: std.StringHashMapUnmanaged(usize) = .empty;
    defer pending_index.deinit(owned);
    var awaited: std.ArrayList(SimulatedTriggerPackage) = .empty;
    defer {
        for (awaited.items) |*entry| entry.values.deinit(owned);
        awaited.deinit(owned);
    }
    var awaited_index: std.StringHashMapUnmanaged(usize) = .empty;
    defer awaited_index.deinit(owned);
    for (database.model.packages) |record| {
        if (record.triggers_pending.len != 0) {
            const entry = try simulatedTriggerPackage(
                owned,
                &pending,
                &pending_index,
                record.name,
                record.architecture,
            );
            var index = record.triggers_pending.len;
            while (index != 0) {
                index -= 1;
                try appendUniqueText(
                    owned,
                    &entry.values,
                    record.triggers_pending[index],
                );
            }
        }
        if (record.triggers_awaited.len != 0) {
            const entry = try simulatedTriggerPackage(
                owned,
                &awaited,
                &awaited_index,
                record.name,
                record.architecture,
            );
            for (record.triggers_awaited) |name|
                try appendUniqueText(owned, &entry.values, name);
        }
    }
    for (events) |event| {
        for (event.listeners) |listener| {
            const handler = try simulatedTriggerPackage(
                owned,
                &pending,
                &pending_index,
                listener.package.name,
                if (listener.package.architecture.len == 0)
                    program.target_architecture
                else
                    listener.package.architecture,
            );
            try appendUniqueText(owned, &handler.values, event.trigger);
            if (event.activation_awaits and listener.await_mode == .awaited) {
                const source = try simulatedTriggerPackage(
                    owned,
                    &awaited,
                    &awaited_index,
                    event.source.name,
                    event.source.architecture,
                );
                try appendUniqueText(owned, &source.values, listener.package.name);
            }
        }
    }
    var updates: std.ArrayList(TriggerPackageUpdate) = .empty;
    defer updates.deinit(allocator);
    for (database.model.packages) |record| {
        var key_buffer: [512]u8 = undefined;
        const key = try std.fmt.bufPrint(
            &key_buffer,
            "{s}\x00{s}",
            .{ record.name, record.architecture },
        );
        const pending_position = pending_index.get(key);
        const awaited_position = awaited_index.get(key);
        if (pending_position == null and awaited_position == null) continue;
        const pending_values = if (pending_position) |position|
            pending.items[position].values.items
        else
            &.{};
        const reversed = try owned.alloc([]const u8, pending_values.len);
        for (pending_values, 0..) |trigger, index|
            reversed[pending_values.len - index - 1] = trigger;
        const awaited_values = if (awaited_position) |position|
            awaited.items[position].values.items
        else
            &.{};
        try updates.append(allocator, .{
            .package = record.identity(),
            .current = if (awaited_values.len != 0)
                .triggers_awaited
            else
                .triggers_pending,
            .config_version = null,
            .pending = reversed,
            .awaited = awaited_values,
        });
    }
    return lifecycleTriggerDatabase(
        execution,
        allocator,
        root,
        install_root,
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        updates.items,
        .{
            .interests = database.model.triggers.interests,
            .pending = if (clear_queue) &.{} else database.model.triggers.pending,
        },
    );
}

fn lifecyclePublishDerivedFinalState(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    initial_model: package_database.Model,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    events: []const RuntimeTriggerEvent,
) !MaterializationResult {
    const expected = try deriveDeferredFinalState(
        scratch,
        authorization.*,
        initial_model,
        events,
    );
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{ .native_architecture = program.target_architecture, .snapshot = captured.snapshot },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "database_rejected" },
    };
    defer database.deinit();
    var updates: std.ArrayList(TriggerPackageUpdate) = .empty;
    defer updates.deinit(allocator);
    for (expected) |package| {
        if (package.state == .config_files) continue;
        const record = database.model.find(
            package.name,
            package.architecture,
        ) orelse return .{
            .outcome = .refused,
            .detail = "derived_trigger_package_missing",
        };
        try updates.append(allocator, .{
            .package = record.identity(),
            .current = switch (package.state) {
                .installed => .installed,
                .triggers_pending => .triggers_pending,
                .triggers_awaited => .triggers_awaited,
                .config_files => unreachable,
            },
            .config_version = null,
            .pending = package.triggers_pending,
            .awaited = package.triggers_awaited,
        });
    }
    return lifecycleTriggerDatabase(
        execution,
        allocator,
        root,
        install_root,
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        updates.items,
        .{
            .interests = database.model.triggers.interests,
            .pending = &.{},
        },
    );
}

fn latestAuthenticatedTriggerCaller(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
) !?package_database.Identity {
    if (execution.recovery == null) return null;
    var progress = try native_recovery.readProgress(allocator, root);
    defer progress.deinit();
    var index = progress.document.records.len;
    while (index != 0) {
        index -= 1;
        const record = progress.document.records[index];
        if (record.stage != .outcome or
            (record.action.kind != .script and
                record.action.kind != .compensation and
                record.action.kind != .trigger))
            continue;
        var outcome = (try native_recovery.readScriptOutcome(
            allocator,
            root,
            record.action,
        )) orelse continue;
        defer outcome.deinit();
        return .{
            .name = try allocator.dupe(u8, outcome.outcome.package),
            .architecture = try allocator.dupe(
                u8,
                outcome.outcome.architecture,
            ),
        };
    }
    return null;
}

fn lifecycleIncorporateTriggerQueue(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    activation_allocator: ?std.mem.Allocator,
    activation_log: ?*std.ArrayList(RuntimeTriggerEvent),
    apply_events: bool,
    initial_pending: []const package_database.PendingTrigger,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{ .native_architecture = program.target_architecture, .snapshot = captured.snapshot },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "trigger_queue_rejected" },
    };
    defer database.deinit();
    if (database.model.triggers.pending.len == 0)
        return .{ .outcome = .applied, .detail = "trigger_queue_empty" };
    const arena = try allocator.create(std.heap.ArenaAllocator);
    defer allocator.destroy(arena);
    arena.* = .init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    var events: std.ArrayList(RuntimeTriggerEvent) = .empty;
    defer events.deinit(owned);
    for (database.model.triggers.pending) |pending| {
        if (pending.packages.len == 0) {
            try appendRuntimeTriggerEvent(
                owned,
                &events,
                .{ .name = "", .architecture = "" },
                pending.trigger,
                false,
                database.model.triggers.interests,
                .dynamic,
            );
        } else {
            for (pending.packages) |source| {
                try appendRuntimeTriggerEvent(
                    owned,
                    &events,
                    .{
                        .name = source.package.name,
                        .architecture = if (source.package.architecture.len == 0)
                            program.target_architecture
                        else
                            source.package.architecture,
                    },
                    pending.trigger,
                    true,
                    database.model.triggers.interests,
                    .dynamic,
                );
            }
            if (pending.noawait)
                try appendRuntimeTriggerEvent(
                    owned,
                    &events,
                    .{ .name = "", .architecture = "" },
                    pending.trigger,
                    false,
                    database.model.triggers.interests,
                    .dynamic,
                );
        }
    }
    if (activation_log) |log| {
        const destination = activation_allocator orelse return error.InvalidLifecycleProgram;
        const noawait_source = try latestAuthenticatedTriggerCaller(
            execution,
            destination,
            root,
        );
        for (database.model.triggers.pending) |pending| {
            const initial = for (initial_pending) |candidate| {
                if (std.mem.eql(u8, candidate.trigger, pending.trigger))
                    break candidate;
            } else null;
            for (pending.packages) |source| {
                var existed = false;
                if (initial) |before| for (before.packages) |candidate| {
                    if (package_database.Identity.eql(
                        source.package,
                        candidate.package,
                    )) existed = true;
                };
                if (existed) continue;
                try appendRuntimeTriggerEvent(
                    destination,
                    log,
                    .{
                        .name = source.package.name,
                        .architecture = if (source.package.architecture.len == 0)
                            program.target_architecture
                        else
                            source.package.architecture,
                    },
                    pending.trigger,
                    true,
                    database.model.triggers.interests,
                    .dynamic,
                );
            }
            if (pending.noawait and
                (initial == null or !initial.?.noawait))
                try appendRuntimeTriggerEvent(
                    destination,
                    log,
                    noawait_source orelse
                        .{ .name = "", .architecture = "" },
                    pending.trigger,
                    false,
                    database.model.triggers.interests,
                    .dynamic,
                );
        }
    }
    if (activation_log) |log|
        try persistRuntimeTriggerEvents(
            execution,
            activation_allocator orelse return error.InvalidLifecycleProgram,
            root,
            log.items,
        );
    if (apply_events)
        return lifecycleApplyTriggerEvents(
            execution,
            allocator,
            root,
            install_root,
            program,
            authorization,
            locks,
            attempt,
            operation,
            policy,
            events.items,
            true,
        );
    return lifecycleTriggerDatabase(
        execution,
        allocator,
        root,
        install_root,
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        &.{},
        .{
            .interests = database.model.triggers.interests,
            .pending = &.{},
        },
    );
}

const PendingTriggerHandler = struct {
    package: native_program.PackageIdentity,
    state_sha256: [32]u8,
    triggers: []const []const u8,
};

fn nextPendingTriggerHandler(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    architecture: []const u8,
) !?PendingTriggerHandler {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{ .native_architecture = architecture, .snapshot = captured.snapshot },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return error.InvalidExternalDatabase,
    };
    defer database.deinit();
    const state_sha256 = native_trigger.stateDigest(database.model);
    for (database.model.packages) |record| {
        if (record.triggers_pending.len == 0) continue;
        const triggers = try allocator.alloc(
            []const u8,
            record.triggers_pending.len,
        );
        for (record.triggers_pending, 0..) |trigger, index|
            triggers[record.triggers_pending.len - index - 1] =
                try allocator.dupe(u8, trigger);
        return .{
            .package = .{
                .name = try allocator.dupe(u8, record.name),
                .version = try allocator.dupe(u8, record.version),
                .architecture = try allocator.dupe(u8, record.architecture),
            },
            .state_sha256 = state_sha256,
            .triggers = triggers,
        };
    }
    return null;
}

fn triggerHandlerBinding(
    program: native_program.Program,
    package: native_program.PackageIdentity,
) ?native_program.TriggerHandlerBinding {
    const authority = program.trigger_authority orelse return null;
    for (authority.handlers) |handler| {
        if (std.mem.eql(u8, handler.package.name, package.name) and
            std.mem.eql(u8, handler.package.version, package.version) and
            std.mem.eql(
                u8,
                handler.package.architecture,
                package.architecture,
            ))
            return handler;
    }
    return null;
}

fn lifecycleCompleteTriggerHandler(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    handler: native_program.PackageIdentity,
    failure: ?struct {
        config_version: ?[]const u8,
        error_state: package_database.ErrorState = .ok,
    },
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{ .native_architecture = program.target_architecture, .snapshot = captured.snapshot },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "database_rejected" },
    };
    defer database.deinit();
    const arena = try allocator.create(std.heap.ArenaAllocator);
    defer allocator.destroy(arena);
    arena.* = .init(allocator);
    defer arena.deinit();
    const owned = arena.allocator();
    var updates: std.ArrayList(TriggerPackageUpdate) = .empty;
    defer updates.deinit(allocator);
    for (database.model.packages) |record| {
        if (std.mem.eql(u8, record.name, handler.name) and
            std.mem.eql(u8, record.architecture, handler.architecture))
        {
            try updates.append(allocator, .{
                .package = record.identity(),
                .current = if (failure != null)
                    .half_configured
                else if (record.triggers_awaited.len != 0)
                    .triggers_awaited
                else
                    .installed,
                .error_state = if (failure) |value| value.error_state else .ok,
                .config_version = if (failure) |value| value.config_version else null,
                .pending = &.{},
                .awaited = if (failure == null) record.triggers_awaited else &.{},
            });
            continue;
        }
        var awaited: std.ArrayList([]const u8) = .empty;
        defer awaited.deinit(owned);
        for (record.triggers_awaited) |name| {
            if (!std.mem.eql(u8, name, handler.name))
                try awaited.append(owned, name);
        }
        if (awaited.items.len == record.triggers_awaited.len) continue;
        try updates.append(allocator, .{
            .package = record.identity(),
            .current = if (awaited.items.len == 0)
                .installed
            else
                .triggers_awaited,
            .config_version = null,
            .pending = record.triggers_pending,
            .awaited = try owned.dupe([]const u8, awaited.items),
        });
    }
    return lifecycleTriggerDatabase(
        execution,
        allocator,
        root,
        install_root,
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        updates.items,
        .{
            .interests = database.model.triggers.interests,
            .pending = database.model.triggers.pending,
        },
    );
}

fn recoveredTriggerOrdinal(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    sequence: u32,
    package: native_program.PackageIdentity,
    arguments: []const []const u8,
) !u32 {
    if (execution.recovery == null) return execution.script_ordinal;
    var progress = try native_recovery.readProgress(allocator, root);
    defer progress.deinit();
    var next: u32 = 0;
    for (progress.document.records) |record| {
        if (record.action.kind != .trigger or
            record.action.program_step != sequence or
            record.stage != .outcome)
            continue;
        next = @max(next, record.action.ordinal +| 1);
        var outcome = (try native_recovery.readScriptOutcome(
            allocator,
            root,
            record.action,
        )) orelse return error.InvalidScriptOutcome;
        defer outcome.deinit();
        if (std.mem.eql(u8, outcome.outcome.package, package.name) and
            std.mem.eql(u8, outcome.outcome.architecture, package.architecture) and
            textListEqual(outcome.outcome.arguments, arguments))
            return record.action.ordinal;
    }
    return next;
}

fn restoreTriggerCycleSignatures(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    sequence: u32,
    produced: *std.AutoHashMapUnmanaged([32]u8, void),
) !void {
    if (execution.recovery == null) return;
    var progress = try native_recovery.readProgress(allocator, root);
    defer progress.deinit();
    for (progress.document.records) |record| {
        if (record.action.kind != .trigger or
            record.action.program_step != sequence or
            record.action.substep != std.math.maxInt(u16) or
            record.stage != .activation)
            continue;
        const digest = native_recovery.parseDigest(
            record.evidence_sha256 orelse return error.InvalidRecoveryProgress,
        ) orelse return error.InvalidRecoveryProgress;
        try produced.put(allocator, digest, {});
    }
}

fn persistTriggerCycleSignature(
    runtime: *native_recovery.Runtime,
    sequence: u32,
    ordinal: u32,
    signature: [32]u8,
) !void {
    const action = nativeAction(
        .trigger,
        sequence,
        std.math.maxInt(u16),
        ordinal,
    );
    if (try runtime.latest(action)) |record| {
        const evidence = record.evidence_sha256 orelse
            return error.InvalidRecoveryProgress;
        if (record.stage != .activation or
            !std.mem.eql(
                u8,
                &evidence,
                &native_recovery.hexDigest(signature),
            ))
            return error.InvalidRecoveryProgress;
        return;
    }
    try runtime.append(
        action,
        .activation,
        .succeeded,
        native_recovery.hexDigest(signature),
    );
}

fn lifecycleProcessTriggers(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    activation_log: *std.ArrayList(RuntimeTriggerEvent),
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    sequence: u32,
    inject_unknown: bool,
) !LifecycleResult {
    var incorporated = try lifecycleIncorporateTriggerQueue(
        execution,
        allocator,
        root,
        install_root,
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        scratch,
        activation_log,
        true,
        &.{},
    );
    if (lifecycleMaterializationFailure(incorporated)) |failure| return failure;
    var produced: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
    defer produced.deinit(allocator);
    try restoreTriggerCycleSignatures(
        execution,
        allocator,
        root,
        sequence,
        &produced,
    );
    var used_fault = false;
    var invocation_count: u32 = 0;
    const maximum_invocations = program.trigger_authority.?.maximum_invocations;
    while (try nextPendingTriggerHandler(
        scratch,
        root,
        program.target_architecture,
    )) |handler| {
        if (invocation_count >= maximum_invocations)
            return .{
                .outcome = .trigger_failed,
                .detail = "trigger_invocation_limit",
                .program_sha256 = program.digest_sha256,
            };
        invocation_count += 1;
        const binding = triggerHandlerBinding(program.*, handler.package) orelse
            return .{ .outcome = .refused, .detail = "trigger_handler_unbound" };
        const joined = try std.mem.join(scratch, " ", handler.triggers);
        const arguments = [_][]const u8{ "triggered", joined };
        if (execution.recovery != null) {
            execution.script_ordinal = try recoveredTriggerOrdinal(
                execution,
                allocator,
                root,
                sequence,
                handler.package,
                &arguments,
            );
            if (execution.script_ordinal >= maximum_invocations)
                return .{
                    .outcome = .trigger_failed,
                    .detail = "trigger_invocation_limit",
                    .program_sha256 = program.digest_sha256,
                };
            invocation_count = @max(
                invocation_count,
                execution.script_ordinal + 1,
            );
        }
        const handler_ordinal = execution.script_ordinal;
        const outcome = try runLifecycleScript(
            execution,
            allocator,
            root,
            install_root,
            program,
            authorization,
            attempt,
            sequence,
            handler.package,
            handler.package,
            .postinst,
            switch (binding.source) {
                .installed_package => .installed_package,
                .new_package => .new_package,
            },
            binding.postinst_sha256,
            &arguments,
            inject_unknown and !used_fault,
        );
        used_fault = true;
        const code = switch (outcome) {
            .recovery_required => return .{
                .outcome = .recovery_required,
                .detail = "trigger_script_outcome_unknown",
                .program_sha256 = program.digest_sha256,
            },
            .exited => |value| value,
            .not_started => 255,
        };
        if (code != 0) {
            const failed = try lifecycleCompleteTriggerHandler(
                execution,
                allocator,
                root,
                install_root,
                program,
                authorization,
                locks,
                attempt,
                operation,
                policy,
                handler.package,
                .{ .config_version = handler.package.version },
            );
            if (lifecycleMaterializationFailure(failed)) |failure| return failure;
            return .{
                .outcome = .trigger_failed,
                .detail = "triggered_postinst",
                .program_sha256 = program.digest_sha256,
            };
        }
        const completed = try lifecycleCompleteTriggerHandler(
            execution,
            allocator,
            root,
            install_root,
            program,
            authorization,
            locks,
            attempt,
            operation,
            policy,
            handler.package,
            null,
        );
        if (lifecycleMaterializationFailure(completed)) |failure| return failure;
        incorporated = try lifecycleIncorporateTriggerQueue(
            execution,
            allocator,
            root,
            install_root,
            program,
            authorization,
            locks,
            attempt,
            operation,
            policy,
            scratch,
            activation_log,
            true,
            &.{},
        );
        if (lifecycleMaterializationFailure(incorporated)) |failure| return failure;
        const next = (try nextPendingTriggerHandler(
            scratch,
            root,
            program.target_architecture,
        )) orelse return .{
            .outcome = .applied,
            .detail = "triggers_processed",
            .program_sha256 = program.digest_sha256,
        };
        const self_cycle = std.mem.eql(u8, next.package.name, handler.package.name) and
            std.mem.eql(
                u8,
                next.package.architecture,
                handler.package.architecture,
            ) and std.mem.eql(u8, &next.state_sha256, &handler.state_sha256);
        if (self_cycle or produced.contains(next.state_sha256)) {
            const failed = try lifecycleCompleteTriggerHandler(
                execution,
                allocator,
                root,
                install_root,
                program,
                authorization,
                locks,
                attempt,
                operation,
                policy,
                next.package,
                .{
                    .config_version = next.package.version,
                },
            );
            if (lifecycleMaterializationFailure(failed)) |failure| return failure;
            return .{
                .outcome = .trigger_failed,
                .detail = "trigger_cycle_no_progress",
                .program_sha256 = program.digest_sha256,
            };
        }
        try produced.put(allocator, next.state_sha256, {});
        if (execution.recovery) |runtime|
            try persistTriggerCycleSignature(
                runtime,
                sequence,
                handler_ordinal,
                next.state_sha256,
            );
    }
    return .{
        .outcome = .applied,
        .detail = "triggers_processed",
        .program_sha256 = program.digest_sha256,
    };
}

fn lifecycleAuxiliary(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    intents: []const root_mutation.Intent,
    label: []const u8,
) !MaterializationResult {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    return lifecycleAuxiliaryMutation(
        allocator,
        lifecyclePhaseRequest(
            execution,
            root,
            install_root,
            captured.snapshot,
            &.{},
            program,
            authorization,
            locks,
            attempt,
            operation,
            policy,
            &.{},
        ),
        intents,
        label,
    );
}

const lifecycle_script_record_path =
    "var/lib/debz/native-lifecycle-script-v1.json";
const lifecycle_tmp_ci = "var/lib/debz-lifecycle-scripts";
const lifecycle_script_directories = [_][]const u8{
    lifecycle_tmp_ci,
    "var/lib/dpkg/info",
};

fn lifecycleScriptPolicy() maintainer_script.Policy {
    return .{ .script_directories = &lifecycle_script_directories };
}

fn publishTriggerAuthority(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    program: native_program.Program,
    attempt: *root_operation.Attempt,
) !?[]u8 {
    const authority = program.trigger_authority orelse return null;
    const handlers = try allocator.alloc(native_trigger.Handler, authority.handlers.len);
    defer allocator.free(handlers);
    for (authority.handlers, 0..) |handler, index| {
        handlers[index] = .{
            .package = handler.package.name,
            .version = handler.package.version,
            .architecture = handler.package.architecture,
            .source = switch (handler.source) {
                .installed_package => .installed_package,
                .new_package => .new_package,
            },
            .postinst_sha256 = parseHex(
                32,
                &handler.postinst_sha256,
            ) orelse return error.InvalidLifecycleProgram,
            .declarations_sha256 = parseHex(
                32,
                &handler.declarations_sha256,
            ) orelse return error.InvalidLifecycleProgram,
        };
    }
    const callers = try allocator.alloc(native_trigger.Caller, authority.callers.len);
    defer allocator.free(callers);
    for (authority.callers, 0..) |caller, index| {
        callers[index] = .{
            .package = caller.package.name,
            .version = caller.package.version,
            .architecture = caller.package.architecture,
            .source = switch (caller.source) {
                .installed_package => .installed_package,
                .new_package => .new_package,
            },
            .kind = caller.kind,
            .script_sha256 = parseHex(
                32,
                &caller.script_sha256,
            ) orelse return error.InvalidLifecycleProgram,
        };
    }
    const bytes = try native_trigger.authorityJson(allocator, .{
        .program_sha256 = parseHex(
            32,
            &program.digest_sha256,
        ) orelse return error.InvalidLifecycleProgram,
        .attempt_id = attempt.record().attempt_id,
        .initial_state_sha256 = parseHex(
            32,
            &authority.initial_state_sha256,
        ) orelse return error.InvalidLifecycleProgram,
        .handlers = handlers,
        .callers = callers,
        .allowed_triggers = authority.allowed_triggers,
        .maximum_invocations = authority.maximum_invocations,
        .final_mode = switch (authority.final_mode) {
            .exact => .exact,
            .derive_from_activations => .derive_from_activations,
        },
        .base_final_state_sha256 = if (authority.base_final_state_sha256) |digest|
            parseHex(32, &digest) orelse return error.InvalidLifecycleProgram
        else
            null,
        .maximum_activations = authority.maximum_activations,
    });
    errdefer allocator.free(bytes);
    if (bytes.len > native_trigger.maximum_document_bytes)
        return error.TriggerAuthorityTooLarge;
    root.publishFile(
        try root_fs.Path.init(native_trigger.authority_path),
        bytes,
        .{
            .permissions = if (builtin.os.tag == .windows)
                .default_file
            else
                .fromMode(0o600),
            .overwrite = .fail_if_exists,
            .durable = true,
        },
    ) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const observed = try root.readFileAlloc(
                allocator,
                try root_fs.Path.init(native_trigger.authority_path),
                native_trigger.maximum_document_bytes,
            );
            defer allocator.free(observed);
            if (!std.mem.eql(u8, observed, bytes))
                return error.TriggerAuthorityChanged;
        },
        else => return err,
    };
    return bytes;
}

fn clearTriggerAuthority(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    expected: ?[]const u8,
) !void {
    const bytes = expected orelse return;
    const path = try root_fs.Path.init(native_trigger.authority_path);
    const observed = try root.readFileAlloc(
        allocator,
        path,
        native_trigger.maximum_document_bytes,
    );
    defer allocator.free(observed);
    if (!std.mem.eql(u8, bytes, observed))
        return error.TriggerAuthorityChanged;
    try root.removeFile(path);
    try root.syncDirectory(try root_fs.Path.init(root_operation.namespace_path));
}

const LifecycleStaging = struct {
    paths: std.ArrayList([]const u8) = .empty,
    packages: std.StringHashMapUnmanaged(void) = .empty,
    directory_created: bool = false,

    fn deinit(self: *LifecycleStaging, allocator: std.mem.Allocator) void {
        self.paths.deinit(allocator);
        self.packages.deinit(allocator);
        self.* = undefined;
    }
};

fn lifecyclePackageKey(
    allocator: std.mem.Allocator,
    package: native_program.PackageIdentity,
) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}\x00{s}",
        .{ package.name, package.architecture },
    );
}

fn stageLifecycleScripts(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    models: []archive_application.Model,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    package: native_program.PackageIdentity,
    staging: *LifecycleStaging,
) !MaterializationResult {
    const key = try lifecyclePackageKey(scratch, package);
    if (staging.packages.contains(key))
        return .{ .outcome = .applied, .detail = "already_staged" };

    var intents: std.ArrayList(root_mutation.Intent) = .empty;
    defer intents.deinit(allocator);
    const directory = try root.entryIfExists(try root_fs.Path.init(lifecycle_tmp_ci));
    if (directory) |entry| {
        if (entry.kind != .directory)
            return .{ .outcome = .refused, .detail = "tmp_ci_not_directory" };
        if (execution.recovery) |runtime|
            staging.directory_created =
                !runtime.staging_directory_initially_present;
    } else {
        try intents.append(allocator, .{ .directory = .{
            .path = lifecycle_tmp_ci,
            .mode = 0o755,
            .uid = 0,
            .gid = 0,
            .overwrite = .require_absent,
        } });
        staging.directory_created = true;
    }

    if (lifecycleArchiveIndex(models, package)) |model_index| {
        const model = &models[model_index];
        for (model.scripts) |script| {
            const kind = lifecycleArchiveScriptKind(script.kind) orelse
                return .{ .outcome = .handoff, .detail = "config_script" };
            const path = try std.fmt.allocPrint(
                scratch,
                "{s}/{s}.{s}",
                .{ lifecycle_tmp_ci, package.name, @tagName(kind) },
            );
            if (try root.entryIfExists(try root_fs.Path.init(path)) != null) {
                if (execution.recovery == null)
                    return .{ .outcome = .refused, .detail = "tmp_ci_collision" };
                const staged_sha = rootFileSha256(
                    allocator,
                    root,
                    path,
                    64 * 1024 * 1024,
                ) catch return .{ .outcome = .refused, .detail = "tmp_ci_changed" };
                if (!std.mem.eql(u8, &staged_sha, &script.sha256))
                    return .{ .outcome = .refused, .detail = "tmp_ci_changed" };
                try staging.paths.append(allocator, path);
                continue;
            }
            try intents.append(allocator, .{ .file = .{
                .path = path,
                .bytes = model.scriptBytes(script),
                .mode = script.mode,
                .uid = 0,
                .gid = 0,
                .overwrite = .require_absent,
                .expected_sha256 = script.sha256,
            } });
            try staging.paths.append(allocator, path);
        }
    }

    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = program.target_architecture,
            .snapshot = captured.snapshot,
        },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return .{ .outcome = .refused, .detail = "database_rejected" },
    };
    defer database.deinit();
    if (database.model.find(package.name, package.architecture)) |record| {
        for (record.scripts) |script| {
            const kind = lifecycleScriptKind(script.kind);
            const source = try std.fmt.allocPrint(
                scratch,
                "{s}/{s}/{s}.{s}",
                .{
                    package_database.database_directory,
                    package_database.info_directory,
                    record.info_stem,
                    @tagName(kind),
                },
            );
            const path = try std.fmt.allocPrint(
                scratch,
                "{s}/{s}:{s}.{s}",
                .{ lifecycle_tmp_ci, package.name, package.architecture, @tagName(kind) },
            );
            if (try root.entryIfExists(try root_fs.Path.init(path)) != null) {
                if (execution.recovery == null)
                    return .{ .outcome = .refused, .detail = "tmp_ci_collision" };
                const staged_sha = rootFileSha256(
                    allocator,
                    root,
                    path,
                    64 * 1024 * 1024,
                ) catch return .{ .outcome = .refused, .detail = "tmp_ci_changed" };
                if (!std.mem.eql(u8, &staged_sha, &script.sha256))
                    return .{ .outcome = .refused, .detail = "tmp_ci_changed" };
                try staging.paths.append(allocator, path);
                continue;
            }
            try intents.append(allocator, .{ .copy = .{
                .path = path,
                .source = source,
                .source_sha256 = script.sha256,
                .mode = script.mode,
                .uid = 0,
                .gid = 0,
                .overwrite = .require_absent,
            } });
            try staging.paths.append(allocator, path);
        }
    }
    const result = try lifecycleAuxiliary(
        execution,
        allocator,
        root,
        install_root,
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        intents.items,
        "stage-scripts",
    );
    if (result.outcome == .applied)
        try staging.packages.put(allocator, key, {});
    return result;
}

fn cleanupLifecycleStaging(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    staging: *LifecycleStaging,
) !MaterializationResult {
    if (staging.paths.items.len == 0 and !staging.directory_created)
        return .{ .outcome = .applied, .detail = "nothing_staged" };
    var intents: std.ArrayList(root_mutation.Intent) = .empty;
    defer intents.deinit(allocator);
    for (staging.paths.items) |path| try intents.append(allocator, .{ .remove = .{
        .path = path,
        .removal = .allow_absent,
    } });
    if (staging.directory_created)
        try intents.append(allocator, .{ .remove_directory = .{
            .path = lifecycle_tmp_ci,
            .removal = .allow_absent,
        } });
    return lifecycleAuxiliary(
        execution,
        allocator,
        root,
        install_root,
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        intents.items,
        "cleanup-scripts",
    );
}

fn lifecycleInstalledScriptPath(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    architecture: []const u8,
    package: native_program.PackageIdentity,
    kind: maintainer_script.Kind,
) ![]const u8 {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{ .native_architecture = architecture, .snapshot = captured.snapshot },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return error.InvalidExternalDatabase,
    };
    defer database.deinit();
    const record = database.model.find(package.name, package.architecture) orelse
        return error.InstalledScriptMissing;
    return std.fmt.allocPrint(
        allocator,
        "{s}/{s}/{s}.{s}",
        .{
            package_database.database_directory,
            package_database.info_directory,
            record.info_stem,
            @tagName(kind),
        },
    );
}

fn lifecycleScriptPath(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    architecture: []const u8,
    package: native_program.PackageIdentity,
    kind: maintainer_script.Kind,
    source: native_program.ScriptSource,
) ![]const u8 {
    const staged = switch (source) {
        .new_package => try std.fmt.allocPrint(
            allocator,
            "{s}/{s}.{s}",
            .{ lifecycle_tmp_ci, package.name, @tagName(kind) },
        ),
        .installed_package => try std.fmt.allocPrint(
            allocator,
            "{s}/{s}:{s}.{s}",
            .{ lifecycle_tmp_ci, package.name, package.architecture, @tagName(kind) },
        ),
    };
    if (try root.entryIfExists(try root_fs.Path.init(staged)) != null)
        return staged;
    allocator.free(staged);
    return lifecycleInstalledScriptPath(
        allocator,
        root,
        architecture,
        package,
        kind,
    );
}

const LifecycleScriptRecord = struct {
    schema: []const u8 = "https://debz.dev/schema/native-lifecycle-script-v1",
    program_sha256: []const u8,
    step: u32,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    kind: []const u8,
    source: []const u8,
    script_sha256: []const u8,
    arguments: []const []const u8,
    outcome: []const u8,
    exit_code: ?u8,
};

fn lifecycleScriptRecordBytes(
    allocator: std.mem.Allocator,
    program: native_program.Program,
    step: u32,
    package: native_program.PackageIdentity,
    kind: maintainer_script.Kind,
    source: native_program.ScriptSource,
    script_sha256: native_program.Digest,
    arguments: []const []const u8,
    outcome: []const u8,
    exit_code: ?u8,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(
        LifecycleScriptRecord{
            .program_sha256 = &program.digest_sha256,
            .step = step,
            .package = package.name,
            .version = package.version,
            .architecture = package.architecture,
            .kind = @tagName(kind),
            .source = @tagName(source),
            .script_sha256 = &script_sha256,
            .arguments = arguments,
            .outcome = outcome,
            .exit_code = exit_code,
        },
        .{ .whitespace = .minified },
        &output.writer,
    );
    try output.writer.writeByte('\n');
    return output.toOwnedSlice();
}

fn publishLifecycleScriptRecord(
    root: root_fs.Root,
    bytes: []const u8,
    overwrite: root_fs.OverwritePolicy,
) !void {
    try root.publishFile(
        try root_fs.Path.init(lifecycle_script_record_path),
        bytes,
        .{
            .permissions = if (builtin.os.tag == .windows)
                .default_file
            else
                .fromMode(0o600),
            .overwrite = overwrite,
            .durable = true,
        },
    );
}

fn clearLifecycleScriptRecord(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    expected: []const u8,
) !void {
    const path = try root_fs.Path.init(lifecycle_script_record_path);
    const observed = try root.readFileAlloc(
        allocator,
        path,
        64 * 1024,
    );
    defer allocator.free(observed);
    if (!std.mem.eql(u8, observed, expected))
        return error.LifecycleScriptRecordChanged;
    try root.removeFile(path);
    try root.syncDirectory(try root_fs.Path.init(root_operation.namespace_path));
}

const LifecycleScriptOutcome = union(enum) {
    exited: u8,
    not_started,
    recovery_required,
};

fn textListEqual(left: []const []const u8, right: []const []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (!std.mem.eql(u8, a, b)) return false;
    return true;
}

fn nativeScriptOutcomeMatches(
    outcome: native_recovery.ScriptOutcome,
    runtime: native_recovery.Runtime,
    action: native_recovery.Action,
    package: native_program.PackageIdentity,
    kind: maintainer_script.Kind,
    source: native_program.ScriptSource,
    script_sha256: [32]u8,
    arguments: []const []const u8,
) bool {
    const expected_script = native_recovery.hexDigest(script_sha256);
    return std.mem.eql(u8, &outcome.intent_sha256, &runtime.intent_sha256) and
        std.meta.eql(outcome.action, action) and
        std.mem.eql(u8, outcome.package, package.name) and
        std.mem.eql(u8, outcome.package_version, package.version) and
        std.mem.eql(u8, outcome.architecture, package.architecture) and
        outcome.kind == kind and
        std.mem.eql(u8, outcome.source, @tagName(source)) and
        std.mem.eql(u8, &outcome.script_sha256, &expected_script) and
        textListEqual(outcome.arguments, arguments);
}

fn nativeScriptDisposition(
    outcome: native_recovery.ScriptOutcome,
) LifecycleScriptOutcome {
    return switch (outcome.disposition) {
        .exited => .{ .exited = outcome.exit_code orelse 255 },
        .setup_failed, .rejected => if (!outcome.spawned)
            .not_started
        else
            .recovery_required,
        .signaled,
        .timed_out,
        .cancelled,
        .output_limit_exceeded,
        => .recovery_required,
    };
}

fn hexBytesAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const output = try allocator.alloc(u8, try std.math.mul(
        usize,
        bytes.len,
        2,
    ));
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output;
}

fn persistNativeScriptOutcome(
    allocator: std.mem.Allocator,
    runtime: *native_recovery.Runtime,
    action: native_recovery.Action,
    package: native_program.PackageIdentity,
    kind: maintainer_script.Kind,
    source: native_program.ScriptSource,
    script_sha256: [32]u8,
    arguments: []const []const u8,
    report: maintainer_script.Report,
) !native_recovery.ScriptOutcome {
    const environment = try allocator.alloc(
        native_recovery.EnvironmentEntry,
        report.environment.len,
    );
    defer allocator.free(environment);
    const stdout_hex = try hexBytesAlloc(allocator, report.stdout);
    defer allocator.free(stdout_hex);
    const stderr_hex = try hexBytesAlloc(allocator, report.stderr);
    defer allocator.free(stderr_hex);
    const combined_hex = try hexBytesAlloc(allocator, report.combined);
    defer allocator.free(combined_hex);
    for (report.environment, 0..) |entry, index| environment[index] = .{
        .key = entry.key,
        .value = entry.value,
    };
    var disposition: native_recovery.ScriptDisposition = undefined;
    var exit_code: ?u8 = null;
    var signal: ?u32 = null;
    var setup_stage: ?maintainer_script.SetupStage = null;
    var setup_errno: ?u32 = null;
    var rejection_reason: ?maintainer_script.RejectionReason = null;
    switch (report.outcome) {
        .exited => |value| {
            disposition = .exited;
            exit_code = value;
        },
        .signaled => |value| {
            disposition = .signaled;
            signal = value;
        },
        .timed_out => disposition = .timed_out,
        .cancelled => disposition = .cancelled,
        .setup_failed => |failure| {
            disposition = .setup_failed;
            setup_stage = failure.stage;
            setup_errno = failure.errno;
        },
        .output_limit_exceeded => disposition = .output_limit_exceeded,
        .rejected => |reason| {
            disposition = .rejected;
            rejection_reason = reason;
        },
    }
    var outcome: native_recovery.ScriptOutcome = .{
        .intent_sha256 = runtime.intent_sha256,
        .action = action,
        .package = package.name,
        .package_version = package.version,
        .architecture = package.architecture,
        .kind = kind,
        .source = @tagName(source),
        .script_sha256 = native_recovery.hexDigest(script_sha256),
        .arguments = arguments,
        .environment = environment,
        .disposition = disposition,
        .exit_code = exit_code,
        .signal = signal,
        .setup_stage = setup_stage,
        .setup_errno = setup_errno,
        .rejection_reason = rejection_reason,
        .spawned = report.outcome.spawned(),
        .invocation_sha256 = native_recovery.hexDigest(
            report.evidence.invocation_sha256,
        ),
        .stdout_sha256 = native_recovery.hexDigest(
            report.evidence.stdout_sha256,
        ),
        .stderr_sha256 = native_recovery.hexDigest(
            report.evidence.stderr_sha256,
        ),
        .combined_sha256 = native_recovery.hexDigest(
            report.evidence.combined_sha256,
        ),
        .stdout_hex = stdout_hex,
        .stderr_hex = stderr_hex,
        .combined_hex = combined_hex,
        .output_bytes = report.output_bytes,
        .output_limit = report.output_limit,
        .terminated_process_group = report.terminated_process_group,
        .escalated_to_kill = report.escalated_to_kill,
        .issued_descendant_sweep = report.issued_descendant_sweep,
        .digest_sha256 = @splat('0'),
    };
    native_recovery.sealScriptOutcome(&outcome);
    try native_recovery.publishScriptOutcome(allocator, runtime.root, outcome);
    return outcome;
}

fn retainNativeEvidence(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
    intent: native_recovery.Intent,
    progress: native_recovery.ProgressDocument,
    managed: native_recovery.ManagedStateDocument,
    trigger_events: native_recovery.TriggerEventsDocument,
) !native_provenance.RetainedEvidence {
    var source_arena = std.heap.ArenaAllocator.init(allocator);
    defer source_arena.deinit();
    const scratch = source_arena.allocator();
    var sources: std.ArrayList(native_provenance.EvidenceSource) = .empty;
    defer sources.deinit(scratch);
    const record = attempt.record();
    try sources.append(scratch, .{
        .kind = .authorization,
        .source_path = root_operation.namespace_path ++ "/" ++
            native_recovery.authorization_name,
        .receipt_name = "authorization.json",
        .document_sha256 = native_recovery.hexDigest(
            record.authorization_sha256 orelse
                return error.InvalidRecoveryIntent,
        ),
    });
    try sources.append(scratch, .{
        .kind = .program,
        .source_path = root_operation.namespace_path ++ "/" ++
            native_recovery.program_name,
        .receipt_name = "program.json",
        .document_sha256 = native_recovery.hexDigest(
            record.program_sha256 orelse return error.InvalidRecoveryIntent,
        ),
    });
    try sources.append(scratch, .{
        .kind = .intent,
        .source_path = native_recovery.intent_path,
        .receipt_name = "intent.json",
        .document_sha256 = intent.digest_sha256,
    });
    for (intent.blobs) |blob| {
        if (blob.kind != .request or
            (!std.mem.eql(u8, blob.logical_path, native_execution_request.logical_path) and
                !std.mem.eql(u8, blob.logical_path, native_execution_request.helper_logical_path)))
            continue;
        const bytes = try native_recovery.verifyBlob(scratch, root, blob);
        var request = try native_execution_request.decodePersisted(scratch, bytes);
        defer request.deinit();
        if (!std.mem.eql(u8, request.logicalPath(), blob.logical_path))
            return error.RecoveryRequestBindingMismatch;
        try native_execution_request.validateIntent(request.execution(), intent);
        try sources.append(scratch, .{
            .kind = .execution_request,
            .source_path = blob.storage_path,
            .receipt_name = "execution-request.json",
            .document_sha256 = request.documentDigest(),
        });
        if (request.helper()) |helper| {
            try verifyNativeHelperBytes(scratch, root, helper);
            try sources.append(scratch, .{
                .kind = .helper_binary,
                .source_path = helper.source_path,
                .receipt_name = "native-trigger-helper.bin",
                .expected_sha256 = helper.sha256,
            });
        }
    }
    try sources.append(scratch, .{
        .kind = .progress,
        .source_path = native_recovery.progress_path,
        .receipt_name = "progress.json",
        .document_sha256 = progress.digest_sha256,
    });
    try sources.append(scratch, .{
        .kind = .managed_state,
        .source_path = native_recovery.managed_state_path,
        .receipt_name = "managed-state.json",
        .document_sha256 = managed.digest_sha256,
    });
    try sources.append(scratch, .{
        .kind = .trigger_events,
        .source_path = native_recovery.trigger_events_path,
        .receipt_name = "trigger-events.json",
        .document_sha256 = trigger_events.digest_sha256,
    });
    try sources.append(scratch, .{
        .kind = .active_script,
        .source_path = lifecycle_script_record_path,
        .receipt_name = "active-script.json",
        .required = false,
    });
    try sources.append(scratch, .{
        .kind = .root_mutation_journal,
        .source_path = root_mutation.journal_path,
        .receipt_name = "root-mutation-journal.json",
        .required = false,
    });
    try sources.append(scratch, .{
        .kind = .root_mutation_progress,
        .source_path = root_mutation.progress_path,
        .receipt_name = "root-mutation-progress.log",
        .required = false,
    });
    for (progress.records) |entry| {
        if (entry.action.kind != .script and
            entry.action.kind != .compensation and
            entry.action.kind != .trigger)
            continue;
        var already_added = false;
        for (sources.items) |source| {
            if (source.action) |action| {
                if (std.meta.eql(action, entry.action)) {
                    already_added = true;
                    break;
                }
            }
        }
        if (already_added) continue;
        var path_buffer: [128]u8 = undefined;
        const source_path = try native_recovery.scriptOutcomePath(
            entry.action,
            &path_buffer,
        );
        var outcome = (try native_recovery.readScriptOutcome(
            scratch,
            root,
            entry.action,
        )) orelse continue;
        defer outcome.deinit();
        if (!std.mem.eql(
            u8,
            &outcome.outcome.intent_sha256,
            &intent.digest_sha256,
        )) return error.InvalidScriptOutcome;
        const receipt_name = try std.fmt.allocPrint(
            scratch,
            "scripts/{s}-{}-{}-{}.json",
            .{
                @tagName(entry.action.kind),
                entry.action.program_step,
                entry.action.substep,
                entry.action.ordinal,
            },
        );
        try sources.append(scratch, .{
            .kind = .script_outcome,
            .source_path = try scratch.dupe(u8, source_path),
            .receipt_name = receipt_name,
            .document_sha256 = outcome.outcome.digest_sha256,
            .action = entry.action,
        });
    }
    return native_provenance.retainEvidence(
        allocator,
        root,
        intent.attempt_id,
        sources.items,
    );
}

fn nativeFinalClosureDigest(
    snapshot: package_database.Snapshot,
) [32]u8 {
    const Closure = struct {
        status: package_database.FileEntry,
        arch: ?package_database.FileEntry,
        triggers_file: ?package_database.FileEntry,
        triggers_unincorp: ?package_database.FileEntry,
        triggers_named: []const package_database.NamedTriggerEntry,
    };
    var buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer.Hashing(Sha256) = .init(&buffer);
    sink.writer.writeAll("debz-native-package-database-closure-v1\x00") catch
        unreachable;
    std.json.Stringify.value(
        Closure{
            .status = snapshot.status,
            .arch = snapshot.arch,
            .triggers_file = snapshot.triggers_file,
            .triggers_unincorp = snapshot.triggers_unincorp,
            .triggers_named = snapshot.triggers_named,
        },
        .{ .whitespace = .minified },
        &sink.writer,
    ) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn publishNativeRecoveryRequiredProvenance(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
    program_sha256: [32]u8,
    detail: []const u8,
) !void {
    const runtime = execution.recovery orelse return;
    var intent = try native_recovery.readIntent(allocator, root);
    defer intent.deinit();
    var progress = try native_recovery.readProgress(allocator, root);
    defer progress.deinit();
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(
        &captured.snapshot,
        intent.intent.architecture,
    );
    const final_generation = try package_database.generation(
        allocator,
        captured.snapshot,
    );
    var script_hash = Sha256.init(.{});
    script_hash.update("debz-native-script-outcomes-v1\x00");
    var recovered_phases: u64 = 0;
    for (progress.document.records) |entry| {
        if ((entry.action.kind == .script or entry.action.kind == .trigger or
            entry.action.kind == .compensation) and
            entry.stage == .outcome)
        {
            script_hash.update(&entry.digest_sha256);
            if (entry.evidence_sha256) |digest| script_hash.update(&digest);
        }
        if (entry.result == .recovered) recovered_phases += 1;
    }
    var trigger_events = try native_recovery.readTriggerEvents(
        allocator,
        root,
    );
    defer trigger_events.deinit();
    if (!std.mem.eql(
        u8,
        &trigger_events.document.intent_sha256,
        &runtime.intent_sha256,
    )) return error.InvalidTriggerEvents;
    var managed = try native_recovery.readManagedState(allocator, root);
    defer managed.deinit();
    if (!std.mem.eql(
        u8,
        &managed.document.intent_sha256,
        &runtime.intent_sha256,
    )) return error.InvalidManagedState;
    var retained = try retainNativeEvidence(
        allocator,
        root,
        attempt,
        intent.intent,
        progress.document,
        managed.document,
        trigger_events.document,
    );
    defer retained.deinit();
    const record = attempt.record();
    var provenance: native_provenance.Document = .{
        .attempt_id = native_provenance.hexDigest(record.attempt_id),
        .install_root = record.install_root,
        .root_identity_sha256 = native_provenance.hexDigest(
            record.root_identity_sha256,
        ),
        .root_inode = (try root.metadataOfRoot()).inode,
        .operation = record.operation,
        .request_sha256 = native_provenance.hexDigest(record.request_sha256),
        .policy_sha256 = native_provenance.hexDigest(record.policy_sha256),
        .authorization_sha256 = native_provenance.hexDigest(
            record.authorization_sha256 orelse
                return error.InvalidRecoveryIntent,
        ),
        .program_sha256 = native_provenance.hexDigest(program_sha256),
        .exact_lock_sha256 = if (record.exact_lock) |lock|
            native_provenance.hexDigest(lock.digest_sha256)
        else
            return error.InvalidRecoveryIntent,
        .artifact_evidence_sha256 = native_provenance.hexDigest(
            record.artifact_evidence_sha256 orelse
                return error.InvalidRecoveryIntent,
        ),
        .initial_database_generation_sha256 = intent.intent.database_generation_sha256,
        .execution_intent_sha256 = runtime.intent_sha256,
        .progress_head_sha256 = progress.document.head_sha256,
        .progress_record_count = progress.document.records.len,
        .script_outcomes_sha256 = native_provenance.hexDigest(
            script_hash.finalResult(),
        ),
        .trigger_evidence_sha256 = trigger_events.document.digest_sha256,
        .final_database_generation_sha256 = native_provenance.hexDigest(
            final_generation.sha256,
        ),
        .final_state_sha256 = native_provenance.hexDigest(
            nativeFinalClosureDigest(captured.snapshot),
        ),
        .recovered_phase_count = recovered_phases,
        .evidence_root = retained.root_path,
        .evidence_files = retained.files,
        .evidence_files_sha256 = retained.digest_sha256,
        .final_state_kind = .package_database_closure_v1,
        .outcome = .recovery_required,
        .detail = detail,
        .digest_sha256 = @splat('0'),
    };
    native_provenance.seal(&provenance);
    try native_provenance.publish(allocator, root, provenance);
}

fn lifecycleScriptOwner(
    authorization: native_authorization.Authorization,
    target: native_program.PackageIdentity,
    source: native_program.ScriptSource,
) !native_program.PackageIdentity {
    return switch (source) {
        .new_package => target,
        .installed_package => .{
            .name = target.name,
            .version = (authorization.findAction(
                target.name,
                target.architecture,
            ) orelse return error.InvalidLifecycleProgram).prior_version orelse
                return error.InvalidLifecycleProgram,
            .architecture = target.architecture,
        },
    };
}

fn runLifecycleScript(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    attempt: *root_operation.Attempt,
    sequence: u32,
    target: native_program.PackageIdentity,
    bound_owner: ?native_program.PackageIdentity,
    kind: maintainer_script.Kind,
    source: native_program.ScriptSource,
    script_sha256: native_program.Digest,
    arguments: []const []const u8,
    inject_unknown: bool,
) !LifecycleScriptOutcome {
    const package = bound_owner orelse
        try lifecycleScriptOwner(authorization.*, target, source);
    const recovery_action = nativeAction(
        if (bound_owner != null) .trigger else .script,
        sequence,
        @intCast(@intFromEnum(kind)),
        execution.script_ordinal,
    );
    execution.script_ordinal +%= 1;
    const previous_action = execution.action;
    execution.action = recovery_action;
    defer execution.action = previous_action;
    const path = try lifecycleScriptPath(
        allocator,
        root,
        program.target_architecture,
        package,
        kind,
        source,
    );
    defer allocator.free(path);
    const expected = parseHex(32, &script_sha256) orelse
        return error.InvalidLifecycleProgram;
    const observed = try rootFileSha256(allocator, root, path, 64 * 1024 * 1024);
    if (!std.mem.eql(u8, &expected, &observed))
        return error.InstalledScriptMismatch;

    if (execution.recovery) |runtime| {
        if (try native_recovery.readScriptOutcome(
            allocator,
            root,
            recovery_action,
        )) |owned_value| {
            var owned = owned_value;
            defer owned.deinit();
            if (!nativeScriptOutcomeMatches(
                owned.outcome,
                runtime.*,
                recovery_action,
                package,
                kind,
                source,
                expected,
                arguments,
            )) return error.InvalidScriptOutcome;
            const latest_record = try runtime.latest(recovery_action) orelse
                return error.InvalidRecoveryProgress;
            const managed_checkpoint_sha256 =
                try native_recovery.managedCheckpointDigestForAction(
                    allocator,
                    root,
                    runtime.intent_sha256,
                    recovery_action,
                );
            if (latest_record.stage != .completed and
                managed_checkpoint_sha256 == null)
            {
                try attempt.requireRecovery(allocator, .script);
                try publishNativeRecoveryRequiredProvenance(
                    execution,
                    allocator,
                    root,
                    attempt,
                    parseHex(32, &program.digest_sha256) orelse
                        return error.InvalidLifecycleProgram,
                    "managed_state_unresolved",
                );
                return .recovery_required;
            }
            {
                const record = latest_record;
                if (record.stage == .in_flight) {
                    try runtime.append(
                        recovery_action,
                        .outcome,
                        switch (owned.outcome.disposition) {
                            .exited => .exited,
                            else => if (!owned.outcome.spawned)
                                .not_started
                            else
                                .recovery_required,
                        },
                        owned.outcome.digest_sha256,
                    );
                    try runtime.append(
                        recovery_action,
                        .completed,
                        switch (owned.outcome.disposition) {
                            .exited => if (owned.outcome.exit_code == 0)
                                .succeeded
                            else
                                .failed,
                            else => if (!owned.outcome.spawned)
                                .not_started
                            else
                                .recovery_required,
                        },
                        managed_checkpoint_sha256 orelse
                            return error.InvalidManagedState,
                    );
                } else if (record.stage == .outcome) {
                    try runtime.append(
                        recovery_action,
                        .completed,
                        switch (owned.outcome.disposition) {
                            .exited => if (owned.outcome.exit_code == 0)
                                .succeeded
                            else
                                .failed,
                            else => if (!owned.outcome.spawned)
                                .not_started
                            else
                                .recovery_required,
                        },
                        managed_checkpoint_sha256 orelse
                            return error.InvalidManagedState,
                    );
                } else if (record.stage != .completed) {
                    return error.InvalidRecoveryProgress;
                }
            }
            const active_path = try root_fs.Path.init(
                lifecycle_script_record_path,
            );
            if (try root.entryIfExists(active_path) != null) {
                const expected_active = try lifecycleScriptRecordBytes(
                    allocator,
                    program.*,
                    sequence,
                    package,
                    kind,
                    source,
                    script_sha256,
                    arguments,
                    "in_flight",
                    null,
                );
                defer allocator.free(expected_active);
                const observed_active = try root.readFileAlloc(
                    allocator,
                    active_path,
                    64 * 1024,
                );
                defer allocator.free(observed_active);
                if (std.mem.eql(u8, observed_active, expected_active)) {
                    const disposition = nativeScriptDisposition(owned.outcome);
                    const terminal_record = switch (disposition) {
                        .exited => |code| try lifecycleScriptRecordBytes(
                            allocator,
                            program.*,
                            sequence,
                            package,
                            kind,
                            source,
                            script_sha256,
                            arguments,
                            "exited",
                            code,
                        ),
                        .not_started => try lifecycleScriptRecordBytes(
                            allocator,
                            program.*,
                            sequence,
                            package,
                            kind,
                            source,
                            script_sha256,
                            arguments,
                            "not_started",
                            null,
                        ),
                        .recovery_required => {
                            try attempt.requireRecovery(allocator, .script);
                            return .recovery_required;
                        },
                    };
                    defer allocator.free(terminal_record);
                    try publishLifecycleScriptRecord(
                        root,
                        terminal_record,
                        .replace,
                    );
                    try clearLifecycleScriptRecord(
                        allocator,
                        root,
                        terminal_record,
                    );
                }
            }
            return nativeScriptDisposition(owned.outcome);
        }
        if (try runtime.latest(recovery_action)) |record| {
            if (record.stage == .in_flight or record.stage == .outcome or
                record.stage == .completed)
            {
                try attempt.requireRecovery(allocator, .script);
                try publishNativeRecoveryRequiredProvenance(
                    execution,
                    allocator,
                    root,
                    attempt,
                    parseHex(32, &program.digest_sha256) orelse
                        return error.InvalidLifecycleProgram,
                    "script_outcome_unknown",
                );
                return .recovery_required;
            }
        } else {
            try runtime.append(recovery_action, .prepared, .none, null);
            runtime.crash.hit(.after_script_prepared);
        }
    }

    var helper_mount: ?maintainer_script.HelperMount = null;
    defer if (helper_mount) |*mount| mount.deinit();
    if (execution.recovery) |runtime| {
        if (runtime.helper_binding) |helper| {
            helper_mount = native_helper.bind(allocator, root, helper) catch |err| {
                if (attempt.record().mutation_started)
                    try attempt.requireRecovery(allocator, .script);
                return err;
            };
        }
    }
    const in_flight = try lifecycleScriptRecordBytes(
        allocator,
        program.*,
        sequence,
        package,
        kind,
        source,
        script_sha256,
        arguments,
        "in_flight",
        null,
    );
    defer allocator.free(in_flight);
    if (execution.recovery) |runtime|
        try runtime.append(recovery_action, .in_flight, .none, null);
    publishLifecycleScriptRecord(
        root,
        in_flight,
        .fail_if_exists,
    ) catch {
        try attempt.requireRecovery(allocator, .script);
        return .recovery_required;
    };
    try attempt.advance(allocator, .{
        .state = if (attempt.record().state == .recovering)
            .recovering
        else
            .mutating,
        .phase = .script,
    });

    var launcher: maintainer_script.SystemLauncher = .{};
    var report = try maintainer_script.run(allocator, .{
        .root = install_root,
        .identity = .{
            .package = package.name,
            .version = package.version,
            .architecture = package.architecture,
            .kind = kind,
            .script_path = path,
            .script_sha256 = expected,
        },
        .arguments = arguments,
        .policy = lifecycleScriptPolicy(),
        .helper_mount = if (helper_mount) |*mount| mount else null,
    }, .{ .launcher = launcher.interface() });
    defer report.deinit();

    if (execution.recovery) |runtime| {
        runtime.crash.hit(.after_script_return_before_outcome);
        if (kind == .postrm and source == .installed_package)
            runtime.crash.hit(.after_upgrade_postrm_return_before_outcome);
    }

    if (inject_unknown) {
        try attempt.requireRecovery(allocator, .script);
        return .recovery_required;
    }
    var native_outcome: ?native_recovery.ScriptOutcome = null;
    var managed_checkpoint_sha256: ?native_recovery.Digest = null;
    if (execution.recovery) |runtime| {
        native_outcome = try persistNativeScriptOutcome(
            allocator,
            runtime,
            recovery_action,
            package,
            kind,
            source,
            expected,
            arguments,
            report,
        );
        managed_checkpoint_sha256 = try checkpointManagedPaths(
            allocator,
            runtime,
            recovery_action,
            execution.phase_steps orelse &.{},
            execution.phase_steps != null,
        );
        try runtime.append(
            recovery_action,
            .outcome,
            switch (report.outcome) {
                .exited => .exited,
                else => if (report.outcome.spawned())
                    .recovery_required
                else
                    .not_started,
            },
            native_outcome.?.digest_sha256,
        );
        runtime.crash.hit(.after_script_outcome);
        switch (report.outcome) {
            .exited => |code| if (code != 0)
                runtime.crash.hit(.after_failure_outcome),
            else => runtime.crash.hit(.after_failure_outcome),
        }
        if (recovery_action.kind == .trigger)
            runtime.crash.hit(.after_trigger_outcome);
    }
    const code = switch (report.outcome) {
        .exited => |value| value,
        else => if (!report.outcome.spawned())
            255
        else {
            try attempt.requireRecovery(allocator, .script);
            return .recovery_required;
        },
    };
    const observed_record = try lifecycleScriptRecordBytes(
        allocator,
        program.*,
        sequence,
        package,
        kind,
        source,
        script_sha256,
        arguments,
        "exited",
        code,
    );
    defer allocator.free(observed_record);
    publishLifecycleScriptRecord(
        root,
        observed_record,
        .replace,
    ) catch {
        try attempt.requireRecovery(allocator, .script);
        return .recovery_required;
    };
    try attempt.advance(allocator, .{
        .state = if (attempt.record().state == .recovering)
            .recovering
        else
            .mutating,
        .phase = .script,
    });
    clearLifecycleScriptRecord(
        allocator,
        root,
        observed_record,
    ) catch {
        try attempt.requireRecovery(allocator, .script);
        return .recovery_required;
    };
    if (execution.recovery) |runtime|
        try runtime.append(
            recovery_action,
            .completed,
            if (code == 0) .succeeded else .failed,
            managed_checkpoint_sha256 orelse
                if (native_outcome) |value| value.digest_sha256 else null,
        );
    if (!report.outcome.spawned()) return .not_started;
    return .{ .exited = code };
}

const PostUnpackScript = struct {
    sequence: u32,
    call: native_program.ScriptCall,
};

fn postUnpackScript(
    program: native_program.Program,
    unpack_sequence: u32,
    package: native_program.PackageIdentity,
) ?PostUnpackScript {
    for (program.steps) |step| {
        if (step.sequence <= unpack_sequence) continue;
        switch (step.operation) {
            .run_maintainer_script => |call| {
                if (step.phase != .unpack) return null;
                if (call.kind == .postrm and call.source == .installed_package and
                    std.mem.eql(u8, call.package.name, package.name) and
                    std.mem.eql(u8, call.package.architecture, package.architecture))
                    return .{ .sequence = step.sequence, .call = call };
            },
            .apply_conffile_decision, .record_package_state => {},
            else => if (step.phase != .unpack) return null,
        }
    }
    return null;
}

const PostUnpackHook = struct {
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    attempt: *root_operation.Attempt,
    target_step: u32,
    script: PostUnpackScript,
    inject_unknown: bool = false,
    fired: bool = false,
    unknown_outcome: bool = false,
    rollback_required: bool = false,
    failed_compensation: ?u32 = null,
};

fn postUnpackHook(
    context_ptr: ?*anyopaque,
    boundary: root_mutation.Boundary,
    index: u32,
) root_mutation.HookError!void {
    const context: *PostUnpackHook = @ptrCast(@alignCast(context_ptr.?));
    if (context.fired or boundary != .verify or index != context.target_step)
        return;
    context.fired = true;
    const primary = runLifecycleScript(
        context.execution,
        context.allocator,
        context.root,
        context.install_root,
        context.program,
        context.authorization,
        context.attempt,
        context.script.sequence,
        context.script.call.package,
        null,
        context.script.call.kind,
        context.script.call.source,
        context.script.call.script_sha256,
        context.script.call.arguments,
        context.inject_unknown,
    ) catch {
        context.attempt.requireRecovery(context.allocator, .script) catch
            return error.SimulatedCrash;
        return error.SimulatedCrash;
    };
    const code = switch (primary) {
        .exited => |value| value,
        .not_started => 255,
        .recovery_required => {
            context.unknown_outcome = true;
            return error.SimulatedCrash;
        },
    };
    if (code == 0) return;
    if (context.script.call.failure.unwind) |unwind| {
        const unwind_outcome = runLifecycleScript(
            context.execution,
            context.allocator,
            context.root,
            context.install_root,
            context.program,
            context.authorization,
            context.attempt,
            context.script.sequence,
            context.script.call.package,
            null,
            unwind.kind,
            unwind.source,
            unwind.script_sha256,
            unwind.arguments,
            false,
        ) catch {
            context.attempt.requireRecovery(context.allocator, .script) catch
                return error.SimulatedCrash;
            return error.SimulatedCrash;
        };
        const unwind_code = switch (unwind_outcome) {
            .exited => |value| value,
            .not_started => 255,
            .recovery_required => {
                context.unknown_outcome = true;
                return error.SimulatedCrash;
            },
        };
        if (unwind_code == 0 and
            context.script.call.failure.resume_after_unwind)
            return;
    }
    const rollback_after =
        context.script.call.failure.rollback_after_compensations orelse 0;
    if (rollback_after > context.script.call.failure.compensations.len)
        return error.AccessDenied;
    for (
        context.script.call.failure.compensations[0..rollback_after],
        0..,
    ) |call, compensation_index| {
        const outcome = runLifecycleScript(
            context.execution,
            context.allocator,
            context.root,
            context.install_root,
            context.program,
            context.authorization,
            context.attempt,
            context.script.sequence,
            context.script.call.package,
            null,
            call.kind,
            call.source,
            call.script_sha256,
            call.arguments,
            false,
        ) catch {
            context.attempt.requireRecovery(context.allocator, .script) catch
                return error.SimulatedCrash;
            return error.SimulatedCrash;
        };
        const compensation_code = switch (outcome) {
            .exited => |value| value,
            .not_started => 255,
            .recovery_required => {
                context.unknown_outcome = true;
                return error.SimulatedCrash;
            },
        };
        if (compensation_code != 0) {
            context.failed_compensation = @intCast(compensation_index);
            break;
        }
    }
    context.rollback_required = true;
    return error.AccessDenied;
}

fn lifecycleMaterializationFailure(
    result: MaterializationResult,
) ?LifecycleResult {
    return switch (result.outcome) {
        .applied => null,
        .rolled_back => .{ .outcome = .script_failed, .detail = result.detail },
        .recovery_required => .{
            .outcome = .recovery_required,
            .detail = result.detail,
        },
        .handoff => .{ .outcome = .handoff, .detail = result.detail },
        .refused => .{ .outcome = .refused, .detail = result.detail },
    };
}

fn restoreLifecycleStatusOld(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    install_root: []const u8,
    program: *const native_program.Program,
    authorization: *const native_authorization.Authorization,
    locks: root_operation.LockBackend,
    attempt: *root_operation.Attempt,
    operation: product_api.Operation,
    policy: transaction_executor.ConffilePolicy,
    initial_status: []const u8,
) !MaterializationResult {
    var digest: [32]u8 = undefined;
    Sha256.hash(initial_status, &digest, .{});
    const path = package_database.database_directory ++ "/" ++
        package_database.status_old_path;
    const current = try root.entryIfExists(try root_fs.Path.init(path));
    const intent = [_]root_mutation.Intent{.{ .file = .{
        .path = path,
        .bytes = initial_status,
        .mode = if (current) |entry| entry.mode else 0o644,
        .uid = if (current) |entry| entry.uid else 0,
        .gid = if (current) |entry| entry.gid else 0,
        .overwrite = if (current == null) .require_absent else .replace,
        .expected_sha256 = digest,
    } }};
    return lifecycleAuxiliary(
        execution,
        allocator,
        root,
        install_root,
        program,
        authorization,
        locks,
        attempt,
        operation,
        policy,
        &intent,
        "restore-status-old",
    );
}

fn finishLifecycleAttempt(
    execution: *ExecutionState,
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
    program_sha256: [32]u8,
    succeeded: bool,
) !void {
    const runtime = execution.recovery orelse {
        try attempt.advance(allocator, .{
            .state = .verifying,
            .phase = .verification,
        });
        try attempt.complete(
            allocator,
            if (succeeded) .succeeded else .failed_after_mutation,
        );
        try attempt.publishProvenance(allocator, program_sha256);
        try attempt.clear();
        return;
    };
    const terminal_action = nativeAction(
        .provenance,
        std.math.maxInt(u32),
        0,
        0,
    );
    var progress = try native_recovery.readProgress(allocator, root);
    defer progress.deinit();
    var terminal_result: native_recovery.Result = if (succeeded)
        if (runtime.recovering) .recovered else .succeeded
    else
        .failed;
    if (native_recovery.latest(progress.document, terminal_action)) |record| {
        if (record.stage != .terminal) return error.InvalidRecoveryProgress;
        terminal_result = record.result;
    } else {
        progress.deinit();
        try runtime.append(
            terminal_action,
            .terminal,
            terminal_result,
            null,
        );
        progress = try native_recovery.readProgress(allocator, root);
    }

    var record = attempt.record();
    if (!runtime.caller_owned and record.state != .completed) {
        if (record.state != .recovering) try attempt.advance(allocator, .{
            .state = .verifying,
            .phase = .verification,
        });
        try attempt.complete(allocator, switch (terminal_result) {
            .succeeded => .succeeded,
            .recovered => .recovered,
            .failed => .failed_after_mutation,
            else => return error.InvalidRecoveryProgress,
        });
        record = attempt.record();
    }

    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(
        &captured.snapshot,
        record.target_architecture,
    );
    const final_generation = try package_database.generation(
        allocator,
        captured.snapshot,
    );

    var script_hash = Sha256.init(.{});
    script_hash.update("debz-native-script-outcomes-v1\x00");
    var recovered_phases: u64 = 0;
    for (progress.document.records) |entry| {
        if ((entry.action.kind == .script or entry.action.kind == .trigger or
            entry.action.kind == .compensation) and
            entry.stage == .outcome)
        {
            script_hash.update(&entry.digest_sha256);
            if (entry.evidence_sha256) |digest| script_hash.update(&digest);
        }
        if (entry.result == .recovered) recovered_phases += 1;
    }
    const script_outcomes_sha256 = script_hash.finalResult();
    var trigger_events = try native_recovery.readTriggerEvents(
        allocator,
        root,
    );
    defer trigger_events.deinit();
    if (!std.mem.eql(
        u8,
        &trigger_events.document.intent_sha256,
        &runtime.intent_sha256,
    )) return error.InvalidTriggerEvents;
    var owned_intent = try native_recovery.readIntent(allocator, root);
    defer owned_intent.deinit();
    if (!std.mem.eql(
        u8,
        &owned_intent.intent.digest_sha256,
        &runtime.intent_sha256,
    )) return error.InvalidRecoveryIntent;
    var managed = try native_recovery.readManagedState(allocator, root);
    defer managed.deinit();
    if (!std.mem.eql(
        u8,
        &managed.document.intent_sha256,
        &runtime.intent_sha256,
    ) or managed.document.transient != null)
        return error.InvalidManagedState;
    var retained = try retainNativeEvidence(
        allocator,
        root,
        attempt,
        owned_intent.intent,
        progress.document,
        managed.document,
        trigger_events.document,
    );
    defer retained.deinit();
    var provenance: native_provenance.Document = .{
        .attempt_id = native_provenance.hexDigest(record.attempt_id),
        .install_root = record.install_root,
        .root_identity_sha256 = native_provenance.hexDigest(
            record.root_identity_sha256,
        ),
        .root_inode = (try root.metadataOfRoot()).inode,
        .operation = record.operation,
        .request_sha256 = native_provenance.hexDigest(record.request_sha256),
        .policy_sha256 = native_provenance.hexDigest(record.policy_sha256),
        .authorization_sha256 = native_provenance.hexDigest(
            record.authorization_sha256 orelse
                return error.InvalidRecoveryIntent,
        ),
        .program_sha256 = native_provenance.hexDigest(program_sha256),
        .exact_lock_sha256 = if (record.exact_lock) |lock|
            native_provenance.hexDigest(lock.digest_sha256)
        else
            return error.InvalidRecoveryIntent,
        .artifact_evidence_sha256 = native_provenance.hexDigest(
            record.artifact_evidence_sha256 orelse
                return error.InvalidRecoveryIntent,
        ),
        .initial_database_generation_sha256 = owned_intent.intent.database_generation_sha256,
        .execution_intent_sha256 = runtime.intent_sha256,
        .progress_head_sha256 = progress.document.head_sha256,
        .progress_record_count = progress.document.records.len,
        .script_outcomes_sha256 = native_provenance.hexDigest(
            script_outcomes_sha256,
        ),
        .trigger_evidence_sha256 = trigger_events.document.digest_sha256,
        .final_database_generation_sha256 = native_provenance.hexDigest(
            final_generation.sha256,
        ),
        .final_state_sha256 = native_provenance.hexDigest(
            nativeFinalClosureDigest(captured.snapshot),
        ),
        .recovered_phase_count = recovered_phases,
        .evidence_root = retained.root_path,
        .evidence_files = retained.files,
        .evidence_files_sha256 = retained.digest_sha256,
        .final_state_kind = .package_database_closure_v1,
        .outcome = switch (terminal_result) {
            .succeeded => .succeeded,
            .recovered => .succeeded,
            .failed => .failed,
            else => return error.InvalidRecoveryProgress,
        },
        .detail = switch (terminal_result) {
            .succeeded => "completed",
            .recovered => "recovered",
            .failed => "failed",
            else => unreachable,
        },
        .digest_sha256 = @splat('0'),
    };
    native_provenance.seal(&provenance);
    const provenance_preexisting = if (try native_provenance.read(
        allocator,
        root,
    )) |owned_value| block: {
        var owned = owned_value;
        defer owned.deinit();
        break :block std.mem.eql(
            u8,
            &owned.document.attempt_id,
            &provenance.attempt_id,
        );
    } else false;
    try native_provenance.publish(allocator, root, provenance);
    if (runtime.caller_owned) {
        runtime.crash.hit(.after_provenance);
        return;
    }

    var statement = try root_operation_completion.create(allocator, .{
        .record = record,
        .transaction_provenance = .{
            .status = if (runtime.recovering and !provenance_preexisting)
                .recovered
            else
                .already_present,
            .schema = native_provenance.schema_id,
            .document_sha256 = parseHex(
                32,
                &provenance.digest_sha256,
            ) orelse return error.InvalidRecoveryProvenance,
            .detail = "native transaction provenance",
        },
        .journal = .{
            .status = .absent,
            .detail = "native phase journals cleared after durable completion",
        },
        .discharge = .{
            .surface = .package_transaction,
            .operation = switch (record.operation) {
                .package_transaction => |value| @tagName(value),
                .repository_bootstrap => return error.InvalidRecoveryIntent,
            },
            .request_sha256 = record.request_sha256,
        },
    });
    defer statement.deinit();
    const completion_store: root_operation_completion.Store = .init(root);
    try completion_store.publish(allocator, statement.document);
    if (record.provenance == .pending) {
        try attempt.publishProvenance(
            allocator,
            root_operation.provenanceDigest(record, .{
                .outcome = record.outcome,
                .document_sha256 = statement.document.digest_sha256,
                .journal_archived = false,
            }),
        );
    }
    runtime.crash.hit(.after_provenance);
    try attempt.clear();
    runtime.crash.hit(.after_active_clear);
    try cleanupNativeExecutionEvidence(allocator, root, owned_intent.intent, progress.document);
}

fn cleanupNativeExecutionEvidence(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent: native_recovery.Intent,
    progress: native_recovery.ProgressDocument,
) !void {
    for (progress.records) |entry| {
        if (entry.action.kind != .script and
            entry.action.kind != .compensation and
            entry.action.kind != .trigger)
            continue;
        var path_buffer: [128]u8 = undefined;
        const path = try native_recovery.scriptOutcomePath(
            entry.action,
            &path_buffer,
        );
        root.removeFile(try root_fs.Path.init(path)) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
    try native_recovery.cleanup(allocator, root, intent);
}

fn lifecyclePackageWant(
    action: ?native_authorization.Action,
    hold: bool,
) package_database.Want {
    // A transaction may install one package and remove another. Trigger-only
    // participants have no package action and retain their selection hold.
    return switch (if (action) |value| value.kind else solver.ActionKind.install) {
        .remove => .deinstall,
        .purge => .purge,
        else => if (hold) .hold else .install,
    };
}

fn lifecycleDatabaseMatchesProgram(
    program: native_program.Program,
    generation: package_database.Generation,
    package_count: usize,
) bool {
    const expected = parseHex(
        32,
        &program.installed_database.generation_sha256,
    ) orelse return false;
    return std.mem.eql(u8, &expected, &generation.sha256) and
        program.installed_database.package_count == package_count;
}

fn lifecycleFinalClosureMatches(
    expected_state: []const native_authorization.FinalPackage,
    database: package_database.Database,
) bool {
    if (database.model.packages.len != expected_state.len)
        return false;
    for (expected_state) |expected| {
        const record = database.model.find(
            expected.name,
            expected.architecture,
        ) orelse return false;
        if (!lifecycleFinalPackageMatches(expected, record.*)) return false;
    }
    return true;
}

fn lifecycleFinalPackageMatches(
    expected: native_authorization.FinalPackage,
    record: package_database.PackageRecord,
) bool {
    if (!std.mem.eql(u8, record.version, expected.version) or
        record.status.error_state != .ok)
        return false;
    const state_matches = switch (expected.state) {
        .installed => record.status.current == .installed,
        .config_files => record.status.current == .config_files,
        .triggers_pending => record.status.current == .triggers_pending,
        .triggers_awaited => record.status.current == .triggers_awaited,
    };
    if (!state_matches) return false;
    if (!textSlicesEqual(
        expected.triggers_pending,
        record.triggers_pending,
    ) or
        !textSlicesEqual(
            expected.triggers_awaited,
            record.triggers_awaited,
        ))
        return false;
    return if (expected.dpkg_selection_hold)
        record.status.want == .hold
    else switch (expected.state) {
        .installed, .triggers_pending, .triggers_awaited => record.status.want == .install,
        .config_files => record.status.want == .deinstall,
    };
}

fn textSlicesEqual(left: []const []const u8, right: []const []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (!std.mem.eql(u8, a, b)) return false;
    }
    return true;
}

fn verifyLifecycleFinalClosure(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    architecture: []const u8,
    expected_state: []const native_authorization.FinalPackage,
) !bool {
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = architecture,
            .snapshot = captured.snapshot,
        },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return false,
    };
    defer database.deinit();
    return lifecycleFinalClosureMatches(expected_state, database);
}

fn recoveryBlobEntryKind(
    value: package_database.EntryKind,
) native_recovery.EntryKind {
    return switch (value) {
        .regular => .regular,
        .directory => .directory,
        .symlink => .symlink,
        .other => .other,
    };
}

fn appendRecoveryBlob(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    blobs: *std.ArrayList(native_recovery.Blob),
    kind: native_recovery.BlobKind,
    key: []const u8,
    logical_path: []const u8,
    bytes: []const u8,
    entry_kind: native_recovery.EntryKind,
    mode: u32,
) !void {
    const index = blobs.items.len;
    const path = switch (kind) {
        .request => try std.fmt.allocPrint(
            allocator,
            "{s}/native-lifecycle.json",
            .{native_recovery.request_directory},
        ),
        .artifact => try std.fmt.allocPrint(
            allocator,
            "{s}/{d:0>5}.deb",
            .{ native_recovery.artifact_directory, index },
        ),
        .database => try std.fmt.allocPrint(
            allocator,
            "{s}/{d:0>5}.blob",
            .{ native_recovery.database_directory, index },
        ),
        .installed_script => try std.fmt.allocPrint(
            allocator,
            "{s}/{d:0>5}.script",
            .{ native_recovery.scripts_directory, index },
        ),
    };
    var sha256: [32]u8 = undefined;
    Sha256.hash(bytes, &sha256, .{});
    const blob: native_recovery.Blob = .{
        .kind = kind,
        .key = try allocator.dupe(u8, key),
        .logical_path = try allocator.dupe(u8, logical_path),
        .storage_path = path,
        .sha256 = native_recovery.hexDigest(sha256),
        .size = bytes.len,
        .entry_kind = entry_kind,
        .mode = mode,
    };
    try native_recovery.publishBlob(allocator, root, path, bytes, sha256);
    try blobs.append(allocator, blob);
}

fn infoBlobKind(name: []const u8) native_recovery.BlobKind {
    inline for (.{ ".preinst", ".postinst", ".prerm", ".postrm" }) |suffix|
        if (std.mem.endsWith(u8, name, suffix)) return .installed_script;
    return .database;
}

fn prepareNativeRecovery(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    external: ExternalLifecycleRequest,
    compiled: *const CompiledLifecycle,
    raw_request: []const u8,
    archive_bytes: []const []const u8,
    initial_snapshot: package_database.Snapshot,
    attempt: *root_operation.Attempt,
    production_request: ?native_execution_request.Document,
    helper_binding: ?native_helper.Binding,
) !native_recovery.Runtime {
    if (production_request) |request| {
        try native_execution_request.validateBinding(request, root, attempt, compiled.program.program);
        var decoded = try native_execution_request.decodePersisted(allocator, raw_request);
        defer decoded.deinit();
        if (!std.mem.eql(u8, &decoded.execution().digest_sha256, &request.digest_sha256))
            return error.RecoveryRequestBindingMismatch;
        try matchNativeHelperBinding(decoded.helper(), helper_binding);
    } else {
        var observed: [32]u8 = undefined;
        Sha256.hash(raw_request, &observed, .{});
        if (!std.mem.eql(u8, &native_recovery.hexDigest(observed), &compiled.program.program.request_sha256))
            return error.InvalidLifecycleProgram;
    }
    for ([_][]const u8{
        native_recovery.workspace_directory,
        native_recovery.artifact_directory,
        native_recovery.database_directory,
        native_recovery.scripts_directory,
        native_recovery.request_directory,
    }) |path| try root.createDirectoryPath(
        try root_fs.Path.init(path),
        if (builtin.os.tag == .windows)
            .default_file
        else
            .fromMode(0o700),
    );
    var namespace = try root.openDirectory(
        try root_fs.Path.init(root_operation.namespace_path),
    );
    defer namespace.close(root.io);
    var authorization_store = try native_authorization.Store.init(
        root.io,
        namespace,
        native_recovery.authorization_name,
    );
    try authorization_store.writeAtomic(
        allocator,
        compiled.authorization.authorization,
    );
    var program_store = try native_program.Store.init(
        root.io,
        namespace,
        native_recovery.program_name,
    );
    try program_store.writeAtomic(
        allocator,
        compiled.program.program,
    );

    var blobs: std.ArrayList(native_recovery.Blob) = .empty;
    try appendRecoveryBlob(
        allocator,
        root,
        &blobs,
        .request,
        "request",
        if (helper_binding != null)
            native_execution_request.helper_logical_path
        else if (production_request != null)
            native_execution_request.logical_path
        else
            "request/native-lifecycle.json",
        raw_request,
        .regular,
        0o600,
    );
    for (archive_bytes, 0..) |bytes, index| {
        const key = try std.fmt.allocPrint(allocator, "artifact:{d}", .{index});
        const logical = try std.fmt.allocPrint(allocator, "artifacts/{d}.deb", .{index});
        try appendRecoveryBlob(
            allocator,
            root,
            &blobs,
            .artifact,
            key,
            logical,
            bytes,
            .regular,
            0o600,
        );
    }
    try appendRecoveryBlob(
        allocator,
        root,
        &blobs,
        .database,
        "status",
        package_database.database_directory ++ "/" ++ package_database.status_path,
        initial_snapshot.status.bytes,
        recoveryBlobEntryKind(initial_snapshot.status.kind),
        initial_snapshot.status.mode,
    );
    const optional_files = .{
        .{ "status-old", package_database.status_old_path, initial_snapshot.status_old },
        .{ "arch", package_database.arch_path, initial_snapshot.arch },
        .{ "diversions", package_database.diversions_path, initial_snapshot.diversions },
        .{ "statoverride", package_database.statoverride_path, initial_snapshot.statoverride },
        .{ "triggers-file", package_database.triggers_file_path, initial_snapshot.triggers_file },
        .{ "triggers-unincorp", package_database.triggers_unincorp_path, initial_snapshot.triggers_unincorp },
    };
    inline for (optional_files) |entry| if (entry[2]) |file| {
        const logical = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}",
            .{ package_database.database_directory, entry[1] },
        );
        try appendRecoveryBlob(
            allocator,
            root,
            &blobs,
            .database,
            entry[0],
            logical,
            file.bytes,
            recoveryBlobEntryKind(file.kind),
            file.mode,
        );
    };
    for (initial_snapshot.info) |entry| {
        const logical = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}/{s}",
            .{
                package_database.database_directory,
                package_database.info_directory,
                entry.name,
            },
        );
        const key = try std.fmt.allocPrint(allocator, "info:{s}", .{entry.name});
        try appendRecoveryBlob(
            allocator,
            root,
            &blobs,
            infoBlobKind(entry.name),
            key,
            logical,
            entry.bytes,
            recoveryBlobEntryKind(entry.kind),
            entry.mode,
        );
    }
    for (initial_snapshot.updates) |entry| {
        const logical = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}/{s}",
            .{
                package_database.database_directory,
                package_database.updates_directory,
                entry.name,
            },
        );
        const key = try std.fmt.allocPrint(allocator, "update:{s}", .{entry.name});
        try appendRecoveryBlob(
            allocator,
            root,
            &blobs,
            .database,
            key,
            logical,
            entry.bytes,
            recoveryBlobEntryKind(entry.kind),
            entry.mode,
        );
    }
    for (initial_snapshot.triggers_named) |entry| {
        const logical = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}/{s}",
            .{
                package_database.database_directory,
                package_database.triggers_directory,
                entry.name,
            },
        );
        const key = try std.fmt.allocPrint(allocator, "trigger:{s}", .{entry.name});
        try appendRecoveryBlob(
            allocator,
            root,
            &blobs,
            .database,
            key,
            logical,
            entry.bytes,
            recoveryBlobEntryKind(entry.kind),
            entry.mode,
        );
    }

    const program = compiled.program.program;
    const authorization = compiled.authorization.authorization;
    const request_sha256 = parseHex(32, &program.request_sha256) orelse
        return error.InvalidLifecycleProgram;
    const policy_sha256 = parseHex(32, &program.executor_policy_sha256) orelse
        return error.InvalidLifecycleProgram;
    const lock_sha256 = parseHex(32, &program.exact_lock.digest_sha256) orelse
        return error.InvalidLifecycleProgram;
    const artifact_sha256 = parseHex(32, &program.artifacts_sha256) orelse
        return error.InvalidLifecycleProgram;
    const database_sha256 = parseHex(
        32,
        &program.installed_database.generation_sha256,
    ) orelse return error.InvalidLifecycleProgram;
    const trigger_sha256 = parseHex(
        32,
        &program.installed_database.trigger_state_sha256,
    ) orelse return error.InvalidLifecycleProgram;
    var packages: std.ArrayList(native_recovery.PackageSelection) = .empty;
    for (external.packages) |selection| try packages.append(allocator, .{
        .name = selection.name,
        .architecture = selection.architecture,
    });
    var ordered: std.ArrayList(native_recovery.OrderedAction) = .empty;
    if (external.ordered_actions) |actions| for (actions) |action|
        try ordered.append(allocator, .{
            .sequence = action.sequence,
            .kind = @tagName(action.kind),
            .package = action.package,
            .version = action.version,
            .architecture = action.architecture,
        });
    const staging_directory_initially_present =
        try root.entryIfExists(try root_fs.Path.init(lifecycle_tmp_ci)) != null;
    const root_metadata = try root.metadataOfRoot();
    var intent: native_recovery.Intent = .{
        .attempt_id = native_recovery.hexDigest(attempt.attemptId()),
        .install_root = external.root,
        .root_identity_sha256 = native_recovery.hexDigest(
            transaction_recovery.rootIdentity(external.root),
        ),
        .root_inode = root_metadata.inode,
        .operation = switch (external.operation) {
            .install => .install,
            .upgrade => .upgrade,
            .downgrade => .downgrade,
            .reinstall => .reinstall,
            .configure => .configure,
            .remove => .remove,
            .purge => .purge,
            .process_triggers => .process_triggers,
            .recover => unreachable,
        },
        .architecture = external.architecture,
        .policy = switch (external.policy) {
            .keep_existing => .keep_existing,
            .use_package_version => .use_package_version,
        },
        .triggers = external.triggers,
        .defer_triggers = external.defer_triggers,
        .staging_directory_initially_present = staging_directory_initially_present,
        .request_sha256 = native_recovery.hexDigest(request_sha256),
        .policy_sha256 = native_recovery.hexDigest(policy_sha256),
        .authorization_sha256 = native_recovery.hexDigest(
            authorization.digest_sha256,
        ),
        .program_sha256 = program.digest_sha256,
        .exact_lock_sha256 = native_recovery.hexDigest(lock_sha256),
        .artifact_evidence_sha256 = native_recovery.hexDigest(artifact_sha256),
        .database_generation_sha256 = native_recovery.hexDigest(database_sha256),
        .initial_trigger_state_sha256 = native_recovery.hexDigest(trigger_sha256),
        .packages = packages.items,
        .ordered_actions = ordered.items,
        .authorization_path = native_recovery.authorization_name,
        .program_path = native_recovery.program_name,
        .blobs = blobs.items,
        .digest_sha256 = @splat('0'),
    };
    native_recovery.sealIntent(&intent);
    if (production_request) |request| try native_execution_request.validateIntent(request, intent);
    try native_recovery.publishIntent(allocator, root, intent);
    try native_recovery.initializeProgress(
        allocator,
        root,
        intent.digest_sha256,
    );
    try native_recovery.initializeTriggerEvents(
        allocator,
        root,
        intent.digest_sha256,
    );
    try native_recovery.initializeManagedState(
        allocator,
        root,
        intent.digest_sha256,
    );
    return .{
        .allocator = allocator,
        .root = root,
        .intent_sha256 = intent.digest_sha256,
        .crash = .{ .selected = external.crash_at },
        .staging_directory_initially_present = staging_directory_initially_present,
        .caller_owned = production_request != null,
        .helper_binding = helper_binding,
    };
}

fn pendingNativeMutationAction(
    progress: native_recovery.ProgressDocument,
) ?native_recovery.Action {
    var index = progress.records.len;
    while (index != 0) {
        index -= 1;
        const record = progress.records[index];
        if (record.action.kind != .filesystem and
            record.action.kind != .database)
            continue;
        const newest = native_recovery.latest(
            progress,
            record.action,
        ) orelse continue;
        if (newest.sequence != record.sequence or
            newest.stage == .completed)
            continue;
        return record.action;
    }
    return null;
}

const ActiveScriptRecovery = enum {
    none,
    known_outcome,
    outcome_unknown,
};

fn activeScriptInvocationMatches(
    authorization: native_authorization.Authorization,
    active: native_trigger.ActiveScript,
    target: native_program.PackageIdentity,
    kind: maintainer_script.Kind,
    source: native_program.ScriptSource,
    script_sha256: native_program.Digest,
    arguments: []const []const u8,
) !bool {
    const owner = try lifecycleScriptOwner(authorization, target, source);
    const expected_sha256 = parseHex(32, &script_sha256) orelse
        return error.InvalidLifecycleProgram;
    return std.mem.eql(u8, active.package, owner.name) and
        std.mem.eql(u8, active.version, owner.version) and
        std.mem.eql(u8, active.architecture, owner.architecture) and
        active.kind == kind and
        std.mem.eql(u8, @tagName(active.source), @tagName(source)) and
        std.mem.eql(u8, &active.script_sha256, &expected_sha256) and
        textListEqual(active.arguments, arguments);
}

fn activeScriptAuthorized(
    program: native_program.Program,
    authorization: native_authorization.Authorization,
    active: native_trigger.ActiveScript,
    action: native_recovery.Action,
) !bool {
    const program_sha256 = parseHex(32, &program.digest_sha256) orelse
        return error.InvalidLifecycleProgram;
    if (!std.mem.eql(
        u8,
        &active.program_sha256,
        &program_sha256,
    ) or active.step != action.program_step)
        return false;
    if (action.kind == .trigger) {
        const authority = program.trigger_authority orelse return false;
        if (active.kind != .postinst or active.arguments.len != 2 or
            !std.mem.eql(u8, active.arguments[0], "triggered"))
            return false;
        const handler = for (authority.handlers) |candidate| {
            if (std.mem.eql(u8, candidate.package.name, active.package) and
                std.mem.eql(u8, candidate.package.version, active.version) and
                std.mem.eql(
                    u8,
                    candidate.package.architecture,
                    active.architecture,
                ))
                break candidate;
        } else return false;
        if (!std.mem.eql(
            u8,
            @tagName(handler.source),
            @tagName(active.source),
        )) return false;
        const expected_sha256 = parseHex(
            32,
            &handler.postinst_sha256,
        ) orelse return error.InvalidLifecycleProgram;
        if (!std.mem.eql(
            u8,
            &expected_sha256,
            &active.script_sha256,
        )) return false;
        var triggers = std.mem.splitScalar(u8, active.arguments[1], ' ');
        var count: usize = 0;
        while (triggers.next()) |trigger| {
            if (trigger.len == 0) return false;
            var allowed = false;
            for (authority.allowed_triggers) |candidate| {
                if (std.mem.eql(u8, candidate, trigger)) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) return false;
            count += 1;
        }
        return count != 0;
    }
    const step = program.step(active.step) orelse return false;
    const call = switch (step.operation) {
        .run_maintainer_script => |value| value,
        else => return false,
    };
    if (try activeScriptInvocationMatches(
        authorization,
        active,
        call.package,
        call.kind,
        call.source,
        call.script_sha256,
        call.arguments,
    )) return true;
    if (call.failure.unwind) |unwind| {
        if (try activeScriptInvocationMatches(
            authorization,
            active,
            call.package,
            unwind.kind,
            unwind.source,
            unwind.script_sha256,
            unwind.arguments,
        )) return true;
    }
    for (call.failure.compensations) |compensation| {
        if (try activeScriptInvocationMatches(
            authorization,
            active,
            call.package,
            compensation.kind,
            compensation.source,
            compensation.script_sha256,
            compensation.arguments,
        )) return true;
    }
    return false;
}

fn classifyActiveScriptBeforeMutationRecovery(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    program: native_program.Program,
    authorization: native_authorization.Authorization,
    runtime: native_recovery.Runtime,
) !ActiveScriptRecovery {
    const record_path = try root_fs.Path.init(lifecycle_script_record_path);
    if (try root.entryIfExists(record_path) == null) return .none;
    const bytes = try root.readFileAlloc(
        allocator,
        record_path,
        native_trigger.maximum_document_bytes,
    );
    defer allocator.free(bytes);
    var active = try native_trigger.decodeActiveScript(allocator, bytes);
    defer active.deinit();
    var progress = try native_recovery.readProgress(allocator, root);
    defer progress.deinit();
    if (!std.mem.eql(
        u8,
        &progress.document.intent_sha256,
        &runtime.intent_sha256,
    )) return error.InvalidRecoveryProgress;
    var selected: ?native_recovery.Record = null;
    var index = progress.document.records.len;
    while (index != 0) {
        index -= 1;
        const record = progress.document.records[index];
        if (record.action.program_step != active.script.step or
            (record.action.kind != .script and
                record.action.kind != .compensation and
                record.action.kind != .trigger))
            continue;
        const newest = native_recovery.latest(
            progress.document,
            record.action,
        ) orelse continue;
        if (newest.sequence != record.sequence) continue;
        selected = record;
        break;
    }
    const record = selected orelse return error.InvalidScriptOutcome;
    if (!try activeScriptAuthorized(
        program,
        authorization,
        active.script,
        record.action,
    )) return error.InvalidScriptOutcome;
    if (try native_recovery.readScriptOutcome(
        allocator,
        root,
        record.action,
    )) |owned_value| {
        var outcome = owned_value;
        defer outcome.deinit();
        const source: native_program.ScriptSource = switch (active.script.source) {
            .installed_package => .installed_package,
            .new_package => .new_package,
        };
        if (!nativeScriptOutcomeMatches(
            outcome.outcome,
            runtime,
            record.action,
            .{
                .name = active.script.package,
                .version = active.script.version,
                .architecture = active.script.architecture,
            },
            active.script.kind,
            source,
            active.script.script_sha256,
            active.script.arguments,
        )) return error.InvalidScriptOutcome;
        return .known_outcome;
    }
    if (record.stage != .in_flight) return error.InvalidScriptOutcome;
    return .outcome_unknown;
}

fn recoverNativeRootMutation(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
    runtime: *native_recovery.Runtime,
) !bool {
    var opened = try root_mutation.open(
        allocator,
        root,
        attempt,
        .{},
    ) orelse {
        try native_recovery.validateStableManagedState(
            allocator,
            root,
            runtime.intent_sha256,
        );
        return true;
    };
    defer opened.deinit();
    if (try native_recovery.managedStateHasTransient(
        allocator,
        root,
        runtime.intent_sha256,
    )) {
        const stage = try root_mutation.inspect(
            allocator,
            root,
            .{},
        ) orelse return error.InvalidManagedState;
        if (stage.direction() != .finish_new)
            return error.ManagedStateChanged;
    }
    var progress = try native_recovery.readProgress(allocator, root);
    defer progress.deinit();
    const action = pendingNativeMutationAction(progress.document) orelse {
        try attempt.requireRecovery(allocator, .mutation);
        return false;
    };
    const report = try root_mutation.recover(&opened);
    switch (report.outcome) {
        .applied => {
            const checkpoint_sha256 = try checkpointManagedPaths(
                allocator,
                runtime,
                action,
                opened.journal().steps,
                false,
            );
            try runtime.append(
                action,
                .completed,
                .recovered,
                checkpoint_sha256,
            );
            runtime.recovered_phase_count += 1;
            try root_mutation.clear(&opened);
            return true;
        },
        .rolled_back => {
            try native_recovery.discardTransientManagedState(
                allocator,
                root,
                runtime.intent_sha256,
            );
            try native_recovery.validateStableManagedState(
                allocator,
                root,
                runtime.intent_sha256,
            );
            try runtime.append(action, .completed, .rolled_back, null);
            try root_mutation.clear(&opened);
            return true;
        },
        .recovery_required => {
            try attempt.requireRecovery(allocator, .mutation);
            return false;
        },
    }
}

const RecoveredLifecycleInputs = struct {
    snapshot: package_database.Snapshot,
    archive_bytes: []const []const u8,
    models: []archive_application.Model,
};

fn recoveredDatabaseEntryKind(
    value: native_recovery.EntryKind,
) package_database.EntryKind {
    return switch (value) {
        .regular => .regular,
        .directory => .directory,
        .symlink => .symlink,
        .other => .other,
    };
}

fn recoveredFileEntry(
    blob: native_recovery.Blob,
    bytes: []const u8,
) package_database.FileEntry {
    return .{
        .bytes = bytes,
        .kind = recoveredDatabaseEntryKind(blob.entry_kind),
        .mode = blob.mode,
    };
}

fn artifactBlobIndex(key: []const u8) !usize {
    const prefix = "artifact:";
    if (!std.mem.startsWith(u8, key, prefix))
        return error.RecoveryRequestBindingMismatch;
    return std.fmt.parseUnsigned(usize, key[prefix.len..], 10) catch
        error.InvalidRecoveryIntent;
}

const ProductionArchives = struct {
    models: []archive_application.Model,
    bytes: []const []const u8,
};

// All allocations belong to the execution/recovery arena. Application models
// are reproduced from the exact program-bound bytes before any script runs.
fn productionArchives(
    allocator: std.mem.Allocator,
    artifacts: []const native_program.ProgramArtifact,
    bytes: []const []const u8,
) !ProductionArchives {
    if (bytes.len != artifacts.len) return error.RecoveryArtifactBindingMismatch;
    var by_digest: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty;
    defer by_digest.deinit(allocator);
    for (bytes) |archive| {
        var sha256: [32]u8 = undefined;
        Sha256.hash(archive, &sha256, .{});
        const entry = try by_digest.getOrPut(allocator, sha256);
        if (entry.found_existing) return error.RecoveryArtifactBindingMismatch;
        entry.value_ptr.* = archive;
    }
    const models = try allocator.alloc(archive_application.Model, bytes.len);
    const ordered = try allocator.alloc([]const u8, bytes.len);
    for (artifacts, 0..) |artifact, index| {
        if (artifact.index != index) return error.RecoveryArtifactBindingMismatch;
        const sha256 = native_recovery.parseDigest(artifact.sha256) orelse
            return error.RecoveryArtifactBindingMismatch;
        ordered[index] = by_digest.get(sha256) orelse return error.RecoveryArtifactBindingMismatch;
        models[index] = switch (archive_application.revalidate(
            allocator,
            ordered[index],
            .{ .local = .{
                .size = artifact.size,
                .sha256 = sha256,
                .identity = .{
                    .package = artifact.package.name,
                    .version = artifact.package.version,
                    .architecture = artifact.package.architecture,
                },
            } },
            .{},
            native_recovery.parseDigest(artifact.application_sha256) orelse
                return error.RecoveryArtifactBindingMismatch,
        )) {
            .model => |value| value,
            .diagnostic => return error.RecoveryArtifactBindingMismatch,
        };
        if (models[index].metadata.len != 0 or models[index].script(.config) != null)
            return error.InvalidExternalArchive;
    }
    return .{ .models = models, .bytes = ordered };
}

fn loadRecoveredLifecycleInputs(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent: native_recovery.Intent,
    program: native_program.Program,
    production: bool,
) !RecoveredLifecycleInputs {
    const artifacts = try allocator.alloc(?[]u8, program.artifacts.len);
    @memset(artifacts, null);
    var info: std.ArrayList(package_database.InfoEntry) = .empty;
    var updates: std.ArrayList(package_database.UpdateEntry) = .empty;
    var named: std.ArrayList(package_database.NamedTriggerEntry) = .empty;
    var snapshot: package_database.Snapshot = undefined;
    var status_seen = false;
    snapshot.status_old = null;
    snapshot.arch = null;
    snapshot.diversions = null;
    snapshot.statoverride = null;
    snapshot.triggers_file = null;
    snapshot.triggers_unincorp = null;
    for (intent.blobs) |blob| {
        const bytes = try native_recovery.verifyBlob(allocator, root, blob);
        switch (blob.kind) {
            .request => {},
            .artifact => {
                const index = try artifactBlobIndex(blob.key);
                if (index >= artifacts.len or artifacts[index] != null)
                    return error.RecoveryRequestBindingMismatch;
                artifacts[index] = bytes;
            },
            .installed_script, .database => {
                if (std.mem.eql(u8, blob.key, "status")) {
                    if (status_seen) return error.InvalidRecoveryIntent;
                    snapshot.status = recoveredFileEntry(blob, bytes);
                    status_seen = true;
                } else if (std.mem.eql(u8, blob.key, "status-old")) {
                    snapshot.status_old = recoveredFileEntry(blob, bytes);
                } else if (std.mem.eql(u8, blob.key, "arch")) {
                    snapshot.arch = recoveredFileEntry(blob, bytes);
                } else if (std.mem.eql(u8, blob.key, "diversions")) {
                    snapshot.diversions = recoveredFileEntry(blob, bytes);
                } else if (std.mem.eql(u8, blob.key, "statoverride")) {
                    snapshot.statoverride = recoveredFileEntry(blob, bytes);
                } else if (std.mem.eql(u8, blob.key, "triggers-file")) {
                    snapshot.triggers_file = recoveredFileEntry(blob, bytes);
                } else if (std.mem.eql(u8, blob.key, "triggers-unincorp")) {
                    snapshot.triggers_unincorp = recoveredFileEntry(blob, bytes);
                } else if (std.mem.startsWith(u8, blob.key, "info:")) {
                    try info.append(allocator, .{
                        .name = blob.key["info:".len..],
                        .bytes = bytes,
                        .kind = recoveredDatabaseEntryKind(blob.entry_kind),
                        .mode = blob.mode,
                    });
                } else if (std.mem.startsWith(u8, blob.key, "update:")) {
                    try updates.append(allocator, .{
                        .name = blob.key["update:".len..],
                        .bytes = bytes,
                        .kind = recoveredDatabaseEntryKind(blob.entry_kind),
                        .mode = blob.mode,
                    });
                } else if (std.mem.startsWith(u8, blob.key, "trigger:")) {
                    try named.append(allocator, .{
                        .name = blob.key["trigger:".len..],
                        .bytes = bytes,
                        .kind = recoveredDatabaseEntryKind(blob.entry_kind),
                        .mode = blob.mode,
                    });
                } else return error.InvalidRecoveryIntent;
            },
        }
    }
    if (!status_seen) return error.InvalidRecoveryIntent;
    snapshot.info = try allocator.dupe(package_database.InfoEntry, info.items);
    snapshot.updates = try allocator.dupe(package_database.UpdateEntry, updates.items);
    snapshot.triggers_named = try allocator.dupe(
        package_database.NamedTriggerEntry,
        named.items,
    );

    const archive_bytes = try allocator.alloc([]u8, artifacts.len);
    for (artifacts, 0..) |maybe_bytes, index|
        archive_bytes[index] = maybe_bytes orelse return error.InvalidRecoveryIntent;
    if (production) {
        const validated = try productionArchives(allocator, program.artifacts, archive_bytes);
        return .{ .snapshot = snapshot, .archive_bytes = validated.bytes, .models = validated.models };
    }
    const models = try allocator.alloc(archive_application.Model, artifacts.len);
    for (artifacts, 0..) |maybe_bytes, index| {
        const bytes = maybe_bytes orelse return error.InvalidRecoveryIntent;
        archive_bytes[index] = bytes;
        models[index] = switch (archive_application.prepare(
            allocator,
            bytes,
            .{ .local = .{} },
            .{},
        )) {
            .model => |value| value,
            .diagnostic => return error.InvalidExternalArchive,
        };
        if (models[index].metadata.len != 0 or
            models[index].script(.config) != null)
            return error.InvalidExternalArchive;
    }
    return .{
        .snapshot = snapshot,
        .archive_bytes = archive_bytes,
        .models = models,
    };
}

fn recoveryExternalRequest(
    allocator: std.mem.Allocator,
    request: ExternalLifecycleRequest,
    intent: native_recovery.Intent,
) !ExternalLifecycleRequest {
    const packages = try allocator.alloc(
        ExternalPackageSelection,
        intent.packages.len,
    );
    for (intent.packages, 0..) |package, index| packages[index] = .{
        .name = package.name,
        .architecture = package.architecture,
    };
    const ordered = try allocator.alloc(
        ExternalLifecycleAction,
        intent.ordered_actions.len,
    );
    for (intent.ordered_actions, 0..) |action, index| ordered[index] = .{
        .sequence = action.sequence,
        .kind = std.meta.stringToEnum(
            solver.OrderedActionKind,
            action.kind,
        ) orelse return error.InvalidRecoveryIntent,
        .package = action.package,
        .version = action.version,
        .architecture = action.architecture,
    };
    return .{
        .root = intent.install_root,
        .architecture = intent.architecture,
        .archives = &.{},
        .operation = switch (intent.operation) {
            .install => .install,
            .upgrade => .upgrade,
            .downgrade => .downgrade,
            .reinstall => .reinstall,
            .configure => .configure,
            .remove => .remove,
            .purge => .purge,
            .process_triggers => .process_triggers,
        },
        .report = request.report,
        .policy = switch (intent.policy) {
            .keep_existing => .keep_existing,
            .use_package_version => .use_package_version,
        },
        .packages = packages,
        .ordered_actions = if (ordered.len == 0) null else ordered,
        .triggers = intent.triggers,
        .defer_triggers = intent.defer_triggers,
        .recovery = true,
        .crash_at = request.crash_at,
    };
}

fn validatePersistedLifecycleRequest(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    intent: native_recovery.Intent,
) !void {
    var request_blob: ?native_recovery.Blob = null;
    var artifact_count: usize = 0;
    for (intent.blobs) |blob| switch (blob.kind) {
        .request => {
            if (request_blob != null or
                !std.mem.eql(u8, blob.key, "request"))
                return error.InvalidRecoveryIntent;
            request_blob = blob;
        },
        .artifact => artifact_count += 1,
        .installed_script, .database => {},
    };
    const blob = request_blob orelse return error.InvalidRecoveryIntent;
    if (!std.mem.eql(u8, &blob.sha256, &intent.request_sha256))
        return error.InvalidRecoveryIntent;
    const bytes = try native_recovery.verifyBlob(allocator, root, blob);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(
        ExternalLifecycleRequest,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
    );
    defer parsed.deinit();
    const request = parsed.value;
    const expected_policy: ExternalConffilePolicy = switch (intent.policy) {
        .keep_existing => .keep_existing,
        .use_package_version => .use_package_version,
    };
    const operation_matches = switch (intent.operation) {
        .install => request.operation == .install,
        .upgrade => request.operation == .upgrade,
        .downgrade => request.operation == .downgrade,
        .reinstall => request.operation == .reinstall,
        .configure => request.operation == .configure,
        .remove => request.operation == .remove,
        .purge => request.operation == .purge,
        .process_triggers => request.operation == .process_triggers,
    };
    if (!operation_matches or
        !std.mem.eql(u8, request.root, intent.install_root) or
        !std.mem.eql(u8, request.architecture, intent.architecture) or
        request.archives.len != artifact_count or
        request.policy != expected_policy or
        request.triggers != intent.triggers or
        request.defer_triggers != intent.defer_triggers or
        !request.recovery or request.packages.len != intent.packages.len)
        return error.RecoveryRequestBindingMismatch;
    for (request.packages, intent.packages) |left, right| {
        if (!std.mem.eql(u8, left.name, right.name) or
            !std.mem.eql(u8, left.architecture, right.architecture))
            return error.RecoveryRequestBindingMismatch;
    }
    const ordered = request.ordered_actions orelse &.{};
    if (ordered.len != intent.ordered_actions.len)
        return error.RecoveryRequestBindingMismatch;
    for (ordered, intent.ordered_actions) |left, right| {
        if (left.sequence != right.sequence or
            !std.mem.eql(u8, @tagName(left.kind), right.kind) or
            !std.mem.eql(u8, left.package, right.package) or
            !std.mem.eql(u8, left.version, right.version) or
            !std.mem.eql(u8, left.architecture, right.architecture))
            return error.RecoveryRequestBindingMismatch;
    }
}

fn rootOperationEvidenceFromRecord(
    record: root_operation.Record,
) root_operation.Evidence {
    return .{
        .authorization_sha256 = record.authorization_sha256,
        .program_sha256 = record.program_sha256,
        .plan_sha256 = record.plan_sha256,
        .exact_lock = record.exact_lock,
        .database_generation_sha256 = record.database_generation_sha256,
        .artifact_evidence_sha256 = record.artifact_evidence_sha256,
    };
}

fn orphanNativeEvidenceDetail(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
) !?[]const u8 {
    const script_path = try root_fs.Path.init(lifecycle_script_record_path);
    if (try root.entryIfExists(script_path) != null) {
        const bytes = try root.readFileAlloc(
            allocator,
            script_path,
            native_trigger.maximum_document_bytes,
        );
        defer allocator.free(bytes);
        var active = native_trigger.decodeActiveScript(
            allocator,
            bytes,
        ) catch return "script_evidence_invalid";
        defer active.deinit();
        return "script_outcome_unknown";
    }
    if (try root.entryIfExists(
        try root_fs.Path.init(root_mutation.journal_path),
    ) != null or try root.entryIfExists(
        try root_fs.Path.init(root_mutation.progress_path),
    ) != null) return "mutation_evidence_unresolved";
    if (try root.entryIfExists(
        try root_fs.Path.init(native_trigger.authority_path),
    ) != null) return "trigger_evidence_unresolved";

    var namespace = root.pinDirectory(
        try root_fs.Path.init(root_operation.namespace_path),
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer namespace.close();
    var observed = try namespace.observeAlloc(
        allocator,
        native_recovery.maximum_records,
        64 * 1024 * 1024,
    );
    defer observed.deinit();
    for (observed.members) |member| {
        const name = member.name;
        if (std.mem.eql(u8, name, "native-recovery-v1") or
            std.mem.eql(u8, name, native_recovery.authorization_name) or
            std.mem.eql(u8, name, native_recovery.program_name) or
            std.mem.eql(u8, name, "native-execution-progress-v1.log") or
            std.mem.eql(u8, name, "native-managed-state-v1.json") or
            std.mem.eql(u8, name, "native-trigger-events-v1.json") or
            std.mem.startsWith(
                u8,
                name,
                native_recovery.script_outcome_prefix,
            ) or std.mem.startsWith(u8, name, ".debz-native-"))
            return "native_recovery_evidence_unresolved";
    }
    return null;
}

fn recoverWithoutNativeIntent(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    request: ExternalLifecycleRequest,
    locks: root_operation.LockBackend,
) !LifecycleResult {
    if (try native_provenance.read(allocator, root)) |prior_value| {
        var prior = prior_value;
        defer prior.deinit();
        if (!std.mem.eql(
            u8,
            prior.document.install_root,
            request.root,
        ) or (try root.metadataOfRoot()).inode != prior.document.root_inode)
            return error.RecoveryRootIdentityMismatch;
    }
    var coordinator = try root_operation.Coordinator.open(
        root.io,
        root,
        request.root,
        locks,
    );
    if (try coordinator.inspect(allocator)) |owned_value| {
        var observed = owned_value;
        defer observed.deinit();
        const record = observed.record;
        var attempt = try coordinator.acquire(allocator, .{
            .intent = .recovery,
            .existing = .fail,
            .backend = record.backend,
            .operation = record.operation,
            .request_sha256 = record.request_sha256,
            .policy_sha256 = record.policy_sha256,
            .evidence = rootOperationEvidenceFromRecord(record),
            .target_architecture = record.target_architecture,
            .foreign_architectures = record.foreign_architectures,
            .adopt_settled_for_acknowledgment = true,
        });
        defer attempt.release();
        if (!std.mem.eql(
            u8,
            &attempt.attemptId(),
            &record.attempt_id,
        )) return error.ActiveAttemptChanged;
        const script_path = try root_fs.Path.init(lifecycle_script_record_path);
        if (try root.entryIfExists(script_path) != null) {
            const bytes = try root.readFileAlloc(
                allocator,
                script_path,
                native_trigger.maximum_document_bytes,
            );
            defer allocator.free(bytes);
            var active = native_trigger.decodeActiveScript(
                allocator,
                bytes,
            ) catch return .{
                .outcome = .recovery_required,
                .detail = "script_evidence_invalid",
            };
            defer active.deinit();
            if (record.program_sha256) |program_sha256| {
                if (!std.mem.eql(
                    u8,
                    &active.script.program_sha256,
                    &program_sha256,
                )) return .{
                    .outcome = .recovery_required,
                    .detail = "script_evidence_invalid",
                };
            }
            return .{
                .outcome = .recovery_required,
                .detail = "script_outcome_unknown",
            };
        }
        return .{
            .outcome = .recovery_required,
            .detail = if (try root.entryIfExists(
                try root_fs.Path.init(root_mutation.journal_path),
            ) != null)
                "mutation_evidence_unresolved"
            else
                "active_attempt_untracked",
        };
    }

    var provenance = try native_provenance.read(allocator, root) orelse
        return error.RecoveryEvidenceMissing;
    defer provenance.deinit();
    const completion_store: root_operation_completion.Store = .init(root);
    var completion = try completion_store.read(allocator) orelse
        return error.RecoveryEvidenceMissing;
    defer completion.deinit();

    var lock_attempt = try coordinator.acquire(allocator, .{
        .intent = .mutation,
        .existing = .fail,
        .backend = completion.document.backend,
        .operation = completion.document.operation,
        .request_sha256 = completion.document.request_sha256,
        .policy_sha256 = completion.document.policy_sha256,
        .evidence = .{
            .authorization_sha256 = completion.document.authorization_sha256,
            .program_sha256 = completion.document.program_sha256,
            .plan_sha256 = completion.document.plan_sha256,
            .exact_lock = completion.document.exact_lock,
            .database_generation_sha256 = completion.document.database_generation_sha256,
            .artifact_evidence_sha256 = completion.document.artifact_evidence_sha256,
        },
        .target_architecture = completion.document.target_architecture,
        .foreign_architectures = completion.document.foreign_architectures,
    });
    var temporary_attempt_active = true;
    defer if (temporary_attempt_active) {
        lock_attempt.abandonIfPreMutation(allocator) catch |err| {
            std.log.err("native recovery could not abandon temporary attempt: {s}", .{@errorName(err)});
        };
        lock_attempt.release();
    };

    if (try orphanNativeEvidenceDetail(allocator, root)) |detail| {
        try lock_attempt.abandonIfPreMutation(allocator);
        lock_attempt.release();
        temporary_attempt_active = false;
        return .{
            .outcome = .recovery_required,
            .detail = detail,
        };
    }

    var locked_provenance = try native_provenance.read(
        allocator,
        root,
    ) orelse return error.RecoveryEvidenceMissing;
    defer locked_provenance.deinit();
    var locked_completion = try completion_store.read(allocator) orelse
        return error.RecoveryEvidenceMissing;
    defer locked_completion.deinit();
    if (!std.mem.eql(
        u8,
        &locked_provenance.document.digest_sha256,
        &provenance.document.digest_sha256,
    ) or !std.mem.eql(
        u8,
        &locked_completion.document.digest_sha256,
        &completion.document.digest_sha256,
    )) return error.ActiveAttemptChanged;
    try native_provenance.verifyEvidence(
        allocator,
        root,
        locked_provenance.document,
    );
    if (!std.mem.eql(
        u8,
        locked_provenance.document.install_root,
        request.root,
    ) or (try root.metadataOfRoot()).inode !=
        locked_provenance.document.root_inode)
        return error.InvalidRecoveryProvenance;
    const provenance_attempt = native_recovery.parseDigest(
        locked_provenance.document.attempt_id,
    ) orelse return error.InvalidRecoveryProvenance;
    const provenance_digest = parseHex(
        32,
        &locked_provenance.document.digest_sha256,
    ) orelse return error.InvalidRecoveryProvenance;
    if (!std.mem.eql(
        u8,
        &locked_completion.document.attempt_id,
        &provenance_attempt,
    ) or locked_completion.document.transaction_provenance.document_sha256 == null or
        !std.mem.eql(
            u8,
            &locked_completion.document.transaction_provenance.document_sha256.?,
            &provenance_digest,
        ))
        return error.InvalidRecoveryProvenance;

    try lock_attempt.abandonIfPreMutation(allocator);
    lock_attempt.release();
    temporary_attempt_active = false;
    return .{
        .outcome = switch (locked_provenance.document.outcome) {
            .succeeded => .applied,
            .failed => .script_failed,
            .recovery_required => .recovery_required,
        },
        .detail = "already_completed",
        .program_sha256 = locked_provenance.document.program_sha256,
        .attempt_id = locked_provenance.document.attempt_id,
        .provenance_path = native_provenance.document_path,
    };
}

fn recoverLifecycleProgram(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    request: ExternalLifecycleRequest,
    locks: root_operation.LockBackend,
) !LifecycleResult {
    var intent = native_recovery.readIntent(allocator, root) catch |err| switch (err) {
        error.FileNotFound => return recoverWithoutNativeIntent(
            allocator,
            root,
            request,
            locks,
        ),
        else => return err,
    };
    defer intent.deinit();
    if ((try root.metadataOfRoot()).inode != intent.intent.root_inode)
        return error.RecoveryRootIdentityMismatch;
    if (!std.mem.eql(u8, intent.intent.install_root, request.root) or
        !std.mem.eql(u8, intent.intent.architecture, request.architecture) or
        !std.mem.eql(
            u8,
            intent.intent.authorization_path,
            native_recovery.authorization_name,
        ) or
        !std.mem.eql(
            u8,
            intent.intent.program_path,
            native_recovery.program_name,
        ))
        return error.InvalidRecoveryIntent;
    var namespace = try root.openDirectory(
        try root_fs.Path.init(root_operation.namespace_path),
    );
    defer namespace.close(root.io);
    const authorization_store = try native_authorization.Store.init(
        root.io,
        namespace,
        native_recovery.authorization_name,
    );
    const program_store = try native_program.Store.init(
        root.io,
        namespace,
        native_recovery.program_name,
    );
    var compiled: CompiledLifecycle = .{
        .authorization = try authorization_store.read(
            allocator,
            native_recovery.maximum_intent_bytes,
        ),
        .program = try program_store.read(
            allocator,
            native_recovery.maximum_intent_bytes,
        ),
    };
    defer compiled.deinit();
    if (!std.mem.eql(
        u8,
        &compiled.program.program.digest_sha256,
        &intent.intent.program_sha256,
    ) or !std.mem.eql(
        u8,
        &native_recovery.hexDigest(
            compiled.authorization.authorization.digest_sha256,
        ),
        &intent.intent.authorization_sha256,
    ) or !compiled.program.program.matchesAuthorization(
        compiled.authorization.authorization,
    )) return error.RecoveryProgramBindingMismatch;
    const persisted_program = compiled.program.program;
    if (!std.mem.eql(
        u8,
        &persisted_program.request_sha256,
        &intent.intent.request_sha256,
    ) or !std.mem.eql(
        u8,
        &persisted_program.executor_policy_sha256,
        &intent.intent.policy_sha256,
    ) or !std.mem.eql(
        u8,
        &persisted_program.exact_lock.digest_sha256,
        &intent.intent.exact_lock_sha256,
    ) or !std.mem.eql(
        u8,
        &persisted_program.artifacts_sha256,
        &intent.intent.artifact_evidence_sha256,
    ) or !std.mem.eql(
        u8,
        &persisted_program.installed_database.generation_sha256,
        &intent.intent.database_generation_sha256,
    ) or !std.mem.eql(
        u8,
        &persisted_program.installed_database.trigger_state_sha256,
        &intent.intent.initial_trigger_state_sha256,
    ) or !std.mem.eql(
        u8,
        persisted_program.install_root,
        intent.intent.install_root,
    ) or !std.mem.eql(
        u8,
        persisted_program.target_architecture,
        intent.intent.architecture,
    )) return error.RecoveryProgramBindingMismatch;
    try validatePersistedLifecycleRequest(allocator, root, intent.intent);
    var cleanup_coordinator = try root_operation.Coordinator.open(
        root.io,
        root,
        request.root,
        locks,
    );
    const active_record = try cleanup_coordinator.inspect(allocator);
    if (active_record == null) {
        // Private pre-integration executions cleared the caller record before
        // native cleanup. Hold rank 0 while verifying terminal receipts, but
        // never manufacture a replacement attempt over their remaining intent.
        const cleanup_lock = try locks.acquire(.{
            .rank = .root_operation,
            .root = root,
            .identity = cleanup_coordinator.identity,
            .path = root_operation.lock_path,
            .wait_ms = 0,
            .cancellation = .never(),
        });
        defer locks.release(cleanup_lock);
        if (try cleanup_coordinator.inspect(allocator)) |value| {
            var unexpected = value;
            unexpected.deinit();
            return error.ActiveAttemptChanged;
        }
        var locked_intent = try native_recovery.readIntent(allocator, root);
        defer locked_intent.deinit();
        if (!std.mem.eql(u8, &locked_intent.intent.digest_sha256, &intent.intent.digest_sha256))
            return error.InvalidRecoveryIntent;
        var progress = try native_recovery.readProgress(allocator, root);
        defer progress.deinit();
        const terminal = native_recovery.latest(
            progress.document,
            nativeAction(.provenance, std.math.maxInt(u32), 0, 0),
        ) orelse return error.RecoveryEvidenceMissing;
        if (terminal.stage != .terminal)
            return error.InvalidRecoveryProgress;
        var provenance = try native_provenance.read(allocator, root) orelse
            return error.RecoveryEvidenceMissing;
        defer provenance.deinit();
        try native_provenance.verifyEvidence(
            allocator,
            root,
            provenance.document,
        );
        const completion_store: root_operation_completion.Store = .init(root);
        var completion = try completion_store.read(allocator) orelse
            return error.RecoveryEvidenceMissing;
        defer completion.deinit();
        const original_attempt = native_recovery.parseDigest(
            intent.intent.attempt_id,
        ) orelse return error.InvalidRecoveryIntent;
        const provenance_digest = parseHex(
            32,
            &provenance.document.digest_sha256,
        ) orelse return error.InvalidRecoveryProvenance;
        if (!std.mem.eql(
            u8,
            &provenance.document.attempt_id,
            &intent.intent.attempt_id,
        ) or !std.mem.eql(
            u8,
            &provenance.document.program_sha256,
            &intent.intent.program_sha256,
        ) or !std.mem.eql(
            u8,
            &completion.document.attempt_id,
            &original_attempt,
        ) or completion.document.transaction_provenance.document_sha256 == null or
            !std.mem.eql(
                u8,
                &completion.document.transaction_provenance.document_sha256.?,
                &provenance_digest,
            )) return error.InvalidRecoveryProvenance;
        for (progress.document.records) |entry| {
            if (entry.action.kind != .script and
                entry.action.kind != .compensation and
                entry.action.kind != .trigger)
                continue;
            var path_buffer: [128]u8 = undefined;
            const path = try native_recovery.scriptOutcomePath(
                entry.action,
                &path_buffer,
            );
            root.removeFile(try root_fs.Path.init(path)) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
        }
        try native_recovery.cleanup(allocator, root, intent.intent);
        return .{
            .outcome = switch (provenance.document.outcome) {
                .succeeded => .applied,
                .failed => .script_failed,
                .recovery_required => .recovery_required,
            },
            .detail = "cleanup_completed",
            .program_sha256 = provenance.document.program_sha256,
            .attempt_id = native_recovery.hexDigest(original_attempt),
            .provenance_path = native_provenance.document_path,
        };
    } else {
        var owned_active = active_record.?;
        owned_active.deinit();
    }
    var recovery_arena = std.heap.ArenaAllocator.init(allocator);
    defer recovery_arena.deinit();
    const owned = recovery_arena.allocator();
    const inputs = try loadRecoveredLifecycleInputs(
        owned,
        root,
        intent.intent,
        compiled.program.program,
        false,
    );
    var initial_database = switch (try package_database.importSnapshot(
        owned,
        .{
            .native_architecture = intent.intent.architecture,
            .snapshot = inputs.snapshot,
        },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return error.InvalidExternalDatabase,
    };
    defer initial_database.deinit();
    if (!std.mem.eql(
        u8,
        &native_recovery.hexDigest(initial_database.generation.sha256),
        &intent.intent.database_generation_sha256,
    ) or !std.mem.eql(
        u8,
        &native_recovery.hexDigest(
            native_trigger.stateDigest(initial_database.model),
        ),
        &intent.intent.initial_trigger_state_sha256,
    )) return error.RecoveryDatabaseBindingMismatch;
    const external = try recoveryExternalRequest(owned, request, intent.intent);
    return executeLifecycleProgram(
        owned,
        root,
        external,
        &compiled,
        inputs.models,
        inputs.archive_bytes,
        inputs.snapshot,
        initial_database.model,
        locks,
        intent.intent,
        null,
    );
}

fn productionLifecycleRequest(
    document: native_execution_request.Document,
    crash_at: ?native_recovery.CrashPoint,
) ExternalLifecycleRequest {
    return .{
        .root = document.install_root,
        .architecture = document.architecture,
        .archives = &.{},
        .operation = std.meta.stringToEnum(ExternalMaterializationOperation, @tagName(document.operation)).?,
        .policy = switch (document.policy) {
            .keep_existing => .keep_existing,
            .use_package_version => .use_package_version,
        },
        .report = "",
        .triggers = document.triggers,
        .defer_triggers = document.defer_triggers,
        .recovery = true,
        .crash_at = crash_at,
    };
}

/// Experimental caller-owned runtime. Product/CLI backend selection remains
/// separate; this interface never accepts fixture requests or alternate helpers.
pub const Runtime = struct {
    pub const PrepareRequest = struct {
        attempt: *root_operation.Attempt,
        plan: *const solver.Plan,
        exact_lock: *const exact_lock_v2.Lock,
        archives: []const []const u8,
        policy: transaction_executor.Policy,
    };

    pub const Request = struct {
        attempt: *root_operation.Attempt,
        prepared: *native_preparation.Prepared,
        archives: []const []const u8,
        operation: native_recovery.Operation,
    };

    pub const Outcome = enum { succeeded, failed, recovery_required, refused };

    pub const Report = struct {
        outcome: Outcome,
        /// Static diagnostic text; only the optional receipt owns memory.
        detail: []const u8,
        program_sha256: ?native_recovery.Digest,
        receipt: ?native_provenance.OwnedDocument = null,

        pub fn deinit(self: *Report) void {
            if (self.receipt) |*receipt| receipt.deinit();
            self.* = undefined;
        }
    };

    /// Preparation must bind this exact script policy.
    pub fn scriptPolicy() maintainer_script.Policy {
        return lifecycleScriptPolicy();
    }

    /// A pre-mutation caller record alone cannot prove that no native intent
    /// was published. Callers may abandon only after this additional check.
    pub fn canAbandon(allocator: std.mem.Allocator, attempt: *root_operation.Attempt) !bool {
        const root = try validateAttempt(attempt);
        if (!attempt.record().state.provenPreMutation()) return false;
        if (try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) != null or
            try orphanNativeEvidenceDetail(allocator, root) != null)
            return false;
        if (try readCompletion(allocator, attempt)) |value| {
            var receipt = value;
            defer receipt.deinit();
            return false;
        }
        return true;
    }

    /// Captures complete root evidence and validates acquired bytes against
    /// their genuine lock origins. This does not publish native active intent.
    pub fn prepare(allocator: std.mem.Allocator, request: PrepareRequest) !native_preparation.ResultWithNoChanges {
        const root = try validateAttempt(request.attempt);
        if (!request.attempt.record().state.provenPreMutation())
            return error.OperationNotMutable;
        if (!std.mem.eql(u8, request.attempt.record().target_architecture, request.plan.target_architecture))
            return error.OperationArchitectureMismatch;
        if (request.archives.len > native_program.maximum_artifacts)
            return error.LimitExceeded;
        var scratch = std.heap.ArenaAllocator.init(allocator);
        defer scratch.deinit();
        const temporary = scratch.allocator();
        var captured = try captureDatabaseSnapshot(allocator, root, .{});
        defer captured.deinit();
        normalizeCapturedNativeArchitecture(&captured.snapshot, request.plan.target_architecture);
        var database = switch (try package_database.importSnapshot(allocator, .{
            .native_architecture = request.plan.target_architecture,
            .snapshot = captured.snapshot,
        }, .{})) {
            .database => |value| value,
            .diagnostic => return error.InvalidNativeDatabase,
        };
        defer database.deinit();
        const foreign = request.attempt.record().foreign_architectures;
        if (foreign.len != database.model.foreign_architectures.len)
            return error.OperationArchitectureMismatch;
        for (foreign, database.model.foreign_architectures) |expected, actual|
            if (!std.mem.eql(u8, expected, actual)) return error.OperationArchitectureMismatch;
        if (database.model.pending_updates.len != 0 or
            database.model.diversions.len != 0 or database.model.stat_overrides.len != 0 or
            database.model.opaque_info.len != 0)
            return error.UnsupportedNativeDatabase;
        const installed = try lifecycleInstalledEvidence(temporary, root, database.model);
        const models = try temporary.alloc(archive_application.Model, request.archives.len);
        const origins = try temporary.alloc(exact_lock_v2.PackageOrigin, request.archives.len);
        var total_bytes: u64 = 0;
        for (request.archives, 0..) |bytes, index| {
            total_bytes = std.math.add(u64, total_bytes, bytes.len) catch
                return error.LimitExceeded;
            if (total_bytes > (Limits{}).max_archive_bytes)
                return error.LimitExceeded;
            models[index] = switch (archive_application.prepare(temporary, bytes, .{ .local = .{} }, .{})) {
                .model => |value| value,
                .diagnostic => return error.InvalidNativeArchive,
            };
            const model = &models[index];
            const locked = request.exact_lock.findPackage(
                model.facts.package,
                model.facts.version,
                model.facts.architecture,
            ) orelse return error.ArchiveEvidenceMismatch;
            if (locked.declared_size != bytes.len or
                !std.mem.eql(u8, &locked.sha256, &model.provenance().sha256))
                return error.ArchiveEvidenceMismatch;
            if (model.metadata.len != 0 or model.script(.config) != null)
                return error.UnsupportedNativeArchive;
            origins[index] = locked.origin;
        }
        const archives = try programArchiveEvidence(temporary, models, request.archives, origins);
        var triggers = database.model.triggers.interests.len != 0 or
            database.model.triggers.pending.len != 0;
        for (installed) |package| {
            triggers = triggers or package.triggers.len != 0 or
                package.triggers_pending.len != 0 or package.triggers_awaited.len != 0;
        }
        for (archives) |archive| triggers = triggers or archive.triggers.len != 0;
        const authority = try lifecycleTriggerAuthority(
            temporary,
            .{ .enabled = triggers, .mode = if (request.plan.actions.len == 0) .process_pending else .transaction },
            database,
            installed,
            archives,
            &.{},
        );
        return native_preparation.prepareOrUnchanged(allocator, .{
            .plan = request.plan,
            .exact_lock = request.exact_lock,
            .install_root = request.attempt.record().install_root,
            .policy = request.policy,
            .script_policy = scriptPolicy(),
            .foreign_architectures = database.model.foreign_architectures,
            .installed = .{
                .generation_sha256 = database.generation.sha256,
                .packages = installed,
                .trigger_state_sha256 = native_trigger.stateDigest(database.model),
                .updates_pending = database.model.pending_updates.len != 0,
            },
            .archives = archives,
            .trigger_authority = authority,
        });
    }

    /// Borrows the caller's held attempt and prepared inputs. Never completes,
    /// releases, or abandons the caller's operation, including on refusal.
    pub fn execute(allocator: std.mem.Allocator, request: Runtime.Request) !Report {
        return executeWithCrash(allocator, request, null);
    }

    fn executeWithCrash(
        allocator: std.mem.Allocator,
        request: Runtime.Request,
        crash_at: ?native_recovery.CrashPoint,
    ) !Report {
        const root = try validateAttempt(request.attempt);
        try native_program.validateDocument(request.prepared.program.program);
        const authorization_bytes = try request.prepared.authorization.authorization.canonicalJson(allocator);
        defer allocator.free(authorization_bytes);
        var authorization = try native_authorization.decode(
            allocator,
            authorization_bytes,
            native_authorization.maximum_document_bytes,
        );
        defer authorization.deinit();
        if (!request.prepared.program.program.matchesAuthorization(authorization.authorization))
            return error.InvalidLifecycleProgram;
        const result = try executePreparedNativeProgramWithHelper(
            allocator,
            root,
            request.prepared,
            request.archives,
            request.attempt,
            request.attempt.coordinator.locks,
            request.operation,
            crash_at,
            native_helper.bundled(),
        );
        return report(allocator, request.attempt, result);
    }

    /// Recovery consumes only persisted evidence from the original attempt.
    pub fn recover(allocator: std.mem.Allocator, attempt: *root_operation.Attempt) !Report {
        const root = try validateAttempt(attempt);
        if (try readCompletion(allocator, attempt)) |receipt|
            return completedReport(receipt);
        const result = try recoverPreparedNativeProgramWithHelper(
            allocator,
            root,
            attempt,
            attempt.coordinator.locks,
            null,
            native_helper.bundled(),
        );
        return report(allocator, attempt, result);
    }

    /// Returns independently owned terminal evidence without probing or
    /// requiring the current package-owned helper target.
    pub fn readCompletion(
        allocator: std.mem.Allocator,
        attempt: *root_operation.Attempt,
    ) !?native_provenance.OwnedDocument {
        const root = try validateAttempt(attempt);
        var receipt = try readProductionCompletion(allocator, root, attempt) orelse return null;
        errdefer receipt.deinit();
        const bytes = try retainedNativeBytes(allocator, root, receipt.document, .execution_request);
        defer allocator.free(bytes);
        var request = try native_execution_request.decodePersisted(allocator, bytes);
        defer request.deinit();
        const helper = request.helper() orelse return error.NativeHelperBindingRequired;
        try helper.matches(native_helper.bundled());
        return receipt;
    }

    /// Clears only native active evidence after an exact receipt acknowledgment.
    /// The caller still owns outer completion, provenance, cleanup, and its lock.
    pub fn acknowledge(
        allocator: std.mem.Allocator,
        attempt: *root_operation.Attempt,
        expected_receipt: native_provenance.Digest,
    ) !void {
        var receipt = try readCompletion(allocator, attempt) orelse return error.RecoveryEvidenceMissing;
        defer receipt.deinit();
        if (!std.mem.eql(u8, &receipt.document.digest_sha256, &expected_receipt))
            return error.InvalidRecoveryProvenance;
        try acknowledgePreparedNativeProgram(
            allocator,
            attempt.coordinator.root,
            attempt,
            expected_receipt,
        );
    }

    fn validateAttempt(attempt: *root_operation.Attempt) !root_fs.Root {
        if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
        if (!attempt.locked()) return error.LockLost;
        const record = attempt.record();
        if (record.backend != .native) return error.OperationBackendMismatch;
        if (std.mem.eql(u8, record.install_root, "/")) return error.HostRootNotSupported;
        const root = attempt.coordinator.root;
        if (!std.mem.eql(u8, record.install_root, attempt.coordinator.install_root))
            return error.OperationRootMismatch;
        var named = try root_fs.openAbsoluteRoot(root.io, record.install_root);
        defer named.close();
        const held = try root.rootEntry();
        const resolved = try named.root.rootEntry();
        if (held.inode != resolved.inode or held.device != resolved.device)
            return error.OperationRootMismatch;
        var host = try root_fs.openAbsoluteRoot(root.io, "/");
        defer host.close();
        const host_entry = try host.root.rootEntry();
        if (held.inode == host_entry.inode and held.device == host_entry.device)
            return error.HostRootNotSupported;
        return root;
    }

    fn completedReport(receipt: native_provenance.OwnedDocument) Report {
        return .{
            .outcome = if (receipt.document.outcome == .succeeded) .succeeded else .failed,
            .detail = "awaiting_caller_acknowledgment",
            .program_sha256 = receipt.document.program_sha256,
            .receipt = receipt,
        };
    }

    fn report(
        allocator: std.mem.Allocator,
        attempt: *root_operation.Attempt,
        result: LifecycleResult,
    ) !Report {
        switch (result.outcome) {
            .applied, .script_failed, .trigger_failed => {
                const receipt = try readCompletion(allocator, attempt) orelse
                    return error.RecoveryEvidenceMissing;
                if ((result.outcome == .applied) != (receipt.document.outcome == .succeeded)) {
                    var invalid = receipt;
                    invalid.deinit();
                    return error.InvalidRecoveryProvenance;
                }
                return completedReport(receipt);
            },
            .recovery_required, .refused, .handoff => {
                const recovery_required = result.outcome == .recovery_required or
                    attempt.record().mutation_started or
                    try attempt.coordinator.root.entryIfExists(
                        try root_fs.Path.init(native_recovery.intent_path),
                    ) != null;
                if (recovery_required and attempt.record().mutation_started)
                    try attempt.requireRecovery(allocator, attempt.record().phase);
                return .{
                    .outcome = if (recovery_required) .recovery_required else .refused,
                    .detail = result.detail,
                    .program_sha256 = result.program_sha256,
                };
            },
        }
    }
};

fn executePreparedNativeProgram(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    compiled: *CompiledLifecycle,
    archive_bytes: []const []const u8,
    attempt: *root_operation.Attempt,
    locks: root_operation.LockBackend,
    operation: native_recovery.Operation,
    crash_at: ?native_recovery.CrashPoint,
) !LifecycleResult {
    return executePreparedNativeProgramWithHelper(
        allocator,
        root,
        compiled,
        archive_bytes,
        attempt,
        locks,
        operation,
        crash_at,
        null,
    );
}

fn matchNativeHelperBinding(left: ?native_helper.Binding, right: ?native_helper.Binding) !void {
    if (left == null or right == null) {
        if ((left == null) != (right == null)) return error.NativeHelperBindingRequired;
        return;
    }
    try left.?.validate();
    try right.?.validate();
    if (left.?.size != right.?.size or !std.mem.eql(u8, &left.?.sha256, &right.?.sha256))
        return error.NativeHelperDigestMismatch;
}

fn verifyNativeHelperBytes(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    helper: native_helper.Binding,
) !void {
    try helper.validate();
    const bytes = try root.readFileAlloc(allocator, try root_fs.Path.init(helper.source_path), native_helper.maximum_bytes);
    defer allocator.free(bytes);
    var sha256: [32]u8 = undefined;
    Sha256.hash(bytes, &sha256, .{});
    try helper.matches(.{ .bytes = bytes, .sha256 = sha256 });
}

fn executePreparedNativeProgramWithHelper(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    compiled: *CompiledLifecycle,
    archive_bytes: []const []const u8,
    attempt: *root_operation.Attempt,
    locks: root_operation.LockBackend,
    operation: native_recovery.Operation,
    crash_at: ?native_recovery.CrashPoint,
    helper_source: ?native_helper.Source,
) !LifecycleResult {
    const program = compiled.program.program;
    if (!std.mem.eql(u8, &program.script_policy_sha256, &native_recovery.hexDigest(
        maintainer_script.policyDigest(lifecycleScriptPolicy()),
    ))) return error.UnsupportedScriptPolicy;
    try native_operation.bind(allocator, root, attempt, program);
    if (try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) != null or
        try orphanNativeEvidenceDetail(allocator, root) != null)
        return error.NativeRecoveryRequired;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    var deployment: ?native_helper.Deployment = null;
    defer if (deployment) |*value| value.deinit();
    if (helper_source) |source| {
        deployment = try native_helper.stage(allocator, root, source);
        try native_helper.probe(allocator, root, deployment.?.binding);
    }
    const document = try native_execution_request.create(root, attempt, program, operation);
    const bytes = if (deployment) |value|
        try native_execution_request.encodeWithHelper(scratch, try native_execution_request.withHelper(document, value.binding))
    else
        try native_execution_request.encode(scratch, document);
    var request = try native_execution_request.decodePersisted(scratch, bytes);
    defer request.deinit();
    const archives = try productionArchives(scratch, program.artifacts, archive_bytes);
    var captured = try captureDatabaseSnapshot(allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, program.target_architecture);
    var database = switch (try package_database.importSnapshot(allocator, .{
        .native_architecture = program.target_architecture,
        .snapshot = captured.snapshot,
    }, .{})) {
        .database => |value| value,
        .diagnostic => return error.InvalidExternalDatabase,
    };
    defer database.deinit();
    if (helper_source != null)
        try validateNativeHelperTargetPlan(compiled.authorization.authorization, archives.models, database.model);
    return executeLifecycleProgramWithRequest(
        allocator,
        root,
        productionLifecycleRequest(request.execution(), crash_at),
        compiled,
        archives.models,
        archives.bytes,
        captured.snapshot,
        database.model,
        locks,
        null,
        bytes,
        attempt,
        request.execution(),
        request.helper(),
    );
}

fn validateNativeHelperTargetPlan(
    authorization: native_authorization.Authorization,
    models: []const archive_application.Model,
    installed: package_database.Model,
) !void {
    for (models) |model| for (model.files) |file| {
        if (std.mem.eql(u8, file.path, native_helper.target_path) and file.kind != .regular)
            return error.NativeHelperTargetMutationUnsupported;
    };
    for (installed.packages) |package| {
        const action = authorization.findAction(package.name, package.architecture) orelse continue;
        const owns_target = for (package.paths orelse &.{}) |path| {
            const relative = relativeListPath(path) orelse continue;
            if (std.mem.eql(u8, relative, native_helper.target_path)) break true;
        } else false;
        if (!owns_target) continue;
        switch (action.kind) {
            .remove, .purge => return error.NativeHelperTargetMutationUnsupported,
            .install, .upgrade, .downgrade, .reinstall => {
                const retained = for (models) |model| {
                    if (!std.mem.eql(u8, model.facts.package, package.name) or
                        !std.mem.eql(u8, model.facts.architecture, package.architecture))
                        continue;
                    for (model.files) |file| {
                        if (std.mem.eql(u8, file.path, native_helper.target_path) and file.kind == .regular)
                            break;
                    } else return error.NativeHelperTargetMutationUnsupported;
                    break true;
                } else false;
                if (!retained) return error.NativeHelperTargetMutationUnsupported;
            },
        }
    }
}

fn retainedNativeBytes(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    receipt: native_provenance.Document,
    kind: native_provenance.EvidenceKind,
) ![]u8 {
    for (receipt.evidence_files) |file| {
        if (file.kind == kind)
            return root.readFileAlloc(allocator, try root_fs.Path.init(file.path), native_provenance.maximum_evidence_file_bytes);
    }
    return error.RecoveryEvidenceMissing;
}

fn readProductionCompletion(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
) !?native_provenance.OwnedDocument {
    var receipt = try native_provenance.read(allocator, root) orelse return null;
    errdefer receipt.deinit();
    if (!std.mem.eql(u8, &receipt.document.attempt_id, &native_recovery.hexDigest(attempt.attemptId())) or
        receipt.document.outcome == .recovery_required)
    {
        receipt.deinit();
        return null;
    }
    try native_provenance.verifyEvidence(allocator, root, receipt.document);
    const request_bytes = try retainedNativeBytes(allocator, root, receipt.document, .execution_request);
    defer allocator.free(request_bytes);
    var request = try native_execution_request.decodePersisted(allocator, request_bytes);
    defer request.deinit();
    const execution = request.execution();
    if (request.helper()) |helper| {
        const helper_bytes = try retainedNativeBytes(allocator, root, receipt.document, .helper_binary);
        defer allocator.free(helper_bytes);
        var sha256: [32]u8 = undefined;
        Sha256.hash(helper_bytes, &sha256, .{});
        try helper.matches(.{ .bytes = helper_bytes, .sha256 = sha256 });
    }
    const program_bytes = try retainedNativeBytes(allocator, root, receipt.document, .program);
    defer allocator.free(program_bytes);
    var program = try native_program.decode(allocator, program_bytes, native_program.maximum_document_bytes);
    defer program.deinit();
    try native_execution_request.validateBinding(execution, root, attempt, program.program);
    const document = receipt.document;
    if (!std.mem.eql(u8, &document.program_sha256, &execution.program.program_sha256) or
        !std.mem.eql(u8, &document.request_sha256, &execution.caller.request_sha256) or
        !std.mem.eql(u8, &document.policy_sha256, &execution.caller.policy_sha256) or
        !document.operation.eql(execution.caller.operation) or
        !std.mem.eql(u8, document.install_root, execution.install_root) or
        document.root_inode != execution.root_inode)
        return error.InvalidRecoveryProvenance;
    if (try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) != null) {
        var active = try native_recovery.readIntent(allocator, root);
        defer active.deinit();
        try native_execution_request.validateIntent(execution, active.intent);
        if (!std.mem.eql(u8, &active.intent.digest_sha256, &document.execution_intent_sha256))
            return error.InvalidRecoveryIntent;
    }
    if (try root.entryIfExists(try root_fs.Path.init(native_recovery.progress_path)) != null) {
        var progress = try native_recovery.readProgress(allocator, root);
        defer progress.deinit();
        if (!std.mem.eql(u8, &progress.document.intent_sha256, &document.execution_intent_sha256) or
            !std.mem.eql(u8, &progress.document.head_sha256, &document.progress_head_sha256))
            return error.InvalidRecoveryProgress;
    }
    return receipt;
}

fn productionCompletionResult(receipt: native_provenance.Document) LifecycleResult {
    return .{
        .outcome = if (receipt.outcome == .succeeded) .applied else .script_failed,
        .detail = "awaiting_caller_acknowledgment",
        .program_sha256 = receipt.program_sha256,
        .attempt_id = receipt.attempt_id,
        .provenance_path = native_provenance.document_path,
    };
}

fn recoverPreparedNativeProgram(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
    locks: root_operation.LockBackend,
    crash_at: ?native_recovery.CrashPoint,
) !LifecycleResult {
    return recoverPreparedNativeProgramWithHelper(allocator, root, attempt, locks, crash_at, null);
}

fn recoverPreparedNativeProgramWithHelper(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
    locks: root_operation.LockBackend,
    crash_at: ?native_recovery.CrashPoint,
    helper_source: ?native_helper.Source,
) !LifecycleResult {
    if (try readProductionCompletion(allocator, root, attempt)) |value| {
        var receipt = value;
        defer receipt.deinit();
        return productionCompletionResult(receipt.document);
    }
    var intent = try native_recovery.readIntent(allocator, root);
    defer intent.deinit();
    const request_blob = for (intent.intent.blobs) |blob| {
        if (blob.kind == .request) break blob;
    } else return error.RecoveryEvidenceMissing;
    if (!std.mem.eql(u8, request_blob.logical_path, native_execution_request.logical_path) and
        !std.mem.eql(u8, request_blob.logical_path, native_execution_request.helper_logical_path))
        return error.ProductionRecoveryRequestRequired;
    const request_bytes = try native_recovery.verifyBlob(allocator, root, request_blob);
    defer allocator.free(request_bytes);
    var request = try native_execution_request.decodePersisted(allocator, request_bytes);
    defer request.deinit();
    if (!std.mem.eql(u8, request.logicalPath(), request_blob.logical_path))
        return error.RecoveryRequestBindingMismatch;
    if (helper_source) |source| {
        const helper = request.helper() orelse return error.NativeHelperBindingRequired;
        try helper.matches(source);
    } else if (request.helper() != null) return error.NativeHelperBindingRequired;
    var namespace = try root.openDirectory(try root_fs.Path.init(root_operation.namespace_path));
    defer namespace.close(root.io);
    const authorization_store = try native_authorization.Store.init(root.io, namespace, native_recovery.authorization_name);
    const program_store = try native_program.Store.init(root.io, namespace, native_recovery.program_name);
    var authorization = try authorization_store.read(allocator, native_recovery.maximum_intent_bytes);
    defer authorization.deinit();
    var program = try program_store.read(allocator, native_recovery.maximum_intent_bytes);
    defer program.deinit();
    var compiled: CompiledLifecycle = .{ .authorization = authorization, .program = program };
    try native_execution_request.validateBinding(request.execution(), root, attempt, program.program);
    try native_execution_request.validateIntent(request.execution(), intent.intent);
    if (request.helper()) |helper| try native_helper.probe(allocator, root, helper);
    if (!std.mem.eql(u8, &program.program.script_policy_sha256, &native_recovery.hexDigest(
        maintainer_script.policyDigest(lifecycleScriptPolicy()),
    ))) return error.UnsupportedScriptPolicy;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const inputs = try loadRecoveredLifecycleInputs(arena.allocator(), root, intent.intent, program.program, true);
    var database = switch (try package_database.importSnapshot(allocator, .{
        .native_architecture = program.program.target_architecture,
        .snapshot = inputs.snapshot,
    }, .{})) {
        .database => |value| value,
        .diagnostic => return error.InvalidExternalDatabase,
    };
    defer database.deinit();
    if (!lifecycleDatabaseMatchesProgram(program.program, database.generation, database.model.packages.len) or
        !std.mem.eql(u8, &native_recovery.hexDigest(native_trigger.stateDigest(database.model)), &intent.intent.initial_trigger_state_sha256))
        return error.RecoveryDatabaseBindingMismatch;
    if (attempt.record().mutation_started)
        try attempt.beginRecovery(allocator, attempt.record().phase);
    return executeLifecycleProgramWithRequest(
        allocator,
        root,
        productionLifecycleRequest(request.execution(), crash_at),
        &compiled,
        inputs.models,
        inputs.archive_bytes,
        inputs.snapshot,
        database.model,
        locks,
        intent.intent,
        null,
        attempt,
        request.execution(),
        request.helper(),
    );
}

fn acknowledgePreparedNativeProgram(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    attempt: *root_operation.Attempt,
    expected_receipt: native_provenance.Digest,
) !void {
    var receipt = try readProductionCompletion(allocator, root, attempt) orelse
        return error.RecoveryEvidenceMissing;
    defer receipt.deinit();
    if (!std.mem.eql(u8, &receipt.document.digest_sha256, &expected_receipt))
        return error.InvalidRecoveryProvenance;
    const intent_bytes = try retainedNativeBytes(allocator, root, receipt.document, .intent);
    defer allocator.free(intent_bytes);
    var intent = try native_recovery.decodeIntent(allocator, intent_bytes);
    defer intent.deinit();
    const progress_bytes = try retainedNativeBytes(allocator, root, receipt.document, .progress);
    defer allocator.free(progress_bytes);
    var progress = try native_recovery.decodeProgress(allocator, progress_bytes);
    defer progress.deinit();
    if (!std.mem.eql(u8, &intent.intent.digest_sha256, &receipt.document.execution_intent_sha256) or
        !std.mem.eql(u8, &progress.document.intent_sha256, &intent.intent.digest_sha256) or
        !std.mem.eql(u8, &progress.document.head_sha256, &receipt.document.progress_head_sha256))
        return error.InvalidRecoveryProvenance;
    if (try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) != null) {
        var active = try native_recovery.readIntent(allocator, root);
        defer active.deinit();
        if (!std.mem.eql(u8, &active.intent.digest_sha256, &intent.intent.digest_sha256))
            return error.InvalidRecoveryIntent;
    }
    try cleanupNativeExecutionEvidence(allocator, root, intent.intent, progress.document);
}

fn executeLifecycleProgram(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    external: ExternalLifecycleRequest,
    compiled: *CompiledLifecycle,
    models: []archive_application.Model,
    archive_bytes: []const []const u8,
    initial_snapshot: package_database.Snapshot,
    initial_model: package_database.Model,
    locks: root_operation.LockBackend,
    recovery_intent: ?native_recovery.Intent,
    raw_request: ?[]const u8,
) !LifecycleResult {
    return executeLifecycleProgramInOperation(
        allocator,
        root,
        external,
        compiled,
        models,
        archive_bytes,
        initial_snapshot,
        initial_model,
        locks,
        recovery_intent,
        raw_request,
        null,
    );
}

fn executeLifecycleProgramInOperation(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    external: ExternalLifecycleRequest,
    compiled: *CompiledLifecycle,
    models: []archive_application.Model,
    archive_bytes: []const []const u8,
    initial_snapshot: package_database.Snapshot,
    initial_model: package_database.Model,
    locks: root_operation.LockBackend,
    recovery_intent: ?native_recovery.Intent,
    raw_request: ?[]const u8,
    borrowed_attempt: ?*root_operation.Attempt,
) !LifecycleResult {
    return executeLifecycleProgramWithRequest(
        allocator,
        root,
        external,
        compiled,
        models,
        archive_bytes,
        initial_snapshot,
        initial_model,
        locks,
        recovery_intent,
        raw_request,
        borrowed_attempt,
        null,
        null,
    );
}

fn executeLifecycleProgramWithRequest(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    external: ExternalLifecycleRequest,
    compiled: *CompiledLifecycle,
    models: []archive_application.Model,
    archive_bytes: []const []const u8,
    initial_snapshot: package_database.Snapshot,
    initial_model: package_database.Model,
    locks: root_operation.LockBackend,
    recovery_intent: ?native_recovery.Intent,
    raw_request: ?[]const u8,
    borrowed_attempt: ?*root_operation.Attempt,
    production_request: ?native_execution_request.Document,
    helper_binding: ?native_helper.Binding,
) !LifecycleResult {
    // The private v1 recovery request cannot describe a caller-owned
    // operation. Do not persist it as if it were a production request.
    if (borrowed_attempt != null and production_request == null and
        (external.recovery or recovery_intent != null or raw_request != null))
        return error.ProductionRecoveryRequestRequired;
    if (production_request != null and borrowed_attempt == null)
        return error.CallerOwnedOperationRequired;
    if ((helper_binding != null and production_request == null) or
        (production_request != null and !external.recovery))
        return error.ProductionRecoveryRequestRequired;
    const program = &compiled.program.program;
    const authorization = &compiled.authorization.authorization;
    if (!program.matchesAuthorization(authorization.*) or
        !std.mem.eql(u8, external.root, program.install_root) or
        !std.mem.eql(u8, external.architecture, program.target_architecture))
        return error.InvalidLifecycleProgram;
    const program_sha256 = parseHex(32, &program.digest_sha256) orelse
        return error.InvalidLifecycleProgram;
    const request_sha256 = parseHex(32, &program.request_sha256) orelse
        return error.InvalidLifecycleProgram;
    const policy_sha256 = parseHex(32, &program.executor_policy_sha256) orelse
        return error.InvalidLifecycleProgram;
    const lock_sha256 = parseHex(32, &program.exact_lock.digest_sha256) orelse
        return error.InvalidLifecycleProgram;
    const artifact_evidence = parseHex(32, &program.artifacts_sha256) orelse
        return error.InvalidLifecycleProgram;
    const initial_database = parseHex(
        32,
        &program.installed_database.generation_sha256,
    ) orelse return error.InvalidLifecycleProgram;
    const operation = externalProductOperation(external.operation);
    const conffile_policy: transaction_executor.ConffilePolicy = switch (external.policy) {
        .keep_existing => .keep_existing,
        .use_package_version => .use_package_version,
    };
    var owned_attempt: root_operation.Attempt = undefined;
    if (borrowed_attempt == null) {
        var coordinator = try root_operation.Coordinator.open(
            root.io,
            root,
            external.root,
            locks,
        );
        owned_attempt = coordinator.acquire(allocator, .{
            .intent = if (recovery_intent != null) .recovery else .mutation,
            .existing = .reclaim_resolved,
            .backend = .native,
            .operation = .{ .package_transaction = operation },
            .request_sha256 = request_sha256,
            .policy_sha256 = policy_sha256,
            .evidence = .{
                .authorization_sha256 = authorization.digest_sha256,
                .program_sha256 = program_sha256,
                .plan_sha256 = program_sha256,
                .exact_lock = .{
                    .schema = program.exact_lock.schema,
                    .version = program.exact_lock.version,
                    .digest_sha256 = lock_sha256,
                },
                .database_generation_sha256 = initial_database,
                .artifact_evidence_sha256 = artifact_evidence,
            },
            .target_architecture = program.target_architecture,
            .foreign_architectures = program.foreign_architectures,
            .adopt_settled_for_acknowledgment = recovery_intent != null,
        }) catch |err| switch (err) {
            error.RecoveryRequired,
            error.OperationInProgress,
            error.ProvenancePending,
            => return .{
                .outcome = .recovery_required,
                .detail = @errorName(err),
                .program_sha256 = program.digest_sha256,
            },
            else => return err,
        };
    }
    const attempt = borrowed_attempt orelse &owned_attempt;
    defer if (borrowed_attempt == null) attempt.release();
    if (borrowed_attempt != null)
        try native_operation.bind(allocator, root, attempt, program.*);
    if (production_request) |request|
        try native_execution_request.validateBinding(request, root, attempt, program.*);
    if (recovery_intent) |intent| {
        if (!std.mem.eql(
            u8,
            &intent.attempt_id,
            &native_recovery.hexDigest(attempt.attemptId()),
        )) {
            return .{
                .outcome = .refused,
                .detail = "attempt_binding_mismatch",
                .program_sha256 = program.digest_sha256,
            };
        }
    }

    var locked_capture = captureDatabaseSnapshot(allocator, root, .{}) catch |err| {
        if (borrowed_attempt == null) try attempt.abandonIfPreMutation(allocator);
        return err;
    };
    defer locked_capture.deinit();
    normalizeCapturedNativeArchitecture(
        &locked_capture.snapshot,
        program.target_architecture,
    );
    var locked_database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = program.target_architecture,
            .snapshot = locked_capture.snapshot,
        },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => {
            if (borrowed_attempt == null) try attempt.abandonIfPreMutation(allocator);
            return .{
                .outcome = .refused,
                .detail = "locked_database_rejected",
                .program_sha256 = program.digest_sha256,
            };
        },
    };
    defer locked_database.deinit();
    if (recovery_intent == null and !lifecycleDatabaseMatchesProgram(
        program.*,
        locked_database.generation,
        locked_database.model.packages.len,
    )) {
        if (borrowed_attempt == null) try attempt.abandonIfPreMutation(allocator);
        return .{
            .outcome = .refused,
            .detail = "database_generation_drift",
            .program_sha256 = program.digest_sha256,
        };
    }
    if (recovery_intent == null and borrowed_attempt == null) try attempt.advance(allocator, .{
        .state = .preflight,
        .phase = .preflight,
    });

    const scratch_arena = try allocator.create(std.heap.ArenaAllocator);
    defer allocator.destroy(scratch_arena);
    scratch_arena.* = .init(allocator);
    defer scratch_arena.deinit();
    const scratch = scratch_arena.allocator();
    var recovery_runtime: native_recovery.Runtime = undefined;
    var execution_state: ExecutionState = .{};
    const execution = &execution_state;
    if (recovery_intent) |intent| {
        recovery_runtime = .{
            .allocator = scratch,
            .root = root,
            .intent_sha256 = intent.digest_sha256,
            .crash = .{ .selected = external.crash_at },
            .recovering = true,
            .staging_directory_initially_present = intent.staging_directory_initially_present,
            .caller_owned = production_request != null,
            .helper_binding = helper_binding,
        };
        execution.recovery = &recovery_runtime;
        const script_recovery = classifyActiveScriptBeforeMutationRecovery(
            allocator,
            root,
            program.*,
            authorization.*,
            recovery_runtime,
        ) catch {
            try attempt.requireRecovery(allocator, .script);
            try publishNativeRecoveryRequiredProvenance(
                execution,
                allocator,
                root,
                attempt,
                program_sha256,
                "script_evidence_invalid",
            );
            return .{
                .outcome = .recovery_required,
                .detail = "script_evidence_invalid",
                .program_sha256 = program.digest_sha256,
            };
        };
        if (script_recovery == .outcome_unknown) {
            try attempt.requireRecovery(allocator, .script);
            try publishNativeRecoveryRequiredProvenance(
                execution,
                allocator,
                root,
                attempt,
                program_sha256,
                "script_outcome_unknown",
            );
            return .{
                .outcome = .recovery_required,
                .detail = "script_outcome_unknown",
                .program_sha256 = program.digest_sha256,
            };
        }
        const mutation_recovered = recoverNativeRootMutation(
            allocator,
            root,
            attempt,
            &recovery_runtime,
        ) catch |err| switch (err) {
            error.ManagedStateChanged,
            error.InvalidManagedState,
            error.UnmodeledManagedState,
            error.ManagedStateLimit,
            => block: {
                try attempt.requireRecovery(allocator, .verification);
                break :block false;
            },
            else => return err,
        };
        if (!mutation_recovered) {
            const detail = if (attempt.record().phase == .verification)
                "managed_state_changed"
            else
                "mutation_evidence_unresolved";
            try publishNativeRecoveryRequiredProvenance(
                execution,
                allocator,
                root,
                attempt,
                program_sha256,
                detail,
            );
            return .{
                .outcome = .recovery_required,
                .detail = detail,
                .program_sha256 = program.digest_sha256,
            };
        }
    } else if (external.recovery) {
        recovery_runtime = try prepareNativeRecovery(
            scratch,
            root,
            external,
            compiled,
            raw_request orelse return error.InvalidLifecycleProgram,
            archive_bytes,
            initial_snapshot,
            attempt,
            production_request,
            helper_binding,
        );
        execution.recovery = &recovery_runtime;
        recovery_runtime.crash.hit(.after_execution_intent);
    }
    if (recovery_intent != null) {
        var terminal_progress = try native_recovery.readProgress(
            allocator,
            root,
        );
        defer terminal_progress.deinit();
        const terminal = native_recovery.latest(
            terminal_progress.document,
            nativeAction(.provenance, std.math.maxInt(u32), 0, 0),
        );
        if (terminal) |record| {
            if (record.stage != .terminal)
                return error.InvalidRecoveryProgress;
            const terminal_succeeded = record.result == .succeeded or
                record.result == .recovered;
            if (borrowed_attempt == null or production_request != null) try finishLifecycleAttempt(
                execution,
                allocator,
                root,
                attempt,
                program_sha256,
                terminal_succeeded,
            );
            return .{
                .outcome = if (terminal_succeeded) .applied else .script_failed,
                .detail = if (terminal_succeeded)
                    "recovered"
                else
                    "recovered_failure",
                .program_sha256 = program.digest_sha256,
            };
        }
    }
    const trigger_authority_bytes = try publishTriggerAuthority(
        allocator,
        root,
        program.*,
        attempt,
    );
    defer if (trigger_authority_bytes) |bytes| allocator.free(bytes);
    var staging: LifecycleStaging = .{};
    defer staging.deinit(allocator);
    var configured: std.StringHashMapUnmanaged(void) = .empty;
    defer configured.deinit(allocator);
    var consumed_scripts: std.AutoHashMapUnmanaged(u32, void) = .empty;
    defer consumed_scripts.deinit(allocator);
    var trigger_events: std.ArrayList(RuntimeTriggerEvent) = .empty;
    defer trigger_events.deinit(scratch);
    try restoreRuntimeTriggerEvents(execution, scratch, root, &trigger_events);
    var fault_used = false;
    var crossed_configure_barrier = false;
    var status_old_baseline = try scratch.dupe(
        u8,
        if (recovery_intent != null)
            initial_snapshot.status.bytes
        else
            locked_capture.snapshot.status.bytes,
    );

    for (program.steps) |step| switch (beginNativeProgramStep(execution, step)) {
        .assert_authorization,
        .assert_root_state,
        .assert_database_generation,
        .assert_installed_package,
        .assert_package_absent,
        .assert_path_ownership,
        .revalidate_artifact,
        .publish_database_generation,
        .verify_final_state,
        .publish_provenance,
        => {},
        .materialize_bootstrap_payload => |intent| {
            const result = try lifecycleDataStep(
                execution,
                allocator,
                root,
                external.root,
                program,
                authorization,
                models,
                archive_bytes,
                locks,
                attempt,
                operation,
                conffile_policy,
                step.sequence,
                intent.package,
                .{},
                null,
            );
            if (lifecycleMaterializationFailure(result)) |failure| return failure;
        },
        .unpack_package => |intent| {
            if (crossed_configure_barrier) {
                status_old_baseline = try root.readFileAlloc(
                    scratch,
                    try root_fs.Path.init(
                        package_database.database_directory ++ "/" ++
                            package_database.status_path,
                    ),
                    (package_database.Limits{}).max_status_bytes,
                );
                crossed_configure_barrier = false;
            }
            const post_unpack = postUnpackScript(program.*, step.sequence, intent.package);
            var hook_context: PostUnpackHook = undefined;
            const hooks: root_mutation.Hooks = if (post_unpack) |script| block: {
                hook_context = .{
                    .execution = execution,
                    .allocator = allocator,
                    .root = root,
                    .install_root = external.root,
                    .program = program,
                    .authorization = authorization,
                    .attempt = attempt,
                    .target_step = 0,
                    .script = script,
                    .inject_unknown = external.fault != null and
                        std.mem.eql(
                            u8,
                            external.fault.?,
                            "after_upgrade_postrm_before_record",
                        ),
                };
                break :block .{
                    .context = &hook_context,
                    .beforeFn = postUnpackHook,
                };
            } else .{};
            const result = try lifecycleDataStep(
                execution,
                allocator,
                root,
                external.root,
                program,
                authorization,
                models,
                archive_bytes,
                locks,
                attempt,
                operation,
                conffile_policy,
                step.sequence,
                intent.package,
                hooks,
                if (post_unpack != null) &hook_context.target_step else null,
            );
            if (post_unpack != null) {
                if (hook_context.unknown_outcome) return .{
                    .outcome = .recovery_required,
                    .detail = "script_outcome_unknown",
                    .program_sha256 = program.digest_sha256,
                };
                if (hook_context.fired)
                    try consumed_scripts.put(
                        allocator,
                        hook_context.script.sequence,
                        {},
                    );
                if (hook_context.rollback_required) {
                    if (result.outcome != .rolled_back) {
                        try attempt.requireRecovery(allocator, .script);
                        return .{
                            .outcome = .recovery_required,
                            .detail = "upgrade_rollback_failed",
                            .program_sha256 = program.digest_sha256,
                        };
                    }
                    const compensation_start =
                        hook_context.script.call.failure
                            .rollback_after_compensations orelse
                        return error.InvalidLifecycleProgram;
                    if (compensation_start >
                        hook_context.script.call.failure.compensations.len)
                        return error.InvalidLifecycleProgram;
                    var failed_compensation = hook_context.failed_compensation;
                    if (failed_compensation == null) {
                        rollback_compensations: for (
                            hook_context.script.call.failure.compensations[compensation_start..],
                            compensation_start..,
                        ) |compensation, compensation_index| {
                            const compensation_outcome = try runLifecycleScript(
                                execution,
                                allocator,
                                root,
                                external.root,
                                program,
                                authorization,
                                attempt,
                                hook_context.script.sequence,
                                intent.package,
                                null,
                                compensation.kind,
                                compensation.source,
                                compensation.script_sha256,
                                compensation.arguments,
                                false,
                            );
                            switch (compensation_outcome) {
                                .exited => |compensation_code| {
                                    if (compensation_code != 0) {
                                        failed_compensation = @intCast(
                                            compensation_index,
                                        );
                                        break :rollback_compensations;
                                    }
                                },
                                .not_started => {
                                    failed_compensation = @intCast(
                                        compensation_index,
                                    );
                                    break :rollback_compensations;
                                },
                                .recovery_required => return .{
                                    .outcome = .recovery_required,
                                    .detail = "rollback_compensation_unknown",
                                    .program_sha256 = program.digest_sha256,
                                },
                            }
                        }
                    }
                    if (failed_compensation) |failed_index| {
                        const compensation =
                            hook_context.script.call.failure.compensations[
                                failed_index
                            ];
                        const failed_state: package_database.CurrentState =
                            if (compensation.kind == .postinst)
                                .unpacked
                            else
                                .half_installed;
                        const failed_error: package_database.ErrorState =
                            if (compensation.kind == .postinst)
                                .ok
                            else
                                .reinst_required;
                        const action = authorization.findAction(
                            intent.package.name,
                            intent.package.architecture,
                        ) orelse return error.InvalidLifecycleProgram;
                        const result_state = try lifecycleRestoredPackageState(
                            execution,
                            allocator,
                            root,
                            external.root,
                            program,
                            authorization,
                            locks,
                            attempt,
                            operation,
                            conffile_policy,
                            initial_snapshot,
                            initial_model,
                            intent.package,
                            .install,
                            failed_error,
                            failed_state,
                            action.prior_version,
                        );
                        if (lifecycleMaterializationFailure(result_state)) |failure|
                            return failure;
                    }
                    const cleanup = try cleanupLifecycleStaging(
                        execution,
                        allocator,
                        root,
                        external.root,
                        program,
                        authorization,
                        locks,
                        attempt,
                        operation,
                        conffile_policy,
                        &staging,
                    );
                    if (lifecycleMaterializationFailure(cleanup)) |failure|
                        return failure;
                    const restored = try restoreLifecycleStatusOld(
                        execution,
                        allocator,
                        root,
                        external.root,
                        program,
                        authorization,
                        locks,
                        attempt,
                        operation,
                        conffile_policy,
                        status_old_baseline,
                    );
                    if (lifecycleMaterializationFailure(restored)) |failure|
                        return failure;
                    try clearTriggerAuthority(
                        allocator,
                        root,
                        trigger_authority_bytes,
                    );
                    if (borrowed_attempt == null or production_request != null) try finishLifecycleAttempt(
                        execution,
                        allocator,
                        root,
                        attempt,
                        program_sha256,
                        false,
                    );
                    return .{
                        .outcome = .script_failed,
                        .detail = "postrm",
                        .program_sha256 = program.digest_sha256,
                    };
                }
            }
            if (lifecycleMaterializationFailure(result)) |failure| return failure;
            if (program.trigger_authority != null) {
                const synced = try lifecycleSyncTriggerRegistry(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                );
                if (lifecycleMaterializationFailure(synced)) |failure|
                    return failure;
                const model_index = lifecycleArchiveIndex(
                    models,
                    intent.package,
                ) orelse return error.InvalidLifecycleProgram;
                const artifact = lifecycleProgramArtifact(
                    program.*,
                    intent.package,
                ) orelse return error.InvalidLifecycleProgram;
                const application = parseHex(
                    32,
                    &artifact.application_sha256,
                ) orelse return error.InvalidLifecycleProgram;
                if (!std.mem.eql(
                    u8,
                    &application,
                    &models[model_index].digest,
                )) return error.InvalidLifecycleProgram;
                try collectArchiveTriggerEvents(
                    scratch,
                    root,
                    program.target_architecture,
                    &models[model_index],
                    &trigger_events,
                );
                try persistRuntimeTriggerEvents(
                    execution,
                    scratch,
                    root,
                    trigger_events.items,
                );
            }
        },
        .configure_barrier => {
            crossed_configure_barrier = true;
        },
        .apply_conffile_decision => |decision| {
            const package = decision.package.ref();
            if (decision.action == .retain_on_remove or decision.action == .delete_on_purge) {
                const action = authorization.findAction(package.name, package.architecture) orelse
                    return error.InvalidLifecycleProgram;
                if ((decision.action == .retain_on_remove and action.kind != .remove) or
                    (decision.action == .delete_on_purge and action.kind != .purge))
                    return error.InvalidLifecycleProgram;
                // Removal and purge publish their conffiles with the matching
                // file phase; neither operation has an archive to configure.
                continue;
            }
            const key = try std.fmt.allocPrint(
                scratch,
                "{s}\x00{s}",
                .{ package.name, package.architecture },
            );
            if (!configured.contains(key)) {
                const result = try lifecycleConfigurePackage(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    models,
                    archive_bytes,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    package,
                );
                if (lifecycleMaterializationFailure(result)) |failure| return failure;
                try configured.put(allocator, key, {});
            }
        },
        .record_package_state => |state| {
            if (state.state == .half_installed or
                state.state == .half_configured)
                continue;
            if ((state.state == .installed or
                state.state == .triggers_awaited or
                state.state == .triggers_pending) and
                lifecycleProgramArtifact(program.*, state.package) != null)
            {
                const key = try std.fmt.allocPrint(
                    scratch,
                    "{s}\x00{s}",
                    .{ state.package.name, state.package.architecture },
                );
                if (!configured.contains(key)) {
                    const result = try lifecycleConfigurePackage(
                        execution,
                        allocator,
                        root,
                        external.root,
                        program,
                        authorization,
                        models,
                        archive_bytes,
                        locks,
                        attempt,
                        operation,
                        conffile_policy,
                        state.package.ref(),
                    );
                    if (lifecycleMaterializationFailure(result)) |failure|
                        return failure;
                    try configured.put(allocator, key, {});
                }
            }
            const result = try lifecycleStateStep(
                execution,
                allocator,
                root,
                external.root,
                program,
                authorization,
                locks,
                attempt,
                operation,
                conffile_policy,
                state,
                lifecyclePackageWant(
                    authorization.findAction(state.package.name, state.package.architecture),
                    state.hold,
                ),
                null,
            );
            if (lifecycleMaterializationFailure(result)) |failure| return failure;
        },
        .remove_package_files => |intent| {
            if (program.trigger_authority != null)
                try collectRemovalTriggerEvents(
                    scratch,
                    root,
                    program.target_architecture,
                    intent.package.ref(),
                    intent.owned_paths_sha256,
                    &trigger_events,
                );
            if (program.trigger_authority != null)
                try persistRuntimeTriggerEvents(
                    execution,
                    scratch,
                    root,
                    trigger_events.items,
                );
            const result = try lifecycleRemovePackage(
                execution,
                allocator,
                root,
                external.root,
                program,
                authorization,
                locks,
                attempt,
                operation,
                conffile_policy,
                intent.package.ref(),
                false,
            );
            if (lifecycleMaterializationFailure(result)) |failure| return failure;
            if (program.trigger_authority != null) {
                const synced = try lifecycleSyncTriggerRegistry(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                );
                if (lifecycleMaterializationFailure(synced)) |failure|
                    return failure;
            }
        },
        .purge_package_files => |intent| {
            const result = try lifecycleRemovePackage(
                execution,
                allocator,
                root,
                external.root,
                program,
                authorization,
                locks,
                attempt,
                operation,
                conffile_policy,
                intent.package.ref(),
                true,
            );
            if (lifecycleMaterializationFailure(result)) |failure| return failure;
            if (program.trigger_authority != null) {
                const synced = try lifecycleSyncTriggerRegistry(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                );
                if (lifecycleMaterializationFailure(synced)) |failure|
                    return failure;
            }
        },
        .run_maintainer_script => |call| {
            if (consumed_scripts.contains(step.sequence)) continue;
            const staged = try stageLifecycleScripts(
                execution,
                allocator,
                scratch,
                root,
                external.root,
                program,
                authorization,
                models,
                locks,
                attempt,
                operation,
                conffile_policy,
                call.package,
                &staging,
            );
            if (lifecycleMaterializationFailure(staged)) |failure| return failure;
            const inject_unknown = !fault_used and external.fault != null and
                std.mem.eql(
                    u8,
                    external.fault.?,
                    "after_script_before_record",
                );
            if (inject_unknown) fault_used = true;
            const outcome = try runLifecycleScript(
                execution,
                allocator,
                root,
                external.root,
                program,
                authorization,
                attempt,
                step.sequence,
                call.package,
                null,
                call.kind,
                call.source,
                call.script_sha256,
                call.arguments,
                inject_unknown,
            );
            const code = switch (outcome) {
                .recovery_required => return .{
                    .outcome = .recovery_required,
                    .detail = "script_outcome_unknown",
                    .program_sha256 = program.digest_sha256,
                },
                .exited => |value| value,
                .not_started => 255,
            };
            if (code == 0) continue;

            var unwind_succeeded = call.failure.unwind == null;
            if (call.failure.unwind) |unwind| {
                const unwind_outcome = try runLifecycleScript(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    attempt,
                    step.sequence,
                    call.package,
                    null,
                    unwind.kind,
                    unwind.source,
                    unwind.script_sha256,
                    unwind.arguments,
                    false,
                );
                unwind_succeeded = switch (unwind_outcome) {
                    .recovery_required => return .{
                        .outcome = .recovery_required,
                        .detail = "unwind_outcome_unknown",
                        .program_sha256 = program.digest_sha256,
                    },
                    .exited => |value| value == 0,
                    .not_started => false,
                };
            }

            const upgrading = call.arguments.len != 0 and
                std.mem.eql(u8, call.arguments[0], "upgrade");
            if (call.failure.resume_after_unwind and unwind_succeeded)
                continue;

            const action = authorization.findAction(
                call.package.name,
                call.package.architecture,
            );
            const prior_version = if (action) |value| value.prior_version else null;
            if (call.failure.rollback_after_compensations != null) {
                try attempt.requireRecovery(allocator, .script);
                return .{
                    .outcome = .recovery_required,
                    .detail = "rollback_boundary_missed",
                    .program_sha256 = program.digest_sha256,
                };
            }
            var failed_compensation: ?native_program.Unwind = null;
            compensations: for (call.failure.compensations) |compensation| {
                const compensation_outcome = try runLifecycleScript(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    attempt,
                    step.sequence,
                    call.package,
                    null,
                    compensation.kind,
                    compensation.source,
                    compensation.script_sha256,
                    compensation.arguments,
                    false,
                );
                switch (compensation_outcome) {
                    .exited => |compensation_code| if (compensation_code != 0) {
                        failed_compensation = compensation;
                        break :compensations;
                    },
                    .not_started => {
                        failed_compensation = compensation;
                        break :compensations;
                    },
                    .recovery_required => return .{
                        .outcome = .recovery_required,
                        .detail = "compensation_outcome_unknown",
                        .program_sha256 = program.digest_sha256,
                    },
                }
            }

            var staging_cleaned = false;
            if (upgrading and prior_version != null and
                failed_compensation != null)
            {
                const compensation = failed_compensation.?;
                const failed_state: package_database.CurrentState =
                    if (compensation.kind == .postinst)
                        .unpacked
                    else
                        .half_installed;
                const failed_error: package_database.ErrorState =
                    if (compensation.kind == .postinst)
                        .ok
                    else
                        .reinst_required;
                const result = try lifecycleRestoredPackageState(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    initial_snapshot,
                    initial_model,
                    call.package,
                    .install,
                    failed_error,
                    failed_state,
                    prior_version,
                );
                if (lifecycleMaterializationFailure(result)) |failure|
                    return failure;
            } else if (call.kind == .preinst and
                call.source == .new_package and
                call.arguments.len == 1 and
                std.mem.eql(u8, call.arguments[0], "install") and
                action != null and action.?.prior_version == null)
            {
                const cleanup = try cleanupLifecycleStaging(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    &staging,
                );
                if (lifecycleMaterializationFailure(cleanup)) |failure|
                    return failure;
                staging_cleaned = true;
                const result = try lifecycleFreshFailure(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    call.package,
                    unwind_succeeded,
                );
                if (lifecycleMaterializationFailure(result)) |failure| return failure;
            } else if (call.kind == .prerm and
                call.arguments.len != 0 and
                std.mem.eql(u8, call.arguments[0], "remove") and
                !unwind_succeeded)
            {
                const result = try lifecycleDetailedState(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    call.package,
                    .deinstall,
                    .ok,
                    .half_configured,
                    if (action) |value| value.prior_version else null,
                );
                if (lifecycleMaterializationFailure(result)) |failure| return failure;
            } else if (call.kind == .postrm and
                call.arguments.len != 0 and
                std.mem.eql(u8, call.arguments[0], "remove"))
            {
                const result = try lifecycleRestoredPackageState(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    initial_snapshot,
                    initial_model,
                    call.package,
                    lifecyclePackageWant(action, false),
                    .ok,
                    .half_installed,
                    if (action) |value| value.prior_version else null,
                );
                if (lifecycleMaterializationFailure(result)) |failure| return failure;
            } else if (call.kind == .postrm and
                call.arguments.len != 0 and
                std.mem.eql(u8, call.arguments[0], "purge"))
            {
                const result = try lifecycleDetailedState(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    call.package,
                    .purge,
                    .ok,
                    .config_files,
                    null,
                );
                if (lifecycleMaterializationFailure(result)) |failure| return failure;
            } else {
                var failure_state: native_program.StateRecord = .{
                    .package = call.package,
                    .state = call.failure.state,
                    .hold = false,
                    .remove_entry = false,
                };
                if (upgrading and prior_version != null)
                    failure_state.state = .installed;
                if (call.kind == .prerm and
                    call.arguments.len != 0 and
                    std.mem.eql(u8, call.arguments[0], "remove") and
                    unwind_succeeded)
                    failure_state.state = .installed;
                const result = try lifecycleStateStep(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    failure_state,
                    lifecyclePackageWant(action, failure_state.hold),
                    null,
                );
                if (lifecycleMaterializationFailure(result)) |failure| return failure;
            }
            if (!staging_cleaned) {
                const cleanup = try cleanupLifecycleStaging(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    &staging,
                );
                if (lifecycleMaterializationFailure(cleanup)) |failure| return failure;
            }
            if (!staging_cleaned) {
                const restored = try restoreLifecycleStatusOld(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    status_old_baseline,
                );
                if (lifecycleMaterializationFailure(restored)) |failure|
                    return failure;
            }
            try clearTriggerAuthority(
                allocator,
                root,
                trigger_authority_bytes,
            );
            if (borrowed_attempt == null or production_request != null) try finishLifecycleAttempt(
                execution,
                allocator,
                root,
                attempt,
                program_sha256,
                false,
            );
            return .{
                .outcome = .script_failed,
                .detail = @tagName(call.kind),
                .program_sha256 = program.digest_sha256,
            };
        },
        .record_trigger_interests, .activate_trigger => {
            if (program.trigger_authority == null)
                return .{
                    .outcome = .handoff,
                    .detail = "trigger",
                    .program_sha256 = program.digest_sha256,
                };
        },
        .process_deferred_triggers => {
            if (program.trigger_authority == null)
                return .{
                    .outcome = .handoff,
                    .detail = "trigger",
                    .program_sha256 = program.digest_sha256,
                };
            if (program.trigger_authority.?.defer_triggers) {
                const incorporated = try lifecycleIncorporateTriggerQueue(
                    execution,
                    allocator,
                    root,
                    external.root,
                    program,
                    authorization,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    scratch,
                    &trigger_events,
                    false,
                    initial_model.triggers.pending,
                );
                if (lifecycleMaterializationFailure(incorporated)) |failure|
                    return failure;
                const derived = try lifecyclePublishDerivedFinalState(
                    execution,
                    allocator,
                    scratch,
                    root,
                    external.root,
                    program,
                    authorization,
                    initial_model,
                    locks,
                    attempt,
                    operation,
                    conffile_policy,
                    trigger_events.items,
                );
                if (lifecycleMaterializationFailure(derived)) |failure|
                    return failure;
                continue;
            }
            const applied_events = try lifecycleApplyTriggerEvents(
                execution,
                allocator,
                root,
                external.root,
                program,
                authorization,
                locks,
                attempt,
                operation,
                conffile_policy,
                trigger_events.items,
                false,
            );
            if (lifecycleMaterializationFailure(applied_events)) |failure|
                return failure;
            const trigger_result = try lifecycleProcessTriggers(
                execution,
                allocator,
                scratch,
                &trigger_events,
                root,
                external.root,
                program,
                authorization,
                locks,
                attempt,
                operation,
                conffile_policy,
                step.sequence,
                external.fault != null and std.mem.eql(
                    u8,
                    external.fault.?,
                    "after_triggered_postinst_before_record",
                ),
            );
            switch (trigger_result.outcome) {
                .applied => {},
                .recovery_required => return trigger_result,
                .trigger_failed => {
                    const cleanup = try cleanupLifecycleStaging(
                        execution,
                        allocator,
                        root,
                        external.root,
                        program,
                        authorization,
                        locks,
                        attempt,
                        operation,
                        conffile_policy,
                        &staging,
                    );
                    if (lifecycleMaterializationFailure(cleanup)) |failure|
                        return failure;
                    const restored = try restoreLifecycleStatusOld(
                        execution,
                        allocator,
                        root,
                        external.root,
                        program,
                        authorization,
                        locks,
                        attempt,
                        operation,
                        conffile_policy,
                        status_old_baseline,
                    );
                    if (lifecycleMaterializationFailure(restored)) |failure|
                        return failure;
                    try clearTriggerAuthority(
                        allocator,
                        root,
                        trigger_authority_bytes,
                    );
                    if (borrowed_attempt == null or production_request != null) try finishLifecycleAttempt(
                        execution,
                        allocator,
                        root,
                        attempt,
                        program_sha256,
                        false,
                    );
                    return trigger_result;
                },
                .script_failed, .handoff, .refused => return trigger_result,
            }
        },
    };

    const cleanup = try cleanupLifecycleStaging(
        execution,
        allocator,
        root,
        external.root,
        program,
        authorization,
        locks,
        attempt,
        operation,
        conffile_policy,
        &staging,
    );
    if (lifecycleMaterializationFailure(cleanup)) |failure| return failure;
    const restored = try restoreLifecycleStatusOld(
        execution,
        allocator,
        root,
        external.root,
        program,
        authorization,
        locks,
        attempt,
        operation,
        conffile_policy,
        status_old_baseline,
    );
    if (lifecycleMaterializationFailure(restored)) |failure| return failure;
    const expected_final_state =
        if (program.trigger_authority) |trigger|
            if (trigger.final_mode == .derive_from_activations)
                deriveDeferredFinalState(
                    scratch,
                    authorization.*,
                    initial_model,
                    trigger_events.items,
                ) catch {
                    try attempt.requireRecovery(allocator, .verification);
                    return .{
                        .outcome = .recovery_required,
                        .detail = "derived_final_state_failed",
                        .program_sha256 = program.digest_sha256,
                    };
                }
            else
                authorization.final_state
        else
            authorization.final_state;
    const closure_matches = verifyLifecycleFinalClosure(
        allocator,
        root,
        program.target_architecture,
        expected_final_state,
    ) catch {
        try attempt.requireRecovery(allocator, .verification);
        return .{
            .outcome = .recovery_required,
            .detail = "final_closure_verification_failed",
            .program_sha256 = program.digest_sha256,
        };
    };
    if (!closure_matches) {
        try attempt.requireRecovery(allocator, .verification);
        return .{
            .outcome = .recovery_required,
            .detail = "final_closure_mismatch",
            .program_sha256 = program.digest_sha256,
        };
    }
    try clearTriggerAuthority(
        allocator,
        root,
        trigger_authority_bytes,
    );
    if (borrowed_attempt == null or production_request != null) try finishLifecycleAttempt(
        execution,
        allocator,
        root,
        attempt,
        program_sha256,
        true,
    );
    return .{
        .outcome = .applied,
        .detail = "completed",
        .program_sha256 = program.digest_sha256,
    };
}

fn readAbsoluteFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(
        allocator,
        .limited(maximum_bytes +| 1),
    ) catch |err| switch (err) {
        error.StreamTooLong => error.FileTooLarge,
        error.ReadFailed => reader.err.?,
        else => |other| other,
    };
}

fn writeMaterializationReport(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    result: MaterializationResult,
) !void {
    const bytes = try std.fmt.allocPrint(
        allocator,
        "{{\"outcome\":\"{s}\",\"detail\":\"{s}\"}}\n",
        .{ @tagName(result.outcome), result.detail },
    );
    defer allocator.free(bytes);
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{
        .truncate = true,
    });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    try file.sync(io);
}

fn writeLifecycleReport(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    result: LifecycleResult,
) !void {
    const Wire = struct {
        outcome: []const u8,
        detail: []const u8,
        program_sha256: ?[]const u8,
    };
    const ProvenanceWire = struct {
        outcome: []const u8,
        detail: []const u8,
        program_sha256: []const u8,
        attempt_id: []const u8,
        provenance_path: []const u8,
    };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    if (result.provenance_path) |provenance_path| {
        const program_sha256 = result.program_sha256 orelse
            return error.InvalidRecoveryProvenance;
        const attempt_id = result.attempt_id orelse
            return error.InvalidRecoveryProvenance;
        try std.json.Stringify.value(
            ProvenanceWire{
                .outcome = @tagName(result.outcome),
                .detail = result.detail,
                .program_sha256 = &program_sha256,
                .attempt_id = &attempt_id,
                .provenance_path = provenance_path,
            },
            .{ .whitespace = .minified },
            &output.writer,
        );
    } else try std.json.Stringify.value(
        Wire{
            .outcome = @tagName(result.outcome),
            .detail = result.detail,
            .program_sha256 = if (result.program_sha256) |*digest| digest else null,
        },
        .{ .whitespace = .minified },
        &output.writer,
    );
    try output.writer.writeByte('\n');
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, output.written());
    try file.sync(io);
}

fn attachLifecycleProvenance(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    result: *LifecycleResult,
) !void {
    var owned = try native_provenance.read(allocator, root) orelse return;
    defer owned.deinit();
    const operation_store: root_operation.Store = .init(root);
    if (try operation_store.read(allocator)) |active_value| {
        var active = active_value;
        defer active.deinit();
        const provenance_attempt = native_recovery.parseDigest(
            owned.document.attempt_id,
        ) orelse return error.InvalidRecoveryProvenance;
        if (!std.mem.eql(
            u8,
            &provenance_attempt,
            &active.record.attempt_id,
        )) return;
    }
    result.attempt_id = owned.document.attempt_id;
    result.provenance_path = native_provenance.document_path;
    if (result.program_sha256 == null)
        result.program_sha256 = owned.document.program_sha256;
}

fn externalProductOperation(value: ExternalMaterializationOperation) product_api.Operation {
    return switch (value) {
        .install, .downgrade => .install,
        .upgrade => .upgrade,
        .reinstall => .reinstall,
        .configure, .process_triggers => .install,
        .remove, .purge => .remove,
        .recover => unreachable,
    };
}

test "native_recovery.test.native_provenance.test.contract coverage" {
    try native_recovery.testContracts();
    try native_provenance.testContract();
}

test "native_unpack.test.materialization external fixture" {
    const raw_request = std.c.getenv("DEBZ_NATIVE_MATERIALIZATION_REQUEST") orelse
        return error.SkipZigTest;
    const request_path = std.mem.span(raw_request);
    if (!absolute_path.nonRoot(request_path))
        return error.InvalidExternalMaterializationRequest;
    const request_bytes = try readAbsoluteFile(
        testing.allocator,
        testing.io,
        request_path,
        1024 * 1024,
    );
    defer testing.allocator.free(request_bytes);
    var parsed = try std.json.parseFromSlice(
        ExternalMaterializationRequest,
        testing.allocator,
        request_bytes,
        .{ .ignore_unknown_fields = false },
    );
    defer parsed.deinit();
    const external = parsed.value;
    const archive_phase = switch (external.operation) {
        .install, .upgrade, .downgrade, .reinstall, .configure => true,
        .remove, .purge, .process_triggers, .recover => false,
    };
    if (!absolute_path.nonRoot(external.root) or
        !absolute_path.nonRoot(external.report) or
        (archive_phase != (external.archives.len != 0)) or
        ((external.operation == .remove or external.operation == .purge) and
            external.packages.len == 0) or
        (external.operation == .process_triggers or external.operation == .recover) or
        (!std.mem.eql(u8, external.architecture, "amd64") and
            !std.mem.eql(u8, external.architecture, "arm64")))
        return error.InvalidExternalMaterializationRequest;
    for (external.archives) |path| {
        if (!absolute_path.nonRoot(path))
            return error.InvalidExternalMaterializationRequest;
    }

    var root_dir = try std.Io.Dir.openDirAbsolute(testing.io, external.root, .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer root_dir.close(testing.io);
    const root: root_fs.Root = .init(testing.io, root_dir);
    const marker = try root.readFileAlloc(
        testing.allocator,
        try root_fs.Path.init(".debz-native-disposable"),
        128,
    );
    defer testing.allocator.free(marker);
    if (!std.mem.eql(
        u8,
        marker,
        "debz native materialization fixture v1\n",
    )) return error.InvalidExternalMaterializationRequest;

    var captured = try captureDatabaseSnapshot(
        testing.allocator,
        root,
        .{},
    );
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(
        &captured.snapshot,
        external.architecture,
    );
    var database = switch (try package_database.importSnapshot(
        testing.allocator,
        .{
            .native_architecture = external.architecture,
            .snapshot = captured.snapshot,
        },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return error.InvalidExternalDatabase,
    };
    defer database.deinit();

    const archive_bytes = try testing.allocator.alloc(
        []u8,
        external.archives.len,
    );
    defer testing.allocator.free(archive_bytes);
    const models = try testing.allocator.alloc(
        archive_application.Model,
        external.archives.len,
    );
    defer testing.allocator.free(models);
    var initialized: usize = 0;
    defer {
        for (models[0..initialized]) |*model| model.deinit();
        for (archive_bytes[0..initialized]) |bytes|
            testing.allocator.free(bytes);
    }
    var total_archive_bytes: u64 = 0;
    for (external.archives, 0..) |path, index| {
        const bytes = try readAbsoluteFile(
            testing.allocator,
            testing.io,
            path,
            1024 * 1024 * 1024,
        );
        errdefer testing.allocator.free(bytes);
        archive_bytes[index] = bytes;
        total_archive_bytes = try std.math.add(u64, total_archive_bytes, bytes.len);
        if (total_archive_bytes > (Limits{}).max_archive_bytes)
            return error.FileTooLarge;
        var model = switch (archive_application.prepare(
            testing.allocator,
            bytes,
            .{ .local = .{} },
            .{},
        )) {
            .model => |value| value,
            .diagnostic => return error.InvalidExternalArchive,
        };
        errdefer model.deinit();
        models[index] = model;
        initialized += 1;
    }

    const artifacts = try testing.allocator.alloc(
        native_program.ProgramArtifact,
        models.len,
    );
    defer testing.allocator.free(artifacts);
    const steps = try testing.allocator.alloc(native_program.Step, models.len);
    defer testing.allocator.free(steps);
    const archives = try testing.allocator.alloc(ArchiveInput, models.len);
    defer testing.allocator.free(archives);
    for (models, 0..) |*model, index| {
        const artifact: u32 = @intCast(index);
        artifacts[index] = testArtifact(
            artifact,
            model,
            archive_bytes[index].len,
        );
        const prior = database.model.find(
            model.facts.package,
            model.facts.architecture,
        );
        const incoming_version = try version_module.DebianVersion.parse(
            model.facts.version,
        );
        switch (external.operation) {
            .install => if (prior != null)
                return error.InvalidExternalOperation,
            .upgrade => {
                const installed = prior orelse return error.InvalidExternalOperation;
                if (installed.parsed_version.order(incoming_version) != .lt)
                    return error.InvalidExternalOperation;
            },
            .downgrade => {
                const installed = prior orelse return error.InvalidExternalOperation;
                if (installed.parsed_version.order(incoming_version) != .gt)
                    return error.InvalidExternalOperation;
            },
            .reinstall => {
                const installed = prior orelse return error.InvalidExternalOperation;
                if (installed.parsed_version.order(incoming_version) != .eq)
                    return error.InvalidExternalOperation;
            },
            .configure => {
                const installed = prior orelse return error.InvalidExternalOperation;
                if (installed.status.current != .unpacked or
                    installed.parsed_version.order(incoming_version) != .eq)
                    return error.InvalidExternalOperation;
            },
            .remove, .purge, .process_triggers, .recover => unreachable,
        }
        steps[index] = unpackStep(
            artifact,
            model,
            artifact,
            if (prior) |record| record.version else null,
            false,
        );
        archives[index] = .{ .artifact = artifact, .bytes = archive_bytes[index] };
    }
    var program = testProgram(
        database.generation.sha256,
        database.model.packages.len,
        artifacts,
        steps,
    );
    const root_identity = transaction_recovery.rootIdentity(external.root);
    program.install_root = external.root;
    program.root_identity_sha256 = hex(32, root_identity);
    program.target_architecture = external.architecture;
    program.foreign_architectures = database.model.foreign_architectures;
    program.policy.conffile = switch (external.policy) {
        .keep_existing => .keep_existing,
        .use_package_version => .use_package_version,
    };
    finalizeFixtureProgram(&program);
    var locks: root_operation.SystemLockBackend = .{
        .allocator = testing.allocator,
        .io = testing.io,
    };
    const phase_request: MaterializationRequest = .{
        .io = testing.io,
        .root = root,
        .install_root = external.root,
        .planning = .{
            .program = &program,
            .snapshot = captured.snapshot,
            .archives = archives,
            .root = root,
            .root_identity_sha256 = root_identity,
            .interoperability = .isolated_root,
            .conffiles = if (external.conffiles) .unpack else .handoff,
            .conffile_policy = switch (external.policy) {
                .keep_existing => .keep_existing,
                .use_package_version => .use_package_version,
            },
        },
        .locks = locks.interface(),
        .operation = externalProductOperation(external.operation),
    };
    const result = switch (external.operation) {
        .configure => materializeConfigure(
            testing.allocator,
            phase_request,
        ) catch |err| switch (err) {
            error.UnsupportedConffile,
            error.ConffileArtifactCollision,
            error.ConffileObservationLimit,
            => MaterializationResult{
                .outcome = .refused,
                .detail = @errorName(err),
            },
            else => return err,
        },
        .remove, .purge => materializeRemoval(
            testing.allocator,
            phase_request,
            external.packages,
            external.operation == .purge,
        ) catch |err| switch (err) {
            error.UnsupportedConffile,
            error.ConffileArtifactCollision,
            error.ConffileObservationLimit,
            => MaterializationResult{
                .outcome = .refused,
                .detail = @errorName(err),
            },
            else => return err,
        },
        else => try materialize(testing.allocator, phase_request),
    };
    try writeMaterializationReport(
        testing.allocator,
        testing.io,
        external.report,
        result,
    );
}

/// dpkg still rotates `status` into `status-old` when remove or purge names no
/// present package. Authorization v1 cannot encode an action for an absent
/// identity, so this bounded path performs only that database bookkeeping and
/// cannot run scripts or touch package-owned data.
fn applyAbsentLifecycleNoOp(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: root_fs.Root,
    install_root: []const u8,
    architecture: []const u8,
    request_bytes: []const u8,
    selections: []const ExternalPackageSelection,
) !LifecycleResult {
    var digest: [32]u8 = undefined;
    Sha256.hash(request_bytes, &digest, .{});
    var locks: root_operation.SystemLockBackend = .{
        .allocator = allocator,
        .io = io,
    };
    var coordinator = try root_operation.Coordinator.open(
        io,
        root,
        install_root,
        locks.interface(),
    );
    var attempt = coordinator.acquire(allocator, .{
        .intent = .mutation,
        .existing = .reclaim_resolved,
        .backend = .native,
        .operation = .{ .package_transaction = .remove },
        .request_sha256 = digest,
        .policy_sha256 = digest,
        .target_architecture = architecture,
    }) catch |err| switch (err) {
        error.RecoveryRequired,
        error.OperationInProgress,
        error.ProvenancePending,
        => return .{ .outcome = .recovery_required, .detail = @errorName(err) },
        else => return err,
    };
    defer attempt.release();

    var captured = captureDatabaseSnapshot(allocator, root, .{}) catch |err| {
        try attempt.abandonIfPreMutation(allocator);
        return err;
    };
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, architecture);
    var database = switch (try package_database.importSnapshot(
        allocator,
        .{
            .native_architecture = architecture,
            .snapshot = captured.snapshot,
        },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => {
            try attempt.abandonIfPreMutation(allocator);
            return .{ .outcome = .refused, .detail = "locked_database_rejected" };
        },
    };
    defer database.deinit();
    for (selections) |selection| {
        if (database.model.find(selection.name, selection.architecture) != null) {
            try attempt.abandonIfPreMutation(allocator);
            return .{ .outcome = .refused, .detail = "absent_package_changed" };
        }
    }

    const status_old_path = package_database.database_directory ++ "/" ++
        package_database.status_old_path;
    const old = try root.entryIfExists(try root_fs.Path.init(status_old_path));
    var status_sha256: [32]u8 = undefined;
    Sha256.hash(captured.snapshot.status.bytes, &status_sha256, .{});
    const intent = [_]root_mutation.Intent{.{ .file = .{
        .path = status_old_path,
        .bytes = captured.snapshot.status.bytes,
        .mode = if (old) |entry| entry.mode else 0o644,
        .uid = if (old) |entry| entry.uid else 0,
        .gid = if (old) |entry| entry.gid else 0,
        .overwrite = if (old == null) .require_absent else .replace,
        .expected_sha256 = status_sha256,
    } }};
    var mutation_plan = switch (try root_mutation.preflight(
        allocator,
        root,
        .{ .intents = &intent },
    )) {
        .plan => |value| value,
        .diagnostic => {
            try attempt.abandonIfPreMutation(allocator);
            return .{ .outcome = .refused, .detail = "no_op_preflight_rejected" };
        },
    };
    defer mutation_plan.deinit();
    var engine = try root_mutation.prepare(
        allocator,
        root,
        &attempt,
        &mutation_plan,
        .{
            .plan_sha256 = mutation_plan.steps_sha256,
            .database_generation_sha256 = database.generation.sha256,
        },
        .{},
    );
    defer engine.deinit();
    const report = try root_mutation.apply(&engine, .fromPlan(&mutation_plan));
    if (report.outcome == .recovery_required)
        return .{ .outcome = .recovery_required, .detail = "no_op_recovery_required" };
    if (report.outcome != .applied)
        return .{ .outcome = .refused, .detail = "no_op_rolled_back" };
    try attempt.advance(allocator, .{
        .state = .verifying,
        .phase = .verification,
    });
    try attempt.complete(allocator, .succeeded);
    try attempt.publishProvenance(allocator, mutation_plan.steps_sha256);
    try root_mutation.clear(&engine);
    try attempt.clear();
    return .{ .outcome = .applied, .detail = "already_absent" };
}

test "native_unpack.test.lifecycle detects stale post-compilation database generation" {
    const compiled_generation: [32]u8 = @splat(0x41);
    const program = testProgram(compiled_generation, 2, &.{}, &.{});
    const matching: package_database.Generation = .{
        .sha256 = compiled_generation,
        .file_count = 7,
        .total_bytes = 1024,
    };
    try testing.expect(lifecycleDatabaseMatchesProgram(program, matching, 2));

    var stale = matching;
    stale.sha256[0] ^= 1;
    try testing.expect(!lifecycleDatabaseMatchesProgram(program, stale, 2));
    try testing.expect(!lifecycleDatabaseMatchesProgram(program, matching, 3));
}

test "native_unpack.test.trigger authority binds old and new scripts of every kind" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const installed_scripts = [_]native_program.InstalledScript{
        .{ .kind = .preinst, .sha256 = @splat(0x11) },
        .{ .kind = .postinst, .sha256 = @splat(0x12) },
        .{ .kind = .prerm, .sha256 = @splat(0x13) },
        .{ .kind = .postrm, .sha256 = @splat(0x14) },
    };
    const archive_scripts = [_]native_program.ArchiveScript{
        .{ .kind = .preinst, .sha256 = @splat(0x21) },
        .{ .kind = .postinst, .sha256 = @splat(0x22) },
        .{ .kind = .prerm, .sha256 = @splat(0x23) },
        .{ .kind = .postrm, .sha256 = @splat(0x24) },
    };
    const installed_triggers = [_]native_program.TriggerDeclaration{.{
        .kind = .interest_noawait,
        .name = "debz-trigger",
    }};
    const archive_triggers = [_]native_program.TriggerDeclaration{.{
        .kind = .interest_await,
        .name = "debz-trigger",
    }};
    const installed = [_]native_program.InstalledPackage{.{
        .name = "demo",
        .version = "1",
        .architecture = "amd64",
        .state = .installed,
        .scripts = &installed_scripts,
        .triggers = &installed_triggers,
    }};
    const archives = [_]native_program.Archive{.{
        .package = "demo",
        .version = "2",
        .architecture = "amd64",
        .sha256 = @splat(0x31),
        .size = 1,
        .origin = .{ .authenticated_repository = .{
            .repository_id = @splat('0'),
            .repository_snapshot_sha256 = @splat(0x32),
        } },
        .application_sha256 = @splat(0x33),
        .scripts = &archive_scripts,
        .triggers = &archive_triggers,
    }};
    var database_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer database_arena.deinit();
    const database: package_database.Database = .{
        .model = .{
            .native_architecture = "amd64",
            .status = .{ .sha256 = @splat(0), .size = 0, .package_count = 0 },
            .packages = &.{},
        },
        .generation = .{ .sha256 = @splat(0), .file_count = 0, .total_bytes = 0 },
        .arena = &database_arena,
        .backing_allocator = testing.allocator,
    };
    const authority = (try lifecycleTriggerAuthority(
        allocator,
        .{ .enabled = true },
        database,
        &installed,
        &archives,
        &.{.{
            .name = "demo",
            .version = "2",
            .architecture = "amd64",
            .state = .installed,
            .dpkg_selection_hold = false,
        }},
    )).?;
    try testing.expectEqual(@as(usize, 8), authority.callers.len);
    for (std.enums.values(maintainer_script.Kind)) |kind| {
        var old_seen = false;
        var new_seen = false;
        for (authority.callers) |caller| {
            if (caller.kind != kind) continue;
            if (caller.source == .installed_package and
                std.mem.eql(u8, caller.version, "1"))
                old_seen = true;
            if (caller.source == .new_package and
                std.mem.eql(u8, caller.version, "2"))
                new_seen = true;
        }
        try testing.expect(old_seen and new_seen);
    }
    try testing.expectEqual(@as(usize, 1), authority.handlers.len);
    try testing.expectEqual(
        native_authorization.TriggerScriptSource.new_package,
        authority.handlers[0].source,
    );
}

test "native_unpack.test.derived trigger closure rejects missing reordered and unrelated changes" {
    const final_state = [_]native_authorization.FinalPackage{
        .{
            .name = "receiver",
            .version = "1",
            .architecture = "amd64",
            .state = .installed,
            .dpkg_selection_hold = false,
        },
        .{
            .name = "source",
            .version = "1",
            .architecture = "amd64",
            .state = .installed,
            .dpkg_selection_hold = false,
        },
    };
    const actions = [_]native_authorization.Action{.{
        .sequence = 0,
        .kind = .install,
        .package = "source",
        .version = "1",
        .architecture = "amd64",
        .prior_version = null,
        .artifact = null,
    }};
    const handlers = [_]native_authorization.TriggerHandler{.{
        .package = "receiver",
        .version = "1",
        .architecture = "amd64",
        .source = .installed_package,
        .postinst_sha256 = @splat(0x11),
        .declarations_sha256 = @splat(0x12),
    }};
    const callers = [_]native_authorization.TriggerCaller{.{
        .package = "source",
        .version = "1",
        .architecture = "amd64",
        .source = .new_package,
        .kind = .postinst,
        .script_sha256 = @splat(0x13),
    }};
    const base_digest = native_authorization.finalStateDigest(&final_state);
    const authorization: native_authorization.Authorization = .{
        .backend = .native,
        .target_architecture = "amd64",
        .foreign_architectures = &.{},
        .install_root = "/srv/root",
        .root_identity_sha256 = @splat(0),
        .request_sha256 = @splat(0),
        .solver_policy_sha256 = @splat(0),
        .executor_policy_sha256 = @splat(0),
        .plan_sha256 = @splat(0),
        .exact_lock = .{
            .schema = exact_lock_v2.schema_id,
            .version = exact_lock_v2.schema_version,
            .digest_sha256 = @splat(0),
        },
        .policy = .{ .conffile = .keep_existing, .force = &.{}, .allow_host_root = false },
        .actions = &actions,
        .final_state = &final_state,
        .trigger_authority = .{
            .mode = .transaction,
            .defer_triggers = true,
            .initial_state_sha256 = @splat(0),
            .handlers = &handlers,
            .callers = &callers,
            .allowed_triggers = &.{ "debz-a", "debz-b" },
            .maximum_invocations = 8,
            .final_mode = .derive_from_activations,
            .base_final_state_sha256 = base_digest,
            .maximum_activations = 8,
        },
        .final_state_sha256 = base_digest,
        .digest_sha256 = @splat(0),
    };
    const listeners = [_]package_database.TriggerInterest{.{
        .trigger = "debz-a",
        .package = .{ .name = "receiver", .architecture = "" },
        .await_mode = .awaited,
    }};
    const second_listeners = [_]package_database.TriggerInterest{.{
        .trigger = "debz-b",
        .package = .{ .name = "receiver", .architecture = "" },
        .await_mode = .awaited,
    }};
    const events = [_]RuntimeTriggerEvent{
        .{
            .origin = .automatic,
            .source = .{ .name = "source", .architecture = "amd64" },
            .trigger = "debz-a",
            .activation_awaits = true,
            .listeners = &listeners,
        },
        .{
            .origin = .automatic,
            .source = .{ .name = "source", .architecture = "amd64" },
            .trigger = "debz-b",
            .activation_awaits = true,
            .listeners = &second_listeners,
        },
    };
    const initial_model: package_database.Model = .{
        .native_architecture = "amd64",
        .status = .{ .sha256 = @splat(0), .size = 0, .package_count = 0 },
        .packages = &.{},
    };
    var tampered = authorization;
    tampered.trigger_authority.?.base_final_state_sha256.?[0] ^= 1;
    try testing.expectError(
        error.InvalidTriggerAuthority,
        deriveDeferredFinalState(
            testing.allocator,
            tampered,
            initial_model,
            &events,
        ),
    );
    tampered = authorization;
    tampered.trigger_authority.?.final_mode = .exact;
    try testing.expectError(
        error.InvalidTriggerAuthority,
        deriveDeferredFinalState(
            testing.allocator,
            tampered,
            initial_model,
            &events,
        ),
    );
    tampered = authorization;
    tampered.trigger_authority.?.maximum_activations = 1;
    try testing.expectError(
        error.InvalidTriggerAuthority,
        deriveDeferredFinalState(
            testing.allocator,
            tampered,
            initial_model,
            &events,
        ),
    );
    var derived_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer derived_arena.deinit();
    const expected = try deriveDeferredFinalState(
        derived_arena.allocator(),
        authorization,
        initial_model,
        &events,
    );
    try testing.expectEqualStrings("debz-b", expected[0].triggers_pending[0]);
    try testing.expectEqualStrings("debz-a", expected[0].triggers_pending[1]);
    try testing.expectEqualStrings(
        "receiver",
        expected[1].triggers_awaited[0],
    );

    const Record = struct {
        fn make(
            name: []const u8,
            version: []const u8,
            state: package_database.CurrentState,
            pending: []const []const u8,
            awaited: []const []const u8,
        ) !package_database.PackageRecord {
            return .{
                .name = name,
                .architecture = "amd64",
                .version = version,
                .parsed_version = try version_module.DebianVersion.parse(version),
                .status = .{ .want = .install, .error_state = .ok, .current = state },
                .multi_arch = null,
                .essential = false,
                .protected = false,
                .fields = &.{},
                .conffiles = &.{},
                .triggers_pending = pending,
                .triggers_awaited = awaited,
                .info_stem = name,
                .paths = &.{},
                .md5sums = null,
                .declared_conffiles = null,
                .trigger_declarations = null,
                .scripts = &.{},
            };
        }
    };
    var receiver = try Record.make(
        "receiver",
        "1",
        .triggers_pending,
        expected[0].triggers_pending,
        &.{},
    );
    var source = try Record.make(
        "source",
        "1",
        .triggers_awaited,
        &.{},
        expected[1].triggers_awaited,
    );
    try testing.expect(lifecycleFinalPackageMatches(expected[0], receiver));
    try testing.expect(lifecycleFinalPackageMatches(expected[1], source));
    receiver.triggers_pending = &.{ "debz-a", "debz-b" };
    try testing.expect(!lifecycleFinalPackageMatches(expected[0], receiver));
    receiver.triggers_pending = &.{"debz-b"};
    try testing.expect(!lifecycleFinalPackageMatches(expected[0], receiver));
    source.triggers_awaited = &.{ "receiver", "extra" };
    try testing.expect(!lifecycleFinalPackageMatches(expected[1], source));
    source.triggers_awaited = expected[1].triggers_awaited;
    source.version = "9";
    try testing.expect(!lifecycleFinalPackageMatches(expected[1], source));
}

fn typedRuntimeFixtureResult(report: Runtime.Report) LifecycleResult {
    return .{
        .outcome = switch (report.outcome) {
            .succeeded => .applied,
            .failed => .script_failed,
            .recovery_required => .recovery_required,
            .refused => .refused,
        },
        .detail = report.detail,
        .program_sha256 = report.program_sha256,
        .attempt_id = if (report.receipt) |receipt| receipt.document.attempt_id else null,
        .provenance_path = if (report.receipt != null) native_provenance.document_path else null,
    };
}

fn callerOwnedLifecycleFixture(
    root: root_fs.Root,
    external: ExternalLifecycleRequest,
    locks: root_operation.LockBackend,
    compiled: ?*CompiledLifecycle,
    archive_bytes: []const []const u8,
    raw_request: []const u8,
) !LifecycleResult {
    const allocator = testing.allocator;
    var coordinator = try root_operation.Coordinator.open(root.io, root, external.root, locks);
    if (external.operation == .recover) {
        var previous = try coordinator.inspect(allocator) orelse return error.RecoveryEvidenceMissing;
        defer previous.deinit();
        const record = previous.record;
        var attempt = try coordinator.acquire(allocator, .{
            .intent = .recovery,
            .backend = .native,
            .operation = record.operation,
            .request_sha256 = record.request_sha256,
            .policy_sha256 = record.policy_sha256,
            .target_architecture = record.target_architecture,
            .foreign_architectures = record.foreign_architectures,
            .evidence = record.evidence(),
        });
        defer attempt.release();
        const result = if (external.isolated_helper) block: {
            var report = try Runtime.recover(allocator, &attempt);
            defer report.deinit();
            break :block typedRuntimeFixtureResult(report);
        } else try recoverPreparedNativeProgramWithHelper(
            allocator,
            root,
            &attempt,
            locks,
            null,
            null,
        );
        if (external.acknowledge_native) {
            var receipt = (if (external.isolated_helper)
                try Runtime.readCompletion(allocator, &attempt)
            else
                try readProductionCompletion(allocator, root, &attempt)) orelse
                return error.RecoveryEvidenceMissing;
            defer receipt.deinit();
            if (external.isolated_helper) {
                try testing.expectError(error.InvalidRecoveryProvenance, Runtime.acknowledge(allocator, &attempt, @splat('0')));
                try testing.expect(try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) != null);
                try Runtime.acknowledge(allocator, &attempt, receipt.document.digest_sha256);
                try Runtime.acknowledge(allocator, &attempt, receipt.document.digest_sha256);
                var repeated = try Runtime.recover(allocator, &attempt);
                defer repeated.deinit();
                try testing.expectEqual(result.outcome, typedRuntimeFixtureResult(repeated).outcome);
                try testing.expect(attempt.locked());
                try testing.expectEqual(root_operation.Outcome.pending, attempt.record().outcome);
            } else try acknowledgePreparedNativeProgram(allocator, root, &attempt, receipt.document.digest_sha256);
            if (attempt.record().state != .recovering)
                try attempt.advance(allocator, .{ .state = .verifying, .phase = .verification });
            try attempt.complete(allocator, if (receipt.document.outcome == .succeeded) .succeeded else .failed_after_mutation);
            var completion = try root_operation_completion.create(allocator, .{
                .record = attempt.record(),
                .transaction_provenance = .{
                    .status = .already_present,
                    .schema = native_provenance.schema_id,
                    .document_sha256 = native_recovery.parseDigest(receipt.document.digest_sha256).?,
                    .detail = "caller-acknowledged native fixture",
                },
                .journal = .{ .status = .absent, .detail = "native phases completed" },
                .discharge = .{
                    .surface = .repository_bootstrap,
                    .operation = "add",
                    .request_sha256 = attempt.record().request_sha256,
                },
            });
            defer completion.deinit();
            const store: root_operation_completion.Store = .init(root);
            try store.publish(allocator, completion.document);
            try attempt.publishProvenance(allocator, completion.document.digest_sha256);
            try attempt.clear();
        }
        return result;
    }
    var caller_hash = Sha256.init(.{});
    caller_hash.update("debz-native-caller-fixture-v1\x00");
    caller_hash.update(raw_request);
    var attempt = try coordinator.acquire(allocator, .{
        .backend = .native,
        .operation = if (external.core_product)
            .{ .package_transaction = switch (external.operation) {
                .remove, .purge => .remove,
                .upgrade => .upgrade,
                .reinstall => .reinstall,
                else => .install,
            } }
        else
            .{ .repository_bootstrap = .add },
        .request_sha256 = caller_hash.finalResult(),
        .policy_sha256 = @splat(0x72),
        .target_architecture = external.architecture,
    });
    defer attempt.release();
    if (external.isolated_helper) {
        const request: Runtime.Request = .{
            .attempt = &attempt,
            .prepared = compiled.?,
            .archives = archive_bytes,
            .operation = std.meta.stringToEnum(native_recovery.Operation, @tagName(external.operation)).?,
        };
        var report = if (external.crash_at) |crash|
            try Runtime.executeWithCrash(allocator, request, crash)
        else
            try Runtime.execute(allocator, request);
        defer report.deinit();
        return typedRuntimeFixtureResult(report);
    }
    return executePreparedNativeProgramWithHelper(
        allocator,
        root,
        compiled.?,
        archive_bytes,
        &attempt,
        locks,
        std.meta.stringToEnum(native_recovery.Operation, @tagName(external.operation)).?,
        external.crash_at,
        null,
    );
}

test "native_unpack.test.lifecycle external fixture" {
    const raw_request = std.c.getenv("DEBZ_NATIVE_LIFECYCLE_REQUEST") orelse
        return error.SkipZigTest;
    const request_path = std.mem.span(raw_request);
    if (!absolute_path.nonRoot(request_path))
        return error.InvalidExternalLifecycleRequest;
    const request_bytes = try readAbsoluteFile(
        testing.allocator,
        testing.io,
        request_path,
        1024 * 1024,
    );
    defer testing.allocator.free(request_bytes);
    var parsed = try std.json.parseFromSlice(
        ExternalLifecycleRequest,
        testing.allocator,
        request_bytes,
        .{ .ignore_unknown_fields = false },
    );
    defer parsed.deinit();
    const external = parsed.value;
    if ((external.caller_owned and (!external.recovery or external.fault != null)) or
        (external.acknowledge_native and (!external.caller_owned or external.operation != .recover)) or
        (external.core_product and (!external.caller_owned or !external.isolated_helper)) or
        (external.core_completion_crash != null and (!external.core_product or external.operation != .recover)) or
        (external.isolated_helper and !external.caller_owned))
        return error.InvalidExternalLifecycleRequest;
    const archive_phase = switch (external.operation) {
        .install, .upgrade, .downgrade, .reinstall, .configure => true,
        .remove, .purge, .process_triggers, .recover => false,
    };
    if (!absolute_path.nonRoot(external.root) or
        !absolute_path.nonRoot(external.report) or
        (archive_phase != (external.archives.len != 0)) or
        ((external.operation == .remove or external.operation == .purge) and
            external.packages.len == 0) or
        (external.operation == .process_triggers and !external.triggers) or
        (!std.mem.eql(u8, external.architecture, "amd64") and
            !std.mem.eql(u8, external.architecture, "arm64")))
        return error.InvalidExternalLifecycleRequest;
    for (external.archives) |path| {
        if (!absolute_path.nonRoot(path))
            return error.InvalidExternalLifecycleRequest;
    }
    if (external.fault) |fault| {
        if (!std.mem.eql(u8, fault, "after_script_before_record") and
            !std.mem.eql(
                u8,
                fault,
                "after_upgrade_postrm_before_record",
            ) and
            !std.mem.eql(
                u8,
                fault,
                "after_triggered_postinst_before_record",
            ))
            return error.InvalidExternalLifecycleRequest;
    }

    var root_dir = try std.Io.Dir.openDirAbsolute(testing.io, external.root, .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer root_dir.close(testing.io);
    const root: root_fs.Root = .init(testing.io, root_dir);
    const marker = try root.readFileAlloc(
        testing.allocator,
        try root_fs.Path.init(".debz-native-disposable"),
        128,
    );
    defer testing.allocator.free(marker);
    if (!std.mem.eql(
        u8,
        marker,
        "debz native materialization fixture v1\n",
    )) return error.InvalidExternalLifecycleRequest;
    if (external.operation == .recover) {
        if (external.archives.len != 0 or external.packages.len != 0 or
            external.ordered_actions != null or external.fault != null)
            return error.InvalidExternalLifecycleRequest;
        if (external.core_product) {
            const product = @import("production_backend.zig");
            const api = @import("product_api.zig");
            const Crash = struct {
                point: ?product.CompletionPoint,
                fn hit(context: *anyopaque, point: product.CompletionPoint) anyerror!void {
                    const self: *@This() = @ptrCast(@alignCast(context));
                    if (self.point == point) std.process.exit(native_recovery.crash_exit_code);
                }
            };
            var crash: Crash = .{ .point = external.core_completion_crash };
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();
            var backend: product.Backend = .{
                .io = testing.io,
                .transaction_backend = .native,
                .completion_crash = .{ .context = &crash, .hitFn = Crash.hit },
            };
            const result = try api.execute(arena.allocator(), .{
                .operation = .recover,
                .options = .{
                    .install_root = external.root,
                    .cache_path = try std.fmt.allocPrint(arena.allocator(), "{s}/unused-cache", .{external.root}),
                    .state_path = try std.fmt.allocPrint(arena.allocator(), "{s}/unused-state", .{external.root}),
                    .architecture = external.architecture,
                    .assume_yes = true,
                },
            }, backend.interface());
            var report: LifecycleResult = .{
                .outcome = switch (result.exit_status) {
                    .success => .applied,
                    .transaction => .script_failed,
                    else => .recovery_required,
                },
                .detail = result.summary,
            };
            try attachLifecycleProvenance(arena.allocator(), root, &report);
            try writeLifecycleReport(testing.allocator, testing.io, external.report, report);
            return;
        }
        var recovery_locks: root_operation.SystemLockBackend = .{
            .allocator = testing.allocator,
            .io = testing.io,
        };
        var result = (if (external.caller_owned) callerOwnedLifecycleFixture(
            root,
            external,
            recovery_locks.interface(),
            null,
            &.{},
            request_bytes,
        ) else recoverLifecycleProgram(
            testing.allocator,
            root,
            external,
            recovery_locks.interface(),
        )) catch |err| LifecycleResult{
            .outcome = .recovery_required,
            .detail = @errorName(err),
        };
        try attachLifecycleProvenance(testing.allocator, root, &result);
        try writeLifecycleReport(
            testing.allocator,
            testing.io,
            external.report,
            result,
        );
        return;
    }
    if (try root.entryIfExists(
        try root_fs.Path.init(native_recovery.intent_path),
    ) != null) {
        try writeLifecycleReport(
            testing.allocator,
            testing.io,
            external.report,
            .{
                .outcome = .recovery_required,
                .detail = "native_recovery_evidence_active",
            },
        );
        return;
    }
    var inspection_locks: root_operation.SystemLockBackend = .{
        .allocator = testing.allocator,
        .io = testing.io,
    };
    const inspection_coordinator = try root_operation.Coordinator.open(
        testing.io,
        root,
        external.root,
        inspection_locks.interface(),
    );
    if (try inspection_coordinator.inspect(testing.allocator)) |value| {
        var active = value;
        defer active.deinit();
        if (active.record.state.blocksMutation()) {
            try writeLifecycleReport(
                testing.allocator,
                testing.io,
                external.report,
                .{ .outcome = .recovery_required, .detail = "active_attempt" },
            );
            return;
        }
    }

    var captured = try captureDatabaseSnapshot(testing.allocator, root, .{});
    defer captured.deinit();
    normalizeCapturedNativeArchitecture(&captured.snapshot, external.architecture);
    var database = switch (try package_database.importSnapshot(
        testing.allocator,
        .{
            .native_architecture = external.architecture,
            .snapshot = captured.snapshot,
        },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => {
            if (external.triggers) {
                try writeLifecycleReport(
                    testing.allocator,
                    testing.io,
                    external.report,
                    .{ .outcome = .refused, .detail = "database_rejected" },
                );
                return;
            }
            return error.InvalidExternalDatabase;
        },
    };
    defer database.deinit();
    if (database.model.pending_updates.len != 0 or
        (!external.triggers and
            (database.model.triggers.interests.len != 0 or
                database.model.triggers.pending.len != 0)) or
        database.model.diversions.len != 0 or
        database.model.stat_overrides.len != 0 or
        database.model.opaque_info.len != 0)
    {
        try writeLifecycleReport(
            testing.allocator,
            testing.io,
            external.report,
            .{ .outcome = .handoff, .detail = "unsupported_database_state" },
        );
        return;
    }

    const archive_bytes = try testing.allocator.alloc([]u8, external.archives.len);
    defer testing.allocator.free(archive_bytes);
    const models = try testing.allocator.alloc(
        archive_application.Model,
        external.archives.len,
    );
    defer testing.allocator.free(models);
    var initialized: usize = 0;
    defer {
        for (models[0..initialized]) |*model| model.deinit();
        for (archive_bytes[0..initialized]) |bytes|
            testing.allocator.free(bytes);
    }
    var total_archive_bytes: u64 = 0;
    for (external.archives, 0..) |path, index| {
        const bytes = try readAbsoluteFile(
            testing.allocator,
            testing.io,
            path,
            1024 * 1024 * 1024,
        );
        errdefer testing.allocator.free(bytes);
        archive_bytes[index] = bytes;
        total_archive_bytes = try std.math.add(u64, total_archive_bytes, bytes.len);
        if (total_archive_bytes > (Limits{}).max_archive_bytes)
            return error.FileTooLarge;
        var model = switch (archive_application.prepare(
            testing.allocator,
            bytes,
            .{ .local = .{} },
            .{},
        )) {
            .model => |value| value,
            .diagnostic => return error.InvalidExternalArchive,
        };
        errdefer model.deinit();
        if ((!external.triggers and model.triggers.len != 0) or
            model.metadata.len != 0 or
            model.script(.config) != null)
        {
            model.deinit();
            try writeLifecycleReport(
                testing.allocator,
                testing.io,
                external.report,
                .{ .outcome = .handoff, .detail = "unsupported_archive_metadata" },
            );
            return;
        }
        models[index] = model;
        initialized += 1;
    }

    if (external.operation == .remove) {
        var any_action = false;
        for (external.packages) |selection| {
            if (database.model.find(selection.name, selection.architecture) != null)
                any_action = true;
        }
        if (!any_action) {
            const result = try applyAbsentLifecycleNoOp(
                testing.allocator,
                testing.io,
                root,
                external.root,
                external.architecture,
                request_bytes,
                external.packages,
            );
            try writeLifecycleReport(
                testing.allocator,
                testing.io,
                external.report,
                result,
            );
            return;
        }
    }
    if (external.operation == .purge) {
        var any_action = false;
        for (external.packages) |selection| {
            if (database.model.find(selection.name, selection.architecture) != null)
                any_action = true;
        }
        if (!any_action) {
            const result = try applyAbsentLifecycleNoOp(
                testing.allocator,
                testing.io,
                root,
                external.root,
                external.architecture,
                request_bytes,
                external.packages,
            );
            try writeLifecycleReport(
                testing.allocator,
                testing.io,
                external.report,
                result,
            );
            return;
        }
    }

    var compiled = (try compileLifecycleProgram(
        testing.allocator,
        request_bytes,
        external,
        root,
        database,
        models,
        archive_bytes,
    )) orelse {
        try writeLifecycleReport(
            testing.allocator,
            testing.io,
            external.report,
            .{ .outcome = .refused, .detail = "program_compile_rejected" },
        );
        return;
    };
    defer compiled.deinit();
    var locks: root_operation.SystemLockBackend = .{
        .allocator = testing.allocator,
        .io = testing.io,
    };
    var result = (if (external.caller_owned) callerOwnedLifecycleFixture(
        root,
        external,
        locks.interface(),
        &compiled,
        archive_bytes,
        request_bytes,
    ) else executeLifecycleProgram(
        testing.allocator,
        root,
        external,
        &compiled,
        models,
        archive_bytes,
        captured.snapshot,
        database.model,
        locks.interface(),
        null,
        request_bytes,
    )) catch |err| LifecycleResult{
        .outcome = .recovery_required,
        .detail = @errorName(err),
        .program_sha256 = compiled.program.program.digest_sha256,
    };
    try attachLifecycleProvenance(testing.allocator, root, &result);
    try writeLifecycleReport(
        testing.allocator,
        testing.io,
        external.report,
        result,
    );
}

test "native_unpack.test.interleaved execution state isolates progress counters and trigger evidence" {
    var outer_fixture: Fixture = undefined;
    try outer_fixture.init(empty_status, &.{});
    defer outer_fixture.deinit();
    var inner_fixture: Fixture = undefined;
    try inner_fixture.init(empty_status, &.{});
    defer inner_fixture.deinit();
    var outer_runtime: native_recovery.Runtime = .{
        .allocator = testing.allocator,
        .root = outer_fixture.root(),
        .intent_sha256 = @splat('a'),
    };
    var inner_runtime: native_recovery.Runtime = .{
        .allocator = testing.allocator,
        .root = inner_fixture.root(),
        .intent_sha256 = @splat('b'),
    };
    for ([_]*native_recovery.Runtime{ &outer_runtime, &inner_runtime }) |runtime| {
        try runtime.root.ensureDirectory(
            try root_fs.Path.init(root_operation.namespace_path),
            root_fs.default_directory_permissions,
        );
        try native_recovery.initializeProgress(testing.allocator, runtime.root, runtime.intent_sha256);
        try native_recovery.initializeTriggerEvents(testing.allocator, runtime.root, runtime.intent_sha256);
    }
    var outer: ExecutionState = .{ .recovery = &outer_runtime };
    var inner: ExecutionState = .{ .recovery = &inner_runtime };
    const step: native_program.Step = .{
        .sequence = 7,
        .phase = .preflight,
        .requires = &.{},
        .operation = .{ .assert_root_state = .{
            .install_root = "/fixture",
            .root_identity_sha256 = @splat('c'),
            .target_architecture = "amd64",
            .foreign_architectures = &.{},
        } },
    };
    _ = beginNativeProgramStep(&outer, step);
    _ = beginNativeProgramStep(&inner, step);
    const outer_action = beginNativePhase(&outer, .filesystem).?;
    const inner_action = beginNativePhase(&inner, .filesystem).?;
    try testing.expectEqual(outer_action, inner_action);
    try outer_runtime.append(outer_action, .prepared, .none, null);
    try inner_runtime.append(inner_action, .prepared, .none, null);
    try inner_runtime.append(inner_action, .completed, .applied, null);
    try testing.expect(!try recoveredActionApplied(&outer));
    try testing.expect(try recoveredActionApplied(&inner));

    outer.script_ordinal = 4;
    outer.phase_steps = &.{};
    var next_step = step;
    next_step.sequence = 11;
    _ = beginNativeProgramStep(&inner, next_step);
    try testPreparedMixedLifecycle(false, .production);
    try testPreparedMixedLifecycle(true, .production_resume);
    try testing.expectEqual(@as(u32, 7), outer.program_step);
    try testing.expectEqual(@as(u16, 1), outer.phase_ordinal);
    try testing.expectEqual(@as(u32, 4), outer.script_ordinal);
    try testing.expectEqual(outer_action, outer.action.?);
    try testing.expect(outer.phase_steps != null);
    try testing.expectEqual(@as(u32, 11), inner.program_step);
    try testing.expectEqual(@as(u16, 0), inner.phase_ordinal);
    try testing.expectEqual(@as(u32, 0), inner.script_ordinal);
    try testing.expect(inner.phase_steps == null);
    try testing.expectEqual(nativeAction(.database, 7, 1, 0), beginNativePhase(&outer, .database).?);

    for ([_]*ExecutionState{ &outer, &inner }, [_][]const u8{ "outer", "inner" }) |execution, name| {
        try persistRuntimeTriggerEvents(execution, testing.allocator, execution.recovery.?.root, &.{.{
            .origin = .dynamic,
            .source = .{ .name = name, .architecture = "amd64" },
            .trigger = name,
            .activation_awaits = false,
            .listeners = &.{},
        }});
    }
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    for ([_]*ExecutionState{ &inner, &outer }, [_][]const u8{ "inner", "outer" }) |execution, name| {
        var events: std.ArrayList(RuntimeTriggerEvent) = .empty;
        try restoreRuntimeTriggerEvents(execution, arena.allocator(), execution.recovery.?.root, &events);
        try testing.expectEqual(@as(usize, 1), events.items.len);
        try testing.expectEqualStrings(name, events.items[0].source.name);
        try testing.expectEqualStrings(name, events.items[0].trigger);
    }
    var standalone: ExecutionState = .{};
    try testing.expect(beginNativePhase(&standalone, .filesystem) == null);
    try testing.expect(!try recoveredActionApplied(&standalone));
    try testing.expectEqual(@as(u32, 4), outer.script_ordinal);
    try testing.expect(outer.recovery == &outer_runtime);
    try testing.expect(inner.recovery == &inner_runtime);
}

test "native_unpack.test.production preparation drives a mixed install and removal program" {
    try testPreparedMixedLifecycle(false, .owned);
}

test "native_unpack.test.public runtime refuses missing helpers before package mutation" {
    try testPreparedMixedLifecycle(false, .public_missing_helper);
}

test "native_unpack.test.runtime preparation captures genuine archive and complete root evidence" {
    try testPreparedMixedLifecycle(false, .captured_preparation);
    try testPreparedMixedLifecycle(true, .captured_preparation);
}

test "native_unpack.test.public runtime requires a held native attempt and its physical named root" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var other: Fixture = undefined;
    try other.init(empty_status, &.{});
    defer other.deinit();
    var root_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
    const install_root = try fixtureInstallRoot(&fixture, &root_buffer);
    var locks: root_operation.TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var coordinator = try root_operation.Coordinator.open(testing.io, fixture.root(), install_root, locks.interface());
    var attempt = try coordinator.acquire(testing.allocator, .{
        .backend = .native,
        .operation = .{ .package_transaction = .install },
        .request_sha256 = @splat(0x11),
        .policy_sha256 = @splat(0x22),
        .target_architecture = "amd64",
    });
    defer attempt.release();
    const before = attempt.record().digest_sha256;
    try testing.expect(try Runtime.readCompletion(testing.allocator, &attempt) == null);
    var refusal = try Runtime.report(testing.allocator, &attempt, .{
        .outcome = .handoff,
        .detail = "unsupported_fixture",
    });
    defer refusal.deinit();
    try testing.expectEqual(Runtime.Outcome.refused, refusal.outcome);
    try testing.expect(refusal.receipt == null);
    coordinator.root = other.root();
    try testing.expectError(error.OperationRootMismatch, Runtime.recover(testing.allocator, &attempt));
    coordinator.root = fixture.root();
    try testing.expectEqual(before, attempt.record().digest_sha256);
    try attempt.abandonIfPreMutation(testing.allocator);
    locks.loseAll();
    try testing.expectError(error.LockLost, Runtime.recover(testing.allocator, &attempt));
}

test "native_unpack.test.public runtime refuses legacy and host-root identities without changing the attempt" {
    for ([_]bool{ false, true }) |host| {
        var fixture: Fixture = undefined;
        try fixture.init(empty_status, &.{});
        defer fixture.deinit();
        var root_buffer: [root_fs.maximum_path_bytes]u8 = undefined;
        const install_root = if (host) "/" else try fixtureInstallRoot(&fixture, &root_buffer);
        var locks: root_operation.TestLockBackend = .{ .allocator = testing.allocator };
        defer locks.deinit();
        var coordinator = try root_operation.Coordinator.open(testing.io, fixture.root(), install_root, locks.interface());
        var attempt = try coordinator.acquire(testing.allocator, .{
            .backend = if (host) .native else .legacy_dpkg,
            .operation = .{ .package_transaction = .install },
            .request_sha256 = @splat(0x11),
            .policy_sha256 = @splat(0x22),
            .target_architecture = "amd64",
        });
        defer attempt.release();
        const before = attempt.record().digest_sha256;
        try testing.expectError(
            if (host) error.HostRootNotSupported else error.OperationBackendMismatch,
            Runtime.recover(testing.allocator, &attempt),
        );
        try testing.expectEqual(before, attempt.record().digest_sha256);
        try testing.expect(attempt.locked());
        try attempt.abandonIfPreMutation(testing.allocator);
    }
}

test "native_unpack.test.production preparation drives a mixed install and purge program" {
    try testPreparedMixedLifecycle(true, .owned);
}

test "native_unpack.test.borrowed native interpreter preserves caller hashes lock and completion" {
    try testPreparedMixedLifecycle(false, .borrowed);
    try testPreparedMixedLifecycle(true, .borrowed);
}

test "native_unpack.test.production request persists distinct bindings and awaits caller acknowledgment" {
    try testPreparedMixedLifecycle(false, .production);
    try testPreparedMixedLifecycle(true, .production);
}

test "native_unpack.test.production recovery resumes persisted preparation without fixture request hashes" {
    try testPreparedMixedLifecycle(false, .production_resume);
    try testPreparedMixedLifecycle(true, .production_resume);
}

test "native_unpack.test.helper preflight refuses planned removal of its target" {
    try testPreparedMixedLifecycle(false, .helper_target_removed);
    try testPreparedMixedLifecycle(true, .helper_target_removed);
}

test "native_unpack.test.production archives are rebound by digest rather than supplied order" {
    var first_data = [_]Entry{
        .{ .path = "first-file", .content = "first\n", .mode = 0o644 },
    };
    const first_bytes = try buildOwnedArchive(.{ .package = "first" }, &first_data);
    defer testing.allocator.free(first_bytes);
    var second_data = [_]Entry{
        .{ .path = "second-file", .content = "second\n", .mode = 0o644 },
    };
    const second_bytes = try buildOwnedArchive(.{ .package = "second" }, &second_data);
    defer testing.allocator.free(second_bytes);
    var first = try modelOf(first_bytes);
    defer first.deinit();
    var second = try modelOf(second_bytes);
    defer second.deinit();
    var artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &first, first_bytes.len),
        testArtifact(1, &second, second_bytes.len),
    };
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const rebound = try productionArchives(arena.allocator(), &artifacts, &.{ second_bytes, first_bytes });
    try testing.expectEqualStrings("first", rebound.models[0].facts.package);
    try testing.expectEqualStrings("second", rebound.models[1].facts.package);
    try testing.expectEqualStrings(first_bytes, rebound.bytes[0]);
    try testing.expectEqualStrings(second_bytes, rebound.bytes[1]);
    try testing.expectError(error.RecoveryArtifactBindingMismatch, productionArchives(
        arena.allocator(),
        &artifacts,
        &.{first_bytes},
    ));
    try testing.expectError(error.RecoveryArtifactBindingMismatch, productionArchives(
        arena.allocator(),
        &artifacts,
        &.{ first_bytes, first_bytes },
    ));
    artifacts[0].application_sha256 = @splat('0');
    try testing.expectError(error.RecoveryArtifactBindingMismatch, productionArchives(
        arena.allocator(),
        &artifacts,
        &.{ first_bytes, second_bytes },
    ));
}

test "native_unpack.test.borrowed preflight refusals leave operation cleanup to the caller" {
    try testPreparedMixedLifecycle(false, .stale_database);
    try testPreparedMixedLifecycle(false, .wrong_plan);
    try testPreparedMixedLifecycle(false, .foreign_root);
    try testPreparedMixedLifecycle(false, .private_recovery);
    try testPreparedMixedLifecycle(false, .legacy_bridge);
    try testPreparedMixedLifecycle(false, .legacy_backend);
    try testPreparedMixedLifecycle(false, .wrong_architecture);
}

test "native_unpack.test.empty v2 closure drives last-package removal purge and receipt recovery" {
    try testPreparedMixedLifecycle(false, .empty_closure);
    try testPreparedMixedLifecycle(true, .empty_closure);
}

const MixedLifecycleCase = enum {
    owned,
    borrowed,
    production,
    production_resume,
    empty_closure,
    helper_target_removed,
    public_missing_helper,
    captured_preparation,
    stale_database,
    wrong_plan,
    foreign_root,
    private_recovery,
    legacy_bridge,
    legacy_backend,
    wrong_architecture,
};

fn testPreparedMixedLifecycle(purge: bool, case: MixedLifecycleCase) !void {
    const empty_closure = case == .empty_closure;
    const status = try std.fmt.allocPrint(
        testing.allocator,
        "Package: old\nStatus: install ok installed\nVersion: 2.0\nArchitecture: amd64\n" ++
            "Conffiles:\n /etc/old.conf {s}\n\n",
        .{hex(16, digestMd5("old configuration\n"))},
    );
    defer testing.allocator.free(status);
    var fixture: Fixture = undefined;
    try fixture.init(status, &.{.{
        .name = "old.list",
        .bytes = if (case == .helper_target_removed)
            "/.\n/etc\n/etc/old.conf\n/usr\n/usr/bin\n/usr/bin/dpkg-trigger\n/usr/share\n/usr/share/old\n"
        else
            "/.\n/etc\n/etc/old.conf\n/usr\n/usr/share\n/usr/share/old\n",
    }});
    defer fixture.deinit();
    const root = fixture.root();
    for ([_][]const u8{ "etc", "usr", "usr/share" }) |path|
        try root.ensureDirectory(try root_fs.Path.init(path), root_fs.default_directory_permissions);
    try root.publishFile(try root_fs.Path.init("etc/old.conf"), "old configuration\n", .{});
    try root.publishFile(try root_fs.Path.init("usr/share/old"), "old payload\n", .{});
    if (case == .helper_target_removed) {
        try root.ensureDirectory(try root_fs.Path.init("usr/bin"), root_fs.default_directory_permissions);
        try root.publishFile(try root_fs.Path.init(native_helper.target_path), "package-owned helper\n", .{});
    }

    var data = [_]Entry{
        .{ .path = "usr", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share/app", .content = "new payload\n", .mode = 0o644 },
    };
    const bytes = try buildOwnedArchive(.{ .package = "app", .version = "1.2" }, &data);
    defer testing.allocator.free(bytes);
    var models = [_]archive_application.Model{try modelOf(bytes)};
    defer models[0].deinit();
    var database = try fixture.database();
    defer database.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(0x22);
    const origin: exact_lock_v2.PackageOrigin = .{ .authenticated_repository = .{
        .repository_id = repository_id,
        .repository_snapshot_sha256 = snapshot,
    } };
    const archives: []const native_program.Archive = if (empty_closure)
        &.{}
    else
        try programArchiveEvidence(arena.allocator(), &models, &.{bytes}, &.{origin});
    var lock = try exact_lock_v2.create(testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(7),
        .policy_sha256 = @splat(8),
        .repositories = if (empty_closure) &.{} else &.{.{
            .id = repository_id,
            .snapshot_sha256 = snapshot,
            .release_sha256 = @splat(3),
            .index_sha256 = @splat(4),
            .signer_fingerprints = &.{@splat(5)},
        }},
        .local_artifacts = &.{},
        .packages = if (empty_closure) &.{} else &.{.{
            .name = "app",
            .version = "1.2",
            .architecture = "amd64",
            .origin = origin,
            .sha256 = models[0].provenance().sha256,
            .declared_size = bytes.len,
            .retention = .requested,
            .dpkg_selection_hold = false,
        }},
        .verified_origins = true,
    });
    defer lock.deinit();
    var actions = [_]solver.PlanAction{
        .{
            .kind = .install,
            .package = "app",
            .version = "1.2",
            .architecture = "amd64",
            .repository = .{ .id = repository_id, .priority = 500 },
            .sha256 = hex(32, models[0].provenance().sha256),
            .package_size = bytes.len,
            .installed_size_delta_bytes = 0,
            .source_package = "app",
            .prior_installed = null,
            .requested = true,
            .reason = .explicit_request,
            .selected_origin = null,
        },
        .{
            .kind = if (purge) .purge else .remove,
            .package = "old",
            .version = "2.0",
            .architecture = "amd64",
            .repository = null,
            .sha256 = null,
            .package_size = null,
            .installed_size_delta_bytes = 0,
            .source_package = "old",
            .prior_installed = .{
                .package = "old",
                .version = "2.0",
                .architecture = "amd64",
                .installed_size_kib = null,
            },
            .requested = empty_closure,
            .reason = if (empty_closure) .explicit_request else .replacement,
            .selected_origin = null,
        },
    };
    var ordered = [_]solver.OrderedAction{
        .{ .sequence = 0, .kind = if (purge) .purge else .remove, .package = "old", .version = "2.0", .architecture = "amd64" },
        .{ .sequence = 1, .kind = .unpack, .package = "app", .version = "1.2", .architecture = "amd64" },
        .{ .sequence = 2, .kind = .configure_pending, .package = "app", .version = "1.2", .architecture = "amd64" },
    };
    const solver_plan: solver.Plan = .{
        .target_architecture = "amd64",
        .mode = .plan_only,
        .actions = if (empty_closure) actions[1..] else &actions,
        .ordered_actions = if (empty_closure) ordered[0..1] else &ordered,
        .summary = .{},
        .download_bytes = if (empty_closure) 0 else bytes.len,
        .installed_size_delta_bytes = 0,
        .backing_allocator = testing.allocator,
        .arena = undefined,
    };
    var root_buffer: [4096]u8 = undefined;
    const install_root = try fixtureInstallRoot(&fixture, &root_buffer);
    var preparation = try native_preparation.prepare(testing.allocator, .{
        .plan = &solver_plan,
        .exact_lock = &lock.lock,
        .install_root = install_root,
        .policy = .{ .conffile = .keep_existing },
        .script_policy = lifecycleScriptPolicy(),
        .installed = .{
            .generation_sha256 = database.generation.sha256,
            .packages = try lifecycleInstalledEvidence(arena.allocator(), root, database.model),
            .trigger_state_sha256 = native_trigger.stateDigest(database.model),
        },
        .archives = archives,
    });
    defer preparation.deinit();
    var compiled: CompiledLifecycle = switch (preparation) {
        .prepared => |value| .{ .authorization = value.authorization, .program = value.program },
        .diagnostic => |value| {
            std.debug.print("production preparation failed: {any}\n", .{value.diagnostic});
            return error.TestUnexpectedResult;
        },
    };
    if (empty_closure) {
        try testing.expectEqual(@as(usize, 0), lock.lock.packages.len);
        try testing.expectEqual(@as(usize, 0), compiled.program.program.artifacts.len);
        try testing.expectEqual(@as(usize, if (purge) 0 else 1), compiled.authorization.authorization.final_state.len);
    }
    if (case == .helper_target_removed) {
        try testing.expectError(error.NativeHelperTargetMutationUnsupported, validateNativeHelperTargetPlan(
            compiled.authorization.authorization,
            &models,
            database.model,
        ));
        try testing.expect(try root.entryIfExists(try root_fs.Path.init("usr/share/app")) == null);
        try testing.expect(try root.entryIfExists(try root_fs.Path.init(native_helper.target_path)) != null);
        return;
    }
    try testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) == null);
    try testing.expect(try root.entryIfExists(try root_fs.Path.init("usr/share/app")) == null);
    var locks: root_operation.TestLockBackend = .{ .allocator = testing.allocator };
    defer locks.deinit();
    var caller: root_operation.Attempt = undefined;
    if (case != .owned) {
        var coordinator = try root_operation.Coordinator.open(testing.io, root, install_root, locks.interface());
        caller = try coordinator.acquire(testing.allocator, .{
            .backend = if (case == .legacy_backend) .legacy_dpkg else .native,
            .operation = .{ .repository_bootstrap = .add },
            .request_sha256 = @splat(0x71),
            .policy_sha256 = @splat(0x72),
            .target_architecture = if (case == .wrong_architecture) "arm64" else "amd64",
            .evidence = .{ .plan_sha256 = if (case == .wrong_plan)
                @splat(0x73)
            else
                transaction_executor.planDigest(solver_plan) },
        });
        if (case == .legacy_bridge)
            try caller.advance(testing.allocator, .{ .state = .mutation_pending, .phase = .mutation });
    }
    defer if (case != .owned) caller.release();
    if (case == .captured_preparation) {
        const original = caller.record().digest_sha256;
        const request: Runtime.PrepareRequest = .{
            .attempt = &caller,
            .plan = &solver_plan,
            .exact_lock = &lock.lock,
            .archives = &.{bytes},
            .policy = .{ .conffile = .keep_existing },
        };
        var captured_preparation = try Runtime.prepare(testing.allocator, request);
        defer captured_preparation.deinit();
        const captured_program = switch (captured_preparation) {
            .prepared => |value| value.program.program,
            .diagnostic, .unchanged => return error.TestUnexpectedResult,
        };
        try testing.expectEqualStrings(&compiled.program.program.digest_sha256, &captured_program.digest_sha256);
        try testing.expectEqual(original, caller.record().digest_sha256);
        try testing.expect(try Runtime.canAbandon(testing.allocator, &caller));
        try testing.expect(try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) == null);
        try testing.expect(try root.entryIfExists(try root_fs.Path.init("usr/share/app")) == null);
        var missing = request;
        missing.archives = &.{};
        var refused = try Runtime.prepare(testing.allocator, missing);
        defer refused.deinit();
        try testing.expect(refused == .diagnostic);
        try testing.expectEqual(.missing_archive, refused.diagnostic.diagnostic.code);
        var changed_lock = lock.lock;
        var changed_package = lock.lock.packages[0];
        changed_package.sha256[0] ^= 1;
        changed_lock.packages = &.{changed_package};
        var changed_request = request;
        changed_request.exact_lock = &changed_lock;
        try testing.expectError(error.ArchiveEvidenceMismatch, Runtime.prepare(testing.allocator, changed_request));
        try caller.abandonIfPreMutation(testing.allocator);
        return;
    }
    const external: ExternalLifecycleRequest = .{
        .root = install_root,
        .architecture = "amd64",
        .archives = &.{},
        .operation = .install,
        .report = "",
        .recovery = case == .private_recovery,
    };
    if (case == .stale_database) {
        const changed_status = try std.mem.concat(testing.allocator, u8, &.{ status, "\n" });
        defer testing.allocator.free(changed_status);
        try root.publishFile(try root_fs.Path.init("var/lib/dpkg/status"), changed_status, .{});
    }
    if (case == .wrong_plan or case == .foreign_root or case == .private_recovery or
        case == .legacy_bridge or case == .legacy_backend or case == .wrong_architecture)
    {
        const original_digest = caller.record().digest_sha256;
        var other = testing.tmpDir(.{});
        defer other.cleanup();
        try testing.expectError(
            switch (case) {
                .wrong_plan => error.InvalidTransition,
                .foreign_root => error.OperationRootMismatch,
                .private_recovery => error.ProductionRecoveryRequestRequired,
                .legacy_bridge => error.OperationNotMutable,
                .legacy_backend => error.OperationBackendMismatch,
                .wrong_architecture => error.OperationArchitectureMismatch,
                else => unreachable,
            },
            executeLifecycleProgramInOperation(
                testing.allocator,
                if (case == .foreign_root) root_fs.Root.init(testing.io, other.dir) else root,
                external,
                &compiled,
                &models,
                &.{bytes},
                fixture.snapshot(),
                database.model,
                locks.interface(),
                null,
                null,
                &caller,
            ),
        );
        try testing.expect(caller.locked());
        try testing.expectEqual(original_digest, caller.record().digest_sha256);
        try testing.expect(try root.entryIfExists(try root_fs.Path.init("usr/share/app")) == null);
        if (case == .legacy_bridge) {
            _ = try caller.witness(testing.allocator, .proved_not_started);
            try caller.clear();
        } else try caller.abandonIfPreMutation(testing.allocator);
        return;
    }
    const production = case == .production or case == .production_resume or empty_closure;
    if (case == .public_missing_helper) {
        try testing.expectError(error.NativeHelperTargetMissing, Runtime.execute(testing.allocator, .{
            .attempt = &caller,
            .prepared = &compiled,
            .archives = &.{bytes},
            .operation = .install,
        }));
        try testing.expect(caller.locked());
        try testing.expect(!caller.record().mutation_started);
        try testing.expectEqual(root_operation.State.preflight, caller.record().state);
        try testing.expect(try root.entryIfExists(try root_fs.Path.init("usr/share/app")) == null);
        try testing.expect(try root.entryIfExists(try root_fs.Path.init(native_helper.directory)) == null);
        try testing.expect(try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) == null);
        try caller.abandonIfPreMutation(testing.allocator);
        return;
    }
    if (case == .production_resume) {
        try native_operation.bind(testing.allocator, root, &caller, compiled.program.program);
        const document = try native_execution_request.create(root, &caller, compiled.program.program, .install);
        const request_bytes = try native_execution_request.encode(arena.allocator(), document);
        _ = try prepareNativeRecovery(
            arena.allocator(),
            root,
            productionLifecycleRequest(document, null),
            &compiled,
            request_bytes,
            &.{bytes},
            fixture.snapshot(),
            &caller,
            document,
            null,
        );
        try testing.expect(try root.entryIfExists(try root_fs.Path.init("usr/share/app")) == null);
        var refused = try Runtime.report(testing.allocator, &caller, .{
            .outcome = .handoff,
            .detail = "unsupported_fixture",
        });
        defer refused.deinit();
        try testing.expectEqual(Runtime.Outcome.recovery_required, refused.outcome);
        try testing.expect(!caller.record().mutation_started);
        try testing.expectError(error.NativeHelperBindingRequired, Runtime.recover(testing.allocator, &caller));
        try testing.expect(try root.entryIfExists(try root_fs.Path.init("usr/share/app")) == null);
    }
    const result = if (case == .production_resume)
        try recoverPreparedNativeProgram(testing.allocator, root, &caller, locks.interface(), null)
    else if (production)
        try executePreparedNativeProgram(
            testing.allocator,
            root,
            &compiled,
            if (empty_closure) &.{} else &.{bytes},
            &caller,
            locks.interface(),
            if (empty_closure) (if (purge) .purge else .remove) else .install,
            null,
        )
    else
        try executeLifecycleProgramInOperation(
            testing.allocator,
            root,
            external,
            &compiled,
            &models,
            &.{bytes},
            fixture.snapshot(),
            database.model,
            locks.interface(),
            null,
            null,
            if (case == .owned) null else &caller,
        );
    if (case == .stale_database) {
        try testing.expectEqual(LifecycleOutcome.refused, result.outcome);
        try testing.expectEqualStrings("database_generation_drift", result.detail);
        try testing.expect(caller.locked());
        try testing.expectEqual(root_operation.State.preflight, caller.record().state);
        try testing.expectEqual(root_operation.Outcome.pending, caller.record().outcome);
        try testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) != null);
        try testing.expect(try root.entryIfExists(try root_fs.Path.init("usr/share/app")) == null);
        try caller.abandonIfPreMutation(testing.allocator);
        return;
    }
    if (result.outcome != .applied) {
        std.debug.print("mixed native execution failed: {any}\n", .{result});
        return error.TestUnexpectedResult;
    }
    if (case == .borrowed or production) {
        try testing.expect(caller.locked());
        try testing.expectEqual(root_operation.State.mutating, caller.record().state);
        try testing.expectEqual(root_operation.Outcome.pending, caller.record().outcome);
        try testing.expect(caller.record().operation.eql(.{ .repository_bootstrap = .add }));
        try testing.expectEqual([_]u8{0x71} ** 32, caller.record().request_sha256);
        try testing.expectEqual([_]u8{0x72} ** 32, caller.record().policy_sha256);
        try testing.expectEqual(transaction_executor.planDigest(solver_plan), caller.record().plan_sha256.?);
        try testing.expectEqual(compiled.authorization.authorization.digest_sha256, caller.record().authorization_sha256.?);
        try testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) != null);
        try testing.expect(try root.entryIfExists(try root_fs.Path.init(root_operation_completion.document_path)) == null);
        if (production) {
            var intent = try native_recovery.readIntent(testing.allocator, root);
            defer intent.deinit();
            const blob = intent.intent.blobs[0];
            try testing.expectEqual(native_recovery.BlobKind.request, blob.kind);
            try testing.expectEqualStrings(native_execution_request.logical_path, blob.logical_path);
            try testing.expect(!std.mem.eql(u8, &blob.sha256, &intent.intent.request_sha256));
            const request_bytes = try native_recovery.verifyBlob(testing.allocator, root, blob);
            defer testing.allocator.free(request_bytes);
            var request = try native_execution_request.decode(testing.allocator, request_bytes);
            defer request.deinit();
            try native_execution_request.validateBinding(request.document, root, &caller, compiled.program.program);
            try testing.expectError(error.InvalidRecoveryIntent, validatePersistedLifecycleRequest(testing.allocator, root, intent.intent));
            var changed_request = request.document;
            changed_request.caller.policy_sha256 = @splat('3');
            native_execution_request.seal(&changed_request);
            try testing.expectError(error.RecoveryRequestBindingMismatch, native_execution_request.validateBinding(changed_request, root, &caller, compiled.program.program));
            const noncanonical = try std.mem.concat(testing.allocator, u8, &.{ request_bytes, "\n" });
            defer testing.allocator.free(noncanonical);
            try testing.expectError(error.NonCanonicalDocument, native_execution_request.decode(testing.allocator, noncanonical));
            var receipt = try readProductionCompletion(testing.allocator, root, &caller) orelse
                return error.TestUnexpectedResult;
            defer receipt.deinit();
            try testing.expectError(error.NativeHelperBindingRequired, Runtime.readCompletion(testing.allocator, &caller));
            try testing.expectError(error.NativeHelperBindingRequired, Runtime.recover(testing.allocator, &caller));
            try testing.expectError(error.NativeHelperBindingRequired, Runtime.acknowledge(
                testing.allocator,
                &caller,
                receipt.document.digest_sha256,
            ));
            try testing.expectEqual(native_provenance.Outcome.succeeded, receipt.document.outcome);
            try testing.expectEqual(request.document.caller.request_sha256, receipt.document.request_sha256);
            try testing.expectEqual(request.document.caller.policy_sha256, receipt.document.policy_sha256);
            try testing.expectError(error.NativeRecoveryRequired, executePreparedNativeProgram(
                testing.allocator,
                root,
                &compiled,
                &.{bytes},
                &caller,
                locks.interface(),
                .install,
                null,
            ));
            // Outer work may change the database after native completion. A
            // repeated native recovery consumes the receipt, not package work.
            const current_status = try root.readFileAlloc(arena.allocator(), try root_fs.Path.init("var/lib/dpkg/status"), 1024 * 1024);
            const outer_status = try std.mem.concat(arena.allocator(), u8, &.{ current_status, "\n" });
            try root.publishFile(try root_fs.Path.init("var/lib/dpkg/status"), outer_status, .{});
            const repeated = try recoverPreparedNativeProgram(testing.allocator, root, &caller, locks.interface(), null);
            try testing.expectEqual(LifecycleOutcome.applied, repeated.outcome);
            try testing.expectEqualStrings("awaiting_caller_acknowledgment", repeated.detail);
            try testing.expectEqual(root_operation.Outcome.pending, caller.record().outcome);
            try testing.expectError(error.InvalidRecoveryProvenance, acknowledgePreparedNativeProgram(
                testing.allocator,
                root,
                &caller,
                @splat('0'),
            ));
            try testing.expect(try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) != null);
            // Retry also works if a previous acknowledgment stopped partway
            // through cleanup: immutable evidence supplies the original set.
            try root.removeFile(try root_fs.Path.init(native_recovery.progress_path));
            try acknowledgePreparedNativeProgram(testing.allocator, root, &caller, receipt.document.digest_sha256);
            try acknowledgePreparedNativeProgram(testing.allocator, root, &caller, receipt.document.digest_sha256);
            try testing.expect(try root.entryIfExists(try root_fs.Path.init(native_recovery.intent_path)) == null);
            try testing.expect(try root.entryIfExists(try root_fs.Path.init(native_recovery.workspace_directory)) == null);
            try native_provenance.verifyEvidence(testing.allocator, root, receipt.document);
            const after_ack = try recoverPreparedNativeProgram(testing.allocator, root, &caller, locks.interface(), null);
            try testing.expectEqual(LifecycleOutcome.applied, after_ack.outcome);
        }
        try caller.advance(testing.allocator, .{ .state = .mutating, .phase = .mutation });
        try caller.advance(testing.allocator, .{ .state = .verifying, .phase = .verification });
        try caller.complete(testing.allocator, .succeeded);
        try caller.publishProvenance(testing.allocator, @splat(0x74));
        try caller.clear();
    }
    var final = try captureDatabaseSnapshot(testing.allocator, root, .{});
    defer final.deinit();
    var imported = switch (try package_database.importSnapshot(testing.allocator, .{
        .native_architecture = "amd64",
        .snapshot = final.snapshot,
    }, .{})) {
        .database => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer imported.deinit();
    if (empty_closure) {
        try testing.expectEqual(@as(usize, if (purge) 0 else 1), imported.model.packages.len);
        try testing.expect(imported.model.find("app", "amd64") == null);
    } else {
        try testing.expectEqual(package_database.Want.install, imported.model.find("app", "amd64").?.status.want);
    }
    if (purge) {
        try testing.expect(imported.model.find("old", "amd64") == null);
        try testing.expect(try root.entryIfExists(try root_fs.Path.init("etc/old.conf")) == null);
    } else {
        try testing.expectEqual(package_database.Want.deinstall, imported.model.find("old", "amd64").?.status.want);
        try testing.expectEqual(package_database.CurrentState.config_files, imported.model.find("old", "amd64").?.status.current);
        const conffile = try root.readFileAlloc(testing.allocator, try root_fs.Path.init("etc/old.conf"), 4096);
        defer testing.allocator.free(conffile);
        try testing.expectEqualStrings("old configuration\n", conffile);
    }
    try testing.expect(try root.entryIfExists(try root_fs.Path.init("usr/share/old")) == null);
    if (empty_closure) {
        try testing.expect(try root.entryIfExists(try root_fs.Path.init("usr/share/app")) == null);
    } else {
        const payload = try root.readFileAlloc(testing.allocator, try root_fs.Path.init("usr/share/app"), 4096);
        defer testing.allocator.free(payload);
        try testing.expectEqualStrings("new payload\n", payload);
    }
}

test "native_unpack.test.materialization adapter applies data-only plan" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{
        .{ .path = "usr", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share/demo", .kind = '5', .mode = 0o750 },
        .{ .path = "usr/share/demo/file", .content = "payload\n", .mode = 0o640 },
        .{ .path = "usr/share/demo/link", .kind = '2', .link = "file" },
        .{
            .path = "usr/share/demo/hard",
            .kind = '1',
            .link = "./usr/share/demo/file",
        },
    };
    const bytes = try buildOwnedArchive(
        .{ .package = "demo", .version = "1" },
        &data,
    );
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    var program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    var root_buffer: [4096]u8 = undefined;
    const install_root = try fixtureInstallRoot(&fixture, &root_buffer);
    const root_identity = bindFixtureProgramRoot(&program, install_root);
    var locks: root_operation.TestLockBackend = .{
        .allocator = testing.allocator,
    };
    defer locks.deinit();
    const result = try materialize(testing.allocator, .{
        .io = testing.io,
        .root = fixture.root(),
        .install_root = install_root,
        .planning = .{
            .program = &program,
            .snapshot = fixture.snapshot(),
            .archives = &.{.{ .artifact = 0, .bytes = bytes }},
            .root = fixture.root(),
            .root_identity_sha256 = root_identity,
            .interoperability = .isolated_root,
        },
        .locks = locks.interface(),
        .operation = .install,
    });
    try testing.expectEqual(MaterializationOutcome.applied, result.outcome);
    const published = try fixture.root().readFileAlloc(
        testing.allocator,
        try root_fs.Path.init("usr/share/demo/file"),
        4096,
    );
    defer testing.allocator.free(published);
    try testing.expectEqualStrings("payload\n", published);
    const file = try fixture.root().entry(try root_fs.Path.init("usr/share/demo/file"));
    const hard = try fixture.root().entry(try root_fs.Path.init("usr/share/demo/hard"));
    try testing.expectEqual(file.inode, hard.inode);
    try testing.expect(try fixture.root().entryIfExists(
        try root_fs.Path.init(root_operation.record_path),
    ) == null);
    try testing.expect(try fixture.root().entryIfExists(
        try root_fs.Path.init(root_mutation.journal_path),
    ) == null);
}

test "native_unpack.test.materialization rejects stale inputs before mutation" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{.{
        .path = "usr/share/demo/file",
        .content = "payload\n",
    }};
    const bytes = try buildOwnedArchive(
        .{ .package = "demo", .version = "1" },
        &data,
    );
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    var program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    const tampered = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    var binding_program = program;
    const binding_artifacts = [_]native_program.ProgramArtifact{
        artifacts[0],
        testArtifact(1, &model, bytes.len),
    };
    binding_program.artifacts = &binding_artifacts;
    if (try bindMaterializationArchives(testing.allocator, .{
        .program = &binding_program,
        .snapshot = fixture.snapshot(),
        .archives = &.{
            .{ .artifact = 0, .bytes = bytes },
            .{ .artifact = 1, .bytes = tampered },
        },
        .root = fixture.root(),
        .root_identity_sha256 = @splat(0),
        .interoperability = .isolated_root,
    })) |value| {
        var unexpected = value;
        defer unexpected.deinit();
        return error.TestUnexpectedResult;
    }
    var locks: root_operation.TestLockBackend = .{
        .allocator = testing.allocator,
    };
    defer locks.deinit();
    const stale_archive = try materializeFixture(
        &fixture,
        &program,
        fixture.snapshot(),
        &.{.{ .artifact = 0, .bytes = tampered }},
        locks.interface(),
        .install,
        .{},
    );
    try testing.expectEqual(MaterializationOutcome.refused, stale_archive.outcome);
    try testing.expect(try fixture.root().entryIfExists(
        try root_fs.Path.init("usr/share/demo/file"),
    ) == null);
    try testing.expect(try fixture.root().entryIfExists(
        try root_fs.Path.init(root_operation.namespace_path),
    ) == null);

    try fixture.root().publishFile(
        try root_fs.Path.init("var/lib/dpkg/status"),
        "\n",
        .{},
    );
    const stale_database = try materializeFixture(
        &fixture,
        &program,
        fixture.snapshot(),
        &.{.{ .artifact = 0, .bytes = bytes }},
        locks.interface(),
        .install,
        .{},
    );
    try testing.expectEqual(MaterializationOutcome.refused, stale_database.outcome);
    try testing.expectEqualStrings(
        "database_generation_drift",
        stale_database.detail,
    );
    try testing.expect(try fixture.root().entryIfExists(
        try root_fs.Path.init(root_operation.namespace_path),
    ) == null);
}

test "native_unpack.test.materialization handoff leaves payload untouched" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{.{
        .path = "etc/demo.conf",
        .content = "value\n",
    }};
    const bytes = try archive_application.test_fixtures.build(
        testing.allocator,
        .{
            .package = "demo",
            .version = "1",
            .control = &.{
                .{ .path = "conffiles", .content = "/etc/demo.conf\n" },
            },
            .data = &data,
        },
    );
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    var program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    var locks: root_operation.TestLockBackend = .{
        .allocator = testing.allocator,
    };
    defer locks.deinit();
    const result = try materializeFixture(
        &fixture,
        &program,
        fixture.snapshot(),
        &.{.{ .artifact = 0, .bytes = bytes }},
        locks.interface(),
        .install,
        .{},
    );
    try testing.expectEqual(MaterializationOutcome.handoff, result.outcome);
    try testing.expect(try fixture.root().entryIfExists(
        try root_fs.Path.init("etc/demo.conf"),
    ) == null);
    try testing.expect(try fixture.root().entryIfExists(
        try root_fs.Path.init(root_operation.namespace_path),
    ) == null);
}

test "native_unpack.test.conffile unpack stages package bytes and database state" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{.{
        .path = "etc/demo.conf",
        .content = "value\n",
        .uid = currentUid(),
        .gid = currentGid(),
    }};
    const bytes = try archive_application.test_fixtures.build(
        testing.allocator,
        .{
            .package = "demo",
            .version = "1",
            .control = &.{
                .{ .path = "conffiles", .content = "/etc/demo.conf\n" },
            },
            .data = &data,
        },
    );
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    var planned = try expectPlan(try plan(testing.allocator, .{
        .program = &program,
        .snapshot = fixture.snapshot(),
        .archives = &.{.{ .artifact = 0, .bytes = bytes }},
        .root = fixture.root(),
        .interoperability = .isolated_root,
        .conffiles = .unpack,
    }));
    defer planned.deinit();
    try testing.expectEqual(@as(usize, 1), planned.packages[0].conffiles.len);
    try testing.expectEqualStrings(
        "etc/demo.conf.dpkg-new",
        planned.packages[0].conffiles[0].staged_path.?,
    );
    var staged = false;
    for (planned.filesystem) |change| switch (change) {
        .file => |file| if (std.mem.eql(
            u8,
            file.path,
            "etc/demo.conf.dpkg-new",
        )) {
            staged = true;
        },
        else => {},
    };
    try testing.expect(staged);
    try testing.expect(std.mem.indexOf(
        u8,
        planned.database.find("status").?.bytes,
        "/etc/demo.conf newconffile",
    ) != null);
    try testing.expectEqualStrings(
        "/etc/demo.conf\n",
        planned.database.find("info/demo.conffiles").?.bytes,
    );
}

test "native_unpack.test.conffile generated path rejects archive collision" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{
        .{
            .path = "etc/demo.conf",
            .content = "value\n",
            .uid = currentUid(),
            .gid = currentGid(),
        },
        .{
            .path = "etc/demo.conf.dpkg-new",
            .content = "collision\n",
            .uid = currentUid(),
            .gid = currentGid(),
        },
    };
    const bytes = try archive_application.test_fixtures.build(
        testing.allocator,
        .{
            .package = "demo",
            .version = "1",
            .control = &.{
                .{ .path = "conffiles", .content = "/etc/demo.conf\n" },
            },
            .data = &data,
        },
    );
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    try expectRefusal(try plan(testing.allocator, .{
        .program = &program,
        .snapshot = fixture.snapshot(),
        .archives = &.{.{ .artifact = 0, .bytes = bytes }},
        .root = fixture.root(),
        .interoperability = .isolated_root,
        .conffiles = .unpack,
    }), .duplicate_archive_path);
}

test "native_unpack.test.conffile phase digest binds mutation steps" {
    const seed: [32]u8 = @splat(0x11);
    const first = boundConffilePhaseDigest(seed, @splat(0x22));
    const second = boundConffilePhaseDigest(seed, @splat(0x23));
    try testing.expect(!std.mem.eql(u8, &first, &second));
}

test "native_unpack.test.conffile observation rejects oversized root file" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    try seedFile(fixture.root(), "etc/demo.conf", "content\n");
    var compared: u64 = 0;
    try testing.expectError(
        error.ConffileObservationLimit,
        rootMd5ForConffile(
            testing.allocator,
            fixture.root(),
            "etc/demo.conf",
            "content\n".len - 1,
            &compared,
            1024,
        ),
    );
    try testing.expectEqual(@as(u64, 0), compared);
}

const MaterializationFault = struct {
    boundary: root_mutation.Boundary,
    crash: bool,
    fired: bool = false,

    fn hooks(self: *MaterializationFault) root_mutation.Hooks {
        return .{ .context = self, .beforeFn = before };
    }

    fn before(
        context: ?*anyopaque,
        boundary: root_mutation.Boundary,
        _: u32,
    ) root_mutation.HookError!void {
        const self: *MaterializationFault = @ptrCast(@alignCast(context.?));
        if (self.fired or boundary != self.boundary) return;
        self.fired = true;
        if (self.crash) return error.SimulatedCrash;
        return error.RenameFailed;
    }
};

test "native_unpack.test.materialization rollback and recovery retain truth" {
    var data = [_]Entry{
        .{ .path = "usr", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share/demo", .kind = '5', .mode = 0o755 },
        .{
            .path = "usr/share/demo/file",
            .content = "payload\n",
        },
    };
    const bytes = try buildOwnedArchive(
        .{ .package = "demo", .version = "1" },
        &data,
    );
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };

    var rollback_fixture: Fixture = undefined;
    try rollback_fixture.init(empty_status, &.{});
    defer rollback_fixture.deinit();
    var rollback_artifacts: [1]native_program.ProgramArtifact = undefined;
    var rollback_program = try singleProgram(
        &rollback_fixture,
        &model,
        bytes,
        &steps,
        &rollback_artifacts,
    );
    var rollback_locks: root_operation.TestLockBackend = .{
        .allocator = testing.allocator,
    };
    defer rollback_locks.deinit();
    var rollback_fault: MaterializationFault = .{
        .boundary = .publish_rename,
        .crash = false,
    };
    const rolled_back = try materializeFixture(
        &rollback_fixture,
        &rollback_program,
        rollback_fixture.snapshot(),
        &.{.{ .artifact = 0, .bytes = bytes }},
        rollback_locks.interface(),
        .install,
        rollback_fault.hooks(),
    );
    try testing.expectEqual(MaterializationOutcome.rolled_back, rolled_back.outcome);
    try testing.expect(try rollback_fixture.root().entryIfExists(
        try root_fs.Path.init("usr/share/demo/file"),
    ) == null);
    try testing.expect(try rollback_fixture.root().entryIfExists(
        try root_fs.Path.init(root_operation.record_path),
    ) == null);
    try testing.expect(try rollback_fixture.root().entryIfExists(
        try root_fs.Path.init(root_mutation.journal_path),
    ) == null);

    var crash_fixture: Fixture = undefined;
    try crash_fixture.init(empty_status, &.{});
    defer crash_fixture.deinit();
    var crash_artifacts: [1]native_program.ProgramArtifact = undefined;
    var crash_program = try singleProgram(
        &crash_fixture,
        &model,
        bytes,
        &steps,
        &crash_artifacts,
    );
    var crash_locks: root_operation.TestLockBackend = .{
        .allocator = testing.allocator,
    };
    defer crash_locks.deinit();
    var crash_fault: MaterializationFault = .{
        .boundary = .publish_rename,
        .crash = true,
    };
    const recovery = try materializeFixture(
        &crash_fixture,
        &crash_program,
        crash_fixture.snapshot(),
        &.{.{ .artifact = 0, .bytes = bytes }},
        crash_locks.interface(),
        .install,
        crash_fault.hooks(),
    );
    try testing.expectEqual(
        MaterializationOutcome.recovery_required,
        recovery.outcome,
    );
    try testing.expect((try root_mutation.inspect(
        testing.allocator,
        crash_fixture.root(),
        .{},
    )) != null);
    try testing.expect(try crash_fixture.root().entryIfExists(
        try root_fs.Path.init(root_operation.record_path),
    ) != null);
}

test "native_unpack.test.materialization repeats without stale journal" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{
        .{ .path = "usr", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share/demo", .kind = '5', .mode = 0o755 },
        .{
            .path = "usr/share/demo/file",
            .content = "payload\n",
        },
    };
    const bytes = try buildOwnedArchive(
        .{ .package = "demo", .version = "1" },
        &data,
    );
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    var locks: root_operation.TestLockBackend = .{
        .allocator = testing.allocator,
    };
    defer locks.deinit();

    const install_steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var install_artifacts: [1]native_program.ProgramArtifact = undefined;
    var install_program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &install_steps,
        &install_artifacts,
    );
    const first = try materializeFixture(
        &fixture,
        &install_program,
        fixture.snapshot(),
        &.{.{ .artifact = 0, .bytes = bytes }},
        locks.interface(),
        .install,
        .{},
    );
    try testing.expectEqual(MaterializationOutcome.applied, first.outcome);

    var captured = try captureDatabaseSnapshot(
        testing.allocator,
        fixture.root(),
        .{},
    );
    defer captured.deinit();
    var database = switch (try package_database.importSnapshot(
        testing.allocator,
        .{
            .native_architecture = "amd64",
            .snapshot = captured.snapshot,
        },
        .{},
    )) {
        .database => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer database.deinit();
    var other_data = [_]Entry{
        .{ .path = "usr", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share/other", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share/other/file", .content = "other\n" },
    };
    const other_bytes = try buildOwnedArchive(
        .{ .package = "other", .version = "1" },
        &other_data,
    );
    defer testing.allocator.free(other_bytes);
    var other_model = try modelOf(other_bytes);
    defer other_model.deinit();
    const other_steps = [_]native_program.Step{
        unpackStep(0, &other_model, 0, null, false),
    };
    var other_artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &other_model, other_bytes.len),
    };
    var other_program = testProgram(
        database.generation.sha256,
        database.model.packages.len,
        &other_artifacts,
        &other_steps,
    );
    const second = try materializeFixture(
        &fixture,
        &other_program,
        captured.snapshot,
        &.{.{ .artifact = 0, .bytes = other_bytes }},
        locks.interface(),
        .install,
        .{},
    );
    try testing.expectEqual(MaterializationOutcome.applied, second.outcome);
    try testing.expect(try fixture.root().entryIfExists(
        try root_fs.Path.init(root_operation.record_path),
    ) == null);
    try testing.expect(try fixture.root().entryIfExists(
        try root_fs.Path.init(root_mutation.journal_path),
    ) == null);
}

test "native_unpack.test.materialization database capture has an aggregate bound" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    try testing.expectError(
        error.DatabaseCaptureLimit,
        captureDatabaseSnapshotBounded(testing.allocator, fixture.root(), .{}, 1),
    );
    var captured = try captureDatabaseSnapshot(testing.allocator, fixture.root(), .{});
    defer captured.deinit();
    try testing.expectEqualStrings(empty_status, captured.snapshot.status.bytes);
}

test "native_unpack.test.planning is deterministic and descriptive only" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();

    const payload = "payload\n";
    var data = [_]Entry{
        .{ .path = "usr", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share/demo", .kind = '5', .mode = 0o755 },
        .{ .path = "usr/share/demo/file", .content = payload, .mode = 0o640 },
        .{ .path = "usr/share/demo/link", .kind = '2', .link = "file" },
        .{ .path = "usr/share/demo/hard", .kind = '1', .link = "./usr/share/demo/file" },
    };
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "1.0" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);

    var first = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer first.deinit();
    var second = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer second.deinit();

    try testing.expectEqualSlices(u8, &first.digest, &second.digest);
    try testing.expectEqual(@as(usize, 1), first.packages.len);
    try testing.expectEqualStrings("demo", first.packages[0].identity.name);
    try testing.expectEqualStrings("amd64", first.packages[0].identity.architecture);
    try testing.expect(first.filesystem.len >= 6);
    var saw_file = false;
    var saw_symlink = false;
    var saw_hardlink = false;
    for (first.filesystem) |change| switch (change) {
        .file => |item| {
            saw_file = saw_file or std.mem.eql(u8, item.path, "usr/share/demo/file");
            if (std.mem.eql(u8, item.path, "usr/share/demo/file"))
                try testing.expectEqual(@as(u32, 0), item.artifact);
        },
        .symlink => |item| saw_symlink = saw_symlink or
            std.mem.eql(u8, item.path, "usr/share/demo/link"),
        .hardlink => |item| saw_hardlink = saw_hardlink or
            std.mem.eql(u8, item.path, "usr/share/demo/hard"),
        else => {},
    };
    try testing.expect(saw_file and saw_symlink and saw_hardlink);
    try testing.expect(first.database.find("status") != null);
    try testing.expect(first.database.find("info/demo.list") != null);
    try testing.expect(first.database.find("info/demo.md5sums") != null);
}

test "native_unpack.test.archive bytes and database generation are revalidated" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{.{ .path = "usr/share/demo", .content = "ok\n" }};
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "1.0" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    var program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);

    const tampered = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try expectRefusal(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = tampered }},
    ), .archive_binding_mismatch);

    program.installed_database.generation_sha256[0] = if (program.installed_database.generation_sha256[0] == '0') '1' else '0';
    try expectRefusal(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .database_generation_mismatch);
}

test "native_unpack.test.replaces updates displaced ownership in the database plan" {
    const status =
        \\Package: oldpkg
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 1.0
        \\Description: old
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "oldpkg.list", .bytes = "/.\n/usr\n/usr/share\n/usr/share/shared\n/usr/share/keep\n" },
        .{ .name = "oldpkg.md5sums", .bytes = "814fa5ca98406a903e22b43d9b610105  usr/share/shared\n814fa5ca98406a903e22b43d9b610105  usr/share/keep\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.init(status, &info);
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/shared", "old\n");
    try seedFile(fixture.root(), "usr/share/keep", "old\n");

    var conflicting_data = [_]Entry{.{ .path = "usr/share/shared", .content = "new\n" }};
    const conflicting_bytes = try buildOwnedArchive(
        .{ .package = "plain", .version = "2.0" },
        &conflicting_data,
    );
    defer testing.allocator.free(conflicting_bytes);
    var conflicting_model = try modelOf(conflicting_bytes);
    defer conflicting_model.deinit();
    const conflicting_steps = [_]native_program.Step{
        unpackStep(0, &conflicting_model, 0, null, false),
    };
    var conflicting_artifacts: [1]native_program.ProgramArtifact = undefined;
    const conflicting_program = try singleProgram(
        &fixture,
        &conflicting_model,
        conflicting_bytes,
        &conflicting_steps,
        &conflicting_artifacts,
    );
    try expectRefusal(try planFor(
        &fixture,
        &conflicting_program,
        &.{.{ .artifact = 0, .bytes = conflicting_bytes }},
    ), .ownership_conflict);

    var data = [_]Entry{.{ .path = "usr/share/shared", .content = "new\n" }};
    const bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "2.0",
        .control_fields = "Replaces: oldpkg (<< 2.0)\n",
    }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);

    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer planned.deinit();
    try testing.expectEqual(@as(usize, 1), planned.displacements.len);
    try testing.expectEqualStrings("oldpkg", planned.displacements[0].holder.name);
    const old_list = planned.database.find("info/oldpkg.list") orelse
        return error.TestUnexpectedResult;
    try testing.expect(std.mem.startsWith(u8, old_list.bytes, "/.\n"));
    try testing.expect(std.mem.indexOf(u8, old_list.bytes, "/usr/share/keep") != null);
    try testing.expect(std.mem.indexOf(u8, old_list.bytes, "/usr/share/shared") == null);
    try testing.expectEqualStrings(
        "/.\n/usr\n/usr/share\n/usr/share/keep\n",
        old_list.bytes,
    );
    try testing.expect(planned.database.find("info/oldpkg.md5sums") == null);
}

test "native_unpack.test.multi arch siblings share only identical content" {
    const status =
        \\Package: demo
        \\Status: install ok unpacked
        \\Architecture: arm64
        \\Version: 1.0
        \\Multi-Arch: same
        \\Description: sibling
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "demo:arm64.list", .bytes = "/.\n/usr/share/demo/shared\n" },
        .{ .name = "demo:arm64.md5sums", .bytes = "0c2710c14e36d184252ea92fc65093f4  usr/share/demo/shared\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.initFull(status, &info, "arm64\n");
    defer fixture.deinit();
    var data = [_]Entry{.{ .path = "usr/share/demo/shared", .content = "shared\n" }};
    const bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1.0",
        .architecture = "amd64",
        .control_fields = "Multi-Arch: same\n",
    }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    try seedFile(fixture.root(), "usr/share/demo/shared", "shared\n");
    try fixture.root().applyMetadata(
        try root_fs.Path.init("usr/share/demo/shared"),
        .{
            .mode = 0o644,
            .uid = currentUid(),
            .gid = currentGid(),
            .modified_nanoseconds = test_mtime_ns,
        },
    );
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer planned.deinit();
    try testing.expectEqual(
        Disposition.share_multi_arch,
        planned.packages[0].paths[0].disposition,
    );
    try testing.expect(!planned.packages[0].paths[0].publish);
    for (planned.filesystem) |change| switch (change) {
        .file => |file| try testing.expect(
            !std.mem.eql(u8, file.path, "usr/share/demo/shared"),
        ),
        else => {},
    };
    const compared_bytes = planned.compared_bytes;
    var bounded = try expectPlan(try planLimited(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
        .{ .max_compared_bytes = compared_bytes },
    ));
    bounded.deinit();
    try expectRefusal(try planLimited(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
        .{ .max_compared_bytes = compared_bytes - 1 },
    ), .path_limit);

    try fixture.root().applyMetadata(
        try root_fs.Path.init("usr/share/demo/shared"),
        .{ .mode = 0o600 },
    );
    try expectRefusal(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .multi_arch_content_mismatch);
    try fixture.root().applyMetadata(
        try root_fs.Path.init("usr/share/demo/shared"),
        .{ .mode = 0o644 },
    );
    try fixture.root().publishFile(
        try root_fs.Path.init("usr/share/demo/shared"),
        "tampered\n",
        .{},
    );
    try expectRefusal(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .multi_arch_content_mismatch);
    try fixture.root().publishFile(
        try root_fs.Path.init("usr/share/demo/shared"),
        "shared\n",
        .{},
    );
    try fixture.root().applyMetadata(
        try root_fs.Path.init("usr/share/demo/shared"),
        .{
            .mode = 0o644,
            .uid = currentUid(),
            .gid = currentGid(),
            .modified_nanoseconds = test_mtime_ns,
        },
    );

    var divergent = [_]Entry{.{ .path = "usr/share/demo/shared", .content = "different\n" }};
    const other_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1.0",
        .architecture = "amd64",
        .control_fields = "Multi-Arch: same\n",
    }, &divergent);
    defer testing.allocator.free(other_bytes);
    var other_model = try modelOf(other_bytes);
    defer other_model.deinit();
    const other_steps = [_]native_program.Step{unpackStep(0, &other_model, 0, null, false)};
    var other_artifacts: [1]native_program.ProgramArtifact = undefined;
    const other_program = try singleProgram(
        &fixture,
        &other_model,
        other_bytes,
        &other_steps,
        &other_artifacts,
    );
    try expectRefusal(try planFor(
        &fixture,
        &other_program,
        &.{.{ .artifact = 0, .bytes = other_bytes }},
    ), .multi_arch_content_mismatch);
}

test "native_unpack.test.merged usr is normalized and dpkg namespace is reserved" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    try fixture.root().ensureDirectory(
        try root_fs.Path.init("usr"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().ensureDirectory(
        try root_fs.Path.init("usr/lib"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().createSymbolicLink(try root_fs.Path.init("lib"), "usr/lib");

    var data = [_]Entry{.{ .path = "lib/libdemo.so", .content = "so\n" }};
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "1.0" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer planned.deinit();
    try testing.expectEqualStrings("usr/lib/libdemo.so", planned.packages[0].paths[0].path);
    try testing.expect(planned.packages[0].paths[0].aliased);
    try testing.expectEqual(@as(usize, 1), planned.aliases.len);
    try testing.expect(planned.aliases[0].inode != 0);
    try testing.expect(planned.aliases[0].change_nanoseconds != 0);

    var reserved_data = [_]Entry{.{ .path = "var/lib/dpkg/status", .content = "owned\n" }};
    const reserved_bytes = try buildOwnedArchive(
        .{ .package = "bad", .version = "1.0" },
        &reserved_data,
    );
    defer testing.allocator.free(reserved_bytes);
    var reserved_model = try modelOf(reserved_bytes);
    defer reserved_model.deinit();
    const reserved_steps = [_]native_program.Step{
        unpackStep(0, &reserved_model, 0, null, false),
    };
    var reserved_artifacts: [1]native_program.ProgramArtifact = undefined;
    const reserved_program = try singleProgram(
        &fixture,
        &reserved_model,
        reserved_bytes,
        &reserved_steps,
        &reserved_artifacts,
    );
    try expectRefusal(try planFor(
        &fixture,
        &reserved_program,
        &.{.{ .artifact = 0, .bytes = reserved_bytes }},
    ), .reserved_path);
}

test "native_unpack.test.deferred lifecycle features are explicit handoffs" {
    const cases = [_]struct {
        control: []const Entry,
        feature: DeferredFeature,
    }{
        .{ .control = &.{.{ .path = "conffiles", .content = "/etc/demo.conf\n" }}, .feature = .conffile },
        .{ .control = &.{.{ .path = "preinst", .mode = 0o755, .content = "#!/bin/sh\n" }}, .feature = .maintainer_script },
        .{ .control = &.{.{ .path = "triggers", .content = "interest /usr/share/demo\n" }}, .feature = .trigger },
        .{ .control = &.{.{ .path = "templates", .content = "Template: demo/value\nType: string\n" }}, .feature = .package_metadata },
    };
    for (cases) |case| {
        var fixture: Fixture = undefined;
        try fixture.init(empty_status, &.{});
        defer fixture.deinit();
        var data = [_]Entry{
            .{ .path = "usr/share/demo", .content = "x\n" },
            .{ .path = "etc/demo.conf", .content = "key=value\n" },
        };
        const bytes = try archive_application.test_fixtures.build(testing.allocator, .{
            .package = "demo",
            .version = "1.0",
            .control = case.control,
            .data = &data,
        });
        defer testing.allocator.free(bytes);
        var model = try modelOf(bytes);
        defer model.deinit();
        const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
        var artifacts: [1]native_program.ProgramArtifact = undefined;
        const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
        try expectHandoff(try planFor(
            &fixture,
            &program,
            &.{.{ .artifact = 0, .bytes = bytes }},
        ), case.feature);
    }
}

test "native_unpack.test.shared roots and unsupported snapshots hand off" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{.{ .path = "usr/share/demo", .content = "x\n" }};
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "1.0" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    const archives = [_]ArchiveInput{.{ .artifact = 0, .bytes = bytes }};

    try expectHandoff(try planWith(
        &fixture,
        &program,
        &archives,
        .shared_root,
        &.{},
        &.{},
    ), .dpkg_interoperability);
    try expectHandoff(try planWith(
        &fixture,
        &program,
        &archives,
        .isolated_root,
        &.{"available"},
        &.{},
    ), .database_surface);
    try expectHandoff(try planWith(
        &fixture,
        &program,
        &archives,
        .isolated_root,
        &.{},
        &.{"usr/share/demo"},
    ), .unsupported_root_feature);
}

test "native_unpack.test.removal purge selection and barriers hand off" {
    const held_status =
        \\Package: demo
        \\Status: hold ok unpacked
        \\Architecture: amd64
        \\Version: 1.0
        \\Description: held
        \\
        \\
    ;
    const held_info = [_]package_database.InfoEntry{
        .{ .name = "demo.list", .bytes = "/.\n/usr/share/demo\n" },
    };
    var held: Fixture = undefined;
    try held.init(held_status, &held_info);
    defer held.deinit();
    var data = [_]Entry{.{ .path = "usr/share/demo", .content = "x\n" }};
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "2.0" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, "1.0", false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&held, &model, bytes, &steps, &artifacts);
    try expectHandoff(try planFor(
        &held,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .selection_change);

    var empty: Fixture = undefined;
    try empty.init(empty_status, &.{});
    defer empty.deinit();
    var database = try empty.database();
    defer database.deinit();
    const identity: native_program.PackageIdentity = .{
        .name = "old",
        .version = "1",
        .architecture = "amd64",
    };
    const remove_steps = [_]native_program.Step{.{
        .sequence = 0,
        .phase = .remove,
        .requires = &.{},
        .operation = .{ .remove_package_files = .{
            .package = identity,
            .owned_paths_sha256 = zeroDigest(),
            .retain_conffiles = true,
        } },
    }};
    const remove_program = testProgram(database.generation.sha256, 0, &.{}, &remove_steps);
    try expectHandoff(try planFor(&empty, &remove_program, &.{}), .package_removal);

    const purge_steps = [_]native_program.Step{.{
        .sequence = 0,
        .phase = .remove,
        .requires = &.{},
        .operation = .{ .purge_package_files = .{
            .package = identity,
            .conffiles_sha256 = zeroDigest(),
        } },
    }};
    const purge_program = testProgram(database.generation.sha256, 0, &.{}, &purge_steps);
    try expectHandoff(try planFor(&empty, &purge_program, &.{}), .package_purge);

    const barrier_steps = [_]native_program.Step{
        .{
            .sequence = 0,
            .phase = .configure,
            .requires = &.{},
            .operation = .{ .configure_barrier = .{
                .reason = .pre_depends,
                .packages = &.{},
            } },
        },
        unpackStep(1, &model, 0, "1.0", false),
    };
    var barrier_artifacts: [1]native_program.ProgramArtifact = undefined;
    const barrier_program = try singleProgram(
        &held,
        &model,
        bytes,
        &barrier_steps,
        &barrier_artifacts,
    );
    try expectHandoff(try planFor(
        &held,
        &barrier_program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .configure_barrier);
}

test "native_unpack.test.package disappearance is handed off" {
    const status =
        \\Package: oldpkg
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 1.0
        \\Description: old
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "oldpkg.list", .bytes = "/.\n/usr/share/only\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.init(status, &info);
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/only", "old\n");
    var data = [_]Entry{.{ .path = "usr/share/only", .content = "new\n" }};
    const bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "2.0",
        .control_fields = "Replaces: oldpkg (<< 2.0)\n",
    }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    try expectHandoff(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .package_disappearance);
}

test "native_unpack.test.ownership index and fuzz boundary are pure" {
    const paths = [_][]const u8{ "/.", "/usr", "/usr/bin/tool", "/usr/share/doc" };
    const record: package_database.PackageRecord = .{
        .name = "demo",
        .architecture = "amd64",
        .version = "1",
        .parsed_version = try version_module.DebianVersion.parse("1"),
        .status = .{ .want = .install, .error_state = .ok, .current = .unpacked },
        .multi_arch = null,
        .essential = false,
        .protected = false,
        .fields = &.{},
        .conffiles = &.{},
        .triggers_pending = &.{},
        .triggers_awaited = &.{},
        .info_stem = "demo",
        .paths = &paths,
        .md5sums = null,
        .declared_conffiles = null,
        .trigger_declarations = null,
        .scripts = &.{},
    };
    const records = [_]package_database.PackageRecord{record};
    const model: package_database.Model = .{
        .native_architecture = "amd64",
        .status = .{ .sha256 = @splat(0), .size = 0, .package_count = 1 },
        .packages = &records,
    };
    var ownership = try indexOwnership(
        testing.allocator,
        model,
        .{ .aliases = &.{}, .foreign = &.{} },
    );
    defer ownership.deinit();
    try testing.expect(ownership.owned("usr/bin/tool"));
    try testing.expectEqual(@as(usize, 1), ownership.ownersOf("usr/bin/tool").len);
    var prefix: [root_fs.maximum_path_bytes]u8 = undefined;
    try testing.expect(try ownership.hasSurvivingDescendant("usr", &.{}, 16, &prefix));
    fuzzOwnership(testing.allocator, "/usr/bin/tool\n/../bad\n/usr/share/doc\n");
}

test "native_unpack.test.refusal diagnostics own archive text" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{.{ .path = "VAR/LIB/DPKG/status", .content = "bad\n" }};
    const bytes = try buildOwnedArchive(.{ .package = "bad", .version = "1" }, &data);
    var model = try modelOf(bytes);
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    const result = try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    );
    model.deinit();
    testing.allocator.free(bytes);

    var refusal = switch (result) {
        .refusal => |value| value,
        else => return error.TestUnexpectedResult,
    };
    defer refusal.deinit();
    var churn: std.ArrayList([]u8) = .empty;
    defer {
        for (churn.items) |item| testing.allocator.free(item);
        churn.deinit(testing.allocator);
    }
    for (0..256) |index| {
        const allocation = try testing.allocator.alloc(u8, 128 + index);
        @memset(allocation, 0xa5);
        try churn.append(testing.allocator, allocation);
    }
    try testing.expectEqual(Code.reserved_path, refusal.diagnostic.code);
    try testing.expectEqualStrings("VAR/LIB/DPKG/status", refusal.diagnostic.path);
    try testing.expectEqualSlices(
        u8,
        &refusal.digest,
        &diagnosticDigest(refusal.diagnostic),
    );
}

test "native_unpack.test.every co-owner must authorize replacement" {
    const statuses = [_][]const u8{
        \\Package: alpha
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 1
        \\Description: alpha
        \\
        \\Package: beta
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 1
        \\Description: beta
        \\
        \\
        ,
        \\Package: beta
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 1
        \\Description: beta
        \\
        \\Package: alpha
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 1
        \\Description: alpha
        \\
        \\
        ,
    };
    const info = [_]package_database.InfoEntry{
        .{ .name = "alpha.list", .bytes = "/.\n/usr/share/shared\n/usr/share/alpha-keep\n" },
        .{ .name = "beta.list", .bytes = "/.\n/usr/share/shared\n/usr/share/beta-keep\n" },
    };
    for (statuses) |status| {
        var fixture: Fixture = undefined;
        try fixture.init(status, &info);
        defer fixture.deinit();
        try seedFile(fixture.root(), "usr/share/shared", "old\n");
        try seedFile(fixture.root(), "usr/share/alpha-keep", "a\n");
        try seedFile(fixture.root(), "usr/share/beta-keep", "b\n");
        var data = [_]Entry{.{ .path = "usr/share/shared", .content = "new\n" }};
        const bytes = try buildOwnedArchive(.{
            .package = "charlie",
            .version = "2",
            .control_fields = "Replaces: alpha (<< 2)\n",
        }, &data);
        defer testing.allocator.free(bytes);
        var model = try modelOf(bytes);
        defer model.deinit();
        const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
        var artifacts: [1]native_program.ProgramArtifact = undefined;
        const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
        try expectRefusal(try planFor(
            &fixture,
            &program,
            &.{.{ .artifact = 0, .bytes = bytes }},
        ), .ownership_conflict);

        var complete_data = [_]Entry{.{ .path = "usr/share/shared", .content = "new\n" }};
        const complete_bytes = try buildOwnedArchive(.{
            .package = "charlie",
            .version = "2",
            .control_fields = "Replaces: alpha (<< 2), beta (<< 2)\n",
        }, &complete_data);
        defer testing.allocator.free(complete_bytes);
        var complete_model = try modelOf(complete_bytes);
        defer complete_model.deinit();
        const complete_steps = [_]native_program.Step{
            unpackStep(0, &complete_model, 0, null, false),
        };
        var complete_artifacts: [1]native_program.ProgramArtifact = undefined;
        const complete_program = try singleProgram(
            &fixture,
            &complete_model,
            complete_bytes,
            &complete_steps,
            &complete_artifacts,
        );
        var complete = try expectPlan(try planFor(
            &fixture,
            &complete_program,
            &.{.{ .artifact = 0, .bytes = complete_bytes }},
        ));
        defer complete.deinit();
        try testing.expectEqual(@as(usize, 2), complete.displacements.len);
    }
}

test "native_unpack.test.invalid Replaces grammar authorizes nothing" {
    const status =
        \\Package: alpha
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 1
        \\Description: alpha
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "alpha.list", .bytes = "/.\n/usr/share/shared\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.init(status, &info);
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/shared", "old\n");
    const fields = [_][]const u8{
        "Replaces: alpha (<< 2) | beta\n",
        "Replaces: alpha [amd64]\n",
        "Replaces: alpha <stage1>\n",
    };
    for (fields) |control_fields| {
        var data = [_]Entry{.{ .path = "usr/share/shared", .content = "new\n" }};
        const bytes = try buildOwnedArchive(.{
            .package = "charlie",
            .version = "2",
            .control_fields = control_fields,
        }, &data);
        defer testing.allocator.free(bytes);
        var model = try modelOf(bytes);
        defer model.deinit();
        const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
        var artifacts: [1]native_program.ProgramArtifact = undefined;
        const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
        try expectRefusal(try planFor(
            &fixture,
            &program,
            &.{.{ .artifact = 0, .bytes = bytes }},
        ), .invalid_replaces);
    }
}

test "native_unpack.test.fresh multi arch siblings share one physical change" {
    var fixture: Fixture = undefined;
    try fixture.initFull(empty_status, &.{}, "arm64\n");
    defer fixture.deinit();

    var amd64_data = [_]Entry{.{ .path = "usr/share/demo/shared", .content = "same\n" }};
    var arm64_data = amd64_data;
    const amd64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .control_fields = "Multi-Arch: same\n",
    }, &amd64_data);
    defer testing.allocator.free(amd64_bytes);
    const arm64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "arm64",
        .control_fields = "Multi-Arch: same\n",
    }, &arm64_data);
    defer testing.allocator.free(arm64_bytes);
    var amd64_model = try modelOf(amd64_bytes);
    defer amd64_model.deinit();
    var arm64_model = try modelOf(arm64_bytes);
    defer arm64_model.deinit();
    var database = try fixture.database();
    defer database.deinit();
    const artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &amd64_model, amd64_bytes.len),
        testArtifact(1, &arm64_model, arm64_bytes.len),
    };
    const steps = [_]native_program.Step{
        unpackStep(0, &amd64_model, 0, null, false),
        unpackStep(1, &arm64_model, 1, null, false),
    };
    const program = testProgram(database.generation.sha256, 0, &artifacts, &steps);
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = arm64_bytes },
        },
    ));
    defer planned.deinit();
    try testing.expectEqual(@as(usize, 2), planned.packages.len);
    var physical: usize = 0;
    for (planned.filesystem) |change| switch (change) {
        .file => |file| {
            if (std.mem.eql(u8, file.path, "usr/share/demo/shared"))
                physical += 1;
        },
        else => {},
    };
    try testing.expectEqual(@as(usize, 1), physical);
    try testing.expect(planned.packages[0].paths[0].publish !=
        planned.packages[1].paths[0].publish);
    try expectRefusal(try planLimited(
        &fixture,
        &program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = arm64_bytes },
        },
        .{ .max_packages = 1 },
    ), .package_limit);
    try expectRefusal(try planLimited(
        &fixture,
        &program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = arm64_bytes },
        },
        .{ .max_artifacts = 1 },
    ), .artifact_mismatch);

    arm64_data[0].mode = 0o600;
    const mismatched_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "arm64",
        .control_fields = "Multi-Arch: same\n",
    }, &arm64_data);
    defer testing.allocator.free(mismatched_bytes);
    var mismatched_model = try modelOf(mismatched_bytes);
    defer mismatched_model.deinit();
    const mismatched_artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &amd64_model, amd64_bytes.len),
        testArtifact(1, &mismatched_model, mismatched_bytes.len),
    };
    const mismatched_steps = [_]native_program.Step{
        unpackStep(0, &amd64_model, 0, null, false),
        unpackStep(1, &mismatched_model, 1, null, false),
    };
    const mismatched_program = testProgram(
        database.generation.sha256,
        0,
        &mismatched_artifacts,
        &mismatched_steps,
    );
    try expectRefusal(try planFor(
        &fixture,
        &mismatched_program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = mismatched_bytes },
        },
    ), .multi_arch_content_mismatch);
}

test "native_unpack.test.nonempty unowned directory transition is refused" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/tree/foreign", "keep\n");
    var data = [_]Entry{.{ .path = "usr/share/tree", .content = "file\n" }};
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "1" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    try expectRefusal(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .directory_transition_unsafe);
}

test "native_unpack.test.case ambiguity and folded dpkg namespace fail closed" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    const cases = [_]struct {
        data: []const Entry,
        code: Code,
    }{
        .{
            .data = &.{.{ .path = "VAR/LIB/DPKG/status", .content = "bad\n" }},
            .code = .reserved_path,
        },
        .{
            .data = &.{
                .{ .path = "usr/share/Foo", .content = "a\n" },
                .{ .path = "usr/share/foo", .content = "b\n" },
            },
            .code = .case_alias,
        },
        .{
            .data = &.{.{ .path = "usr/share/café", .content = "x\n" }},
            .code = .casefold_unknown,
        },
    };
    for (cases) |case| {
        const mutable = try testing.allocator.dupe(Entry, case.data);
        defer testing.allocator.free(mutable);
        const bytes = try buildOwnedArchive(
            .{ .package = "demo", .version = "1" },
            mutable,
        );
        defer testing.allocator.free(bytes);
        var model = try modelOf(bytes);
        defer model.deinit();
        const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
        var artifacts: [1]native_program.ProgramArtifact = undefined;
        const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
        try expectRefusal(try planFor(
            &fixture,
            &program,
            &.{.{ .artifact = 0, .bytes = bytes }},
        ), case.code);
    }
}

test "native_unpack.test.removal triggers preserve every interested identity" {
    const status =
        \\Package: oldpkg
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1
        \\Description: old
        \\
        \\Package: consumer
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 1
        \\Multi-Arch: same
        \\Description: consumer
        \\
        \\Package: consumer
        \\Status: install ok unpacked
        \\Architecture: arm64
        \\Version: 1
        \\Multi-Arch: same
        \\Description: consumer
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "oldpkg.list", .bytes = "/.\n/usr/share/icons/old.png\n" },
        .{ .name = "consumer:amd64.list", .bytes = "/.\n" },
        .{ .name = "consumer:amd64.triggers", .bytes = "interest /usr/share/icons\n" },
        .{ .name = "consumer:arm64.list", .bytes = "/.\n" },
        .{ .name = "consumer:arm64.triggers", .bytes = "interest /usr/share/icons\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.initFull(status, &info, "arm64\n");
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/icons/old.png", "old\n");

    var data = [_]Entry{.{ .path = "usr/share/new", .content = "new\n" }};
    const bytes = try buildOwnedArchive(.{ .package = "oldpkg", .version = "2" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    var snapshot = fixture.snapshot();
    snapshot.triggers_file = package_database.regularFile(
        "/usr/share/icons consumer:amd64\n/usr/share/icons consumer:arm64\n",
    );
    const generation = try package_database.generation(testing.allocator, snapshot);
    const artifacts = [_]native_program.ProgramArtifact{testArtifact(0, &model, bytes.len)};
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, "1", false)};
    const program = testProgram(generation.sha256, 3, &artifacts, &steps);
    const result = try planSnapshot(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
        snapshot,
        .{},
    );
    var handoff = switch (result) {
        .handoff => |value| value,
        else => return error.TestUnexpectedResult,
    };
    defer handoff.deinit();
    var amd64 = false;
    var arm64 = false;
    for (handoff.items) |item| {
        if (item.feature != .trigger or
            !std.mem.eql(u8, item.detail, "usr/share/icons")) continue;
        if (std.mem.eql(u8, item.package, "consumer") and
            std.mem.eql(u8, item.architecture, "amd64")) amd64 = true;
        if (std.mem.eql(u8, item.package, "consumer") and
            std.mem.eql(u8, item.architecture, "arm64")) arm64 = true;
    }
    try testing.expect(amd64 and arm64);
    try expectRefusal(try planSnapshot(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
        snapshot,
        .{ .max_deferred = 1 },
    ), .deferred_limit);
}

test "native_unpack.test.Config-Version is preserved for an unpacked upgrade" {
    const status =
        \\Package: demo
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1.0
        \\Description: installed
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "demo.list", .bytes = "/.\n/usr/share/demo\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.init(status, &info);
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/demo", "old\n");
    var data = [_]Entry{.{ .path = "usr/share/demo", .content = "new\n" }};
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "2.0" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, "1.0", false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer planned.deinit();
    try testing.expectEqualStrings("1.0", planned.packages[0].configured_version.?);
    const status_write = planned.database.find("status") orelse
        return error.TestUnexpectedResult;
    try testing.expect(std.mem.indexOf(
        u8,
        status_write.bytes,
        "Config-Version: 1.0",
    ) != null);
}

test "native_unpack.test.existing directory metadata is never described as a write" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/admin/keep", "x\n");
    try fixture.root().applyMetadata(
        try root_fs.Path.init("usr/share/admin"),
        .{ .mode = 0o700 },
    );
    var data = [_]Entry{.{ .path = "usr/share/admin", .kind = '5', .mode = 0o755 }};
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "1" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer planned.deinit();
    try testing.expect(!planned.packages[0].paths[0].publish);
    const previous = planned.packages[0].paths[0].previous orelse
        return error.TestUnexpectedResult;
    try testing.expect(previous.directory_sha256 != null);
    try testing.expectEqual(@as(?u64, 1), previous.directory_entries);
    try testing.expect(previous.change_nanoseconds != null);
    for (planned.filesystem) |change| switch (change) {
        .directory => |directory| try testing.expect(
            !std.mem.eql(u8, directory.path, "usr/share/admin"),
        ),
        else => {},
    };
    try testing.expectEqual(
        @as(u32, 0o700),
        (try fixture.root().entry(try root_fs.Path.init("usr/share/admin"))).mode,
    );
}

test "native_unpack.test.all planner limits fail before evidence is dropped" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{
        .{ .path = "usr", .kind = '5' },
        .{ .path = "usr/share", .kind = '5' },
        .{ .path = "usr/share/demo", .content = "x\n" },
    };
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "1" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    const archives = [_]ArchiveInput{.{ .artifact = 0, .bytes = bytes }};
    var baseline = try expectPlan(try planFor(&fixture, &program, &archives));
    const path_count = baseline.path_count;
    const intent_count = baseline.filesystem.len;
    const model_bytes = baseline.model_bytes;
    const work_units = baseline.work_units;
    baseline.deinit();
    try testing.expect(path_count > 0 and intent_count > 0 and
        model_bytes > 0 and work_units > 0);

    const exact = [_]Limits{
        .{ .max_archive_bytes = bytes.len },
        .{ .max_model_bytes = model_bytes },
        .{ .max_total_paths = path_count },
        .{ .max_intents = intent_count },
        .{ .max_work = work_units },
    };
    for (exact) |limits| {
        var accepted = try expectPlan(try planLimited(
            &fixture,
            &program,
            &archives,
            limits,
        ));
        accepted.deinit();
    }

    try expectRefusal(try planLimited(&fixture, &program, &archives, .{
        .max_archive_bytes = bytes.len - 1,
    }), .path_limit);
    try expectRefusal(try planLimited(&fixture, &program, &archives, .{
        .max_model_bytes = model_bytes - 1,
    }), .path_limit);
    try expectRefusal(try planLimited(&fixture, &program, &archives, .{
        .max_total_paths = path_count - 1,
    }), .path_limit);
    try expectRefusal(try planLimited(&fixture, &program, &archives, .{
        .max_intents = intent_count - 1,
    }), .path_limit);
    try expectRefusal(try planLimited(&fixture, &program, &archives, .{
        .max_work = work_units - 1,
    }), .path_limit);
    try expectRefusal(try planLimited(&fixture, &program, &archives, .{
        .max_artifacts = 0,
    }), .artifact_mismatch);
    try expectRefusal(try planLimited(&fixture, &program, &archives, .{
        .max_paths_per_package = 0,
    }), .path_limit);
    try expectRefusal(try planFor(
        &fixture,
        &program,
        &.{
            .{ .artifact = 0, .bytes = bytes },
            .{ .artifact = 0, .bytes = bytes },
        },
    ), .artifact_duplicate);
}

test "native_unpack.test.live model budget covers control relationship AST" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();

    var control: std.ArrayList(u8) = .empty;
    defer control.deinit(testing.allocator);
    try control.appendSlice(testing.allocator, "Depends: ");
    for (0..512) |index| {
        var buffer: [64]u8 = undefined;
        const term = try std.fmt.bufPrint(
            &buffer,
            "{s}dependency-{d}",
            .{ if (index == 0) "" else ", ", index },
        );
        try control.appendSlice(testing.allocator, term);
    }
    try control.append(testing.allocator, '\n');

    var data = [_]Entry{.{
        .path = "usr/share/demo",
        .content = "payload\n",
    }};
    const bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .control_fields = control.items,
    }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    const archives = [_]ArchiveInput{.{ .artifact = 0, .bytes = bytes }};
    var baseline = try expectPlan(try planFor(&fixture, &program, &archives));
    const peak = baseline.model_bytes;
    baseline.deinit();
    try testing.expect(peak > control.items.len);

    var exact = try expectPlan(try planLimited(
        &fixture,
        &program,
        &archives,
        .{ .max_model_bytes = peak },
    ));
    exact.deinit();
    try expectRefusal(try planLimited(
        &fixture,
        &program,
        &archives,
        .{ .max_model_bytes = peak - 1 },
    ), .path_limit);
    try expectRefusal(try planLimited(
        &fixture,
        &program,
        &archives,
        .{ .max_model_bytes = 1 },
    ), .path_limit);
}

test "native_unpack.test.zero evidence limits refuse instead of truncating" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();

    var conffile_data = [_]Entry{.{ .path = "etc/demo.conf", .content = "x\n" }};
    const conffile_bytes = try archive_application.test_fixtures.build(testing.allocator, .{
        .package = "demo",
        .version = "1",
        .control = &.{.{ .path = "conffiles", .content = "/etc/demo.conf\n" }},
        .data = &conffile_data,
    });
    defer testing.allocator.free(conffile_bytes);
    var conffile_model = try modelOf(conffile_bytes);
    defer conffile_model.deinit();
    const conffile_steps = [_]native_program.Step{
        unpackStep(0, &conffile_model, 0, null, false),
    };
    var conffile_artifacts: [1]native_program.ProgramArtifact = undefined;
    const conffile_program = try singleProgram(
        &fixture,
        &conffile_model,
        conffile_bytes,
        &conffile_steps,
        &conffile_artifacts,
    );
    try expectRefusal(try planLimited(
        &fixture,
        &conffile_program,
        &.{.{ .artifact = 0, .bytes = conffile_bytes }},
        .{ .max_deferred = 0 },
    ), .deferred_limit);

    var case_data = [_]Entry{
        .{ .path = "usr/share/Foo", .content = "a\n" },
        .{ .path = "usr/share/foo", .content = "b\n" },
    };
    const case_bytes = try buildOwnedArchive(.{ .package = "demo", .version = "1" }, &case_data);
    defer testing.allocator.free(case_bytes);
    var case_model = try modelOf(case_bytes);
    defer case_model.deinit();
    const case_steps = [_]native_program.Step{unpackStep(0, &case_model, 0, null, false)};
    var case_artifacts: [1]native_program.ProgramArtifact = undefined;
    const case_program = try singleProgram(
        &fixture,
        &case_model,
        case_bytes,
        &case_steps,
        &case_artifacts,
    );
    try expectRefusal(try planLimited(
        &fixture,
        &case_program,
        &.{.{ .artifact = 0, .bytes = case_bytes }},
        .{ .max_case_aliases = 0 },
    ), .case_alias_limit);
    try expectRefusal(try planLimited(
        &fixture,
        &case_program,
        &.{.{ .artifact = 0, .bytes = case_bytes }},
        .{ .max_case_index_bytes = 0 },
    ), .case_alias_limit);
}

test "native_unpack.test.Config-Version distinguishes configured and never-configured unpack" {
    const with_config =
        \\Package: demo
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 2.0
        \\Config-Version: 1.5
        \\Description: unpacked
        \\
        \\
    ;
    const without_config =
        \\Package: demo
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 2.0
        \\Description: unpacked
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "demo.list", .bytes = "/.\n/usr/share/demo\n" },
    };
    var data = [_]Entry{.{ .path = "usr/share/demo", .content = "new\n" }};
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "3.0" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, "2.0", false)};

    var configured: Fixture = undefined;
    try configured.init(with_config, &info);
    defer configured.deinit();
    try seedFile(configured.root(), "usr/share/demo", "old\n");
    var configured_artifacts: [1]native_program.ProgramArtifact = undefined;
    const configured_program = try singleProgram(
        &configured,
        &model,
        bytes,
        &steps,
        &configured_artifacts,
    );
    var planned = try expectPlan(try planFor(
        &configured,
        &configured_program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer planned.deinit();
    try testing.expectEqualStrings("1.5", planned.packages[0].configured_version.?);

    var missing: Fixture = undefined;
    try missing.init(without_config, &info);
    defer missing.deinit();
    try seedFile(missing.root(), "usr/share/demo", "old\n");
    var missing_artifacts: [1]native_program.ProgramArtifact = undefined;
    const missing_program = try singleProgram(
        &missing,
        &model,
        bytes,
        &steps,
        &missing_artifacts,
    );
    var never_configured = try expectPlan(try planFor(
        &missing,
        &missing_program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer never_configured.deinit();
    try testing.expect(never_configured.packages[0].configured_version == null);
    const status_write = never_configured.database.find("status") orelse
        return error.TestUnexpectedResult;
    try testing.expect(
        std.mem.indexOf(u8, status_write.bytes, "Config-Version:") == null,
    );
}

test "native_unpack.test.large ownership lowering is linearly budgeted" {
    // Together with the mandatory `/.` record this reaches the database's
    // exact 200,000-path per-package bound.
    const count: usize = 199_999;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try list.appendSlice(testing.allocator, "/.\n");
    var line_buffer: [64]u8 = undefined;
    for (0..count) |index| {
        const line = try std.fmt.bufPrint(&line_buffer, "/usr/share/bulk/{d}\n", .{index});
        try list.appendSlice(testing.allocator, line);
    }
    const status =
        \\Package: oldpkg
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 1
        \\Description: old
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "oldpkg.list", .bytes = list.items },
    };
    var fixture: Fixture = undefined;
    try fixture.init(status, &info);
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/bulk/0", "old\n");
    try seedFile(fixture.root(), "usr/share/bulk/1", "keep\n");

    var data = [_]Entry{.{ .path = "usr/share/bulk/0", .content = "new\n" }};
    const bytes = try buildOwnedArchive(.{
        .package = "newpkg",
        .version = "2",
        .control_fields = "Replaces: oldpkg (<< 2)\n",
    }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer planned.deinit();
    try testing.expect(planned.work_units < count * 9 + 200);
    const updated = planned.database.find("info/oldpkg.list") orelse
        return error.TestUnexpectedResult;
    try testing.expect(std.mem.indexOf(u8, updated.bytes, "/usr/share/bulk/0\n") == null);
    try testing.expect(std.mem.indexOf(
        u8,
        updated.bytes,
        "/usr/share/bulk/199998\n",
    ) != null);
}

test "native_unpack.test.planner owns every allocation failure path" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{
        .{ .path = "usr", .kind = '5' },
        .{ .path = "usr/share/demo", .content = "x\n" },
    };
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "1" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    try testing.checkAllAllocationFailures(
        testing.allocator,
        planUnderAllocationFailure,
        .{ &fixture, &program, bytes },
    );
}

fn planUnderAllocationFailure(
    allocator: std.mem.Allocator,
    fixture: *Fixture,
    program: *const native_program.Program,
    bytes: []const u8,
) !void {
    const result = try plan(allocator, .{
        .program = program,
        .snapshot = fixture.snapshot(),
        .archives = &.{.{ .artifact = 0, .bytes = bytes }},
        .root = fixture.root(),
        .interoperability = .isolated_root,
    });
    switch (result) {
        .plan => |value| {
            var owned = value;
            owned.deinit();
        },
        .handoff => |value| {
            var owned = value;
            owned.deinit();
            return error.TestUnexpectedResult;
        },
        .refusal => |value| {
            var owned = value;
            defer owned.deinit();
            if (owned.diagnostic.code != .out_of_memory)
                return error.TestUnexpectedResult;
            return error.OutOfMemory;
        },
    }
}

test "native_unpack.test.coordinated Multi-Arch upgrades are order independent" {
    const status =
        \\Package: demo
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1
        \\Multi-Arch: same
        \\Description: old
        \\
        \\Package: demo
        \\Status: install ok installed
        \\Architecture: arm64
        \\Version: 1
        \\Multi-Arch: same
        \\Description: old
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "demo:amd64.list", .bytes = "/.\n/usr/share/demo/shared\n" },
        .{ .name = "demo:amd64.md5sums", .bytes = "814fa5ca98406a903e22b43d9b610105  usr/share/demo/shared\n" },
        .{ .name = "demo:arm64.list", .bytes = "/.\n/usr/share/demo/shared\n" },
        .{ .name = "demo:arm64.md5sums", .bytes = "814fa5ca98406a903e22b43d9b610105  usr/share/demo/shared\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.initFull(status, &info, "arm64\n");
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/demo/shared", "old\n");

    var amd64_data = [_]Entry{.{ .path = "usr/share/demo/shared", .content = "new\n" }};
    var arm64_data = amd64_data;
    const amd64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "2",
        .architecture = "amd64",
        .control_fields = "Multi-Arch: same\n",
    }, &amd64_data);
    defer testing.allocator.free(amd64_bytes);
    const arm64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "2",
        .architecture = "arm64",
        .control_fields = "Multi-Arch: same\n",
    }, &arm64_data);
    defer testing.allocator.free(arm64_bytes);
    var amd64_model = try modelOf(amd64_bytes);
    defer amd64_model.deinit();
    var arm64_model = try modelOf(arm64_bytes);
    defer arm64_model.deinit();
    var database = try fixture.database();
    defer database.deinit();
    const artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &amd64_model, amd64_bytes.len),
        testArtifact(1, &arm64_model, arm64_bytes.len),
    };
    const forward = [_]native_program.Step{
        unpackStep(0, &amd64_model, 0, "1", false),
        unpackStep(1, &arm64_model, 1, "1", false),
    };
    const reverse = [_]native_program.Step{
        unpackStep(0, &arm64_model, 1, "1", false),
        unpackStep(1, &amd64_model, 0, "1", false),
    };
    const archives = [_]ArchiveInput{
        .{ .artifact = 0, .bytes = amd64_bytes },
        .{ .artifact = 1, .bytes = arm64_bytes },
    };
    const first_program = testProgram(database.generation.sha256, 2, &artifacts, &forward);
    const second_program = testProgram(database.generation.sha256, 2, &artifacts, &reverse);
    var first = try expectPlan(try planFor(&fixture, &first_program, &archives));
    defer first.deinit();
    var second = try expectPlan(try planFor(&fixture, &second_program, &archives));
    defer second.deinit();
    try testing.expectEqualSlices(u8, &first.digest, &second.digest);
    var replacements: usize = 0;
    for (first.filesystem) |change| switch (change) {
        .file => |file| if (std.mem.eql(u8, file.path, "usr/share/demo/shared")) {
            replacements += 1;
        },
        else => {},
    };
    try testing.expectEqual(@as(usize, 1), replacements);
}

test "native_unpack.test.final ownership graph cancels order-dependent removals" {
    const status =
        \\Package: alpha
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1
        \\Description: alpha
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "alpha.list", .bytes = "/.\n/usr/share/shared\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.init(status, &info);
    defer fixture.deinit();
    try fixture.root().ensureDirectory(
        try root_fs.Path.init("usr"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().ensureDirectory(
        try root_fs.Path.init("usr/share"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().ensureDirectory(
        try root_fs.Path.init("usr/share/shared"),
        root_fs.default_directory_permissions,
    );

    var alpha_data = [_]Entry{.{ .path = "usr/share/alpha", .content = "a\n" }};
    var beta_data = [_]Entry{.{ .path = "usr/share/shared", .kind = '5' }};
    const alpha_bytes = try buildOwnedArchive(.{ .package = "alpha", .version = "2" }, &alpha_data);
    defer testing.allocator.free(alpha_bytes);
    const beta_bytes = try buildOwnedArchive(.{ .package = "beta", .version = "1" }, &beta_data);
    defer testing.allocator.free(beta_bytes);
    var alpha_model = try modelOf(alpha_bytes);
    defer alpha_model.deinit();
    var beta_model = try modelOf(beta_bytes);
    defer beta_model.deinit();
    var database = try fixture.database();
    defer database.deinit();
    const artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &alpha_model, alpha_bytes.len),
        testArtifact(1, &beta_model, beta_bytes.len),
    };
    const forward = [_]native_program.Step{
        unpackStep(0, &alpha_model, 0, "1", false),
        unpackStep(1, &beta_model, 1, null, false),
    };
    const reverse = [_]native_program.Step{
        unpackStep(0, &beta_model, 1, null, false),
        unpackStep(1, &alpha_model, 0, "1", false),
    };
    const archives = [_]ArchiveInput{
        .{ .artifact = 0, .bytes = alpha_bytes },
        .{ .artifact = 1, .bytes = beta_bytes },
    };
    const first_program = testProgram(database.generation.sha256, 1, &artifacts, &forward);
    const second_program = testProgram(database.generation.sha256, 1, &artifacts, &reverse);
    var first = try expectPlan(try planFor(&fixture, &first_program, &archives));
    defer first.deinit();
    var second = try expectPlan(try planFor(&fixture, &second_program, &archives));
    defer second.deinit();
    try testing.expectEqualSlices(u8, &first.digest, &second.digest);
    for (first.filesystem) |change| switch (change) {
        .remove => |removal| try testing.expect(
            !std.mem.eql(u8, removal.path, "usr/share/shared"),
        ),
        else => {},
    };
}

test "native_unpack.test.unchanged Multi-Arch owner suppresses transaction publish" {
    const status =
        \\Package: demo
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1
        \\Multi-Arch: same
        \\Description: demo
        \\
        \\Package: demo
        \\Status: install ok installed
        \\Architecture: arm64
        \\Version: 1
        \\Multi-Arch: same
        \\Description: demo
        \\
        \\Package: demo
        \\Status: install ok installed
        \\Architecture: i386
        \\Version: 1
        \\Multi-Arch: same
        \\Description: demo
        \\
        \\
    ;
    const checksum = try archive_application.test_fixtures.checksumLine(
        testing.allocator,
        "shared\n",
        "usr/share/demo/shared",
    );
    defer testing.allocator.free(checksum);
    const info = [_]package_database.InfoEntry{
        .{
            .name = "demo:amd64.list",
            .bytes = "/.\n/usr/share/demo/shared\n",
        },
        .{ .name = "demo:amd64.md5sums", .bytes = checksum },
        .{
            .name = "demo:arm64.list",
            .bytes = "/.\n/usr/share/demo/shared\n",
        },
        .{ .name = "demo:arm64.md5sums", .bytes = checksum },
        .{
            .name = "demo:i386.list",
            .bytes = "/.\n/usr/share/demo/shared\n",
        },
        .{ .name = "demo:i386.md5sums", .bytes = checksum },
    };
    var fixture: Fixture = undefined;
    try fixture.initFull(status, &info, "arm64\ni386\n");
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/demo/shared", "shared\n");
    try fixture.root().applyMetadata(
        try root_fs.Path.init("usr/share/demo/shared"),
        .{
            .mode = 0o644,
            .uid = currentUid(),
            .gid = currentGid(),
            .modified_nanoseconds = test_mtime_ns,
        },
    );
    var amd64_data = [_]Entry{.{
        .path = "usr/share/demo/shared",
        .content = "shared\n",
    }};
    var arm64_data = amd64_data;
    const amd64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "2",
        .architecture = "amd64",
        .control_fields = "Multi-Arch: same\n",
    }, &amd64_data);
    defer testing.allocator.free(amd64_bytes);
    const arm64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "2",
        .architecture = "arm64",
        .control_fields = "Multi-Arch: same\n",
    }, &arm64_data);
    defer testing.allocator.free(arm64_bytes);
    var amd64_model = try modelOf(amd64_bytes);
    defer amd64_model.deinit();
    var arm64_model = try modelOf(arm64_bytes);
    defer arm64_model.deinit();
    var database = try fixture.database();
    defer database.deinit();
    const artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &amd64_model, amd64_bytes.len),
        testArtifact(1, &arm64_model, arm64_bytes.len),
    };
    const steps = [_]native_program.Step{
        unpackStep(0, &amd64_model, 0, "1", false),
        unpackStep(1, &arm64_model, 1, "1", false),
    };
    const program = testProgram(
        database.generation.sha256,
        3,
        &artifacts,
        &steps,
    );
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = arm64_bytes },
        },
    ));
    defer planned.deinit();
    for (planned.packages) |package| {
        try testing.expectEqual(@as(usize, 1), package.paths.len);
        try testing.expect(!package.paths[0].publish);
    }
    for (planned.filesystem) |change| switch (change) {
        .file => |file| try testing.expect(
            !std.mem.eql(u8, file.path, "usr/share/demo/shared"),
        ),
        else => {},
    };
}

test "native_unpack.test.all retiring Multi-Arch owners remove one shared path" {
    const status =
        \\Package: demo
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1
        \\Multi-Arch: same
        \\Description: demo
        \\
        \\Package: demo
        \\Status: install ok installed
        \\Architecture: arm64
        \\Version: 1
        \\Multi-Arch: same
        \\Description: demo
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "demo:amd64.list", .bytes = "/.\n/usr/share/demo/shared\n" },
        .{ .name = "demo:arm64.list", .bytes = "/.\n/usr/share/demo/shared\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.initFull(status, &info, "arm64\n");
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/demo/shared", "old\n");
    var amd64_data = [_]Entry{.{ .path = "usr/share/demo/amd64", .content = "a\n" }};
    var arm64_data = [_]Entry{.{ .path = "usr/share/demo/arm64", .content = "b\n" }};
    const amd64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "2",
        .architecture = "amd64",
        .control_fields = "Multi-Arch: same\n",
    }, &amd64_data);
    defer testing.allocator.free(amd64_bytes);
    const arm64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "2",
        .architecture = "arm64",
        .control_fields = "Multi-Arch: same\n",
    }, &arm64_data);
    defer testing.allocator.free(arm64_bytes);
    var amd64_model = try modelOf(amd64_bytes);
    defer amd64_model.deinit();
    var arm64_model = try modelOf(arm64_bytes);
    defer arm64_model.deinit();
    var database = try fixture.database();
    defer database.deinit();
    const artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &amd64_model, amd64_bytes.len),
        testArtifact(1, &arm64_model, arm64_bytes.len),
    };
    const steps = [_]native_program.Step{
        unpackStep(0, &arm64_model, 1, "1", false),
        unpackStep(1, &amd64_model, 0, "1", false),
    };
    const program = testProgram(database.generation.sha256, 2, &artifacts, &steps);
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = arm64_bytes },
        },
    ));
    defer planned.deinit();
    var removals: usize = 0;
    for (planned.filesystem) |change| switch (change) {
        .remove => |removal| if (std.mem.eql(u8, removal.path, "usr/share/demo/shared")) {
            removals += 1;
        },
        else => {},
    };
    try testing.expectEqual(@as(usize, 1), removals);
}

test "native_unpack.test.returned plan owns every nested text slice" {
    const status = try testing.allocator.dupe(u8,
        \\Package: oldpkg
        \\Status: install ok unpacked
        \\Architecture: amd64
        \\Version: 1
        \\Description: old
        \\
        \\
    );
    const list = try testing.allocator.dupe(
        u8,
        "/.\n/usr/share/shared\n/usr/share/keep\n",
    );
    var info = [_]package_database.InfoEntry{.{
        .name = "oldpkg.list",
        .bytes = list,
    }};
    var fixture: Fixture = undefined;
    try fixture.init(status, &info);
    try seedFile(fixture.root(), "usr/share/shared", "old\n");
    try seedFile(fixture.root(), "usr/share/keep", "keep\n");

    var data = [_]Entry{.{ .path = "usr/share/shared", .content = "new\n" }};
    const bytes = try buildOwnedArchive(.{
        .package = "charlie",
        .version = "2",
        .control_fields = "Replaces: oldpkg (<< 2)\n",
    }, &data);
    var model = try modelOf(bytes);
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer planned.deinit();

    model.deinit();
    testing.allocator.free(bytes);
    fixture.deinit();
    testing.allocator.free(status);
    testing.allocator.free(list);
    @memset(&info, undefined);
    @memset(&artifacts, undefined);

    var churn: std.ArrayList([]u8) = .empty;
    defer {
        for (churn.items) |item| testing.allocator.free(item);
        churn.deinit(testing.allocator);
    }
    for (0..512) |index| {
        const allocation = try testing.allocator.alloc(u8, 64 + index);
        @memset(allocation, 0xcc);
        try churn.append(testing.allocator, allocation);
    }

    try testing.expectEqualStrings("charlie", planned.packages[0].identity.name);
    try testing.expectEqualStrings("amd64", planned.packages[0].identity.architecture);
    try testing.expectEqualStrings("usr/share/shared", planned.packages[0].paths[0].path);
    try testing.expectEqualStrings("oldpkg", planned.displacements[0].holder.name);
    try testing.expectEqualStrings("usr/share/shared", planned.displacements[0].path);
    const holder_list = planned.database.find("info/oldpkg.list") orelse
        return error.TestUnexpectedResult;
    try testing.expect(std.mem.indexOf(u8, holder_list.bytes, "/usr/share/keep") != null);
    const status_write = planned.database.find("status") orelse
        return error.TestUnexpectedResult;
    try testing.expect(std.mem.indexOf(u8, status_write.bytes, "Package: charlie") != null);
    try testing.expectEqualSlices(u8, &planned.digest, &planDigest(planned));
}

test "native_unpack.test.fresh Multi-Arch symlinks share only exact targets" {
    var fixture: Fixture = undefined;
    try fixture.initFull(empty_status, &.{}, "arm64\n");
    defer fixture.deinit();
    var amd64_data = [_]Entry{.{
        .path = "usr/lib/libdemo.so",
        .kind = '2',
        .link = "libdemo.so.1",
    }};
    var arm64_data = amd64_data;
    const amd64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .control_fields = "Multi-Arch: same\n",
    }, &amd64_data);
    defer testing.allocator.free(amd64_bytes);
    const arm64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "arm64",
        .control_fields = "Multi-Arch: same\n",
    }, &arm64_data);
    defer testing.allocator.free(arm64_bytes);
    var amd64_model = try modelOf(amd64_bytes);
    defer amd64_model.deinit();
    var arm64_model = try modelOf(arm64_bytes);
    defer arm64_model.deinit();
    var database = try fixture.database();
    defer database.deinit();
    const artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &amd64_model, amd64_bytes.len),
        testArtifact(1, &arm64_model, arm64_bytes.len),
    };
    const steps = [_]native_program.Step{
        unpackStep(0, &amd64_model, 0, null, false),
        unpackStep(1, &arm64_model, 1, null, false),
    };
    const program = testProgram(database.generation.sha256, 0, &artifacts, &steps);
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = arm64_bytes },
        },
    ));
    defer planned.deinit();
    var links: usize = 0;
    for (planned.filesystem) |change| switch (change) {
        .symlink => |link| if (std.mem.eql(u8, link.path, "usr/lib/libdemo.so")) {
            links += 1;
        },
        else => {},
    };
    try testing.expectEqual(@as(usize, 1), links);

    arm64_data[0].link = "other.so.1";
    const mismatched = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "arm64",
        .control_fields = "Multi-Arch: same\n",
    }, &arm64_data);
    defer testing.allocator.free(mismatched);
    var mismatch_model = try modelOf(mismatched);
    defer mismatch_model.deinit();
    const mismatch_artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &amd64_model, amd64_bytes.len),
        testArtifact(1, &mismatch_model, mismatched.len),
    };
    const mismatch_steps = [_]native_program.Step{
        unpackStep(0, &amd64_model, 0, null, false),
        unpackStep(1, &mismatch_model, 1, null, false),
    };
    const mismatch_program = testProgram(
        database.generation.sha256,
        0,
        &mismatch_artifacts,
        &mismatch_steps,
    );
    try expectRefusal(try planFor(
        &fixture,
        &mismatch_program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = mismatched },
        },
    ), .multi_arch_content_mismatch);
}

test "native_unpack.test.malformed Config-Version never reaches status output" {
    const values = [_][]const u8{ "", " 1.0 ", "not a version" };
    for (values) |value| {
        const status = try std.fmt.allocPrint(
            testing.allocator,
            "Package: demo\nStatus: install ok unpacked\nArchitecture: amd64\nVersion: 2\nConfig-Version: {s}\nDescription: demo\n\n",
            .{value},
        );
        defer testing.allocator.free(status);
        const info = [_]package_database.InfoEntry{
            .{ .name = "demo.list", .bytes = "/.\n/usr/share/demo\n" },
        };
        var fixture: Fixture = undefined;
        try fixture.init(status, &info);
        defer fixture.deinit();
        try seedFile(fixture.root(), "usr/share/demo", "old\n");
        var data = [_]Entry{.{ .path = "usr/share/demo", .content = "new\n" }};
        const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "3" }, &data);
        defer testing.allocator.free(bytes);
        var model = try modelOf(bytes);
        defer model.deinit();
        const steps = [_]native_program.Step{unpackStep(0, &model, 0, "2", false)};
        var artifacts: [1]native_program.ProgramArtifact = undefined;
        const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
        try expectHandoff(try planFor(
            &fixture,
            &program,
            &.{.{ .artifact = 0, .bytes = bytes }},
        ), .config_version);
    }
}

test "native_unpack.test.root observation failures and symlink directories fail closed" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    try fixture.root().ensureDirectory(
        try root_fs.Path.init("usr"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().ensureDirectory(
        try root_fs.Path.init("usr/share"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().ensureDirectory(
        try root_fs.Path.init("usr/share/real"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().createSymbolicLink(
        try root_fs.Path.init("usr/share/linkdir"),
        "real",
    );
    var directory_data = [_]Entry{.{ .path = "usr/share/linkdir", .kind = '5' }};
    const directory_bytes = try buildOwnedArchive(
        .{ .package = "demo", .version = "1" },
        &directory_data,
    );
    defer testing.allocator.free(directory_bytes);
    var directory_model = try modelOf(directory_bytes);
    defer directory_model.deinit();
    const directory_steps = [_]native_program.Step{
        unpackStep(0, &directory_model, 0, null, false),
    };
    var directory_artifacts: [1]native_program.ProgramArtifact = undefined;
    const directory_program = try singleProgram(
        &fixture,
        &directory_model,
        directory_bytes,
        &directory_steps,
        &directory_artifacts,
    );
    try expectRefusal(try planFor(
        &fixture,
        &directory_program,
        &.{.{ .artifact = 0, .bytes = directory_bytes }},
    ), .directory_transition_unsafe);

    try fixture.root().ensureDirectory(
        try root_fs.Path.init("usr/lib"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().createSymbolicLink(try root_fs.Path.init("lib"), "usr/lib");
    var folded_data = [_]Entry{.{ .path = "LIB/tool", .content = "x\n" }};
    const folded_bytes = try buildOwnedArchive(
        .{ .package = "folded", .version = "1" },
        &folded_data,
    );
    defer testing.allocator.free(folded_bytes);
    var folded_model = try modelOf(folded_bytes);
    defer folded_model.deinit();
    const folded_steps = [_]native_program.Step{
        unpackStep(0, &folded_model, 0, null, false),
    };
    var folded_artifacts: [1]native_program.ProgramArtifact = undefined;
    const folded_program = try singleProgram(
        &fixture,
        &folded_model,
        folded_bytes,
        &folded_steps,
        &folded_artifacts,
    );
    try expectRefusal(try planFor(
        &fixture,
        &folded_program,
        &.{.{ .artifact = 0, .bytes = folded_bytes }},
    ), .case_alias);

    var closed = try fixture.tmp.dir.openDir(testing.io, ".", .{ .iterate = true });
    const closed_root: root_fs.Root = .init(testing.io, closed);
    closed.close(testing.io);
    try expectRefusal(try plan(testing.allocator, .{
        .program = &directory_program,
        .snapshot = fixture.snapshot(),
        .archives = &.{.{ .artifact = 0, .bytes = directory_bytes }},
        .root = closed_root,
        .interoperability = .isolated_root,
    }), .root_unreadable);

    const unmodeled: PreviousState = .{
        .kind = .regular,
        .owned = true,
        .modeled = false,
        .mode = 0o644,
        .uid = 0,
        .gid = 0,
        .size = 1,
        .device = 0,
        .inode = 0,
        .link_count = 1,
        .modified_nanoseconds = 0,
    };
    try testing.expect(!modeledMetadataMatches(unmodeled, 0o644, 0, 0, 0));
}

test "native_unpack.test.merged usr alias detection owns every OOM path" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root: root_fs.Root = .init(testing.io, tmp.dir);
    try root.ensureDirectory(
        try root_fs.Path.init("usr"),
        root_fs.default_directory_permissions,
    );
    try root.ensureDirectory(
        try root_fs.Path.init("usr/lib"),
        root_fs.default_directory_permissions,
    );
    try root.createSymbolicLink(try root_fs.Path.init("lib"), "usr/lib");
    try testing.checkAllAllocationFailures(
        testing.allocator,
        detectAliasesUnderAllocationFailure,
        .{root},
    );
}

fn detectAliasesUnderAllocationFailure(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
) !void {
    const evidence = try detectAliases(allocator, root);
    defer deinitAliasEvidence(allocator, evidence);
    if (evidence.aliases.len != 1) return error.TestUnexpectedResult;
}

test "native_unpack.test.final descendants preserve obsolete directory ancestors" {
    const status =
        \\Package: alpha
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1
        \\Description: alpha
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "alpha.list", .bytes = "/.\n/opt/shared\n/usr/share/alpha\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.init(status, &info);
    defer fixture.deinit();
    try fixture.root().createDirectoryPath(
        try root_fs.Path.init("opt/shared"),
        root_fs.default_directory_permissions,
    );
    try seedFile(fixture.root(), "usr/share/alpha", "old\n");

    var alpha_data = [_]Entry{.{
        .path = "usr/share/alpha",
        .content = "new\n",
    }};
    var beta_data = [_]Entry{.{
        .path = "opt/shared/new",
        .content = "new\n",
    }};
    const alpha_bytes = try buildOwnedArchive(
        .{ .package = "alpha", .version = "2" },
        &alpha_data,
    );
    defer testing.allocator.free(alpha_bytes);
    const beta_bytes = try buildOwnedArchive(
        .{ .package = "beta", .version = "1" },
        &beta_data,
    );
    defer testing.allocator.free(beta_bytes);
    var alpha_model = try modelOf(alpha_bytes);
    defer alpha_model.deinit();
    var beta_model = try modelOf(beta_bytes);
    defer beta_model.deinit();
    var database = try fixture.database();
    defer database.deinit();
    const artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &alpha_model, alpha_bytes.len),
        testArtifact(1, &beta_model, beta_bytes.len),
    };
    var first_digest: ?[32]u8 = null;
    for (0..2) |permutation| {
        var steps = [_]native_program.Step{
            unpackStep(0, &alpha_model, 0, "1", false),
            unpackStep(1, &beta_model, 1, null, false),
        };
        if (permutation != 0) {
            steps[0] = unpackStep(0, &beta_model, 1, null, false);
            steps[1] = unpackStep(1, &alpha_model, 0, "1", false);
        }
        const program = testProgram(
            database.generation.sha256,
            1,
            &artifacts,
            &steps,
        );
        var planned = try expectPlan(try planFor(
            &fixture,
            &program,
            &.{
                .{ .artifact = 0, .bytes = alpha_bytes },
                .{ .artifact = 1, .bytes = beta_bytes },
            },
        ));
        defer planned.deinit();
        if (first_digest) |digest|
            try testing.expectEqualSlices(u8, &digest, &planned.digest)
        else
            first_digest = planned.digest;
        var child_index: ?usize = null;
        for (planned.filesystem, 0..) |change, index| switch (change) {
            .remove => |removal| try testing.expect(
                !std.mem.eql(u8, removal.path, "opt/shared"),
            ),
            .file => |file| {
                if (std.mem.eql(u8, file.path, "opt/shared/new"))
                    child_index = index;
            },
            else => {},
        };
        try testing.expect(child_index != null);
        var retained_shared = false;
        for (planned.retained_directories) |retained| {
            if (!std.mem.eql(u8, retained.path, "opt/shared")) continue;
            retained_shared = true;
            try testing.expect(retained.previous.directory_sha256 != null);
        }
        try testing.expect(retained_shared);
    }
}

test "native_unpack.test.fresh shared directory publisher follows program order" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var z_data = [_]Entry{.{
        .path = "shared",
        .kind = '5',
        .mode = 0o700,
    }};
    var a_data = [_]Entry{.{
        .path = "shared",
        .kind = '5',
        .mode = 0o755,
    }};
    const z_bytes = try buildOwnedArchive(
        .{ .package = "zpkg", .version = "1" },
        &z_data,
    );
    defer testing.allocator.free(z_bytes);
    const a_bytes = try buildOwnedArchive(
        .{ .package = "apkg", .version = "1" },
        &a_data,
    );
    defer testing.allocator.free(a_bytes);
    var z_model = try modelOf(z_bytes);
    defer z_model.deinit();
    var a_model = try modelOf(a_bytes);
    defer a_model.deinit();
    var database = try fixture.database();
    defer database.deinit();
    const artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &z_model, z_bytes.len),
        testArtifact(1, &a_model, a_bytes.len),
    };
    for (0..2) |permutation| {
        var steps = [_]native_program.Step{
            unpackStep(0, &z_model, 0, null, false),
            unpackStep(1, &a_model, 1, null, false),
        };
        var expected_mode: u32 = 0o700;
        if (permutation != 0) {
            steps[0] = unpackStep(0, &a_model, 1, null, false);
            steps[1] = unpackStep(1, &z_model, 0, null, false);
            expected_mode = 0o755;
        }
        const program = testProgram(
            database.generation.sha256,
            0,
            &artifacts,
            &steps,
        );
        var planned = try expectPlan(try planFor(
            &fixture,
            &program,
            &.{
                .{ .artifact = 0, .bytes = z_bytes },
                .{ .artifact = 1, .bytes = a_bytes },
            },
        ));
        defer planned.deinit();
        var found = false;
        for (planned.filesystem) |change| switch (change) {
            .directory => |directory| if (std.mem.eql(
                u8,
                directory.path,
                "shared",
            )) {
                found = true;
                try testing.expectEqual(expected_mode, directory.mode);
            },
            else => {},
        };
        try testing.expect(found);
    }
}

test "native_unpack.test.directory timestamps distinguish archive and synthesized parents" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{.{
        .path = "opt/demo",
        .kind = '5',
        .mode = 0o750,
    }};
    const bytes = try buildOwnedArchive(
        .{ .package = "demo", .version = "1" },
        &data,
    );
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer planned.deinit();
    var parent_seen = false;
    var payload_seen = false;
    var parent_index: ?usize = null;
    var payload_index: ?usize = null;
    for (planned.filesystem, 0..) |change, index| switch (change) {
        .directory => |directory| {
            if (std.mem.eql(u8, directory.path, "opt")) {
                parent_seen = true;
                parent_index = index;
                try testing.expectEqual(@as(?i128, null), directory.modified_nanoseconds);
            } else if (std.mem.eql(u8, directory.path, "opt/demo")) {
                payload_seen = true;
                payload_index = index;
                try testing.expectEqual(
                    @as(?i128, test_mtime_ns),
                    directory.modified_nanoseconds,
                );
            }
        },
        else => {},
    };
    try testing.expect(parent_seen and payload_seen);
    try testing.expect(parent_index.? < payload_index.?);
}

test "native_unpack.test.all installed conffiles block touching claims" {
    const status =
        \\Package: oldpkg
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1
        \\Conffiles:
        \\ /lib/legacy.conf d41d8cd98f00b204e9800998ecf8427e obsolete
        \\Description: old
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "oldpkg.list", .bytes = "/.\n/lib/legacy.conf\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.init(status, &info);
    defer fixture.deinit();
    try fixture.root().createDirectoryPath(
        try root_fs.Path.init("usr/lib"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().createSymbolicLink(
        try root_fs.Path.init("lib"),
        "usr/lib",
    );
    try seedFile(fixture.root(), "usr/lib/legacy.conf", "modified\n");

    var data = [_]Entry{.{
        .path = "usr/lib/legacy.conf",
        .content = "replacement\n",
    }};
    const bytes = try buildOwnedArchive(.{
        .package = "newpkg",
        .version = "1",
        .control_fields = "Replaces: oldpkg\n",
    }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    try expectConffileHandoff(
        try planFor(
            &fixture,
            &program,
            &.{.{ .artifact = 0, .bytes = bytes }},
        ),
        "oldpkg",
        "usr/lib/legacy.conf",
    );

    const config_status =
        \\Package: residual
        \\Status: deinstall ok config-files
        \\Architecture: amd64
        \\Version: 1
        \\Conffiles:
        \\ /etc/residual.conf d41d8cd98f00b204e9800998ecf8427e remove-on-upgrade
        \\Description: residual
        \\
        \\
    ;
    var config_fixture: Fixture = undefined;
    try config_fixture.init(config_status, &.{});
    defer config_fixture.deinit();
    var config_data = [_]Entry{.{
        .path = "etc/residual.conf",
        .content = "new\n",
    }};
    const config_bytes = try buildOwnedArchive(
        .{ .package = "other", .version = "1" },
        &config_data,
    );
    defer testing.allocator.free(config_bytes);
    var config_model = try modelOf(config_bytes);
    defer config_model.deinit();
    const config_steps = [_]native_program.Step{
        unpackStep(0, &config_model, 0, null, false),
    };
    var config_artifacts: [1]native_program.ProgramArtifact = undefined;
    const config_program = try singleProgram(
        &config_fixture,
        &config_model,
        config_bytes,
        &config_steps,
        &config_artifacts,
    );
    try expectConffileHandoff(
        try planFor(
            &config_fixture,
            &config_program,
            &.{.{ .artifact = 0, .bytes = config_bytes }},
        ),
        "residual",
        "etc/residual.conf",
    );
}

test "native_unpack.test.final retirement authorizes replacement and ancestor synthesis" {
    const status =
        \\Package: alpha
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1
        \\Description: alpha
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "alpha.list", .bytes = "/.\n/d\n/usr/share/alpha\n/usr/share/shared\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.init(status, &info);
    defer fixture.deinit();
    try seedFile(fixture.root(), "d", "old ancestor\n");
    try seedFile(fixture.root(), "usr/share/alpha", "old alpha\n");
    try seedFile(fixture.root(), "usr/share/shared", "old shared\n");

    var alpha_data = [_]Entry{.{
        .path = "usr/share/alpha",
        .content = "new alpha\n",
    }};
    var beta_data = [_]Entry{
        .{ .path = "d/new", .content = "descendant\n" },
        .{ .path = "usr/share/shared", .content = "new shared\n" },
    };
    const alpha_bytes = try buildOwnedArchive(
        .{ .package = "alpha", .version = "2" },
        &alpha_data,
    );
    defer testing.allocator.free(alpha_bytes);
    const beta_bytes = try buildOwnedArchive(
        .{ .package = "beta", .version = "1" },
        &beta_data,
    );
    defer testing.allocator.free(beta_bytes);
    var alpha_model = try modelOf(alpha_bytes);
    defer alpha_model.deinit();
    var beta_model = try modelOf(beta_bytes);
    defer beta_model.deinit();
    var database = try fixture.database();
    defer database.deinit();
    const artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &alpha_model, alpha_bytes.len),
        testArtifact(1, &beta_model, beta_bytes.len),
    };
    for (0..2) |permutation| {
        var steps = [_]native_program.Step{
            unpackStep(0, &alpha_model, 0, "1", false),
            unpackStep(1, &beta_model, 1, null, false),
        };
        if (permutation != 0) {
            steps[0] = unpackStep(0, &beta_model, 1, null, false);
            steps[1] = unpackStep(1, &alpha_model, 0, "1", false);
        }
        const program = testProgram(
            database.generation.sha256,
            1,
            &artifacts,
            &steps,
        );
        var planned = try expectPlan(try planFor(
            &fixture,
            &program,
            &.{
                .{ .artifact = 0, .bytes = alpha_bytes },
                .{ .artifact = 1, .bytes = beta_bytes },
            },
        ));
        defer planned.deinit();
        const beta = planned.findPackage("beta", "amd64") orelse
            return error.TestUnexpectedResult;
        var replaced_retired = false;
        for (beta.paths) |path| {
            if (std.mem.eql(u8, path.path, "usr/share/shared")) {
                try testing.expectEqual(Disposition.replace_retired, path.disposition);
                replaced_retired = true;
            }
        }
        try testing.expect(replaced_retired);

        var removed: ?usize = null;
        var recreated: ?usize = null;
        var child: ?usize = null;
        for (planned.filesystem, 0..) |change, index| switch (change) {
            .remove => |removal| {
                if (std.mem.eql(u8, removal.path, "d")) removed = index;
            },
            .directory => |directory| {
                if (std.mem.eql(u8, directory.path, "d")) recreated = index;
            },
            .file => |file| {
                if (std.mem.eql(u8, file.path, "d/new")) child = index;
            },
            else => {},
        };
        try testing.expect(removed.? < recreated.?);
        try testing.expect(recreated.? < child.?);
    }
}

test "native_unpack.test.obsolete special files are never generic removals" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const status =
        \\Package: alpha
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1
        \\Description: alpha
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "alpha.list", .bytes = "/.\n/run/pipe\n/usr/share/alpha\n" },
    };
    var fixture: Fixture = undefined;
    try fixture.init(status, &info);
    defer fixture.deinit();
    try fixture.root().ensureDirectory(
        try root_fs.Path.init("run"),
        root_fs.default_directory_permissions,
    );
    const linux = std.os.linux;
    const fifo_name: [*:0]const u8 = "run/pipe";
    switch (linux.errno(linux.mknodat(
        fixture.tmp.dir.handle,
        fifo_name,
        linux.S.IFIFO | 0o644,
        0,
    ))) {
        .SUCCESS => {},
        else => return error.TestUnexpectedResult,
    }
    try seedFile(fixture.root(), "usr/share/alpha", "old\n");
    var data = [_]Entry{.{
        .path = "usr/share/alpha",
        .content = "new\n",
    }};
    const bytes = try buildOwnedArchive(
        .{ .package = "alpha", .version = "2" },
        &data,
    );
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, "1", false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    try expectRefusal(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .unsupported_entry);
}

test "native_unpack.test.case graph includes intermediate and installed prefixes" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{
        .{ .path = "usr/A/x", .content = "x\n" },
        .{ .path = "usr/a", .content = "a\n" },
    };
    const bytes = try buildOwnedArchive(
        .{ .package = "demo", .version = "1" },
        &data,
    );
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    try expectRefusal(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .case_alias);

    const status =
        \\Package: oldpkg
        \\Status: install ok installed
        \\Architecture: amd64
        \\Version: 1
        \\Description: old
        \\
        \\
    ;
    const info = [_]package_database.InfoEntry{
        .{ .name = "oldpkg.list", .bytes = "/.\n/usr/A/x\n" },
    };
    var installed_fixture: Fixture = undefined;
    try installed_fixture.init(status, &info);
    defer installed_fixture.deinit();
    var incoming = [_]Entry{.{
        .path = "usr/a",
        .content = "new\n",
    }};
    const incoming_bytes = try buildOwnedArchive(
        .{ .package = "newpkg", .version = "1" },
        &incoming,
    );
    defer testing.allocator.free(incoming_bytes);
    var incoming_model = try modelOf(incoming_bytes);
    defer incoming_model.deinit();
    const incoming_steps = [_]native_program.Step{
        unpackStep(0, &incoming_model, 0, null, false),
    };
    var incoming_artifacts: [1]native_program.ProgramArtifact = undefined;
    const incoming_program = try singleProgram(
        &installed_fixture,
        &incoming_model,
        incoming_bytes,
        &incoming_steps,
        &incoming_artifacts,
    );
    try expectRefusal(try planFor(
        &installed_fixture,
        &incoming_program,
        &.{.{ .artifact = 0, .bytes = incoming_bytes }},
    ), .case_alias);
}

test "native_unpack.test.Multi-Arch hardlink sharing preserves topology" {
    var fixture: Fixture = undefined;
    try fixture.initFull(empty_status, &.{}, "arm64\n");
    defer fixture.deinit();
    var amd64_data = [_]Entry{
        .{ .path = "usr/share/group/a", .content = "same\n" },
        .{
            .path = "usr/share/group/b",
            .kind = '1',
            .link = "./usr/share/group/a",
        },
        .{
            .path = "usr/share/group/c",
            .kind = '1',
            .link = "./usr/share/group/a",
        },
    };
    var arm64_data = amd64_data;
    const amd64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .control_fields = "Multi-Arch: same\n",
    }, &amd64_data);
    defer testing.allocator.free(amd64_bytes);
    const arm64_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "arm64",
        .control_fields = "Multi-Arch: same\n",
    }, &arm64_data);
    defer testing.allocator.free(arm64_bytes);
    var amd64_model = try modelOf(amd64_bytes);
    defer amd64_model.deinit();
    var arm64_model = try modelOf(arm64_bytes);
    defer arm64_model.deinit();
    var database = try fixture.database();
    defer database.deinit();
    const artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &amd64_model, amd64_bytes.len),
        testArtifact(1, &arm64_model, arm64_bytes.len),
    };
    const steps = [_]native_program.Step{
        unpackStep(0, &amd64_model, 0, null, false),
        unpackStep(1, &arm64_model, 1, null, false),
    };
    const program = testProgram(database.generation.sha256, 0, &artifacts, &steps);
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = arm64_bytes },
        },
    ));
    defer planned.deinit();
    var files: usize = 0;
    var links: usize = 0;
    for (planned.filesystem) |change| switch (change) {
        .file => |file| {
            if (std.mem.eql(u8, file.path, "usr/share/group/a")) files += 1;
        },
        .hardlink => |link| {
            if ((std.mem.eql(u8, link.path, "usr/share/group/b") or
                std.mem.eql(u8, link.path, "usr/share/group/c")) and
                std.mem.eql(u8, link.source, "usr/share/group/a"))
                links += 1;
        },
        else => {},
    };
    try testing.expectEqual(@as(usize, 1), files);
    try testing.expectEqual(@as(usize, 2), links);
    const reversed_steps = [_]native_program.Step{
        unpackStep(0, &arm64_model, 1, null, false),
        unpackStep(1, &amd64_model, 0, null, false),
    };
    const reversed_program = testProgram(
        database.generation.sha256,
        0,
        &artifacts,
        &reversed_steps,
    );
    var reversed = try expectPlan(try planFor(
        &fixture,
        &reversed_program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = arm64_bytes },
        },
    ));
    defer reversed.deinit();
    try testing.expectEqualSlices(u8, &planned.digest, &reversed.digest);

    arm64_data = .{
        .{ .path = "usr/share/group/b", .content = "same\n" },
        .{
            .path = "usr/share/group/a",
            .kind = '1',
            .link = "./usr/share/group/b",
        },
        .{
            .path = "usr/share/group/c",
            .kind = '1',
            .link = "./usr/share/group/b",
        },
    };
    const mismatched_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "arm64",
        .control_fields = "Multi-Arch: same\n",
    }, &arm64_data);
    defer testing.allocator.free(mismatched_bytes);
    var mismatched_model = try modelOf(mismatched_bytes);
    defer mismatched_model.deinit();
    const mismatch_artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &amd64_model, amd64_bytes.len),
        testArtifact(1, &mismatched_model, mismatched_bytes.len),
    };
    const mismatch_steps = [_]native_program.Step{
        unpackStep(0, &amd64_model, 0, null, false),
        unpackStep(1, &mismatched_model, 1, null, false),
    };
    const mismatch_program = testProgram(
        database.generation.sha256,
        0,
        &mismatch_artifacts,
        &mismatch_steps,
    );
    try expectRefusal(try planFor(
        &fixture,
        &mismatch_program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = mismatched_bytes },
        },
    ), .multi_arch_content_mismatch);

    arm64_data = .{
        .{ .path = "usr/share/group/a", .content = "same\n" },
        .{
            .path = "usr/share/group/b",
            .kind = '1',
            .link = "./usr/share/group/a",
        },
        .{
            .path = "usr/share/group/d",
            .kind = '1',
            .link = "./usr/share/group/a",
        },
    };
    const membership_bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "arm64",
        .control_fields = "Multi-Arch: same\n",
    }, &arm64_data);
    defer testing.allocator.free(membership_bytes);
    var membership_model = try modelOf(membership_bytes);
    defer membership_model.deinit();
    const membership_artifacts = [_]native_program.ProgramArtifact{
        testArtifact(0, &amd64_model, amd64_bytes.len),
        testArtifact(1, &membership_model, membership_bytes.len),
    };
    const membership_steps = [_]native_program.Step{
        unpackStep(0, &amd64_model, 0, null, false),
        unpackStep(1, &membership_model, 1, null, false),
    };
    const membership_program = testProgram(
        database.generation.sha256,
        0,
        &membership_artifacts,
        &membership_steps,
    );
    try expectRefusal(try planFor(
        &fixture,
        &membership_program,
        &.{
            .{ .artifact = 0, .bytes = amd64_bytes },
            .{ .artifact = 1, .bytes = membership_bytes },
        },
    ), .multi_arch_content_mismatch);
}

test "native_unpack.test.installed Multi-Arch hardlinks require one pinned inode group" {
    const status =
        \\Package: demo
        \\Status: install ok installed
        \\Architecture: arm64
        \\Version: 1
        \\Multi-Arch: same
        \\Description: demo
        \\
        \\
    ;
    const first_line = try archive_application.test_fixtures.checksumLine(
        testing.allocator,
        "same\n",
        "usr/share/group/a",
    );
    defer testing.allocator.free(first_line);
    const second_line = try archive_application.test_fixtures.checksumLine(
        testing.allocator,
        "same\n",
        "usr/share/group/b",
    );
    defer testing.allocator.free(second_line);
    const checksums = try std.fmt.allocPrint(
        testing.allocator,
        "{s}{s}",
        .{ first_line, second_line },
    );
    defer testing.allocator.free(checksums);
    const info = [_]package_database.InfoEntry{
        .{
            .name = "demo:arm64.list",
            .bytes = "/.\n/usr/share/group/a\n/usr/share/group/b\n",
        },
        .{ .name = "demo:arm64.md5sums", .bytes = checksums },
    };
    var fixture: Fixture = undefined;
    try fixture.initFull(status, &info, "arm64\n");
    defer fixture.deinit();
    try seedFile(fixture.root(), "usr/share/group/a", "same\n");
    try fixture.root().createHardLink(
        try root_fs.Path.init("usr/share/group/a"),
        try root_fs.Path.init("usr/share/group/b"),
    );
    try fixture.root().applyMetadata(
        try root_fs.Path.init("usr/share/group/a"),
        .{
            .mode = 0o644,
            .uid = currentUid(),
            .gid = currentGid(),
            .modified_nanoseconds = test_mtime_ns,
        },
    );
    var data = [_]Entry{
        .{ .path = "usr/share/group/a", .content = "same\n" },
        .{
            .path = "usr/share/group/b",
            .kind = '1',
            .link = "./usr/share/group/a",
        },
    };
    const bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .control_fields = "Multi-Arch: same\n",
    }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    var shared = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    const hardlink = for (shared.packages[0].paths) |path| {
        if (path.kind == .hardlink) break path;
    } else return error.TestUnexpectedResult;
    const destination = hardlink.previous orelse
        return error.TestUnexpectedResult;
    const source = hardlink.link_source_previous orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(destination.device, source.device);
    try testing.expectEqual(destination.inode, source.inode);
    shared.deinit();

    try fixture.root().createHardLink(
        try root_fs.Path.init("usr/share/group/a"),
        try root_fs.Path.init("usr/share/group/external"),
    );
    try expectRefusal(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .multi_arch_content_mismatch);
    try fixture.root().removeFile(
        try root_fs.Path.init("usr/share/group/external"),
    );

    try fixture.root().removeFile(try root_fs.Path.init("usr/share/group/b"));
    try seedFile(fixture.root(), "usr/share/group/b", "same\n");
    try fixture.root().applyMetadata(
        try root_fs.Path.init("usr/share/group/b"),
        .{
            .mode = 0o644,
            .uid = currentUid(),
            .gid = currentGid(),
            .modified_nanoseconds = test_mtime_ns,
        },
    );
    try expectRefusal(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .multi_arch_content_mismatch);
}

test "native_unpack.test.live listed checksum dominates stale merged alias" {
    const status =
        \\Package: demo
        \\Status: install ok installed
        \\Architecture: arm64
        \\Version: 1
        \\Multi-Arch: same
        \\Description: demo
        \\
        \\
    ;
    const live = try archive_application.test_fixtures.checksumLine(
        testing.allocator,
        "shared\n",
        "usr/lib/x",
    );
    defer testing.allocator.free(live);
    const checksums = try std.fmt.allocPrint(
        testing.allocator,
        "{s}00000000000000000000000000000000  lib/x\n",
        .{live},
    );
    defer testing.allocator.free(checksums);
    const info = [_]package_database.InfoEntry{
        .{ .name = "demo:arm64.list", .bytes = "/.\n/usr/lib/x\n" },
        .{ .name = "demo:arm64.md5sums", .bytes = checksums },
    };
    var fixture: Fixture = undefined;
    try fixture.initFull(status, &info, "arm64\n");
    defer fixture.deinit();
    try fixture.root().createDirectoryPath(
        try root_fs.Path.init("usr/lib"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().createSymbolicLink(
        try root_fs.Path.init("lib"),
        "usr/lib",
    );
    try seedFile(fixture.root(), "usr/lib/x", "shared\n");
    try fixture.root().applyMetadata(
        try root_fs.Path.init("usr/lib/x"),
        .{
            .mode = 0o644,
            .uid = currentUid(),
            .gid = currentGid(),
            .modified_nanoseconds = test_mtime_ns,
        },
    );
    var data = [_]Entry{.{
        .path = "usr/lib/x",
        .content = "shared\n",
    }};
    const bytes = try buildOwnedArchive(.{
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .control_fields = "Multi-Arch: same\n",
    }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    var planned = try expectPlan(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ));
    defer planned.deinit();
    try testing.expectEqual(
        Disposition.share_multi_arch,
        planned.packages[0].paths[0].disposition,
    );
    try testing.expect(!planned.packages[0].paths[0].publish);
}

test "native_unpack.test.root digests never survive a pinned open" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root: root_fs.Root = .init(testing.io, tmp.dir);
    try root.publishFile(try root_fs.Path.init("source"), "payload\n", .{});
    try root.createHardLink(
        try root_fs.Path.init("source"),
        try root_fs.Path.init("alias"),
    );
    const source = try root.entry(try root_fs.Path.init("source"));
    const alias = try root.entry(try root_fs.Path.init("alias"));
    try testing.expectEqual(source.inode, alias.inode);

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var builder: Builder = .{
        .allocator = testing.allocator,
        .model_allocator = .init(testing.allocator, std.math.maxInt(u64)),
        .arena = arena.allocator(),
        .request = .{
            .program = undefined,
            .snapshot = undefined,
            .archives = &.{},
            .root = root,
        },
        .limits = .{
            .max_compared_bytes = source.size * 3 + "changed\n".len,
        },
        .database = undefined,
        .ownership = undefined,
        .aliases = .{ .aliases = &.{}, .foreign = &.{} },
    };
    const source_path = try root_fs.Path.init("source");
    const alias_path = try root_fs.Path.init("alias");
    const first = try rootFileObservation(&builder, source_path, "");
    const alias_observation = try rootFileObservation(&builder, alias_path, "");
    try testing.expectEqualSlices(u8, &first.digest, &alias_observation.digest);
    try testing.expectEqual(source.size * 2, builder.compared_bytes);

    try root.appendAt(source_path, 0, "changed\n", true);
    try root.applyMetadata(source_path, .{
        .modified_nanoseconds = source.modified_nanoseconds,
    });
    const changed = try rootFileObservation(&builder, source_path, "");
    try testing.expect(!std.mem.eql(u8, &first.digest, &changed.digest));
    try testing.expectEqual(
        source.size * 2 + "changed\n".len,
        builder.compared_bytes,
    );

    try root.removeFile(source_path);
    try root.removeFile(alias_path);
    try root.publishFile(source_path, "reused!\n", .{});
    try root.applyMetadata(source_path, .{
        .mode = source.mode,
        .uid = source.uid,
        .gid = source.gid,
        .modified_nanoseconds = source.modified_nanoseconds,
    });
    const recreated = try rootFileObservation(&builder, source_path, "");
    try testing.expect(!std.mem.eql(u8, &changed.digest, &recreated.digest));
    try testing.expectEqual(
        source.size * 3 + "changed\n".len,
        builder.compared_bytes,
    );
}

test "native_unpack.test.plan digest is allocator-telemetry independent" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    var data = [_]Entry{.{
        .path = "usr/share/demo",
        .content = "payload\n",
    }};
    const bytes = try buildOwnedArchive(
        .{ .package = "demo", .version = "1" },
        &data,
    );
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{
        unpackStep(0, &model, 0, null, false),
    };
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(
        &fixture,
        &model,
        bytes,
        &steps,
        &artifacts,
    );
    const archives = [_]ArchiveInput{.{ .artifact = 0, .bytes = bytes }};
    var general = try expectPlan(try planFor(&fixture, &program, &archives));
    defer general.deinit();

    const storage = try testing.allocator.alloc(u8, 16 * 1024 * 1024);
    defer testing.allocator.free(storage);
    var fixed = std.heap.FixedBufferAllocator.init(storage);
    var bounded = try expectPlan(try plan(fixed.allocator(), .{
        .program = &program,
        .snapshot = fixture.snapshot(),
        .archives = &archives,
        .root = fixture.root(),
        .interoperability = .isolated_root,
    }));
    defer bounded.deinit();
    try testing.expectEqualSlices(u8, &general.digest, &bounded.digest);
}

test "native_unpack.test.shared directory observation is cached for 4096 claimants" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const root: root_fs.Root = .init(testing.io, tmp.dir);
    try root.createDirectory(
        try root_fs.Path.init("shared"),
        root_fs.default_directory_permissions,
    );
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var name_bytes: usize = 0;
    for (0..3000) |index| {
        const path = try std.fmt.allocPrint(
            arena.allocator(),
            "shared/entry-{d:0>4}",
            .{index},
        );
        const slash = std.mem.lastIndexOfScalar(u8, path, '/').?;
        name_bytes += path.len - slash - 1;
        try root.publishFile(try root_fs.Path.init(path), "", .{
            .durable = false,
        });
    }
    const empty_ownership: Ownership = .{
        .owners = &.{},
        .entries = &.{},
        .by_owner = &.{},
        .owner_offsets = &.{},
        .rewritten = &.{},
        .allocator = testing.allocator,
    };
    var builder: Builder = .{
        .allocator = testing.allocator,
        .model_allocator = .init(testing.allocator, 1),
        .arena = arena.allocator(),
        .request = .{
            .program = undefined,
            .snapshot = undefined,
            .archives = &.{},
            .root = root,
        },
        .limits = .{
            .max_compare_bytes = name_bytes,
            .max_compared_bytes = name_bytes,
            .max_work = 20_000,
            .max_descendant_scan = 3000,
            .max_total_paths = 5000,
            .max_intents = 5000,
        },
        .database = undefined,
        .ownership = empty_ownership,
        .aliases = .{ .aliases = &.{}, .foreign = &.{} },
    };
    defer builder.deinit();
    var files = [_]archive_application.File{.{
        .path = "shared",
        .kind = .directory,
        .mode = 0o755,
        .uid = 0,
        .gid = 0,
        .owner_name = null,
        .group_name = null,
        .mtime = 1,
        .size = 0,
        .content = null,
        .sha256 = null,
        .md5 = null,
        .link_target = null,
        .link_literal = null,
        .conffile = false,
        .entry_index = 0,
    }};
    var model: archive_application.Model = undefined;
    model.files = &files;
    var claims = [_]Claim{.{
        .path = "shared",
        .archive_path = "shared",
        .kind = .directory,
        .file = 0,
        .aliased = false,
    }};
    for (0..4096) |index| {
        const name = try std.fmt.allocPrint(
            arena.allocator(),
            "package-{d}",
            .{index},
        );
        try builder.work.append(testing.allocator, .{
            .identity = .{
                .name = name,
                .version = "1",
                .architecture = "amd64",
            },
            .stem = name,
            .artifact = 0,
            .archive = 0,
            .model = &model,
            .application_sha256 = @splat(0),
            .operation = .install,
            .bootstrapped = false,
            .sequence = @intCast(index),
            .prior = null,
            .prior_version = null,
            .configured_version = null,
            .owner_index = null,
            .claims = &claims,
        });
        const transaction_claim: TransactionClaim = .{
            .package = @intCast(index),
            .sequence = @intCast(index),
            .name = name,
            .architecture = "amd64",
            .multi_arch_same = false,
            .kind = .directory,
            .sha256 = null,
            .link_target = null,
            .link_source = null,
            .hardlink_group = null,
            .hardlink_group_size = 1,
            .hardlink_group_digest = null,
            .mode = 0o755,
            .uid = 0,
            .gid = 0,
            .modified_nanoseconds = 0,
        };
        const aggregate = try builder.transaction_claims.getOrPut(
            testing.allocator,
            "shared",
        );
        if (!aggregate.found_existing) aggregate.value_ptr.* = .{
            .representative = transaction_claim,
            .publisher = transaction_claim,
            .count = 0,
        };
        try addTransactionClaim(
            &builder,
            aggregate.value_ptr,
            transaction_claim,
            "shared",
        );
    }
    for (builder.work.items, 0..) |*item, index| {
        try planPackageClaims(&builder, item, @intCast(index));
        try testing.expectEqual(@as(usize, 1), item.paths.items.len);
        try testing.expectEqual(@as(?u64, 3000), item.paths.items[0].previous.?.directory_entries);
    }
    try testing.expectEqual(@as(u64, name_bytes), builder.compared_bytes);
    try testing.expectEqual(@as(usize, 1), builder.directory_observations.count());
    try revalidateDirectoryObservations(&builder);

    try root.rename(
        try root_fs.Path.init("shared"),
        try root_fs.Path.init("shared-old"),
        .fail_if_exists,
    );
    try root.createDirectory(
        try root_fs.Path.init("shared"),
        root_fs.default_directory_permissions,
    );
    try testing.expectError(
        error.Rejected,
        revalidateDirectoryObservations(&builder),
    );
    try testing.expectEqual(Code.root_unreadable, builder.diagnostic.?.code);
}

test "native_unpack.test.200k target-last hardlinks resolve linearly once" {
    const count = 200_000;
    const target_index = count / 2;
    const files = try testing.allocator.alloc(archive_application.File, count);
    defer testing.allocator.free(files);
    const claims = try testing.allocator.alloc(Claim, count);
    defer testing.allocator.free(claims);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var content_sha256: [32]u8 = undefined;
    Sha256.hash("x", &content_sha256, .{});

    for (files, 0..) |*file, index| {
        const path = if (index == target_index)
            "target"
        else
            try std.fmt.allocPrint(
                arena.allocator(),
                "{s}/{d}",
                .{ if (index < target_index) "padding" else "hard", index },
            );
        file.* = .{
            .path = path,
            .kind = if (index < target_index)
                .directory
            else if (index == target_index)
                .regular
            else
                .hardlink,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .owner_name = null,
            .group_name = null,
            .mtime = 1,
            .size = if (index == target_index) 1 else 0,
            .content = if (index == target_index)
                .{ .offset = 0, .length = 1 }
            else
                null,
            .sha256 = if (index == target_index) content_sha256 else null,
            .md5 = null,
            .link_target = if (index > target_index) "target" else null,
            .link_literal = null,
            .conffile = false,
            .entry_index = index,
        };
        claims[index] = .{
            .path = path,
            .archive_path = path,
            .kind = kindOf(file.kind),
            .file = index,
            .aliased = false,
        };
    }
    // Force one forward hard-link chain in the synthetic model. The archive
    // validator currently rejects this shape, but the planner's derived
    // index must still resolve it once rather than recurse or rescan if that
    // model contract is ever widened.
    files[target_index + 1].link_target = files[target_index + 2].path;
    var model: archive_application.Model = undefined;
    model.files = files;
    var data_bytes = [_]u8{'x'};
    model.validation.data_bytes = &data_bytes;
    var item: PackageWork = .{
        .identity = .{
            .name = "linear",
            .version = "1",
            .architecture = "amd64",
        },
        .stem = "linear",
        .artifact = 0,
        .archive = 0,
        .model = &model,
        .application_sha256 = @splat(0),
        .operation = .install,
        .bootstrapped = false,
        .sequence = 0,
        .prior = null,
        .prior_version = null,
        .configured_version = null,
        .owner_index = null,
        .claims = claims,
    };
    var builder: Builder = .{
        .allocator = testing.allocator,
        .model_allocator = .init(testing.allocator, 256 * 1024 * 1024),
        .arena = arena.allocator(),
        .request = undefined,
        .limits = .{
            .max_paths_per_package = count,
            .max_compare_bytes = 1,
            .max_compared_bytes = 1,
            .max_work = count + count / 2,
        },
        .database = undefined,
        .ownership = undefined,
        .aliases = .{ .aliases = &.{}, .foreign = &.{} },
    };
    try prepareEffectiveFiles(&builder, &item);
    try prepareHardlinkGroupDigests(&builder, &item);
    {
        defer {
            item.file_index.deinit(builder.model_allocator.allocator());
            item.hardlink_group_digests.deinit(
                builder.model_allocator.allocator(),
            );
            builder.model_allocator.allocator().free(item.effective_files);
        }
        try testing.expectEqual(@as(u64, 1), builder.compared_bytes);
        try testing.expectEqual(count + count / 2, builder.work_units);
        const expected = item.effective_files[target_index].?;
        for (item.effective_files[target_index + 1 ..]) |effective| {
            try testing.expectEqualSlices(u8, &expected.sha256, &effective.?.sha256);
            try testing.expectEqualSlices(u8, &expected.md5, &effective.?.md5);
            try testing.expectEqualStrings("target", effective.?.source_path);
        }
    }
    try testing.expectEqual(@as(u64, 0), builder.model_allocator.live);
    try testing.expect(builder.model_allocator.peak > 0);
}

test "native_unpack.test.4096 shared directory claims aggregate linearly" {
    const count = 4096;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var builder: Builder = .{
        .allocator = testing.allocator,
        .model_allocator = .init(testing.allocator, 1),
        .arena = arena.allocator(),
        .request = undefined,
        .limits = .{ .max_work = count },
        .database = undefined,
        .ownership = undefined,
        .aliases = .{ .aliases = &.{}, .foreign = &.{} },
    };
    const first: TransactionClaim = .{
        .package = 0,
        .sequence = count - 1,
        .name = "package-0",
        .architecture = "amd64",
        .multi_arch_same = false,
        .kind = .directory,
        .sha256 = null,
        .link_target = null,
        .link_source = null,
        .hardlink_group = null,
        .hardlink_group_size = 1,
        .hardlink_group_digest = null,
        .mode = 0o755,
        .uid = 0,
        .gid = 0,
        .modified_nanoseconds = 0,
    };
    var aggregate: TransactionClaims = .{
        .representative = first,
        .publisher = first,
        .count = 0,
    };
    defer {
        aggregate.by_package.deinit(testing.allocator);
        aggregate.directory_groups.deinit(testing.allocator);
    }
    for (0..count) |index| {
        const name = try std.fmt.allocPrint(
            arena.allocator(),
            "package-{d}",
            .{index},
        );
        var claim = first;
        claim.package = @intCast(index);
        claim.sequence = @intCast(count - index - 1);
        claim.name = name;
        claim.mode = if (index % 2 == 0) 0o755 else 0o700;
        try addTransactionClaim(&builder, &aggregate, claim, "shared");
    }
    try testing.expectEqual(count, aggregate.count);
    try testing.expectEqual(count, aggregate.by_package.count());
    try testing.expectEqual(@as(u32, count - 1), aggregate.publisher.package);
    try testing.expectEqual(count, builder.work_units);
}

test "native_unpack.test.120k repeated prefixes allocate one bounded case key" {
    const path = "alpha/beta/gamma/delta/epsilon/zeta";
    var expected_bytes: usize = path.len;
    var components: usize = 1;
    for (path, 0..) |byte, index| {
        if (byte != '/') continue;
        expected_bytes += index;
        components += 1;
    }
    expected_bytes += components *
        (@sizeOf(FoldedPath) + @sizeOf([]u8) + 32);
    var arena_storage: [1]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&arena_storage);
    const empty_ownership: Ownership = .{
        .owners = &.{},
        .entries = &.{},
        .by_owner = &.{},
        .owner_offsets = &.{},
        .rewritten = &.{},
        .allocator = testing.allocator,
    };
    var builder: Builder = .{
        .allocator = testing.allocator,
        .model_allocator = .init(testing.allocator, 1),
        .arena = arena.allocator(),
        .request = undefined,
        .limits = .{
            .max_work = 120_000 * components,
            .max_case_index_bytes = expected_bytes,
        },
        .database = undefined,
        .ownership = empty_ownership,
        .aliases = .{ .aliases = &.{}, .foreign = &.{} },
    };
    defer builder.deinit();
    for (0..120_000) |_|
        try recordPathPrefixes(&builder, path, .regular);
    try testing.expectEqual(components, builder.folded.count());
    try testing.expectEqual(components, builder.folded_keys.items.len);
    try testing.expectEqual(expected_bytes, builder.case_index_bytes);

    var rejected: Builder = .{
        .allocator = testing.allocator,
        .model_allocator = .init(testing.allocator, 1),
        .arena = arena.allocator(),
        .request = undefined,
        .limits = .{
            .max_work = components,
            .max_case_index_bytes = expected_bytes - 1,
        },
        .database = undefined,
        .ownership = empty_ownership,
        .aliases = .{ .aliases = &.{}, .foreign = &.{} },
    };
    defer rejected.deinit();
    try testing.expectError(
        error.Rejected,
        recordPathPrefixes(&rejected, path, .regular),
    );
    try testing.expectEqual(Code.case_alias_limit, rejected.diagnostic.?.code);
}

test "native_unpack.test.100k trigger interests and identities remain bounded" {
    const count = 100_000;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const packages = try testing.allocator.alloc(
        package_database.PackageRecord,
        count,
    );
    defer testing.allocator.free(packages);
    const parsed = try version_module.DebianVersion.parse("1");
    for (packages, 0..) |*record, index| {
        const architecture = try std.fmt.allocPrint(
            arena.allocator(),
            "arch-{d}",
            .{index},
        );
        record.* = .{
            .name = "bulk",
            .architecture = architecture,
            .version = "1",
            .parsed_version = parsed,
            .status = .{
                .want = .install,
                .error_state = .ok,
                .current = .installed,
            },
            .multi_arch = null,
            .essential = false,
            .protected = false,
            .fields = &.{},
            .conffiles = &.{},
            .triggers_pending = &.{},
            .triggers_awaited = &.{},
            .info_stem = "bulk",
            .paths = null,
            .md5sums = null,
            .declared_conffiles = null,
            .trigger_declarations = null,
            .scripts = &.{},
        };
    }
    const interests = try testing.allocator.alloc(
        package_database.TriggerInterest,
        count,
    );
    defer testing.allocator.free(interests);
    for (interests, 0..) |*interest, index| {
        interest.* = .{
            .trigger = if (index + 1 == count) "/affected" else "/irrelevant",
            .package = .{ .name = "bulk", .architecture = "" },
            .await_mode = .awaited,
        };
    }
    var database: package_database.Database = .{
        .model = .{
            .native_architecture = "amd64",
            .status = .{
                .sha256 = @splat(0),
                .size = 0,
                .package_count = count,
            },
            .packages = packages,
            .triggers = .{ .interests = interests },
        },
        .generation = undefined,
        .arena = undefined,
        .backing_allocator = undefined,
    };
    const empty_ownership: Ownership = .{
        .owners = &.{},
        .entries = &.{},
        .by_owner = &.{},
        .owner_offsets = &.{},
        .rewritten = &.{},
        .allocator = testing.allocator,
    };
    var builder: Builder = .{
        .allocator = testing.allocator,
        .model_allocator = .init(testing.allocator, 1),
        .arena = arena.allocator(),
        .request = undefined,
        .limits = .{
            .max_work = count * 2 + 10,
            .max_deferred = 1,
        },
        .database = &database,
        .ownership = empty_ownership,
        .aliases = .{ .aliases = &.{}, .foreign = &.{} },
    };
    defer builder.deinit();
    try builder.published.put(testing.allocator, "affected", .regular);
    try testing.expectError(
        error.Rejected,
        inspectPublicationTriggers(&builder),
    );
    try testing.expectEqual(Code.deferred_limit, builder.diagnostic.?.code);
    try testing.expect(builder.work_units <= count * 2 + 3);
    try testing.expect(
        builder.trigger_index_bytes <= builder.limits.max_trigger_index_bytes,
    );

    var limited: Builder = .{
        .allocator = testing.allocator,
        .model_allocator = .init(testing.allocator, 1),
        .arena = arena.allocator(),
        .request = undefined,
        .limits = .{
            .max_work = count * 2 + 10,
            .max_deferred = 1,
            .max_trigger_index_bytes = 1,
        },
        .database = &database,
        .ownership = empty_ownership,
        .aliases = .{ .aliases = &.{}, .foreign = &.{} },
    };
    defer limited.deinit();
    try limited.published.put(testing.allocator, "affected", .regular);
    try testing.expectError(
        error.Rejected,
        inspectPublicationTriggers(&limited),
    );
    try testing.expectEqual(Code.path_limit, limited.diagnostic.?.code);
}

fn expectPlanDigestChanged(original: [32]u8, plan_value: Plan) !void {
    const changed = planDigest(plan_value);
    try testing.expect(!std.mem.eql(u8, &original, &changed));
}

test "native_unpack.test.plan digest covers semantics and excludes telemetry" {
    var previous: PreviousState = .{
        .kind = .regular,
        .owned = true,
        .modeled = true,
        .mode = 0o644,
        .uid = 1,
        .gid = 2,
        .size = 3,
        .device = 4,
        .inode = 5,
        .link_count = 1,
        .modified_nanoseconds = 6,
        .change_nanoseconds = 7,
        .content_sha256 = @splat(0x11),
        .link_target = "old-target",
        .directory_sha256 = @splat(0x12),
        .directory_entries = 2,
    };
    const path: PlannedPath = .{
        .path = "usr/share/file",
        .absolute = "/usr/share/file",
        .archive_path = "./usr/share/file",
        .kind = .regular,
        .mode = 0o644,
        .uid = 1,
        .gid = 2,
        .modified_nanoseconds = 7,
        .sha256 = @splat(0x22),
        .md5 = @splat(0x33),
        .link_literal = "target",
        .link_source = "source",
        .link_source_previous = previous,
        .archive_entry = 8,
        .package = 0,
        .disposition = .replace_same_package,
        .previous = previous,
        .aliased = true,
        .synthesized = true,
        .publish = true,
    };
    const removal: Removal = .{
        .path = "usr/share/old",
        .absolute = "/usr/share/old",
        .directory = false,
        .package = 0,
        .previous = previous,
    };
    const resolution: Resolution = .{
        .path = "usr/share/file",
        .holder = .{ .name = "old", .architecture = "amd64" },
        .claimant = .{ .name = "new", .architecture = "arm64" },
        .resolution = .replaces,
    };
    var list_paths = [_][]const u8{"/usr/share/file"};
    var md5sums = [_]package_database.Md5sumEntry{.{
        .path = "usr/share/file",
        .digest = @splat(0x44),
    }};
    var conffiles = [_]PlannedConffile{.{
        .path = "etc/demo.conf",
        .staged_path = "etc/demo.conf.dpkg-new",
        .action = .install_new,
        .packaged_md5 = @splat(0x45),
    }};
    var paths = [_]PlannedPath{path};
    var removals = [_]Removal{removal};
    var resolutions = [_]Resolution{resolution};
    var package: PackagePlan = .{
        .identity = .{ .name = "new", .version = "2", .architecture = "arm64" },
        .stem = "new:arm64",
        .artifact = 9,
        .operation = .upgrade,
        .bootstrapped = true,
        .prior_version = "1",
        .configured_version = "0.9",
        .application_sha256 = @splat(0x55),
        .paths = &paths,
        .removals = &removals,
        .list_paths = &list_paths,
        .md5sums = &md5sums,
        .conffiles = &conffiles,
        .resolutions = &resolutions,
        .state = .unpacked,
    };
    var packages = [_]PackagePlan{package};
    var filesystem = [_]FilesystemChange{.{ .file = .{
        .path = "usr/share/file",
        .artifact = 9,
        .archive_entry = 8,
        .sha256 = @splat(0x22),
        .mode = 0o644,
        .uid = 1,
        .gid = 2,
        .modified_nanoseconds = 7,
    } }};
    var writes = [_]package_database_changes.PlannedWrite{.{
        .path = "status",
        .kind = .replace,
        .source = "status-old",
        .bytes = "status bytes",
        .sha256 = @splat(0x66),
        .mode = 0o644,
    }};
    var aliases = [_]Alias{.{
        .from = "lib",
        .to = "usr/lib",
        .link_target = "usr/lib",
        .device = 1,
        .inode = 2,
        .link_count = 1,
        .modified_nanoseconds = 3,
        .change_nanoseconds = 4,
    }};
    var case_aliases = [_]CaseAlias{.{ .first = "Foo", .second = "foo" }};
    var displacements = [_]Displacement{.{
        .path = "usr/share/file",
        .holder = .{ .name = "old", .architecture = "amd64" },
        .holder_index = 3,
        .claimant = .{ .name = "new", .architecture = "arm64" },
    }};
    var retained_directories = [_]RetainedDirectory{.{
        .path = "usr/share",
        .previous = previous,
    }};
    var pending = [_]native_program.PackageRef{.{ .name = "new", .architecture = "arm64" }};
    var plan_value: Plan = .{
        .filesystem = &filesystem,
        .database = .{
            .base_generation = .{ .sha256 = @splat(0x70), .file_count = 1, .total_bytes = 2 },
            .base_status = .{ .sha256 = @splat(0x71), .size = 3, .package_count = 1 },
            .resulting_status = .{ .sha256 = @splat(0x72), .size = 4, .package_count = 1 },
            .writes = &writes,
            .digest = @splat(0x73),
            .arena = undefined,
            .backing_allocator = undefined,
        },
        .packages = &packages,
        .aliases = &aliases,
        .case_aliases = &case_aliases,
        .displacements = &displacements,
        .retained_directories = &retained_directories,
        .pending_configuration = &pending,
        .program_sha256 = @splat(0x80),
        .authorization_sha256 = @splat(0x81),
        .path_count = 10,
        .model_bytes = 11,
        .compared_bytes = 12,
        .work_units = 13,
        .digest = @splat(0),
        .arena = undefined,
        .backing_allocator = undefined,
    };
    const original = planDigest(plan_value);

    plan_value.program_sha256[0] ^= 1;
    try expectPlanDigestChanged(original, plan_value);
    plan_value.program_sha256[0] ^= 1;
    plan_value.authorization_sha256[0] ^= 1;
    try expectPlanDigestChanged(original, plan_value);
    plan_value.authorization_sha256[0] ^= 1;
    plan_value.path_count += 1;
    plan_value.model_bytes += 1;
    plan_value.compared_bytes += 1;
    plan_value.work_units += 1;
    try testing.expectEqualSlices(u8, &original, &planDigest(plan_value));
    plan_value.path_count -= 1;
    plan_value.model_bytes -= 1;
    plan_value.compared_bytes -= 1;
    plan_value.work_units -= 1;

    const old_path = paths[0].path;
    paths[0].path = "usr/share/other";
    try expectPlanDigestChanged(original, plan_value);
    paths[0].path = old_path;
    paths[0].publish = false;
    try expectPlanDigestChanged(original, plan_value);
    paths[0].publish = true;
    paths[0].aliased = false;
    try expectPlanDigestChanged(original, plan_value);
    paths[0].aliased = true;
    paths[0].synthesized = false;
    try expectPlanDigestChanged(original, plan_value);
    paths[0].synthesized = true;
    paths[0].archive_entry = null;
    try expectPlanDigestChanged(original, plan_value);
    paths[0].archive_entry = 8;
    previous.inode += 1;
    paths[0].previous = previous;
    try expectPlanDigestChanged(original, plan_value);
    previous.inode -= 1;
    paths[0].previous = previous;
    previous.content_sha256.?[0] ^= 1;
    paths[0].previous = previous;
    previous.change_nanoseconds.? += 1;
    paths[0].previous = previous;
    try expectPlanDigestChanged(original, plan_value);
    previous.change_nanoseconds.? -= 1;
    paths[0].previous = previous;
    previous.directory_sha256.?[0] ^= 1;
    paths[0].previous = previous;
    try expectPlanDigestChanged(original, plan_value);
    previous.directory_sha256.?[0] ^= 1;
    paths[0].previous = previous;
    paths[0].link_source_previous.?.inode += 1;
    try expectPlanDigestChanged(original, plan_value);
    paths[0].link_source_previous.?.inode -= 1;
    try expectPlanDigestChanged(original, plan_value);
    previous.content_sha256.?[0] ^= 1;
    paths[0].previous = previous;

    const old_absolute = removals[0].absolute;
    removals[0].absolute = "/different";
    try expectPlanDigestChanged(original, plan_value);
    removals[0].absolute = old_absolute;
    removals[0].previous.inode += 1;
    try expectPlanDigestChanged(original, plan_value);
    removals[0].previous.inode -= 1;
    resolutions[0].claimant.architecture = "amd64";
    try expectPlanDigestChanged(original, plan_value);
    resolutions[0].claimant.architecture = "arm64";
    list_paths[0] = "/other";
    try expectPlanDigestChanged(original, plan_value);
    list_paths[0] = "/usr/share/file";
    md5sums[0].digest[0] ^= 1;
    try expectPlanDigestChanged(original, plan_value);
    md5sums[0].digest[0] ^= 1;
    conffiles[0].action = .mark_obsolete;
    try expectPlanDigestChanged(original, plan_value);
    conffiles[0].action = .install_new;

    package.bootstrapped = false;
    packages[0] = package;
    try expectPlanDigestChanged(original, plan_value);
    package.bootstrapped = true;
    packages[0] = package;
    package.configured_version = null;
    packages[0] = package;
    try expectPlanDigestChanged(original, plan_value);
    package.configured_version = "0.9";
    packages[0] = package;

    writes[0].bytes = "different status";
    try expectPlanDigestChanged(original, plan_value);
    writes[0].bytes = "status bytes";
    aliases[0].link_target = "./usr/lib";
    try expectPlanDigestChanged(original, plan_value);
    aliases[0].link_target = "usr/lib";
    aliases[0].change_nanoseconds += 1;
    try expectPlanDigestChanged(original, plan_value);
    aliases[0].change_nanoseconds -= 1;
    case_aliases[0].second = "FOO";
    try expectPlanDigestChanged(original, plan_value);
    case_aliases[0].second = "foo";
    displacements[0].holder_index += 1;
    try expectPlanDigestChanged(original, plan_value);
    displacements[0].holder_index -= 1;
    retained_directories[0].previous.inode += 1;
    try expectPlanDigestChanged(original, plan_value);
    retained_directories[0].previous.inode -= 1;
    pending[0].architecture = "amd64";
    try expectPlanDigestChanged(original, plan_value);

    filesystem[0] = .{ .directory = .{
        .path = "usr/share/directory",
        .mode = 0o755,
        .uid = 0,
        .gid = 0,
        .modified_nanoseconds = null,
    } };
    const directory_digest = planDigest(plan_value);
    filesystem[0].directory.modified_nanoseconds = 9;
    try expectPlanDigestChanged(directory_digest, plan_value);
}

test "native_unpack.test.symbolic-link ancestors are typed refusals" {
    var fixture: Fixture = undefined;
    try fixture.init(empty_status, &.{});
    defer fixture.deinit();
    try fixture.root().ensureDirectory(
        try root_fs.Path.init("usr"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().ensureDirectory(
        try root_fs.Path.init("usr/real"),
        root_fs.default_directory_permissions,
    );
    try fixture.root().createSymbolicLink(
        try root_fs.Path.init("usr/blocked"),
        "real",
    );
    var data = [_]Entry{.{ .path = "usr/blocked/file", .content = "x\n" }};
    const bytes = try buildOwnedArchive(.{ .package = "demo", .version = "1" }, &data);
    defer testing.allocator.free(bytes);
    var model = try modelOf(bytes);
    defer model.deinit();
    const steps = [_]native_program.Step{unpackStep(0, &model, 0, null, false)};
    var artifacts: [1]native_program.ProgramArtifact = undefined;
    const program = try singleProgram(&fixture, &model, bytes, &steps, &artifacts);
    try expectRefusal(try planFor(
        &fixture,
        &program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .symbolic_link_ancestor);
}
