//! Native unpack and file ownership for data-only package transactions.
//!
//! This is roadmap item 10a of the native transaction engine. Its private
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
//! `.list`, and `md5sums`. Actual materialization and differential parity are
//! item 10b, not capabilities or guarantees of this module.
//! Configuration, conffiles, scripts, triggers,
//! removal, and purge belong to the following roadmap items. A package that
//! needs one of them is refused with an explicit typed handoff before any
//! mutation, never approximated and never overwritten as ordinary data.

const std = @import("std");
const builtin = @import("builtin");
const archive_application = @import("archive_application.zig");
const control_record = @import("control_record.zig");
const dpkg_status = @import("dpkg_status.zig");
const native_authorization = @import("native_authorization.zig");
const native_program = @import("native_program.zig");
const package_database = @import("package_database.zig");
const package_database_changes = @import("package_database_changes.zig");
const relation = @import("relation.zig");
const root_fs = @import("root_fs.zig");
const version_module = @import("debian_version.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

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
    limits: Limits = .{},
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
    var unpacks: usize = 0;
    var barrier_seen = false;
    var removal_handoff = false;
    for (program.steps) |step| {
        switch (step.operation) {
            .materialize_bootstrap_payload => |intent| {
                if (barrier_seen) try builder.deferFeature(.{
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
                unpacks += 1;
                if (barrier_seen) try builder.deferFeature(.{
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
            .configure_barrier => barrier_seen = true,
            .remove_package_files => |intent| {
                removal_handoff = true;
                try builder.deferFeature(.{
                    .feature = .package_removal,
                    .package = intent.package.name,
                    .architecture = intent.package.architecture,
                });
            },
            .purge_package_files => |intent| {
                removal_handoff = true;
                try builder.deferFeature(.{
                    .feature = .package_purge,
                    .package = intent.package.name,
                    .architecture = intent.package.architecture,
                });
            },
            .run_maintainer_script => |call| try builder.deferFeature(.{
                .feature = .maintainer_script,
                .package = call.package.name,
                .architecture = call.package.architecture,
                .detail = @tagName(call.kind),
            }),
            .apply_conffile_decision => |decision| try builder.deferFeature(.{
                .feature = .conffile_decision,
                .package = decision.package.name,
                .architecture = decision.package.architecture,
                .detail = decision.path,
            }),
            .record_trigger_interests => |record| try builder.deferFeature(.{
                .feature = .trigger,
                .package = record.package.name,
                .architecture = record.package.architecture,
            }),
            .activate_trigger => |activation| try builder.deferFeature(.{
                .feature = .trigger,
                .package = activation.source.name,
                .architecture = activation.source.architecture,
                .detail = activation.trigger,
            }),
            .process_deferred_triggers => try builder.deferFeature(.{ .feature = .trigger }),
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
    if (!removal_handoff and (unpacks == 0 or builder.work.items.len == 0))
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
            .unpacked => scalarStatusField(record.*, "Config-Version") orelse blk: {
                try builder.deferFeature(.{
                    .feature = .config_version,
                    .package = identity.name,
                    .architecture = identity.architecture,
                });
                break :blk null;
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

fn scalarStatusField(
    record: package_database.PackageRecord,
    name: []const u8,
) ?[]const u8 {
    const field = record.field(name) orelse return null;
    if (field.value_lines.len != 1) return null;
    const value = field.value_lines[0];
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0 or !std.mem.eql(u8, trimmed, value)) return null;
    _ = version_module.DebianVersion.parse(value) catch return null;
    return value;
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
    for (model.triggers.pending) |queued| {
        if (queued.packages.len == 0)
            try builder.deferFeature(.{ .feature = .trigger, .detail = queued.trigger });
        for (queued.packages) |awaiting| try builder.deferFeature(.{
            .feature = .trigger,
            .package = awaiting.package.name,
            .architecture = awaiting.package.architecture,
            .detail = queued.trigger,
        });
    }
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
        for (archive.conffiles) |conffile| try builder.deferFeature(.{
            .feature = .conffile,
            .package = item.identity.name,
            .architecture = item.identity.architecture,
            .detail = conffile.path,
        });
        for (archive.scripts) |script| try builder.deferFeature(.{
            .feature = .maintainer_script,
            .package = item.identity.name,
            .architecture = item.identity.architecture,
            .detail = script.name,
        });
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
        for (prior.conffiles) |conffile| try builder.deferFeature(.{
            .feature = .conffile,
            .package = prior.name,
            .architecture = prior.architecture,
            .detail = conffile.path,
        });
        for (prior.scripts) |script| try builder.deferFeature(.{
            .feature = .maintainer_script,
            .package = prior.name,
            .architecture = prior.architecture,
            .detail = script.kind.suffix(),
        });
        if (prior.trigger_declarations) |declarations| {
            for (declarations) |declaration| try builder.deferFeature(.{
                .feature = .trigger,
                .package = prior.name,
                .architecture = prior.architecture,
                .detail = declaration.name,
            });
        }
        for (prior.triggers_pending) |trigger| try builder.deferFeature(.{
            .feature = .trigger,
            .package = prior.name,
            .architecture = prior.architecture,
            .detail = trigger,
        });
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

// ---------------------------------------------------------------------------
// Per-package planning
// ---------------------------------------------------------------------------

fn preparePackageClaims(
    builder: *Builder,
    item: *PackageWork,
) PlanError!void {
    const model = item.model;
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
                if (transactionPackageClaims(builder, path, work_index)) {
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
        try item.list_paths.append(builder.allocator, planned.absolute);
        switch (planned.kind) {
            .regular, .hardlink => try item.md5sums.append(builder.allocator, .{
                .path = planned.path,
                .digest = planned.md5.?,
            }),
            .directory, .symlink => {},
        }
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

    var field_count: usize = 1 + @as(usize, @intFromBool(
        item.configured_version != null,
    ));
    for (status_field_order) |name| {
        if (std.ascii.eqlIgnoreCase(name, "Status") or
            std.ascii.eqlIgnoreCase(name, "Config-Version")) continue;
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
        try changes.append(builder.allocator, .{ .put_package = .{
            .fields = try statusFields(builder, item, model, .unpacked),
            .paths = item.list_paths.items,
            .md5sums = item.md5sums.items,
            .declared_conffiles = null,
            .trigger_declarations = null,
            .scripts = &.{},
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

test "native_unpack.test.explicit Config-Version is retained and missing evidence hands off" {
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
    try expectHandoff(try planFor(
        &missing,
        &missing_program,
        &.{.{ .artifact = 0, .bytes = bytes }},
    ), .config_version);
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
