//! Bounded, typed native model of the Debian package database under
//! `var/lib/dpkg`.
//!
//! This module owns the v1 database surfaces selected by
//! `doc/native-transaction-engine-v1.md`: `status`, `status-old`, `updates/`,
//! `arch`, `info/*.list`, `info/*.md5sums`, `info/*.conffiles`,
//! `info/*.triggers`, the maintainer scripts, `triggers/File`,
//! `triggers/Unincorp`, `diversions`, and `statoverride`.
//!
//! The module is deliberately filesystem free. Callers supply an already
//! captured, bounded `Snapshot` of one database generation and receive a typed
//! `Database`, or a typed `Diagnostic` describing the exact surface, code,
//! path, and line that failed. Both borrow the snapshot bytes, which must
//! outlive them; only derived structure is allocated. Root-anchored, no-follow reads
//! and crash-safe publication of a planned change set belong to the
//! filesystem and mutation layers; this module never opens, reads, or writes
//! a file. That boundary keeps import validation, canonical serialization,
//! and change staging testable without an install root and prevents partial
//! multi-file mutation from being attempted here.
const std = @import("std");
const deb822 = @import("deb822.zig");
const absolute_path = @import("absolute_path.zig");
const status_model = @import("dpkg_status.zig");
const version_module = @import("debian_version.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Want = status_model.Want;
pub const ErrorState = status_model.ErrorState;
pub const CurrentState = status_model.CurrentState;
pub const MultiArch = status_model.MultiArch;
pub const Status = status_model.Status;
pub const DebianVersion = version_module.DebianVersion;

/// Database paths are always relative to the selected root.
pub const database_directory = "var/lib/dpkg";
pub const status_path = "status";
pub const status_old_path = "status-old";
pub const arch_path = "arch";
pub const diversions_path = "diversions";
pub const statoverride_path = "statoverride";
pub const info_directory = "info";
pub const updates_directory = "updates";
pub const triggers_file_path = "triggers/File";
pub const triggers_unincorp_path = "triggers/Unincorp";
/// `info/format` records the on-disk info-directory format. V1 supports 1.
pub const info_format_name = "format";
pub const supported_info_format = "1";

pub const Limits = struct {
    max_status_bytes: usize = 64 * 1024 * 1024,
    max_packages: usize = 100_000,
    max_fields_per_package: usize = 512,
    max_field_bytes: usize = 1024 * 1024,
    max_package_name_bytes: usize = 255,
    max_architecture_bytes: usize = 64,
    max_version_bytes: usize = 255,
    max_conffiles_per_package: usize = 8_192,
    max_paths_per_package: usize = 200_000,
    max_total_owned_paths: usize = 4_000_000,
    max_path_bytes: usize = 4096,
    max_md5sums_per_package: usize = 200_000,
    max_info_entries: usize = 1_000_000,
    max_info_file_bytes: usize = 64 * 1024 * 1024,
    max_maintainer_script_bytes: usize = 16 * 1024 * 1024,
    max_trigger_declarations_per_package: usize = 4096,
    max_trigger_name_bytes: usize = 4096,
    max_trigger_interests: usize = 200_000,
    max_pending_triggers: usize = 200_000,
    max_packages_per_pending_trigger: usize = 4096,
    max_triggers_per_package: usize = 4096,
    max_foreign_architectures: usize = 64,
    max_update_fragments: usize = 4096,
    max_diversions: usize = 100_000,
    max_stat_overrides: usize = 100_000,
    max_line_bytes: usize = 8192,
};

/// Nonempty `updates/` means a previous database publication was interrupted.
pub const UpdatesPolicy = enum {
    /// Fail import before any mutation can be planned.
    require_empty,
    /// Import the fragments as recovery evidence. Change planning still
    /// refuses to run until recovery clears them.
    import_for_recovery,
};

pub const Options = struct {
    limits: Limits = .{},
    updates_policy: UpdatesPolicy = .require_empty,
};

/// Directory-entry classification supplied by the capturing reader. Only
/// regular files are database content; everything else fails closed.
pub const EntryKind = enum {
    regular,
    directory,
    symlink,
    other,
};

pub const InfoEntry = struct {
    name: []const u8,
    bytes: []const u8 = &.{},
    kind: EntryKind = .regular,
    mode: u32 = 0o644,
};

pub const UpdateEntry = struct {
    name: []const u8,
    bytes: []const u8 = &.{},
    kind: EntryKind = .regular,
};

/// One captured database generation. Absent optional members mean the file
/// does not exist in the root; empty slices mean the file or directory exists
/// and is empty.
pub const Snapshot = struct {
    status: []const u8,
    status_old: ?[]const u8 = null,
    arch: ?[]const u8 = null,
    diversions: ?[]const u8 = null,
    statoverride: ?[]const u8 = null,
    triggers_file: ?[]const u8 = null,
    triggers_unincorp: ?[]const u8 = null,
    info: []const InfoEntry = &.{},
    updates: []const UpdateEntry = &.{},
};

pub const ImportRequest = struct {
    /// Native architecture from the authorized request, not from the root.
    native_architecture: []const u8,
    snapshot: Snapshot,
};

pub const Identity = struct {
    name: []const u8,
    architecture: []const u8,

    pub fn eql(left: Identity, right: Identity) bool {
        return std.mem.eql(u8, left.name, right.name) and
            std.mem.eql(u8, left.architecture, right.architecture);
    }
};

/// Exact ordered status field. Unknown but well-formed fields are retained
/// verbatim so republished status keeps foreign metadata.
pub const StatusField = struct {
    name: []const u8,
    value_lines: []const []const u8,
};

pub const ConffileDigest = union(enum) {
    /// dpkg's placeholder for a conffile that has not been installed yet.
    new_conffile,
    md5: [16]u8,
};

pub const ConffileEntry = struct {
    path: []const u8,
    digest: ConffileDigest,
    obsolete: bool = false,
    remove_on_upgrade: bool = false,
};

pub const Md5sumEntry = struct {
    /// Canonical relative payload path, without a leading slash.
    path: []const u8,
    digest: [16]u8,
};

pub const ScriptKind = enum {
    preinst,
    postinst,
    prerm,
    postrm,

    pub fn suffix(self: ScriptKind) []const u8 {
        return @tagName(self);
    }
};

pub const MaintainerScript = struct {
    kind: ScriptKind,
    mode: u32,
    size: usize,
    sha256: [32]u8,
};

pub const TriggerDeclarationKind = enum {
    interest,
    interest_await,
    interest_noawait,
    activate,
    activate_await,
    activate_noawait,

    pub fn spelling(self: TriggerDeclarationKind) []const u8 {
        return switch (self) {
            .interest => "interest",
            .interest_await => "interest-await",
            .interest_noawait => "interest-noawait",
            .activate => "activate",
            .activate_await => "activate-await",
            .activate_noawait => "activate-noawait",
        };
    }

    pub fn isInterest(self: TriggerDeclarationKind) bool {
        return switch (self) {
            .interest, .interest_await, .interest_noawait => true,
            else => false,
        };
    }

    pub fn awaitMode(self: TriggerDeclarationKind) AwaitMode {
        return switch (self) {
            .interest, .interest_await, .activate, .activate_await => .awaited,
            .interest_noawait, .activate_noawait => .noawait,
        };
    }
};

pub const AwaitMode = enum {
    awaited,
    noawait,
};

pub const TriggerDeclaration = struct {
    kind: TriggerDeclarationKind,
    name: []const u8,
};

/// One `triggers/File` record: a file trigger and the interested package.
pub const TriggerInterest = struct {
    trigger: []const u8,
    package: Identity,
    await_mode: AwaitMode,
};

pub const PendingPackage = struct {
    package: Identity,
    await_mode: AwaitMode,
};

/// One `triggers/Unincorp` record: an activated trigger and its packages.
pub const PendingTrigger = struct {
    trigger: []const u8,
    packages: []const PendingPackage,
};

pub const TriggerState = struct {
    interests: []const TriggerInterest = &.{},
    pending: []const PendingTrigger = &.{},
};

pub const DiversionRecord = struct {
    from: []const u8,
    to: []const u8,
    /// `null` is dpkg's local diversion (`:` in the file).
    package: ?[]const u8,
};

pub const StatOverrideRecord = struct {
    user: []const u8,
    group: []const u8,
    mode: u32,
    path: []const u8,
};

/// A retained but not natively modeled `info` file, such as `templates`,
/// `shlibs`, `symbols`, `config`, or a vendor extension.
pub const OpaqueInfoFile = struct {
    name: []const u8,
    owner: ?Identity,
    mode: u32,
    size: usize,
    sha256: [32]u8,
};

pub const StatusGeneration = struct {
    sha256: [32]u8,
    size: usize,
    package_count: usize,
};

pub const PendingUpdate = struct {
    name: []const u8,
    sequence: u64,
    package_count: usize,
    sha256: [32]u8,
};

pub const PackageRecord = struct {
    name: []const u8,
    architecture: []const u8,
    version: []const u8,
    parsed_version: DebianVersion,
    status: Status,
    multi_arch: ?MultiArch,
    essential: bool,
    protected: bool,
    fields: []const StatusField,
    conffiles: []const ConffileEntry,
    triggers_pending: []const []const u8,
    triggers_awaited: []const []const u8,
    /// `name` or `name:architecture`, exactly as the `info` files spell it.
    info_stem: []const u8,
    /// `info/<stem>.list`, absent for states that own no files.
    paths: ?[]const []const u8,
    md5sums: ?[]const Md5sumEntry,
    declared_conffiles: ?[]const []const u8,
    trigger_declarations: ?[]const TriggerDeclaration,
    scripts: []const MaintainerScript,

    pub fn identity(self: PackageRecord) Identity {
        return .{ .name = self.name, .architecture = self.architecture };
    }

    pub fn ownsPath(self: PackageRecord, path: []const u8) bool {
        const paths = self.paths orelse return false;
        for (paths) |owned| {
            if (std.mem.eql(u8, logicalListPath(owned), logicalListPath(path))) return true;
        }
        return false;
    }

    pub fn script(self: PackageRecord, kind: ScriptKind) ?MaintainerScript {
        for (self.scripts) |entry| {
            if (entry.kind == kind) return entry;
        }
        return null;
    }

    pub fn conffile(self: PackageRecord, path: []const u8) ?ConffileEntry {
        for (self.conffiles) |entry| {
            if (std.mem.eql(u8, entry.path, path)) return entry;
        }
        return null;
    }

    pub fn field(self: PackageRecord, name: []const u8) ?StatusField {
        for (self.fields) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry;
        }
        return null;
    }
};

/// dpkg spells the root directory `/.` in `info/*.list`.
pub const root_list_path = "/.";

pub fn logicalListPath(path: []const u8) []const u8 {
    return if (std.mem.eql(u8, path, root_list_path)) "/" else path;
}

/// The complete typed content of one database generation. `Model` is shared
/// with the change-staging layer, which validates candidate models with the
/// same rules that import uses.
pub const Model = struct {
    native_architecture: []const u8,
    /// Identity of the `status` generation this model serializes to.
    status: StatusGeneration,
    foreign_architectures: []const []const u8 = &.{},
    packages: []const PackageRecord = &.{},
    triggers: TriggerState = .{},
    diversions: []const DiversionRecord = &.{},
    stat_overrides: []const StatOverrideRecord = &.{},
    opaque_info: []const OpaqueInfoFile = &.{},
    pending_updates: []const PendingUpdate = &.{},
    status_old: ?StatusGeneration = null,
    info_format_present: bool = false,

    pub fn find(self: Model, name: []const u8, architecture: []const u8) ?*const PackageRecord {
        for (self.packages) |*record| {
            if (std.mem.eql(u8, record.name, name) and
                std.mem.eql(u8, record.architecture, architecture))
            {
                return record;
            }
        }
        return null;
    }

    pub fn findStem(self: Model, stem: []const u8) ?*const PackageRecord {
        for (self.packages) |*record| {
            if (std.mem.eql(u8, record.info_stem, stem)) return record;
        }
        return null;
    }

    /// Every package that lists `path` in its ownership index. Directories are
    /// legitimately shared, so shared ownership is reported, not rejected.
    pub fn owners(
        self: Model,
        allocator: std.mem.Allocator,
        path: []const u8,
    ) std.mem.Allocator.Error![]Identity {
        var found: std.ArrayList(Identity) = .empty;
        errdefer found.deinit(allocator);
        for (self.packages) |record| {
            if (record.ownsPath(path)) try found.append(allocator, record.identity());
        }
        return found.toOwnedSlice(allocator);
    }

    pub fn knowsArchitecture(self: Model, architecture: []const u8) bool {
        if (std.mem.eql(u8, architecture, "all")) return true;
        if (std.mem.eql(u8, architecture, self.native_architecture)) return true;
        for (self.foreign_architectures) |value| {
            if (std.mem.eql(u8, value, architecture)) return true;
        }
        return false;
    }
};

/// Evidence that binds an authorization to the exact consumed generation.
pub const Generation = struct {
    sha256: [32]u8,
    file_count: usize,
    total_bytes: u64,

    pub fn eql(left: Generation, right: Generation) bool {
        return std.mem.eql(u8, &left.sha256, &right.sha256) and
            left.file_count == right.file_count and
            left.total_bytes == right.total_bytes;
    }
};

/// An imported generation. Text borrows the request snapshot; the arena owns
/// only the derived structure.
pub const Database = struct {
    model: Model,
    generation: Generation,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *Database) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const Surface = enum {
    status,
    status_old,
    updates,
    architectures,
    info_directory,
    info_list,
    info_md5sums,
    info_conffiles,
    info_triggers,
    info_script,
    info_format,
    triggers_file,
    triggers_unincorp,
    diversions,
    statoverride,
    cross_file,
    generation,
    change_set,

    pub fn path(self: Surface) []const u8 {
        return switch (self) {
            .status => status_path,
            .status_old => status_old_path,
            .updates => updates_directory,
            .architectures => arch_path,
            .info_directory,
            .info_list,
            .info_md5sums,
            .info_conffiles,
            .info_triggers,
            .info_script,
            .info_format,
            => info_directory,
            .triggers_file => triggers_file_path,
            .triggers_unincorp => triggers_unincorp_path,
            .diversions => diversions_path,
            .statoverride => statoverride_path,
            .cross_file, .generation, .change_set => database_directory,
        };
    }
};

pub const Code = enum {
    status_syntax,
    status_limit,
    field_limit,
    missing_field,
    invalid_package_name,
    invalid_architecture,
    unknown_architecture,
    invalid_version,
    multiline_scalar,
    malformed_status_field,
    invalid_state,
    invalid_boolean,
    invalid_multi_arch,
    invalid_priority,
    invalid_installed_size,
    invalid_conffile,
    duplicate_conffile,
    conffile_limit,
    repeated_identity,
    multiarch_conflict,
    unterminated_line,
    control_character,
    line_too_long,
    empty_line,
    invalid_path,
    path_too_long,
    duplicate_path,
    path_limit,
    invalid_checksum,
    duplicate_checksum,
    checksum_limit,
    checksum_out_of_inventory,
    malformed_info_name,
    duplicate_info_name,
    orphan_info_file,
    ambiguous_info_file,
    unsupported_info_format,
    unsupported_entry_kind,
    unsafe_mode,
    file_too_large,
    info_limit,
    missing_file_list,
    unexpected_file_list,
    conffile_not_owned,
    declared_conffile_mismatch,
    invalid_trigger_declaration,
    invalid_trigger_name,
    duplicate_trigger_declaration,
    trigger_limit,
    invalid_trigger_record,
    unknown_trigger_package,
    trigger_interest_mismatch,
    duplicate_trigger_interest,
    missing_trigger_state,
    unexpected_trigger_state,
    invalid_architecture_record,
    duplicate_architecture,
    native_architecture_listed,
    architecture_limit,
    update_fragments_present,
    invalid_update_name,
    invalid_update_fragment,
    update_limit,
    invalid_diversion,
    diversion_limit,
    invalid_statoverride,
    statoverride_limit,
    external_generation_change,
    unsupported_diversion,
    unsupported_statoverride,
    unknown_package,
    conflicting_change,
    invalid_transition,
    invalid_script,
    unsupported_info_rename,
    plan_limit,
    out_of_memory,
};

pub const Diagnostic = struct {
    surface: Surface,
    code: Code,
    /// Database-relative path or `info` entry name. Borrowed from the request
    /// snapshot or from static storage; it does not outlive the caller's input.
    path: []const u8 = "",
    package: []const u8 = "",
    line: ?usize = null,
    field_name: ?[]const u8 = null,
    status_syntax: ?deb822.ErrorKind = null,

    pub fn message(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .status_syntax => "status file is not valid DEB822",
            .status_limit => "status file exceeds a configured bound",
            .field_limit => "status paragraph exceeds a configured field bound",
            .missing_field => "status paragraph is missing a required field",
            .invalid_package_name => "package name is not a valid binary package name",
            .invalid_architecture => "architecture is malformed",
            .unknown_architecture => "architecture is neither native, all, nor a listed foreign architecture",
            .invalid_version => "version is not a valid Debian version",
            .multiline_scalar => "scalar status field must not use continuation lines",
            .malformed_status_field => "Status must contain want, error, and current-state tokens",
            .invalid_state => "status contains an unknown state token",
            .invalid_boolean => "boolean status field must be 'yes' or 'no'",
            .invalid_multi_arch => "Multi-Arch contains an unknown value",
            .invalid_priority => "Priority contains an unknown value",
            .invalid_installed_size => "Installed-Size must be an unsigned decimal integer",
            .invalid_conffile => "Conffiles entry is malformed",
            .duplicate_conffile => "Conffiles lists a path twice",
            .conffile_limit => "package exceeds the configured conffile limit",
            .repeated_identity => "package and architecture identity is repeated",
            .multiarch_conflict => "co-installed package instances are not Multi-Arch consistent",
            .unterminated_line => "database file must end with a newline",
            .control_character => "database file contains a control character",
            .line_too_long => "database line exceeds the configured limit",
            .empty_line => "database file contains an unexpected empty line",
            .invalid_path => "path is not a canonical absolute or relative database path",
            .path_too_long => "path exceeds the configured limit",
            .duplicate_path => "file list repeats a path",
            .path_limit => "file list exceeds a configured path limit",
            .invalid_checksum => "checksum record is malformed",
            .duplicate_checksum => "checksum file repeats a path",
            .checksum_limit => "checksum file exceeds the configured limit",
            .checksum_out_of_inventory => "checksum path is not owned by the package",
            .malformed_info_name => "info file name is not a qualified package file name",
            .duplicate_info_name => "info directory repeats an entry name",
            .orphan_info_file => "info file has no status record",
            .ambiguous_info_file => "info file name matches more than one package instance",
            .unsupported_info_format => "info directory format is unsupported",
            .unsupported_entry_kind => "database entry is not a regular file",
            .unsafe_mode => "database file mode is unsafe",
            .file_too_large => "database file exceeds a configured size limit",
            .info_limit => "info directory exceeds the configured entry limit",
            .missing_file_list => "installed package has no ownership list",
            .unexpected_file_list => "package state must not own an ownership list",
            .conffile_not_owned => "conffile is not present in the package ownership list",
            .declared_conffile_mismatch => "declared conffile is absent from the status record",
            .invalid_trigger_declaration => "trigger declaration is malformed",
            .invalid_trigger_name => "trigger name is malformed",
            .duplicate_trigger_declaration => "trigger declaration is repeated",
            .trigger_limit => "trigger state exceeds a configured limit",
            .invalid_trigger_record => "trigger state record is malformed",
            .unknown_trigger_package => "trigger state names an unknown package",
            .trigger_interest_mismatch => "file trigger interest is not declared by the package",
            .duplicate_trigger_interest => "file trigger interest is repeated",
            .missing_trigger_state => "trigger state field is required by the package state",
            .unexpected_trigger_state => "trigger state field contradicts the package state",
            .invalid_architecture_record => "architecture record is malformed",
            .duplicate_architecture => "architecture list repeats an entry",
            .native_architecture_listed => "architecture list must not repeat the native architecture",
            .architecture_limit => "architecture list exceeds the configured limit",
            .update_fragments_present => "interrupted database publication requires explicit recovery",
            .invalid_update_name => "update fragment name is malformed",
            .invalid_update_fragment => "update fragment is not a valid status document",
            .update_limit => "updates directory exceeds the configured limit",
            .invalid_diversion => "diversion record is malformed",
            .diversion_limit => "diversions exceed the configured limit",
            .invalid_statoverride => "statoverride record is malformed",
            .statoverride_limit => "statoverride records exceed the configured limit",
            .external_generation_change => "database generation changed after it was consumed",
            .unsupported_diversion => "a diversion covers a package or path being changed",
            .unsupported_statoverride => "a statoverride covers a path being changed",
            .unknown_package => "change targets a package that is not in the database",
            .conflicting_change => "more than one staged change targets the same subject",
            .invalid_transition => "package state transition is not permitted",
            .invalid_script => "maintainer script content or mode is unsafe",
            .unsupported_info_rename => "package owns unmodeled info files that cannot be renamed",
            .plan_limit => "change set exceeds a configured limit",
            .out_of_memory => "database import exceeded available memory",
        };
    }
};

pub const Result = union(enum) {
    database: Database,
    diagnostic: Diagnostic,
};

const ImportError = std.mem.Allocator.Error || error{Invalid};

const Line = struct {
    text: []const u8,
    number: usize,
    terminated: bool,
};

const Lines = struct {
    rest: []const u8,
    number: usize = 0,

    fn init(bytes: []const u8) Lines {
        return .{ .rest = bytes };
    }

    fn next(self: *Lines) ?Line {
        if (self.rest.len == 0) return null;
        self.number += 1;
        const end = std.mem.indexOfScalar(u8, self.rest, '\n') orelse {
            const text = self.rest;
            self.rest = self.rest[self.rest.len..];
            return .{ .text = text, .number = self.number, .terminated = false };
        };
        const text = self.rest[0..end];
        self.rest = self.rest[end + 1 ..];
        return .{ .text = text, .number = self.number, .terminated = true };
    }
};

pub fn validPackageName(name: []const u8) bool {
    if (name.len < 2) return false;
    if (!std.ascii.isAlphanumeric(name[0]) or std.ascii.isUpper(name[0])) return false;
    for (name) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '+' or byte == '-' or byte == '.';
        if (!ok) return false;
    }
    return true;
}

pub fn validArchitecture(architecture: []const u8) bool {
    if (architecture.len == 0) return false;
    if (!std.ascii.isAlphanumeric(architecture[0])) return false;
    for (architecture) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '-';
        if (!ok) return false;
    }
    return true;
}

/// A trigger is either a file trigger (canonical absolute path) or a named
/// trigger using dpkg's package-name grammar.
pub fn validTriggerName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name[0] == '/') return absolute_path.nonRoot(name);
    return validPackageName(name);
}

fn parseHexDigest(comptime len: usize, text: []const u8) ?[len]u8 {
    if (text.len != len * 2) return null;
    var digest: [len]u8 = undefined;
    for (0..len) |index| {
        const high = hexValue(text[index * 2]) orelse return null;
        const low = hexValue(text[index * 2 + 1]) orelse return null;
        digest[index] = (high << 4) | low;
    }
    return digest;
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        else => null,
    };
}

fn writeHex(writer: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    const digits = "0123456789abcdef";
    for (bytes) |byte| {
        try writer.writeByte(digits[byte >> 4]);
        try writer.writeByte(digits[byte & 0x0f]);
    }
}

fn digestOf(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    return digest;
}

pub fn safeFileMode(mode: u32) bool {
    return safeMode(mode);
}

pub fn executableFileMode(mode: u32) bool {
    return executableMode(mode);
}

fn safeMode(mode: u32) bool {
    const setuid = 0o4000;
    const setgid = 0o2000;
    const world_writable = 0o0002;
    return mode & (setuid | setgid | world_writable) == 0;
}

fn executableMode(mode: u32) bool {
    return mode & 0o100 != 0;
}

pub const FieldsResult = union(enum) {
    record: PackageRecord,
    diagnostic: Diagnostic,
};

/// Interpret one ordered status paragraph. `fields` and every string it
/// references must outlive the returned record; only derived slices are
/// allocated from `arena`. Import and change staging share this routine so a
/// staged record is validated exactly like an imported one.
pub fn interpretPackageFields(
    arena: std.mem.Allocator,
    fields: []const StatusField,
    options: Options,
    surface: Surface,
) std.mem.Allocator.Error!FieldsResult {
    var interpreter: FieldInterpreter = .{
        .arena = arena,
        .options = options,
        .surface = surface,
        .fields = fields,
    };
    const record = interpreter.run() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Invalid => return .{ .diagnostic = interpreter.diagnostic.? },
    };
    return .{ .record = record };
}

const FieldInterpreter = struct {
    arena: std.mem.Allocator,
    options: Options,
    surface: Surface,
    fields: []const StatusField,
    diagnostic: ?Diagnostic = null,

    fn fail(
        self: *FieldInterpreter,
        code: Code,
        field_name: ?[]const u8,
        package: []const u8,
    ) error{Invalid} {
        self.diagnostic = .{
            .surface = self.surface,
            .code = code,
            .path = self.surface.path(),
            .package = package,
            .field_name = field_name,
        };
        return error.Invalid;
    }

    fn find(self: FieldInterpreter, name: []const u8) ?StatusField {
        for (self.fields) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry;
        }
        return null;
    }

    fn scalar(self: *FieldInterpreter, name: []const u8, package: []const u8) ImportError!?[]const u8 {
        const entry = self.find(name) orelse return null;
        if (entry.value_lines.len != 1) return self.fail(.multiline_scalar, name, package);
        return entry.value_lines[0];
    }

    fn required(self: *FieldInterpreter, name: []const u8, package: []const u8) ImportError![]const u8 {
        return try self.scalar(name, package) orelse
            self.fail(.missing_field, name, package);
    }

    fn run(self: *FieldInterpreter) ImportError!PackageRecord {
        if (self.fields.len > self.options.limits.max_fields_per_package) {
            return self.fail(.field_limit, null, "");
        }
        for (self.fields) |entry| {
            if (!validFieldName(entry.name)) return self.fail(.status_syntax, entry.name, "");
        }
        const name = try self.required("Package", "");
        if (name.len > self.options.limits.max_package_name_bytes or !validPackageName(name)) {
            return self.fail(.invalid_package_name, "Package", name);
        }
        const architecture = try self.required("Architecture", name);
        if (architecture.len > self.options.limits.max_architecture_bytes or
            (!std.mem.eql(u8, architecture, "all") and !validArchitecture(architecture)))
        {
            return self.fail(.invalid_architecture, "Architecture", name);
        }
        const version = try self.required("Version", name);
        if (version.len > self.options.limits.max_version_bytes) {
            return self.fail(.invalid_version, "Version", name);
        }
        const parsed_version = DebianVersion.parse(version) catch
            return self.fail(.invalid_version, "Version", name);

        const status = try self.parseStatus(try self.required("Status", name), name);
        const multi_arch = try self.parseMultiArch(name);
        if (try self.scalar("Priority", name)) |priority| {
            if (std.meta.stringToEnum(status_model.Priority, priority) == null) {
                return self.fail(.invalid_priority, "Priority", name);
            }
        }
        if (try self.scalar("Installed-Size", name)) |size| {
            if (size.len == 0) return self.fail(.invalid_installed_size, "Installed-Size", name);
            for (size) |byte| {
                if (!std.ascii.isDigit(byte)) {
                    return self.fail(.invalid_installed_size, "Installed-Size", name);
                }
            }
        }
        const conffiles = try self.parseConffiles(name);
        const triggers_pending = try self.parseTriggerList("Triggers-Pending", name);
        const triggers_awaited = try self.parseTriggerList("Triggers-Awaited", name);

        const stem = if (multi_arch == .same)
            try std.fmt.allocPrint(self.arena, "{s}:{s}", .{ name, architecture })
        else
            name;

        return .{
            .name = name,
            .architecture = architecture,
            .version = version,
            .parsed_version = parsed_version,
            .status = status,
            .multi_arch = multi_arch,
            .essential = try self.parseBoolean("Essential", name),
            .protected = try self.parseBoolean("Protected", name),
            .fields = self.fields,
            .conffiles = conffiles,
            .triggers_pending = triggers_pending,
            .triggers_awaited = triggers_awaited,
            .info_stem = stem,
            .paths = null,
            .md5sums = null,
            .declared_conffiles = null,
            .trigger_declarations = null,
            .scripts = &.{},
        };
    }

    fn parseStatus(self: *FieldInterpreter, text: []const u8, package: []const u8) ImportError!Status {
        var tokens = std.mem.splitScalar(u8, text, ' ');
        const want_text = tokens.next() orelse
            return self.fail(.malformed_status_field, "Status", package);
        const error_text = tokens.next() orelse
            return self.fail(.malformed_status_field, "Status", package);
        const current_text = tokens.next() orelse
            return self.fail(.malformed_status_field, "Status", package);
        if (tokens.next() != null) return self.fail(.malformed_status_field, "Status", package);

        const want = std.meta.stringToEnum(Want, want_text) orelse
            return self.fail(.invalid_state, "Status", package);
        const error_state: ErrorState = if (std.mem.eql(u8, error_text, "ok"))
            .ok
        else if (std.mem.eql(u8, error_text, "reinstreq"))
            .reinst_required
        else
            return self.fail(.invalid_state, "Status", package);
        const current = currentStateFromSpelling(current_text) orelse
            return self.fail(.invalid_state, "Status", package);
        return .{ .want = want, .error_state = error_state, .current = current };
    }

    fn parseBoolean(self: *FieldInterpreter, name: []const u8, package: []const u8) ImportError!bool {
        const text = try self.scalar(name, package) orelse return false;
        if (std.mem.eql(u8, text, "yes")) return true;
        if (std.mem.eql(u8, text, "no")) return false;
        return self.fail(.invalid_boolean, name, package);
    }

    fn parseMultiArch(self: *FieldInterpreter, package: []const u8) ImportError!?MultiArch {
        const text = try self.scalar("Multi-Arch", package) orelse return null;
        return std.meta.stringToEnum(MultiArch, text) orelse
            self.fail(.invalid_multi_arch, "Multi-Arch", package);
    }

    fn parseConffiles(self: *FieldInterpreter, package: []const u8) ImportError![]const ConffileEntry {
        const entry = self.find("Conffiles") orelse return &.{};
        var conffiles: std.ArrayList(ConffileEntry) = .empty;
        defer conffiles.deinit(self.arena);
        for (entry.value_lines) |line| {
            if (line.len == 0) continue;
            if (conffiles.items.len >= self.options.limits.max_conffiles_per_package) {
                return self.fail(.conffile_limit, "Conffiles", package);
            }
            const parsed = try self.parseConffileLine(line, package);
            for (conffiles.items) |existing| {
                if (std.mem.eql(u8, existing.path, parsed.path)) {
                    return self.fail(.duplicate_conffile, "Conffiles", package);
                }
            }
            try conffiles.append(self.arena, parsed);
        }
        return try self.arena.dupe(ConffileEntry, conffiles.items);
    }

    fn parseConffileLine(
        self: *FieldInterpreter,
        line: []const u8,
        package: []const u8,
    ) ImportError!ConffileEntry {
        var tokens = std.mem.splitScalar(u8, line, ' ');
        const path = tokens.next() orelse return self.fail(.invalid_conffile, "Conffiles", package);
        const digest_text = tokens.next() orelse
            return self.fail(.invalid_conffile, "Conffiles", package);
        if (path.len > self.options.limits.max_path_bytes or !absolute_path.nonRoot(path)) {
            return self.fail(.invalid_conffile, "Conffiles", package);
        }
        const digest: ConffileDigest = if (std.mem.eql(u8, digest_text, "newconffile"))
            .new_conffile
        else
            .{ .md5 = parseHexDigest(16, digest_text) orelse
                return self.fail(.invalid_conffile, "Conffiles", package) };

        var obsolete = false;
        var remove_on_upgrade = false;
        while (tokens.next()) |flag| {
            if (std.mem.eql(u8, flag, "obsolete")) {
                if (obsolete) return self.fail(.invalid_conffile, "Conffiles", package);
                obsolete = true;
            } else if (std.mem.eql(u8, flag, "remove-on-upgrade")) {
                if (remove_on_upgrade) return self.fail(.invalid_conffile, "Conffiles", package);
                remove_on_upgrade = true;
            } else {
                return self.fail(.invalid_conffile, "Conffiles", package);
            }
        }
        return .{
            .path = path,
            .digest = digest,
            .obsolete = obsolete,
            .remove_on_upgrade = remove_on_upgrade,
        };
    }

    fn parseTriggerList(
        self: *FieldInterpreter,
        name: []const u8,
        package: []const u8,
    ) ImportError![]const []const u8 {
        const text = try self.scalar(name, package) orelse return &.{};
        var values: std.ArrayList([]const u8) = .empty;
        defer values.deinit(self.arena);
        var tokens = std.mem.tokenizeScalar(u8, text, ' ');
        while (tokens.next()) |token| {
            if (values.items.len >= self.options.limits.max_triggers_per_package) {
                return self.fail(.trigger_limit, name, package);
            }
            if (token.len > self.options.limits.max_trigger_name_bytes) {
                return self.fail(.invalid_trigger_name, name, package);
            }
            const valid = if (std.mem.eql(u8, name, "Triggers-Awaited"))
                validQualifiedPackage(token)
            else
                validTriggerName(token);
            if (!valid) return self.fail(.invalid_trigger_name, name, package);
            for (values.items) |existing| {
                if (std.mem.eql(u8, existing, token)) {
                    return self.fail(.invalid_trigger_name, name, package);
                }
            }
            try values.append(self.arena, token);
        }
        if (values.items.len == 0) return self.fail(.invalid_trigger_name, name, package);
        return try self.arena.dupe([]const u8, values.items);
    }
};

fn currentStateFromSpelling(text: []const u8) ?CurrentState {
    const states = std.StaticStringMap(CurrentState).initComptime(.{
        .{ "not-installed", .not_installed },
        .{ "config-files", .config_files },
        .{ "half-installed", .half_installed },
        .{ "unpacked", .unpacked },
        .{ "half-configured", .half_configured },
        .{ "triggers-awaited", .triggers_awaited },
        .{ "triggers-pending", .triggers_pending },
        .{ "installed", .installed },
    });
    return states.get(text);
}

pub fn currentStateSpelling(state: CurrentState) []const u8 {
    return switch (state) {
        .not_installed => "not-installed",
        .config_files => "config-files",
        .half_installed => "half-installed",
        .unpacked => "unpacked",
        .half_configured => "half-configured",
        .triggers_awaited => "triggers-awaited",
        .triggers_pending => "triggers-pending",
        .installed => "installed",
    };
}

/// States whose packages own an `info/*.list` ownership index.
pub fn stateOwnsFiles(state: CurrentState) bool {
    return switch (state) {
        .not_installed => false,
        .config_files,
        .half_installed,
        .unpacked,
        .half_configured,
        .triggers_awaited,
        .triggers_pending,
        .installed,
        => true,
    };
}

fn validQualifiedPackage(text: []const u8) bool {
    if (std.mem.indexOfScalar(u8, text, ':')) |colon| {
        return validPackageName(text[0..colon]) and validArchitecture(text[colon + 1 ..]);
    }
    return validPackageName(text);
}

fn validFieldName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name[0] == '#' or name[0] == '-') return false;
    for (name) |byte| {
        if (byte <= ' ' or byte > '~' or byte == ':') return false;
    }
    return true;
}

pub fn validRelativePath(path: []const u8) bool {
    if (path.len == 0 or path[0] == '/' or path[path.len - 1] == '/') return false;
    if (!std.unicode.utf8ValidateSlice(path)) return false;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return false;
    for (path) |byte| {
        if (byte < 0x20 or byte == 0x7f) return false;
    }
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return false;
    }
    return true;
}

pub fn validAbsolutePath(path: []const u8) bool {
    return absolute_path.nonRoot(path);
}

pub fn validListPath(path: []const u8) bool {
    if (std.mem.eql(u8, path, root_list_path)) return true;
    return absolute_path.nonRoot(path);
}

const InfoSuffix = enum {
    list,
    md5sums,
    conffiles,
    triggers,
    preinst,
    postinst,
    prerm,
    postrm,
    other,
};

fn infoSuffix(text: []const u8) InfoSuffix {
    const suffixes = std.StaticStringMap(InfoSuffix).initComptime(.{
        .{ "list", .list },
        .{ "md5sums", .md5sums },
        .{ "conffiles", .conffiles },
        .{ "triggers", .triggers },
        .{ "preinst", .preinst },
        .{ "postinst", .postinst },
        .{ "prerm", .prerm },
        .{ "postrm", .postrm },
    });
    return suffixes.get(text) orelse .other;
}

fn scriptKindOf(suffix: InfoSuffix) ?ScriptKind {
    return switch (suffix) {
        .preinst => .preinst,
        .postinst => .postinst,
        .prerm => .prerm,
        .postrm => .postrm,
        else => null,
    };
}

fn validInfoSuffix(text: []const u8) bool {
    if (text.len == 0 or text.len > 32) return false;
    for (text) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9') or byte == '-';
        if (!ok) return false;
    }
    return true;
}

const Importer = struct {
    arena: std.mem.Allocator,
    scratch: std.mem.Allocator,
    options: Options,
    diagnostic: ?Diagnostic = null,

    fn fail(
        self: *Importer,
        surface: Surface,
        code: Code,
        path: []const u8,
        line: ?usize,
    ) error{Invalid} {
        self.diagnostic = .{
            .surface = surface,
            .code = code,
            .path = path,
            .line = line,
        };
        return error.Invalid;
    }

    fn failPackage(
        self: *Importer,
        surface: Surface,
        code: Code,
        path: []const u8,
        package: []const u8,
    ) error{Invalid} {
        self.diagnostic = .{
            .surface = surface,
            .code = code,
            .path = path,
            .package = package,
        };
        return error.Invalid;
    }

    fn text(
        self: *Importer,
        surface: Surface,
        path: []const u8,
        line: Line,
    ) ImportError![]const u8 {
        if (!line.terminated) return self.fail(surface, .unterminated_line, path, line.number);
        if (line.text.len > self.options.limits.max_line_bytes) {
            return self.fail(surface, .line_too_long, path, line.number);
        }
        for (line.text) |byte| {
            if (byte < 0x20 or byte == 0x7f) {
                return self.fail(surface, .control_character, path, line.number);
            }
        }
        return line.text;
    }

    fn parseStatusDocument(
        self: *Importer,
        surface: Surface,
        path: []const u8,
        bytes: []const u8,
    ) ImportError![]PackageRecord {
        const limits = self.options.limits;
        if (bytes.len > limits.max_status_bytes) {
            return self.fail(surface, .status_limit, path, null);
        }
        const outcome = try deb822.parseBorrowed(self.scratch, bytes, .{
            .limits = .{
                .max_total_bytes = limits.max_status_bytes,
                .max_paragraphs = limits.max_packages,
                .max_fields_per_paragraph = limits.max_fields_per_package,
                .max_field_bytes = limits.max_field_bytes,
            },
            .duplicate_policy = .reject,
        });
        var document = switch (outcome) {
            .failure => |failure| {
                self.diagnostic = .{
                    .surface = surface,
                    .code = switch (failure.kind) {
                        .total_bytes_limit, .paragraph_limit => .status_limit,
                        .fields_limit, .field_size_limit => .field_limit,
                        else => .status_syntax,
                    },
                    .path = path,
                    .line = failure.position.line,
                    .status_syntax = failure.kind,
                };
                return error.Invalid;
            },
            .document => |value| value,
        };
        defer document.deinit();

        const records = try self.arena.alloc(PackageRecord, document.paragraphs.len);
        for (document.paragraphs, 0..) |paragraph, index| {
            const fields = try self.arena.alloc(StatusField, paragraph.fields.len);
            for (paragraph.fields, 0..) |source, field_index| {
                const values = try self.arena.alloc([]const u8, source.value_lines.len);
                for (source.value_lines, 0..) |value, value_index| {
                    values[value_index] = value.text;
                }
                fields[field_index] = .{
                    .name = source.name,
                    .value_lines = values,
                };
            }
            switch (try interpretPackageFields(self.arena, fields, self.options, surface)) {
                .diagnostic => |diagnostic| {
                    var located = diagnostic;
                    located.path = path;
                    located.line = paragraph.span.start.line;
                    self.diagnostic = located;
                    return error.Invalid;
                },
                .record => |record| records[index] = record,
            }
        }
        return records;
    }

    fn parseArchitectures(
        self: *Importer,
        native: []const u8,
        bytes: []const u8,
    ) ImportError![]const []const u8 {
        var values: std.ArrayList([]const u8) = .empty;
        defer values.deinit(self.scratch);
        var lines = Lines.init(bytes);
        while (lines.next()) |line| {
            const value = try self.text(.architectures, arch_path, line);
            if (value.len == 0) {
                return self.fail(.architectures, .empty_line, arch_path, line.number);
            }
            if (values.items.len >= self.options.limits.max_foreign_architectures) {
                return self.fail(.architectures, .architecture_limit, arch_path, line.number);
            }
            if (value.len > self.options.limits.max_architecture_bytes or !validArchitecture(value)) {
                return self.fail(.architectures, .invalid_architecture_record, arch_path, line.number);
            }
            if (std.mem.eql(u8, value, native)) {
                return self.fail(.architectures, .native_architecture_listed, arch_path, line.number);
            }
            for (values.items) |existing| {
                if (std.mem.eql(u8, existing, value)) {
                    return self.fail(.architectures, .duplicate_architecture, arch_path, line.number);
                }
            }
            try values.append(self.scratch, value);
        }
        return try self.arena.dupe([]const u8, values.items);
    }

    fn parseList(
        self: *Importer,
        name: []const u8,
        bytes: []const u8,
    ) ImportError![]const []const u8 {
        var paths: std.ArrayList([]const u8) = .empty;
        defer paths.deinit(self.scratch);
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        defer seen.deinit(self.scratch);
        var lines = Lines.init(bytes);
        while (lines.next()) |line| {
            const value = try self.text(.info_list, name, line);
            if (value.len == 0) return self.fail(.info_list, .empty_line, name, line.number);
            if (paths.items.len >= self.options.limits.max_paths_per_package) {
                return self.fail(.info_list, .path_limit, name, line.number);
            }
            if (value.len > self.options.limits.max_path_bytes) {
                return self.fail(.info_list, .path_too_long, name, line.number);
            }
            if (!validListPath(value)) {
                return self.fail(.info_list, .invalid_path, name, line.number);
            }
            const owned = value;
            const entry = try seen.getOrPut(self.scratch, logicalListPath(owned));
            if (entry.found_existing) {
                return self.fail(.info_list, .duplicate_path, name, line.number);
            }
            try paths.append(self.scratch, owned);
        }
        return try self.arena.dupe([]const u8, paths.items);
    }

    fn parseMd5sums(
        self: *Importer,
        name: []const u8,
        bytes: []const u8,
    ) ImportError![]const Md5sumEntry {
        var entries: std.ArrayList(Md5sumEntry) = .empty;
        defer entries.deinit(self.scratch);
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        defer seen.deinit(self.scratch);
        var lines = Lines.init(bytes);
        while (lines.next()) |line| {
            const value = try self.text(.info_md5sums, name, line);
            if (value.len == 0) return self.fail(.info_md5sums, .empty_line, name, line.number);
            if (entries.items.len >= self.options.limits.max_md5sums_per_package) {
                return self.fail(.info_md5sums, .checksum_limit, name, line.number);
            }
            if (value.len < 35 or !std.mem.eql(u8, value[32..34], "  ")) {
                return self.fail(.info_md5sums, .invalid_checksum, name, line.number);
            }
            const digest = parseHexDigest(16, value[0..32]) orelse
                return self.fail(.info_md5sums, .invalid_checksum, name, line.number);
            const path = value[34..];
            if (path.len > self.options.limits.max_path_bytes) {
                return self.fail(.info_md5sums, .path_too_long, name, line.number);
            }
            if (!validRelativePath(path)) {
                return self.fail(.info_md5sums, .invalid_path, name, line.number);
            }
            const owned = path;
            const entry = try seen.getOrPut(self.scratch, owned);
            if (entry.found_existing) {
                return self.fail(.info_md5sums, .duplicate_checksum, name, line.number);
            }
            try entries.append(self.scratch, .{ .path = owned, .digest = digest });
        }
        return try self.arena.dupe(Md5sumEntry, entries.items);
    }

    fn parseDeclaredConffiles(
        self: *Importer,
        name: []const u8,
        bytes: []const u8,
    ) ImportError![]const []const u8 {
        var paths: std.ArrayList([]const u8) = .empty;
        defer paths.deinit(self.scratch);
        var lines = Lines.init(bytes);
        while (lines.next()) |line| {
            const value = try self.text(.info_conffiles, name, line);
            if (value.len == 0) return self.fail(.info_conffiles, .empty_line, name, line.number);
            if (paths.items.len >= self.options.limits.max_conffiles_per_package) {
                return self.fail(.info_conffiles, .conffile_limit, name, line.number);
            }
            if (value.len > self.options.limits.max_path_bytes) {
                return self.fail(.info_conffiles, .path_too_long, name, line.number);
            }
            if (!absolute_path.nonRoot(value)) {
                return self.fail(.info_conffiles, .invalid_path, name, line.number);
            }
            for (paths.items) |existing| {
                if (std.mem.eql(u8, existing, value)) {
                    return self.fail(.info_conffiles, .duplicate_conffile, name, line.number);
                }
            }
            try paths.append(self.scratch, value);
        }
        return try self.arena.dupe([]const u8, paths.items);
    }

    fn parseTriggerDeclarations(
        self: *Importer,
        name: []const u8,
        bytes: []const u8,
    ) ImportError![]const TriggerDeclaration {
        var declarations: std.ArrayList(TriggerDeclaration) = .empty;
        defer declarations.deinit(self.scratch);
        var lines = Lines.init(bytes);
        while (lines.next()) |line| {
            const value = try self.text(.info_triggers, name, line);
            if (value.len == 0 or value[0] == '#') continue;
            if (declarations.items.len >= self.options.limits.max_trigger_declarations_per_package) {
                return self.fail(.info_triggers, .trigger_limit, name, line.number);
            }
            var tokens = std.mem.tokenizeScalar(u8, value, ' ');
            const kind_text = tokens.next() orelse
                return self.fail(.info_triggers, .invalid_trigger_declaration, name, line.number);
            const trigger = tokens.next() orelse
                return self.fail(.info_triggers, .invalid_trigger_declaration, name, line.number);
            if (tokens.next() != null) {
                return self.fail(.info_triggers, .invalid_trigger_declaration, name, line.number);
            }
            const kind = declarationKind(kind_text) orelse
                return self.fail(.info_triggers, .invalid_trigger_declaration, name, line.number);
            if (trigger.len > self.options.limits.max_trigger_name_bytes or !validTriggerName(trigger)) {
                return self.fail(.info_triggers, .invalid_trigger_name, name, line.number);
            }
            for (declarations.items) |existing| {
                if (existing.kind == kind and std.mem.eql(u8, existing.name, trigger)) {
                    return self.fail(.info_triggers, .duplicate_trigger_declaration, name, line.number);
                }
            }
            try declarations.append(self.scratch, .{
                .kind = kind,
                .name = trigger,
            });
        }
        return try self.arena.dupe(TriggerDeclaration, declarations.items);
    }

    fn parseTriggerInterests(self: *Importer, bytes: []const u8) ImportError![]const TriggerInterest {
        var interests: std.ArrayList(TriggerInterest) = .empty;
        defer interests.deinit(self.scratch);
        var lines = Lines.init(bytes);
        while (lines.next()) |line| {
            const value = try self.text(.triggers_file, triggers_file_path, line);
            if (value.len == 0) {
                return self.fail(.triggers_file, .empty_line, triggers_file_path, line.number);
            }
            if (interests.items.len >= self.options.limits.max_trigger_interests) {
                return self.fail(.triggers_file, .trigger_limit, triggers_file_path, line.number);
            }
            var tokens = std.mem.tokenizeScalar(u8, value, ' ');
            const trigger = tokens.next() orelse
                return self.fail(.triggers_file, .invalid_trigger_record, triggers_file_path, line.number);
            const package_text = tokens.next() orelse
                return self.fail(.triggers_file, .invalid_trigger_record, triggers_file_path, line.number);
            if (tokens.next() != null) {
                return self.fail(.triggers_file, .invalid_trigger_record, triggers_file_path, line.number);
            }
            if (trigger.len > self.options.limits.max_trigger_name_bytes or
                trigger.len == 0 or trigger[0] != '/' or !absolute_path.nonRoot(trigger))
            {
                return self.fail(.triggers_file, .invalid_trigger_name, triggers_file_path, line.number);
            }
            const parsed = self.parsePendingPackage(package_text) orelse
                return self.fail(.triggers_file, .invalid_trigger_record, triggers_file_path, line.number);
            for (interests.items) |existing| {
                if (std.mem.eql(u8, existing.trigger, trigger) and
                    existing.package.eql(parsed.package))
                {
                    return self.fail(
                        .triggers_file,
                        .duplicate_trigger_interest,
                        triggers_file_path,
                        line.number,
                    );
                }
            }
            try interests.append(self.scratch, .{
                .trigger = trigger,
                .package = .{
                    .name = parsed.package.name,
                    .architecture = parsed.package.architecture,
                },
                .await_mode = parsed.await_mode,
            });
        }
        return try self.arena.dupe(TriggerInterest, interests.items);
    }

    fn parsePendingTriggers(self: *Importer, bytes: []const u8) ImportError![]const PendingTrigger {
        var pending: std.ArrayList(PendingTrigger) = .empty;
        defer pending.deinit(self.scratch);
        var lines = Lines.init(bytes);
        while (lines.next()) |line| {
            const value = try self.text(.triggers_unincorp, triggers_unincorp_path, line);
            if (value.len == 0) {
                return self.fail(.triggers_unincorp, .empty_line, triggers_unincorp_path, line.number);
            }
            if (pending.items.len >= self.options.limits.max_pending_triggers) {
                return self.fail(.triggers_unincorp, .trigger_limit, triggers_unincorp_path, line.number);
            }
            var tokens = std.mem.tokenizeScalar(u8, value, ' ');
            const trigger = tokens.next() orelse return self.fail(
                .triggers_unincorp,
                .invalid_trigger_record,
                triggers_unincorp_path,
                line.number,
            );
            if (trigger.len > self.options.limits.max_trigger_name_bytes or !validTriggerName(trigger)) {
                return self.fail(
                    .triggers_unincorp,
                    .invalid_trigger_name,
                    triggers_unincorp_path,
                    line.number,
                );
            }
            var packages: std.ArrayList(PendingPackage) = .empty;
            defer packages.deinit(self.scratch);
            while (tokens.next()) |package_text| {
                if (packages.items.len >= self.options.limits.max_packages_per_pending_trigger) {
                    return self.fail(
                        .triggers_unincorp,
                        .trigger_limit,
                        triggers_unincorp_path,
                        line.number,
                    );
                }
                const parsed = self.parsePendingPackage(package_text) orelse return self.fail(
                    .triggers_unincorp,
                    .invalid_trigger_record,
                    triggers_unincorp_path,
                    line.number,
                );
                for (packages.items) |existing| {
                    if (existing.package.eql(parsed.package)) {
                        return self.fail(
                            .triggers_unincorp,
                            .invalid_trigger_record,
                            triggers_unincorp_path,
                            line.number,
                        );
                    }
                }
                try packages.append(self.scratch, .{
                    .package = .{
                        .name = parsed.package.name,
                        .architecture = parsed.package.architecture,
                    },
                    .await_mode = parsed.await_mode,
                });
            }
            if (packages.items.len == 0) {
                return self.fail(
                    .triggers_unincorp,
                    .invalid_trigger_record,
                    triggers_unincorp_path,
                    line.number,
                );
            }
            for (pending.items) |existing| {
                if (std.mem.eql(u8, existing.trigger, trigger)) {
                    return self.fail(
                        .triggers_unincorp,
                        .invalid_trigger_record,
                        triggers_unincorp_path,
                        line.number,
                    );
                }
            }
            try pending.append(self.scratch, .{
                .trigger = trigger,
                .packages = try self.arena.dupe(PendingPackage, packages.items),
            });
        }
        return try self.arena.dupe(PendingTrigger, pending.items);
    }

    /// dpkg spells a noawait package reference with a leading `/`.
    fn parsePendingPackage(self: *Importer, token: []const u8) ?PendingPackage {
        var text_value = token;
        var await_mode: AwaitMode = .awaited;
        if (text_value.len != 0 and text_value[0] == '/') {
            await_mode = .noawait;
            text_value = text_value[1..];
        }
        if (text_value.len > self.options.limits.max_package_name_bytes) return null;
        if (std.mem.indexOfScalar(u8, text_value, ':')) |colon| {
            const name = text_value[0..colon];
            const architecture = text_value[colon + 1 ..];
            if (!validPackageName(name) or !validArchitecture(architecture)) return null;
            return .{
                .package = .{ .name = name, .architecture = architecture },
                .await_mode = await_mode,
            };
        }
        if (!validPackageName(text_value)) return null;
        return .{
            .package = .{ .name = text_value, .architecture = "" },
            .await_mode = await_mode,
        };
    }

    fn parseDiversions(self: *Importer, bytes: []const u8) ImportError![]const DiversionRecord {
        var records: std.ArrayList(DiversionRecord) = .empty;
        defer records.deinit(self.scratch);
        var lines = Lines.init(bytes);
        while (lines.next()) |line| {
            const from = try self.text(.diversions, diversions_path, line);
            const to_line = lines.next() orelse
                return self.fail(.diversions, .invalid_diversion, diversions_path, line.number);
            const to = try self.text(.diversions, diversions_path, to_line);
            const package_line = lines.next() orelse
                return self.fail(.diversions, .invalid_diversion, diversions_path, to_line.number);
            const package = try self.text(.diversions, diversions_path, package_line);
            if (records.items.len >= self.options.limits.max_diversions) {
                return self.fail(.diversions, .diversion_limit, diversions_path, line.number);
            }
            if (!absolute_path.nonRoot(from) or !absolute_path.nonRoot(to) or
                std.mem.eql(u8, from, to) or
                from.len > self.options.limits.max_path_bytes or
                to.len > self.options.limits.max_path_bytes)
            {
                return self.fail(.diversions, .invalid_diversion, diversions_path, line.number);
            }
            const owner: ?[]const u8 = if (std.mem.eql(u8, package, ":"))
                null
            else if (validQualifiedPackage(package))
                package
            else
                return self.fail(.diversions, .invalid_diversion, diversions_path, package_line.number);
            try records.append(self.scratch, .{
                .from = from,
                .to = to,
                .package = owner,
            });
        }
        return try self.arena.dupe(DiversionRecord, records.items);
    }

    fn parseStatOverrides(self: *Importer, bytes: []const u8) ImportError![]const StatOverrideRecord {
        var records: std.ArrayList(StatOverrideRecord) = .empty;
        defer records.deinit(self.scratch);
        var lines = Lines.init(bytes);
        while (lines.next()) |line| {
            const value = try self.text(.statoverride, statoverride_path, line);
            if (records.items.len >= self.options.limits.max_stat_overrides) {
                return self.fail(.statoverride, .statoverride_limit, statoverride_path, line.number);
            }
            var tokens = std.mem.splitScalar(u8, value, ' ');
            const user = tokens.next() orelse
                return self.fail(.statoverride, .invalid_statoverride, statoverride_path, line.number);
            const group = tokens.next() orelse
                return self.fail(.statoverride, .invalid_statoverride, statoverride_path, line.number);
            const mode_text = tokens.next() orelse
                return self.fail(.statoverride, .invalid_statoverride, statoverride_path, line.number);
            const path = tokens.rest();
            if (user.len == 0 or group.len == 0 or path.len == 0 or
                user.len > 255 or group.len > 255 or
                path.len > self.options.limits.max_path_bytes or
                !absolute_path.nonRoot(path))
            {
                return self.fail(.statoverride, .invalid_statoverride, statoverride_path, line.number);
            }
            if (mode_text.len < 3 or mode_text.len > 4) {
                return self.fail(.statoverride, .invalid_statoverride, statoverride_path, line.number);
            }
            const mode = std.fmt.parseUnsigned(u32, mode_text, 8) catch
                return self.fail(.statoverride, .invalid_statoverride, statoverride_path, line.number);
            for (records.items) |existing| {
                if (std.mem.eql(u8, existing.path, path)) {
                    return self.fail(
                        .statoverride,
                        .invalid_statoverride,
                        statoverride_path,
                        line.number,
                    );
                }
            }
            try records.append(self.scratch, .{
                .user = user,
                .group = group,
                .mode = mode,
                .path = path,
            });
        }
        return try self.arena.dupe(StatOverrideRecord, records.items);
    }

    fn parseUpdates(self: *Importer, updates: []const UpdateEntry) ImportError![]const PendingUpdate {
        if (updates.len > self.options.limits.max_update_fragments) {
            return self.fail(.updates, .update_limit, updates_directory, null);
        }
        const fragments = try self.arena.alloc(PendingUpdate, updates.len);
        for (updates, 0..) |entry, index| {
            if (entry.kind != .regular) {
                return self.fail(.updates, .unsupported_entry_kind, entry.name, null);
            }
            if (entry.name.len == 0 or entry.name.len > 8) {
                return self.fail(.updates, .invalid_update_name, entry.name, null);
            }
            for (entry.name) |byte| {
                if (!std.ascii.isDigit(byte)) {
                    return self.fail(.updates, .invalid_update_name, entry.name, null);
                }
            }
            const sequence = std.fmt.parseUnsigned(u64, entry.name, 10) catch
                return self.fail(.updates, .invalid_update_name, entry.name, null);
            for (fragments[0..index]) |existing| {
                if (existing.sequence == sequence) {
                    return self.fail(.updates, .invalid_update_name, entry.name, null);
                }
            }
            const parsed = self.parseStatusDocument(.updates, entry.name, entry.bytes) catch |err| switch (err) {
                error.OutOfMemory => return err,
                error.Invalid => {
                    var diagnostic = self.diagnostic.?;
                    diagnostic.surface = .updates;
                    diagnostic.code = .invalid_update_fragment;
                    self.diagnostic = diagnostic;
                    return error.Invalid;
                },
            };
            fragments[index] = .{
                .name = entry.name,
                .sequence = sequence,
                .package_count = parsed.len,
                .sha256 = digestOf(entry.bytes),
            };
        }
        std.mem.sort(PendingUpdate, fragments, {}, lessPendingUpdate);
        return fragments;
    }

    fn resolveStem(
        self: *Importer,
        stem: []const u8,
        index: RecordIndex,
        entry_name: []const u8,
    ) ImportError!usize {
        if (std.mem.indexOfScalar(u8, stem, ':') != null) {
            return index.by_identity.get(stem) orelse
                self.fail(.info_directory, .orphan_info_file, entry_name, null);
        }
        const entry = index.by_name.get(stem) orelse
            return self.fail(.info_directory, .orphan_info_file, entry_name, null);
        if (entry.count != 1) {
            return self.fail(.info_directory, .ambiguous_info_file, entry_name, null);
        }
        return entry.index;
    }

    fn run(self: *Importer, request: ImportRequest) ImportError!Model {
        const limits = self.options.limits;
        const native = request.native_architecture;
        if (native.len == 0 or native.len > limits.max_architecture_bytes or
            std.mem.eql(u8, native, "all") or !validArchitecture(native))
        {
            return self.fail(.cross_file, .invalid_architecture, database_directory, null);
        }
        const snapshot = request.snapshot;
        const records = try self.parseStatusDocument(.status, status_path, snapshot.status);
        const foreign: []const []const u8 = if (snapshot.arch) |bytes|
            try self.parseArchitectures(native, bytes)
        else
            &.{};

        var index: RecordIndex = .{};
        defer index.deinit(self.scratch);
        for (records, 0..) |record, position| {
            const key = try std.fmt.allocPrint(
                self.scratch,
                "{s}:{s}",
                .{ record.name, record.architecture },
            );
            const identity_entry = index.by_identity.getOrPut(self.scratch, key) catch |err| {
                self.scratch.free(key);
                return err;
            };
            if (identity_entry.found_existing) {
                self.scratch.free(key);
                return self.failPackage(.status, .repeated_identity, status_path, record.name);
            }
            identity_entry.value_ptr.* = position;
            const name_entry = try index.by_name.getOrPut(self.scratch, record.name);
            if (name_entry.found_existing) {
                name_entry.value_ptr.count += 1;
            } else {
                name_entry.value_ptr.* = .{ .index = position, .count = 1 };
            }
        }

        const scripts = try self.scratch.alloc(std.ArrayList(MaintainerScript), records.len);
        defer {
            for (scripts) |*list| list.deinit(self.scratch);
            self.scratch.free(scripts);
        }
        for (scripts) |*list| list.* = .empty;

        const stems = try self.scratch.alloc(?[]const u8, records.len);
        defer self.scratch.free(stems);
        @memset(stems, null);

        var opaque_files: std.ArrayList(OpaqueInfoFile) = .empty;
        defer opaque_files.deinit(self.scratch);
        var seen_info: std.StringHashMapUnmanaged(void) = .empty;
        defer seen_info.deinit(self.scratch);
        var info_format_present = false;

        if (snapshot.info.len > limits.max_info_entries) {
            return self.fail(.info_directory, .info_limit, info_directory, null);
        }
        for (snapshot.info) |entry| {
            if (entry.kind != .regular) {
                return self.fail(.info_directory, .unsupported_entry_kind, entry.name, null);
            }
            if (!safeMode(entry.mode)) {
                return self.fail(.info_directory, .unsafe_mode, entry.name, null);
            }
            if (entry.bytes.len > limits.max_info_file_bytes) {
                return self.fail(.info_directory, .file_too_large, entry.name, null);
            }
            const seen = try seen_info.getOrPut(self.scratch, entry.name);
            if (seen.found_existing) {
                return self.fail(.info_directory, .duplicate_info_name, entry.name, null);
            }
            if (std.mem.eql(u8, entry.name, info_format_name)) {
                const trimmed = std.mem.trimEnd(u8, entry.bytes, "\n");
                if (!std.mem.eql(u8, trimmed, supported_info_format)) {
                    return self.fail(.info_format, .unsupported_info_format, entry.name, null);
                }
                info_format_present = true;
                continue;
            }
            const dot = std.mem.lastIndexOfScalar(u8, entry.name, '.') orelse
                return self.fail(.info_directory, .malformed_info_name, entry.name, null);
            const stem = entry.name[0..dot];
            const suffix_text = entry.name[dot + 1 ..];
            if (!validInfoSuffix(suffix_text) or
                stem.len == 0 or
                stem.len > limits.max_package_name_bytes + limits.max_architecture_bytes + 1 or
                !validQualifiedPackage(stem))
            {
                return self.fail(.info_directory, .malformed_info_name, entry.name, null);
            }
            const position = try self.resolveStem(stem, index, entry.name);
            if (stems[position]) |existing| {
                if (!std.mem.eql(u8, existing, stem)) {
                    return self.fail(.info_directory, .ambiguous_info_file, entry.name, null);
                }
            } else {
                stems[position] = stem;
            }

            switch (infoSuffix(suffix_text)) {
                .list => records[position].paths = try self.parseList(entry.name, entry.bytes),
                .md5sums => records[position].md5sums = try self.parseMd5sums(entry.name, entry.bytes),
                .conffiles => records[position].declared_conffiles =
                    try self.parseDeclaredConffiles(entry.name, entry.bytes),
                .triggers => records[position].trigger_declarations =
                    try self.parseTriggerDeclarations(entry.name, entry.bytes),
                .preinst, .postinst, .prerm, .postrm => |suffix| {
                    if (entry.bytes.len > limits.max_maintainer_script_bytes) {
                        return self.fail(.info_script, .file_too_large, entry.name, null);
                    }
                    if (!executableMode(entry.mode)) {
                        return self.fail(.info_script, .unsafe_mode, entry.name, null);
                    }
                    try scripts[position].append(self.scratch, .{
                        .kind = scriptKindOf(suffix).?,
                        .mode = entry.mode,
                        .size = entry.bytes.len,
                        .sha256 = digestOf(entry.bytes),
                    });
                },
                .other => try opaque_files.append(self.scratch, .{
                    .name = entry.name,
                    .owner = records[position].identity(),
                    .mode = entry.mode,
                    .size = entry.bytes.len,
                    .sha256 = digestOf(entry.bytes),
                }),
            }
        }

        for (records, 0..) |*record, position| {
            if (stems[position]) |stem| record.info_stem = stem;
            record.scripts = try self.arena.dupe(MaintainerScript, scripts[position].items);
        }

        const interests: []const TriggerInterest = if (snapshot.triggers_file) |bytes|
            try self.parseTriggerInterests(bytes)
        else
            &.{};
        const pending: []const PendingTrigger = if (snapshot.triggers_unincorp) |bytes|
            try self.parsePendingTriggers(bytes)
        else
            &.{};
        const diversions: []const DiversionRecord = if (snapshot.diversions) |bytes|
            try self.parseDiversions(bytes)
        else
            &.{};
        const stat_overrides: []const StatOverrideRecord = if (snapshot.statoverride) |bytes|
            try self.parseStatOverrides(bytes)
        else
            &.{};

        var pending_updates: []const PendingUpdate = &.{};
        if (snapshot.updates.len != 0) {
            if (self.options.updates_policy == .require_empty) {
                return self.fail(.updates, .update_fragments_present, updates_directory, null);
            }
            pending_updates = try self.parseUpdates(snapshot.updates);
        }

        var status_old: ?StatusGeneration = null;
        if (snapshot.status_old) |bytes| {
            const previous = try self.parseStatusDocument(.status_old, status_old_path, bytes);
            status_old = .{
                .sha256 = digestOf(bytes),
                .size = bytes.len,
                .package_count = previous.len,
            };
        }

        return .{
            .native_architecture = native,
            .status = .{
                .sha256 = digestOf(snapshot.status),
                .size = snapshot.status.len,
                .package_count = records.len,
            },
            .foreign_architectures = foreign,
            .packages = records,
            .triggers = .{ .interests = interests, .pending = pending },
            .diversions = diversions,
            .stat_overrides = stat_overrides,
            .opaque_info = try self.arena.dupe(OpaqueInfoFile, opaque_files.items),
            .pending_updates = pending_updates,
            .status_old = status_old,
            .info_format_present = info_format_present,
        };
    }
};

fn lessPendingUpdate(_: void, left: PendingUpdate, right: PendingUpdate) bool {
    return left.sequence < right.sequence;
}

fn declarationKind(text: []const u8) ?TriggerDeclarationKind {
    const kinds = std.StaticStringMap(TriggerDeclarationKind).initComptime(.{
        .{ "interest", .interest },
        .{ "interest-await", .interest_await },
        .{ "interest-noawait", .interest_noawait },
        .{ "activate", .activate },
        .{ "activate-await", .activate_await },
        .{ "activate-noawait", .activate_noawait },
    });
    return kinds.get(text);
}

const NameEntry = struct {
    index: usize,
    count: usize,
};

const RecordIndex = struct {
    by_name: std.StringHashMapUnmanaged(NameEntry) = .empty,
    by_identity: std.StringHashMapUnmanaged(usize) = .empty,

    fn deinit(self: *RecordIndex, allocator: std.mem.Allocator) void {
        var identities = self.by_identity.keyIterator();
        while (identities.next()) |key| allocator.free(key.*);
        self.by_name.deinit(allocator);
        self.by_identity.deinit(allocator);
    }
};

/// Import one captured database generation. The returned database and any
/// returned diagnostic borrow `request.snapshot`, which must outlive them.
pub fn importSnapshot(
    allocator: std.mem.Allocator,
    request: ImportRequest,
    options: Options,
) std.mem.Allocator.Error!Result {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = .init(allocator);
    var importer: Importer = .{
        .arena = arena.allocator(),
        .scratch = allocator,
        .options = options,
    };
    const model = importer.run(request) catch |err| {
        const diagnostic: Diagnostic = switch (err) {
            error.OutOfMemory => .{
                .surface = .status,
                .code = .out_of_memory,
                .path = status_path,
            },
            error.Invalid => importer.diagnostic.?,
        };
        arena.deinit();
        allocator.destroy(arena);
        return .{ .diagnostic = diagnostic };
    };
    const validation = validateModel(allocator, model, options) catch |err| switch (err) {
        error.OutOfMemory => blk: {
            break :blk Diagnostic{
                .surface = .cross_file,
                .code = .out_of_memory,
                .path = database_directory,
            };
        },
    };
    if (validation) |diagnostic| {
        arena.deinit();
        allocator.destroy(arena);
        return .{ .diagnostic = diagnostic };
    }
    const captured = generation(allocator, request.snapshot) catch |err| {
        arena.deinit();
        allocator.destroy(arena);
        return switch (err) {
            error.OutOfMemory => .{ .diagnostic = .{
                .surface = .generation,
                .code = .out_of_memory,
                .path = database_directory,
            } },
        };
    };
    return .{ .database = .{
        .model = model,
        .generation = captured,
        .arena = arena,
        .backing_allocator = allocator,
    } };
}

/// Confirm that a freshly captured snapshot is still the generation that was
/// imported. Authorization must not survive an external database change.
pub fn verifyGeneration(
    allocator: std.mem.Allocator,
    database: Database,
    snapshot: Snapshot,
) std.mem.Allocator.Error!?Diagnostic {
    const captured = try generation(allocator, snapshot);
    if (captured.eql(database.generation)) return null;
    return .{
        .surface = .generation,
        .code = .external_generation_change,
        .path = database_directory,
    };
}

const GenerationEntry = struct {
    path: []const u8,
    kind: EntryKind,
    mode: u32,
    size: usize,
    sha256: [32]u8,
};

fn lessGenerationEntry(_: void, left: GenerationEntry, right: GenerationEntry) bool {
    return std.mem.order(u8, left.path, right.path) == .lt;
}

/// Deterministic digest of one complete consumed database generation.
pub fn generation(
    allocator: std.mem.Allocator,
    snapshot: Snapshot,
) std.mem.Allocator.Error!Generation {
    var entries: std.ArrayList(GenerationEntry) = .empty;
    defer {
        for (entries.items) |entry| allocator.free(entry.path);
        entries.deinit(allocator);
    }

    const singles = [_]struct { path: []const u8, bytes: ?[]const u8 }{
        .{ .path = status_path, .bytes = snapshot.status },
        .{ .path = status_old_path, .bytes = snapshot.status_old },
        .{ .path = arch_path, .bytes = snapshot.arch },
        .{ .path = diversions_path, .bytes = snapshot.diversions },
        .{ .path = statoverride_path, .bytes = snapshot.statoverride },
        .{ .path = triggers_file_path, .bytes = snapshot.triggers_file },
        .{ .path = triggers_unincorp_path, .bytes = snapshot.triggers_unincorp },
    };
    for (singles) |single| {
        const bytes = single.bytes orelse continue;
        try entries.append(allocator, .{
            .path = try allocator.dupe(u8, single.path),
            .kind = .regular,
            .mode = 0o644,
            .size = bytes.len,
            .sha256 = digestOf(bytes),
        });
    }
    for (snapshot.info) |entry| {
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ info_directory, entry.name });
        errdefer allocator.free(path);
        try entries.append(allocator, .{
            .path = path,
            .kind = entry.kind,
            .mode = entry.mode,
            .size = entry.bytes.len,
            .sha256 = digestOf(entry.bytes),
        });
    }
    for (snapshot.updates) |entry| {
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ updates_directory, entry.name });
        errdefer allocator.free(path);
        try entries.append(allocator, .{
            .path = path,
            .kind = entry.kind,
            .mode = 0o644,
            .size = entry.bytes.len,
            .sha256 = digestOf(entry.bytes),
        });
    }
    std.mem.sort(GenerationEntry, entries.items, {}, lessGenerationEntry);

    var buffer: [512]u8 = undefined;
    var sink: std.Io.Writer.Hashing(Sha256) = .init(&buffer);
    const writer = &sink.writer;
    writer.writeAll("debz.package-database.generation.v1\n") catch unreachable;
    var total: u64 = 0;
    for (entries.items) |entry| {
        writer.print("{s}\x00{s}\x00{o}\x00{d}\x00", .{
            entry.path,
            @tagName(entry.kind),
            entry.mode,
            entry.size,
        }) catch unreachable;
        writeHex(writer, &entry.sha256) catch unreachable;
        writer.writeByte('\n') catch unreachable;
        total += entry.size;
    }
    writer.flush() catch unreachable;
    return .{
        .sha256 = sink.hasher.finalResult(),
        .file_count = entries.items.len,
        .total_bytes = total,
    };
}

const Validator = struct {
    allocator: std.mem.Allocator,
    model: Model,
    options: Options,
    index: RecordIndex = .{},

    fn deinit(self: *Validator) void {
        self.index.deinit(self.allocator);
    }

    fn fail(self: *Validator, surface: Surface, code: Code, package: []const u8) Diagnostic {
        _ = self;
        return .{
            .surface = surface,
            .code = code,
            .path = surface.path(),
            .package = package,
        };
    }

    fn lookup(self: Validator, name: []const u8, architecture: []const u8) ?usize {
        if (architecture.len == 0) {
            const entry = self.index.by_name.get(name) orelse return null;
            if (entry.count != 1) return null;
            return entry.index;
        }
        var buffer: [512]u8 = undefined;
        const key = std.fmt.bufPrint(&buffer, "{s}:{s}", .{ name, architecture }) catch return null;
        return self.index.by_identity.get(key);
    }

    fn lookupToken(self: Validator, token: []const u8) ?usize {
        if (std.mem.indexOfScalar(u8, token, ':')) |colon| {
            return self.lookup(token[0..colon], token[colon + 1 ..]);
        }
        return self.lookup(token, "");
    }

    fn run(self: *Validator) std.mem.Allocator.Error!?Diagnostic {
        const limits = self.options.limits;
        if (self.model.packages.len > limits.max_packages) {
            return self.fail(.status, .status_limit, "");
        }
        for (self.model.packages, 0..) |record, position| {
            const key = try std.fmt.allocPrint(
                self.allocator,
                "{s}:{s}",
                .{ record.name, record.architecture },
            );
            const entry = self.index.by_identity.getOrPut(self.allocator, key) catch |err| {
                self.allocator.free(key);
                return err;
            };
            if (entry.found_existing) {
                self.allocator.free(key);
                return self.fail(.status, .repeated_identity, record.name);
            }
            entry.value_ptr.* = position;
            const name_entry = try self.index.by_name.getOrPut(self.allocator, record.name);
            if (name_entry.found_existing) {
                name_entry.value_ptr.count += 1;
            } else {
                name_entry.value_ptr.* = .{ .index = position, .count = 1 };
            }
        }

        var total_paths: usize = 0;
        for (self.model.packages) |record| {
            if (validateRecordShape(record, self.options)) |diagnostic| return diagnostic;
            if (!self.model.knowsArchitecture(record.architecture)) {
                return self.fail(.cross_file, .unknown_architecture, record.name);
            }
            if (record.paths) |paths| {
                total_paths += paths.len;
                if (total_paths > limits.max_total_owned_paths) {
                    return self.fail(.cross_file, .path_limit, record.name);
                }
            }
            for (record.triggers_awaited) |token| {
                if (self.lookupToken(token) == null) {
                    return self.fail(.status, .unknown_trigger_package, record.name);
                }
            }
            const siblings = self.index.by_name.get(record.name).?;
            if (siblings.count != 1) {
                const first = self.model.packages[siblings.index];
                if (record.multi_arch != .same or first.multi_arch != .same or
                    !std.mem.eql(u8, record.version, first.version))
                {
                    return self.fail(.cross_file, .multiarch_conflict, record.name);
                }
            }
        }

        if (self.model.triggers.interests.len > limits.max_trigger_interests) {
            return self.fail(.triggers_file, .trigger_limit, "");
        }
        for (self.model.triggers.interests) |interest| {
            const position = self.lookup(interest.package.name, interest.package.architecture) orelse
                return self.fail(.triggers_file, .unknown_trigger_package, interest.package.name);
            const record = self.model.packages[position];
            const declarations = record.trigger_declarations orelse
                return self.fail(.triggers_file, .trigger_interest_mismatch, record.name);
            var declared = false;
            for (declarations) |declaration| {
                if (!declaration.kind.isInterest()) continue;
                if (!std.mem.eql(u8, declaration.name, interest.trigger)) continue;
                if (declaration.kind.awaitMode() != interest.await_mode) continue;
                declared = true;
                break;
            }
            if (!declared) {
                return self.fail(.triggers_file, .trigger_interest_mismatch, record.name);
            }
        }
        for (self.model.triggers.pending) |entry| {
            for (entry.packages) |package| {
                if (self.lookup(package.package.name, package.package.architecture) == null) {
                    return self.fail(.triggers_unincorp, .unknown_trigger_package, package.package.name);
                }
            }
        }
        return null;
    }
};

fn validateRecordShape(record: PackageRecord, options: Options) ?Diagnostic {
    const limits = options.limits;
    if (record.conffiles.len > limits.max_conffiles_per_package) {
        return .{
            .surface = .status,
            .code = .conffile_limit,
            .path = status_path,
            .package = record.name,
        };
    }
    switch (record.status.current) {
        .not_installed => {
            if (record.paths != null) {
                return .{
                    .surface = .cross_file,
                    .code = .unexpected_file_list,
                    .path = info_directory,
                    .package = record.name,
                };
            }
            if (record.md5sums != null) {
                return .{
                    .surface = .cross_file,
                    .code = .unexpected_file_list,
                    .path = info_directory,
                    .package = record.name,
                };
            }
        },
        // dpkg retains an ownership list for the conffiles and directories
        // that survive removal, so `config-files` may or may not have one.
        .config_files => {},
        else => {
            if (record.paths == null) {
                return .{
                    .surface = .cross_file,
                    .code = .missing_file_list,
                    .path = info_directory,
                    .package = record.name,
                };
            }
        },
    }
    if (record.paths) |paths| {
        for (record.conffiles) |conffile| {
            if (conffile.obsolete or conffile.remove_on_upgrade) continue;
            if (record.status.current == .not_installed) continue;
            if (!containsPath(paths, conffile.path)) {
                return .{
                    .surface = .cross_file,
                    .code = .conffile_not_owned,
                    .path = info_directory,
                    .package = record.name,
                };
            }
        }
        if (record.md5sums) |entries| {
            for (entries) |entry| {
                if (!containsRelativePath(paths, entry.path)) {
                    return .{
                        .surface = .cross_file,
                        .code = .checksum_out_of_inventory,
                        .path = info_directory,
                        .package = record.name,
                    };
                }
            }
        }
    }
    if (record.declared_conffiles) |declared| {
        for (declared) |path| {
            if (record.conffile(path) == null) {
                return .{
                    .surface = .cross_file,
                    .code = .declared_conffile_mismatch,
                    .path = info_directory,
                    .package = record.name,
                };
            }
        }
    }
    if (record.status.current == .triggers_awaited and record.triggers_awaited.len == 0) {
        return .{
            .surface = .status,
            .code = .missing_trigger_state,
            .path = status_path,
            .package = record.name,
        };
    }
    if (record.status.current == .triggers_pending and record.triggers_pending.len == 0) {
        return .{
            .surface = .status,
            .code = .missing_trigger_state,
            .path = status_path,
            .package = record.name,
        };
    }
    if (record.triggers_awaited.len != 0 and record.status.current != .triggers_awaited) {
        return .{
            .surface = .status,
            .code = .unexpected_trigger_state,
            .path = status_path,
            .package = record.name,
        };
    }
    if (record.triggers_pending.len != 0 and
        record.status.current != .triggers_pending and
        record.status.current != .triggers_awaited)
    {
        return .{
            .surface = .status,
            .code = .unexpected_trigger_state,
            .path = status_path,
            .package = record.name,
        };
    }
    return null;
}

fn containsPath(paths: []const []const u8, path: []const u8) bool {
    for (paths) |owned| {
        if (std.mem.eql(u8, logicalListPath(owned), logicalListPath(path))) return true;
    }
    return false;
}

fn containsRelativePath(paths: []const []const u8, relative: []const u8) bool {
    for (paths) |owned| {
        if (owned.len == relative.len + 1 and owned[0] == '/' and
            std.mem.eql(u8, owned[1..], relative)) return true;
    }
    return false;
}

/// Cross-file semantic validation shared by import and change staging.
pub fn validateModel(
    allocator: std.mem.Allocator,
    model: Model,
    options: Options,
) std.mem.Allocator.Error!?Diagnostic {
    var validator: Validator = .{
        .allocator = allocator,
        .model = model,
        .options = options,
    };
    defer validator.deinit();
    return validator.run();
}

/// Canonical Debian-compatible serialization of one status paragraph. Fields
/// keep their imported order and spelling, so unknown fields survive
/// republication unchanged.
pub fn writeStatusParagraph(writer: *std.Io.Writer, record: PackageRecord) std.Io.Writer.Error!void {
    for (record.fields) |field| {
        if (field.value_lines.len == 0 or field.value_lines[0].len == 0) {
            try writer.print("{s}:\n", .{field.name});
        } else {
            try writer.print("{s}: {s}\n", .{ field.name, field.value_lines[0] });
        }
        for (field.value_lines[@min(1, field.value_lines.len)..]) |line| {
            try writer.print(" {s}\n", .{line});
        }
    }
}

/// dpkg terminates every record, including the last, with a blank line.
pub fn writeStatusDocument(
    allocator: std.mem.Allocator,
    packages: []const PackageRecord,
) std.mem.Allocator.Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (packages) |record| {
        writeStatusParagraph(&output.writer, record) catch return error.OutOfMemory;
        output.writer.writeByte('\n') catch return error.OutOfMemory;
    }
    return output.toOwnedSlice() catch error.OutOfMemory;
}

/// Render the `Conffiles` field value lines for a typed conffile set. dpkg
/// writes an empty first line and one indented record per conffile.
pub fn conffilesField(
    allocator: std.mem.Allocator,
    entries: []const ConffileEntry,
) std.mem.Allocator.Error!StatusField {
    const lines = try allocator.alloc([]const u8, entries.len + 1);
    errdefer allocator.free(lines);
    lines[0] = "";
    for (entries, 0..) |entry, index| {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        const writer = &output.writer;
        writer.print("{s} ", .{entry.path}) catch return error.OutOfMemory;
        switch (entry.digest) {
            .new_conffile => writer.writeAll("newconffile") catch return error.OutOfMemory,
            .md5 => |digest| writeHex(writer, &digest) catch return error.OutOfMemory,
        }
        if (entry.obsolete) writer.writeAll(" obsolete") catch return error.OutOfMemory;
        if (entry.remove_on_upgrade) {
            writer.writeAll(" remove-on-upgrade") catch return error.OutOfMemory;
        }
        lines[index + 1] = output.toOwnedSlice() catch return error.OutOfMemory;
    }
    return .{ .name = "Conffiles", .value_lines = lines };
}

pub fn writeFileList(
    allocator: std.mem.Allocator,
    paths: []const []const u8,
) std.mem.Allocator.Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (paths) |path| {
        output.writer.print("{s}\n", .{path}) catch return error.OutOfMemory;
    }
    return output.toOwnedSlice() catch error.OutOfMemory;
}

pub fn writeMd5sums(
    allocator: std.mem.Allocator,
    entries: []const Md5sumEntry,
) std.mem.Allocator.Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (entries) |entry| {
        writeHex(&output.writer, &entry.digest) catch return error.OutOfMemory;
        output.writer.print("  {s}\n", .{entry.path}) catch return error.OutOfMemory;
    }
    return output.toOwnedSlice() catch error.OutOfMemory;
}

pub fn writeDeclaredConffiles(
    allocator: std.mem.Allocator,
    paths: []const []const u8,
) std.mem.Allocator.Error![]u8 {
    return writeFileList(allocator, paths);
}

pub fn writeTriggerDeclarations(
    allocator: std.mem.Allocator,
    declarations: []const TriggerDeclaration,
) std.mem.Allocator.Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (declarations) |declaration| {
        output.writer.print("{s} {s}\n", .{
            declaration.kind.spelling(),
            declaration.name,
        }) catch return error.OutOfMemory;
    }
    return output.toOwnedSlice() catch error.OutOfMemory;
}

fn writeTriggerPackage(
    writer: *std.Io.Writer,
    package: Identity,
    await_mode: AwaitMode,
) std.Io.Writer.Error!void {
    if (await_mode == .noawait) try writer.writeByte('/');
    if (package.architecture.len == 0) {
        try writer.writeAll(package.name);
    } else {
        try writer.print("{s}:{s}", .{ package.name, package.architecture });
    }
}

pub fn writeTriggerInterests(
    allocator: std.mem.Allocator,
    interests: []const TriggerInterest,
) std.mem.Allocator.Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (interests) |interest| {
        output.writer.print("{s} ", .{interest.trigger}) catch return error.OutOfMemory;
        writeTriggerPackage(&output.writer, interest.package, interest.await_mode) catch
            return error.OutOfMemory;
        output.writer.writeByte('\n') catch return error.OutOfMemory;
    }
    return output.toOwnedSlice() catch error.OutOfMemory;
}

pub fn writePendingTriggers(
    allocator: std.mem.Allocator,
    pending: []const PendingTrigger,
) std.mem.Allocator.Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (pending) |entry| {
        output.writer.writeAll(entry.trigger) catch return error.OutOfMemory;
        for (entry.packages) |package| {
            output.writer.writeByte(' ') catch return error.OutOfMemory;
            writeTriggerPackage(&output.writer, package.package, package.await_mode) catch
                return error.OutOfMemory;
        }
        output.writer.writeByte('\n') catch return error.OutOfMemory;
    }
    return output.toOwnedSlice() catch error.OutOfMemory;
}

pub fn writeArchitectures(
    allocator: std.mem.Allocator,
    architectures: []const []const u8,
) std.mem.Allocator.Error![]u8 {
    return writeFileList(allocator, architectures);
}

pub fn writeDiversions(
    allocator: std.mem.Allocator,
    records: []const DiversionRecord,
) std.mem.Allocator.Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (records) |record| {
        output.writer.print("{s}\n{s}\n{s}\n", .{
            record.from,
            record.to,
            record.package orelse ":",
        }) catch return error.OutOfMemory;
    }
    return output.toOwnedSlice() catch error.OutOfMemory;
}

pub fn writeStatOverrides(
    allocator: std.mem.Allocator,
    records: []const StatOverrideRecord,
) std.mem.Allocator.Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (records) |record| {
        output.writer.print("{s} {s} {o} {s}\n", .{
            record.user,
            record.group,
            record.mode,
            record.path,
        }) catch return error.OutOfMemory;
    }
    return output.toOwnedSlice() catch error.OutOfMemory;
}

const testing = std.testing;

pub const test_fixtures = struct {
    pub const status: []const u8 = @embedFile("fixtures/package-database/healthy/status");
    pub const arch: []const u8 = @embedFile("fixtures/package-database/healthy/arch");
    pub const format: []const u8 = @embedFile("fixtures/package-database/healthy/format");
    pub const triggers_file: []const u8 = @embedFile("fixtures/package-database/healthy/triggers-File");
    pub const triggers_unincorp: []const u8 =
        @embedFile("fixtures/package-database/healthy/triggers-Unincorp");
    pub const libfoo_amd64_list: []const u8 =
        @embedFile("fixtures/package-database/healthy/libfoo:amd64.list");
    pub const libfoo_amd64_md5sums: []const u8 =
        @embedFile("fixtures/package-database/healthy/libfoo:amd64.md5sums");
    pub const libfoo_amd64_conffiles: []const u8 =
        @embedFile("fixtures/package-database/healthy/libfoo:amd64.conffiles");
    pub const libfoo_i386_list: []const u8 =
        @embedFile("fixtures/package-database/healthy/libfoo:i386.list");
    pub const libfoo_i386_md5sums: []const u8 =
        @embedFile("fixtures/package-database/healthy/libfoo:i386.md5sums");
    pub const toolz_list: []const u8 = @embedFile("fixtures/package-database/healthy/toolz.list");
    pub const toolz_md5sums: []const u8 = @embedFile("fixtures/package-database/healthy/toolz.md5sums");
    pub const toolz_triggers: []const u8 =
        @embedFile("fixtures/package-database/healthy/toolz.triggers");
    pub const toolz_postinst: []const u8 =
        @embedFile("fixtures/package-database/healthy/toolz.postinst");
    pub const toolz_prerm: []const u8 = @embedFile("fixtures/package-database/healthy/toolz.prerm");
    pub const oldpkg_list: []const u8 = @embedFile("fixtures/package-database/healthy/oldpkg.list");
    pub const oldpkg_conffiles: []const u8 =
        @embedFile("fixtures/package-database/healthy/oldpkg.conffiles");

    pub const info: []const InfoEntry = &.{
        .{ .name = "format", .bytes = format },
        .{ .name = "libfoo:amd64.list", .bytes = libfoo_amd64_list },
        .{ .name = "libfoo:amd64.md5sums", .bytes = libfoo_amd64_md5sums },
        .{ .name = "libfoo:amd64.conffiles", .bytes = libfoo_amd64_conffiles },
        .{ .name = "libfoo:i386.list", .bytes = libfoo_i386_list },
        .{ .name = "libfoo:i386.md5sums", .bytes = libfoo_i386_md5sums },
        .{ .name = "toolz.list", .bytes = toolz_list },
        .{ .name = "toolz.md5sums", .bytes = toolz_md5sums },
        .{ .name = "toolz.triggers", .bytes = toolz_triggers },
        .{ .name = "toolz.postinst", .bytes = toolz_postinst, .mode = 0o755 },
        .{ .name = "toolz.prerm", .bytes = toolz_prerm, .mode = 0o755 },
        .{ .name = "oldpkg.list", .bytes = oldpkg_list },
        .{ .name = "oldpkg.conffiles", .bytes = oldpkg_conffiles },
    };

    pub fn snapshot() Snapshot {
        return .{
            .status = status,
            .arch = arch,
            .triggers_file = triggers_file,
            .triggers_unincorp = triggers_unincorp,
            .info = info,
        };
    }

    pub fn request() ImportRequest {
        return .{ .native_architecture = "amd64", .snapshot = snapshot() };
    }
};

fn expectDiagnostic(result: Result, code: Code) !void {
    switch (result) {
        .database => |value| {
            var owned = value;
            owned.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| try testing.expectEqual(code, diagnostic.code),
    }
}

test "package_database.test.healthy root imports every selected surface" {
    const result = try importSnapshot(testing.allocator, test_fixtures.request(), .{});
    var database = switch (result) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer database.deinit();

    const model = database.model;
    try testing.expectEqual(@as(usize, 4), model.packages.len);
    try testing.expectEqualStrings("amd64", model.native_architecture);
    try testing.expectEqual(@as(usize, 1), model.foreign_architectures.len);
    try testing.expectEqualStrings("i386", model.foreign_architectures[0]);
    try testing.expect(model.info_format_present);
    try testing.expectEqual(@as(usize, 0), model.pending_updates.len);

    const libfoo = model.find("libfoo", "amd64").?;
    try testing.expectEqualStrings("libfoo:amd64", libfoo.info_stem);
    try testing.expectEqual(MultiArch.same, libfoo.multi_arch.?);
    try testing.expect(libfoo.status.isFullyInstalled());
    try testing.expectEqual(@as(usize, 1), libfoo.conffiles.len);
    try testing.expectEqualStrings("/etc/foo/foo.conf", libfoo.conffiles[0].path);
    try testing.expect(libfoo.conffiles[0].digest == .md5);
    try testing.expect(!libfoo.conffiles[0].obsolete);
    try testing.expectEqual(@as(usize, 11), libfoo.paths.?.len);
    try testing.expect(libfoo.ownsPath("/usr/lib/libfoo.so.1"));
    try testing.expect(libfoo.ownsPath("/"));
    try testing.expectEqual(@as(usize, 2), libfoo.md5sums.?.len);
    try testing.expectEqual(@as(usize, 1), libfoo.declared_conffiles.?.len);

    const other = model.find("libfoo", "i386").?;
    try testing.expectEqualStrings("libfoo:i386", other.info_stem);
    try testing.expectEqualStrings(libfoo.version, other.version);

    const toolz = model.find("toolz", "amd64").?;
    try testing.expectEqualStrings("toolz", toolz.info_stem);
    try testing.expectEqual(CurrentState.triggers_pending, toolz.status.current);
    try testing.expectEqual(@as(usize, 1), toolz.triggers_pending.len);
    try testing.expectEqual(@as(usize, 2), toolz.scripts.len);
    try testing.expect(toolz.script(.postinst) != null);
    try testing.expect(toolz.script(.prerm) != null);
    try testing.expectEqual(@as(usize, 1), toolz.trigger_declarations.?.len);
    try testing.expectEqual(
        TriggerDeclarationKind.interest,
        toolz.trigger_declarations.?[0].kind,
    );

    const oldpkg = model.find("oldpkg", "amd64").?;
    try testing.expectEqual(CurrentState.config_files, oldpkg.status.current);
    try testing.expectEqual(Want.deinstall, oldpkg.status.want);
    try testing.expect(oldpkg.md5sums == null);

    try testing.expectEqual(@as(usize, 1), model.triggers.interests.len);
    try testing.expectEqualStrings("/usr/share/toolz", model.triggers.interests[0].trigger);
    try testing.expectEqual(AwaitMode.awaited, model.triggers.interests[0].await_mode);
    try testing.expectEqual(@as(usize, 1), model.triggers.pending.len);
    try testing.expectEqual(@as(usize, 1), model.triggers.pending[0].packages.len);

    const owners = try model.owners(testing.allocator, "/usr/lib/libfoo.so.1");
    defer testing.allocator.free(owners);
    try testing.expectEqual(@as(usize, 1), owners.len);
    try testing.expectEqualStrings("libfoo", owners[0].name);
}

test "package_database.test.canonical writers reproduce the imported generation" {
    const result = try importSnapshot(testing.allocator, test_fixtures.request(), .{});
    var database = switch (result) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer database.deinit();
    const model = database.model;

    const status_bytes = try writeStatusDocument(testing.allocator, model.packages);
    defer testing.allocator.free(status_bytes);
    try testing.expectEqualStrings(test_fixtures.status, status_bytes);

    const libfoo = model.find("libfoo", "amd64").?;
    const list_bytes = try writeFileList(testing.allocator, libfoo.paths.?);
    defer testing.allocator.free(list_bytes);
    try testing.expectEqualStrings(test_fixtures.libfoo_amd64_list, list_bytes);

    const md5sums_bytes = try writeMd5sums(testing.allocator, libfoo.md5sums.?);
    defer testing.allocator.free(md5sums_bytes);
    try testing.expectEqualStrings(test_fixtures.libfoo_amd64_md5sums, md5sums_bytes);

    const conffiles_bytes = try writeDeclaredConffiles(
        testing.allocator,
        libfoo.declared_conffiles.?,
    );
    defer testing.allocator.free(conffiles_bytes);
    try testing.expectEqualStrings(test_fixtures.libfoo_amd64_conffiles, conffiles_bytes);

    const toolz = model.find("toolz", "amd64").?;
    const triggers_bytes = try writeTriggerDeclarations(
        testing.allocator,
        toolz.trigger_declarations.?,
    );
    defer testing.allocator.free(triggers_bytes);
    try testing.expectEqualStrings(test_fixtures.toolz_triggers, triggers_bytes);

    const interests_bytes = try writeTriggerInterests(testing.allocator, model.triggers.interests);
    defer testing.allocator.free(interests_bytes);
    try testing.expectEqualStrings(test_fixtures.triggers_file, interests_bytes);

    const pending_bytes = try writePendingTriggers(testing.allocator, model.triggers.pending);
    defer testing.allocator.free(pending_bytes);
    try testing.expectEqualStrings(test_fixtures.triggers_unincorp, pending_bytes);

    const arch_bytes = try writeArchitectures(testing.allocator, model.foreign_architectures);
    defer testing.allocator.free(arch_bytes);
    try testing.expectEqualStrings(test_fixtures.arch, arch_bytes);
}

test "package_database.test.unknown status fields survive a semantic round trip" {
    const first = try importSnapshot(testing.allocator, test_fixtures.request(), .{});
    var database = switch (first) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer database.deinit();

    const libfoo = database.model.find("libfoo", "amd64").?;
    const note = libfoo.field("X-Vendor-Note").?;
    try testing.expectEqualStrings("retained unknown field", note.value_lines[0]);

    const republished = try writeStatusDocument(testing.allocator, database.model.packages);
    defer testing.allocator.free(republished);

    var snapshot = test_fixtures.snapshot();
    snapshot.status = republished;
    const second = try importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{},
    );
    var reimported = switch (second) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer reimported.deinit();
    try testing.expectEqual(
        database.model.packages.len,
        reimported.model.packages.len,
    );
    try testing.expectEqualStrings(
        "retained unknown field",
        reimported.model.find("libfoo", "amd64").?.field("X-Vendor-Note").?.value_lines[0],
    );
    try testing.expectEqualSlices(
        u8,
        &database.model.status.sha256,
        &reimported.model.status.sha256,
    );
}

test "package_database.test.generation evidence detects external database change" {
    const result = try importSnapshot(testing.allocator, test_fixtures.request(), .{});
    var database = switch (result) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer database.deinit();

    try testing.expect(try verifyGeneration(
        testing.allocator,
        database,
        test_fixtures.snapshot(),
    ) == null);

    var changed = test_fixtures.snapshot();
    changed.arch = "i386\nppc64el\n";
    const diagnostic = (try verifyGeneration(testing.allocator, database, changed)).?;
    try testing.expectEqual(Code.external_generation_change, diagnostic.code);

    var touched_info = test_fixtures.snapshot();
    var entries = try testing.allocator.dupe(InfoEntry, test_fixtures.info);
    defer testing.allocator.free(entries);
    entries[0] = .{ .name = "format", .bytes = "1\n", .mode = 0o600 };
    touched_info.info = entries;
    try testing.expect((try verifyGeneration(
        testing.allocator,
        database,
        touched_info,
    )) != null);
}

fn expectImportFailure(snapshot: Snapshot, code: Code) !void {
    const result = try importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{},
    );
    try expectDiagnostic(result, code);
}

fn expectImportSurface(snapshot: Snapshot, surface: Surface, code: Code) !void {
    const result = try importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{},
    );
    switch (result) {
        .database => |value| {
            var owned = value;
            owned.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| {
            try testing.expectEqual(code, diagnostic.code);
            try testing.expectEqual(surface, diagnostic.surface);
        },
    }
}

const minimal_status =
    \\Package: solo
    \\Status: install ok installed
    \\Architecture: amd64
    \\Version: 1.0
    \\
    \\
;
const minimal_list = "/.\n/usr\n/usr/bin\n/usr/bin/solo\n";

fn minimalSnapshot(status_text: []const u8, entries: []const InfoEntry) Snapshot {
    return .{ .status = status_text, .info = entries };
}

fn minimalInfo() []const InfoEntry {
    return &.{.{ .name = "solo.list", .bytes = minimal_list }};
}

fn infoWithout(allocator: std.mem.Allocator, name: []const u8) ![]InfoEntry {
    var entries: std.ArrayList(InfoEntry) = .empty;
    errdefer entries.deinit(allocator);
    for (test_fixtures.info) |entry| {
        if (std.mem.eql(u8, entry.name, name)) continue;
        try entries.append(allocator, entry);
    }
    return entries.toOwnedSlice(allocator);
}

fn infoReplacing(allocator: std.mem.Allocator, replacement: InfoEntry) ![]InfoEntry {
    const entries = try allocator.dupe(InfoEntry, test_fixtures.info);
    for (entries) |*entry| {
        if (std.mem.eql(u8, entry.name, replacement.name)) entry.* = replacement;
    }
    return entries;
}

fn infoPlus(allocator: std.mem.Allocator, extra: InfoEntry) ![]InfoEntry {
    var entries = try allocator.alloc(InfoEntry, test_fixtures.info.len + 1);
    @memcpy(entries[0..test_fixtures.info.len], test_fixtures.info);
    entries[test_fixtures.info.len] = extra;
    return entries;
}

test "package_database.test.malformed status paragraphs fail before any mutation" {
    try expectImportFailure(minimalSnapshot("Package solo\n", &.{}), .status_syntax);
    try expectImportFailure(
        minimalSnapshot(
            "Package: solo\nStatus: install ok wobbly\nArchitecture: amd64\nVersion: 1\n\n",
            &.{},
        ),
        .invalid_state,
    );
    try expectImportFailure(
        minimalSnapshot("Package: solo\nStatus: install ok installed\nVersion: 1\n\n", &.{}),
        .missing_field,
    );
    try expectImportFailure(
        minimalSnapshot(
            "Package: Solo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n",
            &.{},
        ),
        .invalid_package_name,
    );
    try expectImportFailure(
        minimalSnapshot(
            "Package: solo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:\n\n",
            &.{},
        ),
        .invalid_version,
    );
    try expectImportFailure(
        minimalSnapshot(
            minimal_status ++ minimal_status,
            &.{.{ .name = "solo.list", .bytes = minimal_list }},
        ),
        .repeated_identity,
    );
    try expectImportFailure(
        minimalSnapshot(
            "Package: solo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n" ++
                "Conffiles:\n /etc/solo.conf notahash\n\n",
            minimalInfo(),
        ),
        .invalid_conffile,
    );
    try expectImportFailure(
        minimalSnapshot(
            "Package: solo\nStatus: install ok triggers-pending\nArchitecture: amd64\nVersion: 1\n\n",
            minimalInfo(),
        ),
        .missing_trigger_state,
    );
    try expectImportFailure(
        minimalSnapshot(
            "Package: solo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n" ++
                "Triggers-Pending: /usr/share/solo\n\n",
            minimalInfo(),
        ),
        .unexpected_trigger_state,
    );
}

test "package_database.test.package state and ownership must agree across files" {
    try expectImportSurface(
        minimalSnapshot(minimal_status, &.{}),
        .cross_file,
        .missing_file_list,
    );
    try expectImportSurface(
        minimalSnapshot(
            "Package: solo\nStatus: purge ok not-installed\nArchitecture: amd64\nVersion: 1\n\n",
            minimalInfo(),
        ),
        .cross_file,
        .unexpected_file_list,
    );
    try expectImportSurface(
        minimalSnapshot(
            "Package: solo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n" ++
                "Conffiles:\n /etc/solo.conf 5d41402abc4b2a76b9719d911017c592\n\n",
            minimalInfo(),
        ),
        .cross_file,
        .conffile_not_owned,
    );
    try expectImportSurface(
        minimalSnapshot(minimal_status, &.{
            .{ .name = "solo.list", .bytes = minimal_list },
            .{ .name = "solo.md5sums", .bytes = "5d41402abc4b2a76b9719d911017c592  usr/bin/other\n" },
        }),
        .cross_file,
        .checksum_out_of_inventory,
    );
    try expectImportSurface(
        minimalSnapshot(minimal_status, &.{
            .{ .name = "solo.list", .bytes = minimal_list },
            .{ .name = "solo.conffiles", .bytes = "/etc/solo.conf\n" },
        }),
        .cross_file,
        .declared_conffile_mismatch,
    );
    try expectImportSurface(
        minimalSnapshot(
            "Package: solo\nStatus: install ok installed\nArchitecture: i386\nVersion: 1\n\n",
            &.{.{ .name = "solo.list", .bytes = minimal_list }},
        ),
        .cross_file,
        .unknown_architecture,
    );
}

test "package_database.test.corrupt info files are rejected with exact locations" {
    const cases = [_]struct { bytes: []const u8, code: Code }{
        .{ .bytes = "/usr/bin/solo", .code = .unterminated_line },
        .{ .bytes = "/usr/bin/solo\n\n", .code = .empty_line },
        .{ .bytes = "/usr/bin/../etc/shadow\n", .code = .invalid_path },
        .{ .bytes = "usr/bin/solo\n", .code = .invalid_path },
        .{ .bytes = "/usr/bin/solo\n/usr/bin/solo\n", .code = .duplicate_path },
        .{ .bytes = "/usr/bin/so\tlo\n", .code = .control_character },
    };
    for (cases) |case| {
        try expectImportSurface(
            minimalSnapshot(minimal_status, &.{.{ .name = "solo.list", .bytes = case.bytes }}),
            .info_list,
            case.code,
        );
    }

    const checksum_cases = [_]struct { bytes: []const u8, code: Code }{
        .{ .bytes = "5d41402abc4b2a76b9719d911017c592 usr/bin/solo\n", .code = .invalid_checksum },
        .{ .bytes = "5D41402ABC4B2A76B9719D911017C592  usr/bin/solo\n", .code = .invalid_checksum },
        .{ .bytes = "5d41402abc4b2a76b9719d911017c592  /usr/bin/solo\n", .code = .invalid_path },
        .{
            .bytes = "5d41402abc4b2a76b9719d911017c592  usr/bin/solo\n" ++
                "5d41402abc4b2a76b9719d911017c592  usr/bin/solo\n",
            .code = .duplicate_checksum,
        },
    };
    for (checksum_cases) |case| {
        try expectImportSurface(
            minimalSnapshot(minimal_status, &.{
                .{ .name = "solo.list", .bytes = minimal_list },
                .{ .name = "solo.md5sums", .bytes = case.bytes },
            }),
            .info_md5sums,
            case.code,
        );
    }

    try expectImportSurface(
        minimalSnapshot(minimal_status, &.{
            .{ .name = "solo.list", .bytes = minimal_list },
            .{ .name = "solo.triggers", .bytes = "interest\n" },
        }),
        .info_triggers,
        .invalid_trigger_declaration,
    );
    try expectImportSurface(
        minimalSnapshot(minimal_status, &.{
            .{ .name = "solo.list", .bytes = minimal_list },
            .{ .name = "solo.triggers", .bytes = "interest-sometimes /usr/share/solo\n" },
        }),
        .info_triggers,
        .invalid_trigger_declaration,
    );
}

test "package_database.test.info directory entries must be safe qualified regular files" {
    const allocator = testing.allocator;

    const orphan = try infoPlus(allocator, .{ .name = "ghost.list", .bytes = "/.\n" });
    defer allocator.free(orphan);
    var snapshot = test_fixtures.snapshot();
    snapshot.info = orphan;
    try expectImportFailure(snapshot, .orphan_info_file);

    const ambiguous = try infoPlus(allocator, .{ .name = "libfoo.md5sums", .bytes = "" });
    defer allocator.free(ambiguous);
    snapshot.info = ambiguous;
    try expectImportFailure(snapshot, .ambiguous_info_file);

    const malformed = try infoPlus(allocator, .{ .name = "notqualified", .bytes = "" });
    defer allocator.free(malformed);
    snapshot.info = malformed;
    try expectImportFailure(snapshot, .malformed_info_name);

    const symlink = try infoReplacing(allocator, .{
        .name = "toolz.list",
        .bytes = test_fixtures.toolz_list,
        .kind = .symlink,
    });
    defer allocator.free(symlink);
    snapshot.info = symlink;
    try expectImportFailure(snapshot, .unsupported_entry_kind);

    const setuid = try infoReplacing(allocator, .{
        .name = "toolz.postinst",
        .bytes = test_fixtures.toolz_postinst,
        .mode = 0o4755,
    });
    defer allocator.free(setuid);
    snapshot.info = setuid;
    try expectImportFailure(snapshot, .unsafe_mode);

    const not_executable = try infoReplacing(allocator, .{
        .name = "toolz.prerm",
        .bytes = test_fixtures.toolz_prerm,
        .mode = 0o644,
    });
    defer allocator.free(not_executable);
    snapshot.info = not_executable;
    try expectImportSurface(snapshot, .info_script, .unsafe_mode);

    const future_format = try infoReplacing(allocator, .{ .name = "format", .bytes = "2\n" });
    defer allocator.free(future_format);
    snapshot.info = future_format;
    try expectImportFailure(snapshot, .unsupported_info_format);

    const duplicate = try infoPlus(allocator, .{
        .name = "toolz.list",
        .bytes = test_fixtures.toolz_list,
    });
    defer allocator.free(duplicate);
    snapshot.info = duplicate;
    try expectImportFailure(snapshot, .duplicate_info_name);

    const missing_list = try infoWithout(allocator, "toolz.list");
    defer allocator.free(missing_list);
    snapshot.info = missing_list;
    try expectImportFailure(snapshot, .missing_file_list);
}

test "package_database.test.multiarch instances must be consistent" {
    const allocator = testing.allocator;
    const status = try std.mem.replaceOwned(
        u8,
        allocator,
        test_fixtures.status,
        "Architecture: i386\nMulti-Arch: same\nVersion: 1.2-3",
        "Architecture: i386\nMulti-Arch: same\nVersion: 1.2-4",
    );
    defer allocator.free(status);
    var snapshot = test_fixtures.snapshot();
    snapshot.status = status;
    try expectImportFailure(snapshot, .multiarch_conflict);

    const foreign_only = try std.mem.replaceOwned(
        u8,
        allocator,
        test_fixtures.status,
        "Architecture: i386\nMulti-Arch: same\n",
        "Architecture: i386\n",
    );
    defer allocator.free(foreign_only);
    snapshot.status = foreign_only;
    try expectImportFailure(snapshot, .multiarch_conflict);
}

test "package_database.test.trigger state must match declared interests and known packages" {
    const allocator = testing.allocator;
    var snapshot = test_fixtures.snapshot();
    snapshot.triggers_file = "/usr/share/toolz libfoo:amd64\n";
    try expectImportSurface(snapshot, .triggers_file, .trigger_interest_mismatch);

    snapshot = test_fixtures.snapshot();
    snapshot.triggers_file = "usr/share/toolz toolz\n";
    try expectImportSurface(snapshot, .triggers_file, .invalid_trigger_name);

    snapshot = test_fixtures.snapshot();
    snapshot.triggers_unincorp = "/usr/share/toolz ghost\n";
    try expectImportSurface(snapshot, .triggers_unincorp, .unknown_trigger_package);

    snapshot = test_fixtures.snapshot();
    snapshot.triggers_unincorp = "/usr/share/toolz\n";
    try expectImportSurface(snapshot, .triggers_unincorp, .invalid_trigger_record);

    const declarations = try infoReplacing(allocator, .{
        .name = "toolz.triggers",
        .bytes = "interest-noawait /usr/share/toolz\n",
    });
    defer allocator.free(declarations);
    snapshot = test_fixtures.snapshot();
    snapshot.info = declarations;
    try expectImportSurface(snapshot, .triggers_file, .trigger_interest_mismatch);
}

test "package_database.test.interrupted publication and unsupported metadata fail closed" {
    var snapshot = test_fixtures.snapshot();
    snapshot.updates = &.{.{ .name = "0001", .bytes = test_fixtures.status }};
    try expectImportSurface(snapshot, .updates, .update_fragments_present);

    const recovered = try importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{ .updates_policy = .import_for_recovery },
    );
    var database = switch (recovered) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer database.deinit();
    try testing.expectEqual(@as(usize, 1), database.model.pending_updates.len);
    try testing.expectEqual(@as(u64, 1), database.model.pending_updates[0].sequence);
    try testing.expectEqual(@as(usize, 4), database.model.pending_updates[0].package_count);

    snapshot = test_fixtures.snapshot();
    snapshot.updates = &.{.{ .name = "latest", .bytes = "" }};
    const bad_name = try importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{ .updates_policy = .import_for_recovery },
    );
    try expectDiagnostic(bad_name, .invalid_update_name);

    snapshot = test_fixtures.snapshot();
    snapshot.updates = &.{.{ .name = "0002", .bytes = "Package solo\n" }};
    const bad_fragment = try importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{ .updates_policy = .import_for_recovery },
    );
    try expectDiagnostic(bad_fragment, .invalid_update_fragment);

    snapshot = test_fixtures.snapshot();
    snapshot.diversions = "/usr/bin/toolz\n/usr/bin/toolz.real\n";
    try expectImportSurface(snapshot, .diversions, .invalid_diversion);

    snapshot = test_fixtures.snapshot();
    snapshot.statoverride = "root root 07555 /usr/bin/toolz\n";
    try expectImportSurface(snapshot, .statoverride, .invalid_statoverride);

    snapshot = test_fixtures.snapshot();
    snapshot.status_old = "Package solo\n";
    try expectImportSurface(snapshot, .status_old, .status_syntax);

    const invalid_native = try importSnapshot(
        testing.allocator,
        .{ .native_architecture = "all", .snapshot = test_fixtures.snapshot() },
        .{},
    );
    try expectDiagnostic(invalid_native, .invalid_architecture);
}

test "package_database.test.supported diversion and statoverride records are typed" {
    var snapshot = test_fixtures.snapshot();
    snapshot.diversions = "/usr/bin/toolz\n/usr/bin/toolz.real\nother\n";
    snapshot.statoverride = "root staff 2755 /usr/bin/toolz\n";
    const result = try importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{},
    );
    var database = switch (result) {
        .diagnostic => return error.TestUnexpectedResult,
        .database => |value| value,
    };
    defer database.deinit();
    try testing.expectEqual(@as(usize, 1), database.model.diversions.len);
    try testing.expectEqualStrings("other", database.model.diversions[0].package.?);
    try testing.expectEqual(@as(usize, 1), database.model.stat_overrides.len);
    try testing.expectEqual(@as(u32, 0o2755), database.model.stat_overrides[0].mode);

    const diversion_bytes = try writeDiversions(testing.allocator, database.model.diversions);
    defer testing.allocator.free(diversion_bytes);
    try testing.expectEqualStrings(snapshot.diversions.?, diversion_bytes);

    const override_bytes = try writeStatOverrides(testing.allocator, database.model.stat_overrides);
    defer testing.allocator.free(override_bytes);
    try testing.expectEqualStrings(snapshot.statoverride.?, override_bytes);
}

test "package_database.test.configured bounds are enforced" {
    const snapshot = test_fixtures.snapshot();
    const result = try importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{ .limits = .{ .max_packages = 2 } },
    );
    try expectDiagnostic(result, .status_limit);

    const bounded_paths = try importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{ .limits = .{ .max_paths_per_package = 3 } },
    );
    try expectDiagnostic(bounded_paths, .path_limit);

    const bounded_info = try importSnapshot(
        testing.allocator,
        .{ .native_architecture = "amd64", .snapshot = snapshot },
        .{ .limits = .{ .max_info_entries = 4 } },
    );
    try expectDiagnostic(bounded_info, .info_limit);
}
